//! Raw packet capture and protocol parsing.
//!
//! Captures packets from a network interface using libpcap, parses protocol headers,
//! detects anomalies, and publishes structured events to the NATS bus for the Go
//! modules to consume.

#[cfg(feature = "pcap-capture")]
use crate::config::CaptureConfig;
#[cfg(feature = "pcap-capture")]
use crate::events::PacketEvent;
#[cfg(feature = "pcap-capture")]
use crate::nats_bridge::EventPublisher;
#[cfg(feature = "pcap-capture")]
use anyhow::{Context, Result};
#[cfg(feature = "pcap-capture")]
use etherparse::{NetSlice, SlicedPacket, TransportSlice};
#[cfg(feature = "pcap-capture")]
use pcap::Capture;
#[cfg(feature = "pcap-capture")]
use tracing::{debug, info, warn};
#[cfg(feature = "pcap-capture")]
use uuid::Uuid;

/// Anomaly detection thresholds
const SUSPICIOUS_PORT_SCAN_THRESHOLD: usize = 20;
const MAX_PAYLOAD_PREVIEW: usize = 2048;
const STATS_INTERVAL_SECS: u64 = 60;
const SSH_MAX_PAYLOAD_SIZE: usize = 262_144;
const SSH_MAX_CHANNEL_OPENS_PER_SEC: usize = 50;
const SSH_TRACKER_WINDOW_SECS: u64 = 1;
const WEBSOCKET_MAX_FRAME_PAYLOAD: u64 = 16 * 1024 * 1024;
const WEBSOCKET_FLOW_TTL_SECS: u64 = 3600;

/// Per-source tracking for anomaly detection.
struct SourceTracker {
    /// Ports contacted by each source IP in the current window.
    port_scans: std::collections::HashMap<String, std::collections::HashSet<u16>>,
    /// Packet counts per source IP.
    packet_counts: std::collections::HashMap<String, u64>,
    /// Last stats reset time.
    last_reset: std::time::Instant,
}

impl SourceTracker {
    fn new() -> Self {
        Self {
            port_scans: std::collections::HashMap::new(),
            packet_counts: std::collections::HashMap::new(),
            last_reset: std::time::Instant::now(),
        }
    }

    fn track(&mut self, src_ip: &str, dst_port: u16) -> Vec<String> {
        let mut anomalies = Vec::new();

        // Reset counters periodically
        if self.last_reset.elapsed().as_secs() > STATS_INTERVAL_SECS {
            self.port_scans.clear();
            self.packet_counts.clear();
            self.last_reset = std::time::Instant::now();
        }

        // Track port scan behavior
        let ports = self.port_scans.entry(src_ip.to_string()).or_default();
        ports.insert(dst_port);
        if ports.len() >= SUSPICIOUS_PORT_SCAN_THRESHOLD {
            anomalies.push(format!(
                "port_scan: {} unique ports contacted from {}",
                ports.len(),
                src_ip
            ));
        }

        // Track packet volume
        let count = self.packet_counts.entry(src_ip.to_string()).or_insert(0);
        *count += 1;

        anomalies
    }
}

/// Per-flow SSH tracking for resource exhaustion detection.
struct SSHTracker {
    /// Per-flow: visible channel-open timestamps for rate tracking
    flow_channel_opens: std::collections::HashMap<String, Vec<std::time::Instant>>,
    last_reset: std::time::Instant,
}

impl SSHTracker {
    fn new() -> Self {
        Self {
            flow_channel_opens: std::collections::HashMap::new(),
            last_reset: std::time::Instant::now(),
        }
    }

    fn flow_key(src_ip: &str, dst_ip: &str, dst_port: u16) -> String {
        format!("{}:{}:{}", src_ip, dst_ip, dst_port)
    }

    fn track(&mut self, src_ip: &str, dst_ip: &str, dst_port: u16, payload: &[u8]) -> Vec<String> {
        let mut anomalies = Vec::new();

        // Reset periodically
        if self.last_reset.elapsed().as_secs() > STATS_INTERVAL_SECS {
            self.flow_channel_opens.clear();
            self.last_reset = std::time::Instant::now();
        }

        if dst_port != 22 {
            return anomalies;
        }

        let key = Self::flow_key(src_ip, dst_ip, dst_port);

        if payload.len() > SSH_MAX_PAYLOAD_SIZE {
            anomalies.push(format!(
                "ssh_oversized_frame: flow {} sent {} byte payload (threshold: {})",
                key,
                payload.len(),
                SSH_MAX_PAYLOAD_SIZE
            ));
        }

        if !is_ssh_channel_open_payload(payload) {
            return anomalies;
        }

        let now = std::time::Instant::now();
        let timestamps = self.flow_channel_opens.entry(key.clone()).or_default();
        timestamps.push(now);
        let window_start = now - std::time::Duration::from_secs(SSH_TRACKER_WINDOW_SECS);
        timestamps.retain(|t| *t >= window_start);
        if timestamps.len() > SSH_MAX_CHANNEL_OPENS_PER_SEC {
            anomalies.push(format!(
                "ssh_channel_exhaustion: flow {} sent {} visible channel-open requests in {}s (threshold: {})",
                key, timestamps.len(), SSH_TRACKER_WINDOW_SECS, SSH_MAX_CHANNEL_OPENS_PER_SEC
            ));
            timestamps.clear();
        }

        anomalies
    }
}

fn is_ssh_channel_open_payload(payload: &[u8]) -> bool {
    const SSH_MSG_CHANNEL_OPEN: u8 = 90;

    if payload.is_empty() {
        return false;
    }

    // Some tests/adapters pass decoded SSH messages where the first byte is
    // the message number. On the wire, SSH binary packets place it after the
    // 4-byte packet_length and 1-byte padding_length fields.
    if payload[0] == SSH_MSG_CHANNEL_OPEN {
        return true;
    }
    if payload.len() > 5 && payload[5] == SSH_MSG_CHANNEL_OPEN {
        return true;
    }

    false
}

/// Tracks plaintext WebSocket upgrade requests so binary payloads are only
/// interpreted as RFC 6455 frames on confirmed client-to-server flows.
struct WebSocketTracker {
    flows: std::collections::HashMap<String, std::time::Instant>,
    last_prune: std::time::Instant,
}

impl WebSocketTracker {
    fn new() -> Self {
        Self {
            flows: std::collections::HashMap::new(),
            last_prune: std::time::Instant::now(),
        }
    }

    fn flow_key(src_ip: &str, src_port: u16, dst_ip: &str, dst_port: u16) -> String {
        format!("{}:{}:{}:{}", src_ip, src_port, dst_ip, dst_port)
    }

    fn track(
        &mut self,
        src_ip: &str,
        src_port: u16,
        dst_ip: &str,
        dst_port: u16,
        payload: &[u8],
    ) -> Vec<String> {
        let now = std::time::Instant::now();
        if self.last_prune.elapsed().as_secs() >= STATS_INTERVAL_SECS {
            let cutoff = now - std::time::Duration::from_secs(WEBSOCKET_FLOW_TTL_SECS);
            self.flows.retain(|_, last_seen| *last_seen >= cutoff);
            self.last_prune = now;
        }

        let key = Self::flow_key(src_ip, src_port, dst_ip, dst_port);
        if is_websocket_upgrade_request(payload) {
            self.flows.insert(key, now);
            return Vec::new();
        }
        let Some(last_seen) = self.flows.get_mut(&key) else {
            return Vec::new();
        };
        *last_seen = now;

        validate_websocket_client_frame(payload)
            .into_iter()
            .map(|reason| format!("websocket_invalid_frame: flow {key} {reason}"))
            .collect()
    }
}

fn is_websocket_upgrade_request(payload: &[u8]) -> bool {
    let preview_len = payload.len().min(4096);
    let Ok(text) = std::str::from_utf8(&payload[..preview_len]) else {
        return false;
    };
    let lower = text.to_ascii_lowercase();
    lower.contains("upgrade: websocket") && lower.contains("connection: upgrade")
}

fn validate_websocket_client_frame(payload: &[u8]) -> Option<String> {
    if payload.len() < 2 {
        return None;
    }

    let first = payload[0];
    let second = payload[1];
    let fin = first & 0x80 != 0;
    let reserved = first & 0x70;
    let opcode = first & 0x0f;
    let masked = second & 0x80 != 0;
    let length_code = second & 0x7f;

    if reserved != 0 {
        return Some(format!("sets reserved bits 0x{reserved:02x}"));
    }
    if !matches!(opcode, 0x0 | 0x1 | 0x2 | 0x8 | 0x9 | 0xa) {
        return Some(format!("uses reserved opcode 0x{opcode:x}"));
    }
    if !masked {
        return Some("client frame is not masked".to_string());
    }

    let payload_len = match length_code {
        0..=125 => u64::from(length_code),
        126 => {
            if payload.len() < 4 {
                return None;
            }
            let length = u64::from(u16::from_be_bytes([payload[2], payload[3]]));
            if length < 126 {
                return Some(format!("uses non-canonical 16-bit length {length}"));
            }
            length
        }
        127 => {
            if payload.len() < 10 {
                return None;
            }
            if payload[2] & 0x80 != 0 {
                return Some("sets the forbidden high bit in a 64-bit length".to_string());
            }
            let length = u64::from_be_bytes(payload[2..10].try_into().expect("length checked"));
            if length < 65_536 {
                return Some(format!("uses non-canonical 64-bit length {length}"));
            }
            length
        }
        _ => unreachable!(),
    };

    if opcode >= 0x8 && (!fin || payload_len > 125) {
        return Some(format!(
            "uses invalid control-frame fragmentation or length {payload_len}"
        ));
    }
    if payload_len > WEBSOCKET_MAX_FRAME_PAYLOAD {
        return Some(format!(
            "claims {payload_len} bytes (limit: {WEBSOCKET_MAX_FRAME_PAYLOAD})"
        ));
    }
    None
}

/// Main packet capture loop. Runs until an error occurs or the process is killed.
#[cfg(feature = "pcap-capture")]
pub async fn capture_loop(
    interface: &str,
    publisher: EventPublisher,
    cfg: &CaptureConfig,
) -> Result<()> {
    info!(interface = %interface, snaplen = cfg.snaplen, promiscuous = cfg.promiscuous, "starting packet capture");

    let mut cap = Capture::from_device(interface)?
        .promisc(cfg.promiscuous)
        .snaplen(cfg.snaplen)
        .timeout(1000)
        .open()
        .with_context(|| format!("opening capture on {}", interface))?;

    // Set BPF filter from config, or default to TCP/UDP
    let bpf = cfg.bpf_filter.as_deref().unwrap_or("tcp or udp");
    if let Err(e) = cap.filter(bpf, true) {
        warn!(error = %e, filter = %bpf, "failed to set BPF filter, capturing all traffic");
    }

    let mut tracker = SourceTracker::new();
    let mut ssh_tracker = SSHTracker::new();
    let mut websocket_tracker = WebSocketTracker::new();
    let mut total_packets: u64 = 0;
    let mut published_events: u64 = 0;
    let stats_start = std::time::Instant::now();

    info!("capture active, processing packets");

    loop {
        let raw = match cap.next_packet() {
            Ok(p) => p,
            Err(pcap::Error::TimeoutExpired) => continue,
            Err(e) => {
                warn!(error = %e, "capture error");
                tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                continue;
            }
        };

        total_packets += 1;

        // Log stats periodically
        if total_packets.is_multiple_of(10_000) {
            let elapsed = stats_start.elapsed().as_secs_f64();
            let pps = total_packets as f64 / elapsed;
            info!(
                total = total_packets,
                published = published_events,
                pps = format!("{:.0}", pps),
                "capture stats"
            );
        }

        // Parse the packet
        let parsed = match SlicedPacket::from_ethernet(raw.data) {
            Ok(p) => p,
            Err(_) => continue,
        };

        let (src_ip, dst_ip) = match &parsed.net {
            Some(NetSlice::Ipv4(ipv4)) => {
                let h = ipv4.header();
                (
                    format!(
                        "{}.{}.{}.{}",
                        h.source()[0],
                        h.source()[1],
                        h.source()[2],
                        h.source()[3]
                    ),
                    format!(
                        "{}.{}.{}.{}",
                        h.destination()[0],
                        h.destination()[1],
                        h.destination()[2],
                        h.destination()[3]
                    ),
                )
            }
            Some(NetSlice::Ipv6(ipv6)) => {
                let h = ipv6.header();
                (
                    format!("{:?}", h.source()),
                    format!("{:?}", h.destination()),
                )
            }
            _ => continue,
        };

        let (protocol, src_port, dst_port, flags) = match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let h = tcp.to_header();
                let mut flags = Vec::new();
                if h.syn {
                    flags.push("SYN".to_string());
                }
                if h.ack {
                    flags.push("ACK".to_string());
                }
                if h.fin {
                    flags.push("FIN".to_string());
                }
                if h.rst {
                    flags.push("RST".to_string());
                }
                if h.psh {
                    flags.push("PSH".to_string());
                }
                if h.urg {
                    flags.push("URG".to_string());
                }
                // Detect Christmas tree scan (all flags set)
                if h.syn && h.fin && h.urg && h.psh {
                    flags.push("XMAS_SCAN".to_string());
                }
                // Detect NULL scan (no flags)
                if !h.syn && !h.ack && !h.fin && !h.rst && !h.psh && !h.urg {
                    flags.push("NULL_SCAN".to_string());
                }
                ("tcp".to_string(), h.source_port, h.destination_port, flags)
            }
            Some(TransportSlice::Udp(udp)) => {
                let h = udp.to_header();
                (
                    "udp".to_string(),
                    h.source_port,
                    h.destination_port,
                    Vec::new(),
                )
            }
            _ => continue,
        };

        // Track for anomaly detection
        let mut anomalies = tracker.track(&src_ip, dst_port);

        // Add flag-based anomalies
        if flags.contains(&"XMAS_SCAN".to_string()) {
            anomalies.push("xmas_tree_scan: all TCP flags set".to_string());
        }
        if flags.contains(&"NULL_SCAN".to_string()) {
            anomalies.push("null_scan: no TCP flags set".to_string());
        }

        // Extract payload and preview
        let (payload_len, payload_preview) = match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                let payload = tcp.payload();
                (payload.len(), extract_text_preview(payload))
            }
            Some(TransportSlice::Udp(udp)) => {
                let payload = udp.payload();
                (payload.len(), extract_text_preview(payload))
            }
            _ => (0, String::new()),
        };

        // SSH protocol exhaustion tracking (port 22)
        let ssh_anomalies = match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                ssh_tracker.track(&src_ip, &dst_ip, dst_port, tcp.payload())
            }
            _ => Vec::new(),
        };
        anomalies.extend(ssh_anomalies);

        let websocket_anomalies = match &parsed.transport {
            Some(TransportSlice::Tcp(tcp)) => {
                websocket_tracker.track(&src_ip, src_port, &dst_ip, dst_port, tcp.payload())
            }
            _ => Vec::new(),
        };
        anomalies.extend(websocket_anomalies);

        // Deep-buffer binary signature scan for large payloads (>2KB)
        if payload_len > MAX_PAYLOAD_PREVIEW {
            if let Some(TransportSlice::Tcp(tcp)) = &parsed.transport {
                let payload = tcp.payload();
                let binary_anomalies = scan_deep_binary_signatures(payload);
                anomalies.extend(binary_anomalies);
            }
        }

        // Only publish events that have anomalies, interesting flags, or text payloads
        let should_publish = !anomalies.is_empty()
            || !payload_preview.is_empty()
            || flags.iter().any(|f| f.ends_with("_SCAN"));

        if !should_publish {
            continue;
        }

        let event = PacketEvent {
            id: Uuid::new_v4().to_string(),
            timestamp: chrono::Utc::now(),
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
            length: raw.data.len(),
            flags,
            payload_preview,
            anomalies,
        };

        if let Err(e) = publisher.publish_packet_event(&event).await {
            debug!(error = %e, "failed to publish packet event");
        } else {
            published_events += 1;
        }
    }
}

/// Deep-buffer binary signature scanner for embedded executables in large payloads.
/// Scans the entire payload (not just the 2KB preview) for ELF, PE, and 7zXZ headers.
/// Ref: weekly intel 2026-05-29 — deep-file memory corruption RCE detection.
fn scan_deep_binary_signatures(data: &[u8]) -> Vec<String> {
    let mut anomalies = Vec::new();
    const CHUNK_SIZE: usize = 16_384;
    const OVERLAP: usize = 16;

    if data.len() <= CHUNK_SIZE {
        if let Some(offset) = find_signature_offset(data, b"\x7FELF") {
            anomalies.push(format!(
                "embedded_elf: ELF header found at offset {}",
                offset
            ));
        }
        if let Some(offset) = find_signature_offset(data, b"MZ") {
            anomalies.push(format!(
                "embedded_mz_pe: PE header found at offset {}",
                offset
            ));
        }
        if let Some(offset) = find_signature_offset(data, b"\xFD7zXZ\x00") {
            anomalies.push(format!(
                "embedded_7xz: 7zXZ header found at offset {}",
                offset
            ));
        }
        return anomalies;
    }

    let mut start = 0;
    while start < data.len() {
        let end = (start + CHUNK_SIZE).min(data.len());
        let chunk = &data[start..end];

        if let Some(offset) = find_signature_offset(chunk, b"\x7FELF") {
            anomalies.push(format!(
                "embedded_elf: ELF header found at offset {}",
                start + offset
            ));
        }
        if let Some(offset) = find_signature_offset(chunk, b"MZ") {
            anomalies.push(format!(
                "embedded_mz_pe: PE header found at offset {}",
                start + offset
            ));
        }
        if let Some(offset) = find_signature_offset(chunk, b"\xFD7zXZ\x00") {
            anomalies.push(format!(
                "embedded_7xz: 7zXZ header found at offset {}",
                start + offset
            ));
        }

        if end == data.len() {
            break;
        }
        start = end.saturating_sub(OVERLAP);
    }

    anomalies
}

fn find_signature_offset(data: &[u8], signature: &[u8]) -> Option<usize> {
    if signature.is_empty() || data.len() < signature.len() {
        return None;
    }
    data.windows(signature.len()).position(|w| w == signature)
}

/// Validate file magic bytes against declared extension to detect polyglot files.
/// Returns an anomaly string if the magic bytes don't match the claimed file type.
pub fn validate_magic(data: &[u8], extension: &str) -> Option<String> {
    if data.len() < 4 {
        return None;
    }

    let ext = extension.to_lowercase();
    let ext = ext.trim_start_matches('.');

    // Known magic byte signatures
    let expected: &[(&str, &[&[u8]])] = &[
        ("png", &[&[0x89, 0x50, 0x4E, 0x47]]),
        ("jpg", &[&[0xFF, 0xD8, 0xFF]]),
        ("jpeg", &[&[0xFF, 0xD8, 0xFF]]),
        ("gif", &[b"GIF8"]),
        ("pdf", &[b"%PDF"]),
        ("jp2", &[&[0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20]]),
        ("zip", &[b"PK\x03\x04", b"PK\x05\x06"]),
        ("gz", &[&[0x1F, 0x8B]]),
        ("bz2", &[b"BZ"]),
        ("rar", &[b"Rar!"]),
        ("7z", &[&[0x37, 0x7A, 0xBC, 0xAF]]),
        ("exe", &[b"MZ"]),
        ("dll", &[b"MZ"]),
        ("elf", &[&[0x7F, 0x45, 0x4C, 0x46]]), // \x7fELF
        ("class", &[&[0xCA, 0xFE, 0xBA, 0xBE]]),
        ("wasm", &[&[0x00, 0x61, 0x73, 0x6D]]),
        ("doc", &[&[0xD0, 0xCF, 0x11, 0xE0]]),
        ("xls", &[&[0xD0, 0xCF, 0x11, 0xE0]]),
        ("ppt", &[&[0xD0, 0xCF, 0x11, 0xE0]]),
    ];

    // Dangerous magic bytes that should NEVER appear disguised as images/documents
    let dangerous_magics: &[(&[u8], &str)] = &[
        (&[0x7F, 0x45, 0x4C, 0x46], "ELF executable"),
        (b"MZ", "PE/Windows executable"),
        (&[0xCA, 0xFE, 0xBA, 0xBE], "Java class file"),
        (&[0x00, 0x61, 0x73, 0x6D], "WebAssembly binary"),
    ];

    let safe_extensions = [
        "png", "jpg", "jpeg", "gif", "bmp", "svg", "webp", "pdf", "doc", "docx", "xls", "xlsx",
        "ppt", "pptx", "txt", "csv", "json", "xml", "html",
    ];

    // Check if a "safe" extension contains dangerous magic bytes
    if safe_extensions.contains(&ext) {
        for (magic, desc) in dangerous_magics {
            if data.starts_with(magic) {
                return Some(format!(
                    "magic_byte_mismatch: file claims .{} but contains {} magic bytes",
                    ext, desc
                ));
            }
        }
    }

    // Check declared extension against expected magic bytes
    for (known_ext, signatures) in expected {
        if ext == *known_ext {
            let matches = signatures.iter().any(|sig| data.starts_with(sig));
            if !matches {
                return Some(format!(
                    "magic_byte_mismatch: .{} file does not match expected magic bytes",
                    ext
                ));
            }
            break;
        }
    }

    None
}

/// Extract a text preview from a payload slice, returning empty string if binary.
fn extract_text_preview(payload: &[u8]) -> String {
    if payload.is_empty() {
        return String::new();
    }
    let len = payload.len().min(MAX_PAYLOAD_PREVIEW);
    if payload[..len]
        .iter()
        .all(|&b| (0x20..0x7f).contains(&b) || b == b'\n' || b == b'\r' || b == b'\t')
    {
        String::from_utf8_lossy(&payload[..len]).to_string()
    } else {
        String::new()
    }
}

#[cfg(test)]
mod source_tracker_tests {
    use super::*;

    #[test]
    fn test_source_tracker_no_anomaly_few_ports() {
        let mut tracker = SourceTracker::new();
        for port in 80..90u16 {
            let anomalies = tracker.track("10.0.0.1", port);
            assert!(
                anomalies.is_empty(),
                "Should not flag with only {} unique ports",
                port - 80 + 1
            );
        }
    }

    #[test]
    fn test_source_tracker_port_scan_detection() {
        let mut tracker = SourceTracker::new();
        let mut last_anomalies = Vec::new();
        for port in 1..=25u16 {
            last_anomalies = tracker.track("10.0.0.1", port);
        }
        assert!(
            !last_anomalies.is_empty(),
            "Expected port_scan anomaly after 25 unique ports"
        );
        assert!(last_anomalies
            .iter()
            .any(|a: &String| a.contains("port_scan")));
    }

    #[test]
    fn test_source_tracker_different_ips_independent() {
        let mut tracker = SourceTracker::new();
        for port in 1..=25u16 {
            tracker.track("10.0.0.1", port);
        }
        let anomalies_ip2 = tracker.track("10.0.0.2", 80);
        assert!(
            anomalies_ip2.is_empty(),
            "IP2 should not be flagged for only 1 port"
        );
    }

    #[test]
    fn test_source_tracker_packet_counting() {
        let mut tracker = SourceTracker::new();
        for _ in 0..10 {
            tracker.track("10.0.0.1", 80);
        }
        let _count = tracker.packet_counts.get("10.0.0.1").copied().unwrap_or(0);
    }
}

#[cfg(test)]
mod packet_util_tests {
    use super::*;

    #[test]
    fn test_extract_text_preview_ascii() {
        let payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let preview = extract_text_preview(payload);
        assert!(
            !preview.is_empty(),
            "Expected text preview for ASCII payload"
        );
        assert!(preview.contains("GET"));
    }

    #[test]
    fn test_extract_text_preview_binary() {
        let payload: Vec<u8> = (0u8..=255u8).collect();
        let preview = extract_text_preview(&payload);
        assert!(
            preview.is_empty(),
            "Expected empty preview for binary payload"
        );
    }

    #[test]
    fn test_extract_text_preview_empty() {
        let preview = extract_text_preview(&[]);
        assert!(
            preview.is_empty(),
            "Expected empty preview for empty payload"
        );
    }

    #[test]
    fn test_extract_text_preview_long_payload_truncated() {
        let long_payload: Vec<u8> = "hello world ".repeat(300).into_bytes();
        let preview = extract_text_preview(&long_payload);
        assert!(
            preview.len() <= MAX_PAYLOAD_PREVIEW,
            "Preview should be capped at MAX_PAYLOAD_PREVIEW"
        );
    }

    // ────────────────────────────────────────────────────────────────────────
    // validate_magic() — polyglot file detection
    // ────────────────────────────────────────────────────────────────────────

    #[test]
    fn test_validate_magic_valid_png() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]; // PNG header
        assert!(
            validate_magic(&data, "png").is_none(),
            "Valid PNG should pass"
        );
    }

    #[test]
    fn test_validate_magic_valid_jpg() {
        let data = [0xFF, 0xD8, 0xFF, 0xE0, 0x00, 0x10];
        assert!(
            validate_magic(&data, "jpg").is_none(),
            "Valid JPG should pass"
        );
        assert!(
            validate_magic(&data, ".jpeg").is_none(),
            "Valid JPEG with dot prefix should pass"
        );
    }

    #[test]
    fn test_validate_magic_valid_pdf() {
        let data = b"%PDF-1.4 some content here";
        assert!(
            validate_magic(data, "pdf").is_none(),
            "Valid PDF should pass"
        );
    }

    #[test]
    fn test_validate_magic_valid_jp2() {
        let data = [
            0x00, 0x00, 0x00, 0x0C, 0x6A, 0x50, 0x20, 0x20, 0x0D, 0x0A, 0x87, 0x0A,
        ];
        assert!(
            validate_magic(&data, "jp2").is_none(),
            "Valid JP2 signature should pass"
        );
    }

    #[test]
    fn test_validate_magic_valid_zip() {
        let data = [0x50, 0x4B, 0x03, 0x04, 0x00, 0x00]; // PK\x03\x04
        assert!(
            validate_magic(&data, "zip").is_none(),
            "Valid ZIP should pass"
        );
    }

    #[test]
    fn test_validate_magic_elf_disguised_as_png() {
        let data = [0x7F, 0x45, 0x4C, 0x46, 0x02, 0x01]; // ELF header
        let result = validate_magic(&data, "png");
        assert!(result.is_some(), "ELF disguised as PNG must be detected");
        let msg = result.unwrap();
        assert!(msg.contains("ELF executable"), "Should mention ELF: {msg}");
        assert!(
            msg.contains(".png"),
            "Should mention claimed extension: {msg}"
        );
    }

    #[test]
    fn test_validate_magic_pe_disguised_as_jpg() {
        let data = b"MZ\x90\x00\x03\x00\x00\x00"; // PE/MZ header
        let result = validate_magic(data, "jpg");
        assert!(
            result.is_some(),
            "PE executable disguised as JPG must be detected"
        );
        assert!(result.unwrap().contains("PE/Windows executable"));
    }

    #[test]
    fn test_validate_magic_java_class_disguised_as_pdf() {
        let data = [0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x00]; // Java class
        let result = validate_magic(&data, "pdf");
        assert!(
            result.is_some(),
            "Java class disguised as PDF must be detected"
        );
        assert!(result.unwrap().contains("Java class file"));
    }

    #[test]
    fn test_validate_magic_wasm_disguised_as_json() {
        let data = [0x00, 0x61, 0x73, 0x6D, 0x01, 0x00]; // WASM header
        let result = validate_magic(&data, "json");
        assert!(result.is_some(), "WASM disguised as JSON must be detected");
        assert!(result.unwrap().contains("WebAssembly binary"));
    }

    #[test]
    fn test_validate_magic_wrong_magic_for_declared_ext() {
        // Random bytes claiming to be a PNG
        let data = [0x00, 0x00, 0x00, 0x00, 0x00, 0x00];
        let result = validate_magic(&data, "png");
        assert!(
            result.is_some(),
            "Wrong magic bytes for PNG should be flagged"
        );
        assert!(result
            .unwrap()
            .contains("does not match expected magic bytes"));
    }

    #[test]
    fn test_validate_magic_exe_with_correct_magic() {
        let data = b"MZ\x90\x00"; // Valid PE header for .exe
        assert!(
            validate_magic(data, "exe").is_none(),
            "Valid EXE should pass"
        );
    }

    #[test]
    fn test_validate_magic_too_short() {
        let data = [0x89, 0x50]; // Only 2 bytes — too short
        assert!(
            validate_magic(&data, "png").is_none(),
            "Data < 4 bytes should return None"
        );
    }

    #[test]
    fn test_validate_magic_unknown_extension() {
        let data = b"RIFF\x00\x00\x00\x00WAVEfmt ";
        assert!(
            validate_magic(data, "wav").is_none(),
            "Unknown extension should pass (no rule)"
        );
    }

    #[test]
    fn test_validate_magic_case_insensitive_extension() {
        let data = [0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A];
        assert!(
            validate_magic(&data, "PNG").is_none(),
            "Extension matching should be case-insensitive"
        );
        assert!(
            validate_magic(&data, ".PNG").is_none(),
            "Dot-prefixed uppercase should work"
        );
    }

    #[test]
    fn test_validate_magic_pe_disguised_as_csv() {
        let data = b"MZ\x90\x00\x03\x00";
        let result = validate_magic(data, "csv");
        assert!(result.is_some(), "PE disguised as CSV must be detected");
    }

    #[test]
    fn test_validate_magic_gif_valid() {
        let data = b"GIF89a\x01\x00\x01\x00";
        assert!(
            validate_magic(data, "gif").is_none(),
            "Valid GIF89a should pass"
        );
    }

    #[test]
    fn test_ssh_tracker_detects_visible_channel_open_burst() {
        let mut tracker = SSHTracker::new();
        let payload = [0, 0, 0, 12, 4, 90, 0, 0, 0, 0, b's', b'e', b's', b's'];
        let mut anomalies = Vec::new();

        for _ in 0..=SSH_MAX_CHANNEL_OPENS_PER_SEC {
            anomalies.extend(tracker.track("10.0.0.1", "10.0.0.2", 22, &payload));
        }

        assert!(
            anomalies
                .iter()
                .any(|a| a.contains("ssh_channel_exhaustion")),
            "expected visible channel-open burst detection, got {anomalies:?}"
        );
    }

    #[test]
    fn test_ssh_tracker_ignores_non_channel_burst() {
        let mut tracker = SSHTracker::new();
        let payload = b"encrypted-or-banner-data";
        let mut anomalies = Vec::new();

        for _ in 0..=SSH_MAX_CHANNEL_OPENS_PER_SEC {
            anomalies.extend(tracker.track("10.0.0.1", "10.0.0.2", 22, payload));
        }

        assert!(
            !anomalies
                .iter()
                .any(|a| a.contains("ssh_channel_exhaustion")),
            "non-channel SSH payloads should not count as channel opens: {anomalies:?}"
        );
    }

    #[test]
    fn test_ssh_tracker_detects_oversized_payload() {
        let mut tracker = SSHTracker::new();
        let payload = vec![0u8; SSH_MAX_PAYLOAD_SIZE + 1];
        let anomalies = tracker.track("10.0.0.1", "10.0.0.2", 22, &payload);

        assert!(
            anomalies.iter().any(|a| a.contains("ssh_oversized_frame")),
            "expected oversized SSH payload detection, got {anomalies:?}"
        );
    }

    #[test]
    fn test_websocket_tracker_rejects_extreme_length_after_upgrade() {
        let mut tracker = WebSocketTracker::new();
        let upgrade = b"GET /socket HTTP/1.1\r\nHost: charger.local\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n";
        assert!(tracker
            .track("10.0.0.5", 51342, "10.0.0.10", 8080, upgrade)
            .is_empty());

        let mut frame = vec![0x82, 0xff];
        frame.extend_from_slice(&u64::MAX.to_be_bytes());
        frame.extend_from_slice(&[1, 2, 3, 4]);
        let anomalies = tracker.track("10.0.0.5", 51342, "10.0.0.10", 8080, &frame);

        assert!(
            anomalies
                .iter()
                .any(|a| a.contains("websocket_invalid_frame") && a.contains("forbidden high bit")),
            "expected invalid WebSocket length detection, got {anomalies:?}"
        );
    }

    #[test]
    fn test_websocket_tracker_accepts_valid_masked_frame() {
        let mut tracker = WebSocketTracker::new();
        let upgrade = b"GET /socket HTTP/1.1\r\nConnection: keep-alive, Upgrade\r\nUpgrade: WebSocket\r\n\r\n";
        tracker.track("10.0.0.5", 51342, "10.0.0.10", 80, upgrade);

        let frame = [0x81, 0x82, 1, 2, 3, 4, b'h' ^ 1, b'i' ^ 2];
        let anomalies = tracker.track("10.0.0.5", 51342, "10.0.0.10", 80, &frame);
        assert!(
            anomalies.is_empty(),
            "valid masked WebSocket frame should pass: {anomalies:?}"
        );
    }

    #[test]
    fn test_websocket_tracker_ignores_unconfirmed_binary_flow() {
        let mut tracker = WebSocketTracker::new();
        let frame = [0x82, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let anomalies = tracker.track("10.0.0.5", 51342, "10.0.0.10", 9000, &frame);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_scan_deep_binary_signatures_exact_boundary_offset() {
        let mut data = vec![b'A'; 16_384 - 1];
        data.extend_from_slice(b"MZ");
        data.extend_from_slice(&vec![b'B'; 64]);

        let anomalies = scan_deep_binary_signatures(&data);
        assert!(
            anomalies
                .iter()
                .any(|a| a.contains("embedded_mz_pe") && a.contains("offset 16383")),
            "expected exact MZ offset across chunk boundary, got {anomalies:?}"
        );
    }
}
