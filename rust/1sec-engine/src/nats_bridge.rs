//! NATS JetStream bridge — subscribes to security events from the Go engine,
//! runs them through the Rust pattern matcher, and publishes results back.

use crate::events::SecurityEvent;
use crate::events::{MatchResult, Severity};
use crate::matcher::PatternMatcher;
use crate::normalize;
use anyhow::{Context, Result};
use async_nats::jetstream::{self, consumer::PullConsumer};
use std::sync::Arc;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

const DIRECT_FIELD_SCAN_LIMIT: usize = 96 * 1024;
const STREAM_SCAN_CHUNK_SIZE: usize = 64 * 1024;
const STREAM_SCAN_OVERLAP: usize = 4096;

/// Bridge between NATS JetStream and the Rust pattern matcher.
pub struct NatsBridge {
    client: async_nats::Client,
    jetstream: jetstream::Context,
    matcher: Arc<PatternMatcher>,
    shutdown: Arc<Notify>,
    /// Maximum events to buffer before backpressure.
    buffer_size: usize,
}

/// Handle for publishing events from the packet capture thread.
#[derive(Clone)]
pub struct EventPublisher {
    jetstream: jetstream::Context,
}

impl EventPublisher {
    /// Publish a raw packet event to the NATS bus.
    pub async fn publish_packet_event(&self, event: &crate::events::PacketEvent) -> Result<()> {
        let subject = format!("sec.events.packet_capture.{}", event.protocol);
        let payload = serde_json::to_vec(&packet_wire_event(event))?;
        self.jetstream
            .publish(subject, payload.into())
            .await?
            .await?;
        Ok(())
    }
}

fn packet_wire_event(event: &crate::events::PacketEvent) -> serde_json::Value {
    serde_json::json!({
        "id": event.id, "timestamp": event.timestamp, "source": "packet_capture",
        "module": "packet_capture", "type": "network_connection",
        "severity": if event.anomalies.is_empty() { "INFO" } else { "MEDIUM" },
        "source_ip": event.src_ip, "dest_ip": event.dst_ip,
        "summary": "Observed network packet",
        "details": { "protocol": event.protocol, "src_port": event.src_port,
            "dest_port": event.dst_port, "length": event.length, "flags": event.flags,
            "body": event.payload_preview, "packet_anomalies": event.anomalies }
    })
}

fn effective_workers(workers: usize) -> usize {
    if workers == 0 {
        std::thread::available_parallelism()
            .map(|n| n.get())
            .unwrap_or(1)
    } else {
        workers
    }
}

impl NatsBridge {
    /// Connect to NATS and start consuming security events.
    pub async fn connect(
        url: &str,
        matcher: PatternMatcher,
        buffer_size: usize,
        workers: usize,
    ) -> Result<Self> {
        info!(
            buffer_size = buffer_size,
            workers = workers,
            "connecting to NATS"
        );

        let options = match std::env::var("ONESEC_NATS_TOKEN") {
            Ok(token) if !token.is_empty() => async_nats::ConnectOptions::with_token(token),
            _ => async_nats::ConnectOptions::new(),
        };
        let client = options.connect(url).await.context("connecting to NATS")?;

        let jetstream = jetstream::new(client.clone());

        // Ensure the match results stream exists for publishing our results
        let results_stream_config = jetstream::stream::Config {
            name: "SECURITY_MATCH_RESULTS".to_string(),
            subjects: vec!["sec.matches.>".to_string()],
            retention: jetstream::stream::RetentionPolicy::Limits,
            max_age: std::time::Duration::from_secs(7 * 24 * 3600), // 7 days
            max_bytes: 512 * 1024 * 1024,                           // 512MB
            storage: jetstream::stream::StorageType::File,
            discard: jetstream::stream::DiscardPolicy::Old,
            ..Default::default()
        };

        match jetstream.create_stream(results_stream_config.clone()).await {
            Ok(_) => info!("created SECURITY_MATCH_RESULTS stream"),
            Err(_) => {
                // Stream may already exist — try to get it
                match jetstream.get_stream("SECURITY_MATCH_RESULTS").await {
                    Ok(_) => debug!("SECURITY_MATCH_RESULTS stream already exists"),
                    Err(e) => warn!(error = %e, "could not create or get match results stream"),
                }
            }
        }

        let bridge = Self {
            client,
            jetstream,
            matcher: Arc::new(matcher),
            shutdown: Arc::new(Notify::new()),
            buffer_size,
        };

        // Start the consumer loop
        bridge.start_consumer(workers).await?;

        Ok(bridge)
    }

    /// Get a publisher handle for the packet capture thread.
    pub fn clone_publisher(&self) -> EventPublisher {
        EventPublisher {
            jetstream: self.jetstream.clone(),
        }
    }

    /// Start consuming events from the SECURITY_EVENTS stream.
    async fn start_consumer(&self, workers: usize) -> Result<()> {
        // Get or create a durable consumer on the events stream
        let stream = self
            .jetstream
            .get_stream("SECURITY_EVENTS")
            .await
            .with_context(|| "getting SECURITY_EVENTS stream — is the Go engine running?")?;

        let consumer: PullConsumer = stream
            .get_or_create_consumer(
                "rust-engine",
                jetstream::consumer::pull::Config {
                    durable_name: Some("rust-engine".to_string()),
                    filter_subject: "sec.events.>".to_string(),
                    ack_policy: jetstream::consumer::AckPolicy::Explicit,
                    ..Default::default()
                },
            )
            .await
            .with_context(|| "creating consumer on SECURITY_EVENTS")?;

        let matcher = self.matcher.clone();
        let js = self.jetstream.clone();
        let shutdown = self.shutdown.clone();
        let batch_size = self.buffer_size.clamp(1, 100);
        let workers = effective_workers(workers);
        let semaphore = Arc::new(tokio::sync::Semaphore::new(workers));

        tokio::spawn(async move {
            info!(
                workers = workers,
                batch_size = batch_size,
                "event consumer started"
            );
            loop {
                tokio::select! {
                    _ = shutdown.notified() => {
                        info!("consumer shutting down");
                        break;
                    }
                    result = consumer.fetch().max_messages(batch_size).messages() => {
                        match result {
                            Ok(mut messages) => {
                                use futures::StreamExt;
                                while let Some(Ok(msg)) = messages.next().await {
                                    let permit = semaphore.clone().acquire_owned().await;
                                    let matcher = matcher.clone();
                                    let js = js.clone();
                                    tokio::spawn(async move {
                                        let _permit = permit;
                                        process_message(&msg, &matcher, &js).await;
                                        if let Err(e) = msg.ack().await {
                                            warn!(error = %e, "failed to ack message");
                                        }
                                    });
                                }
                            }
                            Err(e) => {
                                warn!(error = %e, "fetch error, retrying in 1s");
                                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                            }
                        }
                    }
                }
            }
        });

        Ok(())
    }

    /// Signal shutdown and wait for cleanup.
    pub async fn shutdown(&self) {
        self.shutdown.notify_waiters();
        // Give consumer a moment to finish
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        // Flush and close
        if let Err(e) = self.client.flush().await {
            warn!(error = %e, "error flushing NATS on shutdown");
        }
    }
}

/// Process a single NATS message: deserialize the event, run pattern matching, publish results.
async fn process_message(
    msg: &async_nats::Message,
    matcher: &PatternMatcher,
    js: &jetstream::Context,
) {
    // Deserialize the security event
    let event: SecurityEvent = match serde_json::from_slice(&msg.payload) {
        Ok(e) => e,
        Err(e) => {
            debug!(error = %e, "failed to deserialize event, skipping");
            return;
        }
    };

    // Extract text fields from the event data for scanning
    let fields = extract_scannable_fields(&event);
    if fields.is_empty() {
        return;
    }

    // Dual-pass scan: raw fields first, then normalized fields. Large fields are
    // streamed in overlapping chunks so deep payloads are inspected without
    // creating unbounded intermediate buffers.
    let mut result = scan_field_collection(matcher, &event.id, &fields, false);
    let normalized_result = scan_field_collection(matcher, &event.id, &fields, true);
    merge_match_results(&mut result, normalized_result);
    enrich_match_context(&mut result, &event);

    // Only publish if we found matches
    if result.matches.is_empty() {
        debug!(event_id = %event.id, time_us = result.processing_time_us, "no matches");
        return;
    }

    info!(
        event_id = %event.id,
        match_count = result.matches.len(),
        score = result.aggregate_score,
        severity = %result.highest_severity.as_str(),
        time_us = result.processing_time_us,
        "patterns matched"
    );

    // Publish match result
    let subject = format!(
        "sec.matches.{}.{}",
        event.module,
        result.highest_severity.as_str()
    );

    match serde_json::to_vec(&result) {
        Ok(payload) => {
            if let Err(e) = js.publish(subject, payload.into()).await {
                error!(error = %e, event_id = %event.id, "failed to publish match result");
            }
        }
        Err(e) => {
            error!(error = %e, "failed to serialize match result");
        }
    }
}

fn enrich_match_context(result: &mut MatchResult, event: &SecurityEvent) {
    let source = if event.source_ip.is_empty() {
        &event.source.ip
    } else {
        &event.source_ip
    };
    if let Ok(ip) = source.parse::<std::net::IpAddr>() {
        result.context.insert("source_ip".into(), ip.to_string());
    }
    for key in ["user_id", "account_id", "session_id"] {
        if let Some(value) = event
            .data
            .get(key)
            .and_then(|v| v.as_str())
            .filter(|v| !v.is_empty() && v.len() <= 256)
        {
            result.context.insert(key.into(), value.into());
        }
    }
}

/// Extract all string fields from a SecurityEvent's data payload for scanning.
fn extract_scannable_fields(event: &SecurityEvent) -> Vec<(String, String)> {
    let mut fields = Vec::new();

    // Always scan the description
    if !event.description.is_empty() {
        fields.push(("description".to_string(), event.description.clone()));
    }

    // Recursively extract string values from the JSON data
    extract_json_strings("data", &event.data, &mut fields, 0);

    fields
}

/// Recursively extract string values from a JSON value, with depth limiting.
fn extract_json_strings(
    prefix: &str,
    value: &serde_json::Value,
    out: &mut Vec<(String, String)>,
    depth: usize,
) {
    if depth > 5 {
        return; // Prevent stack overflow on deeply nested payloads
    }

    match value {
        serde_json::Value::String(s) if s.len() > 1 => {
            out.push((prefix.to_string(), s.clone()));
        }
        serde_json::Value::String(_) => {}
        serde_json::Value::Object(map) => {
            for (key, val) in map {
                let field_name = format!("{}.{}", prefix, key);
                extract_json_strings(&field_name, val, out, depth + 1);
            }
        }
        serde_json::Value::Array(arr) => {
            for (i, val) in arr.iter().enumerate() {
                let field_name = format!("{}[{}]", prefix, i);
                extract_json_strings(&field_name, val, out, depth + 1);
            }
        }
        _ => {} // Skip numbers, bools, nulls
    }
}

fn scan_field_collection(
    matcher: &PatternMatcher,
    event_id: &str,
    fields: &[(String, String)],
    normalized: bool,
) -> MatchResult {
    let mut result = matcher.scan(event_id, &[]);
    for (field_name, value) in fields {
        if value.len() <= DIRECT_FIELD_SCAN_LIMIT {
            let direct_result = if normalized {
                let scan_value = normalize::normalize(value);
                if scan_value.is_empty() {
                    continue;
                }
                let scan_field = format!("{}.normalized", field_name);
                matcher.scan(event_id, &[(scan_field.as_str(), scan_value.as_str())])
            } else {
                matcher.scan(event_id, &[(field_name.as_str(), value.as_str())])
            };
            merge_match_results(&mut result, direct_result);
            continue;
        }
        merge_match_results(
            &mut result,
            scan_large_field(matcher, event_id, field_name, value, normalized),
        );
    }
    result
}

fn scan_large_field(
    matcher: &PatternMatcher,
    event_id: &str,
    field_name: &str,
    value: &str,
    normalized: bool,
) -> MatchResult {
    let mut result = matcher.scan(event_id, &[]);
    let mut start = 0;
    while start < value.len() {
        let end = floor_char_boundary(value, (start + STREAM_SCAN_CHUNK_SIZE).min(value.len()));
        if end <= start {
            break;
        }
        let chunk = &value[start..end];
        let mut chunk_result = if normalized {
            let scan_value = normalize::normalize(chunk);
            if scan_value.is_empty() {
                start = next_stream_start(value, start, end);
                continue;
            }
            let scan_field = format!("{}.normalized", field_name);
            matcher.scan(event_id, &[(scan_field.as_str(), scan_value.as_str())])
        } else {
            matcher.scan(event_id, &[(field_name, chunk)])
        };
        for m in &mut chunk_result.matches {
            m.offset += start;
        }
        merge_match_results(&mut result, chunk_result);

        if end == value.len() {
            break;
        }
        let next = next_stream_start(value, start, end);
        if next <= start {
            break;
        }
        start = next;
    }
    result
}

fn next_stream_start(value: &str, start: usize, end: usize) -> usize {
    let desired = end.saturating_sub(STREAM_SCAN_OVERLAP);
    floor_char_boundary(value, desired).max(start + 1)
}

fn floor_char_boundary(value: &str, mut idx: usize) -> usize {
    if idx >= value.len() {
        return value.len();
    }
    while idx > 0 && !value.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

fn merge_match_results(base: &mut MatchResult, incoming: MatchResult) {
    let mut existing: std::collections::HashSet<(String, String, usize)> = base
        .matches
        .iter()
        .map(|m| (m.pattern_name.clone(), m.field.clone(), m.offset))
        .collect();
    for m in incoming.matches {
        let key = (m.pattern_name.clone(), m.field.clone(), m.offset);
        if existing.insert(key) {
            if m.severity > base.highest_severity {
                base.highest_severity = m.severity;
            }
            base.matches.push(m);
        }
    }
    if !base.matches.is_empty() {
        let sum: f64 = base.matches.iter().map(|m| m.severity.score()).sum();
        let max_possible = base.matches.len() as f64;
        base.aggregate_score = (sum / max_possible).min(1.0);
    } else {
        base.aggregate_score = 0.0;
        base.highest_severity = Severity::Info;
    }
    base.processing_time_us += incoming.processing_time_us;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::patterns::all_patterns;

    #[test]
    fn zero_workers_and_packet_wire_contract() {
        assert!(effective_workers(0) > 0);
        assert_eq!(effective_workers(2), 2);
        let packet = crate::events::PacketEvent {
            id: "captured-packet".into(),
            timestamp: "2026-10-26T00:00:00Z".parse().unwrap(),
            protocol: "tcp".into(),
            src_ip: "192.0.2.10".into(),
            src_port: 12345,
            dst_ip: "198.51.100.20".into(),
            dst_port: 443,
            length: 64,
            flags: vec!["SYN".into()],
            payload_preview: String::new(),
            anomalies: vec!["null_scan: no TCP flags set".into()],
        };
        let expected: serde_json::Value =
            serde_json::from_str(include_str!("../testdata/packet_anomaly.json")).unwrap();
        let actual = packet_wire_event(&packet);
        assert_eq!(actual, expected);
        let canonical: SecurityEvent = serde_json::from_value(actual).unwrap();
        assert_eq!(canonical.event_type, "network_connection");
        assert_eq!(canonical.data["dest_port"], 443);
    }

    #[test]
    fn source_context_reaches_match_result_without_process_authority() {
        let mut event: SecurityEvent =
            serde_json::from_str(include_str!("../testdata/go_http_request.json")).unwrap();
        event.data["user_id"] = serde_json::json!("operator");
        event.data["process_id"] = serde_json::json!("123");
        let mut result = matcher().scan(&event.id, &[]);
        enrich_match_context(&mut result, &event);
        assert_eq!(
            result.context.get("source_ip").map(String::as_str),
            Some("192.0.2.1")
        );
        assert_eq!(
            result.context.get("user_id").map(String::as_str),
            Some("operator")
        );
        assert!(!result.context.contains_key("process_id"));
    }

    fn matcher() -> PatternMatcher {
        PatternMatcher::new(&all_patterns(), 0.0, true)
    }

    #[test]
    fn go_events_reach_the_scanner_and_legacy_events_still_work() {
        let fixture = include_str!("../testdata/go_http_request.json");
        let m = matcher();
        for (wire, severity) in [
            ("INFO", Severity::Info),
            ("LOW", Severity::Low),
            ("MEDIUM", Severity::Medium),
            ("HIGH", Severity::High),
            ("CRITICAL", Severity::Critical),
        ] {
            let json = fixture.replace("\"HIGH\"", &format!("\"{wire}\""));
            let event: SecurityEvent = serde_json::from_str(&json).unwrap();
            assert_eq!(event.severity, severity);
            assert_eq!(event.source.service, "gateway");
            assert_eq!(event.description, "XML request");
            let fields = extract_scannable_fields(&event);
            for normalized in [false, true] {
                let result = scan_field_collection(&m, &event.id, &fields, normalized);
                assert!(result
                    .matches
                    .iter()
                    .any(|p| p.pattern_name == "deser_xml_entity"));
            }
            // Serialization retains the pre-existing Rust wire format.
            let legacy = serde_json::to_string(&event).unwrap();
            let decoded: SecurityEvent = serde_json::from_str(&legacy).unwrap();
            assert_eq!(decoded.data, event.data);
            assert_eq!(decoded.source.service, "gateway");
            assert_eq!(decoded.severity, severity);
        }
        assert!(
            serde_json::from_str::<SecurityEvent>(&fixture.replace("\"HIGH\"", "\"UNKNOWN\""))
                .is_err()
        );

        let mut summary_only: serde_json::Value = serde_json::from_str(fixture).unwrap();
        summary_only.as_object_mut().unwrap().remove("details");
        summary_only["source"] = serde_json::json!("");
        summary_only["summary"] = serde_json::json!("UNION SELECT password FROM users");
        let event: SecurityEvent = serde_json::from_value(summary_only).unwrap();
        let result = scan_field_collection(&m, &event.id, &extract_scannable_fields(&event), false);
        assert!(result.matches.iter().any(|p| p.category == "sqli"));
    }

    #[test]
    fn large_fields_are_streamed_instead_of_skipped() {
        let m = matcher();
        let mut payload = "A".repeat(DIRECT_FIELD_SCAN_LIMIT + STREAM_SCAN_CHUNK_SIZE + 512);
        payload.push_str(" UNION ALL SELECT password FROM users");
        let fields = vec![("data.body".to_string(), payload)];

        let result = scan_field_collection(&m, "deep-buffer-test", &fields, false);

        assert!(
            result.matches.iter().any(|m| m.category == "sqli"),
            "deep SQLi payload should be detected in a large field"
        );
    }

    #[test]
    fn normalized_large_fields_are_streamed() {
        let m = matcher();
        let mut payload = "A".repeat(DIRECT_FIELD_SCAN_LIMIT + 2048);
        payload.push_str("%3Cscript%3Ealert(1)%3C/script%3E");
        let fields = vec![("data.body".to_string(), payload)];

        let result = scan_field_collection(&m, "deep-normalized-test", &fields, true);

        assert!(
            result.matches.iter().any(|m| m.category == "xss"),
            "normalized deep XSS payload should be detected in a large field"
        );
    }
}
