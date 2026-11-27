//! Event types — mirrors the Go `core.SecurityEvent` and `core.Alert` structs
//! so the Rust engine can deserialize events from NATS and publish results back.

use serde::{Deserialize, Serialize};
use time::{OffsetDateTime, UtcOffset};

/// Go-compatible RFC3339 UTC timestamp, including when embedded in json!
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(transparent)]
pub struct EventTimestamp(#[serde(with = "utc_rfc3339")] OffsetDateTime);

impl EventTimestamp {
    pub fn now() -> Self {
        Self(OffsetDateTime::now_utc())
    }
}

mod utc_rfc3339 {
    use serde::{Deserializer, Serializer};
    use time::{serde::rfc3339, OffsetDateTime};

    pub fn serialize<S: Serializer>(
        value: &OffsetDateTime,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        rfc3339::serialize(&value.to_offset(super::UtcOffset::UTC), serializer)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> Result<OffsetDateTime, D::Error> {
        rfc3339::deserialize(deserializer)
    }
}

#[cfg(test)]
mod timestamp_tests {
    use super::*;

    #[test]
    fn rfc3339_timestamp_retains_go_wire_shape_and_precision() {
        let sample = "\"2026-11-27T12:13:14.123456789Z\"";
        let wire: EventTimestamp = serde_json::from_str(sample).unwrap();
        assert_eq!(serde_json::to_string(&wire).unwrap(), sample);
        assert_eq!(
            serde_json::json!({"timestamp": wire})["timestamp"],
            "2026-11-27T12:13:14.123456789Z"
        );

        let offset: EventTimestamp =
            serde_json::from_str("\"2026-11-27T19:13:14.123456789+07:00\"").unwrap();
        assert_eq!(serde_json::to_string(&offset).unwrap(), sample);
        assert!(serde_json::from_str::<EventTimestamp>("1234").is_err());
    }
}

/// Mirrors `core.SecurityEvent` from the Go codebase.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    #[serde(default)]
    pub source_ip: String,
    pub id: String,
    pub timestamp: EventTimestamp,
    pub module: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub severity: Severity,
    #[serde(deserialize_with = "deserialize_event_source")]
    pub source: EventSource,
    #[serde(default, alias = "details")]
    pub data: serde_json::Value,
    #[serde(default)]
    pub tags: Vec<String>,
    #[serde(default, alias = "summary")]
    pub description: String,
}

// Go publishes a collector name; older sidecar events use a source object.
fn deserialize_event_source<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<EventSource, D::Error> {
    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Source {
        Name(String),
        Structured(EventSource),
    }
    Ok(match Source::deserialize(deserializer)? {
        Source::Name(service) => EventSource {
            ip: String::new(),
            port: 0,
            hostname: String::new(),
            service,
        },
        Source::Structured(source) => source,
    })
}

/// Event source information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSource {
    #[serde(default)]
    pub ip: String,
    #[serde(default)]
    pub port: u16,
    #[serde(default)]
    pub hostname: String,
    #[serde(default)]
    pub service: String,
}

/// Severity levels — matches Go's `core.Severity` iota values.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    #[serde(alias = "INFO")]
    Info,
    #[serde(alias = "LOW")]
    Low,
    #[serde(alias = "MEDIUM")]
    Medium,
    #[serde(alias = "HIGH")]
    High,
    #[serde(alias = "CRITICAL")]
    Critical,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }

    pub fn score(&self) -> f64 {
        match self {
            Severity::Info => 0.1,
            Severity::Low => 0.3,
            Severity::Medium => 0.5,
            Severity::High => 0.7,
            Severity::Critical => 0.9,
        }
    }
}

/// Result of pattern matching against an event — published back to NATS.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatchResult {
    #[serde(default)]
    pub context: std::collections::HashMap<String, String>,
    pub event_id: String,
    pub timestamp: EventTimestamp,
    pub matches: Vec<PatternMatch>,
    pub aggregate_score: f64,
    pub highest_severity: Severity,
    pub processing_time_us: u64,
}

/// A single pattern match within an event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PatternMatch {
    pub pattern_name: String,
    pub category: String,
    pub severity: Severity,
    pub matched_text: String,
    pub field: String,
    pub offset: usize,
}

/// Packet event — generated by the Rust packet capture engine.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketEvent {
    pub id: String,
    pub timestamp: EventTimestamp,
    pub protocol: String,
    pub src_ip: String,
    pub src_port: u16,
    pub dst_ip: String,
    pub dst_port: u16,
    pub length: usize,
    pub flags: Vec<String>,
    #[serde(default)]
    pub payload_preview: String,
    #[serde(default)]
    pub anomalies: Vec<String>,
}
