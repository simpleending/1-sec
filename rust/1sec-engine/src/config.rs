//! Configuration loader — reads the same YAML config as the Go engine.

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

#[derive(Debug, Deserialize, Clone)]
pub struct EngineConfig {
    /// NATS server URL
    #[serde(default = "default_nats_url")]
    pub nats_url: String,

    /// Rust engine specific settings
    #[serde(default)]
    pub rust_engine: RustEngineConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct RustEngineConfig {
    /// Maximum events to buffer before backpressure
    #[serde(default = "default_buffer_size")]
    pub buffer_size: usize,

    /// Number of worker threads for pattern matching
    #[serde(default = "default_workers")]
    pub workers: usize,

    /// Minimum score threshold to publish match results (0.0 - 1.0)
    #[serde(default = "default_min_score")]
    pub min_score: f64,

    /// Compatibility name: enable complete RegexSet candidate selection.
    #[serde(default = "default_true")]
    pub aho_corasick_prefilter: bool,

    /// Packet capture settings
    #[serde(default)]
    pub capture: CaptureConfig,
}

#[derive(Debug, Deserialize, Clone)]
pub struct CaptureConfig {
    /// Snap length for packet capture
    #[serde(default = "default_snaplen")]
    pub snaplen: i32,

    /// BPF filter expression
    #[serde(default)]
    pub bpf_filter: Option<String>,

    /// Promiscuous mode
    #[serde(default = "default_true")]
    pub promiscuous: bool,
}

impl Default for RustEngineConfig {
    fn default() -> Self {
        Self {
            buffer_size: default_buffer_size(),
            workers: default_workers(),
            min_score: default_min_score(),
            aho_corasick_prefilter: true,
            capture: CaptureConfig::default(),
        }
    }
}

impl Default for CaptureConfig {
    fn default() -> Self {
        Self {
            snaplen: default_snaplen(),
            bpf_filter: None,
            promiscuous: true,
        }
    }
}

fn default_nats_url() -> String {
    "nats://127.0.0.1:4222".to_string()
}
fn default_buffer_size() -> usize {
    10_000
}
fn default_workers() -> usize {
    num_cpus()
}
fn default_min_score() -> f64 {
    0.1
}
fn default_snaplen() -> i32 {
    65535
}
fn default_true() -> bool {
    true
}

fn num_cpus() -> usize {
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

impl EngineConfig {
    /// Load config from a YAML file. Falls back to defaults if file doesn't exist.
    pub fn load(path: &str) -> Result<Self> {
        let p = Path::new(path);
        if !p.exists() {
            tracing::warn!(path = %path, "config file not found, using defaults");
            return Ok(Self {
                nats_url: default_nats_url(),
                rust_engine: RustEngineConfig::default(),
            });
        }

        let contents =
            std::fs::read_to_string(p).with_context(|| format!("reading config file: {}", path))?;

        // The Go config YAML has a `bus:` section with `url:` — extract NATS URL from there
        // and also look for `rust_engine:` section for Rust-specific settings
        let raw: serde_yaml::Value =
            serde_yaml::from_str(&contents).with_context(|| "parsing config YAML")?;

        let nats_url = raw
            .get("bus")
            .and_then(|b| b.get("url"))
            .and_then(|u| u.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(default_nats_url);

        let rust_engine = if let Some(re) = raw.get("rust_engine") {
            serde_yaml::from_value(re.clone()).unwrap_or_default()
        } else {
            RustEngineConfig::default()
        };

        Ok(Self {
            nats_url,
            rust_engine,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn load_fixture(yaml: &str) -> Result<EngineConfig> {
        let path = std::env::temp_dir().join(format!("1sec-config-{}.yaml", uuid::Uuid::new_v4()));
        std::fs::write(&path, yaml).unwrap();
        let result = EngineConfig::load(path.to_str().unwrap());
        std::fs::remove_file(path).unwrap();
        result
    }

    #[test]
    fn yaml_config_preserves_aliases_and_capture_settings() {
        let cfg = load_fixture(
            r#"
bus:
  url: nats://192.0.2.1:4222
settings: &engine
  buffer_size: 2048
  workers: 2
  min_score: 0.75
  aho_corasick_prefilter: false
  capture:
    snaplen: 4096
    bpf_filter: "tcp port 443"
    promiscuous: false
rust_engine: *engine
management_access:
  allowed_sources: ["10.20.0.0/24"]
  allowed_operators: ["engineer@example.com"]
"#,
        )
        .unwrap();
        assert_eq!(cfg.nats_url, "nats://192.0.2.1:4222");
        assert_eq!(cfg.rust_engine.buffer_size, 2048);
        assert_eq!(cfg.rust_engine.workers, 2);
        assert_eq!(cfg.rust_engine.min_score, 0.75);
        assert!(!cfg.rust_engine.aho_corasick_prefilter);
        assert_eq!(cfg.rust_engine.capture.snaplen, 4096);
        assert_eq!(
            cfg.rust_engine.capture.bpf_filter.as_deref(),
            Some("tcp port 443")
        );
        assert!(!cfg.rust_engine.capture.promiscuous);
    }

    #[test]
    fn malformed_yaml_still_returns_an_error() {
        assert!(load_fixture("bus: [unterminated").is_err());
    }
}
