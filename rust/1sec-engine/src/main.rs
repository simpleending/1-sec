//! 1SEC Engine — High-performance Rust sidecar for the 1SEC cybersecurity platform.
//!
//! This binary connects to the same NATS JetStream bus as the Go engine and provides:
//! - Hot-path regex pattern matching (5-10x faster than Go's RE2)
//! - Optional raw packet capture and protocol parsing
//! - Post-quantum cryptographic operations (when `pqc` feature is enabled)

#[allow(dead_code)]
mod analytics;
mod config;
mod events;
mod matcher;
mod nats_bridge;
mod normalize;
#[allow(dead_code)]
mod packet;
mod patterns;
#[cfg(test)]
mod tests;

use anyhow::Result;
use clap::Parser;
use tracing::info;
#[cfg(feature = "pcap-capture")]
use tracing::warn;

const ENGINE_VERSION: &str = match option_env!("ONESEC_VERSION") {
    Some(version) => version,
    None => env!("CARGO_PKG_VERSION"),
};

#[derive(Parser, Debug)]
#[command(
    name = "1sec-engine",
    version = ENGINE_VERSION,
    about = "1SEC high-performance security engine"
)]
struct Cli {
    /// Path to configuration file
    #[arg(short, long, default_value = "configs/default.yaml")]
    config: String,

    /// NATS server URL (overrides config)
    #[arg(long)]
    nats_url: Option<String>,

    /// Enable packet capture mode
    #[cfg(feature = "pcap-capture")]
    #[arg(long)]
    capture: bool,

    /// Network interface for packet capture
    #[cfg(feature = "pcap-capture")]
    #[arg(long, default_value = "eth0")]
    interface: String,

    /// Log format: "json" or "pretty"
    #[arg(long, default_value = "pretty")]
    log_format: String,

    /// Log level: trace, debug, info, warn, error
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let env_filter = tracing_subscriber::EnvFilter::try_new(&cli.log_level)
        .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));

    if cli.log_format == "json" {
        tracing_subscriber::fmt()
            .json()
            .with_env_filter(env_filter)
            .init();
    } else {
        tracing_subscriber::fmt().with_env_filter(env_filter).init();
    }

    info!(version = ENGINE_VERSION, "starting 1sec-engine");

    // Load config
    let cfg = config::EngineConfig::load(&cli.config)?;
    let nats_url = cli.nats_url.unwrap_or(cfg.nats_url.clone());
    let engine_cfg = &cfg.rust_engine;

    // Compile pattern matcher with config-driven settings
    let matcher = matcher::PatternMatcher::new(
        &patterns::all_patterns(),
        engine_cfg.min_score,
        engine_cfg.aho_corasick_prefilter,
    );
    info!(
        pattern_count = matcher.pattern_count(),
        ac_prefiltered = matcher.ac_prefiltered_count(),
        "pattern matcher compiled"
    );

    // Connect to NATS and start processing with configured buffer/worker limits
    let bridge = nats_bridge::NatsBridge::connect(
        &nats_url,
        matcher,
        engine_cfg.buffer_size,
        engine_cfg.workers,
    )
    .await?;

    // Optionally start packet capture
    #[cfg(feature = "pcap-capture")]
    if cli.capture {
        let capture_bridge = bridge.clone_publisher();
        let iface = cli.interface.clone();
        let capture_cfg = engine_cfg.capture.clone();
        tokio::spawn(async move {
            if let Err(e) = packet::capture_loop(&iface, capture_bridge, &capture_cfg).await {
                warn!(error = %e, "packet capture stopped");
            }
        });
        info!(interface = %cli.interface, "packet capture started");
    }

    info!("1sec-engine running — press Ctrl+C to stop");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;
    bridge.shutdown().await;
    info!("1sec-engine stopped");

    Ok(())
}
