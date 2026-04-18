//! scrcpy-bridge daemon entry point.

use std::net::SocketAddr;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use anyhow::Result;
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use scrcpy_bridge::bridge::Bridge;
use scrcpy_bridge::config::Cli;
use scrcpy_bridge::observability::{self, HealthFlags};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse_args();
    init_tracing(&cli.log_format);

    tracing::info!(
        version = env!("CARGO_PKG_VERSION"),
        scrcpy = scrcpy_bridge::SCRCPY_VERSION,
        device_id = %cli.device_id,
        adb_serial = %cli.adb_serial,
        "scrcpy-bridge starting"
    );

    let health = HealthFlags {
        mqtt_connected: Arc::new(AtomicBool::new(false)),
        scrcpy_running: Arc::new(AtomicBool::new(false)),
    };

    // Register every lazy Prometheus metric so scrapes return a complete
    // set from process start (including counters that may stay at 0 for a
    // while, e.g. `pli_count_total`).
    observability::init_metrics();

    if cli.metrics_port != 0 {
        let addr: SocketAddr = format!("0.0.0.0:{}", cli.metrics_port).parse()?;
        let health_for_metrics = health.clone();
        tokio::spawn(async move {
            if let Err(e) = observability::serve(addr, health_for_metrics).await {
                tracing::warn!(error = %e, "metrics server exited");
            }
        });
    }

    // Run the bridge. It owns the MQTT signaling loop, so returning from
    // `run()` means the broker closed the connection for good.
    let bridge = Bridge::new(cli, health);

    tokio::select! {
        res = bridge.run() => res,
        _ = tokio::signal::ctrl_c() => {
            tracing::info!("caught SIGINT, shutting down");
            Ok(())
        }
    }
}

fn init_tracing(format: &str) {
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("info,rumqttc=warn,str0m=warn"));
    let registry = tracing_subscriber::registry().with(filter);
    match format {
        "json" => registry.with(fmt::layer().json()).init(),
        _ => registry.with(fmt::layer().compact()).init(),
    }
}
