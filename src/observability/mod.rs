//! Prometheus metrics + HTTP `/healthz` + `/metrics`.
//!
//! A minimal hyper 1.x server bound to `127.0.0.1:{metrics_port}`. It is
//! intentionally tiny — anything more elaborate would drag in a full web
//! framework for a single scrape endpoint.

use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::{TokioExecutor, TokioIo};
use hyper_util::server::conn::auto::Builder as HttpBuilder;
use once_cell::sync::Lazy;
use prometheus::{Encoder, IntCounterVec, IntGauge, Registry, TextEncoder};
use tokio::net::TcpListener;
use tracing::{info, warn};

pub static REGISTRY: Lazy<Registry> = Lazy::new(Registry::new);

pub static VIDEO_FRAMES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        prometheus::Opts::new("scrcpy_bridge_video_frames_total", "H.264 frames forwarded to WebRTC"),
        &["kind"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static VIDEO_FRAMES_DROPPED: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        prometheus::Opts::new(
            "scrcpy_bridge_video_frames_dropped_total",
            "H.264 frames dropped by the bridge before reaching the WebRTC peer",
        ),
        &["reason"], // queue_full
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static CONTROL_MESSAGES_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        prometheus::Opts::new(
            "scrcpy_bridge_control_messages_total",
            "Control messages received from the browser",
        ),
        &["type"],
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static VIEWER_CONNECTED: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::new(
        "scrcpy_bridge_viewer_connected",
        "1 when a browser viewer is WebRTC-connected",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static SCRCPY_RUNNING: Lazy<IntGauge> = Lazy::new(|| {
    let g = IntGauge::new(
        "scrcpy_bridge_scrcpy_running",
        "1 when the scrcpy server is up and streaming",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static AUDIO_PACKETS_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        prometheus::Opts::new(
            "scrcpy_bridge_audio_packets_total",
            "OPUS audio packets forwarded to the browser DataChannel",
        ),
        &["kind"], // config | data
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static AUDIO_PACKETS_DROPPED: Lazy<prometheus::IntCounter> = Lazy::new(|| {
    let c = prometheus::IntCounter::new(
        "scrcpy_bridge_audio_packets_dropped_total",
        "OPUS audio packets dropped by the bridge before reaching the WebRTC peer (drop-newest backpressure on the RTP path)",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static VIEWER_RTT_MS: Lazy<prometheus::Gauge> = Lazy::new(|| {
    let g = prometheus::Gauge::new(
        "scrcpy_bridge_viewer_rtt_ms",
        "Most recent round-trip time reported by the browser WebRTC stats (milliseconds)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static VIEWER_BITRATE_BPS: Lazy<prometheus::Gauge> = Lazy::new(|| {
    let g = prometheus::Gauge::new(
        "scrcpy_bridge_viewer_bitrate_bps",
        "Most recent inbound video bitrate reported by the browser WebRTC stats (bits per second)",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static VIEWER_FPS: Lazy<prometheus::Gauge> = Lazy::new(|| {
    let g = prometheus::Gauge::new(
        "scrcpy_bridge_viewer_fps",
        "Most recent frames-per-second reported by the browser WebRTC stats",
    )
    .unwrap();
    REGISTRY.register(Box::new(g.clone())).unwrap();
    g
});

pub static VIEWER_PACKETS_LOST: Lazy<prometheus::IntCounter> = Lazy::new(|| {
    let c = prometheus::IntCounter::new(
        "scrcpy_bridge_viewer_packets_lost_total",
        "Cumulative video packets lost as reported by the browser WebRTC stats",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static MQTT_RECONNECTS_TOTAL: Lazy<prometheus::IntCounter> = Lazy::new(|| {
    let c = prometheus::IntCounter::new(
        "scrcpy_bridge_mqtt_reconnects_total",
        "MQTT client re-connection attempts (including JWT refresh cycles)",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

pub static JWT_REFRESH_TOTAL: Lazy<IntCounterVec> = Lazy::new(|| {
    let c = IntCounterVec::new(
        prometheus::Opts::new(
            "scrcpy_bridge_jwt_refresh_total",
            "MQTT JWT refresh attempts",
        ),
        &["result"], // success | failure
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Number of times the scrcpy video pump was (re)started. Incremented on
/// every successful `on_offer` session start as well as whenever the pump
/// exits abnormally and the bridge signals `stream_restarted` to the
/// browser. Useful for spotting devices that churn the scrcpy server
/// (OOM on low-memory ReDroid pods, Android resume/suspend cycles, etc.).
pub static SCRCPY_RECONNECTS_TOTAL: Lazy<prometheus::IntCounter> = Lazy::new(|| {
    let c = prometheus::IntCounter::new(
        "scrcpy_bridge_scrcpy_reconnects_total",
        "Number of scrcpy video pump restarts (either offer-driven or recovery-driven)",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Cumulative count of RTCP PLI (Picture Loss Indication) / FIR messages
/// received from the browser. Incremented in the bridge event pump on
/// `PeerEvent::KeyframeRequested`.
pub static PLI_COUNT_TOTAL: Lazy<prometheus::IntCounter> = Lazy::new(|| {
    let c = prometheus::IntCounter::new(
        "scrcpy_bridge_pli_count_total",
        "RTCP PLI (Picture Loss Indication) messages received from the browser",
    )
    .unwrap();
    REGISTRY.register(Box::new(c.clone())).unwrap();
    c
});

/// Force-register every `Lazy` metric so they appear on `/metrics` from the
/// first scrape even if no event has fired yet. Prometheus alerts are easier
/// to author against counters that always exist (even at value 0).
pub fn init_metrics() {
    Lazy::force(&VIDEO_FRAMES_TOTAL);
    Lazy::force(&VIDEO_FRAMES_DROPPED);
    Lazy::force(&CONTROL_MESSAGES_TOTAL);
    Lazy::force(&VIEWER_CONNECTED);
    Lazy::force(&SCRCPY_RUNNING);
    Lazy::force(&AUDIO_PACKETS_TOTAL);
    Lazy::force(&AUDIO_PACKETS_DROPPED);
    Lazy::force(&VIEWER_RTT_MS);
    Lazy::force(&VIEWER_BITRATE_BPS);
    Lazy::force(&VIEWER_FPS);
    Lazy::force(&VIEWER_PACKETS_LOST);
    Lazy::force(&MQTT_RECONNECTS_TOTAL);
    Lazy::force(&JWT_REFRESH_TOTAL);
    Lazy::force(&SCRCPY_RECONNECTS_TOTAL);
    Lazy::force(&PLI_COUNT_TOTAL);
}

#[derive(Clone, Default)]
pub struct HealthFlags {
    pub mqtt_connected: Arc<std::sync::atomic::AtomicBool>,
    pub scrcpy_running: Arc<std::sync::atomic::AtomicBool>,
}

pub async fn serve(addr: SocketAddr, health: HealthFlags) -> Result<()> {
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "metrics http server listening");
    loop {
        let (stream, _) = match listener.accept().await {
            Ok(v) => v,
            Err(e) => {
                warn!(error = %e, "accept failed");
                continue;
            }
        };
        let io = TokioIo::new(stream);
        let health = health.clone();
        tokio::spawn(async move {
            let svc = service_fn(move |req: Request<Incoming>| {
                let health = health.clone();
                async move { Ok::<_, std::convert::Infallible>(route(req, health).await) }
            });
            let _ = HttpBuilder::new(TokioExecutor::new()).serve_connection(io, svc).await;
        });
    }
}

async fn route(req: Request<Incoming>, health: HealthFlags) -> Response<Full<Bytes>> {
    if req.method() != Method::GET {
        return not_found();
    }
    match req.uri().path() {
        "/healthz" => {
            let mqtt = health.mqtt_connected.load(std::sync::atomic::Ordering::Relaxed);
            let scrcpy = health.scrcpy_running.load(std::sync::atomic::Ordering::Relaxed);
            let ok = mqtt && scrcpy;
            let body = serde_json::json!({
                "ok": ok,
                "mqtt": mqtt,
                "scrcpy": scrcpy,
            })
            .to_string();
            Response::builder()
                .status(if ok { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE })
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(body)))
                .unwrap()
        }
        "/metrics" => {
            let encoder = TextEncoder::new();
            let metric_families = REGISTRY.gather();
            let mut buf = Vec::new();
            if encoder.encode(&metric_families, &mut buf).is_err() {
                return internal_err();
            }
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", encoder.format_type())
                .body(Full::new(Bytes::from(buf)))
                .unwrap()
        }
        _ => not_found(),
    }
}

fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from_static(b"not found")))
        .unwrap()
}

fn internal_err() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::INTERNAL_SERVER_ERROR)
        .body(Full::new(Bytes::from_static(b"metrics encode failed")))
        .unwrap()
}
