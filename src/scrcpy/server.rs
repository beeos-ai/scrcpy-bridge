//! Scrcpy server lifecycle: push jar, forward port, launch `app_process`, and
//! connect the three protocol sockets (video, audio, control).
//!
//! Equivalent to Python `device_agent.webrtc.scrcpy_adapter.ScrcpyAdapter`,
//! but written in Rust so the critical H.264 path never decodes/re-encodes.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use rand::Rng;
use tokio::net::TcpStream;
use tokio::process::{Child, Command};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tracing::{info, warn};

use crate::adb::Adb;
use crate::SCRCPY_SERVER_JAR;

use super::audio::AudioReader;
use super::control::ControlSocket;
use super::video::VideoReader;

/// Parameters controlling what scrcpy-server encodes on the device.
#[derive(Debug, Clone)]
pub struct ScrcpyServerConfig {
    pub scrcpy_version: String,
    pub remote_jar_path: String,
    pub max_fps: u32,
    pub max_width: u32,
    pub bitrate: u32,
    pub i_frame_interval: u32,
    pub audio: bool,
    pub control: bool,
    /// When set, overrides the embedded JAR with a file from disk. Useful for
    /// local development and protocol upgrades before a release is cut.
    pub override_jar: Option<PathBuf>,
}

impl Default for ScrcpyServerConfig {
    fn default() -> Self {
        Self {
            scrcpy_version: crate::SCRCPY_VERSION.to_string(),
            remote_jar_path: "/data/local/tmp/scrcpy-server.jar".to_string(),
            max_fps: 30,
            max_width: 1920,
            bitrate: 16_000_000,
            i_frame_interval: 2,
            audio: true,
            control: true,
            override_jar: None,
        }
    }
}

/// Live scrcpy session: jar pushed, app_process running, three sockets open.
pub struct ScrcpyServer {
    adb: Adb,
    cfg: ScrcpyServerConfig,
    local_port: u16,
    process: Option<Child>,
    stderr_log: Option<JoinHandle<()>>,
    pub video: Option<VideoReader>,
    pub audio: Option<AudioReader>,
    pub control: Option<ControlSocket>,
}

impl ScrcpyServer {
    pub fn new(adb: Adb, cfg: ScrcpyServerConfig) -> Self {
        Self {
            adb,
            cfg,
            local_port: 0,
            process: None,
            stderr_log: None,
            video: None,
            audio: None,
            control: None,
        }
    }

    /// End-to-end start: push jar, pick port, forward, launch, connect.
    pub async fn start(&mut self) -> Result<()> {
        self.push_server_jar().await?;
        self.adb.kill_stale_scrcpy().await.ok();

        self.local_port = Self::pick_local_port();
        self.adb.remove_forward(self.local_port).await.ok();
        self.adb
            .forward_abstract(self.local_port, "scrcpy")
            .await
            .context("adb forward tcp:local → localabstract:scrcpy")?;

        self.launch_app_process().await?;

        // scrcpy needs a moment to open its listening abstract socket.
        sleep(Duration::from_millis(500)).await;

        // Connection order is fixed by scrcpy with tunnel_forward=true:
        // video first, then audio (if enabled), then control (if enabled).
        let video_stream = Self::connect_with_retry(self.local_port).await?;
        self.video = Some(VideoReader::new(video_stream));
        info!(port = self.local_port, "scrcpy video socket connected");

        if self.cfg.audio {
            match Self::connect_with_retry(self.local_port).await {
                Ok(s) => {
                    self.audio = Some(AudioReader::new(s));
                    info!(port = self.local_port, "scrcpy audio socket connected");
                }
                Err(e) => warn!(error = %e, "audio socket connect failed — continuing without audio"),
            }
        }

        if self.cfg.control {
            match Self::connect_with_retry(self.local_port).await {
                Ok(s) => {
                    self.control = Some(ControlSocket::new(s));
                    info!(port = self.local_port, "scrcpy control socket connected");
                }
                Err(e) => warn!(error = %e, "control socket connect failed"),
            }
        }
        Ok(())
    }

    fn pick_local_port() -> u16 {
        let mut rng = rand::thread_rng();
        rng.gen_range(27_100..28_000)
    }

    async fn connect_with_retry(port: u16) -> Result<TcpStream> {
        for attempt in 0..20 {
            match TcpStream::connect(("127.0.0.1", port)).await {
                Ok(s) => return Ok(s),
                Err(_) => sleep(Duration::from_millis(250 + 50 * attempt)).await,
            }
        }
        Err(anyhow!("could not connect to scrcpy on 127.0.0.1:{port}"))
    }

    async fn push_server_jar(&self) -> Result<()> {
        let bytes: &[u8] = if let Some(p) = self.cfg.override_jar.as_ref() {
            // Load the override once per start, not per frame.
            let data = tokio::fs::read(p)
                .await
                .with_context(|| format!("read override jar {}", p.display()))?;
            return self.adb.push_bytes(&data, &self.cfg.remote_jar_path).await;
        } else {
            SCRCPY_SERVER_JAR
        };
        if bytes.len() < 1024 {
            // build.rs wrote a placeholder when curl/wget were unavailable.
            return Err(anyhow!(
                "embedded scrcpy-server.jar is a placeholder ({} bytes). Rebuild with network access or set SCRCPY_SERVER_JAR to an actual jar path.",
                bytes.len()
            ));
        }
        self.adb.push_bytes(bytes, &self.cfg.remote_jar_path).await
    }

    async fn launch_app_process(&mut self) -> Result<()> {
        let c = &self.cfg;
        let base_args = vec![
            "-H".to_string(),
            self.adb.host.clone(),
            "-P".to_string(),
            self.adb.port.to_string(),
            "-s".to_string(),
            self.adb.serial.clone(),
            "shell".to_string(),
            format!("CLASSPATH={}", c.remote_jar_path),
            "app_process".to_string(),
            "/".to_string(),
            "com.genymobile.scrcpy.Server".to_string(),
            c.scrcpy_version.clone(),
            "video_codec=h264".to_string(),
            format!("max_fps={}", c.max_fps),
            format!("max_size={}", c.max_width),
            format!("video_bit_rate={}", c.bitrate),
            format!(
                "video_codec_options=i-frame-interval={}",
                c.i_frame_interval
            ),
            "tunnel_forward=true".to_string(),
            format!("audio={}", c.audio),
            "audio_codec=opus".to_string(),
            format!("control={}", c.control),
            "send_frame_meta=true".to_string(),
            "send_device_meta=false".to_string(),
            "send_dummy_byte=false".to_string(),
            "send_codec_meta=false".to_string(),
        ];

        let mut cmd = Command::new("adb");
        cmd.args(&base_args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().context("spawn adb shell app_process")?;

        if let Some(stderr) = child.stderr.take() {
            let handle = tokio::spawn(pump_stderr(stderr));
            self.stderr_log = Some(handle);
        }
        self.process = Some(child);
        Ok(())
    }

    /// Graceful shutdown: kill the adb subprocess and clear the forward rule.
    pub async fn stop(&mut self) {
        let mut shutdown = ScrcpyShutdown {
            process: self.process.take(),
            stderr_log: self.stderr_log.take(),
            adb: self.adb.clone(),
            local_port: self.local_port,
        };
        self.local_port = 0;
        shutdown.shutdown().await;
    }

    /// Decompose a running scrcpy session into the three independently
    /// owned I/O halves plus a shutdown handle. After this call the
    /// `ScrcpyServer` is consumed; callers must move the returned parts
    /// into their respective tasks and call `ScrcpyShutdown::shutdown`
    /// exactly once when the session is being torn down.
    pub fn split(mut self) -> ScrcpySessionParts {
        let video = self.video.take();
        let audio = self.audio.take();
        let control = self.control.take().map(Arc::new);
        let shutdown = ScrcpyShutdown {
            process: self.process.take(),
            stderr_log: self.stderr_log.take(),
            adb: self.adb.clone(),
            local_port: self.local_port,
        };
        // `self` is dropped here; `Child` has `kill_on_drop(true)`, but we
        // zero `process` out above so the real reaping happens through
        // `ScrcpyShutdown::shutdown` (which also waits, logs, and clears
        // the adb forward). Drop of the empty `ScrcpyServer` is a no-op.
        ScrcpySessionParts {
            video,
            audio,
            control,
            shutdown,
        }
    }
}

/// Result of [`ScrcpyServer::split`]. Each field moves into the task that
/// owns it; `shutdown` moves into the session supervisor.
pub struct ScrcpySessionParts {
    pub video: Option<VideoReader>,
    pub audio: Option<AudioReader>,
    pub control: Option<Arc<ControlSocket>>,
    pub shutdown: ScrcpyShutdown,
}

/// Owns the pieces that must be torn down when a session ends: the
/// `adb shell app_process` child, its stderr pump, and the reverse-forward
/// rule. Safe to call `shutdown()` exactly once.
pub struct ScrcpyShutdown {
    process: Option<Child>,
    stderr_log: Option<JoinHandle<()>>,
    adb: Adb,
    local_port: u16,
}

impl ScrcpyShutdown {
    pub async fn shutdown(&mut self) {
        if let Some(mut p) = self.process.take() {
            let _ = p.start_kill();
            let _ = tokio::time::timeout(Duration::from_secs(3), p.wait()).await;
        }
        if let Some(h) = self.stderr_log.take() {
            h.abort();
        }
        if self.local_port != 0 {
            let _ = self.adb.remove_forward(self.local_port).await;
            self.local_port = 0;
        }
    }
}

async fn pump_stderr(mut stderr: tokio::process::ChildStderr) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut r = BufReader::new(&mut stderr).lines();
    while let Ok(Some(line)) = r.next_line().await {
        tracing::info!(target: "scrcpy_server", "{}", line);
    }
}
