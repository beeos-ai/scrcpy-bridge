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
    /// Stream Protocol short-edge profile (`MAX_WIDTH` 720 / 1080).
    pub max_width: u32,
    /// Optional explicit scrcpy `max_size` (long edge). When unset,
    /// [`super::scrcpy_max_size`] maps `max_width`.
    pub scrcpy_max_size: Option<u32>,
    pub bitrate: u32,
    pub i_frame_interval: u32,
    pub audio: bool,
    pub control: bool,
    /// When set, overrides the embedded JAR with a file from disk. Useful for
    /// local development and protocol upgrades before a release is cut.
    pub override_jar: Option<PathBuf>,
}

impl ScrcpyServerConfig {
    /// scrcpy `max_size` long-edge cap for this profile.
    pub fn resolved_max_size(&self) -> u32 {
        match self.scrcpy_max_size {
            Some(v) if v > 0 => v,
            _ => super::scrcpy_max_size(self.max_width),
        }
    }
}

impl Default for ScrcpyServerConfig {
    fn default() -> Self {
        Self {
            scrcpy_version: crate::SCRCPY_VERSION.to_string(),
            remote_jar_path: "/data/local/tmp/scrcpy-server.jar".to_string(),
            max_fps: 30,
            max_width: 1920,
            scrcpy_max_size: None,
            bitrate: 8_000_000,
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
    scid: u32,
    local_port: u16,
    process: Option<Child>,
    stderr_log: Option<JoinHandle<()>>,
    pub video: Option<VideoReader>,
    pub audio: Option<AudioReader>,
    pub control: Option<ControlSocket>,
}

impl ScrcpyServer {
    pub fn new(adb: Adb, mut cfg: ScrcpyServerConfig) -> Self {
        let scid = rand::thread_rng().gen_range(1..=i32::MAX as u32);
        // Overlapping reconnects must not unlink or kill the next capture.
        cfg.remote_jar_path = session_jar_path(&cfg.remote_jar_path, scid);
        Self {
            adb,
            cfg,
            scid,
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
        let result = self.start_inner().await;
        if result.is_err() {
            self.stop().await;
        }
        result
    }

    async fn start_inner(&mut self) -> Result<()> {
        self.push_server_jar().await?;

        self.local_port = Self::pick_local_port();
        self.adb.remove_forward(self.local_port).await.ok();
        self.adb
            .forward_abstract(self.local_port, &session_socket_name(self.scid))
            .await
            .context("adb forward tcp:local → localabstract:scrcpy")?;

        self.launch_app_process().await?;

        // scrcpy needs a moment to open its listening abstract socket.
        sleep(Duration::from_millis(500)).await;

        // Connection order is fixed by scrcpy with tunnel_forward=true:
        // video first, then audio (if enabled), then control (if enabled).
        let video_stream = Self::connect_video_with_retry(self.local_port).await?;
        self.video = Some(VideoReader::new(video_stream));
        info!(port = self.local_port, "scrcpy video socket connected");

        if self.cfg.audio {
            match Self::connect_with_retry(self.local_port).await {
                Ok(s) => {
                    self.audio = Some(AudioReader::new(s));
                    info!(port = self.local_port, "scrcpy audio socket connected");
                }
                Err(e) => {
                    warn!(error = %e, "audio socket connect failed — continuing without audio")
                }
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

    async fn connect_video_with_retry(port: u16) -> Result<TcpStream> {
        use tokio::io::AsyncReadExt;
        // adb's forwarding listener accepts TCP even before the Android socket
        // exists. scrcpy's dummy byte proves the server accepted this socket.
        for attempt in 0..20 {
            if let Ok(mut stream) = TcpStream::connect(("127.0.0.1", port)).await {
                let mut ready = [0u8; 1];
                if matches!(
                    tokio::time::timeout(Duration::from_secs(2), stream.read_exact(&mut ready))
                        .await,
                    Ok(Ok(_))
                ) && ready == [0]
                {
                    return Ok(stream);
                }
            }
            sleep(Duration::from_millis(250 + 50 * attempt)).await;
        }
        Err(anyhow!(
            "scrcpy video readiness handshake failed on 127.0.0.1:{port}"
        ))
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
            format!("scid={:08x}", self.scid),
            "video_codec=h264".to_string(),
            format!("max_fps={}", c.max_fps),
            format!("max_size={}", c.resolved_max_size()),
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
            "send_dummy_byte=true".to_string(),
            "send_codec_meta=false".to_string(),
        ];

        let mut cmd = Command::new("adb");
        cmd.args(&base_args);
        cmd.stdout(std::process::Stdio::piped());
        cmd.stderr(std::process::Stdio::piped());
        cmd.kill_on_drop(true);

        let mut child = cmd.spawn().context("spawn adb shell app_process")?;

        let stdout = child.stdout.take().context("capture scrcpy stdout")?;
        let stderr = child.stderr.take().context("capture scrcpy stderr")?;
        self.stderr_log = Some(tokio::spawn(async move {
            tokio::join!(pump_server_output(stdout), pump_server_output(stderr));
        }));
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
    /// No process, no reverse-forward. Used when the ICE session exists
    /// before `app_process` has been attached.
    pub fn idle(adb: Adb) -> Self {
        Self {
            process: None,
            stderr_log: None,
            adb,
            local_port: 0,
        }
    }

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

async fn pump_server_output<R: tokio::io::AsyncRead + Unpin>(output: R) {
    use tokio::io::{AsyncBufReadExt, BufReader};
    let mut r = BufReader::new(output).lines();
    while let Ok(Some(line)) = r.next_line().await {
        if line.contains("ERROR:")
            || line.contains("WARN:")
            || line.trim_start().starts_with("at ")
            || line.contains("Exception")
        {
            tracing::warn!(target: "scrcpy_bridge::bridge", "scrcpy-server: {}", line);
        } else {
            tracing::info!(target: "scrcpy_bridge::bridge", "scrcpy-server: {}", line);
        }
    }
}

fn session_socket_name(scid: u32) -> String {
    format!("scrcpy_{scid:08x}")
}

fn session_jar_path(path: &str, scid: u32) -> String {
    format!(
        "{}-{scid:08x}.jar",
        path.strip_suffix(".jar").unwrap_or(path)
    )
}

#[cfg(test)]
mod session_isolation_tests {
    #[tokio::test]
    async fn video_handshake_retries_forwarded_eof_and_consumes_only_dummy_byte() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (first, _) = listener.accept().await.unwrap();
            drop(first);
            let (mut second, _) = listener.accept().await.unwrap();
            second.write_all(&[0, 42]).await.unwrap();
        });
        let mut stream = super::ScrcpyServer::connect_video_with_retry(port)
            .await
            .unwrap();
        let mut payload = [0];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(payload, [42]);
        server.await.unwrap();
    }
    #[tokio::test]
    async fn output_pump_drains_more_than_the_pipe_capacity() {
        use tokio::io::AsyncWriteExt;
        let (reader, mut writer) = tokio::io::duplex(64);
        let pump = tokio::spawn(super::pump_server_output(reader));
        tokio::time::timeout(std::time::Duration::from_secs(1), async {
            for _ in 0..100 {
                writer
                    .write_all(b"diagnostic line larger than one small pipe buffer\n")
                    .await
                    .unwrap();
            }
            drop(writer);
            pump.await.unwrap();
        })
        .await
        .unwrap();
    }

    #[test]
    fn captures_use_distinct_socket_and_cleanup_paths() {
        assert_eq!(super::session_socket_name(0x123), "scrcpy_00000123");
        assert_eq!(
            super::session_jar_path("/data/local/tmp/server.jar", 0x123),
            "/data/local/tmp/server-00000123.jar"
        );
        assert_ne!(super::session_socket_name(1), super::session_socket_name(2));
        assert_ne!(
            super::session_jar_path("server.jar", 1),
            super::session_jar_path("server.jar", 2)
        );
    }
}
