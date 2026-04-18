//! Thin wrapper around the `adb` CLI.
//!
//! We intentionally shell out to `adb` rather than re-implementing the ADB
//! wire protocol here: the host already has a running `adb` daemon in every
//! supported deployment scenario (ReDroid sidecar, device farm host, dev box)
//! and the Python `device-agent` sibling also uses that same daemon. Going
//! through the daemon keeps everything coherent and avoids double-initializing
//! USB / tcp connections.

use std::path::Path;
use std::time::Duration;

use anyhow::{anyhow, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::process::Command;
use tracing::debug;

/// A handle targeting a specific ADB device via the host's ADB server.
#[derive(Debug, Clone)]
pub struct Adb {
    pub serial: String,
    pub host: String,
    pub port: u16,
}

impl Adb {
    pub fn new(serial: impl Into<String>, host: impl Into<String>, port: u16) -> Self {
        Self {
            serial: serial.into(),
            host: host.into(),
            port,
        }
    }

    fn base(&self) -> Vec<String> {
        vec![
            "-H".into(),
            self.host.clone(),
            "-P".into(),
            self.port.to_string(),
            "-s".into(),
            self.serial.clone(),
        ]
    }

    /// Run `adb <args...>` and collect stdout / stderr as UTF-8 strings.
    pub async fn exec<I, S>(&self, args: I) -> Result<(String, String)>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<std::ffi::OsStr>,
    {
        let mut cmd = Command::new("adb");
        cmd.args(self.base());
        cmd.args(args);
        cmd.kill_on_drop(true);
        let output = cmd
            .output()
            .await
            .with_context(|| format!("adb exec (serial={})", self.serial))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        let stderr = String::from_utf8_lossy(&output.stderr).into_owned();
        if !output.status.success() {
            return Err(anyhow!(
                "adb exit {}: {}",
                output.status.code().unwrap_or(-1),
                stderr.trim()
            ));
        }
        Ok((stdout, stderr))
    }

    /// Push a local file to the device.
    pub async fn push(&self, local: &Path, remote: &str) -> Result<()> {
        self.exec(["push", local.to_str().unwrap_or(""), remote]).await?;
        Ok(())
    }

    /// Forward a local TCP port to a device-side unix abstract socket.
    pub async fn forward_abstract(&self, local_port: u16, abstract_name: &str) -> Result<()> {
        self.exec([
            "forward".to_string(),
            format!("tcp:{}", local_port),
            format!("localabstract:{}", abstract_name),
        ])
        .await?;
        Ok(())
    }

    /// Remove a forward rule (ignores errors).
    pub async fn remove_forward(&self, local_port: u16) -> Result<()> {
        let _ = self
            .exec([
                "forward".to_string(),
                "--remove".to_string(),
                format!("tcp:{}", local_port),
            ])
            .await;
        Ok(())
    }

    /// Run a shell command on the device and return stdout.
    pub async fn shell(&self, cmd: &str) -> Result<String> {
        let (stdout, _) = self.exec(["shell", cmd]).await?;
        Ok(stdout)
    }

    /// Check if the device currently reports `sys.boot_completed=1`.
    pub async fn boot_completed(&self) -> bool {
        match self.shell("getprop sys.boot_completed").await {
            Ok(s) => s.trim() == "1",
            Err(_) => false,
        }
    }

    /// Wait up to `timeout` for boot completion. Useful for ReDroid cold-start.
    pub async fn wait_for_boot(&self, timeout: Duration) -> Result<()> {
        let start = std::time::Instant::now();
        while start.elapsed() < timeout {
            if self.boot_completed().await {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(anyhow!(
            "device {} did not finish booting within {:?}",
            self.serial,
            timeout
        ))
    }

    /// Write `bytes` to a device-side path atomically. Useful for staging the
    /// embedded scrcpy-server.jar without a local temp file.
    pub async fn push_bytes(&self, bytes: &[u8], remote: &str) -> Result<()> {
        let tmp = tempfile::NamedTempFile::new().context("tempfile")?;
        let path: std::path::PathBuf = tmp.path().to_path_buf();
        tokio::fs::write(path.as_path(), bytes)
            .await
            .context("write tmp jar")?;
        self.push(&path, remote).await?;
        Ok(())
    }

    /// Kill any stale scrcpy-server processes on the device.
    pub async fn kill_stale_scrcpy(&self) -> Result<()> {
        let ps = self
            .shell("ps -A -o PID,ARGS 2>/dev/null || ps -o PID,ARGS 2>/dev/null || ps 2>/dev/null")
            .await
            .unwrap_or_default();
        for line in ps.lines() {
            let lower = line.to_lowercase();
            if lower.contains("scrcpy") {
                if let Some(pid) = line.split_whitespace().next() {
                    if pid.chars().all(|c| c.is_ascii_digit()) {
                        debug!(%pid, "killing stale scrcpy");
                        let _ = self
                            .shell(&format!("kill -9 {} 2>/dev/null || true", pid))
                            .await;
                    }
                }
            }
        }
        Ok(())
    }
}

/// Utility for writing a prepared byte slice to a device path via `adb push`.
/// Exists separately from [`Adb::push_bytes`] so the embedded JAR case can be
/// unit tested without needing an actual device.
pub async fn stage_bytes(bytes: &[u8]) -> Result<tempfile::NamedTempFile> {
    let tmp = tempfile::NamedTempFile::new().context("tempfile")?;
    let path: std::path::PathBuf = tmp.path().to_path_buf();
    let mut f: tokio::fs::File = tokio::fs::File::create(path.as_path())
        .await
        .context("create tmp")?;
    f.write_all(bytes).await.context("write tmp")?;
    f.flush().await.ok();
    drop(f);
    Ok(tmp)
}

/// Read a variable number of bytes from anything `AsyncRead`.
pub async fn read_exact<R: AsyncReadExt + Unpin>(r: &mut R, n: usize) -> std::io::Result<Vec<u8>> {
    let mut buf = vec![0u8; n];
    r.read_exact(&mut buf).await?;
    Ok(buf)
}
