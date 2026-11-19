//! Native executor signaling over inherited pipes. The parent owns
//! authentication and the per-phone input fence; the bridge never opens a
//! second public control endpoint. MQTT remains available for existing users.
use crate::{
    bootstrap::IceServerPayload,
    mqtt::{MqttCredentials, MqttSignaling, SignalRequest, SignalResponse},
};
use anyhow::{bail, Result};
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    sync::{mpsc, oneshot, Mutex},
};

pub enum Signaling {
    Mqtt(MqttSignaling),
    Stdio(Arc<Pipe>),
}
pub struct Pipe {
    force_relay: bool,
    output: Mutex<tokio::io::Stdout>,
    pending: Mutex<HashMap<String, oneshot::Sender<bool>>>,
    sequence: AtomicU64,
}
impl Pipe {
    async fn send(&self, value: Value) -> Result<()> {
        let mut bytes = serde_json::to_vec(&value)?;
        bytes.push(b'\n');
        let mut out = self.output.lock().await;
        out.write_all(&bytes).await?;
        out.flush().await?;
        Ok(())
    }
}
impl Signaling {
    pub fn force_relay(&self) -> Option<bool> {
        match self {
            Self::Stdio(p) => Some(p.force_relay),
            _ => None,
        }
    }
    pub fn managed(&self) -> bool {
        matches!(self, Self::Stdio(_))
    }

    /// The first bounded line carries short-lived ICE credentials. They are
    /// never supplied in argv, logs, or a persistent bootstrap file.
    pub async fn stdio() -> Result<(Self, mpsc::Receiver<SignalRequest>, Vec<IceServerPayload>)> {
        let mut input = BufReader::new(tokio::io::stdin());
        let initial =
            tokio::time::timeout(Duration::from_secs(10), read_frame(&mut input)).await??;
        if initial["type"] != "init" {
            bail!("expected native signaling init");
        }
        let ice: Vec<IceServerPayload> = serde_json::from_value(initial["iceServers"].clone())?;
        if ice.len() > 16 {
            bail!("too many ICE servers");
        }
        let policy = initial["iceTransportPolicy"].as_str().unwrap_or("all");
        if policy != "all" && policy != "relay" {
            bail!("invalid ICE policy");
        }
        let pipe = Arc::new(Pipe {
            force_relay: policy == "relay",
            output: Mutex::new(tokio::io::stdout()),
            pending: Mutex::new(HashMap::new()),
            sequence: AtomicU64::new(0),
        });
        let (tx, rx) = mpsc::channel(32);
        let reader = pipe.clone();
        tokio::spawn(async move {
            while let Ok(value) = read_frame(&mut input).await {
                if value["type"] == "input_decision" {
                    if let Some(id) = value["request_id"].as_str() {
                        tracing::debug!(request_id = id, "native input decision received");
                        if let Some(waiter) = reader.pending.lock().await.remove(id) {
                            let _ = waiter.send(value["allow"].as_bool() == Some(true));
                        }
                    }
                } else if let Ok(request) = serde_json::from_value::<SignalRequest>(value) {
                    if tx.send(request).await.is_err() {
                        break;
                    }
                } else {
                    break;
                }
            }
            reader.pending.lock().await.clear();
            // Dropping tx terminates the bridge and tears down the native peer.
        });
        pipe.send(json!({"type":"ready","input":"parent_fenced"}))
            .await?;
        Ok((Self::Stdio(pipe), rx, ice))
    }

    pub async fn reconnect(&self, creds: MqttCredentials) -> Result<()> {
        match self {
            Self::Mqtt(m) => m.reconnect(creds).await,
            _ => bail!("native signaling does not use MQTT credentials"),
        }
    }
    pub async fn publish_response(&self, value: &SignalResponse) -> Result<()> {
        match self {
            Self::Mqtt(m) => m.publish_response(value).await,
            Self::Stdio(p) => p.send(serde_json::to_value(value)?).await,
        }
    }
    pub async fn publish_json(&self, suffix: &str, value: &Value) -> Result<()> {
        match self {
            Self::Mqtt(m) => m.publish_json(suffix, value).await,
            Self::Stdio(p) => {
                p.send(json!({"type":"event","name":suffix,"payload":value}))
                    .await
            }
        }
    }
    pub async fn closed(&self, viewer: &str) -> Result<()> {
        if let Self::Stdio(p) = self {
            p.send(json!({"type":"closed","viewerId":viewer})).await?;
        }
        Ok(())
    }

    /// The parent holds its shared MCP/human gate from authorization until
    /// input_result. No decision, EOF, or late decision can execute an input.
    pub async fn authorize(&self, viewer: &str, text: &str) -> Result<Option<String>> {
        let Self::Stdio(p) = self else {
            return Ok(None);
        };
        if text.len() > 16384 {
            bail!("input too large");
        }
        let payload: Value = serde_json::from_str(text)?;
        let id = format!("input-{}", p.sequence.fetch_add(1, Ordering::Relaxed));
        let (tx, rx) = oneshot::channel();
        p.pending.lock().await.insert(id.clone(), tx);
        let sent = p
            .send(
                json!({"type":"input_request","request_id":id,"viewerId":viewer,"payload":payload}),
            )
            .await;
        let allowed = if sent.is_ok() {
            matches!(
                tokio::time::timeout(Duration::from_secs(3), rx).await,
                Ok(Ok(true))
            )
        } else {
            false
        };
        p.pending.lock().await.remove(&id);
        tracing::debug!(request_id=%id, allowed, "native input authorization completed");
        if !allowed {
            bail!("human input not authorized");
        }
        Ok(Some(id))
    }
    pub async fn input_result(&self, id: &str, succeeded: bool) -> Result<()> {
        if let Self::Stdio(p) = self {
            // scrcpy confirms the socket write, not the Android application
            // effect. Do not mislabel a successful write as an executed action.
            p.send(json!({"type":"input_result","request_id":id,"outcome":if succeeded {"dispatched"} else {"unknown"}})).await?;
        }
        Ok(())
    }
}

async fn read_frame<R: tokio::io::AsyncBufRead + Unpin>(input: &mut R) -> Result<Value> {
    let mut bytes = Vec::new();
    // Bound memory before deserialization, including malicious unterminated lines.
    loop {
        let available = input.fill_buf().await?;
        if available.is_empty() {
            bail!("native signaling closed");
        }
        let n = available
            .iter()
            .position(|b| *b == b'\n')
            .map(|i| i + 1)
            .unwrap_or(available.len());
        if bytes.len() + n > 128 * 1024 {
            bail!("native signaling frame too large");
        }
        let end = available[n - 1] == b'\n';
        bytes.extend_from_slice(&available[..n]);
        input.consume(n);
        if end {
            return Ok(serde_json::from_slice(&bytes)?);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn frame_limit_applies_before_newline() {
        let bytes = vec![b' '; 128 * 1024 + 1];
        assert!(read_frame(&mut bytes.as_slice()).await.is_err());
        assert_eq!(
            read_frame(&mut b"{\"type\":\"init\"}\n".as_slice())
                .await
                .unwrap()["type"],
            "init"
        );
        assert!(read_frame(&mut b"".as_slice()).await.is_err());
    }
}
