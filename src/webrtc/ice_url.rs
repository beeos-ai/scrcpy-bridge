//! ICE URL host rewriting.
//!
//! webrtc-rs TURN allocate calls `getaddrinfo` on the URL host. On China
//! OKE that resolver is `8.8.8.8` (redroid breaks ClusterIP DNS) and a
//! hostname lookup adds ~2.5 s to every gather. Bootstrap already fetched
//! the list; resolve A records then, so `on_offer` hands the peer an
//! IPv4 literal (`turn:47.131.41.222:3478`). TURN username/realm do not
//! depend on the hostname.

use std::collections::HashMap;
use std::net::Ipv4Addr;

use tracing::{info, warn};

use super::IceServer;

/// Rewrite ICE URL hostnames to IPv4 literals.
///
/// Failures keep the original URL so gather still has something to try.
pub async fn resolve_ice_hosts_to_ipv4(servers: Vec<IceServer>) -> Vec<IceServer> {
    let mut cache: HashMap<String, Option<Ipv4Addr>> = HashMap::new();
    let mut out = Vec::with_capacity(servers.len());
    for server in servers {
        let mut urls = Vec::with_capacity(server.urls.len());
        for url in server.urls {
            urls.push(resolve_one_ice_url(&url, &mut cache).await);
        }
        out.push(IceServer {
            urls,
            username: server.username,
            credential: server.credential,
        });
    }
    out
}

async fn resolve_one_ice_url(url: &str, cache: &mut HashMap<String, Option<Ipv4Addr>>) -> String {
    let Some(parts) = IceUrlParts::parse(url) else {
        return url.to_string();
    };
    if parts.host.parse::<Ipv4Addr>().is_ok() {
        return url.to_string();
    }
    if parts.host.starts_with('[') || parts.host.contains(':') {
        return url.to_string();
    }

    if !cache.contains_key(parts.host) {
        let looked_up = lookup_ipv4(parts.host).await;
        cache.insert(parts.host.to_string(), looked_up);
    }
    match cache.get(parts.host).copied().flatten() {
        Some(ipv4) => {
            let rewritten = parts.with_host(&ipv4.to_string());
            info!(
                event = "bridge.ice_url_resolved",
                original_host = parts.host,
                ipv4 = %ipv4,
                "ICE URL hostname resolved to IPv4"
            );
            rewritten
        }
        None => url.to_string(),
    }
}

async fn lookup_ipv4(host: &str) -> Option<Ipv4Addr> {
    match tokio::net::lookup_host((host, 0u16)).await {
        Ok(addrs) => addrs
            .filter_map(|addr| match addr.ip() {
                std::net::IpAddr::V4(ipv4) => Some(ipv4),
                _ => None,
            })
            .next(),
        Err(error) => {
            warn!(
                host,
                error = %error,
                "ICE host IPv4 lookup failed; keeping hostname"
            );
            None
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IceUrlParts<'a> {
    scheme: &'a str,
    host: &'a str,
    port: Option<&'a str>,
    query: Option<&'a str>,
}

impl<'a> IceUrlParts<'a> {
    fn parse(url: &'a str) -> Option<Self> {
        let trimmed = url.trim();
        let (scheme, rest) = trimmed.split_once(':')?;
        if scheme.is_empty() || rest.is_empty() {
            return None;
        }
        let (hostport, query) = match rest.split_once('?') {
            Some((hostport, query)) => (hostport, Some(query)),
            None => (rest, None),
        };
        let (host, port) = split_host_port(hostport)?;
        if host.is_empty() {
            return None;
        }
        Some(Self {
            scheme,
            host,
            port,
            query,
        })
    }

    fn with_host(&self, host: &str) -> String {
        let mut out = String::with_capacity(self.scheme.len() + host.len() + 16);
        out.push_str(self.scheme);
        out.push(':');
        out.push_str(host);
        if let Some(port) = self.port {
            out.push(':');
            out.push_str(port);
        }
        if let Some(query) = self.query {
            out.push('?');
            out.push_str(query);
        }
        out
    }
}

fn split_host_port(hostport: &str) -> Option<(&str, Option<&str>)> {
    if let Some(rest) = hostport.strip_prefix('[') {
        let close = rest.find(']')?;
        let host = &rest[..close];
        let after = &rest[close + 1..];
        if after.is_empty() {
            return Some((host, None));
        }
        let port = after.strip_prefix(':')?;
        if port.is_empty() {
            return None;
        }
        return Some((host, Some(port)));
    }
    if let Some((host, port)) = hostport.rsplit_once(':') {
        if host.is_empty() || port.is_empty() {
            return None;
        }
        return Some((host, Some(port)));
    }
    Some((hostport, None))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_turn_hostname_and_query() {
        let parts = IceUrlParts::parse("turn:turn.beeos.ai:3478?transport=tcp").unwrap();
        assert_eq!(parts.scheme, "turn");
        assert_eq!(parts.host, "turn.beeos.ai");
        assert_eq!(parts.port, Some("3478"));
        assert_eq!(parts.query, Some("transport=tcp"));
    }

    #[test]
    fn parses_stun_without_query() {
        let parts = IceUrlParts::parse("stun:stun.l.google.com:19302").unwrap();
        assert_eq!(parts.host, "stun.l.google.com");
        assert_eq!(parts.port, Some("19302"));
        assert_eq!(parts.query, None);
    }

    #[test]
    fn parses_ipv4_literal() {
        let parts = IceUrlParts::parse("turn:47.131.41.222:3478").unwrap();
        assert_eq!(parts.host, "47.131.41.222");
        assert_eq!(parts.port, Some("3478"));
    }

    #[test]
    fn parses_ipv6_literal() {
        let parts = IceUrlParts::parse("turn:[2001:db8::1]:3478").unwrap();
        assert_eq!(parts.host, "2001:db8::1");
        assert_eq!(parts.port, Some("3478"));
    }

    #[test]
    fn rewrite_preserves_port_and_query() {
        let parts = IceUrlParts::parse("turn:turn.beeos.ai:3478?transport=udp").unwrap();
        assert_eq!(
            parts.with_host("47.131.41.222"),
            "turn:47.131.41.222:3478?transport=udp"
        );
    }

    #[tokio::test]
    async fn ipv4_literals_are_left_alone() {
        let servers = vec![IceServer {
            urls: vec!["turn:47.131.41.222:3478".into()],
            username: Some("u".into()),
            credential: Some("p".into()),
        }];
        let resolved = resolve_ice_hosts_to_ipv4(servers).await;
        assert_eq!(resolved[0].urls, vec!["turn:47.131.41.222:3478"]);
        assert_eq!(resolved[0].username.as_deref(), Some("u"));
    }

    #[test]
    fn split_host_port_rejects_empty_port() {
        assert_eq!(split_host_port("turn.beeos.ai:"), None);
    }
}
