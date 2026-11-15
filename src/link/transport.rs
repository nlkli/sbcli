//! V2Ray-style transport query parameters (`type`, `path`, `host`, …).

use std::collections::BTreeMap;

use crate::models::shared::{
    GrpcTransport, HttpTransport, HttpUpgradeTransport, QuicTransport, V2RayTransport, WsTransport,
};

use super::error::{LinkError, Result};
use super::params::{Params, Query};

/// Header Xray-compatible clients use to carry WebSocket early data.
const WS_EARLY_DATA_HEADER: &str = "Sec-WebSocket-Protocol";

/// Parses `type` (alias `network`, used by some Trojan clients) and its
/// transport-specific parameters. Returns `None` for plain TCP.
///
/// Transports sing-box does not implement (`xhttp`, `kcp`, …) are rejected:
/// ignoring them would silently produce an outbound that cannot connect.
pub(crate) fn parse_transport(p: &Params) -> Result<Option<V2RayTransport>> {
    let path = p.get("path").unwrap_or_default();
    let host = p.get("host");

    let transport = match p.get_any(&["type", "network"]).unwrap_or("tcp") {
        // sing-box has no TCP transport: Xray's plain-HTTP obfuscation
        // (`type=tcp&headerType=http`) maps to its HTTP transport. Xray allows
        // a comma-separated path list there; sing-box takes one path, so the
        // first entry is used.
        "tcp" | "raw" => match p.get("headerType") {
            Some("http") => V2RayTransport::Http(HttpTransport {
                host: p.list("host"),
                path: path.split(',').next().unwrap_or_default().to_owned(),
                ..HttpTransport::default()
            }),
            _ => return Ok(None),
        },
        "ws" => {
            let (path, max_early_data) = split_early_data(path);
            let mut headers = BTreeMap::new();
            if let Some(host) = host {
                headers.insert("Host".to_owned(), host.to_owned());
            }
            V2RayTransport::Ws(WsTransport {
                path,
                headers,
                max_early_data,
                early_data_header_name: if max_early_data > 0 {
                    WS_EARLY_DATA_HEADER.to_owned()
                } else {
                    String::new()
                },
            })
        }
        "grpc" => {
            if p.get("mode") == Some("multi") {
                return Err(LinkError::unsupported("mode", "multi"));
            }
            V2RayTransport::Grpc(GrpcTransport {
                service_name: p.get("serviceName").unwrap_or_default().to_owned(),
                ..GrpcTransport::default()
            })
        }
        "httpupgrade" => V2RayTransport::Httpupgrade(HttpUpgradeTransport {
            host: host.unwrap_or_default().to_owned(),
            path: path.to_owned(),
            ..HttpUpgradeTransport::default()
        }),
        "http" | "h2" => V2RayTransport::Http(HttpTransport {
            host: p.list("host"),
            path: path.to_owned(),
            ..HttpTransport::default()
        }),
        "quic" => {
            // sing-box's QUIC transport has no encryption support.
            if let Some(s) = p.get("quicSecurity").filter(|s| *s != "none") {
                return Err(LinkError::unsupported("quicSecurity", s));
            }
            V2RayTransport::Quic(QuicTransport::default())
        }
        other => return Err(LinkError::unsupported("type", other)),
    };
    Ok(Some(transport))
}

/// Splits a trailing Xray-style early-data suffix (`?ed=N` / `&ed=N`) off a
/// WebSocket path. Returns the clean path and the size (0 if none).
fn split_early_data(path: &str) -> (String, u32) {
    if let Some(pos) = path.rfind(['?', '&']) {
        let early = path[pos + 1..]
            .strip_prefix("ed=")
            .and_then(|n| n.parse::<u32>().ok())
            .filter(|n| *n > 0);
        if let Some(n) = early {
            return (path[..pos].to_owned(), n);
        }
    }
    (path.to_owned(), 0)
}

/// Writes `type` and the transport-specific parameters.
///
/// `tls_enabled` selects the HTTP spelling: `type=http` with TLS, Xray's
/// plain-HTTP obfuscation (`type=tcp&headerType=http`) without.
///
/// Only link-expressible fields are written: for WebSocket that is the path
/// (with `ed=` for early data) and the `Host` header; other headers and
/// timeouts are dropped.
pub(crate) fn write_transport(
    transport: Option<&V2RayTransport>,
    tls_enabled: bool,
    q: &mut Query,
) {
    match transport {
        None => q.push("type", "tcp"),
        Some(V2RayTransport::Ws(ws)) => {
            q.push("type", "ws");
            let mut path = ws.path.clone();
            if ws.max_early_data > 0 {
                if path.is_empty() {
                    path.push('/');
                }
                path.push(if path.contains('?') { '&' } else { '?' });
                path.push_str(&format!("ed={}", ws.max_early_data));
            }
            q.push_non_empty("path", &path);
            if let Some((_, host)) = ws
                .headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("host"))
            {
                q.push_non_empty("host", host);
            }
        }
        Some(V2RayTransport::Grpc(grpc)) => {
            q.push("type", "grpc");
            q.push_non_empty("serviceName", &grpc.service_name);
        }
        Some(V2RayTransport::Httpupgrade(h)) => {
            q.push("type", "httpupgrade");
            q.push_non_empty("path", &h.path);
            q.push_non_empty("host", &h.host);
        }
        Some(V2RayTransport::Http(h)) => {
            if tls_enabled {
                q.push("type", "http");
            } else {
                q.push("type", "tcp");
                q.push("headerType", "http");
            }
            q.push_non_empty("path", &h.path);
            q.push_non_empty("host", &h.host.join(","));
        }
        Some(V2RayTransport::Quic(_)) => q.push("type", "quic"),
    }
}
