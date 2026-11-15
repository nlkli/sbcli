//! `hysteria://host:port?<params>#<tag>` ⇄ sing-box [`Hysteria`] (v1) outbound.
//!
//! The scheme comes from Shadowrocket. Hysteria 1 needs bandwidth figures for
//! congestion control, so `upmbps` and `downmbps` are mandatory.
//!
//! | Parameter            | Maps to                 | Notes                                  |
//! |----------------------|-------------------------|----------------------------------------|
//! | `protocol`           | –                       | `udp` (or absent); others rejected     |
//! | `auth`               | `auth_str`              | plain string                           |
//! | `peer` (alias `sni`) | `tls.server_name`       |                                        |
//! | `insecure`           | `tls.insecure`          | `1` / `true`                           |
//! | `upmbps`/`downmbps`  | `up_mbps` / `down_mbps` | required, 1..=65535                    |
//! | `alpn`               | `tls.alpn`              | comma-separated                        |
//! | `obfs`, `obfsParam`  | `obfs`                  | `xplus` only; `obfsParam` is the secret |
//!
//! `protocol=faketcp` and `protocol=wechat-video` are not implemented by
//! sing-box and are rejected rather than silently downgraded to UDP. Unknown
//! parameters are ignored.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;

use crate::models::outbound::Hysteria;
use crate::models::shared::Tls;

use super::error::{LinkError, Result};
use super::params::{Params, Query};
use super::parts::{LinkUrl, build_link_encoded};
use super::{FromLink, ToLink};

const SCHEME: &str = "hysteria";
const OBFS_XPLUS: &str = "xplus";

impl FromLink for Hysteria {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, &[SCHEME])?;
        let p = &url.params;

        let server_port = url
            .port
            .filter(|port| *port != 0)
            .ok_or(LinkError::MissingField("port"))?;

        match p.get("protocol").map(str::to_ascii_lowercase).as_deref() {
            None | Some("udp") => {}
            Some(other) => return Err(LinkError::unsupported("protocol", other)),
        }

        let up_mbps = mbps_param(p, "upmbps")?;
        let down_mbps = mbps_param(p, "downmbps")?;

        let obfs = match (p.get("obfs"), p.get("obfsParam")) {
            (None, None) => String::new(),
            (Some(kind), _) if !kind.eq_ignore_ascii_case(OBFS_XPLUS) => {
                return Err(LinkError::unsupported("obfs", kind));
            }
            // `obfsParam` alone is accepted: xplus is the only mode there is.
            (_, Some(secret)) => secret.to_owned(),
            (Some(_), None) => return Err(LinkError::MissingField("obfsParam")),
        };

        let tls = Tls {
            enabled: true,
            server_name: p.get_any(&["peer", "sni"]).unwrap_or_default().to_owned(),
            alpn: p.list("alpn"),
            insecure: p.flag(&["insecure", "allowInsecure"]),
            ..Tls::default()
        };

        Ok(Hysteria {
            r#type: SCHEME.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            up_mbps,
            down_mbps,
            obfs,
            auth_str: p.get("auth").unwrap_or_default().to_owned(),
            tls: Some(tls),
            ..Hysteria::default()
        })
    }
}

impl ToLink for Hysteria {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }
        let up = bandwidth(self.up_mbps, &self.up, "up_mbps")?;
        let down = bandwidth(self.down_mbps, &self.down, "down_mbps")?;

        let mut q = Query::default();
        q.push("protocol", "udp");
        q.push_non_empty("auth", &self.auth_string()?);
        if let Some(tls) = self.tls.as_ref() {
            q.push_non_empty("peer", &tls.server_name);
            if tls.insecure {
                q.push("insecure", "1");
            }
        }
        q.push("upmbps", up.to_string());
        q.push("downmbps", down.to_string());
        if let Some(tls) = self.tls.as_ref().filter(|t| !t.alpn.is_empty()) {
            q.push("alpn", tls.alpn.join(","));
        }
        if !self.obfs.is_empty() {
            q.push("obfs", OBFS_XPLUS);
            q.push("obfsParam", self.obfs.as_str());
        }

        Ok(build_link_encoded(
            SCHEME,
            "",
            &self.server,
            self.server_port,
            &q,
            &self.tag,
        ))
    }
}

impl Hysteria {
    /// Auth payload as text: `auth_str`, or the decoded `auth`. Empty if
    /// neither is set.
    fn auth_string(&self) -> Result<String> {
        if !self.auth_str.is_empty() {
            return Ok(self.auth_str.clone());
        }
        if self.auth.is_empty() {
            return Ok(String::new());
        }
        let bytes = STANDARD
            .decode(self.auth.trim())
            .map_err(|_| LinkError::InvalidValue("auth"))?;
        // The link format carries text only.
        String::from_utf8(bytes).map_err(|_| LinkError::InvalidValue("auth"))
    }
}

/// A mandatory, positive Mbps parameter.
fn mbps_param(p: &Params, key: &'static str) -> Result<u16> {
    let raw = p.get(key).ok_or(LinkError::MissingField(key))?;
    raw.trim()
        .parse::<u16>()
        .ok()
        .filter(|v| *v != 0)
        .ok_or(LinkError::InvalidValue(key))
}

/// Resolves bandwidth to whole Mbps from `up_mbps` / `down_mbps` or, failing
/// that, the `"[Integer] [Unit]"` string form (`up` / `down`).
fn bandwidth(mbps: u16, text: &str, field: &'static str) -> Result<u16> {
    if mbps != 0 {
        return Ok(mbps);
    }
    if text.trim().is_empty() {
        return Err(LinkError::MissingField(field));
    }
    parse_bandwidth(text).ok_or(LinkError::InvalidValue(field))
}

/// Parses `"100 Mbps"`, `"1Gbps"`, `"12 MB/s"`, … into whole Mbps (rounded
/// up). Bit units are decimal, byte units binary. `None` for unknown units,
/// zero, or values that overflow `u16`.
fn parse_bandwidth(text: &str) -> Option<u16> {
    let text = text.trim();
    let split = text.find(|c: char| !c.is_ascii_digit())?;
    let (digits, unit) = text.split_at(split);
    let value: u64 = digits.parse().ok()?;
    let bits_per_second: u64 = match unit.trim() {
        "bps" => 1,
        "Kbps" => 1_000,
        "Mbps" => 1_000_000,
        "Gbps" => 1_000_000_000,
        "Tbps" => 1_000_000_000_000,
        "B/s" => 8,
        "KB/s" => 8 * 1024,
        "MB/s" => 8 * 1024 * 1024,
        "GB/s" => 8 * 1024 * 1024 * 1024,
        "TB/s" => 8 * 1024 * 1024 * 1024 * 1024,
        _ => return None,
    };
    let mbps = value.checked_mul(bits_per_second)?.div_ceil(1_000_000);
    u16::try_from(mbps).ok().filter(|v| *v != 0)
}
