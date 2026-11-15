//! `tuic://<uuid>:<password>@<host>:<port>?<params>#<remark>` ⇄ sing-box [`Tuic`] outbound.
//!
//! There is no official URI specification for TUIC; this follows the de facto
//! convention used by 3x-ui, Mihomo, sing-box and NekoBox for **TUIC v5**.
//!
//! * **userinfo** – `uuid:password`. Both parts are mandatory: the colon is a
//!   real delimiter, not part of an opaque token. v4 links (a single token) are
//!   therefore rejected. A password may contain `:` (only the first colon
//!   splits), and both parts are percent-encoded when written.
//! * **port** – defaults to 443 (QUIC, i.e. UDP).
//!
//! | Parameter                                              | Maps to               | Notes                              |
//! |--------------------------------------------------------|-----------------------|------------------------------------|
//! | `sni` (alias `peer`)                                   | `tls.server_name`     |                                    |
//! | `alpn`                                                 | `tls.alpn`            | comma-separated, usually `h3`      |
//! | `allow_insecure` (aliases `allowInsecure`, `insecure`, `skip-cert-verify`) | `tls.insecure` | `1` / `true`     |
//! | `congestion_control` (aliases `congestion-control`, `congestion_controller`) | `congestion_control` | `cubic`, `new_reno`, `bbr` |
//! | `udp_relay_mode` (alias `udp-relay-mode`)              | `udp_relay_mode`      | `native`, `quic`                   |
//! | `udp_over_stream` (alias `udp-over-stream`)            | `udp_over_stream`     | conflicts with `udp_relay_mode`    |
//! | `zero_rtt_handshake` (aliases `zero-rtt-handshake`, `reduce_rtt`) | `zero_rtt_handshake` | `1` / `true`      |
//! | `heartbeat`                                            | `heartbeat`           | duration such as `10s`             |
//!
//! TLS is always enabled (QUIC requires it), so `security` is neither read nor
//! written; Reality parameters (`pbk`, `sid`, …) are meaningless for TUIC and
//! ignored. When a parameter is absent the field stays empty and sing-box
//! applies its own default (`cubic`, `native`, `10s`).
//!
//! `disable_sni` is rejected when set: it is part of the link convention, but
//! dropping it would silently change the handshake. `udp_over_stream` together
//! with `udp_relay_mode` is rejected as well, since sing-box treats them as
//! mutually exclusive. Unknown parameters are ignored. `network`, QUIC window
//! tuning and dial fields cannot be expressed in a link.

use crate::models::outbound::Tuic;
use crate::models::shared::Tls;

use super::error::{LinkError, Result};
use super::params::{Params, Query};
use super::parts::{LinkUrl, build_link_encoded, encode_credentials, parse_uuid};
use super::{FromLink, ToLink};

const SCHEME: &str = "tuic";
const DEFAULT_PORT: u16 = 443;

const CONGESTION_CUBIC: &str = "cubic";
const CONGESTION_NEW_RENO: &str = "new_reno";
const CONGESTION_BBR: &str = "bbr";

const RELAY_NATIVE: &str = "native";
const RELAY_QUIC: &str = "quic";

impl FromLink for Tuic {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, &[SCHEME])?;
        let p = &url.params;

        if url.user.is_empty() {
            return Err(LinkError::MissingField("uuid"));
        }
        let uuid = parse_uuid(&url.user).ok_or(LinkError::InvalidValue("uuid"))?;

        // TUIC v5 needs both credentials; a lone token is a v4 link.
        let password = url
            .password
            .filter(|p| !p.is_empty())
            .ok_or(LinkError::MissingField("password"))?;

        let server_port = match url.port {
            None => DEFAULT_PORT,
            Some(0) => return Err(LinkError::InvalidValue("port")),
            Some(port) => port,
        };

        if p.flag(&["disable_sni", "disable-sni"]) {
            return Err(LinkError::unsupported("disable_sni", "1"));
        }

        let congestion_control = congestion_control_from_params(p)?;
        let udp_relay_mode = udp_relay_mode_from_params(p)?;
        let udp_over_stream = p.flag(&["udp_over_stream", "udp-over-stream"]);
        if udp_over_stream && !udp_relay_mode.is_empty() {
            return Err(LinkError::unsupported(
                "udp_over_stream",
                "together with udp_relay_mode",
            ));
        }

        let heartbeat = match p.get("heartbeat") {
            None => String::new(),
            Some(v) if is_duration(v) => v.to_owned(),
            Some(_) => return Err(LinkError::InvalidValue("heartbeat")),
        };

        Ok(Tuic {
            r#type: SCHEME.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            uuid,
            password,
            congestion_control,
            udp_relay_mode,
            udp_over_stream,
            zero_rtt_handshake: p.flag(&["zero_rtt_handshake", "zero-rtt-handshake", "reduce_rtt"]),
            heartbeat,
            tls: Some(tls_from_params(p)),
            ..Tuic::default()
        })
    }
}

impl ToLink for Tuic {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }
        if self.uuid.is_empty() {
            return Err(LinkError::MissingField("uuid"));
        }
        let uuid = parse_uuid(&self.uuid).ok_or(LinkError::InvalidValue("uuid"))?;
        if self.password.is_empty() {
            return Err(LinkError::MissingField("password"));
        }
        if self.udp_over_stream && !self.udp_relay_mode.is_empty() {
            return Err(LinkError::unsupported(
                "udp_over_stream",
                "together with udp_relay_mode",
            ));
        }

        let mut q = Query::default();

        if let Some(tls) = &self.tls {
            q.push_non_empty("sni", &tls.server_name);
            if !tls.alpn.is_empty() {
                q.push("alpn", tls.alpn.join(","));
            }
            if tls.insecure {
                q.push("allow_insecure", "1");
            }
        }
        q.push_non_empty("congestion_control", &self.congestion_control);
        q.push_non_empty("udp_relay_mode", &self.udp_relay_mode);
        if self.udp_over_stream {
            q.push("udp_over_stream", "1");
        }
        if self.zero_rtt_handshake {
            q.push("zero_rtt_handshake", "1");
        }
        q.push_non_empty("heartbeat", &self.heartbeat);

        Ok(build_link_encoded(
            SCHEME,
            &encode_credentials(&uuid, &self.password),
            &self.server,
            self.server_port,
            &q,
            &self.tag,
        ))
    }
}

/// `tls` for a TUIC link: always enabled (QUIC requires TLS).
fn tls_from_params(p: &Params) -> Tls {
    Tls {
        enabled: true,
        server_name: p.get_any(&["sni", "peer"]).unwrap_or_default().to_owned(),
        alpn: p.list("alpn"),
        insecure: p.flag(&[
            "allow_insecure",
            "allowInsecure",
            "insecure",
            "skip-cert-verify",
        ]),
        ..Tls::default()
    }
}

/// Normalised sing-box value, or empty when the link does not say.
fn congestion_control_from_params(p: &Params) -> Result<String> {
    let Some(value) = p.get_any(&[
        "congestion_control",
        "congestion-control",
        "congestion_controller",
    ]) else {
        return Ok(String::new());
    };
    match value.to_ascii_lowercase().as_str() {
        "cubic" => Ok(CONGESTION_CUBIC.to_owned()),
        "bbr" => Ok(CONGESTION_BBR.to_owned()),
        "new_reno" | "new-reno" | "newreno" => Ok(CONGESTION_NEW_RENO.to_owned()),
        _ => Err(LinkError::unsupported("congestion_control", value)),
    }
}

/// Normalised sing-box value, or empty when the link does not say.
fn udp_relay_mode_from_params(p: &Params) -> Result<String> {
    let Some(value) = p.get_any(&["udp_relay_mode", "udp-relay-mode"]) else {
        return Ok(String::new());
    };
    match value.to_ascii_lowercase().as_str() {
        "native" => Ok(RELAY_NATIVE.to_owned()),
        "quic" => Ok(RELAY_QUIC.to_owned()),
        _ => Err(LinkError::unsupported("udp_relay_mode", value)),
    }
}

/// Go-style duration: one or more `<number><unit>` segments, e.g. `10s`, `1m30s`.
fn is_duration(mut s: &str) -> bool {
    const UNITS: [&str; 7] = ["ns", "us", "µs", "ms", "s", "m", "h"];
    if s.is_empty() {
        return false;
    }
    while !s.is_empty() {
        let end = s
            .find(|c: char| !(c.is_ascii_digit() || c == '.'))
            .unwrap_or(s.len());
        if end == 0 || s[..end].parse::<f64>().is_err() {
            return false;
        }
        s = &s[end..];
        // "ms" must be tried before "m" and "s"; the order of UNITS ensures it.
        match UNITS.iter().find(|u| s.starts_with(**u)) {
            Some(unit) => s = &s[unit.len()..],
            None => return false,
        }
    }
    true
}
