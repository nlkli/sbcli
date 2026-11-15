//! `naive+https://` / `naive+quic://` ⇄ sing-box [`Naive`] outbound.
//!
//! ```text
//! naive+https://[userinfo@]host[:port][/][?params][#remark]     (HTTP/2 over TLS)
//! naive+quic://[userinfo@]host[:port][/][?params][#remark]      (HTTP/3)
//! ```
//!
//! NaiveProxy has no official URI specification; this follows the community
//! "DuckSoft" convention used by NaiveSharp, NekoBox, v2rayN and sing-box tools.
//!
//! * **userinfo** – the *first* `:` (before percent-decoding) decides:
//!   `pass@` is a password only, `user:@` a user name only, `user:pass@` both.
//!   Any further `:` belongs to the password. Both parts are percent-encoded.
//! * **port** – defaults to 443.
//! * **scheme** – `naive+quic` sets `quic`.
//!
//! | Parameter                 | Maps to                   | Notes                                        |
//! |---------------------------|---------------------------|----------------------------------------------|
//! | `sni` (alias `peer`)      | `tls.server_name`         |                                              |
//! | `extra-headers`           | `extra_headers`           | `K: V\r\nK2: V2`, percent-encoded            |
//! | `quic_congestion_control` | `quic_congestion_control` | `bbr`, `bbr2`, `cubic`, `reno`; QUIC only    |
//!
//! sing-box's Naive TLS supports only `server_name`, `certificate`,
//! `certificate_path` and `ech`. Parameters that would *weaken* verification or
//! select an unsupported security layer (`insecure`/`allowInsecure`,
//! `security` other than `tls`, Reality's `pbk`) are rejected instead of being
//! dropped. Harmless leftovers (`alpn`, `fp`, `padding`, unknown keys) are
//! ignored. `insecure_concurrency`, window sizes, UDP-over-TCP, certificates
//! and dial fields cannot be expressed in a link.

use std::collections::BTreeMap;

use crate::models::outbound::Naive;
use crate::models::shared::Tls;

use super::error::{LinkError, Result};
use super::params::{Params, Query};
use super::parts::{LinkUrl, build_link_raw, decode, encode};
use super::{FromLink, ToLink};

const TYPE: &str = "naive";
const SCHEME_HTTPS: &str = "naive+https";
const SCHEME_QUIC: &str = "naive+quic";
const DEFAULT_PORT: u16 = 443;
const CONGESTION_CONTROLS: &[&str] = &["bbr", "bbr2", "cubic", "reno"];

impl FromLink for Naive {
    fn from_link(link: &str) -> Result<Self> {
        let link = link.trim();
        let url = LinkUrl::parse(link, &[SCHEME_HTTPS, SCHEME_QUIC])?;
        let p = &url.params;

        // `url` drops an empty password and cannot tell `user:@` from `user@`,
        // so the user info is split from the raw link instead.
        let (username, password) = parse_credentials(raw_userinfo(link))?;

        // Non-special schemes have no known default port.
        let server_port = match url.port {
            None => DEFAULT_PORT,
            Some(0) => return Err(LinkError::InvalidValue("port")),
            Some(port) => port,
        };

        reject_unsupported(p)?;

        let quic = url.scheme == SCHEME_QUIC;
        let quic_congestion_control = match p.get("quic_congestion_control") {
            // Meaningless over HTTP/2; ignore rather than fail.
            _ if !quic => String::new(),
            None => String::new(),
            Some(cc) if CONGESTION_CONTROLS.contains(&cc) => cc.to_owned(),
            Some(other) => {
                return Err(LinkError::unsupported("quic_congestion_control", other));
            }
        };

        let extra_headers = match p.get("extra-headers") {
            Some(raw) => parse_extra_headers(raw)?,
            None => BTreeMap::new(),
        };

        Ok(Naive {
            r#type: TYPE.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            username,
            password,
            extra_headers,
            quic,
            quic_congestion_control,
            // Naive always runs over TLS and requires a TLS block.
            tls: Some(Tls {
                enabled: true,
                server_name: p.get_any(&["sni", "peer"]).unwrap_or_default().to_owned(),
                ..Tls::default()
            }),
            ..Naive::default()
        })
    }
}

impl ToLink for Naive {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }
        if !self.quic_congestion_control.is_empty()
            && !CONGESTION_CONTROLS.contains(&self.quic_congestion_control.as_str())
        {
            return Err(LinkError::unsupported(
                "quic_congestion_control",
                &self.quic_congestion_control,
            ));
        }

        let mut q = Query::default();
        if let Some(tls) = &self.tls {
            q.push_non_empty("sni", &tls.server_name);
        }
        if !self.extra_headers.is_empty() {
            q.push("extra-headers", write_extra_headers(&self.extra_headers)?);
        }
        if self.quic {
            q.push_non_empty("quic_congestion_control", &self.quic_congestion_control);
        }

        Ok(build_link_raw(
            if self.quic { SCHEME_QUIC } else { SCHEME_HTTPS },
            &encode_userinfo(&self.username, &self.password),
            &self.server,
            &self.server_port.to_string(),
            if q.is_empty() { "" } else { "/" },
            &q,
            &self.tag,
        ))
    }
}

/// The percent-encoded text between `://` and the last `@` of the authority.
fn raw_userinfo(link: &str) -> Option<&str> {
    let rest = &link[link.find("://")? + 3..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    authority.rfind('@').map(|i| &authority[..i])
}

/// DuckSoft semantics: split on the first `:` *before* decoding.
fn parse_credentials(raw: Option<&str>) -> Result<(String, String)> {
    let Some(raw) = raw else {
        return Ok((String::new(), String::new()));
    };
    match raw.split_once(':') {
        None => Ok((String::new(), decode(raw, "password")?)),
        Some((user, pass)) => Ok((decode(user, "username")?, decode(pass, "password")?)),
    }
}

/// Inverse of [`parse_credentials`]. Unlike `encode_credentials`, a user name
/// without a password is written as `user:` so it is not read back as a password.
fn encode_userinfo(username: &str, password: &str) -> String {
    match (username.is_empty(), password.is_empty()) {
        (true, true) => String::new(),
        (true, false) => encode(password),
        (false, true) => format!("{}:", encode(username)),
        (false, false) => format!("{}:{}", encode(username), encode(password)),
    }
}

fn reject_unsupported(p: &Params) -> Result<()> {
    if p.flag(&["allowInsecure", "insecure", "skip-cert-verify"]) {
        return Err(LinkError::unsupported("insecure", "1"));
    }
    if let Some(security) = p.get("security").filter(|s| *s != "tls") {
        return Err(LinkError::unsupported("security", security));
    }
    if p.get("pbk").is_some() {
        return Err(LinkError::unsupported("security", "reality"));
    }
    Ok(())
}

/// `K: V` lines separated by `\r\n` (a bare `\n` is tolerated).
fn parse_extra_headers(raw: &str) -> Result<BTreeMap<String, String>> {
    let mut headers = BTreeMap::new();
    for line in raw.lines().map(str::trim).filter(|l| !l.is_empty()) {
        let (name, value) = line
            .split_once(':')
            .ok_or(LinkError::InvalidValue("extra-headers"))?;
        let name = name.trim();
        if name.is_empty() {
            return Err(LinkError::InvalidValue("extra-headers"));
        }
        headers.insert(name.to_owned(), value.trim().to_owned());
    }
    Ok(headers)
}

/// Refuses names/values that would break the `K: V\r\n…` framing (header injection).
fn write_extra_headers(headers: &BTreeMap<String, String>) -> Result<String> {
    let bad = |s: &str| s.contains(['\r', '\n']);
    let mut lines = Vec::with_capacity(headers.len());
    for (name, value) in headers {
        if name.is_empty() || name.contains(':') || bad(name) || bad(value) {
            return Err(LinkError::InvalidValue("extra_headers"));
        }
        lines.push(format!("{name}: {value}"));
    }
    Ok(lines.join("\r\n"))
}
