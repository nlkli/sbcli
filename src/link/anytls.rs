//! `anytls://` ⇄ sing-box [`AnyTls`] outbound.
//!
//! ```text
//! anytls://[auth@]host[:port]/?[params][#name]
//! ```
//!
//! This follows the official AnyTLS URI specification (`anytls-go`), which
//! deliberately mirrors Hysteria 2's minimal design.
//!
//! * **auth** – the password, in the user-info position and percent-encoded.
//!   AnyTLS has no user name, so an unescaped `:` (read by the URL parser as
//!   `user:password`) is glued back into the password. Required, because
//!   sing-box's AnyTLS outbound needs a password.
//! * **port** – optional, defaults to 443.
//! * **query** – `sni` (alias `peer`) and `insecure` (`1` / `0`; alias
//!   `allowInsecure`). `alpn` is tolerated when reading but never written.
//! * **tag** – the percent-encoded fragment.
//!
//! TLS is always enabled: AnyTLS cannot run without it. When `sni` is an IP
//! address it is kept as the server name; Go's TLS stack does not send SNI for
//! IP literals, which is what the specification requires.
//!
//! Not part of the link, and therefore left at sing-box defaults: the padding
//! scheme (server-driven), `idle_session_check_interval`,
//! `idle_session_timeout`, `min_idle_session`, `client_metadata` and dial
//! fields. `client_id` (an `anytls-rs` panel extension) has no sing-box
//! counterpart and is ignored like any other unknown parameter.
//!
//! The standard URI cannot express Reality, so `security` other than `tls`
//! and `pbk` are rejected, as are `pinSHA256` and `ech`: dropping a pin or an
//! ECH config would silently weaken the connection.

use crate::models::outbound::AnyTls;
use crate::models::shared::{DialFields, Tls};

use super::error::{LinkError, Result};
use super::params::{Params, Query};
use super::parts::{LinkUrl, build_link_raw, encode};
use super::{FromLink, ToLink};

const SCHEME: &str = "anytls";
const DEFAULT_PORT: u16 = 443;

impl FromLink for AnyTls {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, &[SCHEME])?;
        let p = &url.params;

        // Same as Trojan/Hysteria2: no user name exists, so `a:b` is one password.
        let password = match url.password {
            Some(rest) => format!("{}:{rest}", url.user),
            None => url.user,
        };
        if password.is_empty() {
            return Err(LinkError::MissingField("password"));
        }

        let server_port = match url.port {
            None => DEFAULT_PORT,
            Some(0) => return Err(LinkError::InvalidValue("port")),
            Some(port) => port,
        };

        reject_unrepresentable(p)?;

        Ok(AnyTls {
            r#type: SCHEME.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            password,
            tls: Some(tls_from_params(p)),
            dial: DialFields::default(),
            ..AnyTls::default()
        })
    }
}

impl ToLink for AnyTls {
    fn to_link(&self) -> Result<String> {
        if self.password.is_empty() {
            return Err(LinkError::MissingField("password"));
        }
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }
        let tls = self
            .tls
            .as_ref()
            .filter(|t| t.enabled)
            .ok_or(LinkError::MissingField("tls"))?;
        if tls.reality.as_ref().is_some_and(|r| r.enabled) {
            return Err(LinkError::unsupported("tls.reality", "enabled"));
        }

        let mut q = Query::default();
        q.push_non_empty("sni", &tls.server_name);
        if tls.insecure {
            q.push("insecure", "1");
        }

        Ok(build_link_raw(
            SCHEME,
            &encode(&self.password),
            &self.server,
            &self.server_port.to_string(),
            "/",
            &q,
            &self.tag,
        ))
    }
}

/// `tls` for an AnyTLS link: always enabled.
fn tls_from_params(p: &Params) -> Tls {
    Tls {
        enabled: true,
        server_name: p.get_any(&["sni", "peer"]).unwrap_or_default().to_owned(),
        alpn: p.list("alpn"),
        insecure: p.flag(&["insecure", "allowInsecure"]),
        ..Tls::default()
    }
}

/// Features that cannot be expressed here and must not be silently dropped.
fn reject_unrepresentable(p: &Params) -> Result<()> {
    match p.get("security") {
        None | Some("tls") => {}
        Some(other) => return Err(LinkError::unsupported("security", other)),
    }
    for key in ["pbk", "pinSHA256", "ech"] {
        if p.get(key).is_some() {
            return Err(LinkError::unsupported(key, "(present)"));
        }
    }
    Ok(())
}
