//! `shadowtls://<password>@<host>:<port>?<params>#<remark>` ⇄ sing-box [`ShadowTls`] outbound.
//!
//! ShadowTLS has no official share-link specification. This follows the de-facto
//! `shadowtls://` scheme used by dae (v3 only), extended with a `version`
//! parameter so that v1/v2 outbounds can be expressed too. The password lives in
//! the user-info position and is percent-encoded. The port defaults to 443.
//!
//! The link describes **only** the ShadowTLS layer. It is not a complete proxy:
//! in sing-box it is meant to be used as a detour of an inner protocol
//! (typically Shadowsocks). The SIP003 form (`ss://…?plugin=shadow-tls;…`) is a
//! different thing: it would have to yield two outbounds from one link, so it is
//! not handled here.
//!
//! | Parameter                                  | Maps to              | Notes                                 |
//! |--------------------------------------------|----------------------|---------------------------------------|
//! | `version`                                  | `version`            | `1`, `2`, `3`; **defaults to `3`**    |
//! | `sni` (alias `peer`)                       | `tls.server_name`    | the handshake target (mask site)      |
//! | `alpn`                                     | `tls.alpn`           | comma-separated                       |
//! | `fp` (alias `utlsImitate`)                 | `tls.utls`           | e.g. `chrome`                         |
//! | `allowInsecure` (aliases `insecure`, `skip-cert-verify`) | `tls.insecure` | `1` / `true`                   |
//! | `tfo`                                      | `tcp_fast_open`      | `1` / `true`                          |
//!
//! * `version` defaults to `3` (not to sing-box's `1`): v3 is the current
//!   version and the only one the dae scheme knows. [`ToLink`] always writes it
//!   explicitly, so a link never depends on that default.
//! * v2/v3 require a password; v1 has none, so a password in a `version=1` link
//!   is rejected (and [`ToLink`] refuses to drop it) instead of being ignored.
//! * ShadowTLS always needs TLS: `security=none`, `security=reality` and any
//!   other value are rejected. `security=tls` is accepted but not written.
//! * `tlsImplementation` (dae) is ignored: a fingerprint, if present, always
//!   enables uTLS. Unknown parameters are ignored. Multiplex and the other dial
//!   fields cannot be expressed in a link.

use crate::models::outbound::ShadowTls;
use crate::models::shared::DialFields;

use super::error::{LinkError, Result};
use super::params::Query;
use super::parts::{LinkUrl, build_link};
use super::tls::{Security, parse_tls, write_tls_options};
use super::{FromLink, ToLink};

const SCHEME: &str = "shadowtls";
const SCHEME1: &str = "shadow-tls";
const DEFAULT_PORT: u16 = 443;
const DEFAULT_VERSION: u8 = 3;

impl FromLink for ShadowTls {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, &[SCHEME, SCHEME1])?;
        let p = &url.params;

        let version = match p.get("version") {
            None => DEFAULT_VERSION,
            Some("1") => 1,
            Some("2") => 2,
            Some("3") => 3,
            Some(other) => return Err(LinkError::unsupported("version", other)),
        };

        // A password containing an unescaped `:` is read by the URL parser as
        // `user:password`; ShadowTLS has no user name, so glue the halves back.
        let password = match url.password {
            Some(rest) => format!("{}:{rest}", url.user),
            None => url.user,
        };
        match (version, password.is_empty()) {
            (1, false) => return Err(LinkError::InvalidValue("password")),
            (2 | 3, true) => return Err(LinkError::MissingField("password")),
            _ => {}
        }

        let server_port = match url.port {
            None => DEFAULT_PORT,
            Some(0) => return Err(LinkError::InvalidValue("port")),
            Some(port) => port,
        };

        // TLS is mandatory and Reality makes no sense under ShadowTLS.
        match p.get("security") {
            None | Some("tls") => {}
            Some(other) => return Err(LinkError::unsupported("security", other)),
        }
        let tls = parse_tls(p, Security::Tls)?.ok_or(LinkError::MissingField("tls"))?;

        Ok(ShadowTls {
            r#type: SCHEME.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            version,
            password,
            tls: Some(tls),
            dial: DialFields {
                tcp_fast_open: p.flag(&["tfo"]),
                ..DialFields::default()
            },
            ..ShadowTls::default()
        })
    }
}

impl ToLink for ShadowTls {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }

        // `0` means "use the default" in sing-box, which is v1; make it explicit.
        let version = if self.version == 0 { 1 } else { self.version };
        match (version, self.password.is_empty()) {
            (1, false) => return Err(LinkError::InvalidValue("password")),
            (2 | 3, true) => return Err(LinkError::MissingField("password")),
            (1..=3, _) => {}
            _ => return Err(LinkError::unsupported("version", &version.to_string())),
        }

        let tls = self
            .tls
            .as_ref()
            .filter(|t| t.enabled)
            .ok_or(LinkError::MissingField("tls"))?;
        if tls.reality.as_ref().is_some_and(|r| r.enabled) {
            return Err(LinkError::unsupported("tls", "reality"));
        }

        let mut q = Query::default();
        q.push("version", version.to_string());
        write_tls_options(tls, &mut q);
        if self.dial.tcp_fast_open {
            q.push("tfo", "1");
        }

        Ok(build_link(
            SCHEME,
            &self.password,
            &self.server,
            self.server_port,
            &q,
            &self.tag,
        ))
    }
}
