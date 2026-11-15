//! `http://` / `https://` proxy URIs ⇄ sing-box [`Http`] outbound.
//!
//! `http://[user[:pass]@]host[:port][?params][#tag]` is a plain HTTP CONNECT
//! proxy; `https://…` is the same over TLS. No official spec exists — this
//! follows the curl/browser convention.
//!
//! * port defaults to 80 / 443;
//! * `https` enables TLS; `sni`, `alpn`, `fp`, `allowInsecure` tune it, while
//!   `security` is implied by the scheme (`none` and `reality` are rejected);
//! * `version` (`1`/`2`/`3`), `path`, and `host` (the `Host` header) map to
//!   the sing-box fields of the same name (non-standard);
//! * unknown params are ignored; extra headers, `disable_version_fallback`,
//!   HTTP/2 and QUIC tuning, and dial fields have no link representation.

use std::collections::HashMap;

use crate::models::outbound::Http;

use super::error::{LinkError, Result};
use super::params::Query;
use super::parts::{LinkUrl, build_link_encoded, encode_credentials};
use super::tls::{Security, parse_tls, write_tls_options};
use super::{FromLink, ToLink};

const TYPE: &str = "http";
const SCHEMES: &[&str] = &["http", "https"];

impl FromLink for Http {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, SCHEMES)?;
        let p = &url.params;

        let server_port = url
            .port
            .filter(|port| *port != 0)
            .ok_or(LinkError::MissingField("port"))?;

        let tls = if url.scheme == "https" {
            let tls = parse_tls(p, Security::Tls)?
                .ok_or_else(|| LinkError::unsupported("security", "none"))?;
            if tls.reality.is_some() {
                return Err(LinkError::unsupported("security", "reality"));
            }
            Some(tls)
        } else {
            None
        };

        let version = match p.get("version") {
            None => 0,
            Some("1") => 1,
            Some("2") => 2,
            Some("3") => 3,
            Some(other) => return Err(LinkError::unsupported("version", other)),
        };

        let mut headers = HashMap::new();
        if let Some(host) = p.get("host") {
            headers.insert("Host".to_owned(), host.to_owned());
        }

        Ok(Http {
            r#type: TYPE.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            username: url.user,
            password: url.password.unwrap_or_default(),
            path: p.get("path").unwrap_or_default().to_owned(),
            headers,
            version,
            tls,
            ..Http::default()
        })
    }
}

impl ToLink for Http {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }

        let tls = self.tls.as_ref().filter(|t| t.enabled);
        if tls.is_some_and(|t| t.reality.as_ref().is_some_and(|r| r.enabled)) {
            return Err(LinkError::unsupported("security", "reality"));
        }

        let mut q = Query::default();
        match self.version {
            0 => {}
            1..=3 => q.push("version", self.version.to_string()),
            other => return Err(LinkError::unsupported("version", &other.to_string())),
        }
        q.push_non_empty("path", &self.path);
        if let Some((_, host)) = self
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("host"))
        {
            q.push_non_empty("host", host);
        }
        if let Some(tls) = tls {
            write_tls_options(tls, &mut q);
        }

        Ok(build_link_encoded(
            if tls.is_some() { "https" } else { "http" },
            &encode_credentials(&self.username, &self.password),
            &self.server,
            self.server_port,
            &q,
            &self.tag,
        ))
    }
}
