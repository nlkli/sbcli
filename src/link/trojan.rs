//! `trojan://<password>@<host>:<port>?<params>#<remark>` ⇄ sing-box [`Trojan`] outbound.
//!
//! There is no official specification; this follows the Xray/V2Ray share-link
//! convention. The password lives in the user-info position and is
//! percent-encoded. The port defaults to 443.
//!
//! | Parameter                         | Maps to                         | Notes                                   |
//! |-----------------------------------|---------------------------------|-----------------------------------------|
//! | `security`                        | `tls`                           | `tls` (default), `reality`, `none`      |
//! | `sni` (alias `peer`)              | `tls.server_name`               |                                         |
//! | `alpn`                            | `tls.alpn`                      | comma-separated                         |
//! | `allowInsecure` (aliases `insecure`, `skip-cert-verify`) | `tls.insecure` | `1` / `true`             |
//! | `fp`, `pbk`, `sid`                | `tls.utls` / `tls.reality`      | see [`super::tls`]                      |
//! | `type` (alias `network`)          | `transport`                     | `tcp`, `ws`, `grpc`, `http`, `httpupgrade`, `quic` |
//! | `host`, `path`, `serviceName`, …  | `transport`                     | see [`super::transport`]                |
//! | `tfo`                             | `tcp_fast_open`                 | `1` / `true`                            |
//!
//! `security=xtls` and `flow` are rejected: sing-box's Trojan has neither, so
//! ignoring them would silently yield an outbound that cannot connect.
//! Unknown parameters are ignored. Multiplex, `network` (tcp/udp) and the other
//! dial fields cannot be expressed in a link.

use crate::models::outbound::Trojan;
use crate::models::shared::DialFields;

use super::error::{LinkError, Result};
use super::params::Query;
use super::parts::{LinkUrl, build_link};
use super::tls::{Security, parse_tls, write_tls};
use super::transport::{parse_transport, write_transport};
use super::{FromLink, ToLink};

const SCHEME: &str = "trojan";
const DEFAULT_PORT: u16 = 443;

impl FromLink for Trojan {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, &[SCHEME])?;
        let p = &url.params;

        // A password containing an unescaped `:` is read by the URL parser as
        // `user:password`; Trojan has no user name, so glue the halves back.
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

        // XTLS (`security=xtls`) is rejected by `parse_tls`; `flow` is only
        // meaningful together with it.
        if let Some(flow) = p.get("flow").filter(|f| *f != "none") {
            return Err(LinkError::unsupported("flow", flow));
        }

        let tls = parse_tls(p, Security::Tls)?;
        let transport = parse_transport(p)?;

        Ok(Trojan {
            r#type: SCHEME.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            password,
            tls,
            transport,
            dial: DialFields {
                tcp_fast_open: p.flag(&["tfo"]),
                ..DialFields::default()
            },
            ..Trojan::default()
        })
    }
}

impl ToLink for Trojan {
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

        let mut q = Query::default();
        let tls_enabled = self.tls.as_ref().is_some_and(|t| t.enabled);
        write_tls(self.tls.as_ref(), &mut q);
        write_transport(self.transport.as_ref(), tls_enabled, &mut q);
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
