//! `vless://<uuid>@<host>:<port>?<params>#<remark>` ⇄ sing-box [`Vless`] outbound.
//!
//! There is no official specification; this follows the Xray share-link
//! convention. Supported parameters: `encryption` (`none` only), `flow`
//! (`xtls-rprx-vision`), `security`, `sni`, `alpn`, `fp`, `allowInsecure`,
//! `pbk`, `sid`, `type`, `path`, `host`, `serviceName`, `packetEncoding`.
//! Unknown parameters are ignored.

use crate::models::outbound::Vless;

use super::error::{LinkError, Result};
use super::params::Query;
use super::parts::{LinkUrl, build_link, parse_uuid};
use super::tls::{Security, parse_tls, write_tls};
use super::transport::{parse_transport, write_transport};
use super::{FromLink, ToLink};

const SCHEME: &str = "vless";
const FLOW_VISION: &str = "xtls-rprx-vision";

impl FromLink for Vless {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, &[SCHEME])?;
        let p = &url.params;

        if url.user.is_empty() {
            return Err(LinkError::MissingField("uuid"));
        }
        let uuid = parse_uuid(&url.user).ok_or(LinkError::InvalidValue("uuid"))?;
        let server_port = url
            .port
            .filter(|port| *port != 0)
            .ok_or(LinkError::MissingField("port"))?;

        // VLESS Encryption (ML-KEM, …) is not supported by sing-box.
        if let Some(enc) = p.get("encryption").filter(|e| *e != "none") {
            return Err(LinkError::unsupported("encryption", enc));
        }
        let flow = match p.get("flow") {
            None | Some("none") => String::new(),
            Some(FLOW_VISION) => FLOW_VISION.to_owned(),
            Some(other) => return Err(LinkError::unsupported("flow", other)),
        };
        let packet_encoding = match p.get("packetEncoding") {
            Some(v @ ("xudp" | "packetaddr")) => v.to_owned(),
            _ => String::new(),
        };

        let tls = parse_tls(p, Security::None)?;
        let transport = parse_transport(p)?;

        Ok(Vless {
            r#type: SCHEME.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            uuid,
            flow,
            tls,
            transport,
            packet_encoding,
            ..Vless::default()
        })
    }
}

impl ToLink for Vless {
    fn to_link(&self) -> Result<String> {
        if self.uuid.is_empty() {
            return Err(LinkError::MissingField("uuid"));
        }
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }

        let mut q = Query::default();
        q.push("encryption", "none");
        q.push_non_empty("flow", &self.flow);
        let tls_enabled = self.tls.as_ref().is_some_and(|t| t.enabled);
        write_tls(self.tls.as_ref(), &mut q);
        write_transport(self.transport.as_ref(), tls_enabled, &mut q);
        q.push_non_empty("packetEncoding", &self.packet_encoding);

        Ok(build_link(
            SCHEME,
            &self.uuid,
            &self.server,
            self.server_port,
            &q,
            &self.tag,
        ))
    }
}
