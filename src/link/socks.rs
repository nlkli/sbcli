//! `socks5://[user[:pass]@]host[:port][?params][#tag]` ⇄ sing-box [`Socks`] outbound.
//!
//! No official spec exists — this follows the curl/browser convention.
//!
//! | Scheme                       | `version` | Remote DNS |
//! |------------------------------|-----------|------------|
//! | `socks`, `socks5`, `socks5h` | `5`       | yes        |
//! | `socks4`                     | `4`       | no         |
//! | `socks4a`                    | `4a`      | yes        |
//!
//! * port defaults to 1080;
//! * SOCKS4 carries only a user id, so a password in a `socks4`/`socks4a` link
//!   is rejected (and dropped by [`ToLink`]);
//! * the only supported parameter is `network` (`tcp` or `udp`, non-standard);
//!   unknown parameters are ignored;
//! * `udp_over_tcp` and dial fields have no link representation.

use crate::models::outbound::Socks;

use super::error::{LinkError, Result};
use super::params::Query;
use super::parts::{LinkUrl, build_link_encoded, encode_credentials};
use super::{FromLink, ToLink};

const TYPE: &str = "socks";
const SCHEMES: &[&str] = &["socks", "socks4", "socks4a", "socks5", "socks5h"];
const DEFAULT_PORT: u16 = 1080;

impl FromLink for Socks {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, SCHEMES)?;

        let version = match url.scheme.as_str() {
            "socks4" => "4",
            "socks4a" => "4a",
            _ => "5",
        };
        let password = url.password.unwrap_or_default();
        if version != "5" && !password.is_empty() {
            return Err(LinkError::InvalidValue("password"));
        }
        let server_port = match url.port {
            None => DEFAULT_PORT,
            Some(0) => return Err(LinkError::InvalidValue("port")),
            Some(port) => port,
        };
        let network = match url.params.get("network") {
            None => String::new(),
            Some(n @ ("tcp" | "udp")) => n.to_owned(),
            Some(other) => return Err(LinkError::unsupported("network", other)),
        };

        Ok(Socks {
            r#type: TYPE.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            version: version.to_owned(),
            username: url.user,
            password,
            network,
            ..Socks::default()
        })
    }
}

impl ToLink for Socks {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }

        let (scheme, with_password) = match self.version.as_str() {
            "" | "5" => ("socks5", true),
            "4" => ("socks4", false),
            "4a" => ("socks4a", false),
            other => return Err(LinkError::unsupported("version", other)),
        };
        let password = if with_password {
            self.password.as_str()
        } else {
            ""
        };

        let mut q = Query::default();
        q.push_non_empty("network", &self.network);

        Ok(build_link_encoded(
            scheme,
            &encode_credentials(&self.username, password),
            &self.server,
            self.server_port,
            &q,
            &self.tag,
        ))
    }
}
