//! `hysteria2://` ⇄ sing-box [`Hysteria2`] outbound.
//!
//! ```text
//! hysteria2://[auth@]host[:port[,port|a-b…]]/?[params][#name]      (alias: hy2://)
//! hysteria2+realm://<token>@<rendezvous-host>[:port]/<realm-name>?[params][#name]
//! hysteria2+realm+http://…                                          (plain-HTTP rendezvous)
//! ```
//!
//! This follows the official Hysteria 2 URI specification.
//!
//! * **auth** – the password. With `userpass` servers write `user:password`
//!   (sing-box has no separate field, so it is stored as `user:password` in
//!   `password`). In Realm links `userinfo` is the rendezvous *token* and the
//!   password moves to the `auth` query parameter.
//! * **port** – defaults to 443. A list such as `443,5000-6000` enables port
//!   hopping (`server_ports`, written as `5000:6000`); not allowed with Realm.
//! * **query** – `sni` (alias `peer`), `insecure` (alias `allowInsecure`),
//!   `obfs` (`salamander` | `gecko`) with `obfs-password`, `alpn` (tolerated).
//!   Realm adds `auth` and `stun` (repeatable).
//! * **non-standard** – `minPacketSize` / `maxPacketSize` (gecko only) are read
//!   and written the way 3x-ui exports them.
//!
//! Bandwidth (`up`, `down`, `upmbps`, …) is deliberately not part of the link:
//! the specification leaves it to local configuration, so those parameters are
//! ignored and sing-box falls back to BBR.
//!
//! Parameters that sing-box cannot express are rejected rather than dropped,
//! because dropping a pin or ECH config silently weakens the connection:
//! `pinSHA256` (a certificate fingerprint, unlike sing-box's public-key pin),
//! `ech`, and Realm's `lport`.

use url::Url;

use crate::models::outbound::{Hysteria2, Hysteria2Obfs, Hysteria2Realm};
use crate::models::shared::Tls;

use super::error::{LinkError, Result};
use super::params::{Params, Query};
use super::parts::{LinkUrl, build_link_raw, encode, encode_credentials, extract_port_spec};
use super::{FromLink, ToLink};

const TYPE: &str = "hysteria2";
const SCHEMES: &[&str] = &["hysteria2", "hy2"];
const REALM_SCHEME: &str = "hysteria2+realm";
const REALM_HTTP_SCHEME: &str = "hysteria2+realm+http";
const DEFAULT_PORT: u16 = 443;

/// sing-box requires STUN servers for Realm, while the link only lets one
/// *override* them. Used when the link has no `stun` parameter.
const DEFAULT_STUN_SERVERS: &[&str] = &["stun.l.google.com:19302", "stun.cloudflare.com:3478"];

const OBFS_SALAMANDER: &str = "salamander";
const OBFS_GECKO: &str = "gecko";

impl FromLink for Hysteria2 {
    fn from_link(link: &str) -> Result<Self> {
        // `url` cannot parse a port list, so take it out first.
        let (link, port_spec) = extract_port_spec(link.trim());
        let url = LinkUrl::parse(
            &link,
            &["hysteria2", "hy2", REALM_SCHEME, REALM_HTTP_SCHEME],
        )?;
        let p = &url.params;

        let tls = tls_from_params(p);
        let obfs = obfs_from_params(p)?;
        reject_unrepresentable(p)?;

        let mut outbound = Hysteria2 {
            r#type: TYPE.to_owned(),
            tag: url.tag.clone(),
            obfs,
            tls: Some(tls),
            ..Hysteria2::default()
        };

        if SCHEMES.contains(&url.scheme.as_str()) {
            // Direct connection.
            outbound.password = match &url.password {
                Some(password) => format!("{}:{password}", url.user),
                None => url.user.clone(),
            };
            outbound.server = url.host.clone();
            match port_spec {
                None => {
                    outbound.server_port = match url.port {
                        None => DEFAULT_PORT,
                        Some(0) => return Err(LinkError::InvalidValue("port")),
                        Some(port) => port,
                    };
                }
                Some(spec) => {
                    let ranges = parse_port_spec(&spec)?;
                    outbound.server_port = ranges[0].0;
                    outbound.server_ports = ranges.into_iter().map(format_range_sb).collect();
                }
            }
        } else {
            // Realm: rendezvous server + realm name.
            if port_spec.is_some() {
                return Err(LinkError::unsupported("port", "hopping with realm"));
            }
            if url.user.is_empty() {
                return Err(LinkError::MissingField("token"));
            }
            if url.path.is_empty() {
                return Err(LinkError::MissingField("realm_id"));
            }
            if url.port == Some(0) {
                return Err(LinkError::InvalidValue("port"));
            }
            let stun_servers: Vec<String> = match p.get_all("stun") {
                list if list.is_empty() => DEFAULT_STUN_SERVERS
                    .iter()
                    .map(|s| (*s).to_owned())
                    .collect(),
                list => list.into_iter().map(str::to_owned).collect(),
            };
            let http = url.scheme == REALM_HTTP_SCHEME;
            outbound.password = p.get("auth").unwrap_or_default().to_owned();
            outbound.realm = Some(Hysteria2Realm {
                server_url: format!(
                    "{}://{}{}",
                    if http { "http" } else { "https" },
                    url_host(&url.host),
                    url.port.map(|port| format!(":{port}")).unwrap_or_default()
                ),
                token: url.user.clone(),
                realm_id: url.path.clone(),
                stun_servers,
                ..Hysteria2Realm::default()
            });
        }
        Ok(outbound)
    }
}

impl ToLink for Hysteria2 {
    fn to_link(&self) -> Result<String> {
        let mut q = Query::default();

        if let Some(realm) = &self.realm {
            return self.realm_link(realm, q);
        }

        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        let port = if self.server_ports.is_empty() {
            if self.server_port == 0 {
                return Err(LinkError::MissingField("server_port"));
            }
            self.server_port.to_string()
        } else {
            self.server_ports
                .iter()
                .map(|item| parse_port_item(item).map(format_range_uri))
                .collect::<Result<Vec<_>>>()?
                .join(",")
        };

        self.write_common(&mut q)?;
        Ok(build_link_raw(
            "hysteria2",
            &self.userinfo(),
            &self.server,
            &port,
            "/",
            &q,
            &self.tag,
        ))
    }
}

impl Hysteria2 {
    /// `user:password` is written as two percent-encoded parts so that the
    /// link looks like the official `userpass` form; anything else is one token.
    fn userinfo(&self) -> String {
        match self.password.split_once(':') {
            Some((user, password)) if !user.is_empty() && !password.is_empty() => {
                encode_credentials(user, password)
            }
            _ => encode(&self.password),
        }
    }

    /// `insecure`, `obfs`, `obfs-password`, `minPacketSize`, `maxPacketSize`, `sni`.
    fn write_common(&self, q: &mut Query) -> Result<()> {
        if self.tls.as_ref().is_some_and(|t| t.insecure) {
            q.push("insecure", "1");
        }
        if let Some(obfs) = self.obfs.as_ref().filter(|o| !o.r#type.is_empty()) {
            match obfs.r#type.as_str() {
                OBFS_SALAMANDER | OBFS_GECKO => {}
                other => return Err(LinkError::unsupported("obfs", other)),
            }
            if obfs.password.is_empty() {
                return Err(LinkError::MissingField("obfs.password"));
            }
            q.push("obfs", obfs.r#type.as_str());
            q.push("obfs-password", obfs.password.as_str());
            if obfs.r#type == OBFS_GECKO {
                if obfs.min_packet_size != 0 {
                    q.push("minPacketSize", obfs.min_packet_size.to_string());
                }
                if obfs.max_packet_size != 0 {
                    q.push("maxPacketSize", obfs.max_packet_size.to_string());
                }
            }
        }
        if let Some(tls) = &self.tls {
            q.push_non_empty("sni", &tls.server_name);
            if !tls.alpn.is_empty() {
                q.push("alpn", tls.alpn.join(","));
            }
        }
        Ok(())
    }

    fn realm_link(&self, realm: &Hysteria2Realm, mut q: Query) -> Result<String> {
        if realm.token.is_empty() {
            return Err(LinkError::MissingField("realm.token"));
        }
        if realm.realm_id.is_empty() {
            return Err(LinkError::MissingField("realm.realm_id"));
        }
        let server_url = Url::parse(&realm.server_url)
            .map_err(|_| LinkError::InvalidValue("realm.server_url"))?;
        let scheme = match server_url.scheme() {
            "https" => REALM_SCHEME,
            "http" => REALM_HTTP_SCHEME,
            other => return Err(LinkError::unsupported("realm.server_url", other)),
        };
        let host = server_url
            .host_str()
            .filter(|h| !h.is_empty())
            .ok_or(LinkError::MissingField("realm.server_url"))?;
        // `Url::port` is already `None` for the scheme's default port.
        let port = server_url.port().map(|p| p.to_string()).unwrap_or_default();

        q.push_non_empty("auth", &self.password);
        self.write_common(&mut q)?;
        let is_default_stun = realm
            .stun_servers
            .iter()
            .map(String::as_str)
            .eq(DEFAULT_STUN_SERVERS.iter().copied());
        if !is_default_stun {
            for server in &realm.stun_servers {
                q.push("stun", server.as_str());
            }
        }

        Ok(build_link_raw(
            scheme,
            &encode(&realm.token),
            host,
            &port,
            &format!("/{}", encode(&realm.realm_id)),
            &q,
            &self.tag,
        ))
    }
}

/// `tls` for a Hysteria 2 link: always enabled (QUIC requires TLS).
fn tls_from_params(p: &Params) -> Tls {
    Tls {
        enabled: true,
        server_name: p.get_any(&["sni", "peer"]).unwrap_or_default().to_owned(),
        alpn: p.list("alpn"),
        insecure: p.flag(&["insecure", "allowInsecure"]),
        ..Tls::default()
    }
}

fn obfs_from_params(p: &Params) -> Result<Option<Hysteria2Obfs>> {
    let kind = match p.get("obfs") {
        None | Some("none") => return Ok(None),
        Some(k @ (OBFS_SALAMANDER | OBFS_GECKO)) => k,
        Some(other) => return Err(LinkError::unsupported("obfs", other)),
    };
    let password = p
        .get("obfs-password")
        .ok_or(LinkError::MissingField("obfs-password"))?
        .to_owned();

    let (mut min_packet_size, mut max_packet_size) = (0, 0);
    if kind == OBFS_GECKO {
        min_packet_size = packet_size(p, "minPacketSize")?;
        max_packet_size = packet_size(p, "maxPacketSize")?;
        if min_packet_size != 0 && max_packet_size != 0 && min_packet_size > max_packet_size {
            return Err(LinkError::InvalidValue("minPacketSize"));
        }
    }
    Ok(Some(Hysteria2Obfs {
        r#type: kind.to_owned(),
        password,
        min_packet_size,
        max_packet_size,
    }))
}

/// Optional packet size; `0` (sing-box default) when absent.
fn packet_size(p: &Params, key: &'static str) -> Result<u16> {
    match p.get(key) {
        None => Ok(0),
        Some(v) => v
            .parse::<u16>()
            .ok()
            .filter(|n| *n != 0)
            .ok_or(LinkError::InvalidValue(key)),
    }
}

/// Features that exist in the link format but have no sing-box counterpart.
fn reject_unrepresentable(p: &Params) -> Result<()> {
    for key in ["pinSHA256", "ech", "lport"] {
        if p.get(key).is_some() {
            return Err(LinkError::unsupported(key, "(present)"));
        }
    }
    Ok(())
}

/// Brackets IPv6 literals for use inside a URL.
fn url_host(host: &str) -> String {
    if host.contains(':') {
        format!("[{host}]")
    } else {
        host.to_owned()
    }
}

/// `443,5000-6000` → `[(443, 443), (5000, 6000)]`.
fn parse_port_spec(spec: &str) -> Result<Vec<(u16, u16)>> {
    let ranges = spec
        .split(',')
        .map(|item| parse_port_item(item.trim()))
        .collect::<Result<Vec<_>>>()?;
    if ranges.is_empty() {
        return Err(LinkError::InvalidValue("port"));
    }
    Ok(ranges)
}

/// One list item: `5000`, `5000-6000` (link style) or `5000:6000` (sing-box style).
fn parse_port_item(item: &str) -> Result<(u16, u16)> {
    let port = |s: &str| {
        s.trim()
            .parse::<u16>()
            .ok()
            .filter(|p| *p != 0)
            .ok_or(LinkError::InvalidValue("port"))
    };
    let (start, end) = match item.split_once(['-', ':']) {
        Some((start, end)) => (port(start)?, port(end)?),
        None => {
            let single = port(item)?;
            (single, single)
        }
    };
    if start > end {
        return Err(LinkError::InvalidValue("port"));
    }
    Ok((start, end))
}

/// sing-box `server_ports` entry: always `start:end`.
fn format_range_sb((start, end): (u16, u16)) -> String {
    format!("{start}:{end}")
}

/// Link style: `5000-6000`, or just `443` for a single port.
fn format_range_uri((start, end): (u16, u16)) -> String {
    if start == end {
        start.to_string()
    } else {
        format!("{start}-{end}")
    }
}
