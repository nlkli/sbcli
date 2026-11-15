//! Share-link parsing and generation for proxy outbounds.
//!
//! Each outbound type implements [`FromLink`] and/or [`ToLink`]. Shared logic
//! lives in private helper modules:
//!
//! * [`parts`]     – URL anatomy (user info, host, port, tag) and link assembly
//! * [`params`]    – reading and writing query parameters
//! * [`tls`]       – `security`/`sni`/`alpn`/`fp`/Reality parameters ⇄ `Tls`
//! * [`transport`] – `type`/`path`/`host`/… parameters ⇄ `V2RayTransport`
//!
//! To add a protocol: parse with `LinkUrl`, reuse `parse_tls` / `parse_transport`,
//! build the struct; and the reverse with `Query` and `build_link`.

mod anytls;
mod error;
mod http;
mod hysteria;
mod hysteria2;
mod naive;
mod params;
mod parts;
mod shadowsocks;
mod shadowtls;
mod socks;
mod ssh;
mod tls;
mod transport;
mod trojan;
mod tuic;
mod vless;
mod vmess;

pub use error::{LinkError, Result};

use crate::models::{
    AnyOutbound,
    outbound::{
        AnyTls, Http, Hysteria, Hysteria2, Naive, ShadowTls, Shadowsocks, Socks, Ssh, Trojan, Tuic,
        Vless, Vmess,
    },
};

/// Builds a value from a share link (e.g. `vless://…`).
pub trait FromLink: Sized {
    /// Parses `link`. Fails if malformed or if the link uses features the
    /// target type cannot express.
    fn from_link(link: &str) -> Result<Self>;
}

/// Serializes a value into a share link.
///
/// Fields a link cannot carry (multiplex, dial options, advanced TLS tuning, …)
/// are ignored.
pub trait ToLink {
    /// Returns the share link, or an error if required fields are missing.
    fn to_link(&self) -> Result<String>;
}

/// Parses a share link, dispatching on its scheme (case-insensitive).
///
/// Aliases such as `hy2` share an arm; add new protocols here.
pub fn parse_any_link(input: &str) -> Result<AnyOutbound> {
    let link = input.trim();
    let (scheme, _) = link.split_once("://").ok_or(LinkError::WrongScheme)?;
    match scheme.to_ascii_lowercase().as_str() {
        "vmess" | "vmess1" => Vmess::from_link(link).map(AnyOutbound::Vmess),
        "vless" => Vless::from_link(link).map(AnyOutbound::Vless),
        "ss" => Shadowsocks::from_link(link).map(AnyOutbound::Shadowsocks),
        "trojan" => Trojan::from_link(link).map(AnyOutbound::Trojan),
        "http" | "https" => Http::from_link(link).map(AnyOutbound::Http),
        "hysteria" => Hysteria::from_link(link).map(AnyOutbound::Hysteria),
        "hysteria2" | "hy2" | "hysteria2+realm" | "hysteria2+realm+http" => {
            Hysteria2::from_link(link).map(AnyOutbound::Hysteria2)
        }
        "socks" | "socks4" | "socks4a" | "socks5" | "socks5h" => {
            Socks::from_link(link).map(AnyOutbound::Socks)
        }
        "ssh" => Ssh::from_link(link).map(AnyOutbound::Ssh),
        "naive+https" | "naive+quic" => Naive::from_link(link).map(AnyOutbound::Naive),
        "shadowtls" | "shadow-tls" => ShadowTls::from_link(link).map(AnyOutbound::ShadowTls),
        "tuic" => Tuic::from_link(link).map(AnyOutbound::Tuic),
        "anytls" => AnyTls::from_link(link).map(AnyOutbound::AnyTls),
        other if other.len() <= 16 && other.bytes().all(|b| b.is_ascii_alphanumeric()) => {
            Err(LinkError::UnsupportedScheme(other.to_owned()))
        }
        _ => Err(LinkError::WrongScheme),
    }
}

/// Serializes [`AnyOutbound`] into its share link.
pub fn any_outbound_to_link(any: &AnyOutbound) -> Result<String> {
    any.to_link()
}

impl FromLink for AnyOutbound {
    fn from_link(link: &str) -> Result<Self> {
        parse_any_link(link)
    }
}

impl ToLink for AnyOutbound {
    fn to_link(&self) -> Result<String> {
        match self {
            Self::Vmess(o) => o.to_link(),
            Self::Vless(o) => o.to_link(),
            Self::Http(o) => o.to_link(),
            Self::Hysteria(o) => o.to_link(),
            Self::Hysteria2(o) => o.to_link(),
            Self::Naive(o) => o.to_link(),
            Self::Shadowsocks(o) => o.to_link(),
            Self::ShadowTls(o) => o.to_link(),
            Self::Socks(o) => o.to_link(),
            Self::Ssh(o) => o.to_link(),
            Self::Trojan(o) => o.to_link(),
            Self::Tuic(o) => o.to_link(),
            Self::AnyTls(o) => o.to_link(),
        }
    }
}
