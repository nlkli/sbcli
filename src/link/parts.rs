//! URL anatomy shared by all share links: `scheme://user[:pass]@host:port?query#tag`.

use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, percent_decode_str, utf8_percent_encode};
use url::{Host, Url};

use super::error::{LinkError, Result};
use super::params::{Params, Query};

/// RFC 3986 "unreserved" characters are kept, everything else is percent-encoded.
const ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'.')
    .remove(b'_')
    .remove(b'~');

pub(crate) fn encode(s: &str) -> String {
    utf8_percent_encode(s, ENCODE_SET).to_string()
}

pub(crate) fn decode(s: &str, field: &'static str) -> Result<String> {
    percent_decode_str(s)
        .decode_utf8()
        .map(|c| c.into_owned())
        .map_err(|_| LinkError::InvalidValue(field))
}

/// A share link split into its generic parts. Protocol modules interpret them.
pub(crate) struct LinkUrl {
    /// Lowercase URL scheme (one of the `schemes` passed to [`LinkUrl::parse`]).
    pub scheme: String,
    /// Percent-decoded user name (UUID, password, …); empty if absent.
    pub user: String,
    /// Percent-decoded password, if the link has `user:password@`.
    pub password: Option<String>,
    /// Host without IPv6 brackets.
    pub host: String,
    /// Explicit port, or the scheme's well-known default for special schemes
    /// (`http` → 80, `https` → 443), since the `url` crate drops default ports.
    pub port: Option<u16>,
    /// Percent-decoded path without the leading `/`; empty for `host/` or `host`.
    pub path: String,
    pub params: Params,
    /// Percent-decoded fragment (the human-readable remark), may be empty.
    pub tag: String,
}

impl LinkUrl {
    /// Parses `link`, requiring one of `schemes` (e.g. `["hysteria2", "hy2"]`).
    pub(crate) fn parse(link: &str, schemes: &[&str]) -> Result<Self> {
        let url = Url::parse(link.trim())?;
        if !schemes.contains(&url.scheme()) {
            return Err(LinkError::WrongScheme);
        }

        // Non-special schemes use "opaque" hosts: the domain stays percent-encoded.
        let host = match url.host() {
            Some(Host::Domain(d)) => decode(d, "host")?,
            Some(Host::Ipv4(ip)) => ip.to_string(),
            Some(Host::Ipv6(ip)) => ip.to_string(),
            None => String::new(),
        };
        if host.is_empty() {
            return Err(LinkError::MissingField("host"));
        }

        Ok(Self {
            scheme: url.scheme().to_owned(),
            user: decode(url.username(), "user")?,
            password: url.password().map(|p| decode(p, "password")).transpose()?,
            host,
            port: url.port_or_known_default(),
            path: decode(url.path(), "path")?
                .trim_start_matches('/')
                .to_owned(),
            params: Params::from_url(&url),
            tag: url
                .fragment()
                .map(|f| percent_decode_str(f).decode_utf8_lossy().into_owned())
                .unwrap_or_default(),
        })
    }
}

/// Assembles `scheme://userinfo@host:port?query#tag`.
///
/// `userinfo`, `query` and `tag` are omitted when empty; IPv6 hosts are
/// bracketed; everything is percent-encoded as needed. `userinfo` is encoded
/// as a single opaque token (UUID, password, …); for `user:password` use
/// [`encode_credentials`] with [`build_link_encoded`].
pub(crate) fn build_link(
    scheme: &str,
    userinfo: &str,
    server: &str,
    port: u16,
    query: &Query,
    tag: &str,
) -> String {
    build_link_encoded(scheme, &encode(userinfo), server, port, query, tag)
}

/// `user[:password]`, each part percent-encoded separately so that a `:` or
/// `@` inside them cannot be mistaken for a delimiter. Empty if both are empty.
pub(crate) fn encode_credentials(user: &str, password: &str) -> String {
    match (user.is_empty(), password.is_empty()) {
        (true, true) => String::new(),
        (_, true) => encode(user),
        _ => format!("{}:{}", encode(user), encode(password)),
    }
}

/// Like [`build_link`], but `userinfo` is already percent-encoded.
pub(crate) fn build_link_encoded(
    scheme: &str,
    userinfo: &str,
    server: &str,
    port: u16,
    query: &Query,
    tag: &str,
) -> String {
    build_link_raw(scheme, userinfo, server, &port.to_string(), "", query, tag)
}

/// The most general assembler: `scheme://userinfo@host[:port][/path][?query][#tag]`.
///
/// `userinfo` is already percent-encoded. `port` is inserted verbatim (so it
/// may be a port-hopping list such as `443,5000-6000`) and omitted when empty.
/// `path` is inserted verbatim: it must be empty or start with `/` and be
/// percent-encoded already.
pub(crate) fn build_link_raw(
    scheme: &str,
    userinfo: &str,
    server: &str,
    port: &str,
    path: &str,
    query: &Query,
    tag: &str,
) -> String {
    let mut link = format!("{scheme}://");
    if !userinfo.is_empty() {
        link.push_str(userinfo);
        link.push('@');
    }

    let bare = server.trim_start_matches('[').trim_end_matches(']');
    if bare.contains(':') {
        link.push_str(&format!("[{bare}]"));
    } else {
        link.push_str(&encode(bare));
    }
    if !port.is_empty() {
        link.push(':');
        link.push_str(port);
    }

    link.push_str(path);
    if !query.is_empty() {
        link.push('?');
        link.push_str(&query.encode());
    }
    if !tag.is_empty() {
        link.push('#');
        link.push_str(&encode(tag));
    }
    link
}

/// Splits a port-hopping list (`host:443,5000-6000`) out of a link.
///
/// The `url` crate rejects such a port. This returns the link with the list
/// replaced by its first port (so it can go through [`LinkUrl::parse`]) and
/// the raw list. Links with an ordinary port, or none, are returned unchanged
/// with `None`.
pub(crate) fn extract_port_spec(link: &str) -> (String, Option<String>) {
    let unchanged = || (link.to_owned(), None);
    let Some(start) = link.find("://").map(|i| i + 3) else {
        return unchanged();
    };
    let rest = &link[start..];
    let end = rest.find(['/', '?', '#']).unwrap_or(rest.len());
    let authority = &rest[..end];
    // Credentials are percent-encoded, so the last `@` ends the userinfo.
    let host_start = authority.rfind('@').map_or(0, |i| i + 1);
    let host_port = &authority[host_start..];
    let colon = match host_port.rfind(']') {
        Some(bracket) => host_port[bracket..].find(':').map(|i| bracket + i),
        None => host_port.rfind(':'),
    };
    let Some(colon) = colon else {
        return unchanged();
    };
    let spec = &host_port[colon + 1..];
    if !spec.contains([',', '-']) {
        return unchanged();
    }
    let first = spec
        .split([',', '-'])
        .next()
        .unwrap_or_default();
    let cut = start + host_start + colon + 1;
    (
        format!("{}{}{}", &link[..cut], first, &link[start + end..]),
        Some(spec.to_owned()),
    )
}

/// Parses a UUID in any common textual form (hyphenated, bare hex, braced,
/// URN) and returns it in the canonical lowercase hyphenated form.
pub(crate) fn parse_uuid(s: &str) -> Option<String> {
    uuid::Uuid::parse_str(s)
        .ok()
        .map(|u| u.hyphenated().to_string())
}

/// Xray's mapping of a custom user id (up to 30 bytes) to a UUID: UUIDv5 in
/// the nil namespace. Lets links with non-UUID ids work in sing-box.
pub(crate) fn custom_id_to_uuid(id: &str) -> String {
    uuid::Uuid::new_v5(&uuid::Uuid::nil(), id.as_bytes())
        .hyphenated()
        .to_string()
}
