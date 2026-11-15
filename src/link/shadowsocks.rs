//! `ss://…` share links ⇄ sing-box `Shadowsocks` outbound.
//!
//! Formats: SIP002 Base64URL userinfo, SIP002 plaintext (mandatory for `2022-…`),
//! and legacy Base64 payload. [`ToLink`] writes plaintext for `2022-…`, Base64 otherwise.
//!
//! Lenient parsing: standard/URL-safe Base64, any padding, whitespace ignored,
//! optional trailing `/`, `chacha20-poly1305` → `chacha20-ietf-poly1305`.
//!
//! `plugin` → `plugin`/`plugin_opts`; only `obfs-local` (alias `simple-obfs`) and
//! `v2ray-plugin` are supported. Unknown plugins/methods are rejected. Other query
//! params (incl. Xray `security`/`sni`/`type`) are ignored. `udp_over_tcp`,
//! `multiplex` and dial fields cannot be expressed in a link.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, URL_SAFE_NO_PAD};
use percent_encoding::percent_decode_str;

use crate::models::outbound::Shadowsocks;

use super::error::{LinkError, Result};
use super::params::Query;
use super::parts::{build_link_encoded, decode, encode_credentials};
use super::{FromLink, ToLink};

const TYPE: &str = "shadowsocks";
const PREFIX: &str = "ss://";

/// Ciphers supported by sing-box.
const METHODS: &[&str] = &[
    "none",
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-192-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
    "aes-128-ctr",
    "aes-192-ctr",
    "aes-256-ctr",
    "aes-128-cfb",
    "aes-192-cfb",
    "aes-256-cfb",
    "rc4-md5",
    "chacha20-ietf",
    "xchacha20",
];

/// Any padding, non-canonical trailing bits allowed; URL-safe mapped to standard.
const DECODER: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

impl FromLink for Shadowsocks {
    fn from_link(link: &str) -> Result<Self> {
        let rest = strip_scheme(link.trim())?;
        let (body, fragment) = rest
            .split_once('#')
            .map_or((rest, None), |(b, f)| (b, Some(f)));
        let (body, query) = body
            .split_once('?')
            .map_or((body, None), |(b, q)| (b, Some(q)));
        let body = body.trim_end_matches('/');

        // Base64 never contains `@`: SIP002 vs legacy.
        let (method, password, server, server_port) =
            if let Some((userinfo, hostport)) = body.rsplit_once('@') {
                let (method, password) = parse_userinfo(userinfo)?;
                let (server, port) = parse_host_port(hostport)?;
                (method, password, server, port)
            } else {
                let decoded = decode_base64(body, "payload")?;
                let (userinfo, hostport) = decoded
                    .rsplit_once('@')
                    .ok_or(LinkError::InvalidValue("payload"))?;
                let (method, password) = userinfo
                    .split_once(':')
                    .ok_or(LinkError::InvalidValue("payload"))?;
                let (server, port) = parse_host_port(hostport)?;
                (method.to_owned(), password.to_owned(), server, port)
            };

        let method = normalize_method(&method)?;
        if password.is_empty() && method != "none" {
            return Err(LinkError::MissingField("password"));
        }
        let (plugin, plugin_opts) = parse_plugin(query)?;
        let tag = fragment
            .map(|f| percent_decode_str(f).decode_utf8_lossy().into_owned())
            .unwrap_or_default();

        Ok(Shadowsocks {
            r#type: TYPE.to_owned(),
            tag,
            server,
            server_port,
            method,
            password,
            plugin,
            plugin_opts,
            ..Shadowsocks::default()
        })
    }
}

impl ToLink for Shadowsocks {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        if self.server_port == 0 {
            return Err(LinkError::MissingField("server_port"));
        }
        if self.method.is_empty() {
            return Err(LinkError::MissingField("method"));
        }
        if self.password.is_empty() && self.method != "none" {
            return Err(LinkError::MissingField("password"));
        }

        // SIP022: plaintext percent-encoded userinfo for `2022-…`.
        let userinfo = if self.method.starts_with("2022-") {
            encode_credentials(&self.method, &self.password)
        } else {
            URL_SAFE_NO_PAD.encode(format!("{}:{}", self.method, self.password))
        };

        let mut q = Query::default();
        if !self.plugin.is_empty() {
            let value = if self.plugin_opts.is_empty() {
                self.plugin.clone()
            } else {
                format!("{};{}", self.plugin, self.plugin_opts)
            };
            q.push("plugin", value);
        }

        let link = build_link_encoded(
            "ss",
            &userinfo,
            &self.server,
            self.server_port,
            &q,
            &self.tag,
        );
        // SIP002: `/` between port and query (first `?` is the delimiter).
        Ok(if q.is_empty() {
            link
        } else {
            link.replacen('?', "/?", 1)
        })
    }
}

/// Strips case-insensitive `ss://`.
fn strip_scheme(link: &str) -> Result<&str> {
    link.get(..PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
        .map(|_| &link[PREFIX.len()..])
        .ok_or(LinkError::WrongScheme)
}

/// SIP002 userinfo → `(method, password)`. `:` → plaintext (percent-encoded
/// parts, decoded separately so `%3A` in password is safe); else Base64 of
/// `method:password`. Only first `:` splits: AEAD-2022 may be `iPSK:uPSK`.
fn parse_userinfo(userinfo: &str) -> Result<(String, String)> {
    if let Some((method, password)) = userinfo.split_once(':') {
        Ok((decode(method, "method")?, decode(password, "password")?))
    } else {
        let decoded = decode_base64(userinfo, "userinfo")?;
        decoded
            .split_once(':')
            .map(|(m, p)| (m.to_owned(), p.to_owned()))
            .ok_or(LinkError::InvalidValue("userinfo"))
    }
}

/// `host:port` or `[ipv6]:port` → host (no brackets), non-zero port.
fn parse_host_port(s: &str) -> Result<(String, u16)> {
    let s = s.trim();
    let (host, port) = if let Some(rest) = s.strip_prefix('[') {
        let (host, after) = rest
            .split_once(']')
            .ok_or(LinkError::InvalidValue("host"))?;
        let port = after
            .strip_prefix(':')
            .ok_or(LinkError::MissingField("port"))?;
        (host.to_owned(), port)
    } else {
        let (host, port) = s.rsplit_once(':').ok_or(LinkError::MissingField("port"))?;
        (decode(host, "host")?, port)
    };
    if host.is_empty() {
        return Err(LinkError::MissingField("host"));
    }
    let port = port
        .parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(LinkError::InvalidValue("port"))?;
    Ok((host, port))
}

fn normalize_method(raw: &str) -> Result<String> {
    let method = raw.trim().to_ascii_lowercase();
    if method.is_empty() {
        return Err(LinkError::MissingField("method"));
    }
    let method = match method.as_str() {
        // Pre-SIP004 name of the IETF variant.
        "chacha20-poly1305" => "chacha20-ietf-poly1305".to_owned(),
        _ => method,
    };
    if METHODS.contains(&method.as_str()) {
        Ok(method)
    } else {
        Err(LinkError::unsupported("method", &method))
    }
}

/// `plugin=name;opts` → `(plugin, plugin_opts)`; opts passed verbatim.
fn parse_plugin(query: Option<&str>) -> Result<(String, String)> {
    let mut value = None;
    for pair in query.unwrap_or_default().split('&') {
        if let Some(("plugin", raw)) = pair.split_once('=') {
            let decoded = decode(raw, "plugin")?;
            if !decoded.is_empty() {
                value = Some(decoded);
                break;
            }
        }
    }
    let Some(value) = value else {
        return Ok((String::new(), String::new()));
    };

    let (name, opts) = value.split_once(';').unwrap_or((value.as_str(), ""));
    let plugin = match name.trim() {
        "" => return Err(LinkError::InvalidValue("plugin")),
        "obfs-local" | "simple-obfs" => "obfs-local",
        "v2ray-plugin" => "v2ray-plugin",
        other => return Err(LinkError::unsupported("plugin", other)),
    };
    Ok((plugin.to_owned(), opts.to_owned()))
}

/// Base64 (standard/URL-safe, any padding, whitespace ignored) → UTF-8.
/// Errors never echo the payload (credentials).
fn decode_base64(payload: &str, field: &'static str) -> Result<String> {
    let payload = decode(payload, field)?;
    let normalized: String = payload
        .chars()
        .filter(|c| !c.is_whitespace())
        .map(|c| match c {
            '-' => '+',
            '_' => '/',
            other => other,
        })
        .collect();
    if normalized.is_empty() {
        return Err(LinkError::MissingField(field));
    }
    let bytes = DECODER
        .decode(normalized.as_bytes())
        .map_err(|_| LinkError::InvalidValue(field))?;
    String::from_utf8(bytes).map_err(|_| LinkError::InvalidValue(field))
}
