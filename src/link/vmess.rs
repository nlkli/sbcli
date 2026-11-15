//! `vmess://…` share links ⇄ sing-box [`Vmess`] outbound.
//!
//! Three formats are accepted by [`FromLink`]:
//! 1. v2rayN JSON – `vmess://<base64(JSON)>` (`"v": "2"`), most common.
//! 2. Xray URI – `vmess://<uuid>@<host>:<port>?encryption=…&security=…&type=…#remark`.
//! 3. Shadowrocket-style – `vmess://<base64(method:uuid@host:port)>?obfs=…&tls=…&…`.
//!
//! [`ToLink`] always writes format 1.
//!
//! All formats are normalized to the intermediate `Wire` record, so validation
//! and TLS/transport mapping are shared. Parsing is lenient: standard or
//! URL-safe Base64 (any padding, whitespace ignored); JSON numbers/strings
//! interchangeable; `#remark` used as tag when `ps` is empty; custom ids ≤30
//! bytes mapped to UUIDv5 like Xray; TLS without `sni` falls back to a domain
//! `host` for ws/h2/httpupgrade.
//!
//! Rejected rather than dropped: `kcp`/`xhttp`/…, gRPC `multi`, `reality`,
//! QUIC with encryption, link versions other than `2`. Ignored: gRPC authority,
//! extra transport headers, multiplex, dial options.

use base64::Engine as _;
use base64::alphabet;
use base64::engine::DecodePaddingMode;
use base64::engine::general_purpose::{GeneralPurpose, GeneralPurposeConfig, STANDARD};
use percent_encoding::percent_decode_str;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::Value;

use crate::models::outbound::Vmess;

use super::error::{LinkError, Result};
use super::params::{Params, Query};
use super::parts::{LinkUrl, custom_id_to_uuid, parse_uuid};
use super::tls::{Security, parse_tls};
use super::transport::{parse_transport, write_transport};
use super::{FromLink, ToLink};

const SCHEME: &str = "vmess";
const SCHEME1: &str = "vmess1";
const PREFIX: &str = "vmess://";

/// v2rayN's write-only marker for gRPC in the JSON `type` field; not read back.
const GRPC_V2RAYN_MARKER: &str = "gun";

/// Accepts any padding and non-canonical trailing bits; URL-safe alphabet is
/// mapped to standard before decoding.
const DECODER: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new()
        .with_decode_padding_mode(DecodePaddingMode::Indifferent)
        .with_decode_allow_trailing_bits(true),
);

macro_rules! require {
    ($cond:expr, $field:literal) => {
        if !$cond {
            return Err(LinkError::MissingField($field));
        }
    };
}

/// The JSON payload as found in links; every field is read leniently via
/// [`scalar`], unknown fields are ignored.
#[derive(Default, Deserialize)]
#[serde(default)]
struct Wire {
    #[serde(deserialize_with = "scalar")]
    v: String,
    #[serde(deserialize_with = "scalar")]
    ps: String,
    #[serde(deserialize_with = "scalar")]
    add: String,
    #[serde(deserialize_with = "scalar")]
    port: String,
    #[serde(deserialize_with = "scalar")]
    id: String,
    #[serde(deserialize_with = "scalar")]
    aid: String,
    #[serde(deserialize_with = "scalar")]
    scy: String,
    #[serde(deserialize_with = "scalar")]
    net: String,
    #[serde(rename = "type", deserialize_with = "scalar")]
    kind: String,
    #[serde(deserialize_with = "scalar")]
    host: String,
    #[serde(deserialize_with = "scalar")]
    path: String,
    #[serde(deserialize_with = "scalar")]
    tls: String,
    #[serde(deserialize_with = "scalar")]
    sni: String,
    #[serde(deserialize_with = "scalar")]
    alpn: String,
    #[serde(
        rename = "allowInsecure",
        alias = "insecure",
        deserialize_with = "scalar"
    )]
    allow_insecure: String,
    #[serde(deserialize_with = "scalar")]
    fp: String,
}

/// Reads a JSON scalar as a trimmed string: numbers/booleans in text form
/// (`true` → `1`), `null` → empty, string arrays comma-joined.
fn scalar<'de, D>(d: D) -> std::result::Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    match Value::deserialize(d)? {
        Value::String(s) => Ok(s.trim().to_owned()),
        Value::Number(n) => Ok(n.to_string()),
        Value::Bool(b) => Ok(if b { "1" } else { "0" }.to_owned()),
        Value::Null => Ok(String::new()),
        Value::Array(items) => items
            .iter()
            .map(|item| item.as_str().map(str::trim))
            .collect::<Option<Vec<_>>>()
            .map(|parts| parts.join(","))
            .ok_or_else(|| D::Error::custom("expected a list of strings")),
        Value::Object(_) => Err(D::Error::custom("expected a scalar")),
    }
}

/// The JSON payload as written by [`ToLink`]. Field order matches v2rayN.
/// Base fields are always emitted (empty when unset) as v2rayN does; only the
/// optional extensions `allowInsecure` and `fp` are omitted when unused.
#[derive(Serialize)]
struct WireOut {
    v: &'static str,
    ps: String,
    add: String,
    port: String,
    id: String,
    aid: String,
    scy: String,
    net: String,
    #[serde(rename = "type")]
    kind: String,
    host: String,
    path: String,
    tls: String,
    sni: String,
    alpn: String,
    #[serde(rename = "allowInsecure", skip_serializing_if = "String::is_empty")]
    allow_insecure: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    fp: String,
}

impl FromLink for Vmess {
    fn from_link(link: &str) -> Result<Self> {
        let link = link.trim();
        let rest = strip_scheme(link)?;
        let (body, fragment) = rest
            .split_once('#')
            .map_or((rest, None), |(b, f)| (b, Some(f)));
        let (payload, query) = body
            .split_once('?')
            .map_or((body, None), |(p, q)| (p, Some(q)));

        // Base64 never contains `@`, which tells the URI form apart.
        let wire = if payload.contains('@') {
            wire_from_uri(link)?
        } else {
            let bytes = decode_base64(payload)?;
            if bytes.iter().find(|b| !b.is_ascii_whitespace()) == Some(&b'{') {
                serde_json::from_slice(&bytes).map_err(|_| LinkError::InvalidValue("payload"))?
            } else {
                wire_from_legacy(&bytes, query)?
            }
        };
        from_wire(wire, fragment)
    }
}

/// Validates the intermediate record and builds the outbound.
fn from_wire(wire: Wire, fragment: Option<&str>) -> Result<Vmess> {
    // Version 1 packed `host;path` into one field; refuse instead of misreading.
    match wire.v.as_str() {
        "" | "2" => {}
        other => return Err(LinkError::unsupported("v", other)),
    }

    let server = wire
        .add
        .trim_start_matches('[')
        .trim_end_matches(']')
        .to_owned();
    require!(!server.is_empty(), "add");
    let server_port = parse_port(&wire.port)?;
    let uuid = parse_id(&wire.id)?;
    let alter_id = if wire.aid.is_empty() {
        0
    } else {
        wire.aid
            .parse()
            .map_err(|_| LinkError::InvalidValue("aid"))?
    };
    let security = parse_security(&wire.scy)?;

    let params = link_params(&wire)?;
    let tls = parse_tls(&params, Security::None)?;
    let transport = parse_transport(&params)?;

    let tag = if wire.ps.is_empty() {
        fragment
            .map(|f| percent_decode_str(f).decode_utf8_lossy().into_owned())
            .unwrap_or_default()
    } else {
        wire.ps
    };

    Ok(Vmess {
        r#type: SCHEME.to_owned(),
        tag,
        server,
        server_port,
        uuid,
        security,
        alter_id,
        tls,
        transport,
        ..Vmess::default()
    })
}

/// Format 2: `vmess://uuid@host:port?encryption=…&type=…` (Xray URI).
fn wire_from_uri(link: &str) -> Result<Wire> {
    let url = LinkUrl::parse(link, &[SCHEME, SCHEME1])?;
    let p = &url.params;
    let get = |key: &str| p.get(key).unwrap_or_default().to_owned();

    let net = get("type");
    let (host, path) = match net.as_str() {
        // QUIC keeps its security in `host`.
        "quic" => (get("quicSecurity"), get("path")),
        // gRPC authority has no sing-box equivalent; don't carry it.
        "grpc" => (String::new(), get("serviceName")),
        _ => (get("host"), get("path")),
    };
    let kind = if net == "grpc" && p.get("mode") == Some("multi") {
        "multi".to_owned()
    } else {
        get("headerType")
    };

    Ok(Wire {
        add: url.host.clone(),
        port: url.port.map(|n| n.to_string()).unwrap_or_default(),
        id: url.user.clone(),
        scy: get("encryption"),
        aid: p
            .get_any(&["aid", "alterId"])
            .unwrap_or_default()
            .to_owned(),
        net,
        kind,
        host,
        path,
        tls: get("security"),
        sni: p.get_any(&["sni", "peer"]).unwrap_or_default().to_owned(),
        alpn: get("alpn"),
        allow_insecure: p
            .get_any(&["allowInsecure", "insecure"])
            .unwrap_or_default()
            .to_owned(),
        fp: get("fp"),
        ..Wire::default()
    })
}

/// Format 3: Base64 `method:uuid@host:port` plus a query string.
fn wire_from_legacy(bytes: &[u8], query: Option<&str>) -> Result<Wire> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| LinkError::InvalidValue("payload"))?
        .trim();
    let invalid = || LinkError::InvalidValue("payload");
    let (credentials, address) = text.rsplit_once('@').ok_or_else(invalid)?;
    let (method, id) = credentials.split_once(':').ok_or_else(invalid)?;
    let (host, port) = address.rsplit_once(':').ok_or_else(invalid)?;

    let pairs: Vec<(String, String)> =
        url::form_urlencoded::parse(query.unwrap_or_default().as_bytes())
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
    let q = Params::from_pairs(pairs.iter().map(|(k, v)| (k.as_str(), v.as_str())));
    let get = |keys: &[&str]| q.get_any(keys).unwrap_or_default().to_owned();

    let obfs = get(&["obfs", "network"]).to_ascii_lowercase();
    let (net, kind) = match obfs.as_str() {
        "" | "none" | "tcp" => ("tcp", ""),
        "http" => ("tcp", "http"),
        "websocket" | "ws" => ("ws", ""),
        "h2" => ("h2", ""),
        "grpc" => ("grpc", ""),
        other => return Err(LinkError::unsupported("obfs", other)),
    };

    Ok(Wire {
        ps: get(&["remarks", "remark"]),
        add: host.into(),
        port: port.into(),
        id: id.into(),
        scy: method.into(),
        aid: get(&["alterId", "aid"]),
        net: net.into(),
        kind: kind.into(),
        host: get(&["obfsParam", "host"]),
        path: get(&["path"]),
        tls: if q.flag(&["tls"]) { "tls" } else { "" }.into(),
        sni: get(&["peer", "sni"]),
        alpn: get(&["alpn"]),
        allow_insecure: get(&["allowInsecure", "insecure"]),
        fp: get(&["fp"]),
        ..Wire::default()
    })
}

impl ToLink for Vmess {
    fn to_link(&self) -> Result<String> {
        require!(!self.uuid.is_empty(), "uuid");
        require!(!self.server.is_empty(), "server");
        require!(self.server_port != 0, "server_port");

        let tls = self.tls.as_ref().filter(|t| t.enabled);
        // The VMess link format has no way to express Reality.
        if tls.is_some_and(|t| t.reality.as_ref().is_some_and(|r| r.enabled)) {
            return Err(LinkError::unsupported("tls", "reality"));
        }

        // Reuse the query-style transport writer and translate its output.
        let mut q = Query::default();
        write_transport(self.transport.as_ref(), tls.is_some(), &mut q);
        let net = match q.get("type") {
            Some("http") => "h2",
            Some(other) => other,
            None => "tcp",
        };
        let header = match net {
            "tcp" if q.get("headerType") == Some("http") => "http",
            "grpc" => GRPC_V2RAYN_MARKER,
            _ => "none",
        };
        // For gRPC the service name travels in `path`.
        let path = q
            .get("path")
            .or_else(|| q.get("serviceName"))
            .unwrap_or_default();
        let host = q.get("host").unwrap_or_default();

        let wire = WireOut {
            v: "2",
            ps: self.tag.clone(),
            add: self.server.clone(),
            port: self.server_port.to_string(),
            id: self.uuid.clone(),
            aid: self.alter_id.to_string(),
            scy: if self.security.is_empty() {
                "auto".into()
            } else {
                self.security.clone()
            },
            net: net.into(),
            kind: header.into(),
            host: host.into(),
            path: path.into(),
            tls: if tls.is_some() { "tls" } else { "" }.into(),
            sni: tls.map(|t| t.server_name.clone()).unwrap_or_default(),
            alpn: tls.map(|t| t.alpn.join(",")).unwrap_or_default(),
            allow_insecure: if tls.is_some_and(|t| t.insecure) {
                "1".into()
            } else {
                String::new()
            },
            fp: tls
                .and_then(|t| t.utls.as_ref())
                .filter(|u| u.enabled)
                .map(|u| {
                    if u.fingerprint.is_empty() {
                        "chrome".into()
                    } else {
                        u.fingerprint.clone()
                    }
                })
                .unwrap_or_default(),
        };

        let json = serde_json::to_vec(&wire).map_err(|_| LinkError::InvalidValue("payload"))?;
        Ok(format!("{PREFIX}{}", STANDARD.encode(json)))
    }
}

/// Removes the (case-insensitive) `vmess://` prefix.
fn strip_scheme(link: &str) -> Result<&str> {
    link.get(..PREFIX.len())
        .filter(|prefix| prefix.eq_ignore_ascii_case(PREFIX))
        .map(|_| &link[PREFIX.len()..])
        .ok_or(LinkError::WrongScheme)
}

/// Base64 (standard or URL-safe, any padding, whitespace ignored) → bytes.
/// Errors never echo the payload, which contains credentials.
fn decode_base64(payload: &str) -> Result<Vec<u8>> {
    let payload = percent_decode_str(payload)
        .decode_utf8()
        .map_err(|_| LinkError::InvalidValue("payload"))?;
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
        return Err(LinkError::MissingField("payload"));
    }
    DECODER
        .decode(normalized.as_bytes())
        .map_err(|_| LinkError::InvalidValue("payload"))
}

fn parse_port(s: &str) -> Result<u16> {
    if s.is_empty() {
        return Err(LinkError::MissingField("port"));
    }
    s.parse::<u16>()
        .ok()
        .filter(|port| *port != 0)
        .ok_or(LinkError::InvalidValue("port"))
}

/// Normalizes the user id to a canonical UUID; non-UUID ids ≤30 bytes are
/// mapped to UUIDv5 like Xray does.
fn parse_id(id: &str) -> Result<String> {
    if id.is_empty() {
        return Err(LinkError::MissingField("id"));
    }
    if let Some(uuid) = parse_uuid(id) {
        return Ok(uuid);
    }
    if id.len() <= 30 {
        return Ok(custom_id_to_uuid(id));
    }
    Err(LinkError::InvalidValue("id"))
}

/// Normalizes `scy`; empty means `auto`, like in every VMess client.
fn parse_security(scy: &str) -> Result<String> {
    let lower = scy.to_ascii_lowercase();
    match lower.as_str() {
        "" | "auto" => Ok("auto".to_owned()),
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok("chacha20-poly1305".to_owned()),
        "none" | "zero" | "aes-128-gcm" | "aes-128-ctr" => Ok(lower.clone()),
        _ => Err(LinkError::unsupported("scy", scy)),
    }
}

/// TLS server name, falling back to a domain `host` for ws/httpupgrade/h2/http
/// when no `sni` is set — as common clients do.
fn fallback_sni<'a>(w: &'a Wire, security: &str, net: &str) -> &'a str {
    if !w.sni.is_empty() || security != "tls" {
        return w.sni.as_str();
    }
    if !matches!(net, "ws" | "httpupgrade" | "h2" | "http") {
        return "";
    }
    let host = w.host.split(',').next().unwrap_or("").trim();
    if host.parse::<std::net::IpAddr>().is_ok() {
        ""
    } else {
        host
    }
}

/// Translates the JSON fields into the query-style parameters understood by
/// `parse_tls` / `parse_transport`.
fn link_params(w: &Wire) -> Result<Params> {
    let tls = w.tls.to_ascii_lowercase();
    let security = match tls.as_str() {
        "" | "none" => "none",
        "tls" => "tls",
        other => return Err(LinkError::unsupported("tls", other)),
    };

    let net = w.net.to_ascii_lowercase();
    let kind = w.kind.to_ascii_lowercase();
    let sni = fallback_sni(w, security, &net);

    let mut pairs: Vec<(&str, &str)> = vec![
        ("security", security),
        ("sni", sni),
        ("alpn", w.alpn.as_str()),
        ("fp", w.fp.as_str()),
        ("allowInsecure", w.allow_insecure.as_str()),
    ];
    match net.as_str() {
        "" | "tcp" | "raw" => {
            pairs.push(("type", "tcp"));
            if kind == "http" {
                pairs.push(("headerType", "http"));
            }
            pairs.push(("host", w.host.as_str()));
            pairs.push(("path", w.path.as_str()));
        }
        "ws" | "httpupgrade" => {
            pairs.push(("type", net.as_str()));
            pairs.push(("host", w.host.as_str()));
            pairs.push(("path", w.path.as_str()));
        }
        "h2" | "http" => {
            pairs.push(("type", "h2"));
            pairs.push(("host", w.host.as_str()));
            pairs.push(("path", w.path.as_str()));
        }
        "grpc" => {
            pairs.push(("type", "grpc"));
            // `path` is the service name; gRPC authority is not representable.
            pairs.push(("serviceName", w.path.as_str()));
            if kind == "multi" {
                pairs.push(("mode", "multi"));
            }
        }
        "quic" => {
            // v2rayN keeps QUIC security in `host` and the key in `path`.
            if !matches!(kind.as_str(), "" | "none") {
                return Err(LinkError::unsupported("type", kind.as_str()));
            }
            pairs.push(("type", "quic"));
            pairs.push(("quicSecurity", w.host.as_str()));
        }
        other => return Err(LinkError::unsupported("net", other)),
    }
    Ok(Params::from_pairs(pairs))
}
