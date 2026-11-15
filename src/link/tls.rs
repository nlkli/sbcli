//! TLS-related query parameters shared by VLESS, Trojan, VMess-style links.

use crate::models::shared::{Reality, Tls, Utls};

use super::error::{LinkError, Result};
use super::params::{Params, Query};

/// uTLS fingerprints accepted by both Xray-style links and sing-box.
const UTLS_FINGERPRINTS: &[&str] = &[
    "chrome",
    "firefox",
    "edge",
    "safari",
    "360",
    "qq",
    "ios",
    "android",
    "random",
    "randomized",
];
/// sing-box requires uTLS for Reality clients, so this is used when `fp` is absent.
const DEFAULT_FINGERPRINT: &str = "chrome";

/// Security layer of a link (`security=` parameter).
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum Security {
    None,
    Tls,
    Reality,
}

/// Parses `security`, `sni` (alias `peer`), `alpn`, `fp`, `allowInsecure`
/// (alias `insecure`), and for Reality `pbk` / `sid`.
///
/// `default` is the security used when the link has no `security` parameter:
/// `None` for VLESS, `Tls` for Trojan.
pub(crate) fn parse_tls(p: &Params, default: Security) -> Result<Option<Tls>> {
    let security = match p.get("security") {
        None => default,
        Some("none") => Security::None,
        Some("tls") => Security::Tls,
        Some("reality") => Security::Reality,
        Some(other) => return Err(LinkError::unsupported("security", other)),
    };
    if security == Security::None {
        return Ok(None);
    }

    // Unknown fingerprints are ignored rather than rejected.
    let fingerprint = p
        .get_any(&["fp", "utlsImitate"])
        .map(str::to_ascii_lowercase)
        .filter(|f| UTLS_FINGERPRINTS.contains(&f.as_str()));

    let mut tls = Tls {
        enabled: true,
        server_name: p.get_any(&["sni", "peer"]).unwrap_or_default().to_owned(),
        alpn: p.list("alpn"),
        insecure: p.flag(&["allowInsecure", "insecure", "skip-cert-verify"]),
        ..Tls::default()
    };

    if security == Security::Reality {
        let public_key = p
            .get("pbk")
            .ok_or(LinkError::MissingField("pbk"))?
            .to_owned();
        let short_id = p.get("sid").unwrap_or_default().to_owned();
        if !is_valid_short_id(&short_id) {
            return Err(LinkError::InvalidValue("sid"));
        }
        tls.reality = Some(Reality {
            enabled: true,
            public_key,
            short_id,
            ..Default::default()
        });
        tls.utls = Some(Utls {
            enabled: true,
            fingerprint: fingerprint.unwrap_or_else(|| DEFAULT_FINGERPRINT.to_owned()),
        });
    } else if let Some(fingerprint) = fingerprint {
        tls.utls = Some(Utls {
            enabled: true,
            fingerprint,
        });
    }
    Ok(Some(tls))
}

/// Reality short id: up to 8 bytes, hex encoded (so an even number of digits).
fn is_valid_short_id(s: &str) -> bool {
    s.len() <= 16 && s.len() % 2 == 0 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Writes `security` and the matching TLS/Reality parameters.
pub(crate) fn write_tls(tls: Option<&Tls>, q: &mut Query) {
    let Some(tls) = tls.filter(|t| t.enabled) else {
        q.push("security", "none");
        return;
    };
    let reality = tls.reality.as_ref().filter(|r| r.enabled);

    q.push(
        "security",
        if reality.is_some() { "reality" } else { "tls" },
    );
    write_tls_options(tls, q);
    if let Some(r) = reality {
        q.push("pbk", r.public_key.as_str());
        q.push_non_empty("sid", &r.short_id);
    }
}

/// Writes only `sni`, `fp`, `alpn` and `allowInsecure`, without `security`.
///
/// For links whose scheme already says whether TLS is used (`https://`).
pub(crate) fn write_tls_options(tls: &Tls, q: &mut Query) {
    q.push_non_empty("sni", &tls.server_name);
    if let Some(utls) = tls.utls.as_ref().filter(|u| u.enabled) {
        let fp = if utls.fingerprint.is_empty() {
            DEFAULT_FINGERPRINT
        } else {
            &utls.fingerprint
        };
        q.push("fp", fp);
    }
    if !tls.alpn.is_empty() {
        q.push("alpn", tls.alpn.join(","));
    }
    if tls.insecure {
        q.push("allowInsecure", "1");
    }
}
