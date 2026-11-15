use crate::omit_empty;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// HTTP Client: a string tag or an inline object.
/// Docs: https://sing-box.sagernet.org/configuration/shared/http-client/
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum HttpClient {
    /// Tag of a shared HTTP Client in top-level `http_clients`.
    Tag(String),

    /// Inline definition.
    Inline(HttpClientOptions),
}

omit_empty! {
/// Inline HTTP Client definition.
pub struct HttpClientOptions {
    /// HTTP engine: "go" (default) or "apple".
    /// "apple" uses NSURLSession, Apple platforms only, experimental.
    pub engine: String,

    /// HTTP version: 1, 2 or 3. Defaults to 2.
    /// When 3, HTTP2 fields are replaced by QUIC fields.
    pub version: u8,

    /// Disable automatic fallback to a lower HTTP version.
    pub disable_version_fallback: bool,

    /// Custom HTTP headers. The Host header is used as the request host.
    pub headers: BTreeMap<String, String>,

    /// HTTP2 fields (version 2, default) or QUIC fields (version 3).
    /// See Http2QuicFields.
    #[serde(flatten)]
    pub http2_quic: super::http2_quic_fields::Http2QuicFields,

    /// TLS configuration. See TLS.
    pub tls: Option<super::tls::Tls>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: super::dial_fields::DialFields,
}
}
