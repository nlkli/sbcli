use crate::models::shared;
use crate::omit_empty;
use std::collections::HashMap;

omit_empty! {
/// HTTP CONNECT proxy outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/http/
pub struct Http {
    /// Outbound type. Always "http".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// Basic authorization username.
    pub username: String,

    /// Basic authorization password.
    pub password: String,

    /// Path of the HTTP request. Only available for version 1.
    pub path: String,

    /// Extra headers of the HTTP request. The Host header is only available for version 1.
    pub headers: HashMap<String, String>,

    /// HTTP version: 1, 2, or 3.
    /// Defaults to 2, or 1 if `path` or the Host header is set.
    pub version: u8,

    /// Disable automatic fallback to a lower HTTP version.
    pub disable_version_fallback: bool,

    /// TLS configuration. See TLS.
    pub tls: Option<shared::Tls>,

    /// HTTP2 fields (version 2, default) or QUIC fields (version 3).
    #[serde(flatten)]
    pub http2_quic_fields: shared::Http2QuicFields,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
