use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// AnyTLS outbound. Since sing-box 1.12.0.
pub struct AnyTls {
    /// Always "anytls".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// AnyTLS password. Required.
    pub password: String,

    /// Interval checking for idle sessions. Default: 30s.
    pub idle_session_check_interval: String,

    /// In the check, close sessions that have been idle for longer than this. Default: 30s.
    pub idle_session_timeout: String,

    /// In the check, at least the first n idle sessions are kept open. Default: n=0.
    pub min_idle_session: u16,

    /// Check AnyTLS client metadata. Since sing-box 1.13.16.
    pub client_metadata: String,

    /// TLS configuration. Required.
    pub tls: Option<shared::Tls>,

    /// Shared outbound dial fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
