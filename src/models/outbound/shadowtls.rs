use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// ShadowTLS outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/shadowtls/
pub struct ShadowTls {
    /// Outbound type. Always "shadowtls".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// ShadowTLS protocol version: 1 (default), 2, or 3.
    pub version: u8,

    /// Password. Only available in ShadowTLS v2/v3.
    pub password: String,

    /// TLS configuration. Required. See TLS.
    pub tls: Option<shared::Tls>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
