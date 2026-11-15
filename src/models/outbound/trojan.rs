use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// Trojan outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/trojan/
pub struct Trojan {
    /// Outbound type. Always "trojan".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// Trojan password. Required.
    pub password: String,

    /// Enabled network: "tcp" or "udp". Both enabled by default.
    pub network: String,

    /// TLS configuration. See TLS.
    pub tls: Option<shared::Tls>,

    /// Multiplex configuration. See Multiplex.
    pub multiplex: Option<shared::Multiplex>,

    /// V2Ray Transport configuration. See V2Ray Transport.
    pub transport: Option<shared::V2RayTransport>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
