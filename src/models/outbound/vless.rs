use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// VLESS outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/vless/
pub struct Vless {
    /// Outbound type. Always "vless".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// VLESS user id (UUID). Required.
    pub uuid: String,

    /// VLESS sub-protocol: "xtls-rprx-vision".
    pub flow: String,

    /// Enabled network: "tcp" or "udp". Both enabled by default.
    pub network: String,

    /// TLS configuration. See TLS.
    pub tls: Option<shared::Tls>,

    /// UDP packet encoding: "" (disabled), "packetaddr" or "xudp" (default).
    pub packet_encoding: String,

    /// Multiplex configuration. See Multiplex.
    pub multiplex: Option<shared::Multiplex>,

    /// V2Ray Transport configuration. See V2Ray Transport.
    pub transport: Option<shared::V2RayTransport>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
