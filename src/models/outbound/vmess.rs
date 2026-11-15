use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// VMess outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/vmess/
pub struct Vmess {
    /// Outbound type. Always "vmess".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// VMess user id. Required.
    pub uuid: String,

    /// Encryption method: "auto", "none", "zero", "aes-128-gcm",
    /// "chacha20-poly1305" or legacy "aes-128-ctr".
    pub security: String,

    /// Alter ID: 0 = AEAD protocol, 1 (or >1) = legacy protocol.
    pub alter_id: u32,

    /// Protocol parameter. Will waste traffic randomly if enabled
    /// (enabled by default in v2ray and cannot be disabled).
    pub global_padding: bool,

    /// Protocol parameter. Enable length block encryption.
    pub authenticated_length: bool,

    /// Enabled network: "tcp" or "udp". Both enabled by default.
    pub network: String,

    /// TLS configuration. See TLS.
    pub tls: Option<shared::Tls>,

    /// UDP packet encoding: "" (disabled), "packetaddr" or "xudp".
    pub packet_encoding: String,

    /// V2Ray Transport configuration. See V2Ray Transport.
    pub transport: Option<shared::V2RayTransport>,

    /// Multiplex configuration. See Multiplex.
    pub multiplex: Option<shared::Multiplex>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
