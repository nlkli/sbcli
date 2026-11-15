use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// TUIC outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/tuic/
pub struct Tuic {
    /// Outbound type. Always "tuic".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// TUIC user UUID. Required.
    pub uuid: String,

    /// TUIC user password.
    pub password: String,

    /// QUIC congestion control algorithm: "cubic", "new_reno" or "bbr".
    /// Defaults to "cubic".
    pub congestion_control: String,

    /// UDP packet relay mode: "native" or "quic". Defaults to "native".
    /// Conflicts with `udp_over_stream`.
    pub udp_relay_mode: String,

    /// UDP over stream mode. Conflicts with `udp_relay_mode`.
    pub udp_over_stream: bool,

    /// Enable 0-RTT handshake.
    pub zero_rtt_handshake: bool,

    /// Heartbeat interval. Defaults to "10s".
    pub heartbeat: String,

    /// Enabled network: "tcp" or "udp". Both enabled by default.
    pub network: String,

    /// TLS configuration. Required. See TLS.
    pub tls: Option<shared::Tls>,

    /// QUIC fields. See QUIC Fields.
    #[serde(flatten)]
    pub quic: shared::Http2QuicFields,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
