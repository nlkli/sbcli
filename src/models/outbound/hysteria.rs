use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// Hysteria outbound (v1).
/// Docs: https://sing-box.sagernet.org/configuration/outbound/hysteria/
pub struct Hysteria {
    /// Outbound type. Always "hysteria".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required. Conflicts with `server_ports`.
    pub server_port: u16,

    /// Server port range list. Conflicts with `server_port`.
    pub server_ports: Vec<String>,

    /// Port hopping interval. Defaults to "30s".
    pub hop_interval: String,

    /// Upload bandwidth, format "[Integer] [Unit]" (e.g. "100 Mbps"). Required.
    pub up: String,

    /// Upload bandwidth in Mbps. Required.
    pub up_mbps: u16,

    /// Download bandwidth, format "[Integer] [Unit]" (e.g. "100 Mbps"). Required.
    pub down: String,

    /// Download bandwidth in Mbps. Required.
    pub down_mbps: u16,

    /// Obfuscation password.
    pub obfs: String,

    /// Authentication password, base64-encoded.
    pub auth: String,

    /// Authentication password, plain string.
    pub auth_str: String,

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

    /// Deprecated. Use QUIC `stream_receive_window` instead.
    pub recv_window_conn: u32,

    /// Deprecated. Use QUIC `connection_receive_window` instead.
    pub recv_window: u32,

    /// Deprecated. Use QUIC `disable_path_mtu_discovery` instead.
    pub disable_mtu_discovery: bool,
}
}
