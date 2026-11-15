use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// Shadowsocks outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/shadowsocks/
pub struct Shadowsocks {
    /// Outbound type. Always "shadowsocks".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// Encryption method. Required.
    pub method: String,

    /// Shadowsocks password. Required.
    pub password: String,

    /// SIP003 plugin: "obfs-local" or "v2ray-plugin". Disabled if empty.
    pub plugin: String,

    /// SIP003 plugin options.
    pub plugin_opts: String,

    /// Enabled network: "tcp" or "udp". Both enabled by default.
    pub network: String,

    /// UDP over TCP configuration. See UDP Over TCP. Conflicts with `multiplex`.
    pub udp_over_tcp: Option<shared::UdpOverTcp>,

    /// Multiplex configuration. See Multiplex. Conflicts with `udp_over_tcp`.
    pub multiplex: Option<shared::Multiplex>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
