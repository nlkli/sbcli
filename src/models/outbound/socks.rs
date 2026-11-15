use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// SOCKS outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/socks/
pub struct Socks {
    /// Outbound type. Always "socks".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// SOCKS version: "4", "4a" or "5". Defaults to "5".
    pub version: String,

    /// SOCKS username.
    pub username: String,

    /// SOCKS5 password.
    pub password: String,

    /// Enabled network: "tcp" or "udp". Both enabled by default.
    pub network: String,

    /// UDP over TCP configuration. See UDP Over TCP.
    pub udp_over_tcp: Option<shared::UdpOverTcp>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
