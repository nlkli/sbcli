use crate::omit_empty;

omit_empty! {
/// TCP Brutal congestion control settings.
/// Docs: https://sing-box.sagernet.org/configuration/shared/tcp-brutal/
/// Requires the `brutal` kernel module on Linux servers.
pub struct TcpBrutal {
    /// Enable TCP Brutal congestion control algorithm.
    pub enabled: bool,

    /// Upload bandwidth in Mbps. Required.
    pub up_mbps: u16,

    /// Download bandwidth in Mbps. Required.
    pub down_mbps: u16,
}
}
