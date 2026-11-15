use crate::omit_empty;
use serde::{Deserialize, Serialize};

/// UDP over TCP protocol settings.
/// Docs: https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/
///
/// Can be a boolean when the version is not specified, or an object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum UdpOverTcp {
    /// Boolean form. `true` enables the protocol, `false` disables it.
    Bool(bool),

    /// Object form.
    Options(UdpOverTcpOptions),
}

omit_empty! {
/// UDP over TCP options.
pub struct UdpOverTcpOptions {
    /// Enable the UDP over TCP protocol.
    pub enabled: bool,

    /// Protocol version: 1 or 2. Defaults to 2.
    pub version: u8,
}
}
