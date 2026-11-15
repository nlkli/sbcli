use crate::omit_empty;

omit_empty! {
/// Multiplex outbound fields.
/// Docs: https://sing-box.sagernet.org/configuration/shared/multiplex/
pub struct Multiplex {
    /// Enable multiplex.
    pub enabled: bool,

    /// Multiplex protocol: "smux", "yamux" or "h2mux". Defaults to "h2mux".
    pub protocol: String,

    /// Maximum connections. Conflicts with `max_streams`.
    pub max_connections: u16,

    /// Minimum multiplexed streams in a connection before opening a new connection.
    /// Conflicts with `max_streams`.
    pub min_streams: u16,

    /// Maximum multiplexed streams in a connection before opening a new connection.
    /// Conflicts with `max_connections` and `min_streams`.
    pub max_streams: u16,

    /// Enable padding. Requires sing-box server 1.3-beta9 or later.
    pub padding: bool,

    /// TCP Brutal settings. See TCP Brutal.
    pub brutal: Option<super::tcp_brutal::TcpBrutal>,
}
}
