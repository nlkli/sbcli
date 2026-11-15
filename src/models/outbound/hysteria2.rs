use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// Hysteria2 outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/hysteria2/
///
/// Note: the official Hysteria2 `userpass` auth is not aliased by sing-box —
/// combine `<username>:<password>` into `password` when interoperating.
pub struct Hysteria2 {
    /// Outbound type. Always "hysteria2".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required unless `realm` is used. Conflicts with `realm`.
    pub server: String,

    /// Server port. Required. Ignored if `server_ports` is set. Conflicts with `realm`.
    pub server_port: u16,

    /// Server port range list. Conflicts with `server_port` and `realm`.
    pub server_ports: Vec<String>,

    /// Port hopping interval. Defaults to "30s".
    pub hop_interval: String,

    /// Maximum port hopping interval, used for randomization.
    /// If set, actual interval is random between `hop_interval` and `hop_interval_max`.
    pub hop_interval_max: String,

    /// Max upload bandwidth in Mbps. If empty, BBR is used instead of Hysteria CC.
    pub up_mbps: u16,

    /// Max download bandwidth in Mbps. If empty, BBR is used instead of Hysteria CC.
    pub down_mbps: u16,

    /// QUIC traffic obfuscation. Disabled if absent.
    pub obfs: Option<Hysteria2Obfs>,

    /// Authentication password.
    pub password: String,

    /// Enabled network: "tcp" or "udp". Both enabled by default.
    pub network: String,

    /// TLS configuration. Required. See TLS.
    pub tls: Option<shared::Tls>,

    /// QUIC fields. See QUIC Fields.
    #[serde(flatten)]
    pub quic: shared::Http2QuicFields,

    /// BBR congestion control profile: "conservative", "standard" or "aggressive".
    /// Defaults to "standard".
    pub bbr_profile: String,

    /// Enable debug information logging for Hysteria Brutal CC.
    pub brutal_debug: bool,

    /// Disable Chrome QUIC fingerprint parroting.
    pub disable_chrome_parrot: bool,

    /// Hysteria Realm rendezvous service.
    /// Conflicts with `server`, `server_port`, `server_ports`.
    pub realm: Option<Hysteria2Realm>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}

omit_empty! {
/// Hysteria2 QUIC traffic obfuscator.
pub struct Hysteria2Obfs {
    /// Obfuscator type: "salamander" or "gecko". Disabled if empty.
    #[serde(rename = "type")]
    pub r#type: String,

    /// Obfuscator password.
    pub password: String,

    /// Minimum on-wire packet size in bytes. Gecko only. Defaults to 512.
    pub min_packet_size: u16,

    /// Maximum on-wire packet size in bytes. Gecko only. Defaults to 1200.
    pub max_packet_size: u16,
}
}

omit_empty! {
/// Hysteria Realm rendezvous service.
pub struct Hysteria2Realm {
    /// Realm rendezvous service URL. Required.
    pub server_url: String,

    /// Bearer token for the realm. Must match one of `users[].token` on the realm.
    pub token: String,

    /// The same slot identifier the target Hysteria2 server registered. Required.
    pub realm_id: String,

    /// STUN servers (host or host:port) for public address discovery. Required.
    /// Domains resolved via `domain_resolver` from Dial Fields.
    pub stun_servers: Vec<String>,

    /// Restrict realm connections to a single IP version: 4 or 6.
    /// Both used if empty.
    pub ip_version: u8,

    /// UDP port mapping via UPnP / NAT-PMP.
    pub port_mapping: Option<Hysteria2RealmPortMapping>,

    /// HTTP client used to talk to the realm. See HTTP Client.
    pub http_client: Option<shared::HttpClient>,
}
}

omit_empty! {
/// Hysteria Realm UPnP / NAT-PMP port mapping settings.
pub struct Hysteria2RealmPortMapping {
    /// Enable port mapping.
    pub enabled: bool,

    /// Timeout for gateway discovery and mapping operations. Defaults to "10s".
    pub timeout: String,

    /// Lease lifetime of the mapping. Defaults to "10m".
    pub lifetime: String,
}
}
