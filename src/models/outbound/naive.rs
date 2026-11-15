use crate::models::shared;
use crate::omit_empty;
use std::collections::BTreeMap;

omit_empty! {
/// NaiveProxy outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/naive/
///
/// Only available on Apple platforms, Android, Windows, and certain Linux builds.
pub struct Naive {
    /// Outbound type. Always "naive".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Required.
    pub server_port: u16,

    /// Authentication username.
    pub username: String,

    /// Authentication password.
    pub password: String,

    /// Number of concurrent tunnel connections.
    /// More connections make the tunnel easier to detect via traffic analysis.
    pub insecure_concurrency: u16,

    /// Extra headers to send in HTTP requests.
    pub extra_headers: BTreeMap<String, String>,

    /// Flow-control window.
    /// - QUIC enabled: initial QUIC stream receive window. Defaults to "6 MB".
    /// - Otherwise: HTTP/2 session receive window (stream window is half).
    ///   Defaults to "4 MB" on iOS, "128 MB" elsewhere.
    pub stream_receive_window: String,

    /// UDP over TCP protocol settings. See UDP Over TCP.
    pub udp_over_tcp: Option<shared::UdpOverTcp>,

    /// Use QUIC instead of HTTP/2.
    pub quic: bool,

    /// QUIC congestion control algorithm: "bbr", "bbr2", "cubic" or "reno".
    /// Defaults to "cubic".
    pub quic_congestion_control: String,

    /// Initial QUIC session receive window. Only used when `quic` is enabled.
    /// Defaults to "15 MB".
    pub quic_session_receive_window: String,

    /// TLS configuration. Required. See TLS.
    /// Only `server_name`, `certificate`, `certificate_path` and `ech` are supported.
    pub tls: Option<shared::Tls>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
