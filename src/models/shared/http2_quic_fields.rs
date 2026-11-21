use crate::omit_empty;

omit_empty! {
#[allow(dead_code)]
/// HTTP2 fields.
/// Docs: https://sing-box.sagernet.org/configuration/shared/http2/
pub struct Http2Fields {
    /// Idle connection timeout, in Go duration format (e.g. "30s").
    pub idle_timeout: String,

    /// Keep alive period, in Go duration format.
    pub keep_alive_period: String,

    /// HTTP2 stream-level flow-control receive window size (e.g. "64 MB").
    pub stream_receive_window: String,

    /// HTTP2 connection-level flow-control receive window size (e.g. "64 MB").
    pub connection_receive_window: String,

    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,
}
}

omit_empty! {
#[allow(dead_code)]
/// QUIC fields. Extends HTTP2 fields.
/// Docs: https://sing-box.sagernet.org/configuration/shared/quic/
pub struct QuicFields {
    /// Initial QUIC packet size.
    pub initial_packet_size: u32,

    /// Disable QUIC path MTU discovery.
    pub disable_path_mtu_discovery: bool,

    /// HTTP2 fields. See HTTP2 Fields.
    #[serde(flatten)]
    pub http2: Http2Fields,
}
}

omit_empty! {
/// Union of HTTP2 and QUIC fields (shared top-level wire namespace).
/// HTTP2 fields apply to both; QUIC-only fields apply when version = 3.
/// Docs: https://sing-box.sagernet.org/configuration/shared/http2/ ,
/// https://sing-box.sagernet.org/configuration/shared/quic/
pub struct Http2QuicFields {
    /// Idle connection timeout, in Go duration format (e.g. "30s").
    pub idle_timeout: String,

    /// Keep alive period, in Go duration format.
    pub keep_alive_period: String,

    /// HTTP2 stream-level flow-control receive window size (e.g. "64 MB").
    pub stream_receive_window: String,

    /// HTTP2 connection-level flow-control receive window size (e.g. "64 MB").
    pub connection_receive_window: String,

    /// Maximum concurrent streams per connection.
    pub max_concurrent_streams: u32,

    /// Initial QUIC packet size. QUIC only.
    pub initial_packet_size: u32,

    /// Disable QUIC path MTU discovery. QUIC only.
    pub disable_path_mtu_discovery: bool,
}
}
