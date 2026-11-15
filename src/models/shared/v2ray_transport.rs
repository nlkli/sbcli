use crate::omit_empty;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// V2Ray Transport: a tagged union of the supported transports.
/// Docs: https://sing-box.sagernet.org/configuration/shared/v2ray-transport/
///
/// Serialized as a JSON object with a `type` discriminator plus per-variant fields.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum V2RayTransport {
    /// HTTP transport.
    Http(HttpTransport),

    /// WebSocket transport.
    Ws(WsTransport),

    /// QUIC transport.
    Quic(QuicTransport),

    /// gRPC transport.
    Grpc(GrpcTransport),

    /// HTTPUpgrade transport.
    Httpupgrade(HttpUpgradeTransport),
}

omit_empty! {
/// HTTP transport.
pub struct HttpTransport {
    /// List of host domains. Client chooses randomly; server verifies if non-empty.
    pub host: Vec<String>,

    /// Path of the HTTP request. The server will verify.
    pub path: String,

    /// Method of the HTTP request. The server will verify if non-empty.
    pub method: String,

    /// Extra headers of the HTTP request. The server will write in response if non-empty.
    pub headers: BTreeMap<String, String>,

    /// Idle timeout, in Go duration format. Zero disables it.
    pub idle_timeout: String,

    /// PING response timeout, in Go duration format. Defaults to "15s".
    pub ping_timeout: String,
}
}

omit_empty! {
/// WebSocket transport.
pub struct WsTransport {
    /// Path of the HTTP request. The server will verify.
    pub path: String,

    /// Extra headers of the HTTP request. The server will write in response if non-empty.
    pub headers: BTreeMap<String, String>,

    /// Allowed payload size in the request. Enabled if non-zero.
    pub max_early_data: u32,

    /// Header used to carry early data. Set to "Sec-WebSocket-Protocol" for Xray-core compatibility.
    pub early_data_header_name: String,
}
}

omit_empty! {
/// QUIC transport.
pub struct QuicTransport {
    // No additional fields.
}
}

omit_empty! {
/// gRPC transport.
pub struct GrpcTransport {
    /// Service name of gRPC.
    pub service_name: String,

    /// Idle timeout, in Go duration format. Zero disables it.
    pub idle_timeout: String,

    /// PING response timeout, in Go duration format. Defaults to "15s".
    pub ping_timeout: String,

    /// Send keepalive pings even without active streams (standard gRPC client).
    pub permit_without_stream: bool,
}
}

omit_empty! {
/// HTTPUpgrade transport.
pub struct HttpUpgradeTransport {
    /// Host domain. The server will verify if non-empty.
    pub host: String,

    /// Path of the HTTP request. The server will verify.
    pub path: String,

    /// Extra headers of the HTTP request. The server will write in response if non-empty.
    pub headers: BTreeMap<String, String>,
}
}
