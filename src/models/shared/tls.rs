use crate::omit_empty;

omit_empty! {
/// TLS configuration.
/// Docs: https://sing-box.sagernet.org/configuration/shared/tls/
pub struct Tls {
    /// Enable TLS.
    pub enabled: bool,

    /// TLS engine: "go" (default), "apple" or "windows". Client only.
    pub engine: String,

    /// Do not send server name in ClientHello. Client only.
    pub disable_sni: bool,

    /// Hostname for certificate verification and virtual hosting (unless IP).
    pub server_name: String,

    /// Accept any server certificate. Client only.
    pub insecure: bool,

    /// Supported ALPN protocols, in order of preference.
    pub alpn: Vec<String>,

    /// Minimum TLS version: "1.0", "1.1", "1.2" or "1.3". Defaults to "1.2".
    pub min_version: String,

    /// Maximum TLS version: "1.0", "1.1", "1.2" or "1.3". Defaults to "1.3".
    pub max_version: String,

    /// Enabled TLS 1.0–1.2 cipher suites. TLS 1.3 cipher suites are not configurable.
    pub cipher_suites: Vec<String>,

    /// Supported key exchange mechanisms: P256, P384, P521, X25519, X25519MLKEM768.
    pub curve_preferences: Vec<String>,

    /// Server certificates chain line array, in PEM format.
    pub certificate: Vec<String>,

    /// Path to server certificate chain, in PEM format. Auto-reloaded on change.
    pub certificate_path: String,

    /// SHA-256 hashes of server certificates, in base64 format. Client only.
    pub certificate_sha256: Vec<String>,

    /// SHA-256 hashes of server certificate public keys, in base64 format. Client only.
    pub certificate_public_key_sha256: Vec<String>,

    /// Client certificate chain line array, in PEM format. Client only.
    pub client_certificate: Vec<String>,

    /// Path to client certificate chain, in PEM format. Client only.
    pub client_certificate_path: String,

    /// Client private key line array, in PEM format. Client only.
    pub client_key: Vec<String>,

    /// Path to client private key, in PEM format. Client only.
    pub client_key_path: String,

    /// Server private key line array, in PEM format. Server only.
    pub key: Vec<String>,

    /// Path to server private key, in PEM format. Auto-reloaded on change. Server only.
    pub key_path: String,

    /// Client authentication type. Server only.
    pub client_authentication: String,

    /// Client certificate chain line array, in PEM format. Server only.
    pub client_certificate_server: Vec<String>,

    /// Paths to client certificate chain, in PEM format. Auto-reloaded on change. Server only.
    pub client_certificate_path_server: Vec<String>,

    /// SHA-256 hashes of client certificates, in base64 format. Server only.
    pub client_certificate_sha256: Vec<String>,

    /// SHA-256 hashes of client certificate public keys, in base64 format. Server only.
    pub client_certificate_public_key_sha256: Vec<String>,

    /// Enable kernel TLS transmit. Linux 5.1+, TLS 1.3 only.
    pub kernel_tx: bool,

    /// Enable kernel TLS receive. Linux 5.1+, TLS 1.3 only. Not recommended.
    pub kernel_rx: bool,

    /// TLS handshake timeout, in Go duration format. Defaults to "15s".
    pub handshake_timeout: String,

    /// Certificate provider: a string tag or an inline object. Server only.
    pub certificate_provider: Option<serde_json::Value>,

    /// Fragment TLS handshakes to bypass firewalls. Client only.
    pub fragment: bool,

    /// Fallback wait time when fragment cannot auto-detect. Defaults to "500ms".
    pub fragment_fallback_delay: String,

    /// Fragment TLS handshake into multiple TLS records. Client only.
    pub record_fragment: bool,

    /// Forged TLS ClientHello with a whitelisted SNI injected before the real one. Client only.
    pub spoof: String,

    /// Rejection method for the forged segment: "wrong-sequence" (default), "wrong-checksum",
    /// "wrong-ack", "wrong-md5" or "wrong-timestamp".
    pub spoof_method: String,

    /// Encrypted Client Hello configuration.
    pub ech: Option<Ech>,

    /// uTLS ClientHello fingerprint impersonation. Client only. Not recommended.
    pub utls: Option<Utls>,

    /// REALITY configuration.
    pub reality: Option<Reality>,
}
}

omit_empty! {
/// Encrypted Client Hello configuration.
pub struct Ech {
    /// Enable ECH.
    pub enabled: bool,

    /// ECH key line array, in PEM format. Server only.
    pub key: Vec<String>,

    /// Path to ECH key, in PEM format. Server only.
    pub key_path: String,

    /// ECH configuration line array, in PEM format. Client only.
    /// If empty, loading from DNS will be attempted.
    pub config: Vec<String>,

    /// Path to ECH configuration, in PEM format. Client only.
    /// If empty, loading from DNS will be attempted.
    pub config_path: String,

    /// Overrides the domain name used for ECH HTTPS record queries. Client only.
    /// If empty, `server_name` is used.
    pub query_server_name: String,
}
}

omit_empty! {
/// uTLS ClientHello fingerprint impersonation.
pub struct Utls {
    /// Enable uTLS.
    pub enabled: bool,

    /// Fingerprint: "chrome", "firefox", "edge", "safari", "360", "qq", "ios",
    /// "android", "random" or "randomized". Chrome is used if empty.
    pub fingerprint: String,
}
}

omit_empty! {
/// REALITY configuration.
pub struct Reality {
    /// Enable REALITY.
    pub enabled: bool,

    /// Handshake server address and dial fields. Server only. Required.
    pub handshake: Option<RealityHandshake>,

    /// Private key, generated by `sing-box generate reality-keypair`. Server only. Required.
    pub private_key: String,

    /// Public key, generated by `sing-box generate reality-keypair`. Client only. Required.
    pub public_key: String,

    /// Short ID: a hexadecimal string with zero to eight digits. Required.
    pub short_id: String,

    /// Maximum time difference between the server and the client. Server only.
    /// Check disabled if empty.
    pub max_time_difference: String,
}
}

omit_empty! {
/// REALITY handshake server configuration.
pub struct RealityHandshake {
    /// Handshake server address.
    pub server: String,

    /// Handshake server port.
    pub server_port: u16,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: super::dial_fields::DialFields,
}
}
