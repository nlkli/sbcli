use crate::models::shared;
use crate::omit_empty;

omit_empty! {
/// SSH outbound.
/// Docs: https://sing-box.sagernet.org/configuration/outbound/ssh/
pub struct Ssh {
    /// Outbound type. Always "ssh".
    #[serde(rename = "type")]
    pub r#type: String,

    /// Optional unique tag for the outbound.
    pub tag: String,

    /// Server address. Required.
    pub server: String,

    /// Server port. Defaults to 22.
    pub server_port: u16,

    /// SSH user. Defaults to "root".
    pub user: String,

    /// Password.
    pub password: String,

    /// Private key.
    pub private_key: String,

    /// Private key path.
    pub private_key_path: String,

    /// Private key passphrase.
    pub private_key_passphrase: String,

    /// Host key. Accept any if empty.
    pub host_key: Vec<String>,

    /// Host key algorithms.
    pub host_key_algorithms: Vec<String>,

    /// Client version. Random version will be used if empty.
    pub client_version: String,

    /// Allowed ciphers. Default values are used if empty.
    pub cipher: Vec<String>,

    /// Allowed MAC algorithms. Default values are used if empty.
    pub mac: Vec<String>,

    /// Allowed key exchange algorithms. Default values are used if empty.
    pub kex_algorithm: Vec<String>,

    /// Dial fields. See Dial Fields.
    #[serde(flatten)]
    pub dial: shared::DialFields,
}
}
