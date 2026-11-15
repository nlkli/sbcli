//! `ssh://[user[:password]@]host[:port][?params][#tag]` ⇄ sing-box [`Ssh`] outbound.
//!
//! The scheme is registered with IANA (`ssh://[user[;fingerprint=…]@]host[:port]`),
//! but that syntax has no room for passwords, private keys, or sing-box
//! settings, so the query string below is a de-facto extension.
//!
//! * port defaults to 22; the user name defaults to `root` (sing-box applies
//!   that itself when `user` is empty, so it is not filled in here);
//! * the IANA `;fingerprint=…` userinfo parameter is **rejected**: it is a hash
//!   of the host key, while sing-box needs the public key itself. Ignoring it
//!   would silently disable host key verification;
//! * a password in the user-info position is accepted although the IANA draft
//!   deprecates it — for an outbound there is no one to prompt.
//!
//! | Parameter                              | Maps to                  | Notes                                |
//! |----------------------------------------|--------------------------|--------------------------------------|
//! | `pk` (alias `private_key`)             | `private_key`            | PEM text, must be percent-encoded    |
//! | `pkp` (alias `private_key_passphrase`) | `private_key_passphrase` | requires `pk`                        |
//! | `host_key`                             | `host_key`               | repeatable, e.g. `ssh-ed25519 AAAA…` |
//! | `host_key_algorithms`                  | `host_key_algorithms`    | comma-separated                      |
//! | `client_version`                       | `client_version`         | e.g. `SSH-2.0-OpenSSH_9.6`           |
//! | `tfo`                                  | `tcp_fast_open`          | `1` / `true`                         |
//!
//! Without `host_key` the server key is **not verified** (sing-box accepts any
//! key when the list is empty); add one if the link travels over an untrusted
//! channel.
//!
//! `private_key_path` is a local file name and meaningless on another machine,
//! so [`ToLink`] refuses to serialize it instead of dropping the credential.
//! `cipher`, `mac`, `kex_algorithm`, multiplexing, and other dial fields have
//! no link representation. Unknown parameters are ignored.

use crate::models::outbound::Ssh;
use crate::models::shared::DialFields;

use super::error::{LinkError, Result};
use super::params::Query;
use super::parts::{LinkUrl, build_link_encoded, encode_credentials};
use super::{FromLink, ToLink};

const SCHEME: &str = "ssh";
const DEFAULT_PORT: u16 = 22;

impl FromLink for Ssh {
    fn from_link(link: &str) -> Result<Self> {
        let url = LinkUrl::parse(link, &[SCHEME])?;
        let p = &url.params;

        // IANA syntax: `user;param=value@host`. The only defined parameter is
        // `fingerprint`, which cannot be mapped (see module docs); anything
        // else is equally unknown, and silently dropping a security-relevant
        // field is not an option.
        let (user, userinfo_params) = match url.user.split_once(';') {
            Some((user, rest)) => (user.to_owned(), rest),
            None => (url.user.clone(), ""),
        };
        if let Some(param) = userinfo_params.split(';').find(|s| !s.is_empty()) {
            let name = param.split_once('=').map_or(param, |(name, _)| name);
            return Err(LinkError::unsupported("userinfo", name));
        }

        let server_port = match url.port {
            None => DEFAULT_PORT,
            Some(0) => return Err(LinkError::InvalidValue("port")),
            Some(port) => port,
        };

        let private_key = p
            .get_any(&["pk", "private_key"])
            .unwrap_or_default()
            .to_owned();
        let private_key_passphrase = p
            .get_any(&["pkp", "private_key_passphrase"])
            .unwrap_or_default()
            .to_owned();
        // A passphrase without a key means the link was truncated or mangled.
        if private_key.is_empty() && !private_key_passphrase.is_empty() {
            return Err(LinkError::MissingField("private_key"));
        }

        Ok(Ssh {
            r#type: SCHEME.to_owned(),
            tag: url.tag,
            server: url.host,
            server_port,
            user,
            password: url.password.unwrap_or_default(),
            private_key,
            private_key_passphrase,
            host_key: p
                .get_all("host_key")
                .into_iter()
                .map(str::to_owned)
                .collect(),
            host_key_algorithms: p.list("host_key_algorithms"),
            client_version: p.get("client_version").unwrap_or_default().to_owned(),
            dial: DialFields {
                tcp_fast_open: p.flag(&["tfo"]),
                ..DialFields::default()
            },
            ..Ssh::default()
        })
    }
}

impl ToLink for Ssh {
    fn to_link(&self) -> Result<String> {
        if self.server.is_empty() {
            return Err(LinkError::MissingField("server"));
        }
        // Refuse rather than emit a link that lost its only credential.
        if !self.private_key_path.is_empty() {
            return Err(LinkError::unsupported("private_key_path", "file"));
        }
        if self.private_key.is_empty() && !self.private_key_passphrase.is_empty() {
            return Err(LinkError::MissingField("private_key"));
        }

        // `0` means "use the default" in sing-box; make it explicit.
        let port = if self.server_port == 0 {
            DEFAULT_PORT
        } else {
            self.server_port
        };

        let mut q = Query::default();
        q.push_non_empty("pk", &self.private_key);
        q.push_non_empty("pkp", &self.private_key_passphrase);
        for key in self.host_key.iter().filter(|k| !k.is_empty()) {
            q.push("host_key", key.as_str());
        }
        if !self.host_key_algorithms.is_empty() {
            q.push("host_key_algorithms", self.host_key_algorithms.join(","));
        }
        q.push_non_empty("client_version", &self.client_version);
        if self.dial.tcp_fast_open {
            q.push("tfo", "1");
        }

        Ok(build_link_encoded(
            SCHEME,
            &encode_credentials(&self.user, &self.password),
            &self.server,
            port,
            &q,
            &self.tag,
        ))
    }
}
