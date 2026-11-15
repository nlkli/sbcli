use crate::omit_empty;
use serde::{Deserialize, Serialize};

omit_empty! {
/// Dial fields.
/// Docs: https://sing-box.sagernet.org/configuration/shared/dial/
pub struct DialFields {
    /// Tag of the upstream outbound. If set, all other fields are ignored.
    pub detour: String,

    /// Network interface to bind to.
    pub bind_interface: String,

    /// IPv4 address to bind to.
    pub inet4_bind_address: String,

    /// IPv6 address to bind to.
    pub inet6_bind_address: String,

    /// Do not reserve a source port when binding to a source address. Linux only.
    pub bind_address_no_port: bool,

    /// Netfilter routing mark. Linux only. Integers and hex strings are supported.
    pub routing_mark: RoutingMark,

    /// Reuse listener address.
    pub reuse_addr: bool,

    /// Network namespace name or path. Linux only.
    pub netns: String,

    /// Connect timeout, in Go duration format (e.g. "300ms", "-1.5h", "2h45m").
    pub connect_timeout: String,

    /// Enable TCP Fast Open.
    pub tcp_fast_open: bool,

    /// Enable TCP Multi Path. Requires Go 1.21.
    pub tcp_multi_path: bool,

    /// Disable TCP keep alive.
    pub disable_tcp_keep_alive: bool,

    /// TCP keep alive initial period. Defaults to "5m".
    pub tcp_keep_alive: String,

    /// TCP keep alive interval. Defaults to "75s".
    pub tcp_keep_alive_interval: String,

    /// Enable UDP fragmentation.
    pub udp_fragment: bool,

    /// Domain resolver for resolving domain names.
    /// Required for outbound/endpoints using a domain name in the server address since 1.14.0.
    /// See DomainResolver.
    pub domain_resolver: Option<DomainResolver>,

    /// Strategy for selecting network interfaces: "default", "hybrid" or "fallback".
    /// Conflicts with `bind_interface`, `inet4_bind_address` and `inet6_bind_address`.
    pub network_strategy: String,

    /// Network types: "wifi", "cellular", "ethernet", "other".
    pub network_type: Vec<String>,

    /// Fallback network types for the "fallback" network strategy.
    pub fallback_network_type: Vec<String>,

    /// Fast Fallback wait time before spawning a fallback connection. Defaults to "300ms".
    pub fallback_delay: String,

    /// Deprecated. Use `domain_resolver` instead.
    /// Domain resolution strategy: "prefer_ipv4", "prefer_ipv6", "ipv4_only" or "ipv6_only".
    pub domain_strategy: String,
}
}

/// Domain resolver: a plain server tag or inline options object.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum DomainResolver {
    /// DNS server tag.
    Tag(String),

    /// Inline resolver options.
    Inline(DomainResolverOptions),
}

/// Inline domain resolver options.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DomainResolverOptions {
    /// DNS server tag.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub server: String,

    /// Domain resolution strategy.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub strategy: String,
}

/// Netfilter routing mark: integer or hex string.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(untagged)]
pub enum RoutingMark {
    /// Integer value (e.g. 1234).
    Int(u32),

    /// Hex string (e.g. "0x1234").
    Str(String),
}

impl Default for RoutingMark {
    fn default() -> Self {
        RoutingMark::Int(0)
    }
}
