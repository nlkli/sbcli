use serde::{Deserialize, Deserializer, Serialize};

pub mod outbound;
pub mod shared;

/// An outbound parsed from a share link of any supported protocol.
#[derive(Debug, Clone, Serialize, PartialEq)]
#[serde(untagged)]
pub enum AnyOutbound {
    Http(outbound::Http),
    Hysteria(outbound::Hysteria),
    Hysteria2(outbound::Hysteria2),
    Naive(outbound::Naive),
    Shadowsocks(outbound::Shadowsocks),
    ShadowTls(outbound::ShadowTls),
    Socks(outbound::Socks),
    Ssh(outbound::Ssh),
    Trojan(outbound::Trojan),
    Tuic(outbound::Tuic),
    Vless(outbound::Vless),
    Vmess(outbound::Vmess),
    AnyTls(outbound::AnyTls),
}

impl<'de> Deserialize<'de> for AnyOutbound {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;

        let outbound_type = value
            .get("type")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(|| serde::de::Error::missing_field("type"))?;

        match outbound_type {
            "http" => Ok(Self::Http(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "hysteria" => Ok(Self::Hysteria(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "hysteria2" => Ok(Self::Hysteria2(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "naive" => Ok(Self::Naive(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "shadowsocks" => Ok(Self::Shadowsocks(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "shadowtls" => Ok(Self::ShadowTls(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "socks" => Ok(Self::Socks(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "ssh" => Ok(Self::Ssh(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "trojan" => Ok(Self::Trojan(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "tuic" => Ok(Self::Tuic(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "vless" => Ok(Self::Vless(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "vmess" => Ok(Self::Vmess(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            "anytls" => Ok(Self::AnyTls(
                serde_json::from_value(value).map_err(serde::de::Error::custom)?
            )),
            other => Err(serde::de::Error::custom(
                format!("unknown outbound type: {other}")
            )),
        }
    }
}

#[allow(dead_code)]
impl AnyOutbound {
    pub fn tag(&self) -> &str {
        match self {
            AnyOutbound::Http(o) => &o.tag,
            AnyOutbound::Hysteria(o) => &o.tag,
            AnyOutbound::Hysteria2(o) => &o.tag,
            AnyOutbound::Naive(o) => &o.tag,
            AnyOutbound::Shadowsocks(o) => &o.tag,
            AnyOutbound::ShadowTls(o) => &o.tag,
            AnyOutbound::Socks(o) => &o.tag,
            AnyOutbound::Ssh(o) => &o.tag,
            AnyOutbound::Trojan(o) => &o.tag,
            AnyOutbound::Tuic(o) => &o.tag,
            AnyOutbound::Vless(o) => &o.tag,
            AnyOutbound::Vmess(o) => &o.tag,
            AnyOutbound::AnyTls(o) => &o.tag,
        }
    }

    pub fn tag_mut(&mut self) -> &mut String {
        match self {
            AnyOutbound::Http(o) => &mut o.tag,
            AnyOutbound::Hysteria(o) => &mut o.tag,
            AnyOutbound::Hysteria2(o) => &mut o.tag,
            AnyOutbound::Naive(o) => &mut o.tag,
            AnyOutbound::Shadowsocks(o) => &mut o.tag,
            AnyOutbound::ShadowTls(o) => &mut o.tag,
            AnyOutbound::Socks(o) => &mut o.tag,
            AnyOutbound::Ssh(o) => &mut o.tag,
            AnyOutbound::Trojan(o) => &mut o.tag,
            AnyOutbound::Tuic(o) => &mut o.tag,
            AnyOutbound::Vless(o) => &mut o.tag,
            AnyOutbound::Vmess(o) => &mut o.tag,
            AnyOutbound::AnyTls(o) => &mut o.tag,
        }
    }
}

pub fn is_default<T: Default + PartialEq>(v: &T) -> bool {
    *v == T::default()
}

#[macro_export]
macro_rules! omit_empty {
    (
        $(#[$smeta:meta])*
        $vis:vis struct $name:ident {
            $(
                $(#[$fmeta:meta])*
                $fvis:vis $field:ident : $ty:ty
            ),* $(,)?
        }
    ) => {
        #[derive(Debug, Clone, ::serde::Serialize, ::serde::Deserialize, Default, PartialEq)]
        $(#[$smeta])*
        $vis struct $name {
            $(
                $(#[$fmeta])*
                #[serde(default, skip_serializing_if = "crate::models::is_default")]
                $fvis $field : $ty,
            )*
        }
    };
}
