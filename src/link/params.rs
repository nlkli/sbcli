//! Reading and writing of URL query parameters.

use std::collections::HashMap;

use url::Url;

use super::parts::encode;

/// Decoded query parameters of a link.
///
/// Parsing is lenient: empty values count as absent, and for repeated keys the
/// first non-empty occurrence wins (like Go's `url.Values.Get`).
pub(crate) struct Params {
    /// First non-empty value per key.
    map: HashMap<String, String>,
    /// Every non-empty pair in link order (for repeatable parameters).
    all: Vec<(String, String)>,
}

impl Params {
    pub(crate) fn from_url(url: &Url) -> Self {
        Self::from_pairs(
            url.query_pairs()
                .map(|(k, v)| (k.into_owned(), v.into_owned())),
        )
    }

    /// Builds parameters from key/value pairs (for formats carrying the same
    /// data outside a query string, e.g. the VMess JSON payload). Empty values
    /// are dropped and the first occurrence of a key wins.
    pub(crate) fn from_pairs<K, V>(pairs: impl IntoIterator<Item = (K, V)>) -> Self
    where
        K: Into<String>,
        V: Into<String>,
    {
        let mut map = HashMap::new();
        let mut all = Vec::new();
        for (key, value) in pairs {
            let (key, value) = (key.into(), value.into());
            if !value.is_empty() {
                map.entry(key.clone()).or_insert_with(|| value.clone());
                all.push((key, value));
            }
        }
        Self { map, all }
    }

    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.map.get(key).map(String::as_str)
    }

    /// Every non-empty value of a repeatable parameter, in link order.
    pub(crate) fn get_all(&self, key: &str) -> Vec<&str> {
        self.all
            .iter()
            .filter(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
            .collect()
    }

    /// First present key among `keys` (parameter aliases).
    pub(crate) fn get_any(&self, keys: &[&str]) -> Option<&str> {
        keys.iter().find_map(|k| self.get(k))
    }

    /// `true` if the first present key among `keys` is `1` or `true`.
    pub(crate) fn flag(&self, keys: &[&str]) -> bool {
        matches!(self.get_any(keys), Some("1" | "true"))
    }

    /// Comma-separated list; blank items are dropped.
    pub(crate) fn list(&self, key: &str) -> Vec<String> {
        self.get(key)
            .map(|v| {
                v.split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_owned)
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// Ordered query string under construction.
#[derive(Default)]
pub(crate) struct Query(Vec<(&'static str, String)>);

impl Query {
    pub(crate) fn push(&mut self, key: &'static str, value: impl Into<String>) {
        self.0.push((key, value.into()));
    }

    /// Adds the parameter only when `value` is not empty.
    pub(crate) fn push_non_empty(&mut self, key: &'static str, value: &str) {
        if !value.is_empty() {
            self.push(key, value);
        }
    }

    /// Value of the first parameter named `key`.
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.0
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    /// `k1=v1&k2=v2` with percent-encoded values.
    pub(crate) fn encode(&self) -> String {
        self.0
            .iter()
            .map(|(k, v)| format!("{k}={}", encode(v)))
            .collect::<Vec<_>>()
            .join("&")
    }
}
