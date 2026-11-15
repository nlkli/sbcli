use thiserror::Error;

/// Error type shared by all link parsers and generators.
///
/// Messages never contain credentials — only field/parameter names and values
/// of non-secret selector fields (`type`, `security`, `flow`, …).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum LinkError {
    #[error("invalid URL: {0}")]
    InvalidUrl(#[from] url::ParseError),

    #[error("unexpected URL scheme")]
    WrongScheme,

    /// Well-formed link whose protocol has no parser. The scheme is echoed
    /// only when short and alphanumeric.
    #[error("unsupported link scheme `{0}`")]
    UnsupportedScheme(String),

    /// A mandatory part of the link or outbound is absent.
    #[error("missing required `{0}`")]
    MissingField(&'static str),

    /// A value is present but malformed; the value itself is not echoed.
    #[error("invalid value for `{0}`")]
    InvalidValue(&'static str),

    /// A well-formed value the target cannot represent.
    #[error("unsupported value `{value}` for `{field}`")]
    Unsupported { field: &'static str, value: String },
}

impl LinkError {
    pub(crate) fn unsupported(field: &'static str, value: &str) -> Self {
        Self::Unsupported {
            field,
            value: value.to_owned(),
        }
    }
}

pub type Result<T> = std::result::Result<T, LinkError>;
