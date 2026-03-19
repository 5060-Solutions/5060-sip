#[doc(hidden)]
pub use super::tokenizers::NameParamsTokenizer as Tokenizer;

use rsip_derives::TypedHeader;
use std::convert::TryFrom;

/// The `Subscription-State` header in its [typed](super) form (RFC 6665, formerly RFC 3265).
///
/// Format: `substate-value *( ";" subexp-params )`
/// Example: `active;expires=600`, `terminated;reason=timeout`
#[derive(TypedHeader, Eq, PartialEq, Clone, Debug)]
pub struct SubscriptionState {
    pub state: String,
    pub params: Vec<(String, String)>,
}

impl SubscriptionState {
    /// Get the `expires` parameter value in seconds.
    pub fn expires(&self) -> Option<u32> {
        self.params
            .iter()
            .find(|(k, _)| k == "expires")
            .and_then(|(_, v)| v.parse().ok())
    }

    /// Get the `reason` parameter value.
    pub fn reason(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == "reason")
            .map(|(_, v)| v.as_str())
    }

    /// Get the `retry-after` parameter value in seconds.
    pub fn retry_after(&self) -> Option<u32> {
        self.params
            .iter()
            .find(|(k, _)| k == "retry-after")
            .and_then(|(_, v)| v.parse().ok())
    }
}

impl<'a> TryFrom<Tokenizer<'a>> for SubscriptionState {
    type Error = crate::Error;

    fn try_from(tokenizer: Tokenizer) -> Result<Self, Self::Error> {
        Ok(SubscriptionState {
            state: tokenizer.name.trim().to_string(),
            params: tokenizer
                .params
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
    }
}

impl std::fmt::Display for SubscriptionState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.state)?;
        for (key, value) in &self.params {
            write!(f, ";{}={}", key, value)?;
        }
        Ok(())
    }
}
