#[doc(hidden)]
pub use super::tokenizers::NameParamsTokenizer as Tokenizer;

use rsip_derives::TypedHeader;
use std::convert::TryFrom;

/// The `Event` header in its [typed](super) form (RFC 6665, formerly RFC 3265).
///
/// Format: `event-type *( ";" event-param )`
/// Example: `refer`, `presence;id=1234`
#[derive(TypedHeader, Eq, PartialEq, Clone, Debug)]
pub struct Event {
    pub event_type: String,
    pub params: Vec<(String, String)>,
}

impl Event {
    pub fn id(&self) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == "id")
            .map(|(_, v)| v.as_str())
    }
}

impl<'a> TryFrom<Tokenizer<'a>> for Event {
    type Error = crate::Error;

    fn try_from(tokenizer: Tokenizer) -> Result<Self, Self::Error> {
        Ok(Event {
            event_type: tokenizer.name.trim().to_string(),
            params: tokenizer
                .params
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        })
    }
}

impl std::fmt::Display for Event {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.event_type)?;
        for (key, value) in &self.params {
            write!(f, ";{}={}", key, value)?;
        }
        Ok(())
    }
}
