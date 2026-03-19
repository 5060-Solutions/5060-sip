#[doc(hidden)]
pub use super::tokenizers::DisplayUriParamsTokenizer as Tokenizer;

use crate::common::{uri::Param, Uri};
use rsip_derives::{TypedHeader, UriAndParamsHelpers};
use std::convert::{TryFrom, TryInto};

/// The `Refer-To` header in its [typed](super) form (RFC 3515).
///
/// Format: `[display-name] <URI> *( ";" generic-param )`
/// Example: `<sip:alice@atlanta.example.com>`, `Bob <sip:bob@biloxi.example.com?Replaces=12345>`
#[derive(TypedHeader, UriAndParamsHelpers, Eq, PartialEq, Clone, Debug)]
pub struct ReferTo {
    pub display_name: Option<String>,
    pub uri: Uri,
    pub params: Vec<Param>,
}

impl<'a> TryFrom<Tokenizer<'a>> for ReferTo {
    type Error = crate::Error;

    fn try_from(tokenizer: Tokenizer) -> Result<Self, Self::Error> {
        Ok(ReferTo {
            display_name: tokenizer.display_name.map(Into::into),
            uri: tokenizer.uri.try_into()?,
            params: tokenizer
                .params
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
        })
    }
}

impl std::fmt::Display for ReferTo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match &self.display_name {
            Some(display_name) => write!(
                f,
                "{} <{}>{}",
                display_name,
                self.uri,
                self.params
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join("")
            ),
            None => write!(
                f,
                "<{}>{}",
                self.uri,
                self.params
                    .iter()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
                    .join("")
            ),
        }
    }
}

impl std::convert::From<crate::common::Uri> for ReferTo {
    fn from(uri: crate::common::Uri) -> Self {
        Self {
            display_name: None,
            uri,
            params: Default::default(),
        }
    }
}
