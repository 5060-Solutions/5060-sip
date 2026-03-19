#[doc(hidden)]
pub use super::tokenizers::RAckTokenizer as Tokenizer;

use crate::common::Method;
use rsip_derives::TypedHeader;
use std::convert::TryFrom;

/// The `RAck` header in its [typed](super) form (RFC 3262).
///
/// Format: `response-num CSeq-num Method`
/// Example: `776656 1 INVITE`
#[derive(TypedHeader, Eq, PartialEq, Clone, Debug)]
pub struct RAck {
    pub response_num: u32,
    pub cseq_num: u32,
    pub method: Method,
}

impl<'a> TryFrom<Tokenizer<'a>> for RAck {
    type Error = crate::Error;

    fn try_from(tokenizer: Tokenizer) -> Result<Self, Self::Error> {
        Ok(RAck {
            response_num: tokenizer.response_num.parse::<u32>()?,
            cseq_num: tokenizer.cseq_num.parse::<u32>()?,
            method: tokenizer.method.parse::<Method>()?,
        })
    }
}

impl std::fmt::Display for RAck {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} {} {}", self.response_num, self.cseq_num, self.method)
    }
}
