use crate::{common::Method, headers::untyped::ToTypedHeader, Error};
use rsip_derives::{ToTypedHeader, UntypedHeader};

/// The `RAck` header in its [untyped](super) form (RFC 3262).
///
/// Format: `response-num CSeq-num Method`
/// Example: `776656 1 INVITE`
#[derive(UntypedHeader, ToTypedHeader, Debug, PartialEq, Eq, Clone)]
#[header(display_name = "RAck")]
pub struct RAck(String);

impl RAck {
    pub fn response_num(&self) -> Result<u32, Error> {
        self.typed().map(|s| s.response_num)
    }

    pub fn cseq_num(&self) -> Result<u32, Error> {
        self.typed().map(|s| s.cseq_num)
    }

    pub fn method(&self) -> Result<Method, Error> {
        self.typed().map(|s| s.method)
    }
}
