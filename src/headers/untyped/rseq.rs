use rsip_derives::UntypedHeader;

/// The `RSeq` header in its [untyped](super) form (RFC 3262).
///
/// Contains a single response sequence number.
/// Example: `776656`
#[derive(UntypedHeader, Debug, PartialEq, Eq, Clone)]
#[header(display_name = "RSeq")]
pub struct RSeq(String);

impl RSeq {
    pub fn seq(&self) -> Result<u32, crate::Error> {
        use crate::headers::untyped::UntypedHeader;
        Ok(self.value().trim().parse::<u32>()?)
    }
}

impl From<u32> for RSeq {
    fn from(from: u32) -> Self {
        Self(from.to_string())
    }
}
