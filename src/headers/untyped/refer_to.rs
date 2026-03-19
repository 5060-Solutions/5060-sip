use rsip_derives::{ToTypedHeader, UntypedHeader};

/// The `Refer-To` header in its [untyped](super) form (RFC 3515).
#[derive(UntypedHeader, ToTypedHeader, Debug, PartialEq, Eq, Clone)]
#[header(display_name = "Refer-To")]
pub struct ReferTo(String);
