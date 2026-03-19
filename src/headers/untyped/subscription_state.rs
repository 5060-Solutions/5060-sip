use rsip_derives::{ToTypedHeader, UntypedHeader};

/// The `Subscription-State` header in its [untyped](super) form.
#[derive(UntypedHeader, ToTypedHeader, Debug, PartialEq, Eq, Clone)]
pub struct SubscriptionState(String);

impl SubscriptionState {
    /// Get the subscription state value (the part before any parameters).
    pub fn state(&self) -> &str {
        self.0.split(';').next().unwrap_or("").trim()
    }
}
