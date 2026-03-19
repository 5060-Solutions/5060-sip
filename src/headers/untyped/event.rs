use rsip_derives::{ToTypedHeader, UntypedHeader};

/// The `Event` header in its [untyped](super) form.
#[derive(UntypedHeader, ToTypedHeader, Debug, PartialEq, Eq, Clone)]
pub struct Event(String);

impl Event {
    /// Get the event type (the part before any parameters).
    pub fn event_type(&self) -> &str {
        self.0.split(';').next().unwrap_or("").trim()
    }
}
