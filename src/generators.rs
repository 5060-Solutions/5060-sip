//! RFC 3261 identifier generators: Via branch, From/To tags, Call-ID.

/// Generate a unique Via branch parameter (RFC 3261 magic cookie prefix).
pub fn generate_branch() -> String {
    format!("z9hG4bK-{}", uuid::Uuid::new_v4().to_simple())
}

/// Generate a unique tag for From/To headers.
pub fn generate_tag() -> String {
    format!("{:08x}", rand::Rng::gen::<u32>(&mut rand::thread_rng()))
}

/// Generate a unique Call-ID.
pub fn generate_call_id() -> String {
    format!("{}", uuid::Uuid::new_v4().to_simple())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn branch_has_magic_cookie() {
        let branch = generate_branch();
        assert!(branch.starts_with("z9hG4bK-"));
        assert!(branch.len() > 10);
    }

    #[test]
    fn tag_is_hex() {
        let tag = generate_tag();
        assert_eq!(tag.len(), 8);
        assert!(tag.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn call_id_is_nonempty() {
        let cid = generate_call_id();
        assert!(cid.len() > 20);
    }
}
