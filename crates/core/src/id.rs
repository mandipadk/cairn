//! Typed identifiers.
//!
//! Random ids use 26 characters of lowercase Crockford base32 (a full
//! 128 bits), prefixed by object kind so an id is self-describing in
//! logs, URLs, and event payloads. Ordering comes from the event log,
//! not from ids, so ids carry no timestamp.

use serde::{Deserialize, Serialize};
use std::fmt;

const ALPHABET: &[u8; 32] = b"0123456789abcdefghjkmnpqrstvwxyz";

fn random_suffix() -> String {
    let mut n: u128 = rand::random();
    let mut out = [0u8; 26];
    for slot in out.iter_mut().rev() {
        *slot = ALPHABET[(n & 0x1f) as usize];
        n >>= 5;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// Slugs name things humans type: principals, repos, branches.
pub(crate) fn validate_slug(s: &str) -> bool {
    let ok_char = |c: char| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-';
    (2..=64).contains(&s.len())
        && s.chars().all(ok_char)
        && !s.starts_with('-')
        && !s.ends_with('-')
}

macro_rules! random_id {
    ($(#[$doc:meta])* $name:ident, $prefix:literal) => {
        $(#[$doc])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
        #[serde(transparent)]
        pub struct $name(pub String);

        impl $name {
            pub fn generate() -> Self {
                Self(format!(concat!($prefix, "-{}"), random_suffix()))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(&self.0)
            }
        }

        impl From<String> for $name {
            fn from(s: String) -> Self {
                Self(s)
            }
        }
    };
}

random_id!(
    /// Stable identity of a change, constant across revisions and rebases.
    ChangeId, "c");
random_id!(
    /// A durable statement of intent.
    TaskId, "t");
random_id!(
    /// One agent run against a task.
    SessionId, "s");
random_id!(
    /// One verification assertion on a revision.
    ClaimId, "cl");
random_id!(
    /// One review judgment on a revision.
    VerdictId, "v");

/// Principals are named by chosen slug, not random id: identity that
/// humans grant authority to should be identity humans can read.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PrincipalId(pub String);

impl PrincipalId {
    pub fn new(slug: &str) -> Option<Self> {
        validate_slug(slug).then(|| Self(slug.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PrincipalId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl From<String> for PrincipalId {
    fn from(s: String) -> Self {
        Self(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn random_ids_are_prefixed_and_distinct() {
        let a = ChangeId::generate();
        let b = ChangeId::generate();
        assert!(a.as_str().starts_with("c-"));
        assert_eq!(a.as_str().len(), 2 + 26);
        assert_ne!(a, b);
    }

    #[test]
    fn slug_validation() {
        assert!(validate_slug("ada"));
        assert!(validate_slug("scout-1"));
        assert!(!validate_slug("-bad"));
        assert!(!validate_slug("bad-"));
        assert!(!validate_slug("Bad"));
        assert!(!validate_slug("a"));
        assert!(!validate_slug("has space"));
    }
}
