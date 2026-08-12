//! Path leases: coordination before the work, not after it.
//!
//! Claiming a task stops two agents starting the same job. It does
//! nothing about two agents starting *different* jobs that happen to
//! touch the same files — which is where a fleet actually collides,
//! and where the collision is only discovered at rebase time, after
//! both have spent everything they were going to spend.
//!
//! A lease is a declaration of intent over paths: "this session
//! expects to change these". Overlaps are reported, not forbidden —
//! the forge's job is to make the collision visible while it is still
//! cheap, and an agent that knows can wait, narrow its scope, or ask.
//! Leases expire with their session, so a dead agent does not hold
//! ground forever.

use crate::error::CoreResult;
use crate::id::{PrincipalId, SessionId};
use crate::queries::raw;
use crate::types::Lease;
use rusqlite::Connection;
use serde::{Deserialize, Serialize};

/// Someone else's declared intent that overlaps yours.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Overlap {
    pub lease: Lease,
    pub holder: PrincipalId,
    /// The patterns of yours and theirs that collide.
    pub paths: Vec<String>,
    /// True when their work already landed somewhere you are editing —
    /// a rebase is coming, not merely possible.
    pub already_landed: bool,
}

/// Does a declared pattern cover a path? Patterns are literal paths or
/// directory prefixes ending in `/`, plus a trailing `*` wildcard —
/// deliberately small, because a lease a person cannot read at a glance
/// is a lease nobody will trust.
pub fn covers(pattern: &str, path: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        return path.starts_with(prefix);
    }
    if pattern.ends_with('/') {
        return path.starts_with(pattern);
    }
    path == pattern
}

/// Do two declarations describe any common ground?
pub fn patterns_overlap(a: &str, b: &str) -> bool {
    covers(a, b) || covers(b, a) || {
        // Two prefixes overlap when one contains the other.
        let (a_prefix, b_prefix) = (a.trim_end_matches('*'), b.trim_end_matches('*'));
        (a.ends_with('*') || a.ends_with('/'))
            && (b.ends_with('*') || b.ends_with('/'))
            && (a_prefix.starts_with(b_prefix) || b_prefix.starts_with(a_prefix))
    }
}

/// Which live leases collide with these paths, and how badly.
pub(crate) fn conflicts(
    conn: &Connection,
    repo: &str,
    paths: &[String],
    exclude_session: Option<&SessionId>,
) -> CoreResult<Vec<Overlap>> {
    let mut overlaps = Vec::new();
    for lease in raw::live_leases(conn, repo)? {
        if exclude_session.is_some_and(|session| lease.session == *session) {
            continue;
        }
        let colliding: Vec<String> = lease
            .paths
            .iter()
            .filter(|theirs| paths.iter().any(|ours| patterns_overlap(ours, theirs)))
            .cloned()
            .collect();
        if colliding.is_empty() {
            continue;
        }
        // A lease whose session already pushed a revision is further
        // along: whatever lands first, someone is rebasing.
        let already_landed = raw::session_has_revision(conn, lease.session.as_str())?;
        overlaps.push(Overlap {
            holder: lease.holder.clone(),
            lease,
            paths: colliding,
            already_landed,
        });
    }
    // Loudest first: work already in flight matters more than intent.
    overlaps.sort_by_key(|o| (!o.already_landed, o.lease.session.as_str().to_owned()));
    Ok(overlaps)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn patterns_cover_what_they_should() {
        assert!(covers("src/main.rs", "src/main.rs"));
        assert!(!covers("src/main.rs", "src/main.rs.bak"));
        assert!(covers("src/", "src/deep/file.rs"));
        assert!(!covers("src/", "srcish/file.rs"));
        assert!(covers("crates/core/*", "crates/core/src/lib.rs"));
        assert!(!covers("crates/core/*", "crates/server/src/lib.rs"));
    }

    #[test]
    fn overlap_is_symmetric_and_prefix_aware() {
        assert!(patterns_overlap("src/", "src/main.rs"));
        assert!(patterns_overlap("src/main.rs", "src/"));
        assert!(patterns_overlap("crates/", "crates/core/"));
        assert!(patterns_overlap("crates/core/*", "crates/"));
        assert!(!patterns_overlap("crates/core/", "crates/server/"));
        assert!(!patterns_overlap("README.md", "LICENSE"));
    }
}
