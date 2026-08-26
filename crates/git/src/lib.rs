//! Git storage and transport adapter for the cairn graph.
//!
//! This crate is commodity glue by design: the differentiated model
//! lives in `cairn-core`, and this layer's whole job is to let plain
//! `git` speak to it — hosting bare repos, serving smart HTTP by
//! spawning real git, framing pkt-lines for the proc-receive hook, and
//! parsing commit objects for the Change-Id trailer that keeps a
//! change's identity stable across amends.

pub mod commit;
pub mod pkt;
mod store;

pub use commit::{CommitInfo, parse_commit_object};
pub use store::{GitError, GitResult, GitStore, MIN_GIT, RebaseOutcome, Service, preflight};
