//! Git storage and transport adapter for the ambolt graph.
//!
//! This crate is commodity glue by design: the differentiated model
//! lives in `ambolt-core`, and this layer's whole job is to let plain
//! `git` speak to it — hosting bare repos, serving smart HTTP by
//! spawning real git, framing pkt-lines for the proc-receive hook, and
//! parsing commit objects for the Change-Id trailer that keeps a
//! change's identity stable across amends.

pub mod commit;
pub mod pkt;
mod store;

pub use commit::{CommitInfo, parse_commit_object};
pub use store::{
    Blob, GitError, GitResult, GitStore, MAX_COMMAND_BYTES, MIN_GIT, MIN_GIT_SHA256_CLIENT,
    NOTES_REF, RebaseOutcome, RpcInput, RpcStream, Service, preflight, version,
};
