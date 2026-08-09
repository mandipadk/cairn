//! The cairn core: an event-sourced graph of software work.
//!
//! A traditional forge stores code and conversation about code. This core
//! stores the full causal graph of how software comes to exist:
//!
//! - [`Principal`]s — the humans and agents doing the work
//! - Tasks — durable statements of intent ("what and why")
//! - Sessions — individual agent runs against a task ("the attempt")
//! - Changes and revisions — the produced code ("the output")
//! - Claims — structured, reproducible verification assertions,
//!   including what was *not* checked
//! - Verdicts — typed review judgments
//! - Merges — outcomes decided by explainable policy, never by ambient
//!   authority
//!
//! Every mutation is an [`Event`] in an append-only log; all other state is
//! a projection kept transactionally consistent with the log. Consumers
//! resume from any [`EventSeq`] cursor, which is what makes the graph a
//! reliable substrate for stateless agents: the forge remembers, so they
//! don't have to.
//!
//! This crate is pure domain logic over SQLite. It knows nothing about
//! HTTP, git transport, or rendering — those are adapters in sibling
//! crates.
//!
//! [`Principal`]: types::Principal
//! [`Event`]: event::Event
//! [`EventSeq`]: event::EventSeq

mod commands;
mod error;
mod event;
mod id;
mod policy;
mod queries;
mod store;
mod types;

pub use error::{CoreError, CoreResult};
pub use event::{Envelope, Event, EventSeq};
pub use id::{ChangeId, ClaimId, PrincipalId, SessionId, TaskId, VerdictId};
pub use policy::{PolicyTrace, Requirement};
pub use store::Store;
pub use types::{
    Change, ChangeSpec, ChangeState, Claim, ClaimKind, ClaimSpec, Disposition, Principal,
    PrincipalKind, Repo, ReviewDomain, Revision, Session, SessionState, Task, TaskState, Verdict,
};
