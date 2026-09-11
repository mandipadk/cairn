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

/// The version this build reports: the crate version, then the commit
/// and its date as `build.rs` found them (or what CAIRN_BUILD said).
pub const VERSION: &str = concat!(env!("CARGO_PKG_VERSION"), " (", env!("CAIRN_BUILD"), ")");

mod attention;
mod commands;
mod error;
mod event;
mod id;
mod leases;
mod policy;
mod queries;
mod record;
mod search;
mod store;
mod types;

pub use attention::{AttentionItem, Draw, Signal, SignalKind};
pub use commands::{
    INVITATION_LABEL, MAILED_INVITATION_LABEL, password_acceptable, until_in_days, verify_password,
};
pub use error::{CoreError, CoreResult};
pub use event::{Envelope, Event, EventSeq};
pub use id::{
    ChangeId, ClaimId, GrantId, PrincipalId, RESERVED_IDS, SessionId, TaskId, ThreadId, TokenId,
    VerdictId, VerificationId, split_repo_name, validate_repo_name,
};
pub use leases::{Overlap, covers, patterns_overlap};
pub use policy::{PolicyTrace, Requirement};
pub use policy::{packs, path_matches};
pub use record::Record;
pub use search::{HitKind, SearchHit, SearchQuery};
pub use store::Store;
pub use types::Anchor;
pub use types::QuotaOverride;
pub use types::Report;
pub use types::Tag;
pub use types::Usage;
pub use types::WaitlistEntry;
pub use types::{
    BrowserSession, Capability, Change, ChangeSpec, ChangeState, Claim, ClaimKind, ClaimSpec,
    Contact, Cover, DebtSnapshot, Disposition, EarnedTrust, Grant, IdentityLink, Independence,
    Lease, Lesson, LineState, Mirror, Notice, ObjectFormat, PackOrigin, PasskeyRecord, Policy,
    PolicyPack, Preference, Principal, PrincipalKind, Provenance, QueueEntry, Quota, Receipt,
    Replay, Reply, Repo, Resolution, Resolved, ReviewDomain, Revision, Scope, Session,
    SessionState, Side, Simulated, Simulation, Task, TaskState, Thread, ThreadKind, TokenInfo,
    Verdict, Verification, Visibility, Waiver, WorkloadBinding, canonical_json, line_state,
};
pub use types::{GraduatedRepo, Graduation};
