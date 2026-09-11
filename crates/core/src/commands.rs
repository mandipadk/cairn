//! Write side of the graph: the protocol verbs.
//!
//! Each command runs validate → append → apply in one transaction, so a
//! command either fully happens (event logged, projections consistent)
//! or leaves no trace. The verbs deliberately mirror how work actually
//! flows: claim a task, open a session, push revisions, attach claims,
//! collect verdicts, merge under policy.

use crate::error::{CoreError, CoreResult};
use crate::event::{Envelope, Event};
use crate::id::{
    ChangeId, ClaimId, GrantId, PrincipalId, SessionId, TaskId, ThreadId, TokenId, VerdictId,
    VerificationId, random_token_secret, validate_slug,
};
use crate::leases::{self, Overlap};
use crate::policy::{self, PolicyTrace};
use crate::queries::raw;
use crate::store::{Store, append};
use crate::types::{
    Anchor, BrowserSession, Capability, Change, ChangeSpec, ChangeState, ClaimSpec, Contact,
    Disposition, Mirror, ObjectFormat, PasskeyRecord, Policy, Principal, PrincipalKind, Quota,
    Replay, Resolution, ReviewDomain, Scope, SessionState, TaskState, ThreadKind, Usage,
    Visibility,
};
use rusqlite::OptionalExtension;
use rusqlite::Transaction;
use sha2::{Digest, Sha256};

/// The stored fingerprint of a token secret.
pub(crate) fn token_hash(secret: &str) -> String {
    Sha256::digest(secret.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn ensure_actor(tx: &Transaction, actor: &PrincipalId) -> CoreResult<Principal> {
    let principal = raw::principal(tx, actor.as_str())?
        .ok_or_else(|| CoreError::NotFound(format!("principal {actor}")))?;
    if !principal.active {
        return Err(CoreError::Forbidden(format!(
            "{actor} is deactivated; whoever runs the forge can reactivate them"
        )));
    }
    // A team never acts. Its members do, carrying its grants.
    if principal.kind == PrincipalKind::Team {
        return Err(CoreError::Forbidden(format!(
            "{actor} is a team; teams hold authority and their members act with it"
        )));
    }
    Ok(principal)
}

/// The law: humans are sovereign; agents act only under a live grant
/// covering the capability and scope. Refusals name the missing
/// capability and how to obtain it, so an agent can act on them.
fn authorize(
    tx: &Transaction,
    acting: Option<&Scope>,
    actor: &PrincipalId,
    action: Capability,
    repo: Option<&str>,
) -> CoreResult<Principal> {
    let principal = ensure_actor(tx, actor)?;

    // A session credential is checked before any grant: it carries what
    // it carries, and a leak of it buys no more than that.
    if let Some(scope) = acting
        && !scope.covers(action, repo)
    {
        return Err(CoreError::Forbidden(format!(
            "this session credential carries {}; '{}' on {} is outside it",
            scope.describe(),
            action.as_str(),
            repo.unwrap_or("the forge")
        )));
    }
    // A repository may insist that agents work inside sessions, so no
    // standing token of theirs can push, review or merge on it.
    if acting.is_none()
        && principal.kind == PrincipalKind::Agent
        && matches!(
            action,
            Capability::Push | Capability::Review | Capability::Merge
        )
        && let Some(name) = repo
        && raw::repo(tx, name)?.is_some_and(|r| r.policy.agents_act_in_sessions)
    {
        return Err(CoreError::Forbidden(format!(
            "{name} requires agents to act inside a session: claim a task, open a session on it \
             (POST /api/tasks/{{task}}/sessions), and act with its credential \
             (POST /api/sessions/{{session}}/credential)"
        )));
    }

    // Ownership is the one authority nobody is granted: it comes with
    // having made the thing, or belonging to the organisation that did.
    // Everything else — for humans exactly as for agents — is a grant
    // somebody issued and can take back.
    //
    // This used to read "if the principal is a human, allow it", which
    // is right for a forge with one operator and wrong the moment there
    // are two: it made every person who could sign in an administrator
    // of everybody else's work. "Human" was standing in for "the person
    // running this", and those stopped being the same thing.
    if let Some(name) = repo
        && let Some(record) = raw::repo(tx, name)?
        && raw::owns(tx, actor.as_str(), record.owner.as_str())?
    {
        return Ok(principal);
    }

    let grants = raw::effective_grants(tx, actor.as_str())?;
    let now = jiff::Timestamp::now().to_string();
    if raw::grants_cover(&grants, action, repo, &now) {
        return Ok(principal);
    }
    // An unscoped admin grant is what running the forge looks like:
    // registering people, and reaching into repositories you do not own.
    if raw::grants_cover(&grants, Capability::Admin, None, &now) {
        return Ok(principal);
    }

    let scope = repo.map_or_else(|| "all repos".to_owned(), |r| format!("repo {r}"));
    Err(CoreError::Forbidden(format!(
        "{actor} holds no '{}' capability for {scope}; someone who does can issue one: \
         POST /api/grants {{\"grantee\": \"{actor}\", \"actions\": [\"{}\"]}}",
        action.as_str(),
        action.as_str()
    )))
}

/// Who may take part in a change's discussion: the repository's owner,
/// the change's owner, or anyone holding a capability on the repository.
/// Reading alone is not enough - a concern is a commitment the change
/// then carries, and that is not for passers-by to impose.
fn may_discuss(
    tx: &Transaction,
    acting: Option<&Scope>,
    actor: &PrincipalId,
    change: &Change,
) -> CoreResult<Principal> {
    let principal = ensure_actor(tx, actor)?;
    // The owner's shortcut below never consults the scope, so it is
    // asked here: a credential drawn for one repository's work takes
    // no part in another's discussion, even on its holder's own change.
    if let Some(scope) = acting
        && let Some(mine) = &scope.repo
        && *mine != change.repo
    {
        return Err(CoreError::Forbidden(format!(
            "a credential scoped to {mine} takes no part in {}",
            change.repo
        )));
    }
    if change.owner == *actor {
        return Ok(principal);
    }
    let any = [
        Capability::Review,
        Capability::Push,
        Capability::Merge,
        Capability::Verify,
        Capability::Task,
    ];
    if any
        .iter()
        .any(|&c| authorize(tx, acting, actor, c, Some(&change.repo)).is_ok())
    {
        return Ok(principal);
    }
    Err(CoreError::Forbidden(format!(
        "{actor} has no part in {}: its owner, the change's owner, or a holder of a \
         capability on it may take part in discussion",
        change.repo
    )))
}

/// An archived repository takes nothing new. Reads go on; the refusal
/// says how to change that.
fn ensure_writable(tx: &Transaction, repo: &str) -> CoreResult<()> {
    match raw::repo(tx, repo)? {
        Some(record) if record.archived => Err(CoreError::Conflict(format!(
            "{repo} is archived and takes nothing new; unarchive it first"
        ))),
        _ => Ok(()),
    }
}

/// Free text a caller controls is bounded, because an append-only log
/// keeps whatever it is given forever. The limits are generous enough
/// that no honest use meets them.
const MAX_TITLE: usize = 300;
const MAX_TEXT: usize = 8_000;
/// Paths recorded on one revision, at most.
const MAX_PATHS: usize = 1_000;
/// Agents one task may invite at once, at most.
const MAX_ATTEMPTS: u32 = 8;
const MAX_ITEMS: usize = 64;

fn bounded(what: &str, value: &str, limit: usize) -> CoreResult<()> {
    require(value.len() <= limit, || {
        format!("{what} is longer than {limit} bytes")
    })
}

fn require(condition: bool, invalid: impl FnOnce() -> String) -> CoreResult<()> {
    if condition {
        Ok(())
    } else {
        Err(CoreError::Invalid(invalid()))
    }
}

fn valid_branch(name: &str) -> bool {
    !name.is_empty()
        && !name.starts_with(['-', '/'])
        && !name.ends_with('/')
        && !name.contains("..")
        && !name.contains(|c: char| c.is_whitespace() || c == '\\' || c == ':' || c == '~')
}

/// An argon2id hash of a password nobody has, so an unknown principal
/// costs the same to reject as a known one with the wrong password.
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2E$\
                          Gg3AaAVKu1SLGmpQr2WPuoYSJKM9C8pTVWKFGRZuq1o";

fn hash_password(password: &str) -> CoreResult<String> {
    use argon2::password_hash::{PasswordHasher, SaltString};
    // The salt is random per password; `rand` is already a dependency,
    // so take it from there rather than enabling another RNG feature.
    let mut bytes = [0u8; 16];
    rand::fill(&mut bytes);
    let salt = SaltString::encode_b64(&bytes)
        .map_err(|e| CoreError::Invalid(format!("salt encoding failed: {e}")))?;
    argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map(|hash| hash.to_string())
        .map_err(|e| CoreError::Invalid(format!("hashing failed: {e}")))
}

/// Long enough to resist guessing, short enough that a password manager's
/// output always fits. Checked before anything one-time is spent on it.
pub fn password_acceptable(password: &str) -> CoreResult<()> {
    require((12..=1024).contains(&password.len()), || {
        "a password must be between 12 and 1024 characters".into()
    })
}

pub fn verify_password(password: &str, hash: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    PasswordHash::new(hash)
        .map(|parsed| {
            argon2::Argon2::default()
                .verify_password(password.as_bytes(), &parsed)
                .is_ok()
        })
        .unwrap_or(false)
}

/// Deliberately loose. Address syntax is far stranger than any regex
/// people write for it, and the only real proof is sending mail — so
/// this rejects what is obviously not an address and accepts the rest.
fn valid_email(value: &str) -> bool {
    let bytes = value.len();
    if !(3..=320).contains(&bytes) || value.chars().any(char::is_whitespace) {
        return false;
    }
    if value.matches('@').count() != 1
        || value
            .chars()
            .any(|c| matches!(c, ',' | ';' | '<' | '>' | '"'))
    {
        return false;
    }
    match value.split_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    }
}

fn valid_commit_oid(oid: &str) -> bool {
    matches!(oid.len(), 40 | 64) && oid.chars().all(|c| c.is_ascii_hexdigit())
}

/// Who may start a repository.
///
/// Any person may, and becomes its owner — the same bargain every forge
/// offers, and the thing that makes ownership meaningful rather than a
/// label an administrator assigns. An agent needs an admin grant,
/// because an agent creating repositories on its own initiative is not
/// something to allow by default.
/// Whether `actor` may act as `owner` when making or taking something
/// an owner holds: themselves, an organisation they belong to, or
/// anyone at all for whoever runs the forge.
fn may_act_for(
    tx: &Transaction,
    acting: Option<&Scope>,
    actor: &PrincipalId,
    owner: &PrincipalId,
) -> CoreResult<()> {
    let record = raw::principal(tx, owner.as_str())?
        .ok_or_else(|| CoreError::NotFound(format!("principal {owner}")))?;
    // Checked before the shortcut below, so an agent cannot be an owner
    // by being the one asking.
    require(record.kind != PrincipalKind::Agent, || {
        format!("{owner} is an agent; a person or an organisation owns things here")
    })?;
    // A stopped account takes nothing new. What is registered under it
    // would be held by nobody: its holder cannot mint for it or retire
    // it, and it would sit in the dead account's quota until an admin
    // noticed.
    if !record.active {
        return Err(CoreError::Conflict(format!(
            "{owner} is deactivated and takes nothing new"
        )));
    }
    if owner == actor {
        return Ok(());
    }
    match record.kind {
        PrincipalKind::Team if raw::is_team_member(tx, owner.as_str(), actor.as_str())? => Ok(()),
        _ => authorize(tx, acting, actor, Capability::Admin, None)
            .map(|_| ())
            .map_err(|_| {
                CoreError::Forbidden(format!(
                    "{actor} may not act for {owner}: not a member of it, and not running the forge"
                ))
            }),
    }
}

/// Refuse when one more of `what` would put `owner` past what this
/// forge allows them. The refusal names both numbers, because "you
/// cannot" without "you have 50 and the limit is 50" leaves the reader
/// guessing whether to delete something or ask for more.
fn within_quota(
    tx: &Transaction,
    default: &Quota,
    owner: &PrincipalId,
    what: &str,
    limit: impl Fn(&Quota) -> Option<u32>,
    have: impl Fn(&Usage) -> u32,
) -> CoreResult<()> {
    let quota = default.under(&raw::quota(tx, owner.as_str())?.unwrap_or_default());
    let Some(limit) = limit(&quota) else {
        return Ok(());
    };
    let have = have(&raw::usage(tx, owner.as_str())?);
    if have < limit {
        return Ok(());
    }
    Err(CoreError::OverQuota(format!(
        "{owner} has {have} {what}, and this forge allows {limit}"
    )))
}

/// What a principal is, at the moment it is registered. A struct
/// because the alternative is an eight-argument function nobody can
/// read at a call site.
struct NewPrincipal<'a> {
    owner: Option<&'a PrincipalId>,
    kind: PrincipalKind,
    display: &'a str,
    model: Option<&'a str>,
    harness: Option<&'a str>,
}

/// Whether `actor` holds this agent: they own it, or they belong to the
/// organisation that does. An agent its owner cannot give a token, grant
/// a capability or retire is an agent they do not really have.
fn holds_agent(tx: &Transaction, actor: &PrincipalId, subject: &Principal) -> CoreResult<bool> {
    let Some(owner) = subject.owner.as_ref() else {
        return Ok(false);
    };
    if subject.kind != PrincipalKind::Agent {
        return Ok(false);
    }
    // An agent holds nothing: not its owner's other agents, and not the
    // agents of a team somebody put it on. Holding is minting tokens and
    // stopping, and an agent that could do that to its siblings could
    // walk sideways into every grant they hold.
    if raw::principal(tx, actor.as_str())?.is_none_or(|acting| acting.kind != PrincipalKind::Human)
    {
        return Ok(false);
    }
    // The owner has to be somebody who can hold things now. A log from
    // before agents were owned can name an agent as an owner, or a
    // principal since deactivated, and neither should confer anything.
    let Some(record) = raw::principal(tx, owner.as_str())? else {
        return Ok(false);
    };
    if record.kind == PrincipalKind::Agent || !record.active {
        return Ok(false);
    }
    raw::owns(tx, actor.as_str(), owner.as_str())
}

/// Registering a principal is a human act, the way delegation is. An
/// agent does not make principals — not for itself, not for its owner,
/// and not for anybody else even holding the grant that runs the forge,
/// because an agent with that grant registering agents under other
/// people's names and holding their tokens is a thing no operator
/// meant to allow by handing an agent admin. Whatever runs on the
/// operator's behalf acts as the operator, with the operator's own
/// token, and is the operator's to answer for.
fn may_make_principals(tx: &Transaction, actor: &PrincipalId) -> CoreResult<()> {
    let principal = ensure_actor(tx, actor)?;
    if principal.kind == PrincipalKind::Human {
        return Ok(());
    }
    Err(CoreError::Forbidden(format!(
        "{actor} may not register principals: registering is a human act"
    )))
}

/// The same rule, for every other act over principals: minting a
/// token for somebody else, stopping or restarting them, moving a
/// repository between them. The admin grant lets a person run the
/// forge; it does not let an agent be the person, and an agent that
/// holds it (a log from before the grant refused agents can say so)
/// still finds these doors shut.
fn human_act(tx: &Transaction, actor: &PrincipalId, what: &str) -> CoreResult<()> {
    let principal = ensure_actor(tx, actor)?;
    if principal.kind == PrincipalKind::Human {
        return Ok(());
    }
    Err(CoreError::Forbidden(format!(
        "{actor} may not {what}: that is a human act"
    )))
}

/// Whether `actor` may push to `repo`, asked as a plain question. The
/// push door asks it before git is even spawned, so a caller who may
/// not push learns nothing about the repository's owner from the
/// refusal that follows.
pub(crate) fn may_push(
    tx: &Transaction,
    acting: Option<&Scope>,
    actor: &PrincipalId,
    repo: &str,
) -> bool {
    authorize(tx, acting, actor, Capability::Push, Some(repo)).is_ok()
}

/// Refuse a standing act to a session credential.
///
/// A scope says what a session may do with the work it was drawn for:
/// task, push, review, verify, merge. It never says "make a principal"
/// or "mint a credential", and `authorize` is the only place a scope is
/// consulted — so any path that reaches its answer another way, by
/// being your own or by holding the agent, must ask here instead.
fn not_under_a_scope(acting: Option<&Scope>, what: &str) -> CoreResult<()> {
    match acting {
        None => Ok(()),
        Some(scope) => Err(CoreError::Forbidden(format!(
            "a session credential may not {what}: it carries {}",
            scope.describe()
        ))),
    }
}

fn may_create_repo(tx: &Transaction, actor: &PrincipalId) -> CoreResult<()> {
    let principal = ensure_actor(tx, actor)?;
    if principal.kind == PrincipalKind::Human {
        return Ok(());
    }
    let grants = raw::effective_grants(tx, actor.as_str())?;
    let now = jiff::Timestamp::now().to_string();
    if raw::grants_cover(&grants, Capability::Admin, None, &now) {
        return Ok(());
    }
    Err(CoreError::Forbidden(format!(
        "{actor} may not create repositories: that needs an 'admin' grant"
    )))
}

/// The rules a new repository name must satisfy. One definition, used
/// both to answer "may this be created?" and to enforce it at creation,
/// so the two can never disagree.
fn new_repo_is_allowed(tx: &Transaction, name: &str, default_branch: &str) -> CoreResult<()> {
    require(crate::id::validate_repo_name(name), || {
        format!("repo name {name:?} is not owner/name, both lowercase slugs")
    })?;
    require(valid_branch(default_branch), || {
        format!("{default_branch:?} is not a valid branch name")
    })?;
    if raw::repo(tx, name)?.is_some() {
        return Err(CoreError::Conflict(format!("repo {name} already exists")));
    }
    Ok(())
}

impl Store {
    /// Register a principal. Bootstrap exception: the very first principal
    /// may register itself, since no authority exists yet to vouch for it.
    /// Deactivate or reactivate a principal. Running the forge decides;
    /// nobody deactivates themselves, so the forge always has someone
    /// left who can undo it.
    pub fn set_active(
        &mut self,
        actor: &PrincipalId,
        principal: &PrincipalId,
        active: bool,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        // Stopping and starting principals outlives any session, and
        // holding an agent is reached without the authority check
        // below, so the scope is asked first.
        not_under_a_scope(self.acting.as_ref(), "stop or restart a principal")?;
        // Authority before existence, so somebody with none cannot use
        // this to find out which names are taken. Retiring an agent you
        // hold is yours to do, and is how the room it takes in your
        // quota comes back.
        let found = raw::principal(&tx, principal.as_str())?;
        // Retiring an agent you hold is yours to do. Bringing one back is
        // not: deactivation is what whoever runs the forge does about an
        // agent that is misbehaving, and an undo in the hands of the
        // party it was aimed at is no lever at all.
        let holds = !active
            && match &found {
                Some(subject) => holds_agent(&tx, actor, subject)?,
                None => false,
            };
        if !holds {
            human_act(&tx, actor, "stop or restart another principal")?;
            authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        }
        require(actor != principal, || {
            "you cannot deactivate yourself; ask whoever else runs the forge".into()
        })?;
        let subject = found.ok_or_else(|| CoreError::NotFound(format!("principal {principal}")))?;
        if subject.active == active {
            return Err(CoreError::Conflict(format!(
                "{principal} is already {}",
                if active { "active" } else { "deactivated" }
            )));
        }
        // Coming back has to fit, or the limit is one on registering
        // rather than on having: retire twenty-five, make twenty-five
        // more, bring the first twenty-five back.
        if active
            && subject.kind == PrincipalKind::Agent
            && let Some(owner) = subject.owner.as_ref()
        {
            within_quota(
                &tx,
                &self.default_quota,
                owner,
                "agents",
                |q| q.agents,
                |u| u.agents,
            )?;
        }
        // Stopping a person or an organisation stops the agents they
        // hold. Their tokens resolve through the agent's own record, so
        // an owner whose agents kept running would be an owner who was
        // not stopped at all — only inconvenienced.
        if !active && subject.kind != PrincipalKind::Agent {
            for agent in raw::active_agents_of(&tx, principal.as_str())? {
                append(
                    &tx,
                    actor,
                    self.acting.as_ref().and_then(|s| s.session.as_ref()),
                    Event::PrincipalDeactivated {
                        principal: PrincipalId(agent),
                    },
                )?;
            }
            // And the credentials they drew for agents they do not own:
            // a member of a team mints a token for the team's agent and
            // keeps it in their own harness, and their leaving the team
            // would otherwise leave that token working. Their own
            // agents' tokens stop through the agents' records above.
            let drawn: Vec<String> = tx
                .prepare_cached(
                    "SELECT t.id FROM tokens t JOIN principals p ON p.id = t.principal
                      WHERE t.minted_by = ?1 AND t.revoked = 0 AND t.session IS NULL
                        AND p.kind = 'agent' AND p.owner IS NOT ?1
                      ORDER BY t.rowid",
                )?
                .query_map(rusqlite::params![principal.as_str()], |row| row.get(0))?
                .collect::<Result<Vec<_>, _>>()?;
            for token in drawn {
                append(
                    &tx,
                    actor,
                    self.acting.as_ref().and_then(|s| s.session.as_ref()),
                    Event::TokenRevoked {
                        token: TokenId(token),
                    },
                )?;
            }
        }
        let event = if active {
            Event::PrincipalReactivated {
                principal: principal.clone(),
            }
        } else {
            Event::PrincipalDeactivated {
                principal: principal.clone(),
            }
        };
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            event,
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Whether `actor` may push to `repo`, under the scope this handle
    /// is acting in.
    pub fn may_push(&self, actor: &PrincipalId, repo: &str) -> bool {
        let Ok(tx) = self.conn.unchecked_transaction() else {
            return false;
        };
        may_push(&tx, self.acting.as_ref(), actor, repo)
    }

    pub fn register_principal(
        &mut self,
        actor: &PrincipalId,
        id: &PrincipalId,
        kind: PrincipalKind,
        display: &str,
        model: Option<&str>,
        harness: Option<&str>,
    ) -> CoreResult<Envelope> {
        self.register(
            actor,
            id,
            NewPrincipal {
                owner: None,
                kind,
                display,
                model,
                harness,
            },
        )
    }

    /// Register an agent that belongs to `owner`.
    ///
    /// An agent is somebody's: the person who registered it, or an
    /// organisation they belong to, and it counts against that owner's
    /// quota. So a person may make their own agents without running the
    /// forge — the quota is what makes that safe — while registering a
    /// person or an organisation stays the operator's, because a name
    /// in the forge's namespace is not one owner's to hand out.
    pub fn register_agent_for(
        &mut self,
        actor: &PrincipalId,
        owner: Option<&PrincipalId>,
        id: &PrincipalId,
        display: &str,
        model: Option<&str>,
        harness: Option<&str>,
    ) -> CoreResult<Envelope> {
        self.register(
            actor,
            id,
            NewPrincipal {
                owner,
                kind: PrincipalKind::Agent,
                display,
                model,
                harness,
            },
        )
    }

    fn register(
        &mut self,
        actor: &PrincipalId,
        id: &PrincipalId,
        new: NewPrincipal<'_>,
    ) -> CoreResult<Envelope> {
        self.register_as(actor, id, new, false)
    }

    /// A stranger making their own account, where the forge allows it.
    /// The server asks whether sign-up is open; the store only knows how
    /// to write the fact. Recorded as the person registering themselves,
    /// so the log says who made the account: they did.
    pub fn sign_up(&mut self, id: &PrincipalId, display: &str) -> CoreResult<Envelope> {
        self.register_as(
            id,
            id,
            NewPrincipal {
                owner: None,
                kind: PrincipalKind::Human,
                display,
                model: None,
                harness: None,
            },
            true,
        )
    }

    fn register_as(
        &mut self,
        actor: &PrincipalId,
        id: &PrincipalId,
        new: NewPrincipal<'_>,
        by_themselves: bool,
    ) -> CoreResult<Envelope> {
        let NewPrincipal {
            owner,
            kind,
            display,
            model,
            harness,
        } = new;
        let tx = self.conn.transaction()?;
        require(!crate::id::RESERVED_IDS.contains(&id.as_str()), || {
            format!("{id} is reserved: the pages live at that address")
        })?;
        require(validate_slug(id.as_str()), || {
            format!("principal id {id:?} is not a valid slug")
        })?;
        require(!display.trim().is_empty(), || {
            "display name must not be empty".into()
        })?;
        bounded("display name", display, MAX_TITLE)?;
        if let Some(model) = model {
            bounded("model", model, MAX_TITLE)?;
        }
        if let Some(harness) = harness {
            bounded("harness", harness, MAX_TITLE)?;
        }
        if raw::principal(&tx, id.as_str())?.is_some() {
            return Err(CoreError::Conflict(format!(
                "principal {id} already exists"
            )));
        }
        let bootstrap = by_themselves || (raw::principal_count(&tx)? == 0 && actor == id);
        let owner = owner.unwrap_or(actor);
        if !bootstrap {
            not_under_a_scope(self.acting.as_ref(), "register a principal")?;
            may_make_principals(&tx, actor)?;
            if kind == PrincipalKind::Agent {
                may_act_for(&tx, self.acting.as_ref(), actor, owner)?;
                within_quota(
                    &tx,
                    &self.default_quota,
                    owner,
                    "agents",
                    |q| q.agents,
                    |u| u.agents,
                )?;
            } else {
                require(owner == actor, || {
                    "a person and an organisation belong to themselves".to_owned()
                })?;
                authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
            }
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::PrincipalRegistered {
                principal: id.clone(),
                principal_kind: kind,
                display: display.to_owned(),
                model: model.map(str::to_owned),
                harness: harness.map(str::to_owned),
                owner: (kind == PrincipalKind::Agent && owner != actor).then(|| owner.clone()),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Set a password for a human principal.
    ///
    /// A human sets their own; an admin sets anyone's, which is how
    /// somebody locked out gets back in without an email round trip this
    /// forge has no way to make. Agents never get one: they authenticate
    /// with tokens, and a password would be a second, weaker way in.
    ///
    /// Hashing happens here so the plaintext never leaves this call.
    pub fn set_password(
        &mut self,
        actor: &PrincipalId,
        principal: &PrincipalId,
        password: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        // A password outlives every session; a leaked task credential
        // that could set its holder's would be a takeover with a
        // fifteen-minute fuse.
        not_under_a_scope(self.acting.as_ref(), "set a password")?;
        let acting = ensure_actor(&tx, actor)?;
        let target = raw::principal(&tx, principal.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {principal}")))?;
        require(target.kind == PrincipalKind::Human, || {
            format!("{principal} is an agent; agents authenticate with tokens")
        })?;
        if acting.id != target.id {
            // Setting someone else's password is an authority question,
            // not a malformed request, so it answers like one.
            if acting.kind != PrincipalKind::Human {
                return Err(CoreError::Forbidden(format!(
                    "{actor} may not set another principal's password"
                )));
            }
            authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        }
        // Long enough to resist guessing, short enough that a password
        // manager's output always fits.
        password_acceptable(password)?;
        let hash = hash_password(password)?;
        // The credential is written outside the log, in the same
        // transaction as the fact that it changed — so the two cannot
        // disagree, and the secret can still be rotated or erased.
        tx.execute(
            "INSERT INTO credentials (principal, hash, set_at) VALUES (?, ?, ?)
             ON CONFLICT(principal) DO UPDATE SET hash = excluded.hash, set_at = excluded.set_at",
            rusqlite::params![principal.as_str(), hash, jiff::Timestamp::now().to_string()],
        )?;
        // Changing a password ends the sessions it was protecting.
        tx.execute(
            "DELETE FROM browser_sessions WHERE principal = ?",
            rusqlite::params![principal.as_str()],
        )?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::PasswordSet {
                principal: principal.clone(),
                hash: None,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Begin a browser session, returning the secret that names it.
    ///
    /// Only a hash of that secret is stored, for the same reason a token
    /// stores only a hash: reading the database must not yield working
    /// credentials. Sessions persist, so a deploy does not sign everyone
    /// out, and they carry an expiry so an abandoned one stops working
    /// on its own.
    pub fn start_session(
        &mut self,
        principal: &PrincipalId,
        ttl_days: i64,
        agent: Option<&str>,
    ) -> CoreResult<String> {
        // A session secret is a credential of the same weight as a
        // token, so it is generated the same way.
        let secret = format!("s{}", random_token_secret());
        let now = jiff::Timestamp::now();
        // Timestamps are absolute instants, so an expiry is expressed in
        // hours: calendar days are a civil-time idea and mean different
        // amounts of elapsed time across a DST boundary.
        let expires = now + jiff::Span::new().hours(ttl_days * 24);
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, principal)?;
        // Expired rows are dead weight; clear them whenever one is made.
        tx.execute(
            "DELETE FROM browser_sessions WHERE expires <= ?",
            rusqlite::params![now.to_string()],
        )?;
        // Which browser, roughly, so the owner can tell sessions apart.
        // Truncated: a user agent is untrusted input like any other.
        let agent: Option<String> = agent.map(|a| a.chars().take(200).collect());
        tx.execute(
            "INSERT INTO browser_sessions (id_hash, principal, created, expires, last_seen, agent)
             VALUES (?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                token_hash(&secret),
                principal.as_str(),
                now.to_string(),
                expires.to_string(),
                now.to_string(),
                agent
            ],
        )?;
        tx.commit()?;
        Ok(secret)
    }

    /// Note that a session was just used. Written at most every few
    /// minutes, so an ordinary page view does not become a write.
    pub fn touch_session(&mut self, secret: &str) -> CoreResult<()> {
        let now = jiff::Timestamp::now();
        let stale = (now - jiff::Span::new().minutes(5)).to_string();
        self.conn.execute(
            "UPDATE browser_sessions SET last_seen = ?
              WHERE id_hash = ? AND (last_seen IS NULL OR last_seen < ?)",
            rusqlite::params![now.to_string(), token_hash(secret), stale],
        )?;
        Ok(())
    }

    /// Every live session this principal holds, marking the one asking.
    pub fn sessions_of(
        &self,
        principal: &PrincipalId,
        current: Option<&str>,
    ) -> CoreResult<Vec<BrowserSession>> {
        let current_hash = current.map(token_hash);
        let now = jiff::Timestamp::now().to_string();
        Ok(self
            .conn
            .prepare_cached(
                "SELECT id_hash, created, expires, last_seen, agent FROM browser_sessions
                  WHERE principal = ? AND expires > ? ORDER BY last_seen DESC, created DESC",
            )?
            .query_map(rusqlite::params![principal.as_str(), now], |row| {
                let hash: String = row.get(0)?;
                Ok(BrowserSession {
                    current: current_hash.as_deref() == Some(hash.as_str()),
                    id: hash.chars().take(12).collect(),
                    created: row.get(1)?,
                    expires: row.get(2)?,
                    last_seen: row.get(3)?,
                    agent: row.get(4)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// End one of your own sessions by the id the list shows.
    pub fn end_browser_session_by_id(
        &mut self,
        principal: &PrincipalId,
        id: &str,
    ) -> CoreResult<bool> {
        require(
            id.len() == 12 && id.chars().all(|c| c.is_ascii_hexdigit()),
            || "that is not a session id".to_owned(),
        )?;
        let n = self.conn.execute(
            "DELETE FROM browser_sessions WHERE principal = ? AND id_hash LIKE ?",
            rusqlite::params![principal.as_str(), format!("{id}%")],
        )?;
        Ok(n > 0)
    }

    /// End every session but the one asking.
    pub fn end_other_sessions(
        &mut self,
        principal: &PrincipalId,
        current: &str,
    ) -> CoreResult<usize> {
        let n = self.conn.execute(
            "DELETE FROM browser_sessions WHERE principal = ? AND id_hash != ?",
            rusqlite::params![principal.as_str(), token_hash(current)],
        )?;
        Ok(n)
    }

    /// Whose session this is, if it is live.
    pub fn session_holder(&self, secret: &str) -> Option<PrincipalId> {
        self.conn
            .prepare_cached(
                "SELECT s.principal FROM browser_sessions s
                  JOIN principals p ON p.id = s.principal AND p.active = 1
                  WHERE s.id_hash = ? AND s.expires > ?",
            )
            .ok()?
            .query_row(
                rusqlite::params![token_hash(secret), jiff::Timestamp::now().to_string()],
                |row| row.get::<_, String>(0),
            )
            .ok()
            .map(PrincipalId)
    }

    /// End one session — signing out.
    pub fn end_browser_session(&mut self, secret: &str) -> CoreResult<()> {
        self.conn.execute(
            "DELETE FROM browser_sessions WHERE id_hash = ?",
            rusqlite::params![token_hash(secret)],
        )?;
        Ok(())
    }

    /// End every session a principal holds.
    pub fn end_browser_sessions_of(&mut self, principal: &PrincipalId) -> CoreResult<()> {
        self.conn.execute(
            "DELETE FROM browser_sessions WHERE principal = ?",
            rusqlite::params![principal.as_str()],
        )?;
        Ok(())
    }

    /// Record someone asking to be told when this is ready.
    ///
    /// Returns whether they were new, so the page can say something
    /// truthful either way without leaking whether an address is
    /// already on the list to whoever guesses it.
    pub fn join_waitlist(
        &mut self,
        email: &str,
        note: Option<&str>,
        company: Option<&str>,
    ) -> CoreResult<bool> {
        let email = email.trim();
        require(valid_email(email), || {
            "that does not look like an email address".into()
        })?;
        if let Some(note) = note {
            bounded("note", note, MAX_TITLE)?;
        }
        let company = company.map(str::trim).filter(|c| !c.is_empty());
        if let Some(company) = company {
            bounded("company", company, MAX_TITLE)?;
        }
        let changed = self.conn.execute(
            "INSERT INTO waitlist (email, joined, note, company) VALUES (?, ?, ?, ?)
             ON CONFLICT(email) DO NOTHING",
            rusqlite::params![
                email.to_lowercase(),
                jiff::Timestamp::now().to_string(),
                note.filter(|n| !n.trim().is_empty()),
                company,
            ],
        )?;
        Ok(changed == 1)
    }

    /// The waitlist, oldest first.
    pub fn waitlist(&self) -> CoreResult<Vec<crate::types::WaitlistEntry>> {
        Ok(self
            .conn
            .prepare("SELECT email, joined, note, company FROM waitlist ORDER BY joined")?
            .query_map([], |row| {
                Ok(crate::types::WaitlistEntry {
                    email: row.get(0)?,
                    joined: row.get(1)?,
                    note: row.get(2)?,
                    company: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Remove someone, because they asked. The whole reason this is not
    /// in the log.
    pub fn leave_waitlist(&mut self, email: &str) -> CoreResult<bool> {
        let removed = self.conn.execute(
            "DELETE FROM waitlist WHERE email = ?",
            rusqlite::params![email.trim().to_lowercase()],
        )?;
        Ok(removed == 1)
    }

    /// Take a stranger's account of what broke. Bounded like everything
    /// a caller controls; an address is optional and checked when given.
    pub fn file_report(
        &mut self,
        what: &str,
        place: &str,
        contact: &str,
        by: Option<&str>,
        version: &str,
    ) -> CoreResult<i64> {
        let what = what.trim();
        require(what.chars().count() >= 10, || {
            "say a little more: what you did, and what happened".into()
        })?;
        bounded("report", what, MAX_TEXT)?;
        let place = place.trim();
        bounded("where", place, MAX_TITLE)?;
        let contact = contact.trim().to_lowercase();
        require(contact.is_empty() || valid_email(&contact), || {
            "that does not look like an email address".into()
        })?;
        self.conn.execute(
            "INSERT INTO reports (filed, what, place, contact, by, version)
             VALUES (?, ?, ?, ?, ?, ?)",
            rusqlite::params![
                jiff::Timestamp::now().to_string(),
                what,
                (!place.is_empty()).then_some(place),
                (!contact.is_empty()).then_some(contact.as_str()),
                by,
                version
            ],
        )?;
        Ok(self.conn.last_insert_rowid())
    }

    /// What has been reported and not yet dismissed, newest first.
    pub fn reports(&self) -> CoreResult<Vec<crate::types::Report>> {
        Ok(self
            .conn
            .prepare(
                "SELECT id, filed, what, place, contact, by, version FROM reports ORDER BY id DESC",
            )?
            .query_map([], |row| {
                Ok(crate::types::Report {
                    id: row.get(0)?,
                    filed: row.get(1)?,
                    what: row.get(2)?,
                    place: row.get(3)?,
                    contact: row.get(4)?,
                    by: row.get(5)?,
                    version: row.get(6)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Drop a report, because it was dealt with or because whoever sent
    /// it asked.
    pub fn dismiss_report(&mut self, id: i64) -> CoreResult<bool> {
        let removed = self
            .conn
            .execute("DELETE FROM reports WHERE id = ?", rusqlite::params![id])?;
        Ok(removed == 1)
    }

    /// Where a report goes: the confirmed address of everyone who runs
    /// the forge. Nothing to configure, and nothing to leak to a
    /// stranger, since the addresses stay on the sending side.
    pub fn operator_addresses(&self) -> CoreResult<Vec<String>> {
        let mut addresses = Vec::new();
        for admin in raw::admins(&self.conn)? {
            let contact = self.contact_of(&PrincipalId(admin))?;
            if let (true, Some(email)) = (contact.verified, contact.email) {
                addresses.push(email);
            }
        }
        Ok(addresses)
    }

    /// What the log says about a principal over the last `window_days`.
    pub fn record_of(
        &self,
        principal: &PrincipalId,
        window_days: u32,
    ) -> CoreResult<crate::Record> {
        crate::record::record_of(&self.conn, principal.as_str(), window_days)
    }

    /// What this principal's write under `key` answered, if it has been
    /// made and is still remembered.
    pub fn replay_for(&self, principal: &PrincipalId, key: &str) -> CoreResult<Option<Replay>> {
        use rusqlite::OptionalExtension;
        Ok(self
            .conn
            .prepare_cached(
                "SELECT fingerprint, status, content_type, body FROM idempotency
                  WHERE principal = ?1 AND key = ?2 AND created > ?3",
            )?
            .query_row(
                rusqlite::params![principal.as_str(), key, replays_kept_since()],
                |row| {
                    Ok(Replay {
                        fingerprint: row.get(0)?,
                        status: row.get::<_, i64>(1)? as u16,
                        content_type: row.get(2)?,
                        body: row.get(3)?,
                    })
                },
            )
            .optional()?)
    }

    /// Remember what a write answered, and forget what is too old to be
    /// asked about again.
    pub fn remember_replay(
        &mut self,
        principal: &PrincipalId,
        key: &str,
        replay: &Replay,
    ) -> CoreResult<()> {
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM idempotency WHERE created <= ?1",
            rusqlite::params![replays_kept_since()],
        )?;
        tx.execute(
            "INSERT OR REPLACE INTO idempotency
                 (principal, key, fingerprint, status, content_type, body, created)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            rusqlite::params![
                principal.as_str(),
                key,
                replay.fingerprint,
                i64::from(replay.status),
                replay.content_type,
                replay.body,
                jiff::Timestamp::now().to_string(),
            ],
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Check a password. Returns false for an unknown principal, one
    /// with no password, or a wrong password — and takes the same work
    /// to say so in the first two cases as the third, so the answer
    /// cannot be read off the clock.
    /// Whether this person can sign in with a password at all.
    pub fn has_password(&self, principal: &PrincipalId) -> bool {
        self.conn
            .query_row(
                "SELECT 1 FROM credentials WHERE principal = ?",
                rusqlite::params![principal.as_str()],
                |_| Ok(()),
            )
            .optional()
            .ok()
            .flatten()
            .is_some()
    }

    /// Begin putting an address on record: it is pending until a link
    /// mailed to it is followed, because an address nobody has proved
    /// they can read is not somewhere to send a credential. Returns the
    /// secret for that link. A new pending address replaces an old one;
    /// the verified address, if any, stays until the new one is proved.
    pub fn request_email(&mut self, who: &PrincipalId, email: &str) -> CoreResult<String> {
        let email = email.trim();
        require(valid_email(email), || {
            "that does not look like an email address".into()
        })?;
        let target = raw::principal(&self.conn, who.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {who}")))?;
        require(target.kind == PrincipalKind::Human, || {
            format!("{who} is not a person")
        })?;
        let now = jiff::Timestamp::now().to_string();
        let secret = random_token_secret();
        let expires = (jiff::Timestamp::now() + jiff::SignedDuration::from_hours(24)).to_string();
        let tx = self.conn.transaction()?;
        tx.execute(
            "INSERT INTO contact (principal, pending, set_at) VALUES (?1, ?2, ?3)
             ON CONFLICT (principal) DO UPDATE SET pending = ?2, set_at = ?3",
            rusqlite::params![who.as_str(), email, now],
        )?;
        tx.execute(
            "UPDATE email_verifications SET used = 1 WHERE principal = ? AND used = 0",
            rusqlite::params![who.as_str()],
        )?;
        tx.execute(
            "INSERT INTO email_verifications (token_hash, principal, email, expires)
             VALUES (?, ?, ?, ?)",
            rusqlite::params![token_hash(&secret), who.as_str(), email, expires],
        )?;
        tx.commit()?;
        Ok(secret)
    }

    /// Follow a verification link: the pending address becomes the
    /// address. Answers with who and what, or nothing for a link that
    /// is unknown, spent, or old.
    pub fn confirm_email(&mut self, secret: &str) -> CoreResult<Option<(PrincipalId, String)>> {
        let now = jiff::Timestamp::now().to_string();
        let tx = self.conn.transaction()?;
        let row: Option<(String, String)> = tx
            .prepare_cached(
                "SELECT principal, email FROM email_verifications
                  WHERE token_hash = ? AND used = 0 AND expires > ?",
            )?
            .query_row(rusqlite::params![token_hash(secret), now], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })
            .optional()?;
        let Some((who, email)) = row else {
            tx.commit()?;
            return Ok(None);
        };
        tx.execute(
            "UPDATE email_verifications SET used = 1 WHERE token_hash = ?",
            rusqlite::params![token_hash(secret)],
        )?;
        Self::record_verified(&tx, &who, &email, &now)?;
        tx.commit()?;
        Ok(Some((PrincipalId(who), email)))
    }

    /// An invitation mailed to an address and then followed proves that
    /// address as surely as a verification link would.
    pub fn mark_email_verified(&mut self, who: &PrincipalId, email: &str) -> CoreResult<()> {
        let now = jiff::Timestamp::now().to_string();
        let tx = self.conn.transaction()?;
        Self::record_verified(&tx, who.as_str(), email, &now)?;
        tx.commit()?;
        Ok(())
    }

    fn record_verified(tx: &Transaction, who: &str, email: &str, now: &str) -> CoreResult<()> {
        tx.execute(
            "INSERT INTO contact (principal, email, verified_at, pending, set_at)
             VALUES (?1, ?2, ?3, NULL, ?3)
             ON CONFLICT (principal) DO UPDATE
                 SET email = ?2, verified_at = ?3, pending = NULL, set_at = ?3",
            rusqlite::params![who, email, now],
        )?;
        Ok(())
    }

    pub fn contact_of(&self, who: &PrincipalId) -> CoreResult<Contact> {
        Ok(self
            .conn
            .prepare_cached("SELECT email, verified_at, pending FROM contact WHERE principal = ?")?
            .query_row(rusqlite::params![who.as_str()], |row| {
                Ok(Contact {
                    email: row.get(0)?,
                    verified: row.get::<_, Option<String>>(1)?.is_some(),
                    pending: row.get(2)?,
                })
            })
            .optional()?
            .unwrap_or_default())
    }

    /// Whose verified address this is. A pending address identifies
    /// nobody: anyone can type anyone's address into a form.
    pub fn principal_by_email(&self, email: &str) -> CoreResult<Option<PrincipalId>> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT principal FROM contact
                  WHERE email = ? AND verified_at IS NOT NULL ORDER BY set_at LIMIT 1",
            )?
            .query_row(rusqlite::params![email.trim()], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
            .map(PrincipalId))
    }

    /// Record that somebody needs a way back in, on a forge that could
    /// not mail them one. Recorded as an event so the people who run
    /// the forge are told, and so the asking is on the record.
    pub fn request_password_reset(&mut self, who: &PrincipalId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let target = raw::principal(&tx, who.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {who}")))?;
        require(target.kind == PrincipalKind::Human, || {
            format!("{who} is not a person")
        })?;
        let env = append(
            &tx,
            who,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::PasswordResetRequested {
                principal: who.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// The stable, opaque id a person is known by to their authenticators.
    /// Made once, kept forever: changing it would orphan every passkey.
    pub fn passkey_user_id(&mut self, who: &PrincipalId) -> CoreResult<String> {
        if let Some(id) = self
            .conn
            .prepare_cached("SELECT user_id FROM passkey_users WHERE principal = ?")?
            .query_row(rusqlite::params![who.as_str()], |row| {
                row.get::<_, String>(0)
            })
            .optional()?
        {
            return Ok(id);
        }
        let id = random_token_secret();
        self.conn.execute(
            "INSERT INTO passkey_users (principal, user_id) VALUES (?, ?)",
            rusqlite::params![who.as_str(), id],
        )?;
        Ok(id)
    }

    pub fn add_passkey(
        &mut self,
        who: &PrincipalId,
        cred_id: &str,
        passkey_json: &str,
        label: &str,
    ) -> CoreResult<()> {
        bounded("passkey label", label, MAX_TITLE)?;
        let now = jiff::Timestamp::now().to_string();
        let n = self.conn.execute(
            "INSERT OR IGNORE INTO passkeys (cred_id, principal, passkey, label, created)
             VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![cred_id, who.as_str(), passkey_json, label.trim(), now],
        )?;
        require(n == 1, || "that passkey is already registered".to_owned())?;
        Ok(())
    }

    pub fn passkeys_of(&self, who: &PrincipalId) -> CoreResult<Vec<PasskeyRecord>> {
        Ok(self
            .conn
            .prepare_cached(
                "SELECT cred_id, label, created, last_used FROM passkeys
                  WHERE principal = ? ORDER BY created",
            )?
            .query_map(rusqlite::params![who.as_str()], |row| {
                Ok(PasskeyRecord {
                    cred_id: row.get(0)?,
                    label: row.get(1)?,
                    created: row.get(2)?,
                    last_used: row.get(3)?,
                })
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// The stored credentials of one person, as the JSON the server put in.
    pub fn passkey_json_of(&self, who: &PrincipalId) -> CoreResult<Vec<String>> {
        Ok(self
            .conn
            .prepare_cached("SELECT passkey FROM passkeys WHERE principal = ?")?
            .query_map(rusqlite::params![who.as_str()], |row| {
                row.get::<_, String>(0)
            })?
            .collect::<Result<Vec<_>, _>>()?)
    }

    /// Whose credential this is.
    pub fn passkey_owner(&self, cred_id: &str) -> CoreResult<Option<PrincipalId>> {
        Ok(self
            .conn
            .prepare_cached("SELECT principal FROM passkeys WHERE cred_id = ?")?
            .query_row(rusqlite::params![cred_id], |row| row.get::<_, String>(0))
            .optional()?
            .map(PrincipalId))
    }

    /// Whose user id this is, for a discoverable sign-in that names the
    /// user handle rather than the credential.
    pub fn principal_for_passkey_user(&self, user_id: &str) -> CoreResult<Option<PrincipalId>> {
        Ok(self
            .conn
            .prepare_cached("SELECT principal FROM passkey_users WHERE user_id = ?")?
            .query_row(rusqlite::params![user_id], |row| row.get::<_, String>(0))
            .optional()?
            .map(PrincipalId))
    }

    /// After a sign-in: the credential's counter moved, and it was used.
    pub fn touch_passkey(&mut self, cred_id: &str, passkey_json: &str) -> CoreResult<()> {
        self.conn.execute(
            "UPDATE passkeys SET passkey = ?, last_used = ? WHERE cred_id = ?",
            rusqlite::params![passkey_json, jiff::Timestamp::now().to_string(), cred_id],
        )?;
        Ok(())
    }

    pub fn remove_passkey(&mut self, who: &PrincipalId, cred_id: &str) -> CoreResult<bool> {
        let n = self.conn.execute(
            "DELETE FROM passkeys WHERE principal = ? AND cred_id = ?",
            rusqlite::params![who.as_str(), cred_id],
        )?;
        Ok(n > 0)
    }

    /// Park an in-flight WebAuthn ceremony's server state for a few
    /// minutes, under an id the browser hands back. Taken exactly once.
    pub fn put_webauthn_state(
        &mut self,
        principal: Option<&PrincipalId>,
        kind: &str,
        state_json: &str,
    ) -> CoreResult<String> {
        let id = random_token_secret();
        let now = jiff::Timestamp::now();
        let expires = (now + jiff::SignedDuration::from_mins(5)).to_string();
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM webauthn_states WHERE expires <= ?",
            rusqlite::params![now.to_string()],
        )?;
        tx.execute(
            "INSERT INTO webauthn_states (id, principal, kind, state, expires) VALUES (?, ?, ?, ?, ?)",
            rusqlite::params![id, principal.map(|p| p.as_str()), kind, state_json, expires],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Take an in-flight ceremony's state: who it was for, what kind it
    /// was, and the state itself - or nothing if it is unknown or old.
    /// Spent on the way out, whatever the caller then makes of the kind:
    /// one id, one attempt.
    pub fn take_webauthn_state(
        &mut self,
        id: &str,
    ) -> CoreResult<Option<(Option<PrincipalId>, String, String)>> {
        let now = jiff::Timestamp::now().to_string();
        let tx = self.conn.transaction()?;
        let row: Option<(Option<String>, String, String)> = tx
            .prepare_cached(
                "SELECT principal, kind, state FROM webauthn_states
                  WHERE id = ? AND expires > ?",
            )?
            .query_row(rusqlite::params![id, now], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })
            .optional()?;
        tx.execute(
            "DELETE FROM webauthn_states WHERE id = ?",
            rusqlite::params![id],
        )?;
        tx.commit()?;
        Ok(row.map(|(p, kind, state)| (p.map(PrincipalId), kind, state)))
    }

    /// Park something to show a person exactly once on their next page -
    /// a freshly minted secret - under an id that is useless after that
    /// page has been served. The alternative, the secret itself riding
    /// in a redirect URL, leaves it in browser history and edge logs.
    pub fn put_flash(&mut self, who: &PrincipalId, payload: &str) -> CoreResult<String> {
        let id = random_token_secret();
        let now = jiff::Timestamp::now();
        let expires = (now + jiff::SignedDuration::from_mins(5)).to_string();
        let tx = self.conn.transaction()?;
        tx.execute(
            "DELETE FROM flashes WHERE expires <= ?",
            rusqlite::params![now.to_string()],
        )?;
        tx.execute(
            "INSERT INTO flashes (id, principal, payload, expires) VALUES (?, ?, ?, ?)",
            rusqlite::params![id, who.as_str(), payload, expires],
        )?;
        tx.commit()?;
        Ok(id)
    }

    /// Take a flash: the payload if it is this person's and unspent,
    /// and gone either way.
    pub fn take_flash(&mut self, who: &PrincipalId, id: &str) -> CoreResult<Option<String>> {
        let now = jiff::Timestamp::now().to_string();
        let tx = self.conn.transaction()?;
        let payload: Option<String> = tx
            .prepare_cached(
                "SELECT payload FROM flashes WHERE id = ? AND principal = ? AND expires > ?",
            )?
            .query_row(rusqlite::params![id, who.as_str(), now], |row| row.get(0))
            .optional()?;
        tx.execute("DELETE FROM flashes WHERE id = ?", rusqlite::params![id])?;
        tx.commit()?;
        Ok(payload)
    }

    /// Allow something at most once per window per key. Operational and
    /// tiny: it exists so an anonymous form cannot page every admin a
    /// hundred times a minute, or one person mail the world.
    /// Give a throttle slot back, because the attempt it was taken for
    /// was refused before it did anything.
    pub fn forgive(&mut self, key: &str) -> CoreResult<()> {
        self.conn.execute(
            "DELETE FROM throttles WHERE key = ?",
            rusqlite::params![key],
        )?;
        Ok(())
    }

    pub fn throttle(&mut self, key: &str, window_secs: i64) -> CoreResult<bool> {
        let now = jiff::Timestamp::now();
        let until = (now + jiff::SignedDuration::from_secs(window_secs)).to_string();
        let tx = self.conn.transaction()?;
        let held: Option<String> = tx
            .prepare_cached("SELECT until FROM throttles WHERE key = ?")?
            .query_row(rusqlite::params![key], |row| row.get(0))
            .optional()?;
        if held.is_some_and(|u| u > now.to_string()) {
            tx.commit()?;
            return Ok(false);
        }
        tx.execute(
            "INSERT INTO throttles (key, until) VALUES (?1, ?2)
             ON CONFLICT (key) DO UPDATE SET until = ?2",
            rusqlite::params![key, until],
        )?;
        tx.commit()?;
        Ok(true)
    }

    /// A link that signs one person in once, for fifteen minutes. The
    /// caller sends it to their confirmed address and nowhere else; this
    /// only minds the secret. A new link retires any earlier unused one.
    pub fn begin_signin_link(&mut self, who: &PrincipalId) -> CoreResult<String> {
        let target = raw::principal(&self.conn, who.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {who}")))?;
        require(target.kind == PrincipalKind::Human, || {
            format!("{who} is not a person")
        })?;
        let secret = random_token_secret();
        let expires = (jiff::Timestamp::now() + jiff::SignedDuration::from_mins(15)).to_string();
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE signin_links SET used = 1 WHERE principal = ? AND used = 0",
            rusqlite::params![who.as_str()],
        )?;
        tx.execute(
            "INSERT INTO signin_links (token_hash, principal, expires) VALUES (?, ?, ?)",
            rusqlite::params![token_hash(&secret), who.as_str(), expires],
        )?;
        tx.commit()?;
        Ok(secret)
    }

    /// Spend a sign-in link: who it was for, or nothing.
    pub fn redeem_signin_link(&mut self, secret: &str) -> CoreResult<Option<PrincipalId>> {
        let now = jiff::Timestamp::now().to_string();
        let tx = self.conn.transaction()?;
        let who: Option<String> = tx
            .prepare_cached(
                "SELECT principal FROM signin_links
                  WHERE token_hash = ? AND used = 0 AND expires > ?",
            )?
            .query_row(rusqlite::params![token_hash(secret), now], |row| row.get(0))
            .optional()?;
        if who.is_some() {
            tx.execute(
                "UPDATE signin_links SET used = 1 WHERE token_hash = ?",
                rusqlite::params![token_hash(secret)],
            )?;
        }
        tx.commit()?;
        Ok(who.map(PrincipalId))
    }

    /// Begin a password reset: a secret that works once, for half an
    /// hour, for one person. Earlier unused secrets for them die here,
    /// so the newest link is the only one that works. Only the hash is
    /// kept, as with every other secret.
    pub fn begin_password_reset(&mut self, who: &PrincipalId) -> CoreResult<String> {
        let target = raw::principal(&self.conn, who.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {who}")))?;
        require(target.kind == PrincipalKind::Human, || {
            format!("{who} is not a person")
        })?;
        let secret = random_token_secret();
        let expires = (jiff::Timestamp::now() + jiff::SignedDuration::from_mins(30)).to_string();
        let tx = self.conn.transaction()?;
        tx.execute(
            "UPDATE password_resets SET used = 1 WHERE principal = ? AND used = 0",
            rusqlite::params![who.as_str()],
        )?;
        tx.execute(
            "INSERT INTO password_resets (token_hash, principal, expires) VALUES (?, ?, ?)",
            rusqlite::params![token_hash(&secret), who.as_str(), expires],
        )?;
        tx.commit()?;
        Ok(secret)
    }

    /// Spend a reset secret. Valid, unexpired and unused answers with
    /// the person; anything else answers with nothing, and the caller
    /// says the same thing either way.
    pub fn redeem_password_reset(&mut self, secret: &str) -> CoreResult<Option<PrincipalId>> {
        let now = jiff::Timestamp::now().to_string();
        let tx = self.conn.transaction()?;
        let who: Option<String> = tx
            .prepare_cached(
                "SELECT principal FROM password_resets
                  WHERE token_hash = ? AND used = 0 AND expires > ?",
            )?
            .query_row(rusqlite::params![token_hash(secret), now], |row| row.get(0))
            .optional()?;
        if who.is_some() {
            tx.execute(
                "UPDATE password_resets SET used = 1 WHERE token_hash = ?",
                rusqlite::params![token_hash(secret)],
            )?;
        }
        tx.commit()?;
        Ok(who.map(PrincipalId))
    }

    /// The stored hash, or a fixed one for a principal who has none, so
    /// verifying costs the same either way. Verification itself happens
    /// off the store: argon2 takes tens of milliseconds and the store
    /// lock is the whole forge.
    pub fn password_hash_for_check(&self, principal: &PrincipalId) -> (String, bool) {
        match raw::credential(&self.conn, principal.as_str())
            .ok()
            .flatten()
        {
            Some(hash) => (hash, true),
            None => (DUMMY_HASH.to_owned(), false),
        }
    }

    pub fn password_matches(&self, principal: &PrincipalId, password: &str) -> bool {
        let (hash, real) = self.password_hash_for_check(principal);
        verify_password(password, &hash) && real
    }

    /// Everything that must be true before a repository may exist,
    /// checked without creating anything.
    ///
    /// Creating a repository has a side effect outside this store — a
    /// directory on disk — and that side effect must not happen for a
    /// caller who is not allowed to create one, or under a name that is
    /// not allowed at all. So the caller can ask first, and
    /// [`Store::create_repo`] applies exactly the same rules again when
    /// the event is appended.
    pub fn check_new_repo(
        &mut self,
        actor: &PrincipalId,
        owner: Option<&PrincipalId>,
        short: &str,
        default_branch: &str,
    ) -> CoreResult<()> {
        let tx = self.conn.transaction()?;
        // A credential drawn for one repository's work makes no other.
        not_under_a_scope(self.acting.as_ref(), "create a repository")?;
        may_create_repo(&tx, actor)?;
        let owner = owner.unwrap_or(actor);
        may_act_for(&tx, self.acting.as_ref(), actor, owner)?;
        new_repo_is_allowed(&tx, &format!("{owner}/{short}"), default_branch)?;
        within_quota(
            &tx,
            &self.default_quota,
            owner,
            "repositories",
            |q| q.repos,
            |u| u.repos,
        )
        // The transaction is dropped, so nothing here is kept.
    }

    /// Make a repository named `short` under `owner`, who is the actor
    /// unless said otherwise. Under an organisation, any member may;
    /// under another person, only whoever runs the forge.
    pub fn create_repo(
        &mut self,
        actor: &PrincipalId,
        owner: Option<&PrincipalId>,
        short: &str,
        default_branch: &str,
        object_format: ObjectFormat,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        // A credential drawn for one repository's work makes no other.
        not_under_a_scope(self.acting.as_ref(), "create a repository")?;
        may_create_repo(&tx, actor)?;
        let owner = owner.unwrap_or(actor);
        may_act_for(&tx, self.acting.as_ref(), actor, owner)?;
        let name = format!("{owner}/{short}");
        new_repo_is_allowed(&tx, &name, default_branch)?;
        within_quota(
            &tx,
            &self.default_quota,
            owner,
            "repositories",
            |q| q.repos,
            |u| u.repos,
        )?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RepoCreated {
                repo: name,
                default_branch: default_branch.to_owned(),
                object_format,
                owner: (owner != actor).then(|| owner.clone()),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Give every repository still named the old way, without an owner
    /// in its name, its owner's name in front. Run once by whoever runs
    /// the forge when upgrading to the binary that expects it; the
    /// renames are ordinary events, so the log says what happened and
    /// the old addresses redirect.
    pub fn adopt_owners(&mut self, actor: &PrincipalId) -> CoreResult<Vec<Envelope>> {
        let tx = self.conn.transaction()?;
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        let mut renamed = Vec::new();
        for record in raw::repos(&tx)? {
            if record.name.contains('/') {
                continue;
            }
            let to = format!("{}/{}", record.owner, record.name);
            require(raw::repo(&tx, &to)?.is_none(), || {
                format!("{} cannot become {to}: that name is taken", record.name)
            })?;
            renamed.push(append(
                &tx,
                actor,
                None,
                Event::RepoRenamed {
                    repo: record.name.clone(),
                    to,
                },
            )?);
        }
        tx.commit()?;
        Ok(renamed)
    }

    /// Check an import source before anyone connects to it. The command
    /// enforces this too, but a caller that fetches first would have the
    /// forge dial an arbitrary url — and carry a credential there — on
    /// nothing but a caller's say-so. Validate, then fetch.
    pub fn validate_import_source(source: &str, allow_local: bool) -> CoreResult<()> {
        bounded("source", source, MAX_TITLE)?;
        // Only https. file:// would read this machine's own repositories,
        // ssh:// would use this machine's keys; neither is a caller's to
        // spend. A forge in development mode may read local paths, since
        // that mode already trusts whoever is at the keyboard.
        let local_ok = allow_local && source.starts_with("file://");
        require(source.starts_with("https://") || local_ok, || {
            "a source url must be https://".into()
        })?;
        require(!source.contains('@'), || {
            "keep credentials out of the source url: pass a token when serving".into()
        })?;
        Ok(())
    }

    /// What an owner leaves with: every repository they hold, described
    /// well enough to be made again elsewhere. The bundle names are
    /// what the export writes beside the manifest.
    pub fn graduation(&self, owner: &PrincipalId) -> CoreResult<crate::Graduation> {
        raw::principal(&self.conn, owner.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {owner}")))?;
        let repos = self
            .repos_of_owner(owner)?
            .into_iter()
            .map(|repo| {
                let short = crate::id::split_repo_name(&repo.name)
                    .map(|(_, short)| short.to_owned())
                    .unwrap_or_else(|| repo.name.clone());
                crate::GraduatedRepo {
                    bundle: format!("bundles/{short}.bundle"),
                    name: repo.name,
                    short,
                    default_branch: repo.default_branch,
                    visibility: repo.visibility,
                    object_format: repo.object_format,
                    archived: repo.archived,
                    description: repo.description,
                }
            })
            .collect();
        Ok(crate::Graduation {
            version: 1,
            exported: jiff::Timestamp::now().to_string(),
            owner: owner.clone(),
            repos,
        })
    }

    /// May this principal import into this repository? Asked before the
    /// forge connects anywhere on their behalf, so an unauthorised
    /// request costs nothing and fetches nothing.
    pub fn check_import(&self, actor: &PrincipalId, repo: &str) -> CoreResult<()> {
        let tx = self.conn.unchecked_transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        Ok(())
    }

    /// Record that a branch was seeded with history from somewhere
    /// else. Every other way a branch moves carries a policy trace
    /// saying why it was allowed; this one carries the opposite — an
    /// explicit marker that the commits below this tip were never
    /// judged here. Admin authority, and only onto a branch that does
    /// not exist yet: importing over reviewed history would overwrite
    /// exactly the decisions the log exists to keep.
    #[allow(clippy::too_many_arguments)] // one command, one record; a struct here would only rename the fields
    pub fn import_history(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        branch: &str,
        source: &str,
        tip_oid: &str,
        commits: i64,
        allow_local: bool,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(valid_branch(branch), || {
            format!("{branch:?} is not a valid branch name")
        })?;
        Self::validate_import_source(source, allow_local)?;
        require(
            matches!(tip_oid.len(), 40 | 64) && tip_oid.chars().all(|c| c.is_ascii_hexdigit()),
            || format!("{tip_oid:?} is not an object id"),
        )?;
        require(commits > 0, || "an import must carry commits".into())?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::HistoryImported {
                repo: repo.to_owned(),
                branch: branch.to_owned(),
                source: source.to_owned(),
                tip_oid: tip_oid.to_owned(),
                commits,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Whether this principal may read this repository at all.
    ///
    /// Public is public. Otherwise it is the same question as any other
    /// authority: you own it, or somebody granted you something on it.
    /// Holding a grant of any kind is enough — there is no separate
    /// "read" capability, because being trusted to push to a repository
    /// you cannot read would be a strange thing to arrange.
    pub fn may_read(&self, actor: &PrincipalId, repo: &str) -> bool {
        // A session credential sees its own repository and nothing else.
        if let Some(scope) = &self.acting
            && let Some(mine) = &scope.repo
            && mine != repo
        {
            return false;
        }
        let Ok(Some(record)) = raw::repo(&self.conn, repo) else {
            return false;
        };
        if record.visibility == Visibility::Public {
            return true;
        }
        if raw::owns(&self.conn, actor.as_str(), record.owner.as_str()).unwrap_or(false) {
            return true;
        }
        let Ok(grants) = raw::effective_grants(&self.conn, actor.as_str()) else {
            return false;
        };
        let now = jiff::Timestamp::now().to_string();
        grants.iter().any(|grant| {
            !grant.revoked
                && grant
                    .until
                    .as_deref()
                    .is_none_or(|until| until > now.as_str())
                && grant.repo.as_deref().is_none_or(|scope| scope == repo)
        })
    }

    /// The repository, if it exists and this principal may read it. One
    /// answer to both questions on purpose: a private repository has to
    /// look exactly like a missing one to anybody outside it, or which
    /// private repositories exist becomes public by enumeration.
    pub fn readable(
        &self,
        actor: &PrincipalId,
        name: &str,
    ) -> CoreResult<Option<crate::types::Repo>> {
        Ok(raw::repo(&self.conn, name)?.filter(|_| self.may_read(actor, name)))
    }

    /// Whether this principal holds the unscoped admin grant that
    /// running the forge consists of.
    pub fn is_admin(&self, actor: &PrincipalId) -> bool {
        // Running the forge is not among the verbs a session scope can
        // carry, so a credential drawn for one task's work is never an
        // admin, whatever its holder is the rest of the time.
        if self.acting.is_some() {
            return false;
        }
        let Ok(grants) = raw::effective_grants(&self.conn, actor.as_str()) else {
            return false;
        };
        let now = jiff::Timestamp::now().to_string();
        raw::grants_cover(&grants, Capability::Admin, None, &now)
    }

    /// Mark one notice dealt with. Operational, not logged: what you
    /// have read is not a fact about the software.
    pub fn mark_read(&mut self, who: &PrincipalId, seq: i64) -> CoreResult<()> {
        self.conn.execute(
            "INSERT OR IGNORE INTO inbox_read (principal, seq) VALUES (?, ?)",
            rusqlite::params![who.as_str(), seq],
        )?;
        Ok(())
    }

    /// Mark everything so far dealt with, as a single high-water mark.
    pub fn mark_all_read(&mut self, who: &PrincipalId) -> CoreResult<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO inbox_cursor (principal, seq)
             VALUES (?, (SELECT COALESCE(MAX(seq), 0) FROM events))",
            rusqlite::params![who.as_str()],
        )?;
        Ok(())
    }

    /// Every repository this principal may see, in name order.
    pub fn readable_repos(&self, actor: &PrincipalId) -> CoreResult<Vec<crate::types::Repo>> {
        Ok(raw::repos(&self.conn)?
            .into_iter()
            .filter(|repo| self.may_read(actor, &repo.name))
            .collect())
    }

    /// Decide whether a repository can be read without credentials.
    ///
    /// Admin authority, and recorded: making a repository public is a
    /// decision with consequences that someone will want to date later.
    /// Offer the repository to somebody. Nothing moves until they say
    /// yes: a repository cannot be left on somebody's doorstep, because
    /// owning one carries every capability on it and whatever is in it.
    pub fn offer_transfer(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        to: &PrincipalId,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        not_under_a_scope(self.acting.as_ref(), "transfer a repository")?;
        // Giving a repository away is the owner's to do, or the forge's.
        // A grant of admin *on* the repository is not enough: that grant
        // is what an owner hands somebody to run the repository, and
        // running it must not include walking off with it — least of
        // all by offering it to yourself. Ownership is read before
        // authority is settled, but nothing is said about the
        // repository until it is: a stranger meets the same refusal
        // whether or not the name exists.
        let record = raw::repo(&tx, repo)?;
        let owns = match &record {
            Some(record) => raw::owns(&tx, actor.as_str(), record.owner.as_str())?,
            None => false,
        };
        let running = authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None).is_ok();
        if !owns && !running {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not transfer {repo}: its owner may, or whoever runs the forge"
            )));
        }
        human_act(&tx, actor, "transfer a repository")?;
        let record = record.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(record.owner != *to, || "they already own it".to_owned())?;
        // A member of the owning organisation offering its repository
        // to themselves is a member taking it. Whoever runs the forge
        // may still move a repository to their own name — a stopped
        // owner's, say — because there is nobody else to move it.
        require(*to != *actor || running, || {
            "offer it to somebody else; taking an organisation's repository for yourself is not a transfer"
                .to_owned()
        })?;
        let recipient = raw::principal(&tx, to.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {to}")))?;
        require(recipient.kind != PrincipalKind::Agent, || {
            "a person or an organisation can own a repository; grant an agent what it needs instead"
                .to_owned()
        })?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RepoTransferOffered {
                repo: repo.to_owned(),
                to: to.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Take up an offer: the person it was made to, or a member of the
    /// organisation it was made to. The repository takes its new owner's
    /// name in front, so acceptance is two events: accepted, then renamed.
    pub fn accept_transfer(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
    ) -> CoreResult<Vec<Envelope>> {
        let tx = self.conn.transaction()?;
        not_under_a_scope(self.acting.as_ref(), "accept a repository")?;
        ensure_actor(&tx, actor)?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        let Some(to) = record.pending_owner.clone() else {
            return Err(CoreError::Invalid(format!("{repo} is not on offer")));
        };
        let may_accept = to == *actor || raw::is_team_member(&tx, to.as_str(), actor.as_str())?;
        require(may_accept, || {
            format!("{repo} has not been offered to {actor}")
        })?;
        // What is offered still has to fit. Ownership moving is a way
        // past the repository and disk limits otherwise, and a
        // deliberate one: offer everything you hold to an account with
        // room and accept it there.
        within_quota(
            &tx,
            &self.default_quota,
            &to,
            "repositories",
            |q| q.repos,
            |u| u.repos,
        )?;
        // Its open work comes with it. Counting one-more-fits would let
        // two full accounts pass a repository holding hundreds of open
        // tasks back and forth, resetting each other.
        let arriving_tasks: i64 = tx.query_row(
            "SELECT COUNT(*) FROM tasks WHERE repo = ? AND state IN ('open', 'claimed')",
            rusqlite::params![repo],
            |row| row.get(0),
        )?;
        let arriving_changes: i64 = tx.query_row(
            "SELECT COUNT(*) FROM changes WHERE repo = ? AND state = 'open'",
            rusqlite::params![repo],
            |row| row.get(0),
        )?;
        let quota = self
            .default_quota
            .under(&raw::quota(&tx, to.as_str())?.unwrap_or_default());
        let usage = raw::usage(&tx, to.as_str())?;
        let fits = |have: u32, arriving: i64, limit: Option<u32>| -> bool {
            limit.is_none_or(|limit| u64::from(have) + arriving.max(0) as u64 <= u64::from(limit))
        };
        require(fits(usage.open_tasks, arriving_tasks, quota.open_tasks), String::new)
            .map_err(|_| {
                CoreError::OverQuota(format!(
                    "{to} has {} open tasks and {repo} brings {arriving_tasks}, and this forge allows {}",
                    usage.open_tasks,
                    quota.open_tasks.unwrap_or(u32::MAX)
                ))
            })?;
        require(fits(usage.open_changes, arriving_changes, quota.open_changes), String::new)
            .map_err(|_| {
                CoreError::OverQuota(format!(
                    "{to} has {} open changes and {repo} brings {arriving_changes}, and this forge allows {}",
                    usage.open_changes,
                    quota.open_changes.unwrap_or(u32::MAX)
                ))
            })?;
        let arriving: i64 = tx
            .prepare_cached("SELECT COALESCE(bytes, 0) FROM repo_sizes WHERE repo = ?")
            .and_then(|mut q| q.query_row(rusqlite::params![repo], |row| row.get(0)))
            .unwrap_or(0);
        if let Some(limit) = quota.disk {
            let after = usage.disk.saturating_add(arriving.max(0) as u64);
            require(after <= limit, || {
                format!("{to} does not have room on disk for {repo}")
            })
            .map_err(|_| {
                CoreError::OverQuota(format!("{to} does not have room on disk for {repo}"))
            })?;
        }
        let short = crate::id::split_repo_name(repo)
            .map(|(_, short)| short.to_owned())
            .unwrap_or_else(|| repo.to_owned());
        let new_name = format!("{to}/{short}");
        require(raw::repo(&tx, &new_name)?.is_none(), || {
            format!("{to} already has a repository named {short}")
        })?;
        let via = self.acting.as_ref().and_then(|s| s.session.as_ref());
        // What the old owner handed out on it goes with the old owner,
        // and it goes on the record: each grant is revoked by an event
        // of its own, with the reason, so the grantee is told and the
        // log says why a grant that was there is not. (The apply arm
        // for the acceptance revokes them too, for logs written before
        // this was said explicitly; on these it finds nothing left.)
        let handed_out: Vec<String> = tx
            .prepare_cached("SELECT id FROM grants WHERE repo = ? AND revoked = 0 ORDER BY rowid")?
            .query_map(rusqlite::params![repo], |row| row.get(0))?
            .collect::<Result<Vec<_>, _>>()?;
        let mut envelopes = Vec::with_capacity(handed_out.len() + 2);
        for grant in handed_out {
            envelopes.push(append(
                &tx,
                actor,
                via,
                Event::GrantRevoked {
                    grant: GrantId(grant),
                    reason: format!("{repo} was transferred to {to}"),
                },
            )?);
        }
        let accepted = append(
            &tx,
            actor,
            via,
            Event::RepoTransferAccepted {
                repo: repo.to_owned(),
            },
        )?;
        let renamed = append(
            &tx,
            actor,
            via,
            Event::RepoRenamed {
                repo: repo.to_owned(),
                to: new_name,
            },
        )?;
        tx.commit()?;
        envelopes.push(accepted);
        envelopes.push(renamed);
        Ok(envelopes)
    }

    /// Turn an offer down, or take it back: the offeree may decline, and
    /// whoever could have made the offer may withdraw it.
    pub fn decline_transfer(&mut self, actor: &PrincipalId, repo: &str) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        not_under_a_scope(self.acting.as_ref(), "decline or withdraw a transfer")?;
        ensure_actor(&tx, actor)?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(record.pending_owner.is_some(), || {
            format!("{repo} is not on offer")
        })?;
        // The offeree may decline; whoever could have offered — the
        // owner, or the forge — may withdraw.
        if record.pending_owner.as_ref() != Some(actor)
            && !raw::owns(&tx, actor.as_str(), record.owner.as_str())?
        {
            authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RepoTransferDeclined {
                repo: repo.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Put somebody on a team. Running the forge is what this is, since
    /// a team's grants become theirs at once; and a team cannot contain
    /// a team, because authority should be readable in one step.
    pub fn add_team_member(
        &mut self,
        actor: &PrincipalId,
        team: &PrincipalId,
        member: &PrincipalId,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        let team_record = raw::principal(&tx, team.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {team}")))?;
        require(team_record.kind == PrincipalKind::Team, || {
            format!("{team} is not a team")
        })?;
        let who = raw::principal(&tx, member.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {member}")))?;
        require(who.kind != PrincipalKind::Team, || {
            "a team cannot join a team".to_owned()
        })?;
        // Membership is holding: every grant the team has, every agent
        // it owns. An agent on a team would hold its siblings' tokens
        // and, through a team that runs the forge, the forge. An agent
        // that works for a team is registered as the team's own, or
        // granted what it needs on the team's repositories.
        require(who.kind == PrincipalKind::Human, || {
            format!("{member} is an agent; a team's members are people")
        })?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::TeamMemberAdded {
                team: team.clone(),
                member: member.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn remove_team_member(
        &mut self,
        actor: &PrincipalId,
        team: &PrincipalId,
        member: &PrincipalId,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        require(
            raw::members_of(&tx, team.as_str())?
                .iter()
                .any(|m| m == member),
            || format!("{member} is not on {team}"),
        )?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::TeamMemberRemoved {
                team: team.clone(),
                member: member.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Tie a provider identity to yourself. One identity links to one
    /// principal; linking it again to somebody else is refused.
    pub fn link_identity(
        &mut self,
        actor: &PrincipalId,
        issuer: &str,
        subject: &str,
        email: Option<&str>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        not_under_a_scope(self.acting.as_ref(), "link an identity")?;
        let principal = ensure_actor(&tx, actor)?;
        require(principal.kind == PrincipalKind::Human, || {
            format!("{actor} is not a person; agents prove who they are as workloads")
        })?;
        require(
            !issuer.trim().is_empty() && !subject.trim().is_empty(),
            || "an identity needs an issuer and a subject".into(),
        )?;
        if let Some(holder) = raw::identity_of(&tx, issuer, subject)?
            && holder != *actor
        {
            return Err(CoreError::Conflict(format!(
                "that {issuer} identity is already linked to {holder}"
            )));
        }
        let env = append(
            &tx,
            actor,
            None,
            Event::IdentityLinked {
                principal: actor.clone(),
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
                email: email.map(str::to_owned),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// The forge itself links an identity by a verified email, when it
    /// was told to trust that. Attributed to the person it is about.
    pub fn link_identity_by_email(
        &mut self,
        issuer: &str,
        subject: &str,
        email: &str,
    ) -> CoreResult<Option<(PrincipalId, Envelope)>> {
        let Some(principal) = self.principal_by_email(email)? else {
            return Ok(None);
        };
        let env = self.link_identity(&principal, issuer, subject, Some(email))?;
        Ok(Some((principal, env)))
    }

    pub fn unlink_identity(
        &mut self,
        actor: &PrincipalId,
        issuer: &str,
        subject: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        match raw::identity_of(&tx, issuer, subject)? {
            Some(holder) if holder == *actor => {}
            _ => {
                return Err(CoreError::NotFound(format!(
                    "no {issuer} identity of yours is linked here"
                )));
            }
        }
        let env = append(
            &tx,
            actor,
            None,
            Event::IdentityUnlinked {
                principal: actor.clone(),
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Say which workload may act as an agent. Running the forge decides.
    pub fn bind_workload(
        &mut self,
        actor: &PrincipalId,
        principal: &PrincipalId,
        issuer: &str,
        subject: &str,
        bound: bool,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        let subject_principal = raw::principal(&tx, principal.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {principal}")))?;
        require(subject_principal.kind == PrincipalKind::Agent, || {
            format!("{principal} is not an agent; people link identities themselves")
        })?;
        require(
            !issuer.trim().is_empty() && !subject.trim().is_empty(),
            || "a binding needs an issuer and a subject".into(),
        )?;
        let existing = raw::workload_binding(&tx, issuer, subject)?;
        let event = if bound {
            if let Some(holder) = existing
                && holder != *principal
            {
                return Err(CoreError::Conflict(format!(
                    "that workload is already bound to {holder}"
                )));
            }
            Event::WorkloadBound {
                principal: principal.clone(),
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
            }
        } else {
            require(existing.as_ref() == Some(principal), || {
                format!("{principal} has no such binding")
            })?;
            Event::WorkloadUnbound {
                principal: principal.clone(),
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
            }
        };
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            event,
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// A workload proved who it is; hand it a credential that can only
    /// claim a task and open a session, for a quarter of an hour. The
    /// event is the bound principal's own: the workload acts as it.
    pub fn mint_workload_credential(
        &mut self,
        issuer: &str,
        subject: &str,
    ) -> CoreResult<(PrincipalId, TokenId, String, String, Envelope)> {
        let tx = self.conn.transaction()?;
        let principal = raw::workload_binding(&tx, issuer, subject)?.ok_or_else(|| {
            CoreError::Forbidden(format!(
                "no agent is bound to {subject} at {issuer}; whoever runs the forge can bind one \
                 (POST /api/principals/{{agent}}/workload)"
            ))
        })?;
        ensure_actor(&tx, &principal)?;
        let until = (jiff::Timestamp::now() + jiff::Span::new().minutes(15)).to_string();
        let token = TokenId::generate();
        let secret = random_token_secret();
        let env = append(
            &tx,
            &principal,
            None,
            Event::WorkloadCredentialMinted {
                token: token.clone(),
                principal: principal.clone(),
                issuer: issuer.to_owned(),
                subject: subject.to_owned(),
                hash: token_hash(&secret),
                until: until.clone(),
            },
        )?;
        tx.commit()?;
        Ok((principal, token, secret, until, env))
    }

    /// Everything `rename_repo` will insist on, checked ahead of moving
    /// anything on disk.
    pub fn check_rename(&mut self, actor: &PrincipalId, repo: &str, to: &str) -> CoreResult<()> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(validate_slug(to), || {
            format!("{to:?} is not a valid name: lowercase letters, digits and hyphens")
        })?;
        let to = format!("{}/{to}", record.owner);
        require(to != repo, || "that is already its name".into())?;
        require(raw::repo(&tx, &to)?.is_none(), || {
            format!("a repository named {to} already exists")
        })?;
        Ok(())
    }

    /// Rename a repository. Every projection follows, and the old name
    /// answers not found from here on; the owner, or whoever runs the
    /// forge, may do it.
    pub fn rename_repo(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        to: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(validate_slug(to), || {
            format!("{to:?} is not a valid name: lowercase letters, digits and hyphens")
        })?;
        // The owner's name stays in front; a rename changes only what is theirs.
        let to = format!("{}/{to}", record.owner);
        require(to != repo, || "that is already its name".into())?;
        require(raw::repo(&tx, &to)?.is_none(), || {
            format!("a repository named {to} already exists")
        })?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RepoRenamed {
                repo: repo.to_owned(),
                to,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Say what a repository is for, in a line. Owner or admin.
    pub fn describe_repo(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        description: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        let description = description.trim();
        bounded("description", description, MAX_TITLE)?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RepoDescribed {
                repo: repo.to_owned(),
                description: description.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Archive or unarchive: read-only, or not. Owner or admin.
    pub fn set_archived(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        archived: bool,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        if record.archived == archived {
            return Err(CoreError::Conflict(format!(
                "{repo} is already {}",
                if archived { "archived" } else { "active" }
            )));
        }
        let event = if archived {
            Event::RepoArchived {
                repo: repo.to_owned(),
            }
        } else {
            Event::RepoUnarchived {
                repo: repo.to_owned(),
            }
        };
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            event,
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Delete a repository. Its owner, or whoever runs the forge, types
    /// its name to say so; nothing in the landing queue may be waiting on
    /// it. The graph forgets the repository and keeps the log.
    pub fn delete_repo(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        confirm: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(confirm.trim() == repo, || {
            format!("type the repository's name, {repo}, to delete it")
        })?;
        let queued: i64 = tx.query_row(
            "SELECT COUNT(*) FROM merge_queue WHERE repo = ?",
            rusqlite::params![repo],
            |row| row.get(0),
        )?;
        require(queued == 0, || {
            format!(
                "{repo} has {queued} change(s) in the landing queue; let them land or dequeue them first"
            )
        })?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RepoDeleted {
                repo: repo.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn set_visibility(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        visibility: Visibility,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::VisibilitySet {
                repo: repo.to_owned(),
                visibility,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Set the rules a repository requires. Admin authority, because
    /// a policy decides what everyone else's work must satisfy.
    pub fn set_policy(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        policy: Policy,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Admin,
            Some(repo),
        )?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(policy.required_domains.len() <= MAX_ITEMS, || {
            format!("at most {MAX_ITEMS} required domains")
        })?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::PolicySet {
                repo: repo.to_owned(),
                policy,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Point a repository's landed branches at somewhere else, or
    /// stop. The URL is stored without credentials — the secret that
    /// authorises the push is the operator's, kept outside the graph.
    pub fn set_mirror(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        mirror: Option<Mirror>,
        allow_local: bool,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        // The push uses the credential whoever runs the forge configured,
        // so where it goes is theirs to decide, not a repository owner's:
        // an owner pointing a mirror at their own host would be handed it.
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        if let Some(mirror) = &mirror {
            bounded("mirror url", &mirror.url, MAX_TITLE)?;
            // https and ssh reach a hosted forge; file reaches another
            // disk, which is a legitimate place to keep a copy.
            // https only; a development forge may mirror to a local path,
            // since that mode already trusts whoever is at the keyboard.
            let local_ok = allow_local && mirror.url.starts_with("file://");
            require(mirror.url.starts_with("https://") || local_ok, || {
                "a mirror url must be https://".into()
            })?;
            require(!mirror.url.contains('@'), || {
                "keep credentials out of the mirror url: pass a token when serving".into()
            })?;
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::MirrorSet {
                repo: repo.to_owned(),
                mirror,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Give a landed commit a name. The hook has already checked that
    /// the commit is on a branch; this checks who is asking and that
    /// the name is new, since a tag is never moved.
    pub fn push_tag(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        name: &str,
        commit_oid: &str,
        object_oid: Option<&str>,
        message: Option<&str>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Merge,
            Some(repo),
        )?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        ensure_writable(&tx, repo)?;
        bounded("tag name", name, MAX_TITLE)?;
        require(
            !name.is_empty()
                && !name.starts_with('-')
                && !name.ends_with(".lock")
                && !name.contains("..")
                && !name.contains("@{")
                && !name.contains('\\')
                && !name.chars().any(|c| c.is_whitespace() || c.is_control()),
            || format!("{name:?} is not a name git would accept for a tag"),
        )?;
        for oid in std::iter::once(commit_oid).chain(object_oid) {
            require(
                (oid.len() == 40 || oid.len() == 64) && oid.chars().all(|c| c.is_ascii_hexdigit()),
                || format!("{oid:?} is not an object id"),
            )?;
        }
        if let Some(message) = message {
            bounded("tag message", message, MAX_TEXT)?;
        }
        let taken: Option<String> = tx
            .query_row(
                "SELECT commit_oid FROM tags WHERE repo = ? AND name = ?",
                rusqlite::params![repo, name],
                |row| row.get(0),
            )
            .optional()?;
        if let Some(taken) = taken {
            return Err(CoreError::Conflict(format!(
                "tag {name} already names {}; tags are not moved, make a new one",
                &taken[..taken.len().min(12)]
            )));
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::TagPushed {
                repo: repo.to_owned(),
                name: name.to_owned(),
                commit_oid: commit_oid.to_owned(),
                object_oid: object_oid.map(str::to_owned),
                message: message.map(str::to_owned),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Record what happened when a landed branch was copied outward.
    /// Kept whether it worked or not: a mirror that has been quietly
    /// failing for a week is exactly what nobody notices.
    pub fn record_mirror_push(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        branch: &str,
        commit_oid: &str,
        ok: bool,
        detail: Option<&str>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::MirrorPushed {
                repo: repo.to_owned(),
                branch: branch.to_owned(),
                commit_oid: commit_oid.to_owned(),
                ok,
                detail: detail.map(|d| d.chars().take(MAX_TITLE).collect()),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn create_task(
        &mut self,
        actor: &PrincipalId,
        repo: Option<&str>,
        title: &str,
        spec: &str,
        parent: Option<&TaskId>,
    ) -> CoreResult<(TaskId, Envelope)> {
        self.create_task_with_attempts(actor, repo, title, spec, parent, 1)
    }

    /// Create a task that `attempts` agents may hold at once. More than
    /// one invites competing attempts: each becomes a revision of the
    /// task's one change, and a reviewer compares them.
    pub fn create_task_with_attempts(
        &mut self,
        actor: &PrincipalId,
        repo: Option<&str>,
        title: &str,
        spec: &str,
        parent: Option<&TaskId>,
        attempts: u32,
    ) -> CoreResult<(TaskId, Envelope)> {
        let tx = self.conn.transaction()?;
        authorize(&tx, self.acting.as_ref(), actor, Capability::Task, repo)?;
        require((1..=MAX_ATTEMPTS).contains(&attempts), || {
            format!("a task invites between 1 and {MAX_ATTEMPTS} attempts, not {attempts}")
        })?;
        if let Some(repo) = repo {
            ensure_writable(&tx, repo)?;
        }
        require(!title.trim().is_empty(), || {
            "task title must not be empty".into()
        })?;
        bounded("task title", title, MAX_TITLE)?;
        require(!spec.trim().is_empty(), || {
            "task spec must not be empty: the spec is the durable intent".into()
        })?;
        bounded("task spec", spec, MAX_TEXT)?;
        if let Some(repo) = repo {
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        }
        if let Some(parent) = parent {
            raw::task(&tx, parent.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("task {parent}")))?;
        }
        // Open work in a repository is that repository owner's; a task
        // belonging to the forge itself is charged to whoever made it,
        // which for an agent is the owner it belongs to.
        let charged = match repo {
            Some(repo) => raw::repo(&tx, repo)?.map(|record| record.owner),
            None => raw::principal(&tx, actor.as_str())?.and_then(|p| p.owner),
        };
        if let Some(owner) = charged {
            within_quota(
                &tx,
                &self.default_quota,
                &owner,
                "open tasks",
                |q| q.open_tasks,
                |u| u.open_tasks,
            )?;
        }
        let task = TaskId::generate();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::TaskCreated {
                task: task.clone(),
                repo: repo.map(str::to_owned),
                title: title.to_owned(),
                spec: spec.to_owned(),
                parent: parent.cloned(),
                attempts,
            },
        )?;
        tx.commit()?;
        Ok((task, env))
    }

    pub fn claim_task(&mut self, actor: &PrincipalId, task: &TaskId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Task,
            current.repo.as_deref(),
        )?;
        match current.state {
            TaskState::Open => {}
            TaskState::Claimed if current.claimants.contains(actor) => {
                return Err(CoreError::Conflict(format!(
                    "{actor} already holds task {task}"
                )));
            }
            // A task that invites several attempts stays open to claim
            // until it has that many holders.
            TaskState::Claimed if (current.claimants.len() as u32) < current.attempts => {}
            TaskState::Claimed => {
                return Err(CoreError::Conflict(format!(
                    "task {task} is held by {}; it invites {} attempt(s)",
                    current
                        .claimants
                        .iter()
                        .map(|p| p.as_str())
                        .collect::<Vec<_>>()
                        .join(", "),
                    current.attempts
                )));
            }
            other => {
                return Err(CoreError::Conflict(format!(
                    "task {task} is {}, not open",
                    other.as_str()
                )));
            }
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::TaskClaimed { task: task.clone() },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn set_task_state(
        &mut self,
        actor: &PrincipalId,
        task: &TaskId,
        state: TaskState,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Task,
            current.repo.as_deref(),
        )?;
        require(state != TaskState::Claimed, || {
            "use claim_task to claim; claiming records who claimed".into()
        })?;
        // Reopening is taking the work back up, so it has to fit the way
        // opening it did. Without this, landing or abandoning tasks and
        // reopening them is a way to hold any number at once.
        if state == TaskState::Open && current.state != TaskState::Open {
            // Charged as it was when made: to the repository's owner,
            // or for work belonging to the forge, to whoever made it.
            let charged = match current.repo.as_deref() {
                Some(repo) => raw::repo(&tx, repo)?.map(|record| record.owner),
                None => raw::principal(&tx, current.created_by.as_str())?.and_then(|p| p.owner),
            };
            if let Some(owner) = charged {
                within_quota(
                    &tx,
                    &self.default_quota,
                    &owner,
                    "open tasks",
                    |q| q.open_tasks,
                    |u| u.open_tasks,
                )?;
            }
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::TaskStateChanged {
                task: task.clone(),
                state,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Open a session: one run of work against a task the actor has
    /// claimed. Claiming first is deliberate — it is the coordination
    /// point that stops two agents burning tokens on the same task.
    pub fn open_session(
        &mut self,
        actor: &PrincipalId,
        task: &TaskId,
    ) -> CoreResult<(SessionId, Envelope)> {
        let tx = self.conn.transaction()?;
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Task,
            current.repo.as_deref(),
        )?;
        if current.state != TaskState::Claimed || !current.claimants.contains(actor) {
            return Err(CoreError::Conflict(format!(
                "task {task} must be claimed by {actor} before opening a session"
            )));
        }
        let session = SessionId::generate();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::SessionOpened {
                session: session.clone(),
                task: task.clone(),
            },
        )?;
        tx.commit()?;
        Ok((session, env))
    }

    /// Say what one owner may take up here, replacing whatever applied
    /// to them before. Whoever runs the forge decides; this is the one
    /// knob a bigger plan turns.
    pub fn set_quota(
        &mut self,
        actor: &PrincipalId,
        owner: &PrincipalId,
        quota: &crate::types::QuotaOverride,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        let record = raw::principal(&tx, owner.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {owner}")))?;
        require(record.kind != PrincipalKind::Agent, || {
            format!("{owner} is an agent; a quota belongs to a person or an organisation")
        })?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::QuotaOverridden {
                owner: owner.clone(),
                quota: quota.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Remember how much disk a repository takes. A measurement, not an
    /// event: git changes the answer by packing objects, with nothing
    /// happening in the forge to record.
    pub fn record_repo_size(&mut self, repo: &str, bytes: u64) -> CoreResult<()> {
        // Only for a repository that exists now. A measurement in flight
        // while the repository is deleted or renamed would otherwise
        // leave a row under a name that is nobody's, for the next
        // repository of that name to inherit.
        self.conn.execute(
            "INSERT OR REPLACE INTO repo_sizes (repo, bytes, measured)
               SELECT ?1, ?2, ?3 WHERE EXISTS (SELECT 1 FROM repos WHERE name = ?1)",
            rusqlite::params![repo, bytes as i64, jiff::Timestamp::now().to_string()],
        )?;
        Ok(())
    }

    /// The forge's quota for owners nobody has set one for. Configured
    /// at startup, so it is set on the handle rather than logged.
    pub fn with_default_quota(mut self, quota: Quota) -> Self {
        self.default_quota = quota;
        self
    }

    /// Act under a session credential's scope for the calls that follow
    /// on this handle; `None` is a standing credential. The server sets
    /// it per request and clears it afterwards.
    pub fn acting_as(&mut self, scope: Option<&Scope>) -> &mut Self {
        self.acting = scope.cloned();
        self
    }

    pub fn clear_acting(&mut self) {
        self.acting = None;
    }

    /// Draw a credential from an active session: a bearer token shown
    /// once, scoped to the task's repository and the verbs the agent
    /// holds there (or fewer, on request), alive for an hour unless said
    /// otherwise and never past eight, and dead when the session ends.
    /// Under a session credential, a new one can only be narrower.
    pub fn mint_session_credential(
        &mut self,
        actor: &PrincipalId,
        session: &SessionId,
        minutes: Option<u32>,
        actions: Option<Vec<Capability>>,
    ) -> CoreResult<(TokenId, String, Scope, String, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        let current = raw::session(&tx, session.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("session {session}")))?;
        if current.agent != *actor {
            return Err(CoreError::Forbidden(format!(
                "session {session} belongs to {}; only its agent draws credentials from it",
                current.agent
            )));
        }
        if current.state != SessionState::Active {
            return Err(CoreError::Conflict(format!(
                "session {session} has ended; its credentials died with it"
            )));
        }
        let task = raw::task(&tx, current.task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {}", current.task)))?;
        let repo = task.repo.clone();
        let now = jiff::Timestamp::now();
        let now_text = now.to_string();
        let grants = raw::effective_grants(&tx, actor.as_str())?;
        let held: Vec<Capability> = [
            Capability::Task,
            Capability::Push,
            Capability::Review,
            Capability::Verify,
            Capability::Merge,
        ]
        .into_iter()
        .filter(|&c| raw::grants_cover(&grants, c, repo.as_deref(), &now_text))
        .filter(|&c| {
            // A session credential drawn under another can only be
            // narrower. A workload's bootstrap credential is different in
            // kind: it exists to begin work, and the session it opens
            // carries what the agent actually holds here.
            self.acting
                .as_ref()
                .is_none_or(|parent| parent.session.is_none() || parent.covers(c, repo.as_deref()))
        })
        .collect();
        let actions = match actions {
            Some(wanted) => {
                for c in &wanted {
                    require(held.contains(c), || {
                        format!(
                            "a credential cannot carry more than its holder: {actor} does not hold '{}' on {}",
                            c.as_str(),
                            repo.as_deref().unwrap_or("every repository")
                        )
                    })?;
                }
                wanted
            }
            None => held,
        };
        require(!actions.is_empty(), || {
            format!(
                "{actor} holds nothing on {} to put in a credential",
                repo.as_deref().unwrap_or("any repository")
            )
        })?;
        let minutes = minutes.unwrap_or(60);
        require((1..=480).contains(&minutes), || {
            "a session credential lives between 1 minute and 8 hours".into()
        })?;
        let until = (now + jiff::Span::new().minutes(i64::from(minutes))).to_string();
        let scope = Scope {
            session: Some(session.clone()),
            repo,
            actions,
        };
        let token = TokenId::generate();
        let secret = random_token_secret();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::SessionCredentialMinted {
                token: token.clone(),
                session: session.clone(),
                principal: actor.clone(),
                hash: token_hash(&secret),
                until: until.clone(),
                scope: scope.clone(),
            },
        )?;
        tx.commit()?;
        Ok((token, secret, scope, until, env))
    }

    /// End a session. The outcome text is mandatory, for failures most of
    /// all: what was tried and why it didn't work is the knowledge the
    /// next session (or the next agent) starts from.
    pub fn end_session(
        &mut self,
        actor: &PrincipalId,
        session: &SessionId,
        state: SessionState,
        outcome: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        require(state != SessionState::Active, || {
            "a session cannot end as active".into()
        })?;
        require(!outcome.trim().is_empty(), || {
            "session outcome must not be empty: record what happened for the next reader".into()
        })?;
        bounded("session outcome", outcome, MAX_TEXT)?;
        let current = raw::session(&tx, session.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("session {session}")))?;
        let task = raw::task(&tx, current.task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {}", current.task)))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Task,
            task.repo.as_deref(),
        )?;
        if current.agent != *actor {
            return Err(CoreError::Conflict(format!(
                "session {session} belongs to {}",
                current.agent
            )));
        }
        if current.state != SessionState::Active {
            return Err(CoreError::Conflict(format!(
                "session {session} already ended"
            )));
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::SessionEnded {
                session: session.clone(),
                state,
                outcome: outcome.to_owned(),
            },
        )?;
        // Whatever credentials the session drew die with it, on the record.
        let live: i64 = tx.query_row(
            "SELECT COUNT(*) FROM tokens WHERE session = ? AND revoked = 0",
            rusqlite::params![session.as_str()],
            |row| row.get(0),
        )?;
        if live > 0 {
            append(
                &tx,
                actor,
                self.acting.as_ref().and_then(|s| s.session.as_ref()),
                Event::SessionCredentialsRevoked {
                    session: session.clone(),
                    revoked: live,
                },
            )?;
        }
        tx.commit()?;
        Ok(env)
    }

    pub fn open_change(
        &mut self,
        actor: &PrincipalId,
        spec: ChangeSpec,
    ) -> CoreResult<(ChangeId, i64, Envelope)> {
        let tx = self.conn.transaction()?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Push,
            Some(&spec.repo),
        )?;
        let record = raw::repo(&tx, &spec.repo)?
            .ok_or_else(|| CoreError::NotFound(format!("repo {}", spec.repo)))?;
        ensure_writable(&tx, &spec.repo)?;
        require(valid_branch(&spec.target), || {
            format!("{:?} is not a valid branch name", spec.target)
        })?;
        // A change needs no push to open, so it is the cheapest row
        // anybody can make. Counted against the repository's owner, the
        // way its tasks are.
        within_quota(
            &tx,
            &self.default_quota,
            &record.owner,
            "open changes",
            |q| q.open_changes,
            |u| u.open_changes,
        )?;
        require(!spec.title.trim().is_empty(), || {
            "change title must not be empty".into()
        })?;
        bounded("change title", &spec.title, MAX_TITLE)?;
        if let Some(task) = &spec.task {
            raw::task(&tx, task.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
            // One task, one open change: another attempt is a revision of
            // it, not a change beside it.
            if let Some(open) = raw::open_change_for_task(&tx, task.as_str())? {
                return Err(CoreError::Conflict(format!(
                    "task {task} already has an open change, #{} ({}); push a revision to it instead",
                    open.number, open.id
                )));
            }
        }
        if let Some(key) = &spec.external_key {
            require(
                (1..=100).contains(&key.len()) && !key.contains(char::is_whitespace),
                || format!("{key:?} is not a valid external key"),
            )?;
            if raw::change_by_key(&tx, &spec.repo, key)?.is_some() {
                return Err(CoreError::Conflict(format!(
                    "a change with key {key} already exists in {}",
                    spec.repo
                )));
            }
        }
        if let Some(parent) = &spec.parent_change {
            let parent_change = raw::change(&tx, parent.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("change {parent}")))?;
            require(parent_change.repo == spec.repo, || {
                format!("stack parent {parent} lives in repo {}", parent_change.repo)
            })?;
            if parent_change.state != ChangeState::Open {
                return Err(CoreError::Conflict(format!(
                    "stack parent {parent} is {}, not open",
                    parent_change.state.as_str()
                )));
            }
        }
        let change = ChangeId::generate();
        let number = raw::next_change_number(&tx, &spec.repo)?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ChangeOpened {
                change: change.clone(),
                repo: spec.repo,
                number,
                target: spec.target,
                title: spec.title,
                task: spec.task,
                parent_change: spec.parent_change,
                external_key: spec.external_key,
            },
        )?;
        tx.commit()?;
        Ok((change, number, env))
    }

    pub fn push_revision(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        commit_oid: &str,
        session: Option<&SessionId>,
        message: &str,
    ) -> CoreResult<(i64, Envelope)> {
        self.push_revision_with_paths(actor, change, commit_oid, session, message, Vec::new())
    }

    /// Push a revision and record which files its commit touched. More
    /// than a thousand paths is history or a vendored tree, not a change
    /// a path-scoped policy could mean; nothing is recorded for it, and
    /// a waiver that needs paths does not apply.
    pub fn push_revision_with_paths(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        commit_oid: &str,
        session: Option<&SessionId>,
        message: &str,
        paths: Vec<String>,
    ) -> CoreResult<(i64, Envelope)> {
        let paths = if paths.len() > MAX_PATHS {
            Vec::new()
        } else {
            paths
        };
        for path in &paths {
            bounded("a revision path", path, 1_024)?;
        }
        let tx = self.conn.transaction()?;
        require(valid_commit_oid(commit_oid), || {
            format!("{commit_oid:?} is not a valid commit oid")
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Push,
            Some(&current.repo),
        )?;
        ensure_writable(&tx, &current.repo)?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        if let Some(session) = session {
            let s = raw::session(&tx, session.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("session {session}")))?;
            if s.agent != *actor || s.state != SessionState::Active {
                return Err(CoreError::Conflict(format!(
                    "session {session} is not an active session of {actor}"
                )));
            }
        }
        bounded("revision message", message, MAX_TEXT)?;
        let revision = current.latest_revision + 1;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RevisionPushed {
                change: change.clone(),
                revision,
                commit_oid: commit_oid.to_owned(),
                session: session.cloned(),
                message: message.to_owned(),
                paths,
            },
        )?;
        tx.commit()?;
        Ok((revision, env))
    }

    pub fn attach_claim(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        revision: i64,
        spec: ClaimSpec,
    ) -> CoreResult<(ClaimId, Envelope)> {
        let tx = self.conn.transaction()?;
        require(!spec.summary.trim().is_empty(), || {
            "claim summary must not be empty".into()
        })?;
        bounded("claim summary", &spec.summary, MAX_TITLE)?;
        if let Some(command) = &spec.command {
            bounded("claim command", command, MAX_TEXT)?;
        }
        require(spec.unchecked.len() <= MAX_ITEMS, || {
            format!("a claim may declare at most {MAX_ITEMS} gaps")
        })?;
        for gap in &spec.unchecked {
            bounded("a declared gap", gap, MAX_TITLE)?;
        }
        require(spec.covers.len() <= MAX_ITEMS, || {
            format!("a claim covers at most {MAX_ITEMS} paths")
        })?;
        for path in &spec.covers {
            require(
                !path.trim().is_empty() && !path.contains(char::is_whitespace),
                || format!("{path:?} is not a path or a prefix a claim can cover"),
            )?;
            // A cover names code; "*" or "/" names the whole tree, which
            // is not a claim anybody ran a command over.
            require(
                path.chars().any(|c| c != '*' && c != '/' && c != '.'),
                || format!("{path:?} covers everything; name the paths the command exercises"),
            )?;
            bounded("a covered path", path, MAX_TITLE)?;
        }
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Push,
            Some(&current.repo),
        )?;
        require((1..=current.latest_revision).contains(&revision), || {
            format!("change {change} has no revision {revision}")
        })?;
        let claim = ClaimId::generate();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ClaimAttached {
                claim: claim.clone(),
                change: change.clone(),
                revision,
                claim_kind: spec.kind,
                command: spec.command,
                passed: spec.passed,
                summary: spec.summary,
                unchecked: spec.unchecked,
                covers: spec.covers,
            },
        )?;
        tx.commit()?;
        Ok((claim, env))
    }

    pub fn give_verdict(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        revision: i64,
        domain: ReviewDomain,
        disposition: Disposition,
        rationale: &str,
    ) -> CoreResult<(VerdictId, Envelope)> {
        let tx = self.conn.transaction()?;
        require(!rationale.trim().is_empty(), || {
            "verdict rationale must not be empty: judgment without reasons doesn't compose".into()
        })?;
        bounded("verdict rationale", rationale, MAX_TEXT)?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Review,
            Some(&current.repo),
        )?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        require((1..=current.latest_revision).contains(&revision), || {
            format!("change {change} has no revision {revision}")
        })?;
        let verdict = VerdictId::generate();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::VerdictGiven {
                verdict: verdict.clone(),
                change: change.clone(),
                revision,
                domain,
                disposition,
                rationale: rationale.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok((verdict, env))
    }

    /// Spend today's attention budget: draw the changes most worth a
    /// human's time, up to the repository's daily allowance, and say why
    /// and to whom. A change is drawn once; it then waits for a human
    /// verdict before it lands. Deterministic given the graph and the
    /// day, so a second call in the same day draws nothing more. The
    /// draw is the owner's policy acting, and is attributed to them.
    pub fn draw_attention(&mut self, repo: &str, day: &str) -> CoreResult<Vec<Envelope>> {
        let tx = self.conn.transaction()?;
        let Some(record) = raw::repo(&tx, repo)? else {
            return Err(CoreError::NotFound(format!("repo {repo}")));
        };
        let Some(budget) = record.policy.attention_budget else {
            return Ok(Vec::new());
        };
        let spent = raw::draws_on(&tx, repo, day)?;
        let remaining = i64::from(budget) - spent;
        if remaining <= 0 {
            return Ok(Vec::new());
        }
        let reviewers = raw::humans_who_may_review(&tx, repo)?;
        let mut drawn = Vec::new();
        for item in crate::attention::evaluate(&tx, repo)? {
            if drawn.len() as i64 >= remaining {
                break;
            }
            if item.drawn.is_some()
                || crate::attention::human_looked(
                    &tx,
                    item.change.id.as_str(),
                    item.change.latest_revision,
                )?
            {
                continue;
            }
            let asked: Vec<PrincipalId> = reviewers
                .iter()
                .filter(|r| **r != item.change.owner)
                .cloned()
                .collect();
            if asked.is_empty() {
                continue;
            }
            drawn.push(append(
                &tx,
                &record.owner,
                self.acting.as_ref().and_then(|s| s.session.as_ref()),
                Event::AttentionDrawn {
                    repo: repo.to_owned(),
                    day: day.to_owned(),
                    change: item.change.id.clone(),
                    signals: item.signals.iter().map(|s| s.kind).collect(),
                    reviewers: asked,
                },
            )?);
        }
        tx.commit()?;
        Ok(drawn)
    }

    /// Draw now, at somebody's request rather than the clock's. Takes
    /// the merge capability on the repository, which owners hold.
    pub fn draw_attention_now(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        day: &str,
    ) -> CoreResult<Vec<Envelope>> {
        {
            let tx = self.conn.transaction()?;
            authorize(
                &tx,
                self.acting.as_ref(),
                actor,
                Capability::Merge,
                Some(repo),
            )?;
        }
        self.draw_attention(repo, day)
    }

    /// Start a discussion on a change, anchored to a line of a revision's
    /// diff, a claim, a verdict, or the change itself. A claim or verdict
    /// anchor pins the revision it was made on; otherwise the thread is
    /// on the revision given, or the latest.
    pub fn open_thread(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        revision: Option<i64>,
        anchor: Anchor,
        kind: ThreadKind,
        body: &str,
    ) -> CoreResult<(ThreadId, Envelope)> {
        let tx = self.conn.transaction()?;
        require(!body.trim().is_empty(), || {
            "a thread needs something to say".into()
        })?;
        bounded("thread", body, MAX_TEXT)?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        may_discuss(&tx, self.acting.as_ref(), actor, &current)?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        let revision = match &anchor {
            Anchor::Claim { claim } => {
                raw::claim(&tx, claim.as_str())?
                    .filter(|c| c.change == *change)
                    .ok_or_else(|| {
                        CoreError::NotFound(format!("claim {} on change {change}", claim.as_str()))
                    })?
                    .revision
            }
            Anchor::Verdict { verdict } => {
                raw::verdict_ref(&tx, verdict.as_str())?
                    .filter(|(on, _)| on == change.as_str())
                    .ok_or_else(|| {
                        CoreError::NotFound(format!(
                            "verdict {} on change {change}",
                            verdict.as_str()
                        ))
                    })?
                    .1
            }
            Anchor::Line { path, line, .. } => {
                require(!path.trim().is_empty() && *line >= 1, || {
                    "a line anchor needs a path and a line number, counted from 1".into()
                })?;
                bounded("path", path, MAX_TITLE)?;
                revision.unwrap_or(current.latest_revision)
            }
            Anchor::Change => revision.unwrap_or(current.latest_revision),
        };
        require((1..=current.latest_revision).contains(&revision), || {
            format!("change {change} has no revision {revision}")
        })?;
        let thread = ThreadId::generate();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ThreadOpened {
                thread: thread.clone(),
                change: change.clone(),
                revision,
                anchor,
                thread_kind: kind,
                body: body.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok((thread, env))
    }

    /// Say something in a thread. Whoever opened it may always reply;
    /// anyone else needs a part in the repository.
    pub fn reply_thread(
        &mut self,
        actor: &PrincipalId,
        thread: &ThreadId,
        body: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        require(!body.trim().is_empty(), || {
            "a reply needs something to say".into()
        })?;
        bounded("reply", body, MAX_TEXT)?;
        let existing = raw::thread(&tx, thread.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("thread {}", thread.as_str())))?;
        let current = raw::change(&tx, existing.change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {}", existing.change)))?;
        if existing.by == *actor {
            ensure_actor(&tx, actor)?;
        } else {
            may_discuss(&tx, self.acting.as_ref(), actor, &current)?;
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ThreadReplied {
                thread: thread.clone(),
                change: existing.change.clone(),
                body: body.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Close a thread and say how. Withdrawing is the opener's alone;
    /// overruling is for the change's owner or a reviewer, and never the
    /// opener; "fixed" names a revision after the one the thread was
    /// opened on. Resolving twice is refused, so a resolution is never
    /// quietly replaced.
    pub fn resolve_thread(
        &mut self,
        actor: &PrincipalId,
        thread: &ThreadId,
        how: Resolution,
        revision: Option<i64>,
        note: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        bounded("resolution note", note, MAX_TEXT)?;
        let existing = raw::thread(&tx, thread.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("thread {}", thread.as_str())))?;
        if existing.resolved.is_some() {
            return Err(CoreError::Conflict(format!(
                "thread {} is already resolved",
                thread.as_str()
            )));
        }
        let current = raw::change(&tx, existing.change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {}", existing.change)))?;
        let opener = existing.by == *actor;
        let owner_or_reviewer = current.owner == *actor
            || authorize(
                &tx,
                self.acting.as_ref(),
                actor,
                Capability::Review,
                Some(&current.repo),
            )
            .is_ok();
        match how {
            Resolution::Withdrawn if !opener => {
                return Err(CoreError::Forbidden(
                    "only whoever opened a thread can withdraw it".into(),
                ));
            }
            Resolution::Overruled if opener => {
                return Err(CoreError::Forbidden(
                    "you cannot overrule your own thread; withdraw it or answer it".into(),
                ));
            }
            Resolution::Overruled if !owner_or_reviewer => {
                return Err(CoreError::Forbidden(
                    "overruling a thread takes the change's owner or a reviewer".into(),
                ));
            }
            _ => {}
        }
        if opener {
            ensure_actor(&tx, actor)?;
        } else {
            may_discuss(&tx, self.acting.as_ref(), actor, &current)?;
        }
        let revision = match how {
            Resolution::Fixed => {
                let fixed = revision.ok_or_else(|| {
                    CoreError::Invalid("a fix names the revision that made it".into())
                })?;
                require(
                    fixed > existing.revision && fixed <= current.latest_revision,
                    || {
                        format!(
                            "revision {fixed} is not a revision after {} on this change",
                            existing.revision
                        )
                    },
                )?;
                Some(fixed)
            }
            _ => None,
        };
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ThreadResolved {
                thread: thread.clone(),
                change: existing.change.clone(),
                how,
                revision,
                note: note.trim().to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Declare which paths a session expects to touch, and learn who
    /// else is already there. Overlaps are reported, never refused:
    /// the forge makes the collision visible while it is still cheap,
    /// and the agent decides what to do about it.
    pub fn declare_paths(
        &mut self,
        actor: &PrincipalId,
        session: &SessionId,
        repo: &str,
        paths: Vec<String>,
    ) -> CoreResult<(Vec<Overlap>, Envelope)> {
        let tx = self.conn.transaction()?;
        require(!paths.is_empty(), || {
            "declare at least one path, or do not declare".into()
        })?;
        require(paths.iter().all(|p| !p.trim().is_empty()), || {
            "a declared path must not be empty".into()
        })?;
        require(paths.len() <= MAX_ITEMS, || {
            format!("declare at most {MAX_ITEMS} paths; use a prefix instead")
        })?;
        for path in &paths {
            bounded("a declared path", path, MAX_TITLE)?;
        }
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        let current = raw::session(&tx, session.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("session {session}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Push,
            Some(repo),
        )?;
        if current.agent != *actor {
            return Err(CoreError::Conflict(format!(
                "session {session} belongs to {}",
                current.agent
            )));
        }
        if current.state != SessionState::Active {
            return Err(CoreError::Conflict(format!(
                "session {session} has ended; its lease is gone"
            )));
        }
        let overlaps = leases::conflicts(&tx, repo, &paths, Some(session))?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::PathsDeclared {
                session: session.clone(),
                repo: repo.to_owned(),
                paths,
            },
        )?;
        tx.commit()?;
        Ok((overlaps, env))
    }

    /// Record that the forge carried a change onto a new base by
    /// itself. The author's revisions are never rewritten; this adds
    /// one, exactly as a push would.
    pub fn record_rebase(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        commit_oid: &str,
        onto: &str,
    ) -> CoreResult<(i64, Envelope)> {
        self.push_revision(
            actor,
            change,
            commit_oid,
            None,
            &format!("rebased onto {onto} by the forge"),
        )
    }

    /// Record that it could not, and why. A fact about an attempt: it
    /// changes nothing, and asks a person for something.
    pub fn record_rebase_failure(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        onto: &str,
        files: Vec<String>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Merge,
            Some(&current.repo),
        )?;
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RebaseFailed {
                change: change.clone(),
                onto: onto.to_owned(),
                files,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Record an independent re-execution of a claim. The runner must
    /// hold the verify capability and must not be the claimant: a
    /// claim re-checked by its own author proves nothing.
    pub fn verify_claim(
        &mut self,
        actor: &PrincipalId,
        claim: &ClaimId,
        agrees: bool,
        command: &str,
        observed: &str,
    ) -> CoreResult<(VerificationId, Envelope)> {
        let tx = self.conn.transaction()?;
        require(!command.trim().is_empty(), || {
            "a verification must say what it ran".into()
        })?;
        require(!observed.trim().is_empty(), || {
            "a verification must say what it saw".into()
        })?;
        bounded("verification command", command, MAX_TEXT)?;
        bounded("what the verification saw", observed, MAX_TEXT)?;
        let current = raw::claim(&tx, claim.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("claim {claim}")))?;
        let change = raw::change(&tx, current.change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {}", current.change)))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Verify,
            Some(&change.repo),
        )?;
        if current.by == *actor {
            return Err(CoreError::Conflict(format!(
                "{actor} made claim {claim}; verification must be independent"
            )));
        }
        let verification = VerificationId::generate();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ClaimVerified {
                verification: verification.clone(),
                claim: claim.clone(),
                change: current.change.clone(),
                revision: current.revision,
                agrees,
                command: command.to_owned(),
                observed: observed.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok((verification, env))
    }

    /// Compare a change's competing revisions and say which should land.
    /// Review authority, and independence: nobody who wrote one of the
    /// revisions may choose between them.
    pub fn prefer_revision(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        revision: i64,
        rationale: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Review,
            Some(&current.repo),
        )?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        require(!rationale.trim().is_empty(), || {
            "a comparison must say why this revision and not the others".into()
        })?;
        bounded("comparison rationale", rationale, MAX_TEXT)?;
        let revisions = raw::revisions(&tx, change.as_str())?;
        require(revisions.iter().any(|r| r.number == revision), || {
            format!("change {change} has no revision {revision}")
        })?;
        if !current.competing {
            return Err(CoreError::Conflict(format!(
                "change {change} has revisions by one author; there is nothing to compare"
            )));
        }
        if revisions.iter().any(|r| r.by == *actor) {
            return Err(CoreError::Forbidden(format!(
                "{actor} wrote a revision of {change}; the comparison must come from somebody else"
            )));
        }
        let over: Vec<i64> = revisions
            .iter()
            .map(|r| r.number)
            .filter(|n| *n != revision)
            .collect();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::RevisionPreferred {
                change: change.clone(),
                revision,
                over,
                rationale: rationale.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Dry-run the merge policy: what would block a merge right now?
    /// Agents subscribe to events and consult this to decide their next
    /// move — fix a failing requirement, or stop, satisfied.
    pub fn merge_readiness(&self, change: &ChangeId) -> CoreResult<PolicyTrace> {
        let current = raw::change(&self.conn, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        policy::evaluate(&self.conn, &current)
    }

    /// Merge a change if policy allows. Records the decision and its full
    /// justification; advancing the git ref is the transport layer's job,
    /// driven by this event.
    pub fn merge_change(&mut self, actor: &PrincipalId, change: &ChangeId) -> CoreResult<Envelope> {
        self.merge_change_as(actor, change, None)
    }

    /// Merge with an explicit landed commit — the queue's path when it
    /// rebased the reviewed revision onto a moved target.
    pub fn merge_change_as(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        merged_as: Option<&str>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Merge,
            Some(&current.repo),
        )?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        if let Some(oid) = merged_as {
            require(valid_commit_oid(oid), || {
                format!("{oid:?} is not a valid commit oid")
            })?;
        }
        let trace = policy::evaluate(&tx, &current)?;
        if !trace.satisfied {
            return Err(CoreError::PolicyUnsatisfied(trace.unmet_summary()));
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ChangeMerged {
                change: change.clone(),
                revision: current.judged_revision(),
                merged_as: merged_as.map(str::to_owned),
                trace,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Enter the landing queue. Policy must already be satisfied — the
    /// queue lands ready work, it does not wait for reviews — and a
    /// stacked change may only follow its merged parent.
    pub fn enqueue_change(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Merge,
            Some(&current.repo),
        )?;
        ensure_writable(&tx, &current.repo)?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        if raw::queue_entry(&tx, change.as_str())?.is_some() {
            return Err(CoreError::Conflict(format!(
                "change {change} is already queued"
            )));
        }
        if let Some(parent) = &current.parent_change {
            let parent_change = raw::change(&tx, parent.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("change {parent}")))?;
            if parent_change.state != ChangeState::Merged {
                return Err(CoreError::Conflict(format!(
                    "stack parent (change {}) is {}, not merged; enqueue the stack bottom-up",
                    parent_change.number,
                    parent_change.state.as_str()
                )));
            }
        }
        let trace = policy::evaluate(&tx, &current)?;
        if !trace.satisfied {
            return Err(CoreError::PolicyUnsatisfied(trace.unmet_summary()));
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ChangeEnqueued {
                change: change.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Leave the queue without merging. The enqueuer, the change's
    /// owner, or anyone holding merge authority (the processor uses
    /// this to record why a landing was abandoned).
    pub fn dequeue_change(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        reason: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        require(!reason.trim().is_empty(), || {
            "dequeue reason must not be empty".into()
        })?;
        bounded("dequeue reason", reason, MAX_TEXT)?;
        let entry = raw::queue_entry(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change} is not queued")))?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        if entry.enqueued_by != *actor && current.owner != *actor {
            authorize(
                &tx,
                self.acting.as_ref(),
                actor,
                Capability::Merge,
                Some(&current.repo),
            )?;
        } else {
            ensure_actor(&tx, actor)?;
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ChangeDequeued {
                change: change.clone(),
                reason: reason.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn abandon_change(
        &mut self,
        actor: &PrincipalId,
        change: &ChangeId,
        reason: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        require(!reason.trim().is_empty(), || {
            "abandon reason must not be empty".into()
        })?;
        bounded("abandon reason", reason, MAX_TEXT)?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(
            &tx,
            self.acting.as_ref(),
            actor,
            Capability::Push,
            Some(&current.repo),
        )?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::ChangeAbandoned {
                change: change.clone(),
                reason: reason.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }
    /// Mint an API token. The secret is returned exactly once; only its
    /// hash enters the log. A principal may mint for itself; humans may
    /// mint for anyone.
    pub fn mint_token(
        &mut self,
        actor: &PrincipalId,
        principal: &PrincipalId,
        label: Option<&str>,
        until: Option<&str>,
    ) -> CoreResult<(TokenId, String, Envelope)> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        // A standing token outlives every session and carries every
        // grant its principal holds, so drawing one is never something a
        // session credential does — including for itself, which is how a
        // fifteen-minute workload credential could have become permanent.
        not_under_a_scope(self.acting.as_ref(), "mint a standing token")?;
        if let Some(label) = label {
            bounded("label", label, MAX_TITLE)?;
            // An invitation is a token with a label the sign-in page
            // spends for a browser session. That label is the forge's
            // to write, never a caller's: a token minted with it would
            // be a session for whoever the token was minted for.
            require(!label.starts_with(INVITATION_LABEL), || {
                format!("labels beginning with {INVITATION_LABEL:?} are the forge's own")
            })?;
        }
        // Authority before existence, so a caller with none learns
        // nothing about which names are taken from the shape of the
        // refusal. A token is the principal's own credential; minting
        // one for somebody else is running the forge, not being a
        // person — except for an agent you hold, which is yours and
        // cannot work without one.
        let found = raw::principal(&tx, principal.as_str())?;
        let holds = match &found {
            Some(subject) => holds_agent(&tx, actor, subject)?,
            None => false,
        };
        if actor != principal && !holds {
            human_act(&tx, actor, "mint a token for another principal")?;
            authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        }
        let subject = found.ok_or_else(|| CoreError::NotFound(format!("principal {principal}")))?;
        require(subject.kind != PrincipalKind::Team, || {
            format!("{principal} is a team, and a team never signs in")
        })?;
        // A token for a stopped principal would never sign in, and
        // would still take a place in its owner's allowance.
        if !subject.active {
            return Err(CoreError::Conflict(format!(
                "{principal} is deactivated; bring it back before minting for it"
            )));
        }
        // Tokens are rows too, and a principal minting them without end
        // is a principal filling the database. Charged to whoever the
        // token is ultimately for: a person, or an agent's owner.
        if let Some(owner) = subject.owner.as_ref() {
            within_quota(
                &tx,
                &self.default_quota,
                owner,
                "tokens",
                |q| q.tokens,
                |u| u.tokens,
            )?;
        }
        let (token, secret, env) = append_token(&tx, actor, principal, label, until)?;
        tx.commit()?;
        Ok((token, secret, env))
    }

    /// Mint an invitation: a token the sign-in page spends for a
    /// browser session, for a person who has no other way in yet.
    /// Whoever runs the forge does this, in person; `mailed` marks one
    /// that went to the person's address, so following it proves the
    /// address. Not a credential, and not counted as one.
    pub fn mint_invitation(
        &mut self,
        actor: &PrincipalId,
        principal: &PrincipalId,
        mailed: bool,
        until: Option<&str>,
    ) -> CoreResult<(TokenId, String, Envelope)> {
        let tx = self.conn.transaction()?;
        not_under_a_scope(self.acting.as_ref(), "invite somebody")?;
        human_act(&tx, actor, "invite somebody")?;
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        let subject = raw::principal(&tx, principal.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {principal}")))?;
        require(subject.kind == PrincipalKind::Human, || {
            format!("{principal} is not a person; only a person is invited to sign in")
        })?;
        if !subject.active {
            return Err(CoreError::Conflict(format!(
                "{principal} is deactivated; bring them back before inviting them"
            )));
        }
        let label = if mailed {
            MAILED_INVITATION_LABEL
        } else {
            INVITATION_LABEL
        };
        let (token, secret, env) = append_token(&tx, actor, principal, Some(label), until)?;
        tx.commit()?;
        Ok((token, secret, env))
    }

    /// Revoke a token, effective immediately. The owner or any human.
    pub fn revoke_token(&mut self, actor: &PrincipalId, token: &TokenId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        not_under_a_scope(self.acting.as_ref(), "revoke a standing token")?;
        ensure_actor(&tx, actor)?;
        // Authority before existence, as everywhere: your own, an agent
        // you hold, or running the forge.
        let found = raw::token(&tx, token.as_str())?;
        let permitted = match &found {
            Some(current) if current.principal == *actor => true,
            Some(current) => match raw::principal(&tx, current.principal.as_str())? {
                Some(subject) => holds_agent(&tx, actor, &subject)?,
                None => false,
            },
            None => false,
        };
        if !permitted {
            authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        }
        let current = found.ok_or_else(|| CoreError::NotFound(format!("token {token}")))?;
        if current.revoked {
            return Err(CoreError::Conflict(format!(
                "token {token} is already revoked"
            )));
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::TokenRevoked {
                token: token.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Issue a capability grant. Only humans delegate — agents cannot
    /// widen their own authority or another agent's.
    pub fn issue_grant(
        &mut self,
        actor: &PrincipalId,
        grantee: &PrincipalId,
        repo: Option<&str>,
        actions: Vec<Capability>,
        until: Option<&str>,
    ) -> CoreResult<(GrantId, Envelope)> {
        let tx = self.conn.transaction()?;
        let acting = ensure_actor(&tx, actor)?;
        if acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not issue grants: delegation is a human act"
            )));
        }
        // You cannot hand out what you do not hold. Owning the
        // repository is enough for a grant scoped to it; anything wider
        // needs the admin grant that running the forge consists of.
        authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, repo)?;
        let who = raw::principal(&tx, grantee.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {grantee}")))?;
        if let Some(repo) = repo {
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        }
        require(!actions.is_empty(), || {
            "a grant must carry at least one capability".into()
        })?;
        // Running the forge is a person's. An agent handed the admin
        // grant would set policy, quotas and visibility as the forge,
        // and every act over principals it is refused below would be
        // one refusal away from a bypass. Grant it the capabilities its
        // work needs, on the repositories where it does that work.
        require(
            who.kind != PrincipalKind::Agent || !actions.contains(&Capability::Admin),
            || format!("{grantee} is an agent, and admin is never an agent's"),
        )?;
        let mut actions = actions;
        actions.sort_by_key(|c| c.as_str());
        actions.dedup();
        // Store expiry canonically so lexicographic comparison is sound.
        let until = until
            .map(|raw| {
                raw.parse::<jiff::Timestamp>()
                    .map(|ts| ts.to_string())
                    .map_err(|e| CoreError::Invalid(format!("bad expiry {raw:?}: {e}")))
            })
            .transpose()?;
        let grant = GrantId::generate();
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::GrantIssued {
                grant: grant.clone(),
                grantee: grantee.clone(),
                repo: repo.map(str::to_owned),
                actions,
                until,
            },
        )?;
        tx.commit()?;
        Ok((grant, env))
    }

    /// Give somebody the unscoped admin grant that running the forge
    /// consists of, without asking anyone's permission.
    ///
    /// This exists for exactly one caller: the offline admin path, where
    /// having the database file is already the root authority. It is the
    /// answer to the obvious circularity — nobody can grant admin until
    /// somebody holds it — and it is deliberately not reachable over the
    /// API, where that circle should stay unbroken.
    pub fn grant_bootstrap_admin(&mut self, id: &PrincipalId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let who = ensure_actor(&tx, id)?;
        require(who.kind == PrincipalKind::Human, || {
            format!("{id} is not a person, and running the forge is a person's")
        })?;
        let grant = GrantId::generate();
        let env = append(
            &tx,
            id,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::GrantIssued {
                grant,
                grantee: id.clone(),
                repo: None,
                actions: vec![Capability::Admin],
                until: None,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Revoke a grant, effective immediately. The grantor or any human.
    pub fn revoke_grant(
        &mut self,
        actor: &PrincipalId,
        grant: &GrantId,
        reason: &str,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        not_under_a_scope(self.acting.as_ref(), "revoke a grant")?;
        ensure_actor(&tx, actor)?;
        require(!reason.trim().is_empty(), || {
            "revocation reason must not be empty".into()
        })?;
        let current = raw::grant(&tx, grant.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("grant {grant}")))?;
        // The grantor's, the grantee's, the owner's of the repository it
        // is scoped to — whoever holds a repository decides who acts on
        // it, whoever issued the grant — or the forge's.
        let on_their_repo = match current.repo.as_deref() {
            Some(repo) => match raw::repo(&tx, repo)? {
                Some(record) => raw::owns(&tx, actor.as_str(), record.owner.as_str())?,
                None => false,
            },
            None => false,
        };
        if current.grantor != *actor && current.grantee != *actor && !on_their_repo {
            authorize(&tx, self.acting.as_ref(), actor, Capability::Admin, None)?;
        }
        if current.revoked {
            return Err(CoreError::Conflict(format!(
                "grant {grant} is already revoked"
            )));
        }
        let env = append(
            &tx,
            actor,
            self.acting.as_ref().and_then(|s| s.session.as_ref()),
            Event::GrantRevoked {
                grant: grant.clone(),
                reason: reason.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }
}

/// The label that marks a token as an invitation rather than a
/// credential: spent by the sign-in page for a browser session, and
/// never accepted as a bearer token.
pub const INVITATION_LABEL: &str = "invitation";
/// An invitation that went out by mail: following it proves the address.
pub const MAILED_INVITATION_LABEL: &str = "invitation:mailed";

/// Write a token into the log and hand back the one copy of its secret.
fn append_token(
    tx: &Transaction,
    actor: &PrincipalId,
    principal: &PrincipalId,
    label: Option<&str>,
    until: Option<&str>,
) -> CoreResult<(TokenId, String, Envelope)> {
    let token = TokenId::generate();
    let secret = random_token_secret();
    let env = append(
        tx,
        actor,
        None,
        Event::TokenMinted {
            token: token.clone(),
            principal: principal.clone(),
            label: label.map(str::to_owned),
            hash: token_hash(&secret),
            until: until.map(str::to_owned),
        },
    )?;
    Ok((token, secret, env))
}

/// An expiry this many days from now, as the log records instants.
/// Days here are 24-hour spans: an expiry is an instant, and civil days
/// mean different amounts of elapsed time across a DST boundary.
pub fn until_in_days(days: i64) -> String {
    (jiff::Timestamp::now() + jiff::Span::new().hours(days * 24)).to_string()
}

/// How long a write's answer stays replayable. A day is what the
/// industry converged on: long enough for any retry loop, short enough
/// that the table stays a cache rather than a second log.
fn replays_kept_since() -> String {
    (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24)).to_string()
}
