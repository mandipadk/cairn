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
    ChangeId, ClaimId, GrantId, PrincipalId, SessionId, TaskId, TokenId, VerdictId, VerificationId,
    random_token_secret, validate_slug,
};
use crate::leases::{self, Overlap};
use crate::policy::{self, PolicyTrace};
use crate::queries::raw;
use crate::store::{Store, append};
use crate::types::{
    Capability, ChangeSpec, ChangeState, ClaimSpec, Disposition, Mirror, ObjectFormat, Policy,
    Principal, PrincipalKind, ReviewDomain, SessionState, TaskState, Visibility,
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
    raw::principal(tx, actor.as_str())?
        .ok_or_else(|| CoreError::NotFound(format!("principal {actor}")))
}

/// The law: humans are sovereign; agents act only under a live grant
/// covering the capability and scope. Refusals name the missing
/// capability and how to obtain it, so an agent can act on them.
fn authorize(
    tx: &Transaction,
    actor: &PrincipalId,
    action: Capability,
    repo: Option<&str>,
) -> CoreResult<Principal> {
    let principal = ensure_actor(tx, actor)?;

    // Ownership is the one authority nobody is granted: it comes with
    // having made the thing. Everything else — for humans exactly as for
    // agents — is a grant somebody issued and can take back.
    //
    // This used to read "if the principal is a human, allow it", which
    // is right for a forge with one operator and wrong the moment there
    // are two: it made every person who could sign in an administrator
    // of everybody else's work. "Human" was standing in for "the person
    // running this", and those stopped being the same thing.
    if let Some(name) = repo
        && let Some(record) = raw::repo(tx, name)?
        && record.owner == *actor
    {
        return Ok(principal);
    }

    let grants = raw::grants_of(tx, actor.as_str())?;
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

/// Free text a caller controls is bounded, because an append-only log
/// keeps whatever it is given forever. The limits are generous enough
/// that no honest use meets them.
const MAX_TITLE: usize = 300;
const MAX_TEXT: usize = 8_000;
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

fn verify_password(password: &str, hash: &str) -> bool {
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
fn may_create_repo(tx: &Transaction, actor: &PrincipalId) -> CoreResult<()> {
    let principal = ensure_actor(tx, actor)?;
    if principal.kind == PrincipalKind::Human {
        return Ok(());
    }
    let grants = raw::grants_of(tx, actor.as_str())?;
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
    const RESERVED: &[&str] = &["api", "git", "login", "logout", "assets", "ui"];
    require(validate_slug(name), || {
        format!("repo name {name:?} is not a valid slug")
    })?;
    require(!RESERVED.contains(&name), || {
        format!("repo name {name:?} is reserved")
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
    pub fn register_principal(
        &mut self,
        actor: &PrincipalId,
        id: &PrincipalId,
        kind: PrincipalKind,
        display: &str,
        model: Option<&str>,
        harness: Option<&str>,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
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
        let bootstrap = raw::principal_count(&tx)? == 0 && actor == id;
        if !bootstrap {
            authorize(&tx, actor, Capability::Admin, None)?;
        }
        let env = append(
            &tx,
            actor,
            Event::PrincipalRegistered {
                principal: id.clone(),
                principal_kind: kind,
                display: display.to_owned(),
                model: model.map(str::to_owned),
                harness: harness.map(str::to_owned),
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
            authorize(&tx, actor, Capability::Admin, None)?;
        }
        // Long enough to resist guessing, short enough that a password
        // manager's output always fits.
        require((12..=1024).contains(&password.len()), || {
            "a password must be between 12 and 1024 bytes".into()
        })?;
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
    pub fn start_session(&mut self, principal: &PrincipalId, ttl_days: i64) -> CoreResult<String> {
        // A session secret is a credential of the same weight as a
        // token, so it is generated the same way.
        let secret = format!("s{}", random_token_secret());
        let now = jiff::Timestamp::now();
        // Timestamps are absolute instants, so an expiry is expressed in
        // hours: calendar days are a civil-time idea and mean different
        // amounts of elapsed time across a DST boundary.
        let expires = now + jiff::Span::new().hours(ttl_days * 24);
        let tx = self.conn.transaction()?;
        // Expired rows are dead weight; clear them whenever one is made.
        tx.execute(
            "DELETE FROM browser_sessions WHERE expires <= ?",
            rusqlite::params![now.to_string()],
        )?;
        tx.execute(
            "INSERT INTO browser_sessions (id_hash, principal, created, expires) VALUES (?, ?, ?, ?)",
            rusqlite::params![
                token_hash(&secret),
                principal.as_str(),
                now.to_string(),
                expires.to_string()
            ],
        )?;
        tx.commit()?;
        Ok(secret)
    }

    /// Whose session this is, if it is live.
    pub fn session_holder(&self, secret: &str) -> Option<PrincipalId> {
        self.conn
            .prepare_cached(
                "SELECT principal FROM browser_sessions WHERE id_hash = ? AND expires > ?",
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
    pub fn join_waitlist(&mut self, email: &str, note: Option<&str>) -> CoreResult<bool> {
        let email = email.trim();
        require(valid_email(email), || {
            "that does not look like an email address".into()
        })?;
        if let Some(note) = note {
            bounded("note", note, MAX_TITLE)?;
        }
        let changed = self.conn.execute(
            "INSERT INTO waitlist (email, joined, note) VALUES (?, ?, ?)
             ON CONFLICT(email) DO NOTHING",
            rusqlite::params![
                email.to_lowercase(),
                jiff::Timestamp::now().to_string(),
                note.filter(|n| !n.trim().is_empty())
            ],
        )?;
        Ok(changed == 1)
    }

    /// The waitlist, oldest first.
    pub fn waitlist(&self) -> CoreResult<Vec<(String, String, Option<String>)>> {
        Ok(self
            .conn
            .prepare("SELECT email, joined, note FROM waitlist ORDER BY joined")?
            .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
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

    pub fn password_matches(&self, principal: &PrincipalId, password: &str) -> bool {
        let stored = raw::credential(&self.conn, principal.as_str())
            .ok()
            .flatten();
        match stored {
            Some(hash) => verify_password(password, &hash),
            None => {
                // Verify against a fixed hash so a missing principal
                // costs the same as a wrong password.
                verify_password(password, DUMMY_HASH);
                false
            }
        }
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
        name: &str,
        default_branch: &str,
    ) -> CoreResult<()> {
        let tx = self.conn.transaction()?;
        may_create_repo(&tx, actor)?;
        new_repo_is_allowed(&tx, name, default_branch)
        // The transaction is dropped, so nothing here is kept.
    }

    pub fn create_repo(
        &mut self,
        actor: &PrincipalId,
        name: &str,
        default_branch: &str,
        object_format: ObjectFormat,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        may_create_repo(&tx, actor)?;
        new_repo_is_allowed(&tx, name, default_branch)?;
        let env = append(
            &tx,
            actor,
            Event::RepoCreated {
                repo: name.to_owned(),
                default_branch: default_branch.to_owned(),
                object_format,
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Check an import source before anyone connects to it. The command
    /// enforces this too, but a caller that fetches first would have the
    /// forge dial an arbitrary url — and carry a credential there — on
    /// nothing but a caller's say-so. Validate, then fetch.
    pub fn validate_import_source(source: &str) -> CoreResult<()> {
        bounded("source", source, MAX_TITLE)?;
        require(
            ["https://", "ssh://", "file://"]
                .iter()
                .any(|scheme| source.starts_with(scheme)),
            || "a source url must be https://, ssh://, or file://".into(),
        )?;
        require(!source.contains('@'), || {
            "keep credentials out of the source url: pass a token when serving".into()
        })?;
        Ok(())
    }

    /// Record that a branch was seeded with history from somewhere
    /// else. Every other way a branch moves carries a policy trace
    /// saying why it was allowed; this one carries the opposite — an
    /// explicit marker that the commits below this tip were never
    /// judged here. Admin authority, and only onto a branch that does
    /// not exist yet: importing over reviewed history would overwrite
    /// exactly the decisions the log exists to keep.
    pub fn import_history(
        &mut self,
        actor: &PrincipalId,
        repo: &str,
        branch: &str,
        source: &str,
        tip_oid: &str,
        commits: i64,
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(&tx, actor, Capability::Admin, Some(repo))?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(valid_branch(branch), || {
            format!("{branch:?} is not a valid branch name")
        })?;
        Self::validate_import_source(source)?;
        require(
            matches!(tip_oid.len(), 40 | 64) && tip_oid.chars().all(|c| c.is_ascii_hexdigit()),
            || format!("{tip_oid:?} is not an object id"),
        )?;
        require(commits > 0, || "an import must carry commits".into())?;
        let env = append(
            &tx,
            actor,
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
        let Ok(Some(record)) = raw::repo(&self.conn, repo) else {
            return false;
        };
        if record.visibility == Visibility::Public {
            return true;
        }
        if record.owner == *actor {
            return true;
        }
        let Ok(grants) = raw::grants_of(&self.conn, actor.as_str()) else {
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
        let Ok(grants) = raw::grants_of(&self.conn, actor.as_str()) else {
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
        authorize(&tx, actor, Capability::Admin, Some(repo))?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(record.owner != *to, || "they already own it".to_owned())?;
        let recipient = raw::principal(&tx, to.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {to}")))?;
        require(recipient.kind == PrincipalKind::Human, || {
            "only a person can own a repository; grant an agent what it needs instead".to_owned()
        })?;
        let env = append(
            &tx,
            actor,
            Event::RepoTransferOffered {
                repo: repo.to_owned(),
                to: to.clone(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Take up an offer. Only the person it was made to can.
    pub fn accept_transfer(&mut self, actor: &PrincipalId, repo: &str) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(record.pending_owner.as_ref() == Some(actor), || {
            format!("{repo} has not been offered to {actor}")
        })?;
        let env = append(
            &tx,
            actor,
            Event::RepoTransferAccepted {
                repo: repo.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    /// Turn an offer down, or take it back: the offeree may decline, and
    /// whoever could have made the offer may withdraw it.
    pub fn decline_transfer(&mut self, actor: &PrincipalId, repo: &str) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        ensure_actor(&tx, actor)?;
        let record =
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(record.pending_owner.is_some(), || {
            format!("{repo} is not on offer")
        })?;
        if record.pending_owner.as_ref() != Some(actor) {
            authorize(&tx, actor, Capability::Admin, Some(repo))?;
        }
        let env = append(
            &tx,
            actor,
            Event::RepoTransferDeclined {
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
        authorize(&tx, actor, Capability::Admin, Some(repo))?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        let env = append(
            &tx,
            actor,
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
        authorize(&tx, actor, Capability::Admin, Some(repo))?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        require(policy.required_domains.len() <= MAX_ITEMS, || {
            format!("at most {MAX_ITEMS} required domains")
        })?;
        let env = append(
            &tx,
            actor,
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
    ) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        authorize(&tx, actor, Capability::Admin, Some(repo))?;
        raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        if let Some(mirror) = &mirror {
            bounded("mirror url", &mirror.url, MAX_TITLE)?;
            // https and ssh reach a hosted forge; file reaches another
            // disk, which is a legitimate place to keep a copy.
            require(
                ["https://", "ssh://", "file://"]
                    .iter()
                    .any(|scheme| mirror.url.starts_with(scheme)),
                || "a mirror url must be https://, ssh://, or file://".into(),
            )?;
            require(!mirror.url.contains('@'), || {
                "keep credentials out of the mirror url: pass a token when serving".into()
            })?;
        }
        let env = append(
            &tx,
            actor,
            Event::MirrorSet {
                repo: repo.to_owned(),
                mirror,
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
        let tx = self.conn.transaction()?;
        authorize(&tx, actor, Capability::Task, repo)?;
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
        let task = TaskId::generate();
        let env = append(
            &tx,
            actor,
            Event::TaskCreated {
                task: task.clone(),
                repo: repo.map(str::to_owned),
                title: title.to_owned(),
                spec: spec.to_owned(),
                parent: parent.cloned(),
            },
        )?;
        tx.commit()?;
        Ok((task, env))
    }

    pub fn claim_task(&mut self, actor: &PrincipalId, task: &TaskId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let current = raw::task(&tx, task.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
        authorize(&tx, actor, Capability::Task, current.repo.as_deref())?;
        if current.state != TaskState::Open {
            return Err(CoreError::Conflict(format!(
                "task {task} is {}, not open",
                current.state.as_str()
            )));
        }
        let env = append(&tx, actor, Event::TaskClaimed { task: task.clone() })?;
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
        authorize(&tx, actor, Capability::Task, current.repo.as_deref())?;
        require(state != TaskState::Claimed, || {
            "use claim_task to claim; claiming records who claimed".into()
        })?;
        let env = append(
            &tx,
            actor,
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
        authorize(&tx, actor, Capability::Task, current.repo.as_deref())?;
        if current.state != TaskState::Claimed || current.claimed_by.as_ref() != Some(actor) {
            return Err(CoreError::Conflict(format!(
                "task {task} must be claimed by {actor} before opening a session"
            )));
        }
        let session = SessionId::generate();
        let env = append(
            &tx,
            actor,
            Event::SessionOpened {
                session: session.clone(),
                task: task.clone(),
            },
        )?;
        tx.commit()?;
        Ok((session, env))
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
        authorize(&tx, actor, Capability::Task, task.repo.as_deref())?;
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
            Event::SessionEnded {
                session: session.clone(),
                state,
                outcome: outcome.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }

    pub fn open_change(
        &mut self,
        actor: &PrincipalId,
        spec: ChangeSpec,
    ) -> CoreResult<(ChangeId, i64, Envelope)> {
        let tx = self.conn.transaction()?;
        authorize(&tx, actor, Capability::Push, Some(&spec.repo))?;
        raw::repo(&tx, &spec.repo)?
            .ok_or_else(|| CoreError::NotFound(format!("repo {}", spec.repo)))?;
        require(valid_branch(&spec.target), || {
            format!("{:?} is not a valid branch name", spec.target)
        })?;
        require(!spec.title.trim().is_empty(), || {
            "change title must not be empty".into()
        })?;
        bounded("change title", &spec.title, MAX_TITLE)?;
        if let Some(task) = &spec.task {
            raw::task(&tx, task.as_str())?
                .ok_or_else(|| CoreError::NotFound(format!("task {task}")))?;
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
        let tx = self.conn.transaction()?;
        require(valid_commit_oid(commit_oid), || {
            format!("{commit_oid:?} is not a valid commit oid")
        })?;
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Push, Some(&current.repo))?;
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
            Event::RevisionPushed {
                change: change.clone(),
                revision,
                commit_oid: commit_oid.to_owned(),
                session: session.cloned(),
                message: message.to_owned(),
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
        let current = raw::change(&tx, change.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("change {change}")))?;
        authorize(&tx, actor, Capability::Push, Some(&current.repo))?;
        require((1..=current.latest_revision).contains(&revision), || {
            format!("change {change} has no revision {revision}")
        })?;
        let claim = ClaimId::generate();
        let env = append(
            &tx,
            actor,
            Event::ClaimAttached {
                claim: claim.clone(),
                change: change.clone(),
                revision,
                claim_kind: spec.kind,
                command: spec.command,
                passed: spec.passed,
                summary: spec.summary,
                unchecked: spec.unchecked,
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
        authorize(&tx, actor, Capability::Review, Some(&current.repo))?;
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
        authorize(&tx, actor, Capability::Push, Some(repo))?;
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
        authorize(&tx, actor, Capability::Merge, Some(&current.repo))?;
        let env = append(
            &tx,
            actor,
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
        authorize(&tx, actor, Capability::Verify, Some(&change.repo))?;
        if current.by == *actor {
            return Err(CoreError::Conflict(format!(
                "{actor} made claim {claim}; verification must be independent"
            )));
        }
        let verification = VerificationId::generate();
        let env = append(
            &tx,
            actor,
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
        authorize(&tx, actor, Capability::Merge, Some(&current.repo))?;
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
            Event::ChangeMerged {
                change: change.clone(),
                revision: current.latest_revision,
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
        authorize(&tx, actor, Capability::Merge, Some(&current.repo))?;
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
            authorize(&tx, actor, Capability::Merge, Some(&current.repo))?;
        } else {
            ensure_actor(&tx, actor)?;
        }
        let env = append(
            &tx,
            actor,
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
        authorize(&tx, actor, Capability::Push, Some(&current.repo))?;
        if current.state != ChangeState::Open {
            return Err(CoreError::Conflict(format!(
                "change {change} is {}, not open",
                current.state.as_str()
            )));
        }
        let env = append(
            &tx,
            actor,
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
    ) -> CoreResult<(TokenId, String, Envelope)> {
        let tx = self.conn.transaction()?;
        let acting = ensure_actor(&tx, actor)?;
        raw::principal(&tx, principal.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {principal}")))?;
        if actor != principal && acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not mint tokens for {principal}: only the principal itself or a human"
            )));
        }
        let token = TokenId::generate();
        let secret = random_token_secret();
        let env = append(
            &tx,
            actor,
            Event::TokenMinted {
                token: token.clone(),
                principal: principal.clone(),
                label: label.map(str::to_owned),
                hash: token_hash(&secret),
            },
        )?;
        tx.commit()?;
        Ok((token, secret, env))
    }

    /// Revoke a token, effective immediately. The owner or any human.
    pub fn revoke_token(&mut self, actor: &PrincipalId, token: &TokenId) -> CoreResult<Envelope> {
        let tx = self.conn.transaction()?;
        let acting = ensure_actor(&tx, actor)?;
        let current = raw::token(&tx, token.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("token {token}")))?;
        if current.principal != *actor && acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not revoke a token of {}: only the owner or a human",
                current.principal
            )));
        }
        if current.revoked {
            return Err(CoreError::Conflict(format!(
                "token {token} is already revoked"
            )));
        }
        let env = append(
            &tx,
            actor,
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
        authorize(&tx, actor, Capability::Admin, repo)?;
        raw::principal(&tx, grantee.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("principal {grantee}")))?;
        if let Some(repo) = repo {
            raw::repo(&tx, repo)?.ok_or_else(|| CoreError::NotFound(format!("repo {repo}")))?;
        }
        require(!actions.is_empty(), || {
            "a grant must carry at least one capability".into()
        })?;
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
        ensure_actor(&tx, id)?;
        let grant = GrantId::generate();
        let env = append(
            &tx,
            id,
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
        let acting = ensure_actor(&tx, actor)?;
        require(!reason.trim().is_empty(), || {
            "revocation reason must not be empty".into()
        })?;
        let current = raw::grant(&tx, grant.as_str())?
            .ok_or_else(|| CoreError::NotFound(format!("grant {grant}")))?;
        if current.grantor != *actor && acting.kind != PrincipalKind::Human {
            return Err(CoreError::Forbidden(format!(
                "{actor} may not revoke a grant issued by {}",
                current.grantor
            )));
        }
        if current.revoked {
            return Err(CoreError::Conflict(format!(
                "grant {grant} is already revoked"
            )));
        }
        let env = append(
            &tx,
            actor,
            Event::GrantRevoked {
                grant: grant.clone(),
                reason: reason.to_owned(),
            },
        )?;
        tx.commit()?;
        Ok(env)
    }
}
