use cairn_core::{Envelope, PrincipalId, Store};
use cairn_git::GitStore;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// How long a hook's ephemeral token stays valid: comfortably longer
/// than any receive-pack, far shorter than mattering if leaked.
const PUSH_TOKEN_TTL: Duration = Duration::from_secs(600);

/// How long a browser stays signed in without signing in again.
const SESSION_TTL_DAYS: i64 = 14;

/// One change the log says landed, and where.
struct Landed {
    repo: String,
    target: String,
    number: i64,
    oid: Option<String>,
}

/// Git hosting context: the repo store plus the base URL the
/// proc-receive hook uses to call back into this server.
pub(crate) struct GitContext {
    pub(crate) store: Arc<GitStore>,
    pub(crate) base_url: String,
    /// The secret that authorises mirror pushes, supplied by whoever
    /// runs the forge. It is never written to the graph and never
    /// returned by any endpoint.
    pub(crate) mirror_credential: Option<String>,
}

/// Shared server state: the store behind a mutex, and a broadcast bus
/// carrying every committed event to live subscribers.
///
/// The mutex is deliberate, not a placeholder: the core is a single
/// writer over SQLite, commands are short synchronous transactions, and
/// no handler holds the lock across an await. If fleet-scale contention
/// ever bites, the event-sourced design ports to a pooled backend
/// without touching the API layer.
#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<Store>>,
    events: broadcast::Sender<Envelope>,
    git: Option<Arc<GitContext>>,
    dev_identity: bool,
    /// Set when the forge is reached over HTTPS, so session cookies
    /// can be marked Secure.
    secure_cookies: bool,
    proxy_trust: crate::guard::ProxyTrust,
    pub(crate) login_limiter: crate::guard::LoginLimiter,
    /// A public form anyone can post to needs its own allowance, kept
    /// apart from sign-in so neither can exhaust the other.
    pub(crate) waitlist_limiter: crate::guard::LoginLimiter,
    /// Asking for a password reset is a public form too.
    pub(crate) reset_limiter: crate::guard::LoginLimiter,
    /// How the forge sends mail, if it can. None means it cannot, and
    /// the pages that would need to say so.
    mailer: Option<Arc<crate::mail::Mailer>>,
    /// Ephemeral secrets handed to proc-receive hooks, mapped to the
    /// authenticated pusher. In-memory only, expiring, never logged.
    push_tokens: Arc<Mutex<HashMap<String, (PrincipalId, Instant)>>>,
    /// Branches whose advance failed after the merge was recorded, so
    /// the next tick can replay the decision the log already holds.
    refs_needing_advancing: Arc<Mutex<Vec<(String, String)>>>,
}

impl AppState {
    pub fn new(store: Store) -> Self {
        let (events, _) = broadcast::channel(1024);
        AppState {
            store: Arc::new(Mutex::new(store)),
            events,
            git: None,
            dev_identity: false,
            secure_cookies: false,
            proxy_trust: crate::guard::ProxyTrust::Connection,
            login_limiter: crate::guard::LoginLimiter::default(),
            waitlist_limiter: crate::guard::LoginLimiter::new(5, Duration::from_secs(300)),
            reset_limiter: crate::guard::LoginLimiter::new(5, Duration::from_secs(300)),
            mailer: None,
            push_tokens: Arc::new(Mutex::new(HashMap::new())),
            refs_needing_advancing: Arc::new(Mutex::new(Vec::new())),
        }
    }

    /// Remember a branch that did not move after its merge was recorded.
    pub(crate) fn note_ref_needs_advancing(&self, repo: &str, target: &str) {
        let mut pending = self
            .refs_needing_advancing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let entry = (repo.to_owned(), target.to_owned());
        if !pending.contains(&entry) {
            pending.push(entry);
        }
    }

    pub(crate) fn take_refs_needing_advancing(&self) -> Vec<(String, String)> {
        let mut pending = self
            .refs_needing_advancing
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        std::mem::take(&mut *pending)
    }

    /// Begin a browser session for someone who has just proved who they
    /// are. It is stored, so a deploy does not sign everyone out, and
    /// only its hash is kept, so reading the database yields no working
    /// credential.
    pub(crate) fn start_session(&self, principal: &PrincipalId) -> cairn_core::CoreResult<String> {
        self.with_store(|store| store.start_session(principal, SESSION_TTL_DAYS))
    }

    pub(crate) fn resolve_session(&self, secret: &str) -> Option<PrincipalId> {
        self.with_store(|store| store.session_holder(secret))
    }

    pub(crate) fn end_session(&self, secret: &str) {
        let _ = self.with_store(|store| store.end_browser_session(secret));
    }

    /// Drop every session belonging to a principal. Used when their
    /// password changes: a password change that leaves old sessions
    /// alive has not actually locked anyone out.
    pub fn end_sessions_of(&self, principal: &PrincipalId) {
        let _ = self.with_store(|store| store.end_browser_sessions_of(principal));
    }

    /// Accept asserted identity via the dev header. For local
    /// development and in-process tests only; never the default.
    pub fn with_dev_identity(mut self) -> Self {
        self.dev_identity = true;
        self
    }

    pub(crate) fn dev_identity(&self) -> bool {
        self.dev_identity
    }

    /// Mark session cookies Secure. Set this whenever the forge is
    /// reachable over HTTPS; leaving it off on a public deployment
    /// means cookies can travel in the clear.
    pub fn with_secure_cookies(mut self) -> Self {
        self.secure_cookies = true;
        self
    }

    pub(crate) fn secure_cookies(&self) -> bool {
        self.secure_cookies
    }

    /// Believe the forwarded address recorded by whatever sits in
    /// front. Only set this when something trustworthy does, since an
    /// unfiltered header lets any caller claim any address.
    pub fn trusting_proxy(mut self) -> Self {
        self.proxy_trust = crate::guard::ProxyTrust::ForwardedHeader;
        self
    }

    pub(crate) fn proxy_trust(&self) -> crate::guard::ProxyTrust {
        self.proxy_trust
    }

    /// Issue an ephemeral token for a hook spawned on behalf of an
    /// already-authenticated pusher.
    pub(crate) fn issue_push_token(&self, principal: &PrincipalId) -> String {
        let secret = format!("cairnpush_{:032x}", rand::random::<u128>());
        let mut tokens = self
            .push_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokens.retain(|_, (_, issued)| issued.elapsed() < PUSH_TOKEN_TTL);
        tokens.insert(secret.clone(), (principal.clone(), Instant::now()));
        secret
    }

    pub(crate) fn resolve_push_token(&self, secret: &str) -> Option<PrincipalId> {
        let tokens = self
            .push_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokens
            .get(secret)
            .filter(|(_, issued)| issued.elapsed() < PUSH_TOKEN_TTL)
            .map(|(principal, _)| principal.clone())
    }

    /// Enable git hosting. `base_url` must be reachable from spawned
    /// receive-pack processes (i.e. this server's own address).
    pub fn with_git(mut self, git: GitStore, base_url: impl Into<String>) -> Self {
        self.git = Some(Arc::new(GitContext {
            store: Arc::new(git),
            base_url: base_url.into(),
            mirror_credential: None,
        }));
        self
    }

    /// Supply the credential mirror pushes authenticate with.
    pub fn with_mailer(mut self, mailer: crate::mail::Mailer) -> Self {
        self.mailer = Some(Arc::new(mailer));
        self
    }

    pub(crate) fn mailer(&self) -> Option<Arc<crate::mail::Mailer>> {
        self.mailer.clone()
    }

    pub fn with_mirror_credential(mut self, credential: impl Into<String>) -> Self {
        if let Some(git) = self.git.take() {
            self.git = Some(Arc::new(GitContext {
                store: Arc::clone(&git.store),
                base_url: git.base_url.clone(),
                mirror_credential: Some(credential.into()),
            }));
        }
        self
    }

    pub(crate) fn git(&self) -> Option<&GitContext> {
        self.git.as_deref()
    }

    /// Check that live state is still exactly the log applied. Public
    /// because this is a question an operator asks of a *running* forge,
    /// not only of a database file at rest.
    pub fn fsck(&self) -> cairn_core::CoreResult<Vec<String>> {
        self.with_store(|store| store.fsck())
    }

    /// The waitlist, and removing someone from it. Exposed on the state
    /// because it is operational data an operator asks a running forge
    /// about, not part of the graph.
    pub fn waitlist(&self) -> cairn_core::CoreResult<Vec<(String, String, Option<String>)>> {
        self.with_store(|store| store.waitlist())
    }

    pub fn leave_waitlist(&self, email: &str) -> cairn_core::CoreResult<bool> {
        self.with_store(|store| store.leave_waitlist(email))
    }

    /// Every change the log says landed must actually be on the branch
    /// it landed on.
    ///
    /// Recording the merge and moving the ref are two writes to two
    /// different stores. The queue repairs what it safely can, but a
    /// branch that moved somewhere else in between needs a person — and
    /// nothing else would ever notice, because every other query answers
    /// from the graph. This is how someone finds out.
    pub async fn branches_match_the_log(&self) -> cairn_core::CoreResult<Vec<String>> {
        let mut divergences: Vec<String> = self
            .all_merges_missing_from_branches()
            .await?
            .into_iter()
            .map(|(repo, target, number, oid)| {
                format!(
                    "{repo}: change {number} is merged as {oid} but {target} does not contain it"
                )
            })
            .collect();
        // A merged change with no landed commit is its own kind of wrong.
        for change in self.landed_changes()? {
            if change.oid.is_none() {
                divergences.push(format!(
                    "{}: change {} is merged but records no landed commit",
                    change.repo, change.number
                ));
            }
        }
        Ok(divergences)
    }

    /// Everything the log says landed.
    fn landed_changes(&self) -> cairn_core::CoreResult<Vec<Landed>> {
        self.with_store(|store| {
            let mut landed = Vec::new();
            for repo in store.repos()? {
                for change in store.changes_in_repo(&repo.name)? {
                    if change.state == cairn_core::ChangeState::Merged {
                        landed.push(Landed {
                            repo: repo.name.clone(),
                            target: change.target.clone(),
                            number: change.number,
                            oid: change.landed_oid.clone(),
                        });
                    }
                }
            }
            Ok(landed)
        })
    }

    /// Landed changes on one branch that the branch does not contain.
    pub(crate) async fn merges_missing_from_branch(
        &self,
        repo: &str,
        target: &str,
    ) -> cairn_core::CoreResult<Vec<(i64, String)>> {
        let Some(git) = self.git() else {
            return Ok(Vec::new());
        };
        let branch = format!("refs/heads/{target}");
        let mut missing = Vec::new();
        for change in self.landed_changes()? {
            if change.repo != repo || change.target != target {
                continue;
            }
            let Some(oid) = change.oid else { continue };
            if !git
                .store
                .is_ancestor(repo, &oid, &branch)
                .await
                .unwrap_or(true)
            {
                missing.push((change.number, oid));
            }
        }
        Ok(missing)
    }

    /// The same across every repository, for recovery at startup.
    pub(crate) async fn all_merges_missing_from_branches(
        &self,
    ) -> cairn_core::CoreResult<Vec<(String, String, i64, String)>> {
        let Some(git) = self.git() else {
            return Ok(Vec::new());
        };
        let mut missing = Vec::new();
        for change in self.landed_changes()? {
            let Some(oid) = change.oid else { continue };
            let branch = format!("refs/heads/{}", change.target);
            if !git
                .store
                .is_ancestor(&change.repo, &oid, &branch)
                .await
                .unwrap_or(true)
            {
                missing.push((change.repo, change.target, change.number, oid));
            }
        }
        Ok(missing)
    }

    /// Run a closure against the store. Sync on purpose: the closure must
    /// not (and cannot) await while holding the lock.
    pub(crate) fn with_store<T>(&self, f: impl FnOnce(&mut Store) -> T) -> T {
        // A panic in one request poisons the lock. The store itself is
        // fine — every command is a transaction that either committed
        // or rolled back — so recovering beats refusing every request
        // that follows.
        let mut store = match self.store.lock() {
            Ok(store) => store,
            Err(poisoned) => {
                tracing::error!("store lock was poisoned by an earlier panic; continuing");
                poisoned.into_inner()
            }
        };
        f(&mut store)
    }

    /// Publish a committed event to live subscribers. Publishing is
    /// best-effort by design — the store is the source of truth, and the
    /// SSE stream heals gaps and lag by re-reading from it.
    pub(crate) fn publish(&self, envelope: &Envelope) {
        let _ = self.events.send(envelope.clone());
    }

    pub(crate) fn subscribe(&self) -> broadcast::Receiver<Envelope> {
        self.events.subscribe()
    }
}
