use cairn_core::{Envelope, PrincipalId, Store};
use cairn_git::GitStore;
use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

/// How long a hook's ephemeral token stays valid: comfortably longer
/// than any receive-pack, far shorter than mattering if leaked.
const PUSH_TOKEN_TTL: Duration = Duration::from_secs(600);

/// How long a browser stays signed in without signing in again.
const SESSION_TTL_DAYS: i64 = 14;

/// API writes one principal may make in a minute before being told to
/// wait. Ten a second sustained is far past any agent doing work and
/// well short of what a loop stuck on a refusal produces.
pub const DEFAULT_WRITES_PER_MINUTE: u32 = 600;
/// Reads one principal may make per minute. Generous: a person browsing
/// and an agent reading the graph both do a lot of it, and the point is
/// to stop a runaway loop rather than to shape traffic.
pub const DEFAULT_READS_PER_MINUTE: u32 = 1200;
/// And what one address may, with no account behind it. Lower, because
/// a stranger's reads are the ones nobody can be asked about after.
pub const DEFAULT_ANONYMOUS_READS_PER_MINUTE: u32 = 240;

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
/// Who a hook acts as, under what scope, and since when.
/// A receive-pack in flight, as the hook it spawned will present it:
/// who is pushing, under what scope, into which repository — and how
/// much the hook said the push carries, once it had measured the
/// quarantine, so that the next push's room check counts this one.
pub(crate) struct PushToken {
    principal: PrincipalId,
    scope: Option<cairn_core::Scope>,
    repo: String,
    owner: PrincipalId,
    reserved: u64,
    issued: Instant,
}

/// The identity a push token resolves to.
pub(crate) struct PushIdentity {
    pub principal: PrincipalId,
    pub scope: Option<cairn_core::Scope>,
    pub repo: String,
}

/// How many git transfers the forge serves at once, and how many one
/// caller may hold of them. A transfer is a process and a pipe; a
/// caller opening hundreds is not cloning.
const GIT_TRANSFERS_AT_ONCE: usize = 64;
const GIT_TRANSFERS_PER_CALLER: u32 = 6;

/// A place among the transfers being served, given back when dropped.
pub(crate) struct GitSlot {
    _permit: tokio::sync::OwnedSemaphorePermit,
    callers: Arc<Mutex<HashMap<String, u32>>>,
    caller: String,
}

impl Drop for GitSlot {
    fn drop(&mut self) {
        let mut callers = self
            .callers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(held) = callers.get_mut(&self.caller) {
            *held -= 1;
            if *held == 0 {
                callers.remove(&self.caller);
            }
        }
    }
}

#[derive(Clone)]
pub struct AppState {
    store: Arc<Mutex<Store>>,
    events: broadcast::Sender<Envelope>,
    git: Option<Arc<GitContext>>,
    dev_identity: bool,
    /// Whether the landing train spends attention budgets on its tick.
    /// Off only in tests that drive the draw by hand.
    automatic_draws: bool,
    /// Set when the forge is reached over HTTPS, so session cookies
    /// can be marked Secure.
    secure_cookies: bool,
    proxy_trust: crate::guard::ProxyTrust,
    pub(crate) login_limiter: crate::guard::LoginLimiter,
    /// A public form anyone can post to needs its own allowance, kept
    /// apart from sign-in so neither can exhaust the other.
    pub(crate) waitlist_limiter: crate::guard::LoginLimiter,
    pub(crate) report_limiter: crate::guard::LoginLimiter,
    /// Asking for a password reset is a public form too.
    pub(crate) reset_limiter: crate::guard::LoginLimiter,
    /// API writes, per principal: a runaway loop is told to wait.
    pub(crate) write_limiter: crate::guard::Limiter<PrincipalId>,
    /// Reads, per principal, and per source address for a stranger:
    /// two allowances, so neither can exhaust the other.
    pub(crate) read_limiter: crate::guard::Limiter<PrincipalId>,
    pub(crate) anonymous_read_limiter: crate::guard::LoginLimiter,
    /// A credential that was offered and did not resolve spends this on
    /// top of its address's allowance, so a loop on a dead token is
    /// told to stop sooner.
    pub(crate) bad_credential_limiter: crate::guard::Limiter<String>,
    /// The health check's own allowance, per address: a monitor never
    /// runs out, and a loop on it does not reach the store lock for free.
    pub(crate) health_limiter: crate::guard::LoginLimiter,
    /// Event streams open right now, per principal, so one token cannot
    /// hold a thousand replays of the whole log at once.
    pub(crate) streams_open: Arc<Mutex<HashMap<PrincipalId, u32>>>,
    /// Writes under an idempotency key that have not answered yet, so a
    /// second copy arriving meanwhile is refused rather than done twice.
    writes_in_flight: Arc<Mutex<HashSet<(PrincipalId, String)>>>,
    /// How the forge sends mail, if it can. None means it cannot, and
    /// the pages that would need to say so.
    mailer: Option<Arc<crate::mail::Mailer>>,
    /// The WebAuthn relying party, when the forge knows its public URL.
    webauthn: Option<Arc<webauthn_rs::prelude::Webauthn>>,
    /// Where people reach this forge, for every link it writes down.
    public_url: Option<String>,
    /// Sign-in with an OpenID provider, and which workload issuers to
    /// believe, when configured.
    oidc: Option<Arc<crate::oidc::Trust>>,
    /// Verification-debt maps, one per repository, kept while the tip stands.
    debt_cache: Arc<crate::debt::Cache>,
    /// Signs merge receipts, when the forge has a key.
    signer: Option<Arc<crate::receipts::Signer>>,
    /// Ephemeral secrets handed to proc-receive hooks, mapped to the
    /// authenticated pusher. In-memory only, expiring, never logged.
    push_tokens: Arc<Mutex<HashMap<String, PushToken>>>,
    git_slots: Arc<tokio::sync::Semaphore>,
    git_callers: Arc<Mutex<HashMap<String, u32>>>,
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
            automatic_draws: true,
            oidc: None,
            debt_cache: Arc::new(crate::debt::Cache::default()),
            signer: None,
            secure_cookies: false,
            proxy_trust: crate::guard::ProxyTrust::Connection,
            login_limiter: crate::guard::LoginLimiter::default(),
            waitlist_limiter: crate::guard::LoginLimiter::new(5, Duration::from_secs(300)),
            report_limiter: crate::guard::LoginLimiter::new(5, Duration::from_secs(300)),
            reset_limiter: crate::guard::LoginLimiter::new(5, Duration::from_secs(300)),
            write_limiter: crate::guard::Limiter::new(
                DEFAULT_WRITES_PER_MINUTE,
                Duration::from_secs(60),
            ),
            read_limiter: crate::guard::Limiter::new(
                DEFAULT_READS_PER_MINUTE,
                Duration::from_secs(60),
            ),
            anonymous_read_limiter: crate::guard::Limiter::new(
                DEFAULT_ANONYMOUS_READS_PER_MINUTE,
                Duration::from_secs(60),
            ),
            health_limiter: crate::guard::LoginLimiter::new(120, Duration::from_secs(60)),
            bad_credential_limiter: crate::guard::Limiter::new(30, Duration::from_secs(60)),
            streams_open: Arc::new(Mutex::new(HashMap::new())),
            writes_in_flight: Arc::new(Mutex::new(HashSet::new())),
            mailer: None,
            webauthn: None,
            public_url: None,
            push_tokens: Arc::new(Mutex::new(HashMap::new())),
            git_slots: Arc::new(tokio::sync::Semaphore::new(GIT_TRANSFERS_AT_ONCE)),
            git_callers: Arc::new(Mutex::new(HashMap::new())),
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
    pub(crate) fn start_session(
        &self,
        principal: &PrincipalId,
        agent: Option<&str>,
    ) -> cairn_core::CoreResult<String> {
        self.with_store(|store| store.start_session(principal, SESSION_TTL_DAYS, agent))
    }

    pub(crate) fn resolve_session(&self, secret: &str) -> Option<PrincipalId> {
        self.with_store(|store| {
            let who = store.session_holder(secret);
            if who.is_some() {
                let _ = store.touch_session(secret);
            }
            who
        })
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
    pub fn without_automatic_draws(mut self) -> Self {
        self.automatic_draws = false;
        self
    }

    pub fn draws_automatically(&self) -> bool {
        self.automatic_draws
    }

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
    /// Believe the address a proxy recorded, `hops` proxies deep.
    pub fn trusting_proxy(mut self, hops: u8) -> Self {
        self.proxy_trust = crate::guard::ProxyTrust::ForwardedHeader { hops };
        self
    }

    /// Hold a place among the event streams `who` has open. `None`
    /// means they have enough already.
    pub(crate) fn open_stream(&self, who: &PrincipalId) -> Option<StreamPlace> {
        const AT_ONCE: u32 = 4;
        let mut open = self.streams_open.lock().unwrap_or_else(|e| e.into_inner());
        let count = open.entry(who.clone()).or_insert(0);
        if *count >= AT_ONCE {
            return None;
        }
        *count += 1;
        Some(StreamPlace {
            streams: self.streams_open.clone(),
            who: who.clone(),
        })
    }

    pub(crate) fn proxy_trust(&self) -> crate::guard::ProxyTrust {
        self.proxy_trust
    }

    /// How many reads a principal may make per minute, and how many an
    /// address with no account behind it may; 0 for no allowance.
    pub fn with_read_allowance(mut self, per_minute: u32, anonymous: u32) -> Self {
        self.read_limiter = if per_minute == 0 {
            crate::guard::Limiter::unlimited()
        } else {
            crate::guard::Limiter::new(per_minute, Duration::from_secs(60))
        };
        self.anonymous_read_limiter = if anonymous == 0 {
            crate::guard::LoginLimiter::unlimited()
        } else {
            crate::guard::LoginLimiter::new(anonymous, Duration::from_secs(60))
        };
        self
    }

    /// How many API writes a principal may make per minute; 0 means
    /// there is no allowance to run out of.
    pub fn with_write_allowance(mut self, per_minute: u32) -> Self {
        self.write_limiter = if per_minute == 0 {
            crate::guard::Limiter::unlimited()
        } else {
            crate::guard::Limiter::new(per_minute, Duration::from_secs(60))
        };
        self
    }

    /// Claim an idempotency key for the write about to run. False means
    /// the first request under it is still being answered.
    pub(crate) fn begin_write(&self, principal: &PrincipalId, key: &str) -> bool {
        self.writes_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert((principal.clone(), key.to_owned()))
    }

    pub(crate) fn finish_write(&self, principal: &PrincipalId, key: &str) {
        self.writes_in_flight
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(&(principal.clone(), key.to_owned()));
    }

    /// Issue an ephemeral token for the hooks of one receive-pack,
    /// spawned on behalf of an already-authenticated pusher into one
    /// repository. It lives until the receive-pack ends, or until a
    /// transfer could no longer be running.
    pub(crate) fn issue_push_token(
        &self,
        principal: &PrincipalId,
        scope: Option<&cairn_core::Scope>,
        repo: &str,
        owner: &PrincipalId,
    ) -> String {
        let secret = format!("cairnpush_{:032x}", rand::random::<u128>());
        let mut tokens = self
            .push_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokens.retain(|_, token| token.issued.elapsed() < PUSH_TOKEN_TTL);
        tokens.insert(
            secret.clone(),
            PushToken {
                principal: principal.clone(),
                scope: scope.cloned(),
                repo: repo.to_owned(),
                owner: owner.clone(),
                reserved: 0,
                issued: Instant::now(),
            },
        );
        secret
    }

    pub(crate) fn resolve_push_token(&self, secret: &str) -> Option<PushIdentity> {
        let tokens = self
            .push_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokens
            .get(secret)
            .filter(|token| token.issued.elapsed() < PUSH_TOKEN_TTL)
            .map(|token| PushIdentity {
                principal: token.principal.clone(),
                scope: token.scope.clone(),
                repo: token.repo.clone(),
            })
    }

    /// The push behind this token has been measured: this many bytes
    /// are arriving, and every room check until it ends counts them.
    pub(crate) fn reserve_for_push(&self, secret: &str, bytes: u64) {
        let mut tokens = self
            .push_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(token) = tokens.get_mut(secret) {
            token.reserved = bytes;
        }
    }

    /// What other pushes into this owner's repositories are bringing
    /// right now. Fifty pushes fired at once would otherwise each be
    /// checked against the same number from before any of them.
    pub(crate) fn arriving_elsewhere(&self, owner: &PrincipalId, except: &str) -> u64 {
        let tokens = self
            .push_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        tokens
            .iter()
            .filter(|(secret, token)| {
                secret.as_str() != except
                    && token.owner == *owner
                    && token.issued.elapsed() < PUSH_TOKEN_TTL
            })
            .map(|(_, token)| token.reserved)
            .fold(0u64, u64::saturating_add)
    }

    /// The receive-pack this token was issued for has ended, however it
    /// ended. The token stops working, and what it reserved is released:
    /// the measurement that follows the push counts what actually
    /// arrived.
    pub(crate) fn end_push(&self, secret: &str) {
        self.push_tokens
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .remove(secret);
    }

    /// A place among the git transfers being served, or none when the
    /// forge or this caller already holds as many as it may.
    pub(crate) fn git_slot(&self, caller: &str) -> Option<GitSlot> {
        let permit = self.git_slots.clone().try_acquire_owned().ok()?;
        let mut callers = self
            .git_callers
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let held = callers.entry(caller.to_owned()).or_insert(0);
        if *held >= GIT_TRANSFERS_PER_CALLER {
            return None;
        }
        *held += 1;
        drop(callers);
        Some(GitSlot {
            _permit: permit,
            callers: self.git_callers.clone(),
            caller: caller.to_owned(),
        })
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
    /// Tell the forge where it lives, which is what passkeys bind to.
    pub fn with_public_url(mut self, url: &str) -> Result<Self, String> {
        self.webauthn = Some(Arc::new(crate::passkeys::relying_party(url)?));
        self.public_url = Some(url.trim_end_matches('/').to_owned());
        Ok(self)
    }

    /// The configured public URL, without a trailing slash.
    pub(crate) fn public_url(&self) -> Option<&str> {
        self.public_url.as_deref()
    }

    pub(crate) fn webauthn(&self) -> Option<Arc<webauthn_rs::prelude::Webauthn>> {
        self.webauthn.clone()
    }

    pub fn with_oidc(mut self, trust: crate::oidc::Trust) -> Self {
        self.oidc = Some(Arc::new(trust));
        self
    }

    pub(crate) fn debt_cache(&self) -> &crate::debt::Cache {
        &self.debt_cache
    }

    /// Sign merge receipts with this key.
    pub fn with_signer(mut self, signer: crate::receipts::Signer) -> Self {
        self.signer = Some(Arc::new(signer));
        self
    }

    pub(crate) fn signer(&self) -> Option<Arc<crate::receipts::Signer>> {
        self.signer.clone()
    }

    pub(crate) fn oidc(&self) -> Option<Arc<crate::oidc::Trust>> {
        self.oidc.clone()
    }

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

    /// What people reported broke; operational, like the waitlist.
    pub fn reports(&self) -> cairn_core::CoreResult<Vec<cairn_core::Report>> {
        self.with_store(|store| store.reports())
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
        // Tags are the log projected onto git too: every recorded name
        // must be a ref at the recorded object, and no ref may exist
        // that the log never saw.
        if let Some(git) = self.git() {
            fn short(oid: &str) -> &str {
                oid.get(..9).unwrap_or(oid)
            }
            for repo in self.with_store(|store| store.repos())? {
                let recorded = self.with_store(|store| store.tags(&repo.name))?;
                let in_git = match git.store.list_tags(&repo.name).await {
                    Ok(tags) => tags,
                    Err(err) => {
                        divergences.push(format!("{}: tags could not be listed: {err}", repo.name));
                        continue;
                    }
                };
                for tag in &recorded {
                    let want = tag.object_oid.as_deref().unwrap_or(&tag.commit_oid);
                    match in_git.iter().find(|(name, _, _)| *name == tag.name) {
                        None => divergences.push(format!(
                            "{}: tag {} is on the record but refs/tags/{} is missing",
                            repo.name, tag.name, tag.name
                        )),
                        Some((_, object, commit))
                            if object != want || *commit != tag.commit_oid =>
                        {
                            divergences.push(format!(
                                "{}: refs/tags/{} points at {} but the log says {}",
                                repo.name,
                                tag.name,
                                short(object),
                                short(want)
                            ))
                        }
                        Some(_) => {}
                    }
                }
                for (name, object, _) in &in_git {
                    if !recorded.iter().any(|tag| tag.name == *name) {
                        divergences.push(format!(
                            "{}: refs/tags/{name} exists at {} but the log never recorded it",
                            repo.name,
                            short(object)
                        ));
                    }
                }
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
        let out = f(&mut store);
        store.clear_acting();
        out
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

/// One open event stream; giving it back is dropping it.
pub(crate) struct StreamPlace {
    streams: Arc<Mutex<HashMap<PrincipalId, u32>>>,
    who: PrincipalId,
}

impl Drop for StreamPlace {
    fn drop(&mut self) {
        let mut open = self.streams.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(count) = open.get_mut(&self.who) {
            *count = count.saturating_sub(1);
            if *count == 0 {
                open.remove(&self.who);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cairn_core::Store;

    fn state() -> AppState {
        AppState::new(Store::open_in_memory().unwrap())
    }

    /// A push token names one push into one repository, counts what
    /// that push brings for every other push into the same owner's
    /// repositories, and is gone when the push is.
    #[test]
    fn a_push_token_is_one_push_and_its_reservation_ends_with_it() {
        let app = state();
        let ada = PrincipalId::new("ada").unwrap();
        let bee = PrincipalId::new("bee").unwrap();
        let first = app.issue_push_token(&ada, None, "ada/demo", &ada);
        let second = app.issue_push_token(&ada, None, "ada/other", &ada);
        let elsewhere = app.issue_push_token(&bee, None, "bee/demo", &bee);
        let resolved = app.resolve_push_token(&first).expect("live");
        assert_eq!(resolved.repo, "ada/demo");
        assert_eq!(resolved.principal, ada);

        app.reserve_for_push(&first, 1000);
        app.reserve_for_push(&second, 20);
        app.reserve_for_push(&elsewhere, 500);
        // From the second push's point of view, the first is arriving;
        // its own reservation and bee's are not.
        assert_eq!(app.arriving_elsewhere(&ada, &second), 1000);
        assert_eq!(app.arriving_elsewhere(&ada, &first), 20);
        assert_eq!(app.arriving_elsewhere(&bee, &elsewhere), 0);

        app.end_push(&first);
        assert!(app.resolve_push_token(&first).is_none());
        assert_eq!(app.arriving_elsewhere(&ada, &second), 0);
        // A secret nobody issued resolves to nobody.
        assert!(app.resolve_push_token("cairnpush_nope").is_none());
    }

    /// One caller holds a few transfers, not all of them.
    #[test]
    fn transfers_are_shared_out_per_caller() {
        let app = state();
        let mut held = Vec::new();
        for _ in 0..GIT_TRANSFERS_PER_CALLER {
            held.push(app.git_slot("ada").expect("a place"));
        }
        assert!(app.git_slot("ada").is_none(), "the caller's share is spent");
        assert!(app.git_slot("bee").is_some(), "and nobody else's is");
        drop(held.pop());
        assert!(
            app.git_slot("ada").is_some(),
            "a place given back is a place"
        );
    }
}
