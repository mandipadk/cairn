//! The landing train: once a change is enqueued, landing it is the
//! forge's responsibility.
//!
//! A single processor works each (repo, target) lane FIFO. For every
//! lane head it re-checks that the change is still open and still
//! satisfies policy — enqueue-time readiness is not trusted at landing
//! time — then lands it: fast-forward when the target hasn't moved,
//! otherwise an in-memory rebase (`git merge-tree`). Anything that
//! cannot land is dequeued with a reason event naming exactly why:
//! a policy regression, a revoked capability, or the conflicting
//! files. Merges recorded by the queue carry `merged_as` when the
//! landed commit differs from the reviewed revision.
//!
//! Each branch is its own train and they run at the same time, since
//! two lanes never touch the same ref. Within a lane, order is strict:
//! that is what makes every landing explainable.
//!
//! There is deliberately no speculation inside a lane. Speculating —
//! rebasing several queued changes against a projected tip before the
//! ones ahead have landed — exists to avoid repeating attempts that
//! cost minutes, and here an attempt costs tens of milliseconds: a
//! three-way merge in memory plus a policy evaluation. It would buy
//! nothing and cost the property that every landing is a plain
//! consequence of the one before it. That trade changes the day a
//! policy requires the *rebased* result to be verified by a runner,
//! because then each attempt costs a test run; revisit it then.

use crate::state::AppState;
use cairn_core::{Event, QueueEntry};
use cairn_git::RebaseOutcome;
use std::time::Duration;
use tokio::sync::broadcast::error::RecvError;

const TICK: Duration = Duration::from_secs(5);

pub fn spawn_queue_processor(state: AppState) -> tokio::task::JoinHandle<()> {
    tokio::spawn(run(state))
}

async fn run(state: AppState) {
    let mut events = state.subscribe();
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // A forge that just started may be recovering from a crash between
    // recording a merge and moving the branch. Replay those decisions
    // before doing anything new.
    for stuck in reconcile_branches(&state).await {
        tracing::error!("{stuck}");
    }
    loop {
        retry_pending_advances(&state).await;
        process_lanes(&state).await;
        tokio::select! {
            _ = tick.tick() => {}
            received = events.recv() => match received {
                Ok(envelope) => {
                    if !wakes_the_train(&envelope.event) {
                        continue;
                    }
                }
                Err(RecvError::Lagged(_)) => {}
                Err(RecvError::Closed) => return,
            },
        }
    }
}

fn wakes_the_train(event: &Event) -> bool {
    matches!(
        event,
        Event::ChangeEnqueued { .. } | Event::ChangeMerged { .. } | Event::ChangeDequeued { .. }
    )
}

/// Work every lane head until a full pass makes no progress.
async fn process_lanes(state: &AppState) {
    loop {
        let heads = match state.with_store(|s| s.queue_heads()) {
            Ok(heads) => heads,
            Err(err) => {
                tracing::warn!(error = %err, "queue: reading lane heads failed");
                return;
            }
        };
        if heads.is_empty() {
            return;
        }
        // One head per lane, and lanes are disjoint by construction —
        // they advance different refs — so they run together. The git
        // work happens outside the store lock, which is where the time
        // actually goes.
        let mut lanes = tokio::task::JoinSet::new();
        for head in heads {
            let state = state.clone();
            lanes.spawn(async move {
                let outcome = land(&state, &head).await;
                (head, outcome)
            });
        }
        let mut progressed = false;
        while let Some(finished) = lanes.join_next().await {
            match finished {
                Ok((_, Ok(true))) => progressed = true,
                Ok((_, Ok(false))) => {}
                Ok((head, Err(err))) => {
                    // Transient (e.g. a git hiccup): the entry stays
                    // queued and is retried, rather than being lost.
                    tracing::warn!(error = %err, change = %head.change, "queue: landing attempt failed; will retry");
                }
                Err(err) => tracing::warn!(error = %err, "queue: a lane panicked"),
            }
        }
        if !progressed {
            return;
        }
    }
}

/// Try to land one lane head. Ok(true) when the lane moved (merged or
/// dequeued), Ok(false) when it should be left for a retry.
async fn land(
    state: &AppState,
    entry: &QueueEntry,
) -> Result<bool, Box<dyn std::error::Error + Send + Sync>> {
    let Some(git) = state.git() else {
        // No git hosting: nothing to advance; the queue is inert.
        return Ok(false);
    };

    let change = state.with_store(|s| s.change(&entry.change))?;
    let Some(change) = change else {
        dequeue(state, entry, "change no longer exists").await;
        return Ok(true);
    };
    if change.state != cairn_core::ChangeState::Open {
        dequeue(
            state,
            entry,
            &format!("change is {}", change.state.as_str()),
        )
        .await;
        return Ok(true);
    }
    // Enqueue-time readiness is not landing-time readiness.
    let trace = state.with_store(|s| s.merge_readiness(&entry.change))?;
    if !trace.satisfied {
        dequeue(
            state,
            entry,
            &format!("policy no longer satisfied: {}", trace.unmet_summary()),
        )
        .await;
        return Ok(true);
    }
    let revisions = state.with_store(|s| s.revisions(&entry.change))?;
    let Some(revision) = revisions.last() else {
        dequeue(state, entry, "change has no revisions").await;
        return Ok(true);
    };

    let tip = git.store.tip(&entry.repo, &entry.target).await?;
    let (landed, merged_as) = match &tip {
        None => (revision.commit_oid.clone(), None),
        Some(tip) => match git
            .store
            .rebase_onto(&entry.repo, tip, &revision.commit_oid)
            .await?
        {
            RebaseOutcome::FastForward => (revision.commit_oid.clone(), None),
            RebaseOutcome::Rebased(oid) => (oid.clone(), Some(oid)),
            RebaseOutcome::Conflicts(files) => {
                dequeue(
                    state,
                    entry,
                    &format!(
                        "rebase onto {} conflicts in: {}; rebase manually and push a new revision",
                        entry.target,
                        files.join(", ")
                    ),
                )
                .await;
                return Ok(true);
            }
        },
    };

    // The merge is recorded on the enqueuer's authority; if that
    // authority is gone (revoked grant), the refusal becomes the
    // dequeue reason.
    let merged = state
        .with_store(|s| s.merge_change_as(&entry.enqueued_by, &entry.change, merged_as.as_deref()));
    let envelope = match merged {
        Ok(envelope) => envelope,
        Err(err) => {
            dequeue(state, entry, &format!("landing refused: {err}")).await;
            return Ok(true);
        }
    };
    state.publish(&envelope);

    // Children of a landed change are now stale by definition. Carry
    // them forward so a stack does not rot while it waits.
    if let Err(err) = git
        .store
        .advance_ref(&entry.repo, &entry.target, &landed, tip.as_deref())
        .await
    {
        // The graph recorded the merge but the ref did not move. The
        // decision is already durable and names the exact commit meant
        // to land, so recovery replays it rather than recomputing it —
        // remember the branch and retry on the next tick.
        tracing::error!(error = %err, change = %entry.change, "queue: merge recorded but ref advance failed; will retry");
        state.note_ref_needs_advancing(&entry.repo, &entry.target);
        return Ok(true);
    }
    carry_children(state, entry, &landed).await;
    mirror_branch(state, &entry.repo, &entry.target, &landed).await;
    Ok(true)
}

/// Copy a landed branch outward, if the repository mirrors. The
/// attempt is recorded either way: a mirror that has been quietly
/// failing is exactly the thing nobody notices until they need it.
async fn mirror_branch(state: &AppState, repo: &str, branch: &str, landed: &str) {
    let Some(git) = state.git() else { return };
    let Ok(Some(record)) = state.with_store(|s| s.repo(repo)) else {
        return;
    };
    let Some(mirror) = record.mirror.filter(|m| m.enabled) else {
        return;
    };
    let outcome = git
        .store
        .push_to_mirror(repo, &mirror.url, branch, git.mirror_credential.as_deref())
        .await;
    let (ok, detail) = match &outcome {
        Ok(()) => (true, None),
        Err(err) => {
            tracing::warn!(error = %err, repo, branch, "mirror push failed");
            (false, Some(err.to_string()))
        }
    };
    // Recorded as the forge itself: nobody's grant authorised this,
    // the repository's configuration did.
    match state.with_store(|s| {
        s.record_mirror_push(
            &record_actor(s),
            repo,
            branch,
            landed,
            ok,
            detail.as_deref(),
        )
    }) {
        Ok(envelope) => state.publish(&envelope),
        Err(err) => tracing::warn!(error = %err, "queue: recording the mirror push failed"),
    }
}

/// Mirror pushes are the forge's own act, so they are attributed to
/// whoever configured the repository — the first admin-capable human,
/// falling back to the queue entry's enqueuer.
fn record_actor(store: &cairn_core::Store) -> cairn_core::PrincipalId {
    store
        .events_after(cairn_core::EventSeq(0), 1)
        .ok()
        .and_then(|events| events.first().map(|e| e.actor.clone()))
        .unwrap_or_else(|| cairn_core::PrincipalId("cairn".to_owned()))
}

/// Rebase every open child of a just-landed change onto the new tip.
/// Success adds a revision, exactly as a push would; failure records
/// what collided and leaves the change for a person. The author's own
/// revisions are never rewritten.
async fn carry_children(state: &AppState, entry: &QueueEntry, tip: &str) {
    let Some(git) = state.git() else { return };
    let children = match state.with_store(|s| s.open_children(&entry.change)) {
        Ok(children) => children,
        Err(err) => {
            tracing::warn!(error = %err, "queue: reading stacked children failed");
            return;
        }
    };
    for child in children {
        let Ok(revisions) = state.with_store(|s| s.revisions(&child.id)) else {
            continue;
        };
        let Some(revision) = revisions.last() else {
            continue;
        };
        match git
            .store
            .rebase_onto(&entry.repo, tip, &revision.commit_oid)
            .await
        {
            // Already on top of the new tip: nothing to carry.
            Ok(RebaseOutcome::FastForward) => {}
            Ok(RebaseOutcome::Rebased(oid)) => {
                // Recorded on the child's owner's authority: it is
                // still their change, moved to new ground.
                match state
                    .with_store(|s| s.record_rebase(&child.owner, &child.id, &oid, &entry.target))
                {
                    Ok((_, envelope)) => {
                        state.publish(&envelope);
                        // A revision the forge created needs its ref
                        // just as much as one that was pushed.
                        crate::git_http::reconcile_change_refs(state, &entry.repo).await;
                    }
                    Err(err) => {
                        tracing::warn!(error = %err, change = %child.id, "queue: recording a carried rebase failed")
                    }
                }
            }
            Ok(RebaseOutcome::Conflicts(files)) => {
                match state.with_store(|s| {
                    s.record_rebase_failure(&entry.enqueued_by, &child.id, &entry.target, files)
                }) {
                    Ok(envelope) => state.publish(&envelope),
                    Err(err) => {
                        tracing::warn!(error = %err, change = %child.id, "queue: recording a rebase conflict failed")
                    }
                }
            }
            Err(err) => {
                tracing::warn!(error = %err, change = %child.id, "queue: carrying a child failed")
            }
        }
    }
}

async fn dequeue(state: &AppState, entry: &QueueEntry, reason: &str) {
    match state.with_store(|s| s.dequeue_change(&entry.enqueued_by, &entry.change, reason)) {
        Ok(envelope) => state.publish(&envelope),
        Err(err) => {
            tracing::warn!(error = %err, change = %entry.change, "queue: recording dequeue failed")
        }
    }
}

/// Make a branch carry what the log already decided should be on it.
///
/// Recording a merge and moving a branch are two writes to two different
/// stores, so a crash or a second forge process can land between them.
/// The standard shape for that is to make the durable record the
/// intent and the external step an idempotent retry — which works here
/// because the merge event names the exact commit meant to land. Nothing
/// is recomputed: a rebase run a second time would produce a *different*
/// commit and land the work twice.
///
/// Three cases, and only one of them acts:
///
/// - the branch already contains the commit — nothing to do, which is
///   what makes this safe to run repeatedly;
/// - the branch is behind it, so advancing is a fast-forward that
///   discards nothing — do it, compare-and-swap against the tip just
///   read so a concurrent mover still wins;
/// - the branch is somewhere else entirely — something landed in
///   between, and choosing what survives is not a decision to make
///   automatically. Reported, never guessed at.
///
/// No event is appended for a repair. Nothing new was decided; the merge
/// event already explains the branch, and the log records decisions
/// rather than the mechanics of carrying them out.
async fn advance_to_recorded(
    state: &AppState,
    repo: &str,
    target: &str,
    landed: &str,
    change: i64,
) -> Option<String> {
    let git = state.git()?;
    let branch = format!("refs/heads/{target}");
    match git.store.is_ancestor(repo, landed, &branch).await {
        Ok(true) => return None,
        Ok(false) => {}
        Err(err) => {
            return Some(format!(
                "{repo}: change {change} could not be checked against {target}: {err}"
            ));
        }
    }
    let tip = match git.store.tip(repo, target).await {
        Ok(tip) => tip,
        Err(err) => {
            return Some(format!("{repo}: reading {target} failed: {err}"));
        }
    };
    let safe = match &tip {
        None => true,
        Some(tip) => git
            .store
            .is_ancestor(repo, tip, landed)
            .await
            .unwrap_or(false),
    };
    if !safe {
        return Some(format!(
            "{repo}: change {change} is merged as {landed} but {target} moved elsewhere;              this needs a person"
        ));
    }
    match git
        .store
        .advance_ref(repo, target, landed, tip.as_deref())
        .await
    {
        Ok(()) => {
            tracing::warn!(
                repo,
                target,
                change,
                landed,
                "queue: branch was behind a recorded merge; advanced it"
            );
            None
        }
        Err(err) => Some(format!(
            "{repo}: change {change} could not be advanced onto {target}: {err}"
        )),
    }
}

/// Retry branches whose advance failed while this process was running.
/// Cheap: it looks only at what actually failed, not at every merge.
async fn retry_pending_advances(state: &AppState) {
    for (repo, target) in state.take_refs_needing_advancing() {
        let Ok(pending) = state.merges_missing_from_branch(&repo, &target).await else {
            continue;
        };
        for (change, landed) in pending {
            if let Some(stuck) = advance_to_recorded(state, &repo, &target, &landed, change).await {
                tracing::error!("{stuck}");
                state.note_ref_needs_advancing(&repo, &target);
            }
        }
    }
}

/// A full pass over every landed change, for recovering at startup.
/// Returns what could not be repaired without a person.
pub async fn reconcile_branches(state: &AppState) -> Vec<String> {
    let Ok(missing) = state.all_merges_missing_from_branches().await else {
        return vec!["reconcile: reading the graph failed".to_owned()];
    };
    let mut stuck = Vec::new();
    for (repo, target, change, landed) in missing {
        if let Some(problem) = advance_to_recorded(state, &repo, &target, &landed, change).await {
            stuck.push(problem);
        }
    }
    stuck
}
