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
//! Sequential by design: one train, no speculation — v1 favors an
//! outcome you can always explain over throughput tricks.

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
    loop {
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
        let mut progressed = false;
        for head in heads {
            match land(state, &head).await {
                Ok(true) => progressed = true,
                Ok(false) => {}
                Err(err) => {
                    // Transient (e.g. git hiccup): stay queued, retry on
                    // the next tick rather than losing the entry.
                    tracing::warn!(error = %err, change = %head.change, "queue: landing attempt failed; will retry");
                }
            }
        }
        if !progressed {
            return;
        }
    }
}

/// Try to land one lane head. Ok(true) when the lane moved (merged or
/// dequeued), Ok(false) when it should be left for a retry.
async fn land(state: &AppState, entry: &QueueEntry) -> Result<bool, Box<dyn std::error::Error>> {
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
        // The graph recorded the merge but the ref did not move; loud,
        // and safe to retry by hand. Same wrinkle as direct merges.
        tracing::error!(error = %err, change = %entry.change, "queue: merge recorded but ref advance failed");
        return Ok(true);
    }
    carry_children(state, entry, &landed).await;
    Ok(true)
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
