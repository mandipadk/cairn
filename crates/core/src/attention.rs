//! Attention routing: which open changes are worth a human's time,
//! and why.
//!
//! At agent velocity the scarce resource is human judgment, so
//! deciding what to look at deserves the same treatment as deciding
//! what may land: an explainable evaluation over the graph rather than
//! a feed sorted by recency. Every ranked change carries the signals
//! that ranked it, each with its own evidence, so a person can
//! disagree with the ranking on the facts.
//!
//! One signal is different in kind from the rest. [`SignalKind::SpotCheck`]
//! samples changes that no human ever looked at, deterministically by
//! change id, so a fixed share of agent-only work reaches a person
//! whether or not anything about it looks wrong. That makes human
//! attention a governed, auditable quantity: the sampling rate is a
//! policy, and the log records every change the policy drew.

use crate::error::CoreResult;
use crate::queries::raw;
use crate::types::{Change, ChangeState, ClaimKind, Disposition, PrincipalKind};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// One in this many agent-only changes is drawn for a human look.
const SPOT_CHECK_IN: u64 = 10;

macro_rules! signal_kinds {
    ($($(#[$doc:meta])* $variant:ident => $s:literal, $weight:literal);+ $(;)?) => {
        /// Why a change wants attention. Ordered by how much a human's
        /// time is worth on it, not by how recently it changed.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
        #[serde(rename_all = "snake_case")]
        pub enum SignalKind {
            $($(#[$doc])* $variant),+
        }

        impl SignalKind {
            pub fn as_str(self) -> &'static str {
                match self { $(Self::$variant => $s),+ }
            }

            /// How much this signal contributes to the ranking.
            pub fn weight(self) -> i64 {
                match self { $(Self::$variant => $weight),+ }
            }
        }
    };
}

signal_kinds! {
    /// Reviewers reached opposite conclusions — the case where a
    /// human's judgment is worth the most.
    ReviewersDisagree => "reviewers_disagree", 100;
    /// A runner could not reproduce a claim.
    DisputedClaim => "disputed_claim", 90;
    /// Someone blocked it and it has not moved since.
    Blocked => "blocked", 60;
    /// Nothing was executed; the case rests on argument alone.
    NoExecutedCheck => "no_executed_check", 50;
    /// Everything else is satisfied; only independent judgment is missing.
    AwaitingJudgment => "awaiting_judgment", 40;
    /// Drawn by the sampling policy for a human look.
    SpotCheck => "spot_check", 30;
    /// Claims carry commands nobody has re-run.
    UnverifiedClaim => "unverified_claim", 20;
    /// The claims named things they did not cover.
    DeclaredGap => "declared_gap", 15;
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Signal {
    pub kind: SignalKind,
    pub weight: i64,
    /// What this says, in a person's words.
    pub description: String,
    /// What the evaluation actually saw, in graph terms.
    pub evidence: String,
}

/// A change that wants attention, with the reasons that ranked it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttentionItem {
    pub change: Change,
    pub score: i64,
    pub signals: Vec<Signal>,
}

impl AttentionItem {
    /// The single reason to lead with: the heaviest signal.
    pub fn headline(&self) -> &str {
        self.signals
            .first()
            .map_or("needs a look", |signal| signal.description.as_str())
    }
}

/// "1 claim" but "2 claims" — counts read as English, not as output.
fn count(n: usize, noun: &str) -> String {
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// Is this change drawn by the sampling policy? Deterministic in the
/// change id, so the same change is always either drawn or not — no
/// randomness to make the log unreproducible, and no way to reroll.
fn drawn_for_spot_check(change: &Change) -> bool {
    let digest = Sha256::digest(change.id.as_str().as_bytes());
    let bucket = u64::from_be_bytes(digest[..8].try_into().expect("sha256 is 32 bytes"));
    bucket % SPOT_CHECK_IN == 0
}

/// Rank the open changes in a repo by what a human should look at.
pub(crate) fn evaluate(conn: &Connection, repo: &str) -> CoreResult<Vec<AttentionItem>> {
    let mut items = Vec::new();
    for change in raw::changes_in_repo(conn, repo)? {
        if change.state != ChangeState::Open || change.latest_revision == 0 {
            continue;
        }
        let revision = change.latest_revision;
        let claims = raw::claims_on(conn, change.id.as_str(), revision)?;
        let verdicts = raw::verdicts_on(conn, change.id.as_str(), revision)?;
        let verifications = raw::verifications_on(conn, change.id.as_str(), revision)?;
        let mut signals = Vec::new();

        let approvals: Vec<_> = verdicts
            .iter()
            .filter(|v| v.disposition == Disposition::Approve)
            .collect();
        let blocks: Vec<_> = verdicts
            .iter()
            .filter(|v| v.disposition == Disposition::Block)
            .collect();

        if !blocks.is_empty() && !approvals.is_empty() {
            signals.push(Signal {
                kind: SignalKind::ReviewersDisagree,
                weight: SignalKind::ReviewersDisagree.weight(),
                description: format!(
                    "{} approve, {} block — reviewers disagree",
                    approvals.len(),
                    blocks.len()
                ),
                evidence: verdicts
                    .iter()
                    .map(|v| format!("{} {}", v.by, v.disposition.as_str()))
                    .collect::<Vec<_>>()
                    .join(", "),
            });
        } else if !blocks.is_empty() {
            signals.push(Signal {
                kind: SignalKind::Blocked,
                weight: SignalKind::Blocked.weight(),
                description: format!("blocked by {}", blocks[0].by),
                evidence: blocks
                    .iter()
                    .map(|v| format!("{}: {}", v.id, v.rationale))
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        let disputed: Vec<_> = verifications.iter().filter(|v| !v.agrees).collect();
        if !disputed.is_empty() {
            signals.push(Signal {
                kind: SignalKind::DisputedClaim,
                weight: SignalKind::DisputedClaim.weight(),
                description: format!("{} could not reproduce a claim", disputed[0].by),
                evidence: disputed
                    .iter()
                    .map(|v| format!("{} on {}: {}", v.by, v.claim, v.observed))
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        let executed: Vec<_> = claims
            .iter()
            .filter(|c| c.kind != ClaimKind::Reasoning && c.passed)
            .collect();
        if executed.is_empty() && !claims.is_empty() {
            signals.push(Signal {
                kind: SignalKind::NoExecutedCheck,
                weight: SignalKind::NoExecutedCheck.weight(),
                description: "no executed check — reasoning only".into(),
                evidence: format!(
                    "{}, all reasoning: {}",
                    count(claims.len(), "claim"),
                    claims
                        .iter()
                        .map(|c| c.summary.as_str())
                        .collect::<Vec<_>>()
                        .join("; ")
                ),
            });
        }

        // Claims that name a command invite a re-run; ones nobody ran
        // are the verification debt on this change.
        let unverified: Vec<_> = claims
            .iter()
            .filter(|c| c.command.is_some() && !verifications.iter().any(|v| v.claim == c.id))
            .collect();
        if !unverified.is_empty() {
            signals.push(Signal {
                kind: SignalKind::UnverifiedClaim,
                weight: SignalKind::UnverifiedClaim.weight(),
                description: format!("{} nobody re-ran", count(unverified.len(), "claim")),
                evidence: unverified
                    .iter()
                    .filter_map(|c| c.command.as_deref())
                    .collect::<Vec<_>>()
                    .join("; "),
            });
        }

        let gaps: Vec<&str> = {
            let mut gaps: Vec<&str> = claims
                .iter()
                .flat_map(|c| c.unchecked.iter().map(String::as_str))
                .collect();
            gaps.sort_unstable();
            gaps.dedup();
            gaps
        };
        if !gaps.is_empty() {
            signals.push(Signal {
                kind: SignalKind::DeclaredGap,
                weight: SignalKind::DeclaredGap.weight(),
                description: count(gaps.len(), "declared gap"),
                evidence: gaps.join("; "),
            });
        }

        // Independence is the one thing a human alone can always give.
        let human_judged = verdicts.iter().any(|v| {
            raw::principal(conn, v.by.as_str())
                .ok()
                .flatten()
                .is_some_and(|p| p.kind == PrincipalKind::Human)
        });
        if blocks.is_empty() && !executed.is_empty() && !human_judged {
            let trace = crate::policy::evaluate(conn, &change)?;
            let only_independence = trace
                .requirements
                .iter()
                .filter(|r| !r.satisfied)
                .all(|r| r.description.contains("approved independently"));
            if !trace.satisfied && only_independence {
                signals.push(Signal {
                    kind: SignalKind::AwaitingJudgment,
                    weight: SignalKind::AwaitingJudgment.weight(),
                    description: "verified and unblocked — waiting on judgment".into(),
                    evidence: trace.unmet_summary(),
                });
            }
            if drawn_for_spot_check(&change) {
                signals.push(Signal {
                    kind: SignalKind::SpotCheck,
                    weight: SignalKind::SpotCheck.weight(),
                    description: "sampled for a human look".into(),
                    evidence: format!(
                        "no human has judged this; policy samples 1 in {SPOT_CHECK_IN} such changes"
                    ),
                });
            }
        }

        if signals.is_empty() {
            continue;
        }
        signals.sort_by_key(|signal| std::cmp::Reverse(signal.weight));
        items.push(AttentionItem {
            score: signals.iter().map(|s| s.weight).sum(),
            change,
            signals,
        });
    }
    // Heaviest first; ties go to the older change, which has waited longer.
    items.sort_by(|a, b| {
        b.score
            .cmp(&a.score)
            .then_with(|| a.change.number.cmp(&b.change.number))
    });
    Ok(items)
}
