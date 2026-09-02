//! Merge policy: the law that decides when a change may land.
//!
//! Nothing merges on ambient authority. A merge is the outcome of an
//! evaluation over the graph — claims, verdicts, verifications, and
//! the principals behind them — and the full [`PolicyTrace`] is
//! embedded in the `ChangeMerged` event, so every merge is explainable
//! from the log alone, forever.
//!
//! What is required is the repository's own choice, recorded as an
//! event like anything else. The defaults are the rules the forge
//! shipped with, so a repo that never sets a policy behaves exactly as
//! it always did — and the shape of the answer is identical either
//! way: a list of requirements, each satisfied or not, each carrying
//! the evidence it was judged on.

use crate::error::CoreResult;
use crate::queries::raw;
use crate::types::{
    Change, ClaimKind, Disposition, Independence, Policy, PrincipalKind, Verification,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Requirement {
    pub description: String,
    pub satisfied: bool,
    /// What the evaluation actually saw, in terms of graph object ids.
    pub evidence: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyTrace {
    pub satisfied: bool,
    pub requirements: Vec<Requirement>,
}

impl PolicyTrace {
    /// One-line summary of what's missing, for error messages.
    pub fn unmet_summary(&self) -> String {
        self.requirements
            .iter()
            .filter(|r| !r.satisfied)
            .map(|r| r.description.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    }
}

/// Evaluate a change against its repository's policy.
pub(crate) fn evaluate(conn: &Connection, change: &Change) -> CoreResult<PolicyTrace> {
    let policy = raw::repo(conn, &change.repo)?
        .map(|repo| repo.policy)
        .unwrap_or_default();
    evaluate_against(conn, change, &policy)
}

pub(crate) fn evaluate_against(
    conn: &Connection,
    change: &Change,
    policy: &Policy,
) -> CoreResult<PolicyTrace> {
    let mut requirements = Vec::new();
    let revision = change.latest_revision;

    requirements.push(Requirement {
        description: "change has at least one revision".into(),
        satisfied: revision >= 1,
        evidence: format!("latest revision is {revision}"),
    });

    let claims = raw::claims_on(conn, change.id.as_str(), revision)?;
    if policy.require_executed_check {
        let executed: Vec<_> = claims
            .iter()
            .filter(|c| c.kind != ClaimKind::Reasoning && c.passed)
            .collect();
        requirements.push(Requirement {
            description: "latest revision carries a passing test claim".into(),
            satisfied: !executed.is_empty(),
            evidence: if executed.is_empty() {
                format!(
                    "{} claim(s) on revision {revision}, none an executed check",
                    claims.len()
                )
            } else {
                executed
                    .iter()
                    .map(|c| c.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        });
    }

    // A claim someone re-ran and could not reproduce is worse than no
    // claim: it is a contradiction on the record.
    let verifications = raw::verifications_on(conn, change.id.as_str(), revision)?;
    // A runner's verdict on a claim is its current position, not a
    // permanent artefact. When the same runner re-runs the same claim it
    // is saying what it now observes, and its earlier attempt becomes
    // history rather than a standing objection - otherwise one bad
    // afternoon in a runner's environment would brick a change forever,
    // with the log asserting both that the claim was reproduced and that
    // it was not. Two *different* runners disagreeing is not superseded
    // by either of them: that disagreement is real information, and it
    // is exactly the case a person should look at.
    let standing: Vec<&Verification> = {
        let mut latest: BTreeMap<(&str, &str), &Verification> = BTreeMap::new();
        for verification in &verifications {
            latest.insert(
                (verification.claim.as_str(), verification.by.as_str()),
                verification,
            );
        }
        latest.into_values().collect()
    };
    let disputed: Vec<_> = standing.iter().filter(|v| !v.agrees).collect();
    requirements.push(Requirement {
        description: "no claim on the latest revision is disputed by a runner".into(),
        satisfied: disputed.is_empty(),
        evidence: if disputed.is_empty() {
            match standing.len() {
                0 => "no independent re-runs".into(),
                n => format!("{n} re-run(s), all reproduced"),
            }
        } else {
            disputed
                .iter()
                .map(|v| format!("{} could not reproduce claim {}", v.by, v.claim))
                .collect::<Vec<_>>()
                .join(", ")
        },
    });

    if policy.require_runner_verification {
        let reproduced: Vec<_> = standing.iter().filter(|v| v.agrees).collect();
        requirements.push(Requirement {
            description: "a runner reproduced a claim on the latest revision".into(),
            satisfied: !reproduced.is_empty(),
            evidence: if reproduced.is_empty() {
                "nobody has re-run anything on this revision".into()
            } else {
                reproduced
                    .iter()
                    .map(|v| format!("{} reproduced {}", v.by, v.claim))
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        });
    }

    let verdicts = raw::verdicts_on(conn, change.id.as_str(), revision)?;
    let blocks: Vec<_> = verdicts
        .iter()
        .filter(|v| v.disposition == Disposition::Block)
        .collect();
    requirements.push(Requirement {
        description: "no blocking verdict on the latest revision".into(),
        satisfied: blocks.is_empty(),
        evidence: if blocks.is_empty() {
            "no blocks".into()
        } else {
            blocks
                .iter()
                .map(|v| format!("{} blocked by {}", v.id, v.by))
                .collect::<Vec<_>>()
                .join(", ")
        },
    });

    for domain in &policy.required_domains {
        let covered: Vec<_> = verdicts
            .iter()
            .filter(|v| v.domain == *domain && v.disposition == Disposition::Approve)
            .collect();
        requirements.push(Requirement {
            description: format!("approved for {}", domain.as_str()),
            satisfied: !covered.is_empty(),
            evidence: if covered.is_empty() {
                format!("no {} approval on revision {revision}", domain.as_str())
            } else {
                covered
                    .iter()
                    .map(|v| v.by.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        });
    }

    // Independence: whose judgment counts as somebody else's.
    let mut humans = Vec::new();
    let mut agent_models: Vec<(String, String)> = Vec::new();
    for verdict in &verdicts {
        if verdict.disposition != Disposition::Approve || verdict.by == change.owner {
            continue;
        }
        let Some(principal) = raw::principal(conn, verdict.by.as_str())? else {
            continue;
        };
        match principal.kind {
            PrincipalKind::Human => humans.push(verdict.by.as_str().to_owned()),
            PrincipalKind::Agent => {
                let model = principal.model.unwrap_or_else(|| principal.id.0.clone());
                if !agent_models.iter().any(|(m, _)| *m == model) {
                    agent_models.push((model, verdict.by.as_str().to_owned()));
                }
            }
            // A team never acts, so it never gives a verdict; the arm
            // exists so the compiler holds us to that if it changes.
            PrincipalKind::Team => {}
        }
    }
    let (description, satisfied) = match policy.independence {
        Independence::None => ("no independent approval required".to_owned(), true),
        Independence::Anyone => (
            "approved by anyone other than the owner".to_owned(),
            !humans.is_empty() || !agent_models.is_empty(),
        ),
        Independence::HumanOnly => (
            "approved by a human other than the owner".to_owned(),
            !humans.is_empty(),
        ),
        Independence::HumanOrTwoModels => (
            "approved independently of the owner: one human, or two agents of distinct models"
                .to_owned(),
            !humans.is_empty() || agent_models.len() >= 2,
        ),
    };
    requirements.push(Requirement {
        description,
        satisfied,
        evidence: format!(
            "human approvals: [{}]; agent approvals by model: [{}]",
            humans.join(", "),
            agent_models
                .iter()
                .map(|(model, who)| format!("{who} ({model})"))
                .collect::<Vec<_>>()
                .join(", ")
        ),
    });

    Ok(PolicyTrace {
        satisfied: requirements.iter().all(|r| r.satisfied),
        requirements,
    })
}
