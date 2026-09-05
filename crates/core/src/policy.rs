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
    Capability, Change, ClaimKind, Disposition, Independence, Policy, PrincipalKind, Verification,
};
use rusqlite::Connection;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

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

    if policy.attention_budget.is_some()
        && let Some(draw) = raw::draw_of(conn, change.id.as_str())?
    {
        let looked = crate::attention::human_looked(conn, change.id.as_str(), revision)?;
        requirements.push(Requirement {
            description: "a human has looked at this change since it was drawn for one".into(),
            satisfied: looked,
            evidence: format!(
                "drawn {} for {}; asked {}; human verdict on revision {revision}: {}",
                draw.day,
                draw.signals
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                draw.reviewers
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
                if looked { "yes" } else { "none yet" }
            ),
        });
    }

    if policy.require_concerns_resolved {
        let open = raw::open_concerns(conn, change.id.as_str())?;
        requirements.push(Requirement {
            description: "no concern raised in discussion is left unresolved".into(),
            satisfied: open.is_empty(),
            evidence: if open.is_empty() {
                "no unresolved concerns".into()
            } else {
                open.iter()
                    .map(|t| {
                        format!(
                            "{} by {} on revision {}",
                            t.id.as_str(),
                            t.by.as_str(),
                            t.revision
                        )
                    })
                    .collect::<Vec<_>>()
                    .join(", ")
            },
        });
    }

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
    let standing = standing_positions(&verifications);
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
        let quorum = policy.runner_quorum.max(1) as usize;
        let counted = reproductions(conn, &change.repo, &standing)?;
        // The claim with the most provenances behind it is the one that
        // decides; corroboration is per claim, not across them.
        let best = counted
            .by_claim
            .iter()
            .max_by_key(|(_, runners)| runners.len());
        let reached = best.map_or(0, |(_, runners)| runners.len());
        let mut evidence = match best {
            None => "nobody has re-run anything on this revision".to_owned(),
            Some((claim, runners)) => {
                let who = runners
                    .iter()
                    .map(|(provenance, runner)| {
                        if quorum > 1 {
                            format!("{runner} ({provenance}) reproduced {claim}")
                        } else {
                            format!("{runner} reproduced {claim}")
                        }
                    })
                    .collect::<Vec<_>>()
                    .join(", ");
                if quorum > 1 {
                    format!("{who} · {reached} of {quorum} provenances")
                } else {
                    who
                }
            }
        };
        if !counted.not_counted.is_empty() {
            evidence.push_str("; ");
            evidence.push_str(&counted.not_counted.join("; "));
        }
        requirements.push(Requirement {
            description: if quorum > 1 {
                format!(
                    "{quorum} runners of distinct provenance reproduced the same claim on the latest revision"
                )
            } else {
                "a runner reproduced a claim on the latest revision".into()
            },
            satisfied: reached >= quorum,
            evidence,
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

/// Each runner's current position on each claim. A runner's later
/// re-run supersedes its own earlier one; nobody's supersedes anybody
/// else's, which is what keeps two runners' disagreement on the record.
pub(crate) fn standing_positions(verifications: &[Verification]) -> Vec<&Verification> {
    let mut latest: BTreeMap<(&str, &str), &Verification> = BTreeMap::new();
    for verification in verifications {
        latest.insert(
            (verification.claim.as_str(), verification.by.as_str()),
            verification,
        );
    }
    latest.into_values().collect()
}

/// What a runner's word is worth on a repository.
pub struct RunnerStanding {
    /// Where it runs, as well as the forge knows: the issuer that proved
    /// its identity; failing that, the harness it declared; failing that,
    /// the principal itself.
    pub provenance: String,
    /// Verify is all it may do here: not the owner, not an admin, no
    /// push, review or merge. Only such a runner is a third party to the
    /// change, and only a third party's word makes quorum.
    pub third_party: bool,
}

pub(crate) fn runner_standing(
    conn: &Connection,
    principal: &str,
    repo: &str,
) -> CoreResult<RunnerStanding> {
    let record = raw::principal(conn, principal)?;
    let issuer = raw::workload_bindings_of(conn, principal)?
        .into_iter()
        .next()
        .map(|binding| binding.issuer);
    let harness = record
        .as_ref()
        .and_then(|p| p.harness.as_deref())
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .map(str::to_owned);
    let provenance = issuer.or(harness).unwrap_or_else(|| principal.to_owned());

    let owner = raw::repo(conn, repo)?.is_some_and(|r| r.owner.as_str() == principal);
    let grants = raw::effective_grants(conn, principal)?;
    let now = jiff::Timestamp::now().to_string();
    let holds =
        |action: Capability, scope: Option<&str>| raw::grants_cover(&grants, action, scope, &now);
    let third_party = !owner
        && !holds(Capability::Admin, None)
        && !holds(Capability::Push, Some(repo))
        && !holds(Capability::Review, Some(repo))
        && !holds(Capability::Merge, Some(repo));
    Ok(RunnerStanding {
        provenance,
        third_party,
    })
}

/// Who reproduced what, counted the way quorum counts: third parties
/// only, once per provenance, per claim.
pub(crate) struct Reproductions {
    /// claim → provenance → the runner counted for it
    pub by_claim: BTreeMap<String, BTreeMap<String, String>>,
    /// claim → every third-party provenance with a standing position on
    /// it, agreeing or not. A dispute is a position too.
    pub positions: BTreeMap<String, BTreeSet<String>>,
    /// Reproductions that did not count, each saying why.
    pub not_counted: Vec<String>,
}

pub(crate) fn reproductions(
    conn: &Connection,
    repo: &str,
    standing: &[&Verification],
) -> CoreResult<Reproductions> {
    let mut standings: BTreeMap<&str, RunnerStanding> = BTreeMap::new();
    let mut out = Reproductions {
        by_claim: BTreeMap::new(),
        positions: BTreeMap::new(),
        not_counted: Vec::new(),
    };
    for verification in standing {
        let by = verification.by.as_str();
        if !standings.contains_key(by) {
            standings.insert(by, runner_standing(conn, by, repo)?);
        }
        let who = &standings[by];
        if who.third_party {
            out.positions
                .entry(verification.claim.to_string())
                .or_default()
                .insert(who.provenance.clone());
        }
        if !verification.agrees {
            continue;
        }
        if !who.third_party {
            out.not_counted.push(format!(
                "{by} reproduced {} but holds more than verify here",
                verification.claim
            ));
            continue;
        }
        let runners = out
            .by_claim
            .entry(verification.claim.to_string())
            .or_default();
        if let Some(first) = runners.get(&who.provenance) {
            out.not_counted.push(format!(
                "{by} reproduced {} but is also {} like {first}",
                verification.claim, who.provenance
            ));
            continue;
        }
        runners.insert(who.provenance.clone(), by.to_owned());
    }
    Ok(out)
}
