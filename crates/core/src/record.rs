//! What the log says about a principal, counted.
//!
//! Nothing here is stored or declared. A record is the events with this
//! principal's name on them, cut at a window and summed: claims made,
//! how many a third-party runner judged and what it found, how humans
//! judged their changes when the attention budget drew one, what landed
//! and what was abandoned, and how honestly gaps were declared. It is
//! what a policy reads when it decides whether the owner's own word is
//! good for something here.

use crate::error::CoreResult;
use crate::id::PrincipalId;
use crate::queries::raw;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    pub principal: PrincipalId,
    pub window_days: u32,
    /// The window's start, RFC 3339.
    pub since: String,
    /// Claims with a command this principal made in the window.
    pub claims: u32,
    /// Of those, claims a third-party runner re-ran.
    pub judged: u32,
    pub reproduced: u32,
    pub disputed: u32,
    /// Reproduced as a share of judged; absent until anything was judged.
    pub reproduced_percent: Option<u8>,
    /// Human verdicts on this principal's changes in the window, by
    /// somebody else: the sampled audits, and every other human look.
    pub audits: u32,
    pub audits_passed: u32,
    /// Human blocks among them.
    pub blocks: u32,
    pub landed: u32,
    pub abandoned: u32,
    /// Unchecked items declared on their claims: what they said they did
    /// not verify.
    pub gaps_declared: u32,
}

pub(crate) fn record_of(
    conn: &Connection,
    principal: &str,
    window_days: u32,
) -> CoreResult<Record> {
    record_of_until(conn, principal, window_days, None)
}

/// The record as it stood at a position in the log: the window ends at
/// that event, and nothing after it counts. None is now.
pub(crate) fn record_of_until(
    conn: &Connection,
    principal: &str,
    window_days: u32,
    until_seq: Option<i64>,
) -> CoreResult<Record> {
    let window_days = window_days.max(1);
    let now: jiff::Timestamp = match until_seq {
        Some(seq) => conn
            .query_row(
                "SELECT ts FROM events WHERE seq = ?1",
                params![seq],
                |row| row.get::<_, String>(0),
            )
            .optional()?
            .and_then(|ts| ts.parse().ok())
            .unwrap_or_else(jiff::Timestamp::now),
        None => jiff::Timestamp::now(),
    };
    let now_ts = now.to_string();
    let since = (now - jiff::SignedDuration::from_hours(24 * i64::from(window_days))).to_string();
    // The window is a cut in the log: the first event at or after its
    // start. With nothing since, the cut is past the end and nothing counts.
    let since_seq: i64 = conn.query_row(
        "SELECT COALESCE((SELECT MIN(seq) FROM events WHERE ts >= ?1),
                         (SELECT COALESCE(MAX(seq), 0) + 1 FROM events))",
        params![since],
        |row| row.get(0),
    )?;

    let claims: Vec<(String, String, i64, String)> = conn
        .prepare_cached(
            "SELECT id, change_id, revision, unchecked FROM claims
              WHERE by = ?1 AND command IS NOT NULL AND seq >= ?2
                AND (?3 IS NULL OR seq <= ?3)",
        )?
        .query_map(params![principal, since_seq, until_seq], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
        })?
        .collect::<Result<Vec<_>, _>>()?;

    let mut judged = 0;
    let mut disputed = 0;
    let mut gaps_declared = 0u32;
    let mut standings: BTreeMap<(String, String), bool> = BTreeMap::new();
    let mut repo_of: BTreeMap<String, String> = BTreeMap::new();
    for (claim, change, revision, unchecked) in &claims {
        gaps_declared += serde_json::from_str::<Vec<String>>(unchecked)
            .map(|g| g.len() as u32)
            .unwrap_or(0);
        let repo = match repo_of.get(change) {
            Some(repo) => repo.clone(),
            None => {
                let repo = raw::change(conn, change)?
                    .map(|c| c.repo)
                    .unwrap_or_default();
                repo_of.insert(change.clone(), repo.clone());
                repo
            }
        };
        let mut verifications = raw::verifications_on(conn, change, *revision)?;
        verifications.retain(|v| until_seq.is_none_or(|until| v.seq <= until));
        let positions = crate::policy::standing_positions(&verifications);
        let mut any = false;
        let mut against = false;
        for position in positions.iter().filter(|v| v.claim.as_str() == claim) {
            let key = (position.by.to_string(), repo.clone());
            let third_party = match standings.get(&key) {
                Some(known) => *known,
                None => {
                    let standing =
                        crate::policy::runner_standing(conn, position.by.as_str(), &repo)?;
                    standings.insert(key, standing.third_party);
                    standing.third_party
                }
            };
            if !third_party {
                continue;
            }
            any = true;
            if !position.agrees {
                against = true;
            }
        }
        if any {
            judged += 1;
            if against {
                disputed += 1;
            }
        }
    }
    let reproduced = judged - disputed;

    let (mut audits, mut audits_passed, mut blocks) = (0u32, 0u32, 0u32);
    for disposition in conn
        .prepare_cached(
            "SELECT v.disposition FROM verdicts v
               JOIN changes c ON c.id = v.change_id
               JOIN principals p ON p.id = v.by
              WHERE c.owner = ?1 AND v.by != ?1 AND p.kind = 'human' AND v.seq >= ?2
                AND (?3 IS NULL OR v.seq <= ?3)",
        )?
        .query_map(params![principal, since_seq, until_seq], |row| {
            row.get::<_, String>(0)
        })?
    {
        audits += 1;
        match disposition?.as_str() {
            "approve" => audits_passed += 1,
            "block" => blocks += 1,
            _ => {}
        }
    }

    let (mut landed, mut abandoned) = (0u32, 0u32);
    for (state, n) in conn
        .prepare_cached(
            "SELECT state, COUNT(*) FROM changes
              WHERE owner = ?1 AND updated_at >= ?2 AND updated_at <= ?3
                AND state IN ('merged', 'abandoned')
              GROUP BY state",
        )?
        .query_map(params![principal, since, now_ts], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?
        .collect::<Result<Vec<_>, _>>()?
    {
        match state.as_str() {
            "merged" => landed = n as u32,
            "abandoned" => abandoned = n as u32,
            _ => {}
        }
    }

    Ok(Record {
        principal: PrincipalId(principal.to_owned()),
        window_days,
        since,
        claims: claims.len() as u32,
        judged,
        reproduced,
        disputed,
        reproduced_percent: (judged > 0).then(|| (reproduced * 100 / judged) as u8),
        audits,
        audits_passed,
        blocks,
        landed,
        abandoned,
        gaps_declared,
    })
}
