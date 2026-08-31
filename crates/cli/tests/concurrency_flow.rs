//! What happens when two things arrive at once.
//!
//! Concurrency bugs do not announce themselves: they show up later as a
//! revision number reused, a change that landed twice, or a branch tip
//! that disagrees with the log that supposedly produced it. So each test
//! here drives a real race and then checks an invariant that could only
//! survive if the race was handled — including replaying the whole log
//! and demanding it still explains the state it left behind.

mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;
use tokio::task::JoinSet;

fn fake_oid(n: usize) -> String {
    format!("{n:040x}")
}

/// Revision numbers are a sequence per change. If two pushes can both
/// read "latest is 3" and both write 4, the numbering silently stops
/// meaning anything.
#[tokio::test(flavor = "multi_thread")]
async fn concurrent_revisions_get_distinct_numbers() {
    let forge = boot().await;
    let app = &forge.app;

    let (_, change) = api(
        app,
        "POST",
        "/api/changes",
        "ada",
        Some(json!({ "repo": "demo", "target": "main", "title": "Racy" })),
    )
    .await;
    let change_id = change["id"].as_str().unwrap().to_owned();

    const PUSHES: usize = 24;
    let mut set = JoinSet::new();
    for n in 1..=PUSHES {
        let app = app.clone();
        let change_id = change_id.clone();
        set.spawn(async move {
            api(
                &app,
                "POST",
                &format!("/api/changes/{change_id}/revisions"),
                "ada",
                Some(json!({ "commit_oid": fake_oid(n), "message": format!("rev {n}") })),
            )
            .await
        });
    }
    let mut accepted = 0;
    while let Some(result) = set.join_next().await {
        let (status, body) = result.unwrap();
        assert_eq!(status, StatusCode::OK, "a concurrent push failed: {body}");
        accepted += 1;
    }
    assert_eq!(accepted, PUSHES);

    let (_, revisions) = api(
        app,
        "GET",
        &format!("/api/changes/{change_id}/revisions"),
        "ada",
        None,
    )
    .await;
    let mut numbers: Vec<i64> = revisions
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["number"].as_i64().unwrap())
        .collect();
    numbers.sort_unstable();
    assert_eq!(
        numbers,
        (1..=PUSHES as i64).collect::<Vec<_>>(),
        "revision numbers must be exactly 1..n with no gaps or repeats"
    );

    // Every oid arrived exactly once, so nothing was overwritten.
    let oids: std::collections::HashSet<&str> = revisions
        .as_array()
        .unwrap()
        .iter()
        .map(|r| r["commit_oid"].as_str().unwrap())
        .collect();
    assert_eq!(oids.len(), PUSHES, "a revision was lost or duplicated");

    assert!(
        forge.state.fsck().unwrap().is_empty(),
        "the log must still explain the state after a race"
    );
}

/// Enqueueing the same change many times at once must leave one entry
/// in the queue, and landing it must produce exactly one merge.
#[tokio::test(flavor = "multi_thread")]
async fn a_change_enqueued_many_times_at_once_lands_once() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "one.txt", "1\n", "One\n\nChange-Id: Irace1");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let change_id = changes[0]["id"].as_str().unwrap().to_owned();

    // Satisfy policy first, so the only thing under test is the race.
    api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/claims"),
        "scout",
        Some(json!({ "kind": "test", "command": "true", "passed": true, "summary": "ok" })),
    )
    .await;
    api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/verdicts"),
        "ada",
        Some(json!({ "disposition": "approve", "domain": "correctness", "rationale": "fine" })),
    )
    .await;

    let mut set = JoinSet::new();
    for _ in 0..16 {
        let app = app.clone();
        let change_id = change_id.clone();
        set.spawn(async move {
            api(
                &app,
                "POST",
                &format!("/api/changes/{change_id}/enqueue"),
                "ada",
                Some(json!({})),
            )
            .await
            .0
        });
    }
    let mut accepted = 0;
    while let Some(result) = set.join_next().await {
        if result.unwrap() == StatusCode::OK {
            accepted += 1;
        }
    }
    assert!(accepted >= 1, "at least one enqueue should be accepted");

    wait_for(app, "the change to land", async |app: &axum::Router| {
        let (_, c) = api(
            app,
            "GET",
            &format!("/api/changes/{change_id}"),
            "ada",
            None,
        )
        .await;
        c["state"] == "merged"
    })
    .await;

    let (_, events) = api(app, "GET", "/api/events?after=0&limit=500", "ada", None).await;
    let merges = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "change_merged" && e["change"] == change_id.as_str())
        .count();
    assert_eq!(merges, 1, "a change must land exactly once, got {merges}");

    assert!(
        forge.state.fsck().unwrap().is_empty(),
        "the log must still explain the state after a race"
    );
}

/// Many changes across many branches, landing at the same time. Every
/// one must land exactly once, and every branch must end where the log
/// says it ended.
#[tokio::test(flavor = "multi_thread")]
async fn many_changes_landing_at_once_each_land_once_and_the_refs_agree() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");

    // Seed main so the branches have a base commit to fork from.
    commit_file(&wc, "base.txt", "base\n", "Base\n\nChange-Id: Ibase");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let base = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_enqueue(app, &base).await;
    wait_for(app, "the base to land", async |app: &axum::Router| {
        let (_, c) = api(app, "GET", &format!("/api/changes/{base}"), "ada", None).await;
        c["state"] == "merged"
    })
    .await;
    git(&wc, &["fetch", "-q", "origin", "main"]);
    git(&wc, &["reset", "-q", "--hard", "FETCH_HEAD"]);

    // One change per branch, so every lane runs at the same time.
    const LANES: usize = 6;
    let mut ids = Vec::new();
    for lane in 0..LANES {
        git(&wc, &["reset", "-q", "--hard", "FETCH_HEAD"]);
        commit_file(
            &wc,
            &format!("lane{lane}.txt"),
            &format!("lane {lane}\n"),
            &format!("Lane {lane}\n\nChange-Id: Ilane{lane}"),
        );
        git(
            &wc,
            &[
                "push",
                "-q",
                "origin",
                &format!("HEAD:refs/for/branch{lane}"),
            ],
        );
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        let id = changes
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["external_key"] == format!("Ilane{lane}").as_str())
            .expect("the lane's change")["id"]
            .as_str()
            .unwrap()
            .to_owned();
        ids.push(id);
    }

    // Approve everything, then release them all at once.
    for id in &ids {
        api(
            app,
            "POST",
            &format!("/api/changes/{id}/claims"),
            "scout",
            Some(json!({ "kind": "test", "command": "true", "passed": true, "summary": "ok" })),
        )
        .await;
        api(
            app,
            "POST",
            &format!("/api/changes/{id}/verdicts"),
            "ada",
            Some(json!({ "disposition": "approve", "domain": "correctness", "rationale": "fine" })),
        )
        .await;
    }
    let mut set = JoinSet::new();
    for id in ids.clone() {
        let app = app.clone();
        set.spawn(async move {
            api(
                &app,
                "POST",
                &format!("/api/changes/{id}/enqueue"),
                "ada",
                Some(json!({})),
            )
            .await
            .0
        });
    }
    while let Some(result) = set.join_next().await {
        assert_eq!(result.unwrap(), StatusCode::OK);
    }

    for id in &ids {
        let id = id.clone();
        wait_for(
            app,
            "every lane to land",
            async move |app: &axum::Router| {
                let (_, c) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
                c["state"] == "merged"
            },
        )
        .await;
    }

    // Exactly one merge each.
    let (_, events) = api(app, "GET", "/api/events?after=0&limit=800", "ada", None).await;
    let events = events.as_array().unwrap();
    for id in &ids {
        let merges = events
            .iter()
            .filter(|e| e["kind"] == "change_merged" && e["change"] == id.as_str())
            .count();
        assert_eq!(merges, 1, "change {id} landed {merges} times");
    }

    // And every branch tip is what the log says landed on it.
    for (lane, id) in ids.iter().enumerate() {
        let merge = events
            .iter()
            .find(|e| e["kind"] == "change_merged" && e["change"] == id.as_str())
            .unwrap();
        let (_, change) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
        let expected = merge["merged_as"]
            .as_str()
            .map(str::to_owned)
            .unwrap_or_else(|| change["landed_oid"].as_str().unwrap().to_owned());
        let actual = git(
            &wc,
            &[
                "ls-remote",
                &format!("http://scout:x@{addr}/git/demo"),
                &format!("refs/heads/branch{lane}"),
            ],
        );
        assert!(
            actual.contains(&expected),
            "branch{lane} should be at {expected} per the log, got:\n{actual}"
        );
    }

    assert!(
        forge.state.fsck().unwrap().is_empty(),
        "the log must still explain the state after landing in parallel"
    );
}

/// Recording a merge and moving the branch are two steps against two
/// different stores, so they can come apart — a crash, or a second forge
/// process sharing the database. Nothing else notices, because every
/// query answers from the graph. Prove the check that would notice
/// actually notices, by pulling the branch back behind the log.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_that_lost_a_landed_change_is_reported() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "first.txt", "1\n", "First\n\nChange-Id: Ifirst");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let first = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_enqueue(app, &first).await;
    wait_for(
        app,
        "the first change to land",
        async |app: &axum::Router| {
            let (_, c) = api(app, "GET", &format!("/api/changes/{first}"), "ada", None).await;
            c["state"] == "merged"
        },
    )
    .await;

    // Healthy to begin with.
    assert!(
        forge
            .state
            .branches_match_the_log()
            .await
            .unwrap()
            .is_empty(),
        "a freshly landed change should be on its branch"
    );

    // Now the failure this exists to catch: the graph still says merged,
    // the branch no longer contains it.
    let bare = forge._tmp.path().join("repos").join("demo.git");
    let landed = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    std::process::Command::new("git")
        .args([
            "-C",
            bare.to_str().unwrap(),
            "update-ref",
            "-d",
            "refs/heads/main",
            &landed,
        ])
        .output()
        .expect("rewind the branch");

    let divergences = forge.state.branches_match_the_log().await.unwrap();
    assert!(
        divergences
            .iter()
            .any(|d| d.contains("does not contain it")),
        "a branch missing a landed change must be reported; got {divergences:#?}"
    );

    // The projections themselves are still perfectly consistent, which
    // is exactly why this needed its own check: fsck replays the log and
    // finds nothing wrong, because nothing about the log is wrong.
    assert!(
        forge.state.fsck().unwrap().is_empty(),
        "the log still explains the projections; only git disagrees"
    );
}
