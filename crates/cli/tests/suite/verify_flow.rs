//! The runner loop end to end: a real `cairn verify` process re-runs a
//! change's claims in a working directory and records what it saw. A
//! claim it reproduces leaves the gate open; one it cannot blocks the
//! landing until someone resolves it.

use crate::common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::json;
use std::process::Command;

/// Run the runner against a change, returning its combined output.
fn run_verifier(
    server: &str,
    token: &str,
    repo: &str,
    change: i64,
    workdir: &std::path::Path,
) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_cairn"))
        .args([
            "verify",
            "--server",
            server,
            "--token",
            token,
            "--repo",
            repo,
            "--workdir",
            workdir.to_str().unwrap(),
            &change.to_string(),
        ])
        .output()
        .expect("run cairn verify");
    // A dispute is a non-zero exit on purpose — that is how a CI job
    // goes red — so the caller reads the report rather than the status.
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_runner_reproduces_one_claim_and_disputes_another() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    let server = format!("http://{addr}");

    // A runner is a principal like any other, holding one capability.
    let (status, _) = api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "runner", "kind": "agent", "display": "Runner", "model": "sandbox" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "runner", "actions": ["verify"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, minted) = api(
        app,
        "POST",
        "/api/principals/runner/tokens",
        "ada",
        Some(json!({ "label": "ci" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let runner_token = minted["token"].as_str().unwrap().to_owned();

    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "a.txt", "a\n", "Honest change\n\nChange-Id: Ihonest");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let honest = changes[0]["id"].as_str().unwrap().to_owned();

    // A claim whose command genuinely succeeds, as claimed.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{honest}/claims"),
        "scout",
        Some(json!({
            "kind": "test", "passed": true, "summary": "the suite is green",
            "command": "exit 0"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{honest}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "fine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let output = run_verifier(&server, &runner_token, "demo", 1, &wc);
    assert!(output.contains("reproduced"), "runner output: {output}");
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{honest}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(readiness["satisfied"], true);
    let evidence = readiness["requirements"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["description"].as_str().unwrap().contains("disputed"))
        .expect("the disputed-claim requirement should exist");
    assert!(
        evidence["evidence"]
            .as_str()
            .unwrap()
            .contains("reproduced"),
        "the trace should record the re-run: {evidence}"
    );

    // A second change claiming success for a command that fails.
    git(&wc, &["reset", "-q", "--hard", "HEAD"]);
    commit_file(
        &wc,
        "b.txt",
        "b\n",
        "Optimistic change\n\nChange-Id: Ioptimistic",
    );
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let optimistic = changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["number"] == 2)
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{optimistic}/claims"),
        "scout",
        Some(json!({
            "kind": "test", "passed": true, "summary": "the suite is green",
            "command": "echo 'a test failed' >&2; exit 1"
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{optimistic}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "looks ok" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    // Ready on the strength of the claim alone, before anyone re-runs it.
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{optimistic}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(
        readiness["satisfied"], true,
        "unverified claims are taken at face value"
    );

    let output = run_verifier(&server, &runner_token, "demo", 2, &wc);
    assert!(output.contains("DISPUTED"), "runner output: {output}");
    assert!(
        output.contains("cannot land"),
        "runner should say what follows"
    );

    // The dispute is now the forge's position, not just the runner's.
    let (_, readiness) = api(
        app,
        "GET",
        &format!("/api/changes/{optimistic}/readiness"),
        "ada",
        None,
    )
    .await;
    assert_eq!(readiness["satisfied"], false);
    let (status, refusal) = api(
        app,
        "POST",
        &format!("/api/changes/{optimistic}/merge"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal["kind"], "policy_unsatisfied");
    assert!(
        refusal["error"].as_str().unwrap().contains("disputed"),
        "the refusal should name the dispute: {refusal}"
    );

    // What the runner saw is on the record, attributable and readable.
    let (_, verifications) = api(
        app,
        "GET",
        &format!("/api/changes/{optimistic}/verifications"),
        "ada",
        None,
    )
    .await;
    let recorded = &verifications.as_array().unwrap()[0];
    assert_eq!(recorded["by"], "runner");
    assert_eq!(recorded["agrees"], false);
    assert!(
        recorded["observed"]
            .as_str()
            .unwrap()
            .contains("a test failed")
    );

    // The honest change still lands; one dispute does not poison the queue.
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{honest}/enqueue"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    wait_for(
        app,
        "the reproducible change to land",
        async |app: &Router| {
            let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
            changes[0]["state"] == "merged"
        },
    )
    .await;
}

/// What a CI job actually calls: no change number, so it works through
/// everything currently taken on trust, fetching each revision itself
/// rather than trusting the directory it happens to be run in.
#[tokio::test(flavor = "multi_thread")]
async fn a_runner_sweeps_everything_waiting_and_fails_loudly() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    let server = format!("http://{addr}");

    let (status, _) = api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "ci", "kind": "agent", "display": "CI", "model": "actions" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        "/api/grants",
        "ada",
        Some(json!({ "grantee": "ci", "actions": ["verify"] })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (_, minted) = api(
        app,
        "POST",
        "/api/principals/ci/tokens",
        "ada",
        Some(json!({ "label": "actions" })),
    )
    .await;
    let ci_token = minted["token"].as_str().unwrap().to_owned();

    // Two changes: one whose claim holds up, one whose does not.
    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    for (file, key, command) in [
        ("good.txt", "Igood", "test -f good.txt"),
        ("bad.txt", "Ibad", "test -f a-file-that-is-not-here"),
    ] {
        commit_file(&wc, file, "x\n", &format!("Work\n\nChange-Id: {key}"));
        git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        let change = changes
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["external_key"] == key)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned();
        let (status, _) = api(
            app,
            "POST",
            &format!("/api/changes/{change}/claims"),
            "scout",
            Some(json!({
                "kind": "test", "passed": true, "summary": "checked", "command": command
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
    }

    // Both are waiting on somebody to re-run them.
    let (_, waiting) = api(
        app,
        "GET",
        "/api/repos/demo/awaiting-verification",
        "ada",
        None,
    )
    .await;
    assert_eq!(waiting.as_array().unwrap().len(), 2);

    // The sweep checks out each revision itself and goes red when a
    // claim does not hold, which is what makes a CI job useful.
    let workspace = forge.work.join("ci");
    std::fs::create_dir_all(&workspace).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_cairn"))
        .args([
            "verify",
            "--server",
            &server,
            "--token",
            &ci_token,
            "--repo",
            "demo",
            "--workdir",
            workspace.to_str().unwrap(),
            "--checkout",
        ])
        .output()
        .expect("run the sweep");
    let said = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        !output.status.success(),
        "a dispute must fail the job: {said}"
    );
    assert!(said.contains("reproduced"), "the honest claim held: {said}");
    assert!(
        said.contains("DISPUTED"),
        "the dishonest one did not: {said}"
    );
    assert!(!said.contains(&ci_token), "the token must never be echoed");

    // Nothing is waiting any more, and the graph carries both verdicts
    // on the machinery.
    let (_, waiting) = api(
        app,
        "GET",
        "/api/repos/demo/awaiting-verification",
        "ada",
        None,
    )
    .await;
    assert!(waiting.as_array().unwrap().is_empty());
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    for change in changes.as_array().unwrap() {
        let id = change["id"].as_str().unwrap();
        let (_, verifications) = api(
            app,
            "GET",
            &format!("/api/changes/{id}/verifications"),
            "ada",
            None,
        )
        .await;
        let recorded = &verifications.as_array().unwrap()[0];
        assert_eq!(recorded["by"], "ci");
        assert_eq!(
            recorded["agrees"],
            change["external_key"] == "Igood",
            "the runner should agree exactly where the claim was true"
        );
    }
}
