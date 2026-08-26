//! What happens when the input is trying to hurt you.
//!
//! Nearly everything here ends up as an argument to a git subprocess or
//! a path on disk, which makes two classes of bug worth hunting on
//! purpose: a value that escapes the directory it belongs in, and a
//! value that git reads as an *option* rather than data. The second is
//! the quieter one — a commit id of `--upload-pack=…` is a normal
//! string right up until it becomes argv.
//!
//! These tests are written to actually attempt the attack and then check
//! the ground truth (what exists on disk, what came back in the body),
//! rather than trusting that a refusal happened.

mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;

/// A repository name becomes a directory. Anything that could name a
/// directory somewhere else has to be refused before it gets there.
#[tokio::test(flavor = "multi_thread")]
async fn repo_names_that_could_escape_their_directory_are_refused() {
    let forge = boot().await;
    let app = &forge.app;
    let repos = forge._tmp.path().join("repos");

    let hostile = [
        "../escape",
        "..",
        ".",
        "foo/bar",
        "/absolute",
        "a/../../b",
        ".hidden",
        "with space",
        "UPPER",
        "under_score",
        "-leading",
        "trailing-",
        "sem;icolon",
        "dollar$sign",
        "back\\slash",
        "new\nline",
        // Reserved: these would shadow the forge's own routes.
        "api",
        "git",
        "login",
        "assets",
    ];
    for name in hostile {
        let (status, body) = api(
            app,
            "POST",
            "/api/repos",
            "ada",
            Some(json!({ "name": name })),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "repo name {name:?} should have been refused, got {body}"
        );
    }

    // Ground truth: the only repository on disk is the one boot made.
    let mut found: Vec<String> = std::fs::read_dir(&repos)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    found.sort();
    assert_eq!(found, vec!["demo.git"], "something else reached the disk");

    // And nothing was created beside the repos directory either.
    let siblings: Vec<String> = std::fs::read_dir(forge._tmp.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name != "repos" && name != "work")
        .collect();
    assert!(
        siblings.is_empty(),
        "unexpected entries created: {siblings:?}"
    );
}

/// Browsing a tree must not be able to read anything outside it.
#[tokio::test(flavor = "multi_thread")]
async fn tree_paths_cannot_climb_out_of_the_repository() {
    let forge = boot().await;
    let app = &forge.app;

    // Something worth stealing, next to the repositories.
    let secret_path = forge._tmp.path().join("secret.txt");
    std::fs::write(&secret_path, "TOP-SECRET-CANARY\n").unwrap();

    let attempts = [
        "/demo/tree/../../secret.txt",
        "/demo/tree/../../../secret.txt",
        "/demo/tree/..%2f..%2fsecret.txt",
        "/demo/tree/....//....//secret.txt",
        "/demo/tree//etc/hostname",
        "/demo/tree/%2e%2e%2f%2e%2e%2fsecret.txt",
        "/demo/blame/../../secret.txt",
        "/demo/blame/..%2f..%2fsecret.txt",
    ];
    for attempt in attempts {
        let (status, body) = page_with_cookie(app, attempt, "cairn_dev=ada").await;
        assert!(
            !body.contains("TOP-SECRET-CANARY"),
            "{attempt} leaked a file from outside the repository (status {status})"
        );
        assert!(
            !body.contains("root:"),
            "{attempt} leaked something that looks like /etc/passwd (status {status})"
        );
    }
}

/// The quiet one: a value that git parses as an option. Every one of
/// these is a plausible-looking string that would change what git does
/// if it ever reached argv on its own.
#[tokio::test(flavor = "multi_thread")]
async fn values_that_git_would_read_as_options_are_refused() {
    let forge = boot().await;
    let app = &forge.app;

    // A merge target is used to build a ref name.
    for target in [
        "--upload-pack=/bin/sh",
        "-x",
        "--exec=whoami",
        "../../escape",
        "with space",
        "colon:name",
        "tilde~1",
        "back\\slash",
        "trailing/",
        "",
    ] {
        let (status, body) = api(
            app,
            "POST",
            "/api/changes",
            "ada",
            Some(json!({ "repo": "demo", "target": target, "title": "T" })),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "target {target:?} should have been refused, got {body}"
        );
    }

    // A commit id is passed straight to git plumbing.
    let (_, change) = api(
        app,
        "POST",
        "/api/changes",
        "ada",
        Some(json!({ "repo": "demo", "target": "main", "title": "T" })),
    )
    .await;
    let change_id = change["id"].as_str().unwrap().to_owned();
    for oid in [
        "--upload-pack=/bin/sh",
        "-x",
        "--output=/tmp/pwned",
        "; touch /tmp/pwned",
        "$(whoami)",
        "../../../etc/passwd",
        "zz3f1a0000000000000000000000000000000000",
        "abc",
        "",
    ] {
        let (status, body) = api(
            app,
            "POST",
            &format!("/api/changes/{change_id}/revisions"),
            "ada",
            Some(json!({ "commit_oid": oid, "message": "m" })),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "commit oid {oid:?} should have been refused, got {body}"
        );
    }
}

/// An append-only log keeps whatever it is given forever, so oversized
/// text is refused rather than stored and regretted.
#[tokio::test(flavor = "multi_thread")]
async fn oversized_text_is_refused_rather_than_kept_forever() {
    let forge = boot().await;
    let app = &forge.app;

    let huge_title = "t".repeat(100_000);
    let (status, body) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": huge_title, "spec": "work" })),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "an enormous title should be refused: {body}"
    );

    let huge_spec = "s".repeat(2_000_000);
    let (status, _) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": "fine", "spec": huge_spec })),
    )
    .await;
    assert_ne!(
        status,
        StatusCode::OK,
        "a body past the request limit should be refused, not buffered"
    );

    // Nothing hostile survived: the log holds no task at all.
    let (_, tasks) = api(app, "GET", "/api/tasks", "ada", None).await;
    assert!(
        tasks.as_array().map(|t| t.is_empty()).unwrap_or(true),
        "a refused task must leave nothing behind: {tasks}"
    );
}

/// Principal ids name people and appear in refusals; they get the same
/// treatment as repository names.
#[tokio::test(flavor = "multi_thread")]
async fn hostile_principal_ids_are_refused() {
    let forge = boot().await;
    let app = &forge.app;

    for id in [
        "../root",
        "a",
        "-lead",
        "trail-",
        "UPPER",
        "with space",
        "sem;i",
        "nul\u{0}byte",
        "",
        "x".repeat(200).as_str(),
    ] {
        let (status, body) = api(
            app,
            "POST",
            "/api/principals",
            "ada",
            Some(json!({ "id": id, "kind": "agent", "display": "X" })),
        )
        .await;
        assert_ne!(
            status,
            StatusCode::OK,
            "principal id {id:?} should have been refused, got {body}"
        );
    }
}

/// A refused create must leave nothing behind. Creating the bare
/// repository before checking authority meant a caller holding no admin
/// capability still got a directory out of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_caller_without_authority_leaves_nothing_on_disk() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let repos = forge._tmp.path().join("repos");

    // scout holds task and push, never admin.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/repos",
        &forge.scout_token,
        Some(json!({ "name": "sneaky" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    let found: Vec<String> = std::fs::read_dir(&repos)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        found,
        vec!["demo.git"],
        "a refused create must not leave a repository on disk"
    );
}

/// A commit message is the one input an attacker writes in full, and it
/// reaches the graph through the push hook as a title and a Change-Id.
#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_commit_message_smuggles_nothing_into_the_graph() {
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

    // A subject far past the title bound.
    commit_file(&wc, "a.txt", "a\n", &"T".repeat(5_000));
    let refusal = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    assert!(
        refusal.contains("longer than") || refusal.contains("title"),
        "the pusher should be told why: {refusal}"
    );

    // A Change-Id past its bound, and one carrying whitespace. The repo
    // started empty, so there is nothing to reset back to — amend the
    // single commit instead.
    for trailer in [
        format!("Change-Id: I{}", "f".repeat(500)),
        "Change-Id: I with spaces".to_owned(),
    ] {
        git(
            &wc,
            &[
                "commit",
                "-q",
                "--amend",
                "-m",
                &format!("Fine subject\n\n{trailer}"),
            ],
        );
        let refusal = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/main"]);
        assert!(
            !refusal.contains("panicked"),
            "a hostile trailer must be refused, not crash: {refusal}"
        );
    }

    // Nothing hostile reached the graph.
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert!(
        changes.as_array().map(|c| c.is_empty()).unwrap_or(true),
        "no change should exist after only refused pushes: {changes}"
    );
}
