//! What one request is allowed to cost.
//!
//! A forge takes input whose size it does not choose: a repository may
//! legitimately contain a video, a change may legitimately add a
//! generated file, and a push may carry however much history someone
//! has. Every one of those becomes memory in this process, and on a
//! machine shared with other people that is somebody else's problem too.

use crate::common::*;

use axum::http::StatusCode;

/// A file larger than the forge renders must be refused politely, and
/// the bytes must never be turned into a page.
#[tokio::test(flavor = "multi_thread")]
async fn a_large_file_is_described_rather_than_rendered() {
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

    // Comfortably past the 2 MiB render bound, and recognisable if it
    // ever did reach the page.
    let big = "CANARY-".repeat(400_000);
    std::fs::write(wc.join("big.txt"), &big).unwrap();
    // Something binary, too: NUL bytes near the start.
    std::fs::write(wc.join("blob.bin"), [0u8, 1, 2, 3, 0, 9, 9]).unwrap();
    git(&wc, &["add", "."]);
    git(
        &wc,
        &["commit", "-q", "-m", "Add big things\n\nChange-Id: Ibig"],
    );
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let id = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_enqueue(app, &id).await;
    wait_for(app, "the change to land", async |app: &axum::Router| {
        let (_, c) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
        c["state"] == "merged"
    })
    .await;

    let (status, body) = page_with_cookie(app, "/demo/tree/big.txt", "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK, "the page should still render");
    assert!(
        !body.contains("CANARY-"),
        "the file's contents must not reach the page ({} bytes returned)",
        body.len()
    );
    assert!(
        body.contains("larger than"),
        "the reader should be told why, not shown an empty file: {}",
        &body[..body.len().min(400)]
    );
    assert!(
        body.len() < 200_000,
        "the response should stay small; got {} bytes",
        body.len()
    );

    let (status, body) = page_with_cookie(app, "/demo/tree/blob.bin", "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        body.contains("Binary file"),
        "a binary file should say so rather than render as mojibake"
    );
}

/// A README renders on the repository page without anyone asking, so the
/// bound has to hold there too.
#[tokio::test(flavor = "multi_thread")]
async fn an_enormous_readme_does_not_load_the_repository_page() {
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
    std::fs::write(wc.join("README.md"), "CANARY-".repeat(400_000)).unwrap();
    git(&wc, &["add", "."]);
    git(
        &wc,
        &["commit", "-q", "-m", "Huge readme\n\nChange-Id: Iread"],
    );
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let id = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_enqueue(app, &id).await;
    wait_for(app, "the change to land", async |app: &axum::Router| {
        let (_, c) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
        c["state"] == "merged"
    })
    .await;

    let (status, body) = page_with_cookie(app, "/demo", "cairn_dev=ada").await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        !body.contains("CANARY-"),
        "an oversized readme must not be inlined ({} bytes)",
        body.len()
    );
}

/// One push may not become unbounded work. The cap exists; this holds it
/// in place and checks the refusal explains itself.
#[tokio::test(flavor = "multi_thread")]
async fn a_push_carrying_history_is_refused_with_a_reason() {
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
    for n in 0..70 {
        commit_file(
            &wc,
            &format!("f{n}.txt"),
            &format!("{n}\n"),
            &format!("Commit {n}\n\nChange-Id: Ihist{n}"),
        );
    }
    let refusal = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    assert!(
        refusal.contains("history, not a stack"),
        "the pusher should be told what went wrong: {refusal}"
    );

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert!(
        changes.as_array().map(|c| c.is_empty()).unwrap_or(true),
        "a refused push must open no changes: {changes}"
    );
}
