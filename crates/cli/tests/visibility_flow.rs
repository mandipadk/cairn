//! Who can read a repository without proving who they are.
//!
//! The web pages asked for a sign-in, so the forge looked private. The
//! git transport never asked at all, so it was not: `git clone` against
//! any repository worked for anyone who knew the URL. An interface that
//! implies protection it does not provide is worse than one that admits
//! it has none, because nobody goes looking.

mod common;
use common::*;

use axum::http::StatusCode;
use serde_json::json;

/// Clone with no credentials whatsoever, and say whether it worked. The
/// harness already runs git with system and global config disabled, so
/// no inherited helper can quietly supply any.
fn anonymous_clone(
    work: &std::path::Path,
    addr: std::net::SocketAddr,
    repo: &str,
    into: &str,
) -> bool {
    let output = git_raw(
        work,
        &["clone", "-q", &format!("http://{addr}/git/{repo}"), into],
    );
    output.status.success()
}

#[tokio::test(flavor = "multi_thread")]
async fn a_private_repository_cannot_be_read_by_a_stranger() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    // Put something in it, so success would actually be a leak.
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
    commit_file(
        &wc,
        "secret.txt",
        "CANARY\n",
        "Secret\n\nChange-Id: Isecret",
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

    // Private is the default: nobody said otherwise, so nobody gets in.
    let (_, repo) = api(app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(
        repo["visibility"], "private",
        "a repository defaults to private"
    );

    assert!(
        !anonymous_clone(&forge.work, addr, "demo", "stolen"),
        "a stranger must not be able to clone a private repository"
    );
    assert!(
        !forge.work.join("stolen").exists(),
        "and must be left with nothing"
    );

    // Someone holding a token still can.
    assert!(
        git_raw(
            &forge.work,
            &[
                "clone",
                "-q",
                &format!("http://token:{}@{addr}/git/demo", forge.scout_token),
                "allowed"
            ],
        )
        .status
        .success(),
        "a credential should still open it"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_public_repository_can_be_read_by_anyone() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    let (status, body) = api(
        app,
        "POST",
        "/api/repos/demo/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["event"]["kind"], "visibility_set");

    assert!(
        anonymous_clone(&forge.work, addr, "demo", "open"),
        "a public repository should need no credential"
    );

    // And turning it back off takes effect at once.
    api(
        app,
        "POST",
        "/api/repos/demo/visibility",
        "ada",
        Some(json!({ "visibility": "private" })),
    )
    .await;
    assert!(
        !anonymous_clone(&forge.work, addr, "demo", "closed-again"),
        "making a repository private again must close it immediately"
    );
}

/// A private repository and one that does not exist answer a stranger
/// identically. Which private repositories exist is not public either.
#[tokio::test(flavor = "multi_thread")]
async fn a_stranger_cannot_tell_a_private_repository_from_a_missing_one() {
    let forge = boot().await;
    let addr = forge.addr;

    let private = git_expect_fail(
        &forge.work,
        &["ls-remote", &format!("http://{addr}/git/demo")],
    );
    let missing = git_expect_fail(
        &forge.work,
        &["ls-remote", &format!("http://{addr}/git/no-such-repo")],
    );
    // The strongest form of the property: not merely similar, identical.
    // A stranger learns nothing about which repositories are here.
    assert_eq!(
        private, missing,
        "a private repository and a missing one must be indistinguishable"
    );
    assert!(
        !private.contains("demo"),
        "and the refusal must not echo the name back: {private}"
    );
}

/// Only an admin decides.
#[tokio::test(flavor = "multi_thread")]
async fn making_a_repository_public_takes_authority() {
    let forge = boot_token_only().await;
    let (status, body) = api_with_token(
        &forge.app,
        "POST",
        "/api/repos/demo/visibility",
        &forge.scout_token,
        Some(json!({ "visibility": "public" })),
    )
    .await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "an agent must not open a repository to the world: {body}"
    );
}
