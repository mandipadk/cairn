//! Tags: names for landed history, given by whoever may merge, never
//! moved, carried to the mirror with the branches.

use crate::common::*;
use axum::Router;
use http::StatusCode;
use serde_json::json;
use std::path::PathBuf;

/// Clone as scout, push one change for review, land it as ada. Returns
/// the working copy and the landed commit.
async fn land_one(forge: &Forge) -> (PathBuf, String) {
    let (app, addr) = (&forge.app, forge.addr);
    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(
        &wc,
        "tagged.txt",
        "hello\n",
        "Something worth naming\n\nChange-Id: Itag0001",
    );
    let push_url = format!("http://scout:{}@{addr}/git/demo", forge.scout_token);
    git(&wc, &["remote", "set-url", "origin", &push_url]);
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_merge(app, &change).await;
    // What landed is what the forge put on main, which need not be the
    // commit as pushed; ask the forge rather than assume.
    git(&wc, &["fetch", "origin", "main"]);
    let landed = git(&wc, &["rev-parse", "FETCH_HEAD"]).trim().to_owned();
    (wc, landed)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tag_names_landed_history_and_travels_to_the_mirror() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    let elsewhere = forge.work.join("elsewhere.git");
    git(
        &forge.work,
        &["init", "--bare", elsewhere.to_str().unwrap()],
    );
    let (status, _) = api(
        app,
        "POST",
        "/api/repos/demo/mirror",
        "ada",
        Some(json!({
            "mirror": { "url": format!("file://{}", elsewhere.display()), "enabled": true }
        })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (wc, landed) = land_one(&forge).await;

    // ada may merge on demo, so ada may name what landed.
    let ada_url = format!("http://ada:{}@{addr}/git/demo", forge.ada_token);
    git(
        &wc,
        &["tag", "-a", "v0.1", "-m", "First named landing", &landed],
    );
    git(&wc, &["push", &ada_url, "refs/tags/v0.1"]);

    let (status, tags) = api(app, "GET", "/api/repos/demo/tags", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(tags.as_array().unwrap().len(), 1, "{tags}");
    assert_eq!(tags[0]["name"], "v0.1");
    assert_eq!(tags[0]["commit_oid"], landed.as_str());
    assert_eq!(tags[0]["by"], "ada");
    assert_eq!(tags[0]["message"], "First named landing");

    // The ref is really there, and the event is on the record.
    let refs = git(&wc, &["ls-remote", "--tags", &ada_url]);
    assert!(refs.contains("refs/tags/v0.1"), "{refs}");
    let (_, events) = api(app, "GET", "/api/events?after=0&limit=300", "ada", None).await;
    assert!(
        events
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e["kind"] == "tag_pushed" && e["name"] == "v0.1" && e["actor"] == "ada"),
        "no tag_pushed event by ada"
    );

    // Carried outward once the ref exists, without waiting for a landing.
    let far = elsewhere.to_str().unwrap().to_owned();
    let expect = landed.clone();
    wait_for(app, "the tag to reach the mirror", async |_: &Router| {
        std::process::Command::new("git")
            .args([
                "-C",
                &far,
                "rev-parse",
                "--verify",
                "--quiet",
                "refs/tags/v0.1^{commit}",
            ])
            .output()
            .map(|o| o.status.success() && String::from_utf8_lossy(&o.stdout).trim() == expect)
            .unwrap_or(false)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_tag_needs_merge_authority_a_landed_commit_and_a_new_name() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    let (wc, landed) = land_one(&forge).await;
    let ada_url = format!("http://ada:{}@{addr}/git/demo", forge.ada_token);
    let scout_url = format!("http://scout:{}@{addr}/git/demo", forge.scout_token);

    // scout holds push, not merge.
    git(&wc, &["tag", "nope", &landed]);
    let refused = git_expect_fail(&wc, &["push", &scout_url, "refs/tags/nope"]);
    assert!(refused.contains("merge"), "{refused}");

    // A commit nobody landed cannot be named, whoever asks.
    commit_file(
        &wc,
        "unlanded.txt",
        "x\n",
        "Never pushed for review\n\nChange-Id: Itag0002",
    );
    git(&wc, &["tag", "early", "HEAD"]);
    let refused = git_expect_fail(&wc, &["push", &ada_url, "refs/tags/early"]);
    assert!(refused.contains("not on any branch"), "{refused}");

    // A name is given once: no moving, no deleting.
    git(&wc, &["tag", "v1", &landed]);
    git(&wc, &["push", &ada_url, "refs/tags/v1"]);
    git(&wc, &["tag", "-f", "v1", "HEAD"]);
    let refused = git_expect_fail(&wc, &["push", "--force", &ada_url, "refs/tags/v1"]);
    assert!(refused.contains("not moved"), "{refused}");
    let refused = git_expect_fail(&wc, &["push", &ada_url, ":refs/tags/v1"]);
    assert!(refused.contains("deleting"), "{refused}");

    // None of the refusals left anything behind.
    let (_, tags) = api(app, "GET", "/api/repos/demo/tags", "ada", None).await;
    assert_eq!(tags.as_array().unwrap().len(), 1, "{tags}");
    assert_eq!(tags[0]["name"], "v1");
    let refs = git(&wc, &["ls-remote", &ada_url]);
    assert!(
        !refs.contains("refs/tags/nope") && !refs.contains("refs/tags/early"),
        "{refs}"
    );
    assert!(
        refs.lines()
            .any(|l| l.starts_with(&landed) && l.ends_with("refs/tags/v1")),
        "v1 should still name the landed commit:\n{refs}"
    );
}
