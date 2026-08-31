//! The transport end to end: real git client, real receive-pack, the
//! real hook binary, and the graph.

mod common;
use common::*;

use axum::Router;
use axum::http::StatusCode;
use cairn_core::{PrincipalId, PrincipalKind, Store};
use cairn_git::GitStore;
use cairn_server::{AppState, router};
use serde_json::{Value, json};

#[tokio::test(flavor = "multi_thread")]
async fn push_review_merge_over_real_git() {
    single_change_flow(boot().await, 40).await;
}

/// The identical flow on a SHA-256 object database: 64-char oids end
/// to end, from clone through merge.
#[tokio::test(flavor = "multi_thread")]
async fn push_review_merge_sha256_repo() {
    // Cloning an *empty* sha256 repo cannot infer the object format from
    // any object, so it depends on the client being new enough to learn
    // it from the transport. Older git silently makes a sha1 working
    // copy. That is a client limitation the forge cannot fix, and it is
    // documented — so on such a git, assert the documentation actually
    // explains what we are seeing, rather than passing quietly.
    let forge = boot_with("sha256").await;

    // The server half holds on any git: the repository really was
    // created with a sha256 object database. Worth asserting separately,
    // so an old client costs us the end-to-end run and nothing more.
    let (_, repo) = api(&forge.app, "GET", "/api/repos/demo", "ada", None).await;
    assert_eq!(repo["object_format"], "sha256");

    let (running, reported) = cairn_git::version().expect("git on PATH");
    if running < cairn_git::MIN_GIT_SHA256_CLIENT {
        let (major, minor) = cairn_git::MIN_GIT_SHA256_CLIENT;
        eprintln!(
            "not exercising sha256 end to end: {reported} predates the documented \
             client floor of {major}.{minor} for cloning an empty sha256 repository"
        );
        return;
    }
    single_change_flow(forge, 64).await;
}

async fn single_change_flow(forge: Forge, oid_len: usize) {
    let (app, addr) = (&forge.app, forge.addr);

    // Clone (anonymous reads), commit with a Change-Id trailer.
    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(
        &wc,
        "greeting.txt",
        "hello\n",
        "Add greeting\n\nChange-Id: If00dcafe01",
    );
    let first_oid = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    assert_eq!(
        first_oid.len(),
        oid_len,
        "object format should determine oid width"
    );

    // Anonymous pushes are refused before touching receive-pack. Named
    // explicitly rather than via `origin`, whose URL carries the
    // credentials the clone needed — a private repository cannot be
    // read anonymously either, which is the point of the next test.
    git_expect_fail(
        &wc,
        &[
            "push",
            &format!("http://{addr}/git/demo"),
            "HEAD:refs/for/main",
        ],
    );

    // The transport IS the API: push with scout's real token as the
    // Basic password (dev mode would also accept it; the strict path
    // has its own test below).
    let push_url = format!("http://scout:{}@{addr}/git/demo", forge.scout_token);
    git(&wc, &["remote", "set-url", "origin", &push_url]);
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    let (status, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(changes.as_array().unwrap().len(), 1);
    let change = &changes[0];
    assert_eq!(change["number"], 1);
    assert_eq!(change["title"], "Add greeting");
    assert_eq!(change["owner"], "scout");
    assert_eq!(change["external_key"], "If00dcafe01");
    assert_eq!(change["latest_revision"], 1);
    let change_id = change["id"].as_str().unwrap().to_owned();

    // The revision ref exists on the wire and matches the pushed commit.
    let refs = git(&wc, &["ls-remote", "origin"]);
    assert!(
        refs.contains("refs/changes/1/1"),
        "missing change ref:\n{refs}"
    );
    assert!(
        refs.lines()
            .any(|l| l.starts_with(&first_oid) && l.contains("refs/changes/1/1"))
    );

    // Amend (same Change-Id) and push again: revision 2 of the SAME change.
    std::fs::write(wc.join("greeting.txt"), "hello, forge\n").unwrap();
    git(&wc, &["add", "."]);
    git(
        &wc,
        &[
            "commit",
            "--amend",
            "-m",
            "Add greeting\n\nChange-Id: If00dcafe01",
        ],
    );
    let second_oid = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(
        changes.as_array().unwrap().len(),
        1,
        "amend must not open a second change"
    );
    assert_eq!(changes[0]["latest_revision"], 2);

    // Every revision stays fetchable by its stable ref.
    git(&wc, &["fetch", "origin", "refs/changes/1/1"]);
    assert_eq!(git(&wc, &["rev-parse", "FETCH_HEAD"]).trim(), first_oid);

    // Capability precedes policy: scout cannot merge at all, and even
    // the sovereign human is refused until policy is satisfied.
    let (status, refusal) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/merge"),
        "scout",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(refusal["kind"], "forbidden");
    let (status, refusal) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/merge"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_eq!(refusal["kind"], "policy_unsatisfied");

    let merged = approve_and_merge(app, &change_id).await;
    assert_eq!(merged["event"]["kind"], "change_merged");
    assert_eq!(merged["event"]["revision"], 2);

    let main_ref = git(&wc, &["ls-remote", "origin", "refs/heads/main"]);
    assert!(
        main_ref.starts_with(&second_oid),
        "main should point at revision 2 ({second_oid}); got:\n{main_ref}"
    );

    // A fresh clone sees the merged history — the loop is closed.
    git(
        &forge.work,
        &[
            "clone",
            &format!("http://scout:x@{addr}/git/demo"),
            "verify",
        ],
    );
    let contents = std::fs::read_to_string(forge.work.join("verify/greeting.txt")).unwrap();
    assert_eq!(contents, "hello, forge\n");
}

#[tokio::test(flavor = "multi_thread")]
async fn stacked_push_with_guards_and_bottom_up_merge() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");

    // A three-commit stack, each commit carrying its own Change-Id.
    commit_file(
        &wc,
        "base.txt",
        "base\n",
        "Lay the base\n\nChange-Id: Iaaa01",
    );
    commit_file(
        &wc,
        "mid.txt",
        "mid\n",
        "Build the middle\n\nChange-Id: Iaaa02",
    );
    commit_file(&wc, "top.txt", "top\n", "Cap the top\n\nChange-Id: Iaaa03");
    let oids: Vec<String> = ["HEAD~2", "HEAD~1", "HEAD"]
        .iter()
        .map(|r| git(&wc, &["rev-parse", r]).trim().to_owned())
        .collect();

    // Guard: branches advance only by merge, never by direct push.
    let refused = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/heads/main"]);
    assert!(
        refused.contains("direct push"),
        "unexpected refusal:\n{refused}"
    );

    // One push, three linked changes, bottom-up numbering.
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let changes = changes.as_array().unwrap().clone();
    assert_eq!(changes.len(), 3);
    for (index, change) in changes.iter().enumerate() {
        assert_eq!(change["number"], index as i64 + 1);
        assert_eq!(change["latest_revision"], 1);
        if index == 0 {
            assert!(change["parent_change"].is_null());
        } else {
            assert_eq!(
                change["parent_change"],
                changes[index - 1]["id"],
                "stack link broken"
            );
        }
    }
    let refs = git(&wc, &["ls-remote", "origin"]);
    for number in 1..=3 {
        assert!(
            refs.contains(&format!("refs/changes/{number}/1")),
            "missing ref:\n{refs}"
        );
    }

    // Re-pushing the identical stack records nothing new.
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, unchanged) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert!(
        unchanged
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["latest_revision"] == 1),
        "idempotent re-push must not mint revisions"
    );

    // Amending only the top commit touches only the top change.
    std::fs::write(wc.join("top.txt"), "top, improved\n").unwrap();
    git(&wc, &["add", "."]);
    git(
        &wc,
        &[
            "commit",
            "--amend",
            "-m",
            "Cap the top\n\nChange-Id: Iaaa03",
        ],
    );
    let amended_top = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, after) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let revisions: Vec<i64> = after
        .as_array()
        .unwrap()
        .iter()
        .map(|c| c["latest_revision"].as_i64().unwrap())
        .collect();
    assert_eq!(
        revisions,
        [1, 1, 2],
        "only the amended change may gain a revision"
    );

    // A stack without per-commit Change-Ids is refused with advice.
    git(&wc, &["checkout", "-q", "-b", "naked", "HEAD~2"]);
    commit_file(&wc, "a.txt", "a\n", "no trailer here");
    commit_file(&wc, "b.txt", "b\n", "none here either");
    let refused = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/dev"]);
    assert!(
        refused.contains("Change-Id"),
        "unexpected refusal:\n{refused}"
    );

    // Merge bottom-up; each merge fast-forwards main to that commit.
    let expected_tips = [oids[0].clone(), oids[1].clone(), amended_top.clone()];
    for (change, expected_tip) in after.as_array().unwrap().iter().zip(&expected_tips) {
        let change_id = change["id"].as_str().unwrap();
        approve_and_merge(app, change_id).await;
        let main_ref = git(&wc, &["ls-remote", "origin", "refs/heads/main"]);
        assert!(
            main_ref.starts_with(expected_tip.as_str()),
            "after merging change {}, main should be {expected_tip}; got:\n{main_ref}",
            change["number"]
        );
    }
}

/// Push credentials are real: with dev identity off, only a live API
/// token as the Basic password gets through receive-pack.
#[tokio::test(flavor = "multi_thread")]
async fn push_requires_a_live_token_without_dev_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let repos = tmp.path().join("repos");
    let work = tmp.path().join("work");
    std::fs::create_dir_all(&work).unwrap();

    let mut store = Store::open_in_memory().unwrap();
    let ada = PrincipalId::new("ada").unwrap();
    let scout = PrincipalId::new("scout").unwrap();
    store
        .register_principal(&ada, &ada, PrincipalKind::Human, "Ada", None, None)
        .unwrap();
    // This test stands its own forge up, so it also has to say who runs
    // it: being human is no longer authority by itself.
    store.grant_bootstrap_admin(&ada).unwrap();
    store
        .register_principal(&ada, &scout, PrincipalKind::Agent, "Scout", Some("m"), None)
        .unwrap();
    store
        .issue_grant(&ada, &scout, None, vec![cairn_core::Capability::Push], None)
        .unwrap();
    let (_, token, _) = store.mint_token(&scout, &scout, None).unwrap();
    store
        .create_repo(&ada, "demo", "main", cairn_core::ObjectFormat::Sha1)
        .unwrap();

    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let git_store = GitStore::new(&repos, env!("CARGO_BIN_EXE_cairn"));
    // The repo entered the graph through the store, so create the bare
    // repo directly too; no dev identity anywhere in this test.
    git_store.create_repo("demo", "main", "sha1").await.unwrap();
    let app = router(AppState::new(store).with_git(git_store, format!("http://{addr}")));
    tokio::spawn(axum::serve(listener, app.clone()).into_future());

    // Reading a private repository needs a credential too, so the clone
    // that sets this test up carries one.
    git(
        &work,
        &[
            "clone",
            &format!("http://scout:{token}@{addr}/git/demo"),
            "wc",
        ],
    );
    let wc = work.join("wc");
    commit_file(&wc, "f.txt", "x\n", "Add f\n\nChange-Id: Itok01");

    // No credentials, wrong password, and a bare username are all
    // refused for writing.
    for bad in [
        format!("http://{addr}/git/demo"),
        format!("http://scout:wrong@{addr}/git/demo"),
        format!("http://scout@{addr}/git/demo"),
    ] {
        let output = git_raw(&wc, &["push", &bad, "HEAD:refs/for/main"]);
        assert!(
            !output.status.success(),
            "push with bad credentials must fail"
        );
    }

    // The live token authenticates and the change lands on the wire.
    git(
        &wc,
        &[
            "push",
            &format!("http://scout:{token}@{addr}/git/demo"),
            "HEAD:refs/for/main",
        ],
    );
    let refs = git(
        &wc,
        &[
            "ls-remote",
            &format!("http://scout:{token}@{addr}/git/demo"),
        ],
    );
    assert!(
        refs.contains("refs/changes/1/1"),
        "missing change ref:\n{refs}"
    );
}

/// The landing train: two ready changes enqueue; the first lands as a
/// fast-forward, the second is auto-rebased past it (new commit,
/// recorded as merged_as, original author preserved); a genuinely
/// conflicting change is dequeued with the file named in the reason.
#[tokio::test(flavor = "multi_thread")]
async fn merge_queue_lands_trains_and_reports_conflicts() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    // Seed main with a first landed change so later work has a base.
    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "base.txt", "base\n", "Base\n\nChange-Id: Iq00");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let base_change = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_merge(app, &base_change).await;
    git(&wc, &["fetch", "-q", "origin", "main"]);
    git(&wc, &["reset", "-q", "--hard", "FETCH_HEAD"]);

    // Two independent changes from the same base, different files.
    commit_file(&wc, "left.txt", "left\n", "Left\n\nChange-Id: Iq01");
    let left_oid = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    git(&wc, &["reset", "-q", "--hard", "HEAD~1"]);
    commit_file(&wc, "right.txt", "right\n", "Right\n\nChange-Id: Iq02");
    let right_oid = git(&wc, &["rev-parse", "HEAD"]).trim().to_owned();
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let by_key = |key: &str| {
        changes
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["external_key"] == key)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (left, right) = (by_key("Iq01"), by_key("Iq02"));

    // Make both ready, then hand both to the queue.
    for change in [&left, &right] {
        let (status, _) = api(
            app,
            "POST",
            &format!("/api/changes/{change}/claims"),
            "scout",
            Some(json!({ "kind": "test", "passed": true, "summary": "ok" })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, _) = api(
            app,
            "POST",
            &format!("/api/changes/{change}/verdicts"),
            "ada",
            Some(json!({
                "domain": "correctness", "disposition": "approve", "rationale": "fine"
            })),
        )
        .await;
        assert_eq!(status, StatusCode::OK);
        let (status, body) = api(
            app,
            "POST",
            &format!("/api/changes/{change}/enqueue"),
            "ada",
            None,
        )
        .await;
        assert_eq!(status, StatusCode::OK, "enqueue failed: {body}");
    }

    // The train lands both without any further help.
    wait_for(app, "both queued changes to merge", async |app: &Router| {
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        changes
            .as_array()
            .unwrap()
            .iter()
            .all(|c| c["state"] == "merged")
    })
    .await;

    // First-in landed as pushed; second was rebased to a fresh commit.
    let (_, events) = api(app, "GET", "/api/events?after=0&limit=200", "ada", None).await;
    let merged: Vec<&Value> = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "change_merged")
        .collect();
    let landed_of = |id: &str| {
        merged
            .iter()
            .find(|e| e["change"] == id)
            .map(|e| e["merged_as"].clone())
            .unwrap()
    };
    assert!(
        landed_of(&left).is_null(),
        "first in line lands fast-forward"
    );
    let rebased = landed_of(&right);
    let rebased = rebased.as_str().expect("second in line must be rebased");
    assert_ne!(rebased, right_oid);

    // The branch carries both, authorship survived the rebase, and a
    // fresh clone agrees.
    git(&wc, &["fetch", "-q", "origin", "main"]);
    let tip = git(&wc, &["rev-parse", "FETCH_HEAD"]).trim().to_owned();
    assert_eq!(tip, rebased);
    let author = git(&wc, &["log", "-1", "--format=%an <%ae>", &tip]);
    assert_eq!(author.trim(), "Ada <ada@example.test>");
    assert!(git(&wc, &["rev-list", "FETCH_HEAD"]).contains(&left_oid));
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/demo"),
            "train",
        ],
    );
    assert!(forge.work.join("train/left.txt").exists());
    assert!(forge.work.join("train/right.txt").exists());

    // A change conflicting with landed work is dequeued, and the reason
    // names the file.
    git(&wc, &["reset", "-q", "--hard", "HEAD~1"]); // back before left/right
    commit_file(
        &wc,
        "left.txt",
        "different left\n",
        "Clash\n\nChange-Id: Iq03",
    );
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let clash = changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["external_key"] == "Iq03")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{clash}/claims"),
        "scout",
        Some(json!({ "kind": "test", "passed": true, "summary": "ok" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{clash}/verdicts"),
        "ada",
        Some(json!({ "domain": "correctness", "disposition": "approve", "rationale": "fine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{clash}/enqueue"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    wait_for(
        app,
        "the conflicting change to be dequeued",
        async |app: &Router| {
            let (_, queue) = api(app, "GET", "/api/repos/demo/queue", "ada", None).await;
            queue.as_array().unwrap().is_empty()
        },
    )
    .await;
    let (_, change) = api(app, "GET", &format!("/api/changes/{clash}"), "ada", None).await;
    assert_eq!(
        change["state"], "open",
        "a conflict must not merge or abandon the change"
    );
    let (_, events) = api(app, "GET", "/api/events?after=0&limit=300", "ada", None).await;
    let dequeued = events
        .as_array()
        .unwrap()
        .iter()
        .find(|e| e["kind"] == "change_dequeued" && e["change"] == clash.as_str())
        .expect("expected a dequeue event");
    let reason = dequeued["reason"].as_str().unwrap();
    assert!(
        reason.contains("left.txt"),
        "reason should name the file: {reason}"
    );
}

/// When a stack parent lands, its open children are carried onto the
/// new tip by the forge rather than left to rot.
#[tokio::test(flavor = "multi_thread")]
async fn landing_a_parent_carries_its_children_forward() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");

    // Give main a tip to build on.
    commit_file(
        &wc,
        "initial.txt",
        "start\n",
        "Initial\n\nChange-Id: Iinit00",
    );
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let initial = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_enqueue(app, &initial).await;
    wait_for(app, "the initial change to land", async |app: &Router| {
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        changes[0]["state"] == "merged"
    })
    .await;
    git(&wc, &["fetch", "-q", "origin", "main"]);
    git(&wc, &["reset", "-q", "--hard", "FETCH_HEAD"]);

    // A two-change stack on that tip.
    commit_file(&wc, "base.txt", "base\n", "Base\n\nChange-Id: Istack01");
    commit_file(&wc, "top.txt", "top\n", "Top\n\nChange-Id: Istack02");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let by_key = |key: &str| -> String {
        changes
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["external_key"] == key)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let parent = by_key("Istack01");
    let child = by_key("Istack02");
    let child_number = changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["external_key"] == "Istack02")
        .unwrap()["number"]
        .as_i64()
        .unwrap();

    // Something else lands first, so the target moves out from under
    // the stack and a plain fast-forward is no longer possible.
    git(&wc, &["checkout", "-q", "-b", "side", "FETCH_HEAD"]);
    commit_file(&wc, "side.txt", "side\n", "Side\n\nChange-Id: Iside03");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let side = changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["external_key"] == "Iside03")
        .unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    approve_and_enqueue(app, &side).await;
    wait_for(app, "the side change to land", async |app: &Router| {
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        changes
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["external_key"] == "Iside03" && c["state"] == "merged")
    })
    .await;

    // Land the parent; the child should be carried onto the new tip
    // without its author lifting a finger.
    approve_and_enqueue(app, &parent).await;
    wait_for(
        app,
        "the child to be carried forward",
        async |app: &Router| {
            let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
            changes.as_array().unwrap().iter().any(|c| {
                c["id"] == child.as_str() && c["latest_revision"].as_i64().unwrap_or(0) >= 2
            })
        },
    )
    .await;

    // The carry is a new revision, recorded and explained, and the
    // change is still open and still its author's.
    let (_, revisions) = api(
        app,
        "GET",
        &format!("/api/changes/{child}/revisions"),
        "ada",
        None,
    )
    .await;
    let carried = revisions.as_array().unwrap().last().unwrap();
    assert!(
        carried["message"]
            .as_str()
            .unwrap()
            .contains("rebased onto main"),
        "the added revision should say who moved it: {carried}"
    );
    let (_, change) = api(app, "GET", &format!("/api/changes/{child}"), "ada", None).await;
    assert_eq!(change["state"], "open");
    assert_eq!(change["owner"], "scout");

    // And the carried revision really does descend from the new tip.
    git(
        &wc,
        &[
            "fetch",
            "-q",
            "origin",
            &format!("refs/changes/{child_number}/2"),
        ],
    );
    let carried_oid = git(&wc, &["rev-parse", "FETCH_HEAD"]).trim().to_owned();
    git(&wc, &["fetch", "-q", "origin", "main"]);
    let tip = git(&wc, &["rev-parse", "FETCH_HEAD"]).trim().to_owned();
    assert!(
        git_raw(&wc, &["merge-base", "--is-ancestor", &tip, &carried_oid])
            .status
            .success(),
        "the carried revision should descend from the new tip"
    );
}

/// Two branches are two trains: work queued on different targets lands
/// in the same pass rather than waiting in line behind each other.
#[tokio::test(flavor = "multi_thread")]
async fn separate_branches_land_in_parallel() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);

    git(
        &forge.work,
        &["clone", &format!("http://scout:x@{addr}/git/demo"), "wc"],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "root.txt", "root\n", "Root\n\nChange-Id: Iroot");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let root = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_enqueue(app, &root).await;
    wait_for(app, "the root change to land", async |app: &Router| {
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        changes[0]["state"] == "merged"
    })
    .await;

    // One change for main, one for a second branch, queued together.
    git(&wc, &["fetch", "-q", "origin", "main"]);
    git(&wc, &["reset", "-q", "--hard", "FETCH_HEAD"]);
    commit_file(&wc, "on-main.txt", "main\n", "On main\n\nChange-Id: Imain");
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    git(&wc, &["reset", "-q", "--hard", "FETCH_HEAD"]);
    commit_file(&wc, "on-dev.txt", "dev\n", "On dev\n\nChange-Id: Idev");
    git(&wc, &["push", "origin", "HEAD:refs/for/release"]);

    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let of = |key: &str| -> String {
        changes
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["external_key"] == key)
            .unwrap()["id"]
            .as_str()
            .unwrap()
            .to_owned()
    };
    let (on_main, on_release) = (of("Imain"), of("Idev"));
    assert_eq!(
        changes
            .as_array()
            .unwrap()
            .iter()
            .find(|c| c["external_key"] == "Idev")
            .unwrap()["target"],
        "release"
    );

    approve_and_enqueue(app, &on_main).await;
    approve_and_enqueue(app, &on_release).await;

    wait_for(app, "both lanes to land", async |app: &Router| {
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        changes
            .as_array()
            .unwrap()
            .iter()
            .filter(|c| ["Imain", "Idev"].contains(&c["external_key"].as_str().unwrap_or("")))
            .all(|c| c["state"] == "merged")
    })
    .await;

    // Each landed on its own branch, and neither queue is left holding
    // anything.
    let refs = git(&wc, &["ls-remote", "origin"]);
    assert!(refs.contains("refs/heads/main"));
    assert!(refs.contains("refs/heads/release"));
    let (_, queue) = api(app, "GET", "/api/repos/demo/queue", "ada", None).await;
    assert!(queue.as_array().unwrap().is_empty());
}
