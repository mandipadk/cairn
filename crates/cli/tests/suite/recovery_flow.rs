//! Coming back from a crash.
//!
//! A merge is two durable writes to two different stores: the decision
//! goes in the log, then the branch moves. A process that dies between
//! them leaves a forge that believes a change landed on a branch which
//! never received it.
//!
//! The answer is the ordinary one for this shape of problem. The log is
//! written first and is the record of intent, and it names the exact
//! commit meant to land — so recovery replays that decision rather than
//! recomputing it. Recomputing would be actively wrong: rebasing a
//! second time produces a different commit and lands the work twice.
//! Replaying is idempotent, which is what makes it safe to run at every
//! start and after every failure.

use crate::common::*;

/// Land a change on `demo`, and hand back its commit.
async fn land_one(forge: &Forge, name: &str, key: &str) -> String {
    let (app, addr) = (&forge.app, forge.addr);
    let wc = forge.work.join("wc");
    if !wc.exists() {
        git(
            &forge.work,
            &[
                "clone",
                "-q",
                &format!("http://scout:x@{addr}/git/demo"),
                "wc",
            ],
        );
    }
    commit_file(&wc, name, "x\n", &format!("Add {name}\n\nChange-Id: {key}"));
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    let id = changes
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["external_key"] == key)
        .expect("the change")["id"]
        .as_str()
        .unwrap()
        .to_owned();
    approve_and_enqueue(app, &id).await;
    wait_for(app, "the change to land", async |app: &axum::Router| {
        let (_, c) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
        c["state"] == "merged"
    })
    .await;
    git(&wc, &["rev-parse", "HEAD"]).trim().to_owned()
}

/// Run git inside the bare repository the forge serves.
fn bare_git(forge: &Forge, repo: &str, args: &[&str]) -> String {
    let bare = forge._tmp.path().join("repos").join(format!("{repo}.git"));
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&bare)
        .args(args)
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_AUTHOR_NAME", "Other")
        .env("GIT_AUTHOR_EMAIL", "other@example.test")
        .env("GIT_COMMITTER_NAME", "Other")
        .env("GIT_COMMITTER_EMAIL", "other@example.test")
        .output()
        .expect("run git in the bare repo");
    assert!(
        output.status.success(),
        "git {args:?} in bare repo failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).trim().to_owned()
}

/// Rewind a branch to simulate the process dying after the merge was
/// recorded but before the ref moved.
fn rewind_branch(forge: &Forge, repo: &str, branch: &str, to: Option<&str>) {
    let bare = forge._tmp.path().join("repos").join(format!("{repo}.git"));
    let args: Vec<String> = match to {
        Some(oid) => vec![
            "update-ref".into(),
            format!("refs/heads/{branch}"),
            oid.to_owned(),
        ],
        None => vec![
            "update-ref".into(),
            "-d".into(),
            format!("refs/heads/{branch}"),
        ],
    };
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(&bare)
        .args(&args)
        .output()
        .expect("rewind the branch");
    assert!(
        output.status.success(),
        "rewind failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// The plain crash: the merge is recorded, the branch never moved.
/// Recovery must put the branch where the log already says it is.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_left_behind_by_a_crash_is_restored() {
    let forge = boot().await;
    let landed = land_one(&forge, "one.txt", "Ione").await;

    // Die between the two writes.
    rewind_branch(&forge, "demo", "main", None);
    assert!(
        !forge
            .state
            .branches_match_the_log()
            .await
            .unwrap()
            .is_empty(),
        "the setup should have produced a real divergence"
    );

    let stuck = cairn_server::reconcile_branches(&forge.state).await;
    assert!(stuck.is_empty(), "this was repairable: {stuck:#?}");

    assert!(
        forge
            .state
            .branches_match_the_log()
            .await
            .unwrap()
            .is_empty(),
        "the branch should now carry what the log says landed"
    );
    let wc = forge.work.join("wc");
    let actual = git(
        &wc,
        &[
            "ls-remote",
            &format!("http://scout:x@{}/git/demo", forge.addr),
            "refs/heads/main",
        ],
    );
    assert!(
        actual.contains(&landed),
        "branch should be at {landed}:\n{actual}"
    );
}

/// Running recovery when nothing is wrong must change nothing, and
/// running it twice must be the same as running it once. That is the
/// property that makes it safe at every start.
#[tokio::test(flavor = "multi_thread")]
async fn recovery_is_idempotent_and_does_nothing_when_healthy() {
    let forge = boot().await;
    let landed = land_one(&forge, "one.txt", "Ione").await;

    for round in 0..3 {
        let stuck = cairn_server::reconcile_branches(&forge.state).await;
        assert!(stuck.is_empty(), "round {round}: {stuck:#?}");
    }
    let wc = forge.work.join("wc");
    let actual = git(
        &wc,
        &[
            "ls-remote",
            &format!("http://scout:x@{}/git/demo", forge.addr),
            "refs/heads/main",
        ],
    );
    assert!(
        actual.contains(&landed),
        "repeated recovery must leave the branch alone:\n{actual}"
    );

    // And no merge was invented along the way.
    let (_, events) = api(
        &forge.app,
        "GET",
        "/api/events?after=0&limit=400",
        "ada",
        None,
    )
    .await;
    let merges = events
        .as_array()
        .unwrap()
        .iter()
        .filter(|e| e["kind"] == "change_merged")
        .count();
    assert_eq!(merges, 1, "recovery must not append merges of its own");
}

/// The case recovery must refuse: the branch moved somewhere that is not
/// behind the recorded commit. Advancing would discard whatever landed
/// in between, so it is reported rather than guessed at.
#[tokio::test(flavor = "multi_thread")]
async fn a_branch_that_moved_elsewhere_is_reported_not_overwritten() {
    let forge = boot().await;
    let first = land_one(&forge, "one.txt", "Ione").await;
    let second = land_one(&forge, "two.txt", "Itwo").await;
    assert_ne!(first, second);

    // Pull main back to the first commit: the second change is recorded
    // as landed, and the branch is now behind it — but crucially the
    // *first* change's commit is not an ancestor of nothing; rewind
    // further so the tip is unrelated to what the log expects.
    rewind_branch(&forge, "demo", "main", Some(&first));
    let stuck = cairn_server::reconcile_branches(&forge.state).await;
    // Being behind is repairable: this is a fast-forward.
    assert!(
        stuck.is_empty(),
        "a branch merely behind is repairable: {stuck:#?}"
    );
    assert!(
        forge
            .state
            .branches_match_the_log()
            .await
            .unwrap()
            .is_empty(),
        "the branch should have been fast-forwarded back"
    );

    // Now the genuinely ambiguous case: something unrelated sits on the
    // branch, so the recorded commit is neither reachable from it nor
    // behind it, and advancing would throw that work away. Build it
    // inside the bare repo, since that is where the ref must resolve.
    let tree = bare_git(&forge, "demo", &["rev-parse", &format!("{first}^{{tree}}")]);
    let unrelated = bare_git(
        &forge,
        "demo",
        &["commit-tree", &tree, "-p", &first, "-m", "Unrelated work"],
    );
    rewind_branch(&forge, "demo", "main", Some(&unrelated));

    let stuck = cairn_server::reconcile_branches(&forge.state).await;
    assert!(
        stuck.iter().any(|s| s.contains("needs a person")),
        "an ambiguous branch must be reported, not overwritten: {stuck:#?}"
    );

    // And it really was not overwritten.
    let wc = forge.work.join("wc");
    let actual = git(
        &wc,
        &[
            "ls-remote",
            &format!("http://scout:x@{}/git/demo", forge.addr),
            "refs/heads/main",
        ],
    );
    assert!(
        actual.contains(&unrelated),
        "recovery must not discard what it does not understand:\n{actual}"
    );
}
