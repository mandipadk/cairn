//! What one owner may take up here.
//!
//! A forge shared with other people has to be able to say no, and say it
//! in a way the reader can act on: what they have, and what the limit
//! is. The same numbers are what a bigger plan would raise, so this is
//! the shape billing attaches to and nothing else changes.

use crate::common::*;
use axum::http::StatusCode;
use serde_json::json;

/// Set what `owner` may take up. Whatever is left out is left alone.
async fn quota(forge: &Forge, owner: &str, quota: serde_json::Value) {
    let (status, body) = api(
        &forge.app,
        "POST",
        &format!("/api/principals/{owner}/quota"),
        "ada",
        Some(quota),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_repository_past_the_limit_is_refused_with_both_numbers() {
    let forge = boot().await;
    let app = &forge.app;
    // boot() already made ada one repository, so one is the limit here.
    quota(&forge, "ada", json!({ "repos": 1 })).await;

    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "another" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["kind"], "over_quota");
    let said = body["error"].as_str().unwrap_or_default();
    assert!(
        said.contains("has 1 repositories") && said.contains("allows 1"),
        "the refusal must name what they have and what is allowed: {said}"
    );
    // The limit is reached before anything touches the disk, so a
    // refusal leaves no directory to clean up.
    assert!(
        !forge._tmp.path().join("repos/ada/another.git").exists(),
        "a refused create must not leave a repository on disk"
    );

    // Raising it is one call, and then the same request works.
    quota(&forge, "ada", json!({ "repos": 2 })).await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "another" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_person_makes_their_own_agents_and_the_quota_is_what_bounds_it() {
    let forge = boot().await;
    let app = &forge.app;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    quota(&forge, "bee", json!({ "agents": 1 })).await;

    // Bee runs nothing and administers nothing, and still gets an agent.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "bees-hand", "kind": "agent", "display": "Hand", "model": "m" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, agent) = api(app, "GET", "/api/principals/bees-hand", "bee", None).await;
    assert_eq!(agent["owner"], "bee", "the agent is bee's");

    // A token for it: their agent, their credential to mint.
    let (status, minted) = api(
        app,
        "POST",
        "/api/principals/bees-hand/tokens",
        "bee",
        Some(json!({ "label": "work" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{minted}");
    assert!(minted["token"].as_str().is_some_and(|t| !t.is_empty()));

    // The second one is what the quota is for.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "bees-other", "kind": "agent", "display": "Other", "model": "m" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["kind"], "over_quota");

    // Retiring one gives the room back, and that is bee's to do.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/bees-hand/state",
        "bee",
        Some(json!({ "active": false })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "bees-other", "kind": "agent", "display": "Other", "model": "m" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_agent_is_nobody_owner_and_a_person_is_nobody_else() {
    let forge = boot().await;
    let app = &forge.app;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;

    // An agent cannot make more of itself, under itself or anyone.
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.scout_token,
        Some(json!({ "id": "spawn", "kind": "agent", "display": "Spawn", "model": "m" })),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "{body}");

    // A person cannot put an agent on somebody else's account.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "not-mine", "kind": "agent", "display": "Nope", "owner": "ada" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");

    // Nor register a person: a name in the forge's namespace is not
    // one owner's to hand out.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "cat", "kind": "human", "display": "Cat" })),
    )
    .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_organisations_agents_belong_to_it_and_count_against_it() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    post_form(app, "/teams", &ada, "action=create&id=crew&display=Crew").await;
    post_form(app, "/teams", &ada, "action=add&team=crew&member=bee").await;
    quota(&forge, "crew", json!({ "agents": 1 })).await;

    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "crews-hand", "kind": "agent", "display": "Hand", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, agent) = api(app, "GET", "/api/principals/crews-hand", "bee", None).await;
    assert_eq!(agent["owner"], "crew");

    // It is the organisation's allowance that it spends, not bee's.
    let (_, mine) = api(app, "GET", "/api/principals/bee/quota", "bee", None).await;
    assert_eq!(mine["usage"]["agents"], 0);
    let (_, theirs) = api(app, "GET", "/api/principals/crew/quota", "bee", None).await;
    assert_eq!(theirs["usage"]["agents"], 1);
    let (status, body) = api(
        app,
        "POST",
        "/api/principals",
        "bee",
        Some(json!({ "id": "crews-other", "kind": "agent", "display": "Other", "owner": "crew" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn open_tasks_are_counted_against_the_repositorys_owner() {
    let forge = boot().await;
    let app = &forge.app;
    quota(&forge, "ada", json!({ "open_tasks": 1 })).await;
    let (status, body) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "First", "spec": "Do it" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "Second", "spec": "And again" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("open tasks"),
        "{body}"
    );
    // A task that belongs to the forge rather than a repository is
    // nobody's to be charged for.
    let (status, body) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "title": "Forge-wide", "spec": "belongs to no repo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_allowance_is_the_owners_business() {
    let forge = boot().await;
    let app = &forge.app;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;

    // Ada sees hers on her page; bee sees nothing of it.
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (status, page) = page_with_cookie(app, "/ada", &ada).await;
    assert_eq!(status, StatusCode::OK);
    assert!(
        page.contains("Allowance") && page.contains("Open tasks"),
        "{page}"
    );
    api(
        app,
        "POST",
        "/api/repos/ada/demo/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;
    let (_, bee) = sign_in_as(&forge, "bee").await;
    let (status, page) = page_with_cookie(app, "/ada", &bee).await;
    assert_eq!(status, StatusCode::OK, "the page is public now");
    assert!(!page.contains("Allowance"), "but not that part: {page}");
    let (status, _) = api(app, "GET", "/api/principals/ada/quota", "bee", None).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "nor over the API");

    // The numbers a forge answers with are the forge's default until
    // somebody says otherwise.
    let (_, mine) = api(app, "GET", "/api/principals/ada/quota", "ada", None).await;
    assert_eq!(mine["quota"], mine["default"]);
    assert_eq!(mine["usage"]["repos"], 1);
}

/// Every file under a repository's directory, counted. What a refused
/// push must not change.
fn objects_on_disk(repo: &std::path::Path) -> (usize, u64) {
    let mut files = 0;
    let mut bytes = 0;
    let mut pending = vec![repo.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_dir() {
                pending.push(entry.path());
            } else {
                files += 1;
                bytes += meta.len();
            }
        }
    }
    (files, bytes)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_push_from_an_owner_over_their_disk_is_refused_with_the_numbers() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:{}@{addr}/git/ada/demo", forge.scout_token),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "one.txt", "1\n", "First\n\nChange-Id: Ione");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);

    // The push above was measured, so the forge knows a number now.
    let (_, seen) = api(app, "GET", "/api/principals/ada/quota", "ada", None).await;
    let used = seen["usage"]["disk"].as_u64().expect("a measurement");
    assert!(used > 0, "a pushed repository takes room: {seen}");

    // Allow less than that, and the next push is refused by name.
    quota(&forge, "ada", json!({ "disk": 1 })).await;
    let bare = forge._tmp.path().join("repos/ada/demo.git");
    let before = objects_on_disk(&bare);
    commit_file(&wc, "two.txt", "2\n", "Second\n\nChange-Id: Itwo");
    let refusal = git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    assert!(
        refusal.contains("git storage") && refusal.contains("allows"),
        "the pusher should be told what is full: {refusal}"
    );
    // And the bytes did not arrive. Git moves a pushed pack out of
    // quarantine before the hook that would refuse it runs, so a
    // refusal that happens there rejects the ref and keeps the objects
    // — which would let anybody over their limit fill the disk by
    // pushing things that are always refused.
    assert_eq!(
        objects_on_disk(&bare),
        before,
        "a refused push must leave the repository exactly as it was"
    );
    // Not even after several. This is the loop the refusal has to close.
    for n in 3..6 {
        commit_file(
            &wc,
            &format!("f{n}.txt"),
            "x\n",
            &format!("More\n\nChange-Id: If{n}"),
        );
        git_expect_fail(&wc, &["push", "origin", "HEAD:refs/for/main"]);
    }
    assert_eq!(objects_on_disk(&bare), before, "nor after a loop of them");

    // A tag goes through the same door, so it is refused the same way.
    git(&wc, &["tag", "-a", "v1", "-m", "One"]);
    let refusal = git_expect_fail(&wc, &["push", "origin", "v1"]);
    assert!(refusal.contains("git storage"), "{refusal}");
    assert_eq!(
        objects_on_disk(&bare),
        before,
        "a tag push leaves nothing either"
    );
    let (_, changes) = api(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    assert_eq!(
        changes.as_array().map(Vec::len),
        Some(1),
        "the refused push opened nothing new: {changes}"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn the_pack_is_what_a_clone_costs() {
    let forge = boot().await;
    // A clone is an advertisement and then the pack. Counting only the
    // advertisement meters the asking and leaves the answering free,
    // and the answering is the part that forks git.
    let app = cairn_server::router(forge.state.clone().with_read_allowance(25, 25));
    api(
        &app,
        "POST",
        "/api/repos/ada/demo/visibility",
        "ada",
        Some(json!({ "visibility": "public" })),
    )
    .await;

    // One advertisement is one unit; the pack that follows is twenty.
    let (status, _) = api(&app, "GET", "/api/repos/ada/demo", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    let status = status_of(&app, "POST", "/git/ada/demo/git-upload-pack", Some("ada")).await;
    assert_ne!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "the first pack is within the allowance"
    );
    let status = status_of(&app, "POST", "/git/ada/demo/git-upload-pack", Some("ada")).await;
    assert_eq!(
        status,
        StatusCode::TOO_MANY_REQUESTS,
        "and the second is not: a pack is not a page view"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reader_who_will_not_wait_is_told_how_long() {
    let forge = boot().await;
    let app = cairn_server::router(forge.state.clone().with_read_allowance(3, 3));

    for _ in 0..3 {
        let (status, _) = api(&app, "GET", "/api/repos/ada/demo", "ada", None).await;
        assert_eq!(status, StatusCode::OK);
    }
    let (status, body) = api(&app, "GET", "/api/repos/ada/demo", "ada", None).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["kind"], "rate_limited");
    assert!(
        body["detail"]["retry_after"]
            .as_u64()
            .is_some_and(|s| (1..=60).contains(&s)),
        "the wait is stated: {body}"
    );

    // Somebody else's allowance is their own.
    api(
        &app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (status, body) = api(&app, "GET", "/api/repos/ada/demo", "bee", None).await;
    assert_ne!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");

    // The health check is never the thing that runs out: a monitor
    // polling it must not be locked out of saying the forge is up.
    for _ in 0..10 {
        let (status, _) = api(&app, "GET", "/healthz", "ada", None).await;
        assert_eq!(status, StatusCode::OK);
    }
}

/// What an owner is taking up, as the forge itself counts it.
async fn usage(forge: &Forge, owner: &str, field: &str) -> i64 {
    let (_, seen) = api(
        &forge.app,
        "GET",
        &format!("/api/principals/{owner}/quota"),
        "ada",
        None,
    )
    .await;
    seen["usage"][field].as_i64().unwrap_or(-1)
}

#[tokio::test(flavor = "multi_thread")]
async fn a_limit_on_having_is_not_a_limit_on_registering() {
    let forge = boot().await;
    let app = &forge.app;
    // Whatever the forge already has of ada's, plus room for two more.
    let start = usage(&forge, "ada", "agents").await;
    quota(&forge, "ada", json!({ "agents": start + 2 })).await;
    for id in ["one", "two"] {
        let (status, body) = api(
            app,
            "POST",
            "/api/principals",
            "ada",
            Some(json!({ "id": id, "kind": "agent", "display": id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    // Retiring frees the room, on purpose.
    for id in ["one", "two"] {
        api(
            app,
            "POST",
            &format!("/api/principals/{id}/state"),
            "ada",
            Some(json!({ "active": false })),
        )
        .await;
    }
    assert_eq!(usage(&forge, "ada", "agents").await, start);
    for id in ["three", "four"] {
        let (status, body) = api(
            app,
            "POST",
            "/api/principals",
            "ada",
            Some(json!({ "id": id, "kind": "agent", "display": id })),
        )
        .await;
        assert_eq!(status, StatusCode::OK, "{body}");
    }
    // Bringing the retired ones back would be four against a limit of
    // two, so the room has to be there for them as well.
    let (status, body) = api(
        app,
        "POST",
        "/api/principals/one/state",
        "ada",
        Some(json!({ "active": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["kind"], "over_quota");
    assert_eq!(usage(&forge, "ada", "agents").await, start + 2);
}

#[tokio::test(flavor = "multi_thread")]
async fn work_in_hand_counts_and_reopening_asks_again() {
    let forge = boot().await;
    let app = &forge.app;
    quota(&forge, "ada", json!({ "open_tasks": 1 })).await;
    let (status, task) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "First", "spec": "Do it" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{task}");
    let first = task["id"].as_str().unwrap().to_owned();

    // Claiming it does not put it down. A task somebody is working on
    // is more of a commitment than one nobody has picked up.
    api_with_token(
        app,
        "POST",
        &format!("/api/tasks/{first}/claim"),
        &forge.scout_token,
        None,
    )
    .await;
    assert_eq!(usage(&forge, "ada", "open_tasks").await, 1, "still held");
    let (status, body) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "Second", "spec": "And again" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // Finishing it frees the room, and taking it back up asks again.
    api(
        app,
        "POST",
        &format!("/api/tasks/{first}/state"),
        "ada",
        Some(json!({ "state": "abandoned" })),
    )
    .await;
    assert_eq!(usage(&forge, "ada", "open_tasks").await, 0);
    let (status, body) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "Second", "spec": "And again" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = api(
        app,
        "POST",
        &format!("/api/tasks/{first}/state"),
        "ada",
        Some(json!({ "state": "open" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["kind"], "over_quota");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_deleted_repositorys_work_stops_counting_against_nobody() {
    let forge = boot().await;
    let app = &forge.app;
    quota(&forge, "ada", json!({ "open_tasks": 2 })).await;
    for title in ["One", "Two"] {
        api(
            app,
            "POST",
            "/api/tasks",
            "ada",
            Some(json!({ "repo": "ada/demo", "title": title, "spec": "x" })),
        )
        .await;
    }
    assert_eq!(usage(&forge, "ada", "open_tasks").await, 2);

    // Deleting the repository must not turn its open work into work
    // that counts against nobody: make a repository, fill it with
    // tasks, delete it, repeat, and the limit means nothing.
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/ada/demo/delete",
        "ada",
        Some(json!({ "confirm": "ada/demo" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, tasks) = api(app, "GET", "/api/tasks", "ada", None).await;
    let still_open = tasks
        .as_array()
        .map(|all| all.iter().filter(|t| t["state"] == "open").count())
        .unwrap_or(0);
    assert_eq!(still_open, 0, "the work is over, not homeless: {tasks}");
}

#[tokio::test(flavor = "multi_thread")]
async fn ownership_moving_does_not_move_past_a_limit() {
    let forge = boot().await;
    let app = &forge.app;
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    // Bee is allowed one repository and already has it.
    api(
        app,
        "POST",
        "/api/repos",
        "bee",
        Some(json!({ "name": "theirs" })),
    )
    .await;
    quota(&forge, "bee", json!({ "repos": 1 })).await;

    api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer",
        "ada",
        Some(json!({ "to": "bee" })),
    )
    .await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer/accept",
        "bee",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["kind"], "over_quota");
    let (_, repo) = api(app, "GET", "/api/repos/ada/demo", "ada", None).await;
    assert_eq!(repo["owner"], "ada", "it stayed where it was");

    // With room, the same offer is taken up.
    quota(&forge, "bee", json!({ "repos": 2 })).await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos/ada/demo/transfer/accept",
        "bee",
        Some(json!({})),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn changing_one_limit_changes_one_limit() {
    let forge = boot().await;
    let app = &forge.app;
    let (_, before) = api(app, "GET", "/api/principals/ada/quota", "ada", None).await;
    assert_eq!(
        before["quota"], before["default"],
        "nothing said about ada yet"
    );

    // Tightening one thing must not quietly loosen the others. The
    // whole quota used to be replaced, so naming one field granted
    // unlimited everything else.
    quota(&forge, "ada", json!({ "repos": 5 })).await;
    let (_, after) = api(app, "GET", "/api/principals/ada/quota", "ada", None).await;
    assert_eq!(after["quota"]["repos"], 5);
    assert_eq!(
        after["quota"]["agents"], before["default"]["agents"],
        "the rest still follows the forge: {after}"
    );
    assert_eq!(after["quota"]["disk"], before["default"]["disk"]);
    assert_eq!(
        after["override"],
        json!({ "repos": 5 }),
        "and only what was said is remembered: {after}"
    );

    // Null is how you say no limit at all, and zero means zero.
    quota(&forge, "ada", json!({ "agents": null, "open_tasks": 0 })).await;
    let (_, after) = api(app, "GET", "/api/principals/ada/quota", "ada", None).await;
    assert!(after["quota"]["agents"].is_null(), "{after}");
    assert_eq!(after["quota"]["open_tasks"], 0);
    assert_eq!(after["quota"]["repos"], 5, "and the earlier one stands");
    let (status, body) = api(
        app,
        "POST",
        "/api/tasks",
        "ada",
        Some(json!({ "repo": "ada/demo", "title": "x", "spec": "y" })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "zero means zero: {body}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_misspelled_limit_is_refused_rather_than_granted() {
    let forge = boot().await;
    // Every field defaulting meant {"repo": 2} was a quota that said
    // nothing, which replaced the row with no limits at all — a typo
    // that removed every limit and answered 200.
    let status = post_raw(
        &forge.app,
        "/api/principals/ada/quota",
        json!({ "repo": 2 }),
    )
    .await;
    assert_ne!(status, StatusCode::OK, "a field nobody knows is a refusal");
    let (_, seen) = api(&forge.app, "GET", "/api/principals/ada/quota", "ada", None).await;
    assert_eq!(seen["quota"], seen["default"], "nothing changed: {seen}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refusal_that_somebody_else_can_lift_is_not_remembered() {
    let forge = boot().await;
    let app = &forge.app;
    quota(&forge, "ada", json!({ "repos": 1 })).await;
    let key = "the-same-intent";
    let (status, _, _) = call_keyed(app, "/api/repos", key, json!({ "name": "another" })).await;
    assert_eq!(status, StatusCode::CONFLICT);

    // The operator makes room. Retrying the same intent must do the
    // thing, not hand back the refusal it was given before.
    quota(&forge, "ada", json!({ "repos": 2 })).await;
    let (status, _, body) = call_keyed(app, "/api/repos", key, json!({ "name": "another" })).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}
