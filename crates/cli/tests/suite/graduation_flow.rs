//! Leaving with everything: an owner's repositories go out as bundles
//! with a manifest, and another forge takes them in whole — branches
//! recorded as imported history, tags entered into its graph, receipt
//! notes as they are — and is clean by its own fsck afterwards.

use crate::common::*;
use ambolt_core::PrincipalId;
use ambolt_git::GitStore;
use axum::http::StatusCode;
use serde_json::json;

#[tokio::test(flavor = "multi_thread")]
async fn an_owner_leaves_with_bundles_and_another_forge_takes_them_in() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    // History with a landed change, so the bundle carries a receipt note
    // and a change ref, not only a branch.
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
    commit_file(
        &wc,
        "hello.txt",
        "hello\n",
        "Say hello\n\nChange-Id: Ihello",
    );
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    let change = changes[0]["id"].as_str().unwrap().to_owned();
    api(
        app,
        "POST",
        &format!("/api/changes/{change}/claims"),
        "scout",
        Some(json!({ "kind": "test", "passed": true, "summary": "hello", "command": "true" })),
    )
    .await;
    approve_and_merge(app, &change).await;
    // A tag on the landed commit, so the bundle carries one.
    git(&wc, &["fetch", "-q", "origin", "main"]);
    git(
        &wc,
        &[
            "tag",
            "-a",
            "v1",
            "-m",
            "First named landing",
            "origin/main",
        ],
    );
    let ada_url = format!("http://ada:{}@{addr}/git/ada/demo", forge.ada_token);
    git(&wc, &["push", "-q", &ada_url, "refs/tags/v1"]);
    let (_, _) = api(
        app,
        "POST",
        "/api/repos/ada/demo/description",
        "ada",
        Some(json!({ "description": "A demonstration" })),
    )
    .await;

    // Out: the manifest and the bundle, as `ambolt admin export` writes them.
    let manifest = forge
        .state
        .graduation(&PrincipalId::new("ada").unwrap())
        .unwrap();
    assert_eq!(manifest.version, 1);
    assert_eq!(manifest.repos.len(), 1, "{manifest:?}");
    assert_eq!(manifest.repos[0].name, "ada/demo");
    assert_eq!(manifest.repos[0].bundle, "bundles/demo.bundle");
    let out = forge.work.join("out");
    let git_store = GitStore::new(
        forge._tmp.path().join("repos"),
        env!("CARGO_BIN_EXE_ambolt"),
    );
    git_store
        .bundle("ada/demo", &out.join("bundles/demo.bundle"))
        .await
        .unwrap();
    let listed = std::process::Command::new("git")
        .args([
            "bundle",
            "list-heads",
            out.join("bundles/demo.bundle").to_str().unwrap(),
        ])
        .output()
        .unwrap();
    let heads = String::from_utf8_lossy(&listed.stdout).into_owned();
    assert!(heads.contains("refs/heads/main"), "{heads}");
    assert!(heads.contains("refs/tags/v1"), "the tag travels: {heads}");
    assert!(
        heads.contains("refs/notes/ambolt"),
        "the receipts travel: {heads}"
    );
    assert!(
        heads.contains("refs/changes/1/1"),
        "and the change refs, for whoever reads the bundle: {heads}"
    );

    // In: another owner on this forge (as another forge would), made
    // by the operator, taking everything from the bundle.
    api(
        app,
        "POST",
        "/api/principals",
        "ada",
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    let (status, body) = api(
        app,
        "POST",
        "/api/repos",
        "ada",
        Some(json!({ "name": "demo", "owner": "bee" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let source = format!("file://{}", out.join("bundles/demo.bundle").display());
    let (status, taken) = api(
        app,
        "POST",
        "/api/repos/bee/demo/import",
        "ada",
        Some(json!({ "source": source, "everything": true })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{taken}");
    assert_eq!(taken["branches"][0]["branch"], "main", "{taken}");
    assert!(taken["branches"][0]["commits"].as_i64().unwrap() >= 1);
    assert_eq!(taken["tags"][0]["tag"], "v1", "{taken}");
    assert_eq!(taken["left_behind"], json!([]), "{taken}");
    // What arrived: the branch, the note on its tip, the tag in the
    // graph as well as in git; not the other forge's change refs.
    let (_, tags) = api(app, "GET", "/api/repos/bee/demo/tags", "bee", None).await;
    assert_eq!(tags[0]["name"], "v1", "{tags}");
    assert_eq!(tags[0]["message"], "First named landing", "{tags}");
    let bare = forge._tmp.path().join("repos/bee/demo.git");
    let refs = std::process::Command::new("git")
        .args([
            "-C",
            bare.to_str().unwrap(),
            "for-each-ref",
            "--format=%(refname)",
        ])
        .output()
        .unwrap();
    let refs = String::from_utf8_lossy(&refs.stdout).into_owned();
    assert!(refs.contains("refs/heads/main"), "{refs}");
    assert!(refs.contains("refs/tags/v1"), "{refs}");
    assert!(refs.contains("refs/notes/ambolt"), "{refs}");
    assert!(
        !refs.contains("refs/changes/"),
        "the source's change refs stay with its log: {refs}"
    );
    assert!(
        !refs.contains("refs/import"),
        "nothing half-done lingers: {refs}"
    );
    // And the destination is clean by its own fsck: every tag in git
    // is a tag in its graph.
    let divergences = forge.state.fsck().expect("fsck runs");
    assert!(divergences.is_empty(), "{divergences:?}");
    // Everything is what a repository begins with: not again.
    let (status, again) = api(
        app,
        "POST",
        "/api/repos/bee/demo/import",
        "ada",
        Some(json!({ "source": source, "everything": true })),
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{again}");
    let (_, debt) = api(app, "GET", "/api/repos/bee/demo/debt", "ada", None).await;
    assert!(
        debt["counts"]["imported"].as_i64().unwrap_or(0) >= 1,
        "the branch is recorded as imported history: {debt}"
    );
    let (status, page) = api(app, "GET", "/api/repos/bee/demo", "bee", None).await;
    assert_eq!(status, StatusCode::OK, "{page}");
}

/// Importing is the operator's: a local path reads the box's own
/// files, and any source has the forge dialling out on a say-so.
#[tokio::test(flavor = "multi_thread")]
async fn a_local_source_is_the_operators_to_give() {
    let forge = boot_token_only().await;
    let app = &forge.app;
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (_, minted) = api_with_token(
        app,
        "POST",
        "/api/principals/bee/tokens",
        &forge.ada_token,
        Some(json!({ "label": "bee" })),
    )
    .await;
    let bee = minted["token"].as_str().unwrap().to_owned();
    let (status, body) = api_with_token(
        app,
        "POST",
        "/api/repos",
        &bee,
        Some(json!({ "name": "mine" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // An owner is refused before the source is even looked at: the
    // forge dials out for whoever runs it, not for whoever owns the
    // repository, so the same is true of an https source.
    let nowhere = json!({ "source": "file:///nowhere/at/all.bundle", "everything": true });
    for source in [
        nowhere.clone(),
        json!({ "source": "https://example.test/x.git", "branch": "main" }),
    ] {
        let (status, refused) = api_with_token(
            app,
            "POST",
            "/api/repos/bee/mine/import",
            &bee,
            Some(source),
        )
        .await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{refused}");
        assert!(
            refused["error"]
                .as_str()
                .unwrap_or_default()
                .contains("operator"),
            "{refused}"
        );
    }
    // The operator's is let through the check and fails only at the
    // fetch, since nothing is there.
    let (status, answer) = api_with_token(
        app,
        "POST",
        "/api/repos/bee/mine/import",
        &forge.ada_token,
        Some(nowhere),
    )
    .await;
    assert_ne!(status, StatusCode::BAD_REQUEST, "{answer}");
}
