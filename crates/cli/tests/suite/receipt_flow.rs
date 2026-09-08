//! Merge receipts: a landing's evidence, signed by the forge, written on
//! the commit, and checkable without the forge.

use crate::common::*;

use axum::http::StatusCode;
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;

fn verify(file: &Path, key: Option<&str>) -> (bool, String) {
    let mut command = Command::new(env!("CARGO_BIN_EXE_cairn"));
    command.args(["receipt", "verify", file.to_str().unwrap()]);
    if let Some(key) = key {
        command.args(["--key", key]);
    }
    let output = command.output().expect("run cairn receipt verify");
    (
        output.status.success(),
        format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        ),
    )
}

#[tokio::test(flavor = "multi_thread")]
async fn a_landing_leaves_a_signed_receipt_on_the_commit() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/ada/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "docs/a.md", "# A\n", "Write A\n\nChange-Id: Ireceipt");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    let id = changes[0]["id"].as_str().unwrap().to_owned();

    // Nothing to certify until it lands.
    let (status, body) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/receipt"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["kind"], "not_landed");

    approve_and_enqueue(app, &id).await;
    wait_for(app, "the change to land", async |app: &axum::Router| {
        let (_, c) = api(app, "GET", &format!("/api/changes/{id}"), "ada", None).await;
        c["state"] == "merged"
    })
    .await;

    let (status, signed) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/receipt"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    let receipt = &signed["receipt"];
    assert_eq!(receipt["repo"], "ada/demo");
    assert_eq!(receipt["change"]["id"], id);
    assert_eq!(receipt["change"]["number"], 1);
    assert_eq!(receipt["trace"]["satisfied"], true, "{receipt}");
    assert_eq!(receipt["claims"].as_array().unwrap().len(), 1);
    assert_eq!(receipt["verdicts"].as_array().unwrap().len(), 1);
    assert_eq!(receipt["merged_by"], "ada");
    assert_eq!(
        receipt["revision"]["paths"],
        json!(["docs/a.md"]),
        "the revision carries what the commit touched"
    );
    assert_eq!(signed["signature"]["alg"], "ed25519");
    assert_eq!(signed["canonical"], "json:sorted-keys,compact,utf-8");

    // The key the receipt names is the key the forge publishes, to anyone.
    let (status, key) = api_anonymous(app, "GET", "/api/forge/key", None).await;
    assert_eq!(status, StatusCode::OK, "{key}");
    assert_eq!(key["key"], signed["signature"]["key"]);
    assert_eq!(key["public_key"], signed["signature"]["public_key"]);
    let fingerprint = key["key"].as_str().unwrap().to_owned();

    // Checkable offline, by the client alone.
    let file = forge.work.join("receipt.json");
    std::fs::write(&file, serde_json::to_string_pretty(&signed).unwrap()).unwrap();
    let (ok, said) = verify(&file, None);
    assert!(ok, "{said}");
    assert!(said.contains("verified · ada/demo #1 landed as"), "{said}");
    assert!(said.contains("policy satisfied"), "{said}");
    let (ok, _) = verify(&file, Some(&fingerprint));
    assert!(ok, "the expected key is the signing key");
    let (ok, said) = verify(&file, Some("deadbeefdeadbeef"));
    assert!(!ok && said.contains("not the expected"), "{said}");

    // One changed character and the signature no longer holds.
    let mut tampered = signed.clone();
    tampered["receipt"]["change"]["title"] = json!("Something else entirely");
    let forged = forge.work.join("forged.json");
    std::fs::write(&forged, serde_json::to_string_pretty(&tampered).unwrap()).unwrap();
    let (ok, said) = verify(&forged, None);
    assert!(!ok && said.contains("does not match"), "{said}");

    // The same document sits on the commit as a note, and travels.
    let landed = receipt["landed_as"].as_str().unwrap().to_owned();
    let bare = forge._tmp.path().join("repos/ada/demo.git");
    wait_for(app, "the note to be written", async |_: &axum::Router| {
        git_raw(&bare, &["notes", "--ref=refs/notes/cairn", "show", &landed])
            .status
            .success()
    })
    .await;
    let note = git(&bare, &["notes", "--ref=refs/notes/cairn", "show", &landed]);
    let noted: Value = serde_json::from_str(note.trim()).expect("the note is the receipt");
    assert_eq!(noted["receipt"]["change"]["id"], id);
    assert_eq!(
        noted["signature"]["value"], signed["signature"]["value"],
        "the same body under the same key signs the same way"
    );

    // The audit, as a query.
    let (status, list) = api(
        app,
        "GET",
        "/api/repos/ada/demo/receipts?limit=5",
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{list}");
    assert_eq!(list["receipts"].as_array().unwrap().len(), 1);
    assert_eq!(list["receipts"][0]["receipt"]["change"]["id"], id);
    assert!(list["next_before"].is_null());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_direct_merge_is_receipted_too() {
    let forge = boot().await;
    let (app, addr) = (&forge.app, forge.addr);
    git(
        &forge.work,
        &[
            "clone",
            "-q",
            &format!("http://scout:x@{addr}/git/ada/demo"),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(&wc, "b.txt", "b\n", "Add b\n\nChange-Id: Idirect");
    git(&wc, &["push", "-q", "origin", "HEAD:refs/for/main"]);
    let (_, changes) = api(app, "GET", "/api/repos/ada/demo/changes", "ada", None).await;
    let id = changes[0]["id"].as_str().unwrap().to_owned();
    approve_and_merge(app, &id).await;

    let (status, signed) = api(
        app,
        "GET",
        &format!("/api/changes/{id}/receipt"),
        "ada",
        None,
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{signed}");
    let landed = signed["receipt"]["landed_as"].as_str().unwrap().to_owned();
    let bare = forge._tmp.path().join("repos/ada/demo.git");
    let note = git(&bare, &["notes", "--ref=refs/notes/cairn", "show", &landed]);
    let noted: Value = serde_json::from_str(note.trim()).unwrap();
    assert_eq!(
        noted["receipt"]["landed_as"], landed,
        "note: {noted}\nserved: {signed}"
    );
}
