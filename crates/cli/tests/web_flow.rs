//! The web UI end to end over real HTTP: cookie auth, page rendering,
//! escaping of hostile content, the verdict form, and an enqueue that
//! the landing train completes while the browser watches.

mod common;
use common::*;

use axum::Router;
use axum::http::StatusCode;
use serde_json::json;

/// A minimal browser: one cookie jar, no redirect following, so each
/// hop is asserted explicitly.
struct Browser {
    agent: ureq::Agent,
    base: String,
    jar: std::collections::BTreeMap<String, String>,
}

impl Browser {
    fn new(base: String) -> Self {
        let config = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .max_redirects(0)
            .build();
        Browser {
            agent: config.into(),
            base,
            jar: std::collections::BTreeMap::new(),
        }
    }

    fn cookie_header(&self) -> Option<String> {
        if self.jar.is_empty() {
            return None;
        }
        Some(
            self.jar
                .iter()
                .map(|(name, value)| format!("{name}={value}"))
                .collect::<Vec<_>>()
                .join("; "),
        )
    }

    fn remember(&mut self, response: &http::response::Parts) {
        for set in response.headers.get_all("set-cookie") {
            let Ok(text) = set.to_str() else { continue };
            let Some((pair, _)) = text.split_once(';') else {
                continue;
            };
            let Some((name, value)) = pair.split_once('=') else {
                continue;
            };
            if value.is_empty() {
                self.jar.remove(name);
            } else {
                self.jar.insert(name.to_owned(), value.to_owned());
            }
        }
    }

    fn get(&self, path: &str) -> (u16, String, Option<String>) {
        let mut request = self.agent.get(format!("{}{path}", self.base));
        if let Some(cookie) = self.cookie_header() {
            request = request.header("cookie", cookie);
        }
        let mut response = request.call().unwrap();
        let location = response
            .headers()
            .get("location")
            .map(|v| v.to_str().unwrap().to_owned());
        let status = response.status().as_u16();
        let body = response.body_mut().read_to_string().unwrap_or_default();
        (status, body, location)
    }

    fn post_form(&mut self, path: &str, fields: &[(&str, &str)]) -> (u16, Option<String>) {
        let mut request = self.agent.post(format!("{}{path}", self.base));
        if let Some(cookie) = self.cookie_header() {
            request = request.header("cookie", cookie);
        }
        let response = request.send_form(fields.iter().copied()).unwrap();
        let (parts, _) = response.into_parts();
        self.remember(&parts);
        (
            parts.status.as_u16(),
            parts
                .headers
                .get("location")
                .map(|v| v.to_str().unwrap().to_owned()),
        )
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn web_ui_full_journey() {
    let forge = boot().await;
    let base = format!("http://{}", forge.addr);
    let app: &Router = &forge.app;

    // Signed out, every page is one redirect from the door.
    let mut browser = Browser::new(base.clone());
    let (status, _, location) = browser.get("/demo");
    assert_eq!(status, 303);
    assert_eq!(location.as_deref(), Some("/login"));
    let (_, body, _) = browser.get("/login");
    assert!(body.contains("API token"));

    // A bad token bounces with a message; a real one signs in.
    let (_, location) = browser.post_form("/login", &[("token", "cairn_bogus")]);
    assert!(location.unwrap().contains("error="));
    assert!(
        browser.jar.is_empty(),
        "a rejected token must not sign anyone in"
    );
    let scout_token = forge.scout_token.clone();
    let (status, _) = browser.post_form("/login", &[("token", &scout_token)]);
    assert_eq!(status, 303);
    assert!(browser.jar.contains_key("cairn_token"));

    // Dev mode also accepts an asserted principal; ada browses as human.
    let mut ada = Browser::new(base.clone());
    ada.post_form("/login", &[("principal", "ada")]);
    assert!(ada.jar.contains_key("cairn_dev"));

    // Home redirects into the only repo; the tree is empty pre-merge.
    let (status, _, location) = ada.get("/");
    assert_eq!(status, 303);
    assert_eq!(location.as_deref(), Some("/demo"));
    let (_, body, _) = ada.get("/demo");
    assert!(body.contains("Empty repository"));

    // Push a change whose title is actively hostile.
    git(
        &forge.work,
        &[
            "clone",
            &format!("http://scout:x@{}/git/demo", forge.addr),
            "wc",
        ],
    );
    let wc = forge.work.join("wc");
    commit_file(
        &wc,
        "greeting.txt",
        "hello\n",
        "<script>alert('xss')</script>\n\nChange-Id: Iweb01",
    );
    git(&wc, &["push", "origin", "HEAD:refs/for/main"]);

    // The list and the change page render it inert.
    let (_, body, _) = ada.get("/demo/changes");
    assert!(body.contains("&lt;script&gt;"));
    assert!(!body.contains("<script>alert"));
    let (_, body, _) = ada.get("/demo/changes/1");
    assert!(body.contains("Not ready"));
    assert!(body.contains("passing test claim"));
    assert!(body.contains("greeting.txt"), "diff should show the file");

    // Judgment through the form; the claim arrives over the API.
    let (status, _) = ada.post_form(
        "/demo/changes/1/verdict",
        &[
            ("revision", "1"),
            ("domain", "correctness"),
            ("disposition", "approve"),
            ("rationale", "Readable and inert."),
        ],
    );
    assert_eq!(status, 303);
    let (_, body, _) = ada.get("/demo/changes/1");
    assert!(body.contains("Readable and inert."));
    let (status, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
    assert_eq!(status, StatusCode::OK);
    let change_id = changes[0]["id"].as_str().unwrap().to_owned();
    let (status, _) = api(
        app,
        "POST",
        &format!("/api/changes/{change_id}/claims"),
        "scout",
        Some(json!({ "kind": "test", "passed": true, "summary": "renders escaped" })),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Ready — enqueue from the page, and the train lands it.
    let (_, body, _) = ada.get("/demo/changes/1");
    assert!(body.contains("Ready"));
    let (status, _) = ada.post_form("/demo/changes/1/enqueue", &[]);
    assert_eq!(status, 303);
    wait_for(app, "the enqueued change to land", async |app: &Router| {
        let (_, changes) = api(app, "GET", "/api/repos/demo/changes", "ada", None).await;
        changes[0]["state"] == "merged"
    })
    .await;

    // The whole app agrees: change merged, landing tells the story,
    // the tree now exists, and the file renders escaped.
    let (_, body, _) = ada.get("/demo/changes/1");
    assert!(body.contains("merged"));
    let (_, body, _) = ada.get("/demo/landing");
    assert!(body.contains("landed"));
    let (_, body, _) = ada.get("/demo");
    assert!(body.contains("greeting.txt"));
    assert!(!body.contains("Empty repository"));
    let (_, body, _) = ada.get("/demo/tree/greeting.txt");
    assert!(body.contains("hello"));
    let (_, body, _) = ada.get("/demo/log");
    assert!(body.contains("change_merged"));

    // Unknown paths are a page, not a stack trace.
    let (status, _, _) = ada.get("/demo/changes/999");
    assert_eq!(status, 404);
    let (status, _, _) = ada.get("/nosuchrepo");
    assert_eq!(status, 404);

    // Dark is what a fresh viewer gets; the toggle switches and sticks.
    let (_, body, _) = ada.get("/demo");
    assert!(
        body.contains(r#"data-theme="dark""#),
        "dark must be the default palette"
    );
    assert!(
        body.contains(">Light<"),
        "the switch offers the other palette"
    );
    let (status, _) = ada.post_form("/theme", &[("to", "light"), ("back", "/demo")]);
    assert_eq!(status, 303);
    let (_, body, _) = ada.get("/demo");
    assert!(
        body.contains(r#"data-theme="light""#),
        "the choice must persist"
    );
    assert!(body.contains(">Dark<"));
    ada.post_form("/theme", &[("to", "dark"), ("back", "/demo")]);

    // The file view numbers its lines and names the change that landed it.
    let (_, body, _) = ada.get("/demo/tree/greeting.txt");
    assert!(body.contains("1 lines") || body.contains("2 lines"));
    assert!(
        body.contains("last landed by"),
        "a file should link to its change"
    );
    assert!(body.contains(r#"class="cline""#), "lines are numbered rows");

    // Sign out kills the cookie path.
    let (status, _) = ada.post_form("/logout", &[]);
    assert_eq!(status, 303);
    let signed_out = Browser::new(base);
    let (status, _, location) = signed_out.get("/demo");
    assert_eq!(status, 303);
    assert_eq!(location.as_deref(), Some("/login"));
}
