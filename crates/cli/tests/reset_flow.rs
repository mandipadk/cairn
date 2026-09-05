//! Forgetting a password is recoverable without a terminal: an address on
//! record, a link that works once, and the same answer to everyone who
//! asks, whether or not the forge knows them.

mod common;

use axum::http::StatusCode;
use common::*;

fn link_in(mail: &str) -> String {
    let start = mail.find("http").expect("a link in the mail");
    let end = mail[start..]
        .find(char::is_whitespace)
        .map_or(mail.len(), |i| start + i);
    mail[start..end].to_owned()
}

fn path_of(link: &str) -> String {
    let after = link.split_once("://").map_or(link, |(_, rest)| rest);
    after
        .find('/')
        .map_or("/".to_owned(), |i| after[i..].to_owned())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_reset_link_arrives_by_mail_and_works_exactly_once() {
    let outbox = tempfile::tempdir().unwrap();
    let mail_file = outbox.path().join("mail.txt");
    let forge = boot_mailing(&format!("cat > '{}'", mail_file.display())).await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;

    // No address on record: nothing is sent, and the answer is the same.
    let (status, location) = post_form(app, "/forgot", "", "who=ada").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/forgot?done=1");
    assert!(!mail_file.exists(), "nothing to send to");

    // Ada gives an address; it is pending until she follows the link,
    // and a pending address gets no reset.
    let (status, location) = post_form(
        app,
        "/you/settings/email",
        &cookie,
        "email=ada%40example.org",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert_eq!(location, "/you/settings?sent=1");
    let (_, settings) = page_with_cookie(app, "/you/settings", &cookie).await;
    assert!(
        settings.contains("ada@example.org — awaiting confirmation"),
        "{settings}"
    );
    let confirm = std::fs::read_to_string(&mail_file).unwrap();
    assert!(
        confirm.contains("Subject: Confirm your address on cairn"),
        "{confirm}"
    );
    std::fs::remove_file(&mail_file).unwrap();
    let (_, location) = post_form(app, "/forgot", "", "who=ada%40example.org").await;
    assert_eq!(location, "/forgot?done=1");
    assert!(!mail_file.exists(), "no reset to an unconfirmed address");
    let (status, location) = get_redirect(app, &path_of(&link_in(&confirm)), &cookie).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert_eq!(location, "/you/settings?done=1");
    let (_, settings) = page_with_cookie(app, "/you/settings", &cookie).await;
    assert!(
        settings.contains("ada@example.org — confirmed"),
        "{settings}"
    );

    // Asking by address or by name sends a link; a stranger's name does not.
    let (_, location) = post_form(app, "/forgot", "", "who=ada%40example.org").await;
    assert_eq!(location, "/forgot?done=1");
    let mail = std::fs::read_to_string(&mail_file).expect("a mail was written");
    assert!(
        mail.starts_with("From: cairn@forge.example\r\nTo: ada@example.org\r\n"),
        "{mail}"
    );
    assert!(mail.contains("Subject: Reset your cairn password"));
    let link = link_in(&mail);
    assert!(link.contains("/reset?token="), "{link}");
    std::fs::remove_file(&mail_file).unwrap();
    let (_, location) = post_form(app, "/forgot", "", "who=nobody").await;
    assert_eq!(
        location, "/forgot?done=1",
        "the same answer for a name nobody has"
    );
    assert!(!mail_file.exists());

    // The link opens the form; a mismatched pair is refused without
    // spending the link; a proper pair sets the password and signs out.
    let path = path_of(&link);
    let (status, page) = page_with_cookie(app, &path, "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Choose a new password"), "{page}");
    let token = path.split_once("token=").unwrap().1.to_owned();
    let (_, location) = post_form(
        app,
        "/reset",
        "",
        &format!("token={token}&password=a+brand+new+password&confirm=different"),
    )
    .await;
    assert!(location.contains("error="), "{location}");
    let (status, location) = post_form(
        app,
        "/reset",
        "",
        &format!("token={token}&password=a+brand+new+password&confirm=a+brand+new+password"),
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.starts_with("/login?"), "{location}");
    assert_eq!(redirect_of(app, "ada", "a brand new password").await, "/");
    assert_eq!(
        get_with_cookie(app, "/you/settings", &cookie).await,
        StatusCode::SEE_OTHER,
        "old sessions are gone"
    );

    // Spent.
    let (_, location) = post_form(
        app,
        "/reset",
        "",
        &format!("token={token}&password=another+long+password&confirm=another+long+password"),
    )
    .await;
    assert!(location.starts_with("/forgot?error="), "{location}");
}

#[tokio::test(flavor = "multi_thread")]
async fn without_mail_the_request_reaches_whoever_runs_the_forge() {
    let forge = boot().await;
    let app = &forge.app;
    api_with_token(
        app,
        "POST",
        "/api/principals",
        &forge.ada_token,
        Some(serde_json::json!({ "id": "bee", "kind": "human", "display": "Bee" })),
    )
    .await;

    let (status, page) = page_with_cookie(app, "/forgot", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("Ask for a new link"), "{page}");
    let (_, location) = post_form(app, "/forgot", "", "who=bee").await;
    assert_eq!(location, "/forgot?done=1");
    let (_, page) = page_with_cookie(app, "/forgot?done=1", "").await;
    assert!(page.contains("have been told"), "{page}");

    // Ada, who runs the forge, is told and can act from People.
    let (_, ada) = sign_in_as(&forge, "ada").await;
    let (_, inbox) = page_with_cookie(app, "/inbox", &ada).await;
    assert!(
        inbox.contains("bee cannot sign in and asked for a new link"),
        "{inbox}"
    );
    assert!(inbox.contains(r#"href="/people""#));
    let (status, location) = post_form(app, "/people", &ada, "action=relink&id=bee").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.starts_with("/people?once="), "{location}");

    // A name nobody has, or an agent's, gets the same answer and tells nobody new.
    let (_, location) = post_form(app, "/forgot", "", "who=nobody").await;
    assert_eq!(location, "/forgot?done=1");
    let (_, location) = post_form(app, "/forgot", "", "who=scout").await;
    assert_eq!(location, "/forgot?done=1");
}

#[tokio::test(flavor = "multi_thread")]
async fn an_invitation_goes_by_mail_when_the_forge_can_send_it() {
    let outbox = tempfile::tempdir().unwrap();
    let mail_file = outbox.path().join("mail.txt");
    let forge = boot_mailing(&format!("cat > '{}'", mail_file.display())).await;
    let app = &forge.app;
    let (_, ada) = sign_in_as(&forge, "ada").await;

    let (status, location) = post_form(
        app,
        "/people",
        &ada,
        "action=register&id=bee&display=Bee&email=bee%40example.org",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert!(location.starts_with("/people?once="), "{location}");
    let mail = std::fs::read_to_string(&mail_file).unwrap();
    assert!(mail.contains("To: bee@example.org"), "{mail}");
    assert!(mail.contains("/join?token="), "{mail}");
    let (_, page) = page_with_cookie(app, &location, &ada).await;
    assert!(page.contains("Sent to bee@example.org"), "{page}");
    assert!(page.contains("email pending"), "{page}");

    // Following the mailed invitation proves the address.
    let link = link_in(&mail);
    let (status, _) = get_redirect(app, &path_of(&link), "").await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    let (_, page) = page_with_cookie(app, "/people", &ada).await;
    assert!(page.contains("email confirmed"), "{page}");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_sign_in_link_signs_you_in_once_and_only_to_a_confirmed_address() {
    let outbox = tempfile::tempdir().unwrap();
    let mail_file = outbox.path().join("mail.txt");
    let forge = boot_mailing(&format!("cat > '{}'", mail_file.display())).await;
    let app = &forge.app;
    let (_, cookie) = sign_in_as(&forge, "ada").await;

    // No confirmed address yet: the same answer, and no mail.
    let (_, location) = post_form(app, "/login/link", "", "who=ada").await;
    assert_eq!(location, "/login?sent=1");
    assert!(!mail_file.exists());

    // Confirm an address, then ask again.
    post_form(
        app,
        "/you/settings/email",
        &cookie,
        "email=ada%40example.org",
    )
    .await;
    let confirm = std::fs::read_to_string(&mail_file).unwrap();
    std::fs::remove_file(&mail_file).unwrap();
    get_redirect(app, &path_of(&link_in(&confirm)), &cookie).await;
    let (_, location) = post_form(app, "/login/link", "", "who=ada%40example.org").await;
    assert_eq!(location, "/login?sent=1");
    let mail = std::fs::read_to_string(&mail_file).expect("a sign-in link was mailed");
    assert!(mail.contains("Subject: Your cairn sign-in link"), "{mail}");
    let path = path_of(&link_in(&mail));
    assert!(path.starts_with("/signin?token="), "{path}");

    // Following it signs in; following it again does not.
    let response = tower::ServiceExt::oneshot(
        app.clone(),
        axum::http::Request::builder()
            .uri(&path)
            .body(axum::body::Body::empty())
            .unwrap(),
    )
    .await
    .unwrap();
    assert_eq!(response.status(), StatusCode::SEE_OTHER);
    assert_eq!(response.headers()["location"], "/");
    let session = response.headers()["set-cookie"]
        .to_str()
        .unwrap()
        .split(';')
        .next()
        .unwrap()
        .to_owned();
    assert_eq!(
        get_with_cookie(app, "/you/settings", &session).await,
        StatusCode::OK
    );
    let (_, location) = get_redirect(app, &path, "").await;
    assert!(location.starts_with("/login?error="), "{location}");
}
