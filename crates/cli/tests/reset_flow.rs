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

    // Ada records an address; the page keeps it beside her credentials.
    let (status, location) = post_form(
        app,
        "/you/settings/email",
        &cookie,
        "email=ada%40example.org",
    )
    .await;
    assert_eq!(status, StatusCode::SEE_OTHER, "{location}");
    assert_eq!(location, "/you/settings?done=1");
    let (_, settings) = page_with_cookie(app, "/you/settings", &cookie).await;
    assert!(settings.contains(r#"value="ada@example.org""#));

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
async fn a_forge_that_cannot_send_mail_says_so() {
    let forge = boot().await;
    let app = &forge.app;
    let (status, page) = page_with_cookie(app, "/forgot", "").await;
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("cannot send mail"), "{page}");
    let (_, location) = post_form(app, "/forgot", "", "who=ada").await;
    assert!(location.contains("cannot+send+mail"), "{location}");
}
