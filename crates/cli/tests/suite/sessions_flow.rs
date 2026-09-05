//! Where you are signed in is yours to see and to end, one at a time or
//! all at once but this one.

use crate::common::*;
use axum::http::StatusCode;

#[tokio::test(flavor = "multi_thread")]
async fn sessions_are_listed_and_ended_from_settings() {
    let forge = boot().await;
    let app = &forge.app;
    // sign_in_as sets the password, which ends every session by design;
    // further sessions sign in with the password it set.
    const PASSWORD: &str = "a perfectly ordinary password";
    let (_, laptop) = sign_in_as(&forge, "ada").await;
    let phone = sign_in(app, "ada", PASSWORD).await.1.unwrap();

    let (status, page) = page_with_cookie(app, "/you/sessions", &laptop).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(page.matches("this session").count(), 1, "{page}");
    assert_eq!(
        page.matches(r#"name="id""#).count(),
        1,
        "one other session to end"
    );

    // Ending the other one by id signs the phone out and nothing else.
    let id = page
        .split(r#"name="id" value=""#)
        .nth(1)
        .and_then(|rest| rest.split('"').next())
        .expect("a session id")
        .to_owned();
    let (status, location) = post_form(app, "/you/sessions", &laptop, &format!("id={id}")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location, "/you/sessions?done=1");
    assert_eq!(
        get_with_cookie(app, "/you/settings", &phone).await,
        StatusCode::SEE_OTHER,
        "phone is out"
    );
    assert_eq!(
        get_with_cookie(app, "/you/settings", &laptop).await,
        StatusCode::OK,
        "laptop stays"
    );

    // Everywhere else: two more sign-ins, then only this one remains.
    let tablet = sign_in(app, "ada", PASSWORD).await.1.unwrap();
    let work = sign_in(app, "ada", PASSWORD).await.1.unwrap();
    post_form(app, "/you/sessions", &laptop, "others=1").await;
    assert_eq!(
        get_with_cookie(app, "/you/settings", &tablet).await,
        StatusCode::SEE_OTHER
    );
    assert_eq!(
        get_with_cookie(app, "/you/settings", &work).await,
        StatusCode::SEE_OTHER
    );
    let (_, page) = page_with_cookie(app, "/you/sessions", &laptop).await;
    assert_eq!(page.matches(r#"name="id""#).count(), 0, "{page}");

    // Somebody else's id is not yours to end.
    let (_, bee_cookie) = {
        api_with_token(
            app,
            "POST",
            "/api/principals",
            &forge.ada_token,
            Some(serde_json::json!({ "id": "bee", "kind": "human", "display": "Bee" })),
        )
        .await;
        sign_in_as(&forge, "bee").await
    };
    let (_, bee_page) = page_with_cookie(app, "/you/sessions", &bee_cookie).await;
    assert!(bee_page.contains("this session"));
    let (_, location) = post_form(app, "/you/sessions", &bee_cookie, &format!("id={id}")).await;
    assert_eq!(
        location, "/you/sessions?done=1",
        "answers the same, ends nothing of ada's"
    );
    assert_eq!(
        get_with_cookie(app, "/you/settings", &laptop).await,
        StatusCode::OK
    );
}
