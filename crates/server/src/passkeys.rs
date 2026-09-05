//! Passkeys: sign in with the device you are holding.
//!
//! WebAuthn binds a credential to an origin, so this exists only when the
//! forge knows its public URL. The browser talks to four JSON endpoints;
//! the in-flight ceremony state is parked in the store under an id the
//! browser hands back, so any process can finish what another started.
//! The credentials themselves are opaque JSON to the core: this module
//! is the only code that reads them.

use crate::state::AppState;
use crate::web::Viewer;
use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use serde_json::json;
use webauthn_rs::prelude::*;

/// Build the relying party from the forge's public URL. The rp_id is the
/// host, which every credential binds to, so it cannot change later
/// without orphaning every passkey - which is why it comes from
/// configuration and not from a request header.
pub fn relying_party(public_url: &str) -> Result<Webauthn, String> {
    let origin = Url::parse(public_url).map_err(|e| format!("public URL: {e}"))?;
    let host = origin
        .host_str()
        .ok_or("public URL has no host")?
        .to_owned();
    WebauthnBuilder::new(&host, &origin)
        .map_err(|e| format!("cannot build the relying party: {e}"))?
        .rp_name("cairn")
        .build()
        .map_err(|e| format!("cannot build the relying party: {e}"))
}

fn bad(what: &str) -> Response {
    (StatusCode::BAD_REQUEST, Json(json!({ "error": what }))).into_response()
}

fn off() -> Response {
    (
        StatusCode::NOT_FOUND,
        Json(json!({ "error": "passkeys are not configured on this forge" })),
    )
        .into_response()
}

fn cred_id_string(id: &CredentialID) -> String {
    use base64::Engine;
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(id.as_ref())
}

/// Start registering a passkey for the signed-in person.
pub async fn register_begin(State(app): State<AppState>, viewer: Viewer) -> Response {
    let Some(webauthn) = app.webauthn() else {
        return off();
    };
    let who = viewer.0.clone();
    let user_id = match app.with_store(|s| s.passkey_user_id(&who)) {
        Ok(id) => id,
        Err(err) => return crate::web::oops(err),
    };
    let uuid = uuid_from(&user_id);
    // Credentials already registered are excluded, so a device cannot be
    // enrolled twice by accident.
    let existing: Vec<CredentialID> = app
        .with_store(|s| s.passkey_json_of(&who))
        .unwrap_or_default()
        .iter()
        .filter_map(|j| serde_json::from_str::<Passkey>(j).ok())
        .map(|p| p.cred_id().clone())
        .collect();
    let exclude = (!existing.is_empty()).then_some(existing);
    match webauthn.start_passkey_registration(uuid, who.as_str(), who.as_str(), exclude) {
        Ok((challenge, state)) => {
            let state_json = serde_json::to_string(&state).expect("state serialises");
            match app.with_store(|s| s.put_webauthn_state(Some(&who), "register", &state_json)) {
                Ok(id) => Json(json!({ "id": id, "options": challenge })).into_response(),
                Err(err) => crate::web::oops(err),
            }
        }
        Err(err) => {
            tracing::warn!(%err, "passkey registration could not start");
            bad("could not start registration")
        }
    }
}

#[derive(Deserialize)]
pub struct RegisterFinish {
    pub id: String,
    pub credential: RegisterPublicKeyCredential,
    #[serde(default)]
    pub label: String,
}

pub async fn register_finish(
    State(app): State<AppState>,
    viewer: Viewer,
    Json(body): Json<RegisterFinish>,
) -> Response {
    let Some(webauthn) = app.webauthn() else {
        return off();
    };
    let taken = match app.with_store(|s| s.take_webauthn_state(&body.id, "register")) {
        Ok(Some((Some(who), state))) if who == viewer.0 => state,
        Ok(_) => return bad("that registration has expired; start again"),
        Err(err) => return crate::web::oops(err),
    };
    let state: PasskeyRegistration = match serde_json::from_str(&taken) {
        Ok(s) => s,
        Err(_) => return bad("that registration has expired; start again"),
    };
    let passkey = match webauthn.finish_passkey_registration(&body.credential, &state) {
        Ok(p) => p,
        Err(err) => {
            tracing::warn!(%err, "passkey registration refused");
            return bad("the browser's answer was not accepted");
        }
    };
    let cred_id = cred_id_string(passkey.cred_id());
    // A credential id is unique to one authenticator; if it is already
    // somebody's, this is not a new key and it is refused.
    if let Ok(Some(_)) = app.with_store(|s| s.passkey_owner(&cred_id)) {
        return bad("that passkey is already registered");
    }
    let label = if body.label.trim().is_empty() {
        "passkey"
    } else {
        body.label.trim()
    };
    let json = serde_json::to_string(&passkey).expect("passkey serialises");
    match app.with_store(|s| s.add_passkey(&viewer.0, &cred_id, &json, label)) {
        Ok(()) => Json(json!({ "ok": true })).into_response(),
        Err(err) => bad(&err.to_string()),
    }
}

/// Start a discoverable sign-in: the browser picks the credential, and
/// with it the user; the server learns who only when the answer comes.
pub async fn login_begin(State(app): State<AppState>) -> Response {
    let Some(webauthn) = app.webauthn() else {
        return off();
    };
    match webauthn.start_discoverable_authentication() {
        Ok((challenge, state)) => {
            let state_json = serde_json::to_string(&state).expect("state serialises");
            match app.with_store(|s| s.put_webauthn_state(None, "login", &state_json)) {
                Ok(id) => Json(json!({ "id": id, "options": challenge })).into_response(),
                Err(err) => crate::web::oops(err),
            }
        }
        Err(err) => {
            tracing::warn!(%err, "passkey sign-in could not start");
            bad("could not start sign-in")
        }
    }
}

#[derive(Deserialize)]
pub struct LoginFinish {
    pub id: String,
    pub credential: PublicKeyCredential,
}

pub async fn login_finish(
    State(app): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<LoginFinish>,
) -> Response {
    let Some(webauthn) = app.webauthn() else {
        return off();
    };
    let taken = match app.with_store(|s| s.take_webauthn_state(&body.id, "login")) {
        Ok(Some((_, state))) => state,
        Ok(None) => return bad("that sign-in has expired; start again"),
        Err(err) => return crate::web::oops(err),
    };
    let state: DiscoverableAuthentication = match serde_json::from_str(&taken) {
        Ok(s) => s,
        Err(_) => return bad("that sign-in has expired; start again"),
    };
    // The user handle names the person; the credential id names the key.
    // Both must agree with what is stored before anything is trusted.
    let (user_uuid, cred_id) = match webauthn.identify_discoverable_authentication(&body.credential)
    {
        Ok(pair) => pair,
        Err(err) => {
            tracing::warn!(%err, "passkey sign-in: unidentifiable answer");
            return bad("the browser's answer was not accepted");
        }
    };
    let cred_id = cred_id_string(&CredentialID::from(cred_id.to_vec()));
    let who = match app.with_store(|s| s.passkey_owner(&cred_id)) {
        Ok(Some(who)) => who,
        Ok(None) => return bad("that passkey is not registered here"),
        Err(err) => return crate::web::oops(err),
    };
    let expected_uuid = app
        .with_store(|s| s.passkey_user_id(&who))
        .map(|id| uuid_from(&id))
        .unwrap_or_default();
    if expected_uuid != user_uuid {
        return bad("the browser's answer was not accepted");
    }
    let stored: Vec<Passkey> = app
        .with_store(|s| s.passkey_json_of(&who))
        .unwrap_or_default()
        .iter()
        .filter_map(|j| serde_json::from_str(j).ok())
        .collect();
    let keys: Vec<DiscoverableKey> = stored.iter().map(DiscoverableKey::from).collect();
    let result = match webauthn.finish_discoverable_authentication(&body.credential, state, &keys) {
        Ok(r) => r,
        Err(err) => {
            tracing::warn!(%err, "passkey sign-in refused");
            return bad("the browser's answer was not accepted");
        }
    };
    // The stored key learns the new counter. A counter that did not move
    // on an authenticator that is not backed up can mean a clone; the
    // library says so, and a clone is refused rather than trusted.
    let Some(mut key) = stored.into_iter().find(|k| k.cred_id() == result.cred_id()) else {
        return bad("that passkey is not registered here");
    };
    if key.update_credential(&result) == Some(false) {
        tracing::warn!(
            who = who.as_str(),
            "passkey sign-in refused: counter did not advance"
        );
        return bad("that passkey looks cloned and was refused");
    }
    let json = serde_json::to_string(&key).expect("passkey serialises");
    if let Err(err) = app.with_store(|s| s.touch_passkey(&cred_id, &json)) {
        return crate::web::oops(err);
    }
    match app.start_session(
        &who,
        headers
            .get(header::USER_AGENT)
            .and_then(|v| v.to_str().ok()),
    ) {
        Ok(session) => {
            let secure = if app.secure_cookies() { "; Secure" } else { "" };
            let cookie = format!(
                "{}={session}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000{secure}",
                crate::web::SESSION_COOKIE
            );
            ([(header::SET_COOKIE, cookie)], Json(json!({ "to": "/" }))).into_response()
        }
        Err(err) => crate::web::oops(err),
    }
}

#[derive(Deserialize)]
pub struct RemoveForm {
    #[serde(default)]
    pub cred_id: String,
}

pub async fn remove(
    State(app): State<AppState>,
    viewer: Viewer,
    axum::Form(form): axum::Form<RemoveForm>,
) -> Response {
    match app.with_store(|s| s.remove_passkey(&viewer.0, form.cred_id.trim())) {
        Ok(_) => Redirect::to("/you/settings?done=1").into_response(),
        Err(err) => crate::web::oops(err),
    }
}

/// A user handle from the opaque id the store keeps: the first sixteen
/// bytes of its hash, so the same id always yields the same handle.
fn uuid_from(user_id: &str) -> Uuid {
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(user_id.as_bytes());
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&digest[..16]);
    Uuid::from_bytes(bytes)
}

/// Whether a person may see the passkey controls at all.
pub fn enabled(app: &AppState) -> bool {
    app.webauthn().is_some()
}

/// The script that drives the ceremonies. Plain, small, first-party,
/// served under a content hash like the stylesheet. It does nothing on
/// a page without the buttons it looks for.
pub const SCRIPT: &str = r#"(function () {
  'use strict';
  var enc = function (buf) {
    var s = '', b = new Uint8Array(buf);
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  };
  var dec = function (str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    var bin = atob(str), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out.buffer;
  };
  var post = function (url, body) {
    return fetch(url, { method: 'POST', credentials: 'same-origin',
      headers: { 'content-type': 'application/json' }, body: JSON.stringify(body || {}) })
      .then(function (r) { return r.json().then(function (j) { if (!r.ok) throw new Error(j.error || r.statusText); return j; }); });
  };
  var say = function (el, text) { var out = document.getElementById(el.getAttribute('data-say')); if (out) out.textContent = text; };
  var register = document.querySelector('[data-passkey="register"]');
  if (register) register.addEventListener('click', function () {
    if (!window.PublicKeyCredential) { say(register, 'This browser has no passkey support.'); return; }
    var label = (document.getElementById('passkey-label') || {}).value || '';
    post('/passkeys/register/begin').then(function (begin) {
      var pk = begin.options.publicKey;
      pk.challenge = dec(pk.challenge); pk.user.id = dec(pk.user.id);
      (pk.excludeCredentials || []).forEach(function (c) { c.id = dec(c.id); });
      return navigator.credentials.create({ publicKey: pk }).then(function (cred) {
        var r = cred.response;
        return post('/passkeys/register/finish', { id: begin.id, label: label, credential: {
          id: cred.id, rawId: enc(cred.rawId), type: cred.type,
          response: { attestationObject: enc(r.attestationObject), clientDataJSON: enc(r.clientDataJSON) },
          extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {} } });
      });
    }).then(function () { location.reload(); })
      .catch(function (e) { say(register, e.message || String(e)); });
  });
  var login = document.querySelector('[data-passkey="login"]');
  if (login) login.addEventListener('click', function () {
    if (!window.PublicKeyCredential) { say(login, 'This browser has no passkey support.'); return; }
    post('/passkeys/login/begin').then(function (begin) {
      var pk = begin.options.publicKey;
      pk.challenge = dec(pk.challenge);
      (pk.allowCredentials || []).forEach(function (c) { c.id = dec(c.id); });
      return navigator.credentials.get({ publicKey: pk }).then(function (cred) {
        var r = cred.response;
        return post('/passkeys/login/finish', { id: begin.id, credential: {
          id: cred.id, rawId: enc(cred.rawId), type: cred.type,
          response: { authenticatorData: enc(r.authenticatorData), clientDataJSON: enc(r.clientDataJSON),
            signature: enc(r.signature), userHandle: r.userHandle ? enc(r.userHandle) : null },
          extensions: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {} } });
      });
    }).then(function (done) { location.assign(done.to || '/'); })
      .catch(function (e) { say(login, e.message || String(e)); });
  });
})();
"#;
