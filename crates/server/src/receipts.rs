//! Merge receipts: a landing made portable and hard to alter.
//!
//! A landing is already explainable from the log. A receipt is that
//! explanation assembled into one document - the change, the revision
//! and commit that landed, the trace, the claims, the runners' re-runs,
//! the verdicts - signed by the forge, written as a git note on the
//! landed commit so it travels with the code, and served for anyone who
//! may read the change. The signature is over a canonical form anyone
//! can recompute; the forge's public key is published beside it.

use crate::auth::MaybeActor;
use crate::error::{ApiError, ApiResult};
use crate::routes::{readable_change_by, readable_repo_by};
use crate::state::AppState;
use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use cairn_core::{ChangeId, Receipt};
use ring::signature::{Ed25519KeyPair, KeyPair};
use serde::Deserialize;
use serde_json::{Value, json};
use std::path::Path as FsPath;

/// How a receipt is serialized before signing; named in every receipt so
/// a verifier knows what to recompute.
pub const CANONICAL: &str = "json:sorted-keys,compact,utf-8";

/// The forge's signing key. Ed25519: small, fast, one algorithm, no
/// parameters to get wrong.
pub struct Signer {
    key: Ed25519KeyPair,
    public: Vec<u8>,
    id: String,
}

impl Signer {
    /// A key for this process only; tests and dry runs.
    pub fn ephemeral() -> Self {
        let rng = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("the system has randomness");
        Self::from_pkcs8(pkcs8.as_ref()).expect("a key just generated parses")
    }

    /// The key at `path`, or a new one written there (owner-only) when
    /// nothing is. Losing the file means a new fingerprint; receipts
    /// already issued still verify against the key they carry.
    pub fn load_or_create(path: &FsPath) -> Result<Self, String> {
        match std::fs::read(path) {
            Ok(bytes) => Self::from_pkcs8(&bytes),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                let rng = ring::rand::SystemRandom::new();
                let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng)
                    .map_err(|_| "could not generate a signing key".to_owned())?;
                if let Some(dir) = path.parent() {
                    std::fs::create_dir_all(dir)
                        .map_err(|err| format!("creating {}: {err}", dir.display()))?;
                }
                write_private(path, pkcs8.as_ref())
                    .map_err(|err| format!("writing {}: {err}", path.display()))?;
                Self::from_pkcs8(pkcs8.as_ref())
            }
            Err(err) => Err(format!("reading {}: {err}", path.display())),
        }
    }

    fn from_pkcs8(bytes: &[u8]) -> Result<Self, String> {
        let key = Ed25519KeyPair::from_pkcs8(bytes)
            .map_err(|err| format!("the signing key is not a PKCS#8 Ed25519 key: {err}"))?;
        let public = key.public_key().as_ref().to_vec();
        let id = fingerprint(&public);
        Ok(Signer { key, public, id })
    }

    /// The first sixteen hex characters of the public key's SHA-256:
    /// enough to name a key, short enough to read aloud.
    pub fn id(&self) -> &str {
        &self.id
    }

    pub fn public_key_base64(&self) -> String {
        BASE64.encode(&self.public)
    }

    /// Sign a receipt: the canonical body, the signature, the key it
    /// verifies with, and the name of the canonical form.
    pub fn sign(&self, receipt: &Receipt) -> Value {
        let body = serde_json::to_value(receipt).expect("a receipt serializes");
        let canonical = cairn_core::canonical_json(&body);
        let signature = self.key.sign(canonical.as_bytes());
        json!({
            "receipt": body,
            "signature": {
                "alg": "ed25519",
                "key": self.id,
                "public_key": self.public_key_base64(),
                "value": BASE64.encode(signature.as_ref()),
            },
            "canonical": CANONICAL,
        })
    }
}

pub fn fingerprint(public: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, public)
        .as_ref()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn write_private(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)
}

#[cfg(not(unix))]
fn write_private(path: &FsPath, bytes: &[u8]) -> std::io::Result<()> {
    std::fs::write(path, bytes)
}

fn unsigned() -> ApiError {
    ApiError::new(
        StatusCode::CONFLICT,
        "unavailable",
        "this forge is running without a signing key, so it issues no receipts",
    )
}

/// The signed receipt for a change, or why there is none yet.
pub fn signed_receipt(app: &AppState, change: &ChangeId) -> ApiResult<Value> {
    let signer = app.signer().ok_or_else(unsigned)?;
    let receipt = app
        .with_store(|s| s.receipt(change, app.public_url()))?
        .ok_or_else(|| {
            ApiError::new(
                StatusCode::CONFLICT,
                "not_landed",
                "a receipt exists once the change has landed",
            )
        })?;
    Ok(signer.sign(&receipt))
}

/// Write the receipt onto the landed commit. Never fails a landing: the
/// merge is the decision, the note is a copy of it, and a missed copy
/// is logged and still served over the API.
pub async fn attach(app: &AppState, repo: &str, change: &ChangeId, landed: &str) {
    let Some(git) = app.git() else { return };
    if app.signer().is_none() {
        return;
    }
    let receipt = match signed_receipt(app, change) {
        Ok(receipt) => receipt,
        Err(err) => {
            tracing::warn!(change = %change, error = %err.message, "receipt: nothing to attach");
            return;
        }
    };
    let text = serde_json::to_string_pretty(&receipt).expect("a receipt serializes");
    if let Err(err) = git.store.attach_note(repo, landed, &text).await {
        tracing::warn!(error = %err, change = %change, "receipt: could not write the note");
    }
}

pub async fn change_receipt(
    State(app): State<AppState>,
    who: MaybeActor,
    Path(id): Path<String>,
) -> ApiResult<Json<Value>> {
    let change = ChangeId(id);
    readable_change_by(&app, &who, &change)?;
    Ok(Json(signed_receipt(&app, &change)?))
}

#[derive(Deserialize)]
pub struct ReceiptsQuery {
    /// Page by cursor: changes numbered below this, newest first.
    pub before: Option<i64>,
    /// At most this many; 20 when absent, 50 at most.
    pub limit: Option<i64>,
}

/// Every receipt in a repository, newest landing first: the audit,
/// as a query.
pub async fn repo_receipts(
    State(app): State<AppState>,
    who: MaybeActor,
    Path(repo): Path<String>,
    Query(query): Query<ReceiptsQuery>,
) -> ApiResult<Json<Value>> {
    readable_repo_by(&app, &who, &repo)?;
    app.signer().ok_or_else(unsigned)?;
    let limit = query.limit.unwrap_or(20).clamp(1, 50);
    let landed = app.with_store(|s| {
        s.acting_as(who.scope()).changes_page(
            &repo,
            Some(cairn_core::ChangeState::Merged),
            query.before,
            limit,
        )
    })?;
    let next_before = (landed.len() as i64 == limit)
        .then(|| landed.last().map(|c| c.number))
        .flatten();
    let mut receipts = Vec::with_capacity(landed.len());
    for change in &landed {
        if let Ok(receipt) = signed_receipt(&app, &change.id) {
            receipts.push(receipt);
        }
    }
    Ok(Json(
        json!({ "receipts": receipts, "next_before": next_before }),
    ))
}

/// The forge's public key, for checking a receipt against the forge
/// rather than against itself.
pub async fn forge_key(State(app): State<AppState>) -> ApiResult<Json<Value>> {
    let signer = app.signer().ok_or_else(unsigned)?;
    Ok(Json(json!({
        "alg": "ed25519",
        "key": signer.id(),
        "public_key": signer.public_key_base64(),
        "canonical": CANONICAL,
    })))
}
