//! Checking a merge receipt without the forge.
//!
//! A receipt is signed over a canonical form of its body: JSON with
//! keys sorted, no whitespace, UTF-8. Recompute that, check the Ed25519
//! signature with the key the receipt carries (and with the key you
//! were told to expect, if you were told one), and read what it says.

use anyhow::{Context, bail};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use serde_json::Value;

/// What a verified receipt says, in the terms a person asks about.
pub struct Summary {
    /// The forge that issued it, when the receipt names one.
    pub forge: Option<String>,
    pub repo: String,
    pub number: i64,
    pub title: String,
    pub landed_as: String,
    pub landed_at: String,
    pub merged_by: String,
    pub satisfied: bool,
    pub claims: usize,
    pub reproduced: usize,
    pub disputed: usize,
    pub verdicts: usize,
    pub key: String,
}

impl std::fmt::Display for Summary {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "verified · {} #{} landed as {} on {} by {} · policy {} · {} claim(s), {} re-run(s) reproduced, {} disputed, {} verdict(s) · key {}",
            self.repo,
            self.number,
            &self.landed_as[..self.landed_as.len().min(7)],
            &self.landed_at[..self.landed_at.len().min(10)],
            self.merged_by,
            if self.satisfied {
                "satisfied"
            } else {
                "NOT satisfied"
            },
            self.claims,
            self.reproduced,
            self.disputed,
            self.verdicts,
            self.key
        )?;
        if let Some(forge) = &self.forge {
            write!(f, " · from {forge}")?;
        }
        Ok(())
    }
}

/// Verify a signed receipt document. `expected_key` is a fingerprint or
/// a base64 public key the receipt must have been signed with.
pub fn verify(document: &str, expected_key: Option<&str>) -> anyhow::Result<Summary> {
    let signed: Value = serde_json::from_str(document).context("the receipt is not JSON")?;
    let body = signed
        .get("receipt")
        .context("no `receipt` in the document")?;
    let signature = signed
        .get("signature")
        .context("no `signature` in the document")?;
    if signature.get("alg").and_then(Value::as_str) != Some("ed25519") {
        bail!("unsupported signature algorithm");
    }
    if signed.get("canonical").and_then(Value::as_str) != Some("json:sorted-keys,compact,utf-8") {
        bail!("unsupported canonical form");
    }
    let public = BASE64
        .decode(
            signature
                .get("public_key")
                .and_then(Value::as_str)
                .context("no public key in the signature")?,
        )
        .context("the public key is not base64")?;
    let value = BASE64
        .decode(
            signature
                .get("value")
                .and_then(Value::as_str)
                .context("no signature value")?,
        )
        .context("the signature is not base64")?;
    let key_id = fingerprint(&public);
    if signature.get("key").and_then(Value::as_str) != Some(key_id.as_str()) {
        bail!(
            "the signature names key {:?} but carries a key whose fingerprint is {key_id}",
            signature.get("key").and_then(Value::as_str).unwrap_or("")
        );
    }
    if let Some(expected) = expected_key
        && expected != key_id
        && expected != BASE64.encode(&public)
    {
        bail!("signed with key {key_id}, not the expected {expected}");
    }
    let canonical = canonical_json(body);
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, &public)
        .verify(canonical.as_bytes(), &value)
        .map_err(|_| anyhow::anyhow!("the signature does not match the receipt"))?;

    let get = |path: &str| body.pointer(path).cloned().unwrap_or(Value::Null);
    let verifications = get("/verifications");
    let runs = verifications.as_array().cloned().unwrap_or_default();
    Ok(Summary {
        forge: get("/forge").as_str().map(str::to_owned),
        repo: get("/repo").as_str().unwrap_or("").to_owned(),
        number: get("/change/number").as_i64().unwrap_or(0),
        title: get("/change/title").as_str().unwrap_or("").to_owned(),
        landed_as: get("/landed_as").as_str().unwrap_or("").to_owned(),
        landed_at: get("/landed_at").as_str().unwrap_or("").to_owned(),
        merged_by: get("/merged_by").as_str().unwrap_or("").to_owned(),
        satisfied: get("/trace/satisfied").as_bool().unwrap_or(false),
        claims: get("/claims").as_array().map_or(0, Vec::len),
        reproduced: runs.iter().filter(|v| v["agrees"] == true).count(),
        disputed: runs.iter().filter(|v| v["agrees"] == false).count(),
        verdicts: get("/verdicts").as_array().map_or(0, Vec::len),
        key: key_id,
    })
}

/// The first sixteen hex characters of the public key's SHA-256.
pub fn fingerprint(public: &[u8]) -> String {
    ring::digest::digest(&ring::digest::SHA256, public)
        .as_ref()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

/// JSON with keys sorted, no whitespace: the form a receipt is signed
/// over. Kept here in full rather than shared, so this crate stays a
/// complete verifier on its own.
pub fn canonical_json(value: &Value) -> String {
    fn write(out: &mut String, value: &Value) {
        match value {
            Value::Array(items) => {
                out.push('[');
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    write(out, item);
                }
                out.push(']');
            }
            Value::Object(fields) => {
                let mut keys: Vec<&String> = fields.keys().collect();
                keys.sort();
                out.push('{');
                for (index, key) in keys.iter().enumerate() {
                    if index > 0 {
                        out.push(',');
                    }
                    out.push_str(&serde_json::to_string(key).expect("a string serializes"));
                    out.push(':');
                    write(out, &fields[*key]);
                }
                out.push('}');
            }
            scalar => out.push_str(&serde_json::to_string(scalar).expect("a scalar serializes")),
        }
    }
    let mut out = String::new();
    write(&mut out, value);
    out
}
