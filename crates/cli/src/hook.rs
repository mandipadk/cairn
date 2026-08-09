//! The proc-receive hook: where `git push` meets the graph.
//!
//! `git receive-pack` hands us every update to `refs/for/<branch>` over
//! pkt-line on stdio (git's proc-receive protocol, version 1). For each
//! pushed tip we read the commit from quarantine (the environment
//! receive-pack gives us makes not-yet-migrated objects visible), record
//! it through the forge API as a change revision, and answer with an
//! alternate ref name — `refs/changes/<number>/<revision>` — which
//! receive-pack reports to the pusher. The ref itself is created by the
//! server's reconciliation pass once the pushed objects leave
//! quarantine; hooks are forbidden from updating refs before that.
//!
//! The hook holds no state and makes no decisions: it is a translator,
//! and the API's typed refusals become push failures verbatim.

use anyhow::{Context, bail};
use cairn_git::pkt;
use cairn_git::pkt::Packet;
use serde_json::{Value, json};
use std::io::{Read, Write};

const ZERO_OID_PREFIX: &str = "0000000000";

pub fn run() -> anyhow::Result<()> {
    let server = std::env::var("CAIRN_SERVER").context("CAIRN_SERVER not set")?;
    let principal = std::env::var("CAIRN_PRINCIPAL").context("CAIRN_PRINCIPAL not set")?;
    let repo = std::env::var("CAIRN_REPO").context("CAIRN_REPO not set")?;
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    conversation(stdin, stdout, &server, &principal, &repo)
}

fn conversation(
    mut input: impl Read,
    mut output: impl Write,
    server: &str,
    principal: &str,
    repo: &str,
) -> anyhow::Result<()> {
    // Handshake: receive-pack announces its version and features; we
    // speak version 1 and request no features.
    let handshake = pkt::read_text_until_flush(&mut input)?;
    if !handshake.iter().any(|line| line.starts_with("version=1")) {
        bail!("receive-pack offered no proc-receive version 1 (got {handshake:?})");
    }
    pkt::write_data(&mut output, b"version=1\n")?;
    pkt::write_flush(&mut output)?;
    output.flush()?;

    // Commands: "<old-oid> <new-oid> <ref>" lines, then flush.
    let commands = pkt::read_text_until_flush(&mut input)?;

    let client = Client { server, principal };
    for command in &commands {
        let mut parts = command.split(' ');
        let (Some(_old), Some(new), Some(ref_name)) = (parts.next(), parts.next(), parts.next())
        else {
            bail!("malformed proc-receive command {command:?}");
        };
        match handle_push(&client, repo, new, ref_name) {
            Ok((number, revision)) => {
                pkt::write_data(&mut output, format!("ok {ref_name}\n").as_bytes())?;
                pkt::write_data(
                    &mut output,
                    format!("option refname refs/changes/{number}/{revision}\n").as_bytes(),
                )?;
                pkt::write_data(&mut output, format!("option new-oid {new}\n").as_bytes())?;
            }
            Err(reason) => {
                // Single-line reasons only: pkt text lines carry the message
                // to the pusher's terminal.
                let reason = reason.replace('\n', "; ");
                pkt::write_data(&mut output, format!("ng {ref_name} {reason}\n").as_bytes())?;
            }
        }
    }
    pkt::write_flush(&mut output)?;
    output.flush()?;

    // Drain anything receive-pack still has for us (e.g. push options we
    // did not negotiate) so it never blocks on a full pipe.
    loop {
        match pkt::read(&mut input) {
            Ok(Packet::Flush) | Err(_) => break,
            Ok(_) => continue,
        }
    }
    Ok(())
}

/// One ref update → one recorded revision. Returns (change number,
/// revision number) or a reason the pusher will read.
fn handle_push(
    client: &Client,
    repo: &str,
    new_oid: &str,
    ref_name: &str,
) -> Result<(i64, i64), String> {
    let Some(target) = ref_name.strip_prefix("refs/for/") else {
        return Err(format!("{ref_name} is not a refs/for/<branch> ref"));
    };
    if new_oid.starts_with(ZERO_OID_PREFIX) {
        return Err("deleting a change ref is not supported".to_owned());
    }
    let raw = read_commit(new_oid)?;
    let info = cairn_git::parse_commit_object(&raw);
    let (status, body) = client.record_push(&json!({
        "repo": repo,
        "target": target,
        "commit_oid": new_oid,
        "title": info.title,
        "message": info.message,
        "change_id": info.change_id,
    }))?;
    if !(200..300).contains(&status) {
        let detail = body["error"].as_str().unwrap_or("forge rejected the push");
        return Err(detail.to_owned());
    }
    match (body["number"].as_i64(), body["revision"].as_i64()) {
        (Some(number), Some(revision)) => Ok((number, revision)),
        _ => Err(format!("forge returned an unexpected response: {body}")),
    }
}

/// Read a commit object. Inside the hook, receive-pack's environment
/// (GIT_DIR, quarantine object dirs) makes the pushed objects visible.
fn read_commit(oid: &str) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .args(["cat-file", "commit", oid])
        .output()
        .map_err(|e| format!("running git cat-file: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "commit {oid} unreadable: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

struct Client<'a> {
    server: &'a str,
    principal: &'a str,
}

impl Client<'_> {
    fn record_push(&self, body: &Value) -> Result<(u16, Value), String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let mut response = agent
            .post(format!(
                "{}/api/git/pushes",
                self.server.trim_end_matches('/')
            ))
            .header("x-cairn-principal", self.principal)
            .send_json(body)
            .map_err(|e| format!("forge unreachable: {e}"))?;
        let status = response.status().as_u16();
        let value = response
            .body_mut()
            .read_json()
            .map_err(|e| format!("forge sent a non-json reply: {e}"))?;
        Ok((status, value))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    /// The pkt-level conversation shape, with the API layer unreachable:
    /// handshake succeeds, the command gets an `ng` with a readable
    /// reason, and the response ends with a flush.
    #[test]
    fn conversation_reports_ng_when_forge_unreachable() {
        let mut request = Vec::new();
        pkt::write_data(&mut request, b"version=1\0push-options atomic\n").unwrap();
        pkt::write_flush(&mut request).unwrap();
        pkt::write_data(
            &mut request,
            format!("{} {} refs/for/main\n", "0".repeat(40), "a".repeat(40)).as_bytes(),
        )
        .unwrap();
        pkt::write_flush(&mut request).unwrap();

        let mut response = Vec::new();
        conversation(
            Cursor::new(request),
            &mut response,
            "http://127.0.0.1:9", // discard port: nothing listens
            "scout",
            "demo",
        )
        .unwrap();

        let mut cursor = Cursor::new(response);
        let lines = pkt::read_text_until_flush(&mut cursor).unwrap();
        assert_eq!(lines, ["version=1"]);
        let results = pkt::read_text_until_flush(&mut cursor).unwrap();
        assert!(
            results[0].starts_with("ng refs/for/main"),
            "got {results:?}"
        );
    }

    #[test]
    fn non_refs_for_pushes_are_rejected_without_touching_the_forge() {
        let client = Client {
            server: "http://127.0.0.1:9",
            principal: "scout",
        };
        let err = handle_push(&client, "demo", &"a".repeat(40), "refs/heads/main").unwrap_err();
        assert!(err.contains("refs/for/<branch>"));
        let err = handle_push(&client, "demo", &"0".repeat(40), "refs/for/main").unwrap_err();
        assert!(err.contains("not supported"));
    }
}
