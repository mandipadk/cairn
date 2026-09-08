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
//! Tags under `refs/tags/*` take the same road: the hook resolves the
//! pushed object to a commit, refuses one that is on no branch, records
//! the name through the API, and the server writes the ref afterwards.
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
    let token = std::env::var("CAIRN_TOKEN").context("CAIRN_TOKEN not set")?;
    let repo = std::env::var("CAIRN_REPO").context("CAIRN_REPO not set")?;
    let stdin = std::io::stdin().lock();
    let stdout = std::io::stdout().lock();
    conversation(stdin, stdout, &server, &token, &repo)
}

fn conversation(
    mut input: impl Read,
    mut output: impl Write,
    server: &str,
    token: &str,
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

    let client = Client { server, token };
    for command in &commands {
        let mut parts = command.split(' ');
        let (Some(old), Some(new), Some(ref_name)) = (parts.next(), parts.next(), parts.next())
        else {
            bail!("malformed proc-receive command {command:?}");
        };
        if let Some(name) = ref_name.strip_prefix("refs/tags/") {
            // A tag keeps its own name, so there is no option to report;
            // the server writes refs/tags/<name> once the objects have
            // left quarantine, as it does for change refs.
            match handle_tag(&client, repo, old, new, name) {
                Ok(()) => pkt::write_data(&mut output, format!("ok {ref_name}\n").as_bytes())?,
                Err(reason) => {
                    let reason = reason.replace('\n', "; ");
                    pkt::write_data(&mut output, format!("ng {ref_name} {reason}\n").as_bytes())?;
                }
            }
            continue;
        }
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

/// One ref update → one recorded stack. Returns the tip's (change
/// number, revision number) or a reason the pusher will read.
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

    // Bottom-up: every commit the target branch does not already have.
    let commits = list_new_commits(new_oid, target)?;
    if commits.is_empty() {
        return Err(format!(
            "nothing to push: {target} already contains these commits"
        ));
    }
    let mut entries = Vec::new();
    for oid in &commits {
        let info = cairn_git::parse_commit_object(&read_commit(oid)?);
        entries.push(json!({
            "commit_oid": oid,
            "title": info.title,
            "message": info.message,
            "change_id": info.change_id,
            "task": info.task,
        }));
    }
    // Fail the stack-needs-trailers case here, where the message can
    // name the exact commits, before bothering the forge.
    if entries.len() > 1 {
        let missing: Vec<&str> = entries
            .iter()
            .filter(|e| e["change_id"].is_null())
            .filter_map(|e| e["commit_oid"].as_str())
            .collect();
        if !missing.is_empty() {
            return Err(format!(
                "a stack push needs a Change-Id trailer on every commit; missing on: {} \
                 (add trailers, e.g. git rebase --exec with a commit-msg amend, then push again)",
                missing.join(", ")
            ));
        }
    }

    let (status, body) = client.record_push(&json!({
        "repo": repo,
        "target": target,
        "commits": entries,
    }))?;
    if !(200..300).contains(&status) {
        let detail = body["error"].as_str().unwrap_or("forge rejected the push");
        return Err(detail.to_owned());
    }
    match (
        body["tip"]["number"].as_i64(),
        body["tip"]["revision"].as_i64(),
    ) {
        (Some(number), Some(revision)) => Ok((number, revision)),
        _ => Err(format!("forge returned an unexpected response: {body}")),
    }
}

/// One tag → one recorded name for a landed commit. Ok means the forge
/// took the name and will write the ref; Err is what the pusher reads.
fn handle_tag(
    client: &Client,
    repo: &str,
    old_oid: &str,
    new_oid: &str,
    name: &str,
) -> Result<(), String> {
    if new_oid.starts_with(ZERO_OID_PREFIX) {
        return Err(format!(
            "deleting tag {name} is not supported; a tag is a statement the log keeps"
        ));
    }
    if !old_oid.starts_with(ZERO_OID_PREFIX) {
        return Err(format!(
            "tag {name} already exists and tags are not moved; make a new one"
        ));
    }
    let commit = git_out(&[
        "rev-parse",
        "--verify",
        "--quiet",
        &format!("{new_oid}^{{commit}}"),
    ])
    .map_err(|_| format!("tag {name} does not point at a commit"))?;
    let commit = commit.trim().to_owned();
    let branches = git_out(&["branch", "--contains", &commit, "--format=%(refname:short)"])?;
    if branches.trim().is_empty() {
        return Err(format!(
            "{} is not on any branch of {repo}; a tag names landed history",
            &commit[..commit.len().min(12)]
        ));
    }
    // An annotated tag is its own object, with a message worth keeping;
    // a lightweight one is just a name for the commit.
    let annotated = git_out(&["cat-file", "-t", new_oid])?.trim() == "tag";
    let message = if annotated {
        git_out(&["cat-file", "tag", new_oid])
            .ok()
            .and_then(|raw| {
                raw.split_once("\n\n")
                    .map(|(_, body)| body.trim().to_owned())
            })
            .filter(|body| !body.is_empty())
    } else {
        None
    };
    let (status, body) = client.record_tag(&json!({
        "repo": repo,
        "name": name,
        "commit_oid": commit,
        "object_oid": annotated.then(|| new_oid.to_owned()),
        "message": message,
    }))?;
    if !(200..300).contains(&status) {
        return Err(body["error"]
            .as_str()
            .unwrap_or("forge rejected the tag")
            .to_owned());
    }
    Ok(())
}

/// Run git inside the hook's repository and return what it printed.
fn git_out(args: &[&str]) -> Result<String, String> {
    let output = std::process::Command::new("git")
        .args(args)
        .output()
        .map_err(|e| format!("running git {}: {e}", args[0]))?;
    if !output.status.success() {
        return Err(format!(
            "git {} failed: {}",
            args[0],
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

/// Commits reachable from the pushed tip but not from the target
/// branch, oldest first. Inside the hook, quarantined objects are
/// visible through receive-pack's environment.
fn list_new_commits(new_oid: &str, target: &str) -> Result<Vec<String>, String> {
    let target_ref = format!("refs/heads/{target}");
    let target_exists = std::process::Command::new("git")
        .args(["rev-parse", "--verify", "--quiet", &target_ref])
        .output()
        .map_err(|e| format!("running git rev-parse: {e}"))?
        .status
        .success();
    // Against an existing branch, "new" means not already on it.
    // Against a branch that does not exist yet, it means not already
    // anywhere — otherwise opening a change on a fresh branch would
    // re-propose every commit the repo has ever landed.
    let mut args = vec!["rev-list", "--reverse", new_oid, "--not"];
    if target_exists {
        args.push(&target_ref);
    } else {
        args.push("--branches");
    }
    let output = std::process::Command::new("git")
        .args(&args)
        .output()
        .map_err(|e| format!("running git rev-list: {e}"))?;
    if !output.status.success() {
        return Err(format!(
            "listing pushed commits failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::to_owned)
        .collect())
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
    token: &'a str,
}

impl Client<'_> {
    fn record_push(&self, body: &Value) -> Result<(u16, Value), String> {
        self.post("/api/git/pushes", body)
    }

    fn record_tag(&self, body: &Value) -> Result<(u16, Value), String> {
        self.post("/api/git/tags", body)
    }

    fn post(&self, path: &str, body: &Value) -> Result<(u16, Value), String> {
        let agent: ureq::Agent = ureq::Agent::config_builder()
            .http_status_as_error(false)
            .build()
            .into();
        let mut response = agent
            .post(format!("{}{path}", self.server.trim_end_matches('/')))
            .header("Authorization", format!("Bearer {}", self.token))
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
            "cairnpush_test",
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
            token: "cairnpush_test",
        };
        let err = handle_push(&client, "demo", &"a".repeat(40), "refs/heads/main").unwrap_err();
        assert!(err.contains("refs/for/<branch>"));
        let err = handle_push(&client, "demo", &"0".repeat(40), "refs/for/main").unwrap_err();
        assert!(err.contains("not supported"));
    }
}
