//! The runner: re-execute someone else's claims and report what
//! actually happened.
//!
//! A claim is only as good as its reproducibility. This command takes
//! a change, runs each claim's recorded command in the working
//! directory it is pointed at, and records an independent verification
//! — agreeing when the outcome matches what was claimed, disputing
//! when it does not. A disputed claim blocks the landing.
//!
//! Execution happens here, in the runner's own environment, not on the
//! forge: cairn defines the protocol and enforces the consequence.
//! Isolation is the operator's choice — run this inside whatever
//! sandbox the work deserves.

use anyhow::{Context, bail};
use serde_json::{Value, json};
use std::path::Path;
use std::process::Command;

pub struct Runner<'a> {
    pub server: &'a str,
    pub token: &'a str,
    pub repo: &'a str,
    pub change: i64,
    pub workdir: &'a Path,
    /// Print what would run without running or recording anything.
    pub dry_run: bool,
}

pub fn run(runner: Runner) -> anyhow::Result<()> {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let base = runner.server.trim_end_matches('/');

    let (status, change) = get(
        &agent,
        &format!("{base}/api/repos/{}/changes/{}", runner.repo, runner.change),
        runner.token,
    )?;
    if !(200..300).contains(&status) {
        bail!(
            "cannot read change {}: {}",
            runner.change,
            change["error"].as_str().unwrap_or("unknown error")
        );
    }
    let change_id = change["id"]
        .as_str()
        .context("the forge returned a change without an id")?;
    let revision = change["latest_revision"].as_i64().unwrap_or(0);

    let (_, claims) = get(
        &agent,
        &format!("{base}/api/changes/{change_id}/claims"),
        runner.token,
    )?;
    let claims = claims.as_array().cloned().unwrap_or_default();

    let mut ran = 0;
    let mut disputed = 0;
    for claim in &claims {
        let Some(command) = claim["command"].as_str().filter(|c| !c.trim().is_empty()) else {
            println!(
                "skip  {} — no command recorded, nothing to reproduce",
                claim["kind"].as_str().unwrap_or("claim")
            );
            continue;
        };
        let claim_id = claim["id"].as_str().unwrap_or_default();
        let expected = claim["passed"].as_bool().unwrap_or(true);

        if runner.dry_run {
            println!("would run  {command}");
            continue;
        }

        println!("running  {command}");
        let output = Command::new("sh")
            .arg("-c")
            .arg(command)
            .current_dir(runner.workdir)
            .output()
            .with_context(|| format!("running {command:?}"))?;
        let passed = output.status.success();
        let agrees = passed == expected;
        ran += 1;
        if !agrees {
            disputed += 1;
        }

        let observed = summarize(&output, passed);
        let (status, body) = post(
            &agent,
            &format!("{base}/api/claims/{claim_id}/verify"),
            runner.token,
            &json!({ "agrees": agrees, "command": command, "observed": observed }),
        )?;
        if !(200..300).contains(&status) {
            bail!(
                "recording the verification failed: {}",
                body["error"].as_str().unwrap_or("unknown error")
            );
        }
        println!(
            "  {}  {observed}",
            if agrees { "reproduced" } else { "DISPUTED" }
        );
    }

    if runner.dry_run {
        return Ok(());
    }
    println!("\n{ran} claim(s) re-run on revision {revision}; {disputed} disputed",);
    if disputed > 0 {
        println!("the change cannot land until the dispute is resolved");
    }
    Ok(())
}

/// What the runner saw, in one line: the outcome plus the tail of
/// whatever the command said about it.
fn summarize(output: &std::process::Output, passed: bool) -> String {
    let stream = if output.stderr.is_empty() {
        &output.stdout
    } else {
        &output.stderr
    };
    let tail = String::from_utf8_lossy(stream)
        .lines()
        .rev()
        .find(|line| !line.trim().is_empty())
        .unwrap_or("")
        .trim()
        .chars()
        .take(200)
        .collect::<String>();
    let code = output
        .status
        .code()
        .map_or_else(|| "signal".to_owned(), |c| c.to_string());
    if tail.is_empty() {
        format!("exit {code}: {}", if passed { "passed" } else { "failed" })
    } else {
        format!("exit {code}: {tail}")
    }
}

fn get(agent: &ureq::Agent, url: &str, token: &str) -> anyhow::Result<(u16, Value)> {
    let mut response = agent
        .get(url)
        .header("Authorization", format!("Bearer {token}"))
        .call()?;
    Ok((response.status().as_u16(), response.body_mut().read_json()?))
}

fn post(agent: &ureq::Agent, url: &str, token: &str, body: &Value) -> anyhow::Result<(u16, Value)> {
    let mut response = agent
        .post(url)
        .header("Authorization", format!("Bearer {token}"))
        .send_json(body)?;
    Ok((response.status().as_u16(), response.body_mut().read_json()?))
}
