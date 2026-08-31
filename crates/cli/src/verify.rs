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

#[derive(Clone, Copy)]
pub struct Runner<'a> {
    pub server: &'a str,
    pub token: &'a str,
    pub repo: &'a str,
    /// A single change, or every change waiting on a runner.
    pub change: Option<i64>,
    pub workdir: &'a Path,
    /// Print what would run without running or recording anything.
    pub dry_run: bool,
    /// Check out each change's revision here before running its
    /// claims, instead of trusting whatever the working directory
    /// happens to contain. This is what makes the runner correct when
    /// it is a CI job rather than a person at a terminal.
    pub checkout: bool,
}

/// Continuous integration, expressed in the protocol the forge already
/// speaks: fetch what a change actually proposes, re-run what it
/// claims, and record what happened. Nothing here is specific to any
/// CI product — a workflow file just calls this.
/// Confirm this machine can actually run a check before claiming to
/// have run one.
///
/// A runner that cannot write to disk will watch every command fail and
/// record that the claims were false. They were not: the machine was
/// broken. A false dispute blocks a change for a reason that has
/// nothing to do with the change, and it costs somebody an afternoon to
/// work out why — so refuse to start instead, loudly, and record
/// nothing.
fn can_actually_run(workdir: &Path) -> anyhow::Result<()> {
    let probe = std::env::temp_dir().join(format!("cairn-verify-{}", std::process::id()));
    std::fs::write(&probe, b"probe").with_context(|| {
        format!(
            "cannot write to the temporary directory ({}). Set TMPDIR somewhere \
             with space; a runner that cannot write would report every claim as \
             false when the truth is that it could not check",
            std::env::temp_dir().display()
        )
    })?;
    let _ = std::fs::remove_file(&probe);

    std::fs::create_dir_all(workdir)
        .with_context(|| format!("cannot create the working directory {}", workdir.display()))?;
    let probe = workdir.join(".cairn-verify-probe");
    std::fs::write(&probe, b"probe").with_context(|| {
        format!(
            "cannot write in the working directory {}",
            workdir.display()
        )
    })?;
    let _ = std::fs::remove_file(&probe);
    Ok(())
}

pub fn run_all(runner: Runner) -> anyhow::Result<()> {
    can_actually_run(runner.workdir)?;
    let agent = build_agent();
    let base = runner.server.trim_end_matches('/');
    let numbers = match runner.change {
        Some(number) => vec![number],
        None => {
            let (status, waiting) = get(
                &agent,
                &format!("{base}/api/repos/{}/awaiting-verification", runner.repo),
                runner.token,
            )?;
            if !(200..300).contains(&status) {
                bail!(
                    "cannot list work: {}",
                    waiting["error"].as_str().unwrap_or("unknown error")
                );
            }
            waiting
                .as_array()
                .map(|items| {
                    items
                        .iter()
                        .filter_map(|change| change["number"].as_i64())
                        .collect()
                })
                .unwrap_or_default()
        }
    };

    if numbers.is_empty() {
        println!("nothing is waiting on a runner");
        return Ok(());
    }
    let mut disputed_any = false;
    for number in numbers {
        println!("\n--- change {number}");
        let workdir = if runner.checkout {
            let into = runner.workdir.join(format!("change-{number}"));
            checkout_revision(base, runner, number, &into)?;
            into
        } else {
            runner.workdir.to_owned()
        };
        disputed_any |= run(Runner {
            change: Some(number),
            workdir: &workdir,
            ..runner
        })?;
    }
    if disputed_any {
        // A runner that cannot reproduce something should say so with
        // its exit status too, so CI goes red where people look.
        bail!("at least one claim could not be reproduced");
    }
    Ok(())
}

/// Fetch the exact revision a change proposes. Every revision stays
/// fetchable at refs/changes/<number>/<revision>, which is precisely
/// what makes independent verification possible at all.
fn checkout_revision(base: &str, runner: Runner, number: i64, into: &Path) -> anyhow::Result<()> {
    let agent = build_agent();
    let (_, change) = get(
        &agent,
        &format!("{base}/api/repos/{}/changes/{number}", runner.repo),
        runner.token,
    )?;
    let revision = change["latest_revision"].as_i64().unwrap_or(1);
    let git_url = format!("{base}/git/{}", runner.repo);
    // The token authenticates the fetch the same way it does the API.
    let authenticated = git_url.replacen("://", &format!("://runner:{}@", runner.token), 1);

    std::fs::create_dir_all(into).context("preparing a place to check out")?;
    for args in [
        vec!["init", "--quiet"],
        vec![
            "fetch",
            "--quiet",
            "--depth",
            "1",
            &authenticated,
            &format!("refs/changes/{number}/{revision}"),
        ],
        vec!["checkout", "--quiet", "FETCH_HEAD"],
    ] {
        let output = Command::new("git")
            .args(&args)
            .current_dir(into)
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .with_context(|| format!("running git {}", args[0]))?;
        if !output.status.success() {
            // The URL carries the token; never echo it back.
            bail!(
                "git {} failed: {}",
                args[0],
                String::from_utf8_lossy(&output.stderr)
                    .replace(runner.token, "***")
                    .trim()
            );
        }
    }
    Ok(())
}

fn build_agent() -> ureq::Agent {
    ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into()
}

/// Re-run one change's claims. Returns whether anything was disputed.
pub fn run(runner: Runner) -> anyhow::Result<bool> {
    let agent = build_agent();
    let base = runner.server.trim_end_matches('/');
    let change_number = runner.change.context("a change number is required")?;

    let (status, change) = get(
        &agent,
        &format!("{base}/api/repos/{}/changes/{change_number}", runner.repo),
        runner.token,
    )?;
    if !(200..300).contains(&status) {
        bail!(
            "cannot read change {change_number}: {}",
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
        return Ok(false);
    }
    println!("\n{ran} claim(s) re-run on revision {revision}; {disputed} disputed");
    if disputed > 0 {
        println!("the change cannot land until the dispute is resolved");
    }
    Ok(disputed > 0)
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
