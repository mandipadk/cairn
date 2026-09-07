//! Stamp the build with the commit it came from, so a running forge can
//! say which one it is. Falls back to "unknown" when built outside a git
//! checkout (a source archive); CAIRN_BUILD in the environment overrides
//! both, for whoever packages it.

use std::process::Command;

fn git(args: &[&str]) -> Option<String> {
    let out = Command::new("git").args(args).output().ok()?;
    if !out.status.success() {
        return None;
    }
    let text = String::from_utf8(out.stdout).ok()?;
    let text = text.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

fn main() {
    println!("cargo:rerun-if-env-changed=CAIRN_BUILD");
    // Only paths that exist: naming a missing one makes cargo re-run this
    // on every build.
    for path in [
        "../../.git/HEAD",
        "../../.git/refs/heads",
        "../../.git/packed-refs",
    ] {
        if std::path::Path::new(path).exists() {
            println!("cargo:rerun-if-changed={path}");
        }
    }
    let build = std::env::var("CAIRN_BUILD").ok().unwrap_or_else(|| {
        match (
            git(&["describe", "--always", "--dirty", "--abbrev=9"]),
            git(&["log", "-1", "--format=%cs"]),
        ) {
            (Some(describe), Some(date)) => format!("{describe} {date}"),
            (Some(describe), None) => describe,
            _ => "unknown".to_owned(),
        }
    });
    println!("cargo:rustc-env=CAIRN_BUILD={build}");
}
