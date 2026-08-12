//! Every page as a maud template. All interpolation is escaped by
//! maud; the one deliberate exception is README markdown, which is
//! rendered with raw HTML events stripped before it gets here.

use super::diff::{FileDiff, LineKind};
use super::{Brief, LandingData, Sidebar, Viewer};
use cairn_core::{
    Change, ChangeState, Claim, Disposition, Envelope, Event, PolicyTrace, Repo, Revision, Task,
    Verdict, Verification,
};
use maud::{DOCTYPE, Markup, PreEscaped, html};
use std::collections::HashMap;

/// Which palette the page renders in. Dark is the default; a viewer
/// can switch, and the choice rides in a cookie.
#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Theme {
    Dark,
    Light,
}

impl Theme {
    pub fn attr(self) -> &'static str {
        match self {
            Theme::Dark => "dark",
            Theme::Light => "light",
        }
    }

    fn other(self) -> &'static str {
        match self {
            Theme::Dark => "light",
            Theme::Light => "dark",
        }
    }

    fn switch_label(self) -> &'static str {
        match self {
            Theme::Dark => "Light",
            Theme::Light => "Dark",
        }
    }
}

/// One line of a file, with everything the graph knows about it.
pub struct BlameRow {
    pub number: usize,
    pub text: String,
    pub provenance: Option<std::sync::Arc<cairn_core::Provenance>>,
}

/// One row of a tree listing, with the change that last touched it.
pub struct Entry {
    pub is_dir: bool,
    pub name: String,
    pub subject: Option<String>,
    pub change: Option<Change>,
}

#[derive(PartialEq, Eq, Clone, Copy)]
pub enum Tab {
    Code,
    Changes,
    Landing,
    Lessons,
    Log,
}

fn layout(
    theme: Theme,
    viewer: Option<&Viewer>,
    repo: Option<&str>,
    active: Option<Tab>,
    title: &str,
    body: Markup,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=(theme.attr()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · cairn" }
                link rel="stylesheet" href="/assets/app.css";
            }
            body {
                @if let Some(viewer) = viewer {
                    nav class="topnav" {
                        a href="/" aria-label="Home" {
                            span class="stones" aria-hidden="true" { span {} span {} span {} }
                        }
                        @if let Some(repo) = repo {
                            span class="repo" { (repo) }
                            div class="tabs" {
                                (tab(repo, "", "Code", active == Some(Tab::Code)))
                                (tab(repo, "/changes", "Changes", active == Some(Tab::Changes)))
                                (tab(repo, "/landing", "Landing", active == Some(Tab::Landing)))
                                (tab(repo, "/lessons", "Lessons", active == Some(Tab::Lessons)))
                                (tab(repo, "/log", "Log", active == Some(Tab::Log)))
                            }
                        }
                        div class="right" {
                            form method="post" action="/theme" {
                                input type="hidden" name="to" value=(theme.other());
                                button class="quiet" type="submit" { (theme.switch_label()) }
                            }
                            form method="post" action="/logout" {
                                button class="quiet" type="submit" { "Sign out" }
                            }
                            span class="avatar" { (viewer.0.as_str().chars().next().unwrap_or('?').to_uppercase()) }
                        }
                    }
                }
                (body)
            }
        }
    }
}

fn tab(repo: &str, path: &str, label: &str, active: bool) -> Markup {
    html! {
        a class={ "tab" @if active { " active" } } href={ "/" (repo) (path) } { (label) }
    }
}

fn state_dot(state: ChangeState) -> Markup {
    let class = match state {
        ChangeState::Open => "dot idle",
        ChangeState::Merged => "dot ok",
        ChangeState::Abandoned => "dot bad",
    };
    html! { span class=(class) {} }
}

fn short(oid: &str) -> &str {
    &oid[..oid.len().min(7)]
}

fn clock(ts: &str) -> &str {
    ts.get(11..16).unwrap_or(ts)
}

pub fn login(theme: Theme, dev: bool, error: Option<&str>) -> Markup {
    layout(
        theme,
        None,
        None,
        None,
        "Sign in",
        html! {
            div class="center" {
                form class="login" method="post" action="/login" {
                    div class="mark" {
                        span class="stones" aria-hidden="true" { span {} span {} span {} }
                        b { "cairn" }
                    }
                    @if let Some(error) = error {
                        p class="error" { (error) }
                    }
                    div {
                        label for="token" { "API token" }
                        input id="token" name="token" type="password" autocomplete="off" autofocus;
                    }
                    @if dev {
                        div {
                            label for="principal" { "Or a principal name — dev mode accepts asserted identity" }
                            input id="principal" name="principal" type="text" autocomplete="off";
                        }
                    }
                    button class="btn" type="submit" { "Sign in" }
                    p class="hint" { "Mint a token with " code { "cairn admin mint-token" } }
                }
            }
        },
    )
}

pub fn home(theme: Theme, viewer: &Viewer, repos: &[Repo]) -> Markup {
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Repositories",
        html! {
            div class="sechead" { b { "Repositories" } span { (repos.len()) } }
            @if repos.is_empty() {
                p class="empty" { "No repositories yet. Create one over the API: POST /api/repos" }
            }
            @for repo in repos {
                a class="trow" href={ "/" (repo.name) } style="grid-template-columns: minmax(0,1fr) auto;" {
                    span style="font-weight: 500;" { (repo.name) }
                    span class="sec3" { (repo.default_branch) }
                }
            }
        },
    )
}

pub fn error_page() -> Markup {
    layout(
        Theme::Dark,
        None,
        None,
        None,
        "Error",
        html! {
            div class="center" { p class="plain" { "Something went wrong on our side. The log has the details." } }
        },
    )
}

pub fn not_found_page() -> Markup {
    layout(
        Theme::Dark,
        None,
        None,
        None,
        "Not found",
        html! {
            div class="center" { p class="plain" { "Nothing lives at this path." } }
        },
    )
}

#[allow(clippy::too_many_arguments)]
pub fn repository(
    theme: Theme,
    viewer: &Viewer,
    repo: &str,
    branch: &str,
    tip: Option<&str>,
    path: &str,
    entries: &[Entry],
    readme: Option<&str>,
    sidebar: &Sidebar,
) -> Markup {
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Code),
        repo,
        html! {
            div class="cols2" {
                div {
                    div class="repo-bar" {
                        span class="branch" { (branch) }
                        @if let Some(tip) = tip {
                            span class="tip" { code { (short(tip)) } }
                        }
                        span class="stats" { "clone " code { "/git/" (repo) } }
                    }
                    @if !path.is_empty() {
                        div class="crumbs" { (breadcrumbs(repo, path)) }
                    }
                    @if tip.is_none() {
                        p class="empty" { "Empty repository. Push to " code { "refs/for/" (branch) } " to open its first change." }
                    } @else if entries.is_empty() && !path.is_empty() {
                        p class="empty" { "Nothing here." }
                    }
                    div class="ftable" {
                        @for entry in entries {
                            @let target = if path.is_empty() {
                                entry.name.clone()
                            } else {
                                format!("{path}/{}", entry.name)
                            };
                            div class="trow link" {
                                a class={ "fname" @if entry.is_dir { " dir" } }
                                  href={ "/" (repo) "/tree/" (target) } { (entry.name) }
                                @if let Some(change) = &entry.change {
                                    a class="last sec2" href={ "/" (repo) "/changes/" (change.number) } {
                                        "#" (change.number) " " (change.title)
                                    }
                                    span class="sec3 r" { (change.owner) }
                                } @else {
                                    span class="last sec2" { (entry.subject.as_deref().unwrap_or("")) }
                                    span {}
                                }
                            }
                        }
                    }
                    @if let Some(readme) = readme {
                        div class="readme" { (markdown(readme)) }
                    }
                }
                div class="colr" {
                    section class="side-sec" {
                        header {
                            h2 { "Open changes" }
                            span { (sidebar.open_changes.len()) }
                        }
                        @if sidebar.open_changes.is_empty() { p class="none" { "None open." } }
                        @for change in &sidebar.open_changes {
                            a class="srow" href={ "/" (repo) "/changes/" (change.number) } {
                                (state_dot(change.state))
                                span class="t" { "#" (change.number) " " (change.title) }
                                span class="age" { "r" (change.latest_revision) }
                            }
                        }
                    }
                    section class="side-sec" {
                        header {
                            h2 { "Landing" }
                            span { (branch) }
                        }
                        @if sidebar.queue.is_empty() { p class="none" { "Queue is empty." } }
                        @for (index, entry) in sidebar.queue.iter().enumerate() {
                            div class="srow" {
                                span class="sec3" { (index + 1) }
                                span class={ "t" @if index == 0 { " landing-line" } } {
                                    (change_short(&sidebar.numbers, entry.change.as_str()))
                                }
                            }
                        }
                    }
                    section class="side-sec" {
                        header {
                            h2 { "Fleet" }
                            span { (sidebar.sessions.len()) }
                        }
                        @if sidebar.sessions.is_empty() { p class="none" { "No active sessions." } }
                        @for session in &sidebar.sessions {
                            @let held = sidebar
                                .leases
                                .iter()
                                .find(|l| l.session == session.id);
                            div class="srow" {
                                span class="dot ok" {}
                                span class="t" { (session.agent) }
                                @if let Some(lease) = held {
                                    span class="age" { (lease.paths.join(", ")) }
                                } @else {
                                    span class="age" { "working" }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

fn breadcrumbs(repo: &str, path: &str) -> Markup {
    let mut segments = Vec::new();
    let mut acc = String::new();
    for part in path.split('/') {
        if !acc.is_empty() {
            acc.push('/');
        }
        acc.push_str(part);
        segments.push((part.to_owned(), acc.clone()));
    }
    html! {
        a href={ "/" (repo) } { (repo) }
        @for (part, target) in &segments {
            " / "
            a href={ "/" (repo) "/tree/" (target) } { (part) }
        }
    }
}

/// README markdown with raw HTML stripped: content renders, markup
/// from the file never executes.
fn markdown(source: &str) -> Markup {
    use pulldown_cmark::{Event as MdEvent, Parser, html::push_html};
    let events = Parser::new(source)
        .filter(|event| !matches!(event, MdEvent::Html(_) | MdEvent::InlineHtml(_)));
    let mut out = String::new();
    push_html(&mut out, events);
    PreEscaped(out)
}

pub fn file(
    theme: Theme,
    viewer: &Viewer,
    repo: &str,
    path: &str,
    text: &str,
    landed_by: Option<&Change>,
) -> Markup {
    let lines: Vec<&str> = text.split('\n').collect();
    // A trailing newline is a line terminator, not an empty last line.
    let lines = match lines.split_last() {
        Some((last, rest)) if last.is_empty() && !rest.is_empty() => rest,
        _ => &lines[..],
    };
    let binary = text.contains('\u{0}');
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Code),
        path,
        html! {
            div class="crumbs" { (breadcrumbs(repo, path)) }
            div class="file-bar" {
                span { (lines.len()) " lines" }
                @if let Some(change) = landed_by {
                    span class="sep" { "·" }
                    span { "last landed by " }
                    a class="link" href={ "/" (repo) "/changes/" (change.number) } {
                        "#" (change.number) " " (change.title)
                    }
                }
                a class="right-link link" href={ "/" (repo) "/blame/" (path) } { "Blame" }
            }
            @if binary {
                p class="empty" { "Binary file — nothing to show." }
            } @else {
                div class="source" {
                    @for (index, line) in lines.iter().enumerate() {
                        div class="cline" {
                            span class="no" { (index + 1) }
                            span class={ "src" @if is_comment(line) { " comment" } } { (line) }
                        }
                    }
                }
            }
        },
    )
}

/// Comments read as asides, so they are set in the secondary ink. A
/// heuristic across languages, kept deliberately conservative: `#` only
/// counts when followed by a space, so Rust attributes and C includes
/// stay in full ink.
fn is_comment(line: &str) -> bool {
    let t = line.trim_start();
    t.starts_with("//")
        || t.starts_with("/*")
        || t.starts_with('*')
        || t.starts_with("--")
        || t.starts_with("# ")
        || t == "#"
}

pub fn changes(theme: Theme, viewer: &Viewer, repo: &str, changes: &[Change]) -> Markup {
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Changes),
        "Changes",
        html! {
            div class="sechead" { b { "Changes" } span { (changes.len()) } }
            div class="ctable" {
                @for change in changes {
                    a class="trow" href={ "/" (repo) "/changes/" (change.number) } {
                        (state_dot(change.state))
                        span class="sec3" { "#" (change.number) }
                        span style="font-weight: 500;" { (change.title) }
                        span class="sec2" { (change.owner) }
                        span class="sec3 r" { "r" (change.latest_revision) }
                    }
                }
            }
        },
    )
}

pub struct ChangePage<'a> {
    pub theme: Theme,
    pub viewer: &'a Viewer,
    pub repo: &'a str,
    pub change: &'a Change,
    pub task: Option<&'a Task>,
    pub revisions: &'a [Revision],
    pub shown: i64,
    pub files: &'a [FileDiff],
    pub claims: &'a [Claim],
    pub verifications: &'a [Verification],
    pub verdicts: &'a [Verdict],
    pub trace: &'a PolicyTrace,
    pub queued: bool,
    pub error: Option<&'a str>,
}

pub fn change(page: ChangePage) -> Markup {
    let ChangePage {
        theme,
        viewer,
        repo,
        change,
        task,
        revisions,
        shown,
        files,
        claims,
        verifications,
        verdicts,
        trace,
        queued,
        error,
    } = page;
    let title = format!("#{} {}", change.number, change.title);
    let satisfied = trace.requirements.iter().filter(|r| r.satisfied).count();
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Changes),
        &title,
        html! {
            @if let Some(error) = error {
                p class="flash" { (error) }
            }
            div class="chg-title" {
                div class="line1" {
                    span class="ref" { "#" (change.number) }
                    h1 { (change.title) }
                }
                div class="meta" {
                    span { (state_dot(change.state)) " " (change.state.as_str()) }
                    span class="sep" { "·" }
                    span { (change.owner) }
                    @if let Some(task) = task {
                        span class="sep" { "·" }
                        span { "task: " (task.title) }
                    }
                    span class="sep" { "·" }
                    span { "targets " (change.target) }
                    @if queued {
                        span class="sep" { "·" }
                        span { "in the landing queue" }
                    }
                }
                div class="revtabs" {
                    @for revision in revisions {
                        a class={ "revtab" @if revision.number == shown { " active" } }
                          href={ "/" (repo) "/changes/" (change.number) "?r=" (revision.number) } {
                            "r" (revision.number)
                        }
                    }
                }
            }
            (disagreement(verdicts))
            div class="chg-split" {
                div {
                    @if files.is_empty() {
                        p class="nodiff" { "No diff to show for this revision." }
                    }
                    @for file in files {
                        div class="file-head" { code { (file.path) } }
                        @for hunk in &file.hunks {
                            div class="hunk" {
                                div class="hunk-head" { (hunk.header) }
                                @for line in &hunk.lines {
                                    @let (class, sign) = match line.kind {
                                        LineKind::Add => ("ln add", "+"),
                                        LineKind::Del => ("ln del", "−"),
                                        LineKind::Context => ("ln ctx", ""),
                                    };
                                    div class=(class) {
                                        span class="no" { (line.number) }
                                        span class="sign" { (sign) }
                                        span class="code" { (line.text) }
                                    }
                                }
                            }
                        }
                    }
                    @if change.state == ChangeState::Open {
                        form class="composer" method="post" action={ "/" (repo) "/changes/" (change.number) "/verdict" } {
                            input type="hidden" name="revision" value=(shown);
                            select name="domain" aria-label="Domain" {
                                option value="correctness" { "correctness" }
                                option value="security" { "security" }
                                option value="design" { "design" }
                                option value="style" { "style" }
                            }
                            button class="vbtn" type="submit" name="disposition" value="approve" { "Approve" }
                            button class="vbtn" type="submit" name="disposition" value="concern" { "Concern" }
                            button class="vbtn" type="submit" name="disposition" value="block" { "Block" }
                            input type="text" name="rationale" placeholder="Why — required" required;
                        }
                    }
                }
                div class="colr" {
                    div class="rsec" {
                        span class="cap" { "Verification" }
                        @if claims.is_empty() { div class="vrow" { span class="s un" { "○" } span { "No claims on r" (shown) } } }
                        @for claim in claims {
                            (claim_row(claim, verifications))
                        }
                    }
                    div class="rsec" {
                        span class="cap" { "Judgment" }
                        @if verdicts.is_empty() { div class="vrow" { span class="s un" { "○" } span { "No verdicts on r" (shown) } } }
                        @for verdict in verdicts {
                            (verdict_row(verdict))
                        }
                    }
                    @if change.state == ChangeState::Open {
                        div class="ready" {
                            div class="head" {
                                b { @if trace.satisfied { "Ready" } @else { "Not ready" } }
                                span { (satisfied) " of " (trace.requirements.len()) }
                            }
                            @for requirement in &trace.requirements {
                                div class={ "req" @if !requirement.satisfied { " unmet" } } {
                                    span class="s" { @if requirement.satisfied { "✓" } @else { "✕" } }
                                    span { (requirement.description) }
                                }
                            }
                            @if queued {
                                p class="note" { "Queued — the train lands it from here." }
                            } @else {
                                form method="post" action={ "/" (repo) "/changes/" (change.number) "/enqueue" } {
                                    button class="btn wide" type="submit" disabled[!trace.satisfied] { "Enqueue" }
                                }
                            }
                        }
                    }
                }
            }
        },
    )
}

/// Where reviewers reached opposite conclusions, put the positions
/// beside each other. This is the one place a human's judgment is
/// provably worth more than another review, so it gets the top of the
/// page rather than a line in a list.
fn disagreement(verdicts: &[Verdict]) -> Markup {
    let favour: Vec<&Verdict> = verdicts
        .iter()
        .filter(|v| v.disposition == Disposition::Approve)
        .collect();
    let against: Vec<&Verdict> = verdicts
        .iter()
        .filter(|v| v.disposition == Disposition::Block)
        .collect();
    let reserved: Vec<&Verdict> = verdicts
        .iter()
        .filter(|v| v.disposition == Disposition::Concern)
        .collect();
    // Only a genuine conflict qualifies: someone for, someone against.
    if favour.is_empty() || (against.is_empty() && reserved.is_empty()) {
        return html! {};
    }
    html! {
        section class="disagree" {
            header {
                h2 { "Reviewers disagree" }
                span { "your judgment decides this" }
            }
            div class="sides" {
                div class="side" {
                    span class="pos ok" { "In favour" }
                    @for verdict in &favour { (position(verdict)) }
                }
                div class="side" {
                    span class="pos bad" {
                        @if against.is_empty() { "Reserved" } @else { "Against" }
                    }
                    @for verdict in against.iter().chain(reserved.iter()) { (position(verdict)) }
                }
            }
        }
    }
}

fn position(verdict: &Verdict) -> Markup {
    html! {
        div class="stance" {
            div class="who-line" {
                span class="nm" { (verdict.by) }
                span class="sec3" { (verdict.domain.as_str()) }
            }
            q { (verdict.rationale) }
        }
    }
}

fn claim_row(claim: &Claim, verifications: &[Verification]) -> Markup {
    let runs: Vec<&Verification> = verifications
        .iter()
        .filter(|v| v.claim == claim.id)
        .collect();
    let disputed = runs.iter().any(|v| !v.agrees);
    html! {
        div class="vrow" {
            @if disputed { span class="s bad" { "!" } }
            @else if claim.passed { span class="s ok" { "✓" } }
            @else { span class="s bad" { "✕" } }
            div {
                b { (claim.kind.as_str()) } " · " (claim.summary)
                @if let Some(command) = &claim.command {
                    div class="cmd" { (command) }
                }
                @for run in &runs {
                    div class={ "run" @if !run.agrees { " disputed" } } {
                        (run.by)
                        @if run.agrees { " reproduced this" } @else { " could not reproduce this" }
                        ": " (run.observed)
                    }
                }
                @if runs.is_empty() && claim.command.is_some() {
                    div class="run none" { "not re-run by anyone" }
                }
            }
        }
        @for unchecked in &claim.unchecked {
            div class="vrow" {
                span class="s un" { "○" }
                div { "not checked — " (unchecked) }
            }
        }
    }
}

fn verdict_row(verdict: &Verdict) -> Markup {
    let disp = match verdict.disposition {
        Disposition::Approve => ("disp ok", "approve"),
        Disposition::Concern => ("disp warn", "concern"),
        Disposition::Block => ("disp bad", "block"),
    };
    html! {
        div class="vrow" {
            @match verdict.disposition {
                Disposition::Approve => { span class="s ok" { "✓" } }
                Disposition::Concern => { span class="s un" { "○" } }
                Disposition::Block => { span class="s bad" { "✕" } }
            }
            div {
                div class="who-line" {
                    span class="nm" { (verdict.by) }
                    span class=(disp.0) { (disp.1) }
                    span class="sec3" { (verdict.domain.as_str()) }
                }
                q { (verdict.rationale) }
            }
        }
    }
}

pub fn landing(
    theme: Theme,
    viewer: &Viewer,
    repo: &str,
    branch: &str,
    data: &LandingData,
) -> Markup {
    let numbers: Refs = data
        .numbers
        .iter()
        .map(|(id, (number, title))| (id.as_str(), (*number, title.as_str())))
        .collect();
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Landing),
        "Landing",
        html! {
            div class="cols2" {
                div {
                    (brief(repo, &data.brief))
                    div class="need" {
                        div class="sechead" { b { "Needs you" } span { (data.needs_you.len()) } }
                        @if data.needs_you.is_empty() {
                            div class="trow sec3" { span {} span { "Nothing is waiting on a human." } span {} }
                        }
                        @for item in &data.needs_you {
                            a class="trow" href={ "/" (repo) "/changes/" (item.change.number) }
                              title=(attention_evidence(item)) {
                                span class="sec3" { "#" (item.change.number) }
                                span style="font-weight: 500;" { (item.change.title) }
                                span class="reasons" {
                                    @for (index, signal) in item.signals.iter().enumerate() {
                                        @if index > 0 { span class="sec3" { " · " } }
                                        span class={ @if index == 0 { "lead" } @else { "sec3" } } {
                                            (signal.description)
                                        }
                                    }
                                }
                            }
                        }
                    }
                    div {
                        div class="sechead" { b { "Landing" } span { (branch) } }
                        @if data.queue.is_empty() && data.outcomes.is_empty() {
                            div class="lane-row" { span {} span class="sec3" { "Nothing queued yet." } span {} }
                        }
                        @for (index, entry) in data.queue.iter().enumerate() {
                            div class="lane-row" {
                                span class="pos" { (index + 1) }
                                span class={ "t" @if index == 0 { " landing-line" } } {
                                    (change_ref(&numbers, entry.change.as_str()))
                                }
                                span class="st" { @if index == 0 { "landing" } @else { "queued" } }
                            }
                        }
                        @for outcome in &data.outcomes {
                            (outcome_row(&numbers, outcome))
                        }
                    }
                }
                div class="colr" {
                    section class="side-sec" {
                        header {
                            h2 { "Live" }
                            span { "seq " (data.latest_seq) }
                        }
                        @for envelope in &data.live {
                            (event_row(&numbers, envelope))
                        }
                    }
                    section class="side-sec" {
                        header {
                            h2 { "Fleet" }
                            span { (data.sessions.len()) }
                        }
                        @if data.sessions.is_empty() { p class="none" { "No active sessions." } }
                        @for session in &data.sessions {
                            div class="srow" {
                                span class="dot ok" {}
                                span class="t" { (session.agent) }
                                span class="age" { "working" }
                            }
                        }
                    }
                }
            }
        },
    )
}

type Refs<'a> = HashMap<&'a str, (i64, &'a str)>;

/// A change referred to the way a person would: number and title.
fn change_ref(numbers: &Refs, id: &str) -> Markup {
    match numbers.get(id) {
        Some((number, title)) => html! { "#" (number) " " (title) },
        None => html! { code { (short(id)) } },
    }
}

/// Everything behind a ranking, for the reader who wants the facts.
fn attention_evidence(item: &cairn_core::AttentionItem) -> String {
    item.signals
        .iter()
        .map(|s| format!("{}: {}", s.description, s.evidence))
        .collect::<Vec<_>>()
        .join("\n")
}

/// A compact reference for narrow columns: number and title, elided
/// by the layout rather than truncated here.
fn change_short(numbers: &HashMap<String, (i64, String)>, id: &str) -> Markup {
    match numbers.get(id) {
        Some((number, title)) => html! { "#" (number) " " (title) },
        None => html! { code { (short(id)) } },
    }
}

/// Just the number, where the title would repeat what sits beside it.
fn change_num(numbers: &Refs, id: &str) -> Markup {
    match numbers.get(id) {
        Some((number, _)) => html! { "#" (number) },
        None => html! { code { (short(id)) } },
    }
}

fn outcome_row(numbers: &Refs, envelope: &Envelope) -> Markup {
    match &envelope.event {
        Event::ChangeMerged {
            change, merged_as, ..
        } => html! {
            div class="lane-row" {
                span class="pos" { span class="dot ok" {} }
                span class="t sec2" { (change_ref(numbers, change.as_str())) }
                span class="st" {
                    "landed"
                    @if let Some(oid) = merged_as { " as " code { (short(oid)) } " · rebased" }
                }
            }
        },
        Event::ChangeDequeued { change, reason } => html! {
            div class="lane-row" {
                span class="pos" { span class="dot bad" {} }
                span class="t sec2" { (change_ref(numbers, change.as_str())) }
                span class="st" { (reason) }
            }
        },
        _ => html! {},
    }
}

fn event_row(numbers: &Refs, envelope: &Envelope) -> Markup {
    let (dot, text) = describe(numbers, envelope);
    html! {
        div class="ev" {
            span class=(dot) {}
            div {
                (text)
                div class="when" { (clock(&envelope.ts)) }
            }
        }
    }
}

fn describe(numbers: &Refs, envelope: &Envelope) -> (&'static str, Markup) {
    let actor = envelope.actor.as_str();
    match &envelope.event {
        Event::ChangeMerged {
            change, merged_as, ..
        } => (
            "dot ok",
            html! {
                b { (change_num(numbers, change.as_str())) " landed" }
                @if let Some(oid) = merged_as { " as " code { (short(oid)) } }
            },
        ),
        Event::ChangeDequeued { change, .. } => (
            "dot bad",
            html! {
                b { (change_num(numbers, change.as_str())) } " left the queue"
            },
        ),
        Event::ChangeEnqueued { change } => (
            "dot idle",
            html! {
                b { (change_num(numbers, change.as_str())) } " entered the queue"
            },
        ),
        Event::RevisionPushed {
            change, revision, ..
        } => (
            "dot idle",
            html! {
                b { (actor) } " pushed r" (revision) " of " (change_num(numbers, change.as_str()))
            },
        ),
        Event::VerdictGiven {
            change,
            disposition,
            ..
        } => (
            match disposition {
                Disposition::Block => "dot bad",
                Disposition::Concern => "dot idle",
                Disposition::Approve => "dot ok",
            },
            html! {
                b { (actor) } " "
                @match disposition {
                    Disposition::Approve => { "approved " }
                    Disposition::Concern => { "raised a concern on " }
                    Disposition::Block => { "blocked " }
                }
                (change_num(numbers, change.as_str()))
            },
        ),
        Event::ClaimAttached {
            change,
            claim_kind,
            passed,
            ..
        } => (
            if *passed { "dot ok" } else { "dot bad" },
            html! {
                b { (actor) } " recorded a " (claim_kind.as_str()) " check on "
                (change_num(numbers, change.as_str()))
            },
        ),
        Event::ChangeOpened { number, title, .. } => (
            "dot idle",
            html! {
                b { (actor) } " opened #" (number) " " (title)
            },
        ),
        Event::TaskCreated { title, .. } => (
            "dot idle",
            html! { b { (actor) } " filed a task: " (title) },
        ),
        Event::TaskClaimed { .. } => ("dot idle", html! { b { (actor) } " claimed a task" }),
        Event::SessionOpened { .. } => ("dot idle", html! { b { (actor) } " started a session" }),
        Event::PathsDeclared { paths, .. } => (
            "dot idle",
            html! {
                b { (actor) } " is working on " (paths.join(", "))
            },
        ),
        Event::SessionEnded { state, .. } => (
            "dot idle",
            html! {
                b { (actor) } " ended a session · " (state.as_str())
            },
        ),
        Event::GrantIssued { grantee, .. } => (
            "dot idle",
            html! {
                b { (actor) } " granted " (grantee.as_str())
            },
        ),
        Event::GrantRevoked { .. } => ("dot idle", html! { b { (actor) } " revoked a grant" }),
        Event::RepoCreated { repo, .. } => ("dot idle", html! { b { (actor) } " created " (repo) }),
        Event::PolicySet { repo, .. } => (
            "dot idle",
            html! {
                b { (actor) } " set the policy for " (repo)
            },
        ),
        Event::MirrorSet { repo, mirror } => (
            "dot idle",
            html! {
                b { (actor) }
                @match mirror {
                    Some(mirror) => { " mirrors " (repo) " to " (mirror.url) }
                    None => { " stopped mirroring " (repo) }
                }
            },
        ),
        Event::MirrorPushed {
            branch, ok, detail, ..
        } => (
            if *ok { "dot ok" } else { "dot bad" },
            html! {
                @if *ok {
                    "mirrored " b { (branch) } " outward"
                } @else {
                    b { "mirror push failed" } " for " (branch)
                    @if let Some(detail) = detail { " — " (detail) }
                }
            },
        ),
        Event::PrincipalRegistered { principal, .. } => (
            "dot idle",
            html! {
                b { (actor) } " registered " (principal.as_str())
            },
        ),
        Event::TaskStateChanged { state, .. } => (
            "dot idle",
            html! {
                b { (actor) } " moved a task to " (state.as_str())
            },
        ),
        Event::ClaimVerified { change, agrees, .. } => (
            if *agrees { "dot ok" } else { "dot bad" },
            html! {
                b { (actor) }
                @if *agrees { " reproduced a claim on " } @else { " could not reproduce a claim on " }
                (change_num(numbers, change.as_str()))
            },
        ),
        Event::RebaseFailed { change, files, .. } => (
            "dot bad",
            html! {
                b { (change_num(numbers, change.as_str())) }
                " could not be carried onto the new base — conflicts in "
                (files.join(", "))
            },
        ),
        Event::ChangeAbandoned { change, .. } => (
            "dot bad",
            html! {
                b { (change_num(numbers, change.as_str())) } " was abandoned"
            },
        ),
        Event::TokenMinted { principal, .. } => (
            "dot idle",
            html! {
                b { (actor) } " minted a token for " (principal.as_str())
            },
        ),
        Event::TokenRevoked { .. } => ("dot idle", html! { b { (actor) } " revoked a token" }),
    }
}

pub fn log(
    theme: Theme,
    viewer: &Viewer,
    repo: &str,
    numbers: &HashMap<String, (i64, String)>,
    after: i64,
    events: &[Envelope],
) -> Markup {
    let refs: Refs = numbers
        .iter()
        .map(|(id, (number, title))| (id.as_str(), (*number, title.as_str())))
        .collect();
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Log),
        "Log",
        html! {
            div class="sechead" { b { "Log" } span { "from " (after + 1) } }
            div class="log" {
                @for envelope in events {
                    @let (_, text) = describe(&refs, envelope);
                    div class="trow" {
                        span class="sec3" { (envelope.seq.0) }
                        span class="sec3" { (envelope.event.kind()) }
                        span class="sec2" { (envelope.actor) }
                        span { (text) }
                    }
                }
            }
            @if let Some(last) = events.last() {
                div class="pager" {
                    a href={ "/" (repo) "/log?after=" (last.seq.0) } { "Older → newer, next page" }
                }
            }
        },
    )
}

/// Blame that answers what was *known*, not just who typed. Each line
/// carries the change that landed it; lines whose change never ran an
/// executed check, or whose claims named a gap, are marked — the
/// question "which code here was never actually verified" is the one
/// this view exists to answer.
pub fn blame(theme: Theme, viewer: &Viewer, repo: &str, path: &str, rows: &[BlameRow]) -> Markup {
    // A line is flagged when the judgment behind it left something
    // open: no executed check at all, or a claim that named a gap.
    let flagged = |row: &BlameRow| {
        row.provenance
            .as_ref()
            .is_some_and(|p| !p.executed_check() || !p.unchecked().is_empty())
    };
    let with_gaps = rows.iter().filter(|r| flagged(r)).count();
    let unattributed = rows.iter().filter(|r| r.provenance.is_none()).count();
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Code),
        path,
        html! {
            div class="crumbs" { (breadcrumbs(repo, path)) }
            div class="file-bar" {
                span { (rows.len()) " lines" }
                @if with_gaps > 0 {
                    span class="sep" { "·" }
                    span class="warn" { (with_gaps) " under a declared gap" }
                }
                @if unattributed > 0 {
                    span class="sep" { "·" }
                    span { (unattributed) " outside the graph" }
                }
                a class="right-link link" href={ "/" (repo) "/tree/" (path) } { "Source" }
            }
            div class="source blame" {
                @for (index, row) in rows.iter().enumerate() {
                    // Attribution is labelled once per run of lines from
                    // the same change, the way a reader scans it.
                    @let starts_run = index == 0
                        || rows[index - 1].provenance.as_ref().map(|p| p.change.number)
                            != row.provenance.as_ref().map(|p| p.change.number);
                    div class={ "cline" @if flagged(row) { " gap" } @if starts_run { " run" } } {
                        span class="who" {
                            @if starts_run {
                                @match &row.provenance {
                                    Some(p) => {
                                        a class="link" href={ "/" (repo) "/changes/" (p.change.number) }
                                          title=(attribution(p)) {
                                            "#" (p.change.number)
                                        }
                                    }
                                    None => { span class="sec3" { "—" } }
                                }
                            }
                        }
                        span class="no" { (row.number) }
                        span class={ "src" @if is_comment(&row.text) { " comment" } } { (row.text) }
                    }
                }
            }
            (coverage_gaps(repo, rows))
        },
    )
}

/// The tooltip a line carries: what was claimed, who approved, and
/// what nobody checked.
fn attribution(p: &cairn_core::Provenance) -> String {
    let mut parts = vec![p.change.title.clone()];
    for claim in &p.claims {
        let mark = if claim.passed { "passed" } else { "failed" };
        parts.push(format!(
            "{} {mark} — {}",
            claim.kind.as_str(),
            claim.summary
        ));
    }
    for verdict in p.approvals() {
        parts.push(format!(
            "approved by {} ({})",
            verdict.by,
            verdict.domain.as_str()
        ));
    }
    for gap in p.unchecked() {
        parts.push(format!("not checked: {gap}"));
    }
    parts.join("\n")
}

/// Everything the changes behind this file declared out of scope,
/// collected in one place.
fn coverage_gaps(repo: &str, rows: &[BlameRow]) -> Markup {
    let mut seen: Vec<(i64, String, String)> = Vec::new();
    for row in rows {
        let Some(p) = &row.provenance else { continue };
        for gap in p.unchecked() {
            let entry = (p.change.number, p.change.title.clone(), gap.to_owned());
            if !seen.contains(&entry) {
                seen.push(entry);
            }
        }
    }
    html! {
        @if !seen.is_empty() {
            section class="gaps" {
                header { h2 { "Declared gaps" } span { (seen.len()) } }
                @for (number, title, gap) in &seen {
                    div class="gap-row" {
                        a class="link sec2" href={ "/" (repo) "/changes/" (number) } { "#" (number) " " (title) }
                        span { (gap) }
                    }
                }
            }
        }
    }
}

/// The state of things lately, in sentences whose every number is the
/// size of something the reader can go and look at. Nothing here is
/// generated prose: it is the log, counted.
fn brief(repo: &str, brief: &Brief) -> Markup {
    let quiet = brief.landed == 0
        && brief.dequeued.is_empty()
        && brief.failed_sessions.is_empty()
        && brief.disputed == 0;
    html! {
        section class="brief" {
            @if quiet {
                p { "Nothing has landed or failed recently." }
            } @else {
                p {
                    @if brief.landed > 0 {
                        "The train landed "
                        a class="link" href={ "/" (repo) "/log?after=" (brief.since) } {
                            @if brief.landed == 1 { "one change" } @else { (brief.landed) " changes" }
                        }
                        ". "
                    }
                    @if brief.disputed > 0 {
                        @if brief.disputed == 1 { "One claim was disputed by a runner. " }
                        @else { (brief.disputed) " claims were disputed by runners. " }
                    }
                    @for (change, reason) in &brief.dequeued {
                        (change) " left the queue — " (reason) ". "
                    }
                }
                @for lesson in &brief.failed_sessions {
                    p class="lesson" {
                        (lesson.agent) " gave up on " (lesson.task_title) ": " (lesson.outcome)
                    }
                }
            }
            div class="src" {
                "counted from the log after " (brief.since)
                @if !brief.failed_sessions.is_empty() {
                    " · "
                    a class="link" href={ "/" (repo) "/lessons" } { "all lessons" }
                }
            }
        }
    }
}

/// What earlier attempts learned. A corpus nobody has to maintain: the
/// protocol already refuses to let a session end without recording an
/// outcome, so failure leaves knowledge behind by construction.
pub fn lessons(
    theme: Theme,
    viewer: &Viewer,
    repo: &str,
    search: Option<&str>,
    lessons: &[cairn_core::Lesson],
) -> Markup {
    layout(
        theme,
        Some(viewer),
        Some(repo),
        Some(Tab::Lessons),
        "Lessons",
        html! {
            div class="sechead" {
                b { "Lessons" }
                span { (lessons.len()) }
                form class="search-form" method="get" action={ "/" (repo) "/lessons" } {
                    input type="search" name="q" value=[search]
                          placeholder="Has anyone tried this before?";
                }
            }
            @if lessons.is_empty() {
                p class="empty" {
                    @match search {
                        Some(term) => { "Nothing recorded matches " (term) "." }
                        None => { "No sessions have ended yet." }
                    }
                }
            }
            @for lesson in lessons {
                div class="lesson-row" {
                    span class={ "dot " @if lesson.state == cairn_core::SessionState::Failed { "bad" } @else { "ok" } } {}
                    div {
                        div class="head" {
                            span class="t" { (lesson.task_title) }
                            span class="sec3" { (lesson.agent) }
                            span class="sec3" { (lesson.state.as_str()) }
                        }
                        p { (lesson.outcome) }
                    }
                }
            }
        },
    )
}
