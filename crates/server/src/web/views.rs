//! Every page as a maud template. All interpolation is escaped by
//! maud; the one deliberate exception is README markdown, which is
//! rendered with raw HTML events stripped before it gets here.

use super::diff::{FileDiff, LineKind};
use super::{Brief, LandingData, Sidebar, Viewer};
use cairn_core::{
    Change, ChangeState, Claim, Disposition, Envelope, Event, HitKind, Notice, PolicyTrace, Repo,
    Revision, Task, Verdict, Verification, Visibility,
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
    Settings,
}

fn layout(
    theme: Theme,
    viewer: Option<&Viewer>,
    repo: Option<&str>,
    active: Option<Tab>,
    title: &str,
    body: Markup,
) -> Markup {
    layout_with(theme, viewer, repo, active, title, body, None)
}

/// The frame every signed-in page renders inside: a global bar, a
/// sidebar of what you have and who is working, the page itself, and
/// optionally a rail on the right.
fn layout_with(
    theme: Theme,
    viewer: Option<&Viewer>,
    repo: Option<&str>,
    active: Option<Tab>,
    title: &str,
    body: Markup,
    rail: Option<Markup>,
) -> Markup {
    frame(theme, viewer, repo, None, active, title, body, rail)
}

/// A page that belongs to a section of the sidebar - the inbox, people,
/// teams - rather than to a repository. It highlights its entry in the
/// sidebar and renders no repository header, because it is not one.
fn layout_section(
    theme: Theme,
    viewer: &Viewer,
    section: &str,
    title: &str,
    body: Markup,
) -> Markup {
    frame(
        theme,
        Some(viewer),
        None,
        Some(section),
        None,
        title,
        body,
        None,
    )
}

#[allow(clippy::too_many_arguments)]
fn frame(
    theme: Theme,
    viewer: Option<&Viewer>,
    repo: Option<&str>,
    section: Option<&str>,
    active: Option<Tab>,
    title: &str,
    body: Markup,
    rail: Option<Markup>,
) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=(theme.attr()) {
            head {
                meta charset="utf-8";
                meta name="viewport" content="width=device-width, initial-scale=1";
                title { (title) " · cairn" }
                link rel="stylesheet" href=(super::stylesheet_href());
            }
            body {
                @match viewer {
                    Some(viewer) => {
                        div class={ "app" @if rail.is_none() { " narrow" } } {
                            (topbar(theme, viewer))
                            (sidebar(viewer, section.or(repo)))
                            main class="main" {
                                @if let Some(repo) = repo {
                                    div class="repohead" {
                                        span class="repo" { (repo) }
                                        div class="tabs" {
                                            (tab(repo, "", "Code", active == Some(Tab::Code)))
                                            (tab(repo, "/changes", "Changes", active == Some(Tab::Changes)))
                                            (tab(repo, "/landing", "Landing", active == Some(Tab::Landing)))
                                            (tab(repo, "/lessons", "Lessons", active == Some(Tab::Lessons)))
                                            (tab(repo, "/log", "Log", active == Some(Tab::Log)))
                                            @if viewer.1.admin || viewer.1.owned.iter().any(|r| r == repo) {
                                                (tab(repo, "/settings", "Settings", active == Some(Tab::Settings)))
                                            }
                                        }
                                    }
                                }
                                (body)
                            }
                            @if let Some(rail) = rail {
                                aside class="rail" { (rail) }
                            }
                        }
                    }
                    None => (body),
                }
            }
        }
    }
}

fn topbar(theme: Theme, viewer: &Viewer) -> Markup {
    html! {
        div class="bar" {
            a class="brand" href="/" aria-label="Home" {
                span class="stones" aria-hidden="true" { span {} span {} span {} }
                b { "cairn" }
            }
            form class="search" method="get" action="/search" {
                input name="q" type="search" placeholder="Search repositories, changes, people"
                      autocomplete="off" aria-label="Search";
            }
            div class="baractions" {
                a class="quiet" href="/new" { "New" }
                a class="quiet menu" href="#nav" { "Menu" }
                form method="post" action="/theme" {
                    input type="hidden" name="to" value=(theme.other());
                    button class="quiet" type="submit" { (theme.switch_label()) }
                }
                form method="post" action="/logout" {
                    button class="quiet" type="submit" { "Sign out" }
                }
                span class="avatar" title=(viewer.0.as_str()) {
                    (viewer.0.as_str().chars().next().unwrap_or('?').to_uppercase())
                }
            }
        }
    }
}

fn sidebar(viewer: &Viewer, current: Option<&str>) -> Markup {
    let chrome = &viewer.1;
    html! {
        nav class="side" id="nav" {
            h4 { "Repositories" }
            @if chrome.repos.is_empty() {
                div class="row" { span class="n" { "None yet" } span {} }
            }
            @for repo in &chrome.repos {
                a class={ @if current == Some(repo.name.as_str()) { "on" } @else { "" } }
                  href={ "/" (repo.name) } {
                    span { (repo.name) }
                    span class="n" { @if repo.open > 0 { (repo.open) } }
                }
            }

            @if !chrome.working.is_empty() {
                div class="sep" {}
                h4 { "Working now" }
                @for worker in &chrome.working {
                    div class="row" title=(worker.paths.join(", ")) {
                        span class="dotline" { span class="mini live" {} (worker.who) }
                        span class="n" { @if let Some(repo) = &worker.repo { (repo) } }
                    }
                }
            }

            div class="sep" {}
            h4 { "You" }
            a class={ @if current == Some("inbox") { "on" } @else { "" } } href="/inbox" {
                span { "Inbox" } span class="n" { @if chrome.unread > 0 { (chrome.unread) } }
            }
            a href="/you" { span { "Your changes" } span class="n" { @if chrome.yours > 0 { (chrome.yours) } } }
            a href="/agents" { span { "Agents" } span class="n" {} }
            @if chrome.admin {
                a class={ @if current == Some("people") { "on" } @else { "" } } href="/people" {
                    span { "People" } span class="n" {}
                }
                a class={ @if current == Some("teams") { "on" } @else { "" } } href="/teams" {
                    span { "Teams" } span class="n" {}
                }
            }
            a href="/you/tokens" { span { "Tokens" } span class="n" {} }
            a href="/you/settings" { span { "Settings" } span class="n" {} }
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

/// The public page: what this is, and a way to be told when it is
/// ready. Signed-out visitors get this instead of a sign-in form,
/// because a form asks for something they do not have and tells them
/// nothing about why they would want it.
pub fn welcome(theme: Theme, joined: bool, error: Option<&str>) -> Markup {
    layout(
        theme,
        None,
        None,
        None,
        "cairn",
        html! {
            div class="welcome" {
                header {
                    div class="mark" {
                        span class="stones" aria-hidden="true" { span {} span {} span {} }
                        b { "cairn" }
                    }
                    a class="quiet" href="/login" { "Sign in" }
                }

                section class="lede" {
                    h1 { "A git forge that records how software came to exist." }
                    p {
                        "Not who typed which line — what was claimed about the code, who "
                        "re-ran those claims, who judged it, and why anything was allowed "
                        "to land. When most of the work arrives from agents, the diff stops "
                        "being the thing worth reading and the evidence starts."
                    }

                    @if joined {
                        p class="joined" { "You are on the list. We will be in touch." }
                    } @else {
                        form class="join" method="post" action="/waitlist" {
                            input name="email" type="email" required
                                  autocomplete="email" placeholder="you@example.com"
                                  aria-label="Email";
                            button class="btn" type="submit" { "Join the waitlist" }
                        }
                        @if let Some(error) = error {
                            p class="error" { (error) }
                        }
                        p class="fineprint" {
                            "One address, kept so we can tell you when this opens up. "
                            "Ask and it is deleted — it is deliberately not written to the "
                            "log, because a log that cannot forget is the wrong place for a "
                            "person's details."
                        }
                    }
                }

                section class="what" {
                    div class="pair" {
                        h3 { "Claims are contracts, not comments" }
                        p {
                            "\"The tests pass\" is recorded with the command that produced it, "
                            "so somebody else can run it and say whether they saw the same thing. "
                            "A claim nobody could reproduce blocks the change until it is settled."
                        }
                    }
                    div class="pair" {
                        h3 { "Merges explain themselves" }
                        p {
                            "Every merge carries the full evaluation that allowed it — which "
                            "requirements were met, and on what evidence. Months later the "
                            "question \"why did this land?\" has an answer that does not depend "
                            "on anyone remembering."
                        }
                    }
                    div class="pair" {
                        h3 { "Attention is routed, not scrolled" }
                        p {
                            "Open work is ranked by what human judgment is actually worth on "
                            "it — reviewers disagreeing, a disputed claim, code resting on "
                            "argument alone — and a fixed share of unreviewed work is sampled "
                            "regardless, so agent output cannot quietly become unread output."
                        }
                    }
                    div class="pair" {
                        h3 { "Imported history says so" }
                        p {
                            "History that predates the forge is recorded as imported, never "
                            "dressed up as reviewed. The log would rather admit a gap than "
                            "invent a decision."
                        }
                    }
                }

                footer {
                    p {
                        "Early software, self-hosted, and currently hosting itself. "
                        "It speaks ordinary git: clone and push with the client you already have."
                    }
                }
            }
        },
    )
}

/// A page for somebody who is not signed in: the sign-in frame, a
/// heading, and whatever the moment needs.
fn outside(theme: Theme, title: &str, body: Markup) -> Markup {
    layout(
        theme,
        None,
        None,
        None,
        title,
        html! {
            div class="center" {
                div class="login" {
                    div class="mark" {
                        span class="stones" aria-hidden="true" { span {} span {} span {} }
                        b { "cairn" }
                    }
                    p style="font-weight: 500;" { (title) }
                    (body)
                }
            }
        },
    )
}

pub fn forgot(theme: Theme, can_mail: bool, sent: bool, error: Option<&str>) -> Markup {
    outside(
        theme,
        "Reset your password",
        html! {
            @if let Some(error) = error { p class="error" { (error) } }
            @if sent {
                @if can_mail {
                    p { "If that account has an email address on record, a link is on its way. It works once, for thirty minutes." }
                    p class="hint" { "No address on record? The people who run this forge have been told, and can send you a new sign-in link." }
                } @else {
                    p { "The people who run this forge have been told, and can send you a new sign-in link." }
                }
                p class="hint" { a href="/login" { "Back to sign in" } }
            } @else {
                form class="stack" method="post" action="/forgot" {
                    div {
                        label for="who" { "Your name or email" }
                        input id="who" name="who" type="text" autocomplete="username" autofocus;
                    }
                    button class="btn" type="submit" { @if can_mail { "Send a reset link" } @else { "Ask for a new link" } }
                    p class="hint" { a href="/login" { "Back to sign in" } }
                }
            }
        },
    )
}

pub fn reset(theme: Theme, token: &str, error: Option<&str>) -> Markup {
    outside(
        theme,
        "Choose a new password",
        html! {
            @if let Some(error) = error { p class="error" { (error) } }
            form class="stack" method="post" action="/reset" {
                input type="hidden" name="token" value=(token);
                div {
                    label for="password" { "New password" }
                    input id="password" name="password" type="password" autocomplete="new-password" minlength="12" autofocus;
                }
                div {
                    label for="confirm" { "Again" }
                    input id="confirm" name="confirm" type="password" autocomplete="new-password" minlength="12";
                }
                button class="btn" type="submit" { "Set password" }
            }
        },
    )
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
                        label for="principal" { "Name" }
                        input id="principal" name="principal" type="text"
                            autocomplete="username" autocapitalize="none" autofocus;
                    }
                    div {
                        label for="password" { "Password" }
                        input id="password" name="password" type="password"
                            autocomplete="current-password";
                    }
                    button class="btn" type="submit" { "Sign in" }
                    p class="hint" { a href="/forgot" { "Forgot your password?" } }
                    details class="alt" {
                        summary { "Sign in with a token" }
                        div {
                            label for="token" { "API token" }
                            input id="token" name="token" type="password" autocomplete="off";
                        }
                        p class="hint" { "Mint one with " code { "cairn admin mint-token" } }
                    }
                    @if dev {
                        p class="hint" { "Dev mode: a name alone is accepted as asserted identity." }
                    }
                }
            }
        },
    )
}

pub fn home(theme: Theme, viewer: &Viewer, data: &super::HomeData) -> Markup {
    let rail = html! {
        @if !data.lanes.is_empty() {
            div class="card" {
                div class="sechead" { b { "Landing" } span {} }
                @for lane in &data.lanes {
                    div class="line" {
                        span { b { (lane.repo) } " · " (lane.branch) }
                        span class="q" { (lane.queued) " queued" }
                    }
                }
            }
        }
        @if !viewer.1.working.is_empty() {
            div class="card" {
                div class="sechead" { b { "In flight" } span { (viewer.1.working.len()) } }
                @for worker in &viewer.1.working {
                    div class="line" {
                        span {
                            b { (worker.who) }
                            @if let Some(repo) = &worker.repo { " · " (repo) }
                            @if !worker.paths.is_empty() {
                                br;
                                span class="q" { (worker.paths.join(", ")) }
                            }
                        }
                        span class="q" {}
                    }
                }
            }
        }
        @if !data.lessons.is_empty() {
            div class="card" {
                div class="sechead" { b { "Lessons" } span {} }
                @for lesson in &data.lessons {
                    div class="lesson" { (lesson.outcome) }
                }
            }
        }
    };

    layout_with(
        theme,
        Some(viewer),
        None,
        None,
        "Home",
        html! {
            div class="block homeneed" {
                div class="sechead" { b { "Needs you" } span { (data.needs_you.len()) } }
                @if data.needs_you.is_empty() {
                    div class="trow sec3" { span {} span { "Nothing is waiting on a human." } span {} }
                }
                @for entry in &data.needs_you {
                    a class="trow" href={ "/" (entry.repo) "/changes/" (entry.item.change.number) }
                      title=(attention_evidence(&entry.item)) {
                        span class="sec3" { (entry.repo) " #" (entry.item.change.number) }
                        span style="font-weight: 500;" { (entry.item.change.title) }
                        span class="reasons" {
                            @for (index, signal) in entry.item.signals.iter().take(2).enumerate() {
                                @if index > 0 { span class="sec3" { " · " } }
                                span class={ @if index == 0 { "lead" } @else { "sec3" } } {
                                    (signal.description)
                                }
                            }
                            @if entry.item.signals.len() > 2 {
                                span class="sec3" { " · +" (entry.item.signals.len() - 2) }
                            }
                        }
                    }
                }
            }

            @if !data.mine.is_empty() {
                div class="block homemine" {
                    div class="sechead" { b { "Your changes" } span { (data.mine.len()) } }
                    @for (repo, change) in &data.mine {
                        a class="trow" href={ "/" (repo) "/changes/" (change.number) } {
                            span class="sec3" { (repo) " #" (change.number) }
                            span style="font-weight: 500;" { (change.title) }
                            span class="sec3" { "revision " (change.latest_revision) }
                        }
                    }
                }
            }

            @if !data.recent.is_empty() {
                div class="block homefeed" {
                    div class="sechead" { b { "Across your repositories" } span {} }
                    @for line in &data.recent {
                        div class="trow" {
                            span class="sec3" { (line.where_) }
                            span { (line.what) }
                            span class="sec3" { (line.kind) }
                        }
                    }
                }
            }
        },
        Some(rail),
    )
}

/// A forge with nothing in it yet. The first thing anyone sees, so it
/// teaches the model rather than reporting an absence.
pub fn first_run(theme: Theme, viewer: &Viewer) -> Markup {
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Home",
        html! {
            div class="first" {
                h2 { "Nothing here yet" }
                p {
                    "cairn records how software actually came to exist — who claimed what, \
                     who re-ran it, and why anything was allowed to land. It starts \
                     recording from the first push."
                }
                a class="do" href="/new" {
                    b { "Create a repository" }
                    span { "empty, ready for a first push" }
                }
                a class="do" href="/new" {
                    b { "Import from GitHub" }
                    span { "recorded as imported, never as reviewed" }
                }
                a class="do" href="/you/tokens" {
                    b { "Add an agent" }
                    span { "a token and a narrow capability grant" }
                }
            }
        },
    )
}

pub fn search(
    theme: Theme,
    viewer: &Viewer,
    query: &str,
    kind: Option<HitKind>,
    hits: &[super::Hit],
) -> Markup {
    // The filter row rewrites the query rather than adding a control:
    // what it does is visible in the box afterwards, and copyable.
    let without_kind: String = query
        .split_whitespace()
        .filter(|w| !w.to_lowercase().starts_with("kind:"))
        .collect::<Vec<_>>()
        .join(" ");
    let with = |k: Option<HitKind>| -> String {
        let q = match k {
            Some(k) => format!("{} kind:{}", without_kind, k.as_str()),
            None => without_kind.clone(),
        };
        format!("/search?q={}", super::urlencode(q.trim()))
    };
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Search",
        html! {
            div class="sechead" { b { "Search" } span { @if !query.trim().is_empty() { (hits.len()) } } }
            form class="searchbig" method="get" action="/search" {
                input name="q" type="search" value=(query) autofocus
                      placeholder="Repositories, changes, people — or #12, repo:demo, by:scout" aria-label="Search";
            }
            @if !query.trim().is_empty() {
                div class="tabs filters" {
                    a class={ "tab" @if kind.is_none() { " active" } } href=(with(None)) { "All" }
                    @for k in [HitKind::Change, HitKind::Repository, HitKind::Person, HitKind::Task, HitKind::Lesson] {
                        a class={ "tab" @if kind == Some(k) { " active" } } href=(with(Some(k))) {
                            (match k {
                                HitKind::Change => "Changes",
                                HitKind::Repository => "Repositories",
                                HitKind::Person => "People",
                                HitKind::Task => "Tasks",
                                HitKind::Lesson => "Lessons",
                            })
                        }
                    }
                }
            }
            @if query.trim().is_empty() {
                p class="empty" {
                    "Type to search repositories, changes, tasks, lessons and people. "
                    "Narrow with " code { "repo:" } ", " code { "state:open" } ", " code { "by:" } " or " code { "kind:" } "; "
                    code { "#12" } " opens a change by number."
                }
            } @else if hits.is_empty() {
                p class="empty" { "Nothing matches " b { (query) } "." }
            }
            @for hit in hits {
                a class="trow" href=(hit.href) style="grid-template-columns: 92px minmax(0,1fr) auto;" {
                    span class="sec3" { (hit.kind) }
                    span style="font-weight: 500;" { (hit.label) }
                    span class="sec3" { (hit.detail) }
                }
            }
        },
    )
}

pub fn new_repo(theme: Theme, viewer: &Viewer, error: Option<&str>) -> Markup {
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "New repository",
        html! {
            div class="narrowcol" {
                div class="sechead" { b { "New repository" } span {} }
                @if let Some(error) = error {
                    p class="error" { (error) }
                }
                form class="stack" method="post" action="/new" {
                    div {
                        label for="name" { "Name" }
                        input id="name" name="name" type="text" autofocus autocomplete="off"
                              placeholder="lowercase, digits and hyphens";
                    }
                    div {
                        label for="default_branch" { "Default branch" }
                        input id="default_branch" name="default_branch" type="text"
                              autocomplete="off" placeholder="main";
                    }
                    div {
                        label for="source" { "Import from" }
                        input id="source" name="source" type="text" autocomplete="off"
                              placeholder="https://github.com/you/project.git — optional";
                        p class="hint" {
                            "History brought in this way is recorded as imported. \
                             Nothing here was reviewed under this repository's policy, \
                             and the log says so rather than implying otherwise."
                        }
                    }
                    button class="btn" type="submit" { "Create" }
                }
            }
        },
    )
}

pub fn you(theme: Theme, viewer: &Viewer, mine: &[(String, Change)]) -> Markup {
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Your changes",
        html! {
            div class="sechead" { b { "Your open changes" } span { (mine.len()) } }
            @if mine.is_empty() {
                p class="empty" { "Nothing of yours is open." }
            }
            @for (repo, change) in mine {
                a class="trow" href={ "/" (repo) "/changes/" (change.number) }
                  style="grid-template-columns: 120px minmax(0,1fr) auto;" {
                    span class="sec3" { (repo) " #" (change.number) }
                    span style="font-weight: 500;" { (change.title) }
                    span class="sec3" { "revision " (change.latest_revision) }
                }
            }
        },
    )
}

/// What is addressed to the viewer, newest first, grouped by day. An
/// unread row carries a dot and full weight; a read one recedes. Every
/// row is a link to the thing itself, because a notice that cannot be
/// acted on from where it is read is a to-do list somebody has to copy.
pub fn inbox(theme: Theme, viewer: &Viewer, notices: &[Notice], unread: usize) -> Markup {
    layout_section(
        theme,
        viewer,
        "inbox",
        "Inbox",
        html! {
            div class="sechead" {
                b { "Inbox" }
                span { (unread) " unread" }
                @if unread > 0 {
                    form method="post" action="/inbox/read" style="margin-left: auto;" {
                        input type="hidden" name="all" value="1";
                        button class="act" type="submit" { "Mark all read" }
                    }
                }
            }
            @if notices.is_empty() {
                p class="empty" { "Nothing is waiting on you." }
            }
            @let mut day = String::new();
            @for notice in notices {
                @let this_day = day_of(&notice.ts);
                @if this_day != day {
                    div class="day" { (day_label(&this_day)) }
                    ({ day = this_day; "" })
                }
                a class={ "trow notice" @if notice.read { " read" } } href=(notice_href(notice)) {
                    span class="dot" {}
                    span class="what" { (notice.what) }
                    span class="where" {
                        @if let Some(repo) = &notice.repo { (repo) }
                        @if let Some(number) = notice.number { " #" (number) }
                    }
                    span class="when" { (clock_of(&notice.ts)) }
                }
            }
        },
    )
}

/// Where a notice points: the change if it names one, else the
/// repository, else the viewer's own pages.
fn notice_href(notice: &Notice) -> String {
    match (&notice.repo, notice.number) {
        (Some(repo), Some(number)) => format!("/{repo}/changes/{number}"),
        (Some(repo), None) if notice.kind == "transfer" => format!("/{repo}/transfer"),
        (Some(repo), None) => format!("/{repo}"),
        (None, _) => match notice.kind.as_str() {
            "reset-request" => "/people".to_owned(),
            _ => "/you".to_owned(),
        },
    }
}

fn day_of(ts: &str) -> String {
    ts.get(..10).unwrap_or(ts).to_owned()
}

fn clock_of(ts: &str) -> String {
    ts.get(11..16).unwrap_or("").to_owned()
}

/// "Today", "Yesterday", or the date. The comparison is in UTC, which
/// is what the log records; a viewer's own midnight is not something
/// the server knows.
fn day_label(day: &str) -> String {
    let today = jiff::Timestamp::now().to_string();
    let today = today.get(..10).unwrap_or("");
    let yesterday = (jiff::Timestamp::now() - jiff::SignedDuration::from_hours(24)).to_string();
    let yesterday = yesterday.get(..10).unwrap_or("");
    if day == today {
        "Today".to_owned()
    } else if day == yesterday {
        "Yesterday".to_owned()
    } else {
        day.to_owned()
    }
}

pub fn repo_settings(
    theme: Theme,
    viewer: &Viewer,
    repo: &Repo,
    error: Option<&str>,
    done: bool,
) -> Markup {
    layout(
        theme,
        Some(viewer),
        Some(&repo.name),
        Some(Tab::Settings),
        "Settings",
        html! {
            div class="narrowcol" {
                @if let Some(error) = error { p class="error" { (error) } }
                @if done { p class="done" { "Saved." } }

                div class="sechead" { b { "Visibility" } span { (repo.visibility.as_str()) } }
                form class="stack" method="post" action={ "/" (repo.name) "/settings/visibility" } {
                    label class="choice" {
                        input type="radio" name="visibility" value="private" checked[repo.visibility == Visibility::Private];
                        span { b { "Private" } " — only you, and whoever you grant something on it." }
                    }
                    label class="choice" {
                        input type="radio" name="visibility" value="public" checked[repo.visibility == Visibility::Public];
                        span { b { "Public" } " — anyone can read and clone it. Writing still needs authority." }
                    }
                    button class="btn" type="submit" { "Save" }
                }

                div class="sechead" style="margin-top: 30px;" { b { "Ownership" } span { (repo.owner.as_str()) } }
                @if let Some(pending) = &repo.pending_owner {
                    p class="note" { "Offered to " b { (pending.as_str()) } ". Nothing changes until they accept." }
                    form class="stack" method="post" action={ "/" (repo.name) "/settings/transfer" } {
                        input type="hidden" name="action" value="withdraw";
                        button class="btn" type="submit" { "Withdraw the offer" }
                    }
                } @else {
                    p class="note" { "Owning a repository carries every capability on it. Offer it to a person; it moves when they accept." }
                    form class="stack" method="post" action={ "/" (repo.name) "/settings/transfer" } {
                        input type="hidden" name="action" value="offer";
                        div {
                            label for="to" { "Offer to" }
                            input id="to" name="to" type="text" autocomplete="off" placeholder="their name";
                        }
                        button class="btn" type="submit" { "Offer ownership" }
                    }
                }
            }
        },
    )
}

/// What the person an offer was made to sees: the offer, and a yes or no.
pub fn transfer_offer(theme: Theme, viewer: &Viewer, repo: &Repo, error: Option<&str>) -> Markup {
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Ownership offered",
        html! {
            div class="narrowcol" {
                div class="sechead" { b { "Ownership offered" } span { (repo.name) } }
                @if let Some(error) = error { p class="error" { (error) } }
                p class="note" {
                    b { (repo.owner.as_str()) } " has offered you " b { (repo.name) } ". "
                    "If you accept, you hold every capability on it from then on, and they hold none unless you grant it."
                }
                form class="inline" method="post" action={ "/" (repo.name) "/transfer" } {
                    button class="btn" type="submit" name="action" value="accept" { "Accept" }
                    button class="vbtn" type="submit" name="action" value="decline" { "Decline" }
                }
            }
        },
    )
}

pub fn settings(
    theme: Theme,
    viewer: &Viewer,
    email: Option<&str>,
    error: Option<&str>,
    done: bool,
    first: bool,
) -> Markup {
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Settings",
        html! {
            div class="narrowcol" {
                div class="sechead" { b { "Settings" } span { (viewer.0.as_str()) } }
                @if let Some(error) = error { p class="error" { (error) } }
                @if done { p class="done" { "Saved." } }
                @if first {
                    p class="note" { "You are signed in from an invitation, which worked once. Set a password to sign in next time." }
                }

                form class="stack" method="post" action="/you/settings/email" {
                    div {
                        label for="email" { "Email" }
                        input id="email" name="email" type="email" autocomplete="email"
                              value=[email] placeholder="where a password reset can reach you";
                    }
                    p class="hint" { "Kept beside your credentials, not in the log, and shown to nobody." }
                    button class="btn" type="submit" { "Save email" }
                }

                form class="stack" method="post" action="/you/settings" style="margin-top: 28px;" {
                    div {
                        label for="password" { "New password" }
                        input id="password" name="password" type="password"
                              autocomplete="new-password" minlength="12";
                    }
                    div {
                        label for="confirm" { "Again" }
                        input id="confirm" name="confirm" type="password"
                              autocomplete="new-password" minlength="12";
                    }
                    p class="hint" {
                        "Changing this signs out everywhere, including here — a password \
                         change that leaves old sessions alive has not locked anyone out."
                    }
                    button class="btn" type="submit" { "Change password" }
                }
            }
        },
    )
}

pub fn tokens(
    theme: Theme,
    viewer: &Viewer,
    tokens: &[cairn_core::TokenInfo],
    fresh: Option<&str>,
    error: Option<&str>,
) -> Markup {
    let live = tokens.iter().filter(|t| !t.revoked).count();
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Tokens",
        html! {
            div class="sechead" { b { "Your tokens" } span { (live) } }
            @if let Some(error) = error { p class="error" { (error) } }

            @if let Some(secret) = fresh {
                div class="once" {
                    p { b { "Copy this now." } " It is stored only as a hash, so this is the one time it can be shown." }
                    code class="secret" { (secret) }
                }
            }

            form class="inline" method="post" action="/you/tokens" {
                input type="hidden" name="action" value="mint";
                input name="label" type="text" placeholder="what it is for" autocomplete="off";
                button class="btn" type="submit" { "Mint a token" }
            }

            @if tokens.is_empty() {
                p class="empty" { "None yet." }
            }
            @for token in tokens {
                div class="trow" style="grid-template-columns: minmax(0,1fr) 130px 90px;" {
                    span { (token.label.as_deref().unwrap_or("unlabelled")) }
                    span class="sec3" { (token.id.0) }
                    span {
                        @if token.revoked {
                            span class="sec3" { "revoked" }
                        } @else {
                            form method="post" action="/you/tokens" {
                                input type="hidden" name="action" value="revoke";
                                input type="hidden" name="token" value=(token.id.0);
                                button class="quiet" type="submit" { "Revoke" }
                            }
                        }
                    }
                }
            }
        },
    )
}

pub fn teams(
    theme: Theme,
    viewer: &Viewer,
    teams: &[super::TeamRow],
    repos: &[String],
    error: Option<&str>,
) -> Markup {
    layout_section(
        theme,
        viewer,
        "teams",
        "Teams",
        html! {
            div class="sechead" { b { "Teams" } span { (teams.len()) } }
            @if let Some(error) = error { p class="error" { (error) } }
            @if teams.is_empty() {
                p class="empty" { "None yet. A team holds authority; whoever is on it carries that authority, and loses it on leaving." }
            }
            @for row in teams {
                div class="agent" {
                    div class="trow" style="grid-template-columns: 150px minmax(0,1fr) auto;" {
                        span style="font-weight: 500;" { (row.principal.id.as_str()) }
                        span class="sec3" {
                            @if row.members.is_empty() { "nobody yet" }
                            @else { (row.members.iter().map(|m| m.as_str()).collect::<Vec<_>>().join(", ")) }
                        }
                        span class="sec3" {
                            @if row.grants.is_empty() { "holds nothing" }
                            @else {
                                (row.grants.iter().map(|g| format!("{} on {}",
                                    g.actions.iter().map(|a| a.as_str()).collect::<Vec<_>>().join("/"),
                                    g.repo.as_deref().unwrap_or("everything"))).collect::<Vec<_>>().join("; "))
                            }
                        }
                    }
                    div class="composer" {
                        form class="inline" method="post" action="/teams" {
                            input type="hidden" name="action" value="add";
                            input type="hidden" name="team" value=(row.principal.id.as_str());
                            input name="member" type="text" placeholder="add a person or agent" autocomplete="off";
                            button class="vbtn" type="submit" { "Add" }
                        }
                        @for member in &row.members {
                            form class="inline" method="post" action="/teams" {
                                input type="hidden" name="action" value="remove";
                                input type="hidden" name="team" value=(row.principal.id.as_str());
                                input type="hidden" name="member" value=(member.as_str());
                                button class="quiet" type="submit" { "remove " (member.as_str()) }
                            }
                        }
                    }
                    form class="composer" method="post" action="/teams" {
                        input type="hidden" name="action" value="grant";
                        input type="hidden" name="team" value=(row.principal.id.as_str());
                        select name="repo" aria-label="Repository" {
                            option value="" { "every repository" }
                            @for repo in repos { option value=(repo) { (repo) } }
                        }
                        @for (name, label) in [("task", "task"), ("push", "push"), ("review", "review"), ("merge", "merge"), ("verify", "verify"), ("admin", "admin")] {
                            label class="tick" { input type="checkbox" name=(name) value="1"; " " (label) }
                        }
                        button class="vbtn" type="submit" { "Grant" }
                    }
                }
            }

            div class="sechead" style="margin-top: 30px;" { b { "Add a team" } span {} }
            form class="stack narrowcol" method="post" action="/teams" {
                input type="hidden" name="action" value="create";
                div {
                    label for="id" { "Name" }
                    input id="id" name="id" type="text" autocomplete="off"
                          placeholder="lowercase, digits and hyphens";
                }
                div {
                    label for="display" { "Display name" }
                    input id="display" name="display" type="text" autocomplete="off";
                }
                button class="btn" type="submit" { "Add a team" }
            }
        },
    )
}

pub fn people(
    theme: Theme,
    viewer: &Viewer,
    people: &[super::PersonRow],
    can_mail: bool,
    join_link: Option<&str>,
    mailed: Option<&str>,
    error: Option<&str>,
) -> Markup {
    layout_section(
        theme,
        viewer,
        "people",
        "People",
        html! {
            div class="sechead" { b { "People" } span { (people.len()) } }
            @if let Some(error) = error { p class="error" { (error) } }

            @if let Some(link) = join_link {
                div class="once" {
                    @if let Some(to) = mailed {
                        p { b { "Sent to " (to) "." } " The same link is here in case it does not arrive; it signs them in once, then it is spent." }
                    } @else {
                        p { b { "Send them this link." } " It signs them in once, then it is spent; this is the only time it can be shown." }
                    }
                    code class="secret" { (link) }
                }
            }

            @for row in people {
                div class="trow" style="grid-template-columns: 150px minmax(0,1fr) 140px auto;" {
                    span style="font-weight: 500;" { (row.principal.id.as_str()) }
                    span class="sec3" { (row.principal.display) }
                    span class="sec3" {
                        @if row.admin { "runs the forge" }
                        @else if row.has_password { "can sign in" }
                        @else { "no password yet" }
                    }
                    form method="post" action="/people" {
                        input type="hidden" name="action" value="relink";
                        input type="hidden" name="id" value=(row.principal.id.as_str());
                        button class="quiet" type="submit" {
                            @if can_mail && row.has_email { "Send a new sign-in link" } @else { "Make a sign-in link" }
                        }
                    }
                }
            }

            div class="sechead" style="margin-top: 30px;" { b { "Add a person" } span {} }
            form class="stack narrowcol" method="post" action="/people" {
                input type="hidden" name="action" value="register";
                div {
                    label for="id" { "Name" }
                    input id="id" name="id" type="text" autocomplete="off"
                          placeholder="lowercase, digits and hyphens";
                }
                div {
                    label for="display" { "Display name" }
                    input id="display" name="display" type="text" autocomplete="off";
                }
                div {
                    label for="email" { "Email" }
                    input id="email" name="email" type="email" autocomplete="off"
                          placeholder=(if can_mail { "the invitation goes here" } else { "optional; kept for password resets" });
                }
                button class="btn" type="submit" {
                    @if can_mail { "Add and send an invitation" } @else { "Add and make a link" }
                }
            }
        },
    )
}

pub fn agents(
    theme: Theme,
    viewer: &Viewer,
    agents: &[super::AgentRow],
    repos: &[String],
    fresh: Option<&str>,
    error: Option<&str>,
) -> Markup {
    layout(
        theme,
        Some(viewer),
        None,
        None,
        "Agents",
        html! {
            div class="sechead" { b { "Agents" } span { (agents.len()) } }
            @if let Some(error) = error { p class="error" { (error) } }

            @if let Some(secret) = fresh {
                div class="once" {
                    p { b { "Copy this now." } " It is the agent's only credential, and it is stored as a hash." }
                    code class="secret" { (secret) }
                }
            }

            @if agents.is_empty() {
                p class="empty" { "None yet. An agent needs a name, a token, and a grant narrow enough to be worth trusting." }
            }
            @for row in agents {
                div class="agent" {
                    div class="trow" style="grid-template-columns: 150px minmax(0,1fr) auto;" {
                        span style="font-weight: 500;" { (row.principal.id.as_str()) }
                        span class="sec3" { (row.principal.display) }
                        span class="sec3" { (row.principal.model.as_deref().unwrap_or("")) }
                    }
                    @for grant in row.grants.iter().filter(|g| !g.revoked) {
                        div class="grant" {
                            span class="sec3" {
                                @for (index, action) in grant.actions.iter().enumerate() {
                                    @if index > 0 { ", " }
                                    (action.as_str())
                                }
                                @match &grant.repo {
                                    Some(repo) => { " on " (repo) }
                                    None => { " everywhere" }
                                }
                            }
                            form method="post" action="/agents" {
                                input type="hidden" name="action" value="revoke";
                                input type="hidden" name="grant" value=(grant.id.0);
                                button class="quiet" type="submit" { "Revoke" }
                            }
                        }
                    }
                    @if row.grants.iter().all(|g| g.revoked) {
                        p class="grant sec3" { "No live grant — this agent can do nothing yet." }
                    }

                    form class="inline" method="post" action="/agents" {
                        input type="hidden" name="action" value="grant";
                        input type="hidden" name="grantee" value=(row.principal.id.as_str());
                        @for capability in ["task", "push", "review", "merge", "verify"] {
                            label class="check" {
                                input type="checkbox" name=(capability) value="on";
                                (capability)
                            }
                        }
                        select name="repo" {
                            option value="" { "every repository" }
                            @for repo in repos { option value=(repo) { (repo) } }
                        }
                        button class="btn" type="submit" { "Grant" }
                    }
                }
            }

            div class="sechead" style="margin-top: 30px;" { b { "Add an agent" } span {} }
            form class="stack narrowcol" method="post" action="/agents" {
                input type="hidden" name="action" value="register";
                div {
                    label for="id" { "Name" }
                    input id="id" name="id" type="text" autocomplete="off"
                          placeholder="lowercase, digits and hyphens";
                }
                div {
                    label for="display" { "Display name" }
                    input id="display" name="display" type="text" autocomplete="off";
                }
                div {
                    label for="model" { "Model" }
                    input id="model" name="model" type="text" autocomplete="off"
                          placeholder="policy can require judgment from distinct models";
                }
                p class="hint" {
                    "A token is minted at the same time, because an agent without one \
                     cannot do anything. It grants no capability by itself."
                }
                button class="btn" type="submit" { "Add" }
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
                        @if change.state == ChangeState::Open {
                            form class="composer claim" method="post" action={ "/" (repo) "/changes/" (change.number) "/claim" } {
                                input type="hidden" name="revision" value=(shown);
                                div class="line" {
                                    select name="kind" aria-label="Kind" {
                                        option value="test" { "test" }
                                        option value="lint" { "lint" }
                                        option value="typecheck" { "typecheck" }
                                        option value="build" { "build" }
                                        option value="manual" { "manual" }
                                        option value="reasoning" { "reasoning" }
                                    }
                                    input type="text" name="command" placeholder="Command that produced it" autocomplete="off";
                                }
                                input type="text" name="summary" placeholder="What you saw — required" required;
                                input type="text" name="unchecked" placeholder="What this did not check, comma-separated";
                                div class="line" {
                                    button class="vbtn" type="submit" name="passed" value="yes" { "Passed" }
                                    button class="vbtn" type="submit" name="passed" value="no" { "Failed" }
                                }
                            }
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
        Event::PasswordSet { principal, .. } => (
            "dot idle",
            html! { b { (actor) } " set the password for " (principal.as_str()) },
        ),
        Event::HistoryImported {
            branch,
            commits,
            source,
            ..
        } => (
            "dot idle",
            html! {
                b { (actor) } " imported " (commits) " commits onto " (branch)
                " from " (source) ", unreviewed here"
            },
        ),
        Event::VisibilitySet { repo, visibility } => (
            "dot idle",
            html! {
                b { (actor) } " made " (repo) " " (visibility.as_str())
            },
        ),
        Event::RepoTransferOffered { repo, to } => (
            "dot idle",
            html! {
                b { (actor) } " offered " (repo) " to " (to.as_str())
            },
        ),
        Event::RepoTransferAccepted { repo } => (
            "dot ok",
            html! {
                b { (actor) } " now owns " (repo)
            },
        ),
        Event::RepoTransferDeclined { repo } => (
            "dot idle",
            html! {
                b { (actor) } " declined ownership of " (repo)
            },
        ),
        Event::TeamMemberAdded { team, member } => (
            "dot idle",
            html! {
                b { (actor) } " added " (member.as_str()) " to " (team.as_str())
            },
        ),
        Event::PasswordResetRequested { principal } => (
            "dot idle",
            html! {
                b { (principal.as_str()) } " asked for a new sign-in link"
            },
        ),
        Event::TeamMemberRemoved { team, member } => (
            "dot idle",
            html! {
                b { (actor) } " removed " (member.as_str()) " from " (team.as_str())
            },
        ),
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
