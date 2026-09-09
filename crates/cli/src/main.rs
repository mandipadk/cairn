mod hook;
mod watch;

use cairn_client::{mcp, verify};

use anyhow::Context;
use cairn_core::{PrincipalId, PrincipalKind, Store};
use cairn_git::GitStore;
use cairn_server::{AppState, router};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cairn", version = cairn_core::VERSION, about = "An agent-native forge")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
#[allow(clippy::large_enum_variant)]
enum Command {
    /// Run the forge server.
    Serve {
        /// Path to the forge database (created if absent).
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// Address to listen on.
        #[arg(long, default_value = "127.0.0.1:6160")]
        listen: SocketAddr,
        /// Directory holding the hosted bare repositories.
        #[arg(long, default_value = "repos")]
        repos: PathBuf,
        /// Accept asserted identity via the x-cairn-principal header.
        /// Local development only.
        #[arg(long)]
        dev: bool,
        /// The forge is reached over HTTPS, so mark session cookies
        /// Secure. Set this on any deployment that is not localhost.
        #[arg(long)]
        secure_cookies: bool,
        /// Credential used to authenticate mirror pushes, e.g. a
        /// GitHub token. Read from CAIRN_MIRROR_TOKEN when unset.
        #[arg(long)]
        mirror_token: Option<String>,
        /// Believe X-Forwarded-For. Set this only when a proxy you
        /// control sets that header, since otherwise any caller can
        /// claim any address.
        #[arg(long)]
        trust_proxy: bool,
        /// SMTP relay for outbound mail, credentials included:
        /// `smtps://user:pass@host:465`, or
        /// `smtp://user:pass@host:587?tls=required`. Read from
        /// CAIRN_SMTP_URL when unset, which keeps the password out of the
        /// process list.
        #[arg(long)]
        smtp_url: Option<String>,
        /// Instead of SMTP: a command that accepts one message on stdin,
        /// such as `sendmail -t`. Read from CAIRN_MAIL_COMMAND when unset.
        #[arg(long)]
        mail_command: Option<String>,
        /// The From address on mail the forge sends. Read from
        /// CAIRN_MAIL_FROM when unset.
        #[arg(long)]
        mail_from: Option<String>,
        /// Where people reach this forge, e.g. https://cairn.example.org.
        /// Passkeys bind to it, so it cannot change once they exist. Read
        /// from CAIRN_PUBLIC_URL when unset; passkeys are off without it.
        #[arg(long)]
        public_url: Option<String>,
        /// OpenID Connect issuer people may sign in with (e.g. https://accounts.google.com).
        #[arg(long)]
        oidc_issuer: Option<String>,
        /// The client id registered at that issuer.
        #[arg(long)]
        oidc_client_id: Option<String>,
        /// File holding the client secret; never the secret itself.
        #[arg(long)]
        oidc_client_secret_file: Option<std::path::PathBuf>,
        /// What the sign-in button says.
        #[arg(long, default_value = "SSO")]
        oidc_label: String,
        /// Link an unknown provider identity to the one person whose
        /// verified email matches. Off by default: nothing links itself.
        #[arg(long)]
        oidc_link_by_email: bool,
        /// Issuers whose tokens a workload may exchange for a credential
        /// to claim a task and open a session. Repeatable.
        #[arg(long)]
        workload_issuer: Vec<String>,
        /// The audience a workload token must name; the public URL when absent.
        #[arg(long)]
        workload_audience: Option<String>,
        /// API writes one principal may make per minute before being told
        /// to wait (429 with Retry-After). 0 turns the allowance off.
        #[arg(long, default_value_t = cairn_server::DEFAULT_WRITES_PER_MINUTE)]
        api_writes_per_minute: u32,
        /// Repositories one owner may have. 0 for no limit.
        #[arg(long)]
        quota_repos: Option<u32>,
        /// Agents one owner may have. 0 for no limit.
        #[arg(long)]
        quota_agents: Option<u32>,
        /// Open tasks one owner's repositories may hold at once. 0 for no limit.
        #[arg(long)]
        quota_open_tasks: Option<u32>,
        /// Disk one owner's repositories may take, in megabytes. 0 for no limit.
        #[arg(long)]
        quota_disk_mb: Option<u64>,
        /// The Ed25519 key that signs merge receipts; generated there when
        /// absent. Beside the database when unset.
        #[arg(long)]
        signing_key_file: Option<PathBuf>,
    },
    /// Merge receipts: a landing's evidence, signed by the forge.
    Receipt {
        #[command(subcommand)]
        command: ReceiptCommand,
    },
    /// Offline administration against the forge database. Having file
    /// access to the database is the root authority.
    Admin {
        #[command(subcommand)]
        command: AdminCommand,
    },
    /// The proc-receive hook endpoint; spawned by git receive-pack.
    #[command(name = "internal-proc-receive", hide = true)]
    InternalProcReceive,
    /// Re-run claims and record what actually happened. With no
    /// change number, works through everything waiting on a runner —
    /// which is what a CI job should call.
    Verify {
        /// Base URL of the forge.
        #[arg(long, default_value = "http://127.0.0.1:6160")]
        server: String,
        /// API token of a principal holding the verify capability.
        #[arg(long)]
        token: String,
        /// Repository the change belongs to.
        #[arg(long)]
        repo: String,
        /// A single change; omit to take everything waiting.
        change: Option<i64>,
        /// Fetch each change's revision before running its claims,
        /// instead of trusting the working directory. Use this in CI.
        #[arg(long)]
        checkout: bool,
        /// Working directory to run the claims' commands in.
        #[arg(long, default_value = ".")]
        workdir: PathBuf,
        /// Print the commands without running or recording anything.
        #[arg(long)]
        dry_run: bool,
    },
    /// Expose a running forge as MCP tools over stdio for an AI agent.
    Mcp {
        /// Base URL of the forge server to proxy to.
        #[arg(long, default_value = "http://127.0.0.1:6160")]
        server: String,
        /// API token to authenticate with.
        #[arg(long)]
        token: Option<String>,
        /// Principal to assert instead of a token (dev-mode servers only).
        #[arg(long)]
        principal: Option<String>,
    },
}

#[derive(Subcommand)]
enum ReceiptCommand {
    /// Check a receipt's signature offline and say what it certifies.
    Verify {
        /// The receipt document, as served by /api/changes/{id}/receipt
        /// or read from the commit's note.
        file: PathBuf,
        /// The key it must be signed with: a fingerprint or a base64
        /// public key, as /api/forge/key publishes.
        #[arg(long)]
        key: Option<String>,
    },
}

#[derive(Subcommand)]
enum AdminCommand {
    /// First-run setup: register the first human and print their token.
    Bootstrap {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// Slug of the human principal, e.g. "ada".
        principal: String,
        #[arg(long)]
        display: Option<String>,
    },
    /// Mint an API token for an existing principal.
    MintToken {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        principal: String,
        #[arg(long)]
        label: Option<String>,
        /// Days until it expires; omit for a token that lasts until revoked.
        #[arg(long)]
        days: Option<u32>,
    },
    /// Set a human's password. The password is read from stdin, never
    /// from the command line, where it would sit in shell history and in
    /// the process list for anyone on the machine to read.
    SetPassword {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        principal: String,
    },
    /// Give somebody the unscoped admin grant that running the forge
    /// consists of. Offline, because over the API you would already need
    /// admin to grant admin — which is the right rule there and an
    /// impossible one here.
    GrantAdmin {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        principal: String,
    },
    /// Show who has asked to be told when this is ready, or remove
    /// someone who has asked to be forgotten.
    Waitlist {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// Remove this address instead of listing.
        #[arg(long)]
        remove: Option<String>,
    },
    /// Show or set what one owner may take up here. Without any of the
    /// limits, it prints what they may have and what they are using; a
    /// limit given as 0 means no limit at all. Setting one replaces
    /// this owner's quota entirely.
    Quota {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// The person or organisation.
        owner: String,
        /// Who the change is recorded as: an unscoped admin.
        #[arg(long = "as")]
        r#as: Option<String>,
        #[arg(long)]
        repos: Option<u32>,
        #[arg(long)]
        agents: Option<u32>,
        #[arg(long)]
        open_tasks: Option<u32>,
        #[arg(long)]
        disk_mb: Option<u64>,
    },
    /// Give every repository named the old way, without its owner in
    /// front, its owner's name: `demo` becomes `ada/demo`, on the record
    /// and on disk. Run once when upgrading to a forge that expects
    /// owners; `serve` refuses to start until it has been.
    AdoptOwners {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// The repositories directory, so each moves under its owner.
        #[arg(long, default_value = "repos")]
        repos: PathBuf,
        /// Who the renames are recorded as: an unscoped admin.
        #[arg(long)]
        r#as: String,
    },
    /// What people reported broke, newest first; or dismiss one.
    Reports {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// Dismiss this report instead of listing.
        #[arg(long)]
        dismiss: Option<i64>,
    },
    /// Prove the mail configuration without sending anyone anything:
    /// reach the relay, negotiate TLS, authenticate, hang up. Reads the
    /// same flags and environment as `serve`.
    MailCheck {
        #[arg(long)]
        smtp_url: Option<String>,
        #[arg(long)]
        mail_command: Option<String>,
        #[arg(long)]
        mail_from: Option<String>,
    },
    /// Ask a forge whether it is up and say so by mail when that changes.
    /// One invocation is one look; run it from a timer, ideally on a
    /// machine that is not the forge. It mails on transitions and once a
    /// day while down, and exits non-zero while the forge is down so the
    /// timer's own status shows it too.
    Watch {
        /// The forge's public address, e.g. https://cairn.example
        #[arg(long)]
        url: String,
        /// Where the watcher remembers what it last saw.
        #[arg(long, default_value = "cairn-watch.json")]
        state: PathBuf,
        /// Who hears about it. Without this the result is only printed.
        #[arg(long)]
        mail_to: Option<String>,
        #[arg(long)]
        smtp_url: Option<String>,
        #[arg(long)]
        mail_command: Option<String>,
        #[arg(long)]
        mail_from: Option<String>,
    },
    /// Check that current state is exactly the log applied, by replaying
    /// it into empty projections and comparing. Exits non-zero on any
    /// divergence, so it can be run from cron or a health check.
    Fsck {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// Also check that every branch really contains what the log
        /// says landed on it. Recording a merge and moving the branch
        /// are two steps, and a crash or a second forge process sharing
        /// this database can land between them.
        #[arg(long)]
        repos: Option<PathBuf>,
    },
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Logs go to stderr: in MCP mode stdout belongs to the protocol.
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let Cli { command } = Cli::parse();
    match command {
        Command::Serve {
            db,
            listen,
            repos,
            dev,
            secure_cookies,
            mirror_token,
            trust_proxy,
            smtp_url,
            mail_command,
            mail_from,
            public_url,
            oidc_issuer,
            oidc_client_id,
            oidc_client_secret_file,
            oidc_label,
            oidc_link_by_email,
            workload_issuer,
            workload_audience,
            api_writes_per_minute,
            quota_repos,
            quota_agents,
            quota_open_tasks,
            quota_disk_mb,
            signing_key_file,
        } => {
            let git_version = cairn_git::preflight().context("checking the git on PATH")?;
            tracing::info!("cairn {}", cairn_core::VERSION);
            // What an owner may take up here, before anybody's own
            // quota is consulted. Absent leaves the built-in default
            // standing; 0 means that particular limit does not exist.
            let mut quota = cairn_core::Quota::default();
            let limit = |given: Option<u32>| given.map(|n| (n > 0).then_some(n));
            if let Some(repos) = limit(quota_repos) {
                quota.repos = repos;
            }
            if let Some(agents) = limit(quota_agents) {
                quota.agents = agents;
            }
            if let Some(tasks) = limit(quota_open_tasks) {
                quota.open_tasks = tasks;
            }
            if let Some(disk) = quota_disk_mb.map(|mb| (mb > 0).then(|| mb * 1024 * 1024)) {
                quota.disk = disk;
            }
            let store = Store::open(&db)
                .with_context(|| format!("opening forge database at {}", db.display()))?
                .with_default_quota(quota);
            // A repository without its owner in its name predates owners
            // and has no address on this forge; adopting is one command,
            // and refusing to serve is better than serving it nowhere.
            let unowned: Vec<String> = store
                .repos()?
                .into_iter()
                .filter(|r| !r.name.contains('/'))
                .map(|r| r.name)
                .collect();
            if !unowned.is_empty() {
                anyhow::bail!(
                    "{} repositor{} named without an owner ({}): run `cairn admin adopt-owners --db {} --repos {} --as <admin>` first",
                    unowned.len(),
                    if unowned.len() == 1 {
                        "y is"
                    } else {
                        "ies are"
                    },
                    unowned.join(", "),
                    db.display(),
                    repos.display()
                );
            }
            let listener = tokio::net::TcpListener::bind(listen)
                .await
                .with_context(|| format!("binding {listen}"))?;
            // The hook calls back over HTTP, and receive-pack spawns the
            // hook via this very binary.
            let base_url = format!("http://{}", listener.local_addr()?);
            let git = GitStore::new(
                &repos,
                std::env::current_exe().context("locating own binary")?,
            );
            let mut state = AppState::new(store).with_git(git, base_url);
            if dev {
                tracing::warn!("dev identity enabled: the x-cairn-principal header is trusted");
                state = state.with_dev_identity();
            }
            if let Some(token) = mirror_token.or_else(|| std::env::var("CAIRN_MIRROR_TOKEN").ok()) {
                state = state.with_mirror_credential(token);
            }
            if trust_proxy {
                state = state.trusting_proxy();
            }
            state = state.with_write_allowance(api_writes_per_minute);
            let key_path = signing_key_file.unwrap_or_else(|| {
                db.parent()
                    .unwrap_or(std::path::Path::new("."))
                    .join("signing.key")
            });
            let signer = cairn_server::receipts::Signer::load_or_create(&key_path)
                .map_err(|e| anyhow::anyhow!("--signing-key-file: {e}"))?;
            tracing::info!("receipts: signing as key {}", signer.id());
            state = state.with_signer(signer);
            match mailer_from(smtp_url, mail_command, mail_from)? {
                Some(mailer) => {
                    tracing::info!("mail: {}", mailer.describe());
                    state = state.with_mailer(mailer);
                }
                None => tracing::warn!(
                    "no mail configured (CAIRN_SMTP_URL and CAIRN_MAIL_FROM): \
                     password resets and invitations fall back to the People page"
                ),
            }
            match public_url.or_else(|| std::env::var("CAIRN_PUBLIC_URL").ok()) {
                Some(url) => {
                    state = state
                        .with_public_url(&url)
                        .map_err(|e| anyhow::anyhow!("--public-url: {e}"))?;
                    tracing::info!("passkeys: enabled for {url}");
                }
                None => {
                    tracing::info!("no public URL configured (CAIRN_PUBLIC_URL): passkeys are off")
                }
            }
            if secure_cookies {
                state = state.with_secure_cookies();

                let provider = match (oidc_issuer, oidc_client_id, oidc_client_secret_file) {
                    (Some(issuer), Some(client_id), Some(secret_file)) => {
                        let client_secret = std::fs::read_to_string(&secret_file)
                            .with_context(|| format!("reading {}", secret_file.display()))?
                            .trim()
                            .to_owned();
                        anyhow::ensure!(
                            !client_secret.is_empty(),
                            "the client secret file is empty"
                        );
                        Some(cairn_server::oidc::Provider {
                            issuer: issuer.trim_end_matches('/').to_owned(),
                            client_id,
                            client_secret,
                            label: oidc_label,
                            link_by_email: oidc_link_by_email,
                        })
                    }
                    (None, None, None) => None,
                    _ => anyhow::bail!(
                        "sign-in with a provider needs all three of --oidc-issuer, --oidc-client-id and --oidc-client-secret-file"
                    ),
                };
                if provider.is_some() || !workload_issuer.is_empty() {
                    if let Some(p) = &provider {
                        tracing::info!("sign-in with {} at {}", p.label, p.issuer);
                    }
                    for issuer in &workload_issuer {
                        tracing::info!("workload identity trusted from {issuer}");
                    }
                    state = state.with_oidc(cairn_server::oidc::Trust::new(
                        provider,
                        workload_issuer
                            .iter()
                            .map(|i| i.trim_end_matches('/').to_owned())
                            .collect(),
                        workload_audience,
                    ));
                }
            } else if !listen.ip().is_loopback() {
                tracing::warn!(
                    "serving on a non-loopback address without --secure-cookies: \
                     session cookies will not be marked Secure"
                );
            }
            cairn_server::spawn_queue_processor(state.clone());
            let app = router(state);
            tracing::info!(
                %listen,
                db = %db.display(),
                repos = %repos.display(),
                git = %git_version,
                "cairn serving"
            );
            // Connect info is what lets the sign-in limiter tell one
            // caller from another.
            axum::serve(
                listener,
                app.into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            })
            .await?;
        }
        Command::Admin { command } => match command {
            AdminCommand::Bootstrap {
                db,
                principal,
                display,
            } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let id = PrincipalId::new(&principal)
                    .with_context(|| format!("{principal:?} is not a valid principal slug"))?;
                let display = display.unwrap_or_else(|| principal.clone());
                store.register_principal(&id, &id, PrincipalKind::Human, &display, None, None)?;
                // Somebody has to be able to run the forge, and nobody
                // is sovereign by virtue of being human any more. The
                // first person gets an unscoped admin grant — recorded
                // like any other, and revocable like any other.
                store.grant_bootstrap_admin(&id)?;
                let (_, secret, _) = store.mint_token(&id, &id, Some("bootstrap"), None)?;
                println!("registered human {principal} with an admin grant");
                println!("token (shown once, store it safely): {secret}");
            }
            AdminCommand::MintToken {
                db,
                principal,
                label,
                days,
            } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let id = PrincipalId::new(&principal)
                    .with_context(|| format!("{principal:?} is not a valid principal slug"))?;
                let (_, secret, _) = store.mint_token(
                    &id,
                    &id,
                    label.as_deref(),
                    days.map(|d| cairn_core::until_in_days(i64::from(d)))
                        .as_deref(),
                )?;
                println!("token (shown once, store it safely): {secret}");
            }
            AdminCommand::SetPassword { db, principal } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let id = PrincipalId::new(&principal)
                    .with_context(|| format!("{principal:?} is not a valid principal slug"))?;
                eprint!("New password for {principal} (input is not echoed): ");
                let password = rpassword::read_password().context("reading the password")?;
                // File access to the database is the root authority, so
                // this acts as the principal itself rather than needing
                // someone else's admin capability to already exist.
                store.set_password(&id, &id, &password)?;
                println!("password set for {principal}");
            }
            AdminCommand::GrantAdmin { db, principal } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let id = PrincipalId::new(&principal)
                    .with_context(|| format!("{principal:?} is not a valid principal slug"))?;
                store.grant_bootstrap_admin(&id)?;
                println!("{principal} now holds an unscoped admin grant");
            }
            AdminCommand::Quota {
                db,
                owner,
                r#as,
                repos,
                agents,
                open_tasks,
                disk_mb,
            } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let owner_id =
                    PrincipalId::new(&owner).context("the owner must be a valid slug")?;
                let asked = [
                    repos.is_some(),
                    agents.is_some(),
                    open_tasks.is_some(),
                    disk_mb.is_some(),
                ];
                if asked.iter().any(|given| *given) {
                    let actor = PrincipalId::new(r#as.as_deref().unwrap_or(""))
                        .context("--as <admin> says who this is recorded as")?;
                    let mut quota = store.quota(&owner_id)?;
                    let limit = |given: Option<u32>| given.map(|n| (n > 0).then_some(n));
                    if let Some(value) = limit(repos) {
                        quota.repos = value;
                    }
                    if let Some(value) = limit(agents) {
                        quota.agents = value;
                    }
                    if let Some(value) = limit(open_tasks) {
                        quota.open_tasks = value;
                    }
                    if let Some(value) = disk_mb.map(|mb| (mb > 0).then(|| mb * 1024 * 1024)) {
                        quota.disk = value;
                    }
                    store.set_quota(&actor, &owner_id, &quota)?;
                }
                let quota = store.quota(&owner_id)?;
                let usage = store.usage(&owner_id)?;
                let say = |what: &str, used: String, limit: Option<String>| {
                    println!(
                        "{what:<12} {used:>10} of {}",
                        limit.unwrap_or_else(|| "no limit".to_owned())
                    );
                };
                say(
                    "repositories",
                    usage.repos.to_string(),
                    quota.repos.map(|n| n.to_string()),
                );
                say(
                    "agents",
                    usage.agents.to_string(),
                    quota.agents.map(|n| n.to_string()),
                );
                say(
                    "open tasks",
                    usage.open_tasks.to_string(),
                    quota.open_tasks.map(|n| n.to_string()),
                );
                say(
                    "disk",
                    format!("{} MB", usage.disk / (1024 * 1024)),
                    quota.disk.map(|b| format!("{} MB", b / (1024 * 1024))),
                );
            }
            AdminCommand::AdoptOwners { db, repos, r#as } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let actor = PrincipalId::new(&r#as).context("--as must be a slug")?;
                let git = GitStore::new(
                    &repos,
                    std::env::current_exe().context("locating own binary")?,
                );
                let renamed = store.adopt_owners(&actor)?;
                if renamed.is_empty() {
                    println!("every repository already carries its owner's name");
                }
                for env in &renamed {
                    if let cairn_core::Event::RepoRenamed { repo, to } = &env.event {
                        match git.rename_repo(repo, to).await {
                            Ok(()) => println!("{repo} -> {to}"),
                            Err(err) => println!(
                                "{repo} -> {to} (recorded; the directory did not move: {err})"
                            ),
                        }
                    }
                }
            }
            AdminCommand::Reports { db, dismiss } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                match dismiss {
                    Some(id) => {
                        if store.dismiss_report(id)? {
                            println!("dismissed report {id}");
                        } else {
                            println!("no report {id}");
                        }
                    }
                    None => {
                        let reports = store.reports()?;
                        if reports.is_empty() {
                            println!("nothing reported");
                        }
                        for report in reports {
                            let from = match (&report.contact, &report.by) {
                                (Some(c), Some(by)) => format!("{c}, signed in as {by}"),
                                (Some(c), None) => c.clone(),
                                (None, Some(by)) => format!("signed in as {by}"),
                                (None, None) => "no address left".to_owned(),
                            };
                            println!(
                                "#{} {} on {}{}\n  from {from}\n  {}\n",
                                report.id,
                                report.filed.get(..19).unwrap_or(&report.filed),
                                report.version,
                                report
                                    .place
                                    .as_deref()
                                    .map(|p| format!(" at {p}"))
                                    .unwrap_or_default(),
                                report.what.replace('\n', "\n  ")
                            );
                        }
                    }
                }
            }
            AdminCommand::Waitlist { db, remove } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                match remove {
                    Some(email) => {
                        if store.leave_waitlist(&email)? {
                            println!("removed {email}");
                        } else {
                            println!("{email} was not on the list");
                        }
                    }
                    None => {
                        let entries = store.waitlist()?;
                        println!("{} on the waitlist", entries.len());
                        for (email, joined, note) in entries {
                            let when = joined.get(..10).unwrap_or(&joined);
                            match note {
                                Some(note) => println!("  {when}  {email}  {note}"),
                                None => println!("  {when}  {email}"),
                            }
                        }
                    }
                }
            }
            AdminCommand::MailCheck {
                smtp_url,
                mail_command,
                mail_from,
            } => match mailer_from(smtp_url, mail_command, mail_from)? {
                Some(mailer) => match mailer.check() {
                    Ok(report) => println!("ok: {report}"),
                    Err(err) => anyhow::bail!("{err}"),
                },
                None => anyhow::bail!(
                    "no mail configured: set CAIRN_SMTP_URL (or CAIRN_MAIL_COMMAND) and CAIRN_MAIL_FROM"
                ),
            },
            AdminCommand::Watch {
                url,
                state,
                mail_to,
                smtp_url,
                mail_command,
                mail_from,
            } => {
                let mailer = mailer_from(smtp_url, mail_command, mail_from)?;
                if mail_to.is_some() && mailer.is_none() {
                    anyhow::bail!(
                        "--mail-to needs mail configured: set CAIRN_SMTP_URL (or CAIRN_MAIL_COMMAND) and CAIRN_MAIL_FROM"
                    );
                }
                let seen = watch::once(&url, &state, mail_to.as_deref().zip(mailer.as_ref()))?;
                println!(
                    "{}: {} since {} ({})",
                    url,
                    if seen.up { "up" } else { "down" },
                    watch::human(seen.since),
                    seen.detail
                );
                if !seen.up {
                    std::process::exit(1);
                }
            }
            AdminCommand::Fsck { db, repos } => {
                let store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let mut divergences = store.fsck()?;
                if let Some(repos) = repos {
                    let git = GitStore::new(
                        &repos,
                        std::env::current_exe().context("locating own binary")?,
                    );
                    let state = AppState::new(store).with_git(git, String::new());
                    divergences.extend(state.branches_match_the_log().await?);
                }
                if divergences.is_empty() {
                    println!("clean: everything matches the log");
                } else {
                    for divergence in &divergences {
                        eprintln!("diverged: {divergence}");
                    }
                    // Not always a projection: with --repos this also
                    // covers branches, and saying otherwise sends whoever
                    // reads it looking in the wrong place.
                    anyhow::bail!("{} divergence(s) from the log", divergences.len());
                }
            }
        },
        Command::Verify {
            server,
            token,
            repo,
            change,
            checkout,
            workdir,
            dry_run,
        } => {
            verify::run_all(verify::Runner {
                server: &server,
                token: &token,
                repo: &repo,
                change,
                workdir: &workdir,
                dry_run,
                checkout,
            })?;
        }
        Command::InternalProcReceive => {
            hook::run()?;
        }
        Command::Receipt {
            command: ReceiptCommand::Verify { file, key },
        } => {
            let document = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let summary = cairn_client::receipt::verify(&document, key.as_deref())?;
            println!("{summary}");
        }
        Command::Mcp {
            server,
            token,
            principal,
        } => {
            anyhow::ensure!(
                token.is_some() || principal.is_some(),
                "pass --token (normal) or --principal (dev-mode servers)"
            );
            mcp::run(&server, token.as_deref(), principal.as_deref())?;
        }
    }
    Ok(())
}

/// The mail configuration, from flags or the environment: a relay URL or
/// a command, either with a From address, or nothing at all.
fn mailer_from(
    smtp_url: Option<String>,
    mail_command: Option<String>,
    mail_from: Option<String>,
) -> anyhow::Result<Option<cairn_server::Mailer>> {
    let smtp_url = smtp_url.or_else(|| std::env::var("CAIRN_SMTP_URL").ok());
    let mail_command = mail_command.or_else(|| std::env::var("CAIRN_MAIL_COMMAND").ok());
    let mail_from = mail_from.or_else(|| std::env::var("CAIRN_MAIL_FROM").ok());
    match (smtp_url, mail_command, mail_from) {
        (Some(url), _, Some(from)) => cairn_server::Mailer::smtp(&url, from)
            .map(Some)
            .map_err(|e| anyhow::anyhow!("CAIRN_SMTP_URL: {e}")),
        (None, Some(command), Some(from)) => Ok(Some(cairn_server::Mailer::command(command, from))),
        (None, None, None) => Ok(None),
        _ => anyhow::bail!("mail needs a From address together with a relay URL or a command"),
    }
}
