mod hook;
mod mcp;
mod verify;

use anyhow::Context;
use cairn_core::{PrincipalId, PrincipalKind, Store};
use cairn_git::GitStore;
use cairn_server::{AppState, router};
use clap::{Parser, Subcommand};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "cairn", version, about = "An agent-native forge")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
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
        } => {
            let git_version = cairn_git::preflight().context("checking the git on PATH")?;
            let store = Store::open(&db)
                .with_context(|| format!("opening forge database at {}", db.display()))?;
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
            if secure_cookies {
                state = state.with_secure_cookies();
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
                let (_, secret, _) = store.mint_token(&id, &id, Some("bootstrap"))?;
                println!("registered human {principal} with an admin grant");
                println!("token (shown once, store it safely): {secret}");
            }
            AdminCommand::MintToken {
                db,
                principal,
                label,
            } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let id = PrincipalId::new(&principal)
                    .with_context(|| format!("{principal:?} is not a valid principal slug"))?;
                let (_, secret, _) = store.mint_token(&id, &id, label.as_deref())?;
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
