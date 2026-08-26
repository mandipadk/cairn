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
                let (_, secret, _) = store.mint_token(&id, &id, Some("bootstrap"))?;
                println!("registered human {principal}");
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
