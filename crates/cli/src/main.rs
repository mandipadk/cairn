mod hook;
mod mcp;

use anyhow::Context;
use cairn_core::Store;
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
    },
    /// The proc-receive hook endpoint; spawned by git receive-pack.
    #[command(name = "internal-proc-receive", hide = true)]
    InternalProcReceive,
    /// Expose a running forge as MCP tools over stdio for an AI agent.
    Mcp {
        /// Base URL of the forge server to proxy to.
        #[arg(long, default_value = "http://127.0.0.1:6160")]
        server: String,
        /// Principal to act as on the forge.
        #[arg(long)]
        principal: String,
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
        Command::Serve { db, listen, repos } => {
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
            let app = router(AppState::new(store).with_git(git, base_url));
            tracing::info!(%listen, db = %db.display(), repos = %repos.display(), "cairn serving");
            axum::serve(listener, app)
                .with_graceful_shutdown(async {
                    let _ = tokio::signal::ctrl_c().await;
                })
                .await?;
        }
        Command::InternalProcReceive => {
            hook::run()?;
        }
        Command::Mcp { server, principal } => {
            mcp::run(&server, &principal)?;
        }
    }
    Ok(())
}
