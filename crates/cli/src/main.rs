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
        /// Serve the operator's door — registering people, granting,
        /// quotas, the waitlist, invitations, reports, mirrors and
        /// imports — on this loopback address only. The public listener
        /// then refuses those paths, with or without a token, so nothing
        /// that grants access is reachable through a tunnel.
        #[arg(long)]
        operator_listen: Option<SocketAddr>,
        /// Let strangers make their own accounts at /signup. Off, the
        /// page says the forge takes people by invitation.
        #[arg(long)]
        open_signup: bool,
        /// With --open-signup: how many self-made accounts the forge takes
        /// before /signup says it is full. Zero is no cap.
        #[arg(long, default_value_t = 0)]
        signup_cap: u32,
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
        /// How many trusted proxies stand in front, when --trust-proxy is
        /// given: the visitor's address is that many hops from the right
        /// of X-Forwarded-For. One for a reverse proxy; two behind a CDN.
        #[arg(long, default_value_t = 1)]
        proxy_hops: u8,
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
        /// Reads one principal may make per minute before being told to
        /// wait. 0 turns the allowance off.
        #[arg(long, default_value_t = cairn_server::DEFAULT_READS_PER_MINUTE)]
        reads_per_minute: u32,
        /// Reads one address with no account behind it may make per
        /// minute. 0 turns the allowance off.
        #[arg(long, default_value_t = cairn_server::DEFAULT_ANONYMOUS_READS_PER_MINUTE)]
        anonymous_reads_per_minute: u32,
        /// Repositories one owner may have; `none` for no limit.
        #[arg(long)]
        quota_repos: Option<String>,
        /// Agents one owner may have; `none` for no limit.
        #[arg(long)]
        quota_agents: Option<String>,
        /// Open tasks one owner's repositories may hold at once; `none` for no limit.
        #[arg(long)]
        quota_open_tasks: Option<String>,
        /// Disk one owner's repositories may take, in mebibytes; `none` for no limit.
        #[arg(long)]
        quota_disk_mb: Option<String>,
        /// Changes open across one owner's repositories; `none` for no limit.
        #[arg(long)]
        quota_open_changes: Option<String>,
        /// Live tokens one owner and their agents may hold; `none` for no limit.
        #[arg(long)]
        quota_tokens: Option<String>,
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
    /// Asked by the pre-receive hook, while a pushed pack is still in
    /// quarantine and refusing it still costs nothing.
    #[command(name = "internal-pre-receive", hide = true)]
    InternalPreReceive,
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
    /// Who was invited and never came. With --purge, let go those whose
    /// invitation has lapsed: deactivated, on the record, as whoever
    /// runs this command.
    Unclaimed {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        #[arg(long)]
        purge: bool,
        /// Who is letting them go; the forge's first account unless said.
        #[arg(long, default_value = "")]
        r#as: String,
    },
    /// Show or set what one owner may take up here. Without any of the
    /// limits it only prints what they may have and what they are
    /// using. A limit given is laid over what was already said about
    /// this owner, so changing one changes one; `none` means no limit
    /// at all, and a limit this command is not told about keeps
    /// following the forge's own number.
    Quota {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        /// The person or organisation.
        owner: String,
        /// Who the change is recorded as: an unscoped admin.
        #[arg(long = "as")]
        r#as: Option<String>,
        /// Repositories one owner may have; `none` for no limit.
        #[arg(long)]
        repos: Option<String>,
        /// Agents one owner may have; `none` for no limit.
        #[arg(long)]
        agents: Option<String>,
        /// Open tasks their repositories may hold at once; `none` for no limit.
        #[arg(long)]
        open_tasks: Option<String>,
        /// Disk their repositories may take, in mebibytes; `none` for no limit.
        #[arg(long)]
        disk_mb: Option<String>,
        /// Changes open across their repositories; `none` for no limit.
        #[arg(long)]
        open_changes: Option<String>,
        /// Live tokens they and their agents may hold; `none` for no limit.
        #[arg(long)]
        tokens: Option<String>,
    },
    /// Reclaim disk that nothing refers to, in one repository or every
    /// one, and measure again. Git prunes on its own only after two
    /// weeks; this is for the owner who deleted things and wants their
    /// number to say so now.
    Gc {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        #[arg(long, default_value = "repos")]
        repos: PathBuf,
        /// One repository, as owner/name; every repository when absent.
        repo: Option<String>,
    },
    /// Write what an owner leaves with: a manifest of their repositories
    /// and a git bundle of each, in a directory and an archive under
    /// --into, for another forge to take in with `import` … `everything`.
    Export {
        #[arg(long, default_value = "cairn.db")]
        db: PathBuf,
        #[arg(long, default_value = "repos")]
        repos: PathBuf,
        /// The person or organisation leaving.
        #[arg(long)]
        owner: String,
        /// Where the directory and the archive are written.
        #[arg(long, default_value = ".")]
        into: PathBuf,
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
            proxy_hops,
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
            reads_per_minute,
            anonymous_reads_per_minute,
            quota_repos,
            quota_agents,
            quota_open_tasks,
            quota_disk_mb,
            quota_open_changes,
            quota_tokens,
            signing_key_file,
            operator_listen,
            open_signup,
            signup_cap,
        } => {
            let git_version = cairn_git::preflight().context("checking the git on PATH")?;
            tracing::info!("cairn {}", cairn_core::VERSION);
            // What an owner may take up here, before anything said
            // about one owner in particular. Absent leaves the built-in
            // number standing; `none` is no limit; 0 is zero, because
            // an operator who types 0 means none allowed and reading it
            // as "unlimited" is the wrong way round to be wrong.
            let mut quota = cairn_core::Quota::default();
            let said = |given: Option<String>, what: &str| -> anyhow::Result<Option<Option<u64>>> {
                match given.as_deref() {
                    None => Ok(None),
                    Some("none") => Ok(Some(None)),
                    Some(number) => Ok(Some(Some(number.parse::<u64>().with_context(|| {
                        format!("--{what} takes a number or the word none, not {number:?}")
                    })?))),
                }
            };
            let narrow = |given: Option<Option<u64>>| -> anyhow::Result<Option<Option<u32>>> {
                match given {
                    Some(Some(n)) if n > u64::from(u32::MAX) => {
                        anyhow::bail!("{n} is larger than a limit can be")
                    }
                    other => Ok(other.map(|value| value.map(|n| n as u32))),
                }
            };
            if let Some(value) = narrow(said(quota_repos, "quota-repos")?)? {
                quota.repos = value;
            }
            if let Some(value) = narrow(said(quota_agents, "quota-agents")?)? {
                quota.agents = value;
            }
            if let Some(value) = narrow(said(quota_open_tasks, "quota-open-tasks")?)? {
                quota.open_tasks = value;
            }
            if let Some(value) = said(quota_disk_mb, "quota-disk-mb")? {
                quota.disk = value.map(|mb| mb.saturating_mul(1024 * 1024));
            }
            if let Some(value) = narrow(said(quota_open_changes, "quota-open-changes")?)? {
                quota.open_changes = value;
            }
            if let Some(value) = narrow(said(quota_tokens, "quota-tokens")?)? {
                quota.tokens = value;
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
                state = state.trusting_proxy(proxy_hops);
            } else if proxy_hops != 1 {
                tracing::warn!("--proxy-hops does nothing without --trust-proxy");
            }
            state = state
                .with_write_allowance(api_writes_per_minute)
                .with_read_allowance(reads_per_minute, anonymous_reads_per_minute);
            if anonymous_reads_per_minute > 0 && !trust_proxy {
                // Worth saying out loud: behind a proxy without this
                // flag every visitor arrives from the same address, so
                // one allowance is shared by the whole internet and the
                // forge looks broken to everybody at once.
                tracing::info!(
                    "readers with no account are limited by address; behind a reverse proxy, \
                     pass --trust-proxy or they all share one allowance"
                );
            }
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
            if open_signup {
                state = state.with_open_signup().with_signup_cap(signup_cap);
                if signup_cap > 0 {
                    tracing::info!(
                        cap = signup_cap,
                        "sign-up is open: strangers may make accounts at /signup, up to the cap"
                    );
                } else {
                    tracing::info!(
                        "sign-up is open with no cap: strangers may make accounts at /signup"
                    );
                }
                if !trust_proxy {
                    // The sign-up form is limited by address like every
                    // public form; behind a proxy without this flag the
                    // whole internet is one address, and five accounts an
                    // hour is all it gets.
                    tracing::warn!(
                        "--open-signup without --trust-proxy: behind a reverse proxy every stranger \
                         shares one sign-up allowance"
                    );
                }
            }
            cairn_server::spawn_queue_processor(state.clone());
            // The operator's door, when it is served apart: the same
            // forge on a loopback listener, and the public listener
            // refusing everything that door is for.
            let operator = match operator_listen {
                Some(addr) => {
                    anyhow::ensure!(
                        addr.ip().is_loopback(),
                        "--operator-listen must be a loopback address; the point is that the tunnel cannot reach it"
                    );
                    Some(tokio::net::TcpListener::bind(addr).await?)
                }
                None => None,
            };
            let public_state = if operator.is_some() {
                state.clone().with_operator_elsewhere()
            } else {
                state.clone()
            };
            tracing::info!(
                %listen,
                operator = ?operator_listen,
                db = %db.display(),
                repos = %repos.display(),
                git = %git_version,
                "cairn serving"
            );
            // Connect info is what lets the sign-in limiter tell one
            // caller from another.
            let public = axum::serve(
                listener,
                router(public_state).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .with_graceful_shutdown(async {
                let _ = tokio::signal::ctrl_c().await;
            });
            match operator {
                Some(operator) => {
                    let door = axum::serve(
                        operator,
                        router(state).into_make_service_with_connect_info::<SocketAddr>(),
                    )
                    .with_graceful_shutdown(async {
                        let _ = tokio::signal::ctrl_c().await;
                    });
                    let (a, b) = tokio::join!(public, door);
                    a?;
                    b?;
                }
                None => public.await?,
            }
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
                open_changes,
                tokens,
            } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let owner_id =
                    PrincipalId::new(&owner).context("the owner must be a valid slug")?;
                // A confident table about somebody who does not exist is
                // worse than a refusal: it is what an operator reads
                // while working out why somebody is blocked.
                let record = store
                    .principal(&owner_id)?
                    .with_context(|| format!("no principal named {owner}"))?;
                anyhow::ensure!(
                    record.kind != cairn_core::PrincipalKind::Agent,
                    "{owner} is an agent; a quota belongs to a person or an organisation"
                );
                // `none` rather than 0, because 0 is a real answer: it
                // means this owner may have none of that thing.
                let said = |given: Option<&String>| -> anyhow::Result<Option<Option<u64>>> {
                    match given.map(String::as_str) {
                        None => Ok(None),
                        Some("none") => Ok(Some(None)),
                        Some(number) => {
                            Ok(Some(Some(number.parse::<u64>().with_context(|| {
                                format!("{number:?} is not a number, and not the word none")
                            })?)))
                        }
                    }
                };
                let narrow = |given: Option<Option<u64>>| -> anyhow::Result<Option<Option<u32>>> {
                    match given {
                        Some(Some(n)) if n > u64::from(u32::MAX) => {
                            anyhow::bail!("{n} is larger than a limit can be")
                        }
                        other => Ok(other.map(|value| value.map(|n| n as u32))),
                    }
                };
                let patch = cairn_core::QuotaOverride {
                    repos: narrow(said(repos.as_ref())?)?,
                    agents: narrow(said(agents.as_ref())?)?,
                    open_tasks: narrow(said(open_tasks.as_ref())?)?,
                    disk: said(disk_mb.as_ref())?
                        .map(|mb| mb.map(|mb| mb.saturating_mul(1024 * 1024))),
                    open_changes: narrow(said(open_changes.as_ref())?)?,
                    tokens: narrow(said(tokens.as_ref())?)?,
                };
                if !patch.is_empty() {
                    let actor = PrincipalId::new(r#as.as_deref().unwrap_or(""))
                        .context("--as <admin> says who this is recorded as")?;
                    // Laid over what was already said about them, not
                    // over what happens to hold today: merging over the
                    // effective quota would freeze this moment's
                    // defaults into a row they never escape.
                    let merged = store.quota_override(&owner_id)?.and_then(&patch);
                    store.set_quota(&actor, &owner_id, &merged)?;
                }
                let quota = store.quota(&owner_id)?;
                let usage = store.usage(&owner_id)?;
                // Offline, this handle knows the built-in numbers and not
                // the flags the running forge was started with; say so,
                // because this table is what an operator reads while
                // working out why somebody is blocked.
                println!(
                    "limits not set for {owner} are the built-in defaults here; \
                     the running forge's flags may differ (GET /api/principals/{owner}/quota is exact)"
                );
                let say = |what: &str, used: String, limit: Option<String>| {
                    println!(
                        "{what:<12} {used:>12} of {}",
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
                    cairn_server::in_bytes(usage.disk),
                    quota.disk.map(cairn_server::in_bytes),
                );
                say(
                    "open changes",
                    usage.open_changes.to_string(),
                    quota.open_changes.map(|n| n.to_string()),
                );
                say(
                    "tokens",
                    usage.tokens.to_string(),
                    quota.tokens.map(|n| n.to_string()),
                );
            }
            AdminCommand::Gc { db, repos, repo } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let git = GitStore::new(
                    &repos,
                    std::env::current_exe().context("locating own binary")?,
                );
                let names: Vec<String> = match repo {
                    Some(one) => vec![one],
                    None => store.repos()?.into_iter().map(|r| r.name).collect(),
                };
                // Awaited on main's own runtime: a second runtime made
                // here would refuse to start inside the first.
                for name in names {
                    git.gc(&name).await?;
                    let bytes = git.size(&name).await?;
                    store.record_repo_size(&name, bytes)?;
                    println!("{name:<40} {}", cairn_server::in_bytes(bytes));
                }
            }
            AdminCommand::Export {
                db,
                repos,
                owner,
                into,
            } => {
                let store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let git = GitStore::new(
                    &repos,
                    std::env::current_exe().context("locating own binary")?,
                );
                let owner = PrincipalId::new(&owner).context("--owner must be a slug")?;
                let manifest = store.graduation(&owner)?;
                let stamp = jiff::Timestamp::now().strftime("%Y%m%d-%H%M%S").to_string();
                let dir = into.join(format!("{owner}-{stamp}"));
                std::fs::create_dir_all(dir.join("bundles"))?;
                for repo in &manifest.repos {
                    git.bundle(&repo.name, &dir.join(&repo.bundle)).await?;
                    println!("bundled {}", repo.name);
                }
                std::fs::write(
                    dir.join("manifest.json"),
                    serde_json::to_string_pretty(&manifest)?,
                )?;
                let archive = into.join(format!("{owner}-{stamp}.tar.gz"));
                let status = std::process::Command::new("tar")
                    .arg("-C")
                    .arg(&into)
                    .arg("-czf")
                    .arg(&archive)
                    .arg(format!("{owner}-{stamp}"))
                    .status()?;
                anyhow::ensure!(status.success(), "tar failed");
                println!(
                    "{}: {} repositories in {} and {}",
                    owner,
                    manifest.repos.len(),
                    dir.display(),
                    archive.display()
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
            AdminCommand::Unclaimed { db, purge, r#as } => {
                let mut store = Store::open(&db)
                    .with_context(|| format!("opening forge database at {}", db.display()))?;
                let list = store.unclaimed()?;
                println!("{} invited and never came", list.len());
                for who in &list {
                    println!(
                        "  {:<24} {:<24} invitation until {}",
                        who.principal,
                        who.display,
                        who.invitation_until.as_deref().unwrap_or("-")
                    );
                }
                if purge {
                    let actor = if r#as.is_empty() {
                        store
                            .admins()?
                            .into_iter()
                            .next()
                            .context("no admin on this forge to purge as")?
                    } else {
                        cairn_core::PrincipalId::new(&r#as).context("--as is not a valid id")?
                    };
                    let gone = store.purge_unclaimed(&actor)?;
                    println!("{} let go, as {actor}", gone.len());
                    for who in gone {
                        println!("  {who}");
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
                        for entry in entries {
                            let when = entry.joined.get(..10).unwrap_or(&entry.joined);
                            let company = entry
                                .company
                                .as_deref()
                                .map(|c| format!("  for {c}"))
                                .unwrap_or_default();
                            match entry.note.as_deref() {
                                Some(note) => {
                                    println!("  {when}  {}{company}  {note}", entry.email)
                                }
                                None => println!("  {when}  {}{company}", entry.email),
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
        Command::InternalPreReceive => {
            if let Err(err) = hook::room() {
                // Written where git shows it: the pusher's terminal
                // prefixes anything a hook says with "remote:".
                eprintln!("cairn: {err}");
                std::process::exit(1);
            }
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
