//! Bare-repo storage and the glue to real git.
//!
//! The wire protocol is served by spawning `git upload-pack` /
//! `git receive-pack` — deliberately boring, because protocol
//! compatibility is exactly where cleverness goes to die. Push-to-create
//! rides git's own `proc-receive` mechanism (git 2.29+), though merging
//! needs 2.38 and [`preflight`] enforces that floor: repos are
//! configured so pushes to `refs/for/*` are handed to a hook, which
//! records the revision in the graph and reports a
//! `refs/changes/<number>/<revision>` name back to the pusher. The ref
//! itself is created afterwards by server-side reconciliation — hooks
//! cannot update refs while pushed objects are still in quarantine.

use bytes::Bytes;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::task::{Context, Poll};
use std::time::Duration;
use thiserror::Error;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt, ReadBuf};
use tokio::process::{Child, ChildStderr, ChildStdin, ChildStdout, Command};

/// Plumbing commands answer in milliseconds; anything that takes a
/// minute has hung, and holding the connection open helps nobody.
const PLUMBING_TIMEOUT: Duration = Duration::from_secs(60);

/// Serving a pack legitimately takes a while on a large repository,
/// so the wire protocol gets its own, looser bound.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

/// A quarantine directory older than this belongs to no live push:
/// no transfer runs that long, and git removed its own on every exit
/// it controlled.
const QUARANTINE_DEAD_AFTER: Duration = Duration::from_secs(2 * 600);

/// How much of a transfer's stderr is kept for the error it may end in.
const STDERR_KEPT: u64 = 16 * 1024;

/// What one stateless-RPC round reads from the client: the request
/// whole, when it is small and had to be decoded first, or as it
/// arrives, so a push of a large pack costs the forge no memory.
pub enum RpcInput {
    Whole(Vec<u8>),
    Streamed(Pin<Box<dyn futures_core::Stream<Item = std::io::Result<Bytes>> + Send>>),
}

/// A service's output as it is produced. Dropping it kills the
/// process; reading it to the end reaps the process.
pub struct RpcStream {
    child: Option<Child>,
    group: Option<ProcessGroup>,
    stdout: ChildStdout,
    stderr: Option<tokio::task::JoinHandle<String>>,
    deadline: Pin<Box<tokio::time::Sleep>>,
    buffer: Box<[u8]>,
    args: String,
}

impl futures_core::Stream for RpcStream {
    type Item = std::io::Result<Bytes>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        if this.child.is_none() {
            return Poll::Ready(None);
        }
        if this.deadline.as_mut().poll(cx).is_ready() {
            // The guards below kill the process when they drop.
            this.child = None;
            this.group = None;
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                format!(
                    "git {} did not finish within {}s",
                    this.args,
                    TRANSFER_TIMEOUT.as_secs()
                ),
            ))));
        }
        let mut buf = ReadBuf::new(&mut this.buffer);
        match Pin::new(&mut this.stdout).poll_read(cx, &mut buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Err(err)) => Poll::Ready(Some(Err(err))),
            Poll::Ready(Ok(())) if buf.filled().is_empty() => {
                // The service has said everything. Reap it off this
                // path: the reader is a client, and a client waits for
                // its bytes, not for the forge's bookkeeping.
                if let (Some(mut child), Some(mut group), Some(stderr)) =
                    (this.child.take(), this.group.take(), this.stderr.take())
                {
                    tokio::spawn(async move {
                        let _ = child.wait().await;
                        group.disarm();
                        stderr.abort();
                    });
                }
                Poll::Ready(None)
            }
            Poll::Ready(Ok(())) => Poll::Ready(Some(Ok(Bytes::copy_from_slice(buf.filled())))),
        }
    }
}

/// Every process a transfer spawned, killed together. `kill_on_drop`
/// reaches the child; the hooks the child spawned, and the git
/// commands the hooks spawned, would otherwise outlive it, holding a
/// connection to the forge and a quarantine on disk.
struct ProcessGroup(Option<u32>);

impl ProcessGroup {
    fn of(child: &Child) -> Self {
        ProcessGroup(child.id())
    }

    /// The transfer ended on its own; the group is gone, and its id
    /// may already be somebody else's.
    fn disarm(&mut self) {
        self.0 = None;
    }
}

impl Drop for ProcessGroup {
    fn drop(&mut self) {
        #[cfg(unix)]
        if let Some(pid) = self.0.take() {
            // kill(1) with a negative id signals the whole process
            // group; the group is the child's own, made at spawn, and
            // the id is disarmed once the child has exited on its own.
            // The utility rather than the system call, because this
            // crate has no unsafe code and this is not the place to
            // start.
            let _ = std::process::Command::new("kill")
                .args(["-9", "--", &format!("-{pid}")])
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();
        }
    }
}

/// Write the request to the service, however it arrives, and close
/// its stdin so it knows the request has ended.
async fn feed(input: RpcInput, mut stdin: ChildStdin) {
    match input {
        RpcInput::Whole(bytes) => {
            let _ = stdin.write_all(&bytes).await;
        }
        RpcInput::Streamed(mut stream) => loop {
            let next = std::future::poll_fn(|cx| stream.as_mut().poll_next(cx)).await;
            match next {
                Some(Ok(chunk)) => {
                    if stdin.write_all(&chunk).await.is_err() {
                        break;
                    }
                }
                Some(Err(_)) | None => break,
            }
        },
    }
    let _ = stdin.shutdown().await;
}

/// Keep the start of what the service says on stderr, and read the
/// rest so a chatty service never blocks on a full pipe.
async fn drain_stderr(mut stderr: ChildStderr) -> String {
    let mut kept = Vec::new();
    let _ = (&mut stderr).take(STDERR_KEPT).read_to_end(&mut kept).await;
    let mut sink = [0u8; 4096];
    while let Ok(n) = stderr.read(&mut sink).await {
        if n == 0 {
            break;
        }
    }
    String::from_utf8_lossy(&kept).trim().to_owned()
}

/// The forge's git is the forge's: nothing from the operator's own
/// configuration reaches it. A `core.hooksPath` in somebody's
/// ~/.gitconfig would otherwise replace the hooks that are the push
/// door, and a receive-pack that read it would open every branch to
/// a direct push with nothing logged.
fn isolated(command: &mut Command) {
    command
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .env("GIT_TERMINAL_PROMPT", "0");
}

#[derive(Debug, Error)]
pub enum GitError {
    #[error("invalid repo name {0:?}")]
    InvalidRepoName(String),

    #[error("repo {0} not found on disk")]
    RepoMissing(String),

    #[error("git {args}: {stderr}")]
    CommandFailed { args: String, stderr: String },

    #[error("git {args} did not finish within {seconds}s")]
    TimedOut { args: String, seconds: u64 },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type GitResult<T> = Result<T, GitError>;

/// Remotes sometimes quote the URL back at you. Whatever we pass on
/// must not carry a secret with it.
fn redact(message: &str, credential: Option<&str>) -> String {
    let cleaned = match credential {
        Some(secret) if !secret.is_empty() => message.replace(secret, "***"),
        _ => message.to_owned(),
    };
    cleaned.trim().chars().take(400).collect()
}

/// What came back when asking for a file's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Blob {
    Text(String),
    /// Not text; the size is still worth telling someone.
    Binary {
        bytes: u64,
    },
    /// Larger than this forge will render.
    TooLarge {
        bytes: u64,
    },
}

/// How a queued change can land on a moved (or unmoved) target.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RebaseOutcome {
    /// The revision already descends from the tip — land it as-is.
    FastForward,
    /// A fresh commit carrying the change's work merged onto the tip.
    Rebased(String),
    /// The change and the target both touched these files.
    Conflicts(Vec<String>),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Service {
    UploadPack,
    ReceivePack,
}

impl Service {
    pub fn parse(name: &str) -> Option<Self> {
        match name {
            "git-upload-pack" => Some(Service::UploadPack),
            "git-receive-pack" => Some(Service::ReceivePack),
            _ => None,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Service::UploadPack => "git-upload-pack",
            Service::ReceivePack => "git-receive-pack",
        }
    }

    fn subcommand(self) -> &'static str {
        match self {
            Service::UploadPack => "upload-pack",
            Service::ReceivePack => "receive-pack",
        }
    }

    pub fn advertisement_content_type(self) -> String {
        format!("application/x-{}-advertisement", self.name())
    }

    pub fn result_content_type(self) -> String {
        format!("application/x-{}-result", self.name())
    }
}

/// The proc-receive hook script. It execs whatever binary the server
/// names at spawn time, so the same bare repo works for production
/// serving and for tests driving a freshly built binary.
const HOOK_SCRIPT: &str =
    "#!/bin/sh\nexec \"${AMBOLT_HOOK_BIN:?ambolt hook binary not set}\" internal-proc-receive\n";

/// Branches advance only by policy-approved merges; every other write
/// path is closed. proc-receive owns refs/for/* and refs/tags/* (the
/// hook decides whether a tag names landed history and whether the
/// pusher may set one), and this pre-receive guard refuses everything
/// else, which is to say direct branch pushes.
const PRE_RECEIVE_SCRIPT: &str = r#"#!/bin/sh
status=0
while read old new ref; do
  case "$ref" in
    refs/for/*|refs/tags/*) ;;
    *)
      echo "ambolt: direct push to $ref refused; push to refs/for/<branch> - branches advance only by merge" >&2
      status=1
      ;;
  esac
done
[ "$status" -eq 0 ] || exit "$status"
exec "${AMBOLT_HOOK_BIN:?ambolt hook binary not set}" internal-pre-receive
"#;

/// The largest pack one push may carry, said to receive-pack so git
/// refuses it while reading rather than after storing it. Generous for
/// an ordinary repository's first push and far below what an owner's
/// disk quota is likely to be.
pub const MAX_PACK_BYTES: u64 = 256 * 1024 * 1024;

/// The most a push's list of ref updates may take, said to
/// receive-pack. About a hundred bytes each, so this is some ten
/// thousand refs in one push, which nobody has ever meant.
pub const MAX_COMMAND_BYTES: u64 = 1024 * 1024;

/// The oldest git this forge runs on.
///
/// Every git feature used here, with the release that introduced it:
///
/// | feature                            | since |
/// |------------------------------------|-------|
/// | `merge-tree --write-tree`          | 2.38  |
/// | `proc-receive` / `procReceiveRefs` | 2.29  |
/// | `init --object-format`             | 2.29  |
/// | `init --initial-branch`            | 2.28  |
/// | `receive.maxCommandBytes`          | 2.14  |
/// | `receive.maxInputSize`             | 2.11  |
/// | `merge-base --is-ancestor`         | 1.8   |
/// | everything else                    | < 2.0 |
///
/// Merging sets the real floor at 2.38, but this says 2.39, because 2.39
/// is the oldest git the test suite is actually run against (see the
/// `minimum-git` CI job). Claiming support for a version nothing
/// exercises is how a forge ends up deployed somewhere it cannot merge.
/// Anyone adding a git invocation should extend the table above, and
/// lower this only alongside a job that proves the older version works.
pub const MIN_GIT: (u32, u32) = (2, 39);

/// SHA-256 repositories need more than the server floor, and the extra
/// requirement falls on the *client*.
///
/// Cloning an empty repository cannot infer the object format from any
/// object, so it depends on the transport advertising it. Git before
/// 2.43 quietly produces a SHA-1 working copy instead, and the first
/// push from it will not match the repository it came from. Nothing the
/// forge does can fix that from this side; hosting SHA-256 works on the
/// server floor, but whoever clones needs 2.43.
///
/// 2.43 because that is the oldest release verified to work: 2.40 fails,
/// 2.43 succeeds, and the fix landed somewhere between them. Claiming
/// the untested boundary would be a guess.
pub const MIN_GIT_SHA256_CLIENT: (u32, u32) = (2, 43);

/// The git on PATH, as `(major, minor)` plus the version string it
/// reported.
pub fn version() -> GitResult<((u32, u32), String)> {
    let output = std::process::Command::new("git")
        .arg("--version")
        .stdin(Stdio::null())
        .output()
        .map_err(|e| GitError::CommandFailed {
            args: "--version".into(),
            stderr: format!("git is not on PATH: {e}"),
        })?;
    let found = String::from_utf8_lossy(&output.stdout).trim().to_owned();
    let numbers: Vec<u32> = found
        .split_whitespace()
        .find(|word| word.starts_with(|c: char| c.is_ascii_digit()))
        .map(|version| {
            version
                .split('.')
                .map_while(|part| part.parse().ok())
                .collect()
        })
        .unwrap_or_default();
    Ok((
        (
            numbers.first().copied().unwrap_or(0),
            numbers.get(1).copied().unwrap_or(0),
        ),
        found,
    ))
}

/// Check the git on PATH before serving anything.
///
/// A forge that boots happily on a git too old to merge tells nobody
/// anything until the first change is ready to land, and then reports it
/// as a server error to whoever happened to be waiting. Fail here
/// instead, naming the version found and the one needed.
pub fn preflight() -> GitResult<String> {
    let (found_version, found) = version()?;
    if found_version < MIN_GIT {
        return Err(GitError::CommandFailed {
            args: "--version".into(),
            stderr: format!(
                "{found} is too old: ambolt needs git {}.{} or newer. Merging uses \
                 `merge-tree --write-tree`, which does not exist before 2.38",
                MIN_GIT.0, MIN_GIT.1
            ),
        });
    }
    Ok(found)
}

/// Where a landed commit's receipt is kept, mirrored with the branch.
pub const NOTES_REF: &str = "refs/notes/ambolt";

pub struct GitStore {
    root: PathBuf,
    hook_bin: PathBuf,
}

impl GitStore {
    pub fn new(root: impl Into<PathBuf>, hook_bin: impl Into<PathBuf>) -> Self {
        GitStore {
            root: root.into(),
            hook_bin: hook_bin.into(),
        }
    }

    pub fn hook_bin(&self) -> &Path {
        &self.hook_bin
    }

    /// Defense in depth: the core validates repo names, but path
    /// construction re-checks so this layer is safe on its own. A name
    /// is `owner/short`, two slugs, and lives at `<root>/<owner>/<short>.git`;
    /// a name with no owner, from before owners, lives at `<root>/<name>.git`
    /// until it is adopted.
    fn repo_path(&self, name: &str) -> GitResult<PathBuf> {
        let slug = |s: &str| {
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-')
        };
        let valid = match name.split_once('/') {
            Some((owner, short)) => slug(owner) && slug(short),
            None => slug(name),
        };
        if !valid {
            return Err(GitError::InvalidRepoName(name.to_owned()));
        }
        Ok(self.root.join(format!("{name}.git")))
    }

    fn existing_repo_path(&self, name: &str) -> GitResult<PathBuf> {
        let path = self.repo_path(name)?;
        if !path.is_dir() {
            return Err(GitError::RepoMissing(name.to_owned()));
        }
        Ok(path)
    }

    async fn run(&self, current_dir: Option<&Path>, args: &[&str]) -> GitResult<Vec<u8>> {
        let mut command = Command::new("git");
        // Anything that writes a commit - a note, a rebase - has an
        // identity to write it as. A CI runner with no ~/.gitconfig was
        // how this was learned.
        isolated(&mut command);
        command
            .env("GIT_AUTHOR_NAME", "ambolt")
            .env("GIT_AUTHOR_EMAIL", "forge@ambolt.invalid")
            .env("GIT_COMMITTER_NAME", "ambolt")
            .env("GIT_COMMITTER_EMAIL", "forge@ambolt.invalid");
        if let Some(dir) = current_dir {
            command.current_dir(dir);
        }
        command.args(args).stdin(Stdio::null()).kill_on_drop(true);
        let output = tokio::time::timeout(PLUMBING_TIMEOUT, command.output())
            .await
            .map_err(|_| GitError::TimedOut {
                args: args.join(" "),
                seconds: PLUMBING_TIMEOUT.as_secs(),
            })??;
        if !output.status.success() {
            return Err(GitError::CommandFailed {
                args: args.join(" "),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
    }

    pub async fn create_repo(
        &self,
        name: &str,
        default_branch: &str,
        object_format: &str,
    ) -> GitResult<()> {
        let path = self.repo_path(name)?;
        tokio::fs::create_dir_all(path.parent().unwrap_or(&self.root)).await?;
        self.run(
            None,
            &[
                "init",
                "--bare",
                "--initial-branch",
                default_branch,
                &format!("--object-format={object_format}"),
                path.to_str().unwrap(),
            ],
        )
        .await?;
        for refs in ["refs/for", "refs/tags"] {
            self.run(
                Some(&path),
                &["config", "--add", "receive.procReceiveRefs", refs],
            )
            .await?;
        }
        // A half-finished import must not be fetchable by anyone who can
        // read the repository.
        self.run(Some(&path), &["config", "transfer.hideRefs", "refs/import"])
            .await?;
        self.install_hooks(&path).await
    }

    /// Write the hook scripts this binary expects. Run at creation and
    /// again before every receive, so a repository created by an older
    /// forge carries the current scripts without anyone migrating it.
    async fn install_hooks(&self, path: &Path) -> GitResult<()> {
        for (hook, script) in [
            ("proc-receive", HOOK_SCRIPT),
            ("pre-receive", PRE_RECEIVE_SCRIPT),
        ] {
            let hook_path = path.join("hooks").join(hook);
            let current = tokio::fs::read(&hook_path).await.ok();
            if current.as_deref() != Some(script.as_bytes()) {
                // Written beside and renamed over: two receives after an
                // upgrade both install, and a receive-pack that execs a
                // half-written hook is refused for no reason of the
                // pusher's. A rename is whole or not there.
                let staged = path
                    .join("hooks")
                    .join(format!(".{hook}.{}", std::process::id()));
                tokio::fs::write(&staged, script).await?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    tokio::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755))
                        .await?;
                }
                tokio::fs::rename(&staged, &hook_path).await?;
            }
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                tokio::fs::set_permissions(&hook_path, std::fs::Permissions::from_mode(0o755))
                    .await?;
            }
        }
        Ok(())
    }

    /// The smart-HTTP ref advertisement: service banner, flush, then the
    /// service's own advertisement output.
    /// Move a repository's directory to a new name. The graph decides
    /// the name; this only follows it.
    pub async fn rename_repo(&self, from: &str, to: &str) -> GitResult<()> {
        let src = self.existing_repo_path(from)?;
        let dst = self.repo_path(to)?;
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::rename(&src, &dst).await?;
        Ok(())
    }

    /// Whether a repository's directory exists where its name says.
    /// How much disk this repository takes, in bytes: every file under
    /// its directory added up.
    ///
    /// Measured rather than tracked, because git changes the answer on
    /// its own — packing objects makes a repository smaller with nothing
    /// happening in the forge to record. The walk is blocking work, so
    /// it runs off the async threads.
    pub async fn size(&self, name: &str) -> GitResult<u64> {
        let dir = self.existing_repo_path(name)?;
        // An alternates file moves a repository's objects somewhere the
        // walk does not go. This forge never writes one; one that
        // appears was put there by hand, and a number that ignores it
        // would be a number that ignores most of the repository.
        if dir.join("objects/info/alternates").is_file() {
            return Err(GitError::Io(std::io::Error::other(
                "objects/info/alternates is present; storage outside the repository cannot be measured",
            )));
        }
        tokio::task::spawn_blocking(move || directory_size(&dir))
            .await
            .map_err(|err| GitError::Io(std::io::Error::other(err)))?
    }

    /// Reclaim what nothing refers to. A conflicting rebase, an import
    /// that failed, a landing that did not finish: each leaves objects
    /// behind that no ref names, and git prunes them on its own only
    /// after two weeks and only past a threshold. An operator's command
    /// for the owner who cleaned up and wants the number to say so.
    /// Repack, and drop objects nothing refers to — but only objects
    /// older than an hour. A push's objects are referred to by nothing
    /// between leaving quarantine and the reconciliation that writes
    /// their ref; `--prune=now` would delete a push in flight, and the
    /// graph would go on naming a revision git no longer has.
    pub async fn gc(&self, name: &str) -> GitResult<()> {
        let dir = self.existing_repo_path(name)?;
        self.run(Some(&dir), &["gc", "--prune=1.hour.ago", "--quiet"])
            .await
            .map(|_| ())
    }

    /// Remove quarantine directories no push is using. Git removes its
    /// own on every exit it controls; a receive-pack killed at the
    /// timeout, or when the pusher hung up, has no exit, and the pack
    /// it had taken in sits under `objects/tmp_objdir-*` where the
    /// measurement counts it and nothing else does. Returns how many
    /// were removed.
    pub async fn sweep_quarantines(&self, name: &str) -> GitResult<usize> {
        let objects = self.existing_repo_path(name)?.join("objects");
        let mut entries = match tokio::fs::read_dir(&objects).await {
            Ok(entries) => entries,
            Err(_) => return Ok(0),
        };
        let mut swept = 0;
        while let Ok(Some(entry)) = entries.next_entry().await {
            let file_name = entry.file_name();
            let Some(text) = file_name.to_str() else {
                continue;
            };
            if !text.starts_with("tmp_objdir-") {
                continue;
            }
            let Ok(meta) = entry.metadata().await else {
                continue;
            };
            if !meta.is_dir() {
                continue;
            }
            // A live quarantine is being written to; its directory's
            // modification time keeps moving. One that stopped moving
            // longer ago than any transfer may run is dead.
            let dead = meta
                .modified()
                .ok()
                .and_then(|at| at.elapsed().ok())
                .is_some_and(|age| age > QUARANTINE_DEAD_AFTER);
            if dead && tokio::fs::remove_dir_all(entry.path()).await.is_ok() {
                swept += 1;
            }
        }
        Ok(swept)
    }

    /// Whether a commit is reachable from some branch: landed history,
    /// which is what a tag may name.
    pub async fn on_a_branch(&self, name: &str, commit: &str) -> GitResult<bool> {
        let dir = self.existing_repo_path(name)?;
        let out = self
            .run(
                Some(&dir),
                &["branch", "--contains", commit, "--format=%(refname)"],
            )
            .await?;
        Ok(!String::from_utf8_lossy(&out).trim().is_empty())
    }

    pub fn has_repo_dir(&self, name: &str) -> bool {
        self.repo_path(name).map(|p| p.is_dir()).unwrap_or(false)
    }

    /// Remove a repository's directory. Nothing serves a repository the
    /// graph has forgotten, so a directory that lingers is harmless and
    /// one that is gone is what the graph already says.
    pub async fn remove_repo(&self, name: &str) -> GitResult<()> {
        let dir = self.repo_path(name)?;
        if !tokio::fs::try_exists(&dir).await? {
            return Ok(());
        }
        // Moved aside first, which is atomic and immediate, then removed
        // behind that. Removing in place races with anything still
        // writing into the directory — a collection the queue started
        // a moment ago, a measurement walking it — and a directory that
        // changes under remove_dir_all is an error for a deletion that
        // has already happened as far as the forge is concerned.
        let aside = self.root.join(format!(
            ".removed-{}-{}",
            name.replace('/', "-"),
            std::process::id()
        ));
        let aside = if tokio::fs::try_exists(&aside).await? {
            aside.with_extension(format!(
                "{}",
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ))
        } else {
            aside
        };
        tokio::fs::rename(&dir, &aside).await?;
        tokio::spawn(async move {
            // A first attempt may lose to a writer finishing up inside;
            // the second finds it gone.
            for _ in 0..3 {
                match tokio::fs::remove_dir_all(&aside).await {
                    Ok(()) => return,
                    Err(_) => tokio::time::sleep(Duration::from_secs(2)).await,
                }
            }
            let _ = tokio::fs::remove_dir_all(&aside).await;
        });
        Ok(())
    }

    pub async fn advertise_refs(
        &self,
        service: Service,
        name: &str,
        git_protocol: Option<&str>,
    ) -> GitResult<Vec<u8>> {
        let path = self.existing_repo_path(name)?;
        let mut command = Command::new("git");
        isolated(&mut command);
        command
            .arg(service.subcommand())
            .arg("--stateless-rpc")
            .arg("--advertise-refs")
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        if let Some(version) = git_protocol {
            command.env("GIT_PROTOCOL", version);
        }
        let output = tokio::time::timeout(TRANSFER_TIMEOUT, command.output())
            .await
            .map_err(|_| GitError::TimedOut {
                args: format!("{} --advertise-refs", service.subcommand()),
                seconds: TRANSFER_TIMEOUT.as_secs(),
            })??;
        if !output.status.success() {
            return Err(GitError::CommandFailed {
                args: format!("{} --advertise-refs", service.subcommand()),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        let mut body = crate::pkt::data_line(format!("# service={}\n", service.name()).as_bytes());
        body.extend_from_slice(b"0000");
        body.extend_from_slice(&output.stdout);
        Ok(body)
    }

    /// One stateless-RPC round: the request body goes to the service's
    /// stdin, its stdout is the response body. `env` carries the forge
    /// context the proc-receive hook needs.
    /// The command for one stateless-RPC round, with everything the
    /// forge says to git said on the command line rather than read
    /// from any configuration.
    async fn rpc_command(
        &self,
        service: Service,
        path: &Path,
        env: Vec<(String, String)>,
        git_protocol: Option<&str>,
    ) -> GitResult<Command> {
        let mut command = Command::new("git");
        isolated(&mut command);
        if service == Service::ReceivePack {
            self.install_hooks(path).await?;
            // The hooks are the push door, and where they are is this
            // binary's decision; said here so that no configuration
            // anywhere can point receive-pack at other ones. Absolute,
            // because git resolves a relative hooks path from inside
            // the repository, and a forge started with `--repos repos`
            // names its repositories relatively.
            let hooks =
                std::path::absolute(path.join("hooks")).unwrap_or_else(|_| path.join("hooks"));
            command
                .arg("-c")
                .arg(format!("core.hooksPath={}", hooks.display()));
            // Which refs the hook owns is this binary's decision, not the
            // repository's configuration, so it is said on every receive.
            for refs in ["refs/for", "refs/tags"] {
                command
                    .arg("-c")
                    .arg(format!("receive.procReceiveRefs={refs}"));
            }
            // Keep a pushed pack a pack. Git's default explodes any push
            // of a hundred objects or fewer into loose objects, which
            // throws away delta compression: a few megabytes on the wire
            // becomes tens on disk, and a disk quota counted from the
            // disk cannot see it coming. Said here rather than written
            // into each repository's config, so it holds for every
            // repository this binary serves, old ones included.
            command.arg("-c").arg("receive.unpackLimit=1");
            command
                .arg("-c")
                .arg(format!("receive.maxInputSize={MAX_PACK_BYTES}"));
            // One push may update many refs, and each costs the hook
            // several git commands and the forge a write; a push naming
            // millions of them is not a push. A megabyte is thousands.
            command
                .arg("-c")
                .arg(format!("receive.maxCommandBytes={MAX_COMMAND_BYTES}"));
            // What arrives is checked for being well-formed git before
            // it is stored, so a malformed tree cannot be pushed in to
            // break every later read of it.
            command.arg("-c").arg("receive.fsckObjects=true");
        }
        command
            .arg(service.subcommand())
            .arg("--stateless-rpc")
            .arg(path)
            .envs(env)
            .env("AMBOLT_HOOK_BIN", &self.hook_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(version) = git_protocol {
            command.env("GIT_PROTOCOL", version);
        }
        command.kill_on_drop(true);
        // Its own process group, so that the hooks it spawns and the
        // git commands they spawn die with it rather than being
        // reparented to init when it is killed.
        #[cfg(unix)]
        command.process_group(0);
        Ok(command)
    }

    /// One stateless-RPC round, answered whole: the request goes to the
    /// service's stdin as it arrives, and its stdout comes back once it
    /// has exited. For receive-pack, whose answer is a short report and
    /// whose exit is what the forge waits for before writing refs.
    pub async fn serve_rpc(
        &self,
        service: Service,
        name: &str,
        input: RpcInput,
        env: Vec<(String, String)>,
        git_protocol: Option<&str>,
    ) -> GitResult<Vec<u8>> {
        let path = self.existing_repo_path(name)?;
        let mut command = self.rpc_command(service, &path, env, git_protocol).await?;
        let mut child = command.spawn()?;
        let mut group = ProcessGroup::of(&child);
        let stdin = child.stdin.take().expect("stdin piped");
        // Feed the request concurrently with reading the response so a
        // large exchange in either direction cannot deadlock the pipes.
        tokio::spawn(feed(input, stdin));
        let output = tokio::time::timeout(TRANSFER_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| GitError::TimedOut {
                args: format!("{} --stateless-rpc", service.subcommand()),
                seconds: TRANSFER_TIMEOUT.as_secs(),
            })??;
        group.disarm();
        if !output.status.success() {
            return Err(GitError::CommandFailed {
                args: format!("{} --stateless-rpc", service.subcommand()),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
    }

    /// One stateless-RPC round, answered as it is produced: the
    /// service's stdout is handed back as a stream, so a clone of a
    /// large repository costs the forge a buffer's worth of memory
    /// rather than the repository's. For upload-pack, which has nothing
    /// to do once the pack has been sent.
    pub async fn stream_rpc(
        &self,
        service: Service,
        name: &str,
        input: RpcInput,
        git_protocol: Option<&str>,
    ) -> GitResult<RpcStream> {
        let path = self.existing_repo_path(name)?;
        let mut command = self
            .rpc_command(service, &path, Vec::new(), git_protocol)
            .await?;
        let mut child = command.spawn()?;
        let group = ProcessGroup::of(&child);
        let stdin = child.stdin.take().expect("stdin piped");
        let stdout = child.stdout.take().expect("stdout piped");
        let stderr = child.stderr.take().expect("stderr piped");
        tokio::spawn(feed(input, stdin));
        Ok(RpcStream {
            child: Some(child),
            group: Some(group),
            stdout,
            stderr: Some(tokio::spawn(drain_stderr(stderr))),
            deadline: Box::pin(tokio::time::sleep(TRANSFER_TIMEOUT)),
            buffer: vec![0u8; 64 * 1024].into_boxed_slice(),
            args: format!("{} --stateless-rpc", service.subcommand()),
        })
    }

    /// All refs under a prefix, as (refname, oid).
    pub async fn list_refs(&self, name: &str, prefix: &str) -> GitResult<Vec<(String, String)>> {
        let path = self.existing_repo_path(name)?;
        let stdout = self
            .run(
                Some(&path),
                &["for-each-ref", "--format=%(refname) %(objectname)", prefix],
            )
            .await?;
        Ok(String::from_utf8_lossy(&stdout)
            .lines()
            .filter_map(|line| {
                line.split_once(' ')
                    .map(|(r, o)| (r.to_owned(), o.to_owned()))
            })
            .collect())
    }

    /// Every tag: its short name, the object the ref points at, and the
    /// commit that resolves to (the same for a lightweight tag).
    pub async fn list_tags(&self, name: &str) -> GitResult<Vec<(String, String, String)>> {
        let path = self.existing_repo_path(name)?;
        let stdout = self
            .run(
                Some(&path),
                &[
                    "for-each-ref",
                    "--format=%(refname:short) %(objectname) %(*objectname)",
                    "refs/tags",
                ],
            )
            .await?;
        Ok(String::from_utf8_lossy(&stdout)
            .lines()
            .filter_map(|line| {
                let mut parts = line.split(' ');
                let tag = parts.next()?.to_owned();
                let object = parts.next()?.to_owned();
                let commit = parts
                    .next()
                    .filter(|peeled| !peeled.is_empty())
                    .map_or_else(|| object.clone(), str::to_owned);
                Some((tag, object, commit))
            })
            .collect())
    }

    /// Point a ref at an object (creating it if missing). Fails if the
    /// object is not present in the repo.
    pub async fn set_ref(&self, name: &str, refname: &str, oid: &str) -> GitResult<()> {
        let path = self.existing_repo_path(name)?;
        self.run(Some(&path), &["update-ref", refname, oid]).await?;
        Ok(())
    }

    /// Land-readiness of `commit` against `tip`: fast-forward if
    /// possible, otherwise a real three-way merge computed in memory
    /// (`git merge-tree`, no worktree) committed with the original
    /// author preserved and the forge as committer.
    pub async fn rebase_onto(
        &self,
        name: &str,
        tip: &str,
        commit: &str,
    ) -> GitResult<RebaseOutcome> {
        let path = self.existing_repo_path(name)?;
        if self.is_ancestor(name, tip, commit).await? {
            return Ok(RebaseOutcome::FastForward);
        }
        let merge = Command::new("git")
            .current_dir(&path)
            .args(["merge-tree", "--write-tree", "--name-only", tip, commit])
            .stdin(Stdio::null())
            .output()
            .await?;
        let stdout = String::from_utf8_lossy(&merge.stdout);
        let mut lines = stdout.lines();
        let tree = lines.next().unwrap_or("").trim().to_owned();
        match merge.status.code() {
            Some(0) => {}
            // Exit 1 is a content conflict; the remaining lines name
            // the files both sides touched.
            Some(1) => {
                let mut files: Vec<String> = lines
                    .map(str::trim)
                    .filter(|l| !l.is_empty())
                    .map(str::to_owned)
                    .collect();
                files.dedup();
                return Ok(RebaseOutcome::Conflicts(files));
            }
            _ => {
                return Err(GitError::CommandFailed {
                    args: "merge-tree --write-tree".into(),
                    stderr: String::from_utf8_lossy(&merge.stderr).trim().to_owned(),
                });
            }
        }
        // Re-commit the merged tree on the tip, preserving authorship.
        let raw = self
            .run(Some(&path), &["cat-file", "commit", commit])
            .await?;
        let info = crate::commit::parse_commit_object(&String::from_utf8_lossy(&raw));
        let mut command = Command::new("git");
        command
            .current_dir(&path)
            .args(["commit-tree", &tree, "-p", tip, "-m", &info.message])
            .env("GIT_COMMITTER_NAME", "ambolt")
            .env("GIT_COMMITTER_EMAIL", "queue@ambolt.invalid")
            .stdin(Stdio::null());
        if let Some((author_name, email, date)) = &info.author {
            command
                .env("GIT_AUTHOR_NAME", author_name)
                .env("GIT_AUTHOR_EMAIL", email)
                .env("GIT_AUTHOR_DATE", date);
        }
        let committed = command.output().await?;
        if !committed.status.success() {
            return Err(GitError::CommandFailed {
                args: "commit-tree".into(),
                stderr: String::from_utf8_lossy(&committed.stderr).trim().to_owned(),
            });
        }
        Ok(RebaseOutcome::Rebased(
            String::from_utf8_lossy(&committed.stdout).trim().to_owned(),
        ))
    }

    /// Entries of a tree at `rev` (a ref or oid), one path level:
    /// (kind, name), directories first as git emits them sorted.
    pub async fn ls_tree(
        &self,
        name: &str,
        rev: &str,
        path: &str,
    ) -> GitResult<Vec<(String, String)>> {
        let repo = self.existing_repo_path(name)?;
        let spec = if path.is_empty() {
            rev.to_owned()
        } else {
            format!("{rev}:{path}")
        };
        // Default output, not --format: that option arrived in git 2.36,
        // and Ubuntu 22.04 — a normal place to run this — ships 2.34.
        // -z gives NUL-terminated records with raw, unquoted paths, so a
        // filename containing a space or newline still parses.
        let stdout = self.run(Some(&repo), &["ls-tree", "-z", &spec]).await?;
        let mut entries: Vec<(String, String)> = String::from_utf8_lossy(&stdout)
            .split('\0')
            .filter(|record| !record.is_empty())
            .filter_map(|record| {
                // "<mode> <type> <oid>\t<path>"
                let (meta, path) = record.split_once('\t')?;
                let kind = meta.split_whitespace().nth(1)?;
                Some((kind.to_owned(), path.to_owned()))
            })
            .collect();
        entries.sort_by(|a, b| (a.0 != "tree", &a.1).cmp(&(b.0 != "tree", &b.1)));
        Ok(entries)
    }

    /// Every blob path under `rev`, recursively, in tree order.
    pub async fn list_files(&self, name: &str, rev: &str) -> GitResult<Vec<String>> {
        let repo = self.existing_repo_path(name)?;
        let stdout = self
            .run(Some(&repo), &["ls-tree", "-r", "-z", "--name-only", rev])
            .await?;
        Ok(String::from_utf8_lossy(&stdout)
            .split('\0')
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// Whether a ref exists in the repository.
    pub async fn has_ref(&self, name: &str, refname: &str) -> GitResult<bool> {
        let repo = self.existing_repo_path(name)?;
        Ok(self
            .run(Some(&repo), &["rev-parse", "--verify", "--quiet", refname])
            .await
            .is_ok())
    }

    /// Attach a note to a commit under [`NOTES_REF`], replacing
    /// any earlier one. The text goes through a file: a receipt is
    /// larger than an argument should be.
    pub async fn attach_note(&self, name: &str, oid: &str, text: &str) -> GitResult<()> {
        let repo = self.existing_repo_path(name)?;
        // Two landings in the same process at the same instant must not
        // share a scratch file, or one commit gets the other's receipt.
        static NOTES: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let scratch = std::env::temp_dir().join(format!(
            "ambolt-note-{}-{}-{}.json",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or_default(),
            NOTES.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        tokio::fs::write(&scratch, text).await?;
        let file = scratch.to_string_lossy().into_owned();
        let outcome = self
            .run(
                Some(&repo),
                &[
                    "notes",
                    &format!("--ref={NOTES_REF}"),
                    "add",
                    "-f",
                    "-F",
                    &file,
                    oid,
                ],
            )
            .await;
        let _ = tokio::fs::remove_file(&scratch).await;
        outcome.map(|_| ())
    }

    /// The files one commit touched against its first parent (or
    /// everything, for a root commit).
    pub async fn changed_paths(&self, name: &str, oid: &str) -> GitResult<Vec<String>> {
        let repo = self.existing_repo_path(name)?;
        let stdout = self
            .run(
                Some(&repo),
                &[
                    "diff-tree",
                    "--no-commit-id",
                    "--name-only",
                    "-r",
                    "--root",
                    "-z",
                    oid,
                ],
            )
            .await?;
        Ok(String::from_utf8_lossy(&stdout)
            .split('\0')
            .filter(|p| !p.is_empty())
            .map(str::to_owned)
            .collect())
    }

    /// The last commit to touch `path` at `rev`: (oid, subject).
    pub async fn last_commit_for(
        &self,
        name: &str,
        rev: &str,
        path: &str,
    ) -> GitResult<Option<(String, String)>> {
        let repo = self.existing_repo_path(name)?;
        let stdout = self
            .run(
                Some(&repo),
                &["log", "-1", "--format=%H%x1f%s", rev, "--", path],
            )
            .await?;
        Ok(String::from_utf8_lossy(&stdout)
            .trim()
            .split_once('\u{1f}')
            .map(|(oid, subject)| (oid.to_owned(), subject.to_owned())))
    }

    /// Which commit last touched each line of a file: one oid per line,
    /// in file order. `git blame --line-porcelain` gives an oid header
    /// per line; we keep only that.
    pub async fn blame_lines(&self, name: &str, rev: &str, path: &str) -> GitResult<Vec<String>> {
        let repo = self.existing_repo_path(name)?;
        let stdout = self
            .run(Some(&repo), &["blame", "--line-porcelain", rev, "--", path])
            .await?;
        Ok(String::from_utf8_lossy(&stdout)
            .lines()
            .filter(|line| {
                // Header lines are "<oid> <orig-line> <final-line>[ n]";
                // porcelain content lines are tab-prefixed.
                !line.starts_with('\t')
                    && line.len() > 40
                    && line.split(' ').next().is_some_and(|first| {
                        first.len() >= 40 && first.chars().all(|c| c.is_ascii_hexdigit())
                    })
            })
            .filter_map(|line| line.split(' ').next().map(str::to_owned))
            .collect())
    }

    /// A blob's contents at `rev`, or None when the path doesn't exist.
    pub async fn show_file(&self, name: &str, rev: &str, path: &str) -> GitResult<Option<Vec<u8>>> {
        let repo = self.existing_repo_path(name)?;
        match self
            .run(Some(&repo), &["show", &format!("{rev}:{path}")])
            .await
        {
            Ok(bytes) => Ok(Some(bytes)),
            Err(GitError::CommandFailed { .. }) => Ok(None),
            Err(other) => Err(other),
        }
    }

    /// A blob, or a reason it is not being shown.
    ///
    /// Reading first and deciding afterwards is the wrong order when the
    /// caller does not control the size: a repository may legitimately
    /// contain a video, and rendering it would mean the bytes in memory
    /// once, a lossy `String` copy of them, and an escaped HTML copy
    /// larger still — for a file nobody can read anyway. So the size is
    /// asked for before anything is read.
    pub async fn read_blob(
        &self,
        name: &str,
        rev: &str,
        path: &str,
        limit: u64,
    ) -> GitResult<Option<Blob>> {
        let repo = self.existing_repo_path(name)?;
        let spec = format!("{rev}:{path}");
        let Ok(raw) = self.run(Some(&repo), &["cat-file", "-s", &spec]).await else {
            return Ok(None);
        };
        let bytes: u64 = String::from_utf8_lossy(&raw).trim().parse().unwrap_or(0);
        if bytes > limit {
            return Ok(Some(Blob::TooLarge { bytes }));
        }
        let content = match self.run(Some(&repo), &["show", &spec]).await {
            Ok(content) => content,
            Err(GitError::CommandFailed { .. }) => return Ok(None),
            Err(other) => return Err(other),
        };
        // git's own heuristic: a NUL anywhere near the start means this
        // is not text, and showing it as text helps nobody.
        if content.iter().take(8000).any(|byte| *byte == 0) {
            return Ok(Some(Blob::Binary { bytes }));
        }
        Ok(Some(Blob::Text(
            String::from_utf8_lossy(&content).into_owned(),
        )))
    }

    /// The unified diff a commit introduces over its first parent.
    pub async fn show_patch(&self, name: &str, oid: &str) -> GitResult<String> {
        let repo = self.existing_repo_path(name)?;
        let stdout = self
            .run(
                Some(&repo),
                &["show", "--format=", "--patch", "--no-color", oid],
            )
            .await?;
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// What changed between two commits, as a patch: the interdiff between
    /// two revisions of one change.
    pub async fn diff_between(&self, name: &str, from: &str, to: &str) -> GitResult<String> {
        let repo = self.existing_repo_path(name)?;
        let stdout = self
            .run(Some(&repo), &["diff", "--no-color", from, to])
            .await?;
        Ok(String::from_utf8_lossy(&stdout).into_owned())
    }

    /// Copy a branch to an outside remote. The credential is supplied
    /// per call and never stored: it belongs to whoever runs the forge,
    /// not to the graph.
    pub async fn push_to_mirror(
        &self,
        name: &str,
        url: &str,
        branch: &str,
        credential: Option<&str>,
    ) -> GitResult<()> {
        let path = self.existing_repo_path(name)?;
        // Credentials go in the URL only for the lifetime of this
        // process, and never touch a config file or the log.
        let target = match credential {
            Some(secret) if url.starts_with("https://") => {
                url.replacen("https://", &format!("https://{secret}@"), 1)
            }
            _ => url.to_owned(),
        };
        // The receipts travel with the code: the notes ref goes along
        // whenever the repository has one.
        // Tags name landed history, so they travel too; a glob with
        // nothing behind it pushes nothing and is not an error.
        let mut refspecs = vec![
            format!("refs/heads/{branch}:refs/heads/{branch}"),
            "refs/tags/*:refs/tags/*".to_owned(),
        ];
        if self.has_ref(name, NOTES_REF).await? {
            refspecs.push(format!("{NOTES_REF}:{NOTES_REF}"));
        }
        let mut command = Command::new("git");
        command
            .current_dir(&path)
            .args(["push", "--porcelain", &target])
            .args(&refspecs)
            .env("GIT_TERMINAL_PROMPT", "0")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(TRANSFER_TIMEOUT, command.output())
            .await
            .map_err(|_| GitError::TimedOut {
                args: "push (mirror)".into(),
                seconds: TRANSFER_TIMEOUT.as_secs(),
            })??;
        if !output.status.success() {
            // Never echo the target back: it may carry the secret.
            return Err(GitError::CommandFailed {
                args: format!("push {branch} to the mirror"),
                stderr: redact(&String::from_utf8_lossy(&output.stderr), credential),
            });
        }
        Ok(())
    }

    /// Current tip of a branch, or None if the branch doesn't exist yet.
    pub async fn tip(&self, name: &str, branch: &str) -> GitResult<Option<String>> {
        let path = self.existing_repo_path(name)?;
        match self
            .run(
                Some(&path),
                &["rev-parse", "--verify", &format!("refs/heads/{branch}")],
            )
            .await
        {
            Ok(stdout) => Ok(Some(String::from_utf8_lossy(&stdout).trim().to_owned())),
            Err(GitError::CommandFailed { .. }) => Ok(None),
            Err(other) => Err(other),
        }
    }

    pub async fn is_ancestor(
        &self,
        name: &str,
        ancestor: &str,
        descendant: &str,
    ) -> GitResult<bool> {
        let path = self.existing_repo_path(name)?;
        let mut command = Command::new("git");
        let output = command
            .current_dir(&path)
            .args(["merge-base", "--is-ancestor", ancestor, descendant])
            .stdin(Stdio::null())
            .output()
            .await?;
        Ok(output.status.success())
    }

    /// Fetch a branch's history from elsewhere into this repository,
    /// without publishing it. Returns the fetched tip and how many
    /// commits came with it. Nothing is pointed at the branch here: the
    /// caller records the import first, so the log never trails the ref.
    pub async fn fetch_history(
        &self,
        name: &str,
        source: &str,
        branch: &str,
    ) -> GitResult<(String, i64)> {
        let path = self.existing_repo_path(name)?;
        // Land it on a holding ref so a failed fetch leaves the branch
        // untouched, and so nothing is reachable under refs/heads until
        // the import is on the record.
        let staging = format!("refs/import/{branch}");
        let from = Self::fetch_source(source);
        self.run(
            Some(&path),
            &[
                "fetch",
                "--no-tags",
                &from,
                &format!("+refs/heads/{branch}:{staging}"),
            ],
        )
        .await?;
        let tip = String::from_utf8_lossy(&self.run(Some(&path), &["rev-parse", &staging]).await?)
            .trim()
            .to_owned();
        let count = String::from_utf8_lossy(
            &self
                .run(Some(&path), &["rev-list", "--count", &staging])
                .await?,
        )
        .trim()
        .parse()
        .unwrap_or(0);
        Ok((tip, count))
    }

    /// What git is told to fetch from. A `file://` address that names a
    /// file rather than a directory is a bundle, which git reads only as
    /// a plain path: the url form would try to run upload-pack inside
    /// a file.
    fn fetch_source(source: &str) -> String {
        if let Some(path) = source.strip_prefix("file://")
            && Path::new(path).is_file()
        {
            return path.to_owned();
        }
        source.to_owned()
    }

    /// Everything a repository holds, as one file git can fetch from:
    /// every ref — branches, tags, the change refs, the receipt notes —
    /// and the objects they reach. How a repository leaves a forge.
    pub async fn bundle(&self, name: &str, into: &Path) -> GitResult<()> {
        let path = self.existing_repo_path(name)?;
        // git runs inside the repository, so a relative destination
        // would land inside it; the caller's path is taken from where
        // the caller stands.
        let into = std::path::absolute(into)?;
        if let Some(parent) = into.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        self.run(
            Some(&path),
            &[
                "bundle",
                "create",
                into.to_str().unwrap_or("bundle"),
                "--all",
            ],
        )
        .await?;
        Ok(())
    }

    /// Fetch all of a source: its branches and tags onto holding refs,
    /// and its receipt notes as they are. Returns each branch with its
    /// tip and how many commits it carries, for the record to be
    /// written before any branch is published; the tags wait on
    /// [`Self::holding_tags`] for the same treatment. The source's
    /// change refs stay behind: they are that forge's log projected
    /// onto git, and would collide with this one's numbering.
    pub async fn fetch_everything(
        &self,
        name: &str,
        source: &str,
    ) -> GitResult<Vec<(String, String, i64)>> {
        let path = self.existing_repo_path(name)?;
        let from = Self::fetch_source(source);
        self.run(
            Some(&path),
            &[
                "fetch",
                "--no-tags",
                &from,
                "+refs/heads/*:refs/import/*",
                "+refs/tags/*:refs/import-tags/*",
                "+refs/notes/*:refs/notes/*",
            ],
        )
        .await?;
        let mut branches = Vec::new();
        for (refname, tip) in self.list_refs(name, "refs/import/").await? {
            let Some(branch) = refname.strip_prefix("refs/import/") else {
                continue;
            };
            let count = String::from_utf8_lossy(
                &self
                    .run(Some(&path), &["rev-list", "--count", &refname])
                    .await?,
            )
            .trim()
            .parse()
            .unwrap_or(0);
            branches.push((branch.to_owned(), tip, count));
        }
        Ok(branches)
    }

    /// A fetched source's tags, waiting on their holding refs: each
    /// tag's name, the object the ref points at, the commit that
    /// resolves to, and the message if it is an annotated tag.
    pub async fn holding_tags(
        &self,
        name: &str,
    ) -> GitResult<Vec<(String, String, String, Option<String>)>> {
        let path = self.existing_repo_path(name)?;
        let stdout = self
            .run(
                Some(&path),
                &[
                    "for-each-ref",
                    "--format=%(refname) %(objectname) %(*objectname) %(objecttype)",
                    "refs/import-tags/",
                ],
            )
            .await?;
        let mut tags = Vec::new();
        for line in String::from_utf8_lossy(&stdout).lines() {
            let mut parts = line.split(' ');
            let (Some(refname), Some(object)) = (parts.next(), parts.next()) else {
                continue;
            };
            let Some(tag) = refname.strip_prefix("refs/import-tags/") else {
                continue;
            };
            let peeled = parts.next().filter(|p| !p.is_empty());
            let annotated = parts.next() == Some("tag");
            let commit = peeled.unwrap_or(object).to_owned();
            // An annotated tag is its own object, with a message worth
            // keeping; a lightweight one is just a name for the commit.
            let message = if annotated {
                String::from_utf8_lossy(&self.run(Some(&path), &["cat-file", "tag", object]).await?)
                    .split_once("\n\n")
                    .map(|(_, body)| body.trim().to_owned())
                    .filter(|body| !body.is_empty())
            } else {
                None
            };
            tags.push((tag.to_owned(), object.to_owned(), commit, message));
        }
        Ok(tags)
    }

    /// Drop a tag's holding ref, whether it was taken in or not.
    pub async fn clear_holding_tag(&self, name: &str, tag: &str) -> GitResult<()> {
        let path = self.existing_repo_path(name)?;
        self.run(
            Some(&path),
            &["update-ref", "-d", &format!("refs/import-tags/{tag}")],
        )
        .await?;
        Ok(())
    }

    /// Whether a branch exists.
    pub async fn branch_exists(&self, name: &str, branch: &str) -> GitResult<bool> {
        let wanted = format!("refs/heads/{branch}");
        Ok(self
            .list_refs(name, &wanted)
            .await?
            .iter()
            .any(|(refname, _)| *refname == wanted))
    }

    /// Whether the repository has any ref at all.
    pub async fn has_refs(&self, name: &str) -> GitResult<bool> {
        Ok(!self.list_refs(name, "refs/").await?.is_empty())
    }

    /// Drop an import's holding ref once the branch carries it.
    pub async fn clear_import_ref(&self, name: &str, branch: &str) -> GitResult<()> {
        let path = self.existing_repo_path(name)?;
        self.run(
            Some(&path),
            &["update-ref", "-d", &format!("refs/import/{branch}")],
        )
        .await?;
        Ok(())
    }

    /// Fast-forward a branch, compare-and-swap against the expected old
    /// tip (zero-oid when creating the branch).
    pub async fn advance_ref(
        &self,
        name: &str,
        branch: &str,
        to_oid: &str,
        expected_old: Option<&str>,
    ) -> GitResult<()> {
        let path = self.existing_repo_path(name)?;
        // The zero-oid must match the repo's hash width (40 for SHA-1,
        // 64 for SHA-256); the new oid is already the right size.
        let zero = "0".repeat(to_oid.len());
        let old = expected_old.unwrap_or(&zero);
        self.run(
            Some(&path),
            &["update-ref", &format!("refs/heads/{branch}"), to_oid, old],
        )
        .await?;
        Ok(())
    }
}

/// Every file under `dir`, added up. Symlinks are counted as the links
/// they are and never followed, so a link into somebody else's tree
/// cannot make a repository look enormous or walk out of its own
/// directory.
fn directory_size(dir: &Path) -> GitResult<u64> {
    let mut total = 0u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(path) = pending.pop() {
        // A directory that vanished under us is not a failure of the
        // measurement: git removes its own temporary directories while
        // this walks, and losing the whole answer to that would freeze
        // the number at whatever it was last time.
        let Ok(entries) = std::fs::read_dir(&path) else {
            continue;
        };
        for entry in entries {
            let Ok(entry) = entry else { continue };
            let Ok(meta) = entry.metadata() else { continue };
            total = total.saturating_add(occupied(&meta));
            if meta.is_dir() {
                pending.push(entry.path());
            }
        }
    }
    Ok(total)
}

/// What a file takes up, rather than what it says it is.
///
/// A git object is tens of bytes of content in a whole filesystem block,
/// so on a repository of loose objects the apparent size understates the
/// disk by two orders of magnitude — and a disk quota that trusts it is
/// counting the wrong thing. Directories take room too.
#[cfg(unix)]
fn occupied(meta: &std::fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    // Whichever is larger. Allocated blocks count the granularity a
    // small file is stored at; the length counts what a filesystem
    // has not yet said it allocated — ZFS reports a file just written
    // as nearly empty until its transaction group syncs, which is
    // exactly when a push is measured — and what compression hid,
    // which is the pusher's bytes all the same.
    meta.blocks().saturating_mul(512).max(meta.len())
}

#[cfg(not(unix))]
fn occupied(meta: &std::fs::Metadata) -> u64 {
    if meta.is_dir() { 0 } else { meta.len() }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The git this test suite is running against must itself satisfy
    /// the floor, or every merge test here is proving something about a
    /// git nobody will deploy on.
    #[test]
    fn preflight_accepts_the_git_we_test_with() {
        let found = preflight().expect("the test environment needs a supported git");
        assert!(found.contains("git version"), "unexpected output: {found}");
    }

    /// A quarantine a killed push left behind is removed once it is
    /// older than any transfer can be; one a push is writing to now is
    /// left alone.
    #[test]
    fn dead_quarantines_are_swept_and_live_ones_kept() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(sweep_scenario());
    }

    async fn sweep_scenario() {
        let tmp = tempfile::tempdir().unwrap();
        let store = GitStore::new(tmp.path().join("repos"), "/nonexistent/ambolt");
        store.create_repo("ada/demo", "main", "sha1").await.unwrap();
        let objects = tmp.path().join("repos/ada/demo.git/objects");
        let dead = objects.join("tmp_objdir-incoming-dead");
        let live = objects.join("tmp_objdir-incoming-live");
        std::fs::create_dir_all(&dead).unwrap();
        std::fs::create_dir_all(&live).unwrap();
        std::fs::write(dead.join("pack"), b"x").unwrap();
        let long_ago =
            std::time::SystemTime::now() - QUARANTINE_DEAD_AFTER - Duration::from_secs(60);
        std::fs::File::open(&dead)
            .unwrap()
            .set_modified(long_ago)
            .unwrap();
        assert_eq!(store.sweep_quarantines("ada/demo").await.unwrap(), 1);
        assert!(!dead.exists(), "the dead one is gone");
        assert!(live.exists(), "the live one is not touched");
        assert_eq!(store.sweep_quarantines("ada/demo").await.unwrap(), 0);
    }

    /// Bytes no filesystem can compress away: the measurement is what
    /// the disk holds, and a filesystem that compresses (ZFS, where
    /// the forge runs) would hold a run of one letter in nothing.
    fn incompressible(len: usize) -> Vec<u8> {
        let mut state = 0x9E37_79B9_7F4A_7C15_u64;
        (0..len)
            .map(|_| {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                state as u8
            })
            .collect()
    }

    /// The measurement counts every file under the directory, however
    /// deep, and nothing a symlink points at: a link planted into
    /// somebody else's tree neither inflates the number nor walks out.
    #[test]
    fn directory_size_counts_what_is_inside_and_follows_no_link() {
        let tmp = tempfile::tempdir().unwrap();
        let inside = tmp.path().join("repo");
        std::fs::create_dir_all(inside.join("objects/ab")).unwrap();
        std::fs::write(inside.join("HEAD"), incompressible(10_000)).unwrap();
        std::fs::write(inside.join("objects/ab/cdef"), incompressible(20_000)).unwrap();
        let outside = tmp.path().join("elsewhere");
        std::fs::write(&outside, incompressible(4_000_000)).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, inside.join("objects/link")).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(tmp.path(), inside.join("objects/up")).unwrap();
        let measured = directory_size(&inside).unwrap();
        assert!(measured >= 30_000, "every file is counted: {measured}");
        assert!(measured < 4_000_000, "the link's target is not: {measured}");
        assert_eq!(directory_size(&tmp.path().join("nowhere")).unwrap(), 0);
    }

    #[test]
    fn ls_tree_records_parse_with_awkward_paths() {
        // What `ls-tree -z` actually emits: NUL-separated, tab before a
        // raw path that may contain spaces.
        let raw = "100644 blob abc123\ta file.txt\u{0}040000 tree def456\tsub dir\u{0}";
        let entries: Vec<(String, String)> = raw
            .split('\0')
            .filter(|record| !record.is_empty())
            .filter_map(|record| {
                let (meta, path) = record.split_once('\t')?;
                Some((meta.split_whitespace().nth(1)?.to_owned(), path.to_owned()))
            })
            .collect();
        assert_eq!(
            entries,
            vec![
                ("blob".to_owned(), "a file.txt".to_owned()),
                ("tree".to_owned(), "sub dir".to_owned()),
            ]
        );
    }
}
