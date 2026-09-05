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

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

/// Plumbing commands answer in milliseconds; anything that takes a
/// minute has hung, and holding the connection open helps nobody.
const PLUMBING_TIMEOUT: Duration = Duration::from_secs(60);

/// Serving a pack legitimately takes a while on a large repository,
/// so the wire protocol gets its own, looser bound.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(600);

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
    "#!/bin/sh\nexec \"${CAIRN_HOOK_BIN:?cairn hook binary not set}\" internal-proc-receive\n";

/// Branches advance only by policy-approved merges; every other write
/// path is closed. proc-receive owns refs/for/*, and this pre-receive
/// guard refuses everything else (direct branch pushes, tags).
const PRE_RECEIVE_SCRIPT: &str = r#"#!/bin/sh
status=0
while read old new ref; do
  case "$ref" in
    refs/for/*) ;;
    *)
      echo "cairn: direct push to $ref refused; push to refs/for/<branch> - branches advance only by merge" >&2
      status=1
      ;;
  esac
done
exit $status
"#;

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
                "{found} is too old: cairn needs git {}.{} or newer. Merging uses \
                 `merge-tree --write-tree`, which does not exist before 2.38",
                MIN_GIT.0, MIN_GIT.1
            ),
        });
    }
    Ok(found)
}

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

    /// Defense in depth: the core validates repo slugs, but path
    /// construction re-checks so this layer is safe on its own.
    fn repo_path(&self, name: &str) -> GitResult<PathBuf> {
        let valid = !name.is_empty()
            && name
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-');
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
        tokio::fs::create_dir_all(&self.root).await?;
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
        self.run(
            Some(&path),
            &["config", "receive.procReceiveRefs", "refs/for"],
        )
        .await?;
        // A half-finished import must not be fetchable by anyone who can
        // read the repository.
        self.run(Some(&path), &["config", "transfer.hideRefs", "refs/import"])
            .await?;
        for (hook, script) in [
            ("proc-receive", HOOK_SCRIPT),
            ("pre-receive", PRE_RECEIVE_SCRIPT),
        ] {
            let hook_path = path.join("hooks").join(hook);
            tokio::fs::write(&hook_path, script).await?;
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
        let src = self.root.join(format!("{from}.git"));
        let dst = self.root.join(format!("{to}.git"));
        tokio::fs::rename(&src, &dst).await?;
        Ok(())
    }

    /// Remove a repository's directory. Nothing serves a repository the
    /// graph has forgotten, so a directory that lingers is harmless and
    /// one that is gone is what the graph already says.
    pub async fn remove_repo(&self, name: &str) -> GitResult<()> {
        let dir = self.root.join(format!("{name}.git"));
        if tokio::fs::try_exists(&dir).await? {
            tokio::fs::remove_dir_all(&dir).await?;
        }
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
    pub async fn serve_rpc(
        &self,
        service: Service,
        name: &str,
        input: Vec<u8>,
        env: Vec<(String, String)>,
        git_protocol: Option<&str>,
    ) -> GitResult<Vec<u8>> {
        let path = self.existing_repo_path(name)?;
        let mut command = Command::new("git");
        command
            .arg(service.subcommand())
            .arg("--stateless-rpc")
            .arg(&path)
            .envs(env)
            .env("CAIRN_HOOK_BIN", &self.hook_bin)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if let Some(version) = git_protocol {
            command.env("GIT_PROTOCOL", version);
        }
        command.kill_on_drop(true);
        let mut child = command.spawn()?;
        let mut stdin = child.stdin.take().expect("stdin piped");
        // Feed the request concurrently with reading the response so a
        // large exchange in either direction cannot deadlock the pipes.
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        });
        let output = tokio::time::timeout(TRANSFER_TIMEOUT, child.wait_with_output())
            .await
            .map_err(|_| GitError::TimedOut {
                args: format!("{} --stateless-rpc", service.subcommand()),
                seconds: TRANSFER_TIMEOUT.as_secs(),
            })??;
        if !output.status.success() {
            return Err(GitError::CommandFailed {
                args: format!("{} --stateless-rpc", service.subcommand()),
                stderr: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
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
            .env("GIT_COMMITTER_NAME", "cairn")
            .env("GIT_COMMITTER_EMAIL", "queue@cairn.invalid")
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
        let mut command = Command::new("git");
        command
            .current_dir(&path)
            .args([
                "push",
                "--porcelain",
                &target,
                &format!("refs/heads/{branch}:refs/heads/{branch}"),
            ])
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
        self.run(
            Some(&path),
            &[
                "fetch",
                "--no-tags",
                source,
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
