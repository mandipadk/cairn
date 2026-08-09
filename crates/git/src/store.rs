//! Bare-repo storage and the glue to real git.
//!
//! The wire protocol is served by spawning `git upload-pack` /
//! `git receive-pack` — deliberately boring, because protocol
//! compatibility is exactly where cleverness goes to die. Push-to-create
//! rides git's own `proc-receive` mechanism (git 2.29+): repos are
//! configured so pushes to `refs/for/*` are handed to a hook, which
//! records the revision in the graph and reports a
//! `refs/changes/<number>/<revision>` name back to the pusher. The ref
//! itself is created afterwards by server-side reconciliation — hooks
//! cannot update refs while pushed objects are still in quarantine.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use thiserror::Error;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;

#[derive(Debug, Error)]
pub enum GitError {
    #[error("invalid repo name {0:?}")]
    InvalidRepoName(String),

    #[error("repo {0} not found on disk")]
    RepoMissing(String),

    #[error("git {args}: {stderr}")]
    CommandFailed { args: String, stderr: String },

    #[error(transparent)]
    Io(#[from] std::io::Error),
}

pub type GitResult<T> = Result<T, GitError>;

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
        let output = command.args(args).stdin(Stdio::null()).output().await?;
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
            .stderr(Stdio::piped());
        if let Some(version) = git_protocol {
            command.env("GIT_PROTOCOL", version);
        }
        let output = command.output().await?;
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
        let mut child = command.spawn()?;
        let mut stdin = child.stdin.take().expect("stdin piped");
        // Feed the request concurrently with reading the response so a
        // large exchange in either direction cannot deadlock the pipes.
        tokio::spawn(async move {
            let _ = stdin.write_all(&input).await;
            let _ = stdin.shutdown().await;
        });
        let output = child.wait_with_output().await?;
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
