//! NodeWe's agent core.
//!
//! This crate deliberately contains only product domain rules and local
//! execution primitives. Transport, persistence and optional device adapters
//! belong to other crates or directories.

use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeId(String);

impl NodeId {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|b| {
                b.is_ascii_graphic()
                    && !matches!(b, b'/' | b'\\' | b'?' | b'&' | b'=' | b'#' | b'%')
            })
        {
            return Err("invalid node id");
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operation {
    Read,
    Write,
    Execute,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Scope {
    root: PathBuf,
}

impl Scope {
    pub fn new(root: impl AsRef<Path>) -> Result<Self, &'static str> {
        let root = root.as_ref();
        if !root.is_dir() {
            return Err("scope root must be an existing directory");
        }
        let root = root
            .canonicalize()
            .map_err(|_| "scope root is not accessible")?;
        Ok(Self { root })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Resolve a path without permitting traversal or symlink escape.
    pub fn resolve(&self, requested: impl AsRef<Path>) -> Result<PathBuf, &'static str> {
        let requested = requested.as_ref();
        let candidate = if requested.is_absolute() {
            requested.to_path_buf()
        } else {
            self.root.join(requested)
        };
        self.reject_symlink_components(&candidate)?;
        let resolved = if candidate.exists() {
            candidate
                .canonicalize()
                .map_err(|_| "path is not accessible")?
        } else {
            let parent = candidate
                .parent()
                .ok_or("invalid path")?
                .canonicalize()
                .map_err(|_| "parent path is not accessible")?;
            parent.join(candidate.file_name().ok_or("invalid path")?)
        };
        if resolved == self.root || resolved.starts_with(&self.root) {
            Ok(resolved)
        } else {
            Err("path is outside the scope")
        }
    }

    /// Reject symlink components before an operation opens the path. The
    /// operation layer also uses O_NOFOLLOW on Unix, covering the final path
    /// component while this check protects the parent chain.
    fn reject_symlink_components(&self, candidate: &Path) -> Result<(), &'static str> {
        let mut current = candidate.to_path_buf();
        loop {
            if let Ok(metadata) = std::fs::symlink_metadata(&current) {
                if metadata.file_type().is_symlink() {
                    return Err("symlink paths are not allowed in the scope");
                }
            }
            if current == self.root || !current.pop() {
                break;
            }
        }
        Ok(())
    }

    pub fn authorize(
        &self,
        requested: impl AsRef<Path>,
        operation: Operation,
    ) -> Result<PathBuf, &'static str> {
        let path = self.resolve(requested)?;
        if operation == Operation::Delete && path == self.root {
            return Err("deleting the scope root is not allowed");
        }
        Ok(path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TaskState {
    Pending,
    Approved,
    Running,
    Succeeded,
    Failed,
    CancelRequested,
    Cancelled,
    TimedOut,
}

impl TaskState {
    pub fn can_transition_to(&self, next: &Self) -> bool {
        use TaskState::*;
        matches!(
            (self, next),
            (Pending, Approved | CancelRequested)
                | (Approved, Running | CancelRequested)
                | (Running, Succeeded | Failed | CancelRequested | TimedOut)
                | (CancelRequested, Cancelled)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TaskRecord {
    pub id: String,
    pub node_id: NodeId,
    pub state: TaskState,
    pub command: Vec<String>,
}

impl TaskRecord {
    pub fn new(
        id: impl Into<String>,
        node_id: NodeId,
        command: Vec<String>,
    ) -> Result<Self, &'static str> {
        let id = id.into();
        if id.is_empty() || command.is_empty() || command[0].is_empty() {
            return Err("task id and command are required");
        }
        Ok(Self {
            id,
            node_id,
            state: TaskState::Pending,
            command,
        })
    }

    pub fn transition(&mut self, next: TaskState) -> Result<(), &'static str> {
        if self.state.can_transition_to(&next) {
            self.state = next;
            Ok(())
        } else {
            Err("invalid task state transition")
        }
    }
}

pub fn validate_command(command: &[String], allowlist: &[&str]) -> Result<(), &'static str> {
    let program = command.first().ok_or("command is required")?;
    if program.contains('/') || program.contains('\\') {
        return Err("command paths are not allowed; use an approved executable name");
    }
    let basename = Path::new(program)
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("invalid command")?;
    if allowlist.contains(&basename) {
        Ok(())
    } else {
        Err("command is not allowed by policy")
    }
}

/// Resolve an approved executable against fixed system directories. This keeps
/// a remote task from selecting an attacker-controlled executable with the
/// same basename through a mutable `PATH` or an arbitrary absolute path.
pub fn resolve_command(
    command: &[String],
    allowlist: &[&str],
) -> Result<Vec<String>, &'static str> {
    validate_command(command, allowlist)?;
    let program = &command[0];
    for directory in ["/usr/bin", "/bin", "/usr/local/bin", "/opt/homebrew/bin"] {
        let candidate = Path::new(directory).join(program);
        if candidate.is_file() {
            let mut resolved = command.to_vec();
            resolved[0] = candidate.to_string_lossy().into_owned();
            return Ok(resolved);
        }
    }
    Err("approved executable is not installed in a trusted system directory")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty_node_id() {
        assert!(NodeId::new("").is_err());
    }

    #[test]
    fn rejects_path_separator_in_node_id() {
        assert!(NodeId::new("node/a").is_err());
        assert!(NodeId::new("node?target=other").is_err());
    }

    #[test]
    fn task_transitions_are_one_way() {
        assert!(TaskState::Pending.can_transition_to(&TaskState::Approved));
        assert!(!TaskState::Succeeded.can_transition_to(&TaskState::Running));
    }

    #[test]
    fn allowlist_checks_program_basename() {
        assert!(validate_command(&["echo".into()], &["echo"]).is_ok());
        assert!(validate_command(&["/bin/echo".into()], &["echo"]).is_err());
        assert!(validate_command(&["rm".into()], &["echo"]).is_err());
    }

    #[test]
    fn resolves_only_from_trusted_system_directories() {
        let command = resolve_command(&["echo".into()], &["echo"]).unwrap();
        assert!(command[0].ends_with("/echo"));
    }
}
