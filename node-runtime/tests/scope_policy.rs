use nodewe_runtime::{Operation, Scope};

#[test]
fn scope_rejects_parent_path() {
    let scope = Scope::new(env!("CARGO_MANIFEST_DIR")).unwrap();
    assert!(scope.authorize("..", Operation::Read).is_err());
}

#[test]
fn scope_allows_relative_existing_file() {
    let scope = Scope::new(env!("CARGO_MANIFEST_DIR")).unwrap();
    assert!(scope.authorize("Cargo.toml", Operation::Read).is_ok());
}

#[cfg(unix)]
#[test]
fn scope_rejects_symlink_components() {
    use std::os::unix::fs::symlink;
    let root = tempfile_dir("nodewe-scope-symlink");
    let target = root.parent().unwrap().join("nodewe-scope-target");
    std::fs::create_dir_all(&target).unwrap();
    std::fs::write(target.join("secret"), "secret").unwrap();
    symlink(&target, root.join("link")).unwrap();
    let scope = Scope::new(&root).unwrap();
    assert!(scope.authorize("link/secret", Operation::Read).is_err());
    let _ = std::fs::remove_dir_all(&root);
    let _ = std::fs::remove_dir_all(&target);
}

fn tempfile_dir(prefix: &str) -> std::path::PathBuf {
    let path = std::env::temp_dir().join(format!("{prefix}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    path
}
