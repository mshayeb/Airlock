//! Atomic CoW Commit Gate: structural validation, protected paths, secret scan,
//! 3-way conflict check, and write-ahead undo journal (`FR-CMT`, `AT-7`, `AT-8`).

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

use airlock_policy::crypto::sha256;

/// Proposed filesystem mutation extracted from guest `CoW Upper`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiffAction {
    WriteFile(Vec<u8>),
    Delete,
    Symlink(PathBuf),
}

/// Single entry in a Chamber changeset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiffEntry {
    pub rel_path: String,
    pub action: DiffAction,
    pub mode: u32,
}

/// Inspection output produced by the Commit Gate before host write.
#[derive(Debug, Clone, Default)]
pub struct CommitGateReport {
    pub hard_blocks: Vec<String>,
    pub protected_paths: Vec<String>,
    pub secret_findings: Vec<(String, &'static str)>,
    pub conflict_paths: Vec<String>,
}

impl CommitGateReport {
    pub fn has_hard_blocks(&self) -> bool {
        !self.hard_blocks.is_empty()
    }

    pub fn requires_review(&self) -> bool {
        !self.protected_paths.is_empty()
            || !self.secret_findings.is_empty()
            || !self.conflict_paths.is_empty()
    }
}

/// Evaluates candidate diff entries against structural, protected-path, secret,
/// and baseline host-conflict checks (`FR-CMT-2`..`FR-CMT-5`).
pub fn inspect_diff(
    host_repo: &Path,
    baseline_digests: &BTreeMap<String, [u8; 32]>,
    entries: &[DiffEntry],
) -> CommitGateReport {
    let mut report = CommitGateReport::default();

    for entry in entries {
        if let Err(reason) = validate_relative_path(&entry.rel_path) {
            report
                .hard_blocks
                .push(format!("{}: {reason}", entry.rel_path));
            continue;
        }

        if (entry.mode & 0o6000) != 0 {
            report.hard_blocks.push(format!(
                "{}: setuid/setgid bits (mode {:o}) forbidden",
                entry.rel_path, entry.mode
            ));
            continue;
        }

        match &entry.action {
            DiffAction::Symlink(target) => {
                if !symlink_stays_inside_repo(&entry.rel_path, target) {
                    report.hard_blocks.push(format!(
                        "{}: symlink target `{}` escapes workspace root",
                        entry.rel_path,
                        target.display()
                    ));
                    continue;
                }
            }
            DiffAction::WriteFile(bytes) => {
                if let Ok(text) = std::str::from_utf8(bytes) {
                    if let Some(kind) = detect_secret_in_text(text) {
                        report.secret_findings.push((entry.rel_path.clone(), kind));
                    }
                }
            }
            DiffAction::Delete => {}
        }

        if is_protected_path(&entry.rel_path) {
            report.protected_paths.push(entry.rel_path.clone());
        }

        // 3-way conflict check (`FR-CMT-5`).
        let host_path = host_repo.join(&entry.rel_path);
        match (baseline_digests.get(&entry.rel_path), fs::read(&host_path)) {
            (Some(base_hash), Ok(cur_bytes)) => {
                if sha256(&cur_bytes) != *base_hash {
                    report.conflict_paths.push(entry.rel_path.clone());
                }
            }
            (Some(_), Err(_)) => {
                report.conflict_paths.push(entry.rel_path.clone());
            }
            (None, Ok(_)) => {
                report.conflict_paths.push(entry.rel_path.clone());
            }
            (None, Err(_)) => {}
        }
    }

    report
}

fn validate_relative_path(rel_path: &str) -> Result<(), &'static str> {
    if rel_path.is_empty() || rel_path.starts_with('/') || rel_path.starts_with('\\') {
        return Err("path must be relative");
    }
    let path = Path::new(rel_path);
    for comp in path.components() {
        match comp {
            Component::Normal(_) => {}
            _ => return Err("unsafe path traversal or root component"),
        }
    }
    Ok(())
}

fn symlink_stays_inside_repo(rel_link: &str, target: &Path) -> bool {
    if target.is_absolute() {
        return false;
    }
    let mut depth = Path::new(rel_link)
        .parent()
        .map(|p| p.components().count() as isize)
        .unwrap_or(0);
    for comp in target.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                depth -= 1;
                if depth < 0 {
                    return false;
                }
            }
            Component::Normal(_) => depth += 1,
            Component::RootDir | Component::Prefix(_) => return false,
        }
    }
    true
}

fn is_protected_path(rel_path: &str) -> bool {
    let norm = rel_path.replace('\\', "/");
    norm == ".git"
        || norm.starts_with(".git/")
        || norm.starts_with(".github/workflows/")
        || norm == ".gitlab-ci.yml"
        || norm == ".airlock"
        || norm.starts_with(".airlock/")
        || norm == "airlock.toml"
        || norm == "Dockerfile"
        || norm == "Makefile"
}

fn detect_secret_in_text(text: &str) -> Option<&'static str> {
    for line in text.lines() {
        if line.contains("-----BEGIN ") && line.contains("PRIVATE KEY") {
            return Some("private_key_pem");
        }
        if line.contains("AKIA") && line.split(|c: char| !c.is_ascii_alphanumeric()).any(|w| w.starts_with("AKIA") && w.len() >= 16) {
            return Some("aws_access_key_id");
        }
        if line.contains("ghp_") || line.contains("github_pat_") {
            return Some("github_token");
        }
        if line.split(|c: char| c.is_whitespace() || c == '"' || c == '\'')
            .any(|tok| (tok.starts_with("sk-") || tok.starts_with("sk_live_")) && tok.len() >= 20)
        {
            return Some("api_secret_key");
        }
        for tok in line.split(|c: char| c.is_whitespace() || c == '"' || c == '\'' || c == '=') {
            if tok.len() >= 28 && !tok.contains('/') && shannon_entropy(tok) >= 4.2 {
                return Some("high_entropy_secret");
            }
        }
    }
    None
}

fn shannon_entropy(s: &str) -> f64 {
    let mut counts = [0u32; 256];
    let bytes = s.as_bytes();
    for &b in bytes {
        counts[b as usize] += 1;
    }
    let len = bytes.len() as f64;
    let mut entropy = 0.0f64;
    for &c in &counts {
        if c > 0 {
            let p = (c as f64) / len;
            entropy -= p * p.log2();
        }
    }
    entropy
}

/// Applies validated changesets atomically to the host repository with a
/// write-ahead backup journal supporting `airlock undo` (`FR-CMT-7`, `AT-8`).
pub struct JournaledCommitter {
    undo_root: PathBuf,
}

impl JournaledCommitter {
    pub fn new(undo_root: PathBuf) -> Self {
        Self { undo_root }
    }

    pub fn apply_atomic(
        &self,
        host_repo: &Path,
        session_id: &str,
        entries: &[DiffEntry],
    ) -> io::Result<PathBuf> {
        let session_dir = self.undo_root.join(session_id);
        let originals_dir = session_dir.join("originals");
        fs::create_dir_all(&originals_dir)?;

        let mut manifest = String::new();
        for entry in entries {
            validate_relative_path(&entry.rel_path)
                .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
            let host_target = host_repo.join(&entry.rel_path);
            if host_target.exists() {
                let backup = originals_dir.join(&entry.rel_path);
                if let Some(parent) = backup.parent() {
                    fs::create_dir_all(parent)?;
                }
                fs::copy(&host_target, &backup)?;
                manifest.push_str(&format!("EX {}\n", entry.rel_path));
            } else {
                manifest.push_str(&format!("NEW {}\n", entry.rel_path));
            }
        }

        let manifest_path = session_dir.join("manifest.txt");
        fs::write(&manifest_path, manifest.as_bytes())?;

        // Stage and atomically rename each entry into place.
        for (idx, entry) in entries.iter().enumerate() {
            let host_target = host_repo.join(&entry.rel_path);
            match &entry.action {
                DiffAction::WriteFile(bytes) => {
                    let parent = host_target
                        .parent()
                        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
                    fs::create_dir_all(parent)?;
                    let tmp_path = parent.join(format!(".airlock-tmp-{}-{idx}", std::process::id()));
                    {
                        let mut file = fs::File::create(&tmp_path)?;
                        file.write_all(bytes)?;
                        file.sync_all()?;
                    }
                    fs::rename(&tmp_path, &host_target)?;
                }
                DiffAction::Delete => {
                    if host_target.exists() {
                        fs::remove_file(&host_target)?;
                    }
                }
                DiffAction::Symlink(target) => {
                    if host_target.exists() {
                        fs::remove_file(&host_target)?;
                    }
                    #[cfg(unix)]
                    std::os::unix::fs::symlink(target, &host_target)?;
                }
            }
        }

        Ok(session_dir)
    }

    pub fn undo(&self, host_repo: &Path, session_id: &str) -> io::Result<()> {
        let session_dir = self.undo_root.join(session_id);
        let originals_dir = session_dir.join("originals");
        let manifest = fs::read_to_string(session_dir.join("manifest.txt"))?;

        for line in manifest.lines() {
            if let Some(rel) = line.strip_prefix("EX ") {
                let backup = originals_dir.join(rel);
                let host_target = host_repo.join(rel);
                let parent = host_target
                    .parent()
                    .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no parent"))?;
                fs::create_dir_all(parent)?;
                let tmp = parent.join(format!(".airlock-undo-{}", std::process::id()));
                fs::copy(&backup, &tmp)?;
                fs::File::open(&tmp)?.sync_all()?;
                fs::rename(&tmp, &host_target)?;
            } else if let Some(rel) = line.strip_prefix("NEW ") {
                let host_target = host_repo.join(rel);
                if host_target.exists() {
                    fs::remove_file(&host_target)?;
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn blocks_symlink_escapes_hooks_secrets_and_conflicts() {
        let base = std::env::temp_dir().join(format!("airlock-cg-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(base.join("src")).unwrap();
        fs::write(base.join("src/lib.rs"), b"v1").unwrap();

        let mut baseline = BTreeMap::new();
        baseline.insert("src/lib.rs".to_owned(), sha256(b"v1"));

        // External host edit creates 3-way conflict (`AT-8`).
        fs::write(base.join("src/lib.rs"), b"v2-host").unwrap();

        let entries = vec![
            DiffEntry {
                rel_path: "escape.txt".to_owned(),
                action: DiffAction::Symlink(PathBuf::from("../../.ssh/authorized_keys")),
                mode: 0o120777,
            },
            DiffEntry {
                rel_path: ".git/hooks/post-checkout".to_owned(),
                action: DiffAction::WriteFile(b"#!/bin/sh\necho pwn\n".to_vec()),
                mode: 0o100755,
            },
            DiffEntry {
                rel_path: "leaked.txt".to_owned(),
                action: DiffAction::WriteFile(b"key = \"sk-live-secret-abcdef1234567890\"".to_vec()),
                mode: 0o100644,
            },
            DiffEntry {
                rel_path: "src/lib.rs".to_owned(),
                action: DiffAction::WriteFile(b"v2-guest".to_vec()),
                mode: 0o100644,
            },
        ];

        let report = inspect_diff(&base, &baseline, &entries);
        assert!(report.has_hard_blocks());
        assert_eq!(report.protected_paths, vec![".git/hooks/post-checkout"]);
        assert_eq!(report.secret_findings.len(), 1);
        assert_eq!(report.conflict_paths, vec!["src/lib.rs"]);

        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn atomic_commit_and_undo_restores_exact_bytes() {
        let base = std::env::temp_dir().join(format!("airlock-undo-test-{}", std::process::id()));
        let repo = base.join("repo");
        let undo_root = base.join("undo");
        let _ = fs::remove_dir_all(&base);
        fs::create_dir_all(repo.join("src")).unwrap();
        fs::write(repo.join("src/main.rs"), b"original-bytes").unwrap();

        let committer = JournaledCommitter::new(undo_root);
        let entries = vec![
            DiffEntry {
                rel_path: "src/main.rs".to_owned(),
                action: DiffAction::WriteFile(b"modified-bytes".to_vec()),
                mode: 0o100644,
            },
            DiffEntry {
                rel_path: "src/new_file.rs".to_owned(),
                action: DiffAction::WriteFile(b"created".to_vec()),
                mode: 0o100644,
            },
        ];

        committer.apply_atomic(&repo, "sess_01", &entries).unwrap();
        assert_eq!(fs::read(repo.join("src/main.rs")).unwrap(), b"modified-bytes");
        assert!(repo.join("src/new_file.rs").exists());

        committer.undo(&repo, "sess_01").unwrap();
        assert_eq!(fs::read(repo.join("src/main.rs")).unwrap(), b"original-bytes");
        assert!(!repo.join("src/new_file.rs").exists());

        let _ = fs::remove_dir_all(&base);
    }
}
