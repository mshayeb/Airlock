//! Copy-on-Write workspace cloning and pre-mount secret scrubbing (`FR-FS`, `SEC-8`).

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use airlock_policy::crypto::sha256;
use airlock_policy::is_scrubbed_secret_path;

/// Mechanism used to create the scrubbed workspace clone.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CloneMethod {
    ApfsDirClonefile,
    ApfsPerFileClonefile,
    RecursiveCopy,
}

/// Summary produced after creating a read-only `Scrubbed Base`.
#[derive(Debug, Clone)]
pub struct ScrubReport {
    pub clone_method: CloneMethod,
    pub scrubbed_files: Vec<String>,
    pub sanitized_git_config: bool,
    pub synthesized_env: bool,
    pub baseline_digests: BTreeMap<String, [u8; 32]>,
}

#[cfg(target_os = "macos")]
mod darwin {
    use std::ffi::{c_char, c_int, CString};
    use std::io;
    use std::os::unix::ffi::OsStrExt;
    use std::path::Path;

    const CLONE_NOFOLLOW: u32 = 0x0001;

    extern "C" {
        fn clonefile(src: *const c_char, dst: *const c_char, flags: u32) -> c_int;
    }

    pub fn try_clonefile(src: &Path, dst: &Path) -> io::Result<()> {
        let c_src = CString::new(src.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interior NUL in src path"))?;
        let c_dst = CString::new(dst.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "interior NUL in dst path"))?;

        let rc = unsafe { clonefile(c_src.as_ptr(), c_dst.as_ptr(), CLONE_NOFOLLOW) };
        if rc == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    }
}

/// Clones `src` workspace to `dst` using APFS `clonefile(2)` on macOS when possible,
/// falling back cleanly to per-file `clonefile` or recursive file copy across devices/OSes.
pub fn clone_workspace_cow(src: &Path, dst: &Path) -> io::Result<CloneMethod> {
    if dst.exists() {
        fs::remove_dir_all(dst)?;
    }
    if let Some(parent) = dst.parent() {
        fs::create_dir_all(parent)?;
    }

    #[cfg(target_os = "macos")]
    {
        if darwin::try_clonefile(src, dst).is_ok() {
            return Ok(CloneMethod::ApfsDirClonefile);
        }
        let mut used_apfs_file = false;
        copy_tree_recursive(src, dst, &mut used_apfs_file)?;
        return Ok(if used_apfs_file {
            CloneMethod::ApfsPerFileClonefile
        } else {
            CloneMethod::RecursiveCopy
        });
    }

    #[cfg(not(target_os = "macos"))]
    {
        let mut unused = false;
        copy_tree_recursive(src, dst, &mut unused)?;
        Ok(CloneMethod::RecursiveCopy)
    }
}

fn copy_tree_recursive(src: &Path, dst: &Path, used_apfs: &mut bool) -> io::Result<()> {
    fs::create_dir_all(dst)?;
    for entry in fs::read_dir(src)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());

        if file_type.is_dir() {
            copy_tree_recursive(&src_path, &dst_path, used_apfs)?;
        } else if file_type.is_symlink() {
            let target = fs::read_link(&src_path)?;
            #[cfg(unix)]
            std::os::unix::fs::symlink(&target, &dst_path)?;
        } else if file_type.is_file() {
            #[cfg(target_os = "macos")]
            {
                if darwin::try_clonefile(&src_path, &dst_path).is_ok() {
                    *used_apfs = true;
                    continue;
                }
            }
            fs::copy(&src_path, &dst_path)?;
        }
    }
    Ok(())
}

/// Clones `host_repo` into `staging_base`, strips denylisted secrets, sanitizes
/// `.git/config`, optionally synthesizes a safe `.env`, and records baseline SHA-256 digests.
pub fn prepare_scrubbed_base(
    host_repo: &Path,
    staging_base: &Path,
    synthesize_env: bool,
) -> io::Result<ScrubReport> {
    let clone_method = clone_workspace_cow(host_repo, staging_base)?;
    let mut scrubbed_files = Vec::new();
    let mut sanitized_git_config = false;
    let mut baseline_digests = BTreeMap::new();

    walk_and_scrub(
        staging_base,
        staging_base,
        &mut scrubbed_files,
        &mut sanitized_git_config,
        &mut baseline_digests,
    )?;

    let mut synthesized_env = false;
    if synthesize_env && !staging_base.join(".env").exists() {
        let template = [".env.example", ".env.template"]
            .iter()
            .map(|name| staging_base.join(name))
            .find(|p| p.is_file());
        if let Some(tpl_path) = template {
            let raw = fs::read_to_string(&tpl_path)?;
            let safe = synthesize_safe_env(&raw);
            fs::write(staging_base.join(".env"), safe)?;
            synthesized_env = true;
        }
    }

    Ok(ScrubReport {
        clone_method,
        scrubbed_files,
        sanitized_git_config,
        synthesized_env,
        baseline_digests,
    })
}

fn walk_and_scrub(
    root: &Path,
    dir: &Path,
    scrubbed_files: &mut Vec<String>,
    sanitized_git_config: &mut bool,
    baseline_digests: &mut BTreeMap<String, [u8; 32]>,
) -> io::Result<()> {
    let entries: Vec<PathBuf> = fs::read_dir(dir)?
        .filter_map(|e| e.ok().map(|de| de.path()))
        .collect();

    for path in entries {
        let meta = fs::symlink_metadata(&path)?;
        let rel = path
            .strip_prefix(root)
            .unwrap_or(&path)
            .to_string_lossy()
            .replace('\\', "/");

        if meta.file_type().is_dir() {
            walk_and_scrub(
                root,
                &path,
                scrubbed_files,
                sanitized_git_config,
                baseline_digests,
            )?;
            continue;
        }

        if !meta.file_type().is_file() {
            continue;
        }

        if is_scrubbed_secret_path(&rel) {
            fs::remove_file(&path)?;
            scrubbed_files.push(rel);
            continue;
        }

        if rel == ".git/config" {
            let raw = fs::read_to_string(&path)?;
            let clean = sanitize_git_config(&raw);
            if clean != raw {
                fs::write(&path, clean.as_bytes())?;
                *sanitized_git_config = true;
            }
        }

        let bytes = fs::read(&path)?;
        baseline_digests.insert(rel, sha256(&bytes));
    }
    Ok(())
}

/// Strips embedded HTTP Basic/PAT credentials and dangerous hook/executor overrides from `.git/config`.
pub fn sanitize_git_config(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_ascii_lowercase();
        if lower.starts_with("fsmonitor")
            || lower.starts_with("sshcommand")
            || lower.starts_with("hookspath")
        {
            continue;
        }
        let cleaned = strip_url_userinfo(line);
        out.push_str(&cleaned);
        out.push('\n');
    }
    out
}

fn strip_url_userinfo(line: &str) -> String {
    let mut result = line.to_owned();
    for scheme in ["https://", "http://"] {
        let mut search_from = 0usize;
        while let Some(rel_idx) = result[search_from..].find(scheme) {
            let start = search_from + rel_idx + scheme.len();
            if let Some(at_rel) = result[start..].find('@') {
                let slash_rel = result[start..].find('/').unwrap_or(usize::MAX);
                if at_rel < slash_rel {
                    result.replace_range(start..start + at_rel + 1, "");
                    search_from = start;
                    continue;
                }
            }
            search_from = start;
        }
    }
    result
}

fn synthesize_safe_env(example: &str) -> String {
    let mut out = String::from("# Synthesized by Airlock Phase 1 from .env.example (zero raw secrets)\n");
    for line in example.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        let Some((key, val)) = trimmed.split_once('=') else {
            continue;
        };
        let key_upper = key.trim().to_ascii_uppercase();
        let looks_secret = ["KEY", "SECRET", "TOKEN", "PASS", "DSN", "DATABASE_URL", "AUTH"]
            .iter()
            .any(|kw| key_upper.contains(kw));
        if looks_secret {
            out.push_str(&format!("{}=AIRLOCK_PHANTOM_PLACEHOLDER\n", key.trim()));
        } else {
            out.push_str(&format!("{}={}\n", key.trim(), val.trim()));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scrubs_secrets_and_git_config_credentials() {
        let base = std::env::temp_dir().join(format!("airlock-cow-test-{}", std::process::id()));
        let host = base.join("host repo ");
        let stage = base.join("scrubbed");
        let _ = fs::remove_dir_all(&base);

        fs::create_dir_all(host.join(".git")).unwrap();
        fs::write(host.join(".env"), "OPENAI_API_KEY=sk-real-secret-999\n").unwrap();
        fs::write(host.join(".env.example"), "PORT=8080\nOPENAI_API_KEY=\n").unwrap();
        fs::write(
            host.join(".git/config"),
            "[remote \"origin\"]\n\turl = https://x-access-token:ghp_live_secret@github.com/org/app.git\n[core]\n\tfsmonitor = /tmp/evil.sh\n",
        )
        .unwrap();
        fs::write(host.join("README.md"), "# Airlock\n").unwrap();

        let report = prepare_scrubbed_base(&host, &stage, true).expect("scrub");
        assert!(report.scrubbed_files.contains(&".env".to_owned()));
        assert!(report.sanitized_git_config);
        assert!(report.synthesized_env);

        let guest_env = fs::read_to_string(stage.join(".env")).unwrap();
        assert!(!guest_env.contains("sk-real-secret-999"));
        assert!(guest_env.contains("PORT=8080"));
        assert!(guest_env.contains("OPENAI_API_KEY=AIRLOCK_PHANTOM_PLACEHOLDER"));

        let git_cfg = fs::read_to_string(stage.join(".git/config")).unwrap();
        assert!(!git_cfg.contains("ghp_live_secret"));
        assert!(!git_cfg.contains("fsmonitor"));
        assert!(git_cfg.contains("https://github.com/org/app.git"));

        let _ = fs::remove_dir_all(&base);
    }
}
