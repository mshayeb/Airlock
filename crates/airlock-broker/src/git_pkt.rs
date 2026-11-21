//! Git smart-HTTP `git-receive-pack` pkt-line ref-update inspector (`FR-BRK-6`, `AT-5`).

use crate::BrokerError;

/// 40-hex-char zero OID used by Git for branch creation/deletion.
pub const ZERO_OID: &str = "0000000000000000000000000000000000000000";

/// Parsed ref-update directive from a `git-receive-pack` request stream.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GitRefUpdate {
    pub old_oid: String,
    pub new_oid: String,
    pub refname: String,
    pub is_create: bool,
    pub is_delete: bool,
}

/// Parses `git-receive-pack` pkt-line command headers up to the `0000` flush packet.
pub fn parse_receive_pack_pkt_lines(mut buf: &[u8]) -> Result<Vec<GitRefUpdate>, BrokerError> {
    let mut updates = Vec::new();

    while !buf.is_empty() {
        if buf.len() < 4 {
            return Err(BrokerError::MalformedGitPktLine("truncated pkt-line header"));
        }
        let len_hex = std::str::from_utf8(&buf[..4])
            .map_err(|_| BrokerError::MalformedGitPktLine("non-UTF8 pkt-line length"))?;
        let pkt_len = usize::from_str_radix(len_hex, 16)
            .map_err(|_| BrokerError::MalformedGitPktLine("invalid hex pkt-line length"))?;

        if pkt_len == 0 {
            // Flush packet `0000` terminates ref-update header lines before PACK data.
            break;
        }
        if pkt_len < 4 || buf.len() < pkt_len {
            return Err(BrokerError::MalformedGitPktLine("invalid or truncated pkt-line body"));
        }

        let line_bytes = &buf[4..pkt_len];
        buf = &buf[pkt_len..];

        let without_caps = line_bytes.split(|&b| b == 0).next().unwrap_or(line_bytes);
        let text = std::str::from_utf8(without_caps)
            .map_err(|_| BrokerError::MalformedGitPktLine("non-UTF8 ref update"))?
            .trim_end_matches(|c| c == '\n' || c == '\r');

        let mut parts = text.split_whitespace();
        let (Some(old_oid), Some(new_oid), Some(refname), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(BrokerError::MalformedGitPktLine("expected <old> <new> <ref>"));
        };
        if !is_valid_oid(old_oid) || !is_valid_oid(new_oid) {
            return Err(BrokerError::MalformedGitPktLine("invalid object ID length/hex"));
        }

        updates.push(GitRefUpdate {
            old_oid: old_oid.to_owned(),
            new_oid: new_oid.to_owned(),
            refname: refname.to_owned(),
            is_create: old_oid == ZERO_OID,
            is_delete: new_oid == ZERO_OID,
        });
    }

    Ok(updates)
}

/// Validates ref updates against allowed branch globs and force-push policy (`FR-BRK-6`).
///
/// `fast_forward_verified` indicates whether the broker confirmed via upstream refs
/// and pack ancestry that any update (`!is_create && !is_delete`) is strictly fast-forward.
pub fn authorize_git_push(
    updates: &[GitRefUpdate],
    allowed_branches: &[&str],
    allow_force_push: bool,
    fast_forward_verified: bool,
) -> Result<(), BrokerError> {
    if updates.is_empty() {
        return Err(BrokerError::MalformedGitPktLine("no ref updates in receive-pack"));
    }

    for upd in updates {
        if !matches_branch_policy(&upd.refname, allowed_branches) {
            return Err(BrokerError::PolicyRefDenied(upd.refname.clone()));
        }
        if upd.is_delete && !allow_force_push {
            return Err(BrokerError::PolicyRefDenied(format!(
                "ref deletion denied for {}",
                upd.refname
            )));
        }
        if !upd.is_create && !upd.is_delete && !allow_force_push && !fast_forward_verified {
            return Err(BrokerError::ForcePushDenied(upd.refname.clone()));
        }
    }

    Ok(())
}

fn matches_branch_policy(refname: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pat| {
        if let Some(prefix) = pat.strip_suffix('*') {
            refname.starts_with(prefix)
        } else {
            refname == *pat
        }
    })
}

fn is_valid_oid(oid: &str) -> bool {
    (oid.len() == 40 || oid.len() == 64) && oid.bytes().all(|b| b.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkt_line(body: &str) -> Vec<u8> {
        let total = 4 + body.len();
        format!("{total:04x}{body}").into_bytes()
    }

    #[test]
    fn allows_agent_branch_and_blocks_main_and_force_push() {
        let old = "0000000000000000000000000000000000000000";
        let tip = "1111111111111111111111111111111111111111";
        let next_tip = "2222222222222222222222222222222222222222";

        let mut payload = pkt_line(&format!("{old} {tip} refs/heads/agent/fix-1\0report-status\n"));
        payload.extend_from_slice(b"0000PACK...");
        let parsed = parse_receive_pack_pkt_lines(&payload).expect("parse pkt-line");
        assert_eq!(parsed.len(), 1);
        assert!(parsed[0].is_create);
        assert!(authorize_git_push(&parsed, &["refs/heads/agent/*"], false, false).is_ok());

        // Fast-forward update on allowed branch succeeds when verified.
        let mut ff_payload = pkt_line(&format!("{tip} {next_tip} refs/heads/agent/fix-1\n"));
        ff_payload.extend_from_slice(b"0000");
        let ff_parsed = parse_receive_pack_pkt_lines(&ff_payload).expect("parse ff");
        assert!(authorize_git_push(&ff_parsed, &["refs/heads/agent/*"], false, true).is_ok());

        // Non-fast-forward (`--force`) update blocked when allow_force_push=false (`AT-5`).
        assert!(matches!(
            authorize_git_push(&ff_parsed, &["refs/heads/agent/*"], false, false),
            Err(BrokerError::ForcePushDenied(_))
        ));

        // Direct push to `refs/heads/main` blocked (`AT-5`).
        let mut main_payload = pkt_line(&format!("{tip} {next_tip} refs/heads/main\n"));
        main_payload.extend_from_slice(b"0000");
        let main_parsed = parse_receive_pack_pkt_lines(&main_payload).expect("parse main");
        assert_eq!(
            authorize_git_push(&main_parsed, &["refs/heads/agent/*"], false, true),
            Err(BrokerError::PolicyRefDenied("refs/heads/main".to_owned()))
        );
    }
}
