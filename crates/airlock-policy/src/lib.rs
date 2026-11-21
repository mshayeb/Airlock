//! Policy manifest, secret-scrubbing rules, and CID-bound phantom tokens.

pub mod crypto;
pub mod manifest;

use std::fmt;

use crypto::{ct_eq, hex_decode, hex_encode, hmac_sha256};

pub use manifest::{AirlockManifest, CapabilityConfig};

/// Prefix identifying an Airlock session-bound phantom capability token.
pub const PHANTOM_PREFIX: &str = "airlock-phantom:cap_";

/// Errors produced by policy parsing and phantom capability validation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PolicyError {
    CapabilityReplayDetected(&'static str),
    FuturePhaseRequired(&'static str),
    InvalidManifest(String),
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityReplayDetected(msg) => {
                write!(f, "CAPABILITY_REPLAY_DETECTED: {msg}")
            }
            Self::FuturePhaseRequired(msg) => write!(f, "FUTURE_PHASE_REQUIRED: {msg}"),
            Self::InvalidManifest(msg) => write!(f, "INVALID_MANIFEST: {msg}"),
        }
    }
}

impl std::error::Error for PolicyError {}

/// Minting and verification for session-bound phantom tokens (`FR-BRK-1`, `SEC-4`).
pub struct PhantomToken;

impl PhantomToken {
    /// Mints `airlock-phantom:cap_<capability_id>_<hex_hmac>` bound to `(chamber_id, vsock_cid)`.
    pub fn mint(
        master_key: &[u8; 32],
        chamber_id: &str,
        vsock_cid: u32,
        capability_id: &str,
    ) -> String {
        let msg = format!("{chamber_id}\0{vsock_cid}\0{capability_id}");
        let mac = hmac_sha256(master_key, msg.as_bytes());
        format!("{PHANTOM_PREFIX}{capability_id}_{}", hex_encode(&mac))
    }

    /// Verifies that `token` matches `(expected_chamber_id, actual_vsock_cid)` and returns `capability_id`.
    pub fn verify(
        token: &str,
        master_key: &[u8; 32],
        expected_chamber_id: &str,
        actual_vsock_cid: u32,
    ) -> Result<String, PolicyError> {
        let rest = token
            .strip_prefix(PHANTOM_PREFIX)
            .ok_or(PolicyError::CapabilityReplayDetected("missing phantom prefix"))?;
        let (cap_id, hex_mac) = rest
            .rsplit_once('_')
            .ok_or(PolicyError::CapabilityReplayDetected("malformed phantom token"))?;
        if cap_id.is_empty() || hex_mac.len() != 64 {
            return Err(PolicyError::CapabilityReplayDetected("invalid token structure"));
        }
        let provided_mac = hex_decode(hex_mac)
            .ok_or(PolicyError::CapabilityReplayDetected("invalid token MAC hex"))?;
        let msg = format!("{expected_chamber_id}\0{actual_vsock_cid}\0{cap_id}");
        let expected_mac = hmac_sha256(master_key, msg.as_bytes());

        if !ct_eq(&provided_mac, &expected_mac) {
            return Err(PolicyError::CapabilityReplayDetected(
                "token does not match originating chamber_id and vsock_cid",
            ));
        }
        Ok(cap_id.to_owned())
    }
}

/// Evaluates whether a workspace-relative path must be scrubbed before VM boot (`FR-FS-2`).
pub fn is_scrubbed_secret_path(rel_path: &str) -> bool {
    let norm = rel_path.replace('\\', "/");
    let norm = norm.trim_start_matches("./").trim_start_matches('/');
    if norm.is_empty() {
        return false;
    }

    if norm == ".git/credentials"
        || norm.ends_with("/.git/credentials")
        || norm == ".aws/credentials"
        || norm.ends_with("/.aws/credentials")
    {
        return true;
    }

    let file_name = norm.rsplit('/').next().unwrap_or(norm);

    if file_name == ".env" {
        return true;
    }
    if file_name.starts_with(".env.") {
        return file_name != ".env.example" && file_name != ".env.template";
    }
    if matches!(
        file_name,
        ".npmrc" | ".pypirc" | ".netrc"
    ) {
        return true;
    }
    if file_name.starts_with("id_rsa")
        || file_name.starts_with("id_ed25519")
        || file_name.starts_with("id_ecdsa")
    {
        return true;
    }

    let lower = file_name.to_ascii_lowercase();
    [".pem", ".key", ".p12", ".pfx"]
        .iter()
        .any(|ext| lower.ends_with(ext))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn phantom_token_binds_to_chamber_and_cid() {
        let key = [0x42u8; 32];
        let tok = PhantomToken::mint(&key, "chmb_01", 7, "github_agent_pr");
        assert!(tok.starts_with("airlock-phantom:cap_github_agent_pr_"));

        let verified = PhantomToken::verify(&tok, &key, "chmb_01", 7).expect("same CID passes");
        assert_eq!(verified, "github_agent_pr");

        // Replay from a different chamber CID must fail (`AT-4`).
        assert_eq!(
            PhantomToken::verify(&tok, &key, "chmb_01", 8),
            Err(PolicyError::CapabilityReplayDetected(
                "token does not match originating chamber_id and vsock_cid"
            ))
        );
        // Replay under a different chamber ID must fail.
        assert!(matches!(
            PhantomToken::verify(&tok, &key, "chmb_02", 7),
            Err(PolicyError::CapabilityReplayDetected(_))
        ));
    }

    #[test]
    fn secret_path_scrubber_preserves_examples_and_drops_keys() {
        assert!(is_scrubbed_secret_path(".env"));
        assert!(is_scrubbed_secret_path("services/api/.env.production"));
        assert!(!is_scrubbed_secret_path(".env.example"));
        assert!(!is_scrubbed_secret_path("apps/web/.env.template"));
        assert!(is_scrubbed_secret_path("certs/dev.pem"));
        assert!(is_scrubbed_secret_path("secrets/signing.key"));
        assert!(is_scrubbed_secret_path(".git/credentials"));
        assert!(is_scrubbed_secret_path(".npmrc"));
        assert!(is_scrubbed_secret_path(".ssh/id_ed25519"));
        assert!(!is_scrubbed_secret_path("src/main.rs"));
    }

    #[test]
    fn parses_example_manifest_and_rejects_future_phase_tables() {
        let example = include_str!("../../../airlock.toml.example");
        let parsed = AirlockManifest::parse(example).expect("example manifest parses");
        assert_eq!(parsed.version, "1");
        assert_eq!(parsed.chamber.target, "local");
        assert_eq!(parsed.capabilities.len(), 3);
        assert_eq!(parsed.capabilities[0].id, "github_agent_pr");
        assert_eq!(
            parsed.capabilities[0].allowed_branches,
            vec!["refs/heads/agent/*"]
        );
        assert!(!parsed.capabilities[0].allow_force_push);

        let phase2 = "version = \"1\"\n[mcp]\nservers = [\"fs\"]\n";
        assert!(matches!(
            AirlockManifest::parse(phase2),
            Err(PolicyError::FuturePhaseRequired(_))
        ));

        let phase3 = "version = \"1\"\n[ifc]\nstrict = true\n";
        assert!(matches!(
            AirlockManifest::parse(phase3),
            Err(PolicyError::FuturePhaseRequired(_))
        ));
    }
}
