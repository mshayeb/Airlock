//! Airlock Secretless Capability Broker core policy & inspection primitives.

pub mod git_pkt;
pub mod http_policy;
pub mod ssrf;

use std::fmt;
use std::net::IpAddr;

/// Errors raised during broker policy, SSRF, or Git packet enforcement.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BrokerError {
    SsrfBlocked(IpAddr),
    MalformedGitPktLine(&'static str),
    PolicyRefDenied(String),
    ForcePushDenied(String),
    PassthroughWithCredentialForbidden(String),
    PolicyHostOrActionDenied {
        method: String,
        host: String,
        path: String,
    },
}

impl fmt::Display for BrokerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::SsrfBlocked(ip) => {
                write!(f, "SSRF_BLOCKED: resolved address {ip} is non-public")
            }
            Self::MalformedGitPktLine(msg) => write!(f, "MALFORMED_GIT_PKT: {msg}"),
            Self::PolicyRefDenied(r) => write!(f, "POLICY_REF_DENIED: {r}"),
            Self::ForcePushDenied(r) => write!(f, "FORCE_PUSH_DENIED: {r}"),
            Self::PassthroughWithCredentialForbidden(id) => write!(
                f,
                "D3_POLICY_CONFLICT: capability `{id}` cannot combine sni_passthrough with secret injection"
            ),
            Self::PolicyHostOrActionDenied { method, host, path } => write!(
                f,
                "POLICY_EGRESS_DENIED: {method} https://{host}{path} matched no active capability"
            ),
        }
    }
}

impl std::error::Error for BrokerError {}
