//! Guest chamber bootstrap configuration (`FR-FS-5`, `FR-NET-3`, `FR-BRK-4`, `FR-BRK-7`).

use std::collections::BTreeMap;

/// Default local guest HTTP/CONNECT proxy address forwarded over `AF_VSOCK`.
pub const GUEST_PROXY_ADDR: &str = "http://127.0.0.1:3128";

/// Default guest fallback `tun0` CIDR capturing non-proxy-aware TCP/DNS packets.
pub const GUEST_TUN_CIDR: &str = "100.64.0.2/30";

/// Default guest DNS stub endpoint routed through `airlock-broker`.
pub const GUEST_DNS_ADDR: &str = "127.0.0.53:53";

/// Default installed path for the ephemeral per-chamber Root CA inside the guest.
pub const GUEST_CA_BUNDLE_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Bootstrap plan rendered inside the Linux guest chamber prior to launching agent shells.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GuestBootstrapPlan {
    pub overlay_mount_opts: String,
    pub workspace_target: String,
    pub tun_interface: String,
    pub tun_cidr: String,
    pub dns_listen_addr: String,
    pub env_vars: BTreeMap<String, String>,
    pub gitconfig: String,
}

/// Builds the deterministic guest initialization plan for a Chamber.
pub fn build_bootstrap_plan(
    github_phantom_token: Option<&str>,
    extra_phantom_env: &[(&str, &str)],
) -> GuestBootstrapPlan {
    let mut env_vars = BTreeMap::new();
    env_vars.insert("HTTP_PROXY".to_owned(), GUEST_PROXY_ADDR.to_owned());
    env_vars.insert("HTTPS_PROXY".to_owned(), GUEST_PROXY_ADDR.to_owned());
    env_vars.insert("ALL_PROXY".to_owned(), GUEST_PROXY_ADDR.to_owned());
    env_vars.insert("http_proxy".to_owned(), GUEST_PROXY_ADDR.to_owned());
    env_vars.insert("https_proxy".to_owned(), GUEST_PROXY_ADDR.to_owned());
    env_vars.insert("NO_PROXY".to_owned(), "127.0.0.1,localhost".to_owned());
    env_vars.insert("SSL_CERT_FILE".to_owned(), GUEST_CA_BUNDLE_PATH.to_owned());
    env_vars.insert("NODE_EXTRA_CA_CERTS".to_owned(), GUEST_CA_BUNDLE_PATH.to_owned());
    env_vars.insert("REQUESTS_CA_BUNDLE".to_owned(), GUEST_CA_BUNDLE_PATH.to_owned());
    env_vars.insert("CURL_CA_BUNDLE".to_owned(), GUEST_CA_BUNDLE_PATH.to_owned());
    env_vars.insert("CARGO_HTTP_CAINFO".to_owned(), GUEST_CA_BUNDLE_PATH.to_owned());

    for &(k, v) in extra_phantom_env {
        env_vars.insert(k.to_owned(), v.to_owned());
    }

    let gitconfig = match github_phantom_token {
        Some(phantom) => format!(
            concat!(
                "[http]\n",
                "\tproxy = {proxy}\n",
                "\tsslCAInfo = {ca}\n",
                "[url \"https://x-access-token:{tok}@github.com/\"]\n",
                "\tinsteadOf = git@github.com:\n",
                "\tinsteadOf = ssh://git@github.com/\n",
                "[safe]\n",
                "\tdirectory = /workspace\n"
            ),
            proxy = GUEST_PROXY_ADDR,
            ca = GUEST_CA_BUNDLE_PATH,
            tok = phantom,
        ),
        None => format!(
            concat!(
                "[http]\n",
                "\tproxy = {proxy}\n",
                "\tsslCAInfo = {ca}\n",
                "[safe]\n",
                "\tdirectory = /workspace\n"
            ),
            proxy = GUEST_PROXY_ADDR,
            ca = GUEST_CA_BUNDLE_PATH,
        ),
    };

    GuestBootstrapPlan {
        overlay_mount_opts:
            "lowerdir=/mnt/base,upperdir=/mnt/upper/work_upper,workdir=/mnt/upper/work".to_owned(),
        workspace_target: "/workspace".to_owned(),
        tun_interface: "tun0".to_owned(),
        tun_cidr: GUEST_TUN_CIDR.to_owned(),
        dns_listen_addr: GUEST_DNS_ADDR.to_owned(),
        env_vars,
        gitconfig,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builds_overlay_proxy_ca_and_ssh_rewrite_with_phantom_token() {
        let phantom = "airlock-phantom:cap_gh_deadbeef";
        let plan = build_bootstrap_plan(Some(phantom), &[("GITHUB_TOKEN", phantom)]);

        assert_eq!(plan.tun_interface, "tun0");
        assert_eq!(plan.tun_cidr, "100.64.0.2/30");
        assert_eq!(
            plan.env_vars.get("NODE_EXTRA_CA_CERTS").map(String::as_str),
            Some(GUEST_CA_BUNDLE_PATH)
        );
        assert_eq!(
            plan.env_vars.get("GITHUB_TOKEN").map(String::as_str),
            Some(phantom)
        );
        assert!(plan.gitconfig.contains("insteadOf = git@github.com:"));
        assert!(plan.gitconfig.contains(phantom));
    }
}
