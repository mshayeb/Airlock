//! L7 HTTP capability evaluator, query-param sanitizer, and response scrubber (`FR-BRK`, `D-3`).

use airlock_policy::CapabilityConfig;

use crate::BrokerError;

/// Normalized outbound HTTP request summary evaluated by the broker.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpRequestMeta<'a> {
    pub method: &'a str,
    pub host: &'a str,
    pub path_and_query: &'a str,
    pub tls_terminated: bool,
}

/// Result of L7 capability matching.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct L7Decision {
    pub capability_id: String,
    pub sanitized_path: String,
    pub inject_header: Option<String>,
    pub provider: String,
}

/// Evaluates an outbound HTTP request against configured Phase 1 capabilities.
pub fn evaluate_http_request(
    req: &HttpRequestMeta<'_>,
    capabilities: &[CapabilityConfig],
) -> Result<L7Decision, BrokerError> {
    for cap in capabilities {
        if !cap.hosts.iter().any(|h| h.eq_ignore_ascii_case(req.host)) {
            continue;
        }

        // Enforce `D-3` / `FR-BRK-9`: sni_passthrough forbids credential injection.
        if cap.tls_mode == "sni_passthrough" {
            if cap.provider != "none" || cap.inject_header.is_some() {
                return Err(BrokerError::PassthroughWithCredentialForbidden(
                    cap.id.clone(),
                ));
            }
            if !req.tls_terminated {
                return Ok(L7Decision {
                    capability_id: cap.id.clone(),
                    sanitized_path: String::new(),
                    inject_header: None,
                    provider: cap.provider.clone(),
                });
            }
        }

        if !cap
            .allow_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(req.method))
        {
            continue;
        }

        let raw_path = req.path_and_query;
        let path_only = raw_path.split('?').next().unwrap_or(raw_path);

        if !cap.allow_paths.is_empty()
            && !cap
                .allow_paths
                .iter()
                .any(|pat| match_path_glob(path_only, pat))
        {
            continue;
        }

        let sanitized_path = if cap.strip_query_params {
            path_only.to_owned()
        } else {
            raw_path.to_owned()
        };

        return Ok(L7Decision {
            capability_id: cap.id.clone(),
            sanitized_path,
            inject_header: cap.inject_header.clone(),
            provider: cap.provider.clone(),
        });
    }

    Err(BrokerError::PolicyHostOrActionDenied {
        method: req.method.to_owned(),
        host: req.host.to_owned(),
        path: req.path_and_query.to_owned(),
    })
}

/// Scrubs any real host secrets accidentally echoed back inside upstream HTTP responses (`FR-BRK-10`).
pub fn scrub_response_secrets(body: &str, active_secrets: &[&str]) -> String {
    let mut out = body.to_owned();
    for secret in active_secrets {
        if !secret.is_empty() && out.contains(secret) {
            out = out.replace(secret, "[REDACTED:AIRLOCK_CREDENTIAL]");
        }
    }
    out
}

fn match_path_glob(path: &str, pat: &str) -> bool {
    if let Some(prefix) = pat.strip_suffix('*') {
        path.starts_with(prefix)
    } else {
        path == pat
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_registry_queries_and_forbids_passthrough_secrets() {
        let mut pkg = CapabilityConfig::default();
        pkg.id = "pkg_registries".to_owned();
        pkg.hosts = vec!["pypi.org".to_owned()];
        pkg.allow_methods = vec!["GET".to_owned(), "HEAD".to_owned()];
        pkg.strip_query_params = true;

        let dec = evaluate_http_request(
            &HttpRequestMeta {
                method: "GET",
                host: "pypi.org",
                path_and_query: "/simple/requests/?leak=secret_repo_bytes",
                tls_terminated: true,
            },
            &[pkg.clone()],
        )
        .expect("allowed registry GET");
        assert_eq!(dec.sanitized_path, "/simple/requests/");

        // POST to read-only registry must fail.
        assert!(evaluate_http_request(
            &HttpRequestMeta {
                method: "POST",
                host: "pypi.org",
                path_and_query: "/simple/requests/",
                tls_terminated: true,
            },
            &[pkg],
        )
        .is_err());

        // `D-3`: sni_passthrough + credential injection must be rejected.
        let mut bad = CapabilityConfig::default();
        bad.id = "pinned_api".to_owned();
        bad.hosts = vec!["api.example.com".to_owned()];
        bad.provider = "keychain:token".to_owned();
        bad.tls_mode = "sni_passthrough".to_owned();
        assert!(matches!(
            evaluate_http_request(
                &HttpRequestMeta {
                    method: "GET",
                    host: "api.example.com",
                    path_and_query: "/",
                    tls_terminated: false,
                },
                &[bad],
            ),
            Err(BrokerError::PassthroughWithCredentialForbidden(_))
        ));
    }

    #[test]
    fn scrubs_echoed_upstream_credentials() {
        let echoed = r#"{"headers":{"x-api-key":"sk-ant-real-secret-99"}}"#;
        let clean = scrub_response_secrets(echoed, &["sk-ant-real-secret-99"]);
        assert!(!clean.contains("sk-ant-real-secret-99"));
        assert!(clean.contains("[REDACTED:AIRLOCK_CREDENTIAL]"));
    }
}
