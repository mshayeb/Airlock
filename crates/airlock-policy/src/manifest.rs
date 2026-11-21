//! Minimal `airlock.toml` (`version = "1"`) parser with Phase 2/3 forward-compat checks.

use crate::PolicyError;

/// Parsed `airlock.toml` configuration.
#[derive(Debug, Clone, PartialEq)]
pub struct AirlockManifest {
    pub version: String,
    pub chamber: ChamberConfig,
    pub workspace: WorkspaceConfig,
    pub capabilities: Vec<CapabilityConfig>,
    pub commit_gate: CommitGateConfig,
    pub audit: AuditConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChamberConfig {
    pub target: String,
    pub profile: String,
    pub vcpus: u16,
    pub memory_mib: u32,
    pub disk_upper_mib: u32,
    pub max_pids: u32,
    pub ttl_seconds: u64,
    pub idle_ttl_seconds: u64,
}

impl Default for ChamberConfig {
    fn default() -> Self {
        Self {
            target: "local".to_owned(),
            profile: "standard".to_owned(),
            vcpus: 2,
            memory_mib: 4096,
            disk_upper_mib: 8192,
            max_pids: 512,
            ttl_seconds: 3600,
            idle_ttl_seconds: 900,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkspaceConfig {
    pub scrub_globs: Vec<String>,
    pub synthesize_env_from_example: bool,
    pub protected_paths: Vec<String>,
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            scrub_globs: vec![
                ".env".to_owned(),
                ".env.*".to_owned(),
                "!.env.example".to_owned(),
                "!.env.template".to_owned(),
            ],
            synthesize_env_from_example: true,
            protected_paths: vec![
                ".git/**".to_owned(),
                ".github/workflows/**".to_owned(),
                ".airlock/**".to_owned(),
                "airlock.toml".to_owned(),
            ],
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct CapabilityConfig {
    pub id: String,
    pub cap_type: String,
    pub provider: String,
    pub hosts: Vec<String>,
    pub allow_methods: Vec<String>,
    pub allow_paths: Vec<String>,
    pub allowed_branches: Vec<String>,
    pub allow_force_push: bool,
    pub inject_header: Option<String>,
    pub env_var: Option<String>,
    pub max_budget_usd: Option<f64>,
    pub rate_limit_rpm: Option<u32>,
    pub strip_query_params: bool,
    pub tls_mode: String,
}

impl Default for CapabilityConfig {
    fn default() -> Self {
        Self {
            id: String::new(),
            cap_type: "http".to_owned(),
            provider: "none".to_owned(),
            hosts: Vec::new(),
            allow_methods: vec!["GET".to_owned()],
            allow_paths: Vec::new(),
            allowed_branches: Vec::new(),
            allow_force_push: false,
            inject_header: None,
            env_var: None,
            max_budget_usd: None,
            rate_limit_rpm: None,
            strip_query_params: false,
            tls_mode: "terminate".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommitGateConfig {
    pub mode: String,
    pub secret_scan: String,
    pub max_diff_mib: u32,
}

impl Default for CommitGateConfig {
    fn default() -> Self {
        Self {
            mode: "interactive".to_owned(),
            secret_scan: "block".to_owned(),
            max_diff_mib: 50,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuditConfig {
    pub log_dir: String,
    pub hash_chain: bool,
    pub capture_http_bodies: bool,
    pub retention_days: u32,
}

impl Default for AuditConfig {
    fn default() -> Self {
        Self {
            log_dir: "~/.local/state/airlock/audit".to_owned(),
            hash_chain: true,
            capture_http_bodies: false,
            retention_days: 30,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Section {
    Root,
    Chamber,
    Workspace,
    Capability,
    CommitGate,
    Audit,
}

impl AirlockManifest {
    /// Parses a Phase 1 `airlock.toml` string, rejecting unsupported Phase 2/3 tables explicitly.
    pub fn parse(input: &str) -> Result<Self, PolicyError> {
        let mut version: Option<String> = None;
        let mut chamber = ChamberConfig::default();
        let mut workspace = WorkspaceConfig::default();
        let mut capabilities: Vec<CapabilityConfig> = Vec::new();
        let mut commit_gate = CommitGateConfig::default();
        let mut audit = AuditConfig::default();

        let mut section = Section::Root;
        let lines: Vec<&str> = input.lines().collect();
        let mut idx = 0usize;

        while idx < lines.len() {
            let line = strip_toml_comment(lines[idx]).trim();
            idx += 1;
            if line.is_empty() {
                continue;
            }

            if line == "[[capabilities]]" {
                capabilities.push(CapabilityConfig::default());
                section = Section::Capability;
                continue;
            }

            if line.starts_with('[') && line.ends_with(']') {
                let header = line.trim_matches(|c| c == '[' || c == ']').trim();
                if header == "mcp" || header.starts_with("mcp.") {
                    return Err(PolicyError::FuturePhaseRequired(
                        "Table [mcp] requires Airlock Phase 2; upgrade runtime or remove section",
                    ));
                }
                if header == "ifc" || header.starts_with("ifc.") {
                    return Err(PolicyError::FuturePhaseRequired(
                        "Table [ifc] requires Airlock Phase 3; upgrade runtime or remove section",
                    ));
                }
                section = match header {
                    "chamber" => Section::Chamber,
                    "workspace" => Section::Workspace,
                    "commit_gate" => Section::CommitGate,
                    "audit" => Section::Audit,
                    other => return Err(PolicyError::InvalidManifest(format!("unknown section [{other}]"))),
                };
                continue;
            }

            let Some((raw_key, raw_val)) = line.split_once('=') else {
                return Err(PolicyError::InvalidManifest(format!("expected key = value near: {line}")));
            };
            let key = raw_key.trim();
            let mut val_buf = raw_val.trim().to_owned();

            // Support multi-line `[ ... ]` arrays.
            if val_buf.starts_with('[') && !array_is_closed(&val_buf) {
                while idx < lines.len() {
                    let cont = strip_toml_comment(lines[idx]).trim();
                    idx += 1;
                    val_buf.push(' ');
                    val_buf.push_str(cont);
                    if array_is_closed(&val_buf) {
                        break;
                    }
                }
            }

            match section {
                Section::Root => {
                    if key == "version" {
                        version = Some(parse_str(&val_buf)?);
                    } else {
                        return Err(PolicyError::InvalidManifest(format!("unknown root key `{key}`")));
                    }
                }
                Section::Chamber => match key {
                    "target" => chamber.target = parse_str(&val_buf)?,
                    "profile" => chamber.profile = parse_str(&val_buf)?,
                    "vcpus" => chamber.vcpus = parse_int(&val_buf)?,
                    "memory_mib" => chamber.memory_mib = parse_int(&val_buf)?,
                    "disk_upper_mib" => chamber.disk_upper_mib = parse_int(&val_buf)?,
                    "max_pids" => chamber.max_pids = parse_int(&val_buf)?,
                    "ttl_seconds" => chamber.ttl_seconds = parse_int(&val_buf)?,
                    "idle_ttl_seconds" => chamber.idle_ttl_seconds = parse_int(&val_buf)?,
                    _ => {}
                },
                Section::Workspace => match key {
                    "scrub_globs" => workspace.scrub_globs = parse_str_array(&val_buf)?,
                    "synthesize_env_from_example" => {
                        workspace.synthesize_env_from_example = parse_bool(&val_buf)?
                    }
                    "protected_paths" => workspace.protected_paths = parse_str_array(&val_buf)?,
                    _ => {}
                },
                Section::Capability => {
                    let cap = capabilities.last_mut().expect("active capability");
                    match key {
                        "id" => cap.id = parse_str(&val_buf)?,
                        "type" => cap.cap_type = parse_str(&val_buf)?,
                        "provider" => cap.provider = parse_str(&val_buf)?,
                        "hosts" => cap.hosts = parse_str_array(&val_buf)?,
                        "allow_methods" => cap.allow_methods = parse_str_array(&val_buf)?,
                        "allow_paths" => cap.allow_paths = parse_str_array(&val_buf)?,
                        "allowed_branches" => cap.allowed_branches = parse_str_array(&val_buf)?,
                        "allow_force_push" => cap.allow_force_push = parse_bool(&val_buf)?,
                        "inject_header" => cap.inject_header = Some(parse_str(&val_buf)?),
                        "env_var" => cap.env_var = Some(parse_str(&val_buf)?),
                        "max_budget_usd" => {
                            cap.max_budget_usd = Some(val_buf.trim().parse::<f64>().map_err(|_| {
                                PolicyError::InvalidManifest(format!("invalid float for {key}"))
                            })?);
                        }
                        "rate_limit_rpm" => cap.rate_limit_rpm = Some(parse_int(&val_buf)?),
                        "strip_query_params" => cap.strip_query_params = parse_bool(&val_buf)?,
                        "tls_mode" => cap.tls_mode = parse_str(&val_buf)?,
                        _ => {}
                    }
                }
                Section::CommitGate => match key {
                    "mode" => commit_gate.mode = parse_str(&val_buf)?,
                    "secret_scan" => commit_gate.secret_scan = parse_str(&val_buf)?,
                    "max_diff_mib" => commit_gate.max_diff_mib = parse_int(&val_buf)?,
                    _ => {}
                },
                Section::Audit => match key {
                    "log_dir" => audit.log_dir = parse_str(&val_buf)?,
                    "hash_chain" => audit.hash_chain = parse_bool(&val_buf)?,
                    "capture_http_bodies" => audit.capture_http_bodies = parse_bool(&val_buf)?,
                    "retention_days" => audit.retention_days = parse_int(&val_buf)?,
                    _ => {}
                },
            }
        }

        let ver = version.ok_or_else(|| {
            PolicyError::InvalidManifest("missing required top-level `version = \"1\"`".to_owned())
        })?;
        if ver != "1" {
            return Err(PolicyError::InvalidManifest(format!(
                "unsupported manifest version `{ver}`; expected \"1\""
            )));
        }

        Ok(Self {
            version: ver,
            chamber,
            workspace,
            capabilities,
            commit_gate,
            audit,
        })
    }
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_quotes = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if ch == '#' && !in_quotes {
            return &line[..idx];
        }
    }
    line
}

fn array_is_closed(s: &str) -> bool {
    let mut in_quotes = false;
    let mut escaped = false;
    let mut depth = 0i32;
    for ch in s.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_quotes {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_quotes = !in_quotes;
            continue;
        }
        if !in_quotes {
            if ch == '[' {
                depth += 1;
            } else if ch == ']' {
                depth -= 1;
            }
        }
    }
    depth <= 0
}

fn parse_str(s: &str) -> Result<String, PolicyError> {
    let trimmed = s.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        Ok(trimmed[1..trimmed.len() - 1].to_owned())
    } else {
        Err(PolicyError::InvalidManifest(format!("expected quoted string, got `{trimmed}`")))
    }
}

fn parse_bool(s: &str) -> Result<bool, PolicyError> {
    match s.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(PolicyError::InvalidManifest(format!("expected bool, got `{other}`"))),
    }
}

fn parse_int<T: std::str::FromStr>(s: &str) -> Result<T, PolicyError> {
    s.trim()
        .parse::<T>()
        .map_err(|_| PolicyError::InvalidManifest(format!("expected integer, got `{s}`")))
}

fn parse_str_array(s: &str) -> Result<Vec<String>, PolicyError> {
    let trimmed = s.trim();
    if !(trimmed.starts_with('[') && trimmed.ends_with(']')) {
        return Err(PolicyError::InvalidManifest(format!("expected array, got `{trimmed}`")));
    }
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_quotes = false;
    let mut has_token = false;

    for ch in inner.chars() {
        match ch {
            '"' => {
                in_quotes = !in_quotes;
                has_token = true;
            }
            ',' if !in_quotes => {
                if has_token {
                    out.push(cur.trim().to_owned());
                    cur.clear();
                    has_token = false;
                }
            }
            _ if in_quotes => cur.push(ch),
            _ if ch.is_whitespace() => {}
            other => {
                cur.push(other);
                has_token = true;
            }
        }
    }
    if has_token && !cur.is_empty() {
        out.push(cur.trim().to_owned());
    }
    Ok(out)
}
