//! Tamper-evident SHA-256 hash-chained JSONL audit log (`FR-AUD`, `SEC-12`, `AT-11`).

use std::fmt;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, Write};
use std::path::Path;

use airlock_policy::crypto::{hex_encode, sha256};

const GENESIS_HASH: &str =
    "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// Structured audit event metadata (`spec.md` §8.3).
#[derive(Debug, Clone)]
pub struct AuditEventInput<'a> {
    pub timestamp: &'a str,
    pub chamber_id: &'a str,
    pub vsock_cid: u32,
    pub agent_step_id: Option<&'a str>,
    pub event_type: &'a str,
    pub capability_id: &'a str,
    pub decision: &'a str,
    pub reason_code: &'a str,
    pub detail: &'a str,
}

/// Errors returned when verifying an existing `audit.jsonl` hash chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuditVerifyError {
    Io(String),
    MalformedLine(usize),
    SequenceMismatch { line: usize, expected: u64, found: u64 },
    PrevHashMismatch { line: usize },
    EventHashMismatch { line: usize },
}

impl fmt::Display for AuditVerifyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Io(msg) => write!(f, "audit I/O error: {msg}"),
            Self::MalformedLine(line) => write!(f, "malformed audit JSONL at line {line}"),
            Self::SequenceMismatch { line, expected, found } => {
                write!(f, "sequence mismatch at line {line}: expected {expected}, found {found}")
            }
            Self::PrevHashMismatch { line } => {
                write!(f, "prev_hash linkage broken at line {line}")
            }
            Self::EventHashMismatch { line } => {
                write!(f, "event_hash tamper detected at line {line}")
            }
        }
    }
}

impl std::error::Error for AuditVerifyError {}

/// Append-only hash-chained `audit.jsonl` writer.
pub struct AuditLog {
    file: File,
    seq: u64,
    prev_hash: String,
}

impl AuditLog {
    pub fn create_or_open(path: &Path) -> io::Result<Self> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let file = OpenOptions::new().create(true).append(true).open(path)?;
        Ok(Self {
            file,
            seq: 0,
            prev_hash: GENESIS_HASH.to_owned(),
        })
    }

    /// Scrubs active credentials and appends one hash-chained JSONL record.
    pub fn append(
        &mut self,
        input: &AuditEventInput<'_>,
        active_secrets: &[&str],
    ) -> io::Result<()> {
        self.seq += 1;
        let detail_clean = scrub_secrets(input.detail, active_secrets);
        let step_json = match input.agent_step_id {
            Some(s) => format!("\"{}\"", escape_json(&scrub_secrets(s, active_secrets))),
            None => "null".to_owned(),
        };

        let body = format!(
            "\"seq\":{},\"timestamp\":\"{}\",\"prev_hash\":\"{}\",\"chamber_id\":\"{}\",\"vsock_cid\":{},\"principal_id\":\"agent:main\",\"agent_step_id\":{},\"event_type\":\"{}\",\"capability_id\":\"{}\",\"decision\":\"{}\",\"reason_code\":\"{}\",\"detail\":\"{}\"",
            self.seq,
            escape_json(input.timestamp),
            self.prev_hash,
            escape_json(input.chamber_id),
            input.vsock_cid,
            step_json,
            escape_json(input.event_type),
            escape_json(input.capability_id),
            escape_json(input.decision),
            escape_json(input.reason_code),
            escape_json(&detail_clean),
        );

        let hash_input = format!("{}\n{{{body}}}", self.prev_hash);
        let event_hash = format!("sha256:{}", hex_encode(&sha256(hash_input.as_bytes())));
        let line = format!("{{\"event_hash\":\"{event_hash}\",{body}}}\n");

        self.file.write_all(line.as_bytes())?;
        self.file.flush()?;
        self.prev_hash = event_hash;
        Ok(())
    }

    /// Verifies sequence monotonicity, `prev_hash` linkage, and `event_hash` integrity (`AT-11`).
    pub fn verify_file(path: &Path) -> Result<u64, AuditVerifyError> {
        let file = File::open(path).map_err(|e| AuditVerifyError::Io(e.to_string()))?;
        let reader = BufReader::new(file);

        let mut expected_seq = 0u64;
        let mut expected_prev = GENESIS_HASH.to_owned();

        for (idx, line_res) in reader.lines().enumerate() {
            let line_no = idx + 1;
            let line = line_res.map_err(|e| AuditVerifyError::Io(e.to_string()))?;
            if line.trim().is_empty() {
                continue;
            }
            expected_seq += 1;

            let prefix = "{\"event_hash\":\"";
            let rest = line
                .strip_prefix(prefix)
                .ok_or(AuditVerifyError::MalformedLine(line_no))?;
            let (event_hash, body_with_brace) = rest
                .split_once("\",")
                .ok_or(AuditVerifyError::MalformedLine(line_no))?;
            let body = body_with_brace
                .strip_suffix('}')
                .ok_or(AuditVerifyError::MalformedLine(line_no))?;

            let seq = extract_u64(body, "\"seq\":")
                .ok_or(AuditVerifyError::MalformedLine(line_no))?;
            if seq != expected_seq {
                return Err(AuditVerifyError::SequenceMismatch {
                    line: line_no,
                    expected: expected_seq,
                    found: seq,
                });
            }

            let prev_hash = extract_str(body, "\"prev_hash\":\"")
                .ok_or(AuditVerifyError::MalformedLine(line_no))?;
            if prev_hash != expected_prev {
                return Err(AuditVerifyError::PrevHashMismatch { line: line_no });
            }

            let computed = format!(
                "sha256:{}",
                hex_encode(&sha256(format!("{prev_hash}\n{{{body}}}").as_bytes()))
            );
            if event_hash != computed {
                return Err(AuditVerifyError::EventHashMismatch { line: line_no });
            }

            expected_prev = event_hash.to_owned();
        }

        Ok(expected_seq)
    }
}

fn scrub_secrets(input: &str, secrets: &[&str]) -> String {
    let mut out = input.to_owned();
    for secret in secrets {
        if !secret.is_empty() && out.contains(secret) {
            out = out.replace(secret, "[REDACTED:SECRET]");
        }
    }
    out
}

fn escape_json(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c => out.push(c),
        }
    }
    out
}

fn extract_u64(body: &str, key: &str) -> Option<u64> {
    let start = body.find(key)? + key.len();
    let end = body[start..].find(',').map(|i| start + i).unwrap_or(body.len());
    body[start..end].parse::<u64>().ok()
}

fn extract_str<'a>(body: &'a str, key: &str) -> Option<&'a str> {
    let start = body.find(key)? + key.len();
    let end = body[start..].find('"')? + start;
    Some(&body[start..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_tamper_and_scrubs_secrets() {
        let dir = std::env::temp_dir().join(format!("airlock-audit-test-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let log_path = dir.join("audit.jsonl");

        let mut log = AuditLog::create_or_open(&log_path).unwrap();
        let secret = "sk-real-key-1234567890";
        for i in 1..=5 {
            log.append(
                &AuditEventInput {
                    timestamp: "2026-11-20T22:30:00Z",
                    chamber_id: "chmb_test",
                    vsock_cid: 7,
                    agent_step_id: Some("step_1"),
                    event_type: "BROKER_HTTP",
                    capability_id: "llm_anthropic",
                    decision: "ALLOW",
                    reason_code: "OK",
                    detail: &format!("call {i} leaked header {secret}"),
                },
                &[secret],
            )
            .unwrap();
        }
        drop(log);

        let contents = fs::read_to_string(&log_path).unwrap();
        assert!(!contents.contains(secret));
        assert_eq!(AuditLog::verify_file(&log_path).unwrap(), 5);

        // Tamper line 3 (`AT-11`).
        let mut lines: Vec<String> = contents.lines().map(str::to_owned).collect();
        lines[2] = lines[2].replace("ALLOW", "DENY");
        fs::write(&log_path, lines.join("\n") + "\n").unwrap();

        assert_eq!(
            AuditLog::verify_file(&log_path),
            Err(AuditVerifyError::EventHashMismatch { line: 3 })
        );

        let _ = fs::remove_dir_all(&dir);
    }
}
