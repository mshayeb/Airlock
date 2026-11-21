"""Stage 3: Security & accessibility acceptance tests (AT-11, AT-13, AT-14, FR-NET-1)."""

from __future__ import annotations

import hashlib
import json
import os
import platform
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

pytestmark = pytest.mark.security

GENESIS_HASH = "sha256:" + ("0" * 64)


def _build_hash_chained_audit(events: list[tuple[str, str, str]]) -> list[str]:
    """Builds JSONL lines matching `airlockd::audit::AuditLog::append`."""
    lines: list[str] = []
    prev_hash = GENESIS_HASH
    for seq, (event_type, decision, reason) in enumerate(events, start=1):
        body = (
            f'"seq":{seq},'
            f'"timestamp":"2026-11-21T12:00:0{seq}Z",'
            f'"prev_hash":"{prev_hash}",'
            f'"chamber_id":"chmb_sec_01",'
            f'"vsock_cid":7,'
            f'"principal_id":"agent:main",'
            f'"agent_step_id":"step_{seq}",'
            f'"event_type":"{event_type}",'
            f'"capability_id":"github_agent_pr",'
            f'"decision":"{decision}",'
            f'"reason_code":"{reason}",'
            f'"detail":"audit check {seq}"'
        )
        digest = hashlib.sha256(f"{prev_hash}\n{{{body}}}".encode("utf-8")).hexdigest()
        event_hash = f"sha256:{digest}"
        lines.append(f'{{"event_hash":"{event_hash}",{body}}}')
        prev_hash = event_hash
    return lines


def test_at11_audit_hash_chain_verify_and_tamper_detection(
    airlock_bin: Path,
    tmp_path: Path,
) -> None:
    audit_file = tmp_path / "audit.jsonl"
    lines = _build_hash_chained_audit(
        [
            ("CHAMBER_SEALED", "ALLOW", "OK"),
            ("BROKER_HTTP", "ALLOW", "OK"),
            ("BROKER_GIT_PUSH", "DENY", "POLICY_REF_DENIED"),
        ]
    )
    audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok = subprocess.run(
        [str(airlock_bin), "logs", "--verify", str(audit_file), "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(ok.stdout)
    assert data["status"] == "SEALED"
    assert data["verified_events"] == 3

    # Tamper line 2 (`AT-11`) and confirm exit 79 (EXIT_REJECTED) + BLOCKED status.
    tampered = list(lines)
    tampered[1] = tampered[1].replace('"ALLOW"', '"DENY"')
    audit_file.write_text("\n".join(tampered) + "\n", encoding="utf-8")

    bad = subprocess.run(
        [str(airlock_bin), "logs", "--verify", str(audit_file), "--json"],
        capture_output=True,
        text=True,
    )
    assert bad.returncode == 79
    err_data = json.loads(bad.stdout)
    assert err_data["status"] == "BLOCKED"
    assert "line 2" in err_data["error"]


def test_at13_wcag_no_color_and_plain_accessibility(airlock_bin: Path) -> None:
    env = dict(os.environ)
    env["NO_COLOR"] = "1"
    env["TERM"] = "dumb"

    proc = subprocess.run(
        [str(airlock_bin), "doctor", "--plain"],
        capture_output=True,
        text=True,
        env=env,
    )
    expected_codes = (0,) if sys.platform == "darwin" else (0, 70)
    assert proc.returncode in expected_codes
    assert "\x1b[" not in proc.stdout
    assert "\x1b[" not in proc.stderr
    assert any(
        badge in proc.stdout
        for badge in ("[SEALED]", "[ALLOW]", "[REVIEW]", "[BLOCKED]")
    )


def test_at14_workspace_with_spaces_and_trailing_space(airlock_bin: Path) -> None:
    with tempfile.TemporaryDirectory(prefix="Airlock Space ") as parent:
        repo = Path(parent) / "repo "
        repo.mkdir()
        init_proc = subprocess.run(
            [str(airlock_bin), "init", ".", "--json"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(init_proc.stdout)["status"] == "SEALED"
        assert (repo / "airlock.toml").is_file()

        audit_file = repo / "audit.jsonl"
        lines = _build_hash_chained_audit([("CHAMBER_SEALED", "ALLOW", "OK")])
        audit_file.write_text("\n".join(lines) + "\n", encoding="utf-8")
        verify_proc = subprocess.run(
            [str(airlock_bin), "logs", "--verify", str(audit_file), "--json"],
            cwd=str(repo),
            capture_output=True,
            text=True,
            check=True,
        )
        assert json.loads(verify_proc.stdout)["verified_events"] == 1


@pytest.mark.skipif(
    sys.platform != "darwin" or platform.machine() != "arm64",
    reason="Apple Silicon Virtualization.framework helper applies only on macOS arm64",
)
def test_macos_vz_helper_zero_nic_invariant(repo_root: Path) -> None:
    helper = repo_root / "macos" / "airlock-vz-helper" / "bin" / "airlock-vz-helper"
    if not helper.is_file():
        pytest.skip("airlock-vz-helper binary not built yet")
    proc = subprocess.run(
        [str(helper), "--probe", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    report = json.loads(proc.stdout)
    assert report["is_supported"] is True
    assert report["config_validated"] is True
    assert report["virtio_net_count"] == 0
    assert report["vsock_configured"] is True
