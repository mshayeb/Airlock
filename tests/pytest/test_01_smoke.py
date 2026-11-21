"""Stage 1: Fast smoke gate tests run first in CI before heavier matrices."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.smoke


def test_cli_version_json(airlock_bin: Path) -> None:
    proc = subprocess.run(
        [str(airlock_bin), "version", "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    data = json.loads(proc.stdout)
    assert data["name"] == "airlock"
    assert data["phase"] == 1
    assert data["spec_version"] == "1.0"


def test_cli_doctor_json_smoke(airlock_bin: Path) -> None:
    proc = subprocess.run(
        [str(airlock_bin), "doctor", "--json"],
        capture_output=True,
        text=True,
    )
    payload = json.loads(proc.stdout)
    assert payload["os"] in ("macos", "linux")
    assert isinstance(payload["checks"], list) and len(payload["checks"]) >= 2

    if sys.platform == "darwin":
        assert proc.returncode == 0
    else:
        kvm_ok = any(
            c["check"] == "linux_kvm" and c["status"] == "ALLOW"
            for c in payload["checks"]
        )
        assert proc.returncode == (0 if kvm_ok else 70)


def test_cli_init_smoke(airlock_bin: Path, tmp_path: Path) -> None:
    proc = subprocess.run(
        [str(airlock_bin), "init", str(tmp_path), "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    result = json.loads(proc.stdout)
    assert result["status"] == "SEALED"
    manifest = (tmp_path / "airlock.toml").read_text(encoding="utf-8")
    assert 'version = "1"' in manifest
    assert "strip_query_params = true" in manifest


def test_sdk_import_and_handle_smoke(tmp_path: Path) -> None:
    from airlock_sdk import (
        AirlockClient,
        ClaudeAgentSandbox,
        LangGraphSandbox,
        OpenAIAgentSandbox,
        OpenHandsSandbox,
    )

    client = AirlockClient(target="local", socket_path="/tmp/nonexistent-smoke.sock")
    ch = client.chamber(str(tmp_path))
    assert ch.chamber_id is None
    assert ch.target == "local"
    assert all(
        cls is not None
        for cls in (LangGraphSandbox, ClaudeAgentSandbox, OpenAIAgentSandbox, OpenHandsSandbox)
    )
