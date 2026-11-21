"""Stage 2: End-to-end integration tests over a live AF_UNIX mock airlockd server & CLI."""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from airlock_sdk import AirlockClient
from conftest import MockAirlockServer

pytestmark = pytest.mark.integration


def test_full_chamber_lifecycle_over_unix_socket(
    mock_airlockd_socket: MockAirlockServer,
    tmp_path: Path,
) -> None:
    client = AirlockClient(target="local", socket_path=mock_airlockd_socket.socket_path)
    with client.chamber(str(tmp_path)) as ch:
        assert ch.chamber_id == "chmb_test_01"
        assert ch.phantom_env["GITHUB_TOKEN"].startswith("airlock-phantom:cap_")
        assert "ghp_" not in ch.phantom_env["GITHUB_TOKEN"]

        exec_res = ch.exec("pytest -q", agent_step_id="step_07")
        assert exec_res.exit_code == 0
        assert exec_res.stdout == "chamber ok\n"
        assert exec_res.agent_step_id == "step_07"

        diff_res = ch.diff()
        assert diff_res["modified"] == ["src/main.py"]

        commit_res = ch.commit(approve_protected=False)
        assert commit_res["committed"] is True

        undo_res = ch.undo()
        assert undo_res["restored"] is True

    methods_paths = [(r["method"], r["path"]) for r in mock_airlockd_socket.requests]
    assert methods_paths == [
        ("POST", "/v1/chambers"),
        ("POST", "/v1/chambers/chmb_test_01/exec"),
        ("GET", "/v1/chambers/chmb_test_01/diff"),
        ("POST", "/v1/chambers/chmb_test_01/commit"),
        ("POST", "/v1/chambers/chmb_test_01/undo"),
        ("DELETE", "/v1/chambers/chmb_test_01"),
    ]
    exec_body = mock_airlockd_socket.requests[1]["json"]
    assert exec_body["agent_step_id"] == "step_07"
    assert exec_body["command"] == ["/bin/sh", "-lc", "pytest -q"]


def test_bearer_token_and_http_policy_error_surface(
    mock_airlockd_socket: MockAirlockServer,
    tmp_path: Path,
) -> None:
    client = AirlockClient(
        target="local",
        socket_path=mock_airlockd_socket.socket_path,
        bearer_token="oidc-jwt-sample",
    )
    with client.chamber(str(tmp_path)) as ch:
        assert (
            mock_airlockd_socket.requests[0]["headers"].get("authorization")
            == "Bearer oidc-jwt-sample"
        )
        mock_airlockd_socket.next_status = 403
        with pytest.raises(RuntimeError, match="Airlock API 403"):
            ch.exec("git push origin HEAD:main")


def test_cli_init_stack_detection_and_force_guard(airlock_bin: Path, tmp_path: Path) -> None:
    (tmp_path / "Cargo.toml").write_text("[package]\nname='x'\n", encoding="utf-8")
    (tmp_path / "package.json").write_text('{"name":"x"}\n', encoding="utf-8")
    (tmp_path / "pyproject.toml").write_text('[project]\nname="x"\n', encoding="utf-8")

    first = subprocess.run(
        [str(airlock_bin), "init", str(tmp_path), "--json"],
        capture_output=True,
        text=True,
        check=True,
    )
    assert '"SEALED"' in first.stdout
    manifest = (tmp_path / "airlock.toml").read_text(encoding="utf-8")
    for registry in ("crates.io", "registry.npmjs.org", "pypi.org"):
        assert registry in manifest

    # Second init without --force must exit 78 (EXIT_CONFIG).
    second = subprocess.run(
        [str(airlock_bin), "init", str(tmp_path)],
        capture_output=True,
        text=True,
    )
    assert second.returncode == 78

    # With --force it succeeds cleanly.
    forced = subprocess.run(
        [str(airlock_bin), "init", str(tmp_path), "--force"],
        capture_output=True,
        text=True,
    )
    assert forced.returncode == 0
