"""Stage 2: Isolated unit tests for Python SDK guards and harness adapters."""

from __future__ import annotations

import base64
import pytest

from airlock_sdk import (
    AirlockClient,
    ClaudeAgentSandbox,
    ExecResult,
    LangGraphSandbox,
    OpenAIAgentSandbox,
    OpenHandsSandbox,
)

pytestmark = pytest.mark.unit


class _RecordingChamber:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.files: dict[str, str] = {"src/app.py": "print('airlock')\n"}

    def exec(
        self,
        command: list[str] | str,
        *,
        agent_step_id: str | None = None,
        cwd: str = "/workspace",
    ) -> ExecResult:
        cmd = command if isinstance(command, list) else ["/bin/sh", "-lc", command]
        self.calls.append((cmd, agent_step_id))
        if cmd[:2] == ["cat", "--"]:
            rel = cmd[2]
            if rel in self.files:
                return ExecResult(0, self.files[rel], "", agent_step_id)
            return ExecResult(1, "", f"missing: {rel}", agent_step_id)
        if cmd[:2] == ["python3", "-c"] and len(cmd) == 5:
            rel, b64 = cmd[3], cmd[4]
            self.files[rel] = base64.b64decode(b64).decode("utf-8")
            return ExecResult(0, "", "", agent_step_id)
        return ExecResult(0, "ok\n", "", agent_step_id)


def test_chamber_guards_before_start() -> None:
    client = AirlockClient(target="local", socket_path="/tmp/unused.sock")
    ch = client.chamber("/tmp")
    for fn in (lambda: ch.exec("true"), ch.diff, ch.commit, ch.undo):
        with pytest.raises(RuntimeError, match="not been started"):
            fn()


def test_remote_client_requires_remote_url() -> None:
    client = AirlockClient(target="remote", remote_url=None)
    ch = client.chamber("/tmp")
    with pytest.raises(ValueError, match="remote_url is required"):
        ch.start()


@pytest.mark.parametrize(
    "adapter_cls",
    [LangGraphSandbox, ClaudeAgentSandbox, OpenAIAgentSandbox, OpenHandsSandbox],
)
def test_adapters_handle_shell_metacharacters_and_missing_files(adapter_cls: type) -> None:
    rec = _RecordingChamber()
    adapter = adapter_cls(rec)

    tricky = "line1 'single' \"double\" $(whoami)\n__AIRLOCK_EOF__\nunicode: \u2713"
    adapter.write_file("notes/spec'd.txt", tricky, step_id="step_w1")
    assert adapter.read_file("notes/spec'd.txt", step_id="step_r1") == tricky

    with pytest.raises(FileNotFoundError):
        adapter.read_file("does/not/exist.txt", step_id="step_r2")

    res = adapter.run_shell("echo hi", step_id="step_sh")
    assert res.exit_code == 0
    assert res.agent_step_id == "step_sh"
