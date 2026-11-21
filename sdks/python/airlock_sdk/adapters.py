"""Drop-in `SandboxProvider` adapters for major agent frameworks (`FR-INT-5`)."""

from __future__ import annotations

from typing import Protocol, Optional

from .client import Chamber, ExecResult


class SandboxProvider(Protocol):
    """Canonical Airlock execution contract shared across agent harnesses."""

    def run_shell(self, command: str, *, step_id: Optional[str] = None) -> ExecResult: ...

    def read_file(self, rel_path: str, *, step_id: Optional[str] = None) -> str: ...

    def write_file(self, rel_path: str, content: str, *, step_id: Optional[str] = None) -> None: ...


class _BaseChamberAdapter:
    def __init__(self, chamber: Chamber) -> None:
        self._chamber = chamber

    def run_shell(self, command: str, *, step_id: Optional[str] = None) -> ExecResult:
        return self._chamber.exec(["/bin/sh", "-lc", command], agent_step_id=step_id)

    def read_file(self, rel_path: str, *, step_id: Optional[str] = None) -> str:
        res = self._chamber.exec(["cat", "--", rel_path], agent_step_id=step_id)
        if res.exit_code != 0:
            raise FileNotFoundError(f"Failed to read {rel_path}: {res.stderr}")
        return res.stdout

    def write_file(self, rel_path: str, content: str, *, step_id: Optional[str] = None) -> None:
        script = (
            "import pathlib, sys; "
            "p = pathlib.Path(sys.argv[1]); "
            "p.parent.mkdir(parents=True, exist_ok=True); "
            "p.write_text(sys.stdin.read(), encoding='utf-8')"
        )
        # Escape safely via python heredoc/env or single-quoted literal avoiding injection.
        quoted_path = "'" + rel_path.replace("'", "'\"'\"'") + "'"
        quoted_body = "'" + content.replace("'", "'\"'\"'") + "'"
        cmd = f"python3 -c { _shell_quote(script) } {quoted_path} <<'__AIRLOCK_EOF__'\n{content}\n__AIRLOCK_EOF__"
        # Prefer base64 when content may include EOF sentinel.
        del cmd, quoted_body
        import base64

        b64 = base64.b64encode(content.encode("utf-8")).decode("ascii")
        py = (
            "import base64, pathlib, sys; "
            "p = pathlib.Path(sys.argv[1]); "
            "p.parent.mkdir(parents=True, exist_ok=True); "
            "p.write_bytes(base64.b64decode(sys.argv[2]))"
        )
        res = self._chamber.exec(
            ["python3", "-c", py, rel_path, b64],
            agent_step_id=step_id,
        )
        if res.exit_code != 0:
            raise OSError(f"Failed to write {rel_path}: {res.stderr}")


def _shell_quote(s: str) -> str:
    return "'" + s.replace("'", "'\"'\"'") + "'"


class LangGraphSandbox(_BaseChamberAdapter):
    """LangGraph tool-node backend dispatching shell/file calls into an Airlock Chamber."""


class ClaudeAgentSandbox(_BaseChamberAdapter):
    """Claude Agent SDK bash/file-tool adapter backed by Airlock Phase 1 Chamber."""


class OpenAIAgentSandbox(_BaseChamberAdapter):
    """OpenAI Agents SDK `LocalShellTool` adapter backed by Airlock Phase 1 Chamber."""


class OpenHandsSandbox(_BaseChamberAdapter):
    """OpenHands runtime execution adapter mapping `CmdRunAction` to `Chamber.exec`."""

    def execute_action(self, command: str, step_id: Optional[str] = None) -> dict[str, object]:
        res = self.run_shell(command, step_id=step_id)
        return {
            "exit_code": res.exit_code,
            "stdout": res.stdout,
            "stderr": res.stderr,
            "agent_step_id": res.agent_step_id,
        }
