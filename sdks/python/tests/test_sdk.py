import base64
import unittest

from airlock_sdk import (
    AirlockClient,
    ClaudeAgentSandbox,
    ExecResult,
    LangGraphSandbox,
    OpenAIAgentSandbox,
    OpenHandsSandbox,
)


class _FakeChamber:
    def __init__(self) -> None:
        self.calls: list[tuple[list[str], str | None]] = []
        self.files: dict[str, str] = {"README.md": "# Airlock\n"}

    def exec(self, command: list[str] | str, *, agent_step_id=None, cwd: str = "/workspace") -> ExecResult:
        cmd = command if isinstance(command, list) else ["/bin/sh", "-lc", command]
        self.calls.append((cmd, agent_step_id))
        if cmd[0] == "cat":
            target = cmd[2]
            if target in self.files:
                return ExecResult(0, self.files[target], "", agent_step_id)
            return ExecResult(1, "", "No such file", agent_step_id)
        if cmd[0] == "python3" and len(cmd) == 5:
            rel_path, b64 = cmd[3], cmd[4]
            self.files[rel_path] = base64.b64decode(b64).decode("utf-8")
            return ExecResult(0, "", "", agent_step_id)
        return ExecResult(0, "ok\n", "", agent_step_id)


class AirlockSdkTests(unittest.TestCase):
    def test_client_constructs_chamber_handle(self) -> None:
        client = AirlockClient(target="local", socket_path="/tmp/test.sock")
        ch = client.chamber("/tmp/Airlock Test /repo ")
        self.assertEqual(ch.target, "local")
        self.assertIsNone(ch.chamber_id)

    def test_harness_adapters_forward_step_ids_and_safe_io(self) -> None:
        fake = _FakeChamber()
        for adapter_cls in (LangGraphSandbox, ClaudeAgentSandbox, OpenAIAgentSandbox):
            adapter = adapter_cls(fake)  # type: ignore[arg-type]
            self.assertEqual(adapter.read_file("README.md", step_id="s1"), "# Airlock\n")
            adapter.write_file("out/note.txt", "hello\n__AIRLOCK_EOF__", step_id="s2")
            self.assertEqual(fake.files["out/note.txt"], "hello\n__AIRLOCK_EOF__")

        oh = OpenHandsSandbox(fake)  # type: ignore[arg-type]
        out = oh.execute_action("pytest -q", step_id="step_99")
        self.assertEqual(out["exit_code"], 0)
        self.assertEqual(out["agent_step_id"], "step_99")


if __name__ == "__main__":
    unittest.main()
