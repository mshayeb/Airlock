"""Shared pytest fixtures for Airlock smoke, unit, integration, and security tests."""

from __future__ import annotations

import json
import socketserver
import subprocess
import tempfile
import threading
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Iterator

import pytest


@pytest.fixture(scope="session")
def repo_root() -> Path:
    return Path(__file__).resolve().parents[2]


@pytest.fixture(scope="session")
def airlock_bin(repo_root: Path) -> Path:
    for profile in ("debug", "release"):
        candidate = repo_root / "target" / profile / "airlock"
        if candidate.is_file():
            return candidate
    subprocess.run(
        ["cargo", "build", "-p", "airlock-cli"],
        cwd=str(repo_root),
        check=True,
    )
    built = repo_root / "target" / "debug" / "airlock"
    assert built.is_file(), f"Expected built binary at {built}"
    return built


@dataclass
class MockAirlockServer:
    socket_path: str
    requests: list[dict[str, Any]] = field(default_factory=list)
    next_status: int | None = None
    next_error_body: dict[str, Any] = field(
        default_factory=lambda: {"error": "POLICY_REF_DENIED", "message": "main push blocked"}
    )


class _ThreadingUnixStreamServer(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


@pytest.fixture()
def mock_airlockd_socket() -> Iterator[MockAirlockServer]:
    # Keep Unix socket path strictly short (<104-byte macOS SUN_LEN limit).
    with tempfile.TemporaryDirectory(dir="/tmp", prefix="al-") as tmpdir:
        sock_path = f"{tmpdir}/d.sock"
        state = MockAirlockServer(socket_path=sock_path)

        class Handler(BaseHTTPRequestHandler):
            def address_string(self) -> str:
                return "unix-peer"

            def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
                return

            def _handle(self, method: str) -> None:
                length = int(self.headers.get("Content-Length", "0"))
                raw = self.rfile.read(length) if length > 0 else b""
                payload = json.loads(raw.decode("utf-8")) if raw else None
                state.requests.append(
                    {
                        "method": method,
                        "path": self.path,
                        "headers": {k.lower(): v for k, v in self.headers.items()},
                        "json": payload,
                    }
                )

                if state.next_status is not None:
                    code = state.next_status
                    state.next_status = None
                    self._send_json(code, state.next_error_body)
                    return

                if method == "POST" and self.path == "/v1/chambers":
                    self._send_json(
                        201,
                        {
                            "chamber_id": "chmb_test_01",
                            "status": "SEALED",
                            "phantom_env": {
                                "GITHUB_TOKEN": "airlock-phantom:cap_github_deadbeef",
                                "ANTHROPIC_API_KEY": "airlock-phantom:cap_anthropic_cafebabe",
                            },
                        },
                    )
                elif method == "POST" and self.path.endswith("/exec"):
                    self._send_json(
                        200,
                        {"exit_code": 0, "stdout": "chamber ok\n", "stderr": ""},
                    )
                elif method == "GET" and self.path.endswith("/diff"):
                    self._send_json(
                        200,
                        {
                            "modified": ["src/main.py"],
                            "protected_paths": [],
                            "secret_findings": [],
                            "conflicts": [],
                        },
                    )
                elif method == "POST" and self.path.endswith("/commit"):
                    self._send_json(200, {"committed": True, "undo_session_id": "sess_01"})
                elif method == "POST" and self.path.endswith("/undo"):
                    self._send_json(200, {"restored": True})
                elif method == "DELETE" and self.path.startswith("/v1/chambers/"):
                    self._send_json(200, {"sealed": False, "destroyed": True})
                else:
                    self._send_json(404, {"error": "NOT_FOUND"})

            def _send_json(self, status: int, obj: dict[str, Any]) -> None:
                body = json.dumps(obj).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self) -> None:  # noqa: N802
                self._handle("GET")

            def do_POST(self) -> None:  # noqa: N802
                self._handle("POST")

            def do_DELETE(self) -> None:  # noqa: N802
                self._handle("DELETE")

        server = _ThreadingUnixStreamServer(sock_path, Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            yield state
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)
