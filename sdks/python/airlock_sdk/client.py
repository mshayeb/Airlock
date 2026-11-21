"""Control plane client for local Unix socket and remote mTLS Airlock endpoints."""

from __future__ import annotations

import http.client
import json
import os
import socket
from dataclasses import dataclass
from typing import Any, Literal, Mapping, Optional

ChamberTarget = Literal["local", "remote"]


@dataclass(frozen=True)
class ExecResult:
    exit_code: int
    stdout: str
    stderr: str
    agent_step_id: Optional[str] = None


class _UnixSocketHTTPConnection(http.client.HTTPConnection):
    def __init__(self, socket_path: str, timeout: float = 30.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self.timeout)
        sock.connect(self._socket_path)
        self.sock = sock


class AirlockClient:
    """Thin zero-dependency client talking to `airlockd` over Unix socket or HTTPS."""

    def __init__(
        self,
        *,
        target: ChamberTarget = "local",
        socket_path: Optional[str] = None,
        remote_url: Optional[str] = None,
        bearer_token: Optional[str] = None,
    ) -> None:
        self.target = target
        default_sock = os.path.expanduser("~/.local/state/airlock/airlockd.sock")
        self.socket_path = socket_path or os.environ.get("AIRLOCK_SOCKET", default_sock)
        self.remote_url = remote_url or os.environ.get("AIRLOCK_REMOTE_URL")
        self.bearer_token = bearer_token or os.environ.get("AIRLOCK_OIDC_TOKEN")

    def chamber(
        self,
        workspace: str,
        *,
        manifest_path: Optional[str] = None,
        target: Optional[ChamberTarget] = None,
    ) -> "Chamber":
        return Chamber(
            client=self,
            workspace=os.path.abspath(workspace),
            manifest_path=manifest_path,
            target=target or self.target,
        )

    def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Mapping[str, Any]] = None,
    ) -> dict[str, Any]:
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers: dict[str, str] = {"Accept": "application/json"}
        if body is not None:
            headers["Content-Type"] = "application/json"
        if self.bearer_token:
            headers["Authorization"] = f"Bearer {self.bearer_token}"

        if self.target == "local":
            conn: http.client.HTTPConnection = _UnixSocketHTTPConnection(self.socket_path)
        else:
            if not self.remote_url:
                raise ValueError("remote_url is required when target='remote'")
            host = self.remote_url.removeprefix("https://").removeprefix("http://").rstrip("/")
            conn = http.client.HTTPSConnection(host, timeout=30.0)

        try:
            conn.request(method, path, body=body, headers=headers)
            resp = conn.getresponse()
            raw = resp.read().decode("utf-8", errors="replace")
            data = json.loads(raw) if raw else {}
            if resp.status >= 400:
                raise RuntimeError(f"Airlock API {resp.status}: {data}")
            return data
        finally:
            conn.close()


class Chamber:
    """Context-managed Airlock microVM Chamber handle."""

    def __init__(
        self,
        *,
        client: AirlockClient,
        workspace: str,
        manifest_path: Optional[str],
        target: ChamberTarget,
    ) -> None:
        self._client = client
        self.workspace = workspace
        self.manifest_path = manifest_path
        self.target = target
        self.chamber_id: Optional[str] = None
        self.phantom_env: dict[str, str] = {}

    def __enter__(self) -> "Chamber":
        return self.start()

    def __exit__(self, _exc_type: Any, _exc: Any, _tb: Any) -> None:
        self.close()

    def start(self) -> "Chamber":
        resp = self._client._request(
            "POST",
            "/v1/chambers",
            {
                "workspace": self.workspace,
                "target": self.target,
                "manifest_path": self.manifest_path,
            },
        )
        self.chamber_id = resp["chamber_id"]
        self.phantom_env = dict(resp.get("phantom_env", {}))
        return self

    def exec(
        self,
        command: list[str] | str,
        *,
        agent_step_id: Optional[str] = None,
        cwd: str = "/workspace",
    ) -> ExecResult:
        if not self.chamber_id:
            raise RuntimeError("Chamber has not been started")
        cmd = command if isinstance(command, list) else ["/bin/sh", "-lc", command]
        resp = self._client._request(
            "POST",
            f"/v1/chambers/{self.chamber_id}/exec",
            {"command": cmd, "cwd": cwd, "agent_step_id": agent_step_id},
        )
        return ExecResult(
            exit_code=int(resp["exit_code"]),
            stdout=str(resp.get("stdout", "")),
            stderr=str(resp.get("stderr", "")),
            agent_step_id=agent_step_id,
        )

    def diff(self) -> dict[str, Any]:
        if not self.chamber_id:
            raise RuntimeError("Chamber has not been started")
        return self._client._request("GET", f"/v1/chambers/{self.chamber_id}/diff")

    def commit(self, *, approve_protected: bool = False) -> dict[str, Any]:
        if not self.chamber_id:
            raise RuntimeError("Chamber has not been started")
        return self._client._request(
            "POST",
            f"/v1/chambers/{self.chamber_id}/commit",
            {"approve_protected": approve_protected},
        )

    def undo(self) -> dict[str, Any]:
        if not self.chamber_id:
            raise RuntimeError("Chamber has not been started")
        return self._client._request("POST", f"/v1/chambers/{self.chamber_id}/undo", {})

    def close(self) -> None:
        if self.chamber_id:
            try:
                self._client._request("DELETE", f"/v1/chambers/{self.chamber_id}")
            finally:
                self.chamber_id = None
