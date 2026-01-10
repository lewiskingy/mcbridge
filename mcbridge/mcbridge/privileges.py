"""Privileged action helpers backed by the mcbridge agent."""

from __future__ import annotations

import os
import subprocess
import pwd
import grp
from functools import lru_cache
from pathlib import Path
from typing import Mapping, Sequence

from .agent import AgentClient, AgentError, AgentProcessResult, DEFAULT_SOCKET, DEFAULT_TIMEOUT


class AgentUnavailableError(PermissionError):
    """Raised when the mcbridge agent cannot fulfil a request."""

    def __init__(
        self,
        message: str,
        *,
        command: Sequence[str] | None = None,
        allowlist_blocked: bool = False,
        path_resolution_failed: bool = False,
        returncode: int | None = None,
        stderr: str | None = None,
    ) -> None:
        super().__init__(message)
        self.command = list(command) if command else None
        self.allowlist_blocked = allowlist_blocked
        self.path_resolution_failed = path_resolution_failed
        self.returncode = returncode
        self.stderr = stderr


def _agent_settings() -> tuple[Path, float]:
    socket_path = Path(os.environ.get("MCBRIDGE_AGENT_SOCKET", DEFAULT_SOCKET))
    timeout_env = os.environ.get("MCBRIDGE_AGENT_TIMEOUT")
    timeout = float(timeout_env) if timeout_env else DEFAULT_TIMEOUT
    return socket_path, timeout


@lru_cache(maxsize=4)
def _cached_client(socket_path: Path, timeout: float) -> AgentClient:
    return AgentClient(socket_path, timeout=timeout)


def _client(timeout: float | None = None) -> AgentClient:
    socket_path, default_timeout = _agent_settings()
    effective_timeout = default_timeout if timeout is None else timeout
    return _cached_client(socket_path, effective_timeout)


def _agent_error(
    exc: Exception,
    *,
    command: Sequence[str] | None = None,
    allowlist_blocked: bool = False,
    path_resolution_failed: bool = False,
    returncode: int | None = None,
    stderr: str | None = None,
) -> AgentUnavailableError:
    socket_path, _ = _agent_settings()
    message = f"mcbridge agent unavailable at {socket_path}: {exc}. Start mcbridge-agent.service or prepare the socket with mcbridge-agent-socket-helper."
    return AgentUnavailableError(
        message,
        command=command,
        allowlist_blocked=allowlist_blocked,
        path_resolution_failed=path_resolution_failed,
        returncode=returncode,
        stderr=stderr,
    )


def _ensure_agent_accessible() -> None:
    try:
        _client().ping()
    except Exception as exc:  # pragma: no cover - transport errors
        raise _agent_error(exc) from exc


def ensure_escalation_available() -> None:
    """Validate that the agent socket is reachable."""

    if os.geteuid() != 0:
        _ensure_agent_accessible()


def sudo_run(
    command: Sequence[str],
    *,
    env: Mapping[str, str] | None = None,
    check: bool = False,
    text: bool = True,
    input: str | None = None,
    timeout: float | None = None,
):
    """Proxy an allowlisted command through the agent."""

    socket_path, default_timeout = _agent_settings()
    agent_timeout = timeout if timeout is not None else default_timeout
    local_timeout = timeout
    in_agent_context = os.environ.get("MCBRIDGE_AGENT_CONTEXT") == "1"
    running_as_root = os.geteuid() == 0
    prefer_local = running_as_root
    use_agent = not prefer_local and not in_agent_context and (not running_as_root or socket_path.exists())

    if not running_as_root:
        _ensure_agent_accessible()

    if use_agent:
        step = {
            "action": "run",
            "command": list(command),
            "env": dict(env or {}),
            "input": input,
            "timeout": agent_timeout,
            "text": text,
        }
        try:
            response = _client(agent_timeout).apply_plan([step], timeout=agent_timeout)
        except AgentError as exc:
            if running_as_root:
                use_agent = False
            else:
                allowlist_blocked = "command not permitted" in str(exc).lower()
                path_resolution_failed = "no such file" in str(exc).lower() or "not found" in str(exc).lower()
                raise _agent_error(
                    exc,
                    command=command,
                    allowlist_blocked=allowlist_blocked,
                    path_resolution_failed=path_resolution_failed,
                ) from exc
        else:
            results = response.get("results") or []
            first = results[0] if results else {}
            process = AgentProcessResult(
                args=list(command),
                returncode=first.get("returncode"),
                stdout=first.get("stdout", ""),
                stderr=first.get("stderr", ""),
            )
            if check:
                process.check_returncode()
            return process

    if running_as_root:
        local_command = list(command)
        if local_command and local_command[0] == "bash" and len(local_command) > 1:
            local_command = local_command[1:]
        kwargs = {
            "capture_output": True,
            "text": text,
            "env": env,
            "check": check,
        }
        if input is not None:
            kwargs["input"] = input
        if local_timeout is not None:
            kwargs["timeout"] = local_timeout
        return subprocess.run(local_command, **kwargs)

    raise _agent_error(PermissionError("mcbridge agent unavailable"), command=command) from None


def sudo_write_file(
    path: Path,
    contents: str | bytes,
    *,
    mode: int = 0o664,
    owner: str | None = None,
    group: str | None = None,
):
    """Write a file via the privileged agent."""

    socket_path, default_timeout = _agent_settings()
    effective_timeout = default_timeout
    running_as_root = os.geteuid() == 0
    prefer_local = running_as_root
    in_agent_context = os.environ.get("MCBRIDGE_AGENT_CONTEXT") == "1"
    use_agent = not prefer_local and not in_agent_context and (not running_as_root or socket_path.exists())

    if not running_as_root:
        _ensure_agent_accessible()

    if use_agent:
        binary = isinstance(contents, (bytes, bytearray))
        encoded_contents = contents
        if binary:
            import base64

            encoded_contents = base64.b64encode(contents).decode("utf-8")
        step = {
            "action": "write_file",
            "path": str(path),
            "contents": encoded_contents if binary else str(contents),
            "binary": binary,
            "mode": mode,
            "owner": owner,
            "group": group,
        }
        try:
            _client(effective_timeout).apply_plan([step], timeout=effective_timeout)
            return
        except AgentError as exc:
            if not running_as_root:
                raise _agent_error(exc) from exc

    if running_as_root:
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, (bytes, bytearray)):
            target.write_bytes(contents)
        else:
            target.write_text(str(contents), encoding="utf-8")
        target.chmod(mode)
        if owner or group:
            uid = -1
            gid = -1
            if owner:
                try:
                    uid = int(owner) if str(owner).isdigit() else pwd.getpwnam(owner).pw_uid  # type: ignore[arg-type]
                except Exception:
                    uid = -1
            if group:
                try:
                    gid = int(group) if str(group).isdigit() else grp.getgrnam(group).gr_gid
                except Exception:
                    gid = -1
            os.chown(target, uid, gid)
        return

    raise _agent_error(PermissionError("mcbridge agent unavailable")) from None


def apply_plan(steps: Sequence[Mapping[str, object]], *, timeout: float | None = None) -> Mapping[str, object]:
    """Send a batch plan to the agent."""

    socket_path, default_timeout = _agent_settings()
    effective_timeout = timeout if timeout is not None else default_timeout
    if os.geteuid() != 0:
        _ensure_agent_accessible()
    elif not socket_path.exists():
        raise _agent_error(PermissionError("mcbridge agent socket not found"))

    try:
        return _client(effective_timeout).apply_plan(steps, timeout=effective_timeout)
    except AgentError as exc:
        raise _agent_error(exc) from exc


__all__ = [
    "AgentUnavailableError",
    "apply_plan",
    "ensure_escalation_available",
    "sudo_run",
    "sudo_write_file",
]
