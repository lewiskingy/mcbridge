"""Privileged agent for mcbridge.

This module exposes a tiny Unix domain socket service that performs limited
operations requiring elevated privileges. Clients submit JSON requests to a
socket owned by ``mcbridge-operators`` and receive structured JSON responses.
Supported actions include running allowlisted system commands and writing
configuration/unit files with controlled ownership and permissions.
"""

from __future__ import annotations

import argparse
import base64
import grp
import json
import logging
import os
import pwd
import shlex
import shutil
import socket
import subprocess
import sys
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

DEFAULT_SOCKET = Path(os.environ.get("MCBRIDGE_AGENT_SOCKET", "/run/mcbridge/agent.sock"))
DEFAULT_GROUP = os.environ.get("MCBRIDGE_OPERATOR_GROUP", "mcbridge-operators")
DEFAULT_TIMEOUT = float(os.environ.get("MCBRIDGE_AGENT_TIMEOUT", "15"))
CAPABILITY_SET = "CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_FOWNER CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE"
REQUIRED_SETID_CAPABILITIES = ("CAP_SETUID", "CAP_SETGID")
SETID_CAPABILITY_BITS = {"CAP_SETGID": 6, "CAP_SETUID": 7}

LOG = logging.getLogger(__name__)
LOG.setLevel(logging.INFO)
if not LOG.handlers:
    _handler = logging.StreamHandler(stream=sys.stderr)
    _handler.setLevel(logging.INFO)
    _handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    LOG.addHandler(_handler)


class AgentError(RuntimeError):
    """Raised when an agent operation cannot be fulfilled."""

    def __init__(self, message: str, *, detail: Mapping[str, Any] | None = None) -> None:
        super().__init__(message)
        self.detail = dict(detail or {})


@dataclass
class AgentProcessResult:
    args: Sequence[str]
    returncode: int | None
    stdout: str
    stderr: str

    def check_returncode(self) -> None:
        if self.returncode and self.returncode != 0:
            raise subprocess.CalledProcessError(
                self.returncode,
                self.args,
                output=self.stdout,
                stderr=self.stderr,
            )


class AgentClient:
    """Simple JSON-over-UDS client for the mcbridge agent."""

    def __init__(self, socket_path: Path | str = DEFAULT_SOCKET, *, timeout: float | None = DEFAULT_TIMEOUT) -> None:
        self.socket_path = Path(socket_path)
        self.timeout = timeout

    def _request(self, payload: Mapping[str, Any], *, timeout: float | None = None) -> Mapping[str, Any]:
        if not self.socket_path.exists():
            raise AgentError(f"Agent socket not found at {self.socket_path}. Is mcbridge-agent.service running?")

        message = json.dumps(payload).encode("utf-8") + b"\n"
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.settimeout(timeout or self.timeout)
                client.connect(str(self.socket_path))
                client.sendall(message)
                response = self._recv_all(client)
        except OSError as exc:  # pragma: no cover - transport failures
            raise AgentError(f"Failed to contact mcbridge agent: {exc}") from exc

        try:
            data = json.loads(response)
        except json.JSONDecodeError as exc:  # pragma: no cover - defensive
            raise AgentError(f"Agent returned invalid JSON: {response!r}") from exc

        if not isinstance(data, Mapping):
            raise AgentError("Agent returned non-mapping response")
        if data.get("status") == "error":
            detail = data.get("error") or data
            raise AgentError(str(detail), detail=data)
        return data

    @staticmethod
    def _recv_all(sock: socket.socket) -> str:
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
            if b"\n" in chunk:
                break
        payload = b"".join(chunks)
        return payload.split(b"\n", 1)[0].decode("utf-8", errors="replace")

    def ping(self) -> Mapping[str, Any]:
        return self._request({"action": "ping"})

    def run_command(
        self,
        command: Sequence[str],
        *,
        env: Mapping[str, str] | None = None,
        check: bool = False,
        input: str | None = None,
        timeout: float | None = None,
        text: bool = True,
    ) -> AgentProcessResult:
        request: MutableMapping[str, Any] = {
            "action": "run",
            "command": list(command),
            "env": dict(env or {}),
            "timeout": timeout,
            "text": text,
        }
        if input is not None:
            request["input"] = input
        response = self._request(request, timeout=timeout)
        result = AgentProcessResult(
            args=list(command),
            returncode=response.get("returncode"),
            stdout=response.get("stdout", ""),
            stderr=response.get("stderr", ""),
        )
        if check:
            result.check_returncode()
        return result

    def apply_plan(
        self, steps: Sequence[Mapping[str, Any]], *, timeout: float | None = None
    ) -> Mapping[str, Any]:
        payload: MutableMapping[str, Any] = {
            "action": "apply_plan",
            "steps": list(steps),
            "timeout": timeout,
        }
        return self._request(payload, timeout=timeout)

    def write_file(
        self,
        path: Path | str,
        contents: str | bytes,
        *,
        mode: int | None = None,
        owner: str | None = None,
        group: str | None = None,
    ) -> Mapping[str, Any]:
        binary = isinstance(contents, (bytes, bytearray))
        payload: MutableMapping[str, Any] = {
            "action": "write_file",
            "path": str(path),
            "mode": mode,
            "owner": owner,
            "group": group,
            "binary": binary,
            "contents": base64.b64encode(contents).decode("utf-8") if binary else str(contents),
        }
        return self._request(payload)


@contextmanager
def _root_privileges() -> Iterable[None]:
    original_euid = os.geteuid()
    original_egid = os.getegid()
    keepcaps_enabled = False
    try:
        if original_egid != 0:
            os.setegid(0)
        if original_euid != 0:
            os.seteuid(0)
            keepcaps_enabled = _set_keepcaps(True)
        yield
    finally:  # pragma: no cover - privilege restoration
        try:
            if original_euid != os.geteuid():
                os.seteuid(original_euid)
        finally:
            if original_egid != os.getegid():
                os.setegid(original_egid)
        if keepcaps_enabled:
            _set_keepcaps(False)


def _set_keepcaps(enabled: bool) -> bool:
    """Enable PR_SET_KEEPCAPS to preserve capabilities across UID changes."""

    try:
        import ctypes
        import ctypes.util
    except Exception:
        return False

    libc_name = ctypes.util.find_library("c") or "libc.so.6"
    try:
        libc = ctypes.CDLL(libc_name, use_errno=True)
    except OSError:
        return False

    prctl = getattr(libc, "prctl", None)
    if prctl is None:
        return False

    PR_SET_KEEPCAPS = 8
    result = prctl(PR_SET_KEEPCAPS, 1 if enabled else 0, 0, 0, 0)
    if result != 0:
        errno = ctypes.get_errno()
        if enabled:
            LOG.warning("Failed to set PR_SET_KEEPCAPS=%s: errno=%s", int(enabled), errno)
        return False
    return True


def _allowed_command(command: Sequence[str]) -> bool:
    if not command:
        return False
    binary = Path(command[0]).name
    allowed = {
        "bash",
        "groupadd",
        "install",
        "iptables",
        "iptables-save",
        "ip",
        "iw",
        "mcbridge-agent-socket-helper",
        "mcbridge",
        "nmcli",
        "openssl",
        "systemctl",
        "useradd",
        "usermod",
    }
    return binary in allowed


def _capability_only_command(command: Sequence[str]) -> bool:
    """Return True for commands that should run without setuid privileges."""

    if not command:
        return False
    name = Path(command[0]).name
    return name in {"nmcli"}


def _privileged_binary(command: Sequence[str], *, env: Mapping[str, str] | None = None) -> bool:
    """Return True if the binary should run via the privilege helper."""

    if not command:
        return False

    binary = str(command[0])
    name = Path(binary).name
    privileged_names = {"systemctl"}
    mcbridge_candidates = _mcbridge_candidates(env)

    return name in privileged_names or name in mcbridge_candidates or binary in mcbridge_candidates


def _mcbridge_candidates(env: Mapping[str, str] | None = None) -> set[str]:
    candidates: set[str] = {"mcbridge", "/usr/local/bin/mcbridge", "/usr/bin/mcbridge"}

    for source in (env or {}, os.environ):
        override = str(source.get("MCBRIDGE_CLI_BIN") or "").strip()
        if not override:
            continue
        try:
            parsed = shlex.split(override)
        except ValueError:
            continue
        if not parsed:
            continue
        first = parsed[0]
        first_name = Path(first).name
        if first_name == "mcbridge":
            candidates.update({first, first_name})

    return candidates


def _mcbridge_cli_paths(env: Mapping[str, str] | None = None) -> list[Path]:
    candidates: list[Path] = []

    def _add(path: Path) -> None:
        parent = path.parent
        if not parent or not parent.is_absolute():
            return
        if parent not in candidates:
            candidates.append(parent)

    _add(Path("/usr/local/bin/mcbridge"))
    _add(Path("/usr/bin/mcbridge"))

    for source in (env or {}, os.environ):
        override = str(source.get("MCBRIDGE_CLI_BIN") or "").strip()
        if not override:
            continue
        try:
            parsed = shlex.split(override)
        except ValueError:
            continue
        if not parsed:
            continue
        candidate = Path(parsed[0])
        if candidate.name == "mcbridge":
            _add(candidate)

    return candidates


def _extend_path(env: MutableMapping[str, str], extra_paths: Iterable[Path]) -> None:
    path_entries = [entry for entry in str(env.get("PATH", "")).split(os.pathsep) if entry]

    for path in reversed(list(extra_paths)):
        path_str = str(path)
        if not path_str:
            continue
        path_entries = [entry for entry in path_entries if entry != path_str]
        path_entries.insert(0, path_str)

    env["PATH"] = os.pathsep.join(path_entries)


@contextmanager
def _agent_context_env() -> Iterable[None]:
    original = os.environ.get("MCBRIDGE_AGENT_CONTEXT")
    os.environ["MCBRIDGE_AGENT_CONTEXT"] = "1"
    try:
        yield
    finally:
        if original is None:
            os.environ.pop("MCBRIDGE_AGENT_CONTEXT", None)
        else:
            os.environ["MCBRIDGE_AGENT_CONTEXT"] = original


@contextmanager
def _temporary_env(overrides: Mapping[str, str]) -> Iterable[None]:
    previous: dict[str, str] = {}
    missing: list[str] = []

    for key, value in overrides.items():
        if key in os.environ:
            previous[key] = os.environ[key]
        else:
            missing.append(key)
        os.environ[key] = value

    try:
        yield
    finally:
        for key, value in previous.items():
            os.environ[key] = value
        for key in missing:
            os.environ.pop(key, None)


class _ArgumentParser(argparse.ArgumentParser):
    """Argument parser that raises ValueError instead of exiting."""

    def error(self, message: str) -> None:
        raise ValueError(message)


def _domain_env_overrides(command_env: Mapping[str, str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for key, value in command_env.items():
        str_value = str(value)
        if os.environ.get(key) != str_value:
            overrides[key] = str_value
    return overrides


def _serialize_payload(payload: Mapping[str, Any], *, text_mode: bool) -> str:
    if not text_mode:
        return json.dumps(payload)
    return json.dumps(payload, indent=2)


def _domain_dns_status(command: Sequence[str], *, text_mode: bool) -> Mapping[str, Any]:
    from . import dns

    debug_json = "--debug-json" in command[3:]
    result = dns.status(debug_json=debug_json)
    return {
        "status": "ok",
        "returncode": result.exit_code,
        "stdout": _serialize_payload(result.payload, text_mode=text_mode),
        "stderr": "",
    }


def _domain_dns_update(command: Sequence[str], *, text_mode: bool) -> Mapping[str, Any]:
    from . import dns

    parser = _ArgumentParser(prog="mcbridge dns update", add_help=False)
    parser.add_argument("--redirect")
    parser.add_argument("--target")
    parser.add_argument("--dry-run", dest="dry_run", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--debug-json", dest="debug_json", action="store_true")
    try:
        parsed = parser.parse_args(command[3:])
    except ValueError as exc:
        return {"status": "ok", "returncode": 2, "stdout": "", "stderr": str(exc)}

    result = dns.update(
        redirect=parsed.redirect,
        target=parsed.target,
        dry_run=parsed.dry_run,
        force=parsed.force,
        debug_json=parsed.debug_json,
    )
    return {
        "status": "ok",
        "returncode": result.exit_code,
        "stdout": _serialize_payload(result.payload, text_mode=text_mode),
        "stderr": "",
    }


def _domain_ap_status(command: Sequence[str], *, text_mode: bool) -> Mapping[str, Any]:
    from . import ap

    debug_json = "--debug-json" in command[3:]
    result = ap.status(debug_json=debug_json)
    return {
        "status": "ok",
        "returncode": result.exit_code,
        "stdout": _serialize_payload(result.payload, text_mode=text_mode),
        "stderr": "",
    }


def _domain_ap_update(command: Sequence[str], *, text_mode: bool) -> Mapping[str, Any]:
    from . import ap

    parser = _ArgumentParser(prog="mcbridge ap update", add_help=False)
    parser.add_argument("--ssid")
    parser.add_argument("--password")
    parser.add_argument("--octet", dest="subnet_octet", type=int)
    parser.add_argument("--channel", type=int)
    parser.add_argument("--dry-run", dest="dry_run", action="store_true")
    parser.add_argument("--force", action="store_true")
    parser.add_argument("--debug-json", dest="debug_json", action="store_true")
    parser.add_argument("--force-restart", dest="force_restart", action="store_true")
    try:
        parsed = parser.parse_args(command[3:])
    except ValueError as exc:
        return {"status": "ok", "returncode": 2, "stdout": "", "stderr": str(exc)}

    result = ap.update(
        ssid=parsed.ssid,
        password=parsed.password,
        subnet_octet=parsed.subnet_octet,
        channel=parsed.channel,
        dry_run=parsed.dry_run,
        force=parsed.force,
        force_restart=parsed.force_restart,
        debug_json=parsed.debug_json,
    )
    return {
        "status": "ok",
        "returncode": result.exit_code,
        "stdout": _serialize_payload(result.payload, text_mode=text_mode),
        "stderr": "",
    }


def _domain_upstream_apply(command: Sequence[str], *, text_mode: bool) -> Mapping[str, Any]:
    from . import upstream

    result = upstream.apply_upstream()
    return {
        "status": "ok",
        "returncode": result.exit_code,
        "stdout": _serialize_payload(result.payload, text_mode=text_mode),
        "stderr": "",
    }


def _domain_upstream_activate(command: Sequence[str], *, text_mode: bool) -> Mapping[str, Any]:
    from . import upstream

    parser = _ArgumentParser(prog="mcbridge upstream activate", add_help=False)
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--interface")
    try:
        parsed = parser.parse_args(command[3:])
    except ValueError as exc:
        return {"status": "ok", "returncode": 2, "stdout": "", "stderr": str(exc)}

    result = upstream.activate_upstream(ssid=parsed.ssid, interface=parsed.interface)
    return {
        "status": "ok",
        "returncode": result.exit_code,
        "stdout": _serialize_payload(result.payload, text_mode=text_mode),
        "stderr": "",
    }


def _domain_upstream_forget(command: Sequence[str], *, text_mode: bool) -> Mapping[str, Any]:
    from . import upstream

    parser = _ArgumentParser(prog="mcbridge upstream forget", add_help=False)
    parser.add_argument("--ssid", required=True)
    parser.add_argument("--interface")
    try:
        parsed = parser.parse_args(command[3:])
    except ValueError as exc:
        return {"status": "ok", "returncode": 2, "stdout": "", "stderr": str(exc)}

    result = upstream.forget_system_profile(ssid=parsed.ssid, interface=parsed.interface)
    return {
        "status": "ok",
        "returncode": result.exit_code,
        "stdout": _serialize_payload(result.payload, text_mode=text_mode),
        "stderr": "",
    }


DOMAIN_ALLOWLIST = {
    ("dns", "status"): _domain_dns_status,
    ("dns", "update"): _domain_dns_update,
    ("ap", "status"): _domain_ap_status,
    ("ap", "update"): _domain_ap_update,
    ("upstream", "apply"): _domain_upstream_apply,
    ("upstream", "activate"): _domain_upstream_activate,
    ("upstream", "forget"): _domain_upstream_forget,
}


def _domain_handler_for(command: Sequence[str]):
    if len(command) < 3:
        return None

    binary = str(command[0])
    name = Path(binary).name
    if name != "mcbridge":
        return None

    domain = command[1]
    action = command[2]
    return DOMAIN_ALLOWLIST.get((domain, action))


def _run_command(request: Mapping[str, Any]) -> Mapping[str, Any]:
    command = request.get("command")
    if not isinstance(command, list) or not all(isinstance(entry, str) for entry in command):
        return {"status": "error", "error": "command must be a list of strings"}

    capability_snapshot = _capability_snapshot()
    _log_capability_snapshot("mcbridge agent capability snapshot before command", capability_snapshot)
    env = request.get("env") if isinstance(request.get("env"), Mapping) else None
    command_env: MutableMapping[str, str] = {**os.environ}
    if env:
        command_env.update({str(key): str(value) for key, value in env.items()})
    timeout = request.get("timeout")
    input_data = request.get("input")
    text_mode = bool(request.get("text", True))
    mcbridge_candidates = _mcbridge_candidates(command_env)

    normalized_command = list(command)
    binary = str(normalized_command[0]) if normalized_command else ""
    name = Path(binary).name if binary else ""

    if name == "bash" and len(normalized_command) >= 3 and normalized_command[1] in ("-lc", "-c"):
        try:
            parsed = shlex.split(normalized_command[2])
        except ValueError:
            parsed = []
        if parsed:
            parsed_binary = str(parsed[0])
            parsed_name = Path(parsed_binary).name
            if parsed_binary in mcbridge_candidates or parsed_name in mcbridge_candidates:
                normalized_command = parsed
                binary = parsed_binary
                name = parsed_name

    mcbridge_cli = bool(binary and (binary in mcbridge_candidates or name in mcbridge_candidates))
    capability_only = _capability_only_command(normalized_command)
    if not normalized_command:
        return {"status": "error", "error": "command must not be empty"}
    if not _allowed_command(normalized_command):
        return {"status": "error", "error": f"Command not permitted: {normalized_command[0]}"}

    use_privileged_helper = _privileged_binary(normalized_command, env=command_env)

    try:
        if mcbridge_cli:
            mcbridge_env = dict(command_env)
            _extend_path(mcbridge_env, _mcbridge_cli_paths(mcbridge_env))
            mcbridge_env["MCBRIDGE_AGENT_CONTEXT"] = os.environ.get("MCBRIDGE_AGENT_CONTEXT", "1")

            def _set_root_ids() -> None:
                try:
                    if os.getegid() != 0:
                        os.setegid(0)
                except PermissionError:
                    pass
                try:
                    if os.geteuid() != 0:
                        os.seteuid(0)
                except PermissionError:
                    pass

            with _agent_context_env():
                process = subprocess.run(
                    normalized_command,
                    capture_output=True,
                    text=text_mode,
                    input=input_data,
                    env=mcbridge_env,
                    timeout=timeout,
                    preexec_fn=_set_root_ids,
                )
        elif capability_only:
            process = subprocess.run(
                normalized_command,
                capture_output=True,
                text=text_mode,
                input=input_data,
                env=command_env,
                timeout=timeout,
            )
        elif use_privileged_helper:
            from . import privileges

            mcbridge_env = dict(command_env)
            if mcbridge_cli:
                _extend_path(mcbridge_env, _mcbridge_cli_paths(mcbridge_env))
            with _root_privileges(), _agent_context_env():
                mcbridge_env["MCBRIDGE_AGENT_CONTEXT"] = os.environ.get("MCBRIDGE_AGENT_CONTEXT", "1")
                process = privileges.sudo_run(
                    normalized_command,
                    env=mcbridge_env,
                    input=input_data,
                    timeout=timeout,
                    text=text_mode,
                )
        else:
            with _root_privileges():
                process = subprocess.run(
                    normalized_command,
                    capture_output=True,
                    text=text_mode,
                    input=input_data,
                    env=command_env,
                    timeout=timeout,
                )
    except subprocess.TimeoutExpired as exc:
        return {
            "status": "error",
            "returncode": None,
            "stdout": getattr(exc, "stdout", "") or "",
            "stderr": getattr(exc, "stderr", str(exc)) or str(exc),
            "timeout": True,
        }
    except FileNotFoundError as exc:
        return {"status": "error", "error": str(exc), "returncode": 127, "stdout": "", "stderr": str(exc)}
    except Exception as exc:  # pragma: no cover - defensive
        return {"status": "error", "error": str(exc), "returncode": None}

    current_capabilities = _capability_snapshot()
    _log_capability_snapshot("mcbridge agent capability snapshot after command", current_capabilities)
    _log_capability_drop(capability_snapshot, current_capabilities)

    return {
        "status": "ok",
        "returncode": process.returncode,
        "stdout": process.stdout or "",
        "stderr": process.stderr or "",
    }


def _write_file(request: Mapping[str, Any]) -> Mapping[str, Any]:
    path_value = request.get("path")
    if not path_value:
        return {"status": "error", "error": "path is required"}
    path = Path(str(path_value))
    binary = bool(request.get("binary"))
    contents_raw = request.get("contents", "")
    try:
        contents = base64.b64decode(contents_raw) if binary else str(contents_raw)
    except Exception as exc:  # pragma: no cover - invalid base64
        return {"status": "error", "error": f"invalid contents: {exc}"}

    mode = request.get("mode")
    owner = request.get("owner")
    group = request.get("group")

    try:
        with _root_privileges():
            path.parent.mkdir(parents=True, exist_ok=True)
            if binary and isinstance(contents, (bytes, bytearray)):
                path.write_bytes(contents)
            else:
                path.write_text(str(contents), encoding="utf-8")
            if mode:
                path.chmod(mode)
            if owner or group:
                _chown(path, owner=owner, group=group)
    except Exception as exc:  # pragma: no cover - filesystem edge cases
        return {"status": "error", "error": str(exc)}

    return {"status": "ok", "path": str(path)}


def _apply_plan(request: Mapping[str, Any]) -> Mapping[str, Any]:
    steps = request.get("steps")
    if not isinstance(steps, Sequence):
        return {"status": "error", "error": "steps must be a list"}

    timeout = request.get("timeout")
    results: list[Mapping[str, Any]] = []
    for index, step in enumerate(steps):
        if not isinstance(step, Mapping):
            results.append({"status": "error", "error": "invalid step", "index": index})
            continue
        action = step.get("action")
        if action == "run":
            result = _run_command(step)
            results.append({"index": index, "action": "run", **result})
        elif action == "write_file":
            result = _write_file(step)
            results.append({"index": index, "action": "write_file", **result})
        else:
            results.append({"status": "error", "error": "unknown plan action", "index": index})

    errored = [entry for entry in results if entry.get("status") == "error"]
    status = "error" if errored else "ok"
    return {"status": status, "results": results, "timeout": timeout}


def _chown(path: Path, *, owner: str | None, group: str | None) -> None:
    uid = -1
    gid = -1
    if owner:
        try:
            uid = int(owner) if owner.isdigit() else pwd.getpwnam(owner).pw_uid  # type: ignore[arg-type]
        except Exception:
            uid = -1
    if group:
        try:
            gid = int(group) if group.isdigit() else grp.getgrnam(group).gr_gid
        except Exception:
            gid = -1
    if uid != -1 or gid != -1:
        os.chown(path, uid if uid != -1 else -1, gid if gid != -1 else -1)


@dataclass
class _CapabilitySnapshot:
    effective: int | None
    permitted: int | None


def _parse_capability_value(field: str, status_text: str | None) -> int | None:
    if not status_text:
        return None

    prefix = f"{field}:"
    for line in status_text.splitlines():
        if not line.startswith(prefix):
            continue
        parts = line.split()
        if len(parts) < 2:
            return None
        try:
            return int(parts[1], 16)
        except ValueError:
            return None
    return None


def _capability_snapshot() -> _CapabilitySnapshot:
    status_text = _read_proc_status()
    return _CapabilitySnapshot(
        effective=_parse_capability_value("CapEff", status_text),
        permitted=_parse_capability_value("CapPrm", status_text),
    )


def _format_capability_value(value: int | None) -> str:
    if value is None:
        return "unknown"
    return f"0x{value:x}"


def _log_capability_snapshot(prefix: str, snapshot: _CapabilitySnapshot) -> None:
    LOG.info(
        "%s: CapEff=%s, CapPrm=%s",
        prefix,
        _format_capability_value(snapshot.effective),
        _format_capability_value(snapshot.permitted),
    )


def _log_capability_drop(previous: _CapabilitySnapshot, current: _CapabilitySnapshot) -> None:
    dropped_fields: list[str] = []

    def _dropped(previous_value: int | None, current_value: int | None, label: str) -> None:
        if previous_value is None or current_value is None:
            return
        if previous_value == current_value:
            return
        if current_value & previous_value == previous_value:
            return
        dropped_fields.append(f"{label} {_format_capability_value(previous_value)} -> {_format_capability_value(current_value)}")

    _dropped(previous.effective, current.effective, "CapEff")
    _dropped(previous.permitted, current.permitted, "CapPrm")

    if not dropped_fields:
        return

    LOG.warning(
        "mcbridge agent capabilities changed during request: %s. Restart mcbridge-agent.service to restore capabilities.",
        "; ".join(dropped_fields),
    )

    capability_settings = (
        f"AmbientCapabilities={CAPABILITY_SET}, CapabilityBoundingSet={CAPABILITY_SET}, and NoNewPrivileges=no"
    )
    LOG.error(
        "mcbridge agent lost required Linux capabilities after handling a request: %s. "
        "Restart mcbridge-agent.service and verify the systemd unit sets %s.",
        "; ".join(dropped_fields),
        capability_settings,
    )


def _capng_has_capability(capability: str) -> bool:
    try:
        import capng  # type: ignore[import-untyped]
    except Exception:
        return False

    cap_constant = getattr(capng, capability, None)
    effective_constant = getattr(capng, "CAPNG_EFFECTIVE", None)
    if cap_constant is None or effective_constant is None:
        return False

    try:
        return bool(capng.capng_has_capability(effective_constant, cap_constant))
    except Exception:
        return False


def _read_proc_status() -> str | None:
    status_path = Path("/proc/self/status")
    try:
        return status_path.read_text(encoding="utf-8")
    except OSError:
        return None


def _capabilities_from_status_text(status_text: str | None) -> set[str]:
    value = _parse_capability_value("CapEff", status_text)
    if value is None:
        return set()

    return {name for name, bit in SETID_CAPABILITY_BITS.items() if value & (1 << bit)}


def _effective_setid_capabilities() -> set[str]:
    status_text = _read_proc_status()
    return _capabilities_from_status_text(status_text)


def _check_setid_capabilities() -> tuple[bool, str | None]:
    snapshot = _capability_snapshot()
    capability_settings = (
        f"AmbientCapabilities={CAPABILITY_SET}, CapabilityBoundingSet={CAPABILITY_SET}, and NoNewPrivileges=no"
    )
    if snapshot.effective == 0 or snapshot.permitted == 0:
        message = (
            "mcbridge agent started without required Linux capabilities. "
            f"CapEff={_format_capability_value(snapshot.effective)}, CapPrm={_format_capability_value(snapshot.permitted)}. "
            f"Update the systemd unit to set {capability_settings}; then run "
            "'systemctl daemon-reload' and restart mcbridge-agent.service."
        )
        return False, message

    available_from_capng = {cap for cap in REQUIRED_SETID_CAPABILITIES if _capng_has_capability(cap)}
    effective_capabilities = _effective_setid_capabilities()
    available = available_from_capng | effective_capabilities
    missing = [cap for cap in REQUIRED_SETID_CAPABILITIES if cap not in available]
    if missing:
        effective_description = ", ".join(sorted(available)) if available else "none"
        message = (
            "mcbridge agent requires CAP_SETUID and CAP_SETGID to adjust user/group IDs, "
            f"but the effective capability set is missing: {', '.join(missing)}. "
            f"Effective capabilities: {effective_description}. "
            f"Update the systemd unit to set {capability_settings}; then run "
            "'systemctl daemon-reload' and restart mcbridge-agent.service."
        )
        return False, message
    return True, None


def _handle_request(request: Mapping[str, Any]) -> Mapping[str, Any]:
    action = request.get("action")
    if action == "ping":
        return {"status": "ok", "message": "pong"}
    if action == "run":
        return _run_command(request)
    if action == "write_file":
        return _write_file(request)
    if action == "apply_plan":
        return _apply_plan(request)
    return {"status": "error", "error": "unknown action"}


def _serve(socket_path: Path, *, group: str) -> None:
    if socket_path.exists():
        try:
            socket_path.unlink()
        except OSError:
            pass

    socket_path.parent.mkdir(parents=True, exist_ok=True)

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as server:
        server.bind(str(socket_path))
        try:
            if group:
                gid = grp.getgrnam(group).gr_gid
                os.chown(socket_path, -1, gid)
        except KeyError:
            pass
        except PermissionError:
            pass
        try:
            os.chmod(socket_path, 0o660)
        except PermissionError:
            pass
        server.listen(5)
        while True:
            conn, _ = server.accept()
            with conn:
                data = AgentClient._recv_all(conn)
                try:
                    request = json.loads(data)
                except json.JSONDecodeError:
                    response = {"status": "error", "error": "invalid json"}
                else:
                    if not isinstance(request, Mapping):
                        response = {"status": "error", "error": "request must be object"}
                    else:
                        response = _handle_request(request)
                conn.sendall(json.dumps(response).encode("utf-8") + b"\n")


def _path_is_relative_to(path: Path, other: Path) -> bool:
    try:
        base = other.resolve(strict=False)
        target = path.resolve(strict=False)
    except Exception:
        base = other
        target = path

    try:
        return target.is_relative_to(base)
    except AttributeError:  # pragma: no cover - fallback for older Python versions
        try:
            target.relative_to(base)
            return True
        except ValueError:
            return False
    except ValueError:
        return False


def _home_for_path(path: Path) -> tuple[str | None, Path | None]:
    try:
        candidate = path.expanduser().resolve(strict=False)
    except Exception:
        candidate = path

    for entry in pwd.getpwall():
        home = Path(entry.pw_dir)
        if not str(home) or home == Path("/"):
            continue
        if _path_is_relative_to(candidate, home):
            return entry.pw_name, home
    return None, None


def resolve_socket_helper(
    *, socket_helper: Path | str | None = None, service_user: str = "mcbridge"
) -> tuple[Path, str | None, Path | None]:
    candidate = Path(socket_helper) if socket_helper else Path(shutil.which("mcbridge-agent-socket-helper") or "/usr/bin/mcbridge-agent-socket-helper")
    owner, home = _home_for_path(candidate)

    if not candidate.exists():
        system_helper = Path("/usr/bin/mcbridge-agent-socket-helper")
        if system_helper.exists() and system_helper != candidate:
            candidate = system_helper
            owner, home = _home_for_path(candidate)

    return candidate, owner, home


def resolve_agent_interpreter(
    *, python_executable: Path | str | None = None, service_user: str = "mcbridge"
) -> tuple[Path, str | None, Path | None]:
    candidate = Path(python_executable) if python_executable else Path(sys.executable)
    owner, home = _home_for_path(candidate)

    if not candidate.exists():
        system_python = Path("/usr/bin/python3")
        if system_python.exists():
            candidate = system_python
            owner, home = _home_for_path(candidate)

    return candidate, owner, home


def agent_service_template(
    *,
    socket_path: Path = DEFAULT_SOCKET,
    user: str = "mcbridge",
    group: str = "mcbridge",
    operator_group: str = DEFAULT_GROUP,
    socket_helper: Path | str | None = None,
    python_executable: Path | str | None = None,
) -> str:
    helper_path, _, _ = resolve_socket_helper(socket_helper=socket_helper, service_user=user)
    interpreter_path, _, _ = resolve_agent_interpreter(python_executable=python_executable, service_user=user)
    lines = [
        "[Unit]",
        "Description=mcbridge privileged agent",
        "After=network.target",
        "",
        "[Service]",
        "Type=simple",
        f"User={user}",
        f"Group={group}",
        f"SupplementaryGroups={operator_group}",
        "PermissionsStartOnly=yes",
        "RuntimeDirectory=mcbridge",
        "RuntimeDirectoryMode=0770",
        "UMask=0007",
        "Environment=PYTHONUNBUFFERED=1",
        "Environment=PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        f"Environment=MCBRIDGE_AGENT_SOCKET={socket_path}",
        f"ExecStartPre={shlex.quote(str(helper_path))} --recreate",
        f"ExecStart={shlex.quote(str(interpreter_path))} -m mcbridge.agent --socket {shlex.quote(str(socket_path))} --group {operator_group}",
        "NoNewPrivileges=no",
        "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_FOWNER CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE",
        "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_DAC_OVERRIDE CAP_FOWNER CAP_DAC_READ_SEARCH CAP_AUDIT_WRITE",
        "Restart=on-failure",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(description="Run the mcbridge privileged agent")
    parser.add_argument("--socket", default=DEFAULT_SOCKET, type=Path, help="Path to Unix domain socket")
    parser.add_argument("--group", default=DEFAULT_GROUP, help="Group ownership for the socket")
    args = parser.parse_args(argv)

    ok, error = _check_setid_capabilities()
    if not ok:
        LOG.error(error)
        sys.exit(1)

    _serve(Path(args.socket), group=args.group)


if __name__ == "__main__":  # pragma: no cover - runtime entrypoint
    main()
