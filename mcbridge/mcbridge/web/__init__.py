"""Lightweight Flask wrapper for mcbridge domain functions."""

from __future__ import annotations

import argparse
import base64
import binascii
import contextlib
import io
import inspect
import json
import logging
import os
import shlex
import shutil
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass
from http import HTTPStatus
from pathlib import Path
import threading
from typing import Any, Callable, Mapping, Sequence

from flask import Flask, Response, jsonify, render_template, request
from werkzeug.exceptions import BadRequest
from werkzeug.serving import make_server

from .. import ap, cli as cli_module, dns, init as init_module, upstream
from ..agent import AgentClient, AgentError, DEFAULT_SOCKET as DEFAULT_AGENT_SOCKET, DEFAULT_TIMEOUT as DEFAULT_AGENT_TIMEOUT
from ..common import (
    KNOWN_SERVERS_JSON,
    diff_text,
    ensure_parent,
    load_json,
    response_payload,
    set_default_permissions,
)
from ..paths import CONFIG_DIR, ETC_DIR
from ..service_enablement import ensure_services_enabled
from ..dns import _normalise_known_servers
from . import wifi
from .config import DEFAULT_WEB_CONFIG_PATH, WebConfig, load_web_config

LOG = logging.getLogger(__name__)

AGENT_UNAVAILABLE_HINT = "agent socket reachable? mcbridge-agent.service running? service user in mcbridge-operators?"

_Bool = bool | None
JOB_REGISTRY: dict[str, dict[str, Any]] = {}
JOB_LOCK = threading.Lock()
JOB_TTL_SECONDS = 300

@dataclass
class WebInitResult:
    payload: Mapping[str, Any]
    exit_code: int

WEB_SERVICE_PATH = Path(os.environ.get("MCBRIDGE_WEB_SERVICE", "/etc/systemd/system/mcbridge-web.service"))
WEB_SERVICE_NAME = WEB_SERVICE_PATH.name
WEB_HOST = os.environ.get("MCBRIDGE_WEB_HOST", "0.0.0.0")
WEB_PORT = int(os.environ.get("MCBRIDGE_WEB_PORT", "443"))
WEB_HTTP_PORT = int(os.environ.get("MCBRIDGE_WEB_HTTP_PORT", "80"))
WEB_USER = os.environ.get("MCBRIDGE_WEB_USER", "mcbridge")
WEB_GROUP = os.environ.get("MCBRIDGE_WEB_GROUP", WEB_USER)
WEB_TLS_CERT = os.environ.get("MCBRIDGE_WEB_TLS_CERT")
WEB_TLS_KEY = os.environ.get("MCBRIDGE_WEB_TLS_KEY")
DEFAULT_TLS_CERT_PATH = CONFIG_DIR / "web-cert.pem"
DEFAULT_TLS_KEY_PATH = CONFIG_DIR / "web-key.pem"
DEFAULT_TLS_DAYS = 825


def _resolve_executable(env_var: str, expected_name: str, fallback: str) -> str:
    override = os.environ.get(env_var)
    if override:
        return override

    argv0 = sys.argv[0] if sys.argv else None
    try:
        resolved_arg = Path(argv0).resolve() if argv0 else None
    except OSError:
        resolved_arg = None

    if resolved_arg and resolved_arg.name == expected_name and resolved_arg.is_file():
        return str(resolved_arg)

    discovered = shutil.which(expected_name)
    if discovered:
        return discovered

    return fallback


WEB_CLI_BIN = _resolve_executable("MCBRIDGE_WEB_CLI_BIN", "mcbridge", "/usr/local/bin/mcbridge")
WEB_BIN = _resolve_executable("MCBRIDGE_WEB_BIN", "mcbridge-web", "/usr/local/bin/mcbridge-web")


class DocEntry(dict):
    """Simple helper for template-friendly documentation metadata."""

    def __init__(self, slug: str, title: str, filename: str, path: Path):
        super().__init__(slug=slug, title=title, filename=filename, path=path)
        self.slug = slug
        self.title = title
        self.filename = filename
        self.path = path


class CliProxyError(RuntimeError):
    """Raised when the mcbridge CLI cannot be invoked cleanly."""

    def __init__(self, message: str, *, status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR, exit_code: int | None = None):
        super().__init__(message)
        self.status = status
        self.exit_code = exit_code


class WebCommandError(RuntimeError):
    """Raised when an in-process command cannot be fulfilled."""

    def __init__(
        self,
        message: str,
        *,
        status: HTTPStatus = HTTPStatus.INTERNAL_SERVER_ERROR,
        exit_code: int | None = None,
        stderr: str | None = None,
        detail: Mapping[str, object] | None = None,
        timeout: bool = False,
    ):
        super().__init__(message)
        self.status = status
        self.exit_code = exit_code
        self.stderr = stderr
        self.detail = dict(detail or {})
        self.timeout = timeout


def _http_status_from_exit(exit_code: int) -> HTTPStatus:
    if exit_code == 0:
        return HTTPStatus.OK
    if exit_code == 10:
        return HTTPStatus.OK
    if exit_code == 2:
        return HTTPStatus.BAD_REQUEST
    return HTTPStatus.INTERNAL_SERVER_ERROR


def _env_flag(name: str, default: bool = False) -> bool:
    value = os.environ.get(name)
    parsed = _coerce_boolish(value)
    if parsed is None:
        return default
    return parsed


def _coerce_boolish(value: Any) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return None


def _agent_settings() -> tuple[Path, float]:
    socket_env = os.environ.get("MCBRIDGE_AGENT_SOCKET", str(DEFAULT_AGENT_SOCKET))
    timeout_env = os.environ.get("MCBRIDGE_AGENT_TIMEOUT")
    timeout = float(timeout_env) if timeout_env else DEFAULT_AGENT_TIMEOUT
    return Path(socket_env), timeout


def _agent_client(timeout: float | None = None) -> AgentClient:
    socket_path, default_timeout = _agent_settings()
    return AgentClient(socket_path, timeout=timeout or default_timeout)


def _agent_unavailable_error(exc: Exception, *, hint: str | None = AGENT_UNAVAILABLE_HINT) -> WebCommandError:
    socket_path, _ = _agent_settings()
    error_message = str(exc) if exc is not None else ""
    hint_text = (hint or "").strip() or None
    detail: dict[str, object] = {"agent_socket": str(socket_path)}
    message_parts = [f"mcbridge agent unavailable at {socket_path}"]
    if error_message:
        message_parts.append(error_message)
        detail["error"] = error_message
    if hint_text:
        detail["hint"] = hint_text
    message = ": ".join(message_parts) if len(message_parts) > 1 else message_parts[0]
    if hint_text:
        message = f"{message} ({hint_text})"
    return WebCommandError(
        message,
        status=HTTPStatus.SERVICE_UNAVAILABLE,
        exit_code=3,
        stderr=error_message or None,
        detail=detail,
    )


def _exception_to_web_error(exc: Exception) -> WebCommandError:
    if isinstance(exc, WebCommandError):
        return exc
    if isinstance(exc, AgentError):
        detail = getattr(exc, "detail", {})
        if isinstance(detail, Mapping) and detail.get("timeout") is True:
            return WebCommandError(
                "",
                status=HTTPStatus.GATEWAY_TIMEOUT,
                exit_code=3,
                detail={"timeout": True},
                timeout=True,
            )
        return _agent_unavailable_error(exc)
    if isinstance(exc, CliProxyError):
        return WebCommandError(str(exc), status=exc.status, exit_code=exc.exit_code)
    if isinstance(exc, PermissionError):
        message = str(exc)
        lowered = message.lower()
        if "mcbridge agent" in lowered or "agent unavailable" in lowered:
            return _agent_unavailable_error(exc)
        return WebCommandError(message, status=HTTPStatus.FORBIDDEN, exit_code=3, stderr=message)
    if isinstance(exc, ValueError):
        return WebCommandError(str(exc), status=HTTPStatus.BAD_REQUEST, exit_code=2, stderr=str(exc))
    if isinstance(exc, FileNotFoundError):
        return WebCommandError(str(exc), status=HTTPStatus.INTERNAL_SERVER_ERROR, exit_code=3, stderr=str(exc))
    if isinstance(exc, subprocess.CalledProcessError):
        detail = {
            "stdout": getattr(exc, "stdout", "") or "",
            "stderr": getattr(exc, "stderr", "") or "",
            "returncode": exc.returncode,
        }
        stderr = detail["stderr"] or None
        detail = {key: value for key, value in detail.items() if value not in ("", None)}
        return WebCommandError(
            str(exc),
            status=HTTPStatus.INTERNAL_SERVER_ERROR,
            exit_code=exc.returncode or 3,
            stderr=stderr,
            detail=detail,
        )
    if isinstance(exc, RuntimeError):
        return WebCommandError(str(exc), status=HTTPStatus.INTERNAL_SERVER_ERROR, exit_code=3, stderr=str(exc))
    return WebCommandError("Unexpected server error.", status=HTTPStatus.INTERNAL_SERVER_ERROR)


def _cli_base_command() -> list[str]:
    override = os.environ.get("MCBRIDGE_CLI_BIN", "").strip()
    if override:
        parsed = shlex.split(override)
        if not parsed:
            raise CliProxyError("MCBRIDGE_CLI_BIN was set but empty.")
        return parsed
    return [sys.executable, "-m", "mcbridge"]


def _cli_env() -> Mapping[str, str]:
    return dict(os.environ)


def _systemctl(args: Sequence[str], *, allow_local_fallback: bool = False) -> dict[str, object]:
    command = ["systemctl", *args]
    try:
        process = _agent_client().run_command(command)
    except AgentError as exc:
        if not allow_local_fallback:
            raise _agent_unavailable_error(exc)
        try:
            completed = subprocess.run(command, capture_output=True, text=True, env=_cli_env(), check=False)
        except FileNotFoundError as file_exc:
            return {
                "command": command,
                "stdout": "",
                "stderr": str(file_exc),
                "returncode": 127,
                "error": str(file_exc),
            }
        except subprocess.SubprocessError as sub_exc:  # pragma: no cover - defensive
            return {
                "command": command,
                "stdout": getattr(sub_exc, "stdout", ""),
                "stderr": getattr(sub_exc, "stderr", str(sub_exc)),
                "returncode": None,
                "error": str(sub_exc),
            }
        return {"command": command, "stdout": completed.stdout, "stderr": completed.stderr, "returncode": completed.returncode}
    except Exception as exc:  # pragma: no cover - defensive
        return {
            "command": command,
            "stdout": "",
            "stderr": str(exc),
            "returncode": None,
            "error": str(exc),
        }

    return {"command": command, "stdout": process.stdout, "stderr": process.stderr, "returncode": process.returncode}


def _write_file(path: Path, contents: str, *, dry_run: bool, allow_local_fallback: bool = False) -> dict[str, object]:
    try:
        current = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = ""
    except OSError as exc:
        return {"status": "error", "path": str(path), "error": str(exc)}

    diff = diff_text(current, contents, fromfile=str(path), tofile=f"{path} (candidate)")
    changed = current != contents
    result: dict[str, object] = {
        "status": "planned" if changed else "unchanged",
        "path": str(path),
        "changed": changed,
        "diff": diff,
        "applied": False,
    }
    if dry_run:
        return result

    try:
        response = _agent_client().write_file(path, contents, mode=0o664)
    except AgentError as exc:
        if not allow_local_fallback:
            raise _agent_unavailable_error(exc)
        try:
            ensure_parent(path)
            path.write_text(contents, encoding="utf-8")
            set_default_permissions(path)
        except Exception as local_exc:  # pragma: no cover - defensive
            result["status"] = "error"
            result["error"] = str(local_exc)
            return result
        response = {"status": "ok"}
    except Exception as exc:  # pragma: no cover - defensive
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    if response.get("status") not in {None, "ok"}:
        result["status"] = "error"
        result["error"] = str(response)
        return result

    try:
        set_default_permissions(path)
    except Exception as exc:  # pragma: no cover - defensive
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    result["applied"] = True
    result["status"] = "updated" if changed else "unchanged"
    return result


def _generate_self_signed_certificate(
    cert_path: Path, key_path: Path, *, dry_run: bool, allow_local_fallback: bool = False
) -> dict[str, object]:
    command = [
        "openssl",
        "req",
        "-x509",
        "-newkey",
        "rsa:2048",
        "-sha256",
        "-days",
        str(DEFAULT_TLS_DAYS),
        "-nodes",
        "-subj",
        "/CN=mcbridge",
        "-keyout",
        str(key_path),
        "-out",
        str(cert_path),
    ]
    result: dict[str, object] = {
        "status": "planned",
        "command": command,
        "returncode": None,
        "stdout": "",
        "stderr": "",
        "cert": str(cert_path),
        "key": str(key_path),
    }

    if dry_run:
        return result
    parents = {cert_path.parent, key_path.parent}
    steps: list[Mapping[str, object]] = [
        {"action": "run", "command": ["install", "-d", str(parent)]} for parent in parents
    ]
    steps.append({"action": "run", "command": command})

    try:
        response = _agent_client().apply_plan(steps)
    except AgentError as exc:
        if not allow_local_fallback:
            raise _agent_unavailable_error(exc)
        try:
            for parent in parents:
                parent.mkdir(parents=True, exist_ok=True)
            process = subprocess.run(command, capture_output=True, text=True, check=False)
        except Exception as local_exc:  # pragma: no cover - defensive
            result["status"] = "error"
            result["stderr"] = str(local_exc)
            result["error"] = str(local_exc)
            return result
        plan_results = [{"returncode": process.returncode, "stdout": process.stdout, "stderr": process.stderr}]
    except Exception as exc:  # pragma: no cover - defensive
        result["status"] = "error"
        result["stderr"] = str(exc)
        result["error"] = str(exc)
        return result
    else:
        plan_results = response.get("results") or []
    errors = [entry for entry in plan_results if entry.get("status") == "error"]
    if errors:
        first_error = errors[0]
        result["status"] = "error"
        result["stderr"] = str(first_error.get("stderr") or first_error.get("error") or "")
        result["error"] = str(first_error.get("error") or "Failed to execute plan.")
        result["returncode"] = first_error.get("returncode")
        return result

    command_result = plan_results[-1] if plan_results else {}
    result["returncode"] = command_result.get("returncode")
    result["stdout"] = command_result.get("stdout", "")
    result["stderr"] = command_result.get("stderr", "")
    if result["returncode"] not in (0, None):
        result["status"] = "error"
        return result

    set_default_permissions(cert_path)
    set_default_permissions(key_path)

    result["status"] = "generated"
    result["cert"] = str(cert_path)
    result["key"] = str(key_path)
    return result


def _ensure_self_signed_certificate(
    cert_path: Path, key_path: Path, *, dry_run: bool, allow_local_fallback: bool = False
) -> dict[str, object]:
    cert_exists = cert_path.exists()
    key_exists = key_path.exists()

    if cert_exists and key_exists:
        return {"status": "unchanged", "cert": str(cert_path), "key": str(key_path)}

    return _generate_self_signed_certificate(cert_path, key_path, dry_run=dry_run, allow_local_fallback=allow_local_fallback)


def _web_service_template(*, host: str, port: int, http_port: int | None, tls_cert: Path | None, tls_key: Path | None) -> str:
    exec_start = f"{shlex.quote(WEB_BIN)} --host {shlex.quote(host)} --port {port}"
    if http_port:
        exec_start += f" --http-port {http_port}"
    env_lines: list[str] = [
        f"Environment=MCBRIDGE_CLI_BIN={WEB_CLI_BIN}",
        f"Environment=MCBRIDGE_ETC_DIR={ETC_DIR}",
        f"Environment=MCBRIDGE_WEB_CONFIG={DEFAULT_WEB_CONFIG_PATH}",
        "Environment=MCBRIDGE_AGENT_SOCKET=/run/mcbridge/agent.sock",
        "Environment=MCBRIDGE_WEB_USE_SUBPROCESS=1",
    ]
    capability_lines: list[str] = [
        "AmbientCapabilities=CAP_NET_BIND_SERVICE",
        "CapabilityBoundingSet=CAP_NET_BIND_SERVICE",
        "NoNewPrivileges=yes",
    ]
    if tls_cert:
        env_lines.append(f"Environment=MCBRIDGE_WEB_TLS_CERT={tls_cert}")
    if tls_key:
        env_lines.append(f"Environment=MCBRIDGE_WEB_TLS_KEY={tls_key}")
    if http_port:
        env_lines.append(f"Environment=MCBRIDGE_WEB_HTTP_PORT={http_port}")

    lines = [
        "[Unit]",
        "Description=mcbridge web console",
        "After=network-online.target mcbridge-agent.service",
        "Wants=network-online.target mcbridge-agent.service",
        "Requires=mcbridge-agent.service",
        "",
        "[Service]",
        "Type=simple",
        f"User={WEB_USER}",
        f"Group={WEB_GROUP}",
        "SupplementaryGroups=mcbridge-operators",
        "Restart=on-failure",
        "Environment=PYTHONUNBUFFERED=1",
        *env_lines,
        *capability_lines,
        f"ExecStart={exec_start}",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    return "\n".join(lines) + "\n"


def _write_web_config(
    password: str | None, tls_cert: Path | None, tls_key: Path | None, *, dry_run: bool, allow_local_fallback: bool = False
) -> dict[str, object]:
    existing = load_json(DEFAULT_WEB_CONFIG_PATH, default={})
    candidate = dict(existing)
    if password is not None:
        candidate["auth_password"] = password
    if tls_cert is not None:
        candidate["tls_cert"] = str(tls_cert)
    if tls_key is not None:
        candidate["tls_key"] = str(tls_key)
    existing_text = json.dumps(existing, indent=2, sort_keys=True) + "\n" if existing else ""
    candidate_text = json.dumps(candidate, indent=2, sort_keys=True) + "\n"
    result = _write_file(DEFAULT_WEB_CONFIG_PATH, candidate_text, dry_run=dry_run, allow_local_fallback=allow_local_fallback)
    result["candidate"] = candidate
    result["existing"] = existing
    result["diff"] = diff_text(
        existing_text, candidate_text, fromfile=str(DEFAULT_WEB_CONFIG_PATH), tofile=f"{DEFAULT_WEB_CONFIG_PATH} (candidate)"
    )
    return result

def _invoke_cli(args: Sequence[str], timeout: float | None = None) -> tuple[Mapping[str, Any], HTTPStatus]:
    base_command = _cli_base_command() + [str(part) for part in args]
    cli_command = ["bash", "-lc", shlex.join(base_command)]
    try:
        client = _agent_client(timeout=timeout)
        result = client.run_command(cli_command, env=_cli_env(), timeout=timeout)
    except AgentError as exc:
        detail = getattr(exc, "detail", {})
        if isinstance(detail, Mapping) and detail.get("timeout") is True:
            raise
        raise _agent_unavailable_error(exc)
    except Exception as exc:  # pragma: no cover - unexpected subprocess errors
        LOG.exception("mcbridge CLI invocation failed")
        raise CliProxyError("mcbridge CLI invocation failed.") from exc

    exit_code = result.returncode if result.returncode is not None else 1
    stdout = (result.stdout or "").strip()
    stderr = (result.stderr or "").strip()

    if not stdout:
        raise CliProxyError(
            "mcbridge CLI returned no output.", status=_http_status_from_exit(exit_code), exit_code=exit_code
        )

    try:
        payload = json.loads(stdout)
    except json.JSONDecodeError as exc:
        LOG.error("mcbridge CLI returned non-JSON output (exit %s): %s", exit_code, stdout)
        raise CliProxyError(
            "mcbridge CLI returned non-JSON output.", status=_http_status_from_exit(exit_code), exit_code=exit_code
        ) from exc

    if not isinstance(payload, Mapping):
        raise CliProxyError(
            "mcbridge CLI returned a non-object JSON response.",
            status=_http_status_from_exit(exit_code),
            exit_code=exit_code,
        )

    response_payload = dict(payload)
    response_payload.setdefault("exit_code", exit_code)
    if stderr:
        response_payload.setdefault("stderr", stderr)

    return response_payload, _http_status_from_exit(exit_code)


def _parse_in_process_args(args: Sequence[str]) -> argparse.Namespace:
    parser = cli_module._build_parser()
    stderr_capture = io.StringIO()
    with contextlib.redirect_stderr(stderr_capture):
        try:
            return parser.parse_args(args=list(args))
        except SystemExit as exc:  # pragma: no cover - defensive; API builds validated args
            code = exc.code if isinstance(exc.code, int) else 2
            message = "Invalid command arguments."
            stderr_output = stderr_capture.getvalue().strip() or None
            raise WebCommandError(message, status=HTTPStatus.BAD_REQUEST, exit_code=code, stderr=stderr_output)


def _select_handler(args: argparse.Namespace) -> Callable[[], Any]:
    if args.domain == "ap" and args.action == "status":
        return lambda: ap.status(debug_json=args.debug_json)
    if args.domain == "ap" and args.action == "update":
        return lambda: ap.update(
            ssid=args.ssid,
            password=args.password,
            channel=args.channel,
            subnet_octet=args.subnet_octet,
            dry_run=args.dry_run,
            force=args.force,
            force_restart=getattr(args, "force_restart", False),
            debug_json=args.debug_json,
        )
    if args.domain == "dns" and args.action == "status":
        return lambda: dns.status(debug_json=args.debug_json)
    if args.domain == "dns" and args.action == "update":
        return lambda: dns.update(
            redirect=args.redirect,
            target=args.target,
            dry_run=args.dry_run,
            force=args.force,
            debug_json=args.debug_json,
        )
    if args.domain == "dns" and args.action == "menu":
        return lambda: dns.menu(dry_run=args.dry_run, force=args.force, debug_json=args.debug_json)
    if args.domain == "upstream" and args.action == "apply":
        return lambda: upstream.apply_upstream()
    if args.domain == "upstream" and args.action == "activate":
        return lambda: upstream.activate_upstream(ssid=args.ssid, interface=args.interface)
    if args.domain == "init":
        return lambda: init_module.run(
            ssid=args.ssid,
            password=args.password,
            octet=args.subnet_octet,
            channel=args.channel,
            force=args.force,
            force_restart=args.force_restart,
            prepare_only=args.prepare_only,
            dry_run=args.dry_run,
            assume_yes=args.yes,
            debug_json=getattr(args, "debug_json", None),
            redirect=args.redirect,
            target=args.target,
        )
    raise WebCommandError("Unsupported command.", status=HTTPStatus.BAD_REQUEST, exit_code=2)


def _invoke_in_process(args: Sequence[str], timeout: float | None = None) -> tuple[Mapping[str, Any], HTTPStatus]:
    parsed_args = _parse_in_process_args(args)
    handler = _select_handler(parsed_args)
    try:
        result = handler()
    except SystemExit as exc:
        exit_code = exc.code if isinstance(exc.code, int) else 3
        message = str(exc) or "Command requires elevated privileges."
        raise WebCommandError(message, status=HTTPStatus.FORBIDDEN, exit_code=exit_code, stderr=str(exc) or None)
    except (PermissionError, FileNotFoundError, subprocess.CalledProcessError, RuntimeError, ValueError) as exc:
        raise _exception_to_web_error(exc)

    payload = dict(result.payload)
    exit_code = result.exit_code
    payload.setdefault("exit_code", exit_code)
    return payload, _http_status_from_exit(exit_code)


def _json_body() -> Mapping[str, Any]:
    body = request.get_json(silent=True)
    if body is None:
        raise BadRequest("Request body must be JSON.")
    if not isinstance(body, Mapping):
        raise BadRequest("JSON body must be an object.")
    return body


def _web_init_body(
    password: str | None = None,
    *,
    dry_run: bool = False,
    allow_local_fallback: bool = False,
    start_service: bool = True,
    systemctl_runner: Callable[[Sequence[str]], Mapping[str, object]] | None = None,
) -> WebInitResult:
    warnings: list[str] = []
    tls_cert_path = Path(WEB_TLS_CERT) if WEB_TLS_CERT else DEFAULT_TLS_CERT_PATH
    tls_key_path = Path(WEB_TLS_KEY) if WEB_TLS_KEY else DEFAULT_TLS_KEY_PATH
    tls_result = _ensure_self_signed_certificate(tls_cert_path, tls_key_path, dry_run=dry_run, allow_local_fallback=allow_local_fallback)
    http_port = WEB_HTTP_PORT if WEB_HTTP_PORT > 0 else None
    config_result = _write_web_config(
        password, tls_cert=tls_cert_path, tls_key=tls_key_path, dry_run=dry_run, allow_local_fallback=allow_local_fallback
    )

    service_contents = _web_service_template(host=WEB_HOST, port=WEB_PORT, http_port=http_port, tls_cert=tls_cert_path, tls_key=tls_key_path)
    service_result = _write_file(WEB_SERVICE_PATH, service_contents, dry_run=dry_run, allow_local_fallback=allow_local_fallback)

    daemon_reload: dict[str, object] | None = None
    enable_results: dict[str, object] = {}
    enable_errors: list[str] = []
    restart_result: dict[str, object] | None = None
    systemctl = systemctl_runner or (lambda args: _systemctl(list(args), allow_local_fallback=allow_local_fallback))

    if service_result.get("status") != "error":
        if not dry_run:
            daemon_reload = systemctl(["daemon-reload"])
        enable_results, enable_errors = ensure_services_enabled(
            (WEB_SERVICE_NAME,),
            runner=systemctl,
            dry_run=dry_run,
            start_services=start_service,
        )
        if not dry_run and start_service:
            restart_result = systemctl(["restart", WEB_SERVICE_NAME])

    candidate_config = config_result.get("candidate") or {}
    if not (candidate_config.get("auth_password") or candidate_config.get("auth_token")):
        warnings.append("No web authentication configured; supply --password to require Basic auth.")
    if http_port is None:
        warnings.append("HTTP listener disabled; only HTTPS will be started.")

    status = "ok"
    errors: list[str] = []
    if tls_result.get("status") == "error":
        status = "error"
        errors.append(str(tls_result.get("error") or "Failed to generate TLS assets."))
    if service_result.get("status") == "error":
        status = "error"
        errors.append(str(service_result.get("error") or "Failed to write service unit."))
    if enable_errors:
        status = "error"
        errors.extend(enable_errors)
    if restart_result and restart_result.get("returncode") not in (0, None):
        status = "warning" if status != "error" else status
        warnings.append(f"systemctl restart {WEB_SERVICE_NAME} returned {restart_result.get('returncode')}.")
    if warnings and status == "ok":
        status = "warning"

    applied = bool(
        tls_result.get("status") not in {"unchanged", "planned"}
        or config_result.get("applied")
        or service_result.get("applied")
        or any(entry.get("applied") for entry in enable_results.values())
        or (restart_result and restart_result.get("returncode") == 0)
    )

    payload = response_payload(
        {
            "status": status,
            "operation": "web_init",
            "config": config_result,
            "tls": tls_result,
            "service": {
                "unit": service_result,
                "daemon_reload": daemon_reload,
                "enable": enable_results,
                "restart": restart_result,
            },
            "warnings": warnings,
            "errors": errors,
            "applied": applied,
        },
        verbose=True,
    )
    exit_code = 0 if status in {"ok", "warning"} else 2
    return WebInitResult(payload=payload, exit_code=exit_code)


def web_init(
    password: str | None = None,
    *,
    dry_run: bool = False,
    allow_local_fallback: bool = False,
    start_service: bool = True,
    systemctl_runner: Callable[[Sequence[str]], Mapping[str, object]] | None = None,
) -> WebInitResult:
    try:
        return _web_init_body(
            password,
            dry_run=dry_run,
            allow_local_fallback=allow_local_fallback,
            start_service=start_service,
            systemctl_runner=systemctl_runner,
        )
    except WebCommandError as exc:
        error_payload = response_payload(
            {
                "status": "error",
                "operation": "web_init",
                "errors": [str(exc)],
                "detail": exc.detail,
                "stderr": exc.stderr,
            },
            verbose=True,
        )
        exit_code = exc.exit_code if exc.exit_code is not None else 3
        return WebInitResult(payload=error_payload, exit_code=exit_code)
    except AgentError as exc:  # pragma: no cover - defensive catch
        web_error = _agent_unavailable_error(exc)
        error_payload = response_payload(
            {
                "status": "error",
                "operation": "web_init",
                "errors": [str(web_error)],
                "detail": web_error.detail,
                "stderr": web_error.stderr,
            },
            verbose=True,
        )
        exit_code = web_error.exit_code if web_error.exit_code is not None else 3
        return WebInitResult(payload=error_payload, exit_code=exit_code)


def _coerce_bool(value: Any, field: str, *, default: _Bool = None) -> _Bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    raise BadRequest(f"{field} must be a boolean value.")


def _coerce_positive_int(value: Any, field: str, *, default: int | None = None) -> int | None:
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:  # pragma: no cover - covered by BadRequest branch
        raise BadRequest(f"{field} must be an integer.") from exc
    if parsed <= 0:
        raise BadRequest(f"{field} must be a positive integer.")
    return parsed


def _coerce_positive_float(value: Any, field: str, *, default: float | None = None) -> float | None:
    if value is None:
        return default
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:  # pragma: no cover - covered by BadRequest branch
        raise BadRequest(f"{field} must be a number.") from exc
    if parsed <= 0:
        raise BadRequest(f"{field} must be a positive number.")
    return parsed


def _coerce_str(value: Any, field: str, *, required: bool = False) -> str | None:
    if value is None:
        if required:
            raise BadRequest(f"{field} is required.")
        return None
    if not isinstance(value, str):
        raise BadRequest(f"{field} must be a string.")
    return value


def _error_response(
    message: str,
    status: HTTPStatus,
    *,
    exit_code: int | None = None,
    stderr: str | None = None,
    detail: Mapping[str, object] | None = None,
    timeout: bool | None = None,
):
    payload: dict[str, object] = {"status": "error", "message": message}
    if exit_code is not None:
        payload["exit_code"] = exit_code
    if stderr:
        payload["stderr"] = stderr
    if detail:
        payload["detail"] = detail
    if timeout is not None:
        payload["timeout"] = timeout
    return jsonify(payload), status


def _wifi_payload(profiles: list[dict[str, object]]) -> tuple[Any, HTTPStatus]:
    payload = {"status": "ok", "exit_code": 0, "profiles": profiles, "count": len(profiles)}
    return jsonify(payload), HTTPStatus.OK


def _parse_basic_password(header: str) -> str | None:
    try:
        encoded = header.split(None, 1)[1]
    except IndexError:
        return None
    try:
        decoded = base64.b64decode(encoded).decode()
    except (binascii.Error, UnicodeDecodeError):
        return None
    if ":" not in decoded:
        return None
    _, password = decoded.split(":", 1)
    return password


def _auth_error(*, basic_realm: str | None = None) -> tuple[Any, HTTPStatus]:
    response, status = _error_response("Authentication required.", HTTPStatus.UNAUTHORIZED)
    if basic_realm:
        response.headers["WWW-Authenticate"] = f'Basic realm="{basic_realm}", charset="UTF-8"'
    return response, status


def _runner_error_response(exc: Exception, *, fallback_detail: Mapping[str, object] | None = None):
    web_error = _exception_to_web_error(exc)
    detail = dict(web_error.detail)
    if fallback_detail:
        detail.setdefault("fallback_from", fallback_detail)
    return _error_response(
        str(web_error),
        web_error.status,
        exit_code=web_error.exit_code,
        stderr=web_error.stderr,
        detail=detail or None,
        timeout=web_error.timeout or None,
    )


def _validate_auth(config: WebConfig):
    if not config.requires_authentication:
        return None

    header = request.headers.get("Authorization", "")
    provided_token: str | None = None
    provided_password: str | None = None

    if header.lower().startswith("bearer "):
        provided_token = header.split(None, 1)[1].strip()
    elif header.lower().startswith("basic "):
        provided_password = _parse_basic_password(header)

    header_token = request.headers.get("X-Auth-Token") or request.headers.get("X-Mcbridge-Token")
    provided_token = provided_token or (header_token.strip() if header_token else None)

    if config.auth_token and provided_token == config.auth_token:
        return None
    if config.auth_password and provided_password == config.auth_password:
        return None

    basic_realm = "mcbridge" if config.auth_password else None
    return _auth_error(basic_realm=basic_realm)


def _add_flag(args: list[str], flag: str, enabled: bool | None) -> None:
    if enabled:
        args.append(flag)


def _add_option(args: list[str], flag: str, value: object | None) -> None:
    if value is not None:
        args.extend([flag, str(value)])


def _title_from_stem(stem: str) -> str:
    cleaned = stem.replace("_", " ").replace("-", " ").strip()
    if cleaned.lower() == "readme":
        return "README"
    if cleaned:
        return cleaned.title()
    return stem


def _load_docs_index(static_folder: str | None) -> list[DocEntry]:
    if not static_folder:
        return []
    docs_dir = Path(static_folder) / "docs"
    if not docs_dir.is_dir():
        return []

    docs: list[DocEntry] = []
    for path in docs_dir.glob("*.md"):
        slug = path.stem.lower()
        docs.append(DocEntry(slug=slug, title=_title_from_stem(path.stem), filename=path.name, path=path))

    docs.sort(key=lambda entry: (0 if entry.slug == "overview" else 1, entry.title.lower()))
    return docs


def _runner_accepts_timeout(runner: Callable[..., Any]) -> bool:
    try:
        signature = inspect.signature(runner)
    except (TypeError, ValueError):
        return False
    params = list(signature.parameters.values())
    if any(param.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD) for param in params):
        return True
    return len(params) >= 2


def _resolve_runner_preferences(preferred: bool | None) -> tuple[bool, bool]:
    env_preference = _coerce_boolish(os.environ.get("MCBRIDGE_WEB_USE_SUBPROCESS"))
    explicit_preference = preferred if preferred is not None else env_preference
    prefer_subprocess = explicit_preference if explicit_preference is not None else os.geteuid() != 0
    allow_subprocess_fallback = explicit_preference is None
    return prefer_subprocess, allow_subprocess_fallback


def _job_now() -> float:
    return time.time()


def _prune_jobs(now: float | None = None) -> None:
    cutoff = now if now is not None else _job_now()
    with JOB_LOCK:
        expired = [
            job_id
            for job_id, job in JOB_REGISTRY.items()
            if job.get("completed_at") is not None and cutoff - float(job["completed_at"]) > JOB_TTL_SECONDS
        ]
        for job_id in expired:
            JOB_REGISTRY.pop(job_id, None)


def _create_job() -> dict[str, Any]:
    job_id = str(uuid.uuid4())
    now = _job_now()
    job = {
        "job_id": job_id,
        "state": "running",
        "created_at": now,
        "updated_at": now,
        "completed_at": None,
        "payload": None,
        "error": None,
        "http_status": None,
    }
    with JOB_LOCK:
        JOB_REGISTRY[job_id] = job
    _prune_jobs(now)
    return dict(job)


def _update_job(job_id: str, **updates: Any) -> dict[str, Any] | None:
    with JOB_LOCK:
        job = JOB_REGISTRY.get(job_id)
        if not job:
            return None
        job.update(updates)
        return dict(job)


def _get_job(job_id: str) -> dict[str, Any] | None:
    with JOB_LOCK:
        job = JOB_REGISTRY.get(job_id)
        return dict(job) if job else None


def _job_payload(job: Mapping[str, Any]) -> dict[str, Any]:
    state = str(job.get("state") or "running")
    return {
        "job_id": job.get("job_id"),
        "state": state,
        "created_at": job.get("created_at"),
        "updated_at": job.get("updated_at"),
        "completed_at": job.get("completed_at"),
        "done": state in {"completed", "error"},
        "payload": job.get("payload"),
        "error": job.get("error"),
        "http_status": job.get("http_status"),
    }


def _is_privilege_error(exc: Exception) -> bool:
    if isinstance(exc, PermissionError):
        return True
    if isinstance(exc, WebCommandError) and exc.status == HTTPStatus.FORBIDDEN:
        return True
    return False


def _call_runner(
    runner: Callable[[Sequence[str], float | None], tuple[Mapping[str, Any], HTTPStatus]],
    args: list[str],
    *,
    fallback_runner: Callable[[Sequence[str], float | None], tuple[Mapping[str, Any], HTTPStatus]] | None = None,
    timeout: float | None = None,
) -> tuple[tuple[Mapping[str, Any], HTTPStatus] | None, tuple[Any, HTTPStatus] | None]:
    try:
        return runner(args, timeout), None
    except BadRequest:
        raise
    except Exception as exc:  # pragma: no cover - routed through _runner_error_response
        primary_error = _exception_to_web_error(exc)
        fallback_allowed = fallback_runner is not None and (
            _is_privilege_error(exc) or primary_error.status == HTTPStatus.SERVICE_UNAVAILABLE
        )
        if fallback_allowed:
            try:
                return fallback_runner(args, timeout), None
            except BadRequest:
                raise
            except Exception as fallback_exc:  # pragma: no cover - routed through _runner_error_response
                return None, _runner_error_response(fallback_exc, fallback_detail=primary_error.detail or None)
        return None, _runner_error_response(primary_error)


def _handle_cli(
    runner: Callable[[Sequence[str], float | None], tuple[Mapping[str, Any], HTTPStatus]],
    args: list[str],
    *,
    fallback_runner: Callable[[Sequence[str], float | None], tuple[Mapping[str, Any], HTTPStatus]] | None = None,
    timeout: float | None = None,
):
    result, error = _call_runner(runner, args, fallback_runner=fallback_runner, timeout=timeout)
    if error:
        return error

    payload, status = result

    response_payload = dict(payload)
    exit_code = int(response_payload.get("exit_code", 0) or 0)
    response_payload.setdefault("exit_code", exit_code)
    status = _http_status_from_exit(exit_code)
    return jsonify(response_payload), status


def create_app(
    cli_runner: Callable[[Sequence[str], float | None], tuple[Mapping[str, Any], HTTPStatus]] | None = None,
    web_config: WebConfig | None = None,
    *,
    use_subprocess_runner: bool | None = None,
) -> Flask:
    """Application factory for the mcbridge web API."""

    app = Flask(__name__, template_folder="templates", static_folder="static", static_url_path="/static")
    app.config["JSON_SORT_KEYS"] = False
    prefer_subprocess, allow_subprocess_fallback = _resolve_runner_preferences(use_subprocess_runner)
    runner = cli_runner or (_invoke_cli if prefer_subprocess else _invoke_in_process)
    if cli_runner is not None and not _runner_accepts_timeout(cli_runner):
        runner = lambda args, timeout=None: cli_runner(args)
    fallback_runner: Callable[[Sequence[str], float | None], tuple[Mapping[str, Any], HTTPStatus]] | None = None
    if cli_runner is None and allow_subprocess_fallback:
        fallback_runner = _invoke_in_process if prefer_subprocess else _invoke_cli
    config = web_config or load_web_config()
    app.config["WEB_CONFIG"] = config
    docs_index = _load_docs_index(app.static_folder)
    docs_map = {entry.slug: entry for entry in docs_index}
    app.config["DOCS_INDEX"] = docs_index

    def _dispatch_runner(args: list[str], *, timeout: float | None = None):
        return _handle_cli(runner, args, fallback_runner=fallback_runner, timeout=timeout)

    def _call_with_fallback(args: list[str], *, timeout: float | None = None):
        return _call_runner(runner, args, fallback_runner=fallback_runner, timeout=timeout)

    def _wifi_response(operation: Callable[[], list[dict[str, object]]]):
        try:
            profiles = operation()
        except BadRequest:
            raise
        except Exception as exc:  # pragma: no cover - routed through _runner_error_response
            return _runner_error_response(exc)
        return _wifi_payload(profiles)

    def _start_upstream_apply_job(*, timeout: float | None = None, prune_missing: bool = False) -> dict[str, Any]:
        job = _create_job()
        job_id = str(job["job_id"])

        def _run_job():
            with app.app_context():
                args = ["upstream", "apply"]
                _add_flag(args, "--prune-missing", prune_missing)
                result, error = _call_runner(runner, args, fallback_runner=fallback_runner, timeout=timeout)
            now = _job_now()
            if error:
                response, status = error
                payload = response.get_json(silent=True) if hasattr(response, "get_json") else None
                _update_job(
                    job_id,
                    state="error",
                    updated_at=now,
                    completed_at=now,
                    payload=payload,
                    error=payload,
                    http_status=status.value if isinstance(status, HTTPStatus) else status,
                )
                _prune_jobs(now)
                return
            payload, _ = result
            response_payload = dict(payload)
            exit_code = int(response_payload.get("exit_code", 0) or 0)
            response_payload.setdefault("exit_code", exit_code)
            http_status = _http_status_from_exit(exit_code)
            state = "completed" if exit_code == 0 else "error"
            _update_job(
                job_id,
                state=state,
                updated_at=now,
                completed_at=now,
                payload=response_payload,
                error=None,
                http_status=http_status.value,
            )
            _prune_jobs(now)

        thread = threading.Thread(
            target=_run_job,
            name=f"mcbridge-upstream-apply-{job_id}",
            daemon=True,
        )
        thread.start()
        return job

    @app.before_request
    def _require_authentication():
        failure = _validate_auth(config)
        if failure:
            return failure

    @app.errorhandler(BadRequest)
    def _bad_request(exc: BadRequest):  # pragma: no cover - simple error path
        return _error_response(str(exc.description or exc), HTTPStatus.BAD_REQUEST)

    @app.get("/ap/status")
    def ap_status():
        debug_json = _coerce_bool(request.args.get("debug_json"), "debug_json", default=None)
        args = ["ap", "status"]
        _add_flag(args, "--debug-json", debug_json)
        return _dispatch_runner(args)

    @app.post("/ap/update")
    def ap_update():
        body = _json_body()
        args = ["ap", "update"]
        _add_option(args, "--ssid", _coerce_str(body.get("ssid"), "ssid"))
        _add_option(args, "--password", _coerce_str(body.get("password"), "password"))
        _add_option(args, "--channel", _coerce_positive_int(body.get("channel"), "channel"))
        _add_option(args, "--octet", _coerce_positive_int(body.get("subnet_octet"), "subnet_octet"))
        _add_flag(args, "--dry-run", _coerce_bool(body.get("dry_run"), "dry_run", default=False))
        _add_flag(args, "--force", _coerce_bool(body.get("force"), "force", default=False))
        _add_flag(args, "--force-restart", _coerce_bool(body.get("force_restart"), "force_restart", default=False))
        _add_flag(args, "--debug-json", _coerce_bool(body.get("debug_json"), "debug_json", default=None))
        return _dispatch_runner(args)

    @app.get("/dns/status")
    def dns_status():
        debug_json = _coerce_bool(request.args.get("debug_json"), "debug_json", default=None)
        args = ["dns", "status"]
        _add_flag(args, "--debug-json", debug_json)
        return _dispatch_runner(args)

    @app.get("/dns/knownservers")
    def dns_known_servers():
        try:
            entries = _normalise_known_servers(load_json(KNOWN_SERVERS_JSON, default={}))
        except BadRequest:
            raise
        except Exception:
            LOG.exception("Failed to load known servers from %s", KNOWN_SERVERS_JSON)
            return _error_response("Unable to load known servers.", HTTPStatus.INTERNAL_SERVER_ERROR)

        payload = {"status": "ok", "entries": entries, "servers": entries, "count": len(entries), "exit_code": 0}
        return jsonify(payload), HTTPStatus.OK

    @app.get("/status")
    def combined_status():
        ap_result, ap_error = _call_with_fallback(["ap", "status"])
        if ap_error:
            return ap_error
        dns_result, dns_error = _call_with_fallback(["dns", "status"])
        if dns_error:
            return dns_error

        ap_payload, ap_http_status = ap_result
        dns_payload, dns_http_status = dns_result

        ap_section = dict(ap_payload or {})
        dns_section = dict(dns_payload or {})
        ap_section.setdefault("exit_code", 0)
        dns_section.setdefault("exit_code", 0)

        overall_status = "ok"
        for section in (ap_section, dns_section):
            status_value = str(section.get("status") or "").lower()
            if status_value == "error":
                overall_status = "error"
                break
            if status_value and status_value != "ok":
                overall_status = "warning"
        combined_exit = max(int(ap_section.get("exit_code") or 0), int(dns_section.get("exit_code") or 0))
        http_status = HTTPStatus(
            max(
                _http_status_from_exit(int(ap_section.get("exit_code") or 0)).value,
                _http_status_from_exit(int(dns_section.get("exit_code") or 0)).value,
            )
        )
        payload = {
            "status": overall_status,
            "exit_code": combined_exit,
            "ap": ap_section,
            "dns": dns_section,
        }
        return jsonify(payload), http_status

    @app.post("/dns/update")
    def dns_update():
        body = _json_body()
        args = ["dns", "update"]
        _add_option(args, "--redirect", _coerce_str(body.get("redirect"), "redirect"))
        _add_option(args, "--target", _coerce_str(body.get("target"), "target"))
        _add_flag(args, "--dry-run", _coerce_bool(body.get("dry_run"), "dry_run", default=False))
        _add_flag(args, "--force", _coerce_bool(body.get("force"), "force", default=False))
        _add_flag(args, "--debug-json", _coerce_bool(body.get("debug_json"), "debug_json", default=None))
        return _dispatch_runner(args)

    @app.get("/wifi/profiles")
    def wifi_profiles():
        return _wifi_response(lambda: wifi.list_profiles())

    @app.post("/wifi/profiles")
    def wifi_profiles_add():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        security = _coerce_str(body.get("security"), "security", required=True)
        priority = _coerce_positive_int(body.get("priority"), "priority")
        if priority is None:
            raise BadRequest("priority is required.")
        active = _coerce_bool(body.get("active"), "active", default=None)
        return _wifi_response(lambda: wifi.add_profile(ssid=ssid, priority=priority, security=security, active=active))

    @app.patch("/wifi/profiles")
    def wifi_profiles_update():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        priority = _coerce_positive_int(body.get("priority"), "priority", default=None)
        security = _coerce_str(body.get("security"), "security") if "security" in body else None
        active = _coerce_bool(body.get("active"), "active", default=None)
        return _wifi_response(lambda: wifi.update_profile(ssid=ssid, priority=priority, security=security, active=active))

    @app.delete("/wifi/profiles")
    def wifi_profiles_delete():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        return _wifi_response(lambda: wifi.remove_profile(ssid=ssid))

    @app.get("/upstream/profiles")
    def upstream_profiles():
        return _wifi_response(lambda: upstream.list_profiles())

    @app.get("/upstream/status")
    def upstream_status():
        try:
            payload = upstream.status()
        except BadRequest:
            raise
        except Exception as exc:  # pragma: no cover - routed through _runner_error_response
            return _runner_error_response(exc)
        return jsonify(payload), HTTPStatus.OK

    @app.post("/upstream/profiles")
    def upstream_profiles_add():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        security = _coerce_str(body.get("security"), "security", required=True)
        priority = _coerce_positive_int(body.get("priority"), "priority")
        if priority is None:
            raise BadRequest("priority is required.")
        password = body.get("password", "")
        if not isinstance(password, str):
            raise BadRequest("password must be a string.")
        return _wifi_response(
            lambda: upstream.add_profile(ssid=ssid, password=password, priority=priority, security=security)
        )

    @app.patch("/upstream/profiles")
    def upstream_profiles_update():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        priority = _coerce_positive_int(body.get("priority"), "priority", default=None)
        security = _coerce_str(body.get("security"), "security") if "security" in body else None
        password = body.get("password") if "password" in body else None
        if password is not None and not isinstance(password, str):
            raise BadRequest("password must be a string.")
        return _wifi_response(
            lambda: upstream.update_profile(ssid=ssid, password=password, priority=priority, security=security)
        )

    @app.delete("/upstream/profiles")
    def upstream_profiles_delete():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        return _wifi_response(lambda: upstream.remove_profile(ssid=ssid))

    @app.post("/upstream/system/forget")
    def upstream_system_forget():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        args = ["upstream", "forget"]
        _add_option(args, "--ssid", ssid)
        _add_option(args, "--interface", _coerce_str(body.get("interface"), "interface"))
        return _dispatch_runner(args)

    @app.post("/upstream/save-current")
    def upstream_save_current():
        return _wifi_response(lambda: upstream.save_current_config())

    @app.post("/upstream/apply")
    def upstream_apply():
        body = request.get_json(silent=True)
        if body is None:
            body = {}
        if not isinstance(body, Mapping):
            raise BadRequest("JSON body must be an object.")
        timeout = None
        if "timeout" in body:
            timeout = _coerce_positive_float(body.get("timeout"), "timeout")
        if timeout is None:
            timeout = config.agent_timeout
        prune_missing = config.upstream_prune_missing or False
        if "prune_missing" in body:
            prune_missing = _coerce_bool(body.get("prune_missing"), "prune_missing", default=prune_missing)
        job = _start_upstream_apply_job(timeout=timeout, prune_missing=bool(prune_missing))
        return jsonify(_job_payload(job)), HTTPStatus.ACCEPTED

    @app.get("/upstream/apply/status/<string:job_id>")
    def upstream_apply_status(job_id: str):
        _prune_jobs()
        job = _get_job(job_id)
        if not job:
            return _error_response("Upstream apply job not found.", HTTPStatus.NOT_FOUND)
        return jsonify(_job_payload(job)), HTTPStatus.OK

    @app.post("/upstream/activate")
    def upstream_activate():
        body = _json_body()
        ssid = _coerce_str(body.get("ssid"), "ssid", required=True)
        args = ["upstream", "activate"]
        _add_option(args, "--ssid", ssid)
        _add_option(args, "--interface", _coerce_str(body.get("interface"), "interface"))
        return _dispatch_runner(args)

    @app.post("/dns/menu")
    def dns_menu():
        body = _json_body()
        args = ["dns", "menu"]
        _add_flag(args, "--dry-run", _coerce_bool(body.get("dry_run"), "dry_run", default=False))
        _add_flag(args, "--force", _coerce_bool(body.get("force"), "force", default=False))
        _add_flag(args, "--debug-json", _coerce_bool(body.get("debug_json"), "debug_json", default=None))
        return _dispatch_runner(args)

    @app.post("/init")
    def init_run():
        body = _json_body()
        subnet_octet = _coerce_positive_int(body.get("subnet_octet") or body.get("octet"), "subnet_octet")
        channel = _coerce_positive_int(body.get("channel"), "channel")
        args = ["init"]
        _add_option(args, "--ssid", _coerce_str(body.get("ssid"), "ssid", required=True))
        _add_option(args, "--password", _coerce_str(body.get("password"), "password"))
        _add_option(args, "--octet", subnet_octet)
        _add_option(args, "--channel", channel)
        _add_option(args, "--target", _coerce_str(body.get("target"), "target", required=True))
        _add_option(args, "--redirect", _coerce_str(body.get("redirect"), "redirect"))
        _add_flag(args, "--force", _coerce_bool(body.get("force"), "force", default=False))
        force_restart = _coerce_bool(body.get("force_restart"), "force_restart", default=True)
        if force_restart is False:
            args.append("--no-force-restart")
        elif force_restart is True:
            args.append("--force-restart")
        _add_flag(args, "--prepare-only", _coerce_bool(body.get("prepare_only"), "prepare_only", default=False))
        _add_flag(args, "--dry-run", _coerce_bool(body.get("dry_run"), "dry_run", default=False))
        _add_flag(args, "--yes", _coerce_bool(body.get("assume_yes") or body.get("yes"), "assume_yes", default=False))
        _add_flag(args, "--debug-json", _coerce_bool(body.get("debug_json"), "debug_json", default=None))
        return _dispatch_runner(args)

    @app.get("/")
    def index_page():  # pragma: no cover - thin view wrapper
        return render_template("index.html", docs=docs_index)

    @app.get("/docs")
    def docs_page():  # pragma: no cover - thin view wrapper
        requested_slug = (request.args.get("doc") or "").lower()
        active_doc = requested_slug if requested_slug in docs_map else (docs_index[0].slug if docs_index else None)
        return render_template("docs.html", docs=docs_index, active_doc=active_doc)

    @app.get("/docs/content/<string:slug>")
    def docs_content(slug: str) -> Response:
        entry = docs_map.get(slug.lower())
        if not entry:
            return app.response_class("Document not found.", status=HTTPStatus.NOT_FOUND)

        try:
            content = entry.path.read_text(encoding="utf-8")
        except OSError:
            LOG.exception("Failed to read docs file: %s", entry.path)
            return app.response_class("Unable to read documentation.", status=HTTPStatus.INTERNAL_SERVER_ERROR)

        return app.response_class(content, mimetype="text/markdown")

    return app


def _serve_app(
    app: Flask,
    *,
    host: str,
    https_port: int | None,
    ssl_context: tuple[str, str] | None,
    http_port: int | None,
    debug: bool,
) -> None:
    app.debug = debug
    servers = []
    threads: list[threading.Thread] = []

    http_server = None
    if http_port:
        http_server = make_server(host, http_port, app)
        servers.append(http_server)
        if ssl_context and https_port:
            http_thread = threading.Thread(target=http_server.serve_forever, daemon=True)
            threads.append(http_thread)
            http_thread.start()
        LOG.info("HTTP server listening on %s:%s", host, http_port)

    https_server = None
    if ssl_context and https_port:
        https_server = make_server(host, https_port, app, ssl_context=ssl_context)
        servers.append(https_server)
        LOG.info("HTTPS server listening on %s:%s", host, https_port)

    primary_server = https_server or http_server
    if not primary_server:
        LOG.error("No servers configured to run; refusing to start.")
        return

    try:
        primary_server.serve_forever()
    except KeyboardInterrupt:  # pragma: no cover - interactive convenience
        LOG.info("Received interrupt; shutting down web servers.")
    finally:
        for server in servers:
            try:
                server.shutdown()
            except Exception:  # pragma: no cover - defensive cleanup
                addr = getattr(server, "server_address", (host, port))
                addr_host, addr_port = (addr + ("",))[:2] if isinstance(addr, tuple) else (host, port)
                LOG.exception("Failed to cleanly shut down server on %s:%s", addr_host, addr_port)
        for thread in threads:
            thread.join(timeout=2)


def main(argv: list[str] | None = None) -> None:
    args = sys.argv[1:] if argv is None else argv

    if args and args[0] == "init":
        init_parser = argparse.ArgumentParser(description="Install and enable mcbridge web console service")
        init_parser.add_argument("--password", help="Set HTTP Basic auth password for the web console")
        init_parser.add_argument("--dry-run", action="store_true", help="Preview changes without writing files or enabling services")
        parsed = init_parser.parse_args(args[1:])
        result = web_init(parsed.password, dry_run=parsed.dry_run)
        print(json.dumps(result.payload, indent=2))
        raise SystemExit(result.exit_code)

    parser = argparse.ArgumentParser(description="mcbridge web server")
    parser.add_argument("--host", default=WEB_HOST, help="Host/IP to bind")
    parser.add_argument("--port", default=WEB_PORT, type=int, help="HTTPS port to listen on (ignored when TLS is absent)")
    parser.add_argument(
        "--http-port",
        default=WEB_HTTP_PORT,
        type=int,
        help="HTTP port to listen on (set 0 to disable; required when TLS is absent)",
    )
    parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    runner_group = parser.add_mutually_exclusive_group()
    runner_group.add_argument(
        "--subprocess-runner",
        action="store_true",
        help="Proxy through the mcbridge CLI subprocess instead of in-process domain calls",
    )
    runner_group.add_argument(
        "--in-process-runner",
        action="store_true",
        help="Force in-process domain handlers instead of using the mcbridge CLI agent subprocess",
    )
    parsed = parser.parse_args(args)

    config = load_web_config()
    ssl_context = config.ssl_context
    http_port = parsed.http_port if parsed.http_port and parsed.http_port > 0 else None
    https_port: int | None = None

    if ssl_context:
        https_port = parsed.port
        LOG.info("Starting HTTPS server using cert %s", ssl_context[0])
    elif config.tls_cert or config.tls_key:
        LOG.warning("TLS partially configured (cert/key missing); starting HTTP only.")
    else:
        LOG.info("Starting HTTP server (no TLS cert/key configured).")

    if not ssl_context:
        if http_port is None:
            parser.error("TLS cert/key missing; provide --http-port to enable HTTP or configure TLS for HTTPS.")
        if parsed.port and parsed.port != http_port:
            LOG.warning(
                "TLS unavailable; ignoring --port=%s and listening for HTTP on --http-port=%s instead.",
                parsed.port,
                http_port,
            )

    if parsed.subprocess_runner:
        runner_preference: bool | None = True
    elif parsed.in_process_runner:
        runner_preference = False
    else:
        runner_preference = None

    app = create_app(web_config=config, use_subprocess_runner=runner_preference)
    _serve_app(
        app,
        host=parsed.host,
        https_port=https_port,
        ssl_context=ssl_context,
        http_port=http_port,
        debug=parsed.debug,
    )


__all__ = ["create_app", "load_web_config", "main", "web_init", "WebInitResult"]
