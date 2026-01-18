"""Initial provisioning orchestration for mcbridge."""

from __future__ import annotations

import getpass
import importlib.metadata
import importlib.resources
import json
import logging
import os
import inspect
from ipaddress import IPv4Network, ip_address, ip_network
import pwd
import re
import shutil
import subprocess
import sys
import grp
import textwrap
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Mapping, Sequence

from . import agent, ap, dns, upstream_dns
from .common import (
    AP_JSON,
    CONFIG_DIR,
    CONFIG_HISTORY_DIR,
    DEFAULT_DIR_MODE,
    DNS_OVERRIDES_JSON,
    FAILED_GENERATED_DIR,
    GENERATED_DIR,
    GENERATED_HISTORY_DIR,
    INITIALISED_MARKER,
    KNOWN_SERVERS_JSON,
    check_interface_exists,
    diff_text,
    ensure_parent,
    logger,
    load_dns_overrides_config,
    load_json,
    response_payload,
    save_json,
)
from . import privileges
from .paths import ETC_DIR
from . import systemd_units
from .service_enablement import ensure_services_enabled

LOG = logging.getLogger(__name__)

SSID_PATTERN = re.compile(r"^[\x20-\x7E]{1,32}$")
PASSWORD_PATTERN = re.compile(r"^[\x20-\x7E]{8,63}$")
VALID_CHANNELS = set(range(1, 14))
DEFAULT_CHANNEL = 6
AP_INTERFACE = os.environ.get("MCBRIDGE_AP_INTERFACE", "wlan0ap")
UPSTREAM_INTERFACE = os.environ.get("MCBRIDGE_UPSTREAM_INTERFACE", "wlan0")
WLAN0AP_SERVICE_PATH = Path(os.environ.get("MCBRIDGE_WLAN0AP_SERVICE", "/etc/systemd/system/wlan0ap.service"))
AGENT_SERVICE_PATH = Path(os.environ.get("MCBRIDGE_AGENT_SERVICE", "/etc/systemd/system/mcbridge-agent.service"))
POLKIT_RULES_PATH = Path(os.environ.get("MCBRIDGE_POLKIT_RULES", "/etc/polkit-1/rules.d/90-mcbridge.rules"))
SYSCTL_CONF_PATH = Path(os.environ.get("MCBRIDGE_SYSCTL_CONF", "/etc/sysctl.d/99-mcbridge.conf"))
IPTABLES_RULES_V4 = Path(os.environ.get("MCBRIDGE_IPTABLES_RULES_V4", "/etc/iptables/rules.v4"))
SUDOERS_POLICY_PATH = Path(os.environ.get("MCBRIDGE_SUDOERS_DROPIN", "/etc/sudoers.d/mcbridge"))
WLAN0AP_IP_REMEDIATION = (
    "Retry: systemctl daemon-reload && systemctl enable --now wlan0ap.service wlan0ap-ip.service. "
    "Check 'systemctl status wlan0ap.service wlan0ap-ip.service' for detailed errors."
)
SERVICE_USER = "mcbridge"
SERVICE_GROUP = "mcbridge"
OPERATOR_GROUP = "mcbridge-operators"
SERVICE_HOME = Path("/var/lib/mcbridge")
AGENT_SOCKET_PATH = Path(os.environ.get("MCBRIDGE_AGENT_SOCKET", str(agent.DEFAULT_SOCKET)))
REQUIRED_SERVICES = (
    "mcbridge-agent.service",
    "mcbridge-web.service",
    "hostapd.service",
    "dnsmasq.service",
)
ADMIN_PATH = "/usr/sbin:/usr/bin:/sbin:/bin"


@dataclass
class PrivilegeContext:
    agent_ready: bool = False
    agent_checked: bool = False
    agent_error: str | None = None
    used_local: bool = False
    force_local: bool = False
    agent_failures: list[Mapping[str, object]] = field(default_factory=list)
    preflight: Mapping[str, Any] | None = None

    def mark_local(self, reason: str | None = None) -> None:
        self.used_local = True
        if reason and not self.agent_error:
            self.agent_error = reason

    def refresh_agent_health(self, *, force: bool = False) -> bool:
        if self.force_local:
            return False
        if self.agent_ready and not force:
            return True
        healthy, error = _agent_health_check()
        self.agent_ready = healthy
        self.agent_checked = True
        if not healthy:
            self.agent_error = error or self.agent_error
        return healthy


def _agent_health_check() -> tuple[bool, str | None]:
    if not AGENT_SOCKET_PATH.exists():
        return False, f"Agent socket missing at {AGENT_SOCKET_PATH}"

    try:
        response = agent.AgentClient(AGENT_SOCKET_PATH).ping()
    except Exception as exc:  # pragma: no cover - transport failures
        return False, str(exc)

    if isinstance(response, Mapping) and response.get("status") in (None, "ok"):
        return True, None

    return False, f"Agent ping failed: {response}"


def _required_agent_commands() -> list[str]:
    return [
        "bash",
        "groupadd",
        "install",
        "iptables-save",
        "mcbridge-agent-socket-helper",
        "systemctl",
        "useradd",
        "usermod",
    ]


def _agent_preflight(ctx: PrivilegeContext, required_commands: Sequence[str]) -> Mapping[str, Any]:
    socket_present = AGENT_SOCKET_PATH.exists()
    ping_ok = False
    ping_error: str | None = None
    allowlist_missing = [command for command in required_commands if not agent._allowed_command([command])]

    if socket_present:
        ping_ok = ctx.refresh_agent_health(force=True)
        ping_error = ctx.agent_error if not ping_ok else None
    else:
        ping_error = f"Agent socket missing at {AGENT_SOCKET_PATH}"
        ctx.agent_ready = False
        ctx.agent_checked = True

    preflight_status = "ok"
    fallback_reason = None
    if allowlist_missing:
        fallback_reason = f"Agent allowlist missing commands: {', '.join(allowlist_missing)}"
    elif not socket_present or not ping_ok:
        fallback_reason = ping_error

    if fallback_reason:
        preflight_status = "local_fallback"
        ctx.mark_local(fallback_reason)
        ctx.agent_ready = False
        ctx.force_local = True
        LOG.info("Agent preflight failed: %s. Using local execution where possible.", fallback_reason)

    preflight = {
        "status": preflight_status,
        "agent_socket_present": socket_present,
        "agent_ping": {"ok": bool(ping_ok), "error": ping_error},
        "allowlist": {
            "required": list(required_commands),
            "missing": allowlist_missing,
            "ok": not allowlist_missing,
        },
    }

    if fallback_reason:
        preflight["fallback_reason"] = fallback_reason

    ctx.preflight = preflight
    return preflight


def _admin_env(extra: Mapping[str, str] | None = None) -> dict[str, str]:
    env = {"PATH": ADMIN_PATH}
    if extra:
        env.update(extra)
    return env


def _invoke_with_optional_ctx(func, ctx: PrivilegeContext | None, *args, **kwargs):
    try:
        signature = inspect.signature(func)
        parameters = signature.parameters
        accepts_kwargs = any(param.kind == inspect.Parameter.VAR_KEYWORD for param in parameters.values())
    except (TypeError, ValueError):
        return func(*args, **kwargs)

    call_kwargs: dict[str, object] = {}
    if ctx is not None and ("ctx" in parameters or accepts_kwargs):
        call_kwargs["ctx"] = ctx
    for key, value in kwargs.items():
        if key in parameters or accepts_kwargs:
            call_kwargs[key] = value
    return func(*args, **call_kwargs)


def _which_admin(binary: str) -> str | None:
    try:
        return shutil.which(binary, path=ADMIN_PATH)
    except TypeError:
        return shutil.which(binary)


def _socket_helper_path() -> str:
    helper_candidate = shutil.which("mcbridge-agent-socket-helper")
    if isinstance(helper_candidate, str) and helper_candidate:
        return helper_candidate
    return "/usr/bin/mcbridge-agent-socket-helper"


@dataclass
class InitResult:
    payload: Mapping[str, Any]
    exit_code: int


def _service_account_exists(name: str) -> bool:
    try:
        pwd.getpwnam(name)
        return True
    except KeyError:
        return False


def _require_root() -> None:
    privileges.ensure_escalation_available()


def _group_exists(name: str) -> bool:
    try:
        grp.getgrnam(name)
        return True
    except KeyError:
        return False
    except Exception:
        return False


def _user_in_group(user: str, group: str) -> bool:
    try:
        group_entry = grp.getgrnam(group)
    except KeyError:
        return False
    except Exception:
        return False

    if user in group_entry.gr_mem:
        return True

    try:
        user_entry = pwd.getpwnam(user)
    except KeyError:
        return False
    except Exception:
        return False

    return user_entry.pw_gid == group_entry.gr_gid


def _installer_user() -> str | None:
    for env_key in ("MCBRIDGE_INSTALLER_USER", "SUDO_USER", "LOGNAME", "USER"):
        candidate = os.environ.get(env_key)
        if candidate:
            return candidate
    try:
        return getpass.getuser()
    except Exception:
        return None


def _privileged_status(command: Sequence[str], *, dry_run: bool, ctx: PrivilegeContext) -> dict[str, object]:
    if dry_run:
        return {"command": list(command), "status": "planned", "returncode": None}

    result = _invoke_with_optional_ctx(_run_privileged, ctx, command)
    result["status"] = "ok" if result.get("returncode") in (0,) else "error"
    return result


def _ensure_group_present(name: str, *, system: bool, dry_run: bool, ctx: PrivilegeContext) -> dict[str, object]:
    if _group_exists(name):
        return {"group": name, "status": "present"}

    args = ["groupadd"]
    if system:
        args.append("--system")
    args.append(name)
    result = _privileged_status(args, dry_run=dry_run, ctx=ctx)
    result["group"] = name
    return result


def _ensure_user_present(*, name: str, home: Path, group: str, dry_run: bool, ctx: PrivilegeContext) -> dict[str, object]:
    if _service_account_exists(name):
        return {"user": name, "status": "present"}

    command = ["useradd", "--system", "--home", str(home), "--shell", "/usr/sbin/nologin", "--gid", group, name]
    result = _privileged_status(command, dry_run=dry_run, ctx=ctx)
    result["user"] = name
    return result


def _ensure_owned_directory(
    path: Path, *, mode: int, service_user: str, operator_group: str, dry_run: bool, ctx: PrivilegeContext
) -> dict[str, object]:
    command = ["/usr/bin/install", "-d", f"-m{mode:o}", f"-o{service_user}", f"-g{operator_group}", str(path)]
    result = _privileged_status(command, dry_run=dry_run, ctx=ctx)
    result["path"] = str(path)
    return result


def _ensure_socket_directory(
    *,
    socket_path: Path,
    service_user: str,
    operator_group: str,
    mode: int = 0o770,
    recreate: bool = True,
    dry_run: bool,
    ctx: PrivilegeContext,
) -> dict[str, object]:
    directory = socket_path.parent
    helper_path, helper_owner, helper_home = agent.resolve_socket_helper(
        socket_helper=_socket_helper_path(), service_user=service_user
    )
    helper_path_valid = helper_path.exists()
    if helper_path_valid:
        command = [
            str(helper_path),
            "--socket",
            str(socket_path),
            "--service-user",
            service_user,
            "--operator-group",
            operator_group,
            "--mode",
            f"{mode:o}",
        ]
        if recreate:
            command.append("--recreate")
    else:
        command = [
            "/usr/bin/install",
            "-d",
            f"-m{mode:o}",
            f"-o{service_user}",
            f"-g{operator_group}",
            str(directory),
        ]
    result = _privileged_status(command, dry_run=dry_run, ctx=ctx)
    result["directory"] = str(directory)
    result["socket"] = str(socket_path)
    result["helper"] = str(helper_path)
    result["helper_owner"] = helper_owner
    result["helper_home"] = str(helper_home) if helper_home else None
    result["helper_invoked"] = helper_path_valid
    if helper_path_valid and result.get("status") == "error":
        result["message"] = "Agent socket helper failed."
        result["details"] = {
            "returncode": result.get("returncode"),
            "stderr": result.get("stderr"),
        }
    return result


def _ensure_group_membership(*, user: str, group: str, dry_run: bool, ctx: PrivilegeContext) -> dict[str, object]:
    result: dict[str, object] = {"user": user, "group": group}

    if _user_in_group(user, group):
        result["status"] = "present"
        return result

    if dry_run:
        update = _privileged_status(["usermod", "-a", "-G", group, user], dry_run=dry_run, ctx=ctx)
        result.update(update)
        return result

    if not (_service_account_exists(user) and _group_exists(group)):
        result["status"] = "missing_prerequisite"
        return result

    update = _privileged_status(["usermod", "-a", "-G", group, user], dry_run=dry_run, ctx=ctx)
    result.update(update)
    return result


def _principal_step_succeeded(step: Mapping[str, object]) -> bool:
    if not isinstance(step, Mapping):
        return False
    return step.get("status") in {"present", "ok", "planned"}


def _ensure_principals(
    *,
    service_user: str,
    service_group: str,
    operator_group: str,
    service_home: Path,
    dry_run: bool,
    ctx: PrivilegeContext,
) -> dict[str, object]:
    preflight_errors: list[str] = []
    path_value = os.environ.get("PATH", "")
    path_entries = [entry for entry in [*ADMIN_PATH.split(":"), *path_value.split(":")] if entry]
    path_contains_sbin = "/usr/sbin" in path_entries or "/sbin" in path_entries
    helper_binary = shutil.which("mcbridge-agent-socket-helper")
    required_binaries = [
        ("groupadd", _which_admin("groupadd")),
        ("useradd", _which_admin("useradd")),
        ("/usr/bin/install", "/usr/bin/install" if Path("/usr/bin/install").exists() else None),
    ]
    if helper_binary:
        required_binaries.append(("mcbridge-agent-socket-helper", helper_binary))
    for binary, resolved in required_binaries:
        if resolved:
            continue
        remediation = f"Install or make {binary} available in PATH before retrying."
        preflight_errors.append(f"Missing required binary: {binary}. {remediation}")

    if not path_contains_sbin:
        preflight_errors.append(
            "PATH is missing /usr/sbin or /sbin; ensure privileged administration binaries are discoverable."
        )

    if preflight_errors:
        return {
            "status": "error",
            "message": "Preflight checks failed.",
            "details": preflight_errors,
        }

    installer = _installer_user()
    steps = {
        "service_group": _ensure_group_present(service_group, system=True, dry_run=dry_run, ctx=ctx),
        "operator_group": _ensure_group_present(operator_group, system=False, dry_run=dry_run, ctx=ctx),
        "service_user": _ensure_user_present(
            name=service_user, home=service_home, group=service_group, dry_run=dry_run, ctx=ctx
        ),
        "directories": [],
        "installer_group_membership": None,
        "service_operator_membership": None,
        "agent_socket": None,
    }

    if not (_principal_step_succeeded(steps["service_user"]) and _principal_step_succeeded(steps["operator_group"])):
        return {
            "status": "error",
            "message": "Service user/operator group setup failed. Resolve user/group creation before retrying.",
            "details": [steps["operator_group"], steps["service_user"]],
        }

    critical_dirs = [
        ETC_DIR,
        CONFIG_DIR,
        CONFIG_HISTORY_DIR,
        GENERATED_DIR,
        GENERATED_HISTORY_DIR,
        FAILED_GENERATED_DIR,
    ]
    for path in critical_dirs:
        steps["directories"].append(
            _ensure_owned_directory(
                path,
                mode=DEFAULT_DIR_MODE,
                service_user=service_user,
                operator_group=operator_group,
                dry_run=dry_run,
                ctx=ctx,
            )
        )

    if installer and installer not in {service_user, "root"}:
        steps["installer_group_membership"] = _privileged_status(
            ["usermod", "-a", "-G", operator_group, installer],
            dry_run=dry_run,
            ctx=ctx,
        )
        steps["installer_group_membership"]["user"] = installer
    steps["service_operator_membership"] = _invoke_with_optional_ctx(
        _ensure_group_membership, ctx, user=service_user, group=operator_group, dry_run=dry_run
    )
    helper_path, helper_owner, _ = agent.resolve_socket_helper(
        socket_helper=_socket_helper_path(), service_user=service_user
    )
    steps["agent_socket"] = _ensure_socket_directory(
        socket_path=AGENT_SOCKET_PATH,
        service_user=service_user,
        operator_group=operator_group,
        mode=DEFAULT_DIR_MODE,
        recreate=True,
        dry_run=dry_run,
        ctx=ctx,
    )

    if helper_owner and helper_owner != service_user:
        steps["agent_socket"]["warning"] = {
            "status": "warning",
            "message": (
                "Resolved mcbridge-agent-socket-helper path is under a different user's home."
                " Install mcbridge system-wide or override the socket helper path to one accessible by the service account."
            ),
            "path": str(helper_path),
            "owner": helper_owner,
        }

    return steps


def _sudoers_policy(operator_group: str) -> str:
    systemctl_candidates = [
        path for path in ("/bin/systemctl", "/usr/bin/systemctl") if Path(path).exists()
    ] or ["/bin/systemctl"]
    units = [
        "mcbridge-agent.service",
        "mcbridge-web.service",
        "hostapd.service",
        "dnsmasq.service",
    ]
    actions = ("start", "stop", "restart", "status")
    commands: list[str] = []
    for systemctl_path in systemctl_candidates:
        for action in actions:
            for unit in units:
                commands.append(f"{systemctl_path} {action} {unit}")
    socket_helper = _socket_helper_path()
    commands.extend([socket_helper, f"{socket_helper} *"])

    cmnd_alias = ", \\\n  ".join(commands)
    return textwrap.dedent(
        f"""\
        # mcbridge operator privileges (install-managed)
        Defaults:%{operator_group} !requiretty
        Cmnd_Alias MCBRIDGE_CMDS = \\
          {cmnd_alias}
        %{operator_group} ALL=(root) NOPASSWD: MCBRIDGE_CMDS
        """
    )


def _polkit_rules(operator_group: str) -> str:
    allowed_units = [
        "mcbridge-agent.service",
        "mcbridge-web.service",
        "hostapd.service",
        "dnsmasq.service",
    ]
    allowed_regex = "|".join(allowed_units)
    return textwrap.dedent(
        f"""\
        // mcbridge operator privileges (install-managed)
        polkit.addRule(function(action, subject) {{
            if ((action.id === "org.freedesktop.systemd1.manage-units" || action.id === "org.freedesktop.systemd1.manage-units.restart") &&
                subject.isInGroup("{operator_group}") &&
                action.lookup("unit") && /^(?:{allowed_regex})$/.test(action.lookup("unit"))) {{
                return polkit.Result.YES;
            }}
        }});
        """
    )


def _sync_operator_privilege_policy(*, operator_group: str, dry_run: bool) -> dict[str, object]:
    contents = _sudoers_policy(operator_group)
    path = SUDOERS_POLICY_PATH
    try:
        current = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = ""
    except OSError as exc:
        return {"status": "error", "path": str(path), "error": str(exc)}

    changed = current != contents
    result: dict[str, object] = {
        "status": "planned" if changed else "unchanged",
        "path": str(path),
        "changed": changed,
        "applied": False,
    }

    if dry_run:
        return result

    try:
        privileges.sudo_write_file(path, contents, mode=0o440, owner="root", group="root")
    except PermissionError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    result["applied"] = changed
    result["status"] = "applied" if changed else "unchanged"
    return result


def _sync_polkit_policy(*, operator_group: str, dry_run: bool) -> dict[str, object]:
    contents = _polkit_rules(operator_group)
    path = POLKIT_RULES_PATH
    try:
        current = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = ""
    except OSError as exc:
        return {"status": "error", "path": str(path), "error": str(exc)}

    changed = current != contents
    result: dict[str, object] = {
        "status": "planned" if changed else "unchanged",
        "path": str(path),
        "changed": changed,
        "applied": False,
    }

    if dry_run:
        return result

    try:
        privileges.sudo_write_file(path, contents, mode=0o644, owner="root", group="root")
    except PermissionError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    result["applied"] = changed
    result["status"] = "applied" if changed else "unchanged"
    return result


def _debug_verbose(flag: bool | None = None) -> bool:
    env_value = os.environ.get("MCBRIDGE_DEBUG_JSON", "")
    env_enabled = env_value.lower() in {"1", "true", "yes", "on"}
    return bool(flag) or env_enabled


def _load_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    if not path.exists():
        return {}
    try:
        contents = path.read_text(encoding="utf-8")
    except OSError as exc:
        LOG.debug("Could not read %s: %s", path, exc)
        return {}
    data: dict[str, str] = {}
    for line in contents.splitlines():
        if "=" not in line:
            continue
        key, _, value = line.partition("=")
        data[key.strip()] = value.strip().strip('"')
    return data


def _load_default_known_servers() -> dict[str, Any] | None:
    resource = importlib.resources.files("mcbridge.resources").joinpath("knownservers.json")
    try:
        with importlib.resources.as_file(resource) as path:
            data = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError) as exc:
        LOG.debug("Unable to load packaged knownservers.json: %s", exc)
        return None

    if not isinstance(data, Mapping):
        LOG.debug("Packaged knownservers.json is not an object; got %s", type(data).__name__)
        return None

    redirects = data.get("redirects")
    if not isinstance(redirects, (list, tuple)):
        LOG.debug("Packaged knownservers.json missing 'redirects' array; got %s", type(redirects).__name__)
        return None
    return data


def _validate_arguments(
    *,
    ssid: str,
    password: str | None,
    octet: int,
    channel: int,
    redirect: str | None,
    target: str | None,
) -> tuple[list[str], dict[str, Any]]:
    errors: list[str] = []
    details: dict[str, Any] = {"validated": {}}
    target_value = (target or "").strip()
    redirect_value = (redirect or "").strip()

    if not SSID_PATTERN.fullmatch(ssid or ""):
        errors.append("SSID must be 1-32 printable ASCII characters without leading/trailing whitespace.")
    else:
        details["validated"]["ssid"] = ssid

    password_value = password or ""
    if password_value and not PASSWORD_PATTERN.fullmatch(password_value):
        errors.append("Password must be 8-63 printable ASCII characters (empty allowed for open APs).")
    elif password_value:
        details["validated"]["password_length"] = len(password_value)

    if octet < 1 or octet > 254:
        errors.append("Subnet octet must be between 1 and 254 (inclusive).")
    else:
        details["validated"]["octet"] = octet

    if channel not in VALID_CHANNELS:
        errors.append("Channel must be a valid 2.4 GHz channel (1-13).")
    else:
        details["validated"]["channel"] = channel

    if not target_value:
        errors.append("Target is required to seed or overwrite known servers during init.")
        details["validated"]["target"] = False
    else:
        details["validated"]["target"] = target_value

    if not _resolve_target(target, redirect):
        errors.append("Redirect requires a target.")
        details["validated"]["redirect"] = bool(redirect_value)

    return errors, details


def _resolve_target(target: str | None, redirect: str | None) -> bool:
    target_value = (target or "").strip()
    redirect_value = (redirect or "").strip()
    if redirect_value and not target_value:
        return False
    return True


def _network_from_gateway(value: str) -> IPv4Network | None:
    try:
        gateway = ip_address(value)
    except ValueError:
        return None

    try:
        return ip_network(f"{gateway}/24", strict=False)
    except ValueError:
        return None


def _parse_json_routes(output: str) -> list[IPv4Network]:
    routes: list[IPv4Network] = []
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return routes

    if not isinstance(data, list):
        return routes

    for entry in data:
        if not isinstance(entry, Mapping):
            continue

        destination = entry.get("dst") or entry.get("destination")
        if destination and destination != "default":
            try:
                network = ip_network(destination, strict=False)
            except ValueError:
                continue
            if isinstance(network, IPv4Network):
                routes.append(network)
            continue

        if destination == "default":
            gateway = entry.get("gateway")
            network = _network_from_gateway(str(gateway)) if gateway else None
            if network:
                routes.append(network)

    return routes


def _parse_text_routes(output: str) -> list[IPv4Network]:
    routes: list[IPv4Network] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue

        tokens = line.split()
        destination = tokens[0]
        if destination and destination != "default":
            try:
                network = ip_network(destination, strict=False)
            except ValueError:
                continue
            if isinstance(network, IPv4Network):
                routes.append(network)
            continue

        if destination == "default" and "via" in tokens:
            try:
                gateway = tokens[tokens.index("via") + 1]
            except (IndexError, ValueError):
                continue
            network = _network_from_gateway(gateway)
            if network:
                routes.append(network)

    return routes


def _dedupe_networks(networks: Sequence[IPv4Network]) -> list[IPv4Network]:
    unique: dict[str, IPv4Network] = {}
    for network in networks:
        key = str(network)
        if key not in unique:
            unique[key] = network
    return list(unique.values())


def _select_available_octet(upstream_networks: Sequence[IPv4Network], preferred_octet: int) -> int | None:
    def overlaps(candidate: int) -> bool:
        subnet = ip_network(f"192.168.{candidate}.0/24")
        return any(network.overlaps(subnet) for network in upstream_networks)

    if not overlaps(preferred_octet):
        return preferred_octet

    # Prefer nearby octets first (scan upward, then wrap).
    for candidate in range(preferred_octet + 1, 255):
        if not overlaps(candidate):
            return candidate
    for candidate in range(1, preferred_octet):
        if not overlaps(candidate):
            return candidate
    return None


def _detect_upstream_networks(interface: str) -> tuple[list[str], list[IPv4Network], dict[str, Any]]:
    errors: list[str] = []
    networks: list[IPv4Network] = []
    details: dict[str, Any] = {"interface": interface, "commands": []}

    commands = [
        ["ip", "-j", "-4", "route", "show", "dev", interface],
        ["ip", "-4", "route", "show", "dev", interface],
    ]

    for command in commands:
        command_entry = {"command": command}
        try:
            process = subprocess.run(command, capture_output=True, text=True)
        except FileNotFoundError as exc:  # pragma: no cover - platform specific
            errors.append("ip command is required but was not found on PATH.")
            command_entry["error"] = str(exc)
            details["commands"].append(command_entry)
            break

        command_entry["returncode"] = process.returncode
        parser = _parse_json_routes if "-j" in command else _parse_text_routes
        parsed_networks = parser(process.stdout or "")
        command_entry["networks"] = [str(network) for network in parsed_networks]
        details["commands"].append(command_entry)
        networks.extend(parsed_networks)

        if parsed_networks:
            break

    return errors, _dedupe_networks(networks), details


def _check_environment(*, octet: int, allow_octet_substitution: bool) -> tuple[list[str], dict[str, Any], int]:
    errors: list[str] = []
    details: dict[str, Any] = {"environment": {}}
    selected_octet = octet

    os_release = _load_os_release()
    distro_flags = {os_release.get("ID", ""), *(os_release.get("ID_LIKE", "").split())}
    details["environment"]["os_release"] = os_release
    if not any(flag.lower() == "debian" for flag in distro_flags if flag):
        errors.append("Host OS is not Debian-based (expected ID/ID_LIKE to include 'debian').")

    if not shutil.which("apt"):
        errors.append("apt is required but not available on PATH.")
    if not shutil.which("systemctl"):
        errors.append("systemctl is required but not available on PATH.")

    upstream_exists, upstream_check = check_interface_exists(UPSTREAM_INTERFACE)
    details["environment"]["upstream_interface_check"] = upstream_check
    if not upstream_exists:
        errors.append(f"Wireless interface {UPSTREAM_INTERFACE} is missing.")

    subnet = ip_network(f"192.168.{octet}.0/24")
    route_errors, upstream_networks, route_details = _detect_upstream_networks(UPSTREAM_INTERFACE)
    details["environment"]["upstream_routes"] = route_details
    details["environment"]["upstream_networks"] = [str(network) for network in upstream_networks]
    details["environment"]["ap_subnet"] = str(subnet)
    if route_errors:
        errors.extend(route_errors)
    else:
        conflicting = [network for network in upstream_networks if network.overlaps(subnet)]
        if conflicting:
            conflict = conflicting[0]
            alternative = _select_available_octet(upstream_networks, octet) if allow_octet_substitution else None
            if alternative and alternative != octet:
                selected_octet = alternative
                details["environment"]["octet_substitution"] = {
                    "requested": octet,
                    "selected": alternative,
                    "conflicts": [str(network) for network in conflicting],
                }
            else:
                errors.append(
                    (
                        f"AP subnet {subnet} overlaps with upstream network {conflict} on {UPSTREAM_INTERFACE}. "
                        "Choose a different --octet or use --force only if overlap is intentional."
                    )
                )
                details["environment"]["upstream_subnet_conflict"] = {
                    "ap_subnet": str(subnet),
                    "conflicts": [str(network) for network in conflicting],
                }

    return errors, details, selected_octet


def _plan_summary(octet: int, *, include_web: bool) -> list[str]:
    services_line = "- Enable services: hostapd, dnsmasq"
    if include_web:
        services_line = "- Enable services: mcbridge-agent, mcbridge-web, hostapd, dnsmasq"
    else:
        services_line = "- Enable services: mcbridge-agent, hostapd, dnsmasq"
    return [
        "mcbridge initialisation plan:",
        "",
        "- Install packages: hostapd, dnsmasq, iptables",
        f"- Create {AP_INTERFACE} access point",
        f"- Assign IP: 192.168.{octet}.1/24",
        f"- Enable NAT between {AP_INTERFACE} \u2192 {UPSTREAM_INTERFACE}",
        services_line,
        "",
        "This may interrupt network connectivity.",
    ]


def _confirm(summary: Sequence[str]) -> bool:
    print("\n".join(summary), file=sys.stderr)
    try:
        answer = input("Continue? [y/N] ").strip().lower()
    except EOFError:
        return False
    return answer in {"y", "yes"}


def _seed_configs(
    *,
    ssid: str,
    password: str,
    channel: int,
    octet: int,
    redirect: str | None,
    target: str | None,
    dry_run: bool,
) -> dict[str, Any]:
    ap_payload = {"ssid": ssid, "password": password, "channel": channel, "subnet_octet": octet}
    packaged_known_servers = _load_default_known_servers()
    base_known_servers = packaged_known_servers or {"redirects": []}
    known_servers_source = "packaged" if packaged_known_servers else "generated"
    known_servers_exists = KNOWN_SERVERS_JSON.exists()
    existing_known_servers: Mapping[str, Any] | None = None
    if known_servers_exists:
        existing_known_servers = load_json(KNOWN_SERVERS_JSON, default=base_known_servers)
        if isinstance(existing_known_servers, Mapping):
            known_servers = dict(existing_known_servers)
            known_servers_source = "existing"
        else:
            known_servers = json.loads(json.dumps(base_known_servers))
    else:
        known_servers = json.loads(json.dumps(base_known_servers))
    redirect_value = (redirect or "").strip()
    target_value = (target or "").strip()
    known_servers["target"] = target_value
    if redirect_value:
        new_entry = {"redirect": redirect_value}
        if target_value:
            new_entry["target"] = target_value
        existing_redirects = [
            entry for entry in known_servers.get("redirects", []) if entry.get("redirect") != redirect_value
        ]
        known_servers["redirects"] = [new_entry, *existing_redirects]
    known_servers_plan = {
        "path": str(KNOWN_SERVERS_JSON),
        "payload": known_servers,
        "source": known_servers_source,
        "status": "update_existing" if known_servers_exists else "seed_missing",
    }
    if known_servers_exists:
        known_servers_plan["note"] = "Init overwrites knownservers.json target with the provided --target."
    dns_payload = {"redirect": redirect_value, "target": target_value, "enabled": True} if (redirect_value or target_value) else None
    dns_plan = {
        "path": str(DNS_OVERRIDES_JSON),
        "payload": dns_payload or {},
        "status": "planned" if DNS_OVERRIDES_JSON.exists() else "seed_missing",
        "applied": False,
    }
    if not dns_payload:
        dns_plan["status"] = "skipped"

    plan = {
        "ap_json": {"path": str(AP_JSON), "payload": ap_payload},
        "knownservers_json": known_servers_plan,
        "dns_overrides_json": dns_plan,
    }

    if dry_run:
        plan["applied"] = False
        return plan

    ensure_parent(CONFIG_DIR)
    save_json(AP_JSON, ap_payload)
    if dns_payload:
        ensure_parent(DNS_OVERRIDES_JSON)
        save_json(DNS_OVERRIDES_JSON, dns_payload)
        dns_plan["status"] = "seeded"
        dns_plan["applied"] = True
    save_json(KNOWN_SERVERS_JSON, known_servers)
    known_servers_plan["status"] = "updated" if known_servers_exists else "seeded"
    known_servers_plan["applied"] = True
    plan["applied"] = True
    return plan


def _extract_provision_script() -> Path:
    resource = importlib.resources.files("mcbridge.resources").joinpath("provision.sh")
    with importlib.resources.as_file(resource) as script_path:
        contents = script_path.read_text(encoding="utf-8")
    target = Path("/var/tmp/mcbridge-provision.sh")
    try:
        privileges.sudo_write_file(target, contents, mode=0o755, owner="root", group="root")
    except PermissionError:
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(contents, encoding="utf-8")
        target.chmod(0o755)
    return target


def _parse_provision_status(stdout: str | None) -> str | None:
    if not stdout:
        return None
    for line in stdout.splitlines():
        if line.startswith("PROVISION_STATUS="):
            return line.partition("=")[2].strip() or None
    return None


@contextmanager
def _render_provisioning_artifacts(
    *,
    ap_config: Mapping[str, object],
    dns_overrides: Mapping[str, object],
    ap_ip_cidr: str,
    service_user: str,
    service_group: str,
) -> dict[str, str]:
    stack = ExitStack()
    temp_paths: dict[str, str] = {}

    def _write_temp(label: str, contents: str, suffix: str) -> None:
        temp_file = stack.enter_context(
            NamedTemporaryFile(
                "w",
                delete=False,
                encoding="utf-8",
                prefix=f"mcbridge-{label}-",
                suffix=suffix,
            )
        )
        temp_file.write(contents)
        temp_file.flush()
        temp_paths[label] = temp_file.name

    try:
        _write_temp("hostapd", ap._hostapd_template(ap_config), ".conf")
        dns_override_body = ap._dns_override_template(dns_overrides)
        _write_temp(
            "dnsmasq",
            ap._dnsmasq_template(ap_config, override_body=dns_override_body),
            ".conf",
        )
        _write_temp(
            "unit_wlan0ap",
            systemd_units.wlan0ap_service_template(
                ap_interface=AP_INTERFACE,
                upstream_interface=UPSTREAM_INTERFACE,
                service_user=service_user,
                service_group=service_group,
            ),
            ".service",
        )
        _write_temp(
            "unit_wlan0ap_ip",
            systemd_units.wlan0ap_ip_service_template(
                ap_interface=AP_INTERFACE,
                ap_ip_cidr=ap_ip_cidr,
                ap_service_unit=WLAN0AP_SERVICE_PATH.name,
                service_user=service_user,
                service_group=service_group,
            ),
            ".service",
        )
        _write_temp(
            "unit_upstream_dns_refresh",
            systemd_units.upstream_dns_refresh_service_template(
                upstream_interface=UPSTREAM_INTERFACE,
                debounce_seconds=upstream_dns.DEBOUNCE_SECONDS,
            ),
            ".service",
        )
        yield temp_paths
    finally:
        stack.close()
        for path in temp_paths.values():
            if not path:
                continue
            try:
                Path(path).unlink()
            except FileNotFoundError:
                continue
            except OSError as exc:  # pragma: no cover - defensive cleanup
                LOG.debug("Could not delete temporary provisioning file %s: %s", path, exc)


@contextmanager
def _maybe_render_provisioning_artifacts(
    *,
    ap_config: Mapping[str, object],
    dns_overrides: Mapping[str, object],
    ap_ip_cidr: str,
    service_user: str,
    service_group: str,
) -> dict[str, str]:
    try:
        with _render_provisioning_artifacts(
            ap_config=ap_config,
            dns_overrides=dns_overrides,
            ap_ip_cidr=ap_ip_cidr,
            service_user=service_user,
            service_group=service_group,
        ) as artifacts:
            yield artifacts
    except Exception as exc:  # pragma: no cover - defensive fallback
        LOG.warning("Unable to pre-render provisioning templates; falling back to inline rendering: %s", exc)
        yield {}


def _run_provisioning_script(
    *,
    ssid: str,
    password: str,
    octet: int,
    channel: int,
    force: bool,
    service_user: str,
    service_group: str,
    operator_group: str,
) -> dict[str, Any]:
    script_path = _extract_provision_script()
    ap_ip_cidr = f"192.168.{octet}.1/24"
    ap_config = load_json(AP_JSON, default={})
    dns_overrides_config, _ = load_dns_overrides_config(default={})
    # provision.sh relies on bash-only features; force a bash invocation to avoid POSIX sh errors.
    command = [
        "bash",
        str(script_path),
        "--ap-interface",
        AP_INTERFACE,
        "--upstream-interface",
        UPSTREAM_INTERFACE,
        "--ap-service-path",
        str(WLAN0AP_SERVICE_PATH),
        "--ap-ip-service-path",
        str(ap.WLAN0AP_IP_SERVICE),
        "--ap-ip-cidr",
        ap_ip_cidr,
        "--sysctl-conf-path",
        str(SYSCTL_CONF_PATH),
        "--iptables-rules-path",
        str(IPTABLES_RULES_V4),
    ]
    if force:
        command.append("--force")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin")}
    if "MCBRIDGE_ETC_DIR" in os.environ:
        env["MCBRIDGE_ETC_DIR"] = os.environ["MCBRIDGE_ETC_DIR"]
    env.update(
        {
            "MCBRIDGE_SERVICE_USER": service_user,
            "MCBRIDGE_SERVICE_GROUP": service_group,
            "MCBRIDGE_OPERATOR_GROUP": operator_group,
        }
    )

    LOG.info("Starting provisioning script at %s", script_path)
    print("Running mcbridge provisioning; output from provision.sh will follow...\n", file=sys.stdout)

    def _emit_provision_output(stdout: str | None, stderr: str | None) -> None:
        for stream in (stdout, stderr):
            if stream:
                end = "" if stream.endswith("\n") else "\n"
                print(stream, file=sys.stdout, end=end)

    with _maybe_render_provisioning_artifacts(
        ap_config=ap_config,
        dns_overrides=dns_overrides_config,
        ap_ip_cidr=ap_ip_cidr,
        service_user=service_user,
        service_group=service_group,
    ) as artifacts:
        if artifacts.get("hostapd"):
            command.extend(["--hostapd-template", artifacts["hostapd"]])
        if artifacts.get("dnsmasq"):
            command.extend(["--dnsmasq-template", artifacts["dnsmasq"]])
        if artifacts.get("unit_wlan0ap"):
            command.extend(["--unit-wlan0ap", artifacts["unit_wlan0ap"]])
        if artifacts.get("unit_wlan0ap_ip"):
            command.extend(["--unit-wlan0ap-ip", artifacts["unit_wlan0ap_ip"]])
        if artifacts.get("unit_upstream_dns_refresh"):
            command.extend(["--unit-upstream-dns-refresh", artifacts["unit_upstream_dns_refresh"]])

        try:
            process = privileges.sudo_run(command, env=env, check=True)
        except FileNotFoundError as exc:
            return {"command": command, "error": str(exc), "returncode": 127, "stdout": "", "stderr": str(exc)}
        except subprocess.CalledProcessError as exc:
            _emit_provision_output(exc.stdout, exc.stderr)
            return {
                "command": command,
                "returncode": exc.returncode,
                "stdout": exc.stdout,
                "stderr": exc.stderr,
                "error": "provisioning failed",
                "provision_status": _parse_provision_status(exc.stdout),
            }

    _emit_provision_output(process.stdout, process.stderr)
    LOG.info("Provisioning script finished with return code %s", process.returncode)

    return {
        "command": command,
        "returncode": process.returncode,
        "stdout": process.stdout,
        "stderr": process.stderr,
        "provision_status": _parse_provision_status(process.stdout),
        "path": str(script_path),
    }


def _run_systemctl(args: Sequence[str], *, ctx: PrivilegeContext | None = None) -> dict[str, object]:
    command = ["systemctl", *args]
    return _invoke_with_optional_ctx(_run_privileged, ctx, command)


def _systemctl_helper_missing_hint(socket_helper: Path, result: Mapping[str, object]) -> str | None:
    if socket_helper.exists():
        return None
    if result.get("returncode") in (0, None):
        return None

    combined_output = " ".join(str(result.get(key) or "") for key in ("stdout", "stderr")).lower()
    helper_path = str(socket_helper).lower()
    helper_name = socket_helper.name.lower()
    missing_markers = ("no such file", "not found", "failed to locate", "failed at step", "failed to execute")
    mentions_helper = helper_path in combined_output or helper_name in combined_output or "socket-helper" in combined_output
    if mentions_helper and any(marker in combined_output for marker in missing_markers):
        return (
            f"mcbridge-agent-socket-helper missing at {socket_helper}; "
            "install or place the helper, then rerun mcbridge init."
        )

    return (
        f"mcbridge-agent-socket-helper not found at {socket_helper}; "
        "install or place the helper, then rerun mcbridge init."
    )


def _collect_service_states(services: Sequence[str], *, ctx: PrivilegeContext) -> tuple[dict[str, object], list[str]]:
    states: dict[str, object] = {}
    errors: list[str] = []

    for service in services:
        result = _invoke_with_optional_ctx(_run_systemctl, ctx, ["is-active", service])
        stdout = str(result.get("stdout") or "").strip()
        if stdout:
            state = stdout
        elif result.get("returncode") == 0:
            state = "active"
        else:
            state = "unknown"
        states[service] = {"state": state, "check": result}
        if result.get("returncode") not in (0,) or state != "active":
            remediation = f"Service {service} is {state}; run 'systemctl status {service}' for details and ensure it is running."
            errors.append(remediation)

    return states, errors


def _run_command(command: Sequence[str]) -> dict[str, object]:
    try:
        process = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError as exc:
        return {
            "command": list(command),
            "stdout": "",
            "stderr": str(exc),
            "returncode": 127,
            "error": str(exc),
        }
    except subprocess.SubprocessError as exc:
        return {
            "command": list(command),
            "stdout": getattr(exc, "stdout", ""),
            "stderr": getattr(exc, "stderr", str(exc)),
            "returncode": None,
            "error": str(exc),
        }

    return {
        "command": list(command),
        "stdout": process.stdout,
        "stderr": process.stderr,
        "returncode": process.returncode,
    }


def _run_privileged(
    command: Sequence[str],
    *,
    ctx: PrivilegeContext | None = None,
    env: Mapping[str, str] | None = None,
    text: bool = True,
    check: bool = False,
    input: str | None = None,
    timeout: float | None = None,
) -> dict[str, object]:
    ctx = ctx or PrivilegeContext()
    env_with_path = _admin_env(env)
    agent_attempt: Mapping[str, object] | None = None

    if ctx.refresh_agent_health():
        try:
            process = privileges.sudo_run(
                command,
                env=env_with_path,
                text=text,
                check=check,
                input=input,
                timeout=timeout,
            )
            return {
                "command": list(command),
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
                "path_resolution_failed": False,
                "execution_mode": "agent",
            }
        except privileges.AgentUnavailableError as exc:
            agent_attempt = {
                "command": list(command),
                "error": str(exc),
                "returncode": getattr(exc, "returncode", None),
                "stderr": getattr(exc, "stderr", None),
                "allowlist_blocked": getattr(exc, "allowlist_blocked", False),
                "path_resolution_failed": getattr(exc, "path_resolution_failed", False),
                "mode": "agent",
            }
            ctx.agent_ready = False
            ctx.mark_local(str(exc))
            ctx.agent_failures.append(agent_attempt)
            ctx.force_local = True
            LOG.info("Agent execution failed for %s: %s. Falling back to local execution.", " ".join(command), exc)
        except FileNotFoundError as exc:
            agent_attempt = {
                "command": list(command),
                "error": str(exc),
                "returncode": 127,
                "stderr": str(exc),
                "allowlist_blocked": False,
                "path_resolution_failed": True,
                "mode": "agent",
            }
            ctx.agent_ready = False
            ctx.mark_local(str(exc))
            ctx.agent_failures.append(agent_attempt)
            ctx.force_local = True
            LOG.info("Agent failed to resolve command %s; retrying locally.", " ".join(command))
        except PermissionError as exc:
            agent_attempt = {
                "command": list(command),
                "error": str(exc),
                "returncode": None,
                "stderr": str(exc),
                "allowlist_blocked": False,
                "path_resolution_failed": False,
                "mode": "agent",
            }
            ctx.agent_ready = False
            ctx.mark_local(str(exc))
            ctx.agent_failures.append(agent_attempt)
            ctx.force_local = True
            LOG.info("Agent permission failure for %s; retrying locally.", " ".join(command))
        except subprocess.SubprocessError as exc:
            return {
                "command": list(command),
                "stdout": getattr(exc, "stdout", ""),
                "stderr": getattr(exc, "stderr", str(exc)),
                "returncode": None,
                "error": str(exc),
                "path_resolution_failed": False,
                "agent_attempt": agent_attempt,
            }

    ctx.mark_local(ctx.agent_error or "mcbridge agent unavailable; using local execution")

    if os.geteuid() != 0:
        return {
            "command": list(command),
            "stdout": "",
            "stderr": ctx.agent_error or "mcbridge agent unavailable",
            "returncode": None,
            "error": ctx.agent_error or "mcbridge agent unavailable",
            "path_resolution_failed": False,
            "agent_attempt": agent_attempt,
            "execution_mode": "local",
        }

    local_command = list(command)
    if local_command and local_command[0] == "bash" and len(local_command) > 1:
        local_command = local_command[1:]

    kwargs: dict[str, object] = {
        "capture_output": True,
        "text": text,
        "env": env_with_path,
        "check": check,
    }
    if input is not None:
        kwargs["input"] = input
    if timeout is not None:
        kwargs["timeout"] = timeout

    try:
        process = subprocess.run(local_command, **kwargs)
    except FileNotFoundError as exc:
        return {
            "command": list(command),
            "stdout": "",
            "stderr": str(exc),
            "returncode": 127,
            "error": str(exc),
            "path_resolution_failed": True,
            "agent_attempt": agent_attempt,
            "execution_mode": "local",
        }
    except subprocess.SubprocessError as exc:
        return {
            "command": list(command),
            "stdout": getattr(exc, "stdout", ""),
            "stderr": getattr(exc, "stderr", str(exc)),
            "returncode": None,
            "error": str(exc),
            "path_resolution_failed": False,
            "agent_attempt": agent_attempt,
            "execution_mode": "local",
        }

    return {
        "command": list(command),
        "stdout": process.stdout,
        "stderr": process.stderr,
        "returncode": process.returncode,
        "path_resolution_failed": False,
        "agent_attempt": agent_attempt,
        "execution_mode": "local",
    }


def _write_unit_file(
    path: Path,
    contents: str,
    *,
    dry_run: bool,
    service_user: str,
    service_group: str,
    service_account_exists: bool,
    ctx: PrivilegeContext,
) -> dict[str, object]:
    try:
        current = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        current = ""
    except OSError as exc:
        return {
            "status": "error",
            "path": str(path),
            "error": str(exc),
        }

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
        ensure_parent(path)
        path.write_text(contents, encoding="utf-8")
    except PermissionError:
        owner = service_user if service_account_exists else None
        group = service_group if service_account_exists else None
        if ctx.refresh_agent_health():
            try:
                privileges.sudo_write_file(path, contents, mode=0o644, owner=owner, group=group)
            except Exception as exc:  # pragma: no cover - defensive
                result["status"] = "error"
                result["error"] = str(exc)
                return result
        else:
            ctx.mark_local(ctx.agent_error or "mcbridge agent unavailable; using local execution")
            result["status"] = "error"
            result["error"] = ctx.agent_error or "insufficient privileges to write unit file"
            return result
    except OSError as exc:
        result["status"] = "error"
        result["error"] = str(exc)
        return result

    result["applied"] = True
    result["status"] = "updated" if changed else "unchanged"
    return result


def _sync_agent_unit(
    *,
    dry_run: bool,
    service_user: str,
    service_group: str,
    operator_group: str,
    ctx: PrivilegeContext,
) -> dict[str, object]:
    socket_helper_path, helper_owner, helper_home = agent.resolve_socket_helper(
        socket_helper=_socket_helper_path(), service_user=service_user
    )
    interpreter_path, interpreter_owner, interpreter_home = agent.resolve_agent_interpreter(
        service_user=service_user
    )
    contents = agent.agent_service_template(
        user=service_user,
        group=service_group,
        operator_group=operator_group,
        socket_helper=socket_helper_path,
        python_executable=interpreter_path,
    )
    service_account_exists = _service_account_exists(service_user)
    unit_result = _write_unit_file(
        AGENT_SERVICE_PATH,
        contents,
        dry_run=dry_run,
        service_user=service_user,
        service_group=service_group,
        service_account_exists=service_account_exists,
        ctx=ctx,
    )
    result: dict[str, object] = {
        "status": "planned",
        "unit": unit_result,
        "daemon_reload": None,
        "enable": None,
        "applied": False,
        "socket_helper": str(socket_helper_path),
        "socket_helper_exists": socket_helper_path.exists(),
        "python_executable": str(interpreter_path),
        "python_executable_exists": interpreter_path.exists(),
    }

    path_warnings: list[dict[str, object]] = []
    if helper_owner and helper_owner != service_user:
        path_warnings.append(
            {
                "status": "warning",
                "message": (
                    "Resolved mcbridge-agent-socket-helper path is under a different user's home."
                    " Install mcbridge system-wide or override the socket helper path to one accessible by the service account."
                ),
                "path": str(socket_helper_path),
                "owner": helper_owner,
                "home": str(helper_home) if helper_home else None,
            }
        )
    if interpreter_owner and interpreter_owner != service_user:
        path_warnings.append(
            {
                "status": "warning",
                "message": (
                    "Resolved Python interpreter is under a different user's home."
                    " Install Python system-wide or override the agent interpreter path to one accessible by the service account."
                ),
                "path": str(interpreter_path),
                "owner": interpreter_owner,
                "home": str(interpreter_home) if interpreter_home else None,
            }
        )
    if path_warnings:
        result["warnings"] = path_warnings

    if unit_result.get("status") == "error":
        result["status"] = "error"
        result["error"] = unit_result.get("error") or "Failed to write agent unit."
        return result
    if dry_run:
        return result

    reload_result = _invoke_with_optional_ctx(_run_systemctl, ctx, ["daemon-reload"])
    enable_result = _invoke_with_optional_ctx(_run_systemctl, ctx, ["enable", "--now", AGENT_SERVICE_PATH.name])
    result["daemon_reload"] = reload_result
    result["enable"] = enable_result
    if reload_result.get("returncode") not in (0,) or enable_result.get("returncode") not in (0,):
        result["status"] = "error"
        result["error"] = "Failed to enable mcbridge-agent.service"
        helper_message = _systemctl_helper_missing_hint(socket_helper_path, enable_result)
        if helper_message:
            result["helper_missing"] = True
            result["remediation"] = helper_message
        return result

    result["status"] = "updated"
    result["applied"] = True
    return result


def _sync_wlan0ap_units(
    *, octet: int, dry_run: bool, service_user: str, service_group: str, ctx: PrivilegeContext
) -> dict[str, object]:
    ap_contents = systemd_units.wlan0ap_service_template(
        ap_interface=AP_INTERFACE,
        upstream_interface=UPSTREAM_INTERFACE,
        service_user=service_user,
        service_group=service_group,
    )
    ap_ip_cidr = f"192.168.{octet}.1/24"
    ap_ip_contents = systemd_units.wlan0ap_ip_service_template(
        ap_interface=AP_INTERFACE,
        ap_ip_cidr=ap_ip_cidr,
        ap_service_unit=WLAN0AP_SERVICE_PATH.name,
        service_user=service_user,
        service_group=service_group,
    )

    service_account_exists = _service_account_exists(service_user)
    ap_service = _write_unit_file(
        WLAN0AP_SERVICE_PATH,
        ap_contents,
        dry_run=dry_run,
        service_user=service_user,
        service_group=service_group,
        service_account_exists=service_account_exists,
        ctx=ctx,
    )
    ap_ip_service = _write_unit_file(
        ap.WLAN0AP_IP_SERVICE,
        ap_ip_contents,
        dry_run=dry_run,
        service_user=service_user,
        service_group=service_group,
        service_account_exists=service_account_exists,
        ctx=ctx,
    )

    result: dict[str, object] = {
        "status": "planned",
        "ap_service": ap_service,
        "ap_ip_service": ap_ip_service,
        "ap_ip_cidr": ap_ip_cidr,
        "daemon_reload": None,
        "enable": [],
        "remediation": None,
        "applied": False,
        "ip_check": None,
    }

    if ap_service.get("status") == "error" or ap_ip_service.get("status") == "error":
        result["status"] = "error"
        result["remediation"] = WLAN0AP_IP_REMEDIATION
        return result

    if dry_run:
        return result

    reload_result = _invoke_with_optional_ctx(_run_systemctl, ctx, ["daemon-reload"])
    enable_results = [
        _invoke_with_optional_ctx(_run_systemctl, ctx, ["enable", "--now", WLAN0AP_SERVICE_PATH.name]),
        _invoke_with_optional_ctx(_run_systemctl, ctx, ["enable", "--now", ap.WLAN0AP_IP_SERVICE.name]),
    ]
    result["daemon_reload"] = reload_result
    result["enable"] = enable_results

    ip_check = _run_command(["ip", "addr", "show", AP_INTERFACE])
    ip_output = str(ip_check.get("stdout") or "")
    ip_present = ip_check.get("returncode") in (0,) and f"inet {ap_ip_cidr}" in ip_output
    result["ip_check"] = {**ip_check, "expected_ip": ap_ip_cidr, "ip_present": ip_present}

    failures = [entry for entry in [reload_result, *enable_results] if entry.get("returncode") not in (0,)]
    if failures:
        failed = failures[0]
        result["status"] = "error"
        result["remediation"] = WLAN0AP_IP_REMEDIATION
        result["error"] = "Failed to enable wlan0ap units."
        result["failed_command"] = " ".join(str(part) for part in failed.get("command") or [])
        result["failed_returncode"] = failed.get("returncode")
        result["failed_stderr"] = failed.get("stderr")
    elif not ip_present:
        LOG.error("%s missing expected IP %s after enabling wlan0ap-ip.service", AP_INTERFACE, ap_ip_cidr)
        result["status"] = "error"
        result["remediation"] = WLAN0AP_IP_REMEDIATION
        result["error"] = f"{AP_INTERFACE} missing expected IP {ap_ip_cidr} after enabling wlan0ap-ip.service"
    else:
        result["status"] = "applied"
        result["applied"] = True
    return result


def _write_marker(*, version: str | None) -> dict[str, Any]:
    ensure_parent(INITIALISED_MARKER)
    metadata = {
        "initialised_at": datetime.now(timezone.utc).isoformat(),
        "version": version or "unknown",
    }
    INITIALISED_MARKER.write_text(f"{metadata['initialised_at']} (version {metadata['version']})\n", encoding="utf-8")
    return {"marker_path": str(INITIALISED_MARKER), "metadata": metadata}


def _log_validation_summary(ap_payload: Mapping[str, Any] | None) -> None:
    if not ap_payload:
        return

    hostapd_result = (ap_payload.get("changes") or {}).get("hostapd") or {}
    validation = hostapd_result.get("validation") or {}
    if validation.get("status") != "failed":
        return

    summary = validation.get("summary")
    first_line = validation.get("first_stderr_line")
    failed_paths = validation.get("failed_paths") or {}
    if isinstance(failed_paths, Mapping):
        failed_values = [str(path) for path in failed_paths.values()]
    elif isinstance(failed_paths, Sequence) and not isinstance(failed_paths, (str, bytes, bytearray)):
        failed_values = [str(path) for path in failed_paths]
    else:
        failed_values = [str(failed_paths)]

    message_parts: list[str] = []
    if summary:
        message_parts.append(summary)
    else:
        if first_line:
            message_parts.append(first_line)
        if failed_values:
            message_parts.append(f"artifacts saved to {', '.join(failed_values)}")

    if message_parts:
        LOG.error("hostapd validation failed: %s", "; ".join(message_parts))


def _hostapd_validation_failure(ap_payload: Mapping[str, Any] | None) -> dict[str, Any] | None:
    if not ap_payload:
        return None

    hostapd_result = (ap_payload.get("changes") or {}).get("hostapd") or {}
    validation = hostapd_result.get("validation") or {}
    if not validation or validation.get("skipped"):
        return None

    returncode = validation.get("returncode")
    failed = validation.get("status") == "failed" or validation.get("timeout") or returncode is None or returncode not in (
        0,
        None,
    )
    if not failed:
        return None

    failed_paths = validation.get("failed_paths") or {}
    if isinstance(failed_paths, Mapping):
        failed_paths = [str(path) for path in failed_paths.values()]
    elif isinstance(failed_paths, Sequence) and not isinstance(failed_paths, (str, bytes, bytearray)):
        failed_paths = [str(path) for path in failed_paths]
    else:
        failed_paths = []

    summary = (
        validation.get("summary")
        or validation.get("first_stderr_line")
        or validation.get("stderr")
        or "hostapd validation failed"
    )
    return {
        "failed": True,
        "status": validation.get("status"),
        "summary": summary,
        "returncode": returncode,
        "timeout": validation.get("timeout"),
        "timeout_seconds": validation.get("timeout_seconds"),
        "failed_paths": failed_paths,
    }


def run(
    *,
    ssid: str,
    password: str | None,
    octet: int | None = None,
    channel: int | None = None,
    target: str | None = None,
    redirect: str | None = None,
    force: bool = False,
    force_restart: bool = True,
    prepare_only: bool = False,
    dry_run: bool = False,
    assume_yes: bool = False,
    debug_json: bool | None = None,
    service_user: str = SERVICE_USER,
    service_group: str = SERVICE_GROUP,
    operator_group: str = OPERATOR_GROUP,
    web_password: str | None = None,
    enable_web: bool = True,
) -> InitResult:
    debug_verbose = _debug_verbose(debug_json)
    resolved_password = password or ""
    resolved_octet = ap.DEFAULT_SUBNET_OCTET if octet is None else octet
    resolved_channel = DEFAULT_CHANNEL if channel is None else channel
    resolved_service_user = service_user or SERVICE_USER
    resolved_service_group = service_group or resolved_service_user or SERVICE_GROUP
    resolved_operator_group = operator_group or OPERATOR_GROUP
    web_enabled = bool(enable_web)
    required_services = [service for service in REQUIRED_SERVICES if web_enabled or service != "mcbridge-web.service"]
    if web_enabled:
        os.environ.setdefault("MCBRIDGE_WEB_USER", resolved_service_user)
        os.environ.setdefault("MCBRIDGE_WEB_GROUP", resolved_service_group)
        from . import web
    privilege_ctx = PrivilegeContext()
    try:
        _require_root()
    except PermissionError as exc:
        payload = response_payload(
            {"status": "error", "message": str(exc)},
            {"privileges": {"mode": "local", "agent_ready": False, "local_execution_used": privilege_ctx.used_local}},
        )
        return InitResult(payload=payload, exit_code=3)

    required_agent_commands = _required_agent_commands()
    agent_preflight = _agent_preflight(privilege_ctx, required_agent_commands)

    def _privileges_section() -> dict[str, Any]:
        summary: dict[str, Any] = {
            "mode": "agent" if privilege_ctx.agent_ready else "local",
            "agent_ready": privilege_ctx.agent_ready,
            "local_execution_used": privilege_ctx.used_local,
        }
        if privilege_ctx.agent_error:
            summary["note"] = f"Used local execution because {privilege_ctx.agent_error}"
        if privilege_ctx.agent_failures:
            summary["agent_failures"] = privilege_ctx.agent_failures
        if privilege_ctx.preflight:
            summary["preflight"] = privilege_ctx.preflight
        return {"privileges": summary}

    def _build_payload(*sections: Mapping[str, Any], verbose: bool | None = None) -> Mapping[str, Any]:
        effective_verbose = debug_verbose if verbose is None else verbose
        return response_payload({"preflight": agent_preflight}, *sections, _privileges_section(), verbose=effective_verbose)

    principal_setup = _ensure_principals(
        service_user=resolved_service_user,
        service_group=resolved_service_group,
        operator_group=resolved_operator_group,
        service_home=SERVICE_HOME,
        dry_run=dry_run,
        ctx=privilege_ctx,
    )

    if isinstance(principal_setup, Mapping) and principal_setup.get("status") == "error":
        payload = _build_payload(principal_setup)
        return InitResult(payload=payload, exit_code=3)

    principal_errors: list[Mapping[str, object]] = []
    for value in (principal_setup.get("service_group"), principal_setup.get("operator_group"), principal_setup.get("service_user")):
        if isinstance(value, Mapping) and value.get("status") == "error":
            principal_errors.append(value)
    for entry in principal_setup.get("directories", []):
        if isinstance(entry, Mapping) and entry.get("status") == "error":
            principal_errors.append(entry)
    installer_status = principal_setup.get("installer_group_membership")
    if isinstance(installer_status, Mapping) and installer_status.get("status") == "error":
        principal_errors.append(installer_status)
    membership_status = principal_setup.get("service_operator_membership")
    if isinstance(membership_status, Mapping) and membership_status.get("status") == "error":
        principal_errors.append(membership_status)
    socket_status = principal_setup.get("agent_socket")
    if isinstance(socket_status, Mapping) and socket_status.get("status") == "error":
        principal_errors.append(socket_status)

    if principal_errors:
        payload = _build_payload(
            {"status": "error", "message": "Failed to prepare mcbridge service principals.", "details": principal_errors}
        )
        return InitResult(payload=payload, exit_code=3)

    validation_errors, validation_details = _validate_arguments(
        ssid=ssid,
        password=resolved_password,
        octet=resolved_octet,
        channel=resolved_channel,
        redirect=redirect,
        target=target,
    )
    if validation_errors:
        payload = _build_payload(
            {
                "status": "error",
                "message": "Invalid init arguments.",
                "validation": {"errors": validation_errors},
                "validation_errors": validation_errors,
            },
            validation_details,
        )
        return InitResult(payload=payload, exit_code=2)

    octet_was_explicit = octet is not None
    env_errors, env_details, resolved_octet = _check_environment(
        octet=resolved_octet, allow_octet_substitution=not octet_was_explicit
    )
    if env_errors:
        payload = _build_payload(
            {"status": "error", "message": "System prerequisites not met.", "environment_errors": env_errors},
            env_details,
        )
        return InitResult(payload=payload, exit_code=3)

    octet_substitution = env_details.get("environment", {}).get("octet_substitution")
    octet_selection_note = None
    if octet_substitution:
        octet_selection_note = {
            "status": "ok",
            "message": (
                "Requested subnet octet conflicts with upstream network; selected alternative octet automatically."
            ),
            "details": octet_substitution,
        }
        logger.warning(
            "Requested octet %s overlaps upstream networks %s; selected %s instead.",
            octet_substitution["requested"],
            ", ".join(octet_substitution.get("conflicts", [])),
            octet_substitution["selected"],
        )

    marker_exists = INITIALISED_MARKER.exists()
    marker_note = None
    if marker_exists and not force:
        marker_note = f"System already initialised (marker at {INITIALISED_MARKER}); proceeding in idempotent mode."

    summary = _plan_summary(resolved_octet, include_web=web_enabled)
    for line in summary:
        LOG.info(line)

    seed_plan = _seed_configs(
        ssid=ssid,
        password=resolved_password,
        channel=resolved_channel,
        octet=resolved_octet,
        redirect=redirect,
        target=target,
        dry_run=dry_run,
    )

    payload_sections: list[Mapping[str, Any]] = [{"status": "ok", "message": "mcbridge init plan ready.", "plan": summary}]
    if octet_selection_note:
        payload_sections.append({"octet_selection": octet_selection_note})
    if marker_note:
        payload_sections.append({"marker": {"status": "present", "path": str(INITIALISED_MARKER), "note": marker_note}})
    payload_sections.append({"principals": principal_setup})
    payload_sections.append({"seed_config": seed_plan})
    if prepare_only:
        payload_sections.append({"prepare_only": True})

    confirmation_required = not dry_run and not (force or assume_yes)

    operator_policy_index = len(payload_sections)
    operator_policy = _sync_operator_privilege_policy(
        operator_group=resolved_operator_group, dry_run=dry_run or confirmation_required
    )
    payload_sections.append({"operator_policy": operator_policy})
    if operator_policy.get("status") == "error":
        payload = _build_payload(
            {"status": "error", "message": "Failed to install operator privilege policy.", "operator_policy": operator_policy},
        )
        return InitResult(payload=payload, exit_code=3)

    polkit_policy_index = len(payload_sections)
    polkit_policy = _sync_polkit_policy(operator_group=resolved_operator_group, dry_run=dry_run or confirmation_required)
    payload_sections.append({"polkit_policy": polkit_policy})
    if polkit_policy.get("status") == "error":
        payload = _build_payload(
            {"status": "error", "message": "Failed to install polkit policy.", "polkit_policy": polkit_policy},
        )
        return InitResult(payload=payload, exit_code=3)

    agent_section_index = len(payload_sections)
    agent_unit = _sync_agent_unit(
        dry_run=dry_run or confirmation_required,
        service_user=resolved_service_user,
        service_group=resolved_service_group,
        operator_group=resolved_operator_group,
        ctx=privilege_ctx,
    )
    payload_sections.append({"agent_unit": agent_unit})
    if agent_unit.get("status") == "error":
        payload = _build_payload(
            {
                "status": "error",
                "message": "Failed to prepare mcbridge-agent systemd unit.",
                "agent_unit": agent_unit,
            },
        )
        return InitResult(payload=payload, exit_code=3)

    try:
        unit_sync = _invoke_with_optional_ctx(
            _sync_wlan0ap_units,
            privilege_ctx,
            octet=resolved_octet,
            dry_run=dry_run or confirmation_required,
            service_user=resolved_service_user,
            service_group=resolved_service_group,
        )
    except TypeError:  # pragma: no cover - backward compatibility for monkeypatched tests
        unit_sync = _sync_wlan0ap_units(octet=resolved_octet, dry_run=dry_run or confirmation_required)
    payload_sections.append({"ap_units": unit_sync})
    if unit_sync.get("status") == "error":
        payload = _build_payload(
            {
                "status": "error",
                "message": "Failed to prepare wlan0ap systemd units.",
                "ap_units": unit_sync,
                "remediation": unit_sync.get("remediation"),
            },
        )
        return InitResult(payload=payload, exit_code=3)

    web_section_index: int | None = None
    web_exit_code = 0
    web_payload: Mapping[str, Any] | None = None
    if web_enabled:
        web_init_result = web.web_init(
            password=web_password,
            dry_run=dry_run or confirmation_required,
            allow_local_fallback=True,
            start_service=not prepare_only,
            systemctl_runner=lambda args: _invoke_with_optional_ctx(_run_systemctl, privilege_ctx, args),
        )
        web_section_index = len(payload_sections)
        payload_sections.append({"web": web_init_result.payload})
        web_payload = web_init_result.payload
        web_exit_code = web_init_result.exit_code or 0
        if web_exit_code not in (0,):
            payload = _build_payload(
                {
                    "status": "error",
                    "message": "Failed to prepare mcbridge web console.",
                    "web_init": web_init_result.payload,
                },
            )
            return InitResult(payload=payload, exit_code=web_exit_code if web_exit_code else 3)
    elif web_password:
        skip_payload = {
            "status": "skipped",
            "reason": "web_disabled",
            "message": "Web console disabled via --no-web; password ignored.",
        }
        payload_sections.append(
            {
                "web": skip_payload
            }
        )
        web_payload = skip_payload

    if dry_run:
        payload = _build_payload(*payload_sections)
        return InitResult(payload=payload, exit_code=0)

    if confirmation_required:
        confirmed = _confirm(summary)
        if not confirmed:
            payload = _build_payload({"status": "error", "message": "Initialisation aborted by operator."})
            return InitResult(payload=payload, exit_code=3)

        operator_policy = _sync_operator_privilege_policy(
            operator_group=resolved_operator_group, dry_run=False
        )
        payload_sections[operator_policy_index] = {"operator_policy": operator_policy}
        if operator_policy.get("status") == "error":
            payload = _build_payload(
                {
                    "status": "error",
                    "message": "Failed to install operator privilege policy.",
                    "operator_policy": operator_policy,
                },
            )
            return InitResult(payload=payload, exit_code=3)

        polkit_policy = _sync_polkit_policy(operator_group=resolved_operator_group, dry_run=False)
        payload_sections[polkit_policy_index] = {"polkit_policy": polkit_policy}
        if polkit_policy.get("status") == "error":
            payload = _build_payload(
                {
                    "status": "error",
                    "message": "Failed to install polkit policy.",
                    "polkit_policy": polkit_policy,
                },
            )
            return InitResult(payload=payload, exit_code=3)

        agent_unit = _sync_agent_unit(
            dry_run=False,
            service_user=resolved_service_user,
            service_group=resolved_service_group,
            operator_group=resolved_operator_group,
            ctx=privilege_ctx,
        )
        payload_sections[agent_section_index] = {"agent_unit": agent_unit}
        if agent_unit.get("status") == "error":
            payload = _build_payload(
                {
                    "status": "error",
                    "message": "Failed to prepare mcbridge-agent systemd unit.",
                    "agent_unit": agent_unit,
                },
            )
            return InitResult(payload=payload, exit_code=3)

        try:
            unit_sync = _invoke_with_optional_ctx(
                _sync_wlan0ap_units,
                privilege_ctx,
                octet=resolved_octet,
                dry_run=False,
                service_user=resolved_service_user,
                service_group=resolved_service_group,
            )
        except TypeError:  # pragma: no cover - backward compatibility for monkeypatched tests
            unit_sync = _sync_wlan0ap_units(octet=resolved_octet, dry_run=False)
        payload_sections[-1] = {"ap_units": unit_sync}
        if unit_sync.get("status") == "error":
            payload = _build_payload(
                {
                    "status": "error",
                    "message": "Failed to prepare wlan0ap systemd units.",
                    "ap_units": unit_sync,
                    "remediation": unit_sync.get("remediation"),
                },
            )
            return InitResult(payload=payload, exit_code=3)

        if web_enabled and web_section_index is not None:
            web_init_result = web.web_init(
                password=web_password,
                dry_run=False,
                allow_local_fallback=True,
                start_service=not prepare_only,
                systemctl_runner=lambda args: _invoke_with_optional_ctx(_run_systemctl, privilege_ctx, args),
            )
            payload_sections[web_section_index] = {"web": web_init_result.payload}
            web_payload = web_init_result.payload
            web_exit_code = web_init_result.exit_code or 0
            if web_exit_code not in (0,):
                payload = _build_payload(
                    {
                        "status": "error",
                        "message": "Failed to configure mcbridge web console.",
                        "web_init": web_init_result.payload,
                    },
                )
                return InitResult(payload=payload, exit_code=web_exit_code if web_exit_code else 3)

    provision_result = _run_provisioning_script(
        ssid=ssid,
        password=resolved_password,
        octet=resolved_octet,
        channel=resolved_channel,
        force=force,
        service_user=resolved_service_user,
        service_group=resolved_service_group,
        operator_group=resolved_operator_group,
    )
    payload_sections.append({"provision": provision_result})
    if provision_result.get("returncode") not in (0, None):
        payload = _build_payload(
            {"status": "error", "message": "Provisioning script failed.", "provision": provision_result}
        )
        return InitResult(payload=payload, exit_code=3)

    provision_status = provision_result.get("provision_status")
    payload_sections.append({"provision_status": provision_status})

    service_enablement, service_errors = ensure_services_enabled(
        required_services,
        runner=lambda args: _invoke_with_optional_ctx(_run_systemctl, privilege_ctx, args),
        start_services=not prepare_only,
    )
    if service_errors:
        payload = _build_payload(
            *payload_sections,
            {"status": "error", "message": "; ".join(service_errors), "service_enablement": service_enablement},
        )
        return InitResult(payload=payload, exit_code=3)
    payload_sections.append({"service_enablement": service_enablement})

    service_states, service_state_errors = _invoke_with_optional_ctx(_collect_service_states, privilege_ctx, required_services)
    payload_sections.append({"service_states": service_states})
    if service_state_errors and not prepare_only:
        message = "; ".join(service_state_errors)
        payload = _build_payload(
            *payload_sections,
            {"status": "error", "message": message, "service_state_errors": service_state_errors},
        )
        return InitResult(payload=payload, exit_code=3)
    if marker_exists and not force and provision_status == "applied":
        payload = _build_payload(
            *payload_sections,
            {
                "status": "error",
                "message": (
                    "System already initialised; provisioning detected drift. Re-run with --force to reapply."
                ),
                "provision": provision_result,
            },
        )
        return InitResult(payload=payload, exit_code=3)

    ap_result = None
    dns_result = None
    hostapd_validation = None
    post_apply_checks = None

    if not prepare_only:
        if redirect or target or DNS_OVERRIDES_JSON.exists():
            dns_result = dns.update(
                redirect=redirect,
                target=target,
                dry_run=False,
                force=True,
                default_target=target,
                debug_json=True,
            )
            payload_sections.append({"dns_update": dns_result.payload})
        else:
            payload_sections.append({"dns_update": {"skipped": True, "reason": "no_redirect_target"}})

        upstream_dns_result = upstream_dns.refresh_upstream_dns(interface=UPSTREAM_INTERFACE)
        payload_sections.append({"upstream_dns_refresh": upstream_dns_result.payload})

        ap_result = ap.update(
            ssid=ssid,
            password=resolved_password,
            channel=resolved_channel,
            subnet_octet=resolved_octet,
            dry_run=False,
            force=True,
            force_restart=force_restart,
            debug_json=True,
        )
        _log_validation_summary(ap_result.payload)
        hostapd_validation = _hostapd_validation_failure(ap_result.payload)
        if hostapd_validation:
            payload_sections.append({"hostapd_validation": hostapd_validation})
        payload_sections.append({"ap_update": ap_result.payload})

        post_apply_checks = _invoke_with_optional_ctx(_collect_post_apply_checks, privilege_ctx, octet=resolved_octet)
        payload_sections.append({"post_apply_checks": post_apply_checks})
    else:
        payload_sections.append({"dns_update": {"skipped": True, "reason": "prepare_only"}})
        payload_sections.append({"ap_update": {"skipped": True, "reason": "prepare_only"}})
        payload_sections.append({"post_apply_checks": {"skipped": True, "reason": "prepare_only"}})

    exit_code = 0
    if hostapd_validation:
        exit_code = 2
    elif ap_result and ap_result.exit_code == 2:
        exit_code = 2
    elif ap_result and ap_result.exit_code != 0:
        exit_code = 3
    elif dns_result and dns_result.exit_code != 0:
        exit_code = 3 if dns_result.exit_code not in (2,) else 2
    elif post_apply_checks and post_apply_checks.get("status") != "ok":
        exit_code = 3

    if prepare_only:
        payload_sections.insert(
            0,
            {
                "status": "ok",
                "message": "Preparation completed; ready for AP configuration. Run 'mcbridge ap update' to render and apply hostapd/dnsmasq configs.",
            },
        )
        payload_sections.append({"ready_for_ap_update": True})
        payload = _build_payload(*payload_sections)
        return InitResult(payload=payload, exit_code=0)

    if exit_code == 0:
        marker_info = _write_marker(version=_package_version())
        payload_sections.append({"marker": marker_info})
    else:
        payload_sections.append({"marker": {"skipped": True, "reason": "post_apply_failure"}})

    if exit_code == 0:
        final_message = "Provisioning completed and services converged."
        final_status = "ok"
    else:
        final_message = "Initialisation completed with warnings."
        final_status = "error"
    if hostapd_validation:
        artifact_note = ""
        if hostapd_validation.get("failed_paths"):
            artifact_note = f" Artifacts saved to {', '.join(hostapd_validation['failed_paths'])}."
        final_message = f"Initialisation halted by hostapd validation failure: {hostapd_validation.get('summary')}." + artifact_note
    post_init_notes = []
    if resolved_operator_group:
        post_init_notes.append(
            "You have been added to mcbridge-operators. Log out and back in so the group membership applies to new sessions."
        )
    if web_enabled:
        post_init_notes.append(
            "mcbridge-web.service installed and enabled; edit /etc/mcbridge/config/web.json to adjust TLS/authentication."
        )
        if isinstance(web_payload, Mapping):
            for warning in web_payload.get("warnings") or []:
                post_init_notes.append(f"Web console warning: {warning}")
    else:
        post_init_notes.append("Web console setup skipped (--no-web). Run 'mcbridge-web init' later if you enable it.")
    for note in post_init_notes:
        LOG.info(note)
    payload_sections.insert(
        0, {"status": final_status, "message": final_message, "post_init_notes": post_init_notes}
    )

    payload = _build_payload(*payload_sections)
    return InitResult(payload=payload, exit_code=exit_code)


def _collect_post_apply_checks(*, octet: int, ctx: PrivilegeContext) -> dict[str, Any]:
    expected_ip = f"192.168.{octet}.1"
    expected_ip_cidr = f"{expected_ip}/24"

    ip_link = _run_command(["ip", "link", "show", AP_INTERFACE])
    link_output = str(ip_link.get("stdout") or "")
    link_up = ip_link.get("returncode") == 0 and "state up" in link_output.lower()

    ip_addr = _run_command(["ip", "addr", "show", AP_INTERFACE])
    ip_addr_output = str(ip_addr.get("stdout") or "")
    ip_present = ip_addr.get("returncode") == 0 and expected_ip in ip_addr_output

    hostapd_state = _invoke_with_optional_ctx(_run_systemctl, ctx, ["is-active", "hostapd"])
    hostapd_active = str(hostapd_state.get("stdout") or "").strip() == "active"

    dnsmasq_state = _invoke_with_optional_ctx(_run_systemctl, ctx, ["is-active", "dnsmasq"])
    dnsmasq_active = str(dnsmasq_state.get("stdout") or "").strip() == "active"

    iptables_save = _invoke_with_optional_ctx(_run_privileged, ctx, ["iptables-save"])
    iptables_output = str(iptables_save.get("stdout") or "")
    expected_rules = {
        "masquerade": f"-A POSTROUTING -o {UPSTREAM_INTERFACE} -j MASQUERADE",
        "forward_ap_to_upstream": f"-A FORWARD -i {AP_INTERFACE} -o {UPSTREAM_INTERFACE} -j ACCEPT",
        "forward_upstream_to_ap": f"-A FORWARD -i {UPSTREAM_INTERFACE} -o {AP_INTERFACE} -m state --state ESTABLISHED,RELATED -j ACCEPT",
    }

    def _rule_present(rule: str) -> bool:
        if not rule:
            return False
        if rule in iptables_output:
            return True
        if "ESTABLISHED,RELATED" in rule:
            alternate = rule.replace("ESTABLISHED,RELATED", "RELATED,ESTABLISHED")
            return alternate in iptables_output
        return False

    rules_present = {name: _rule_present(value) for name, value in expected_rules.items()}
    missing_rules = [name for name, present in rules_present.items() if not present]

    errors: list[str] = []
    if not link_up:
        errors.append(f"{AP_INTERFACE} link is not UP")
    if not ip_present:
        errors.append(f"{AP_INTERFACE} missing expected IP {expected_ip_cidr}")
    if not hostapd_active:
        errors.append("hostapd is not active")
    if not dnsmasq_active:
        errors.append("dnsmasq is not active")
    if iptables_save.get("returncode") not in (0,) or missing_rules:
        errors.append("iptables-save missing required NAT/forwarding rules")

    return {
        "status": "ok" if not errors else "error",
        "errors": errors,
        "expected_ip": expected_ip_cidr,
        "ap_interface": {**ip_link, "up": link_up, "expected_state": "UP"},
        "ap_ip": {**ip_addr, "ip_present": ip_present},
        "services": {
            "hostapd": {**hostapd_state, "active": hostapd_active},
            "dnsmasq": {**dnsmasq_state, "active": dnsmasq_active},
        },
        "iptables": {
            **iptables_save,
            "expected_rules": expected_rules,
            "rules_present": rules_present,
            "missing_rules": missing_rules,
        },
    }


def _package_version() -> str | None:
    try:
        return importlib.metadata.version("mcbridge")
    except importlib.metadata.PackageNotFoundError:
        return None


__all__ = ["InitResult", "run"]
