"""Access point domain logic.

This module hosts the reusable implementation that previously lived in the
``manage-ap`` script. All helpers are structured so that callers can preview or
apply configuration changes while keeping stdout machine-readable JSON and
stderr available for logs.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Mapping, Sequence

from .common import (
    AP_JSON,
    CONFIG_HISTORY_DIR,
    DEFAULT_FILE_GROUP,
    DEFAULT_FILE_MODE,
    DEFAULT_FILE_OWNER,
    DNSMASQ_ACTIVE_CONF,
    DNSMASQ_CONF,
    DNSMASQ_OVERRIDES_CONF,
    KNOWN_SERVERS_JSON,
    FAILED_GENERATED_DIR,
    GENERATED_HISTORY_DIR,
    HOSTAPD_ACTIVE_CONF,
    HOSTAPD_CONF,
    MANAGE_AP_SECTION_END,
    MANAGE_AP_SECTION_START,
    MANAGE_DNSMASQ_SECTION_END,
    MANAGE_DNSMASQ_SECTION_START,
    analyse_dnsmasq_layout,
    assemble_dnsmasq_config,
    check_interface_exists,
    collect_file_mtimes,
    compare_configs,
    config_source_label,
    diff_text,
    ensure_parent,
    extract_section_body,
    format_dns_override_lines,
    load_dns_overrides_config,
    load_json,
    logger,
    mismatch_summary,
    parse_dns_overrides,
    read_system_ap_config,
    read_text,
    reload_or_restart_service,
    restart_service,
    response_payload,
    set_default_permissions,
    restore_from_history,
    save_failed_validation_artifacts,
    save_json,
    normalize_dns_override_payload,
    service_status,
    write_history_file,
)
from . import privileges, upstream, upstream_dns
from .paths import GENERATED_DIR
from .service_enablement import ensure_services_enabled

AP_FIELDS = ("ssid", "password", "channel", "subnet_octet")
DEFAULT_SUBNET_OCTET = 50
DEFAULT_DNS_TARGET: str | None = None
VALIDATION_TIMEOUT_SECONDS = 15.0
SERVICE_TIMEOUT_SECONDS = 15.0
AP_INTERFACE = os.environ.get("MCBRIDGE_AP_INTERFACE", "wlan0ap")
UPSTREAM_INTERFACE = os.environ.get("MCBRIDGE_UPSTREAM_INTERFACE", "wlan0")
WLAN0AP_IP_UNIT = "wlan0ap-ip.service"
WLAN0AP_IP_SERVICE = Path(os.environ.get("MCBRIDGE_WLAN0AP_IP_SERVICE", f"/etc/systemd/system/{WLAN0AP_IP_UNIT}"))
WLAN0AP_IP_GENERATED = Path(
    os.environ.get("MCBRIDGE_GENERATED_WLAN0AP_IP_SERVICE", str(GENERATED_DIR / WLAN0AP_IP_UNIT))
)
WLAN0AP_IP_REMEDIATION = "systemctl daemon-reload && systemctl restart wlan0ap-ip.service"
HOSTAPD_DEFAULTS = Path(os.environ.get("MCBRIDGE_HOSTAPD_DEFAULT", "/etc/default/hostapd"))
UPSTREAM_WPA_SUPPLICANT_CONF = Path(
    os.environ.get("MCBRIDGE_UPSTREAM_WPA_CONF", f"/etc/wpa_supplicant/wpa_supplicant-{UPSTREAM_INTERFACE}.conf")
)
UPSTREAM_WPA_GENERATED_CONF = Path(
    os.environ.get(
        "MCBRIDGE_GENERATED_UPSTREAM_WPA_CONF", str(GENERATED_DIR / f"wpa_supplicant-{UPSTREAM_INTERFACE}.conf")
    )
)
UPSTREAM_OVERRIDE_FIELDS = ("upstream_dns", "dns_servers", "upstream_servers")
UPSTREAM_DHCP_RESOLV_PATHS = (
    Path("/run/systemd/resolve/resolv.conf"),
    Path("/etc/resolv.conf"),
)


@dataclass
class ApResult:
    """Domain result with the rendered payload and exit code."""

    payload: Mapping[str, Any]
    exit_code: int


def _debug_verbose(flag: bool | None = None) -> bool:
    env_value = os.environ.get("MCBRIDGE_DEBUG_JSON", "")
    env_enabled = env_value.lower() in {"1", "true", "yes", "on"}
    return bool(flag) or env_enabled


def _dns_override_lines(redirect: str, target: str) -> list[str]:
    target_value = str(target or "").strip()
    redirect_value = str(redirect or "").strip()

    if not redirect_value or not target_value:
        return []

    return format_dns_override_lines([redirect_value], target_value)


def _apply_overrides(base: Mapping[str, object], overrides: Mapping[str, object]) -> dict[str, object]:
    merged = dict(base or {})
    merged.update({key: value for key, value in overrides.items() if value is not None})
    return merged


def _sanitize_ap_config(config: Mapping[str, object]) -> dict[str, object]:
    cleaned = dict(config or {})
    for field in UPSTREAM_OVERRIDE_FIELDS:
        cleaned.pop(field, None)
    return cleaned


def _normalize_timeout_stream(stream: object) -> str:
    if isinstance(stream, (bytes, bytearray)):
        try:
            return stream.decode("utf-8", errors="replace")
        except Exception:
            return str(stream)
    if stream is None:
        return ""
    return str(stream)


def _wpa_security_lines(profile: upstream.UpstreamProfile) -> list[str]:
    security = profile.security.strip().lower()
    if security in {"open", "none"}:
        return ["    key_mgmt=NONE"]
    return ["    key_mgmt=WPA-PSK", f'    psk="{profile.password}"']


def _render_wpa_network(profile: upstream.UpstreamProfile) -> str:
    lines = [
        "network={",
        f'    ssid="{profile.ssid}"',
        f"    priority={profile.priority}",
        *_wpa_security_lines(profile),
        "}",
    ]
    return "\n".join(lines)


def _render_wpa_supplicant(interface: str, profiles: Sequence[upstream.UpstreamProfile]) -> str:
    header = [
        "# Generated by mcbridge upstream sync",
        f"# interface={interface}",
        "ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev",
        "update_config=1",
        "",
    ]
    body = "\n\n".join(_render_wpa_network(profile) for profile in profiles)
    return "\n".join(header) + body + ("\n" if body else "")


def _run_command(command: Sequence[str]) -> dict[str, object]:
    privileged_binaries = {"systemctl", "ip", "iptables", "iptables-save", "iw", "sysctl"}
    runner = subprocess.run
    if command and command[0] in privileged_binaries:
        runner = privileges.sudo_run

    try:
        if runner is privileges.sudo_run:
            process = runner(command)
        else:
            process = runner(command, capture_output=True, text=True)
    except FileNotFoundError as exc:
        return {
            "command": " ".join(command),
            "stdout": "",
            "stderr": str(exc),
            "returncode": 127,
            "error": str(exc),
        }
    except (PermissionError, subprocess.SubprocessError) as exc:
        return {
            "command": " ".join(command),
            "stdout": getattr(exc, "stdout", ""),
            "stderr": getattr(exc, "stderr", str(exc)),
            "returncode": None,
            "error": str(exc),
        }

    return {
        "command": " ".join(command),
        "stdout": process.stdout,
        "stderr": process.stderr,
        "returncode": process.returncode,
    }


def _is_loopback_address(server: str) -> bool:
    try:
        ip_value = ipaddress.ip_address(server)
    except ValueError:
        return False
    return bool(ip_value.is_loopback or ip_value.is_unspecified)


def _parse_resolv_nameservers(contents: str) -> list[str]:
    servers: list[str] = []
    for line in contents.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2 or parts[0] != "nameserver":
            continue
        server = parts[1].strip()
        if not server or _is_loopback_address(server):
            continue
        servers.append(server)
    return list(dict.fromkeys(servers))


def _desired_ap_ip(subnet_octet: int) -> str:
    return f"192.168.{subnet_octet}.1/24"


def _expected_dhcp_range(subnet_octet: int) -> str:
    base = f"192.168.{subnet_octet}."
    return f"dhcp-range={base}10,{base}60,12h"


def _dhcp_range_matches(config_text: str, expected_range: str) -> bool:
    pattern = re.compile(rf"^\s*{re.escape(expected_range)}(?:\s|$)", re.MULTILINE)
    return bool(pattern.search(config_text))


def _post_apply_verification(
    subnet_octet: int, *, desired_ip: str, dnsmasq_candidate: str | None = None
) -> dict[str, object]:
    current_ip, commands = _detect_wlan0ap_ip()
    dnsmasq_text = read_text(DNSMASQ_ACTIVE_CONF)
    managed_ap_body = extract_section_body(dnsmasq_text, MANAGE_AP_SECTION_START, MANAGE_AP_SECTION_END)
    candidate_ap_body = (
        extract_section_body(dnsmasq_candidate, MANAGE_AP_SECTION_START, MANAGE_AP_SECTION_END)
        if dnsmasq_candidate
        else None
    )
    expected_range = _expected_dhcp_range(subnet_octet)
    range_sources: list[tuple[str, str]] = []
    if managed_ap_body is not None:
        range_sources.append(("dnsmasq_active_managed", managed_ap_body))
    if dnsmasq_text:
        range_sources.append(("dnsmasq_active", dnsmasq_text))
    if candidate_ap_body is not None:
        range_sources.append(("dnsmasq_candidate_managed", candidate_ap_body))
    if dnsmasq_candidate:
        range_sources.append(("dnsmasq_candidate", dnsmasq_candidate))
    dhcp_range_source = next(
        (name for name, text in range_sources if _dhcp_range_matches(text, expected_range)),
        None,
    )

    return {
        "desired_ip": desired_ip,
        "current_ip": current_ip,
        "ip_matches": current_ip == desired_ip,
        "ip_commands": commands,
        "dnsmasq_conf_path": str(DNSMASQ_ACTIVE_CONF),
        "dnsmasq_conf_present": bool(dnsmasq_text),
        "expected_dhcp_range": expected_range,
        "dhcp_range_matches": dhcp_range_source is not None,
        "dhcp_range_source": dhcp_range_source,
        "managed_ap_section_found": managed_ap_body is not None,
        "dnsmasq_candidate_checked": bool(dnsmasq_candidate),
    }


def _post_apply_warning(checks: Mapping[str, object]) -> str | None:
    if not checks:
        return None

    issues: list[str] = []
    desired_ip = str(checks.get("desired_ip") or "")
    current_ip = checks.get("current_ip")
    if desired_ip and current_ip != desired_ip:
        observed_ip = str(current_ip) if current_ip else "unknown"
        issues.append(f"wlan0ap IP is {observed_ip} (expected {desired_ip})")
    if not checks.get("dhcp_range_matches"):
        expected_range = checks.get("expected_dhcp_range")
        issues.append(f"dnsmasq.conf missing expected dhcp-range {expected_range}")

    if not issues:
        return None

    remediation = (
        f"Retry: {WLAN0AP_IP_REMEDIATION} && systemctl restart dnsmasq && systemctl restart hostapd. "
        "If dnsmasq range stays stale, restart DNS with 'systemctl restart dnsmasq'."
    )
    return f"Post-apply check: {'; '.join(issues)}. {remediation}"


def _iptables_rule_present(save_output: str, rule: str) -> bool:
    if not rule:
        return False
    if rule in save_output:
        return True
    if "ESTABLISHED,RELATED" in rule:
        alternate = rule.replace("ESTABLISHED,RELATED", "RELATED,ESTABLISHED")
        return alternate in save_output
    return False


def _parse_default_route_interface(output: str) -> str | None:
    try:
        entries = json.loads(output)
    except json.JSONDecodeError:
        entries = None

    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, Mapping):
                continue
            if entry.get("dst") not in {None, "default"}:
                continue
            device = entry.get("dev")
            if isinstance(device, str) and device.strip():
                return device.strip()

    match = re.search(r"^default\b.*?\bdev\s+(\S+)", output, flags=re.MULTILINE)
    if match:
        return match.group(1)

    return None


def _select_uplink_interface(
    configured: str | None, *, default_route: str | None, env_override: str | None = None
) -> tuple[str, str | None]:
    candidates = [configured, env_override, default_route, UPSTREAM_INTERFACE, "eth0"]
    for candidate in candidates:
        if candidate and candidate != AP_INTERFACE:
            source = "configured" if candidate == configured else None
            if not source and candidate == env_override:
                source = "env"
            elif not source and candidate == default_route:
                source = "route"
            elif not source and candidate == UPSTREAM_INTERFACE:
                source = "default"
            elif not source:
                source = "fallback"
            return candidate, source
    fallback = UPSTREAM_INTERFACE if UPSTREAM_INTERFACE != AP_INTERFACE else "eth0"
    return fallback, "fallback"


def _detect_uplink_interface(config: Mapping[str, object]) -> tuple[str, dict[str, object]]:
    configured = str(
        config.get("upstream_interface")
        or config.get("uplink_interface")
        or config.get("wan_interface")
        or ""
    ).strip()
    env_override = os.environ.get("MCBRIDGE_UPSTREAM_INTERFACE", "").strip()

    route_checks: list[dict[str, object]] = []
    default_route: str | None = None
    for command in ("-j", ""):
        route_command = ["ip", *("-j" if command else []), "route", "show", "default"]
        route_result = _run_command(route_command)
        route_checks.append(route_result)
        if not _command_success(route_result) or default_route:
            continue
        default_route = _parse_default_route_interface(str(route_result.get("stdout") or ""))

    uplink, source = _select_uplink_interface(configured or None, default_route=default_route, env_override=env_override)
    return uplink, {
        "configured": configured or None,
        "env": env_override or None,
        "default_route": default_route,
        "source": source,
        "route_checks": route_checks,
    }


def _ensure_forwarding_and_nat(
    uplink_interface: str, *, dry_run: bool, detection: Mapping[str, object] | None = None
) -> dict[str, object]:
    nat_interface = uplink_interface if uplink_interface != AP_INTERFACE else UPSTREAM_INTERFACE
    if nat_interface == AP_INTERFACE:
        nat_interface = "eth0"
    ip_forward_check = _run_command(["sysctl", "-n", "net.ipv4.ip_forward"])
    ip_forward_enabled = str(ip_forward_check.get("stdout") or "").strip() == "1"
    ip_forward_set: dict[str, object] | None = None
    if not ip_forward_enabled and not dry_run:
        ip_forward_set = _run_command(["sysctl", "-w", "net.ipv4.ip_forward=1"])
        ip_forward_enabled = _command_success(ip_forward_set)
    ip_forward_status = "ok" if ip_forward_enabled else "warning"
    ip_forward_message = (
        None if ip_forward_enabled else f"net.ipv4.ip_forward is disabled (required for {AP_INTERFACE} -> {nat_interface})"
    )

    iptables_save = _run_command(["iptables-save"])
    save_output = str(iptables_save.get("stdout") or "")
    inspection_failed = iptables_save.get("returncode") not in (0,)
    inspection_error = iptables_save.get("stderr") or iptables_save.get("error") or save_output
    expected_rules = {
        "masquerade": {
            "table": "nat",
            "chain": "POSTROUTING",
            "args": ["-o", nat_interface, "-j", "MASQUERADE"],
            "match": f"-A POSTROUTING -o {nat_interface} -j MASQUERADE",
        },
        "forward_ap_to_upstream": {
            "table": "",
            "chain": "FORWARD",
            "args": ["-i", AP_INTERFACE, "-o", nat_interface, "-j", "ACCEPT"],
            "match": f"-A FORWARD -i {AP_INTERFACE} -o {nat_interface} -j ACCEPT",
        },
        "forward_upstream_to_ap": {
            "table": "",
            "chain": "FORWARD",
            "args": ["-i", nat_interface, "-o", AP_INTERFACE, "-m", "state", "--state", "ESTABLISHED,RELATED", "-j", "ACCEPT"],
            "match": f"-A FORWARD -i {nat_interface} -o {AP_INTERFACE} -m state --state ESTABLISHED,RELATED -j ACCEPT",
        },
    }
    status = "ok"
    message_parts: list[str] = []
    missing_rules: list[str] = []
    applied_rules: list[str] = []
    rule_results: dict[str, object] = {}

    inspection_message = None
    if inspection_failed:
        warning_detail = inspection_error.strip() if inspection_error else None
        inspection_message = "iptables inspection failed; attempting to enforce NAT/forwarding directly"
        if warning_detail:
            inspection_message = f"{inspection_message} ({warning_detail})"
        message_parts.append(f"{inspection_message} on {nat_interface}.")

    for name, rule in expected_rules.items():
        present = (not inspection_failed) and _iptables_rule_present(save_output, rule["match"])
        check_cmd: dict[str, object] | None = None
        apply_cmd: dict[str, object] | None = None
        ensured = present
        if not present:
            missing_rules.append(name)
            if not dry_run:
                check_cmd = _run_command(["iptables", "-t", rule["table"], "-C", rule["chain"], *rule["args"]] if rule["table"] else ["iptables", "-C", rule["chain"], *rule["args"]])
                ensured = _command_success(check_cmd)
                if not ensured:
                    apply_cmd = _run_command(["iptables", "-t", rule["table"], "-A", rule["chain"], *rule["args"]] if rule["table"] else ["iptables", "-A", rule["chain"], *rule["args"]])
                    ensured = _command_success(apply_cmd)
                    if ensured:
                        applied_rules.append(name)
        rule_results[name] = {
            "present": present,
            "ensured": ensured,
            "check": check_cmd,
            "apply": apply_cmd,
            "rule": rule,
        }

    unresolved_rules = [name for name, details in rule_results.items() if not details.get("ensured")]
    guidance: str | None = None

    if dry_run and missing_rules:
        status = "warning"
        guidance = f"iptables NAT/forwarding rules missing for {nat_interface}; would add {', '.join(missing_rules)}"
    elif unresolved_rules:
        status = "error"
        failed_rules = ", ".join(unresolved_rules)
        guidance = f"iptables NAT/forwarding rules missing on {nat_interface} and could not be installed: {failed_rules}"
    elif applied_rules:
        guidance = f"iptables NAT/forwarding rules were missing for {nat_interface}; reapplied {', '.join(applied_rules)}"
    elif inspection_failed:
        guidance = f"iptables inspection failed; verified NAT/forwarding rules directly on {nat_interface}."
    else:
        guidance = f"NAT/forwarding rules verified on {nat_interface}."

    if ip_forward_status != "ok":
        status = "warning" if status == "ok" else status
        if ip_forward_message:
            message_parts.append(ip_forward_message)

    if guidance:
        message_parts.append(guidance)

    repair_attempted = bool(applied_rules) or (inspection_failed and not dry_run)

    return {
        "status": status,
        "message": "; ".join(message_parts) if message_parts else None,
        "guidance": guidance,
        "inspection_failed": inspection_failed,
        "inspection_message": inspection_message,
        "inspection_error": inspection_error,
        "iptables_save": iptables_save,
        "ip_forwarding": {
            "enabled": ip_forward_enabled,
            "check": ip_forward_check,
            "set": ip_forward_set,
        },
        "nat_interface": nat_interface,
        "uplink_detection": dict(detection or {}),
        "rules": rule_results,
        "missing_rules": missing_rules,
        "unresolved_rules": unresolved_rules,
        "applied_rules": applied_rules,
        "repair_attempted": repair_attempted,
    }


def _parse_wlan0ap_ip_from_ip_addr(output: str) -> str | None:
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return None

    for entry in data if isinstance(data, list) else []:
        if entry.get("ifname") != "wlan0ap":
            continue
        for addr in entry.get("addr_info") or []:
            if addr.get("family") == "inet" and addr.get("local"):
                prefix = addr.get("prefixlen")
                suffix = f"/{prefix}" if prefix is not None else ""
                return f"{addr.get('local')}{suffix}"
    return None


def _detect_wlan0ap_ip() -> tuple[str | None, list[dict[str, object]]]:
    commands: list[dict[str, object]] = []
    primary = _run_command(["ip", "-j", "addr", "show", "wlan0ap"])
    commands.append(primary)
    if primary.get("returncode") == 0 and primary.get("stdout"):
        current_ip = _parse_wlan0ap_ip_from_ip_addr(str(primary.get("stdout")))
        if current_ip:
            return current_ip, commands
    return None, commands


def _persist_ap_json(updated_config: Mapping[str, object], *, dry_run: bool) -> dict[str, object]:
    sanitized_config = _sanitize_ap_config(updated_config)
    current_json_text = read_text(AP_JSON)
    new_json_text = json.dumps(sanitized_config, indent=2) + "\n"
    result = {
        "path": str(AP_JSON),
        "diff": diff_text(current_json_text, new_json_text, fromfile=str(AP_JSON), tofile=f"{AP_JSON} (candidate)"),
        "actions": [f"write {AP_JSON}"],
        "applied": False,
        "changed": current_json_text != new_json_text,
    }

    if dry_run:
        result["status"] = "planned" if result["changed"] else "unchanged"
        return result

    if current_json_text and current_json_text != new_json_text:
        write_history_file(CONFIG_HISTORY_DIR, suffix="ap.json", contents=current_json_text)
    save_json(AP_JSON, dict(sanitized_config))
    result["applied"] = True
    result["status"] = "updated" if result["changed"] else "unchanged"
    return result


def _wlan0ap_ip_service_contents(desired_ip: str) -> str:
    lines = [
        "# Generated by mcbridge manage-ap",
        "",
        "[Unit]",
        f"Description=Assign static IP {desired_ip} to {AP_INTERFACE}",
        "After=wlan0ap.service",
        "Requires=wlan0ap.service",
        "Before=hostapd.service dnsmasq.service",
        "",
        "[Service]",
        "Type=oneshot",
        f"ExecStartPre=/sbin/ip addr flush dev {AP_INTERFACE} scope global",
        f"ExecStart=/sbin/ip addr replace {desired_ip} dev {AP_INTERFACE}",
        f"ExecStart=/sbin/ip link set {AP_INTERFACE} up",
        "RemainAfterExit=yes",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    return "\n".join(lines) + "\n"


def _command_success(result: Mapping[str, object] | None) -> bool:
    if not isinstance(result, Mapping):
        return False
    return result.get("returncode") == 0


def _interface_is_up(check_result: Mapping[str, object] | None) -> bool:
    if not isinstance(check_result, Mapping):
        return False
    stdout = str(check_result.get("stdout") or "")
    if "state UP" in stdout:
        return True
    return bool(re.search(r"<[^>]*\\bUP\\b[^>]*>", stdout))


def _sync_wlan0ap_ip_service(desired_ip: str, *, dry_run: bool) -> dict[str, object]:
    candidate = _wlan0ap_ip_service_contents(desired_ip)
    current_service = read_text(WLAN0AP_IP_SERVICE)
    current_generated = read_text(WLAN0AP_IP_GENERATED)
    diff_active = diff_text(
        current_service, candidate, fromfile=str(WLAN0AP_IP_SERVICE), tofile=f"{WLAN0AP_IP_SERVICE} (candidate)"
    )
    diff_generated = diff_text(
        current_generated,
        candidate,
        fromfile=str(WLAN0AP_IP_GENERATED),
        tofile=f"{WLAN0AP_IP_GENERATED} (candidate)",
    )
    changed = (current_service != candidate) or (current_generated != candidate)
    actions = [
        f"write {WLAN0AP_IP_GENERATED}",
        f"write {WLAN0AP_IP_SERVICE}",
        "systemctl daemon-reload",
        f"systemctl enable --now {WLAN0AP_IP_UNIT}",
        f"systemctl restart {WLAN0AP_IP_UNIT}",
    ]
    result: dict[str, object] = {
        "status": "planned" if changed else "unchanged",
        "path": str(WLAN0AP_IP_SERVICE),
        "generated_path": str(WLAN0AP_IP_GENERATED),
        "changed": changed,
        "applied": False,
        "actions": actions,
        "diff_active": diff_active,
        "diff_generated": diff_generated,
        "reload": None,
        "enable": None,
        "restart": None,
        "remediation": WLAN0AP_IP_REMEDIATION,
        "service_enabled": None,
        "ip_check": None,
        "ip_matches": None,
    }

    if dry_run:
        return result

    if changed:
        if current_service:
            write_history_file(GENERATED_HISTORY_DIR, suffix=WLAN0AP_IP_UNIT, contents=current_service)
        privileges.sudo_write_file(
            WLAN0AP_IP_GENERATED,
            candidate,
            mode=0o644,
            owner="root",
            group="root",
        )
        privileges.sudo_write_file(
            WLAN0AP_IP_SERVICE,
            candidate,
            mode=0o644,
            owner="root",
            group="root",
        )
        result["status"] = "updated"
    result["reload"] = _run_command(["systemctl", "daemon-reload"])
    result["enable"] = _run_command(["systemctl", "enable", "--now", WLAN0AP_IP_UNIT])
    result["service_enabled"] = _command_success(result["enable"])

    restart_result = None
    if result["service_enabled"]:
        restart_result = _run_command(["systemctl", "restart", WLAN0AP_IP_UNIT])
    result["restart"] = restart_result

    current_ip, ip_commands = _detect_wlan0ap_ip()
    result["ip_check"] = {"current_ip": current_ip, "commands": ip_commands}
    result["ip_matches"] = current_ip == desired_ip

    reload_success = _command_success(result["reload"])
    restart_success = _command_success(restart_result) if restart_result is not None else result["service_enabled"]
    commands_success = reload_success and result["service_enabled"] and restart_success
    result["applied"] = commands_success and bool(result["ip_matches"])

    if not commands_success:
        result["status"] = "failed"
        errors = [
            (result["reload"] or {}).get("stderr"),
            (result["enable"] or {}).get("stderr"),
            (restart_result or {}).get("stderr"),
        ]
        result["error"] = next((err for err in errors if err), "Failed to apply wlan0ap-ip.service")
    elif not result["ip_matches"]:
        result["status"] = "failed"
        result["error"] = f"{AP_INTERFACE} missing expected IP {desired_ip} after enabling {WLAN0AP_IP_UNIT}"
    return result


def _ensure_ap_interface(upstream: str | None = None, *, dry_run: bool = False) -> dict[str, object]:
    upstream_iface = upstream or UPSTREAM_INTERFACE
    commands: list[dict[str, object]] = []
    check = _run_command(["ip", "link", "show", AP_INTERFACE])
    commands.append(check)
    if _command_success(check):
        return {
            "status": "present",
            "applied": True,
            "created": False,
            "commands": commands,
            "upstream": upstream_iface,
        }

    if dry_run:
        logger.warning(
            "Access point interface %s missing; would create using upstream %s (dry run)", AP_INTERFACE, upstream_iface
        )
        return {
            "status": "planned",
            "applied": False,
            "created": True,
            "commands": commands,
            "upstream": upstream_iface,
            "reason": "dry_run",
            "error": check.get("stderr") or check.get("stdout") or f"{AP_INTERFACE} missing",
        }

    logger.warning("Access point interface %s missing; attempting creation using upstream %s", AP_INTERFACE, upstream_iface)
    create = _run_command(["iw", "dev", upstream_iface, "interface", "add", AP_INTERFACE, "type", "__ap"])
    commands.append(create)
    if not _command_success(create):
        error = create.get("stderr") or create.get("stdout") or f"Failed to create {AP_INTERFACE}"
        logger.error("Failed to create %s via iw: %s", AP_INTERFACE, error)
        return {
            "status": "failed",
            "applied": False,
            "created": False,
            "commands": commands,
            "upstream": upstream_iface,
            "error": error,
        }

    link_up = _run_command(["ip", "link", "set", AP_INTERFACE, "up"])
    commands.append(link_up)
    if not _command_success(link_up):
        error = link_up.get("stderr") or link_up.get("stdout") or f"Failed to bring {AP_INTERFACE} up"
        logger.error("Failed to bring %s up: %s", AP_INTERFACE, error)
        return {
            "status": "failed",
            "applied": False,
            "created": False,
            "commands": commands,
            "upstream": upstream_iface,
            "error": error,
        }

    verify = _run_command(["ip", "link", "show", AP_INTERFACE])
    commands.append(verify)
    if _command_success(verify):
        logger.info("Created %s using upstream %s", AP_INTERFACE, upstream_iface)
        return {
            "status": "created",
            "applied": True,
            "created": True,
            "commands": commands,
            "upstream": upstream_iface,
        }

    error = verify.get("stderr") or verify.get("stdout") or f"{AP_INTERFACE} still missing after creation"
    logger.error("Failed to verify %s after creation: %s", AP_INTERFACE, error)
    return {
        "status": "failed",
        "applied": False,
        "created": False,
        "commands": commands,
        "upstream": upstream_iface,
        "error": error,
    }


def _stop_hostapd_and_remove_interface(*, dry_run: bool) -> dict[str, object]:
    actions = [
        ["systemctl", "stop", "hostapd"],
        ["ip", "link", "set", AP_INTERFACE, "down"],
        ["iw", "dev", AP_INTERFACE, "del"],
    ]
    if dry_run:
        return {
            "status": "planned",
            "applied": False,
            "success": None,
            "commands": actions,
        }

    command_results = [_run_command(command) for command in actions]
    success = all(_command_success(result) for result in command_results)
    return {
        "status": "attempted",
        "applied": True,
        "success": success,
        "commands": command_results,
    }


def _ensure_ap_interface_up_for_validation(*, dry_run: bool) -> tuple[bool, dict[str, object]]:
    checks: list[dict[str, object]] = []
    restart_result: dict[str, object] | None = None
    exists, first_check = check_interface_exists(AP_INTERFACE)
    checks.append(first_check)
    interface_up = exists and _interface_is_up(first_check)

    if not interface_up:
        restart_result = _run_command(["systemctl", "restart", "wlan0ap.service"])
        exists, second_check = check_interface_exists(AP_INTERFACE)
        checks.append(second_check)
        interface_up = exists and _interface_is_up(second_check)

    ensure_result: dict[str, object] | None = None
    if not interface_up:
        ensure_result = _ensure_ap_interface(dry_run=dry_run)
        interface_up = ensure_result.get("status") in {"present", "created"}
        if not interface_up:
            exists, final_check = check_interface_exists(AP_INTERFACE)
            checks.append(final_check)
            interface_up = exists and _interface_is_up(final_check)

    ap_interface_info = dict(ensure_result or {})
    if "status" not in ap_interface_info:
        ap_interface_info["status"] = "present" if interface_up else "missing"
    ap_interface_info.setdefault("applied", interface_up)
    ap_interface_info.setdefault("created", False)
    ap_interface_info["checks"] = checks
    ap_interface_info["wlan0ap_service"] = restart_result
    return interface_up, ap_interface_info


def _hostapd_template(config: Mapping[str, object]) -> str:
    ssid = str(config.get("ssid") or "Minecraft")
    password = str(config.get("password") or "")
    channel = int(config.get("channel") or 6)

    security_lines = ["wpa=0", "auth_algs=1"]
    if password:
        security_lines = [
            "wpa=2",
            "wpa_key_mgmt=WPA-PSK",
            "rsn_pairwise=CCMP",
            f"wpa_passphrase={password}",
        ]

    lines = [
        "# Generated by mcbridge manage-ap",
        "interface=wlan0ap",
        "driver=nl80211",
        f"ssid={ssid}",
        "hw_mode=g",
        f"channel={channel}",
        "ieee80211n=1",
        "wmm_enabled=1",
        "ignore_broadcast_ssid=0",
        *security_lines,
    ]
    return "\n".join(lines) + "\n"


def _resolve_upstream_servers() -> list[str]:
    persisted = upstream_dns.load_upstream_dns()
    if persisted.servers:
        return persisted.servers
    for resolv_path in UPSTREAM_DHCP_RESOLV_PATHS:
        contents = read_text(resolv_path)
        if not contents:
            continue
        servers = _parse_resolv_nameservers(contents)
        if servers:
            return servers
    return []


def _apply_upstream_wifi_config(*, dry_run: bool) -> dict[str, object]:
    warnings: list[str] = []
    profiles = upstream.load_profiles(warnings=warnings)
    if not profiles:
        return {
            "status": "skipped",
            "reason": "no_profiles",
            "applied": False,
            "path": str(UPSTREAM_WPA_SUPPLICANT_CONF),
            "generated_path": str(UPSTREAM_WPA_GENERATED_CONF),
            "warnings": warnings,
        }

    candidate = _render_wpa_supplicant(UPSTREAM_INTERFACE, profiles)
    current = read_text(UPSTREAM_WPA_SUPPLICANT_CONF)
    changed = candidate != current

    if dry_run:
        return {
            "status": "planned",
            "applied": False,
            "changed": changed,
            "path": str(UPSTREAM_WPA_SUPPLICANT_CONF),
            "generated_path": str(UPSTREAM_WPA_GENERATED_CONF),
            "candidate": candidate,
            "warnings": warnings,
            "profiles": [
                {
                    "ssid": profile.ssid,
                    "priority": profile.priority,
                    "security": profile.security,
                    "has_password": profile.has_password,
                }
                for profile in profiles
            ],
        }

    backup_path: Path | None = None
    if changed:
        if current:
            backup_path = write_history_file(
                GENERATED_HISTORY_DIR, suffix=UPSTREAM_WPA_SUPPLICANT_CONF.name, contents=current
            )
            logger.info("Archived previous version of %s to history", UPSTREAM_WPA_SUPPLICANT_CONF)

        ensure_parent(UPSTREAM_WPA_SUPPLICANT_CONF)
        privileges.sudo_write_file(
            UPSTREAM_WPA_SUPPLICANT_CONF,
            candidate,
            mode=0o600,
            owner="root",
            group="root",
        )
        set_default_permissions(UPSTREAM_WPA_SUPPLICANT_CONF)
    else:
        logger.info("Upstream Wi-Fi configuration already matches %s", UPSTREAM_WPA_SUPPLICANT_CONF)

    generated_written: Path | None = None
    if UPSTREAM_WPA_GENERATED_CONF != UPSTREAM_WPA_SUPPLICANT_CONF:
        ensure_parent(UPSTREAM_WPA_GENERATED_CONF)
        privileges.sudo_write_file(
            UPSTREAM_WPA_GENERATED_CONF,
            candidate,
            mode=DEFAULT_FILE_MODE,
            owner=DEFAULT_FILE_OWNER,
            group=DEFAULT_FILE_GROUP,
        )
        set_default_permissions(UPSTREAM_WPA_GENERATED_CONF)
        generated_written = UPSTREAM_WPA_GENERATED_CONF

    status = "unchanged" if not changed else "updated"
    return {
        "status": status,
        "applied": True,
        "changed": changed,
        "path": str(UPSTREAM_WPA_SUPPLICANT_CONF),
        "generated_path": str(generated_written or UPSTREAM_WPA_GENERATED_CONF),
        "backup_path": str(backup_path) if backup_path else None,
        "warnings": warnings,
        "profiles": [
            {
                "ssid": profile.ssid,
                "priority": profile.priority,
                "security": profile.security,
                "has_password": profile.has_password,
            }
            for profile in profiles
        ],
    }


def _ap_section_body(config: Mapping[str, object], *, upstream_servers: Sequence[str] | None = None) -> str:
    ssid = str(config.get("ssid") or "Minecraft")
    subnet_octet = int(config.get("subnet_octet") or DEFAULT_SUBNET_OCTET)
    base = f"192.168.{subnet_octet}."

    upstream_servers = list(upstream_servers) if upstream_servers is not None else _resolve_upstream_servers()
    if not upstream_servers:
        resolv_paths = ", ".join(str(path) for path in UPSTREAM_DHCP_RESOLV_PATHS)
        raise ValueError(
            "No upstream DNS servers detected in upstream DNS cache or DHCP-derived resolv.conf data. "
            f"Checked {upstream_dns.UPSTREAM_DNS_JSON} and {resolv_paths}; connect the upstream interface and retry."
        )

    lines = [
        "",
        "interface=wlan0ap",
        "bind-interfaces",
        "",
        "",
        "# DHCP (clients on %s SSID)" % ssid,
        "# set by manage-ap",
        f"dhcp-range={base}10,{base}60,12h",
        f"dhcp-option=3,{base}1     # gateway",
        f"dhcp-option=6,{base}1     # DNS",
        "",
        "# Upstream DNS",
        *(f"server={server}" for server in upstream_servers),
    ]
    return "\n".join(lines)


def _default_dnsmasq_section_body(overrides_text: str = "") -> str:
    override_lines = [line for line in overrides_text.splitlines() if line.strip()]
    if any(line.strip() == "# --- DNS overrides ---" for line in override_lines):
        return "\n".join(override_lines)

    lines = ["", "# --- DNS overrides ---", "# overrides set by manage-dnsmasq"]
    if override_lines:
        lines.extend(override_lines)
    else:
        lines.append("# (none configured)")
    return "\n".join(lines)


def _dns_override_template(config: Mapping[str, object]) -> str:
    redirect = str(config.get("redirect") or "").strip()
    target = str(config.get("target") or "").strip()
    enabled = bool(config.get("enabled", True))
    name = str(config.get("name") or "").strip()

    lines = ["", "# --- DNS overrides ---", "# overrides set by manage-dnsmasq"]
    if name:
        lines.append(f"# name={name}")
    if redirect:
        lines.append(f"# redirect={redirect}")
    if target:
        lines.append(f"# target={target}")
    if enabled and redirect and target:
        lines.extend(_dns_override_lines(redirect, target))
    else:
        lines.append("# overrides disabled")
    return "\n".join(lines)


def _load_dns_override_config() -> dict[str, object]:
    raw_config, source = load_dns_overrides_config(default={})
    if source == "dnsmasq.json":
        logger.warning("dns_overrides.json missing; using legacy dnsmasq.json for DNS overrides.")
    try:
        normalized = normalize_dns_override_payload(raw_config, default_target=_load_knownservers_target())
    except ValueError as exc:
        raise ValueError(f"{source} requires migration: {exc}") from exc
    return normalized


def _load_knownservers_target() -> str | None:
    raw = load_json(KNOWN_SERVERS_JSON, default={})
    if not isinstance(raw, Mapping):
        return None
    target_value = str(raw.get("target") or "").strip()
    return target_value or None


def _resolve_override_body(*, active_config: str = "", generated_config: str = "") -> str:
    overrides_file_text = read_text(DNSMASQ_OVERRIDES_CONF)
    parsed_override_config: Mapping[str, object] = {}
    default_body: str | None = None
    for source in (overrides_file_text, generated_config, active_config):
        section_body = extract_section_body(source, MANAGE_DNSMASQ_SECTION_START, MANAGE_DNSMASQ_SECTION_END)
        if section_body is not None:
            default_body = _default_dnsmasq_section_body(section_body)
            parsed_override_config = parse_dns_overrides(default_body.splitlines())
            break
    else:
        for source in (overrides_file_text, generated_config, active_config):
            if not source:
                continue
            parsed = parse_dns_overrides(source.splitlines())
            if parsed.get("redirect") or parsed.get("target"):
                default_body = default_body or _default_dnsmasq_section_body(source)
                parsed_override_config = parsed
                break

    override_json_config = _load_dns_override_config()
    default_target = _load_knownservers_target()
    if override_json_config:
        merged_config = {
            "redirect": override_json_config.get("redirect") or parsed_override_config.get("redirect"),
            "target": override_json_config.get("target") or parsed_override_config.get("target") or default_target,
            "enabled": bool(override_json_config.get("enabled", parsed_override_config.get("enabled", True))),
            "name": override_json_config.get("name") or parsed_override_config.get("name"),
        }
        return _dns_override_template(merged_config)

    if parsed_override_config.get("redirect") or parsed_override_config.get("target"):
        if (parsed_override_config.get("target_conflict") or parsed_override_config.get("redirect_conflict")) and default_body:
            return default_body
        return _dns_override_template(
            {
                "redirect": parsed_override_config.get("redirect"),
                "target": parsed_override_config.get("target") or default_target,
                "enabled": parsed_override_config.get("enabled", True),
                "name": parsed_override_config.get("name"),
            }
        )

    return _default_dnsmasq_section_body()


def _ensure_overrides_conf(override_body: str) -> dict[str, object]:
    current = read_text(DNSMASQ_OVERRIDES_CONF)
    updated = current != override_body
    result = {
        "path": str(DNSMASQ_OVERRIDES_CONF),
        "updated": False,
    }
    if updated:
        DNSMASQ_OVERRIDES_CONF.parent.mkdir(parents=True, exist_ok=True)
        DNSMASQ_OVERRIDES_CONF.write_text(override_body, encoding="utf-8")
        result["updated"] = True
    return result


def _managed_sections_conflict(active_config: str, generated_config: str) -> bool:
    if not active_config or not generated_config:
        return False

    managed_pairs = (
        (MANAGE_AP_SECTION_START, MANAGE_AP_SECTION_END),
        (MANAGE_DNSMASQ_SECTION_START, MANAGE_DNSMASQ_SECTION_END),
    )
    for start_marker, end_marker in managed_pairs:
        active_body = extract_section_body(active_config, start_marker, end_marker)
        generated_body = extract_section_body(generated_config, start_marker, end_marker)
        if active_body is None or generated_body is None:
            continue
        if active_body.strip() != generated_body.strip():
            return True
    return False


def _deduplicate_managed_sections(contents: str) -> tuple[str, bool]:
    lines = contents.splitlines()
    markers = (
        (MANAGE_AP_SECTION_START, MANAGE_AP_SECTION_END),
        (MANAGE_DNSMASQ_SECTION_START, MANAGE_DNSMASQ_SECTION_END),
    )
    start_counts = {start: sum(1 for line in lines if line.strip() == start) for start, _ in markers}
    has_duplicates = any(count > 1 for count in start_counts.values())
    if not has_duplicates:
        return contents, False

    ap_body = extract_section_body(contents, MANAGE_AP_SECTION_START, MANAGE_AP_SECTION_END) or ""
    dns_body = (
        extract_section_body(contents, MANAGE_DNSMASQ_SECTION_START, MANAGE_DNSMASQ_SECTION_END)
        or _default_dnsmasq_section_body()
    )
    cleaned = assemble_dnsmasq_config(ap_body, dns_body)
    return cleaned, True


def _dnsmasq_template(
    config: Mapping[str, object],
    *,
    existing_config: str = "",
    active_config: str = "",
    generated_config: str = "",
    override_body: str | None = None,
) -> str:
    override_body = override_body or _default_dnsmasq_section_body()
    upstream_servers = _resolve_upstream_servers()
    merged_active = active_config or existing_config
    if _managed_sections_conflict(merged_active, generated_config):
        logger.warning(
            "Active dnsmasq.conf contains managed sections that differ from the generated template; preferring generated content."
        )
        merged_active = ""
    layout_active = analyse_dnsmasq_layout(merged_active)
    layout_generated = analyse_dnsmasq_layout(generated_config)
    layout_warn = layout_active.get("needs_cleanup") or layout_generated.get("needs_cleanup")
    if layout_warn:
        logger.warning(
            "Detected duplicate managed sections, missing managed overrides, or stray inline overrides; rebuilding dnsmasq.conf with managed content."
        )
    return assemble_dnsmasq_config(_ap_section_body(config, upstream_servers=upstream_servers), override_body)


def _ensure_hostapd_daemon_conf(*, dry_run: bool) -> dict[str, object]:
    target = str(HOSTAPD_ACTIVE_CONF)
    desired_line = f'DAEMON_CONF="{target}"'
    actions = ["ensure hostapd defaults", f"set DAEMON_CONF={target}"]

    if dry_run:
        logger.info("Dry run: would set DAEMON_CONF in %s", HOSTAPD_DEFAULTS)
        return {"path": str(HOSTAPD_DEFAULTS), "status": "skipped", "reason": "dry_run", "actions": actions}

    existing = read_text(HOSTAPD_DEFAULTS)
    lines = existing.splitlines()
    updated_lines: list[str] = []
    replaced = False
    for line in lines:
        if re.match(r"^#?DAEMON_CONF=", line.strip()):
            updated_lines.append(desired_line)
            replaced = True
        else:
            updated_lines.append(line)
    if not replaced:
        if updated_lines and updated_lines[-1].strip():
            updated_lines.append("")
        updated_lines.append(desired_line)
    new_contents = "\n".join(updated_lines) + ("\n" if updated_lines else desired_line + "\n")
    if new_contents == existing or (existing and new_contents.rstrip("\n") == existing.rstrip("\n")):
        logger.info("DAEMON_CONF already points to %s in %s", target, HOSTAPD_DEFAULTS)
        return {"path": str(HOSTAPD_DEFAULTS), "status": "unchanged", "actions": actions}

    ensure_parent(HOSTAPD_DEFAULTS)
    privileges.sudo_write_file(
        HOSTAPD_DEFAULTS,
        new_contents,
        mode=0o644,
        owner="root",
        group="root",
    )
    logger.info("Updated DAEMON_CONF in %s to %s", HOSTAPD_DEFAULTS, target)
    return {"path": str(HOSTAPD_DEFAULTS), "status": "updated", "actions": actions}


def _validate_and_apply(
    *,
    path: Path,
    candidate: str,
    deploy_paths: tuple[Path, ...] | None = None,
    snapshot_paths: tuple[Path, ...] | None = None,
    validate_command: list[str],
    service: str,
    dry_run: bool,
    history_suffix: str,
    history_dir: Path,
    force_restart: bool = False,
) -> dict:
    cleanup_applied = False
    if service == "dnsmasq":
        candidate, cleanup_applied = _deduplicate_managed_sections(candidate)
        if cleanup_applied:
            logger.warning("Detected duplicate managed dnsmasq sections; normalizing configuration before validation.")

    current = read_text(path)
    current_mtime = collect_file_mtimes([path]).get(str(path))
    diff = diff_text(current, candidate, fromfile=str(path), tofile=f"{path} (candidate)")
    if diff:
        logger.debug("Planned diff for %s:\n%s", path, diff)
    else:
        logger.debug("No content changes detected for %s", path)
    changed = bool(diff)
    restart_action_label = f"restart {service}"
    if service != "dnsmasq":
        restart_action_label = f"reload-or-restart {service}"
    actions = [
        f"write {path}",
        *(f"copy {path} -> {dest}" for dest in deploy_paths or ()),
        f"validate with {' '.join(validate_command)}",
        restart_action_label,
    ]
    if service == "hostapd":
        actions.insert(0, "systemctl stop hostapd")
        actions[-1] = "start hostapd"
    elif service == "dnsmasq":
        actions.insert(0, "systemctl stop dnsmasq")

    validation_result: dict[str, object] | None = None
    hostapd_defaults_result: dict[str, object] | None = None
    hostapd_status: dict[str, object] | None = None
    hostapd_running = False
    hostapd_status_unavailable = False
    hostapd_status_message: str | None = None
    hostapd_stopped: dict[str, object] | None = None
    dnsmasq_stopped: dict[str, object] | None = None
    service_stop_action: dict[str, object] | None = None
    post_write_validation: dict[str, object] | None = None
    hostapd_stop_ok: bool | None = None
    if service == "hostapd":
        hostapd_defaults_result = _ensure_hostapd_daemon_conf(dry_run=dry_run)
        hostapd_status = service_status(service, timeout=SERVICE_TIMEOUT_SECONDS) if not dry_run else None
        hostapd_running = bool(hostapd_status and hostapd_status.get("returncode") == 0)
        hostapd_status_unavailable = bool(hostapd_status and hostapd_status.get("returncode") is None)
        if hostapd_status_unavailable:
            hostapd_status_message = (
                hostapd_status.get("stderr")
                or hostapd_status.get("stdout")
                or "hostapd status check returned no exit code"
            )
        if hostapd_running and validation_result is None and not force_restart:
            validation_result = {
                "status": "skipped",
                "skipped": True,
                "stdout": hostapd_status.get("stdout") if hostapd_status else "",
                "stderr": hostapd_status.get("stderr") or "",
                "returncode": None,
                "reason": "hostapd_running",
                "service_status": hostapd_status,
            }

    if dry_run:
        logger.info("Dry run: would validate and deploy %s (service=%s)", path, service)
        return {
            "path": str(path),
            "changed": changed,
            "validation": {"status": "skipped", "reason": "dry_run"},
            "service_restart": {"service": service, "status": "skipped", "success": None},
            "service_stop": hostapd_stopped,
            "actions": actions,
            "applied": False,
            "file_mtimes": {"before": current_mtime, "after": current_mtime},
            "pre_deploy_history": [],
            "candidate": candidate,
            "hostapd_defaults": hostapd_defaults_result,
        }

    with NamedTemporaryFile("w", delete=False, encoding="utf-8") as temp_file:
        temp_file.write(candidate)
        temp_path = Path(temp_file.name)

    interface_check: dict[str, object] | None = None
    interface_exists = False
    force_restart_cleanup: dict[str, object] | None = None
    ap_interface_after_validation: dict[str, object] | None = None
    backup_path: Path | None = None

    pre_deploy_history: list[dict[str, str]] = []
    if snapshot_paths:
        for snapshot_path in snapshot_paths:
            try:
                existing_contents = snapshot_path.read_text(encoding="utf-8")
            except FileNotFoundError:
                continue
            except OSError as exc:  # pragma: no cover - defensive for odd IO errors
                logger.debug("Could not read snapshot source %s: %s", snapshot_path, exc)
                continue
            if existing_contents == candidate:
                continue
            saved_path = write_history_file(
                history_dir, suffix=f"{snapshot_path.name}.active", contents=existing_contents
            )
            logger.info("Saved pre-deploy snapshot of %s to %s", snapshot_path, saved_path)
            pre_deploy_history.append({"path": str(snapshot_path), "saved_path": str(saved_path)})

    if current and current != candidate:
        backup_path = write_history_file(history_dir, suffix=history_suffix, contents=current)
        logger.info("Archived previous version of %s to history (%s)", path, history_suffix)

    deployed_paths: list[Path] = []

    try:
        placeholder_present = any("{path}" in str(entry) for entry in validate_command)
        validation_target = temp_path
        command = [str(entry).replace("{path}", str(validation_target)) for entry in validate_command]
        if not placeholder_present:
            command.append(str(validation_target))

        restart_after_failure: dict[str, object] | None = None
        if service == "hostapd":
            if hostapd_status_unavailable:
                validation_result = {
                    "status": "failed",
                    "skipped": False,
                    "stdout": hostapd_status.get("stdout") if hostapd_status else "",
                    "stderr": hostapd_status_message,
                    "returncode": hostapd_status.get("returncode") if hostapd_status else None,
                    "timeout": bool(hostapd_status and hostapd_status.get("timeout")),
                    "timeout_seconds": hostapd_status.get("timeout_seconds") if hostapd_status else None,
                    "service_status": hostapd_status,
                    "reason": "hostapd_status_unavailable",
                }
            if force_restart and validation_result is None:
                force_restart_cleanup = _stop_hostapd_and_remove_interface(dry_run=dry_run)
                hostapd_stopped = hostapd_stopped or force_restart_cleanup
                service_stop_action = service_stop_action or hostapd_stopped
                hostapd_stop_ok = force_restart_cleanup.get("success") if isinstance(force_restart_cleanup, Mapping) else None
            if validation_result is None and hostapd_stop_ok is None and not dry_run:
                hostapd_stopped = _run_command(["systemctl", "stop", "hostapd"])
                service_stop_action = service_stop_action or hostapd_stopped
                hostapd_stop_ok = _command_success(hostapd_stopped)
            if validation_result is None and hostapd_stop_ok is False:
                validation_result = {
                    "status": "failed",
                    "skipped": False,
                    "stdout": hostapd_stopped.get("stdout") if isinstance(hostapd_stopped, Mapping) else "",
                    "stderr": hostapd_stopped.get("stderr") if isinstance(hostapd_stopped, Mapping) else "",
                    "returncode": hostapd_stopped.get("returncode") if isinstance(hostapd_stopped, Mapping) else None,
                    "reason": "hostapd_stop_failed",
                    "service_stop": hostapd_stopped,
                }
            if validation_result is None:
                interface_ready, ap_interface_after_validation = _ensure_ap_interface_up_for_validation(dry_run=dry_run)
                interface_checks = ap_interface_after_validation.get("checks") or []
                interface_check = interface_checks[-1] if interface_checks else interface_check
                if not interface_ready:
                    error_message = (
                        f"{AP_INTERFACE} missing or down after restarting wlan0ap.service; "
                        "hostapd validation aborted"
                    )
                    validation_result = {
                        "status": "failed",
                        "skipped": False,
                        "stdout": "",
                        "stderr": error_message,
                        "returncode": 1,
                        "interface_check": interface_check,
                        "reason": "ap_interface_missing",
                    }

        if validation_result is None:
            logger.info("Validating %s with %s", path, " ".join(command))
            logger.debug("Validation command argv=%s", command)
            try:
                process = subprocess.run(command, capture_output=True, text=True, timeout=VALIDATION_TIMEOUT_SECONDS)
            except FileNotFoundError as exc:
                validation_result = {
                    "status": "failed",
                    "skipped": False,
                    "stdout": "",
                    "stderr": str(exc),
                    "returncode": 127,
                }
            except subprocess.TimeoutExpired as exc:
                stdout = getattr(exc, "stdout", getattr(exc, "output", ""))
                stderr = getattr(exc, "stderr", "")
                validation_result = {
                    "status": "failed",
                    "skipped": False,
                    "stdout": _normalize_timeout_stream(stdout),
                    "stderr": _normalize_timeout_stream(stderr),
                    "returncode": None,
                    "timeout": True,
                    "timeout_seconds": VALIDATION_TIMEOUT_SECONDS,
                }
            else:
                validation_result = {
                    "status": "passed" if process.returncode == 0 else "failed",
                    "skipped": False,
                    "stdout": process.stdout,
                    "stderr": process.stderr,
                    "returncode": process.returncode,
                }
        stdout_value = validation_result.get("stdout")
        if isinstance(stdout_value, (bytes, bytearray)):
            stdout_value = _normalize_timeout_stream(stdout_value)
            validation_result["stdout"] = stdout_value
        if stdout_value:
            logger.debug("Validation stdout for %s:\n%s", path, stdout_value)
        stderr_value = validation_result.get("stderr") or ""
        if isinstance(stderr_value, (bytes, bytearray)):
            stderr_text = _normalize_timeout_stream(stderr_value)
        else:
            stderr_text = str(stderr_value)
        validation_result["stderr"] = stderr_text
        if stderr_text:
            logger.debug("Validation stderr for %s:\n%s", path, stderr_text)
            is_failure = validation_result.get("status") == "failed" or (
                validation_result.get("returncode") not in (0, None) and not validation_result.get("skipped")
            )
            if command and command[0] == "dnsmasq":
                log_level = logging.ERROR if is_failure else logging.INFO
                logger.log(log_level, "dnsmasq validation stderr for %s:\n%s", path, stderr_text)
        logger.log(
            logging.INFO if validation_result.get("status") == "passed" else logging.ERROR,
            "Validation %s for %s (rc=%s)",
            validation_result.get("status"),
            path,
            validation_result.get("returncode"),
        )
        if validation_result.get("status") == "failed":
            stderr_text = validation_result.get("stderr") or ""
            first_stderr_line = stderr_text.splitlines()[0] if stderr_text else ""
            if isinstance(first_stderr_line, (bytes, bytearray)):
                first_stderr_line = _normalize_timeout_stream(first_stderr_line)
            else:
                first_stderr_line = str(first_stderr_line)
            if validation_result.get("timeout") and not first_stderr_line:
                first_stderr_line = (
                    f"Validation timed out after {validation_result.get('timeout_seconds') or VALIDATION_TIMEOUT_SECONDS}s"
                )
            if validation_result.get("returncode") is None and not validation_result.get("timeout") and not first_stderr_line:
                first_stderr_line = "Validation exited without a return code; treating as failure"
            line_hint = None
            if command and command[0] == "dnsmasq":
                match = re.search(r"line\s+(\d+)", stderr_text)
                if match:
                    line_hint = match.group(1)
            hint_segments: list[str] = []
            if line_hint:
                hint_segments.append(f"line {line_hint}")
            if first_stderr_line:
                hint_segments.append(first_stderr_line)
            error_message = f"Validation failed for {path}; see logs for validation output"
            if hint_segments:
                error_message = (
                    f"Validation failed for {path} (dnsmasq {'; '.join(hint_segments)}); see logs for validation output"
                )
            if first_stderr_line:
                print(f"{path}: {first_stderr_line}", file=sys.stderr)
            failed_paths = save_failed_validation_artifacts(
                candidate_contents=candidate,
                candidate_name=path.name,
                validate_command=command,
                returncode=validation_result.get("returncode"),
                stdout=validation_result.get("stdout") or "",
                stderr=stderr_text,
                failed_dir=FAILED_GENERATED_DIR,
            )
            validation_summary: str | None = None
            if service == "hostapd":
                summary_parts: list[str] = []
                if first_stderr_line:
                    summary_parts.append(first_stderr_line)
                elif validation_result.get("timeout"):
                    summary_parts.append(
                        f"hostapd validation timed out after {validation_result.get('timeout_seconds') or VALIDATION_TIMEOUT_SECONDS}s"
                    )
                if validation_result.get("returncode") is None and not validation_result.get("timeout") and not first_stderr_line:
                    summary_parts.append("hostapd validation exited without a return code")
                if failed_paths:
                    summary_parts.append(f"artifacts saved to {', '.join(failed_paths.values())}")
                if summary_parts:
                    validation_summary = "; ".join(summary_parts)
                    logger.error("hostapd validation summary for %s: %s", path, validation_summary)
            restored: Path | None = None
            if service == "hostapd" and hostapd_status and hostapd_status.get("returncode") == 0:
                restore_source = backup_path or restore_from_history(path, history_dir, suffix=history_suffix)
                if restore_source:
                    try:
                        ensure_parent(path)
                        path.write_text(Path(restore_source).read_text(encoding="utf-8"), encoding="utf-8")
                        for dest in deploy_paths or ():
                            ensure_parent(dest)
                            dest.write_text(path.read_text(encoding="utf-8"), encoding="utf-8")
                        restored = Path(restore_source)
                    except OSError as exc:  # pragma: no cover - defensive for odd IO errors
                        logger.debug("Could not restore %s from %s: %s", path, restore_source, exc)
                if restored:
                    logger.info("Restored %s from %s after failed validation", path, restored)
            else:
                restored = restore_from_history(path, history_dir, suffix=history_suffix)
                if restored:
                    logger.info("Restored %s from %s after failed validation", path, restored)
            if validation_result.get("stdout"):
                logger.debug("Validation stdout for %s:\n%s", path, validation_result.get("stdout"))
            if validation_result.get("stderr"):
                logger.debug("Validation stderr for %s:\n%s", path, validation_result.get("stderr"))
            if service == "hostapd" and force_restart:
                restart_after_failure = reload_or_restart_service(service, timeout=SERVICE_TIMEOUT_SECONDS)
                if restart_after_failure and not restart_after_failure.get("success"):
                    logger.error(
                        "hostapd restart after failed validation did not succeed (rc=%s)",
                        restart_after_failure.get("returncode"),
                    )
            return {
                "path": str(path),
                "changed": bool(diff),
                "validation": {
                    "status": validation_result.get("status") or "failed",
                    "returncode": validation_result.get("returncode"),
                    "timeout": validation_result.get("timeout", False),
                    "timeout_seconds": validation_result.get("timeout_seconds"),
                    "stdout": validation_result.get("stdout"),
                    "stderr": validation_result.get("stderr"),
                    "failed_paths": failed_paths,
                    "summary": validation_summary,
                    "first_stderr_line": first_stderr_line,
                    "skipped": validation_result.get("skipped", False),
                    "reason": validation_result.get("reason"),
                },
                "restored_from": str(restored) if restored else None,
                "applied": False,
                "service_restart": {"service": service, "status": "skipped", "success": False},
                "service_stop": service_stop_action or hostapd_stopped,
                "actions": actions,
                "error": validation_summary or error_message,
                "file_mtimes": {"before": current_mtime, "after": collect_file_mtimes([path]).get(str(path))},
                "pre_deploy_history": pre_deploy_history,
                "candidate": candidate,
                "force_restart_cleanup": force_restart_cleanup,
                "service_restart_after_failure": restart_after_failure,
                "ap_interface": ap_interface_after_validation,
                "hostapd_defaults": hostapd_defaults_result,
            }
        if service == "dnsmasq":
            dnsmasq_stopped = _run_command(["systemctl", "stop", service])
            service_stop_action = dnsmasq_stopped
            if not _command_success(dnsmasq_stopped):
                error_message = dnsmasq_stopped.get("stderr") or dnsmasq_stopped.get("stdout") or "dnsmasq stop failed"
                return {
                    "path": str(path),
                    "changed": changed,
                    "validation": {
                        "status": "passed",
                        "returncode": validation_result.get("returncode"),
                        "stdout": validation_result.get("stdout"),
                        "stderr": validation_result.get("stderr"),
                        "skipped": False,
                        "reason": "dnsmasq_stop_failed",
                    },
                    "applied": False,
                    "service_restart": {"service": service, "status": "skipped", "success": False},
                    "service_stop": dnsmasq_stopped,
                    "actions": actions,
                    "error": f"Failed to stop dnsmasq before applying configuration: {error_message}",
                    "file_mtimes": {"before": current_mtime, "after": collect_file_mtimes([path]).get(str(path))},
                    "pre_deploy_history": pre_deploy_history,
                    "candidate": candidate,
                    "force_restart_cleanup": force_restart_cleanup,
                }
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(candidate, encoding="utf-8")
        set_default_permissions(path)
        for dest in deploy_paths or ():
            ensure_parent(dest)
            dest.write_text(candidate, encoding="utf-8")
            set_default_permissions(dest)
            deployed_paths.append(dest)
            logger.info("Deployed %s to %s", path, dest)

        if service == "dnsmasq":
            post_write_validation = _run_command(["dnsmasq", "--test", f"--conf-file={path}"])
            service_stop_action = service_stop_action or dnsmasq_stopped
            if post_write_validation.get("returncode") not in (0,):
                stderr_text = (post_write_validation.get("stderr") or "").strip()
                first_line = stderr_text.splitlines()[0] if stderr_text else ""
                error_message = first_line or "dnsmasq reported an error validating the applied configuration"
                restored_from: Path | None = None
                if backup_path:
                    try:
                        ensure_parent(path)
                        path.write_text(Path(backup_path).read_text(encoding="utf-8"), encoding="utf-8")
                        set_default_permissions(path)
                        restored_from = backup_path
                    except OSError as exc:  # pragma: no cover - defensive
                        logger.debug("Could not restore %s from backup %s: %s", path, backup_path, exc)
                if restored_from is None:
                    restored_from = restore_from_history(path, history_dir, suffix=history_suffix)
                return {
                    "path": str(path),
                    "changed": changed,
                    "validation": {
                        "status": "failed",
                        "returncode": post_write_validation.get("returncode"),
                        "stdout": post_write_validation.get("stdout"),
                        "stderr": stderr_text,
                        "skipped": False,
                        "reason": "dnsmasq_post_write_validation_failed",
                        "first_stderr_line": first_line,
                    },
                    "restored_from": str(restored_from) if restored_from else None,
                    "applied": False,
                    "service_restart": {"service": service, "status": "skipped", "success": False},
                    "service_stop": service_stop_action,
                    "actions": actions,
                    "error": f"Validation failed for applied dnsmasq.conf: {error_message}",
                    "file_mtimes": {"before": current_mtime, "after": collect_file_mtimes([path]).get(str(path))},
                    "pre_deploy_history": pre_deploy_history,
                    "candidate": candidate,
                    "force_restart_cleanup": force_restart_cleanup,
                    "post_write_validation": post_write_validation,
                }

        if service == "hostapd":
            service_action = _run_command(["systemctl", "start", service])
            service_action["service"] = service
            service_action["success"] = _command_success(service_action)
        elif service == "dnsmasq":
            service_action = restart_service(service, timeout=SERVICE_TIMEOUT_SECONDS)
        elif force_restart:
            ap_interface_after_validation = _ensure_ap_interface(dry_run=dry_run)
            if ap_interface_after_validation.get("status") == "failed":
                service_action = {
                    "service": service,
                    "success": False,
                    "returncode": None,
                    "error": ap_interface_after_validation.get("error"),
                }
            else:
                service_action = reload_or_restart_service(service, timeout=SERVICE_TIMEOUT_SECONDS)
        else:
            service_action = reload_or_restart_service(service, timeout=SERVICE_TIMEOUT_SECONDS)
        status_result = service_status(service, timeout=SERVICE_TIMEOUT_SECONDS)
        action_label = "Started" if service == "hostapd" else "Restarted" if service == "dnsmasq" else "Reloaded"
        logger.info(
            "%s %s via systemctl (success=%s, returncode=%s)",
            action_label,
            service,
            service_action.get("success"),
            service_action.get("returncode"),
        )
    finally:
        temp_path.unlink(missing_ok=True)

    service_stop_action = service_stop_action or hostapd_stopped or dnsmasq_stopped
    updated_mtime = collect_file_mtimes([path]).get(str(path))
    result = {
        "path": str(path),
        "changed": changed,
        "validation": {
            "status": validation_result.get("status") or ("skipped" if validation_result.get("reason") else "passed"),
            "returncode": validation_result.get("returncode"),
            "timeout": validation_result.get("timeout", False),
            "timeout_seconds": validation_result.get("timeout_seconds"),
            "stdout": validation_result.get("stdout"),
            "stderr": validation_result.get("stderr"),
            "skipped": validation_result.get("skipped", False),
            "reason": validation_result.get("reason"),
        },
        "service_restart": {
            "service": service,
            "returncode": service_action.get("returncode"),
            "success": service_action.get("success"),
            "status": status_result,
        },
        "applied": bool(service_action.get("success")),
        "file_mtimes": {"before": current_mtime, "after": updated_mtime},
        "deployed_paths": [str(path) for path in deploy_paths or ()],
        "actions": actions,
        "pre_deploy_history": pre_deploy_history,
        "candidate": candidate,
        "force_restart_cleanup": force_restart_cleanup,
        "ap_interface": ap_interface_after_validation,
        "hostapd_defaults": hostapd_defaults_result,
        "service_stop": service_stop_action,
        "post_write_validation": post_write_validation,
    }
    if service == "dnsmasq" and not service_action.get("success"):
        restart_message = service_action.get("stderr") or service_action.get("stdout") or "dnsmasq restart failed"
        result["error"] = restart_message
    return result


def _restart_dnsmasq_after_wlan0ap_ip(
    *, wlan0ap_ip_sync: Mapping[str, object], dnsmasq_result: Mapping[str, object], dry_run: bool
) -> tuple[dict[str, object], bool, str | None]:
    restart_failed = False
    restart_message: str | None = None
    dnsmasq_restart_after_ip: dict[str, object]

    if dry_run:
        return {"service": "dnsmasq", "status": "skipped", "reason": "dry_run"}, restart_failed, restart_message

    dnsmasq_apply_restart = dnsmasq_result.get("service_restart") or {}
    dnsmasq_was_restarted = bool(dnsmasq_apply_restart)

    if wlan0ap_ip_sync.get("changed") and wlan0ap_ip_sync.get("applied"):
        dnsmasq_restart_after_ip = restart_service("dnsmasq", timeout=SERVICE_TIMEOUT_SECONDS)
        dnsmasq_restart_after_ip["trigger"] = "wlan0ap_ip_service"
        if not dnsmasq_restart_after_ip.get("success"):
            restart_failed = True
            restart_message = "dnsmasq restart after wlan0ap-ip.service update failed"
        return dnsmasq_restart_after_ip, restart_failed, restart_message

    reasons: list[str] = []
    if not wlan0ap_ip_sync.get("changed"):
        reasons.append("wlan0ap-ip.service unchanged")
        if dnsmasq_was_restarted:
            reasons.append("dnsmasq already reloaded during apply")
    elif not wlan0ap_ip_sync.get("applied"):
        reasons.append("wlan0ap-ip.service restart failed")

    reason_text = "; ".join(reasons) if reasons else "wlan0ap-ip.service unchanged or not applied"
    dnsmasq_restart_after_ip = {"service": "dnsmasq", "status": "skipped", "reason": reason_text}
    return dnsmasq_restart_after_ip, restart_failed, restart_message


def _apply_hostapd_dnsmasq(
    config: Mapping[str, object],
    *,
    dry_run: bool,
    ap_interface_result: Mapping[str, object] | None = None,
    force_restart: bool = False,
    pre_restart_cleanup: Mapping[str, object] | None = None,
) -> dict[str, object]:
    upstream_wifi_result = _apply_upstream_wifi_config(dry_run=dry_run)
    dnsmasq_active_text = read_text(DNSMASQ_ACTIVE_CONF)
    dnsmasq_generated_text = read_text(DNSMASQ_CONF)
    try:
        override_body = _resolve_override_body(active_config=dnsmasq_active_text, generated_config=dnsmasq_generated_text)
    except ValueError as exc:
        error_message = str(exc)
        overrides_sync = {
            "path": str(DNSMASQ_OVERRIDES_CONF),
            "updated": False,
            "status": "error",
            "error": error_message,
        }
        hostapd_result = {
            "path": str(HOSTAPD_ACTIVE_CONF),
            "changed": False,
            "validation": {"status": "skipped", "reason": "dns_override_error"},
            "service_restart": {"service": "hostapd", "status": "skipped", "success": None},
            "applied": False,
            "actions": [],
            "error": error_message,
        }
        dnsmasq_result = {
            "path": str(DNSMASQ_ACTIVE_CONF),
            "changed": False,
            "validation": {"status": "error", "reason": "dns_override_error", "message": error_message},
            "service_restart": {"service": "dnsmasq", "status": "skipped", "success": None},
            "applied": False,
            "actions": [],
            "error": error_message,
        }
        return {
            "ap_interface": ap_interface_result,
            "hostapd": hostapd_result,
            "dnsmasq": dnsmasq_result,
            "dnsmasq_overrides": overrides_sync,
            "upstream_wifi": upstream_wifi_result,
        }
    overrides_sync = _ensure_overrides_conf(override_body)
    if not force_restart:
        ap_interface_result = ap_interface_result or _ensure_ap_interface(dry_run=dry_run)
    hostapd_result: dict[str, object]
    if ap_interface_result and ap_interface_result.get("status") == "failed":
        error_message = ap_interface_result.get("error") or f"Failed to ensure {AP_INTERFACE} exists."
        hostapd_result = {
            "path": str(HOSTAPD_ACTIVE_CONF),
            "changed": False,
            "validation": {"status": "skipped", "reason": "ap_interface_failed"},
            "service_restart": {"service": "hostapd", "status": "skipped", "success": None},
            "applied": False,
            "actions": ["ensure_ap_interface"],
            "ap_interface": ap_interface_result,
            "error": error_message,
        }
    else:
        hostapd_result = _validate_and_apply(
            path=HOSTAPD_ACTIVE_CONF,
            candidate=_hostapd_template(config),
            deploy_paths=(HOSTAPD_CONF,),
            snapshot_paths=(HOSTAPD_ACTIVE_CONF,),
            validate_command=["hostapd", "-t"],
            service="hostapd",
            dry_run=dry_run,
            history_suffix="hostapd.conf",
            history_dir=GENERATED_HISTORY_DIR,
            force_restart=force_restart,
        )
        if force_restart and pre_restart_cleanup and not hostapd_result.get("force_restart_cleanup"):
            hostapd_result["force_restart_cleanup"] = pre_restart_cleanup
        if hostapd_result.get("ap_interface"):
            ap_interface_result = hostapd_result["ap_interface"]
        hostapd_result["ap_interface"] = ap_interface_result or pre_restart_cleanup
    dnsmasq_result = _validate_and_apply(
        path=DNSMASQ_ACTIVE_CONF,
        candidate=_dnsmasq_template(
            config,
            active_config=dnsmasq_active_text,
            generated_config=dnsmasq_generated_text,
            override_body=override_body,
        ),
        deploy_paths=(DNSMASQ_CONF,),
        snapshot_paths=(DNSMASQ_ACTIVE_CONF,),
        validate_command=["dnsmasq", "--test", "--conf-file={path}"],
        service="dnsmasq",
        dry_run=dry_run,
        history_suffix="dnsmasq.conf",
        history_dir=GENERATED_HISTORY_DIR,
    )
    return {
        "ap_interface": ap_interface_result,
        "hostapd": hostapd_result,
        "dnsmasq": dnsmasq_result,
        "dnsmasq_overrides": overrides_sync,
        "upstream_wifi": upstream_wifi_result,
    }


def build_payload(
    *,
    source: str,
    active_config: dict,
    mismatches: list,
    stored: dict,
    system: dict,
    status: str = "ok",
    message: str | None = None,
    config_sources: dict | None = None,
) -> dict:
    summary = _ap_summary(active_config)
    payload = {
        "status": status,
        "source": source,
        "ap_config": active_config,
        "mismatches": mismatches,
        "mismatch_summary": mismatch_summary(mismatches),
        "system_config": system,
        "stored_config": stored,
        "ap_summary": summary,
        "ssid": summary.get("ssid"),
        "subnet_octet": summary.get("subnet_octet"),
        "channel": summary.get("channel"),
    }
    if message:
        payload["message"] = message
    if config_sources:
        payload["config_sources"] = config_sources
    return payload


def _exit_code_from_status(status: str, *, drift: bool = False) -> int:
    if status == "error":
        return 3
    if drift:
        return 10
    if status == "warning":
        return 2
    return 0


def _ap_summary(config: Mapping[str, object] | None) -> dict[str, object]:
    source = config or {}
    return {
        "ssid": source.get("ssid") or None,
        "subnet_octet": source.get("subnet_octet"),
        "channel": source.get("channel"),
    }


def status(*, debug_json: bool | None = None) -> ApResult:
    verbose = _debug_verbose(debug_json)
    stored_config = load_json(AP_JSON, default={})
    system_config, system_sources = read_system_ap_config(include_sources=True)
    mismatches = compare_configs(system_config, stored_config, fields=AP_FIELDS)
    status_label = "ok" if not mismatches else "warning"
    message = "Status only: live and stored configurations match."
    if mismatches:
        message = "Status only: live access point configuration differs from stored JSON."
    payload = build_payload(
        source="status (read-only)",
        active_config=system_config,
        mismatches=mismatches,
        stored=stored_config,
        system=system_config,
        status=status_label,
        message=message,
        config_sources=system_sources,
    )
    merged = response_payload(payload, verbose=verbose)
    drift = bool(mismatches)
    return ApResult(payload=merged, exit_code=_exit_code_from_status(status_label, drift=drift))


def _config_with_overrides(
    stored_config: Mapping[str, object], system_config: Mapping[str, object], overrides: Mapping[str, object]
) -> tuple[dict[str, object], dict[str, object]]:
    stored_with_overrides = _apply_overrides(stored_config, overrides)
    system_with_overrides = _apply_overrides(system_config, overrides)
    return stored_with_overrides, system_with_overrides


def _apply_update(
    *,
    config_to_apply: Mapping[str, object],
    stored_config: Mapping[str, object],
    system_config: Mapping[str, object],
    system_sources: Mapping[str, object],
    planned_mismatches: list,
    source_label: str,
    base_message: str,
    dry_run: bool,
    debug_json: bool,
    force_restart: bool = False,
) -> ApResult:
    desired_ip = _desired_ap_ip(int(config_to_apply.get("subnet_octet") or DEFAULT_SUBNET_OCTET))
    service_enablement, service_errors = ensure_services_enabled(
        ("hostapd", "dnsmasq"),
        runner=lambda args: _run_command(["systemctl", *args]),
        dry_run=dry_run,
    )
    if service_errors and not dry_run:
        payload = build_payload(
            source=f"update ({source_label})",
            active_config=dict(config_to_apply),
            mismatches=planned_mismatches,
            stored=dict(stored_config),
            system=dict(system_config),
            status="error",
            message="; ".join(service_errors),
            config_sources=system_sources,
        )
        payload["service_enablement"] = service_enablement
        payload["error"] = "; ".join(service_errors)
        merged = response_payload(payload, verbose=debug_json)
        return ApResult(payload=merged, exit_code=3)

    ap_json_result = _persist_ap_json(config_to_apply, dry_run=dry_run)
    pre_restart_cleanup: dict[str, object] | None = None
    ap_interface_result: dict[str, object] | None = None
    if force_restart:
        pre_restart_cleanup = _stop_hostapd_and_remove_interface(dry_run=dry_run)
    ap_interface_result = _ensure_ap_interface(dry_run=dry_run)
    if ap_interface_result and ap_interface_result.get("status") == "failed":
        error_message = ap_interface_result.get("error") or f"Failed to create {AP_INTERFACE} interface."
        payload = build_payload(
            source=f"update ({source_label})",
            active_config=dict(config_to_apply),
            mismatches=planned_mismatches,
            stored=dict(stored_config),
            system=dict(system_config),
            status="error",
            message=(
                f"Access point interface {AP_INTERFACE} is missing and automatic creation failed. "
                "See command output for details."
            ),
            config_sources=system_sources,
        )
        payload["ap_interface"] = ap_interface_result
        payload["error"] = error_message
        merged = response_payload(payload, verbose=debug_json)
        return ApResult(payload=merged, exit_code=3)
    service_results = _apply_hostapd_dnsmasq(
        config_to_apply,
        dry_run=dry_run,
        ap_interface_result=dict(ap_interface_result) if ap_interface_result else None,
        force_restart=force_restart,
        pre_restart_cleanup=pre_restart_cleanup,
    )
    ap_interface_result = service_results.get("ap_interface", ap_interface_result)
    hostapd_result = service_results["hostapd"]
    dnsmasq_result = service_results["dnsmasq"]
    overrides_sync = service_results["dnsmasq_overrides"]
    upstream_wifi_result = service_results.get("upstream_wifi")
    wlan0ap_ip_sync = _sync_wlan0ap_ip_service(desired_ip, dry_run=dry_run)

    ip_ready = dry_run or (
        wlan0ap_ip_sync.get("service_enabled", True) and wlan0ap_ip_sync.get("ip_matches") is True
    )
    ip_failure_reason = None
    if not dry_run and not ip_ready:
        current_ip = (wlan0ap_ip_sync.get("ip_check") or {}).get("current_ip")
        observed = current_ip or "unknown"
        ip_failure_reason = (
            wlan0ap_ip_sync.get("error")
            or f"{AP_INTERFACE} missing expected IP {desired_ip} after enabling {WLAN0AP_IP_UNIT} (observed {observed})"
        )
    if not dry_run and wlan0ap_ip_sync.get("status") == "failed":
        ip_failure_reason = wlan0ap_ip_sync.get("error") or ip_failure_reason

    if ip_failure_reason:
        logger.error("wlan0ap-ip preflight failed: %s", ip_failure_reason)
        payload = build_payload(
            source=f"update ({source_label})",
            active_config=dict(config_to_apply),
            mismatches=planned_mismatches,
            stored=dict(stored_config),
            system=dict(system_config),
            status="error",
            message=ip_failure_reason,
            config_sources=system_sources,
        )
        payload["changes"] = {
            "service_enablement": service_enablement,
            "ap_interface": ap_interface_result,
            "ap_json": ap_json_result,
            "wlan0ap_ip_service": wlan0ap_ip_sync,
            "hostapd": hostapd_result,
            "dnsmasq": dnsmasq_result,
            "dnsmasq_overrides": overrides_sync,
        }
        payload["service_enablement"] = service_enablement
        payload["ap_interface"] = ap_interface_result
        payload["wlan0ap_ip_service_status"] = wlan0ap_ip_sync.get("status")
        payload["wlan0ap_ip_changed"] = wlan0ap_ip_sync.get("changed", False)
        payload["error"] = ip_failure_reason
        merged = response_payload(payload, verbose=debug_json)
        return ApResult(payload=merged, exit_code=3)
    dnsmasq_restart_after_ip: dict[str, object] | None = None
    status_label = "ok"
    message_parts: list[str] = [base_message]
    primary_error = None

    runtime_failure = False

    def _validation_failure(result: Mapping[str, object]) -> tuple[bool, str | None]:
        validation = (result or {}).get("validation") or {}
        if not validation or validation.get("skipped"):
            return False, None
        if validation.get("status") == "failed" or validation.get("timeout"):
            summary_hint = validation.get("summary") or validation.get("first_stderr_line") or validation.get("stderr")
            return True, summary_hint or "Validation failed"
        return_code = validation.get("returncode")
        if return_code not in (0, None):
            return True, validation.get("summary")
        if return_code is None:
            return True, validation.get("summary") or "Validation returned no exit code"
        return False, None

    hostapd_validation_failed, hostapd_validation_error = _validation_failure(hostapd_result)
    dnsmasq_validation_failed, dnsmasq_validation_error = _validation_failure(dnsmasq_result)
    validation_failed = bool(
        hostapd_validation_failed
        or dnsmasq_validation_failed
        or hostapd_result.get("error")
        or dnsmasq_result.get("error")
    )

    if validation_failed:
        status_label = "error"
        message_parts = ["Configuration validation failed; see details."]
        primary_error = (
            dnsmasq_result.get("error")
            or hostapd_result.get("error")
            or dnsmasq_validation_error
            or hostapd_validation_error
        )
    elif dry_run:
        message_parts.append("Dry run; no files written or services restarted.")

    upstream_warnings: list[str] = []
    if upstream_wifi_result:
        upstream_warnings = [warning for warning in upstream_wifi_result.get("warnings") or [] if warning]
        if upstream_warnings and status_label == "ok":
            status_label = "warning"
        if upstream_wifi_result.get("changed"):
            message_parts.append("Upstream Wi-Fi profiles synced.")
        if upstream_warnings:
            message_parts.append("; ".join(upstream_warnings))

    dnsmasq_restart_after_ip, restart_failed, restart_message = _restart_dnsmasq_after_wlan0ap_ip(
        wlan0ap_ip_sync=wlan0ap_ip_sync, dnsmasq_result=dnsmasq_result, dry_run=dry_run
    )
    if restart_failed:
        if status_label == "ok":
            status_label = "warning"
        if restart_message:
            message_parts.append(restart_message)
            primary_error = primary_error or dnsmasq_restart_after_ip.get("error") or restart_message
        runtime_failure = True

    uplink_interface, uplink_detection = _detect_uplink_interface(config_to_apply)
    forwarding_result = _ensure_forwarding_and_nat(uplink_interface, dry_run=dry_run, detection=uplink_detection)
    forwarding_status = forwarding_result.get("status")
    forwarding_message = forwarding_result.get("message")
    if forwarding_status in {"warning", "error"}:
        if status_label == "ok":
            status_label = "warning"
        if forwarding_message:
            message_parts.append(forwarding_message)
        if forwarding_status == "error":
            runtime_failure = True
            primary_error = primary_error or forwarding_result.get("error") or forwarding_message
    elif forwarding_message:
        message_parts.append(forwarding_message)

    ip_restart_required = wlan0ap_ip_sync.get("changed", False) and not dry_run
    ip_restart_failed = ip_restart_required and not wlan0ap_ip_sync.get("applied", False)
    if wlan0ap_ip_sync.get("status") == "failed" or ip_restart_failed:
        if status_label == "ok":
            status_label = "warning"
        ip_warning = (
            "wlan0ap-ip.service reload/restart failed; retry: "
            f"{WLAN0AP_IP_REMEDIATION} && systemctl restart hostapd && systemctl restart dnsmasq"
        )
        message_parts.append(ip_warning)
        primary_error = primary_error or wlan0ap_ip_sync.get("error") or ip_warning
        runtime_failure = True
    elif wlan0ap_ip_sync.get("status") == "updated" and not dry_run:
        message_parts.append("wlan0ap-ip.service updated and restarted.")
    elif dry_run and wlan0ap_ip_sync.get("changed", False):
        message_parts.append("Dry run: wlan0ap-ip.service would be updated and restarted.")

    post_apply_verification: dict[str, object] | None = None
    post_apply_warning: str | None = None
    can_verify = (
        not dry_run
        and hostapd_result.get("validation", {}).get("status") != "failed"
        and dnsmasq_result.get("validation", {}).get("status") != "failed"
    )
    if can_verify:
        post_apply_verification = _post_apply_verification(
            int(config_to_apply.get("subnet_octet") or DEFAULT_SUBNET_OCTET),
            desired_ip=desired_ip,
            dnsmasq_candidate=dnsmasq_result.get("candidate"),
        )
        post_apply_warning = _post_apply_warning(post_apply_verification)
        if post_apply_warning:
            status_label = "warning" if status_label == "ok" else status_label
            message_parts.append(post_apply_warning)
            runtime_failure = True

    restart_failures: list[str] = []
    for service_name, result in (("hostapd", hostapd_result), ("dnsmasq", dnsmasq_result)):
        restart = result.get("service_restart") or {}
        if restart.get("success") is False:
            restart_failures.append(service_name)

    if restart_failures:
        runtime_failure = True
        if status_label == "ok":
            status_label = "warning"
        message_parts.append(
            f"{', '.join(restart_failures)} reload/restart failed; check systemctl status for details."
        )
        primary_error = primary_error or ", ".join(restart_failures)

    payload = build_payload(
        source=f"update ({source_label})",
        active_config=dict(config_to_apply),
        mismatches=planned_mismatches,
        stored=dict(stored_config),
        system=dict(system_config),
        message=" ".join(message_parts),
        status=status_label,
        config_sources=system_sources,
    )
    payload["upstream_wifi"] = upstream_wifi_result
    payload["changes"] = {
        "service_enablement": service_enablement,
        "ap_interface": ap_interface_result,
        "ap_json": ap_json_result,
        "wlan0ap_ip_service": wlan0ap_ip_sync,
        "hostapd": hostapd_result,
        "dnsmasq": dnsmasq_result,
        "dnsmasq_overrides": overrides_sync,
        "upstream_wifi": upstream_wifi_result,
        "dnsmasq_restart_after_wlan0ap_ip": dnsmasq_restart_after_ip,
        "iptables": forwarding_result,
    }
    payload["iptables"] = forwarding_result
    if hostapd_validation_failed:
        payload["hostapd_validation"] = {
            "status": (hostapd_result.get("validation") or {}).get("status"),
            "summary": hostapd_validation_error
            or (hostapd_result.get("validation") or {}).get("summary")
            or (hostapd_result.get("validation") or {}).get("first_stderr_line"),
            "failed_paths": (hostapd_result.get("validation") or {}).get("failed_paths"),
        }
    if dnsmasq_validation_failed:
        payload["dnsmasq_validation"] = {
            "status": (dnsmasq_result.get("validation") or {}).get("status"),
            "summary": dnsmasq_validation_error
            or (dnsmasq_result.get("validation") or {}).get("summary")
            or (dnsmasq_result.get("validation") or {}).get("first_stderr_line"),
        }
    payload["service_enablement"] = service_enablement
    payload["ap_interface"] = ap_interface_result
    payload["wlan0ap_ip_service_status"] = wlan0ap_ip_sync.get("status")
    payload["wlan0ap_ip_restart_returncode"] = (wlan0ap_ip_sync.get("restart") or {}).get("returncode")
    payload["wlan0ap_ip_changed"] = wlan0ap_ip_sync.get("changed", False)
    if post_apply_verification:
        payload["post_apply_verification"] = post_apply_verification
    if post_apply_warning:
        payload["post_apply_warning"] = post_apply_warning
    if primary_error:
        payload["error"] = primary_error

    merged = response_payload(payload, verbose=debug_json)
    exit_code = _exit_code_from_status(status_label)
    if validation_failed:
        exit_code = 2
    elif runtime_failure:
        exit_code = 3
    return ApResult(payload=merged, exit_code=exit_code)


def update(
    *,
    ssid: str | None = None,
    password: str | None = None,
    channel: int | None = None,
    subnet_octet: int | None = None,
    dry_run: bool = False,
    force: bool = False,
    force_restart: bool = False,
    debug_json: bool | None = None,
) -> ApResult:
    debug_verbose = _debug_verbose(debug_json)
    overrides = {
        "ssid": ssid,
        "password": password,
        "channel": channel,
        "subnet_octet": subnet_octet,
    }
    stored_config = load_json(AP_JSON, default={})
    system_config, system_sources = read_system_ap_config(include_sources=True)
    stored_with_overrides, system_with_overrides = _config_with_overrides(stored_config, system_config, overrides)
    mismatches = compare_configs(system_config, stored_config, fields=AP_FIELDS)
    source_label = "stored JSON" if not mismatches or force else config_source_label(mismatches)
    config_to_apply: Mapping[str, object] = (
        stored_with_overrides if source_label == "stored JSON" else system_with_overrides
    )
    config_to_apply = _sanitize_ap_config(config_to_apply)
    planned_mismatches = compare_configs(system_config, config_to_apply, fields=AP_FIELDS)

    if mismatches and not force:
        payload = build_payload(
            source=f"update ({source_label})",
            active_config=dict(config_to_apply),
            mismatches=mismatches,
            stored=dict(stored_config),
            system=dict(system_config),
            status="warning",
            message=(
                "Live access point configuration differs from stored JSON. "
                "Re-run with --force to overwrite system state."
            ),
            config_sources=system_sources,
        )
        merged = response_payload(payload, verbose=debug_verbose)
        return ApResult(payload=merged, exit_code=_exit_code_from_status("warning"))

    if mismatches and force:
        logger.warning("Forcing overwrite of system AP configuration with stored JSON")

    if not dry_run:
        save_json(AP_JSON, dict(config_to_apply))

    base_message = "Update mode: stored configuration updated and applied to services."
    if mismatches and force:
        base_message = "Update mode: system configuration differed; proceeding with stored JSON (--force)."
    elif dry_run:
        base_message = "Update mode: dry run; configuration would be applied." if not mismatches else base_message

    return _apply_update(
        config_to_apply=config_to_apply,
        stored_config=stored_config,
        system_config=system_config,
        system_sources=system_sources,
        planned_mismatches=planned_mismatches,
        source_label=source_label,
        base_message=base_message,
        dry_run=dry_run,
        debug_json=debug_verbose,
        force_restart=force_restart,
    )


__all__ = ["ApResult", "status", "update"]
