"""CLI dispatcher for mcbridge."""

from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from typing import Any, Callable, Sequence

from . import agent, ap, dns, init, upstream, upstream_dns

LOG = logging.getLogger(__name__)


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:  # pragma: no cover - argparse maps to SystemExit
        raise argparse.ArgumentTypeError(f"{value} is not a valid integer") from exc
    if parsed <= 0:
        raise argparse.ArgumentTypeError("Value must be positive")
    return parsed


def _non_negative_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:  # pragma: no cover - argparse maps to SystemExit
        raise argparse.ArgumentTypeError(f"{value} is not a valid integer") from exc
    if parsed < 0:
        raise argparse.ArgumentTypeError("Value must be zero or positive")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcbridge", description="mcbridge management CLI")
    parser.add_argument(
        "--agent-socket",
        default=os.environ.get("MCBRIDGE_AGENT_SOCKET", str(agent.DEFAULT_SOCKET)),
        help="Path to the mcbridge agent socket (default: %(default)s)",
    )
    parser.add_argument(
        "--agent-timeout",
        type=float,
        default=float(os.environ.get("MCBRIDGE_AGENT_TIMEOUT", str(agent.DEFAULT_TIMEOUT))),
        help="Agent request timeout in seconds (default: %(default)s)",
    )
    subparsers = parser.add_subparsers(dest="domain", required=True)

    init_parser = subparsers.add_parser("init", help="Initial provisioning (wrapper around provision.sh)")
    init_parser.add_argument("--ssid", required=True, help="SSID for the access point")
    init_parser.add_argument("--password", default="", help="WPA2 passphrase (empty for open networks)")
    init_parser.add_argument(
        "--octet",
        dest="subnet_octet",
        default=ap.DEFAULT_SUBNET_OCTET,
        type=_positive_int,
        help="Third octet for AP subnet",
    )
    init_parser.add_argument(
        "--channel", default=init.DEFAULT_CHANNEL, type=_positive_int, help="Wireless channel (default 6)"
    )
    init_parser.add_argument("--force", action="store_true", help="Re-run even if drift is detected or already initialised")
    init_parser.add_argument("--dry-run", action="store_true", help="Preview without applying")
    init_parser.add_argument(
        "--target",
        required=True,
        help="Required default target hostname or IP for known servers (init overwrites knownservers.json target).",
    )
    init_parser.add_argument("--redirect", help="Hostname to redirect during init (paired with --target)")
    init_parser.add_argument(
        "--prepare-only",
        action="store_true",
        help="Validate, seed configs, provision units/packages, and enable services without rendering hostapd/dnsmasq."
        " Follow with 'mcbridge ap update' to generate configs and start services.",
    )
    init_parser.add_argument("--recovery-ssid", help="Recovery hotspot SSID for upstream commissioning")
    init_parser.add_argument("--recovery-password", help="Recovery hotspot password")
    init_parser.add_argument("--primary-ssid", help="Primary upstream SSID")
    init_parser.add_argument("--primary-password", help="Primary upstream password")
    init_parser.add_argument("--secondary-ssid", help="Optional secondary upstream SSID")
    init_parser.add_argument("--secondary-password", help="Optional secondary upstream password")
    init_parser.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")
    init_parser.add_argument("--yes", action="store_true", help="Skip confirmation prompts")
    init_parser.add_argument("--service-user", default=init.SERVICE_USER, help="Service user for mcbridge-managed units")
    init_parser.add_argument("--service-group", default=init.SERVICE_GROUP, help="Primary group for the service user")
    init_parser.add_argument("--operator-group", default=init.OPERATOR_GROUP, help="Operator group for managed files")
    init_parser.add_argument("--web-password", help="Set HTTP Basic auth password for the web console during init")
    init_parser.add_argument(
        "--no-web",
        dest="disable_web",
        action="store_true",
        help="Skip mcbridge web console setup (certificate, config, service unit)",
    )
    init_force_restart = init_parser.add_mutually_exclusive_group()
    init_force_restart.add_argument(
        "--force-restart", dest="force_restart", action="store_true", help="Restart AP services during validation"
    )
    init_force_restart.add_argument(
        "--no-force-restart",
        dest="force_restart",
        action="store_false",
        help="Do not restart AP services before validation",
    )
    init_parser.set_defaults(force_restart=True)

    ap_parser = subparsers.add_parser("ap", help="Access point controls")
    ap_sub = ap_parser.add_subparsers(dest="action", required=True)

    ap_status = ap_sub.add_parser("status", help="Show AP status")
    ap_status.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")

    ap_update = ap_sub.add_parser("update", help="Update AP configuration")
    ap_update.add_argument("--ssid", help="Override SSID")
    ap_update.add_argument("--password", help="Override WPA2 passphrase (empty for open mode)")
    ap_update.add_argument("--octet", dest="subnet_octet", type=_positive_int, help="Third octet for AP subnet")
    ap_update.add_argument("--channel", type=_positive_int, help="Wireless channel")
    ap_update.add_argument("--dry-run", action="store_true", help="Preview without applying")
    ap_update.add_argument("--force", action="store_true", help="Apply even if live config differs")
    ap_update.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")
    ap_update.add_argument(
        "--force-restart",
        dest="force_restart",
        action="store_true",
        help="Restart hostapd and recreate wlan0ap before applying",
    )

    dns_parser = subparsers.add_parser(
        "dns",
        help="DNS overrides controls (requires root; run with sudo mcbridge dns ...)",
        description="DNS overrides controls (requires root privileges; rerun as 'sudo mcbridge dns ...').",
    )
    dns_sub = dns_parser.add_subparsers(dest="action", required=True)

    dns_status = dns_sub.add_parser("status", help="Show DNS status")
    dns_status.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")

    dns_update = dns_sub.add_parser("update", help="Update DNS overrides")
    dns_update.add_argument("--redirect", help="Hostname to redirect")
    dns_update.add_argument("--target", help="Target hostname or IP for the redirect")
    dns_update.add_argument("--dry-run", action="store_true", help="Preview without applying")
    dns_update.add_argument("--force", action="store_true", help="Apply even if live config differs")
    dns_update.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")

    dns_menu = dns_sub.add_parser("menu", help="Interactive DNS override selection")
    dns_menu.add_argument("--dry-run", action="store_true", help="Preview without applying")
    dns_menu.add_argument("--force", action="store_true", help="Apply even if live config differs")
    dns_menu.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")

    upstream_parser = subparsers.add_parser("upstream", help="Upstream Wi-Fi controls")
    upstream_sub = upstream_parser.add_subparsers(dest="action", required=True)
    upstream_status = upstream_sub.add_parser("status", help="Show upstream Wi-Fi status")
    upstream_status.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")
    upstream_update = upstream_sub.add_parser("update", help="Create or update an upstream Wi-Fi profile")
    upstream_update.add_argument("--ssid", required=True, help="SSID to create or update")
    upstream_update.add_argument("--password", help="Passphrase or pre-hashed PSK")
    upstream_update.add_argument("--priority", type=_positive_int, help="Connection priority")
    upstream_update.add_argument("--security", help="Security mode (wpa2, wpa3, open)")
    upstream_update.add_argument("--role", choices=sorted(upstream.UPSTREAM_ROLES), help="Role for the upstream profile")
    upstream_update.add_argument("--enabled", dest="enabled", action="store_true", help="Enable the profile")
    upstream_update.add_argument("--disabled", dest="enabled", action="store_false", help="Disable the profile")
    upstream_update.add_argument("--autoconnect", dest="autoconnect", action="store_true", help="Allow autoconnect")
    upstream_update.add_argument("--no-autoconnect", dest="autoconnect", action="store_false", help="Disable autoconnect")
    upstream_update.set_defaults(enabled=None, autoconnect=None)
    upstream_apply = upstream_sub.add_parser("apply", help="Apply upstream Wi-Fi profiles")
    upstream_apply.add_argument(
        "--prune-missing",
        action="store_true",
        help="Delete NetworkManager Wi-Fi profiles not present in saved upstream profiles",
    )
    upstream_reconnect = upstream_sub.add_parser("reconnect", help="Force an upstream reconnect using selection policy")
    upstream_reconnect.add_argument(
        "--prune-missing",
        action="store_true",
        help="Delete NetworkManager Wi-Fi profiles not present in saved upstream profiles",
    )
    upstream_diag = upstream_sub.add_parser("diagnostics", help="Manage upstream diagnostics")
    upstream_diag_sub = upstream_diag.add_subparsers(dest="diagnostics_action", required=True)
    upstream_diag_enable = upstream_diag_sub.add_parser("enable", help="Enable upstream diagnostics")
    upstream_diag_disable = upstream_diag_sub.add_parser("disable", help="Disable upstream diagnostics")
    upstream_diag_show = upstream_diag_sub.add_parser("show", help="Show upstream diagnostics")
    upstream_prefer = upstream_sub.add_parser("prefer-recovery", help="Toggle prefer recovery mode")
    upstream_prefer.add_argument("state", choices=["enable", "disable"])
    upstream_activate = upstream_sub.add_parser("activate", help="Activate an upstream Wi-Fi connection")
    upstream_activate.add_argument("--ssid", required=True, help="SSID to activate")
    upstream_activate.add_argument("--interface", help="Network interface to activate on")
    upstream_forget = upstream_sub.add_parser("forget", help="Forget an upstream Wi-Fi connection")
    upstream_forget.add_argument("--ssid", required=True, help="SSID to forget")
    upstream_forget.add_argument("--interface", help="Network interface used for active connection checks")
    upstream_dns_refresh = upstream_sub.add_parser(
        "dns-refresh", help="Discover upstream DNS and optionally apply updates"
    )
    upstream_dns_refresh.add_argument("--interface", help="Interface to inspect for DNS servers")
    upstream_dns_refresh.add_argument(
        "--debounce-seconds",
        type=_non_negative_int,
        default=upstream_dns.DEBOUNCE_SECONDS,
        help="Seconds to debounce repeat refresh requests (default: %(default)s)",
    )
    upstream_dns_refresh.add_argument(
        "--apply",
        action="store_true",
        help="Apply updated dnsmasq configuration if upstream DNS changes",
    )
    upstream_dns_refresh.add_argument("--debug-json", action="store_true", help="Emit full JSON payload")

    return parser


def _emit(payload) -> None:
    print(json.dumps(payload, indent=2))


def _handle_ap_status(args: argparse.Namespace) -> ap.ApResult:
    return ap.status(debug_json=args.debug_json)


def _handle_ap_update(args: argparse.Namespace) -> ap.ApResult:
    return ap.update(
        ssid=args.ssid,
        password=args.password,
        channel=args.channel,
        subnet_octet=args.subnet_octet,
        dry_run=args.dry_run,
        force=args.force,
        force_restart=getattr(args, "force_restart", False),
        debug_json=args.debug_json,
    )


def _handle_dns_status(args: argparse.Namespace) -> dns.DnsResult:
    return dns.status(debug_json=args.debug_json)


def _handle_dns_update(args: argparse.Namespace) -> dns.DnsResult:
    return dns.update(
        redirect=args.redirect,
        target=args.target,
        dry_run=args.dry_run,
        force=args.force,
        debug_json=args.debug_json,
    )


def _handle_dns_menu(args: argparse.Namespace) -> dns.DnsResult:
    return dns.menu(dry_run=args.dry_run, force=args.force, debug_json=args.debug_json)


def _handle_upstream_status(args: argparse.Namespace) -> upstream.UpstreamResult:
    payload = upstream.status()
    return upstream.UpstreamResult(payload=payload, exit_code=int(payload.get("exit_code", 0) or 0))


def _handle_upstream_update(args: argparse.Namespace) -> upstream.UpstreamResult:
    existing = {entry["ssid"].lower(): entry for entry in upstream.list_profiles()}
    key = args.ssid.strip().lower()
    if key in existing:
        profiles = upstream.update_profile(
            ssid=args.ssid,
            password=args.password,
            priority=args.priority,
            security=args.security,
            role=args.role,
            enabled=args.enabled,
            autoconnect=args.autoconnect,
        )
    else:
        if args.priority is None:
            raise ValueError("priority is required when creating a new upstream profile")
        if args.security is None:
            raise ValueError("security is required when creating a new upstream profile")
        profiles = upstream.add_profile(
            ssid=args.ssid,
            password=args.password or "",
            priority=args.priority,
            security=args.security,
            role=args.role or upstream.DEFAULT_ROLE,
            enabled=True if args.enabled is None else args.enabled,
            autoconnect=True if args.autoconnect is None else args.autoconnect,
        )
    payload = {"status": "ok", "exit_code": 0, "profiles": profiles}
    return upstream.UpstreamResult(payload=payload, exit_code=0)


def _handle_upstream_apply(args: argparse.Namespace) -> upstream.UpstreamResult:
    return upstream.apply_upstream(prune_missing=args.prune_missing)


def _handle_upstream_reconnect(args: argparse.Namespace) -> upstream.UpstreamResult:
    return upstream.reconnect_upstream(prune_missing=args.prune_missing)


def _handle_upstream_diagnostics(args: argparse.Namespace) -> upstream.UpstreamResult:
    if args.diagnostics_action == "enable":
        return upstream.set_diagnostics_enabled(True)
    if args.diagnostics_action == "disable":
        return upstream.set_diagnostics_enabled(False)
    payload = upstream.diagnostics_status()
    return upstream.UpstreamResult(payload=payload, exit_code=int(payload.get("exit_code", 0) or 0))


def _handle_upstream_prefer_recovery(args: argparse.Namespace) -> upstream.UpstreamResult:
    payload = {"status": "ok", "exit_code": 0, "mode": upstream.update_mode(prefer_recovery=args.state == "enable")}
    return upstream.UpstreamResult(payload=payload, exit_code=0)


def _handle_upstream_activate(args: argparse.Namespace) -> upstream.UpstreamResult:
    return upstream.activate_upstream(ssid=args.ssid, interface=args.interface)


def _handle_upstream_forget(args: argparse.Namespace) -> upstream.UpstreamResult:
    return upstream.forget_system_profile(ssid=args.ssid, interface=args.interface)


def _handle_upstream_dns_refresh(args: argparse.Namespace) -> upstream_dns.UpstreamDnsResult:
    return upstream_dns.refresh_upstream_dns(
        interface=args.interface,
        debounce_seconds=args.debounce_seconds,
        apply=args.apply,
        debug_json=args.debug_json,
    )


def _handle_init(args: argparse.Namespace) -> init.InitResult:
    return init.run(
        ssid=args.ssid,
        password=args.password,
        octet=args.subnet_octet,
        channel=args.channel,
        force=args.force,
        force_restart=args.force_restart,
        prepare_only=args.prepare_only,
        dry_run=args.dry_run,
        assume_yes=args.yes,
        debug_json=args.debug_json,
        service_user=args.service_user,
        service_group=args.service_group,
        operator_group=args.operator_group,
        web_password=args.web_password,
        enable_web=not args.disable_web,
        redirect=args.redirect,
        target=args.target,
        recovery_ssid=args.recovery_ssid,
        recovery_password=args.recovery_password,
        primary_ssid=args.primary_ssid,
        primary_password=args.primary_password,
        secondary_ssid=args.secondary_ssid,
        secondary_password=args.secondary_password,
    )


def _run(handler: Callable[[argparse.Namespace], Any], args: argparse.Namespace) -> int:
    try:
        result = handler(args)
    except ValueError as exc:
        LOG.error("%s", exc)
        return 2
    except (PermissionError, FileNotFoundError, subprocess.CalledProcessError, RuntimeError) as exc:
        LOG.error("%s", exc)
        return 3

    _emit(result.payload)
    return result.exit_code


def main(argv: Sequence[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(args=argv)
    os.environ["MCBRIDGE_AGENT_SOCKET"] = args.agent_socket
    os.environ["MCBRIDGE_AGENT_TIMEOUT"] = str(args.agent_timeout)

    if args.domain == "init":
        exit_code = _run(_handle_init, args)
    elif args.domain == "ap" and args.action == "status":
        exit_code = _run(_handle_ap_status, args)
    elif args.domain == "ap" and args.action == "update":
        exit_code = _run(_handle_ap_update, args)
    elif args.domain == "dns" and args.action == "status":
        exit_code = _run(_handle_dns_status, args)
    elif args.domain == "dns" and args.action == "update":
        exit_code = _run(_handle_dns_update, args)
    elif args.domain == "dns" and args.action == "menu":
        exit_code = _run(_handle_dns_menu, args)
    elif args.domain == "upstream" and args.action == "status":
        exit_code = _run(_handle_upstream_status, args)
    elif args.domain == "upstream" and args.action == "update":
        exit_code = _run(_handle_upstream_update, args)
    elif args.domain == "upstream" and args.action == "apply":
        exit_code = _run(_handle_upstream_apply, args)
    elif args.domain == "upstream" and args.action == "reconnect":
        exit_code = _run(_handle_upstream_reconnect, args)
    elif args.domain == "upstream" and args.action == "diagnostics":
        exit_code = _run(_handle_upstream_diagnostics, args)
    elif args.domain == "upstream" and args.action == "prefer-recovery":
        exit_code = _run(_handle_upstream_prefer_recovery, args)
    elif args.domain == "upstream" and args.action == "activate":
        exit_code = _run(_handle_upstream_activate, args)
    elif args.domain == "upstream" and args.action == "forget":
        exit_code = _run(_handle_upstream_forget, args)
    elif args.domain == "upstream" and args.action == "dns-refresh":
        exit_code = _run(_handle_upstream_dns_refresh, args)
    else:  # pragma: no cover - argparse enforces choices
        parser.error("Unsupported command")
        return

    raise SystemExit(exit_code)
