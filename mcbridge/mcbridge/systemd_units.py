"""Systemd unit templates shared across provisioning flows."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

AP_INTERFACE = os.environ.get("MCBRIDGE_AP_INTERFACE", "wlan0ap")
UPSTREAM_INTERFACE = os.environ.get("MCBRIDGE_UPSTREAM_INTERFACE", "wlan0")
WLAN0AP_UNIT = "wlan0ap.service"
WLAN0AP_IP_UNIT = "wlan0ap-ip.service"


def _normalize_cidr(value: str) -> str:
    return value.strip()


def wlan0ap_service_template(
    *, ap_interface: str, upstream_interface: str, service_user: str = "mcbridge", service_group: str = "mcbridge"
) -> str:
    lines = [
        "[Unit]",
        f"Description=Create AP interface {ap_interface}",
        f"After=sys-subsystem-net-devices-{upstream_interface}.device",
        f"Requires=sys-subsystem-net-devices-{upstream_interface}.device",
        "",
        "[Service]",
        "Type=oneshot",
        "RemainAfterExit=yes",
        f"User={service_user}",
        f"Group={service_group}",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
        "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW",
        f"ExecStart=/sbin/iw dev {upstream_interface} interface add {ap_interface} type __ap",
        f"ExecStart=/sbin/ip link set {ap_interface} up",
        f"ExecStop=/sbin/ip link set {ap_interface} down",
        f"ExecStop=/sbin/iw dev {ap_interface} del",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    return "\n".join(lines) + "\n"


def wlan0ap_ip_service_template(
    *,
    ap_interface: str,
    ap_ip_cidr: str,
    ap_service_unit: str = WLAN0AP_UNIT,
    service_user: str = "mcbridge",
    service_group: str = "mcbridge",
) -> str:
    cidr = _normalize_cidr(ap_ip_cidr)
    lines = [
        "[Unit]",
        f"Description=Assign static IP {cidr} to {ap_interface}",
        f"After={ap_service_unit} network.target",
        f"Requires={ap_service_unit}",
        "Before=hostapd.service dnsmasq.service",
        "",
        "[Service]",
        "Type=oneshot",
        "RemainAfterExit=yes",
        f"User={service_user}",
        f"Group={service_group}",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW",
        "AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW",
        f"ExecStartPre=/sbin/ip addr flush dev {ap_interface} scope global",
        f"ExecStart=/sbin/ip addr replace {cidr} dev {ap_interface}",
        f"ExecStart=/sbin/ip link set {ap_interface} up",
        "",
        "[Install]",
        "WantedBy=multi-user.target",
    ]
    return "\n".join(lines) + "\n"


def _write_output(contents: str, output: str | None) -> None:
    if not output:
        print(contents, end="")
        return
    path = Path(output)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Render mcbridge systemd units.")
    subparsers = parser.add_subparsers(dest="unit", required=True)

    wlan0ap = subparsers.add_parser("wlan0ap", help="Render wlan0ap.service")
    wlan0ap.add_argument("--ap-interface", default=AP_INTERFACE)
    wlan0ap.add_argument("--upstream-interface", default=UPSTREAM_INTERFACE)
    wlan0ap.add_argument("--output")

    wlan0ap_ip = subparsers.add_parser("wlan0ap-ip", help="Render wlan0ap-ip.service")
    wlan0ap_ip.add_argument("--ap-interface", default=AP_INTERFACE)
    wlan0ap_ip.add_argument("--ap-ip-cidr", required=True)
    wlan0ap_ip.add_argument("--ap-service-unit", default=WLAN0AP_UNIT)
    wlan0ap_ip.add_argument("--output")
    return parser


def _main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)

    if args.unit == "wlan0ap":
        contents = wlan0ap_service_template(ap_interface=args.ap_interface, upstream_interface=args.upstream_interface)
    elif args.unit == "wlan0ap-ip":
        contents = wlan0ap_ip_service_template(
            ap_interface=args.ap_interface, ap_ip_cidr=args.ap_ip_cidr, ap_service_unit=args.ap_service_unit
        )
    else:
        parser.error(f"Unknown unit: {args.unit}")
        return 2

    _write_output(contents, getattr(args, "output", None))
    return 0


if __name__ == "__main__":  # pragma: no cover - CLI convenience
    raise SystemExit(_main())
