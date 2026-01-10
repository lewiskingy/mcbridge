"""Helper for preparing the mcbridge agent socket directory.

This helper is intended to be invoked via a constrained sudoers/polkit policy.
It creates the runtime directory for the agent socket, optionally removes stale
socket files, and enforces ownership/permissions for the service user and
operator group.
"""

from __future__ import annotations

import argparse
import os
import pwd
import grp
from pathlib import Path

DEFAULT_SOCKET = Path(os.environ.get("MCBRIDGE_AGENT_SOCKET", "/run/mcbridge/agent.sock"))
DEFAULT_SERVICE_USER = os.environ.get("MCBRIDGE_SERVICE_USER", "mcbridge")
DEFAULT_OPERATOR_GROUP = os.environ.get("MCBRIDGE_OPERATOR_GROUP", "mcbridge-operators")
DEFAULT_MODE = 0o770


class SocketHelperError(RuntimeError):
    """Raised when the socket helper cannot complete safely."""


def _resolve_ids(user: str, group: str) -> tuple[int, int]:
    try:
        uid = pwd.getpwnam(user).pw_uid
    except KeyError as exc:
        raise SocketHelperError(f"User {user} not found") from exc

    try:
        gid = grp.getgrnam(group).gr_gid
    except KeyError as exc:
        raise SocketHelperError(f"Group {group} not found") from exc

    return uid, gid


def ensure_socket_directory(
    *,
    socket_path: Path = DEFAULT_SOCKET,
    service_user: str = DEFAULT_SERVICE_USER,
    operator_group: str = DEFAULT_OPERATOR_GROUP,
    mode: int = DEFAULT_MODE,
    recreate: bool = False,
) -> dict[str, object]:
    """Ensure the agent socket directory exists with correct permissions."""

    if os.geteuid() != 0:
        raise SocketHelperError("mcbridge-agent-socket-helper must run as root.")

    directory = socket_path.parent
    uid, gid = _resolve_ids(service_user, operator_group)

    directory.mkdir(parents=True, exist_ok=True)
    os.chown(directory, uid, gid)
    os.chmod(directory, mode)

    removed_socket = False
    if recreate and socket_path.exists():
        socket_path.unlink()
        removed_socket = True

    return {
        "status": "ok",
        "socket": str(socket_path),
        "directory": str(directory),
        "owner": service_user,
        "group": operator_group,
        "mode": f"{mode:o}",
        "removed_socket": removed_socket,
    }


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Prepare the mcbridge agent socket directory.")
    parser.add_argument("--socket", type=Path, default=DEFAULT_SOCKET, help="Path to the agent socket")
    parser.add_argument("--service-user", default=DEFAULT_SERVICE_USER, help="Service user that owns the socket")
    parser.add_argument("--operator-group", default=DEFAULT_OPERATOR_GROUP, help="Operator group allowed to access the socket")
    parser.add_argument("--mode", default=f"{DEFAULT_MODE:o}", help="Octal directory mode (default 770)")
    parser.add_argument("--recreate", action="store_true", help="Remove an existing socket before preparing the directory")
    return parser


def main(argv: list[str] | None = None) -> None:
    parser = _build_parser()
    args = parser.parse_args(args=argv)

    try:
        mode_int = int(str(args.mode), 8)
    except ValueError as exc:
        raise SystemExit(f"Invalid mode: {args.mode}") from exc

    try:
        result = ensure_socket_directory(
            socket_path=args.socket,
            service_user=args.service_user,
            operator_group=args.operator_group,
            mode=mode_int,
            recreate=args.recreate,
        )
    except SocketHelperError as exc:
        raise SystemExit(str(exc)) from exc

    print(result)


if __name__ == "__main__":  # pragma: no cover - CLI entrypoint
    main()
