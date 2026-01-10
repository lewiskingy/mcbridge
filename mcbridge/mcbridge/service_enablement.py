"""Helpers to ensure required systemd services are enabled."""

from __future__ import annotations

from typing import Callable, Mapping, Sequence, Tuple


def _service_state(result: Mapping[str, object]) -> str:
    stdout = str(result.get("stdout") or "").strip().lower()
    if "masked" in stdout:
        return "masked"
    if stdout == "disabled":
        return "disabled"
    if stdout == "enabled":
        return "enabled"
    if stdout:
        return stdout
    if result.get("returncode") == 0:
        return "enabled"
    return "unknown"


def _command_output(result: Mapping[str, object]) -> str:
    stderr = str(result.get("stderr") or "").strip()
    stdout = str(result.get("stdout") or "").strip()
    return stderr or stdout or "no output"


def _format_error(action: str, service: str, result: Mapping[str, object]) -> str:
    rc = result.get("returncode")
    output = _command_output(result)
    return f"{action} {service} failed (returncode={rc}): {output}"


def ensure_services_enabled(
    services: Sequence[str],
    *,
    runner: Callable[[Sequence[str]], Mapping[str, object]],
    dry_run: bool = False,
    start_services: bool = True,
) -> Tuple[dict[str, object], list[str]]:
    """Ensure the given services are unmasked and enabled.

    The ``runner`` callable should accept a sequence of systemctl arguments,
    returning a mapping with ``stdout``, ``stderr``, and ``returncode`` keys.
    """

    statuses: dict[str, object] = {}
    errors: list[str] = []

    for service in services:
        entry: dict[str, object] = {"service": service, "actions": [], "applied": False}

        is_enabled = runner(["is-enabled", service])
        state = _service_state(is_enabled)
        entry["is_enabled"] = is_enabled
        entry["state"] = state
        entry["actions"].append(f"systemctl is-enabled {service}")

        if is_enabled.get("returncode") not in (0, 1):
            message = _format_error("systemctl is-enabled", service, is_enabled)
            entry["status"] = "error"
            entry["error"] = message
            errors.append(message)
            statuses[service] = entry
            continue

        if state == "masked":
            entry["actions"].append(f"systemctl unmask {service}")
            if dry_run:
                entry["status"] = "planned"
                entry["reason"] = "dry_run"
            else:
                unmask_result = runner(["unmask", service])
                entry["unmask"] = unmask_result
                if unmask_result.get("returncode") not in (0,):
                    message = _format_error("systemctl unmask", service, unmask_result)
                    entry["status"] = "error"
                    entry["error"] = message
                    errors.append(message)
                    statuses[service] = entry
                    continue
                state = "unmasked"

        if state in {"disabled", "masked", "unmasked"}:
            enable_args = ["enable", "--now", service] if start_services else ["enable", service]
            entry["actions"].append("systemctl " + " ".join(enable_args))
            if dry_run:
                entry["status"] = entry.get("status", "planned")
                entry.setdefault("reason", "dry_run")
            else:
                enable_result = runner(enable_args)
                entry["enable"] = enable_result
                if enable_result.get("returncode") not in (0,):
                    message = _format_error("systemctl enable" + (" --now" if start_services else ""), service, enable_result)
                    entry["status"] = "error"
                    entry["error"] = message
                    errors.append(message)
                    statuses[service] = entry
                    continue
                entry["status"] = "updated"
                entry["applied"] = True
        else:
            entry["status"] = entry.get("status", "ok")

        statuses[service] = entry

    return statuses, errors


__all__ = ["ensure_services_enabled"]
