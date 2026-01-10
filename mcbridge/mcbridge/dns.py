"""DNS domain logic.

This module refactors the behaviour from ``manage-dnsmasq`` into reusable
functions that can be invoked by the CLI dispatcher. The public entrypoints
mirror the legacy script operations while keeping stdout machine-readable JSON
and stderr available for operational logs.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import NamedTemporaryFile
from typing import Any, Mapping, MutableMapping, Sequence

from .common import (
    CONFIG_HISTORY_DIR,
    DNSMASQ_ACTIVE_CONF,
    DNSMASQ_CONF,
    DNSMASQ_JSON,
    DNSMASQ_OVERRIDES_CONF,
    FAILED_GENERATED_DIR,
    GENERATED_HISTORY_DIR,
    KNOWN_SERVERS_JSON,
    DNS_OVERRIDES_JSON,
    MANAGE_AP_SECTION_END,
    MANAGE_AP_SECTION_START,
    MANAGE_DNSMASQ_SECTION_END,
    MANAGE_DNSMASQ_SECTION_START,
    analyse_dnsmasq_layout,
    assemble_dnsmasq_config,
    collect_file_mtimes,
    compare_configs,
    config_source_label,
    diff_text,
    format_dns_override_lines,
    extract_section_body,
    load_dns_overrides_config,
    load_json,
    logger,
    mismatch_summary,
    read_text,
    read_system_dns_config,
    restart_service,
    response_payload,
    restore_from_history,
    save_dns_overrides_config,
    save_failed_validation_artifacts,
    save_json,
    service_status,
    normalize_dns_override_payload,
    write_history_file,
)

DNS_FIELDS = ("redirect", "target", "enabled")
DEFAULT_TARGET: str | None = None
ACTIVE_BYPASS_REASON = "active_conf_bypassed"


@dataclass
class DnsResult:
    """Domain result with the rendered payload and exit code."""

    payload: Mapping[str, Any]
    exit_code: int


def _debug_verbose(flag: bool | None = None) -> bool:
    env_value = os.environ.get("MCBRIDGE_DEBUG_JSON", "")
    env_enabled = env_value.lower() in {"1", "true", "yes", "on"}
    return bool(flag) or env_enabled


def _unique_list(items: Sequence[object]) -> list[str]:
    return list(dict.fromkeys([str(entry).strip() for entry in items if str(entry or "").strip()]))


def _command_success(result: Mapping[str, object] | None) -> bool:
    if not isinstance(result, Mapping):
        return False
    return result.get("returncode") == 0


DNS_CAPABILITY_BITS = {
    "CAP_DAC_OVERRIDE": 1,
    "CAP_SETUID": 7,
    "CAP_NET_ADMIN": 12,
}
TRUSTED_DNS_CONTEXT_ENV = "MCBRIDGE_TRUSTED_DNS_CONTEXT"


def _read_proc_status() -> str | None:
    status_path = Path("/proc/self/status")
    try:
        return status_path.read_text(encoding="utf-8")
    except OSError:
        return None


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


def _effective_capabilities() -> set[str]:
    value = _parse_capability_value("CapEff", _read_proc_status())
    if value is None:
        return set()
    return {name for name, bit in DNS_CAPABILITY_BITS.items() if value & (1 << bit)}


def _trusted_dns_context() -> bool:
    env_value = os.environ.get(TRUSTED_DNS_CONTEXT_ENV, "")
    trusted_env = env_value.lower() in {"1", "true", "yes", "on"}
    return trusted_env or os.environ.get("MCBRIDGE_AGENT_CONTEXT") == "1"


def _require_dns_privileges() -> None:
    if os.geteuid() == 0:
        return

    effective_capabilities = _effective_capabilities()
    has_dns_capabilities = all(cap in effective_capabilities for cap in DNS_CAPABILITY_BITS)
    if has_dns_capabilities or _trusted_dns_context():
        return

    raise SystemExit("mcbridge dns commands require root privileges. Re-run with 'sudo mcbridge dns ...'.")


def _run_command(command: Sequence[str]) -> dict[str, object]:
    try:
        if command and command[0] == "systemctl":
            from . import privileges

            process = privileges.sudo_run(command)
        else:
            process = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError as exc:
        return {
            "command": " ".join(command),
            "stdout": "",
            "stderr": str(exc),
            "returncode": 127,
            "error": str(exc),
        }
    except subprocess.SubprocessError as exc:
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


def _dns_override_lines(redirect: str, target: str) -> list[str]:
    target_value = str(target or "").strip()
    redirect_value = str(redirect or "").strip()

    if not redirect_value or not target_value:
        return []

    return format_dns_override_lines([redirect_value], target_value)


def _dns_override_template(config: Mapping[str, object]) -> str:
    target = str(config.get("target") or "").strip()
    redirect = str(config.get("redirect") or "").strip()
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


def _persist_dns_override_json(
    payload: Mapping[str, Any],
    *,
    apply_changes: bool = True,
    sync_legacy: bool = True,
    mark_skipped: bool = False,
) -> MutableMapping[str, object]:
    canonical_path = DNS_OVERRIDES_JSON
    current_json_text = read_text(canonical_path)
    new_json_text = json.dumps(payload, indent=2) + "\n"
    actions = [f"write {canonical_path}"]
    if sync_legacy and DNSMASQ_JSON.exists():
        actions.append(f"write {DNSMASQ_JSON} (legacy mirror)")

    result: MutableMapping[str, object] = {
        "path": str(canonical_path),
        "diff": diff_text(current_json_text, new_json_text, fromfile=str(canonical_path), tofile=f"{canonical_path} (candidate)"),
        "actions": actions,
        "applied": False,
    }

    if not apply_changes:
        if mark_skipped:
            result["skipped"] = True
        return result

    if current_json_text and current_json_text != new_json_text:
        write_history_file(CONFIG_HISTORY_DIR, suffix=canonical_path.name, contents=current_json_text)
    save_dns_overrides_config(dict(payload), sync_legacy=sync_legacy)
    result["applied"] = True
    return result


def _strip_existing_override_block(contents: str) -> str:
    if not contents:
        return ""

    lines = contents.splitlines()
    cleaned: list[str] = []
    for line in lines:
        if line.strip().startswith("# Generated by mcbridge manage-dnsmasq"):
            break
        cleaned.append(line)

    while cleaned and not cleaned[-1].strip():
        cleaned.pop()

    return "\n".join(cleaned) + ("\n" if cleaned else "")


def _split_combined_directives(line: str) -> list[str]:
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return [stripped]

    tokens = stripped.split()
    if len(tokens) < 2:
        return [stripped]

    if any(token.startswith("#") for token in tokens[1:]):
        return [stripped]

    def _looks_like_directive(token: str) -> bool:
        return "=" in token or token.startswith("#") or token.replace("-", "").isalnum()

    if all(_looks_like_directive(token) for token in tokens):
        return tokens
    return [stripped]


def _normalise_ap_section_body(body: str) -> str:
    if not body:
        return ""

    normalised: list[str] = []
    for line in body.splitlines():
        normalised.extend(_split_combined_directives(line))

    while normalised and not normalised[0].strip():
        normalised.pop(0)
    while normalised and not normalised[-1].strip():
        normalised.pop()
    return "\n".join(normalised)


def _prepare_merged_config(
    *,
    override_block: str,
    active_contents: str,
    base_contents: str,
    prefer_active: bool = True,
    reason: str | None = None,
) -> tuple[str, str, str | None, dict[str, object]]:
    _ = override_block  # retained for interface compatibility; overrides are embedded inline
    sources: list[tuple[str, str]] = []
    if prefer_active and active_contents:
        sources.append(("active", active_contents))
    if base_contents:
        sources.append(("base", base_contents))

    ap_section_body: str | None = None
    ap_section_source = ""

    for source_name, contents in sources:
        ap_section_body = extract_section_body(contents, MANAGE_AP_SECTION_START, MANAGE_AP_SECTION_END)
        if ap_section_body is not None:
            ap_section_source = source_name
            break
        if source_name == "active" and base_contents:
            reason = reason or ACTIVE_BYPASS_REASON

    if ap_section_body is None:
        fallback_contents = base_contents or active_contents
        ap_section_body = _strip_existing_override_block(fallback_contents).strip("\n")
        ap_section_source = sources[0][0] if sources else ""

    ap_section_body = _normalise_ap_section_body(ap_section_body or "")
    merged_config = assemble_dnsmasq_config(ap_section_body or "", override_block)

    cleanup_details = {
        "active": analyse_dnsmasq_layout(active_contents),
        "base": analyse_dnsmasq_layout(base_contents),
    }
    cleanup_needed = any(entry.get("needs_cleanup") for entry in cleanup_details.values())
    overrides_missing = not any(entry.get("overrides_present") for entry in cleanup_details.values())
    cleanup_details["applied"] = bool(cleanup_needed or overrides_missing)
    cleanup_details["overrides_added"] = overrides_missing
    cleanup_details["warnings"] = []
    if cleanup_needed:
        cleanup_details["warnings"].append(
            "Detected duplicate managed sections or stray inline overrides; rewriting with managed template."
        )
    if overrides_missing:
        cleanup_details["warnings"].append("Missing managed overrides; embedding overrides inline.")
    if cleanup_details["warnings"]:
        logger.warning(" ".join(cleanup_details["warnings"]))
    return merged_config, ap_section_source, reason, cleanup_details


def _validate_and_apply(
    *,
    path: Path,
    mirror_path: Path | None = None,
    mirror_candidate: str | None = None,
    candidate: str,
    validate_command: list[str],
    service: str,
    dry_run: bool,
    history_suffix: str,
    history_dir: Path,
    restore_on_failure: bool = True,
) -> dict:
    current = read_text(path)
    current_mtime = collect_file_mtimes([path]).get(str(path))
    diff = diff_text(current, candidate, fromfile=str(path), tofile=f"{path} (candidate)")
    if diff:
        logger.debug("Planned diff for %s:\n%s", path, diff)
    else:
        logger.debug("No content changes detected for %s", path)
    mirror_actions = [f"mirror to {mirror_path}"] if mirror_path else []
    restart_action_label = f"restart {service}"
    if service != "dnsmasq":
        restart_action_label = f"reload-or-restart {service}"
    actions = [
        f"write {path}",
        *mirror_actions,
        f"validate with {' '.join(validate_command)}",
        restart_action_label,
    ]
    if service == "dnsmasq":
        actions.insert(0, "systemctl stop dnsmasq")
    mirror_text = mirror_candidate if mirror_candidate is not None else candidate

    if dry_run:
        logger.info("Dry run: would validate and deploy %s (service=%s)", path, service)
        return {
            "path": str(path),
            "mirror_path": str(mirror_path) if mirror_path else None,
            "candidate": candidate,
            "changed": bool(diff),
            "validation": {"status": "skipped", "reason": "dry_run"},
            "service_restart": {"service": service, "status": "skipped", "success": None},
            "applied": False,
            "actions": actions,
            "file_mtimes": {"before": current_mtime, "after": current_mtime},
        }

    mirror_original = None
    mirror_updated_for_validation = False
    service_stop: dict[str, object] | None = None
    post_write_validation: dict[str, object] | None = None
    service_action: dict[str, object] | None = None
    status_result: dict[str, object] | None = None
    backup_path: Path | None = None
    original_contents = current
    if mirror_path and mirror_candidate is not None:
        mirror_original = read_text(mirror_path)
        if mirror_original != mirror_candidate:
            mirror_path.parent.mkdir(parents=True, exist_ok=True)
            mirror_path.write_text(mirror_candidate, encoding="utf-8")
            mirror_updated_for_validation = True

    with NamedTemporaryFile("w", delete=False, encoding="utf-8") as temp_file:
        temp_file.write(candidate)
        temp_path = Path(temp_file.name)

    try:
        placeholder_present = any("{path}" in str(entry) for entry in validate_command)
        command = [str(entry).replace("{path}", str(temp_path)) for entry in validate_command]
        if not placeholder_present:
            command.append(str(temp_path))
        logger.info("Validating %s with %s", path, " ".join(command))
        logger.debug("Validation command argv=%s", command)
        try:
            process = subprocess.run(command, capture_output=True, text=True)
        except FileNotFoundError as exc:
            validation = {"status": "failed", "stdout": "", "stderr": str(exc), "returncode": 127, "skipped": False}
        else:
            validation = {
                "status": "passed" if process.returncode == 0 else "failed",
                "stdout": process.stdout,
                "stderr": process.stderr,
                "returncode": process.returncode,
                "skipped": False,
            }
        if validation.get("stdout"):
            logger.debug("Validation stdout for %s:\n%s", path, validation["stdout"])
        stderr_text = validation.get("stderr") or ""
        if stderr_text:
            logger.debug("Validation stderr for %s:\n%s", path, stderr_text)
            if command and command[0] == "dnsmasq":
                is_failure = validation.get("status") == "failed" or (
                    validation.get("returncode") not in (0, None) and not validation.get("skipped")
                )
                log_level = logging.ERROR if is_failure else logging.INFO
                logger.log(log_level, "dnsmasq validation stderr for %s:\n%s", path, stderr_text)
        logger.log(
            logging.INFO if validation.get("status") == "passed" else logging.ERROR,
            "Validation %s for %s (rc=%s)",
            validation.get("status"),
            path,
            validation.get("returncode"),
        )

        if validation.get("status") == "failed":
            stderr_text = validation.get("stderr") or ""
            first_stderr_line = stderr_text.splitlines()[0] if stderr_text else ""
            dnsmasq_line_hint = None
            if command and command[0] == "dnsmasq":
                match = re.search(r"line\s+(\d+)", stderr_text)
                if match:
                    dnsmasq_line_hint = match.group(1)
            hint_segments = []
            if dnsmasq_line_hint:
                hint_segments.append(f"line {dnsmasq_line_hint}")
            if first_stderr_line:
                hint_segments.append(first_stderr_line)
                print(f"{path}: {first_stderr_line}", file=sys.stderr)
            dnsmasq_hint = "; ".join(hint_segments) if hint_segments else None

            failed_paths = save_failed_validation_artifacts(
                candidate_contents=candidate,
                candidate_name=path.name,
                mirror_contents=mirror_text if mirror_path else None,
                mirror_name=mirror_path.name if mirror_path else None,
                validate_command=command,
                returncode=validation.get("returncode"),
                stdout=validation.get("stdout") or "",
                stderr=stderr_text,
                failed_dir=FAILED_GENERATED_DIR,
            )
            restored = restore_from_history(path, history_dir, suffix=history_suffix) if restore_on_failure else None
            if restored:
                logger.info("Restored %s from %s after failed validation", path, restored)
            if mirror_path and mirror_updated_for_validation:
                if mirror_original:
                    mirror_path.write_text(mirror_original, encoding="utf-8")
                else:
                    mirror_path.unlink(missing_ok=True)
            return {
                "path": str(path),
                "mirror_path": str(mirror_path) if mirror_path else None,
                "candidate": candidate,
                "changed": bool(diff),
                "validation": {
                    "status": validation.get("status") or "failed",
                    "returncode": validation.get("returncode"),
                    "failed_paths": failed_paths,
                },
                "restored_from": str(restored) if restored else None,
                "applied": False,
                "actions": actions,
                "error": (
                    f"Validation failed for {path} (dnsmasq {dnsmasq_hint}); see logs for validation output"
                    if dnsmasq_hint
                    else f"Validation failed for {path}; see logs for validation output"
                ),
                "file_mtimes": {"before": current_mtime, "after": collect_file_mtimes([path]).get(str(path))},
            }

        if current and current != candidate:
            backup_path = write_history_file(history_dir, suffix=history_suffix, contents=current)
            logger.info("Archived previous version of %s to history (%s)", path, history_suffix)

        service_stop = _run_command(["systemctl", "stop", service])
        if not _command_success(service_stop):
            error_message = service_stop.get("stderr") or service_stop.get("stdout") or f"{service} stop failed"
            if mirror_path and mirror_updated_for_validation:
                if mirror_original:
                    mirror_path.write_text(mirror_original, encoding="utf-8")
                else:
                    mirror_path.unlink(missing_ok=True)
            return {
                "path": str(path),
                "mirror_path": str(mirror_path) if mirror_path else None,
                "candidate": candidate,
                "changed": bool(diff),
                "validation": {
                    "status": validation.get("status") or "passed",
                    "returncode": validation.get("returncode"),
                    "stdout": validation.get("stdout"),
                    "stderr": validation.get("stderr"),
                    "skipped": False,
                    "reason": "dnsmasq_stop_failed",
                },
                "applied": False,
                "actions": actions,
                "error": f"Failed to stop dnsmasq before applying configuration: {error_message}",
                "file_mtimes": {"before": current_mtime, "after": collect_file_mtimes([path]).get(str(path))},
                "service_stop": service_stop,
            }

        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(candidate, encoding="utf-8")
        if mirror_path:
            mirror_path.parent.mkdir(parents=True, exist_ok=True)
            mirror_path.write_text(mirror_text, encoding="utf-8")
            logger.info("Mirrored %s to %s", path, mirror_path)

        post_write_validation = _run_command(["dnsmasq", "--test", f"--conf-file={path}"])
        if not _command_success(post_write_validation):
            stderr_text = (post_write_validation.get("stderr") or "").strip()
            first_line = stderr_text.splitlines()[0] if stderr_text else ""
            restored_from: Path | None = None
            if original_contents is not None:
                try:
                    path.write_text(original_contents, encoding="utf-8")
                    restored_from = backup_path
                except OSError as exc:  # pragma: no cover - defensive for odd IO errors
                    logger.debug("Could not restore %s from backup %s: %s", path, backup_path, exc)
            if restored_from is None:
                restored_from = restore_from_history(path, history_dir, suffix=history_suffix)
            if restored_from is None and original_contents is None:
                path.unlink(missing_ok=True)
            if mirror_path:
                if mirror_original:
                    mirror_path.write_text(mirror_original, encoding="utf-8")
                else:
                    mirror_path.unlink(missing_ok=True)
            service_action = restart_service(service)
            status_result = service_status(service)
            error_message = first_line or "dnsmasq reported an error validating the applied configuration"
            return {
                "path": str(path),
                "mirror_path": str(mirror_path) if mirror_path else None,
                "candidate": candidate,
                "changed": bool(diff),
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
                "actions": actions,
                "error": f"Validation failed for applied dnsmasq.conf: {error_message}",
                "file_mtimes": {"before": current_mtime, "after": collect_file_mtimes([path]).get(str(path))},
                "service_restart": {
                    "service": service,
                    "returncode": (service_action or {}).get("returncode"),
                    "success": (service_action or {}).get("success"),
                    "status": status_result,
                },
                "service_stop": service_stop,
                "post_write_validation": post_write_validation,
            }

        service_action = restart_service(service)
        status_result = service_status(service)
        logger.info(
            "Restarted %s via systemctl (success=%s, returncode=%s)",
            service,
            service_action.get("success"),
            service_action.get("returncode"),
        )
    finally:
        temp_path.unlink(missing_ok=True)

    updated_mtime = collect_file_mtimes([path]).get(str(path))
    result = {
        "path": str(path),
        "mirror_path": str(mirror_path) if mirror_path else None,
        "candidate": candidate,
        "changed": bool(diff),
        "validation": {
            "status": validation.get("status") or "passed",
            "returncode": validation.get("returncode"),
            "stdout": validation.get("stdout"),
            "stderr": validation.get("stderr"),
        },
        "service_restart": {
            "service": service,
            "returncode": service_action.get("returncode"),
            "success": service_action.get("success"),
            "status": status_result,
        },
        "applied": bool(service_action.get("success")),
        "file_mtimes": {"before": current_mtime, "after": updated_mtime},
        "actions": actions,
        "service_stop": service_stop,
        "post_write_validation": post_write_validation,
    }
    if service == "dnsmasq" and not service_action.get("success"):
        restart_message = service_action.get("stderr") or service_action.get("stdout") or "dnsmasq restart failed"
        result["error"] = restart_message
    return result


def _normalise_known_servers(raw: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []

    if isinstance(raw, Mapping):
        default_target = str(raw.get("target") or "").strip() or None
        redirects = raw.get("redirects")
        redirect_items: Sequence[object] = []
        if isinstance(redirects, Mapping):
            redirect_items = [redirects]
        elif isinstance(redirects, Sequence) and not isinstance(redirects, (str, bytes, bytearray)):
            redirect_items = redirects

        for item in redirect_items:
            if not isinstance(item, Mapping):
                continue
            redirect = str(item.get("redirect") or item.get("hostname") or item.get("host") or "").strip()
            target = str(item.get("target") or "").strip() or None
            label = item.get("name") or item.get("label") or redirect or target
            if not redirect:
                continue
            entries.append(
                {
                    "label": str(label or redirect or target),
                    "redirect": redirect or None,
                    "target": target or default_target,
                    "default_target": default_target,
                }
            )
        return entries

    if not isinstance(raw, (list, tuple)):
        return entries

    for item in raw:
        if isinstance(item, str):
            redirect = item
            label = item
            target = None
        elif isinstance(item, Mapping):
            redirect = item.get("redirect") or item.get("hostname") or item.get("host")
            hijacks = item.get("hijacks")
            hijack_value = None
            if isinstance(hijacks, Sequence) and not isinstance(hijacks, (str, bytes, bytearray)):
                hijack_candidates = [str(entry or "").strip() for entry in hijacks if str(entry or "").strip()]
                if len(hijack_candidates) == 1:
                    hijack_value = hijack_candidates[0]
            label = item.get("name") or item.get("label") or redirect or hijack_value
            target = item.get("target")
        else:
            continue

        redirect_value = str(redirect or hijack_value or "").strip()
        target_value = str(target or "").strip()
        if not redirect_value:
            continue

        entries.append(
            {
                "label": str(label or redirect_value or target_value),
                "redirect": redirect_value or None,
                "target": target_value or None,
                "default_target": None,
            }
        )

    return entries


def _load_knownservers_target() -> str | None:
    raw = load_json(KNOWN_SERVERS_JSON, default={})
    if not isinstance(raw, Mapping):
        return None
    target_value = str(raw.get("target") or "").strip()
    return target_value or None


def _select_from_menu(entries: Sequence[Mapping[str, Any]]) -> Mapping[str, Any]:
    print("Select a redirect target from knownservers.json:", file=sys.stderr)
    for index, entry in enumerate(entries, start=1):
        redirect = entry.get("redirect")
        target = entry.get("target") or entry.get("default_target")

        details = []
        if redirect:
            details.append(f"redirect={redirect}")
        if target:
            details.append(f"target={target}")

        suffix = f" ({'; '.join(details)})" if details else ""
        print(f"{index}) {entry.get('label') or redirect}{suffix}", file=sys.stderr)

    try:
        choice = input("Enter a number: ").strip()
    except EOFError as exc:
        raise ValueError("No input available to select from menu.") from exc

    if not choice.isdigit():
        raise ValueError("Menu selection must be a number.")

    choice_index = int(choice)
    if choice_index < 1 or choice_index > len(entries):
        raise ValueError(f"Selection {choice_index} is out of range.")
    return entries[choice_index - 1]


def _exit_code_from_status(status: str, *, drift: bool = False) -> int:
    if status == "error":
        return 3
    if drift:
        return 10
    if status == "warning":
        return 2
    return 0


def _dns_summary(config: Mapping[str, object] | None) -> dict[str, object]:
    source = config or {}
    return {
        "redirect": source.get("redirect") or None,
        "target": source.get("target") or None,
        "enabled": source.get("enabled", True),
        "name": source.get("name") or None,
    }


def build_payload(
    *,
    operation: str,
    source: str,
    active_config: dict,
    mismatches: list,
    stored: dict,
    system: dict,
    status: str = "ok",
    message: str | None = None,
    config_sources: dict | None = None,
) -> dict:
    summary = _dns_summary(active_config)
    payload = {
        "status": status,
        "source": source,
        "dnsmasq_config": active_config,
        "mismatches": mismatches,
        "mismatch_summary": mismatch_summary(mismatches),
        "system_config": system,
        "stored_config": stored,
        "operation": operation,
        "dns_summary": summary,
        "redirect": summary.get("redirect"),
        "target": summary.get("target"),
        "dns_enabled": summary.get("enabled"),
        "dns_name": summary.get("name"),
    }
    if message:
        payload["message"] = message
    if config_sources:
        payload["config_sources"] = config_sources
    return payload


def _load_override_config(*, default_target: str | None = None) -> tuple[dict[str, Any], str]:
    raw_config, source = load_dns_overrides_config(default={})
    try:
        normalized = normalize_dns_override_payload(raw_config, default_target=default_target)
    except ValueError as exc:
        raise ValueError(f"{source} requires migration: {exc}") from exc
    return normalized, source


def status(*, debug_json: bool | None = None) -> DnsResult:
    _require_dns_privileges()
    debug_verbose = _debug_verbose(debug_json)
    try:
        stored_config, _stored_source = _load_override_config()
    except ValueError as exc:
        payload = {
            "status": "error",
            "message": str(exc),
            "operation": "status",
            "stored_config": {},
            "system_config": {},
            "source": "stored JSON",
        }
        merged = response_payload(payload, verbose=debug_verbose)
        return DnsResult(payload=merged, exit_code=2)

    system_config, system_sources = read_system_dns_config(include_sources=True)
    mismatches = compare_configs(system_config, stored_config, fields=DNS_FIELDS)
    source_label = config_source_label(mismatches)
    status_label = "ok" if not mismatches else "warning"
    message = "Status only: live dnsmasq configuration matches stored JSON."
    if mismatches:
        message = "Status only: live dnsmasq configuration differs from stored JSON."

    payload = build_payload(
        operation="status",
        source=source_label,
        active_config=system_config if source_label == "system" else stored_config,
        mismatches=mismatches,
        stored=stored_config,
        system=system_config,
        status=status_label,
        message=message,
        config_sources=system_sources,
    )
    merged = response_payload(payload, verbose=debug_verbose)
    drift = bool(mismatches)
    return DnsResult(payload=merged, exit_code=_exit_code_from_status(status_label, drift=drift))


def _resolve_update_inputs(
    *,
    redirect: str | None,
    target: str | None,
    stored_config: Mapping[str, Any],
    default_target: str | None = None,
) -> dict[str, object]:
    redirect_value = str(redirect or stored_config.get("redirect") or "").strip()
    target_value = str(target or stored_config.get("target") or default_target or "").strip()
    enabled = bool(stored_config.get("enabled", True))
    name = str(stored_config.get("name") or "").strip()

    if not redirect_value:
        raise ValueError("DNS update requires --redirect or a menu selection.")
    if not target_value:
        raise ValueError("DNS update requires --target or a knownservers default.")

    result: dict[str, object] = {"redirect": redirect_value, "target": target_value, "enabled": enabled}
    if name:
        result["name"] = name
    return result


def update(
    *,
    redirect: str | None = None,
    target: str | None = None,
    dry_run: bool = False,
    force: bool = False,
    default_target: str | None = None,
    debug_json: bool | None = None,
) -> DnsResult:
    _require_dns_privileges()
    debug_verbose = _debug_verbose(debug_json)
    if default_target is None and target is None:
        default_target = _load_knownservers_target()
    try:
        stored_config, _stored_source = _load_override_config(default_target=default_target)
    except ValueError as exc:
        payload = {
            "status": "error",
            "message": str(exc),
            "operation": "update",
            "stored_config": {},
            "system_config": {},
            "source": "stored JSON",
        }
        merged = response_payload(payload, verbose=debug_verbose)
        return DnsResult(payload=merged, exit_code=2)

    system_config, system_sources = read_system_dns_config(include_sources=True)
    mismatches = compare_configs(system_config, stored_config, fields=DNS_FIELDS)

    if mismatches and not force:
        payload = build_payload(
            operation="update",
            source="system",
            active_config=system_config,
            mismatches=mismatches,
            stored=stored_config,
            system=system_config,
            status="warning",
            message="Live dnsmasq configuration differs from stored JSON. Re-run with --force to overwrite system state.",
            config_sources=system_sources,
        )
        merged = response_payload(payload, verbose=debug_verbose)
        return DnsResult(payload=merged, exit_code=2)

    if mismatches and force:
        logger.warning("Proceeding despite mismatch between system dnsmasq configuration and stored JSON (--force).")

    try:
        updated_config = _resolve_update_inputs(
            redirect=redirect, target=target, stored_config=stored_config, default_target=default_target
        )
    except ValueError as exc:
        payload = build_payload(
            operation="update",
            source="stored JSON",
            active_config=stored_config,
            mismatches=mismatches,
            stored=stored_config,
            system=system_config,
            status="error",
            message=str(exc),
            config_sources=system_sources,
        )
        merged = response_payload(payload, verbose=debug_verbose)
        return DnsResult(payload=merged, exit_code=2)
    json_plan = _persist_dns_override_json(updated_config, apply_changes=False)

    override_block = _dns_override_template(updated_config)
    active_contents = read_text(DNSMASQ_ACTIVE_CONF)
    base_contents = read_text(DNSMASQ_CONF)
    merged_config, ap_section_source, bypass_reason, cleanup_details = _prepare_merged_config(
        override_block=override_block,
        active_contents=active_contents,
        base_contents=base_contents or "",
        prefer_active=True,
    )

    overrides_result = _validate_and_apply(
        path=DNSMASQ_ACTIVE_CONF,
        mirror_path=DNSMASQ_OVERRIDES_CONF,
        mirror_candidate=override_block,
        candidate=merged_config,
        validate_command=["dnsmasq", "--test", "--conf-file={path}"],
        service="dnsmasq",
        dry_run=dry_run,
        history_suffix="dnsmasq.conf",
        history_dir=GENERATED_HISTORY_DIR,
        restore_on_failure=not bool(base_contents),
    )
    overrides_result["ap_section_source"] = ap_section_source or "active"
    overrides_result["cleanup"] = cleanup_details

    validation_attempts = [overrides_result.get("validation")]

    if not dry_run and overrides_result.get("error") and base_contents:
        merged_config, base_ap_source, fallback_reason, cleanup_details = _prepare_merged_config(
            override_block=override_block,
            active_contents=active_contents,
            base_contents=base_contents,
            prefer_active=False,
            reason=bypass_reason or "validation_failed",
        )
        fallback_result = _validate_and_apply(
            path=DNSMASQ_ACTIVE_CONF,
            mirror_path=DNSMASQ_OVERRIDES_CONF,
            mirror_candidate=override_block,
            candidate=merged_config,
            validate_command=["dnsmasq", "--test", "--conf-file={path}"],
            service="dnsmasq",
            dry_run=dry_run,
            history_suffix="dnsmasq.conf",
            history_dir=GENERATED_HISTORY_DIR,
        )
        validation_attempts.append(fallback_result.get("validation"))
        overrides_result = {
            **fallback_result,
            "fallback_used": True,
            "fallback_reason": fallback_reason or "validation_failed",
            "previous_validation": validation_attempts[0],
            "ap_section_source": base_ap_source or "base",
            "cleanup": cleanup_details,
        }

    overrides_result["validation_attempts"] = validation_attempts

    validation_failed = bool(overrides_result.get("error"))
    if validation_failed:
        json_result = dict(json_plan)
        json_result["rolled_back"] = True
    elif dry_run:
        json_result = _persist_dns_override_json(updated_config, apply_changes=False, mark_skipped=True)
    else:
        json_result = _persist_dns_override_json(updated_config, apply_changes=True)

    final_stored_config: MutableMapping[str, Any] = dict(stored_config)
    system_after: MutableMapping[str, Any] = dict(system_config)
    if not dry_run and not validation_failed:
        final_stored_config = dict(updated_config)
        if overrides_result.get("applied"):
            system_after = dict(updated_config)
        else:
            system_after = read_system_dns_config(dnsmasq_path=DNSMASQ_ACTIVE_CONF, dnsmasq_generated_path=DNSMASQ_OVERRIDES_CONF)
    elif dry_run:
        final_stored_config = dict(stored_config)

    post_update_mismatches = compare_configs(system_after, final_stored_config, fields=DNS_FIELDS)

    source_label = "stored JSON" if not post_update_mismatches or force else config_source_label(post_update_mismatches)
    proceed_message = "DNS overrides configuration updated."
    status_label = "ok"
    validation_failed = bool(overrides_result.get("error")) or (
        overrides_result.get("validation", {}).get("status") == "failed"
    )
    service_restart = overrides_result.get("service_restart") or {}
    runtime_failure = service_restart.get("success") is False

    if overrides_result.get("error"):
        proceed_message = "Configuration validation failed; stored configuration unchanged."
        status_label = "error"
    elif post_update_mismatches:
        proceed_message += " System configuration differs; regenerate or reload dnsmasq to apply."
        status_label = "warning"
    if dry_run:
        proceed_message += " Dry run; no files written or services restarted."
    if runtime_failure and status_label == "ok":
        status_label = "warning"
        proceed_message += " dnsmasq reload/restart failed; check systemctl status."

    payload = build_payload(
        operation="update",
        source=source_label,
        active_config=final_stored_config if source_label == "stored JSON" else system_after,
        mismatches=post_update_mismatches,
        stored=final_stored_config,
        system=system_after,
        message=proceed_message,
        status=status_label,
        config_sources=system_sources,
    )
    payload["changes"] = {"config_json": json_result, "overrides": overrides_result}
    merged = response_payload(payload, verbose=debug_verbose)

    exit_code = 0
    if validation_failed:
        exit_code = 2
    elif runtime_failure:
        exit_code = 3
    elif status_label == "warning":
        exit_code = 0

    return DnsResult(payload=merged, exit_code=exit_code)


def menu(*, dry_run: bool = False, force: bool = False, debug_json: bool | None = None) -> DnsResult:
    _require_dns_privileges()
    if not sys.stdin.isatty():
        raise ValueError("Interactive menu selection requires a TTY. Supply --redirect for headless usage.")

    entries = _normalise_known_servers(load_json(KNOWN_SERVERS_JSON, default={}))
    if not entries:
        return DnsResult(payload={"status": "error", "message": f"No entries found in {KNOWN_SERVERS_JSON}."}, exit_code=2)

    choice = _select_from_menu(entries)
    selected_redirect = choice.get("redirect")
    selected_target = choice.get("target") or choice.get("default_target")

    return update(
        redirect=selected_redirect,
        target=selected_target,
        default_target=choice.get("default_target"),
        dry_run=dry_run,
        force=force,
        debug_json=debug_json,
    )


__all__ = ["DnsResult", "status", "update", "menu"]
