"""Shared helpers for mcbridge management logic.

This module centralises safe file access for stored JSON configuration and
parsing of the generated system configuration files under ``/etc/mcbridge``.
It also offers helpers to compare live system state with the persisted JSON so
callers can warn before overwriting changes that were applied manually.
"""
from __future__ import annotations

import difflib
import ipaddress
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping, MutableMapping, Optional, Sequence

from .paths import (
    CONFIG_DIR,
    CONFIG_HISTORY_DIR,
    ETC_DIR,
    GENERATED_DIR,
    GENERATED_HISTORY_DIR,
    INIT_MARKER,
    LOG_DIR,
)

AP_JSON = CONFIG_DIR / "ap.json"
DNSMASQ_JSON = CONFIG_DIR / "dnsmasq.json"
KNOWN_SERVERS_JSON = CONFIG_DIR / "knownservers.json"
HOSTAPD_CONF = GENERATED_DIR / "hostapd.conf"
HOSTAPD_ACTIVE_CONF = Path("/etc/hostapd/hostapd.conf")
DNSMASQ_ACTIVE_CONF = Path("/etc/dnsmasq.conf")
DNSMASQ_CONF = GENERATED_DIR / "dnsmasq.conf"
DNSMASQ_OVERRIDES_CONF = GENERATED_DIR / "dnsmasq-mcbridge.conf"
DNS_OVERRIDES_JSON = CONFIG_DIR / "dns_overrides.json"
INITIALISED_MARKER = INIT_MARKER

LOG_FILE = LOG_DIR / "mcbridge-scripts.log"
HISTORY_RETENTION = 20
FAILED_GENERATED_DIR = Path(os.environ.get("MCBRIDGE_FAILED_ROOT", str(GENERATED_DIR / "failed")))
DEFAULT_FILE_OWNER = os.environ.get("MCBRIDGE_FILE_OWNER", "mcbridge")
DEFAULT_FILE_GROUP = os.environ.get("MCBRIDGE_FILE_GROUP", "mcbridge-operators")
DEFAULT_FILE_MODE = int(os.environ.get("MCBRIDGE_FILE_MODE", "660"), 8)
DEFAULT_DIR_MODE = int(os.environ.get("MCBRIDGE_DIR_MODE", "770"), 8)

MANAGE_AP_SECTION_START = "### SECTION START - MANAGED BY manage-ap"
MANAGE_AP_SECTION_END = "### SECTION END - MANAGED BY manage-ap"
MANAGE_DNSMASQ_SECTION_START = "### SECTION START - MANAGED BY manage-dnsmasq"
MANAGE_DNSMASQ_SECTION_END = "### SECTION END - MANAGED BY manage-dnsmasq"

logger = logging.getLogger("mcbridge.scripts")
logger.setLevel(logging.DEBUG)
if not logger.handlers:
    stream_handler = logging.StreamHandler(stream=sys.stderr)
    stream_handler.setLevel(logging.INFO)
    stream_handler.setFormatter(logging.Formatter("%(levelname)s: %(message)s"))
    logger.addHandler(stream_handler)

    journald_handler = None
    try:  # pragma: no cover - optional dependency on systemd environments
        from systemd.journal import JournalHandler  # type: ignore[import-untyped]
    except Exception:
        journald_handler = None
    else:
        journald_handler = JournalHandler(SYSLOG_IDENTIFIER="mcbridge-scripts")
        journald_handler.setLevel(logging.DEBUG)
        journald_handler.setFormatter(logging.Formatter("%(name)s[%(process)d]: %(levelname)s %(message)s"))
        logger.addHandler(journald_handler)

    if journald_handler is None:
        try:
            LOG_DIR.mkdir(parents=True, exist_ok=True)
            file_handler = RotatingFileHandler(LOG_FILE, maxBytes=1_000_000, backupCount=5, encoding="utf-8")
        except OSError as exc:  # pragma: no cover - permissions may block log file creation
            logger.debug("Could not create log file %s: %s", LOG_FILE, exc)
        else:
            file_handler.setLevel(logging.DEBUG)
            file_handler.setFormatter(logging.Formatter("%(asctime)s %(name)s %(levelname)s: %(message)s"))
            logger.addHandler(file_handler)

logger.propagate = False


def emit_error_payload(message: str, *, stream: Any | None = None) -> None:
    output = stream if stream is not None else sys.stdout
    print(json.dumps({"status": "error", "message": message}, separators=(",", ":")), file=output)


def check_interface_exists(interface: str) -> tuple[bool, dict[str, object]]:
    command = ["ip", "link", "show", interface]
    try:
        process = subprocess.run(command, capture_output=True, text=True)
    except FileNotFoundError as exc:  # pragma: no cover - platform specific
        return False, {
            "interface": interface,
            "command": command,
            "stdout": "",
            "stderr": str(exc),
            "returncode": 127,
        }

    return process.returncode == 0, {
        "interface": interface,
        "command": command,
        "stdout": process.stdout,
        "stderr": process.stderr,
        "returncode": process.returncode,
    }


def _mtime(path: Path) -> Optional[str]:
    try:
        stat = path.stat()
    except OSError:
        return None
    return datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc).isoformat()


def collect_file_mtimes(paths: Sequence[Path]) -> Dict[str, Optional[str]]:
    return {str(path): _mtime(path) for path in paths}


def _chown(path: Path) -> None:
    fallback_owner = "root"
    fallback_group = "root"
    try:
        shutil.chown(path, user=DEFAULT_FILE_OWNER, group=DEFAULT_FILE_GROUP)
    except LookupError as exc:  # pragma: no cover - defensive
        logger.debug("Could not chown %s to %s:%s: %s", path, DEFAULT_FILE_OWNER, DEFAULT_FILE_GROUP, exc)
        try:
            shutil.chown(path, user=fallback_owner, group=fallback_group)
        except Exception as fallback_exc:  # pragma: no cover - defensive
            logger.debug("Fallback chown to %s:%s failed for %s: %s", fallback_owner, fallback_group, path, fallback_exc)
    except (PermissionError, FileNotFoundError) as exc:  # pragma: no cover - defensive
        logger.debug("Could not chown %s to %s:%s: %s", path, DEFAULT_FILE_OWNER, DEFAULT_FILE_GROUP, exc)


def _should_skip_chown(path: Path) -> bool:
    return False


def set_default_permissions(path: Path, *, is_dir: bool | None = None) -> None:
    """Apply default mcbridge permissions to files and directories.

    Ownership defaults to ``MCBRIDGE_FILE_OWNER``/``MCBRIDGE_FILE_GROUP`` (falling
    back to ``admin``) and permissions default to 0664 for files and 0775 for
    directories. All operations are best-effort to avoid breaking callers in
    restricted environments.
    """

    expected_mode = DEFAULT_DIR_MODE if is_dir or (is_dir is None and path.is_dir()) else DEFAULT_FILE_MODE
    if _should_skip_chown(path):
        logger.debug("Skipping chown for %s (managed by privileged execution)", path)
    else:
        _chown(path)
    try:
        path.chmod(expected_mode)
    except OSError as exc:  # pragma: no cover - defensive for odd filesystems
        logger.debug("Could not chmod %s to %o: %s", path, expected_mode, exc)


def _snippet(text: str, limit: int = 2000) -> str:
    value = text or ""
    if len(value) <= limit:
        return value
    return f"{value[: limit - 3]}..."


def save_failed_validation_artifacts(
    *,
    candidate_contents: str,
    candidate_name: str,
    validate_command: Sequence[str],
    returncode: int | None,
    stdout: str,
    stderr: str,
    mirror_contents: str | None = None,
    mirror_name: str | None = None,
    failed_dir: Path = FAILED_GENERATED_DIR,
) -> Dict[str, str]:
    failed_dir.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    mirror_path: Path | None = None

    def _write(contents: str, name: str) -> Path:
        path = failed_dir / f"{timestamp}-{name}"
        path.write_text(contents, encoding="utf-8")
        return path

    failed_paths: Dict[str, str] = {}
    candidate_path = _write(candidate_contents, candidate_name)
    failed_paths["candidate"] = str(candidate_path)

    if mirror_contents is not None and mirror_name:
        mirror_path = _write(mirror_contents, mirror_name)
        failed_paths["mirror"] = str(mirror_path)

    metadata = {
        "validation_command": list(validate_command),
        "returncode": returncode,
        "stdout_snippet": _snippet(stdout),
        "stderr_snippet": _snippet(stderr),
        "candidate_path": str(candidate_path),
    }
    if mirror_contents is not None and mirror_name:
        metadata["mirror_path"] = failed_paths["mirror"]

    metadata_path = failed_dir / f"{timestamp}-metadata.json"
    metadata_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    set_default_permissions(failed_dir, is_dir=True)
    for candidate in (candidate_path, metadata_path):
        set_default_permissions(candidate)
    if mirror_path is not None:
        set_default_permissions(mirror_path)
    failed_paths["metadata"] = str(metadata_path)
    return failed_paths


def read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except OSError as exc:  # pragma: no cover - defensive for odd IO errors
        logger.debug("Could not read %s: %s", path, exc)
        return ""


def load_json(path: Path, *, default: Optional[Any] = None) -> Any:
    """Load a JSON file if present, returning a default fallback on error."""

    if default is None:
        fallback: Any = {}
    elif isinstance(default, Mapping):
        fallback = dict(default)
    elif isinstance(default, Sequence) and not isinstance(default, (str, bytes, bytearray)):
        fallback = list(default)
    else:
        fallback = default

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return fallback
    except json.JSONDecodeError as exc:
        logger.warning("Invalid JSON in %s: %s", path, exc)
        return fallback
    except OSError as exc:
        logger.warning("Could not read %s: %s", path, exc)
        return fallback


def load_dns_overrides_config(*, default: Optional[Any] = None) -> tuple[dict[str, Any], str]:
    """Load DNS overrides, preferring the canonical ``dns_overrides.json`` file.

    Returns a tuple of ``(payload, source_label)``. When the canonical file is
    missing, the function falls back to the legacy ``dnsmasq.json`` path while
    emitting a warning so callers can surface migration guidance.
    """

    canonical_exists = DNS_OVERRIDES_JSON.exists()
    raw_config = load_json(DNS_OVERRIDES_JSON, default=default or {})
    canonical_payload: dict[str, Any] = dict(raw_config) if isinstance(raw_config, Mapping) else {}

    if canonical_exists or canonical_payload:
        return canonical_payload, "dns_overrides.json"

    if DNSMASQ_JSON.exists():
        legacy_payload = load_json(DNSMASQ_JSON, default=default or {})
        if isinstance(legacy_payload, Mapping):
            logger.warning(
                "dns_overrides.json missing; falling back to legacy dnsmasq.json for DNS overrides."
            )
            return dict(legacy_payload), "dnsmasq.json"

    return canonical_payload, "dns_overrides.json"


def normalize_embedded_newlines(contents: str) -> str:
    """Convert literal escape sequences into real newlines.

    Some deployments accidentally persist configuration files with literal
    ``"\\n"`` sequences instead of real line breaks, which leaves everything on
    a single line and confuses parsers like ``dnsmasq``. This helper restores
    those escape sequences to actual newlines so downstream parsing works as
    intended. Existing newline characters are preserved.
    """

    if "\\n" not in contents and "\\r" not in contents:
        return contents

    normalized = contents.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\r", "\n")
    return normalized


def is_ip_address(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def format_dns_override_lines(hostnames: Sequence[str], target: str) -> list[str]:
    target_value = str(target or "").strip()
    cleaned_hostnames = [str(hostname or "").strip() for hostname in hostnames if str(hostname or "").strip()]

    if not cleaned_hostnames or not target_value:
        return []

    if is_ip_address(target_value):
        return [f"address=/{hostname}/{target_value}" for hostname in cleaned_hostnames]
    return [f"cname={hostname},{target_value}" for hostname in cleaned_hostnames]


def _read_lines(path: Path) -> List[str]:
    try:
        text = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return []
    except OSError as exc:  # pragma: no cover - defensive for odd IO errors
        logger.debug("Could not read %s: %s", path, exc)
        return []

    normalized = normalize_embedded_newlines(text)
    return normalized.splitlines()


def _extract_octet(address: str) -> Optional[int]:
    try:
        parts = address.strip().split(".")
        if len(parts) != 4:
            return None
        return int(parts[2])
    except (ValueError, IndexError):
        return None


def parse_hostapd(lines: Sequence[str]) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        key, _, value = stripped.partition("=")
        if key == "ssid":
            parsed["ssid"] = value
        elif key == "channel":
            try:
                parsed["channel"] = int(value)
            except ValueError:
                continue
        elif key in {"wpa_passphrase", "wpa_psk"}:
            parsed["password"] = value
        elif key == "ipaddr":
            octet = _extract_octet(value)
            if octet is not None:
                parsed.setdefault("subnet_octet", octet)
    return parsed


def parse_dnsmasq(lines: Sequence[str]) -> Dict[str, Any]:
    parsed: Dict[str, Any] = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.startswith("dhcp-range="):
            range_value = stripped.split("=", 1)[1].split(",", 1)[0]
            octet = _extract_octet(range_value)
            if octet is not None:
                parsed.setdefault("subnet_octet", octet)
        elif stripped.startswith("ssid="):
            parsed.setdefault("ssid", stripped.split("=", 1)[1])
    return parsed


def parse_dns_overrides(lines: Sequence[str]) -> Dict[str, Any]:
    target_hint: Optional[str] = None
    name_hint: Optional[str] = None
    redirect_hint: Optional[str] = None
    redirects: List[str] = []
    targets: List[str] = []

    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.startswith("#"):
            if stripped.lower().startswith("# target="):
                target_hint = stripped.split("=", 1)[1].strip()
            elif stripped.lower().startswith("# name="):
                name_hint = stripped.split("=", 1)[1].strip()
            elif stripped.lower().startswith("# redirect="):
                redirect_hint = stripped.split("=", 1)[1].strip()
            continue

        address_match = re.match(r"address=/([^/]+)/(.+)", stripped)
        cname_match = re.match(r"cname=([^,]+),(.+)", stripped)
        if address_match:
            hostname, target = address_match.groups()
        elif cname_match:
            hostname, target = cname_match.groups()
        else:
            continue

        hostname = hostname.strip()
        target = target.strip()
        if hostname and target:
            redirects.append(hostname)
            targets.append(target)

    unique_targets = list(dict.fromkeys(targets))
    primary_target = target_hint or (unique_targets[0] if unique_targets else "")
    target_conflict = bool(primary_target and any(entry != primary_target for entry in unique_targets))
    redirect_conflict = bool(redirects and any(entry != redirects[0] for entry in redirects))

    redirect_value = redirects[0] if redirects else (redirect_hint or "")

    return {
        "redirect": redirect_value,
        "redirect_conflict": redirect_conflict,
        "target": primary_target,
        "enabled": bool(primary_target and redirects),
        "target_conflict": target_conflict,
        "name": name_hint or None,
    }


def normalize_dns_override_payload(payload: Any, *, default_target: str | None = None) -> dict[str, Any]:
    if not isinstance(payload, Mapping):
        return {}

    redirect = str(payload.get("redirect") or "").strip()
    target = str(payload.get("target") or "").strip()
    enabled = bool(payload.get("enabled", True))
    name = payload.get("name")
    if name is not None:
        name = str(name)

    legacy_hijacks = payload.get("hijacks")
    if isinstance(legacy_hijacks, (list, tuple)):
        hijack_list = [str(entry or "").strip() for entry in legacy_hijacks if str(entry or "").strip()]
        unique_hijacks = list(dict.fromkeys(hijack_list))
        if unique_hijacks:
            if not redirect and len(unique_hijacks) == 1:
                redirect = unique_hijacks[0]
            elif len(unique_hijacks) > 1 and not redirect:
                raise ValueError(
                    "dns_overrides.json uses legacy 'hijacks' with multiple entries; convert to a single redirect/target pair."
                )
            elif redirect and any(entry != redirect for entry in unique_hijacks):
                raise ValueError(
                    "dns_overrides.json mixes 'hijacks' with a different redirect; update the file to use only redirect/target."
                )

    legacy_targets = payload.get("targets")
    if isinstance(legacy_targets, (list, tuple)):
        target_list = [str(entry or "").strip() for entry in legacy_targets if str(entry or "").strip()]
        unique_targets = list(dict.fromkeys(target_list))
        if unique_targets:
            if not target and len(unique_targets) == 1:
                target = unique_targets[0]
            elif len(unique_targets) > 1 and not target:
                raise ValueError(
                    "dns_overrides.json lists multiple targets; collapse to a single 'target' value in the new schema."
                )

    if redirect and not target and default_target:
        target = default_target

    result: dict[str, Any] = {"redirect": redirect, "target": target, "enabled": enabled}
    if name:
        result["name"] = name

    if not redirect and not target and not name:
        return {}
    return result


def extract_section_body(contents: str, start_marker: str, end_marker: str) -> Optional[str]:
    if not contents:
        return None

    lines = contents.splitlines()
    start_index: Optional[int] = None
    end_index: Optional[int] = None
    for index, line in enumerate(lines):
        if line.strip() == start_marker:
            start_index = index
            continue
        if start_index is not None and line.strip() == end_marker:
            end_index = index
            break

    if start_index is None or end_index is None or end_index <= start_index:
        return None

    body_lines = lines[start_index + 1 : end_index]
    while body_lines and not body_lines[0].strip():
        body_lines.pop(0)
    while body_lines and not body_lines[-1].strip():
        body_lines.pop()
    return "\n".join(body_lines)


def _format_section(start_marker: str, body: str, end_marker: str) -> str:
    cleaned_body = body.strip("\n")
    if cleaned_body:
        return f"{start_marker}\n\n{cleaned_body}\n{end_marker}"
    return f"{start_marker}\n{end_marker}"


def assemble_dnsmasq_config(ap_section_body: str, dnsmasq_section_body: str) -> str:
    ap_section = _format_section(MANAGE_AP_SECTION_START, ap_section_body, MANAGE_AP_SECTION_END).rstrip("\n")
    dns_section = _format_section(
        MANAGE_DNSMASQ_SECTION_START, dnsmasq_section_body, MANAGE_DNSMASQ_SECTION_END
    ).rstrip("\n")
    return f"{ap_section}\n\n{dns_section}\n"


def analyse_dnsmasq_layout(contents: str, *, overrides_path: Path = DNSMASQ_OVERRIDES_CONF) -> Dict[str, object]:
    lines = contents.splitlines()
    ap_sections = sum(1 for line in lines if line.strip() == MANAGE_AP_SECTION_START)
    dns_sections = sum(1 for line in lines if line.strip() == MANAGE_DNSMASQ_SECTION_START)
    dns_body = extract_section_body(contents, MANAGE_DNSMASQ_SECTION_START, MANAGE_DNSMASQ_SECTION_END) or ""
    include_line = f"conf-file={overrides_path}"

    inline_override_markers = ("# --- DNS overrides ---", "cname=", "address=/")
    inline_overrides = any(marker in dns_body for marker in inline_override_markers)
    stray_override_block = any(marker in contents for marker in inline_override_markers) and not inline_overrides
    include_present = include_line in contents
    overrides_present = inline_overrides or include_present

    return {
        "ap_sections": ap_sections,
        "dns_sections": dns_sections,
        "inline_overrides": inline_overrides or stray_override_block,
        "include_present": include_present,
        "overrides_present": overrides_present,
        "needs_cleanup": bool(ap_sections > 1 or dns_sections > 1 or stray_override_block or not overrides_present),
    }


def read_system_ap_config(
    *,
    hostapd_path: Path | None = None,
    hostapd_generated_path: Path | None = HOSTAPD_CONF,
    dnsmasq_path: Path = DNSMASQ_ACTIVE_CONF,
    include_sources: bool = False,
) -> Dict[str, Any] | tuple[Dict[str, Any], Dict[str, Any]]:
    active_hostapd_path = hostapd_path or HOSTAPD_ACTIVE_CONF
    hostapd_lines = _read_lines(active_hostapd_path)
    generated_lines: List[str] = []
    if hostapd_generated_path:
        generated_lines = _read_lines(hostapd_generated_path)

    parsed_active = parse_hostapd(hostapd_lines)
    parsed_generated = parse_hostapd(generated_lines)
    hostapd_config = parsed_active or parsed_generated

    dnsmasq_lines = _read_lines(dnsmasq_path)
    parsed = dict(hostapd_config)
    parsed.update({k: v for k, v in parse_dnsmasq(dnsmasq_lines).items() if k not in parsed})

    if include_sources:
        sources = {
            "hostapd": {
                "active_path": str(active_hostapd_path),
                "generated_path": str(hostapd_generated_path) if hostapd_generated_path else None,
                "active_matches_generated": (hostapd_lines == generated_lines) if hostapd_generated_path else None,
                "active_config": parsed_active,
                "generated_config": parsed_generated,
                "source": "active" if parsed_active else "generated",
                "description": "hostapd reads from the active_path; generated_path is mirrored for diagnostics/history.",
            },
            "dnsmasq": {"path": str(dnsmasq_path)},
        }
        return parsed, sources

    return parsed


def read_system_dns_config(
    *,
    dnsmasq_path: Path | None = None,
    dnsmasq_generated_path: Path | None = DNSMASQ_OVERRIDES_CONF,
    include_sources: bool = False,
) -> Dict[str, Any] | tuple[Dict[str, Any], Dict[str, Any]]:
    active_path = dnsmasq_path or DNSMASQ_ACTIVE_CONF
    generated_path = dnsmasq_generated_path if dnsmasq_generated_path != active_path else None

    active_lines = _read_lines(active_path)
    generated_lines: List[str] = []
    if generated_path:
        generated_lines = _read_lines(generated_path)

    parsed_active = parse_dns_overrides(active_lines)
    parsed_generated = parse_dns_overrides(generated_lines)
    dns_config = parsed_active or parsed_generated

    if include_sources:
        sources = {
            "dnsmasq": {
                "active_path": str(active_path),
                "generated_path": str(generated_path) if generated_path else None,
                "active_matches_generated": (parsed_active == parsed_generated) if generated_path else None,
                "active_config": parsed_active,
                "generated_config": parsed_generated,
                "source": "active" if parsed_active else "generated",
                "description": (
                    "dnsmasq reads from the active_path; generated_path mirrors the overrides block for diagnostics/history."
                ),
            }
        }
        return dns_config, sources

    return dns_config


def compare_configs(
    system_config: Mapping[str, Any], stored_config: Mapping[str, Any], *, fields: Iterable[str]
) -> List[Dict[str, Any]]:
    mismatches: List[Dict[str, Any]] = []
    for field in fields:
        system_value = system_config.get(field)
        stored_value = stored_config.get(field)

        if system_value == stored_value:
            continue
        mismatches.append({"field": field, "system": system_value, "stored": stored_value})
    return mismatches


def mismatch_summary(mismatches: Sequence[Mapping[str, Any]]) -> str:
    parts = [f"{entry.get('field')}: system={entry.get('system')} stored={entry.get('stored')}" for entry in mismatches]
    return "; ".join(parts)


def config_source_label(mismatches: Sequence[Mapping[str, Any]]) -> str:
    return "stored JSON" if not mismatches else "system"


def diff_text(current: str, candidate: str, *, fromfile: str, tofile: str) -> str:
    return "".join(
        difflib.unified_diff(
            current.splitlines(),
            candidate.splitlines(),
            fromfile=fromfile,
            tofile=tofile,
            lineterm="",
        )
    )


def ensure_parent(path: Path) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        set_default_permissions(path.parent, is_dir=True)
    except PermissionError:
        # In restricted environments we may not be able to create /etc paths; callers should handle downstream errors.
        logger.debug("Could not ensure directory for %s", path)


def save_json(path: Path, payload: MutableMapping[str, Any]) -> None:
    ensure_parent(path)
    try:
        with path.open("w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
            handle.write("\n")
        set_default_permissions(path)
        return
    except PermissionError:
        logger.debug("Falling back to privileged write for %s", path)

    try:
        from . import privileges
    except Exception as exc:  # pragma: no cover - defensive import path
        logger.debug("Privilege helpers unavailable for %s: %s", path, exc)
        raise

    payload_text = json.dumps(payload, indent=2) + "\n"
    privileges.sudo_write_file(
        path,
        payload_text,
        mode=DEFAULT_FILE_MODE,
        owner=DEFAULT_FILE_OWNER,
        group=DEFAULT_FILE_GROUP,
    )


def save_dns_overrides_config(payload: Mapping[str, Any], *, sync_legacy: bool = True) -> None:
    """Persist DNS overrides to the canonical JSON file and optionally mirror legacy storage."""

    canonical_payload = dict(payload)
    save_json(DNS_OVERRIDES_JSON, canonical_payload)

    if sync_legacy and DNSMASQ_JSON.exists():
        logger.warning("Updating legacy dnsmasq.json to mirror dns_overrides.json; legacy path is deprecated.")
        save_json(DNSMASQ_JSON, canonical_payload)


def _is_simple_value(value: Any) -> bool:
    return isinstance(value, (str, int, float, bool)) or value is None


def _compact_payload(payload: Mapping[str, Any]) -> Dict[str, Any]:
    compact: Dict[str, Any] = {}
    preferred_keys = ("status", "message", "source", "operation", "mismatch_summary")
    for key in preferred_keys:
        if key in payload:
            compact[key] = payload[key]

    if "details" in payload:
        compact["details"] = payload["details"]

    for key, value in payload.items():
        if key in compact:
            continue
        if _is_simple_value(value):
            compact[key] = value
        elif isinstance(value, list) and all(_is_simple_value(item) for item in value):
            compact[key] = value
    return compact


def response_payload(*sections: Mapping[str, Any] | None, verbose: bool = False) -> Dict[str, Any]:
    """Merge payload sections and optionally return a compact representation.

    When ``verbose`` is truthy, the merged payload is returned unchanged. In compact
    mode, only top-level status, message, and other simple context values are kept,
    suppressing detailed diff and validation structures unless debugging is enabled.
    """

    merged: Dict[str, Any] = {}
    for section in sections:
        if section:
            merged.update(section)

    if verbose:
        return merged
    return _compact_payload(merged)


def write_history_file(
    history_dir: Path,
    *,
    suffix: str,
    contents: str | bytes,
    binary: bool = False,
    retain: int = HISTORY_RETENTION,
) -> Path:
    """Write a timestamped history entry and prune older entries for the category.

    ``suffix`` represents the file category (e.g. ``ap.json``, ``dnsmasq.json``,
    ``hostapd.conf``). After writing the timestamped file, the function removes
    older files with the same suffix, keeping only the newest ``retain`` entries.
    """

    safe_suffix = suffix.lstrip(".")
    filename = f"{datetime.utcnow().strftime('%Y-%m-%dT%H-%M-%S')}.{safe_suffix}"
    history_path = history_dir / filename
    ensure_parent(history_path)
    set_default_permissions(history_dir, is_dir=True)

    try:
        if binary:
            data = contents if isinstance(contents, (bytes, bytearray)) else str(contents).encode("utf-8")
            history_path.write_bytes(data)
        else:
            history_path.write_text(str(contents), encoding="utf-8")
    except (PermissionError, FileNotFoundError):
        logger.debug("Falling back to privileged history write for %s", history_path)
        try:
            from . import privileges
        except Exception as exc:  # pragma: no cover - defensive import path
            logger.debug("Privilege helpers unavailable for %s: %s", history_path, exc)
            raise

        payload = contents if isinstance(contents, (bytes, bytearray)) else str(contents)
        privileges.sudo_write_file(
            history_path,
            payload,
            mode=DEFAULT_FILE_MODE,
            owner=DEFAULT_FILE_OWNER,
            group=DEFAULT_FILE_GROUP,
        )
    set_default_permissions(history_path)

    _prune_history(history_path, retain=retain)
    return history_path


def _prune_history(latest_path: Path, *, retain: int) -> None:
    try:
        suffix = "".join(latest_path.suffixes)
        if not suffix:
            return
        history_files = sorted(
            (path for path in latest_path.parent.glob(f"*{suffix}") if path.is_file()),
            key=lambda candidate: candidate.stat().st_mtime,
            reverse=True,
        )
    except OSError as exc:  # pragma: no cover - defensive for odd IO errors
        logger.debug("Could not inspect history for %s: %s", latest_path, exc)
        return

    for old_path in history_files[retain:]:
        try:
            old_path.unlink(missing_ok=True)
        except OSError as exc:  # pragma: no cover - defensive for odd IO errors
            logger.debug("Could not remove history entry %s: %s", old_path, exc)


def latest_history_entry(history_dir: Path, *, suffix: str) -> Optional[Path]:
    try:
        candidates = sorted(
            (candidate for candidate in history_dir.glob(f"*{suffix}") if candidate.is_file()),
            key=lambda path: path.stat().st_mtime,
            reverse=True,
        )
    except OSError as exc:  # pragma: no cover - defensive for odd IO errors
        logger.debug("Could not inspect history directory %s: %s", history_dir, exc)
        return None
    return candidates[0] if candidates else None


def restore_from_history(path: Path, history_dir: Path, *, suffix: Optional[str] = None) -> Optional[Path]:
    suffix_value = suffix or path.name
    last_good = latest_history_entry(history_dir, suffix=suffix_value)
    if not last_good:
        return None

    try:
        ensure_parent(path)
        shutil.copy2(last_good, path)
    except OSError as exc:  # pragma: no cover - defensive for odd IO errors
        logger.debug("Could not restore %s from %s: %s", path, last_good, exc)
        return None
    return last_good


def _normalize_timeout_stream(stream: object) -> str:
    if isinstance(stream, (bytes, bytearray)):
        try:
            return stream.decode("utf-8", errors="replace")
        except Exception:
            return str(stream)
    if stream is None:
        return ""
    return str(stream)


def service_status(service: str, *, timeout: float | None = None) -> Dict[str, object]:
    command = ["systemctl", "status", "--no-pager", service]
    try:
        process = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
    except FileNotFoundError as exc:  # pragma: no cover - systemctl may be absent in tests
        return {"command": command, "stdout": "", "stderr": str(exc), "returncode": 127}
    except subprocess.TimeoutExpired as exc:
        stdout = getattr(exc, "stdout", getattr(exc, "output", ""))
        stderr = getattr(exc, "stderr", "")
        return {
            "command": command,
            "stdout": _normalize_timeout_stream(stdout),
            "stderr": _normalize_timeout_stream(stderr),
            "returncode": None,
            "timeout": True,
            "timeout_seconds": timeout,
        }
    return {
        "command": command,
        "stdout": process.stdout,
        "stderr": process.stderr,
        "returncode": process.returncode,
    }


def reload_or_restart_service(service: str, *, timeout: float | None = None) -> Dict[str, object]:
    command = ["systemctl", "reload-or-restart", service]
    try:
        from . import privileges

        process = privileges.sudo_run(command, timeout=timeout)
    except FileNotFoundError as exc:  # pragma: no cover - systemctl may be absent in tests
        message = f"systemctl not available to reload-or-restart {service}: {exc}"
        logger.warning("%s", message)
        return {
            "service": service,
            "command": command,
            "stdout": "",
            "stderr": message,
            "returncode": 127,
            "success": False,
        }
    except subprocess.TimeoutExpired as exc:
        message = f"Timed out reloading or restarting {service} after {timeout}s"
        stdout = getattr(exc, "stdout", getattr(exc, "output", ""))
        stderr = getattr(exc, "stderr", message)
        logger.warning("%s", message)
        return {
            "service": service,
            "command": command,
            "stdout": _normalize_timeout_stream(stdout),
            "stderr": _normalize_timeout_stream(stderr),
            "returncode": None,
            "success": False,
            "timeout": True,
            "timeout_seconds": timeout,
        }

    success = process.returncode == 0
    if not success:
        logger.warning("Failed to reload-or-restart %s (exit %s)", service, process.returncode)
    return {
        "service": service,
        "command": command,
        "stdout": (process.stdout or "").strip(),
        "stderr": (process.stderr or "").strip(),
        "returncode": process.returncode,
        "success": success,
    }


def restart_service(service: str, *, timeout: float | None = None) -> Dict[str, object]:
    command = ["systemctl", "restart", service]
    try:
        from . import privileges

        process = privileges.sudo_run(command, timeout=timeout)
    except FileNotFoundError as exc:  # pragma: no cover - systemctl may be absent in tests
        message = f"systemctl not available to restart {service}: {exc}"
        logger.warning("%s", message)
        return {
            "service": service,
            "command": command,
            "stdout": "",
            "stderr": message,
            "returncode": 127,
            "success": False,
        }
    except subprocess.TimeoutExpired as exc:
        message = f"Timed out restarting {service} after {timeout}s"
        stdout = getattr(exc, "stdout", getattr(exc, "output", ""))
        stderr = getattr(exc, "stderr", message)
        logger.warning("%s", message)
        return {
            "service": service,
            "command": command,
            "stdout": _normalize_timeout_stream(stdout),
            "stderr": _normalize_timeout_stream(stderr),
            "returncode": None,
            "success": False,
            "timeout": True,
            "timeout_seconds": timeout,
        }

    success = process.returncode == 0
    if not success:
        logger.warning("Failed to restart %s (exit %s)", service, process.returncode)
    return {
        "service": service,
        "command": command,
        "stdout": (process.stdout or "").strip(),
        "stderr": (process.stderr or "").strip(),
        "returncode": process.returncode,
        "success": success,
    }


__all__ = [
    "AP_JSON",
    "check_interface_exists",
    "collect_file_mtimes",
    "CONFIG_HISTORY_DIR",
    "DNSMASQ_JSON",
    "HOSTAPD_CONF",
    "HOSTAPD_ACTIVE_CONF",
    "DNSMASQ_ACTIVE_CONF",
    "DNSMASQ_CONF",
    "DNSMASQ_OVERRIDES_CONF",
    "DNS_OVERRIDES_JSON",
    "compare_configs",
    "config_source_label",
    "assemble_dnsmasq_config",
    "extract_section_body",
    "load_json",
    "load_dns_overrides_config",
    "mismatch_summary",
    "MANAGE_AP_SECTION_END",
    "MANAGE_AP_SECTION_START",
    "MANAGE_DNSMASQ_SECTION_END",
    "MANAGE_DNSMASQ_SECTION_START",
    "save_dns_overrides_config",
    "parse_dns_overrides",
    "parse_dnsmasq",
    "parse_hostapd",
    "read_system_ap_config",
    "read_system_dns_config",
    "save_json",
    "set_default_permissions",
    "write_history_file",
    "ensure_parent",
    "save_failed_validation_artifacts",
    "HISTORY_RETENTION",
    "FAILED_GENERATED_DIR",
    "GENERATED_HISTORY_DIR",
    "diff_text",
    "latest_history_entry",
    "read_text",
    "restore_from_history",
    "service_status",
    "reload_or_restart_service",
    "restart_service",
    "format_dns_override_lines",
    "is_ip_address",
    "analyse_dnsmasq_layout",
    "response_payload",
    "normalize_dns_override_payload",
    "DEFAULT_DIR_MODE",
    "DEFAULT_FILE_MODE",
    "DEFAULT_FILE_OWNER",
    "DEFAULT_FILE_GROUP",
]
