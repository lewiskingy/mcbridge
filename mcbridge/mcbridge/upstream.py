"""Persistence helpers for upstream Wi-Fi network profiles."""

from __future__ import annotations

import hashlib
import logging
import os
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

from .agent import AgentProcessResult
from .common import load_json, response_payload, save_json
from . import privileges
from .paths import CONFIG_DIR

UPSTREAM_NETWORKS_JSON = CONFIG_DIR / "upstream_networks.json"
LEGACY_UPSTREAM_JSON = CONFIG_DIR / "upstream_wifi.json"
UPSTREAM_INTERFACE = os.environ.get("MCBRIDGE_UPSTREAM_INTERFACE", "wlan0")
UPSTREAM_WPA_SUPPLICANT_CONF = Path(
    os.environ.get("MCBRIDGE_UPSTREAM_WPA_CONF", f"/etc/wpa_supplicant/wpa_supplicant-{UPSTREAM_INTERFACE}.conf")
)
LOG = logging.getLogger(__name__)
WIFI_TYPES = {"wifi", "802-11-wireless", "802.11-wireless", "wireless"}


@dataclass
class UpstreamProfile:
    ssid: str
    password: str
    priority: int
    security: str

    @property
    def has_password(self) -> bool:
        return bool(self.password)


def _profile_key(ssid: str) -> str:
    return (ssid or "").strip().lower()


def _validate_ssid(ssid: Any) -> str:
    if not isinstance(ssid, str):
        raise ValueError("ssid is required.")
    cleaned = ssid.strip()
    if not cleaned:
        raise ValueError("ssid is required.")
    return cleaned


def _validate_priority(priority: Any) -> int:
    if priority is None:
        raise ValueError("priority is required.")
    if isinstance(priority, bool):
        raise ValueError("priority must be a positive integer.")
    try:
        parsed = int(priority)
    except (TypeError, ValueError) as exc:
        raise ValueError("priority must be a positive integer.") from exc
    if parsed <= 0:
        raise ValueError("priority must be a positive integer.")
    return parsed


def _validate_security(security: Any) -> str:
    if security is None:
        return "open"
    if not isinstance(security, str):
        raise ValueError("security must be a string.")
    cleaned = security.strip()
    if not cleaned:
        raise ValueError("security is required.")
    return cleaned


def _normalize_password(password: Any) -> str:
    if password is None:
        return ""
    if not isinstance(password, str):
        raise ValueError("password must be a string.")
    return password


def _is_hashed_psk(candidate: str) -> bool:
    return bool(re.fullmatch(r"[0-9a-fA-F]{64}", candidate or ""))


def _derive_psk(ssid: str, password: str) -> str:
    return hashlib.pbkdf2_hmac("sha1", password.encode("utf-8"), ssid.encode("utf-8"), 4096, dklen=32).hex()


def _prepare_psk(ssid: str, security: str, password: str, *, require: bool) -> str:
    cleaned_password = _normalize_password(password)
    if not _requires_password(security):
        return ""
    if not cleaned_password:
        if require:
            raise ValueError("password is required for secured networks.")
        return ""
    if _is_hashed_psk(cleaned_password):
        return cleaned_password
    return _derive_psk(ssid, cleaned_password)


def _requires_password(security: str) -> bool:
    return _profile_key(security) not in {"open", "none"}


def _load_raw(path: Path) -> Mapping[str, Any]:
    return load_json(path, default={})


def _load_profiles(path: Path | None = None, warnings: list[str] | None = None) -> tuple[list[UpstreamProfile], Path]:
    storage_path = path or UPSTREAM_NETWORKS_JSON
    raw_config = _load_raw(storage_path)

    if not raw_config and not storage_path.exists() and path is None:
        legacy = _load_raw(LEGACY_UPSTREAM_JSON)
        if isinstance(legacy, Mapping) and legacy:
            raw_config = legacy

    profiles: list[UpstreamProfile] = []
    if isinstance(raw_config, Mapping):
        for entry in raw_config.get("profiles", []) or []:
            if not isinstance(entry, Mapping):
                continue
            try:
                ssid = _validate_ssid(entry.get("ssid"))
                priority = _validate_priority(entry.get("priority"))
                security = _validate_security(entry.get("security"))
                password = _prepare_psk(ssid, security, entry.get("password", ""), require=False)
                if _requires_password(security) and not password:
                    if warnings is not None:
                        warnings.append(f"password missing for secured SSID {ssid}")
                    continue
            except ValueError as exc:
                if warnings is not None:
                    warnings.append(str(exc))
                continue
            profiles.append(
                UpstreamProfile(
                    ssid=ssid,
                    password=password,
                    priority=priority,
                    security=security,
                )
            )
    return profiles, storage_path


def load_profiles(path: Path | None = None, *, warnings: list[str] | None = None) -> list[UpstreamProfile]:
    profiles, storage_path = _load_profiles(path, warnings)
    if not profiles and path is None and storage_path.exists():
        return []
    return _sorted_profiles(profiles)


def _save_profiles(profiles: Sequence[UpstreamProfile], path: Path) -> None:
    payload: MutableMapping[str, Any] = {
        "profiles": [
            {
                "ssid": profile.ssid,
                "password": profile.password,
                "priority": profile.priority,
                "security": profile.security,
            }
            for profile in profiles
        ]
    }
    save_json(path, payload)


def _sorted_profiles(profiles: Iterable[UpstreamProfile]) -> list[UpstreamProfile]:
    return sorted(profiles, key=lambda profile: (-profile.priority, profile.ssid.lower()))


def _annotate_profiles(profiles: Sequence[UpstreamProfile]) -> list[dict[str, object]]:
    annotated: list[dict[str, object]] = []
    for profile in profiles:
        annotated.append(
            {
                "ssid": profile.ssid,
                "priority": profile.priority,
                "security": profile.security,
                "has_password": profile.has_password,
            }
        )
    return annotated


def _inject_saved_passwords(
    system_profiles: Sequence[DiscoveredProfile], stored_profiles: Sequence[UpstreamProfile]
) -> list[DiscoveredProfile]:
    stored_map = {_profile_key(profile.ssid): profile for profile in stored_profiles}
    updated: list[DiscoveredProfile] = []
    for profile in system_profiles:
        match = stored_map.get(_profile_key(profile.ssid))
        if match and _requires_password(profile.security) and match.password:
            profile.psk = match.password
            profile.password = profile.password or ""
            profile.password_missing = False
        updated.append(profile)
    return updated


def list_profiles(path: Path | None = None) -> list[dict[str, object]]:
    profiles, storage_path = _load_profiles(path)
    if not profiles and path is None and storage_path.exists():
        return []
    return _annotate_profiles(_sorted_profiles(profiles))


def add_profile(
    *, ssid: str, password: str, priority: int, security: str, path: Path | None = None
) -> list[dict[str, object]]:
    cleaned_ssid = _validate_ssid(ssid)
    cleaned_security = _validate_security(security)
    cleaned_priority = _validate_priority(priority)
    cleaned_password = _prepare_psk(cleaned_ssid, cleaned_security, password, require=True)

    profiles, storage_path = _load_profiles(path)
    key = _profile_key(cleaned_ssid)
    if any(_profile_key(profile.ssid) == key for profile in profiles):
        raise ValueError(f"SSID {cleaned_ssid} already exists.")

    profiles.append(
        UpstreamProfile(
            ssid=cleaned_ssid,
            password=cleaned_password,
            priority=cleaned_priority,
            security=cleaned_security,
        )
    )

    sorted_profiles = _sorted_profiles(profiles)
    _save_profiles(sorted_profiles, storage_path)
    return _annotate_profiles(sorted_profiles)


def update_profile(
    *,
    ssid: str,
    password: str | None = None,
    priority: int | None = None,
    security: str | None = None,
    path: Path | None = None,
) -> list[dict[str, object]]:
    cleaned_ssid = _validate_ssid(ssid)
    profiles, storage_path = _load_profiles(path)
    key = _profile_key(cleaned_ssid)
    existing = next((profile for profile in profiles if _profile_key(profile.ssid) == key), None)
    if existing is None:
        raise ValueError(f"SSID {cleaned_ssid} was not found.")

    if priority is None and security is None and password is None:
        raise ValueError("No fields to update.")

    if priority is not None:
        existing.priority = _validate_priority(priority)
    if security is not None:
        existing.security = _validate_security(security)
    if password is not None:
        existing.password = _prepare_psk(existing.ssid, existing.security, password, require=True)

    if _requires_password(existing.security) and not existing.password:
        raise ValueError("password is required for secured networks.")

    sorted_profiles = _sorted_profiles(profiles)
    _save_profiles(sorted_profiles, storage_path)
    return _annotate_profiles(sorted_profiles)


def remove_profile(*, ssid: str, path: Path | None = None) -> list[dict[str, object]]:
    cleaned_ssid = _validate_ssid(ssid)
    profiles, storage_path = _load_profiles(path)
    key = _profile_key(cleaned_ssid)
    remaining = [profile for profile in profiles if _profile_key(profile.ssid) != key]

    if len(remaining) == len(profiles):
        raise ValueError(f"SSID {cleaned_ssid} was not found.")

    sorted_profiles = _sorted_profiles(remaining)
    _save_profiles(sorted_profiles, storage_path)
    return _annotate_profiles(sorted_profiles)


@dataclass
class DiscoveredProfile:
    ssid: str
    priority: int
    security: str
    password: str = ""
    psk: str | None = None
    source: str | None = None
    password_missing: bool = False

    @property
    def has_password(self) -> bool:
        return not self.password_missing and bool(self.password or self.psk)

    @property
    def prepared_password(self) -> str:
        return (self.psk or self.password) or ""


def _run_nmcli(args: Sequence[str]) -> subprocess.CompletedProcess[str] | AgentProcessResult:
    return privileges.sudo_run(["nmcli", *args], check=False, text=True)


def _parse_priority(value: Any, *, fallback: int = 1) -> int:
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return fallback
    return parsed if parsed > 0 else fallback


def _security_from_keymgmt(key_mgmt: str | None) -> str:
    normalized = (key_mgmt or "").strip().lower()
    if not normalized or normalized == "none":
        return "open"
    if "sae" in normalized or "owe" in normalized:
        return "wpa3"
    return "wpa2"


def _parse_wpa_supplicant(path: Path) -> tuple[list[DiscoveredProfile], list[str], dict[str, object]]:
    warnings: list[str] = []
    details: dict[str, object] = {"path": str(path), "found": path.exists()}
    try:
        contents = path.read_text(encoding="utf-8")
    except FileNotFoundError:
        return [], warnings, details
    except OSError as exc:
        warnings.append(f"Unable to read {path}: {exc}")
        details["error"] = str(exc)
        return [], warnings, details

    networks: list[DiscoveredProfile] = []
    current: dict[str, str] = {}
    in_network = False
    for raw_line in contents.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("network={"):
            current = {}
            in_network = True
            continue
        if in_network and line == "}":
            ssid = current.get("ssid")
            if ssid:
                try:
                    cleaned_ssid = _validate_ssid(ssid)
                except ValueError as exc:
                    warnings.append(str(exc))
                    current = {}
                    in_network = False
                    continue
                priority = _parse_priority(current.get("priority"), fallback=1)
                key_mgmt = current.get("key_mgmt")
                security = _security_from_keymgmt(key_mgmt)
                raw_password = current.get("psk", "")
                prepared_psk = _prepare_psk(cleaned_ssid, security, raw_password, require=False)
                password_missing = not prepared_psk and _requires_password(security)
                stored_password = "" if _is_hashed_psk(raw_password) else prepared_psk
                networks.append(
                    DiscoveredProfile(
                        ssid=cleaned_ssid,
                        priority=priority,
                        security=security,
                        password=stored_password,
                        psk=prepared_psk,
                        source="wpa_supplicant",
                        password_missing=password_missing,
                    )
                )
            current = {}
            in_network = False
            continue
        if in_network and "=" in line:
            key, value = line.split("=", 1)
            current[key.strip()] = re.sub(r'^"|"$', "", value.strip())

    details["count"] = len(networks)
    return _sorted_profiles(networks), warnings, details


def _parse_nmcli_wifi() -> tuple[list[DiscoveredProfile], list[str], dict[str, object]]:
    warnings: list[str] = []
    details: dict[str, object] = {"available": False}
    try:
        list_result = _run_nmcli(["-t", "-f", "NAME,TYPE", "connection", "show"])
    except (FileNotFoundError, PermissionError) as exc:
        warnings.append(f"nmcli unavailable; unable to inspect NetworkManager profiles: {exc}")
        details["error"] = str(exc)
        return [], warnings, details

    details["available"] = True
    if list_result.returncode != 0:
        message = list_result.stderr.strip() or "nmcli connection list failed"
        warnings.append(message)
        details["error"] = message
        details["returncode"] = list_result.returncode
        return [], warnings, details

    wifi_connections = []
    for line in list_result.stdout.splitlines():
        parts = line.split(":", 1)
        if len(parts) != 2:
            continue
        name, conn_type = parts
        conn_type_lower = (conn_type or "").strip().lower()
        if conn_type_lower in WIFI_TYPES:
            wifi_connections.append(name.strip())

    profiles: list[DiscoveredProfile] = []
    for connection in wifi_connections:
        detail_result = _run_nmcli(
            [
                "-g",
                "802-11-wireless.ssid,802-11-wireless-security.key-mgmt,connection.autoconnect-priority,802-11-wireless-security.psk",
                "connection",
                "show",
                connection,
            ]
        )
        if detail_result.returncode != 0:
            warnings.append(f"nmcli failed for {connection}: {detail_result.stderr.strip() or 'unknown error'}")
            continue
        ssid, key_mgmt, priority, password = ((detail_result.stdout.splitlines() + ["", "", "", ""])[:4])
        cleaned_ssid = ssid or connection
        security = _security_from_keymgmt(key_mgmt)
        prepared_psk = _prepare_psk(cleaned_ssid, security, password, require=False)
        password_missing = not prepared_psk and _requires_password(security)
        stored_password = "" if _is_hashed_psk(password) else prepared_psk
        try:
            validated_ssid = _validate_ssid(cleaned_ssid)
        except ValueError as exc:
            warnings.append(str(exc))
            continue
        profiles.append(
            DiscoveredProfile(
                ssid=validated_ssid,
                priority=_parse_priority(priority, fallback=1),
                security=security,
                password=stored_password,
                psk=prepared_psk,
                source="nmcli",
                password_missing=password_missing,
            )
        )

    details["count"] = len(profiles)
    return _sorted_profiles(profiles), warnings, details


def _key_mgmt_for_security(security: str) -> str:
    normalized = _profile_key(security)
    if normalized in {"wpa3", "sae"}:
        return "sae"
    if _requires_password(security):
        return "wpa-psk"
    return "none"


def _nmcli_stdout(
    result: subprocess.CompletedProcess[str] | AgentProcessResult | None,
) -> str:
    if result is None:
        return ""
    return (result.stdout or "").strip()


def _nmcli_stderr(
    result: subprocess.CompletedProcess[str] | AgentProcessResult | None,
) -> str:
    if result is None:
        return ""
    return (result.stderr or "").strip()


def _parse_nmcli_line(line: str, *, expected: int) -> list[str]:
    parts: list[str] = []
    current: list[str] = []
    escape = False
    for char in line:
        if escape:
            current.append(char)
            escape = False
            continue
        if char == "\\":
            escape = True
            continue
        if char == ":" and len(parts) < expected - 1:
            parts.append("".join(current))
            current = []
            continue
        current.append(char)
    parts.append("".join(current))
    if len(parts) < expected:
        parts.extend([""] * (expected - len(parts)))
    return parts[:expected]


def _scan_nmcli_wifi(
    interface: str, active_ssid: str | None
) -> tuple[dict[str, dict[str, object]], list[str], dict[str, object]]:
    warnings: list[str] = []
    details: dict[str, object] = {"available": False, "interface": interface}
    try:
        result = _run_nmcli(
            ["-t", "-f", "SSID,SIGNAL,IN-USE,SECURITY,DEVICE", "dev", "wifi", "list", "ifname", interface]
        )
    except (FileNotFoundError, PermissionError) as exc:
        warnings.append(f"nmcli unavailable; unable to scan Wi-Fi: {exc}")
        details["error"] = str(exc)
        return {}, warnings, details

    details["available"] = True
    if result.returncode != 0:
        message = _nmcli_stderr(result) or "nmcli wifi scan failed"
        warnings.append(message)
        details["error"] = message
        details["returncode"] = result.returncode
        return {}, warnings, details

    scan_map: dict[str, dict[str, object]] = {}
    active_key = _profile_key(active_ssid or "")
    for line in _nmcli_stdout(result).splitlines():
        ssid, signal, in_use, security, device = _parse_nmcli_line(line, expected=5)
        if not ssid:
            continue
        if device and device != interface:
            continue
        key = _profile_key(ssid)
        if not key:
            continue
        try:
            signal_value = int(signal.strip())
        except (TypeError, ValueError):
            signal_value = None
        active = in_use.strip() == "*" or (active_key and key == active_key)
        scan_map[key] = {
            "ssid": ssid,
            "available": True,
            "signal_percent": signal_value,
            "active": active,
            "security": security.strip(),
        }

    details["count"] = len(scan_map)
    return scan_map, warnings, details


def _list_nmcli_wifi_connections() -> tuple[dict[str, tuple[str, str]], list[str]]:
    errors: list[str] = []
    result = _run_nmcli(["-t", "-f", "NAME,TYPE", "connection", "show"])
    if result.returncode != 0:
        errors.append(_nmcli_stderr(result) or "nmcli connection show failed")
        return {}, errors

    ssid_map: dict[str, tuple[str, str]] = {}
    for line in _nmcli_stdout(result).splitlines():
        name, conn_type = (line.split(":", 1) + [""])[:2]
        if not name:
            continue
        conn_type_lower = conn_type.strip().lower()
        if conn_type_lower not in WIFI_TYPES:
            continue
        detail = _run_nmcli(["-g", "802-11-wireless.ssid", "connection", "show", name])
        if detail.returncode != 0:
            errors.append(_nmcli_stderr(detail) or f"nmcli connection show failed for {name}")
            continue
        ssid = _nmcli_stdout(detail) or name
        ssid_map[_profile_key(ssid)] = (name, ssid)
    return ssid_map, errors


def _active_upstream_details(interface: str) -> tuple[str | None, str | None, list[str]]:
    errors: list[str] = []
    try:
        result = _run_nmcli(["-t", "-f", "DEVICE,TYPE,STATE,CONNECTION", "device", "status"])
    except Exception as exc:
        errors.append(f"nmcli device status failed: {exc}")
        return None, None, errors
    if result.returncode != 0:
        errors.append(_nmcli_stderr(result) or "nmcli device status failed")
        return None, None, errors

    active_connection = None
    for line in _nmcli_stdout(result).splitlines():
        device, conn_type, state, connection = (line.split(":", 3) + ["", "", "", ""])[:4]
        if device.strip() != interface:
            continue
        if conn_type.strip().lower() not in WIFI_TYPES:
            continue
        if state.strip().lower() not in {"connected", "connecting", "activated"}:
            continue
        active_connection = connection.strip() or None
        break

    if not active_connection:
        return None, None, errors

    try:
        detail = _run_nmcli(["-g", "802-11-wireless.ssid", "connection", "show", active_connection])
    except Exception as exc:
        errors.append(f"nmcli connection show failed for {active_connection}: {exc}")
        return None, active_connection, errors
    if detail.returncode != 0:
        errors.append(_nmcli_stderr(detail) or f"nmcli connection show failed for {active_connection}")
        return None, active_connection, errors
    ssid = _nmcli_stdout(detail) or active_connection
    return ssid, active_connection, errors


def _active_upstream_connection(interface: str) -> tuple[str | None, list[str]]:
    ssid, _, errors = _active_upstream_details(interface)
    return ssid, errors


@dataclass
class UpstreamResult:
    payload: Mapping[str, Any]
    exit_code: int


def _safe_nmcli(
    args: Sequence[str], *, errors: list[str], context: str
) -> subprocess.CompletedProcess[str] | AgentProcessResult | None:
    try:
        return _run_nmcli(args)
    except Exception as exc:
        errors.append(f"{context}: {exc}")
        return None


def apply_upstream(
    path: Path | None = None,
    *,
    interface: str | None = None,
    prune_missing: bool = False,
) -> UpstreamResult:
    warnings: list[str] = []
    profiles = load_profiles(path, warnings=warnings)
    if not profiles:
        payload = {
            "status": "error",
            "exit_code": 2,
            "message": "No upstream Wi-Fi profiles saved.",
            "warnings": warnings,
        }
        return UpstreamResult(response_payload(payload, verbose=True), 2)

    interface_name = interface or UPSTREAM_INTERFACE
    changes: list[dict[str, object]] = []
    errors: list[str] = []
    try:
        connection_map, list_errors = _list_nmcli_wifi_connections()
    except Exception as exc:
        payload = {
            "status": "error",
            "exit_code": 3,
            "message": f"Unable to query NetworkManager: {exc}",
            "warnings": warnings,
        }
        return UpstreamResult(response_payload(payload, verbose=True), 3)

    errors.extend(list_errors)

    sorted_profiles = _sorted_profiles(profiles)
    stored_keys = {_profile_key(profile.ssid) for profile in sorted_profiles}
    all_connection_names = {connection_name for connection_name, _ in connection_map.values()}
    saved_connection_names = {
        connection_name for key, (connection_name, _) in connection_map.items() if key in stored_keys
    }

    active_ssid, active_connection_name, active_errors = _active_upstream_details(interface_name)
    errors.extend(active_errors)
    active_key = _profile_key(active_ssid or "")
    prune_allowed = prune_missing and not active_errors
    if prune_missing and active_errors:
        warnings.append("Skipping prune_missing because active connection could not be determined.")

    if prune_allowed:
        for key, (connection_name, ssid) in sorted(connection_map.items(), key=lambda item: item[0]):
            if key in stored_keys:
                continue
            if connection_name in saved_connection_names:
                continue
            if active_connection_name and connection_name == active_connection_name:
                changes.append(
                    {
                        "ssid": ssid,
                        "action": "prune_skipped_active",
                        "connection": connection_name,
                    }
                )
                continue
            if active_key and key == active_key:
                changes.append(
                    {
                        "ssid": ssid,
                        "action": "prune_skipped_active",
                        "connection": connection_name,
                    }
                )
                continue
            try:
                delete_result = _run_nmcli(["connection", "delete", connection_name])
            except Exception as exc:
                errors.append(f"Failed to delete {connection_name}: {exc}")
                continue
            if delete_result.returncode != 0:
                errors.append(_nmcli_stderr(delete_result) or f"Failed to delete {connection_name}")
                continue
            changes.append({"ssid": ssid, "action": "deleted", "connection": connection_name})

    for profile in sorted_profiles:
        key = _profile_key(profile.ssid)
        connection_name = connection_map.get(key, (profile.ssid, profile.ssid))[0]
        created = connection_name not in all_connection_names
        if created:
            result = _safe_nmcli(
                [
                    "connection",
                    "add",
                    "type",
                    "wifi",
                    "ifname",
                    interface_name,
                    "con-name",
                    connection_name,
                    "ssid",
                    profile.ssid,
                ],
                errors=errors,
                context=f"Failed to create connection for {profile.ssid}",
            )
            if result is None:
                continue
            if result.returncode != 0:
                errors.append(_nmcli_stderr(result) or f"Failed to create connection for {profile.ssid}")
                continue
            changes.append({"ssid": profile.ssid, "action": "created", "connection": connection_name})
        elif connection_name != profile.ssid:
            rename = _safe_nmcli(
                ["connection", "modify", connection_name, "connection.id", profile.ssid],
                errors=errors,
                context=f"Failed to rename {connection_name} to {profile.ssid}",
            )
            if rename is not None and rename.returncode == 0:
                changes.append(
                    {
                        "ssid": profile.ssid,
                        "action": "renamed",
                        "connection": profile.ssid,
                        "previous": connection_name,
                    }
                )
                connection_name = profile.ssid
            else:
                if rename is not None:
                    errors.append(_nmcli_stderr(rename) or f"Failed to rename {connection_name} to {profile.ssid}")

        key_mgmt = _key_mgmt_for_security(profile.security)
        modify_args = [
            "connection",
            "modify",
            connection_name,
            "connection.autoconnect",
            "yes",
            "connection.autoconnect-priority",
            str(profile.priority),
            "connection.interface-name",
            interface_name,
            "802-11-wireless.ssid",
            profile.ssid,
            "802-11-wireless-security.key-mgmt",
            key_mgmt,
        ]
        if _requires_password(profile.security):
            modify_args += [
                "802-11-wireless-security.psk",
                profile.password,
                "802-11-wireless-security.psk-flags",
                "0",
            ]
        else:
            modify_args += ["802-11-wireless-security.psk", ""]
        modify = _safe_nmcli(modify_args, errors=errors, context=f"Failed to update {profile.ssid}")
        if modify is None:
            continue
        if modify.returncode != 0:
            errors.append(_nmcli_stderr(modify) or f"Failed to update {profile.ssid}")
            continue
        if not created:
            changes.append({"ssid": profile.ssid, "action": "updated", "connection": connection_name})

    preferred = sorted_profiles[0]
    connect_result = _safe_nmcli(
        ["connection", "up", preferred.ssid, "ifname", interface_name],
        errors=errors,
        context=f"Failed to activate {preferred.ssid}",
    )
    if connect_result is None:
        pass
    elif connect_result.returncode != 0:
        errors.append(_nmcli_stderr(connect_result) or f"Failed to activate {preferred.ssid}")
    else:
        changes.append({"ssid": preferred.ssid, "action": "activated", "connection": preferred.ssid})

    active_ssid, active_errors = _active_upstream_connection(interface_name)
    errors.extend(active_errors)

    status = "ok"
    exit_code = 0
    if errors:
        status = "error"
        exit_code = 3
    elif warnings:
        status = "warning"
        exit_code = 0

    payload = {
        "status": status,
        "exit_code": exit_code,
        "interface": interface_name,
        "active_ssid": active_ssid,
        "prune_missing": prune_missing,
        "changes": changes,
        "warnings": warnings,
        "errors": errors,
    }
    if errors:
        payload["message"] = "; ".join(errors)
    return UpstreamResult(response_payload(payload, verbose=True), exit_code)


def activate_upstream(ssid: str, *, interface: str | None = None) -> UpstreamResult:
    cleaned_ssid = _validate_ssid(ssid)
    interface_name = interface or UPSTREAM_INTERFACE
    warnings: list[str] = []
    errors: list[str] = []

    try:
        connection_map, list_errors = _list_nmcli_wifi_connections()
    except Exception as exc:
        payload = {
            "status": "error",
            "exit_code": 3,
            "message": f"Unable to query NetworkManager: {exc}",
            "warnings": warnings,
        }
        return UpstreamResult(response_payload(payload, verbose=True), 3)

    errors.extend(list_errors)

    connection_name = connection_map.get(_profile_key(cleaned_ssid), (cleaned_ssid, cleaned_ssid))[0]
    connect_result = _safe_nmcli(
        ["connection", "up", connection_name, "ifname", interface_name],
        errors=errors,
        context=f"Failed to activate {cleaned_ssid}",
    )
    if connect_result is not None and connect_result.returncode != 0:
        errors.append(_nmcli_stderr(connect_result) or f"Failed to activate {cleaned_ssid}")

    active_ssid, active_errors = _active_upstream_connection(interface_name)
    errors.extend(active_errors)

    status = "ok"
    exit_code = 0
    if errors:
        status = "error"
        exit_code = 3

    payload = {
        "status": status,
        "exit_code": exit_code,
        "interface": interface_name,
        "ssid": cleaned_ssid,
        "connection": connection_name,
        "active_ssid": active_ssid,
        "warnings": warnings,
        "errors": errors,
    }
    if errors:
        payload["message"] = "; ".join(errors)
    return UpstreamResult(response_payload(payload, verbose=True), exit_code)


def forget_system_profile(ssid: str, *, interface: str | None = None) -> UpstreamResult:
    cleaned_ssid = _validate_ssid(ssid)
    interface_name = interface or UPSTREAM_INTERFACE
    warnings: list[str] = []
    errors: list[str] = []

    try:
        connection_map, list_errors = _list_nmcli_wifi_connections()
    except Exception as exc:
        payload = {
            "status": "error",
            "exit_code": 3,
            "message": f"Unable to query NetworkManager: {exc}",
            "warnings": warnings,
        }
        return UpstreamResult(response_payload(payload, verbose=True), 3)

    errors.extend(list_errors)

    active_ssid, active_connection_name, active_errors = _active_upstream_details(interface_name)
    errors.extend(active_errors)
    if active_errors:
        payload = {
            "status": "error",
            "exit_code": 3,
            "message": "Unable to determine the active upstream connection; refusing to forget a system profile.",
            "interface": interface_name,
            "errors": errors,
        }
        return UpstreamResult(response_payload(payload, verbose=True), 3)

    target_key = _profile_key(cleaned_ssid)
    connection_name, resolved_ssid = connection_map.get(target_key, ("", ""))
    if not connection_name:
        payload = {
            "status": "error",
            "exit_code": 2,
            "message": f"SSID {cleaned_ssid} was not found.",
            "interface": interface_name,
            "errors": errors,
        }
        return UpstreamResult(response_payload(payload, verbose=True), 2)

    active_key = _profile_key(active_ssid or "")
    if (
        (active_connection_name and connection_name == active_connection_name)
        or (active_connection_name and _profile_key(active_connection_name) == target_key)
        or (active_key and active_key == target_key)
    ):
        payload = {
            "status": "error",
            "exit_code": 2,
            "message": f"Cannot forget active upstream connection {cleaned_ssid}.",
            "interface": interface_name,
            "connection": connection_name,
            "errors": errors,
        }
        return UpstreamResult(response_payload(payload, verbose=True), 2)

    delete_result = _safe_nmcli(
        ["connection", "delete", connection_name],
        errors=errors,
        context=f"Failed to delete {cleaned_ssid}",
    )
    if delete_result is None or delete_result.returncode != 0:
        if delete_result is not None and delete_result.returncode != 0:
            errors.append(_nmcli_stderr(delete_result) or f"Failed to delete {cleaned_ssid}")

    status = "ok"
    exit_code = 0
    if errors:
        status = "error"
        exit_code = 3

    payload = {
        "status": status,
        "exit_code": exit_code,
        "interface": interface_name,
        "ssid": resolved_ssid or cleaned_ssid,
        "connection": connection_name,
        "warnings": warnings,
        "errors": errors,
    }
    if errors:
        payload["message"] = "; ".join(errors)
    return UpstreamResult(response_payload(payload, verbose=True), exit_code)


def _merge_profiles(preferred: list[DiscoveredProfile], secondary: list[DiscoveredProfile]) -> list[DiscoveredProfile]:
    combined: dict[str, DiscoveredProfile] = {_profile_key(profile.ssid): profile for profile in preferred}
    for profile in secondary:
        key = _profile_key(profile.ssid)
        existing = combined.get(key)
        if not existing:
            combined[key] = profile
            continue
        if profile.has_password and not existing.has_password:
            combined[key] = profile
    return _sorted_profiles(combined.values())


def discover_system_profiles() -> tuple[list[DiscoveredProfile], list[str], dict[str, object]]:
    warnings: list[str] = []
    details: dict[str, object] = {}
    wpa_profiles, wpa_warnings, wpa_details = _parse_wpa_supplicant(UPSTREAM_WPA_SUPPLICANT_CONF)
    warnings.extend(wpa_warnings)
    details["wpa_supplicant"] = wpa_details

    nmcli_profiles, nmcli_warnings, nmcli_details = _parse_nmcli_wifi()
    warnings.extend(nmcli_warnings)
    details["nmcli"] = nmcli_details

    merged = _merge_profiles(wpa_profiles, nmcli_profiles)
    return merged, warnings, details


def _drift_summary(
    stored_profiles: Sequence[UpstreamProfile],
    system_profiles: Sequence[DiscoveredProfile],
) -> dict[str, object]:
    stored_map = {_profile_key(profile.ssid): profile for profile in stored_profiles}
    system_map = {_profile_key(profile.ssid): profile for profile in system_profiles}

    missing_in_system = [profile.ssid for key, profile in stored_map.items() if key not in system_map]
    missing_in_storage = [profile.ssid for key, profile in system_map.items() if key not in stored_map]

    mismatched: list[dict[str, object]] = []
    for key, stored_profile in stored_map.items():
        system_profile = system_map.get(key)
        if not system_profile:
            continue
        if stored_profile.priority != system_profile.priority or stored_profile.security != system_profile.security:
            mismatched.append(
                {
                    "ssid": stored_profile.ssid,
                    "stored": {"priority": stored_profile.priority, "security": stored_profile.security},
                    "system": {"priority": system_profile.priority, "security": system_profile.security},
                }
            )

    password_gaps = [
        profile.ssid
        for profile in system_profiles
        if profile.password_missing and _requires_password(profile.security)
    ]

    return {
        "missing_in_system": missing_in_system,
        "missing_in_storage": missing_in_storage,
        "mismatched": mismatched,
        "password_gaps": password_gaps,
        "has_drift": bool(missing_in_system or missing_in_storage or mismatched or password_gaps),
    }


def _annotate_discovered(profiles: Sequence[DiscoveredProfile]) -> list[dict[str, object]]:
    annotated: list[dict[str, object]] = []
    for profile in profiles:
        annotated.append(
            {
                "ssid": profile.ssid,
                "priority": profile.priority,
                "security": profile.security,
                "has_password": profile.has_password,
                "password_missing": profile.password_missing,
                "source": profile.source or "system",
            }
        )
    return annotated


def _combine_display_profiles(
    stored_profiles: Sequence[UpstreamProfile],
    system_profiles: Sequence[DiscoveredProfile],
) -> list[dict[str, object]]:
    stored_map = {_profile_key(profile.ssid): profile for profile in stored_profiles}
    display: list[dict[str, object]] = []

    for profile in system_profiles:
        key = _profile_key(profile.ssid)
        stored_match = stored_map.pop(key, None)
        entry = {
            "ssid": profile.ssid,
            "priority": profile.priority,
            "security": profile.security,
            "has_password": profile.has_password,
            "password_missing": profile.password_missing,
            "source": profile.source or "system",
            "saved": stored_match is not None,
            "drift": False,
        }
        if stored_match and (
            stored_match.priority != profile.priority or stored_match.security != profile.security
        ):
            entry["drift"] = True
        display.append(entry)

    for leftover in stored_map.values():
        display.append(
            {
                "ssid": leftover.ssid,
                "priority": leftover.priority,
                "security": leftover.security,
                "has_password": leftover.has_password,
                "password_missing": False,
                "source": "saved",
                "saved": True,
                "drift": True,
            }
        )

    return sorted(
        display,
        key=lambda entry: (-int(entry.get("priority") or 0), str(entry.get("ssid") or "").lower()),
    )


def _merge_scan_results(
    profiles: Sequence[dict[str, object]],
    scan_results: Mapping[str, Mapping[str, object]],
) -> list[dict[str, object]]:
    merged: list[dict[str, object]] = []
    for entry in profiles:
        ssid = entry.get("ssid")
        key = _profile_key(ssid if isinstance(ssid, str) else "")
        scan = scan_results.get(key)
        availability = "unavailable"
        signal_strength = None
        if scan:
            if scan.get("active"):
                availability = "active"
            elif scan.get("available"):
                availability = "available"
            signal_strength = scan.get("signal_percent")
        merged_entry = dict(entry)
        merged_entry["availability"] = availability
        merged_entry["signal_strength"] = signal_strength
        merged.append(merged_entry)
    return merged


def status(path: Path | None = None) -> dict[str, object]:
    stored_warnings: list[str] = []
    stored_profiles = load_profiles(path, warnings=stored_warnings)
    system_profiles, system_warnings, discovery_details = discover_system_profiles()
    system_profiles = _inject_saved_passwords(system_profiles, stored_profiles)
    drift = _drift_summary(stored_profiles, system_profiles)
    interface_name = UPSTREAM_INTERFACE
    active_ssid, active_errors = _active_upstream_connection(interface_name)
    scan_results, scan_warnings, scan_details = _scan_nmcli_wifi(interface_name, active_ssid)
    warnings = [*stored_warnings, *system_warnings, *active_errors, *scan_warnings]
    status_label = "ok" if not drift["has_drift"] else "warning"
    profiles = _combine_display_profiles(stored_profiles, system_profiles)
    profiles = _merge_scan_results(profiles, scan_results)
    payload: dict[str, object] = {
        "status": status_label,
        "exit_code": 0,
        "stored_profiles": _annotate_profiles(stored_profiles),
        "system_profiles": _annotate_discovered(system_profiles),
        "profiles": profiles,
        "drift": drift,
        "warnings": warnings,
        "discovery": {**discovery_details, "scan": scan_details},
    }
    if drift["has_drift"]:
        payload["message"] = "Upstream Wi-Fi configuration differs between saved and system state."
    if system_warnings:
        payload["message"] = "; ".join(system_warnings)
        payload["status"] = "warning"
    return payload


def save_current_config(path: Path | None = None) -> list[dict[str, object]]:
    stored_profiles = load_profiles(path)
    system_profiles, warnings, _ = discover_system_profiles()
    system_profiles = _inject_saved_passwords(system_profiles, stored_profiles)
    if not system_profiles:
        raise ValueError("No upstream Wi-Fi profiles detected on the system.")
    missing_passwords = [
        profile.ssid for profile in system_profiles if profile.password_missing and _requires_password(profile.security)
    ]
    if missing_passwords:
        raise ValueError(
            "Cannot save current configuration; missing passwords for: " + ", ".join(sorted(missing_passwords))
        )

    storage_path = path or UPSTREAM_NETWORKS_JSON
    upstream_profiles = [
        UpstreamProfile(
            ssid=profile.ssid,
            password=profile.prepared_password,
            priority=profile.priority,
            security=profile.security,
        )
        for profile in system_profiles
    ]
    _save_profiles(_sorted_profiles(upstream_profiles), storage_path)
    if warnings:
        LOG.warning("Warnings while saving current upstream config: %s", "; ".join(warnings))
    return _annotate_profiles(upstream_profiles)


__all__ = [
    "LEGACY_UPSTREAM_JSON",
    "UPSTREAM_NETWORKS_JSON",
    "UpstreamProfile",
    "DiscoveredProfile",
    "UpstreamResult",
    "activate_upstream",
    "add_profile",
    "apply_upstream",
    "discover_system_profiles",
    "forget_system_profile",
    "list_profiles",
    "load_profiles",
    "save_current_config",
    "status",
    "remove_profile",
    "update_profile",
]
