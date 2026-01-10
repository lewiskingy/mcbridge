"""Helpers for upstream Wi-Fi profile storage and validation."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, MutableMapping, Sequence

from ..common import load_json, save_json
from ..paths import CONFIG_DIR

UPSTREAM_WIFI_JSON = CONFIG_DIR / "upstream_wifi.json"


@dataclass
class WifiProfile:
    ssid: str
    priority: int
    security: str


def _profile_key(ssid: str) -> str:
    return ssid.strip().lower()


def _validate_required(value: Any, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} is required.")
    cleaned = value.strip()
    if not cleaned:
        raise ValueError(f"{field} is required.")
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


def _normalise_profile(entry: Mapping[str, Any]) -> WifiProfile | None:
    try:
        ssid = _validate_required(entry.get("ssid"), "ssid")
        priority = _validate_priority(entry.get("priority"))
        security = _validate_required(entry.get("security"), "security")
    except ValueError:
        return None
    return WifiProfile(ssid=ssid, priority=priority, security=security)


def _load_config(path: Path | None = None) -> tuple[list[WifiProfile], str | None]:
    target = path or UPSTREAM_WIFI_JSON
    raw_config = load_json(target, default={})
    if not isinstance(raw_config, Mapping):
        return [], None

    profiles: list[WifiProfile] = []
    for entry in raw_config.get("profiles", []) or []:
        if not isinstance(entry, Mapping):
            continue
        normalised = _normalise_profile(entry)
        if normalised:
            profiles.append(normalised)

    active_ssid = raw_config.get("active_ssid")
    return profiles, active_ssid if isinstance(active_ssid, str) else None


def _save_config(profiles: Sequence[WifiProfile], active_ssid: str | None, path: Path | None = None) -> None:
    payload: MutableMapping[str, Any] = {
        "profiles": [profile.__dict__ for profile in profiles],
    }
    if active_ssid:
        payload["active_ssid"] = active_ssid
    target = path or UPSTREAM_WIFI_JSON
    save_json(target, payload)


def _sorted_profiles(profiles: Iterable[WifiProfile]) -> list[WifiProfile]:
    return sorted(profiles, key=lambda profile: (-profile.priority, profile.ssid.lower()))


def _annotate_profiles(profiles: Sequence[WifiProfile], active_ssid: str | None) -> list[dict[str, object]]:
    annotated: list[dict[str, object]] = []
    for profile in profiles:
        annotated.append(
            {
                "ssid": profile.ssid,
                "priority": profile.priority,
                "security": profile.security,
                "active": _profile_key(profile.ssid) == _profile_key(active_ssid) if active_ssid else False,
            }
        )
    return annotated


def list_profiles(path: Path | None = None) -> list[dict[str, object]]:
    profiles, active_ssid = _load_config(path)
    return _annotate_profiles(_sorted_profiles(profiles), active_ssid)


def add_profile(
    *, ssid: str, priority: int, security: str, active: bool | None = None, path: Path | None = None
) -> list[dict[str, object]]:
    clean_ssid = _validate_required(ssid, "ssid")
    clean_security = _validate_required(security, "security")
    clean_priority = _validate_priority(priority)

    profiles, active_ssid = _load_config(path)
    if any(_profile_key(profile.ssid) == _profile_key(clean_ssid) for profile in profiles):
        raise ValueError(f"SSID {clean_ssid} already exists.")

    profiles.append(WifiProfile(ssid=clean_ssid, priority=clean_priority, security=clean_security))
    if active is True:
        active_ssid = clean_ssid
    elif active is False and active_ssid and _profile_key(active_ssid) == _profile_key(clean_ssid):
        active_ssid = None

    sorted_profiles = _sorted_profiles(profiles)
    _save_config(sorted_profiles, active_ssid, path)
    return _annotate_profiles(sorted_profiles, active_ssid)


def update_profile(
    *, ssid: str, priority: int | None = None, security: str | None = None, active: bool | None = None, path: Path | None = None
) -> list[dict[str, object]]:
    clean_ssid = _validate_required(ssid, "ssid")
    profiles, active_ssid = _load_config(path)
    key = _profile_key(clean_ssid)
    existing = None
    for profile in profiles:
        if _profile_key(profile.ssid) == key:
            existing = profile
            break
    if existing is None:
        raise ValueError(f"SSID {clean_ssid} was not found.")

    if priority is None and security is None and active is None:
        raise ValueError("No fields to update.")

    if priority is not None:
        existing.priority = _validate_priority(priority)
    if security is not None:
        existing.security = _validate_required(security, "security")

    if active is True:
        active_ssid = existing.ssid
    elif active is False and active_ssid and _profile_key(active_ssid) == key:
        active_ssid = None

    sorted_profiles = _sorted_profiles(profiles)
    _save_config(sorted_profiles, active_ssid, path)
    return _annotate_profiles(sorted_profiles, active_ssid)


def remove_profile(*, ssid: str, path: Path | None = None) -> list[dict[str, object]]:
    clean_ssid = _validate_required(ssid, "ssid")
    profiles, active_ssid = _load_config(path)
    key = _profile_key(clean_ssid)
    remaining = [profile for profile in profiles if _profile_key(profile.ssid) != key]

    if len(remaining) == len(profiles):
        raise ValueError(f"SSID {clean_ssid} was not found.")

    if active_ssid and _profile_key(active_ssid) == key:
        active_ssid = None

    sorted_profiles = _sorted_profiles(remaining)
    _save_config(sorted_profiles, active_ssid, path)
    return _annotate_profiles(sorted_profiles, active_ssid)

