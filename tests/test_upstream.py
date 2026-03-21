import json
from pathlib import Path

import pytest

from mcbridge import upstream


def test_upstream_add_and_list_persists(tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"

    profiles = upstream.add_profile(
        ssid="HomeNet",
        password="hunter2",
        priority=10,
        security="wpa2",
        path=storage,
    )

    assert storage.exists()
    assert profiles == upstream.list_profiles(path=storage)

    data = json.loads(storage.read_text())
    assert data["profiles"][0]["ssid"] == "HomeNet"
    derived = upstream._derive_psk("HomeNet", "hunter2")
    assert data["profiles"][0]["password"] == derived
    assert len(derived) == 64
    assert profiles[0]["has_password"] is True
    assert data["mode"]["prefer_recovery"] is True


def test_upstream_validation(tmp_path: Path):
    storage = tmp_path / "data.json"

    with pytest.raises(ValueError):
        upstream.add_profile(ssid="", password="", priority=1, security="open", path=storage)

    with pytest.raises(ValueError):
        upstream.add_profile(ssid="Net", password="", priority=0, security="open", path=storage)

    with pytest.raises(ValueError):
        upstream.add_profile(ssid="Secured", password="", priority=1, security="wpa2", path=storage)


def test_upstream_accepts_prehashed_psk(tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"
    prehashed = "abcdef0123456789" * 4

    profiles = upstream.add_profile(ssid="PreHashed", password=prehashed, priority=3, security="wpa2", path=storage)

    assert json.loads(storage.read_text())["profiles"][0]["password"] == prehashed
    assert profiles[0]["has_password"] is True


def test_upstream_distinguishes_passphrase_and_psk(tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"
    uppercase_psk = "A1" * 32

    upstream.add_profile(ssid="UpperPSK", password=uppercase_psk, priority=6, security="wpa2", path=storage)
    upstream.add_profile(ssid="PassphraseNet", password="passphrase", priority=5, security="wpa2", path=storage)

    stored = json.loads(storage.read_text())["profiles"]
    saved_psk = next(entry for entry in stored if entry["ssid"] == "UpperPSK")
    saved_passphrase = next(entry for entry in stored if entry["ssid"] == "PassphraseNet")

    assert saved_psk["password"] == uppercase_psk
    assert saved_passphrase["password"] != "passphrase"
    assert len(saved_passphrase["password"]) == 64


def test_upstream_update_and_priority_merge(tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"

    upstream.add_profile(ssid="First", password="pass1", priority=5, security="wpa2", path=storage)
    upstream.add_profile(ssid="Second", password="", priority=2, security="open", path=storage)

    profiles = upstream.update_profile(ssid="Second", priority=10, path=storage)
    assert profiles[0]["ssid"] == "Second"
    assert profiles[0]["priority"] == 10

    with pytest.raises(ValueError):
        upstream.update_profile(ssid="Second", security="wpa3", path=storage)

    updated = upstream.update_profile(ssid="Second", password="secure", security="wpa3", path=storage)
    assert updated[0]["security"] == "wpa3"
    assert updated[0]["has_password"] is True

    remaining = upstream.remove_profile(ssid="First", path=storage)
    assert len(remaining) == 1
    assert remaining[0]["ssid"] == "Second"


def test_upstream_status_hides_passwords(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"
    upstream.add_profile(ssid="HomeNet", password="secret123", priority=1, security="wpa2", path=storage)

    system_profile = upstream.DiscoveredProfile(
        ssid="HomeNet", priority=1, security="wpa2", password="", password_missing=True
    )
    monkeypatch.setattr(
        upstream,
        "discover_system_profiles",
        lambda: ([system_profile], [], {"source": "tests"}),
    )

    payload = upstream.status(path=storage)

    assert payload["profiles"][0]["has_password"] is True
    assert payload["drift"]["password_gaps"] == []
    assert "passwords" not in payload
    for section in ("stored_profiles", "system_profiles", "profiles"):
        for profile in payload[section]:
            assert "password" not in profile


def test_upstream_status_flags_missing_password(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"
    upstream.add_profile(ssid="Other", password="", priority=1, security="open", path=storage)

    system_profile = upstream.DiscoveredProfile(
        ssid="SecureNet", priority=3, security="wpa2", password="", password_missing=True
    )
    monkeypatch.setattr(
        upstream,
        "discover_system_profiles",
        lambda: ([system_profile], [], {"source": "tests"}),
    )

    payload = upstream.status(path=storage)

    assert payload["drift"]["password_gaps"] == ["SecureNet"]
    assert "passwords" not in payload


def test_update_profile_handles_password_changes(tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"
    upstream.add_profile(ssid="Guest", password="temp", priority=1, security="wpa2", path=storage)

    updated = upstream.update_profile(ssid="Guest", password="newpass", path=storage)
    assert updated[0]["has_password"] is True

    cleared = upstream.update_profile(ssid="Guest", security="open", password="", path=storage)
    assert cleared[0]["has_password"] is False


def test_save_current_config_uses_saved_passwords(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"
    upstream.add_profile(ssid="SavedOnly", password="persisted", priority=4, security="wpa2", path=storage)

    system_profile = upstream.DiscoveredProfile(
        ssid="SavedOnly", priority=4, security="wpa2", password="", password_missing=True
    )
    monkeypatch.setattr(
        upstream,
        "discover_system_profiles",
        lambda: ([system_profile], [], {"source": "tests"}),
    )

    persisted = upstream.save_current_config(path=storage)

    assert persisted[0]["ssid"] == "SavedOnly"
    assert persisted[0]["has_password"] is True


def test_normalize_mode_defaults_to_prefer_recovery():
    assert upstream._normalize_mode().prefer_recovery is True
    assert upstream._normalize_mode({}).prefer_recovery is True
    assert upstream._normalize_mode({"operation": "normal"}).prefer_recovery is False


def test_set_mode_persists_explicit_prefer_primary(tmp_path: Path):
    storage = tmp_path / "etc" / "config" / "upstream_networks.json"
    upstream.add_profile(ssid="HomeNet", password="hunter2", priority=10, security="wpa2", path=storage)

    payload = upstream.set_mode(operation="prefer_primary", path=storage)

    assert payload["prefer_recovery"] is False
    assert payload["operation"] == "prefer_primary"
    stored = json.loads(storage.read_text())
    assert stored["mode"]["prefer_recovery"] is False


def test_select_profile_prefers_recovery_by_default():
    recovery = upstream.UpstreamProfile("Recovery", "secret", 1, "wpa2", role="recovery")
    primary = upstream.UpstreamProfile("Primary", "secret", 100, "wpa2", role="primary")

    selected = upstream._select_profile([primary, recovery], available_ssids={"recovery", "primary"})
    normal_selected = upstream._select_profile(
        [primary, recovery],
        mode=upstream.UpstreamMode(prefer_recovery=False),
        available_ssids={"recovery", "primary"},
    )

    assert selected is recovery
    assert normal_selected is primary


def test_autoconnect_priority_respects_mode():
    recovery = upstream.UpstreamProfile("Recovery", "secret", 5, "wpa2", role="recovery")
    primary = upstream.UpstreamProfile("Primary", "secret", 99, "wpa2", role="primary")

    assert upstream._autoconnect_priority(recovery) > upstream._autoconnect_priority(primary)
    assert upstream._autoconnect_priority(
        primary, mode=upstream.UpstreamMode(prefer_recovery=False)
    ) > upstream._autoconnect_priority(recovery, mode=upstream.UpstreamMode(prefer_recovery=False))
