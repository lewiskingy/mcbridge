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
