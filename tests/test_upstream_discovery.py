import json
from pathlib import Path
from subprocess import CompletedProcess

import pytest

from mcbridge import upstream


def test_discover_system_profiles_accepts_netplan_wifi_type(monkeypatch: pytest.MonkeyPatch):
    calls: list[list[str]] = []

    def fake_run(args, capture_output=True, text=True, check=False):
        calls.append(args)
        if "NAME,TYPE" in args:
            # Simulate netplan wifi connections using the longer type string.
            return CompletedProcess(args, 0, "netplan-wlan0-Almy:802-11-wireless\nlo:loopback\n", "")
        if args and args[-1] == "netplan-wlan0-Almy":
            return CompletedProcess(args, 0, "Almy\nwpa-psk\n5\nsecretpass\n", "")
        return CompletedProcess(args, 1, "", "not found")

    monkeypatch.setattr(upstream, "_run_nmcli", fake_run)
    monkeypatch.setattr(upstream, "_parse_wpa_supplicant", lambda path: ([], [], {"path": str(path), "found": False}))

    profiles, warnings, details = upstream.discover_system_profiles()

    assert warnings == []
    assert details["nmcli"]["count"] == 1
    assert profiles[0].ssid == "Almy"
    assert profiles[0].priority == 5
    assert profiles[0].security == "wpa2"
    derived = upstream._derive_psk("Almy", "secretpass")
    assert profiles[0].has_password is True
    assert profiles[0].psk == derived
    assert profiles[0].password_missing is False


def test_discover_system_profiles_handles_hashed_nmcli_psk(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    hashed_psk = "abcd" * 16

    def fake_run(args, capture_output=True, text=True, check=False):
        if "NAME,TYPE" in args:
            return CompletedProcess(args, 0, "netplan-wlan0-Hashed:802-11-wireless\n", "")
        if args and args[-1] == "netplan-wlan0-Hashed":
            return CompletedProcess(args, 0, f"Hashed\nwpa-psk\n1\n{hashed_psk}\n", "")
        return CompletedProcess(args, 1, "", "not found")

    monkeypatch.setattr(upstream, "_run_nmcli", fake_run)
    monkeypatch.setattr(upstream, "_parse_wpa_supplicant", lambda path: ([], [], {"path": str(path), "found": False}))

    profiles, warnings, details = upstream.discover_system_profiles()

    assert warnings == []
    assert details["nmcli"]["count"] == 1
    assert profiles[0].has_password is True
    assert profiles[0].password_missing is False
    assert profiles[0].psk == hashed_psk
    assert profiles[0].password == ""

    payload = upstream.status(path=tmp_path / "status.json")
    assert payload["system_profiles"][0]["has_password"] is True
    assert payload["system_profiles"][0]["password_missing"] is False
    serialized = json.dumps(payload)
    assert hashed_psk not in serialized
