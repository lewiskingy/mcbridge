import json
from pathlib import Path


def test_upstream_apply_writes_wpa_config(mcbridge_modules):
    _, _, ap, _ = mcbridge_modules

    config_dir = ap.AP_JSON.parent
    config_dir.mkdir(parents=True, exist_ok=True)
    upstream_path = config_dir / "upstream_networks.json"
    upstream_path.write_text(
        json.dumps(
            {
                "profiles": [
                    {"ssid": "HomeNet", "password": "secret", "priority": 20, "security": "wpa2"},
                    {"ssid": "GuestNet", "password": "", "priority": 5, "security": "open"},
                ]
            }
        ),
        encoding="utf-8",
    )

    result = ap._apply_upstream_wifi_config(dry_run=False)

    assert result["status"] == "updated"
    generated = Path(ap.UPSTREAM_WPA_SUPPLICANT_CONF).read_text(encoding="utf-8")
    assert 'ssid="HomeNet"' in generated
    assert "priority=20" in generated
    assert 'ssid="GuestNet"' in generated
    assert "priority=5" in generated
    assert Path(ap.UPSTREAM_WPA_GENERATED_CONF).exists()


def test_upstream_apply_warns_when_credentials_missing(mcbridge_modules):
    _, _, ap, _ = mcbridge_modules

    config_dir = ap.AP_JSON.parent
    config_dir.mkdir(parents=True, exist_ok=True)
    upstream_path = config_dir / "upstream_networks.json"
    upstream_path.write_text(
        json.dumps({"profiles": [{"ssid": "Secure", "priority": 3, "security": "wpa2", "password": ""}]}),
        encoding="utf-8",
    )

    result = ap._apply_upstream_wifi_config(dry_run=True)

    assert result["status"] == "skipped"
    assert result["warnings"]
    assert "password missing" in result["warnings"][0]
    assert not Path(ap.UPSTREAM_WPA_SUPPLICANT_CONF).exists()
