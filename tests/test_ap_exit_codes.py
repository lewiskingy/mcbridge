import pytest


def test_ap_status_reports_drift_exit_code(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")
    monkeypatch.setenv("MCBRIDGE_DEBUG_JSON", "1")
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})

    def fake_read_system_ap_config(include_sources: bool = False):
        return {"ssid": "live"}, {"hostapd": {}, "dnsmasq": {}}

    monkeypatch.setattr(ap, "read_system_ap_config", fake_read_system_ap_config)

    result = ap.status()

    assert result.exit_code == 10
    assert result.payload["status"] == "warning"


def test_ap_status_exposes_summary_fields(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules

    def fake_read_system_ap_config(include_sources: bool = False):
        return {"ssid": "live-ssid", "subnet_octet": 42, "channel": 11}, {"hostapd": {}, "dnsmasq": {}}

    monkeypatch.setattr(ap, "read_system_ap_config", fake_read_system_ap_config)

    result = ap.status()

    assert result.payload["ssid"] == "live-ssid"
    assert result.payload["subnet_octet"] == 42
    assert result.payload["channel"] == 11


def test_ap_update_drift_exit_code(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})

    def fake_read_system_ap_config(include_sources: bool = False):
        return {"ssid": "live"}, {"hostapd": {}, "dnsmasq": {}}

    monkeypatch.setattr(ap, "read_system_ap_config", fake_read_system_ap_config)

    result = ap.update()

    assert result.exit_code == 2
    assert result.payload["status"] == "warning"


def test_ap_update_validation_failure_exit_code(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})

    def fake_read_system_ap_config(include_sources: bool = False):
        return {"ssid": "stored"}, {"hostapd": {}, "dnsmasq": {}}

    monkeypatch.setattr(ap, "read_system_ap_config", fake_read_system_ap_config)
    monkeypatch.setattr(ap, "_persist_ap_json", lambda *_, **__: {"applied": False})
    monkeypatch.setattr(
        ap,
        "_sync_wlan0ap_ip_service",
        lambda *_, **__: {"status": "unchanged", "applied": True, "ip_matches": True, "service_enabled": True},
    )
    monkeypatch.setattr(ap, "_apply_hostapd_dnsmasq", lambda *_, **__: {
        "hostapd": {"validation": {"status": "failed"}, "error": "hostapd validation failed"},
        "dnsmasq": {"validation": {"status": "passed"}},
        "dnsmasq_overrides": {},
    })
    monkeypatch.setattr(ap, "_restart_dnsmasq_after_wlan0ap_ip", lambda **__: ({"status": "skipped"}, False, None))
    monkeypatch.setattr(ap, "check_interface_exists", lambda *_: (True, {}))

    result = ap.update(dry_run=True)

    assert result.exit_code == 2
    assert result.payload["status"] == "error"


def test_ap_update_runtime_failure_exit_code(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})

    def fake_read_system_ap_config(include_sources: bool = False):
        return {"ssid": "stored"}, {"hostapd": {}, "dnsmasq": {}}

    monkeypatch.setattr(ap, "read_system_ap_config", fake_read_system_ap_config)
    monkeypatch.setattr(ap, "_persist_ap_json", lambda *_, **__: {"applied": True})
    monkeypatch.setattr(
        ap,
        "_sync_wlan0ap_ip_service",
        lambda *_, **__: {"status": "updated", "applied": True, "ip_matches": True, "service_enabled": True},
    )
    monkeypatch.setattr(
        ap,
        "_apply_hostapd_dnsmasq",
        lambda *_, **__: {
            "hostapd": {
                "validation": {"status": "passed", "returncode": 0},
                "service_restart": {"service": "hostapd", "success": True},
            },
            "dnsmasq": {
                "validation": {"status": "passed", "returncode": 0},
                "service_restart": {"service": "dnsmasq", "success": True},
            },
            "dnsmasq_overrides": {},
        },
    )
    monkeypatch.setattr(ap, "_restart_dnsmasq_after_wlan0ap_ip", lambda **__: (
        {"service": "dnsmasq", "status": "skipped", "reason": "test"}, False, None
    ))
    monkeypatch.setattr(ap, "_post_apply_verification", lambda *_, **__: {})
    monkeypatch.setattr(ap, "_post_apply_warning", lambda *_: "Post-apply verification failed.")
    monkeypatch.setattr(ap, "check_interface_exists", lambda *_: (True, {}))
    monkeypatch.setattr(ap, "save_json", lambda *_, **__: None)

    result = ap.update(dry_run=False)

    assert result.exit_code == 3
    assert result.payload["status"] == "warning"


def test_ap_update_fails_when_ip_service_not_ready(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")
    monkeypatch.setenv("MCBRIDGE_DEBUG_JSON", "1")
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})

    def fake_read_system_ap_config(include_sources: bool = False):
        return {"ssid": "stored"}, {"hostapd": {}, "dnsmasq": {}}

    monkeypatch.setattr(ap, "read_system_ap_config", fake_read_system_ap_config)
    monkeypatch.setattr(ap, "_persist_ap_json", lambda *_, **__: {"applied": True})
    monkeypatch.setattr(
        ap,
        "_sync_wlan0ap_ip_service",
        lambda *_, **__: {
            "status": "failed",
            "applied": False,
            "ip_matches": False,
            "service_enabled": False,
            "error": "wlan0ap-ip.service disabled",
            "ip_check": {"current_ip": None},
        },
    )
    monkeypatch.setattr(
        ap,
        "_apply_hostapd_dnsmasq",
        lambda *_, **__: {
            "hostapd": {
                "validation": {"status": "passed", "returncode": 0},
                "service_restart": {"service": "hostapd", "success": True},
            },
            "dnsmasq": {
                "validation": {"status": "passed", "returncode": 0},
                "service_restart": {"service": "dnsmasq", "success": True},
            },
            "dnsmasq_overrides": {},
        },
    )

    result = ap.update(dry_run=False)

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert "wlan0ap-ip" in result.payload["message"]
    assert "hostapd" in result.payload["changes"]


def test_ap_update_service_enablement_error(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")

    def failing_service_enablement(services, *, runner=None, dry_run=False, start_services=True):
        return (
            {"dnsmasq": {"status": "error", "is_enabled": {"stdout": "masked", "returncode": 1}}},
            ["dnsmasq enable failed: masked"],
        )

    monkeypatch.setattr(ap, "ensure_services_enabled", failing_service_enablement)
    monkeypatch.setattr(ap, "_persist_ap_json", lambda *_, **__: (_ for _ in ()).throw(AssertionError("persist should not run")))
    monkeypatch.setattr(ap, "read_system_ap_config", lambda include_sources=False: ({"ssid": "stored"}, {}))

    result = ap.update(dry_run=False)

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert "dnsmasq enable failed" in result.payload["message"]
