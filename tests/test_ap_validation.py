from pathlib import Path
from unittest import mock

import pytest


def test_validate_and_apply_records_history_and_snapshots(mcbridge_modules, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    paths, _, ap, _ = mcbridge_modules
    hostapd_path = ap.HOSTAPD_ACTIVE_CONF
    deploy_target = ap.HOSTAPD_CONF
    history_dir = paths.GENERATED_HISTORY_DIR

    hostapd_path.parent.mkdir(parents=True, exist_ok=True)
    hostapd_path.write_text("old-config\n", encoding="utf-8")
    deploy_target.parent.mkdir(parents=True, exist_ok=True)

    snapshot_path = tmp_path / "hostapd.conf.active"
    snapshot_path.write_text("snapshot-config\n", encoding="utf-8")

    validation_success = mock.Mock(returncode=0, stdout="ok", stderr="", args=["hostapd", "-t"])
    monkeypatch.setattr(ap.subprocess, "run", lambda *args, **kwargs: validation_success)
    monkeypatch.setattr(ap, "reload_or_restart_service", lambda service, timeout=None: {"service": service, "success": True, "returncode": 0})
    monkeypatch.setattr(ap, "service_status", lambda service, timeout=None: {"returncode": 1})
    monkeypatch.setattr(ap, "check_interface_exists", lambda interface: (False, {"stdout": "", "returncode": 1}))

    result = ap._validate_and_apply(  # type: ignore[attr-defined]
        path=hostapd_path,
        candidate="ssid=test\n",
        deploy_paths=(deploy_target,),
        snapshot_paths=(snapshot_path,),
        validate_command=["hostapd", "-t", "{path}"],
        service="hostapd",
        dry_run=False,
        history_suffix="hostapd.conf",
        history_dir=history_dir,
    )

    assert result["validation"]["status"] == "passed"
    assert result["applied"] is True
    assert result["pre_deploy_history"]
    history_entries = list(history_dir.glob("*.conf")) + list(history_dir.glob("*hostapd.conf"))
    assert history_entries


def test_apply_hostapd_dnsmasq_generates_templates(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    override_body = "# overrides\ncname=keep.example,target.test"

    monkeypatch.setattr(ap, "_resolve_override_body", lambda active_config="", generated_config="": override_body)
    monkeypatch.setattr(ap, "read_text", lambda path: "")
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})

    overrides_calls: list[str] = []
    monkeypatch.setattr(
        ap,
        "_ensure_overrides_conf",
        lambda body: overrides_calls.append(body) or {"path": str(ap.DNSMASQ_OVERRIDES_CONF), "updated": True},
    )

    calls: list[dict] = []

    def fake_validate_and_apply(**kwargs):
        calls.append(kwargs)
        return {
            "service": kwargs["service"],
            "candidate": kwargs["candidate"],
            "validation": {"status": "passed"},
            "service_restart": {"service": kwargs["service"], "success": True, "returncode": 0},
        }

    monkeypatch.setattr(ap, "_validate_and_apply", fake_validate_and_apply)

    result = ap._apply_hostapd_dnsmasq({"ssid": "Net", "password": "secret", "subnet_octet": 77}, dry_run=True)

    hostapd_call = next(call for call in calls if call["service"] == "hostapd")
    dnsmasq_call = next(call for call in calls if call["service"] == "dnsmasq")

    assert "ssid=Net" in hostapd_call["candidate"]
    assert "wpa_passphrase=secret" in hostapd_call["candidate"]
    assert "192.168.77.10,192.168.77.60,12h" in dnsmasq_call["candidate"]
    assert ap.MANAGE_AP_SECTION_START in dnsmasq_call["candidate"]
    assert override_body in dnsmasq_call["candidate"]
    assert result["dnsmasq_overrides"]["updated"] is True
    assert override_body in overrides_calls


def test_dry_run_skips_validation_and_restarts(mcbridge_modules, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    paths, _, ap, _ = mcbridge_modules
    hostapd_path = tmp_path / "hostapd.conf"
    history_dir = paths.GENERATED_HISTORY_DIR

    with monkeypatch.context() as mp:
        mp.setattr(ap.subprocess, "run", mock.Mock())
        result = ap._validate_and_apply(  # type: ignore[attr-defined]
            path=hostapd_path,
            candidate="ssid=test\n",
            deploy_paths=(ap.HOSTAPD_CONF,),
            snapshot_paths=(hostapd_path,),
            validate_command=["hostapd", "-t"],
            service="hostapd",
            dry_run=True,
            history_suffix="hostapd.conf",
            history_dir=history_dir,
        )

    assert result["validation"]["status"] == "skipped"
    assert result["service_restart"]["status"] == "skipped"
    assert not hostapd_path.exists()
    assert result["applied"] is False
