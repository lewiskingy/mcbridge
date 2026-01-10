import json
import subprocess
from pathlib import Path
from unittest import mock

import pytest


def test_validate_and_apply_timeout_serializes_bytes(mcbridge_modules, tmp_path: Path):
    _, _, ap, _ = mcbridge_modules
    history_dir = tmp_path / "history"
    hostapd_conf = tmp_path / "hostapd.conf"

    timeout_exc = subprocess.TimeoutExpired(
        cmd=["validate"],
        timeout=ap.VALIDATION_TIMEOUT_SECONDS,
        output=b"validation-bytes",
        stderr=b"\xffstderr-bytes",
    )

    with mock.patch.object(ap.subprocess, "run", side_effect=timeout_exc):
        with mock.patch.object(ap, "service_status", return_value={"returncode": 1}):
            with mock.patch.object(ap, "check_interface_exists", return_value=(False, {"stdout": "", "returncode": 1})):
                result = ap._validate_and_apply(  # type: ignore[attr-defined]
                    path=hostapd_conf,
                    candidate="ssid=test\n",
                    deploy_paths=None,
                    snapshot_paths=None,
                    validate_command=["validate"],
                    service="hostapd",
                    dry_run=False,
                    history_suffix="hostapd.conf",
                    history_dir=history_dir,
                )

    assert result["validation"]["timeout"] is True
    assert "stderr-bytes" in result["validation"]["stderr"]
    assert result["validation"]["timeout_seconds"] == ap.VALIDATION_TIMEOUT_SECONDS
    json.dumps(result)


def test_service_status_timeout_normalizes_bytes(mcbridge_modules):
    _, common, _, _ = mcbridge_modules

    timeout_exc = subprocess.TimeoutExpired(
        cmd=["systemctl", "status", "dummy"],
        timeout=2.5,
        output=b"status-output",
        stderr=b"\xffstatus-error",
    )
    with mock.patch.object(common.subprocess, "run", side_effect=timeout_exc):
        result = common.service_status("dummy", timeout=2.5)

    assert result["stdout"] == "status-output"
    assert "status-error" in result["stderr"]
    assert result["timeout"] is True
    assert result["timeout_seconds"] == 2.5
    json.dumps(result)


def test_reload_or_restart_timeout_normalizes_bytes(mcbridge_modules):
    _, common, _, _ = mcbridge_modules

    timeout_exc = subprocess.TimeoutExpired(
        cmd=["systemctl", "reload-or-restart", "dummy"],
        timeout=3.0,
        output=b"reload-output",
        stderr=b"\xffreload-error",
    )
    with mock.patch.object(common.subprocess, "run", side_effect=timeout_exc):
        result = common.reload_or_restart_service("dummy", timeout=3.0)

    assert result["stdout"] == "reload-output"
    assert "reload-error" in result["stderr"]
    assert result["timeout"] is True
    assert result["timeout_seconds"] == 3.0
    json.dumps(result)


def test_hostapd_validation_skips_when_service_active(mcbridge_modules, tmp_path: Path):
    _, _, ap, _ = mcbridge_modules

    hostapd_conf = tmp_path / "hostapd.conf"
    history_dir = tmp_path / "history"
    status_running = {"command": ["systemctl", "status", "hostapd"], "stdout": "active", "stderr": "", "returncode": 0}
    interface_stdout = "3: wlan0ap: <BROADCAST,MULTICAST,UP,LOWER_UP> state UP"

    with mock.patch.object(ap, "service_status", side_effect=[status_running, status_running]):
        with mock.patch.object(ap, "check_interface_exists", return_value=(True, {"stdout": interface_stdout, "returncode": 0})):
            with mock.patch.object(ap, "reload_or_restart_service", return_value={"service": "hostapd", "success": True}):
                result = ap._validate_and_apply(  # type: ignore[attr-defined]
                    path=hostapd_conf,
                    candidate="ssid=test\n",
                    deploy_paths=None,
                    snapshot_paths=None,
                    validate_command=["hostapd", "-t"],
                    service="hostapd",
                    dry_run=False,
                    history_suffix="hostapd.conf",
                    history_dir=history_dir,
                )

    assert result["validation"]["skipped"] is True
    assert "hostapd" in result["validation"]["reason"]
    assert result["validation"]["returncode"] is None
    assert result["applied"] is True
