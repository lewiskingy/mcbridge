import logging
from pathlib import Path
from unittest import mock

import pytest


def test_dnsmasq_validation_stderr_logged_as_info(mcbridge_modules, tmp_path: Path, log_capture):
    _, common, _, dns = mcbridge_modules

    history_dir = tmp_path / "history"
    handler = log_capture

    validation_success = mock.Mock(returncode=0, stdout="", stderr="syntax check OK.\n", args=["dnsmasq"])
    with mock.patch.object(dns.subprocess, "run", return_value=validation_success):
        with mock.patch.object(dns, "restart_service", return_value={"service": "dnsmasq", "success": True}):
            with mock.patch.object(dns, "service_status", return_value={"returncode": 0}):
                dns._validate_and_apply(  # type: ignore[attr-defined]
                    path=tmp_path / "dnsmasq.conf",
                    mirror_path=None,
                    mirror_candidate=None,
                    candidate="# candidate\n",
                    validate_command=["dnsmasq", "--test", "{path}"],
                    service="dnsmasq",
                    dry_run=False,
                    history_suffix="dnsmasq.conf",
                    history_dir=history_dir,
                )

    error_records = [
        rec for rec in handler.records if "dnsmasq validation stderr" in rec.getMessage() and rec.levelno >= logging.ERROR
    ]
    info_records = [rec for rec in handler.records if "dnsmasq validation stderr" in rec.getMessage()]
    assert not error_records
    assert info_records
    assert all(rec.levelno == logging.INFO for rec in info_records)


def test_manage_ap_dnsmasq_validation_stderr_logged_as_info(mcbridge_modules, tmp_path: pytest.TempPathFactory, log_capture):
    _, common, ap, _ = mcbridge_modules

    history_dir = tmp_path / "history"
    handler = log_capture

    validation_process = mock.Mock(returncode=0, stdout="", stderr="syntax check OK.\n", args=["dnsmasq"])
    with mock.patch.object(ap.subprocess, "run", return_value=validation_process):
        with mock.patch.object(ap, "reload_or_restart_service", return_value={"service": "dnsmasq", "success": True}):
            with mock.patch.object(ap, "service_status", return_value={"returncode": 0}):
                ap._validate_and_apply(  # type: ignore[attr-defined]
                    path=tmp_path / "dnsmasq.conf",
                    candidate="# candidate\n",
                    deploy_paths=None,
                    snapshot_paths=None,
                    validate_command=["dnsmasq", "--test", "{path}"],
                    service="dnsmasq",
                    dry_run=False,
                    history_suffix="dnsmasq.conf",
                    history_dir=history_dir,
                )

    error_records = [
        rec for rec in handler.records if "dnsmasq validation stderr" in rec.getMessage() and rec.levelno >= logging.ERROR
    ]
    info_records = [rec for rec in handler.records if "dnsmasq validation stderr" in rec.getMessage()]
    assert not error_records
    assert info_records
    assert all(rec.levelno == logging.INFO for rec in info_records)
