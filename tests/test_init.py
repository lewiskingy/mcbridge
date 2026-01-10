import importlib
import importlib.resources as resources
import json
import os
import shutil
from pathlib import Path
from ipaddress import ip_network

import pytest


@pytest.fixture
def init_modules(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    etc_dir = tmp_path / "etc"
    monkeypatch.setenv("MCBRIDGE_ETC_DIR", str(etc_dir))
    monkeypatch.setenv("MCBRIDGE_FAILED_ROOT", str(etc_dir / "generated" / "failed"))
    monkeypatch.setenv("MCBRIDGE_WLAN0AP_IP_SERVICE", str(etc_dir / "systemd/system/wlan0ap-ip.service"))
    monkeypatch.setenv("MCBRIDGE_WLAN0AP_SERVICE", str(etc_dir / "systemd/system/wlan0ap.service"))
    monkeypatch.setenv("MCBRIDGE_GENERATED_WLAN0AP_IP_SERVICE", str(etc_dir / "generated" / "wlan0ap-ip.service"))
    monkeypatch.setenv("MCBRIDGE_WEB_SERVICE", str(etc_dir / "systemd/system/mcbridge-web.service"))
    monkeypatch.setenv("MCBRIDGE_WEB_TLS_CERT", str(etc_dir / "config/web-cert.pem"))
    monkeypatch.setenv("MCBRIDGE_WEB_TLS_KEY", str(etc_dir / "config/web-key.pem"))

    import mcbridge.ap as mc_ap
    import mcbridge.common as mc_common
    import mcbridge.dns as mc_dns
    import mcbridge.init as mc_init
    import mcbridge.paths as mc_paths

    paths = importlib.reload(mc_paths)
    common = importlib.reload(mc_common)
    ap = importlib.reload(mc_ap)
    dns = importlib.reload(mc_dns)
    init = importlib.reload(mc_init)

    hostapd_active = etc_dir / "hostapd.conf"
    dnsmasq_active = etc_dir / "dnsmasq.conf"
    overrides_conf = etc_dir / "dnsmasq-mcbridge.conf"
    for module in (common, ap, dns, init):
        module.HOSTAPD_ACTIVE_CONF = hostapd_active
        module.DNSMASQ_ACTIVE_CONF = dnsmasq_active
        module.DNSMASQ_OVERRIDES_CONF = overrides_conf

    monkeypatch.setattr(
        init,
        "_run_systemctl",
        lambda args: {"command": ["systemctl", *args], "stdout": "", "stderr": "", "returncode": 0},
    )
    monkeypatch.setattr(
        init,
        "_sync_wlan0ap_units",
        lambda *, octet, dry_run=False: {"status": "ok", "applied": True, "octet": octet},
    )
    monkeypatch.setattr(init, "_collect_post_apply_checks", lambda *, octet: {"status": "ok", "errors": []})

    return paths, common, ap, dns, init, etc_dir


def test_init_validation_errors(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: False)

    result = init.run(
        ssid="",
        password="short",
        octet=0,
        channel=20,
        target="not a host",
        redirect="redirect host",
        dry_run=True,
    )

    assert result.exit_code == 2
    assert result.payload["status"] == "error"
    assert "validation_errors" in result.payload


def test_init_reports_service_operator_membership(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_sync_wlan0ap_units", lambda **kwargs: {"status": "ok"})

    membership_calls: list[dict[str, object]] = []

    def fake_membership(user: str, group: str, dry_run: bool) -> dict[str, object]:
        membership_calls.append({"user": user, "group": group, "dry_run": dry_run})
        return {
            "user": user,
            "group": group,
            "status": "planned",
            "command": ["usermod", "-a", "-G", group, user],
        }

    monkeypatch.setattr(init, "_ensure_group_membership", fake_membership)

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=25,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        dry_run=True,
        debug_json=True,
    )

    assert result.exit_code == 0
    assert membership_calls == [
        {"user": init.SERVICE_USER, "group": init.OPERATOR_GROUP, "dry_run": True},
    ]
    principals = result.payload["principals"]
    assert principals["service_operator_membership"]["status"] == "planned"
    assert "command" in principals["service_operator_membership"]


def test_init_marker_blocks_without_force(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, common, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0, "provision_status": "noop"})

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)

    common.INITIALISED_MARKER.parent.mkdir(parents=True, exist_ok=True)
    common.INITIALISED_MARKER.write_text("already initialised\n", encoding="utf-8")

    result = init.run(
        ssid="MySSID",
        password="password1",
        octet=10,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
    )

    assert result.exit_code == 0
    assert result.payload["status"] == "ok"
    assert result.payload["provision_status"] == "noop"


def test_init_success_seeds_and_marks(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, common, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)

    result = init.run(
        ssid="MySSID",
        password="password1",
        octet=42,
        channel=6,
        target="target.example.com",
        redirect="redirect.example.com",
        assume_yes=True,
    )

    assert result.exit_code == 0
    assert common.AP_JSON.exists()
    assert common.DNS_OVERRIDES_JSON.exists()
    assert common.KNOWN_SERVERS_JSON.exists()
    assert common.INITIALISED_MARKER.exists()

    ap_payload = json.loads(common.AP_JSON.read_text(encoding="utf-8"))
    overrides_payload = json.loads(common.DNS_OVERRIDES_JSON.read_text(encoding="utf-8"))
    known_servers = json.loads(common.KNOWN_SERVERS_JSON.read_text(encoding="utf-8"))

    assert ap_payload["ssid"] == "MySSID"
    assert overrides_payload["target"] == "target.example.com"
    assert overrides_payload["redirect"] == "redirect.example.com"
    assert overrides_payload["enabled"] is True
    assert known_servers["target"] == "target.example.com"
    assert known_servers["redirects"][0]["redirect"] == "redirect.example.com"

    marker_text = common.INITIALISED_MARKER.read_text(encoding="utf-8")
    assert "version" in marker_text


def test_extract_provision_script_creates_executable(tmp_path: Path):
    import mcbridge.init as mc_init

    script_path = mc_init._extract_provision_script()
    try:
        assert script_path.exists()
        assert os.access(script_path, os.X_OK)
    finally:
        shutil.rmtree(script_path.parent, ignore_errors=True)


def test_provision_invocation_uses_explicit_args(init_modules, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)

    script_path = tmp_path / "provision.sh"
    script_path.write_text("#!/usr/bin/env bash\nexit 0\n", encoding="utf-8")
    script_path.chmod(0o755)
    monkeypatch.setattr(init, "_extract_provision_script", lambda: script_path)

    captured: dict[str, object] = {}

    def fake_run(command, check, capture_output, text, env):
        captured["command"] = command
        return type("Proc", (), {"returncode": 0, "stdout": "", "stderr": ""})()

    monkeypatch.setattr(init.subprocess, "run", fake_run)

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)

    result = init.run(
        ssid="MySSID",
        password="password1",
        octet=77,
        channel=6,
        target="target.example.com",
        redirect="redirect.example.com",
        assume_yes=True,
    )

    assert result.exit_code == 0
    command = captured.get("command")
    assert command is not None
    assert str(script_path) == command[0]
    assert command[command.index("--ap-interface") + 1] == init.AP_INTERFACE
    assert command[command.index("--upstream-interface") + 1] == init.UPSTREAM_INTERFACE
    assert command[command.index("--ap-ip-cidr") + 1] == "192.168.77.1/24"
    assert command[command.index("--sysctl-conf-path") + 1] == str(init.SYSCTL_CONF_PATH)
    assert command[command.index("--iptables-rules-path") + 1] == str(init.IPTABLES_RULES_V4)


def test_init_requires_root_and_skips_provision(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules

    def require_root():
        raise PermissionError("root needed")

    monkeypatch.setattr(init, "_require_root", require_root)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)

    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: (_ for _ in ()).throw(AssertionError("provision should be skipped")))
    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=10,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"


def test_init_validation_failure_skips_provision_and_updates(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: False)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))

    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: (_ for _ in ()).throw(AssertionError("provision should not run")))

    ap_called = False
    dns_called = False

    def ap_update(**_):
        nonlocal ap_called
        ap_called = True
        return init.ap.ApResult(payload={}, exit_code=0)

    def dns_update(**_):
        nonlocal dns_called
        dns_called = True
        return init.dns.DnsResult(payload={}, exit_code=0)

    monkeypatch.setattr(init.ap, "update", ap_update)
    monkeypatch.setattr(init.dns, "update", dns_update)

    result = init.run(
        ssid="",
        password="short",
        octet=0,
        channel=99,
        target="bad host",
        redirect="redirect",
        debug_json=True,
    )

    assert result.exit_code == 2
    assert result.payload["status"] == "error"
    assert not ap_called
    assert not dns_called


def test_init_environment_failure_sets_runtime_exit(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(
        init,
        "_check_environment",
        lambda **kwargs: (["systemctl missing"], {"environment": {"systemctl": "missing"}}, kwargs.get("octet", 50)),
    )

    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: (_ for _ in ()).throw(AssertionError("provision should not run")))
    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    result = init.run(
        ssid="MySSID",
        password="password1",
        octet=10,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        debug_json=True,
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert "systemctl" in json.dumps(result.payload)


def test_init_aborts_when_upstream_subnet_overlaps(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_load_os_release", lambda: {"ID_LIKE": "debian"})
    monkeypatch.setattr(init.shutil, "which", lambda _: True)
    monkeypatch.setattr(init, "check_interface_exists", lambda iface: (True, {"interface": iface, "returncode": 0}))
    monkeypatch.setattr(
        init,
        "_detect_upstream_networks",
        lambda iface: ([], [ip_network("192.168.50.0/24")], {"interface": iface, "commands": []}),
    )

    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: (_ for _ in ()).throw(AssertionError("provision should not run")))
    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    result = init.run(
        ssid="OverlapSSID",
        password="password1",
        octet=50,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
    )

    assert result.exit_code == 3
    assert "overlaps with upstream network" in result.payload["environment_errors"][0]
    assert "50.0/24" in result.payload["environment_errors"][0]


def test_init_allows_non_overlapping_upstream_subnet(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_load_os_release", lambda: {"ID_LIKE": "debian"})
    monkeypatch.setattr(init.shutil, "which", lambda _: True)
    monkeypatch.setattr(init, "check_interface_exists", lambda iface: (True, {"interface": iface, "returncode": 0}))
    monkeypatch.setattr(
        init,
        "_detect_upstream_networks",
        lambda iface: ([], [ip_network("10.0.0.0/24")], {"interface": iface, "commands": []}),
    )

    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)

    result = init.run(
        ssid="NonOverlapSSID",
        password="password1",
        octet=50,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
    )

    assert result.exit_code == 0


def test_init_reassigns_default_octet_when_conflicting(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_load_os_release", lambda: {"ID_LIKE": "debian"})
    monkeypatch.setattr(init.shutil, "which", lambda _: True)
    monkeypatch.setattr(init, "check_interface_exists", lambda iface: (True, {"interface": iface, "returncode": 0}))
    monkeypatch.setattr(
        init,
        "_detect_upstream_networks",
        lambda iface: ([], [ip_network("192.168.50.0/24")], {"interface": iface, "commands": []}),
    )

    captured: dict[str, object] = {}

    def seed_configs(**kwargs):
        captured["octet"] = kwargs["octet"]
        return {"applied": True, "payload": {"subnet_octet": kwargs["octet"]}}

    monkeypatch.setattr(init, "_seed_configs", seed_configs)
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})
    monkeypatch.setattr(init, "_collect_post_apply_checks", lambda *, octet: {"status": "ok", "octet": octet})

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)

    result = init.run(
        ssid="ReassignSSID",
        password="password1",
        octet=None,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 0
    assert captured["octet"] != init.ap.DEFAULT_SUBNET_OCTET
    assert captured["octet"] == result.payload["seed_config"]["payload"]["subnet_octet"]
    assert "octet_selection" in result.payload
    assert result.payload["octet_selection"]["details"]["requested"] == init.ap.DEFAULT_SUBNET_OCTET
    assert result.payload["octet_selection"]["details"]["selected"] == captured["octet"]


def test_init_service_enablement_failure(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})
    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    def failing_service_enablement(services, *, runner=None, dry_run=False, start_services=True):
        return (
            {"hostapd": {"status": "error", "is_enabled": {"stdout": "masked", "returncode": 1}}},
            ["hostapd is masked; unmask failed: permission denied"],
        )

    monkeypatch.setattr(init, "ensure_services_enabled", failing_service_enablement)

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=10,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert "hostapd is masked" in result.payload["message"]


def test_init_dry_run_emits_plan_without_applying(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, common, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: (_ for _ in ()).throw(AssertionError("provision should not run")))
    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    result = init.run(
        ssid="DrySSID",
        password="password1",
        octet=20,
        channel=1,
        target="example.com",
        redirect="redirect.example.com",
        dry_run=True,
        debug_json=True,
    )

    assert result.exit_code == 0
    assert "plan" in result.payload
    seed_plan = result.payload["seed_config"]
    assert seed_plan["applied"] is False
    assert not common.AP_JSON.exists()
    assert not common.DNS_OVERRIDES_JSON.exists()
    assert not common.INITIALISED_MARKER.exists()


def test_init_force_overrides_existing_marker(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, common, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})

    ap_called = False
    dns_called = False

    def ap_update(**kwargs):
        nonlocal ap_called
        ap_called = True
        return init.ap.ApResult(payload={"status": "ok"}, exit_code=0)

    def dns_update(**kwargs):
        nonlocal dns_called
        dns_called = True
        return init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)

    monkeypatch.setattr(init.ap, "update", ap_update)
    monkeypatch.setattr(init.dns, "update", dns_update)

    common.INITIALISED_MARKER.parent.mkdir(parents=True, exist_ok=True)
    common.INITIALISED_MARKER.write_text("initialised", encoding="utf-8")

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=30,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        force=True,
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 0
    assert ap_called and dns_called
    assert common.INITIALISED_MARKER.exists()


def test_init_marker_requires_force_when_drift_detected(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, common, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0, "provision_status": "applied"})

    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    common.INITIALISED_MARKER.parent.mkdir(parents=True, exist_ok=True)
    common.INITIALISED_MARKER.write_text("initialised\n", encoding="utf-8")

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=31,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert "drift" in result.payload["message"]


def test_init_provision_failure_sets_runtime_exit(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, common, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 1, "stderr": "boom"})

    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=40,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert not common.INITIALISED_MARKER.exists()


def test_init_post_apply_checks_escalate_exit(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})
    monkeypatch.setattr(init, "_collect_post_apply_checks", lambda *, octet: {"status": "error", "errors": ["missing"]})

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=41,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 3
    assert "post_apply_checks" in result.payload
    assert result.payload["post_apply_checks"]["errors"]


def test_updates_called_after_successful_provision(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})

    calls: dict[str, int] = {"ap": 0, "dns": 0}

    def ap_update(**kwargs):
        calls["ap"] += 1
        return init.ap.ApResult(payload={"status": "ok"}, exit_code=0)

    def dns_update(**kwargs):
        calls["dns"] += 1
        return init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)

    monkeypatch.setattr(init.ap, "update", ap_update)
    monkeypatch.setattr(init.dns, "update", dns_update)

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=50,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 0
    assert calls == {"ap": 1, "dns": 1}


def test_init_applies_defaults_and_allows_empty_password(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))

    captured: dict[str, object] = {}

    def seed_configs(**kwargs):
        captured["seed"] = kwargs
        return {"applied": True}

    def sync_units(**kwargs):
        captured["units"] = kwargs
        return {"status": "applied", "octet": kwargs["octet"]}

    def ap_update(**kwargs):
        captured["ap_update"] = kwargs
        return init.ap.ApResult(payload={"status": "ok"}, exit_code=0)

    def dns_update(**kwargs):
        captured["dns_update"] = kwargs
        return init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)

    monkeypatch.setattr(init, "_seed_configs", seed_configs)
    monkeypatch.setattr(init, "_sync_wlan0ap_units", sync_units)
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})
    monkeypatch.setattr(init, "_collect_post_apply_checks", lambda *, octet: {"status": "ok", "octet": octet})
    monkeypatch.setattr(init.ap, "update", ap_update)
    monkeypatch.setattr(init.dns, "update", dns_update)

    result = init.run(
        ssid="SSID",
        password="",
        octet=None,
        channel=None,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
    )

    assert result.exit_code == 0
    assert captured["seed"]["password"] == ""
    assert captured["seed"]["octet"] == init.ap.DEFAULT_SUBNET_OCTET
    assert captured["seed"]["channel"] == init.DEFAULT_CHANNEL
    assert captured["units"]["octet"] == init.ap.DEFAULT_SUBNET_OCTET
    assert captured["ap_update"]["password"] == ""
    assert captured["ap_update"]["subnet_octet"] == init.ap.DEFAULT_SUBNET_OCTET
    assert captured["ap_update"]["channel"] == init.DEFAULT_CHANNEL


def test_init_syncs_units_before_provision(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)

    unit_called = {"flag": False}

    def sync_units(**kwargs):
        unit_called["flag"] = True
        return {"status": "applied"}

    monkeypatch.setattr(init, "_sync_wlan0ap_units", sync_units)

    def fake_provision(**kwargs):
        assert unit_called["flag"]
        return {"returncode": 0}

    monkeypatch.setattr(init, "_run_provisioning_script", fake_provision)

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=51,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
    )

    assert result.exit_code == 0
    assert unit_called["flag"] is True


def test_init_defers_unit_apply_until_after_confirmation(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_confirm", lambda summary: True)

    calls: list[bool] = []

    def sync_units(**kwargs):
        calls.append(kwargs["dry_run"])
        return {"status": "planned" if kwargs["dry_run"] else "applied"}

    monkeypatch.setattr(init, "_sync_wlan0ap_units", sync_units)

    ap_result = init.ap.ApResult(payload={"status": "ok"}, exit_code=0)
    dns_result = init.dns.DnsResult(payload={"status": "ok"}, exit_code=0)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap_result)
    monkeypatch.setattr(init.dns, "update", lambda **__: dns_result)
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: {"returncode": 0})

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=51,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
    )

    assert result.exit_code == 0
    assert calls == [True, False]


def test_run_provisioning_script_emits_output(monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]):
    import types

    import mcbridge.init as init

    monkeypatch.setattr(init, "_extract_provision_script", lambda: Path("/tmp/mock-provision.sh"))
    monkeypatch.setattr(init, "_parse_provision_status", lambda stdout: "applied")

    def fake_sudo_run(command, env=None, check=False):
        assert check is True
        assert command[0] == "bash"
        assert command[1] == "/tmp/mock-provision.sh"
        return types.SimpleNamespace(stdout="provision stdout\n", stderr="provision stderr\n", returncode=0)

    monkeypatch.setattr(init.privileges, "sudo_run", fake_sudo_run)

    result = init._run_provisioning_script(
        ssid="SSID",
        password="password1",
        octet=51,
        channel=6,
        force=False,
        service_user="mcbridge",
        service_group="mcbridge",
        operator_group="mcbridge-operators",
    )

    output = capsys.readouterr().out
    assert "provision stdout" in output
    assert "provision stderr" in output
    assert result["returncode"] == 0
    assert result["provision_status"] == "applied"


def test_init_unit_enable_failure_surfaces_remediation(init_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, _, init, _ = init_modules
    monkeypatch.setattr(init, "_require_root", lambda: None)
    monkeypatch.setattr(init, "_check_environment", lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)))
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)

    monkeypatch.setattr(
        init,
        "_sync_wlan0ap_units",
        lambda **kwargs: {
            "status": "error",
            "enable": [{"returncode": 1, "stderr": "no service"}],
            "remediation": "Retry systemctl enable",
        },
    )

    monkeypatch.setattr(init, "_run_provisioning_script", lambda **_: (_ for _ in ()).throw(AssertionError("provision should not run")))
    monkeypatch.setattr(init.ap, "update", lambda **_: (_ for _ in ()).throw(AssertionError("ap.update should not run")))
    monkeypatch.setattr(init.dns, "update", lambda **_: (_ for _ in ()).throw(AssertionError("dns.update should not run")))

    result = init.run(
        ssid="SSID",
        password="password1",
        octet=52,
        channel=6,
        target="example.com",
        redirect="redirect.example.com",
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 3
    assert result.payload["status"] == "error"
    assert result.payload["ap_units"]["remediation"]


def test_provision_resource_accessible_via_importlib_resources():
    resource = resources.files("mcbridge.resources").joinpath("provision.sh")
    with resources.as_file(resource) as path:
        contents = path.read_text(encoding="utf-8")
    assert "provision" in contents
    assert path.name == "provision.sh"
