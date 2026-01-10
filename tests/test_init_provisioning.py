import importlib
from pathlib import Path

import pytest


def _reload_init(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    etc_dir = tmp_path / "etc"
    systemd_dir = etc_dir / "systemd" / "system"
    generated_dir = etc_dir / "generated"
    socket_path = tmp_path / "run" / "mcbridge" / "agent.sock"
    monkeypatch.setenv("MCBRIDGE_ETC_DIR", str(etc_dir))
    monkeypatch.setenv("MCBRIDGE_FAILED_ROOT", str(etc_dir / "generated" / "failed"))
    monkeypatch.setenv("MCBRIDGE_WLAN0AP_IP_SERVICE", str(systemd_dir / "wlan0ap-ip.service"))
    monkeypatch.setenv("MCBRIDGE_WLAN0AP_SERVICE", str(systemd_dir / "wlan0ap.service"))
    monkeypatch.setenv("MCBRIDGE_GENERATED_WLAN0AP_IP_SERVICE", str(generated_dir / "wlan0ap-ip.service"))
    monkeypatch.setenv("MCBRIDGE_AGENT_SERVICE", str(systemd_dir / "mcbridge-agent.service"))
    monkeypatch.setenv("MCBRIDGE_POLKIT_RULES", str(etc_dir / "polkit-1" / "rules.d" / "90-mcbridge.rules"))
    monkeypatch.setenv("MCBRIDGE_SUDOERS_DROPIN", str(etc_dir / "sudoers.d" / "mcbridge"))
    monkeypatch.setenv("MCBRIDGE_AGENT_SOCKET", str(socket_path))
    monkeypatch.setenv("MCBRIDGE_WEB_SERVICE", str(systemd_dir / "mcbridge-web.service"))
    monkeypatch.setenv("MCBRIDGE_WEB_TLS_CERT", str(etc_dir / "config/web-cert.pem"))
    monkeypatch.setenv("MCBRIDGE_WEB_TLS_KEY", str(etc_dir / "config/web-key.pem"))

    import mcbridge.paths as mc_paths
    import mcbridge.common as mc_common
    import mcbridge.ap as mc_ap
    import mcbridge.dns as mc_dns
    import mcbridge.init as mc_init

    paths = importlib.reload(mc_paths)
    common = importlib.reload(mc_common)
    ap = importlib.reload(mc_ap)
    dns = importlib.reload(mc_dns)
    init = importlib.reload(mc_init)
    init.SERVICE_HOME = tmp_path / "var" / "lib" / "mcbridge"
    monkeypatch.setattr(
        init,
        "_run_systemctl",
        lambda args, ctx=None: {"command": ["systemctl", *args], "stdout": "", "stderr": "", "returncode": 0},
    )
    return init, ap, dns, common


def test_init_dry_run_reports_agent_artifacts(use_fake_agent, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    agent = use_fake_agent(socket_path=tmp_path / "run" / "mcbridge" / "agent.sock")
    init, _, _, _ = _reload_init(monkeypatch, tmp_path)
    monkeypatch.setattr(
        init,
        "_check_environment",
        lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)),
    )
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)

    result = init.run(
        ssid="DryRunSSID",
        password="password1",
        octet=42,
        channel=6,
        dry_run=True,
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 0
    principals = result.payload["principals"]
    assert principals["agent_socket"]["status"] == "planned"
    assert result.payload["agent_unit"]["unit"]["status"] == "planned"
    assert result.payload["polkit_policy"]["status"] == "planned"
    assert result.payload["operator_policy"]["status"] == "planned"
    assert agent.plans == []


def test_init_applies_agent_and_policies(use_fake_agent, monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    socket_path = tmp_path / "run" / "mcbridge" / "agent.sock"
    agent = use_fake_agent(socket_path=socket_path)
    init, ap, dns, common = _reload_init(monkeypatch, tmp_path)
    monkeypatch.setattr(
        init,
        "_check_environment",
        lambda **kwargs: ([], {"environment": {"ok": True}}, kwargs.get("octet", 50)),
    )
    monkeypatch.setattr(init, "_resolve_target", lambda *_: True)
    monkeypatch.setattr(init, "_run_provisioning_script", lambda **kwargs: {"returncode": 0, "provision_status": "applied"})

    systemctl_calls: list[list[str]] = []

    def _fake_run_systemctl(args):
        systemctl_calls.append(list(args))
        if args and args[0] == "is-enabled":
            return {"command": ["systemctl", *args], "stdout": "disabled", "stderr": "", "returncode": 1}
        if args and args[0] == "is-active":
            return {"command": ["systemctl", *args], "stdout": "active", "stderr": "", "returncode": 0}
        return {"command": ["systemctl", *args], "stdout": "", "stderr": "", "returncode": 0}

    enable_calls: list[dict[str, object]] = []

    def _fake_enable(services, *, runner=None, dry_run=False, start_services=True):
        enable_calls.append({"services": tuple(services), "start_services": start_services})
        statuses = {
            service: {"service": service, "status": "updated", "actions": ["systemctl enable --now " + service], "applied": True}
            for service in services
        }
        return statuses, []

    iptables_rules = "\n".join(
        [
            f"-A POSTROUTING -o {init.UPSTREAM_INTERFACE} -j MASQUERADE",
            f"-A FORWARD -i {init.AP_INTERFACE} -o {init.UPSTREAM_INTERFACE} -j ACCEPT",
            f"-A FORWARD -i {init.UPSTREAM_INTERFACE} -o {init.AP_INTERFACE} -m state --state ESTABLISHED,RELATED -j ACCEPT",
        ]
    )

    def _fake_run_privileged(command):
        stdout = iptables_rules if command and command[0] == "iptables-save" else ""
        return {"command": list(command), "stdout": stdout, "stderr": "", "returncode": 0}

    monkeypatch.setattr(init, "_run_systemctl", _fake_run_systemctl)
    monkeypatch.setattr(init, "ensure_services_enabled", _fake_enable)
    monkeypatch.setattr(init, "_collect_service_states", lambda services: ({svc: {"state": "active"} for svc in services}, []))
    monkeypatch.setattr(init, "_run_privileged", _fake_run_privileged)
    expected_ip = "192.168.51.1/24"

    def _fake_run_command(command):
        stdout = ""
        if command and command[:3] == ["ip", "link", "show"]:
            stdout = "state UP"
        elif command and command[:3] == ["ip", "addr", "show"]:
            stdout = f"inet {expected_ip}"
        elif command and command[0] == "ip":
            stdout = f"inet {expected_ip}"
        return {"command": list(command), "stdout": stdout, "stderr": "", "returncode": 0}

    monkeypatch.setattr(init, "_run_command", _fake_run_command)
    monkeypatch.setattr(init.ap, "update", lambda **__: ap.ApResult(payload={"status": "ok"}, exit_code=0))
    monkeypatch.setattr(init.dns, "update", lambda **__: dns.DnsResult(payload={"status": "ok"}, exit_code=0))

    result = init.run(
        ssid="ApplySSID",
        password="password1",
        octet=51,
        channel=6,
        dry_run=False,
        assume_yes=True,
        debug_json=True,
    )

    assert result.exit_code == 0
    assert init.AGENT_SERVICE_PATH.exists()
    assert init.POLKIT_RULES_PATH.exists()
    assert init.SUDOERS_POLICY_PATH.exists()
    assert init.AGENT_SOCKET_PATH.parent.exists()
    assert any(call[0] == "daemon-reload" for call in systemctl_calls)
    assert any("mcbridge-agent.service" in call for call in systemctl_calls if call and call[0] == "enable")
    assert enable_calls and enable_calls[0]["start_services"] is True
    principals = result.payload["principals"]
    assert principals["agent_socket"]["status"] in {"present", "created", "attempted", "planned", "ok"}
    assert agent.plans  # run + write_file actions for agent-managed operations
    assert common.INITIALISED_MARKER.exists()
