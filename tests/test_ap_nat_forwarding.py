import pytest


def test_update_reapplies_missing_nat_rule(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")

    commands: list[list[str]] = []

    def fake_run_command(command):
        commands.append(command)
        if command and command[0] == "iptables-save":
            return {"command": command, "stdout": "*nat\nCOMMIT\n*filter\nCOMMIT\n", "stderr": "", "returncode": 0}
        if command and command[0] == "iptables":
            return {"command": command, "stdout": "", "stderr": "", "returncode": 1 if "-C" in command else 0}
        if command and command[0] == "sysctl":
            key = command[-1]
            if key == "net.ipv4.ip_forward":
                return {"command": command, "stdout": "1\n", "stderr": "", "returncode": 0}
            if key == "net.ipv4.ip_forward=1":
                return {"command": command, "stdout": "net.ipv4.ip_forward = 1\n", "stderr": "", "returncode": 0}
        return {"command": command, "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(ap, "_run_command", fake_run_command)
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})
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
    monkeypatch.setattr(
        ap,
        "_sync_wlan0ap_ip_service",
        lambda *_, **__: {"status": "unchanged", "applied": True, "ip_matches": True, "service_enabled": True},
    )
    monkeypatch.setattr(
        ap, "_restart_dnsmasq_after_wlan0ap_ip", lambda **__: ({"service": "dnsmasq", "status": "skipped"}, False, None)
    )
    monkeypatch.setattr(ap, "save_json", lambda *_, **__: None)
    monkeypatch.setattr(ap, "read_system_ap_config", lambda include_sources=False: ({"ssid": "stored"}, {"hostapd": {}, "dnsmasq": {}}))

    result = ap.update(dry_run=False, debug_json=True)

    nat_applied = any(
        command
        for command in commands
        if command
        and command[0] == "iptables"
        and "-A" in command
        and "MASQUERADE" in command
        and ap.UPSTREAM_INTERFACE in command
    )
    assert nat_applied
    assert result.payload["changes"]["iptables"]["status"] == "ok"
    assert "NAT/forwarding rules were missing" in (result.payload["message"] or "")


def _stub_update_dependencies(ap, monkeypatch: pytest.MonkeyPatch, *, config: dict | None = None):
    monkeypatch.setattr(ap, "_ensure_ap_interface", lambda **__: {"status": "present", "created": False})
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
    monkeypatch.setattr(
        ap,
        "_sync_wlan0ap_ip_service",
        lambda *_, **__: {"status": "unchanged", "applied": True, "ip_matches": True, "service_enabled": True},
    )
    monkeypatch.setattr(
        ap, "_restart_dnsmasq_after_wlan0ap_ip", lambda **__: ({"service": "dnsmasq", "status": "skipped"}, False, None)
    )
    monkeypatch.setattr(ap, "_post_apply_verification", lambda *_, **__: {})
    monkeypatch.setattr(ap, "_post_apply_warning", lambda *_: None)
    monkeypatch.setattr(ap, "save_json", lambda *_, **__: None)
    monkeypatch.setattr(
        ap, "read_system_ap_config", lambda include_sources=False: (config or {"ssid": "stored"}, {"hostapd": {}, "dnsmasq": {}})
    )


def test_nat_inspection_permission_error_does_not_block_update(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")

    commands: list[list[str]] = []

    def fake_run_command(command):
        commands.append(command)
        if command and command[0] == "iptables-save":
            return {"command": command, "stdout": "", "stderr": "permission denied", "returncode": None, "error": "permission denied"}
        if command and command[0] == "iptables":
            return {"command": command, "stdout": "", "stderr": "", "returncode": 1 if "-C" in command else 0}
        if command and command[0] == "sysctl":
            key = command[-1]
            if key == "net.ipv4.ip_forward":
                return {"command": command, "stdout": "1\n", "stderr": "", "returncode": 0}
            if key == "net.ipv4.ip_forward=1":
                return {"command": command, "stdout": "net.ipv4.ip_forward = 1\n", "stderr": "", "returncode": 0}
        return {"command": command, "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(ap, "_run_command", fake_run_command)
    _stub_update_dependencies(ap, monkeypatch)

    result = ap.update(dry_run=False, debug_json=True)

    nat_applied = any(
        command
        for command in commands
        if command
        and command[0] == "iptables"
        and "-A" in command
        and "MASQUERADE" in command
        and ap.UPSTREAM_INTERFACE in command
    )
    assert nat_applied
    assert result.exit_code == 0
    assert result.payload["changes"]["iptables"]["status"] == "ok"
    assert "iptables inspection failed" in (result.payload["message"] or "")


def test_nat_inspection_exit_failure_uses_uplink_interface(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored"}', encoding="utf-8")
    monkeypatch.setattr(ap, "UPSTREAM_INTERFACE", ap.AP_INTERFACE)

    commands: list[list[str]] = []

    def fake_run_command(command):
        commands.append(command)
        if command and command[0] == "iptables-save":
            return {"command": command, "stdout": "", "stderr": "mock failure", "returncode": 1}
        if command and command[0] == "iptables":
            return {"command": command, "stdout": "", "stderr": "", "returncode": 1 if "-C" in command else 0}
        if command and command[0] == "sysctl":
            key = command[-1]
            if key == "net.ipv4.ip_forward":
                return {"command": command, "stdout": "1\n", "stderr": "", "returncode": 0}
            if key == "net.ipv4.ip_forward=1":
                return {"command": command, "stdout": "net.ipv4.ip_forward = 1\n", "stderr": "", "returncode": 0}
        return {"command": command, "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(ap, "_run_command", fake_run_command)
    _stub_update_dependencies(ap, monkeypatch)

    result = ap.update(dry_run=False, debug_json=True)

    nat_commands = [
        command for command in commands if command and command[0] == "iptables" and "-A" in command and "MASQUERADE" in command
    ]
    assert any("eth0" in command for command in nat_commands)
    assert all(ap.AP_INTERFACE not in command for command in nat_commands)
    assert result.exit_code == 0
    assert result.payload["changes"]["iptables"]["status"] == "ok"


def test_missing_nat_rules_use_configured_uplink(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, ap, _ = mcbridge_modules
    ap.AP_JSON.parent.mkdir(parents=True, exist_ok=True)
    ap.AP_JSON.write_text('{"ssid": "stored", "upstream_interface": "eth0"}', encoding="utf-8")

    commands: list[list[str]] = []

    def fake_run_command(command):
        commands.append(command)
        if command and command[0] == "iptables-save":
            return {"command": command, "stdout": "*nat\nCOMMIT\n*filter\nCOMMIT\n", "stderr": "", "returncode": 0}
        if command and command[0] == "iptables":
            return {"command": command, "stdout": "", "stderr": "", "returncode": 1 if "-C" in command else 0}
        if command and command[0] == "sysctl":
            key = command[-1]
            if key == "net.ipv4.ip_forward":
                return {"command": command, "stdout": "1\n", "stderr": "", "returncode": 0}
            if key == "net.ipv4.ip_forward=1":
                return {"command": command, "stdout": "net.ipv4.ip_forward = 1\n", "stderr": "", "returncode": 0}
        if command and command[0] == "ip":
            if "-j" in command:
                return {"command": command, "stdout": '[{"dst":"default","dev":"eth0"}]', "stderr": "", "returncode": 0}
            return {"command": command, "stdout": "default via 0.0.0.0 dev eth0", "stderr": "", "returncode": 0}
        return {"command": command, "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(ap, "_run_command", fake_run_command)
    _stub_update_dependencies(
        ap,
        monkeypatch,
        config={"ssid": "stored", "upstream_interface": "eth0"},
    )

    result = ap.update(dry_run=False, debug_json=True)

    nat_commands = [
        command for command in commands if command and command[0] == "iptables" and "-A" in command and "MASQUERADE" in command
    ]
    assert any("eth0" in command for command in nat_commands)
    assert all(ap.AP_INTERFACE not in command for command in nat_commands)
    assert result.payload["changes"]["iptables"]["nat_interface"] == "eth0"
    assert result.payload["changes"]["iptables"]["status"] == "ok"
    assert result.exit_code == 0
    assert "warning" not in (result.payload["message"] or "").lower()
