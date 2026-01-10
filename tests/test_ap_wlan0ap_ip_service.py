import json
from pathlib import Path


def test_sync_wlan0ap_ip_service_flushes_previous_addresses(monkeypatch, mcbridge_modules):
    _, _, ap, _ = mcbridge_modules
    desired_ip = "192.168.77.1/24"
    commands: list[list[str]] = []

    def fake_run_command(command):
        commands.append(command)
        if command[:3] == ["ip", "-j", "addr"]:
            payload = [
                {
                    "ifname": ap.AP_INTERFACE,
                    "addr_info": [{"family": "inet", "local": "192.168.77.1", "prefixlen": 24}],
                }
            ]
            return {"command": " ".join(command), "stdout": json.dumps(payload), "stderr": "", "returncode": 0}
        return {"command": " ".join(command), "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(ap, "_run_command", fake_run_command)

    result = ap._sync_wlan0ap_ip_service(desired_ip, dry_run=False)

    contents = ap.WLAN0AP_IP_SERVICE.read_text()
    assert "ExecStartPre=/sbin/ip addr flush dev wlan0ap scope global" in contents
    assert result["ip_matches"] is True
    assert any(cmd[:2] == ["systemctl", "restart"] for cmd in commands)
    assert any(cmd[:3] == ["ip", "-j", "addr"] for cmd in commands)


def test_sync_wlan0ap_ip_service_uses_privileged_writer(monkeypatch, mcbridge_modules):
    _, _, ap, _ = mcbridge_modules
    desired_ip = "192.168.55.1/24"
    writes: list[dict[str, object]] = []

    def fake_run_command(command):
        if command[:3] == ["ip", "-j", "addr"]:
            payload = [
                {
                    "ifname": ap.AP_INTERFACE,
                    "addr_info": [{"family": "inet", "local": "192.168.55.1", "prefixlen": 24}],
                }
            ]
            return {"command": " ".join(command), "stdout": json.dumps(payload), "stderr": "", "returncode": 0}
        return {"command": " ".join(command), "stdout": "", "stderr": "", "returncode": 0}

    def tracking_sudo_write_file(path, contents, *, mode=0o644, owner=None, group=None):
        writes.append({"path": Path(path), "mode": mode, "owner": owner, "group": group})
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(str(contents), encoding="utf-8")

    monkeypatch.setattr(ap, "_run_command", fake_run_command)
    monkeypatch.setattr(ap.privileges, "sudo_write_file", tracking_sudo_write_file)

    result = ap._sync_wlan0ap_ip_service(desired_ip, dry_run=False)

    written_paths = {entry["path"] for entry in writes}
    assert ap.WLAN0AP_IP_SERVICE in written_paths
    assert ap.WLAN0AP_IP_GENERATED in written_paths
    assert all(entry["mode"] == 0o644 for entry in writes)
    assert result["ip_matches"] is True
