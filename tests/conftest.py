import base64
import importlib
import logging
import sys
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
PACKAGE_ROOT = ROOT / "mcbridge"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from mcbridge import privileges  # noqa: E402
from mcbridge.agent import AgentError  # noqa: E402


class _ListHandler(logging.Handler):
    def __init__(self):
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record):  # pragma: no cover - logging internals
        self.records.append(record)


@pytest.fixture
def mcbridge_modules(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    etc_dir = tmp_path / "etc"
    monkeypatch.setenv("MCBRIDGE_ETC_DIR", str(etc_dir))
    monkeypatch.setenv("MCBRIDGE_FAILED_ROOT", str(etc_dir / "generated" / "failed"))
    monkeypatch.setenv("MCBRIDGE_WLAN0AP_IP_SERVICE", str(etc_dir / "systemd/system/wlan0ap-ip.service"))
    monkeypatch.setenv("MCBRIDGE_GENERATED_WLAN0AP_IP_SERVICE", str(etc_dir / "generated" / "wlan0ap-ip.service"))
    monkeypatch.setenv("MCBRIDGE_HOSTAPD_DEFAULT", str(etc_dir / "default" / "hostapd"))
    monkeypatch.setenv("MCBRIDGE_UPSTREAM_WPA_CONF", str(etc_dir / "wpa_supplicant-wlan0.conf"))
    monkeypatch.setenv("MCBRIDGE_GENERATED_UPSTREAM_WPA_CONF", str(etc_dir / "generated" / "wpa_supplicant-wlan0.conf"))

    import mcbridge.ap as mc_ap
    import mcbridge.common as mc_common
    import mcbridge.dns as mc_dns
    import mcbridge.paths as mc_paths
    import mcbridge.upstream as mc_upstream

    paths = importlib.reload(mc_paths)
    common = importlib.reload(mc_common)
    ap = importlib.reload(mc_ap)
    dns = importlib.reload(mc_dns)
    upstream = importlib.reload(mc_upstream)

    upstream.UPSTREAM_NETWORKS_JSON = etc_dir / "config" / "upstream_networks.json"
    upstream.LEGACY_UPSTREAM_JSON = upstream.UPSTREAM_NETWORKS_JSON

    hostapd_active = etc_dir / "hostapd.conf"
    dnsmasq_active = etc_dir / "dnsmasq.conf"
    overrides_conf = etc_dir / "dnsmasq-mcbridge.conf"
    for module in (common, ap, dns):
        module.HOSTAPD_ACTIVE_CONF = hostapd_active
        module.DNSMASQ_ACTIVE_CONF = dnsmasq_active
        module.DNSMASQ_OVERRIDES_CONF = overrides_conf

    def fake_sudo_write_file(path, contents, *, mode=0o664, owner=None, group=None):
        target = Path(path)
        target.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(contents, (bytes, bytearray)):
            target.write_bytes(contents)
        else:
            target.write_text(str(contents), encoding="utf-8")
        target.chmod(mode)

    monkeypatch.setattr(ap.privileges, "sudo_write_file", fake_sudo_write_file)

    def fake_run_command(command):
        if command and command[0] == "iptables-save":
            rules = "\n".join(
                [
                    "*nat",
                    f"-A POSTROUTING -o {ap.UPSTREAM_INTERFACE} -j MASQUERADE",
                    "COMMIT",
                    "*filter",
                    f"-A FORWARD -i {ap.AP_INTERFACE} -o {ap.UPSTREAM_INTERFACE} -j ACCEPT",
                    f"-A FORWARD -i {ap.UPSTREAM_INTERFACE} -o {ap.AP_INTERFACE} -m state --state ESTABLISHED,RELATED -j ACCEPT",
                    "COMMIT",
                ]
            )
            return {"command": command, "stdout": rules, "stderr": "", "returncode": 0}
        if command and command[0] == "sysctl":
            key = command[-1]
            if key == "net.ipv4.ip_forward":
                return {"command": command, "stdout": "1\n", "stderr": "", "returncode": 0}
            if key == "net.ipv4.ip_forward=1":
                return {"command": command, "stdout": "net.ipv4.ip_forward = 1\n", "stderr": "", "returncode": 0}
        return {"command": command, "stdout": "", "stderr": "", "returncode": 0}

    monkeypatch.setattr(ap, "_run_command", fake_run_command)

    def fake_service_enablement(services, *, runner=None, dry_run=False, start_services=True):
        statuses = {}
        for service in services:
            statuses[service] = {
                "service": service,
                "status": "ok",
                "state": "enabled",
                "actions": [f"systemctl is-enabled {service}"],
                "is_enabled": {
                    "command": ["systemctl", "is-enabled", service],
                    "stdout": "enabled",
                    "stderr": "",
                    "returncode": 0,
                },
                "applied": False,
            }
        return statuses, []

    monkeypatch.setattr(ap, "ensure_services_enabled", fake_service_enablement)

    return paths, common, ap, dns


@pytest.fixture
def log_handler():
    return _ListHandler()


@pytest.fixture
def log_capture(log_handler: _ListHandler, mcbridge_modules):
    _, common, _, _ = mcbridge_modules
    common.logger.addHandler(log_handler)
    try:
        yield log_handler
    finally:
        common.logger.removeHandler(log_handler)


class FakeAgentClient:
    def __init__(self, socket_path: Path, *, error: Exception | None = None):
        self.socket_path = Path(socket_path)
        self.socket_path.parent.mkdir(parents=True, exist_ok=True)
        self.socket_path.write_text("", encoding="utf-8")
        self.error = error
        self.plans: list[dict[str, object]] = []

    def ping(self):
        if isinstance(self.error, AgentError):
            raise self.error
        return {"status": "ok"}

    def _write_file(self, step: dict[str, object]) -> None:
        path = Path(step.get("path") or "")
        contents = step.get("contents") or ""
        binary = bool(step.get("binary"))
        path.parent.mkdir(parents=True, exist_ok=True)
        if binary:
            data = base64.b64decode(contents)
            path.write_bytes(data)
        else:
            path.write_text(str(contents), encoding="utf-8")
        mode = step.get("mode")
        if mode is not None:
            path.chmod(int(mode))

    def _simulate_install_directory(self, command: list[str]) -> None:
        if "install" not in command or "-d" not in command:
            return
        target = Path(command[-1])
        target.mkdir(parents=True, exist_ok=True)
        mode_arg = next((part for part in command if part.startswith("-m")), None)
        if mode_arg:
            try:
                target.chmod(int(mode_arg.lstrip("-m"), 8))
            except ValueError:
                target.chmod(0o755)
        if "--socket" in command:
            socket_arg = command[command.index("--socket") + 1]
            Path(socket_arg).parent.mkdir(parents=True, exist_ok=True)

    def apply_plan(self, steps, timeout=None):
        if self.error:
            raise self.error

        results: list[dict[str, object]] = []
        for step in steps:
            action = step.get("action")
            if action == "write_file":
                self._write_file(step)
            elif action == "run":
                command = step.get("command") or []
                if isinstance(command, list):
                    self._simulate_install_directory(command)
            results.append({"returncode": 0, "stdout": "", "stderr": ""})
        self.plans.append({"steps": [dict(step) for step in steps], "timeout": timeout})
        return {"status": "ok", "results": results}


@pytest.fixture
def use_fake_agent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    def _factory(*, socket_path: Path | None = None, error: Exception | None = None) -> FakeAgentClient:
        socket = socket_path or (tmp_path / "agent.sock")
        agent = FakeAgentClient(socket, error=error)
        monkeypatch.setenv("MCBRIDGE_AGENT_SOCKET", str(socket))
        monkeypatch.setenv("MCBRIDGE_AGENT_TIMEOUT", "1")
        monkeypatch.setattr(privileges.os, "geteuid", lambda: 1000)
        monkeypatch.setattr(privileges, "_cached_client", lambda _socket, _timeout: agent)
        return agent

    return _factory
