import json
import os
from contextlib import contextmanager

from mcbridge import agent, dns
from mcbridge import ap as ap_module


def test_agent_client_dns_status_in_process(monkeypatch, tmp_path):
    calls: dict[str, object] = {}

    @contextmanager
    def _no_root_switch():
        yield

    def _fake_request(self, payload, *, timeout=None):
        return agent._handle_request(payload)

    def _fake_dns_status(*, debug_json=None):
        calls["debug_json"] = debug_json
        calls["agent_context"] = os.environ.get("MCBRIDGE_AGENT_CONTEXT")
        return dns.DnsResult(payload={"status": "dns"}, exit_code=0)

    def _fail_sudo_run(*args, **kwargs):
        raise AssertionError("sudo_run should not be called")

    monkeypatch.setattr(agent, "_root_privileges", _no_root_switch)
    monkeypatch.setattr(agent.AgentClient, "_request", _fake_request)
    monkeypatch.setattr("mcbridge.dns.status", _fake_dns_status)
    monkeypatch.setattr("mcbridge.privileges.sudo_run", _fail_sudo_run)
    monkeypatch.delenv("MCBRIDGE_AGENT_CONTEXT", raising=False)

    client = agent.AgentClient(socket_path=tmp_path / "agent.sock")
    result = client.run_command(["mcbridge", "dns", "status", "--debug-json"])

    assert result.returncode == 0
    assert json.loads(result.stdout)["status"] == "dns"
    assert calls["debug_json"] is True
    assert calls["agent_context"] == "1"


def test_agent_client_ap_status_in_process(monkeypatch, tmp_path):
    calls: dict[str, object] = {}

    @contextmanager
    def _no_root_switch():
        yield

    def _fake_request(self, payload, *, timeout=None):
        return agent._handle_request(payload)

    def _fake_ap_status(*, debug_json=None):
        calls["debug_json"] = debug_json
        calls["agent_context"] = os.environ.get("MCBRIDGE_AGENT_CONTEXT")
        return ap_module.ApResult(payload={"status": "ap"}, exit_code=1)

    def _fail_sudo_run(*args, **kwargs):
        raise AssertionError("sudo_run should not be called")

    monkeypatch.setattr(agent, "_root_privileges", _no_root_switch)
    monkeypatch.setattr(agent.AgentClient, "_request", _fake_request)
    monkeypatch.setattr("mcbridge.ap.status", _fake_ap_status)
    monkeypatch.setattr("mcbridge.privileges.sudo_run", _fail_sudo_run)
    monkeypatch.delenv("MCBRIDGE_AGENT_CONTEXT", raising=False)

    client = agent.AgentClient(socket_path=tmp_path / "agent.sock")
    result = client.run_command(["mcbridge", "ap", "status"])

    assert result.returncode == 1
    assert json.loads(result.stdout)["status"] == "ap"
    assert calls["debug_json"] is False
    assert calls["agent_context"] == "1"
