from http import HTTPStatus

import pytest

from mcbridge import ap, cli, dns, init
from mcbridge import privileges
from mcbridge.agent import AgentError
from mcbridge.web import create_app
from mcbridge.web.config import WebConfig


def test_cli_commands_use_agent_socket(use_fake_agent, monkeypatch):
    agent = use_fake_agent()

    def _stub_ap_update(**_):
        privileges.sudo_run(["ip", "link", "show", "wlan0ap"])
        return ap.ApResult(payload={"status": "ok", "source": "ap"}, exit_code=0)

    def _stub_dns_update(**_):
        privileges.sudo_run(["ip", "link", "show", "wlan0ap"])
        return dns.DnsResult(payload={"status": "ok", "source": "dns"}, exit_code=0)

    def _stub_init_run(**_):
        privileges.sudo_run(["ip", "link", "show", "wlan0ap"])
        return init.InitResult(payload={"status": "ok", "source": "init"}, exit_code=0)

    monkeypatch.setattr(ap, "update", _stub_ap_update)
    monkeypatch.setattr(dns, "update", _stub_dns_update)
    monkeypatch.setattr(init, "run", _stub_init_run)

    commands = [
        ["--agent-socket", str(agent.socket_path), "--agent-timeout", "1", "ap", "update", "--dry-run"],
        ["--agent-socket", str(agent.socket_path), "--agent-timeout", "1", "dns", "update"],
        [
            "--agent-socket",
            str(agent.socket_path),
            "--agent-timeout",
            "1",
            "init",
            "--ssid",
            "TestSSID",
            "--password",
            "password1",
            "--octet",
            "50",
            "--channel",
            "6",
            "--yes",
        ],
    ]

    for argv in commands:
        with pytest.raises(SystemExit) as excinfo:
            cli.main(argv)
        assert excinfo.value.code == 0

    assert len(agent.plans) == len(commands)
    for entry in agent.plans:
        assert entry["steps"][0]["action"] == "run"
        assert entry["steps"][0]["command"][0] == "ip"


def test_cli_agent_error_sets_exit_code(use_fake_agent, monkeypatch):
    agent = use_fake_agent(error=AgentError("agent down"))

    def _stub_dns_update(**_):
        privileges.sudo_run(["ip", "link", "show", "wlan0ap"])
        return dns.DnsResult(payload={"status": "ok"}, exit_code=0)

    monkeypatch.setattr(dns, "update", _stub_dns_update)

    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--agent-socket", str(agent.socket_path), "dns", "update"])

    assert excinfo.value.code == 3
    assert agent.plans == []


def test_web_maps_agent_failure_to_service_unavailable(monkeypatch):
    def _failing_runner(_):
        raise AgentError("agent unreachable")

    app = create_app(cli_runner=_failing_runner, web_config=WebConfig())
    client = app.test_client()

    response = client.post("/ap/update", json={})

    assert response.status_code == HTTPStatus.SERVICE_UNAVAILABLE
    payload = response.get_json()
    assert payload["status"] == "error"
    assert payload["exit_code"] == 3
