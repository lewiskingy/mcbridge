import json
import logging
from http import HTTPStatus

import pytest

from mcbridge import ap, dns
from mcbridge.web import wifi

pytest.importorskip("flask")

from mcbridge.web import create_app
from mcbridge.web.config import WebConfig, load_web_config


def test_ap_status_returns_payload():
    captured: dict[str, object] = {}

    def runner(args):
        captured["args"] = args
        return {"status": "ok", "details": "ready"}, HTTPStatus.OK

    client = create_app(cli_runner=runner).test_client()

    response = client.get("/ap/status")

    assert response.status_code == 200
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["exit_code"] == 0
    assert captured["args"] == ["ap", "status"]


def test_ap_update_validates_positive_integers():
    client = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK)).test_client()

    response = client.post("/ap/update", json={"channel": 0})

    assert response.status_code == 400
    assert "channel" in response.get_json()["message"]


def test_init_run_applies_cli_defaults():
    captured: dict[str, object] = {}

    def runner(args):
        captured["args"] = args
        return {"status": "ok"}, HTTPStatus.OK

    client = create_app(cli_runner=runner).test_client()

    response = client.post("/init", json={"ssid": "NewNet"})

    assert response.status_code == 200
    assert captured["args"][0:2] == ["init", "--ssid"]
    assert "NewNet" in captured["args"]
    assert "--force-restart" in captured["args"]


def test_dns_update_exit_code_sets_conflict():
    client = create_app(
        cli_runner=lambda args: ({"status": "warning", "exit_code": 10}, HTTPStatus.CONFLICT)
    ).test_client()

    response = client.post("/dns/update", json={"redirect": "a.example", "target": "b.example"})

    assert response.status_code == 200
    assert response.get_json()["exit_code"] == 10


def test_authentication_required(monkeypatch: pytest.MonkeyPatch, tmp_path):
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    cert.write_text("cert")
    key.write_text("key")
    config_path = tmp_path / "web.json"
    config_path.write_text(
        '{"tls_cert": "%s", "tls_key": "%s", "auth_token": "secret-token"}' % (cert, key)
    )
    monkeypatch.setenv("MCBRIDGE_WEB_CONFIG", str(config_path))
    app = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK), web_config=load_web_config())
    client = app.test_client()

    response = client.get("/ap/status")

    assert response.status_code == HTTPStatus.UNAUTHORIZED

    authed = client.get("/ap/status", headers={"Authorization": "Bearer secret-token"})
    assert authed.status_code == HTTPStatus.OK


def test_basic_authentication(monkeypatch: pytest.MonkeyPatch, tmp_path):
    config_path = tmp_path / "web.json"
    config_path.write_text('{"auth_password": "bridge-pass"}')
    monkeypatch.setenv("MCBRIDGE_WEB_CONFIG", str(config_path))
    app = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK), web_config=load_web_config())
    client = app.test_client()

    response = client.post("/dns/update", json={"redirect": "a", "target": "b"})
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert response.headers.get("WWW-Authenticate") == 'Basic realm="mcbridge", charset="UTF-8"'

    basic_header = "Basic YXBpOmJyaWRnZS1wYXNz"
    authed = client.post(
        "/dns/update",
        json={"redirect": "a", "target": "b"},
        headers={"Authorization": basic_header},
    )

    assert authed.status_code == HTTPStatus.OK


def test_dns_known_servers_route(monkeypatch: pytest.MonkeyPatch, tmp_path):
    import mcbridge.web as web

    etc_dir = tmp_path / "etc"
    known_servers_path = etc_dir / "config" / "knownservers.json"
    known_servers_path.parent.mkdir(parents=True, exist_ok=True)
    known_servers_path.write_text(
        json.dumps({"redirects": [{"redirect": "local.test", "target": "1.2.3.4"}]}), encoding="utf-8"
    )
    monkeypatch.setenv("MCBRIDGE_ETC_DIR", str(etc_dir))
    monkeypatch.setattr(web, "KNOWN_SERVERS_JSON", known_servers_path)

    app = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK), web_config=load_web_config())

    known_server_rules = [rule for rule in app.url_map.iter_rules() if rule.rule == "/dns/knownservers"]
    assert len(known_server_rules) == 1

    response = app.test_client().get("/dns/knownservers")
    assert response.status_code == HTTPStatus.OK
    data = response.get_json()
    assert data["status"] == "ok"
    assert data["exit_code"] == 0
    assert data["servers"] == [
        {
            "label": "local.test",
            "redirect": "local.test",
            "target": "1.2.3.4",
            "default_target": None,
        }
    ]


def test_combined_status_merges_sections():
    calls: list[list[str]] = []

    def runner(args):
        calls.append(args)
        if args[0] == "ap":
            return {"status": "ok", "ssid": "ap"}, HTTPStatus.OK
        return {"status": "warning", "exit_code": 10}, HTTPStatus.CONFLICT

    client = create_app(cli_runner=runner).test_client()
    response = client.get("/status")

    assert response.status_code == HTTPStatus.OK
    data = response.get_json()
    assert data["status"] == "warning"
    assert data["ap"]["status"] == "ok"
    assert data["dns"]["status"] == "warning"
    assert calls == [["ap", "status"], ["dns", "status"]]


def test_in_process_runner_invokes_domain_handlers(monkeypatch: pytest.MonkeyPatch):
    from mcbridge import ap as ap_module
    from mcbridge.ap import ApResult

    captured: dict[str, object] = {}

    def fake_status(debug_json=None):
        captured["debug_json"] = debug_json
        return ApResult(payload={"status": "ok"}, exit_code=0)

    monkeypatch.setattr(ap_module, "status", fake_status)

    client = create_app().test_client()
    response = client.get("/ap/status?debug_json=1")

    assert response.status_code == HTTPStatus.OK
    assert response.get_json()["status"] == "ok"
    assert captured["debug_json"] is True


def test_permission_errors_are_wrapped(monkeypatch: pytest.MonkeyPatch):
    from mcbridge import ap as ap_module

    def raise_permission(debug_json=None):
        raise PermissionError("needs root")

    monkeypatch.setattr(ap_module, "status", raise_permission)

    client = create_app(use_subprocess_runner=False).test_client()
    response = client.get("/ap/status")

    assert response.status_code == HTTPStatus.FORBIDDEN
    data = response.get_json()
    assert data["status"] == "error"
    assert data["stderr"] == "needs root"
    assert data["exit_code"] == 3


def test_dns_status_permission_error_returns_json(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(dns.os, "geteuid", lambda: 1000)

    client = create_app(use_subprocess_runner=False).test_client()
    response = client.get("/dns/status")

    assert response.status_code == HTTPStatus.FORBIDDEN
    data = response.get_json()
    assert data["status"] == "error"
    assert data["exit_code"] == 3
    assert "require root privileges" in data["message"]


def test_combined_status_surfaces_dns_permission_error(monkeypatch: pytest.MonkeyPatch):
    from mcbridge.ap import ApResult

    monkeypatch.setattr(ap, "status", lambda debug_json=None: ApResult(payload={"status": "ok"}, exit_code=0))

    def dns_status(debug_json=None):
        dns._require_dns_privileges()
        return dns.DnsResult(payload={"status": "ok"}, exit_code=0)

    monkeypatch.setattr(dns, "status", dns_status)
    monkeypatch.setattr(dns.os, "geteuid", lambda: 1000)

    client = create_app(use_subprocess_runner=False).test_client()
    response = client.get("/status")

    assert response.status_code == HTTPStatus.FORBIDDEN
    data = response.get_json()
    assert data["status"] == "error"
    assert data["exit_code"] == 3
    assert "require root privileges" in data["message"]


def test_in_process_permission_error_falls_back_to_subprocess(monkeypatch: pytest.MonkeyPatch):
    import mcbridge.web as web

    calls: dict[str, object] = {"in_process": 0, "subprocess": []}

    def failing_runner(args):
        calls["in_process"] = calls.get("in_process", 0) + 1
        raise PermissionError("needs privileges")

    def subprocess_runner(args):
        calls["subprocess"].append(list(args))
        return {"status": "ok", "exit_code": 0}, HTTPStatus.OK

    monkeypatch.setattr(web, "_invoke_in_process", failing_runner)
    monkeypatch.setattr(web, "_invoke_cli", subprocess_runner)
    monkeypatch.setattr(web.os, "geteuid", lambda: 0)
    monkeypatch.delenv("MCBRIDGE_WEB_USE_SUBPROCESS", raising=False)

    client = create_app().test_client()
    response = client.get("/ap/status")

    assert response.status_code == HTTPStatus.OK
    assert calls["in_process"] == 1
    assert calls["subprocess"] == [["ap", "status"]]


def test_agent_unavailable_falls_back_to_in_process(monkeypatch: pytest.MonkeyPatch):
    import mcbridge.web as web

    calls: dict[str, int] = {"cli": 0, "in_process": 0}

    def failing_cli(args):
        calls["cli"] += 1
        raise web.AgentError("socket unreachable")

    def succeeding_in_process(args):
        calls["in_process"] += 1
        return {"status": "ok", "exit_code": 0}, HTTPStatus.OK

    monkeypatch.setattr(web, "_invoke_cli", failing_cli)
    monkeypatch.setattr(web, "_invoke_in_process", succeeding_in_process)
    monkeypatch.setattr(web.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("MCBRIDGE_WEB_USE_SUBPROCESS", raising=False)

    client = create_app().test_client()
    response = client.get("/ap/status")

    assert response.status_code == HTTPStatus.OK
    assert calls["cli"] == 1
    assert calls["in_process"] == 1


def test_service_unavailable_in_process_falls_back_to_cli(monkeypatch: pytest.MonkeyPatch):
    import mcbridge.web as web

    calls: dict[str, int] = {"in_process": 0, "cli": 0}

    def failing_in_process(args):
        calls["in_process"] += 1
        raise web.WebCommandError("agent down", status=HTTPStatus.SERVICE_UNAVAILABLE, detail={"source": "in-process"})

    def succeeding_cli(args):
        calls["cli"] += 1
        return {"status": "ok", "exit_code": 0, "runner": "cli"}, HTTPStatus.OK

    monkeypatch.setattr(web, "_invoke_in_process", failing_in_process)
    monkeypatch.setattr(web, "_invoke_cli", succeeding_cli)
    monkeypatch.setattr(web.os, "geteuid", lambda: 0)
    monkeypatch.delenv("MCBRIDGE_WEB_USE_SUBPROCESS", raising=False)

    client = create_app().test_client()
    response = client.get("/ap/status")
    data = response.get_json()

    assert response.status_code == HTTPStatus.OK
    assert data["runner"] == "cli"
    assert calls["in_process"] == 1
    assert calls["cli"] == 1


def test_fallback_preserves_original_detail(monkeypatch: pytest.MonkeyPatch):
    import mcbridge.web as web

    def failing_cli(args):
        raise web._agent_unavailable_error(web.AgentError("socket unreachable"))

    def failing_in_process(args):
        raise PermissionError("needs root")

    monkeypatch.setattr(web, "_invoke_cli", failing_cli)
    monkeypatch.setattr(web, "_invoke_in_process", failing_in_process)
    monkeypatch.setattr(web.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("MCBRIDGE_WEB_USE_SUBPROCESS", raising=False)

    client = create_app().test_client()
    response = client.get("/ap/status")
    data = response.get_json()

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert data["status"] == "error"
    assert data["detail"]["fallback_from"]["agent_socket"]


def test_wifi_profiles_crud(monkeypatch: pytest.MonkeyPatch, tmp_path):
    import mcbridge.web as web

    config_dir = tmp_path / "etc" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    wifi_path = config_dir / "upstream_wifi.json"
    monkeypatch.setattr(wifi, "UPSTREAM_WIFI_JSON", wifi_path)

    client = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK)).test_client()

    empty = client.get("/wifi/profiles")
    assert empty.status_code == HTTPStatus.OK
    assert empty.get_json()["profiles"] == []

    added = client.post(
        "/wifi/profiles",
        json={"ssid": "HomeNet", "priority": 10, "security": "wpa2", "active": True},
    )
    assert added.status_code == HTTPStatus.OK
    added_payload = added.get_json()
    assert added_payload["profiles"][0]["ssid"] == "HomeNet"
    assert added_payload["profiles"][0]["active"] is True
    assert added_payload["profiles"][0]["priority"] == 10

    updated = client.patch(
        "/wifi/profiles",
        json={"ssid": "HomeNet", "priority": 5, "active": False},
    )
    assert updated.status_code == HTTPStatus.OK
    updated_payload = updated.get_json()
    assert updated_payload["profiles"][0]["active"] is False
    assert updated_payload["profiles"][0]["priority"] == 5

    removed = client.delete("/wifi/profiles", json={"ssid": "HomeNet"})
    assert removed.status_code == HTTPStatus.OK
    assert removed.get_json()["profiles"] == []


def test_wifi_profiles_validation(monkeypatch: pytest.MonkeyPatch, tmp_path):
    import mcbridge.web as web

    config_dir = tmp_path / "etc" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    wifi_path = config_dir / "upstream_wifi.json"
    monkeypatch.setattr(wifi, "UPSTREAM_WIFI_JSON", wifi_path)

    client = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK)).test_client()

    missing_security = client.post("/wifi/profiles", json={"ssid": "Net", "priority": 1})
    assert missing_security.status_code == HTTPStatus.BAD_REQUEST

    bad_priority = client.post("/wifi/profiles", json={"ssid": "Net", "priority": 0, "security": "wpa2"})
    assert bad_priority.status_code == HTTPStatus.BAD_REQUEST

    client.post("/wifi/profiles", json={"ssid": "Net", "priority": 1, "security": "wpa2"})
    duplicate = client.post("/wifi/profiles", json={"ssid": "Net", "priority": 2, "security": "wpa2"})
    assert duplicate.status_code == HTTPStatus.BAD_REQUEST

    no_fields = client.patch("/wifi/profiles", json={"ssid": "Net"})
    assert no_fields.status_code == HTTPStatus.BAD_REQUEST



def test_upstream_profiles_crud(monkeypatch: pytest.MonkeyPatch, tmp_path):
    import mcbridge.web as web

    config_dir = tmp_path / "etc" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    upstream_path = config_dir / "upstream_networks.json"
    monkeypatch.setattr(web.upstream, "UPSTREAM_NETWORKS_JSON", upstream_path)
    monkeypatch.setattr(web.upstream, "LEGACY_UPSTREAM_JSON", upstream_path)

    client = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK)).test_client()

    empty = client.get("/upstream/profiles")
    assert empty.status_code == HTTPStatus.OK
    assert empty.get_json()["profiles"] == []

    added = client.post(
        "/upstream/profiles",
        json={"ssid": "Home", "priority": 10, "security": "wpa2", "password": "secret"},
    )
    assert added.status_code == HTTPStatus.OK
    added_payload = added.get_json()
    assert added_payload["profiles"][0]["ssid"] == "Home"
    assert added_payload["profiles"][0]["has_password"] is True

    updated = client.patch(
        "/upstream/profiles",
        json={"ssid": "Home", "priority": 3, "password": "newpass", "security": "wpa3"},
    )
    assert updated.status_code == HTTPStatus.OK
    updated_payload = updated.get_json()
    assert updated_payload["profiles"][0]["priority"] == 3
    assert updated_payload["profiles"][0]["security"] == "wpa3"

    removed = client.delete("/upstream/profiles", json={"ssid": "Home"})
    assert removed.status_code == HTTPStatus.OK
    assert removed.get_json()["profiles"] == []


def test_upstream_profiles_validation(monkeypatch: pytest.MonkeyPatch, tmp_path):
    import mcbridge.web as web

    config_dir = tmp_path / "etc" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    upstream_path = config_dir / "upstream_networks.json"
    monkeypatch.setattr(web.upstream, "UPSTREAM_NETWORKS_JSON", upstream_path)
    monkeypatch.setattr(web.upstream, "LEGACY_UPSTREAM_JSON", upstream_path)

    client = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK)).test_client()

    missing_password = client.post(
        "/upstream/profiles", json={"ssid": "Secure", "priority": 1, "security": "wpa2", "password": ""}
    )
    assert missing_password.status_code == HTTPStatus.BAD_REQUEST

    bad_priority = client.post("/upstream/profiles", json={"ssid": "Open", "priority": 0, "security": "open"})
    assert bad_priority.status_code == HTTPStatus.BAD_REQUEST

    client.post("/upstream/profiles", json={"ssid": "Open", "priority": 1, "security": "open", "password": ""})
    duplicate = client.post(
        "/upstream/profiles", json={"ssid": "Open", "priority": 2, "security": "open", "password": ""}
    )
    assert duplicate.status_code == HTTPStatus.BAD_REQUEST

    no_fields = client.patch("/upstream/profiles", json={"ssid": "Open"})
    assert no_fields.status_code == HTTPStatus.BAD_REQUEST


def test_upstream_status_with_system_profiles(monkeypatch: pytest.MonkeyPatch, tmp_path):
    import mcbridge.web as web

    config_dir = tmp_path / "etc" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    upstream_path = config_dir / "upstream_networks.json"
    monkeypatch.setattr(web.upstream, "UPSTREAM_NETWORKS_JSON", upstream_path)
    monkeypatch.setattr(web.upstream, "LEGACY_UPSTREAM_JSON", upstream_path)

    web.upstream.add_profile(ssid="Saved", password="secret", priority=2, security="wpa2", path=upstream_path)
    system_profile = web.upstream.DiscoveredProfile(
        ssid="Live", priority=5, security="wpa3", password="secret", source="nmcli"
    )
    monkeypatch.setattr(web.upstream, "discover_system_profiles", lambda: ([system_profile], [], {}))

    client = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK)).test_client()
    status = client.get("/upstream/status")
    assert status.status_code == HTTPStatus.OK
    payload = status.get_json()
    assert payload["profiles"][0]["ssid"] == "Live"
    assert payload["drift"]["missing_in_storage"] == ["Live"]
    assert payload["drift"]["missing_in_system"] == ["Saved"]


def test_upstream_save_current(monkeypatch: pytest.MonkeyPatch, tmp_path):
    import mcbridge.web as web

    config_dir = tmp_path / "etc" / "config"
    config_dir.mkdir(parents=True, exist_ok=True)
    upstream_path = config_dir / "upstream_networks.json"
    monkeypatch.setattr(web.upstream, "UPSTREAM_NETWORKS_JSON", upstream_path)
    monkeypatch.setattr(web.upstream, "LEGACY_UPSTREAM_JSON", upstream_path)

    system_profile = web.upstream.DiscoveredProfile(
        ssid="SystemNet", priority=7, security="wpa2", password="secret", source="nmcli"
    )
    monkeypatch.setattr(web.upstream, "discover_system_profiles", lambda: ([system_profile], [], {}))

    client = create_app(cli_runner=lambda args: ({}, HTTPStatus.OK)).test_client()
    response = client.post("/upstream/save-current")
    assert response.status_code == HTTPStatus.OK
    saved_payload = response.get_json()
    assert saved_payload["profiles"][0]["ssid"] == "SystemNet"
    stored = json.loads(upstream_path.read_text())
    assert stored["profiles"][0]["ssid"] == "SystemNet"


def test_agent_unavailable_error_includes_hint(monkeypatch: pytest.MonkeyPatch):
    import mcbridge.web as web

    monkeypatch.setenv("MCBRIDGE_AGENT_SOCKET", "/tmp/test-agent.sock")
    hint = "agent socket reachable?"

    exc = web.AgentError("socket unreachable")
    error = web._agent_unavailable_error(exc, hint=hint)

    assert hint in str(error)
    assert "socket unreachable" in str(error)
    assert error.stderr == "socket unreachable"
    assert error.detail["agent_socket"] == "/tmp/test-agent.sock"
    assert error.detail["hint"] == hint
    assert error.detail["error"] == "socket unreachable"
    assert error.status == HTTPStatus.SERVICE_UNAVAILABLE

def test_subprocess_runner_auto_selected_for_non_root(monkeypatch: pytest.MonkeyPatch):
    import mcbridge.web as web

    calls: list[list[str]] = []

    def fake_cli(args):
        calls.append(list(args))
        return {"status": "ok", "exit_code": 0}, HTTPStatus.OK

    monkeypatch.setattr(web, "_invoke_cli", fake_cli)
    monkeypatch.setattr(web.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("MCBRIDGE_WEB_USE_SUBPROCESS", raising=False)

    client = create_app().test_client()
    response = client.get("/ap/status")

    assert response.status_code == HTTPStatus.OK
    assert calls == [["ap", "status"]]

def test_status_uses_agent_runner(monkeypatch: pytest.MonkeyPatch):
    import mcbridge.web as web

    class FakeResult:
        def __init__(self, payload):
            self.returncode = 0
            self.stdout = json.dumps(payload)
            self.stderr = ""

    class FakeAgent:
        def __init__(self):
            self.commands: list[list[str]] = []

        def run_command(self, command, env=None):
            self.commands.append(list(command))
            return FakeResult({"status": "ok"})

    fake_agent = FakeAgent()

    monkeypatch.setattr(web, "_agent_client", lambda timeout=None: fake_agent)
    monkeypatch.setattr(web.os, "geteuid", lambda: 1000)
    monkeypatch.delenv("MCBRIDGE_WEB_USE_SUBPROCESS", raising=False)

    client = create_app().test_client()
    response = client.get("/status")

    assert response.status_code == HTTPStatus.OK
    assert len(fake_agent.commands) == 2
    joined_commands = " ".join(fake_agent.commands[0])
    assert "ap status" in joined_commands
    assert any("dns status" in " ".join(cmd) for cmd in fake_agent.commands)
    data = response.get_json()
    assert data["status"] == "ok"


def test_main_avoids_https_without_cert(monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture):
    import mcbridge.web as web

    captured: dict[str, object] = {}

    def fake_serve_app(app, *, host, https_port, ssl_context, http_port, debug):
        captured.update(
            {
                "host": host,
                "https_port": https_port,
                "ssl_context": ssl_context,
                "http_port": http_port,
                "debug": debug,
            }
        )

    monkeypatch.setattr(web, "_serve_app", fake_serve_app)
    monkeypatch.setattr(web, "load_web_config", lambda: WebConfig())
    caplog.set_level(logging.INFO)

    web.main(["--host", "127.0.0.1", "--port", "4443", "--http-port", "8080"])

    assert captured["https_port"] is None
    assert captured["ssl_context"] is None
    assert captured["http_port"] == 8080
    assert "TLS unavailable; ignoring --port=4443 and listening for HTTP on --http-port=8080 instead." in caplog.text
