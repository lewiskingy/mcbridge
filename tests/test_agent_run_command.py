import logging
from contextlib import contextmanager

from mcbridge import agent


def test_agent_runs_mcbridge_command_with_privileges(monkeypatch):
    executed: dict[str, object] = {}
    capability_snapshot = agent._CapabilitySnapshot(effective=0x1A, permitted=0x2B)
    snapshots = [capability_snapshot, capability_snapshot]
    drops: list[tuple[agent._CapabilitySnapshot, agent._CapabilitySnapshot]] = []

    @contextmanager
    def _no_root_switch():
        raise AssertionError("mcbridge CLI should not escalate parent process")
        yield

    monkeypatch.setattr(agent, "_capability_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(agent, "_log_capability_drop", lambda prev, curr: drops.append((prev, curr)))
    monkeypatch.setattr(agent, "_root_privileges", _no_root_switch)
    monkeypatch.setattr(agent.os, "geteuid", lambda: 2001)
    monkeypatch.setattr(agent.os, "getegid", lambda: 3001)
    set_calls: list[tuple[str, int]] = []
    monkeypatch.setattr(agent.os, "seteuid", lambda value: set_calls.append(("euid", value)))
    monkeypatch.setattr(agent.os, "setegid", lambda value: set_calls.append(("egid", value)))

    def fake_run(command, capture_output=True, text=True, input=None, env=None, timeout=None, preexec_fn=None):
        executed["command"] = command
        executed["env"] = env
        executed["timeout"] = timeout
        if preexec_fn:
            preexec_fn()
        return type("Result", (), {"returncode": 0, "stdout": "cli ok", "stderr": ""})()

    monkeypatch.setattr(agent.subprocess, "run", fake_run)

    response = agent._run_command({"command": ["mcbridge", "dns", "status"], "env": {"EXTRA": "1"}, "timeout": 5})

    assert response["status"] == "ok"
    assert response["returncode"] == 0
    assert response["stdout"] == "cli ok"
    assert executed["command"] == ["mcbridge", "dns", "status"]
    assert executed["env"]["MCBRIDGE_AGENT_CONTEXT"] == "1"
    assert executed["env"]["EXTRA"] == "1"
    assert ("egid", 0) in set_calls
    assert ("euid", 0) in set_calls
    assert drops == [(capability_snapshot, capability_snapshot)]


def test_agent_client_unwraps_bash_for_mcbridge(monkeypatch, tmp_path):
    executed: dict[str, object] = {}
    capability_snapshot = agent._CapabilitySnapshot(effective=0x2, permitted=0x2)
    snapshots = [capability_snapshot, capability_snapshot]

    @contextmanager
    def _no_root_switch():
        raise AssertionError("mcbridge CLI should not escalate parent process")
        yield

    def _fake_request(self, payload, *, timeout=None):
        return agent._handle_request(payload)

    monkeypatch.setattr(agent, "_capability_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(agent, "_root_privileges", _no_root_switch)
    monkeypatch.setattr(agent.AgentClient, "_request", _fake_request)
    monkeypatch.setattr(agent.os, "geteuid", lambda: 1001)
    monkeypatch.setattr(agent.os, "getegid", lambda: 1002)
    set_calls: list[tuple[str, int]] = []
    monkeypatch.setattr(agent.os, "seteuid", lambda value: set_calls.append(("euid", value)))
    monkeypatch.setattr(agent.os, "setegid", lambda value: set_calls.append(("egid", value)))

    def fake_run(command, capture_output=True, text=True, input=None, env=None, timeout=None, preexec_fn=None):
        executed["command"] = command
        executed["env"] = env
        if preexec_fn:
            preexec_fn()
        return type("Result", (), {"returncode": 9, "stdout": "wrapped ok", "stderr": ""})()

    monkeypatch.setattr(agent.subprocess, "run", fake_run)

    client = agent.AgentClient(socket_path=tmp_path / "agent.sock")
    result = client.run_command(["bash", "-lc", "mcbridge dns status --debug-json"])

    assert result.returncode == 9
    assert executed["command"] == ["mcbridge", "dns", "status", "--debug-json"]
    assert executed["env"]["MCBRIDGE_AGENT_CONTEXT"] == "1"
    assert ("egid", 0) in set_calls
    assert ("euid", 0) in set_calls


def test_agent_logs_capability_drop(monkeypatch, caplog):
    snapshots = [
        agent._CapabilitySnapshot(effective=0x80, permitted=0x80),
        agent._CapabilitySnapshot(effective=0, permitted=0),
    ]

    @contextmanager
    def _no_root_switch():
        yield

    def _fake_run(command, capture_output=True, text=True, input=None, env=None, timeout=None):
        class _Result:
            stdout = ""
            stderr = ""
            returncode = 0

        return _Result()

    monkeypatch.setattr(agent, "_capability_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(agent, "_root_privileges", _no_root_switch)
    monkeypatch.setattr(agent.subprocess, "run", _fake_run)
    caplog.set_level(logging.ERROR, logger=agent.LOG.name)

    response = agent._run_command({"command": ["bash", "-c", "true"]})

    assert response["status"] == "ok"
    messages = [record.getMessage() for record in caplog.records if record.levelno >= logging.ERROR]
    assert any(
        "lost required Linux capabilities after handling a request" in message
        and "CapEff 0x80 -> 0x0" in message
        and "CapPrm 0x80 -> 0x0" in message
        and "AmbientCapabilities" in message
        and "CapabilityBoundingSet" in message
        and "NoNewPrivileges=no" in message
        for message in messages
    )


def test_agent_logs_partial_capability_drop(monkeypatch, caplog):
    snapshots = [
        agent._CapabilitySnapshot(effective=0x30, permitted=0x30),
        agent._CapabilitySnapshot(effective=0x10, permitted=0x30),
    ]

    @contextmanager
    def _no_root_switch():
        yield

    def _fake_run(command, capture_output=True, text=True, input=None, env=None, timeout=None):
        class _Result:
            stdout = ""
            stderr = ""
            returncode = 0

        return _Result()

    monkeypatch.setattr(agent, "_capability_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(agent, "_root_privileges", _no_root_switch)
    monkeypatch.setattr(agent.subprocess, "run", _fake_run)
    caplog.set_level(logging.WARNING, logger=agent.LOG.name)

    response = agent._run_command({"command": ["bash", "-c", "true"]})

    assert response["status"] == "ok"
    messages = [record.getMessage() for record in caplog.records if record.levelno >= logging.WARNING]
    assert any("CapEff 0x30 -> 0x10" in message for message in messages)
    assert any("lost required Linux capabilities after handling a request" in message for message in messages)


def test_agent_logs_capability_snapshots(monkeypatch, caplog):
    snapshots = [
        agent._CapabilitySnapshot(effective=0x1, permitted=0x1),
        agent._CapabilitySnapshot(effective=0, permitted=0),
    ]

    @contextmanager
    def _no_root_switch():
        yield

    def _fake_run(command, capture_output=True, text=True, input=None, env=None, timeout=None):
        class _Result:
            stdout = ""
            stderr = ""
            returncode = 0

        return _Result()

    monkeypatch.setattr(agent, "_capability_snapshot", lambda: snapshots.pop(0))
    monkeypatch.setattr(agent, "_root_privileges", _no_root_switch)
    monkeypatch.setattr(agent.subprocess, "run", _fake_run)
    caplog.set_level(logging.INFO, logger=agent.LOG.name)

    response = agent._run_command({"command": ["bash", "-c", "true"]})

    assert response["status"] == "ok"
    messages = [record.getMessage() for record in caplog.records]
    assert any(
        "capability snapshot before command" in message and "CapEff=0x1" in message and "CapPrm=0x1" in message
        for message in messages
    )
    assert any(
        "capability snapshot after command" in message and "CapEff=0x0" in message and "CapPrm=0x0" in message
        for message in messages
    )
    assert any("capabilities changed during request" in message for message in messages)
