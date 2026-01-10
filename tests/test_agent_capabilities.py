import logging
import subprocess

import pytest

from mcbridge import agent


def test_agent_exits_without_setid_capabilities(monkeypatch: pytest.MonkeyPatch, caplog, tmp_path):
    monkeypatch.setattr(agent, "_capng_has_capability", lambda _: False)
    monkeypatch.setattr(
        agent,
        "_read_proc_status",
        lambda: "CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n",
    )

    caplog.set_level(logging.ERROR, logger=agent.LOG.name)

    with pytest.raises(SystemExit) as excinfo:
        agent.main(["--socket", str(tmp_path / "agent.sock"), "--group", "mcbridge-operators"])

    assert excinfo.value.code == 1
    messages = [record.getMessage() for record in caplog.records if record.levelno == logging.ERROR]
    assert any(
        "mcbridge agent started without required Linux capabilities" in message
        and "CapEff=0x0" in message
        and "CapPrm=0x0" in message
        and "AmbientCapabilities" in message
        and "CapabilityBoundingSet" in message
        and "NoNewPrivileges=no" in message
        and "daemon-reload" in message
        and "restart mcbridge-agent.service" in message
        for message in messages
    )


def test_root_privileges_preserve_capabilities(monkeypatch: pytest.MonkeyPatch):
    capability_state = {"effective": 0x1A, "permitted": 0x2B}
    ids = {"euid": 1000, "egid": 1000}
    keepcaps_calls: list[bool] = []

    monkeypatch.setattr(agent, "_capability_snapshot", lambda: agent._CapabilitySnapshot(**capability_state))
    monkeypatch.setattr(agent, "_log_capability_snapshot", lambda *_, **__: None)
    monkeypatch.setattr(agent, "_log_capability_drop", lambda *_, **__: None)

    def fake_set_keepcaps(enabled: bool) -> bool:
        keepcaps_calls.append(enabled)
        return True

    monkeypatch.setattr(agent, "_set_keepcaps", fake_set_keepcaps)
    monkeypatch.setattr(agent.os, "geteuid", lambda: ids["euid"])
    monkeypatch.setattr(agent.os, "getegid", lambda: ids["egid"])

    def fake_seteuid(value: int) -> None:
        ids["euid"] = value
        keepcaps_active = keepcaps_calls[-1] if keepcaps_calls else False
        if value != 0 and not keepcaps_active:
            capability_state["effective"] = 0
            capability_state["permitted"] = 0

    def fake_setegid(value: int) -> None:
        ids["egid"] = value

    monkeypatch.setattr(agent.os, "seteuid", fake_seteuid)
    monkeypatch.setattr(agent.os, "setegid", fake_setegid)
    monkeypatch.setattr(agent, "_privileged_binary", lambda *_, **__: False)
    monkeypatch.setattr(agent, "_allowed_command", lambda _command: True)

    monkeypatch.setattr(
        agent.subprocess,
        "run",
        lambda *_, **__: subprocess.CompletedProcess(["ip", "addr"], 0, "ok", ""),
    )

    result = agent._run_command({"command": ["ip", "addr"]})

    assert result["status"] == "ok"
    assert capability_state == {"effective": 0x1A, "permitted": 0x2B}
    assert keepcaps_calls[0] is True
    assert keepcaps_calls[-1] is False
