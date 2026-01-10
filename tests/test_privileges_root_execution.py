from pathlib import Path

import pytest

from mcbridge import privileges
from mcbridge.agent import AgentError


def _broken_client(*_, **__):
    raise AgentError("agent unavailable")


@pytest.fixture(autouse=True)
def _clear_cached_client():
    privileges._cached_client.cache_clear()
    yield
    privileges._cached_client.cache_clear()


def test_sudo_run_uses_local_execution_when_root_agent_broken(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    socket_path = tmp_path / "agent.sock"
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MCBRIDGE_AGENT_SOCKET", str(socket_path))
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privileges, "_cached_client", _broken_client)

    result = privileges.sudo_run(["echo", "ok"])

    assert result.returncode == 0
    assert result.stdout.strip() == "ok"


def test_sudo_write_file_prefers_local_when_root_agent_broken(monkeypatch: pytest.MonkeyPatch, tmp_path: Path):
    socket_path = tmp_path / "agent.sock"
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    socket_path.write_text("", encoding="utf-8")
    monkeypatch.setenv("MCBRIDGE_AGENT_SOCKET", str(socket_path))
    monkeypatch.setattr(privileges.os, "geteuid", lambda: 0)
    monkeypatch.setattr(privileges, "_cached_client", _broken_client)

    target = tmp_path / "output.txt"
    privileges.sudo_write_file(target, "contents", mode=0o640)

    assert target.read_text(encoding="utf-8") == "contents"
    assert (target.stat().st_mode & 0o777) == 0o640
