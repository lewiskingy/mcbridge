import pytest


def _seed_dns_status_fixtures(monkeypatch: pytest.MonkeyPatch, dns):
    monkeypatch.setattr(
        dns, "_load_override_config", lambda default_target=None: ({"redirect": "stored", "target": "stored"}, "dns_overrides.json")
    )
    monkeypatch.setattr(
        dns,
        "read_system_dns_config",
        lambda include_sources=True, **kwargs: ({"redirect": "stored", "target": "stored"}, {"active": {}}),
    )


def test_dns_status_reports_drift_exit_code(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, dns = mcbridge_modules

    monkeypatch.setattr(
        dns, "_load_override_config", lambda default_target=None: ({"redirect": "stored", "target": "stored"}, "dns_overrides.json")
    )

    def fake_read_system_dns_config(include_sources: bool = False, **kwargs):
        return {"redirect": "live", "target": "live"}, {"active": {}}

    monkeypatch.setattr(dns, "read_system_dns_config", fake_read_system_dns_config)

    result = dns.status()

    assert result.exit_code == 10
    assert result.payload["status"] == "warning"


def test_dns_status_exposes_summary_fields(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, dns = mcbridge_modules

    monkeypatch.setattr(
        dns, "_load_override_config", lambda default_target=None: ({"redirect": "stored", "target": "stored"}, "dns_overrides.json")
    )

    def fake_read_system_dns_config(include_sources: bool = False, **kwargs):
        return {"redirect": "redirect.test", "target": "target.test", "enabled": False, "name": "override"}, {"active": {}}

    monkeypatch.setattr(dns, "read_system_dns_config", fake_read_system_dns_config)

    result = dns.status()

    assert result.payload["redirect"] == "redirect.test"
    assert result.payload["target"] == "target.test"
    assert result.payload["dns_enabled"] is False
    assert result.payload["dns_name"] == "override"


def test_dns_update_validation_error_exit_code(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, dns = mcbridge_modules

    monkeypatch.setattr(dns, "_load_override_config", lambda default_target=None: ({}, "dns_overrides.json"))
    monkeypatch.setattr(dns, "read_system_dns_config", lambda include_sources=True, **kwargs: ({}, {}))

    result = dns.update()

    assert result.exit_code == 2
    assert result.payload["status"] == "error"


def test_dns_update_runtime_failure_exit_code(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, dns = mcbridge_modules

    stored = {"target": "stored.test", "redirect": "keep.example", "enabled": True}
    monkeypatch.setattr(dns, "_load_override_config", lambda default_target=None: (stored, "dns_overrides.json"))
    monkeypatch.setattr(dns, "read_system_dns_config", lambda include_sources=True, **kwargs: (stored, {}))
    monkeypatch.setattr(dns, "_persist_dns_override_json", lambda *_, **__: {"applied": True})
    monkeypatch.setattr(
        dns,
        "_prepare_merged_config",
        lambda **__: ("candidate", "active", None, {"cleanup": {"warnings": [], "applied": False, "overrides_added": False}}),
    )
    monkeypatch.setattr(
        dns,
        "_validate_and_apply",
        lambda **__: {
            "validation": {"status": "passed"},
            "service_restart": {"service": "dnsmasq", "success": False},
            "applied": True,
            "cleanup": {},
        },
    )

    result = dns.update(dry_run=False)

    assert result.exit_code == 3
    assert result.payload["status"] == "warning"


def test_dns_status_allows_capability_context(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, dns = mcbridge_modules
    _seed_dns_status_fixtures(monkeypatch, dns)

    monkeypatch.setattr(dns.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        dns,
        "_read_proc_status",
        lambda: "CapEff:\t0000000000001082\nCapPrm:\t0000000000001082\n",
    )

    result = dns.status()

    assert result.exit_code == 0
    assert result.payload["status"] == "ok"


def test_dns_status_trusted_context_env(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, dns = mcbridge_modules
    _seed_dns_status_fixtures(monkeypatch, dns)

    monkeypatch.setattr(dns.os, "geteuid", lambda: 1000)
    monkeypatch.setenv("MCBRIDGE_TRUSTED_DNS_CONTEXT", "1")
    monkeypatch.setattr(
        dns,
        "_read_proc_status",
        lambda: "CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n",
    )

    result = dns.status()

    assert result.exit_code == 0
    assert result.payload["status"] == "ok"


def test_dns_status_still_requires_privileges(mcbridge_modules, monkeypatch: pytest.MonkeyPatch):
    _, _, _, dns = mcbridge_modules
    _seed_dns_status_fixtures(monkeypatch, dns)

    monkeypatch.setattr(dns.os, "geteuid", lambda: 1000)
    monkeypatch.setattr(
        dns,
        "_read_proc_status",
        lambda: "CapEff:\t0000000000000000\nCapPrm:\t0000000000000000\n",
    )

    with pytest.raises(SystemExit) as excinfo:
        dns.status()

    assert "require root privileges" in str(excinfo.value)
