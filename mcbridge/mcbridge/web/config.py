"""Configuration helpers for the mcbridge web console."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from ..paths import CONFIG_DIR

DEFAULT_WEB_CONFIG_PATH = CONFIG_DIR / "web.json"


def _coerce_path(raw: str | None) -> Path | None:
    if not raw:
        return None
    return Path(raw).expanduser()


def _coerce_float(raw: str | int | float | None) -> float | None:
    if raw is None:
        return None
    try:
        value = float(raw)
    except (TypeError, ValueError):
        return None
    return value


def _coerce_bool(raw: Any) -> bool | None:
    if raw is None:
        return None
    if isinstance(raw, bool):
        return raw
    if isinstance(raw, str):
        lowered = raw.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    return None


def _load_json(path: Path) -> dict[str, Any]:
    try:
        content = path.read_text()
    except FileNotFoundError:
        return {}
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        return {}


@dataclass(frozen=True)
class WebConfig:
    tls_cert: Path | None = None
    tls_key: Path | None = None
    auth_token: str | None = None
    auth_password: str | None = None
    agent_timeout: float | None = None
    upstream_prune_missing: bool | None = None

    @property
    def ssl_context(self) -> tuple[str, str] | None:
        if self.tls_cert and self.tls_key:
            return (str(self.tls_cert), str(self.tls_key))
        return None

    @property
    def requires_authentication(self) -> bool:
        return bool(self.auth_token or self.auth_password)


def load_web_config(config_path: Path | None = None) -> WebConfig:
    path_override = os.environ.get("MCBRIDGE_WEB_CONFIG")
    config_source = Path(path_override) if path_override else (config_path or DEFAULT_WEB_CONFIG_PATH)
    file_config = _load_json(config_source)

    def pick(key: str, env_var: str) -> Any:
        if env_var in os.environ:
            return os.environ[env_var]
        return file_config.get(key)

    tls_cert = _coerce_path(pick("tls_cert", "MCBRIDGE_WEB_TLS_CERT"))
    tls_key = _coerce_path(pick("tls_key", "MCBRIDGE_WEB_TLS_KEY"))

    return WebConfig(
        tls_cert=tls_cert,
        tls_key=tls_key,
        auth_token=pick("auth_token", "MCBRIDGE_WEB_AUTH_TOKEN"),
        auth_password=pick("auth_password", "MCBRIDGE_WEB_AUTH_PASSWORD"),
        agent_timeout=_coerce_float(pick("agent_timeout", "MCBRIDGE_AGENT_TIMEOUT")),
        upstream_prune_missing=_coerce_bool(pick("upstream_prune_missing", "MCBRIDGE_UPSTREAM_PRUNE_MISSING")),
    )


__all__ = ["DEFAULT_WEB_CONFIG_PATH", "WebConfig", "load_web_config"]
