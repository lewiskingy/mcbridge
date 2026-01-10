"""Canonical filesystem paths for mcbridge.

The constants in this module centralise access to runtime paths under
``/etc/mcbridge`` while supporting an environment override for tests. When the
``MCBRIDGE_ETC_DIR`` environment variable is set, it takes precedence over the
default root.
"""

from __future__ import annotations

import os
from pathlib import Path

_etc_override = os.environ.get("MCBRIDGE_ETC_DIR")
ETC_DIR = Path(_etc_override) if _etc_override else Path("/etc/mcbridge")

CONFIG_DIR = ETC_DIR / "config"
GENERATED_DIR = ETC_DIR / "generated"
CONFIG_HISTORY_DIR = CONFIG_DIR / "history"
GENERATED_HISTORY_DIR = GENERATED_DIR / "history"
LOG_DIR = ETC_DIR / "logs"
INIT_MARKER = ETC_DIR / ".initialised"

__all__ = [
    "CONFIG_DIR",
    "CONFIG_HISTORY_DIR",
    "ETC_DIR",
    "GENERATED_DIR",
    "GENERATED_HISTORY_DIR",
    "INIT_MARKER",
    "LOG_DIR",
]
