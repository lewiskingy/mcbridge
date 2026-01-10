# Install

Goal: Stand up a Pi that stays on your home Wi‑Fi (STA) while broadcasting an AP (e.g., SSID **Minecraft**) that serves DHCP/DNS and forwards traffic via NAT. mcbridge wraps these actions behind validated commands and history-backed configs.

Design rationale and safety mechanisms live in [DESIGN.md](DESIGN.md). Provisioning is consolidated in [PROVISIONING.md](PROVISIONING.md); this file summarizes how to prepare the system and where to go next.

## Prerequisites
- Hardware: Raspberry Pi Zero 2 W (or similar) with built-in Wi‑Fi, microSD, and power.
- OS: Raspberry Pi OS Lite (Debian-based) with systemd.
- Network: Pi is already online as a Wi‑Fi client (STA) and can reach the internet.
- Privileges: sudo/root required for provisioning or any command that mutates system configs.
- CLI install: `pipx install mcbridge` (recommended) or `pip install mcbridge` in the active environment. To track `main`, use `pipx install git+https://github.com/lewiskingy/mcbridge-console.git`.

## Installation
Install the CLI in your preferred environment:
```bash
pipx install mcbridge
# or track main:
pipx install git+https://github.com/lewiskingy/mcbridge-console.git
```

## Provisioning entry points
- **Preferred**: `mcbridge init` for validated, idempotent provisioning. See [PROVISIONING.md](PROVISIONING.md#quick-start-mcbridge-init-preferred) for the command contract and examples.
- **Manual**: If you need explicit OS-level steps (audits, partial remediation), use [PROVISIONING.md](PROVISIONING.md#manual-path-explicit-os-level-steps).

## After provisioning
- AP/DNS management: `mcbridge ap ...` and `mcbridge dns ...` (workflows in [USAGE.md](USAGE.md)).
- Reference design details: [DESIGN.md](DESIGN.md).
- Developer roadmap: [DEVELOPER_ROADMAP.md](DEVELOPER_ROADMAP.md) for current engineering priorities.
