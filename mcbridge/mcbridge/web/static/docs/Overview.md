# mcbridge overview

`mcbridge` is a lightweight Minecraft Wi‑Fi bridge appliance for consoles. It runs a small Wi‑Fi access point and DNS redirect so Bedrock clients can reach your preferred server without manual network changes.

## What it does

- Creates a local AP (e.g., SSID **Minecraft**) and NATs traffic to your upstream Wi‑Fi.
- Rewrites selected Minecraft hostnames via DNS to point at your chosen server.
- Manages configs with JSON + history snapshots for safe rollbacks.

## Documentation map

Use the guides below to avoid duplication and keep each document scoped to a single purpose:

- **INSTALL.md** — prerequisites and how to install the CLI and system services.
- **PROVISIONING.md** — first-time provisioning and rebuild workflows (quick start + manual steps).
- **USAGE.md** — day-to-day AP/DNS changes, dry runs, and troubleshooting workflows.
- **DESIGN.md** — architecture, safety mechanisms, and recovery guidance.
- **DEVELOPER_ROADMAP.md** — engineering priorities and known gaps.

## Quick start (summary)

1. Install with pipx: `pipx install mcbridge`.
2. Provision with sudo: `sudo mcbridge init --ssid ... --password ...`.
3. Use `mcbridge ap ...` and `mcbridge dns ...` for ongoing changes.

For details, follow the linked documents above or browse them in the web console under **Docs**.
