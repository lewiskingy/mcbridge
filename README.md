# mcbridge — Lightweight Minecraft Wi‑Fi Bridge Appliance

`mcbridge` stands up a self-contained Wi‑Fi access point and DNS redirect so consoles can connect to your preferred Minecraft Bedrock server. It targets Raspberry Pi-class devices and keeps privileged work behind a small agent + systemd-managed services.

## Getting started (summary)

1. Install the CLI (pipx recommended): `pipx install mcbridge`.
2. Provision the device: `sudo mcbridge init --ssid ... --password ...`.
3. Manage AP/DNS changes with `mcbridge ap ...` and `mcbridge dns ...`.

Full details live in the web console docs (served under **Docs**) and in GitHub at `mcbridge/mcbridge/web/static/docs/`:

<<<<<<< HEAD
## Design notes

- Runs in **NAT/router mode** (STA on `wlan0`, AP on `wlan0ap`) for stability on single-radio Pis; true Wi‑Fi bridging is intentionally avoided.
- `hostapd`, `dnsmasq`, and `iptables` are driven by JSON under `/etc/mcbridge/config/` and rendered configs in `/etc/mcbridge/generated/`, with history snapshots and dry-run/force workflows for safety.
- Assumes `wlan0`/`wlan0ap` by default—adjust the AP service, JSON interfaces, and iptables rules if your interface names differ.

See [docs/DESIGN.md](docs/DESIGN.md) for detailed rationale, safety mechanisms, and recovery guidance.

## Directory layout

```
/etc/mcbridge/
├── config/
│   ├── ap.json
│   ├── dns_overrides.json        # canonical DNS overrides
│   ├── dnsmasq.json              # legacy mirror maintained for compatibility
│   ├── knownservers.json
│   └── history/
│       ├── 2025-03-01T18-22.ap.json
│       ├── 2025-03-01T19-05.upstream_wifi.json
│       └── ...
│
├── generated/
│   ├── hostapd.conf
│   ├── dnsmasq.conf
│   ├── dnsmasq-mcbridge.conf     # generated overrides (deployed to /etc/dnsmasq.conf)
│   └── history/
│       ├── 2025-03-01T18-22.dnsmasq.conf
│       ├── 2025-03-01T19-05.hostapd.conf
│       └── ...
│
└── logs/                       # operational logs are emitted to stderr and collected by journald
```

## Installation and first run

Choose one of the two supported, root-visible installs (pipx preferred):

- **Option A — pipx (recommended):**
  ```bash
  sudo apt-get update && sudo apt-get install -y pipx python3-venv
  sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx ensurepath
  sudo PIPX_HOME=/opt/pipx PIPX_BIN_DIR=/usr/local/bin pipx install --global mcbridge
  sudo ln -sf /usr/local/bin/mcbridge /usr/bin/mcbridge
  sudo ln -sf /usr/local/bin/mcbridge-agent-socket-helper /usr/bin/mcbridge-agent-socket-helper
  sudo ln -sf /usr/local/bin/mcbridge-web /usr/bin/mcbridge-web
  ```
- **Option B — dedicated venv (alternative):**
  ```bash
  sudo apt-get install -y python3-venv
  sudo python3 -m venv /opt/mcbridge-venv
  sudo /opt/mcbridge-venv/bin/pip install --upgrade pip
  sudo /opt/mcbridge-venv/bin/pip install mcbridge
  sudo ln -sf /opt/mcbridge-venv/bin/mcbridge /usr/bin/mcbridge
  sudo ln -sf /opt/mcbridge-venv/bin/mcbridge-agent-socket-helper /usr/bin/mcbridge-agent-socket-helper
  sudo ln -sf /opt/mcbridge-venv/bin/mcbridge-web /usr/bin/mcbridge-web
  ```
- Use a full PATH when running under sudo so `groupadd`, `useradd`, and mcbridge binaries resolve:
  ```bash
  sudo env "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" mcbridge init --yes --ssid ... --password ... --octet ...
  ```
- `mcbridge init` provisions principals (`mcbridge` service user/group, `mcbridge-operators` operator group) and writes a constrained sudoers drop-in at `/etc/sudoers.d/mcbridge`. The policy only allows members of `mcbridge-operators` to start/stop/restart/status `mcbridge-agent`, `mcbridge-web`, `hostapd`, and `dnsmasq`, plus invoke `mcbridge-agent-socket-helper` to recreate the agent socket—no shells or arbitrary services are permitted. There are no sudo/polkit rules for general root access; the scope is limited to mcbridge services and socket repair.
- Privileged actions always flow through the agent socket. The CLI and web UI refuse to run when the socket is missing or unreadable; start `mcbridge-agent.service` or run `mcbridge-agent-socket-helper` (via the sudoers policy) to recreate `/run/mcbridge/agent.sock` with `mcbridge:mcbridge-operators` ownership and 0770 on the parent runtime directory.

Quick start (root required for init):

1. Flash Raspberry Pi OS and boot the Pi.
2. Install mcbridge system-wide using Option A (pipx) or Option B (venv) above.
3. Provision with sudo so the system-level changes succeed (defaults: `--octet 50`, `--channel 6`, empty password allowed for an open AP):
   ```bash
   sudo env "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" mcbridge init --ssid ... --password ... --octet ... --channel ...
   ```
4. Initialise the web UI (optional):
   ```bash
   sudo env "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" mcbridge-web init --yes
   ```
4. Optional hardening: pass `--web-password <http-basic-password>` to `mcbridge init` to seed the web console with Basic auth (or `--no-web` if you prefer to skip installing the web UI).

### First-time setup checklist

1. Ensure the service principals exist (defaults): system group/user `mcbridge`, operator group `mcbridge-operators`.
2. Add anyone who will run the CLI or web UI to `mcbridge-operators` (log out/in for membership to apply).
3. Enable and start `mcbridge-agent.service` so `/run/mcbridge/agent.sock` exists; use `mcbridge-agent-socket-helper --recreate` if the socket directory needs to be repaired.
4. `mcbridge init` installs and enables `mcbridge-web.service` by default; adjust TLS/auth in `/etc/mcbridge/config/web.json`, pass `--web-password` during init to seed Basic auth, or disable the web console entirely with `--no-web`.
5. Run `sudo mcbridge init ...` to render configs, sync units, and seed JSON under `/etc/mcbridge/config/`.


### First-time provisioning with `mcbridge init` (preferred)

`mcbridge init` is the primary first-run path. It validates inputs, seeds JSON configs, renders hostapd/dnsmasq and systemd files, and then delegates OS-level work to `provision.sh` with explicit paths so sudo uses the same Python environment. This pre-rendered flow avoids `ModuleNotFoundError` when the escalated interpreter differs from the one that installed mcbridge. The provisioning script is idempotent: reruns exit cleanly when no drift is detected, while drift requires `--force` to reapply.

- Must be run as root (e.g., `sudo mcbridge init ...`).
- Required arguments: `--ssid`. Include `--password` to enable WPA2; leave it empty for an open AP.
- Optional (recommended): `--octet` (defaults to `50`), `--channel` (defaults to `6`). DNS overrides can be added later via `mcbridge dns ...`.
- Troubleshooting while running under sudo: add `--debug-json` so you get the structured payload in stdout for logs/support, e.g., `sudo mcbridge init --debug-json --ssid ...`.
- Subnet safety: init inspects IPv4 routes on the upstream interface (default `wlan0`). If you omit `--octet` and the default overlaps, init will warn and auto-select a free octet; if you explicitly set an overlapping `--octet`, init aborts (override only with `--force` when overlap is intentional).
- Service principals: override the defaults with `--service-user`, `--service-group`, and `--operator-group` (defaults remain `mcbridge`, `mcbridge`, and `mcbridge-operators`). These values flow into file ownership, systemd unit `User=`/`Group=`, and the provisioning script environment.
- Web console: init now installs and enables `mcbridge-web.service` automatically (TLS cert/key + `/etc/mcbridge/config/web.json`). Provide `--web-password` to require HTTP Basic auth, or `--no-web` to skip installing the console.
- Staged flow: `--prepare-only` validates, seeds JSON, syncs units, and enables services without starting hostapd/dnsmasq or rendering their configs. Follow with `mcbridge ap update` to generate and apply hostapd/dnsmasq once you are ready for the AP to come up.
- Safety: `--dry-run` prints the planned actions and exits without changes.
- Idempotence guard: `/etc/mcbridge/.initialised` records successful runs. If present, `mcbridge init` will continue in a read/apply mode; if the provisioning preflight shows drift, you must pass `--force` to correct it.
- Example invocation (explicitly setting the optional parameters):
  ```bash
  sudo mcbridge init \
    --ssid Minecraft \
    --password mypwd123 \
    --octet 168 \
    --channel 6
  ```

### Ongoing changes

After provisioning, use the normal management commands instead of rerunning init:

- AP updates: `sudo mcbridge ap update ...` or `sudo mcbridge ap menu` for an interactive flow.
- DNS updates: `sudo mcbridge dns update ...` or `sudo mcbridge dns menu` when you want the guided picker.
- DNS commands must run as root; rerun them as `sudo mcbridge dns ...` to avoid permission errors.

Re-run `mcbridge init` only when you intentionally want to wipe and reprovision, and only with `--force`.

### Direct CLI invocation

- After installation, the `mcbridge` entry point resolves to `mcbridge.cli:main`; verify with a quick smoke test:
  - `mcbridge ap status --debug-json`
- If you are running directly from a clone without installing, you can still invoke the CLI via the module launcher:
  - `python -m mcbridge ap status --debug-json`

Operators looking for the full provisioning flow can read the consolidated guide at [docs/PROVISIONING.md](docs/PROVISIONING.md).

## How it works

- **hostapd**: creates the console-facing AP (e.g., SSID “Minecraft”) on `wlan0ap` and enforces channel and security settings.
- **dnsmasq**: serves DHCP on the AP and rewrites selected Bedrock hostnames via generated overrides—hostname targets become `cname=` entries while literal IP targets keep `address=/host/ip` lines. Overrides are rendered from the canonical `/etc/mcbridge/config/dns_overrides.json` (with `/etc/mcbridge/config/dnsmasq.json` kept only as a legacy mirror) into `/etc/mcbridge/generated/dnsmasq-mcbridge.conf`, which is deployed to `/etc/dnsmasq.conf`.
- **iptables**: provides IPv4 forwarding and NAT so AP clients reach your upstream Wi‑Fi while remaining isolated from the LAN.
- **JSON configs**: `ap.json`, **`dns_overrides.json` (canonical)**, optional legacy `dnsmasq.json` (mirrored from the canonical file), and `knownservers.json` live under `/etc/mcbridge/config/` with timestamped histories to make changes auditable and reversible. On first install, `mcbridge init` seeds `/etc/mcbridge/config/knownservers.json` from the packaged default (`mcbridge.resources/knownservers.json`) so you have a starter menu you can edit locally.
- **systemd units**: manage AP interface creation, hostapd/dnsmasq lifecycles, and persistent firewall rules so the bridge survives reboots.
- **Web console**: Flask server installed by default during `mcbridge init` (unless you pass `--no-web`) that calls the AP/DNS/init domain functions in-process (no sudo/subprocess hop) with an opt-in CLI subprocess fallback (`MCBRIDGE_WEB_USE_SUBPROCESS=1` or `--subprocess-runner` when launching). TLS cert/key and a shared token/password can be supplied via environment variables or `/etc/mcbridge/config/web.json`. When both cert and key are present, the server binds HTTPS; otherwise, it falls back to HTTP. The systemd unit still runs as `MCBRIDGE_WEB_USER`/`MCBRIDGE_WEB_GROUP` (defaults `admin`) so you can continue using the admin/install user if it already owns the mcbridge config and systemd files.

## Setup and usage

- Installation and base network setup: see [docs/INSTALL.md](docs/INSTALL.md).
- Operating the scripts (AP/DNS changes, dry runs, history replays): see [docs/USAGE.md](docs/USAGE.md).
- Current engineering focus and remaining refactor goals: see [docs/DEVELOPER_ROADMAP.md](docs/DEVELOPER_ROADMAP.md).

### Sample configuration JSON

Store these under `/etc/mcbridge/config/`:

```json
// ap.json
{
  "ssid": "Minecraft",
  "password": "",
  "channel": 6,
  "subnet_octet": 50
}
```

```json
// dns_overrides.json (canonical)
{
  "redirect": "play.cubecraft.net",
  "target": "example.ddns.com",
  "enabled": true,
  "name": "Cubecraft"
}
```

`dnsmasq.json` is written only as a legacy mirror of the canonical overrides file during migration.

```json
// knownservers.json
{
  "target": "example.ddns.com",
  "redirects": [
    { "name": "Cubecraft", "redirect": "play.cubecraft.net" },
    { "name": "Lifeboat", "redirect": "mco.lbsg.net" },
    { "name": "Example override", "redirect": "proxy.example.net", "target": "play.example.net" }
  ]
}
```
Legacy `dns_overrides.json` files that used `hijacks` arrays must be collapsed into the single-object schema above (one `redirect` + `target`). The CLI now refuses multi-entry `hijacks` arrays and will point to the new shape if migration is required.

## What’s included

- **mcbridge CLI** (`mcbridge ap ...`, `mcbridge dns ...`) for non-interactive or menu-driven AP/DNS updates—see the usage guide for workflows.
- **Configuration storage** under `/etc/mcbridge/config/` plus generated files in `/etc/mcbridge/generated/`—details in [docs/INSTALL.md](docs/INSTALL.md).
- **System services** (`wlan0ap.service`, `hostapd.service`, `dnsmasq.service`, iptables persistence) that bring up the AP, DNS overrides, and NAT automatically—install steps in [docs/INSTALL.md](docs/INSTALL.md).
=======
- [Overview](mcbridge/mcbridge/web/static/docs/Overview.md)
- [Install](mcbridge/mcbridge/web/static/docs/INSTALL.md)
- [Provisioning](mcbridge/mcbridge/web/static/docs/PROVISIONING.md)
- [Usage](mcbridge/mcbridge/web/static/docs/USAGE.md)
- [Design](mcbridge/mcbridge/web/static/docs/DESIGN.md)
- [Developer roadmap](mcbridge/mcbridge/web/static/docs/DEVELOPER_ROADMAP.md)
>>>>>>> d083580a4ae66dac60936b95e1c61f9bf9bb7bce
