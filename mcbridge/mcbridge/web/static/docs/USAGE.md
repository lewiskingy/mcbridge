# Usage and operations

Use these workflows after the base installation is complete. They assume the default layout under `/etc/mcbridge/` for stored JSON and `/etc/mcbridge/generated/` for rendered configs (hostapd), with DNS overrides rendered from `/etc/mcbridge/config/dns_overrides.json` into `/etc/mcbridge/generated/dnsmasq-mcbridge.conf` and deployed to `/etc/dnsmasq.conf` (histories live under `/etc/mcbridge/config/history/` and `/etc/mcbridge/generated/history/`).

If you need a refresher on the topology, component roles, or safety/recovery mechanics, see [DESIGN.md](DESIGN.md) before running the scripts.

## Installing and invoking the CLI
- Install in an isolated environment (recommended): `pipx install mcbridge`
- Install into the active environment: `pip install mcbridge`
- Install the latest from `main` via pipx: `pipx install git+https://github.com/lewiskingy/mcbridge-console.git`
- Invoke after installation using the console script entry point: `mcbridge ap status --debug-json`
- Run directly from a clone without installing: `python -m mcbridge ap status --debug-json`
- Customise service principals during provisioning with `mcbridge init --service-user ... --service-group ... --operator-group ...`; defaults remain `mcbridge`, `mcbridge`, and `mcbridge-operators`, and the service user is always added to the operator group for access to managed paths.

## Logging and output
- JSON is emitted on stdout for automation. Human-readable INFO/WARN/ERROR messages continue on stderr.
- Detailed validation traces (commands, stdout/stderr, diffs, rollback paths) are sent to the `mcbridge.scripts` logger. On systems with journald, these land under the `mcbridge-scripts` identifier; otherwise they rotate under `/etc/mcbridge/logs/mcbridge-scripts.log` (override with `MCBRIDGE_LOG_ROOT`). Use these logs to debug failed validations or rollbacks.

## Quickstart (AP + DNS override)
1) Confirm install state
- Services: `systemctl status wlan0ap hostapd dnsmasq --no-pager`
- Config files: `sudo ls /etc/mcbridge/config/{ap.json,dns_overrides.json,dnsmasq.json,knownservers.json}` (dnsmasq.json is legacy and mirrored only when present)
- Interfaces: `ip addr show wlan0ap` (expects `192.168.50.1/24`)

2) Set AP SSID/PSK/channel
- Edit `/etc/mcbridge/config/ap.json` as needed, then preview: `sudo mcbridge ap status --debug-json`
- Or pass overrides on the CLI to avoid editing the JSON (e.g., `--ssid`, `--password`, `--channel`, `--octet`): `sudo mcbridge ap update --ssid "LAN Party" --password "secret12345" --channel 11 --octet 60 --dry-run`
- Apply and restart services if it looks correct: rerun the update command without `--dry-run` (add `--force` if live config differs from stored JSON).

3) Choose the DNS redirect target
- Interactive menu (TTY required): `sudo mcbridge dns menu`
- Headless redirect + optional target: `sudo mcbridge dns update --redirect cubecraft.net --target example.ddns.com --force` (automatically renders `cname=` for hostname targets and `address=/host/ip` for literal IP targets)

4) Verify clients
- Check DHCP leases: `sudo cat /var/lib/misc/dnsmasq.leases`
- Confirm overrides resolve: `dig +short cubecraft.net @192.168.50.1`
- Spot-check traffic counters: `sudo iptables -t nat -L -v -n`

## mcbridge ap workflows
- Inspect without changes: `sudo mcbridge ap status --debug-json` (detailed diffs and validation output are logged under the `mcbridge.scripts` logger).
- Apply overrides without hand-editing JSON:
  - Preview: `sudo mcbridge ap update --ssid "Minecraft Party" --password "secret12345" --channel 11 --octet 60 --dry-run`
  - Apply: re-run without `--dry-run` (add `--force` if live config differs from stored JSON).
- Force-apply stored JSON: `sudo mcbridge ap update --force`
  - Treats `/etc/mcbridge/config/ap.json` as source of truth when live files differ.
- Replay a previous snapshot: `sudo mcbridge ap update --file /etc/mcbridge/config/history/2025-03-01T18-22.ap.json --force`
  - Useful for rolling back to a known-good SSID/password/channel.

Outputs include JSON on stdout and human-readable logs on stderr. The CLI restarts `wlan0ap.service`, `hostapd.service`, and `dnsmasq.service` when the AP or DHCP ranges change.

## mcbridge dns workflows
- DNS commands require root privileges; run them as `sudo mcbridge dns ...` so writes succeed.
- Interactive selection from knownservers.json (requires TTY):
  - `sudo mcbridge dns menu`
- Redirect to a known server with an optional override target (non-interactive):
  - `sudo mcbridge dns update --redirect play.enchanted.gg --target example.ddns.com` (hostname targets write `cname=...`; literal IP targets write `address=/.../ip`)
- Preview only (no writes or restarts):
  - `sudo mcbridge dns update --redirect cubecraft.net --dry-run`
- Apply even when live state differs from stored JSON:
  - `sudo mcbridge dns update --redirect cubecraft.net --force`

## Upstream Wi‑Fi workflows
- Add or edit upstream networks from the web UI or `/upstream` API endpoints using a single password field.
- The upstream password input accepts either a normal passphrase or a 64-character hexadecimal PSK. PSKs are stored exactly as entered, while other passwords are hashed with the SSID before being saved to `upstream_networks.json`.

## Upstream DNS handling
- Upstream DNS servers are discovered from the active upstream DHCP lease and injected into the rendered `dnsmasq` configuration.
- There is no CLI or config override for upstream DNS; mcbridge always uses the DHCP-provided servers.
- When the upstream Wi‑Fi connection changes (new SSID, reconnect, DHCP renew), mcbridge regenerates and restarts `dnsmasq` to apply the updated DNS servers.

knownservers.json is now a **single object** with a default `target` and a `redirects` array of menu entries. Each entry should include a friendly `name` and the `redirect` hostname, with optional per-entry `target` overrides. Example:
```json
{
  "target": "example.ddns.com",
  "redirects": [
    { "name": "Cubecraft", "redirect": "play.cubecraft.net" },
    { "name": "Lifeboat", "redirect": "mco.lbsg.net" },
    { "name": "Example override", "redirect": "proxy.example.net", "target": "play.example.net" }
  ]
}
```
If `/etc/mcbridge/config/knownservers.json` is missing during provisioning, `mcbridge init` copies the packaged default menu (`mcbridge.resources/knownservers.json`) into place so you can curate it locally afterward. Legacy array-based files still load, but entries lacking a single `redirect` will be skipped.

DNS overrides now use `/etc/mcbridge/config/dns_overrides.json` as the single source of truth, stored as one object with `redirect`, `target`, `enabled`, and optional `name` fields. If you still have a legacy `hijacks` array in that file, collapse it to a single redirect/target pair; the CLI will raise a migration error for multi-entry arrays.

The script rewrites `/etc/mcbridge/config/dns_overrides.json` (mirroring legacy `/etc/mcbridge/config/dnsmasq.json` when present), regenerates `/etc/mcbridge/generated/dnsmasq-mcbridge.conf`, deploys that file to `/etc/dnsmasq.conf`, and restarts `dnsmasq` when changes apply. Status/history operations read from `/etc/dnsmasq.conf` and snapshot histories under `/etc/mcbridge/config/history/` and `/etc/mcbridge/generated/history/`. It emits warnings if the live config drifts from stored JSON; add `--force` to reconcile.

## Web API service
- The Flask app is a thin HTTP wrapper that proxies to the mcbridge CLI. It shell-execs the CLI with validated arguments (no raw string interpolation) and returns JSON plus the CLI exit code as the HTTP status (0 → 200, 2 → 400, 10 → 200 with `status: "warning"`, other → 500).
- Because the CLI performs targeted sudo escalation only for privileged helpers, the web service itself does not need to run as root. If you run it under systemd, propagate `MCBRIDGE_ETC_DIR` (and other `MCBRIDGE_*` variables) so the subprocess uses the same config/history paths as the rest of the tooling. The systemd unit installed by `mcbridge init` (or regenerated with `mcbridge-web init`) defaults to running as `mcbridge` and no longer creates a sudoers drop-in.
- The systemd unit now always runs with sudo-capable capabilities (`AmbientCapabilities=CAP_NET_BIND_SERVICE CAP_SETUID CAP_SETGID CAP_AUDIT_WRITE`, mirrored in `CapabilityBoundingSet` with `NoNewPrivileges=no`) so privileged CLI helpers can still perform escalations while the service stays non-root. Keep the service user in `mcbridge-operators` (the unit adds `SupplementaryGroups=mcbridge-operators`) so it can access managed paths without separate sudoers tweaks.
- Override the CLI entry point with `MCBRIDGE_CLI_BIN` when needed (e.g., a venv-specific `python -m mcbridge`). Subprocess stderr is surfaced in the JSON payload when the CLI exits non-zero or returns non-JSON output to aid debugging.
- Agent timeouts: set `MCBRIDGE_AGENT_TIMEOUT` (or `agent_timeout` in `web.json`) to control how long web-triggered CLI calls wait on the agent. You can also override it per `/upstream/apply` request by passing `{ "timeout": <seconds> }` in the JSON body.
- TLS and auth: mcbridge-web now defaults to HTTPS on port **443** and also starts an HTTP listener on **80** (set `MCBRIDGE_WEB_HTTP_PORT=0` or `--http-port 0` to disable HTTP). `mcbridge init` seeds `/etc/mcbridge/config/web.json` and generates a self-signed cert/key pair under `/etc/mcbridge/config/web-cert.pem` and `/etc/mcbridge/config/web-key.pem` when none are present. Provide `MCBRIDGE_WEB_AUTH_TOKEN` (Bearer token or `X-Auth-Token` header), `MCBRIDGE_WEB_AUTH_PASSWORD` (HTTP Basic password), or pass `--web-password` to `mcbridge init` to require authentication. Missing credentials leaves the API open on the bound host/port. Override the paths with `MCBRIDGE_WEB_TLS_CERT`/`MCBRIDGE_WEB_TLS_KEY` or edit `web.json` if you have a real certificate. Re-run `mcbridge-web init` when you want to regenerate the config/certificates without redoing the full init flow.
- Minimal setup still supports supplying your own certificate/key pair; create `/etc/mcbridge/config/web.json` if you prefer to manage TLS manually:
  ```json
  {
    "tls_cert": "/etc/mcbridge/config/cert.pem",
    "tls_key": "/etc/mcbridge/config/key.pem",
    "auth_token": "change-me-token"
  }
  ```
  Point `MCBRIDGE_WEB_CONFIG` to an alternate JSON path if desired. Environment variables override JSON values when both are present.
- Running alongside the CLI: start the server with `python -m mcbridge.web --host 0.0.0.0 --port 443 --http-port 80` (add `--debug` when developing). The web process uses the same CLI binary that you would invoke locally, so keep `MCBRIDGE_CLI_BIN` and `MCBRIDGE_ETC_DIR` aligned between the web service and your shell.

## Validation and troubleshooting
- Expected service states
  - `systemctl status wlan0ap hostapd dnsmasq --no-pager` (all active)
  - `sysctl net.ipv4.ip_forward` should return `1`
  - `ip addr show wlan0ap` should show `192.168.50.1/24`
- DNS and DHCP checks
  - DNS override from AP side: `dig +short cubecraft.net @192.168.50.1`
  - DHCP leases: `sudo cat /var/lib/misc/dnsmasq.leases`
  - Generated config history: `ls -1 /etc/mcbridge/generated/history/`
- Logs and counters
  - `journalctl -u hostapd -n 200 --no-pager`
  - `journalctl -u dnsmasq -n 200 --no-pager`
  - Firewall counters: `sudo iptables -L -v -n` and `sudo iptables -t nat -L -v -n`
- Failed validations
  - On validation errors, the candidate files are saved under `/etc/mcbridge/generated/failed/` (override with `MCBRIDGE_FAILED_ROOT`) alongside a `*-metadata.json` file that captures the validation command, return code, and stdout/stderr snippets.
  - You can manually retry dnsmasq validation with: `dnsmasq --test --conf-file <saved-file>`

Common issues
- SSID not visible: check `wlan0ap.service` and `hostapd` status/logs.
- Clients fail DHCP: review `dnsmasq` status/logs and confirm `wlan0ap` has the static IP.
- Override not applied: ensure you’re redirecting the exact hostname; rerun `mcbridge dns update --force` and retest with `dig`.
- Traffic exits AP but not internet: verify `net.ipv4.ip_forward=1` and NAT rules on the upstream interface.
