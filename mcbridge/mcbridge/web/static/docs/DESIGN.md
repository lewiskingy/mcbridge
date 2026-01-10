# Design notes

## Topology choice
- **NAT/router mode (default):** The AP on `wlan0ap` is NATed to the upstream STA interface (`wlan0`). This is stable on single-radio boards like the Pi Zero 2 W, isolates the console from the LAN, and keeps DHCP/DNS control on the bridge.
- **Why not a true bridge:** L2 Wi‑Fi bridging with simultaneous STA+AP on one radio is unreliable on consumer chipsets (frame forwarding and WDS gaps), so the project intentionally avoids it.

## Components and config flow
- **hostapd** brings up the console-facing AP (SSID, channel, security) using a generated `hostapd.conf`.
- **dnsmasq** provides DHCP for the AP network and injects Bedrock DNS overrides through a generated `dnsmasq-mcbridge.conf` that is deployed to `/etc/dnsmasq.conf` (with a mirrored copy kept under `/etc/mcbridge/generated/` when present).
- **iptables** handles IPv4 forwarding and MASQUERADE from `wlan0ap` to the upstream interface.
- **JSON-driven configs:** `/etc/mcbridge/config/ap.json` and `/etc/mcbridge/config/dns_overrides.json` are the sources of truth (with `/etc/mcbridge/config/dnsmasq.json` maintained only as a legacy mirror during migration). The `mcbridge ap ...` / `mcbridge dns ...` commands render them into `/etc/mcbridge/generated/hostapd.conf` and `/etc/dnsmasq.conf` (while also refreshing `/etc/mcbridge/generated/dnsmasq-mcbridge.conf`) before restarting services. `knownservers.json` feeds the DNS override menu.

## Safety and recovery
- **History snapshots:** Both config (`/etc/mcbridge/config/history/`) and generated files (`/etc/mcbridge/generated/history/`) are timestamped on each run to make diffs and rollbacks easy.
- **Dry runs:** `--dry-run` validates JSON, shows planned file diffs, and skips writes/restarts.
- **Force applies:** `--force` reconciles drift between JSON and live configs when you intentionally want to overwrite live state.
- **Recovery approach:** If a change misbehaves, replay a prior snapshot with `--file <history/ap.json>` or re-point DNS to a previous `dns_overrides.json` snapshot (or its mirrored `dnsmasq.json`), then restart via the scripts. Worst case, stop `hostapd`/`dnsmasq`, restore the generated files from history, and re-enable services once verified.

## Interface assumptions
- Default expectation is **`wlan0`** as the upstream STA and **`wlan0ap`** as the AP.
- If your device names differ (e.g., `wlp2s0`), adjust:
  - The virtual AP service (`wlan0ap.service`) so it creates the correct AP interface name.
  - `ap.json` (`interface`, channel, SSID) and `dns_overrides.json` (and its mirrored `dnsmasq.json` for DHCP/interface fields where applicable) to match.
  - iptables rules and persistence so MASQUERADE and forwarding reference your upstream interface.
