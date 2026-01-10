# Provisioning guide (operators)

> This is the **canonical provisioning document**. It replaces the previous split guidance across older install/provisioning notes. Use it for both first-time setup and rebuilds. For ongoing AP/DNS changes, see [USAGE.md](USAGE.md).

## Audience and scope
- Operators setting up mcbridge on a fresh Pi (or similar Linux host).
- Anyone rerunning provisioning with `--force` to correct drift.

## Quick start: `mcbridge init` (preferred)
1. Install the CLI (pipx recommended; `pip` works in the active environment):
   ```bash
   pipx install mcbridge
   # or track main:
   pipx install git+https://github.com/lewiskingy/mcbridge-console.git
   ```
2. Ensure the Pi already has internet access; run as root/sudo because provisioning installs packages and writes to `/etc/mcbridge`.
3. Execute init (defaults: `--octet 50`, `--channel 6`, empty password allowed for an open AP):
   ```bash
   sudo mcbridge init --ssid <name> --password <pass> --octet <1-254> --channel <wifi-channel>
   ```
   - `--dry-run`: validate and show the plan without changes.
   - `--prepare-only`: stage validation, seeding, provisioning, and service enablement without rendering or starting hostapd/dnsmasq. Follow with `sudo mcbridge ap update --force` to generate and apply configs.
   - `--force`: reapply even when the system appears provisioned (required to remediate drift).
   - Defaults when omitted: empty `--password` (open AP), `--octet 50`, `--channel 6`.
   - Subnet safety: `mcbridge init` inspects upstream IPv4 routes on the WAN interface (default `wlan0`). If you omit `--octet` and the default AP subnet (e.g., `192.168.50.0/24`) overlaps upstream, init warns and auto-selects a free octet; explicitly overlapping octets still fail unless you intentionally override with `--force`.
   - Service principals: override `--service-user`, `--service-group`, and `--operator-group` to change file ownership and the systemd unit `User=`/`Group=` values (defaults stay `mcbridge`, `mcbridge`, and `mcbridge-operators`). The service user is always added to the operator group so it can read/write mcbridge-managed files.
   - Marker: `/etc/mcbridge/.initialised` records success and keeps reruns idempotent.

Example:
```bash
sudo mcbridge init \
  --ssid Minecraft \
  --password mypwd123 \
  --octet 168 \
  --channel 6
```

After `init`, manage AP/DNS via `mcbridge ap ...` and `mcbridge dns ...`; add DNS overrides later (e.g., `mcbridge dns update --redirect ... --target ...`). Rerun provisioning only when you deliberately want to rebuild (pass `--force` if drift is reported).

Running `init --prepare-only` is useful when you want to validate and install prerequisites ahead of time (for example, on an image or in a maintenance window) while leaving hostapd/dnsmasq configs untouched. Once ready to converge the services, run `mcbridge ap update --force` to render hostapd/dnsmasq and bring them up.

---

## Manual path: explicit OS-level steps
Use these steps when you need the detailed actions (audits, partial remediation, or environments where you cannot run `mcbridge init`). Commands assume Debian-based systems with `wlan0` upstream and `wlan0ap` for the AP.

### 1) System prep and packages
- Confirm interfaces and upstream route: `iw dev`, `ip link show`, `ip route` (look for `default via ... dev wlan0`).
- Update/install dependencies:
  ```bash
  sudo apt update && sudo apt upgrade -y
  sudo apt install -y hostapd dnsmasq iptables iptables-persistent
  sudo systemctl stop hostapd dnsmasq || true
  ```

### 2) Create the AP interface (`wlan0ap`)
Create and enable a systemd unit:
```bash
sudo tee /etc/systemd/system/wlan0ap.service >/dev/null <<'EOF'
[Unit]
Description=Create AP interface wlan0ap
After=network-pre.target
Wants=network-pre.target

[Service]
Type=oneshot
ExecStart=/sbin/iw dev wlan0 interface add wlan0ap type __ap
ExecStart=/sbin/ip link set wlan0ap up
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl enable --now wlan0ap.service
ip link show wlan0ap
```

### 3) Assign the AP IP
Choose your network manager:
- `dhcpcd`:
  ```bash
  sudo tee -a /etc/dhcpcd.conf >/dev/null <<'EOF'

interface wlan0ap
  static ip_address=192.168.50.1/24
  nohook wpa_supplicant
EOF

  sudo systemctl restart dhcpcd
  ```
- NetworkManager:
  ```bash
  sudo nmcli con add type ethernet ifname wlan0ap con-name wlan0ap-static ip4 192.168.50.1/24
  sudo nmcli con up wlan0ap-static
  ```

### 4) Configure hostapd and dnsmasq
Back up existing configs (`sudo cp /etc/hostapd/hostapd.conf{,.bak} 2>/dev/null || true` and `sudo cp /etc/dnsmasq.conf{,.bak} 2>/dev/null || true`). Then:
```bash
sudo tee /etc/hostapd/hostapd.conf >/dev/null <<'EOF'
interface=wlan0ap
driver=nl80211
ssid=Minecraft
hw_mode=g
channel=6
ieee80211n=1
wmm_enabled=1
auth_algs=1
ignore_broadcast_ssid=0

# OPEN network
wpa=0
EOF

sudo sed -i 's|^#DAEMON_CONF=.*|DAEMON_CONF="/etc/hostapd/hostapd.conf"|' /etc/default/hostapd

sudo mv /etc/dnsmasq.conf /etc/dnsmasq.conf.orig 2>/dev/null || true

sudo tee /etc/dnsmasq.conf >/dev/null <<'EOF'
interface=wlan0ap
bind-interfaces

# DHCP (clients on Minecraft SSID)
dhcp-range=192.168.50.10,192.168.50.60,12h
dhcp-option=3,192.168.50.1     # gateway
dhcp-option=6,192.168.50.1     # DNS

# Upstream DNS
server=1.1.1.1
server=8.8.8.8

# --- DNS overrides ---
# Example: cubecraft.net -> example.ddns.com
cname=cubecraft.net,example.ddns.com
EOF
```

### 5) Enable forwarding and NAT
```bash
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-ipforward.conf >/dev/null
sudo sysctl --system

sudo iptables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
sudo iptables -A FORWARD -i wlan0ap -o wlan0 -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o wlan0ap -m state --state ESTABLISHED,RELATED -j ACCEPT

sudo netfilter-persistent save
```

### 6) Start services
```bash
sudo systemctl unmask hostapd || true
sudo systemctl enable --now hostapd dnsmasq
systemctl status hostapd dnsmasq --no-pager
```

### 7) Verify and hand off to the CLI
- Connectivity: `ip addr show wlan0ap` (expect `192.168.50.1/24`).
- DHCP/DNS: `sudo cat /var/lib/misc/dnsmasq.leases` and `dig cubecraft.net @192.168.50.1`.
- NAT: `sudo iptables -t nat -L -v -n`.

Once the base network is healthy, manage ongoing changes via:
- AP updates: `sudo mcbridge ap update ...`
- DNS updates: `sudo mcbridge dns update ...` or `sudo mcbridge dns menu`
- Usage details: [USAGE.md](USAGE.md)
