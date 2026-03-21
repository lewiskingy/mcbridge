# mcbridge — Lightweight Minecraft Wi‑Fi Bridge Appliance

`mcbridge` stands up a self-contained Wi‑Fi access point and DNS redirect so consoles can connect to your preferred Minecraft Bedrock server. It targets Raspberry Pi-class devices and keeps privileged work behind a small agent + systemd-managed services.

## Getting started (summary)

1. Install the CLI (pipx recommended): `pipx install mcbridge`.
2. Provision the device: `sudo mcbridge init --ssid ... --password ...`.
3. Manage AP/DNS changes with `mcbridge ap ...` and `mcbridge dns ...`.

## Contributing

In flight work is documented in /plans. If you want to contribute, please open an issue or PR.

Full details live in the web console docs (served under **Docs**) and in GitHub at `mcbridge/mcbridge/web/static/docs/`:

- [Overview](https://raw.githubusercontent.com/lewiskingy/mcbridge/refs/heads/main/mcbridge/mcbridge/web/static/docs/Overview.md)
- [Install](https://raw.githubusercontent.com/lewiskingy/mcbridge/refs/heads/main/mcbridge/mcbridge/web/static/docs/INSTALL.md)
- [Provisioning](https://raw.githubusercontent.com/lewiskingy/mcbridge/refs/heads/main/mcbridge/mcbridge/web/static/docs/PROVISIONING.md)
- [Usage](https://raw.githubusercontent.com/lewiskingy/mcbridge/refs/heads/main/mcbridge/mcbridge/web/static/docs/USAGE.md)
- [Design](https://raw.githubusercontent.com/lewiskingy/mcbridge/refs/heads/main/mcbridge/mcbridge/web/static/docs/DESIGN.md)
- [Developer roadmap](https://raw.githubusercontent.com/lewiskingy/mcbridge/refs/heads/main/mcbridge/mcbridge/web/static/docs/DEVELOPER_ROADMAP.md)
