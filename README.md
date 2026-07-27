# Cerberus: The Network Sentinel

A self-hosted network monitoring tool that continuously discovers every device on your network, tells trusted devices apart from unknown ones, and alerts you the moment something unfamiliar shows up.

Cerberus runs a hybrid of active scanning (ARP + Nmap) and passive discovery (mDNS, DHCP, SSDP, LLMNR) across every network interface on the machine it runs on, keeps a persistent device history in SQLite, and surfaces all of it through a terminal, a JSON API, and a web dashboard.

## Why

Most home routers only show you a device list, not a history — and they don't tell you when something new joins. Cerberus is built to sit quietly on a machine (or a Linux server, for always-on deployment) and answer one question reliably: *is everything on this network something I recognize?*

## Features

- **Multi-network discovery** — detects every active network interface and scans all of them independently, not just one default subnet
- **Hybrid scanning** — fast ARP sweeps (Scapy) every ~60s for presence, deeper Nmap fingerprinting (vendor, OS, open ports) on a slower cycle, with per-network locking so the two never collide
- **Passive discovery** — mDNS, DHCP, SSDP, and LLMNR listeners pick up hostnames and device info that active scanning alone misses
- **Trust engine + learning mode** — a first-run window to auto-trust devices already on your network, so you're not immediately flooded with "intruder" alerts for your own hardware
- **Email alerts** — notified when an unrecognized device appears, with one-click Trust/Block links embedded directly in the email
- **Web dashboard** — live device table, trust/untrust actions, scan history, alert log (React + Vite)
- **JSON API** — every dashboard action is backed by a documented REST endpoint, so it's scriptable independently of the UI
- **CLI** — full terminal interface (`list`, `show`, `trust`, `untrust`, `label`, `history`, `alerts`, `status`, `learning`) for headless/SSH use
- **Cross-platform** — runs natively on Windows, macOS, and Linux, or containerized via Docker Compose for Linux/server deployment

## Deployment modes

Raw ARP scanning needs direct access to your machine's real network interfaces. Docker's `--network host` mode, which Cerberus's backend container relies on for this, is a Linux-only Docker feature — Docker Desktop on Windows and macOS runs containers inside an internal VM by design, so a "host-networked" container there never actually sees your real LAN, regardless of configuration. That's a platform limitation, not something specific to this project.

So Cerberus supports two run modes, matched to what actually works on each OS:

| Platform | Mode | Command |
|---|---|---|
| **Linux** (bare metal, VM, or server — recommended for production) | Docker Compose | `docker compose up -d` |
| **Windows / macOS** (desktop use) | Native launcher | `python run_dev.py` |

`run_dev.py` runs the backend and frontend together with one command, and handles Npcap setup on Windows automatically.

## Setup

### Native (Windows / macOS / Linux desktop)

```bash
git clone https://github.com/<your-username>/cerberus.git
cd cerberus
pip install -r requirements.txt
cp .env.example .env          # fill in values if you want email alerts
python run_dev.py
```

### Docker (Linux / production)

```bash
git clone https://github.com/<your-username>/cerberus.git
cd cerberus
cp .env.example .env          # fill in values, set CERBERUS_API_SECRET
docker compose up -d
```

Cerberus needs raw socket access to scan the network, so both modes require elevated privileges — `sudo` on Linux/macOS, Administrator on Windows.

## Configuration

Non-secret settings (scan intervals, feature toggles, ports) live in `config/config.json` and are created with sensible defaults on first run. Secrets (SMTP password, API key, link-signing secret, router credentials) are read from environment variables only, via `.env` — see `.env.example` for the full list with explanations. Environment variables always take priority over `config.json`.

## CLI

```bash
python -m cerberus.cli.terminal list              # all devices
python -m cerberus.cli.terminal list --untrusted   # unknown devices only
python -m cerberus.cli.terminal show <mac>
python -m cerberus.cli.terminal trust <mac>
python -m cerberus.cli.terminal status
python -m cerberus.cli.terminal alerts
```

Run `python -m cerberus.cli.terminal --help` for the full command list.

## API

The backend exposes a REST API at `/api/*` (default port 5000) — device list/detail/trust/untrust/label/history, alert log, learning-mode control, scan status, and settings. If `CERBERUS_API_SECRET` is set, every request requires it. See `cerberus/api/server.py` for the full route list.

## Architecture

```
cerberus/
├── core/            → scanning engine (Scapy + Nmap) and the scheduler that coordinates them
├── detection/        → network interface discovery, vendor lookup, mDNS/DHCP/SSDP/LLMNR
├── intelligence/     → trust engine, learning mode
├── storage/          → SQLite — the only module that touches the database directly
├── alerts/           → alert dispatch with cooldowns, SMTP delivery
├── service/          → the seam — CLI and API both call only this layer, never storage directly
├── cli/               → terminal interface
├── api/               → Flask JSON API
└── utils/             → config loading, logging, link-token signing

frontend/              → React + Vite dashboard, talks only to the API
```

The scheduler is the only module allowed to call both the network scanners and the detection layer — everything downstream only ever sees its output. CLI and the web API both go through `service/` rather than touching storage or intelligence directly, so either interface can be swapped or extended without touching the other.

## License

MIT — see [LICENSE](LICENSE).