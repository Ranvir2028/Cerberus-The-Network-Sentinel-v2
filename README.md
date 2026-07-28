# CERBERUS v2 — The Network Sentinel.

A self-hosted network monitoring tool that watches every device on your LAN, tells the ones you actually own apart from the ones you don't, and tells you the moment something unfamiliar joins.

Most consumer routers show you a device list and stop there — no history, no alerting, nothing that survives a reboot. Cerberus is built to run quietly in the background (a spare machine, a Raspberry Pi, a always-on Linux box) and keep answering one question: is everything on this network something I recognize?


## Features

- **Multi-source detection** — Scapy ARP (60s), two-tier Nmap fingerprinting (vendor/OS/ports/services), plus mDNS, DHCP, SSDP, and LLMNR for hostnames/vendors that ARP alone misses. All sources merge into one record per device, never overwriting a better-known field with a worse one.
- **Trust engine, not just a device list** — new devices alert, trusted ones don't. A 24h learning window on first run auto-trusts what's already on your network so you start from a clean baseline.
- **MAC-randomization aware** — falls back to hostname/vendor/label matching so a phone rotating its MAC doesn't look like a new intruder every reconnect.
- **Actionable alert emails** — signed, single-use, click-to-confirm Trust link; a Block link straight to your router's admin page with credentials shown alongside. Nothing is auto-blocked.
- **Dashboard, API, and CLI** — same service layer underneath all three; nothing is dashboard-exclusive.

## Deployment

Raw ARP scanning needs real interface access. Docker's host-network mode only works this way on Linux — Docker Desktop on Windows/macOS runs inside a VM and can't see your actual LAN regardless of config. Use whichever matches your OS:

| Platform | Mode | Command |
|---|---|---|
| Linux (server / always-on) | Docker Compose | `docker compose up -d` |
| Windows / macOS (desktop) | Native launcher | `python run_dev.py` |

`run_dev.py` runs backend + frontend together, installs Npcap on Windows automatically, and installs npm deps on first run.

## Requirements

- Python 3.9+, Node.js 18+ (frontend only)
- [Nmap](https://nmap.org/download.html) on `PATH`
- Windows: [Npcap](https://npcap.com/) (auto-installed by `run_dev.py` if missing, needs Admin)
- Raw socket access → `sudo` (Linux/macOS) or Administrator (Windows)

## Setup

**Native:**
```bash
git clone https://github.com/Ranvir2028/Cerberus-The-Network-Sentinel-v2.git && cd cerberus
pip install -r requirements.txt
cp .env.example .env                      # Setup this so that you can get the email alerts / Trust links
cp frontend/.env.example frontend/.env    # Setup this so that you can get the defaults already work for localhost
python run_dev.py
```

**Docker:**
```bash
git clone https://github.com/Ranvir2028/Cerberus-The-Network-Sentinel-v2.git && cd cerberus
cp .env.example .env
docker compose up -d
```
No separate `frontend/.env` needed — the frontend container gets `CERBERUS_PUBLIC_URL` and `CERBERUS_API_SECRET` from the root `.env` as build args. Set `CERBERUS_PUBLIC_URL` to this machine's LAN IP — the core service uses host networking, so there's no Docker-internal hostname for the frontend to reach it by.

## Configuration

`config/config.json` for non-secrets (scan intervals, toggles — auto-created with defaults on first run, editable via dashboard Settings). `.env` for secrets (SMTP, API key, link-signing secret, router creds) — never written to `config.json`, gitignored. Env vars win over the config file.

<details>
<summary><code>config.json</code> keys</summary>

| Key | Default | Meaning |
|---|---|---|
| `scapy_interval` | `60` | Seconds between ARP sweeps |
| `nmap_quick_interval` | `180` | Seconds between quick Nmap passes |
| `nmap_aggressive_interval` | `360` | Seconds between full fingerprint passes |
| `aggressive_workers` | `8` | Thread pool size, aggressive Nmap tier |
| `learning_mode_hours` | `24` | Auto-trust window on first run |
| `alert_cooldown_minutes` | `10` | Min. gap between repeat alerts per device |
| `email_alerts_enabled` | `false` | SMTP alerts master switch |
| `api_host` / `api_port` | `0.0.0.0` / `5000` | Flask API bind address |
| `mdns_enabled` / `mdns_interval` | `true` / `120` | Bonjour/Zeroconf discovery |
| `dhcp_enabled` / `dhcp_drain_interval` | `true` / `60` | Passive DHCP hostname sniffing |
| `ssdp_enabled` / `ssdp_interval` | `true` / `180` | UPnP device discovery |
| `llmnr_enabled` / `llmnr_interval` | `true` / `90` | Windows LLMNR reverse lookup |
| `link_token_expiry_hours` | `72` | Trust-link validity window |

</details>

<details>
<summary><code>.env</code> variables</summary>

| Variable | Purpose |
|---|---|
| `CERBERUS_API_SECRET` | If set, `/api/*` requires it in `X-API-Key`. Blank = no auth (fine for localhost). |
| `CERBERUS_EMAIL_ALERTS` | `true` to enable SMTP alerts |
| `CERBERUS_SMTP_SENDER` / `_PASSWORD` / `_RECIPIENTS` | SMTP config — Gmail needs an App Password, not your login password |
| `CERBERUS_LINK_SECRET` | Signs Trust-link tokens. Unset = random per boot, so old links stop verifying after a restart |
| `CERBERUS_PUBLIC_URL` | This machine's real LAN address — required for Trust links opened from another device |
| `CERBERUS_ROUTER_USER` / `_PASSWORD` | Shown next to Block links, never auto-submitted |
| `CERBERUS_FRONTEND_PORT` | Docker only — host port for the dashboard container |

</details>

## CLI

```bash
python -m cerberus.cli.terminal list [--untrusted]
python -m cerberus.cli.terminal show <mac>
python -m cerberus.cli.terminal trust <mac>
python -m cerberus.cli.terminal untrust <mac>
python -m cerberus.cli.terminal label <mac> "Owner's Device"
python -m cerberus.cli.terminal delete <mac>
python -m cerberus.cli.terminal history <mac>
python -m cerberus.cli.terminal alerts
python -m cerberus.cli.terminal status
python -m cerberus.cli.terminal learning
```
`--debug` for full tracebacks. `--help` for the complete flag list.

## API
 
Base `/api/*`, port `5000`. Requires `X-API-Key` if `CERBERUS_API_SECRET` is set (`/api/health` excepted).
 
| Route | Method | Purpose |
|---|---|---|
| `/api/devices` | GET | List all devices |
| `/api/devices/<mac>` | GET / DELETE | Detail / remove |
| `/api/devices/<mac>/history` | GET | Scan history |
| `/api/devices/<mac>/trust`, `/untrust` | POST | Change trust state |
| `/api/devices/<mac>/label` | POST | Set display name |
| `/api/devices/<mac>/request-id` | POST | Single-use "identify yourself" link for one device |
| `/api/devices/counts` | GET | Trusted/untrusted/total |
| `/api/alerts` | GET / DELETE | Alert log |
| `/api/alerts/<id>` | DELETE | Remove one alert |
| `/api/alerts/counts` | GET | Alert count summary |
| `/api/alerts/manager-status` | GET | Cooldown/manager internal state |
| `/api/learning`, `/start`, `/stop` | GET / POST | Learning-mode control |
| `/api/scan/status` | GET | Live scan status |
| `/api/settings` | GET / POST | Editable config |
| `/api/status` | GET | Combined snapshot — what the dashboard polls most |
| `/api/health` | GET | Liveness, no auth |
 
`GET/POST /confirm/trust/<token>` and `/confirm/identify/<token>` sit outside `/api/*`, unauthenticated by design — the signed token is the credential, same as any password-reset email link.

## Architecture

```
cerberus/
├── core/           scanner engine (Scapy + Nmap) + scheduler
├── detection/      interface/vendor lookup, mDNS/DHCP/SSDP/LLMNR
├── intelligence/   trust engine, learning mode
├── storage/        SQLite — only module that touches the DB
├── alerts/         cooldown logic, SMTP delivery
├── service/        seam — CLI and API call only this layer
├── cli/ · api/     terminal + Flask interfaces
└── utils/          config, logging, link-token signing

frontend/           React + Vite, talks only to the API
```

## Security

- SQLite in WAL mode — CLI and scanner (separate processes) read/write concurrently without corruption.
- Trust tokens: HMAC-signed, single-use via DB-level unique constraint, not just app logic.
- Trust link is GET-to-confirm, POST-to-act — protects against email clients that pre-fetch links.
- Block links never submit credentials — they open your router's login page, you handle it.

## Limitations

- Single-operator — no accounts/permissions. API key (or localhost access) is full control.
- DHCP discovery can miss a device that goes silent before the next ARP sweep — rare, ARP runs far more often.
- Docker is Linux-only — a Docker host-networking constraint, not a Cerberus one.

## License

MIT — see [LICENSE](LICENSE).