# PROJECT: CERBERUS: THE NETWORK SENTINEL v2 — FINAL ARCHITECTURE
## CORE GOAL
Continuously discover every device across all active subnets, separate trusted from unknown using a hybrid Scapy+Nmap strategy, and surface that state through both a terminal and a web interface — identically on your laptop and in a container, and extensible to multi-segment org use later without a rewrite.

## FOLDER STRUCTURE (full end-state)

```
cerberus_v2/
├── cerberus/
│   ├── __init__.py
│   ├── detection/
│   │   ├── __init__.py
│   │   ├── router_detector.py      → finds active networks (Phase 1)
│   │   └── vendor_lookup.py        → MAC → manufacturer (Phase 2)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── scanner_scapy.py        → fast ARP scan, fixed (Phase 1)
│   │   ├── scanner_nmap.py         → deep scan, fixed (Phase 1)
│   │   └── scheduler.py            → timing + coordination (Phase 1)
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── trust_engine.py         → trust verdicts (Phase 2)
│   │   └── learning_mode.py        → first-run auto-trust window (Phase 2)
│   ├── storage/
│   │   ├── __init__.py
│   │   └── device_store.py         → only SQLite writer (Phase 1)
│   ├── alerts/
│   │   ├── __init__.py
│   │   ├── alert_manager.py        → cooldown + dispatch (Phase 3)
│   │   └── email_alert.py          → SMTP channel (Phase 3)
│   ├── service/
│   │   ├── __init__.py
│   │   └── cerberus_service.py     → seam: CLI + API both call only this (Phase 3)
│   ├── cli/
│   │   ├── __init__.py
│   │   └── terminal.py             → terminal interface (Phase 3)
│   ├── api/
│   │   ├── __init__.py
│   │   └── server.py               → JSON API for frontend (Phase 3)
│   └── utils/
│       ├── __init__.py
│       ├── logger.py                → done, no changes
│       ├── config_loader.py         → env vars + JSON (Phase 3)
│       └── npcap_installer.py       → fix no-return bug (Phase 1, dev-only, excluded from container) 
├── frontend/          ← NEW, everything below goes here → React, separate codebase entirely (Phase 4)
│   ├── package.json
│   ├── vite.config.js
│   ├── index.html
│   ├── .gitignore
│   ├── .env.example
│   └── src/
│       ├── main.jsx
│       ├── App.jsx
│       ├── api.js
│       └── index.css
├── config/
│   └── config.json
├── data/
│   └── devices.db
├── logs/
│   └── cerberus.log
├── cerberus_main.py                  → wires scheduler → storage (Phase 1), grows over phases
├── requirements.txt
└── docker-compose.yml                 → two services: core+api (host networking, NET_RAW), frontend (Phase 4)
```

### PHASES (final, five, in order):

1. Core loop runs — router_detector, both scanners fixed, scheduler, device_store, minimal main. Done = headless engine finds real devices and saves them.
2. Intelligence — trust_engine, learning_mode, vendor_lookup. Done = no more false "intruder" alerts for devices that were just asleep.
3. Reachable — service seam, CLI, alert_manager, email_alert, config_loader, API server. Done = you can run it from a terminal and get emailed when something unknown shows up.
4. Face — React frontend, Docker (host networking + NET_RAW for core, isolated frontend container). Done = dashboard works locally and in containers identically.
5. Org-scale — multi-segment scan policy, auth on API/frontend. Not started until you decide to pursue it — explicitly out of scope until then.

### RULES THAT DON'T CHANGE:

1. Scanners never import detection — scheduler injects the network string.
2. Only device_store.py opens the database.
3. CLI and frontend only ever talk to service/ — never storage, scanners, or intelligence directly.
4. No secrets/config hardcoded — config_loader from Phase 3 onward.
5. npcap_installer.py never ships in the container image.

This is final. Nothing more gets added on top of this unless something breaks the design once you're actually building — and if that happens, we fix the seam that broke, not bolt on a new module to route around it.

## Detailed breakdown, phase by phase — structure, responsibilities, boundaries.

### PHASE 1 — Make the core loop actually run

#### 1. `detection/router_detector.py`
Job: answer one question — "what networks is this machine currently on, and how do I describe each one in CIDR notation?" Walks every network interface present on the machine (skipping loopback), reads each interface's IP + subnet mask, calculates the network address by ANDing IP and mask, converts the mask to a CIDR prefix length, and also resolves the gateway IP for each interface where one exists. Returns a list of dicts: {interface, ip, network, netmask, gateway} — one entry per active interface. Must NOT touch Scapy, Nmap, or the database — this module knows about network topology, not about scanning or devices. Failure mode to design for: a machine with zero active interfaces (e.g., airplane mode) should return an empty list, not crash — every caller downstream needs to treat "no networks" as a normal, handle-able state.

#### 2. `core/scanner_scapy.py`
Job: given one network CIDR string, send one ARP broadcast (optionally preceded by a wake-up ICMP broadcast ping) and return every device that answered, as a list of {ip, mac} dicts. This module takes a network string as a parameter — it does NOT detect networks itself, does NOT know RouterDetector exists, does NOT store anything, does NOT decide trust. Pure function: network in, raw device list out. Fixes needed: the network: network dict-key bug, the broken retry-loop logic, and the dead line in update_network. Once fixed, the only structural change needed is removing its direct import of RouterDetector — the scheduler will inject the network string instead.

#### 3. `core/scanner_nmap.py`
Job: same contract as the Scapy scanner — network in, device list out — but uses Nmap underneath, either a quick ping-sweep (-sn) or a deep scan (OS detection, top ports) depending on which method is called. Returns richer dicts: {ip, mac, vendor, hostname, os, open_ports} for deep scans, a subset for quick ones. Same isolation rule as the Scapy scanner: no detection-layer imports, no storage, no trust logic. Fix needed: the scan_all_networks_quick() method that builds results but never extends the aggregate list — currently always returns empty regardless of what it actually found.

#### 4. `core/scheduler.py — new module`
Job: the conductor. On startup, calls detection/router_detector.py once to get the list of active networks. Then, on a timing loop, decides which scanner runs against which network and when: Scapy every ~60 seconds for fast awake-device checks, Nmap every ~10-15 minutes for deep fingerprinting, with the explicit rule that Nmap and Scapy never scan the same network simultaneously (a simple lock per network is enough — you don't need a complex scheduler library for this scale). Passes each scan result, as it comes in, to storage/device_store.py — the scheduler does not store anything itself, it routes. This is the one module allowed to call both detection/ and both scanner modules — everything else only sees the scheduler's output stream.

#### 5. `storage/device_store.py`
Job: the only module in the entire project allowed to open a connection to the SQLite file. Two tables: devices (one row per MAC, current state: ip, vendor, os, ports, trusted flag, first_seen, last_seen) and scan_history (append-only log: every time a MAC was seen, by which scanner, when). Exposes a small, deliberate method set: add-or-update a device, get one device, get all devices, get devices filtered by trust status, mark trusted/untrusted, delete a device, get counts. Nothing outside this file ever writes raw SQL — scheduler and scanners hand it dicts, it handles the rest. This is also where the earlier "concurrent writes" failure point gets isolated: because this is the only writer, there's no race condition to design around — there's only one door.

#### 6. `cerberus_main.py (minimal version)`
Job: at this phase, just wire scheduler → storage into a running loop and prove it works headless, with logging, before any CLI/API/frontend exists. This is your "does the engine actually turn over" checkpoint. No user interaction yet beyond Ctrl+C to stop it.

### PHASE 2 — Make it smart

#### 7. `intelligence/trust_engine.py — new module`
Job: takes the current device list from storage and answers exactly one question per device — trusted, untrusted-new, or untrusted-returning? The core fix for your original problem: a MAC that was trusted before and simply wasn't seen for a few scan cycles (asleep, powered off) must NOT be re-flagged as an intruder the moment it reappears — the engine checks first_seen history, not just "is this MAC currently marked trusted," to make that call correctly. One important addition worth naming now: modern phones and laptops increasingly randomize their MAC address for privacy (iOS, recent Android, Windows "random hardware addresses" for Wi-Fi) — meaning the same physical device can show up under a different MAC every time it reconnects. Pure MAC-based trust will eventually generate false "new device" alerts for your own phone. The engine doesn't need to solve this fully in Phase 2, but it should be designed knowing this is coming — e.g., correlating by hostname/vendor pattern as a secondary signal, not relying on MAC as the sole identity key forever. Flagging this now so it isn't a surprise rebuild in three months.

#### 8. `intelligence/learning_mode.py — new module`
Job: a time-boxed window (configurable, default e.g. 24 hours) starting from first run, during which every device discovered gets auto-marked trusted instead of flagged. After the window closes, trust_engine.py takes over normal judgment. This module owns exactly one piece of state — "is learning mode currently active" — and exposes that as a simple check the trust engine consults; it does not duplicate trust logic itself.

#### 9. `detection/vendor_lookup.py — new module`
Job: pure lookup — given a MAC address, return the manufacturer name using the OUI (first three bytes) against a vendor database (a static text/CSV file bundled locally — no live API call needed, no new runtime dependency on network access for this). No side effects, no state, no scanning. Used by trust_engine.py (for the vendor-pattern correlation above) and by alerts/CLI for human-readable output.

### PHASE 3 — Make it reachable

#### 10. `service/cerberus_service.py — new module, the seam`
Job: the single internal API both the CLI and the web API are required to call — never storage or intelligence directly. Exposes operations like "get current device list," "get device detail," "trust/untrust a device," "get recent alerts," "get scan status." Owns zero logic of its own — every call here is a thin dispatch into storage/intelligence/alerts. This is the literal embodiment of the "function call beats an API call, but design the seam" rule from earlier: today this is just a Python class CLI and Flask both import; tomorrow, if Cerberus ever needs to run as a true client-server split, this seam is exactly where you'd insert a network call without touching CLI or web code at all.

#### 11. `cli/terminal.py — new module`
Job: thin text rendering over service/. Commands like "list devices," "show intruders," "trust [mac]," "show status." This module's real purpose is proof: if this works correctly using only service/ and nothing else, you've proven the seam is real and not just theoretical.

#### 12. `alerts/alert_manager.py — new module`
Job: receives trust verdicts (specifically: new untrusted device events) from the scheduler/intelligence pipeline and decides whether to fire a notification, applying a cooldown window per device (so one intruder doesn't trigger 50 emails over an hour) and routing to whichever alert channel(s) are enabled. Owns the "spam prevention" logic — channels themselves own nothing but the sending mechanics.

#### 13. `alerts/email_alert.py — new module`
Job: one concrete channel — SMTP send, given a subject/body and recipient list. Reads SMTP credentials from config (config_loader), not hardcoded. Knows nothing about cooldowns, trust logic, or scanning — alert_manager decides whether to call it, this module only knows how to send.

#### 14. `utils/config_loader.py`
Job: loads scan intervals, alert toggles, SMTP credentials, DB path, and learning-mode duration from environment variables first, with a JSON file as fallback/defaults — finally closing the "config_loader.py is empty" gap from the original design rule that secrets/config are never hardcoded. Validates required fields exist and gives a clear error rather than a silent None if something's missing.

#### 15. `api/server.py — new module`
Job: Flask or FastAPI app exposing service/cerberus_service.py as JSON HTTP endpoints — device list, device detail, trust/untrust actions, live scan status, alert history. Thin by design: every route handler is a one-line call into service/, with the HTTP/JSON translation being the only thing this file does.

### PHASE 4 — Give it a face

#### 16. `frontend/ (React)`
Job: a dashboard that talks only to api/server.py — live device table (sortable by trust status, last seen, vendor), trust/untrust action buttons, scan history timeline, alert log view. Built and deployed as a fully separate codebase from the Python package, so it can be redesigned or rebuilt without touching cerberus/ at all.

#### 17. `Docker`
Two containers: core+API (needs --network host and NET_RAW capability to see your real LAN, not Docker's bridge network — the failure point flagged earlier), and frontend (no special privileges, just serves static assets/dev server). npcap_installer.py formally excluded from the deployable image at this point — Windows-dev-only, irrelevant inside a Linux container.

### PHASE 5 — Org-scale (later, only if pursued)

#### 18. `Multi-segment scan policy` — which subnets get scanned at what depth; an org has segments (production VLANs) you explicitly do not want deep-Nmap'd by default.

#### 19. `Auth on API/frontend` — irrelevant solo, mandatory the moment a second person can view the dashboard.