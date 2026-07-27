"""
cerberus_main.py — Phase 1+2+3 headless engine, plus email Trust/Block
links and the expanded passive/active discovery stack.

Config priority: env vars > config/config.json > built-in defaults.
CLI args override the config file for quick one-off runs.

Scan tiers:
  Scapy ARP        every scapy_interval        (default 60s)
  Nmap quick       every nmap_quick_interval    (default 180s)
  Nmap aggressive  every nmap_aggressive_interval (default 360s)
  mDNS discovery   every mdns_interval          (default 120s, global)
  DHCP sniffing    continuous, drained every dhcp_drain_interval (default 60s)
  SSDP discovery   every ssdp_interval          (default 180s, global)
  LLMNR discovery  every llmnr_interval         (default 90s, global)

On Windows, checks for Npcap (needed for Scapy's raw ARP scanning) and
silently installs it if missing — fully non-interactive. See
npcap_installer.py's docstring for why this matters for Linux/macOS
correctness too. If Npcap is required and can't be made available
(no admin rights, download failure), Cerberus exits rather than
starting a scanner that can't actually capture packets — a clear
failure at boot beats a silent partial start.

CerberusService gets constructed with link_secret=cfg.link_secret,
which is what enables the /confirm/trust/<token> routes in
server.py — without it those routes still exist but every request
returns "Trust links are not enabled" (verify_trust_token() checks for
a missing link_secret explicitly).

Learning-mode auto-start had a real bug: learning_mode.start() used to
get called unconditionally on every launch, so deliberately stopping
learning mode via `learning stop` and then restarting the scanner
would silently reopen a fresh 24h auto-trust window, undoing that
decision with no warning. Fixed by checking
learning_mode.has_ever_started() first — a genuine first-ever run
(no state file, or one that's never recorded a start) still
auto-starts as before, but any run after that, including after a
deliberate stop, doesn't. The operator has to explicitly run
`learning start` (CLI), POST /api/learning/start (API), or pass
--force-relearn — e.g. after moving to a new network and wanting a
fresh trust-everything baseline.
"""

import argparse
import logging
import sys
import os
import signal
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cerberus.utils.logger import setup_logging
from cerberus.utils.config_loader import get_config, ConfigError
try:
    from cerberus.utils.npcap_installer import handle_npcap_installation
except ImportError:
    # Per the project's own architectural rule ("npcap_installer.py
    # never ships in the container image" — it's Windows-only and
    # irrelevant on Linux), the Docker build's .dockerignore excludes
    # this file entirely from the image. Without this try/except, that
    # exclusion would break cerberus_main.py's own import chain and
    # crash the container before it ever starts. handle_npcap_installation
    # being None is the signal that this build simply doesn't include
    # the check — main() below treats that as "nothing to do here,"
    # not an error.
    handle_npcap_installation = None
from cerberus.storage.device_store import DeviceStore
from cerberus.core.scheduler import Scheduler
from cerberus.intelligence.trust_engine import TrustEngine
from cerberus.intelligence.learning_mode import LearningMode
from cerberus.alerts.alert_manager import AlertManager
from cerberus.alerts.email_alert import EmailAlert
from cerberus.service.cerberus_service import CerberusService
from cerberus.api.server import run_server


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="cerberus",
        description=(
            "Cerberus v2 — Network Sentinel.\n"
            "Config loaded from config/config.json and env vars.\n"
            "CLI args override config file values."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--db",           default=None,
                        help="SQLite DB path (overrides config)")
    parser.add_argument("--log-file",     default=None,
                        help="Log file path (overrides config)")
    parser.add_argument("--debug",        action="store_true",
                        help="Force DEBUG log level")
    parser.add_argument("--silent",       action="store_true",
                        help="Log to file only, suppress console output")
    parser.add_argument("--scapy-interval",           type=int, default=None,
                        help="Seconds between ARP sweeps (overrides config)")
    parser.add_argument("--nmap-quick-interval",      type=int, default=None,
                        help="Seconds between Nmap quick scans (overrides config)")
    parser.add_argument("--nmap-aggressive-interval", type=int, default=None,
                        help="Seconds between aggressive scans (overrides config)")
    parser.add_argument("--aggressive-workers",       type=int, default=None,
                        help="Thread pool size for aggressive scans (overrides config)")
    parser.add_argument("--mdns-interval", type=int, default=None,
                        help="Seconds between mDNS browse cycles (overrides config)")
    parser.add_argument("--dhcp-drain-interval", type=int, default=None,
                        help="Seconds between DHCP sighting drains (overrides config)")
    parser.add_argument("--ssdp-interval", type=int, default=None,
                        help="Seconds between SSDP browse cycles (overrides config)")
    parser.add_argument("--llmnr-interval", type=int, default=None,
                        help="Seconds between LLMNR resolve cycles (overrides config)")
    parser.add_argument("--learning-hours", type=int, default=None,
                        help="Learning mode window in hours (overrides config; "
                             "only applies on a genuine first-ever run or "
                             "with --force-relearn)")
    parser.add_argument("--no-learning",   action="store_true",
                        help="Never auto-start learning mode, even on first run")
    parser.add_argument("--force-relearn", action="store_true",
                        help="Force a fresh learning-mode window on THIS boot "
                             "regardless of history — e.g. you've deliberately "
                             "moved to a new network location.")
    parser.add_argument("--no-alerts",     action="store_true",
                        help="Disable the alert pipeline entirely")
    parser.add_argument("--no-api",        action="store_true",
                        help="Disable the embedded API server even if "
                             "api_enabled is true in config")
    parser.add_argument("--no-mdns",       action="store_true",
                        help="Disable mDNS discovery even if "
                             "mdns_enabled is true in config")
    parser.add_argument("--no-dhcp",       action="store_true",
                        help="Disable DHCP sniffing even if "
                             "dhcp_enabled is true in config")
    parser.add_argument("--no-ssdp",       action="store_true",
                        help="Disable SSDP discovery even if "
                             "ssdp_enabled is true in config")
    parser.add_argument("--no-llmnr",      action="store_true",
                        help="Disable LLMNR discovery even if "
                             "llmnr_enabled is true in config")
    parser.add_argument("--no-npcap-check", action="store_true",
                        help="Skip the Npcap check entirely on Windows "
                             "(advanced — only if you've verified it "
                             "yourself, or are troubleshooting)")
    parser.add_argument("--config",        default=None,
                        help="Path to config.json (default: config/config.json)")
    return parser.parse_args()


def _ensure_dirs(*paths: str) -> None:
    for path in paths:
        d = os.path.dirname(path)
        if d:
            os.makedirs(d, exist_ok=True)


def _print_banner(logger: logging.Logger) -> None:
    logger.info("""
╔══════════════════════════════════════════════════════╗
║          CERBERUS v2 — The Network Sentinel          ║
║          Three-Tier Aggressive Scanner                ║
╚══════════════════════════════════════════════════════╝""")


def _print_summary(store: DeviceStore, logger: logging.Logger) -> None:
    try:
        c = store.counts()
        logger.info("─" * 56)
        logger.info("SHUTDOWN SUMMARY")
        logger.info(f"  Total devices : {c['total']}")
        logger.info(f"  Trusted       : {c['trusted']}")
        logger.info(f"  Untrusted     : {c['untrusted']}")
        logger.info("─" * 56)

        devices = store.get_all()
        if devices:
            logger.info("Known devices:")
            for d in devices:
                tag     = "✔ trusted" if d["trusted"] else "? unknown"
                vendor  = d.get("vendor") or "unknown vendor"
                os_name = d.get("os") or "OS unknown"
                acc     = d.get("os_accuracy")
                acc_str = f" ({acc}%)" if acc else ""
                label   = f" [{d['label']}]" if d.get("label") else ""
                model   = f" ({d['model']})" if d.get("model") else ""
                ports   = d.get("open_ports") or []
                svc     = d.get("services") or {}
                logger.info(
                    f"  {d['ip']:<16} {d['mac']}  "
                    f"{vendor:<22}{model} {os_name}{acc_str}  [{tag}]{label}"
                )
                for port in ports[:8]:
                    s = svc.get(port, svc.get(str(port), {}))
                    svc_str = f"{s.get('name','')} {s.get('product','')} {s.get('version','')}".strip()
                    logger.info(f"    {port}/tcp  {svc_str or 'unknown'}")
        else:
            logger.info("No devices recorded.")
    except Exception as e:
        logger.error(f"Summary error: {e}")


def _build_alert_manager(cfg, logger: logging.Logger) -> AlertManager:
    manager = AlertManager()

    email = EmailAlert()
    manager.register_channel(email.send)

    if cfg.email_alerts_enabled:
        logger.info("Email alert channel registered and ACTIVE.")
    else:
        logger.info(
            "Email alert channel registered but INACTIVE "
            "(CERBERUS_EMAIL_ALERTS is off or credentials missing) — "
            "alerts will log only until enabled in .env."
        )

    return manager


def _handle_learning_mode_startup(
    learning_mode: LearningMode, args: argparse.Namespace, logger: logging.Logger
) -> None:
    """
    Decide whether to (re-)start learning mode on THIS boot.

    Rules, in order:
      1. --force-relearn  → always start fresh (operator override, e.g.
                             new network location).
      2. Never started before (has_ever_started() is False) → genuine
         first-ever run, auto-start exactly like the original behaviour.
      3. Otherwise → do nothing. If already active, it stays active. If
         it was deliberately stopped, it STAYS stopped — this is the
         actual bugfix. The operator must use --force-relearn or the
         `learning start` CLI/API command to open a new window.
    """
    if args.force_relearn:
        learning_mode.start(force_restart=True)
        logger.info("Learning mode force-started (--force-relearn).")
        return

    if not learning_mode.has_ever_started():
        learning_mode.start()
        logger.info("Learning mode auto-started (genuine first-ever run).")
        return

    if learning_mode.is_active():
        logger.info("Learning mode already active from a previous session — resuming.")
    else:
        logger.info(
            "Learning mode was previously stopped/expired and will NOT "
            "auto-restart. Use `learning start` (CLI) or --force-relearn "
            "if you want a fresh baseline window."
        )


def _install_sigterm_handler() -> None:
    """
    Translate SIGTERM into the SAME graceful-shutdown path already
    correctly handled for Ctrl+C (SIGINT) below, rather than
    duplicating the cleanup logic.

    Why this matters (Docker specifically): `docker stop` sends
    SIGTERM by default, waits a grace period (10s unless configured
    otherwise), then sends SIGKILL if the process hasn't exited.
    Python's default disposition for SIGTERM is immediate termination
    — it does NOT raise a catchable exception unless a handler is
    installed. Without this, `docker stop` would kill Cerberus before
    scheduler.stop() (which joins every worker thread), _print_summary(),
    or service.close() (clean SQLite close) ever ran — every container
    stop would look like a crash, not a shutdown, even though nothing
    was actually wrong.
    """
    def _handle_sigterm(signum, frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, _handle_sigterm)


def main() -> None:
    _install_sigterm_handler()
    args = _parse_args()

    try:
        cfg = get_config(config_file=args.config)
    except ConfigError as e:
        print(f"\n[CONFIG ERROR] {e}\n")
        sys.exit(1)

    db_path    = args.db       or cfg.db_path
    log_file   = args.log_file or cfg.log_file
    log_level  = "DEBUG" if args.debug else cfg.log_level

    scapy_interval           = args.scapy_interval           or cfg.scapy_interval
    nmap_quick_interval      = args.nmap_quick_interval      or cfg.nmap_quick_interval
    nmap_aggressive_interval = args.nmap_aggressive_interval or cfg.nmap_aggressive_interval
    aggressive_workers       = args.aggressive_workers       or cfg.aggressive_workers
    mdns_interval            = args.mdns_interval            or cfg.mdns_interval
    dhcp_drain_interval      = args.dhcp_drain_interval      or cfg.dhcp_drain_interval
    ssdp_interval            = args.ssdp_interval            or cfg.ssdp_interval
    llmnr_interval           = args.llmnr_interval           or cfg.llmnr_interval
    learning_hours           = args.learning_hours           or cfg.learning_mode_hours

    _ensure_dirs(db_path, log_file)
    logger = setup_logging(
        log_file=log_file,
        level=log_level,
        silent_mode=args.silent,
    )

    _print_banner(logger)

    # --- Npcap check (Windows-only in effect; instant no-op elsewhere) ---
    if handle_npcap_installation is None:
        logger.debug(
            "npcap_installer module not present in this build "
            "(expected in container images — Windows-only, excluded by design)."
        )
    elif not args.no_npcap_check:
        if not handle_npcap_installation():
            logger.critical(
                "Npcap is required for scanning on Windows and could not be "
                "made available. Re-run as Administrator, install Npcap "
                "manually (https://npcap.com/#download), or pass "
                "--no-npcap-check if you've already verified capture works. "
                "Exiting."
            )
            sys.exit(1)
    else:
        logger.warning("Npcap check skipped (--no-npcap-check).")

    api_will_run   = cfg.api_enabled  and not args.no_api
    mdns_will_run  = cfg.mdns_enabled and not args.no_mdns
    dhcp_will_run  = cfg.dhcp_enabled and not args.no_dhcp
    ssdp_will_run  = cfg.ssdp_enabled and not args.no_ssdp
    llmnr_will_run = cfg.llmnr_enabled and not args.no_llmnr

    logger.info(f"DB                  : {db_path}")
    logger.info(f"Config file         : {args.config or 'config/config.json'}")
    logger.info(f"Scapy interval      : {scapy_interval}s")
    logger.info(f"Nmap quick interval : {nmap_quick_interval}s")
    logger.info(f"Nmap aggressive     : {nmap_aggressive_interval}s "
                f"({aggressive_workers} workers)")
    logger.info(f"mDNS discovery      : {'ON every ' + str(mdns_interval) + 's' if mdns_will_run else 'OFF'}")
    logger.info(f"DHCP sniffing       : {'ON, drained every ' + str(dhcp_drain_interval) + 's' if dhcp_will_run else 'OFF'}")
    logger.info(f"SSDP discovery      : {'ON every ' + str(ssdp_interval) + 's' if ssdp_will_run else 'OFF'}")
    logger.info(f"LLMNR discovery     : {'ON every ' + str(llmnr_interval) + 's' if llmnr_will_run else 'OFF'}")
    logger.info(f"Email alerts        : {'ON' if cfg.email_alerts_enabled else 'OFF'}")
    logger.info(f"Alert pipeline      : {'OFF (--no-alerts)' if args.no_alerts else 'ON'}")
    logger.info(f"Trust/Block links   : {'ON' if cfg.link_secret else 'OFF (no link_secret)'}")
    logger.info(f"API server          : {'ON at ' + cfg.api_host + ':' + str(cfg.api_port) if api_will_run else 'OFF'}")
    if api_will_run and not cfg.api_secret_key:
        logger.warning(
            "API server is starting WITHOUT authentication "
            "(CERBERUS_API_SECRET not set in .env) — "
            "only safe on a fully trusted local network."
        )
    logger.info("─" * 56)

    # --- Storage ---
    store = DeviceStore(db_path=db_path)

    # --- Intelligence ---
    trust_engine  = TrustEngine()
    learning_mode = None
    if not args.no_learning:
        learning_mode = LearningMode(
            device_store=store,
            duration_hours=learning_hours,
            state_file=cfg.learning_mode_state_file,
        )
        _handle_learning_mode_startup(learning_mode, args, logger)
        lm_s = learning_mode.status()
        logger.info(
            f"Learning mode status — active={lm_s['active']} | "
            f"remaining: {lm_s['remaining_str']} | "
            f"auto-trusted: {lm_s['auto_trusted']}"
        )

    # --- Alerts ---
    alert_manager = None
    if not args.no_alerts:
        alert_manager = _build_alert_manager(cfg, logger)

    # --- Scheduler (conductor) ---
    scheduler = Scheduler(
        device_store=store,
        trust_engine=trust_engine,
        learning_mode=learning_mode,
        alert_manager=alert_manager,
        scapy_interval=scapy_interval,
        nmap_quick_interval=nmap_quick_interval,
        nmap_aggressive_interval=nmap_aggressive_interval,
        aggressive_workers=aggressive_workers,
        mdns_enabled=mdns_will_run,
        mdns_interval=mdns_interval,
        dhcp_enabled=dhcp_will_run,
        dhcp_drain_interval=dhcp_drain_interval,
        ssdp_enabled=ssdp_will_run,
        ssdp_interval=ssdp_interval,
        llmnr_enabled=llmnr_will_run,
        llmnr_interval=llmnr_interval,
    )

    # --- Service seam — EVERYTHING attached, including Trust-link secret ---
    service = CerberusService(
        device_store=store,
        trust_engine=trust_engine,
        alert_manager=alert_manager,
        scheduler=scheduler,
        learning_mode=learning_mode,
        link_secret=cfg.link_secret,
        link_token_expiry_hours=cfg.link_token_expiry_hours,
    )

    # --- Embedded API server ---
    api_thread = None
    if api_will_run:
        api_thread = threading.Thread(
            target=run_server,
            kwargs={
                "service": service,
                "host": cfg.api_host,
                "port": cfg.api_port,
                "api_secret": cfg.api_secret_key,
            },
            name="api-server",
            daemon=True,
        )
        api_thread.start()
        logger.info(f"Embedded API server thread started → "
                    f"http://{cfg.api_host}:{cfg.api_port}/api/health")

    # --- Run ---
    try:
        scheduler.start(blocking=True)
    except KeyboardInterrupt:
        pass
    finally:
        logger.info("Cerberus shutting down...")
        scheduler.stop()
        _print_summary(store, logger)
        service.close()
        logger.info("Cerberus offline. Goodbye.")


if __name__ == "__main__":
    main()