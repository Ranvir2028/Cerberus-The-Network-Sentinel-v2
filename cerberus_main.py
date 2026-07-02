"""
cerberus_main.py — Phase 1+2+3 headless engine.

Config priority: env vars > config/config.json > built-in defaults.
CLI args override config file for quick one-off runs.

Scan tiers:
  Scapy ARP        every scapy_interval       (default 60s)
  Nmap quick       every nmap_quick_interval   (default 180s)
  Nmap aggressive  every nmap_aggressive_interval (default 360s)
  mDNS discovery   every mdns_interval         (default 120s, global)

Learning-mode auto-start (bugfix, this revision):
  Previously, learning_mode.start() was called UNCONDITIONALLY on every
  launch — meaning if you deliberately stopped learning mode via the
  CLI (`learning stop`) and then restarted the scanner, it would
  silently re-open a brand new 24h auto-trust window, undoing your
  decision with no warning. Fixed: this now checks
  learning_mode.has_ever_started() first. A genuine first-ever run
  (no state file, or a state file that's never recorded a start) still
  auto-starts exactly as before. Any run after that — including after
  a deliberate stop — does NOT auto-start; the operator must explicitly
  run `learning start` (CLI) or POST /api/learning/start (API), or pass
  --force-relearn, e.g. when they've deliberately changed network
  location and want a fresh trust-everything baseline.
"""

import argparse
import logging
import sys
import os
import threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from cerberus.utils.logger import setup_logging
from cerberus.utils.config_loader import get_config, ConfigError
from cerberus.storage.device_store import DeviceStore
from cerberus.core.scheduler import Scheduler
from cerberus.intelligence.trust_engine import TrustEngine
from cerberus.intelligence.learning_mode import LearningMode
from cerberus.alerts.alert_manager import AlertManager
from cerberus.alerts.email_alert import EmailAlert
from cerberus.service.cerberus_service import CerberusService
from cerberus.api.server import run_server
from cerberus.utils.npcap_installer import handle_npcap_installation


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
║          Three-Tier Aggressive Scanner               ║
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
                ports   = d.get("open_ports") or []
                svc     = d.get("services") or {}
                logger.info(
                    f"  {d['ip']:<16} {d['mac']}  "
                    f"{vendor:<22} {os_name}{acc_str}  [{tag}]{label}"
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


def main() -> None:
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
    learning_hours           = args.learning_hours           or cfg.learning_mode_hours

    _ensure_dirs(db_path, log_file)
    logger = setup_logging(
        log_file=log_file,
        level=log_level,
        silent_mode=args.silent,
    )

    api_will_run  = cfg.api_enabled  and not args.no_api
    mdns_will_run = cfg.mdns_enabled and not args.no_mdns

    _print_banner(logger)
    
    # Npcap check — Windows-only, no-ops cleanly on Linux/macOS
    if not handle_npcap_installation():
        logger.critical("Npcap unavailable and required for scanning. Exiting.")
        sys.exit(1)

    logger.info(f"DB                  : {db_path}")
    logger.info(f"Config file         : {args.config or 'config/config.json'}")
    logger.info(f"Scapy interval      : {scapy_interval}s")
    logger.info(f"Nmap quick interval : {nmap_quick_interval}s")
    logger.info(f"Nmap aggressive     : {nmap_aggressive_interval}s "
                f"({aggressive_workers} workers)")
    logger.info(f"mDNS discovery      : {'ON every ' + str(mdns_interval) + 's' if mdns_will_run else 'OFF'}")
    logger.info(f"Email alerts        : {'ON' if cfg.email_alerts_enabled else 'OFF'}")
    logger.info(f"Alert pipeline      : {'OFF (--no-alerts)' if args.no_alerts else 'ON'}")
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
            state_file="data/learning_mode.json",
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
    )

    # --- Service seam — EVERYTHING attached ---
    service = CerberusService(
        device_store=store,
        trust_engine=trust_engine,
        alert_manager=alert_manager,
        scheduler=scheduler,
        learning_mode=learning_mode,
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
        store.close()
        logger.info("Cerberus offline. Goodbye.")


if __name__ == "__main__":
    main()