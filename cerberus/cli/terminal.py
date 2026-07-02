# deps: none beyond stdlib + project modules
"""
cli/terminal.py

Job: thin text rendering over service/cerberus_service.py — and NOTHING
else. This module's real purpose is proof: if every command here works
correctly using only the service seam, the seam is real, not theoretical.

Rules:
  - NEVER imports device_store, trust_engine, alert_manager, or scheduler
    directly. Only cerberus_service.CerberusService.
  - Runs as its OWN process, separate from cerberus_main.py's scan loop.
    This works safely because device_store.py opens SQLite with
    PRAGMA journal_mode=WAL — which explicitly supports one writer
    (the running scanner) and multiple readers/writers from other
    processes (this CLI) concurrently, without corruption.
  - No scheduler reference is available in this process (the scanner
    runs in a different OS process). get_scan_status() will report
    {"attached": False} — this is expected, not a bug.
  - learning_mode IS constructed here, pointed at the SAME state file
    cerberus_main.py uses. Because learning_mode.py re-syncs from that
    file's mtime on every check (see its module docstring), the
    `learning stop` command issued from THIS process will actually
    take effect in the live scanner's process within one scan cycle —
    this is real cross-process control, not a CLI-local-only no-op.
  - alert_manager IS constructed here too (for clear_cooldown on
    trust/untrust), but it is a SEPARATE in-memory instance from the
    one running inside cerberus_main.py — cooldown state is NOT
    shared across processes for alert_manager (unlike learning_mode,
    which IS file-synced). Functionally harmless: trust_engine's
    verdict is what actually matters for whether future alerts fire,
    and that IS shared via the DB.

Usage:
    python -m cerberus.cli.terminal list
    python -m cerberus.cli.terminal list --untrusted
    python -m cerberus.cli.terminal show aa:bb:cc:dd:ee:ff
    python -m cerberus.cli.terminal intruders
    python -m cerberus.cli.terminal trust aa:bb:cc:dd:ee:ff
    python -m cerberus.cli.terminal untrust aa:bb:cc:dd:ee:ff
    python -m cerberus.cli.terminal label aa:bb:cc:dd:ee:ff "Harsh's Laptop"
    python -m cerberus.cli.terminal history aa:bb:cc:dd:ee:ff
    python -m cerberus.cli.terminal alerts
    python -m cerberus.cli.terminal status
    python -m cerberus.cli.terminal learning status
    python -m cerberus.cli.terminal learning stop
"""

import argparse
import sys
import os
from typing import Dict, List

sys.path.insert(
    0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
)

from cerberus.utils.logger import setup_logging
from cerberus.utils.config_loader import get_config, ConfigError
from cerberus.storage.device_store import DeviceStore
from cerberus.intelligence.trust_engine import TrustEngine
from cerberus.intelligence.learning_mode import LearningMode
from cerberus.alerts.alert_manager import AlertManager
from cerberus.detection.vendor_lookup import VendorLookup
from cerberus.service.cerberus_service import CerberusService

# Module-level — cheap to construct (just an OUI file read), used purely
# for display annotation, never for trust decisions.
_vendor_lookup = VendorLookup()


# ---------------------------------------------------------------------------
# Construction — CLI builds its own service instance, same DB + state files
# ---------------------------------------------------------------------------

def _build_service(args: argparse.Namespace) -> CerberusService:
    """
    Construct a CerberusService for this CLI invocation. Reads the same
    config (and therefore the same db_path / learning_mode state_file)
    as cerberus_main.py, so it points at the exact same files — just
    from a separate process.
    """
    try:
        cfg = get_config(config_file=args.config)
    except ConfigError as e:
        print(f"\n[CONFIG ERROR] {e}\n")
        sys.exit(1)

    # Logging suppressed to file only — CLI output should be clean,
    # not interleaved with INFO-level construction noise.
    setup_logging(log_file=cfg.log_file, level="WARNING", silent_mode=True)

    store         = DeviceStore(db_path=cfg.db_path)
    trust_engine  = TrustEngine()
    alert_manager = AlertManager()   # separate instance — see module docstring
    learning_mode = LearningMode(
        device_store=store,
        duration_hours=cfg.learning_mode_hours,
        state_file="data/learning_mode.json",
    )

    return CerberusService(
        device_store=store,
        trust_engine=trust_engine,
        alert_manager=alert_manager,
        scheduler=None,   # no scheduler in this process — see docstring
        learning_mode=learning_mode,
    )


# ---------------------------------------------------------------------------
# Rendering helpers — pure text formatting, no logic
# ---------------------------------------------------------------------------

def _fmt_trust(trusted: bool) -> str:
    return "✔ trusted" if trusted else "? unknown"


def _fmt_vendor(vendor: str) -> str:
    """Vendor string, with a VM tag appended if it matches a hypervisor."""
    vendor = vendor or "unknown vendor"
    if _vendor_lookup.is_likely_hypervisor(vendor):
        return f"{vendor} (possible VM)"
    return vendor


def _print_device_row(d: Dict) -> None:
    tag    = _fmt_trust(d.get("trusted", False))
    vendor = _fmt_vendor(d.get("vendor"))
    label  = f" [{d['label']}]" if d.get("label") else ""
    print(
        f"  {d.get('ip',''):<16} {d.get('mac',''):<18} "
        f"{vendor:<32} {tag}{label}"
    )


def _print_device_table(devices: List[Dict], title: str) -> None:
    print(f"\n{title} ({len(devices)})")
    print("-" * 80)
    if not devices:
        print("  (none)")
        return
    for d in devices:
        _print_device_row(d)
    print()


def _print_device_detail(d: Dict) -> None:
    vendor = _fmt_vendor(d.get("vendor"))
    print("\n" + "=" * 60)
    print(f"  DEVICE DETAIL — {d.get('mac','')}")
    print("=" * 60)
    print(f"  IP          : {d.get('ip','')}")
    print(f"  Network     : {d.get('network','')}")
    print(f"  Vendor      : {vendor}")
    print(f"  Hostname    : {d.get('hostname') or 'unknown'}")
    print(f"  OS          : {d.get('os') or 'unknown'}"
          + (f" ({d['os_accuracy']}%)" if d.get('os_accuracy') else ""))
    print(f"  Label       : {d.get('label') or '(none)'}")
    print(f"  Trust       : {_fmt_trust(d.get('trusted', False))}")
    ports = d.get("open_ports") or []
    print(f"  Open ports  : {ports if ports else 'none'}")
    services = d.get("services") or {}
    for port in ports[:10]:
        s = services.get(port) or services.get(str(port)) or {}
        svc_str = f"{s.get('name','')} {s.get('product','')} {s.get('version','')}".strip()
        print(f"    {port}/tcp  {svc_str or 'unknown'}")
    print(f"  First seen  : {d.get('first_seen','')}")
    print(f"  Last seen   : {d.get('last_seen','')}")
    print("=" * 60 + "\n")


def _print_alerts(alerts: List[Dict]) -> None:
    print(f"\nRECENT ALERTS ({len(alerts)})")
    print("-" * 70)
    if not alerts:
        print("  (none fired yet)")
        return
    for a in alerts:
        print(
            f"  {a.get('fired_at',''):<20} {a.get('verdict',''):<22} "
            f"{a.get('ip',''):<16} {a.get('message_summary','')}"
        )
    print()


def _print_status(full_status: Dict) -> None:
    devices = full_status["devices"]
    alerts  = full_status["alerts"]
    am      = full_status["alert_manager"]
    lm      = full_status["learning_mode"]
    scan    = full_status["scan"]

    print("\n" + "=" * 60)
    print("  CERBERUS STATUS")
    print("=" * 60)
    print(f"  Devices       : {devices['total']} total | "
          f"{devices['trusted']} trusted | {devices['untrusted']} untrusted")
    print(f"  Alerts (life) : {alerts['total']} total | "
          f"{alerts['new_unknown']} new | {alerts['returning_unknown']} returning")

    if am.get("attached"):
        print(f"  Alert manager : cooldown={am['cooldown_minutes']}min | "
              f"channels={am['channels_registered']} | "
              f"active cooldowns={len(am['active_cooldowns'])}")
    else:
        print("  Alert manager : not attached in this CLI process "
              "(separate instance from the running scanner — expected)")

    if lm.get("active"):
        print(f"  Learning mode : ACTIVE | remaining={lm['remaining_str']} | "
              f"auto-trusted so far={lm['auto_trusted']}")
        print("                  Every newly discovered device is being "
              "auto-trusted right now. Run 'learning stop' to end this early.")
    else:
        print("  Learning mode : not active")

    if scan.get("attached"):
        print(f"  Scan engine   : running={scan['running']} | "
              f"networks={scan['networks']}")
    else:
        print("  Scan engine   : not attached in this CLI process — "
              "the scanner runs in cerberus_main.py's own process. "
              "Live scan status is available via the API server "
              "(Module 15), which runs inside that same process.")
    print("=" * 60 + "\n")


# ---------------------------------------------------------------------------
# Commands — each is a thin call into service, then a print
# ---------------------------------------------------------------------------

def cmd_list(service: CerberusService, args: argparse.Namespace) -> None:
    if args.trusted and args.untrusted:
        print("Error: --trusted and --untrusted are mutually exclusive.")
        return
    trusted_only = True if args.trusted else (False if args.untrusted else None)
    devices = service.get_devices(trusted_only=trusted_only)
    title = (
        "TRUSTED DEVICES" if trusted_only is True else
        "UNTRUSTED DEVICES" if trusted_only is False else
        "ALL DEVICES"
    )
    _print_device_table(devices, title)


def cmd_show(service: CerberusService, args: argparse.Namespace) -> None:
    device = service.get_device(args.mac)
    if not device:
        print(f"\nNo device found for MAC: {args.mac}\n")
        return
    _print_device_detail(device)


def cmd_intruders(service: CerberusService, args: argparse.Namespace) -> None:
    devices = service.get_devices(trusted_only=False)
    _print_device_table(devices, "UNTRUSTED DEVICES (\"intruders\")")


def cmd_trust(service: CerberusService, args: argparse.Namespace) -> None:
    ok = service.trust_device(args.mac)
    if ok:
        print(f"\n✔ {args.mac} marked TRUSTED.\n")
    else:
        print(f"\nMAC not found: {args.mac}\n")


def cmd_untrust(service: CerberusService, args: argparse.Namespace) -> None:
    ok = service.untrust_device(args.mac)
    if ok:
        print(f"\n? {args.mac} marked UNTRUSTED. "
              "It will be re-evaluated as unknown on the next scan cycle.\n")
    else:
        print(f"\nMAC not found: {args.mac}\n")


def cmd_label(service: CerberusService, args: argparse.Namespace) -> None:
    ok = service.label_device(args.mac, args.name)
    if ok:
        shown = args.name or "(cleared)"
        print(f"\nLabel for {args.mac} set to: {shown}\n")
    else:
        print(f"\nMAC not found: {args.mac}\n")


def cmd_delete(service: CerberusService, args: argparse.Namespace) -> None:
    ok = service.delete_device(args.mac)
    if ok:
        print(f"\nDevice {args.mac} deleted (and its scan history).\n")
    else:
        print(f"\nMAC not found: {args.mac}\n")


def cmd_history(service: CerberusService, args: argparse.Namespace) -> None:
    rows = service.get_device_history(args.mac, limit=args.limit)
    print(f"\nSCAN HISTORY — {args.mac} (last {len(rows)})")
    print("-" * 70)
    if not rows:
        print("  (no history — MAC may not exist, or has never been scanned)")
    for r in rows:
        print(f"  {r['seen_at']:<20} {r['scanner']:<16} {r['ip']:<16} via {r['interface']}")
    print()


def cmd_alerts(service: CerberusService, args: argparse.Namespace) -> None:
    alerts = service.get_recent_alerts(limit=args.limit)
    _print_alerts(alerts)


def cmd_status(service: CerberusService, args: argparse.Namespace) -> None:
    _print_status(service.get_full_status())


def cmd_learning(service: CerberusService, args: argparse.Namespace) -> None:
    if args.action == "status":
        lm = service.get_learning_mode_status()
        print("\n" + "=" * 50)
        print("  LEARNING MODE STATUS")
        print("=" * 50)
        if lm["active"]:
            print(f"  Active            : YES")
            print(f"  Remaining         : {lm['remaining_str']}")
            print(f"  Auto-trusted      : {lm['auto_trusted']} device(s)")
            print(f"  Started at        : {lm['started_at']}")
            print(f"  Ends at           : {lm['ends_at']}")
        else:
            print("  Active            : NO")
        print("=" * 50 + "\n")

    elif args.action == "stop":
        ok = service.stop_learning_mode()
        if ok:
            print(
                "\nLearning mode STOP signal written.\n"
                "If a Cerberus scanner is currently running, it will pick "
                "this up and stop auto-trusting new devices within one "
                "scan cycle (≤ ~60s by default).\n"
            )
        else:
            print(
                "\nNo learning_mode state available — nothing to stop.\n"
            )

    elif args.action == "start":
        ok = service.start_learning_mode(
            force_restart=True, duration_hours=args.hours
        )
        if ok:
            hours_note = f"{args.hours}h" if args.hours else "the configured default duration"
            print(
                f"\nLearning mode START signal written — window: {hours_note}.\n"
                "Use this when you've deliberately changed network location "
                "(e.g. a different home) and want a fresh trust-everything "
                "baseline. If a scanner is running, it will pick this up "
                "within one scan cycle.\n"
                "Note: this does NOT auto-fire on every restart — only when "
                "you explicitly run this command.\n"
            )
        else:
            print(
                "\nNo learning_mode available in this process to start.\n"
            )


# ---------------------------------------------------------------------------
# Argument parsing
# ---------------------------------------------------------------------------

def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cerberus-cli",
        description="Cerberus v2 — terminal interface. Talks ONLY to service/cerberus_service.py.",
    )
    parser.add_argument("--config", default=None, help="Path to config.json")
    sub = parser.add_subparsers(dest="command", required=True)

    p_list = sub.add_parser("list", help="List devices")
    p_list.add_argument("--trusted", action="store_true", help="Show only trusted devices")
    p_list.add_argument("--untrusted", action="store_true", help="Show only untrusted devices")
    p_list.set_defaults(func=cmd_list)

    p_show = sub.add_parser("show", help="Show full detail for one device")
    p_show.add_argument("mac", help="MAC address")
    p_show.set_defaults(func=cmd_show)

    p_intr = sub.add_parser("intruders", help="Shortcut for: list --untrusted")
    p_intr.set_defaults(func=cmd_intruders)

    p_trust = sub.add_parser("trust", help="Mark a device trusted")
    p_trust.add_argument("mac", help="MAC address")
    p_trust.set_defaults(func=cmd_trust)

    p_untrust = sub.add_parser("untrust", help="Mark a device untrusted")
    p_untrust.add_argument("mac", help="MAC address")
    p_untrust.set_defaults(func=cmd_untrust)

    p_label = sub.add_parser("label", help="Assign a human-readable name to a device")
    p_label.add_argument("mac", help="MAC address")
    p_label.add_argument("name", help="Label text (use '' to clear)")
    p_label.set_defaults(func=cmd_label)

    p_delete = sub.add_parser("delete", help="Delete a device and its history")
    p_delete.add_argument("mac", help="MAC address")
    p_delete.set_defaults(func=cmd_delete)

    p_history = sub.add_parser("history", help="Show scan history for one device")
    p_history.add_argument("mac", help="MAC address")
    p_history.add_argument("--limit", type=int, default=20)
    p_history.set_defaults(func=cmd_history)

    p_alerts = sub.add_parser("alerts", help="Show recent fired alerts")
    p_alerts.add_argument("--limit", type=int, default=20)
    p_alerts.set_defaults(func=cmd_alerts)

    p_status = sub.add_parser("status", help="Show overall system status")
    p_status.set_defaults(func=cmd_status)

    p_learning = sub.add_parser("learning", help="View or control learning mode")
    p_learning.add_argument("action", choices=["status", "stop", "start"])
    p_learning.add_argument("--hours", type=int, default=None,
                            help="Override window duration in hours (only used with 'start')")
    p_learning.set_defaults(func=cmd_learning)

    return parser


def main() -> None:
    parser = _build_parser()
    args = parser.parse_args()

    service = _build_service(args)
    try:
        args.func(service, args)
    finally:
        # Service doesn't expose close() directly (it's not its job to —
        # it's a thin seam, not a lifecycle owner) but the underlying
        # store does, and the CLI process is short-lived per invocation,
        # so closing it here is the correct place.
        service._store.close()


if __name__ == "__main__":
    main()