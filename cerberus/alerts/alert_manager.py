"""
alerts/alert_manager.py

Job: receives trust verdicts from the scheduler/trust_engine pipeline
and decides whether to fire a notification, applying a cooldown window
per device so one intruder doesn't trigger 50 alerts over an hour.

Rules:
  - Cooldown per MAC: if a device was alerted within cooldown_minutes,
    skip it. Clock resets when the device disappears and reappears.
  - Channels (email, future: webhook, desktop) are owned by their own
    modules. alert_manager decides WHETHER to alert — channels only
    know HOW to send.
  - No storage writes — alert_manager never touches the DB. (The one
    exception in spirit, not in fact: Trust-link TOKEN GENERATION below
    is pure signing via utils/link_tokens.py, itself DB-free. Recording
    a token as REDEEMED is device_store.mark_token_used()'s job, called
    from api/server.py — not here.)
  - Reads config via get_config() — never hardcodes cooldown or toggles.
  - Thread-safe: scheduler calls process_verdicts() from worker threads.

Persistence note (module 13):
  process_verdicts() RETURNS the list of verdicts that were actually
  fired — see scheduler.py for how that's persisted to alerts_log.

VM/hypervisor tagging (Phase 3 hardening):
  message composition annotates the alert if the device's vendor
  matches a known virtualization platform — purely informational.

Email Trust/Block action links (this revision):
  Every alert-worthy verdict now gets composed into an AlertMessage —
  both a plain-text body (unchanged format from before) and a styled
  HTML body with two action elements:

    TRUST — a signed, single-use, time-limited link
      (utils/link_tokens.generate_token) pointing at
      <public_base_url>/confirm/trust/<token>. Clicking it lands on a
      confirmation page (api/server.py) that requires an explicit
      button click before calling service.trust_device() — this
      indirection exists specifically because some email providers
      pre-fetch/scan links before a human ever sees them, and a link
      that performed the trust action on mere GET would be silently
      triggered by that prefetching. See api/server.py's /confirm/
      trust/<token> routes for the confirmation step itself.

    BLOCK — per the operator's explicit decision, this is NOT an
      automated action. It is a direct link to the device's network
      gateway (http://<gateway>, from RouterDetector via
      set_network_gateways()) plus the router admin username/password
      displayed as plain text in the email, so the operator can log in
      and block the device manually. No per-router-vendor automation,
      no credentials submitted on the operator's behalf — Cerberus
      only ever navigates them to their own router's existing login
      page. If no gateway is known for the device's network, or no
      router credentials are configured, the email explains what's
      missing instead of showing a broken/incomplete section.

  Both links are built fresh per alert (trust_link needs a new signed
  token every time; block_link is just a lookup) inside
  _compose_message() — channels receive the finished AlertMessage and
  never build links themselves.

Block-this-device hint (superseded by the above):
  Earlier revisions embedded a text-only "block hint" pointing at the
  gateway inside the plain-text message body. That's now folded into
  AlertMessage.block_link + the dedicated Block section of both the
  text and HTML bodies, rather than being inline prose — same content,
  more structured.
"""

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional, Callable

from cerberus.intelligence.trust_engine import DeviceVerdict, TrustVerdict
from cerberus.detection.vendor_lookup import VendorLookup
from cerberus.utils.config_loader import get_config
from cerberus.utils.link_tokens import generate_token

logger = logging.getLogger("cerberus.alerts.alert_manager")


def _now() -> datetime:
    return datetime.now(timezone.utc)


@dataclass
class AlertMessage:
    """
    A composed alert, in both plain-text and HTML form, plus the
    Trust/Block action links this revision adds.

    Channels use whichever representation suits them — email_alert.py
    sends both .text and .html as a multipart/alternative message; a
    future channel (webhook, desktop notification, etc.) can read
    .text alone and ignore .html/.trust_link/.block_link entirely.
    alert_manager owns composing this; channels never build links or
    format bodies themselves.
    """
    text:       str
    html:       str
    trust_link: Optional[str] = None
    block_link: Optional[str] = None


class AlertManager:
    """
    Cooldown-aware alert dispatcher.

    Usage:
        manager = AlertManager()
        manager.register_channel(email.send)        # Phase 3
        manager.set_network_gateways({"192.168.1.0/24": "192.168.1.1"})
        fired = manager.process_verdicts(verdicts)    # called by scheduler

    Channel contract:
        A registered channel must be callable as
        send_fn(verdict: DeviceVerdict, message: AlertMessage) -> None
    """

    def __init__(self, cooldown_minutes: Optional[int] = None):
        cfg = get_config()
        self._cooldown = timedelta(
            minutes=cooldown_minutes
            if cooldown_minutes is not None
            else cfg.alert_cooldown_minutes
        )

        # Trust/Block link configuration — read once at construction,
        # same pattern as cooldown above. Never re-read per-alert; if
        # config changes at runtime the process needs a restart to
        # pick it up, consistent with how the rest of this class works.
        self._link_secret        = cfg.link_secret
        self._link_expiry_hours  = cfg.link_token_expiry_hours
        self._base_url           = (
            cfg.public_base_url or f"http://localhost:{cfg.api_port}"
        )
        self._router_user        = cfg.router_user
        self._router_password    = cfg.router_password

        # {mac: last_alerted_datetime} — in-memory only, resets on restart
        self._last_alerted: Dict[str, datetime] = {}
        self._lock = threading.Lock()

        # Registered alert channels — callables that accept (verdict, message)
        self._channels: List[Callable] = []

        # {network_cidr: gateway_ip} — populated by scheduler via
        # set_network_gateways(). Used for the Block link; never
        # affects trust decisions or whether an alert fires.
        self._network_gateways: Dict[str, str] = {}

        # Used only for display annotation in message composition —
        # never affects trust decisions or whether an alert fires.
        self._vendor_lookup = VendorLookup()

        # Alert counters for status()
        self._total_alerts_fired:   int = 0
        self._total_alerts_skipped: int = 0

        logger.info(
            f"AlertManager ready — "
            f"cooldown={self._cooldown.total_seconds() / 60:.0f}min | "
            f"channels={len(self._channels)} | "
            f"trust_link_base={self._base_url} | "
            f"router_creds={'configured' if self._router_user else 'not set'}"
        )

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def register_channel(self, send_fn: Callable) -> None:
        """
        Register an alert channel.
        send_fn must accept (verdict: DeviceVerdict, message: AlertMessage).
        """
        self._channels.append(send_fn)
        logger.info(f"Alert channel registered: {send_fn.__qualname__}")

    def set_network_gateways(self, gateways: Dict[str, str]) -> None:
        """
        Provide the {network_cidr: gateway_ip} map so the Block link can
        point at the device's actual router. Called by scheduler once
        it has detected networks — alert_manager never does network
        detection itself.

        Args:
            gateways: e.g. {"192.168.1.0/24": "192.168.1.1"}.
                      Networks with no known gateway can be omitted;
                      the Block section explains this is unavailable
                      for those devices instead of showing a dead link.
        """
        self._network_gateways = dict(gateways)
        logger.debug(f"Network gateways set: {self._network_gateways}")

    def process_verdicts(self, verdicts: List[DeviceVerdict]) -> List[DeviceVerdict]:
        """
        Main entry point — called by scheduler after every trust evaluation.
        Filters alert-worthy verdicts, applies cooldown, fires channels.

        Returns:
            The subset of verdicts that were ACTUALLY fired this cycle.
        """
        if not verdicts:
            return []

        alert_worthy = [v for v in verdicts if v.is_alert_worthy]
        if not alert_worthy:
            logger.debug(f"No alert-worthy verdicts this cycle.")
            return []

        fired: List[DeviceVerdict] = []
        for verdict in alert_worthy:
            if self._should_alert(verdict.mac):
                message = self._compose_message(verdict)
                self._fire(verdict, message)
                fired.append(verdict)
            else:
                logger.debug(
                    f"[cooldown] Skipping {verdict.mac} — "
                    f"alerted within last {self._cooldown.total_seconds() / 60:.0f}min."
                )
                with self._lock:
                    self._total_alerts_skipped += 1

        return fired

    def clear_cooldown(self, mac: str) -> None:
        """Reset the cooldown for one device — next detection will alert immediately."""
        mac = mac.lower()
        with self._lock:
            if mac in self._last_alerted:
                del self._last_alerted[mac]
                logger.info(f"Cooldown cleared for {mac}")

    def status(self) -> Dict:
        """Return alert manager state snapshot for CLI / service layer."""
        with self._lock:
            active_cooldowns = {
                mac: int((dt + self._cooldown - _now()).total_seconds() // 60)
                for mac, dt in self._last_alerted.items()
                if _now() < dt + self._cooldown
            }
        return {
            "cooldown_minutes":     int(self._cooldown.total_seconds() // 60),
            "channels_registered":  len(self._channels),
            "total_alerts_fired":   self._total_alerts_fired,
            "total_alerts_skipped": self._total_alerts_skipped,
            "active_cooldowns":     active_cooldowns,
        }

    # ------------------------------------------------------------------
    # Private — cooldown
    # ------------------------------------------------------------------

    def _should_alert(self, mac: str) -> bool:
        mac = mac.lower()
        with self._lock:
            last = self._last_alerted.get(mac)
            if last and _now() < last + self._cooldown:
                return False
            self._last_alerted[mac] = _now()
            return True

    # ------------------------------------------------------------------
    # Private — Trust/Block link building
    # ------------------------------------------------------------------

    def _build_trust_link(self, verdict: DeviceVerdict) -> Optional[str]:
        """
        Issue a fresh signed, single-use, time-limited token for this
        verdict's MAC and build the confirmation-page URL. A NEW token
        is generated every time this is called (i.e. every alert email),
        never reused — each email's Trust link is independently valid
        and independently single-use.

        Returns None (rather than raising) if token generation fails
        for any reason — a broken Trust link should never prevent the
        rest of the alert from being sent.
        """
        try:
            token, token_id, expires_at = generate_token(
                mac=verdict.mac,
                purpose="trust",
                secret=self._link_secret,
                expiry_hours=self._link_expiry_hours,
            )
            logger.debug(
                f"[token] Trust link issued — mac={verdict.mac} "
                f"token_id={token_id} expires={expires_at}"
            )
            return f"{self._base_url}/confirm/trust/{token}"
        except Exception as e:
            logger.error(
                f"[token] Failed to generate Trust link for {verdict.mac}: {e}"
            )
            return None

    def _build_block_link(self, verdict: DeviceVerdict) -> Optional[str]:
        """
        Look up the gateway for this verdict's network and build a
        direct link to the router's own admin page. Returns None if no
        gateway is known for this network — callers must handle that
        by explaining the Block section is unavailable, not by hiding
        it silently.
        """
        gateway = self._network_gateways.get(verdict.network)
        return f"http://{gateway}" if gateway else None

    # ------------------------------------------------------------------
    # Private — message composition
    # ------------------------------------------------------------------

    def _compose_message(self, verdict: DeviceVerdict) -> AlertMessage:
        """
        Build the full AlertMessage (text + html + links) for one
        verdict. This is the single place both representations are
        assembled, so text and html never drift out of sync in content
        (only in formatting).
        """
        trust_link = self._build_trust_link(verdict)
        block_link = self._build_block_link(verdict)

        text = self._build_text_message(verdict, trust_link, block_link)
        html = self._build_html_message(verdict, trust_link, block_link)

        return AlertMessage(
            text=text, html=html, trust_link=trust_link, block_link=block_link
        )

    def _build_text_message(
        self,
        verdict: DeviceVerdict,
        trust_link: Optional[str],
        block_link: Optional[str],
    ) -> str:
        """
        Plain-text alert body — unchanged formatting from before this
        revision, with Trust/Block now shown as plain URLs (a text
        client has no concept of a styled button) plus router creds
        inline for Block, same content the HTML version shows.
        """
        if verdict.verdict == TrustVerdict.UNTRUSTED_NEW:
            headline = "⚠ NEW UNKNOWN DEVICE DETECTED"
        else:
            headline = "↩ RETURNING UNKNOWN DEVICE"

        rand_note = ""
        if verdict.mac_randomization_suspected:
            rand_note = "\nNote: MAC randomization suspected — may be a known device."

        vm_note = ""
        if self._vendor_lookup.is_likely_hypervisor(verdict.vendor):
            vm_note = (
                "\nNote: vendor matches a known virtualization platform "
                "(VMware/VirtualBox/Hyper-V/etc) — possibly a VM running "
                "on a machine on this network, not necessarily an intruder. "
                "Verify before assuming malicious intent."
            )

        port_str = ""
        if verdict.open_ports:
            port_str = f"\nOpen ports : {', '.join(str(p) for p in verdict.open_ports[:10])}"

        trust_section = (
            f"\n\nTRUST THIS DEVICE:\n{trust_link}"
            if trust_link
            else "\n\nTRUST THIS DEVICE: link unavailable — check Cerberus logs."
        )

        if block_link:
            creds_line = (
                f"Router login — username: {self._router_user}  "
                f"password: {self._router_password}"
                if self._router_user and self._router_password
                else "Router credentials not configured "
                     "(set CERBERUS_ROUTER_USER / CERBERUS_ROUTER_PASSWORD in .env)."
            )
            block_section = (
                f"\n\nBLOCK THIS DEVICE:\n{block_link}\n{creds_line}"
            )
        else:
            block_section = (
                "\n\nBLOCK THIS DEVICE: no gateway known for this network — "
                "open your router's admin page manually."
            )

        msg = (
            f"{headline}\n"
            f"{'─' * 48}\n"
            f"Name       : {verdict.display_name}\n"
            f"IP address : {verdict.ip}\n"
            f"MAC address: {verdict.mac}\n"
            f"Vendor     : {verdict.vendor or 'unknown'}\n"
            f"Hostname   : {verdict.hostname or 'unknown'}\n"
            f"OS         : {verdict.os or 'unknown'}\n"
            f"Network    : {verdict.network or 'unknown'}"
            f"{port_str}"
            f"{rand_note}"
            f"{vm_note}\n"
            f"{'─' * 48}\n"
            f"First seen : {verdict.first_seen or 'this session'}\n"
            f"Last seen  : {verdict.last_seen or 'just now'}"
            f"{trust_section}"
            f"{block_section}"
        )
        return msg

    def _build_html_message(
        self,
        verdict: DeviceVerdict,
        trust_link: Optional[str],
        block_link: Optional[str],
    ) -> str:
        """
        Styled HTML alert body — dark HUD theme matching the dashboard
        (cyan/copper/coral), a real Trust button, and a Block section
        with the direct router link plus credentials shown as
        selectable text. Kept as a single self-contained HTML document
        with inline styles only — email clients strip <style> blocks
        and external stylesheets unpredictably, so every rule here is
        inline by necessity, not by choice.
        """
        is_new = verdict.verdict == TrustVerdict.UNTRUSTED_NEW
        headline = "NEW UNKNOWN DEVICE DETECTED" if is_new else "RETURNING UNKNOWN DEVICE"
        accent = "#FF5D4A" if is_new else "#E0913F"  # coral for new, copper for returning

        rand_note_html = ""
        if verdict.mac_randomization_suspected:
            rand_note_html = (
                '<p style="margin:12px 0 0;color:#E0913F;font-size:13px;">'
                'Note: MAC randomization suspected — may be a known device.</p>'
            )

        vm_note_html = ""
        if self._vendor_lookup.is_likely_hypervisor(verdict.vendor):
            vm_note_html = (
                '<p style="margin:12px 0 0;color:#3FE0E8;font-size:13px;">'
                'Note: vendor matches a known virtualization platform — '
                'possibly a VM on this network, not necessarily an intruder.</p>'
            )

        ports_html = ""
        if verdict.open_ports:
            ports_str = ", ".join(str(p) for p in verdict.open_ports[:10])
            ports_html = (
                f'<tr><td style="padding:4px 12px 4px 0;color:#7C8A9A;'
                f'font-size:12px;">Open ports</td>'
                f'<td style="padding:4px 0;color:#D7E1EA;font-family:monospace;'
                f'font-size:12px;">{ports_str}</td></tr>'
            )

        def _row(label: str, value: str) -> str:
            return (
                f'<tr><td style="padding:4px 12px 4px 0;color:#7C8A9A;'
                f'font-size:12px;white-space:nowrap;">{label}</td>'
                f'<td style="padding:4px 0;color:#D7E1EA;font-family:monospace;'
                f'font-size:12px;">{value}</td></tr>'
            )

        details_rows = (
            _row("IP address", verdict.ip)
            + _row("MAC address", verdict.mac)
            + _row("Vendor", verdict.vendor or "unknown")
            + _row("Hostname", verdict.hostname or "unknown")
            + _row("OS", verdict.os or "unknown")
            + _row("Network", verdict.network or "unknown")
            + ports_html
            + _row("First seen", verdict.first_seen or "this session")
            + _row("Last seen", verdict.last_seen or "just now")
        )

        if trust_link:
            trust_html = (
                f'<a href="{trust_link}" target="_blank" '
                f'style="display:inline-block;background:#3FE0E8;color:#080B10;'
                f'text-decoration:none;font-weight:700;font-size:13px;'
                f'letter-spacing:0.04em;text-transform:uppercase;'
                f'padding:12px 28px;border-radius:2px;">Trust this device</a>'
            )
        else:
            trust_html = (
                '<p style="color:#7C8A9A;font-size:13px;">'
                'Trust link unavailable — check Cerberus logs.</p>'
            )

        if block_link:
            if self._router_user and self._router_password:
                creds_html = (
                    f'<p style="margin:10px 0 0;color:#7C8A9A;font-size:12px;">'
                    f'Router login — username: '
                    f'<span style="color:#D7E1EA;font-family:monospace;">{self._router_user}</span>'
                    f'&nbsp;&nbsp;password: '
                    f'<span style="color:#D7E1EA;font-family:monospace;">{self._router_password}</span>'
                    f'</p>'
                )
            else:
                creds_html = (
                    '<p style="margin:10px 0 0;color:#7C8A9A;font-size:12px;">'
                    'Router credentials not configured — set CERBERUS_ROUTER_USER '
                    '/ CERBERUS_ROUTER_PASSWORD in .env to show them here.</p>'
                )
            block_html = (
                f'<a href="{block_link}" target="_blank" '
                f'style="display:inline-block;background:transparent;color:#FF5D4A;'
                f'text-decoration:none;font-weight:700;font-size:13px;'
                f'letter-spacing:0.04em;text-transform:uppercase;'
                f'padding:11px 27px;border:1px solid #FF5D4A;border-radius:2px;">'
                f'Open router admin panel</a>{creds_html}'
            )
        else:
            block_html = (
                '<p style="color:#7C8A9A;font-size:13px;">'
                'No gateway known for this network — open your router\'s '
                'admin page manually.</p>'
            )

        html = f"""\
<html>
<body style="margin:0;padding:0;background:#080B10;font-family:Arial,Helvetica,sans-serif;">
  <table role="presentation" width="100%" cellpadding="0" cellspacing="0" style="background:#080B10;padding:24px 0;">
    <tr><td align="center">
      <table role="presentation" width="560" cellpadding="0" cellspacing="0"
             style="background:#0E141C;border:1px solid #1C2733;">
        <tr>
          <td style="padding:20px 24px;border-bottom:1px solid #1C2733;">
            <span style="color:#3FE0E8;font-family:monospace;font-size:11px;
                         letter-spacing:0.15em;text-transform:uppercase;">
              // Cerberus — Network Sentinel</span>
          </td>
        </tr>
        <tr>
          <td style="padding:24px;">
            <p style="margin:0 0 16px;color:{accent};font-weight:700;
                      font-size:15px;letter-spacing:0.04em;text-transform:uppercase;">
              {headline}
            </p>
            <p style="margin:0 0 16px;color:#D7E1EA;font-size:16px;font-weight:600;">
              {verdict.display_name}
            </p>
            <table role="presentation" cellpadding="0" cellspacing="0" style="width:100%;margin-bottom:8px;">
              {details_rows}
            </table>
            {rand_note_html}
            {vm_note_html}
          </td>
        </tr>
        <tr>
          <td style="padding:0 24px 24px;">
            <p style="margin:0 0 10px;color:#4A5866;font-size:10.5px;
                      letter-spacing:0.1em;text-transform:uppercase;">Trust</p>
            {trust_html}
          </td>
        </tr>
        <tr>
          <td style="padding:0 24px 24px;border-top:1px solid #1C2733;padding-top:20px;">
            <p style="margin:0 0 10px;color:#4A5866;font-size:10.5px;
                      letter-spacing:0.1em;text-transform:uppercase;">Block</p>
            {block_html}
          </td>
        </tr>
      </table>
    </td></tr>
  </table>
</body>
</html>"""
        return html

    # ------------------------------------------------------------------
    # Private — dispatch
    # ------------------------------------------------------------------

    def _fire(self, verdict: DeviceVerdict, message: AlertMessage) -> None:
        severity = (
            "CRITICAL" if verdict.verdict == TrustVerdict.UNTRUSTED_NEW
            else "WARNING"
        )
        logger.log(
            logging.CRITICAL if severity == "CRITICAL" else logging.WARNING,
            f"[alert] {severity} — {verdict.display_name} | "
            f"{verdict.ip} | {verdict.mac} | "
            f"verdict={verdict.verdict.value}"
        )

        if not self._channels:
            logger.debug("[alert] No channels registered — logged only.")
        else:
            for channel in self._channels:
                try:
                    channel(verdict, message)
                except Exception as e:
                    logger.error(
                        f"[alert] Channel {channel.__qualname__} failed: {e}"
                    )

        with self._lock:
            self._total_alerts_fired += 1