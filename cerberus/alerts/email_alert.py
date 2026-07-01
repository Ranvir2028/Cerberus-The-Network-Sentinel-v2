# deps: none beyond stdlib (smtplib, email) + project config_loader
"""
alerts/email_alert.py

Job: one concrete alert channel — SMTP send, given a verdict + message.

Rules:
  - Reads SMTP credentials from config_loader.get_config() — never
    hardcoded, never reads env vars or files directly itself.
  - Knows NOTHING about cooldowns, trust logic, or scanning.
    alert_manager decides WHETHER to call this — this module only
    knows HOW to send.
  - Matches the (verdict, message) signature alert_manager.register_channel()
    expects: send_fn(verdict: DeviceVerdict, message: str) -> None
  - Any send failure raises — alert_manager already wraps channel calls
    in try/except per-channel, so a raised exception here is caught
    there and logged, without blocking other registered channels.
  - If email_alerts_enabled is False in config, send() is a no-op that
    logs at DEBUG and returns — lets you register the channel
    unconditionally without an extra "if enabled" check at every call site.

Usage:
    from cerberus.alerts.email_alert import EmailAlert

    email = EmailAlert()
    alert_manager.register_channel(email.send)
"""

import logging
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate
from typing import Optional

from cerberus.utils.config_loader import get_config
from cerberus.intelligence.trust_engine import DeviceVerdict, TrustVerdict

logger = logging.getLogger("cerberus.alerts.email_alert")


class EmailAlert:
    """
    SMTP email channel. One responsibility: send a message.

    Usage:
        email = EmailAlert()
        email.send(verdict, message)   # called by alert_manager._fire()
    """

    def __init__(self):
        cfg = get_config()

        self._enabled     = cfg.email_alerts_enabled
        self._host        = cfg.smtp_host
        self._port        = cfg.smtp_port
        self._sender      = cfg.smtp_sender
        self._password    = cfg.smtp_password
        self._recipients  = cfg.smtp_recipients

        if self._enabled:
            missing = []
            if not self._sender:
                missing.append("smtp_sender")
            if not self._password:
                missing.append("CERBERUS_SMTP_PASSWORD")
            if not self._recipients:
                missing.append("smtp_recipients")
            if missing:
                # config_loader._validate() should have already caught this
                # at get_config() time, but double-guard here in case this
                # class is ever constructed with a stale/forced config.
                logger.error(
                    f"EmailAlert enabled but missing: {', '.join(missing)}. "
                    "send() will no-op until fixed."
                )
                self._enabled = False

        logger.info(
            f"EmailAlert ready — "
            f"enabled={self._enabled} | "
            f"host={self._host}:{self._port} | "
            f"recipients={len(self._recipients)}"
        )

    # ------------------------------------------------------------------
    # Public API — matches alert_manager's send_fn(verdict, message) contract
    # ------------------------------------------------------------------

    def send(self, verdict: DeviceVerdict, message: str) -> None:
        """
        Send one alert email. Called by AlertManager._fire() — never
        called directly by scheduler, trust_engine, or anything else.

        Args:
            verdict : DeviceVerdict — used only for the subject line here.
                      alert_manager has already decided this is alert-worthy
                      and already formatted `message` — this method does
                      not re-evaluate trust or re-format content.
            message : Pre-formatted human-readable body from
                      alert_manager._format_message().

        Raises:
            Re-raises any smtplib/socket exception so alert_manager's
            per-channel try/except can log it and continue with other
            channels. Never silently swallows a real send failure.
        """
        if not self._enabled:
            logger.debug(
                "EmailAlert.send() called but email alerts disabled "
                "(or missing credentials) — no-op."
            )
            return

        subject = self._build_subject(verdict)
        msg = self._build_mime(subject, message)

        try:
            with smtplib.SMTP(self._host, self._port, timeout=15) as server:
                server.starttls()
                server.login(self._sender, self._password)
                server.sendmail(self._sender, self._recipients, msg.as_string())

            logger.info(
                f"[email] Alert sent — '{subject}' → "
                f"{len(self._recipients)} recipient(s)"
            )

        except smtplib.SMTPAuthenticationError as e:
            logger.error(
                f"[email] SMTP auth failed — check CERBERUS_SMTP_SENDER and "
                f"CERBERUS_SMTP_PASSWORD (must be an app password, not your "
                f"normal account password, for Gmail/most providers): {e}"
            )
            raise
        except (smtplib.SMTPException, OSError) as e:
            logger.error(f"[email] Send failed: {e}")
            raise

    def test_connection(self) -> bool:
        """
        Verify SMTP credentials work without sending a real alert.
        Useful for a one-off CLI/setup check before relying on this
        in production. Logs in and immediately quits — sends nothing.

        Returns:
            True if login succeeded, False otherwise (never raises).
        """
        if not self._enabled:
            logger.warning("test_connection() — email alerts not enabled.")
            return False

        try:
            with smtplib.SMTP(self._host, self._port, timeout=15) as server:
                server.starttls()
                server.login(self._sender, self._password)
            logger.info("[email] Test connection succeeded — credentials valid.")
            return True
        except Exception as e:
            logger.error(f"[email] Test connection failed: {e}")
            return False

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _build_subject(self, verdict: DeviceVerdict) -> str:
        """Short, scannable subject line — full detail lives in the body."""
        if verdict.verdict == TrustVerdict.UNTRUSTED_NEW:
            prefix = "🚨 Cerberus: NEW unknown device"
        else:
            prefix = "↩ Cerberus: returning unknown device"
        return f"{prefix} — {verdict.display_name} ({verdict.ip})"

    def _build_mime(self, subject: str, body: str) -> MIMEMultipart:
        msg = MIMEMultipart()
        msg["From"]    = self._sender
        msg["To"]      = ", ".join(self._recipients)
        msg["Subject"] = subject
        msg["Date"]    = formatdate(localtime=True)
        msg.attach(MIMEText(body, "plain", "utf-8"))
        return msg


# ---------------------------------------------------------------------------
# Standalone smoke-test — sends ONE real test email if credentials are set
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from datetime import datetime, timezone

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    email = EmailAlert()

    print("\n" + "=" * 60)
    print("EMAIL ALERT — SMOKE TEST")
    print("=" * 60)

    if not email._enabled:
        print(
            "\nEmail alerts are disabled or credentials are missing.\n"
            "Set CERBERUS_EMAIL_ALERTS=true and fill in CERBERUS_SMTP_SENDER / "
            "CERBERUS_SMTP_PASSWORD / CERBERUS_SMTP_RECIPIENTS in .env, then re-run."
        )
        sys.exit(1)

    print("\nStep 1: Testing SMTP login (no email sent yet)...")
    if not email.test_connection():
        print("Login failed — check credentials. See error above.")
        sys.exit(1)
    print("Login succeeded.\n")

    if "--send" not in sys.argv:
        print(
            "Skipping actual send. Re-run with --send to fire one real "
            "test email to your configured recipients."
        )
        sys.exit(0)

    print("Step 2: Sending one real test alert email...")

    fake_verdict = DeviceVerdict(
        mac="aa:bb:cc:dd:ee:ff",
        ip="192.168.1.250",
        verdict=TrustVerdict.UNTRUSTED_NEW,
        label=None,
        vendor="Test Vendor Inc.",
        hostname="test-device",
        os="Test OS",
        open_ports=[22, 80],
        first_seen=None,
        last_seen=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        network="192.168.1.0/24",
    )
    fake_message = (
        "This is a TEST alert from Cerberus v2's email_alert.py smoke test.\n"
        "If you received this, your SMTP configuration is working correctly.\n"
        "No actual unknown device was detected — this is a drill."
    )

    email.send(fake_verdict, fake_message)
    print("\nTest email sent. Check your inbox.")
    print("=" * 60)