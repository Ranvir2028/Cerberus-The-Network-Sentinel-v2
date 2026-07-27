"""
One concrete alert channel: SMTP send, given a verdict plus an already-
composed AlertMessage. Reads SMTP creds from get_config() only, knows
nothing about cooldowns/trust/scanning — alert_manager decides whether
to call this and builds the whole message, this file just sends it.
Signature matches what register_channel() expects:
send_fn(verdict, message) -> None. Raises on failure (alert_manager
already wraps each channel in try/except so one bad channel doesn't
block the rest). No-ops quietly if email_alerts_enabled is False.

Sends the message as multipart/alternative: text part first, HTML part
last, per RFC 2046's convention that clients render the last part they
support — so HTML-capable clients show the styled Trust/Block buttons
and everything else falls back to plain text with the same info as
plain URLs.

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
                                        # message is an AlertMessage
                                        # (see alert_manager.py), not a
                                        # plain string
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

    def send(self, verdict: DeviceVerdict, message) -> None:
        """
        Send one alert email. Called by AlertManager._fire() — never
        called directly by scheduler, trust_engine, or anything else.

        Args:
            verdict : DeviceVerdict — used only for the subject line here.
                      alert_manager has already decided this is alert-worthy
                      and already formatted the message content — this
                      method does not re-evaluate trust or re-format content.
            message : alerts.alert_manager.AlertMessage — carries both
                      .text and .html bodies, already fully composed
                      (Trust link, Block link, router creds, all baked
                      in) by alert_manager. This module reads .text and
                      .html only; it never inspects .trust_link or
                      .block_link directly, since it has no business
                      logic of its own about what those mean.

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

    def _build_mime(self, subject: str, message) -> MIMEMultipart:
        """
        Build a multipart/alternative message with both the plain-text
        and HTML bodies from the AlertMessage. "alternative" (not
        "mixed") tells email clients these two parts represent the SAME
        content in two forms — render one or the other, not both.

        message is duck-typed here rather than type-hinted against
        AlertMessage directly, to avoid a circular import between
        alert_manager.py and this module (alert_manager already imports
        FROM email_alert indirectly via cerberus_main.py's wiring, not
        the reverse — but keeping this module import-light is simplest).
        Any object with .text and .html string attributes works.
        """
        msg = MIMEMultipart("alternative")
        msg["From"]    = self._sender
        msg["To"]      = ", ".join(self._recipients)
        msg["Subject"] = subject
        msg["Date"]    = formatdate(localtime=True)

        text_body = getattr(message, "text", None) or str(message)
        html_body = getattr(message, "html", None)

        # Plain-text part first, HTML part last — most clients render
        # the LAST alternative part they're capable of displaying, so
        # this ordering makes HTML the "preferred" rendering wherever
        # supported, with .text as the genuine fallback everywhere else.
        msg.attach(MIMEText(text_body, "plain", "utf-8"))
        if html_body:
            msg.attach(MIMEText(html_body, "html", "utf-8"))

        return msg


# ---------------------------------------------------------------------------
# Standalone smoke-test — sends ONE real test email if credentials are set
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import sys
    from dataclasses import dataclass
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

    print("Step 2: Sending one real test alert email (with HTML + text parts)...")

    # Minimal local stand-in for AlertMessage — avoids importing
    # alert_manager.py just for this smoke test (keeps this test
    # runnable even if alert_manager.py has an unrelated issue).
    @dataclass
    class _FakeAlertMessage:
        text: str
        html: str
        trust_link: str = None
        block_link: str = None

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
    fake_message = _FakeAlertMessage(
        text=(
            "This is a TEST alert from Cerberus v2's email_alert.py smoke test.\n"
            "If you received this, your SMTP configuration is working correctly.\n"
            "No actual unknown device was detected — this is a drill.\n\n"
            "TRUST THIS DEVICE:\nhttp://localhost:5000/confirm/trust/FAKE_TOKEN\n\n"
            "BLOCK THIS DEVICE:\nhttp://192.168.1.1\n"
            "Router login — username: admin  password: (test)"
        ),
        html=(
            "<html><body style='background:#080B10;color:#D7E1EA;"
            "font-family:sans-serif;padding:24px;'>"
            "<h2 style='color:#FF5D4A;'>TEST ALERT</h2>"
            "<p>This is a TEST alert from Cerberus v2's email_alert.py smoke test.</p>"
            "<p>If you can read this styled version, HTML rendering works.</p>"
            "<a href='http://localhost:5000/confirm/trust/FAKE_TOKEN' "
            "style='background:#3FE0E8;color:#080B10;padding:12px 24px;"
            "text-decoration:none;font-weight:bold;'>Trust this device</a>"
            "</body></html>"
        ),
        trust_link="http://localhost:5000/confirm/trust/FAKE_TOKEN",
        block_link="http://192.168.1.1",
    )

    email.send(fake_verdict, fake_message)
    print("\nTest email sent — check your inbox for both a styled HTML view "
          "and, if you view 'plain text' / 'original message', the text fallback.")
    print("=" * 60)