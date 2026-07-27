"""
Generates and verifies signed, time-limited tokens for the email
Trust-confirmation links (/confirm/trust/<token> in api/server.py,
composed in alert_manager.py). Owns signature + expiry checking only —
"already used" is device_store's used_tokens table
(mark_token_used / is_token_used), checked separately by server.py
after verify_token() passes here. Splitting it this way keeps this
module DB-free and easy to unit-test, and keeps device_store as the
one place that owns "has this been redeemed," consistent with it being
the only module allowed to touch SQLite.

Token format: <base64url-payload>.<hex-hmac-signature>, where the
payload is JSON: mac (lowercase), purpose (e.g. "trust"), jti (random
single-use id, the primary key used_tokens tracks), and exp (unix
expiry). HMAC instead of a DB-only random token means server.py can
verify authenticity and expiry without a DB round-trip and without
ever storing the unredeemed token anywhere — the signature itself
(derived from cfg.link_secret) proves it was genuinely issued by this
instance. The DB only records tokens after redemption.

Signature comparison uses hmac.compare_digest() for constant time, jti
comes from secrets.token_urlsafe() so it's not guessable or
sequential, and mac/purpose/exp are all covered by the signature so
none of them can be tampered with in transit without invalidating it.
Tokens are stateless until redeemed — losing or restarting the DB
doesn't invalidate outstanding tokens, only cfg.link_secret changing
does (e.g. a restart with no persisted CERBERUS_LINK_SECRET — see
config_loader's ephemeral-secret warning).

Usage:
    from cerberus.utils.link_tokens import generate_token, verify_token, TokenError

    token, token_id, expires_at = generate_token(
        mac="aa:bb:cc:dd:ee:ff",
        purpose="trust",
        secret=cfg.link_secret,
        expiry_hours=cfg.link_token_expiry_hours,
    )
    # ... embed `token` in the email link ...

    try:
        payload = verify_token(token, secret=cfg.link_secret)
        # payload.mac, payload.purpose, payload.token_id, payload.expires_at
    except TokenError as e:
        # e.reason: "malformed" | "bad_signature" | "expired"
        ...
"""

import base64
import hashlib
import hmac
import json
import logging
import secrets
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Optional

logger = logging.getLogger("cerberus.utils.link_tokens")


class TokenError(Exception):
    """
    Raised by verify_token() for any reason a token should be rejected.

    Attributes:
        reason: short machine-readable code — "malformed", "bad_signature",
                or "expired" — so api/server.py can show an appropriate
                message without string-matching the exception text.
    """

    def __init__(self, reason: str, message: str = ""):
        self.reason = reason
        super().__init__(message or reason)


@dataclass
class TokenPayload:
    """Decoded, VERIFIED token contents. Only ever constructed by
    verify_token() after signature + expiry checks pass."""
    mac:         str
    purpose:     str
    token_id:    str   # the "jti" — what device_store.used_tokens keys on
    expires_at:  str   # ISO 8601 UTC string, for audit/display purposes


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def generate_token(
    mac: str,
    purpose: str,
    secret: str,
    expiry_hours: int = 72,
) -> "tuple[str, str, str]":
    """
    Create a new signed, single-use, time-limited token.

    Args:
        mac          : Device MAC this token authorizes an action for.
                       Lowercased before signing.
        purpose      : What the token allows, e.g. "trust". Bound into
                       the signature — a token issued for "trust" can
                       never be reinterpreted as authorizing anything else.
        secret       : cfg.link_secret. Required, non-empty — this
                       function does NOT fall back to any default; an
                       empty secret would make every token forgeable.
        expiry_hours : How many hours from now this token remains valid.

    Returns:
        (token, token_id, expires_at_iso) — the full token string to
        embed in the email link, the token_id (jti) for logging/
        reference, and the ISO expiry timestamp for the same purpose.

    Raises:
        ValueError: if secret is empty/None, or mac is empty.
    """
    if not secret:
        raise ValueError(
            "generate_token() called with an empty secret — refusing to "
            "issue a forgeable token. Set CERBERUS_LINK_SECRET in .env."
        )
    if not mac:
        raise ValueError("generate_token() requires a non-empty mac.")

    mac = mac.lower()
    token_id = secrets.token_urlsafe(24)
    exp_unix = int(time.time()) + (expiry_hours * 3600)
    expires_at_iso = datetime.fromtimestamp(exp_unix, tz=timezone.utc).isoformat(
        timespec="seconds"
    )

    payload = {
        "mac":     mac,
        "purpose": purpose,
        "jti":     token_id,
        "exp":     exp_unix,
    }

    token = _encode(payload, secret)

    logger.debug(
        f"[token] Generated — mac={mac} purpose={purpose} "
        f"token_id={token_id} expires={expires_at_iso}"
    )
    return token, token_id, expires_at_iso


def verify_token(token: str, secret: str) -> TokenPayload:
    """
    Verify a token's signature and expiry, and return its contents if valid.

    Does NOT check whether the token has already been redeemed — that
    is a separate step the caller (api/server.py) must perform via
    device_store.is_token_used() / mark_token_used() after this
    succeeds. A token can pass verify_token() and still be rejected as
    "already used."

    Args:
        token  : The full token string from the email link.
        secret : cfg.link_secret — must match what generate_token() used.

    Returns:
        TokenPayload with the verified mac/purpose/token_id/expires_at.

    Raises:
        TokenError: with .reason of "malformed", "bad_signature", or
                    "expired" — callers should catch this broadly and
                    branch on .reason for the confirmation page's
                    error message, rather than assuming any specific
                    exception subtype.
    """
    if not secret:
        raise TokenError("malformed", "No link secret configured.")
    if not token or "." not in token:
        raise TokenError("malformed", "Token is empty or has no signature segment.")

    payload_b64, _, signature = token.partition(".")
    if not payload_b64 or not signature:
        raise TokenError("malformed", "Token is missing a payload or signature segment.")

    expected_signature = _sign(payload_b64.encode("ascii"), secret)
    if not hmac.compare_digest(expected_signature, signature):
        raise TokenError("bad_signature", "Token signature does not match.")

    try:
        payload_json = _b64url_decode(payload_b64)
        payload = json.loads(payload_json)
    except Exception as e:
        raise TokenError("malformed", f"Token payload could not be decoded: {e}")

    required_fields = ("mac", "purpose", "jti", "exp")
    if not all(f in payload for f in required_fields):
        raise TokenError("malformed", "Token payload is missing required fields.")

    if int(time.time()) >= int(payload["exp"]):
        raise TokenError("expired", "Token has expired.")

    expires_at_iso = datetime.fromtimestamp(
        int(payload["exp"]), tz=timezone.utc
    ).isoformat(timespec="seconds")

    return TokenPayload(
        mac=str(payload["mac"]).lower(),
        purpose=str(payload["purpose"]),
        token_id=str(payload["jti"]),
        expires_at=expires_at_iso,
    )


# ---------------------------------------------------------------------------
# Private — encoding / signing helpers
# ---------------------------------------------------------------------------

def _b64url_encode(data: bytes) -> str:
    """Base64url without padding — keeps tokens URL-safe with no '=' clutter."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    """Reverse of _b64url_encode — restores padding before decoding."""
    padding = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + padding)


def _sign(payload_b64_bytes: bytes, secret: str) -> str:
    """HMAC-SHA256 over the base64url payload, hex-encoded."""
    return hmac.new(
        secret.encode("utf-8"), payload_b64_bytes, hashlib.sha256
    ).hexdigest()


def _encode(payload: dict, secret: str) -> str:
    payload_json = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    payload_b64 = _b64url_encode(payload_json.encode("utf-8"))
    signature = _sign(payload_b64.encode("ascii"), secret)
    return f"{payload_b64}.{signature}"


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    SECRET = "test-secret-do-not-use-in-prod"

    print("\n" + "=" * 60)
    print("LINK TOKENS — SMOKE TEST")
    print("=" * 60)

    # --- Happy path ---
    token, token_id, expires_at = generate_token(
        mac="AA:BB:CC:DD:EE:FF", purpose="trust", secret=SECRET, expiry_hours=1
    )
    assert isinstance(token, str) and "." in token
    print(f"[PASS] generate_token() → token_id={token_id}, expires={expires_at}")

    payload = verify_token(token, secret=SECRET)
    assert payload.mac == "aa:bb:cc:dd:ee:ff"  # normalized lowercase
    assert payload.purpose == "trust"
    assert payload.token_id == token_id
    print(f"[PASS] verify_token() round-trip → mac={payload.mac}, purpose={payload.purpose}")

    # --- Tampered payload (mac swapped) rejected ---
    payload_b64, sig = token.split(".")
    tampered_json = json.dumps(
        {"mac": "11:22:33:44:55:66", "purpose": "trust", "jti": token_id,
         "exp": int(time.time()) + 3600},
        sort_keys=True, separators=(",", ":"),
    )
    tampered_b64 = _b64url_encode(tampered_json.encode("utf-8"))
    tampered_token = f"{tampered_b64}.{sig}"
    try:
        verify_token(tampered_token, secret=SECRET)
        print("[FAIL] Tampered token was accepted!")
    except TokenError as e:
        assert e.reason == "bad_signature"
        print(f"[PASS] Tampered token rejected — reason={e.reason}")

    # --- Wrong secret rejected ---
    try:
        verify_token(token, secret="wrong-secret")
        print("[FAIL] Token verified with wrong secret!")
    except TokenError as e:
        assert e.reason == "bad_signature"
        print(f"[PASS] Wrong secret rejected — reason={e.reason}")

    # --- Expired token rejected ---
    expired_token, _, _ = generate_token(
        mac="aa:bb:cc:dd:ee:ff", purpose="trust", secret=SECRET, expiry_hours=0
    )
    time.sleep(1.1)  # ensure exp timestamp (whole seconds) has passed
    try:
        verify_token(expired_token, secret=SECRET)
        print("[FAIL] Expired token was accepted!")
    except TokenError as e:
        assert e.reason == "expired"
        print(f"[PASS] Expired token rejected — reason={e.reason}")

    # --- Malformed tokens rejected ---
    for bad in ["", "no-dot-here", ".", "abc.", ".xyz"]:
        try:
            verify_token(bad, secret=SECRET)
            print(f"[FAIL] Malformed token {bad!r} was accepted!")
        except TokenError as e:
            assert e.reason in ("malformed", "bad_signature")
            print(f"[PASS] Malformed token {bad!r} rejected — reason={e.reason}")

    # --- Empty secret raises on generate ---
    try:
        generate_token(mac="aa:bb:cc:dd:ee:ff", purpose="trust", secret="")
        print("[FAIL] generate_token() accepted an empty secret!")
    except ValueError:
        print("[PASS] generate_token() refuses an empty secret")

    print("\nAll assertions passed.")
    print("=" * 60)