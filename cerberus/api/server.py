"""
Flask app exposing CerberusService as JSON over HTTP. Every route is
close to a one-line dispatch into service/ — this file's only real job
is the HTTP/JSON translation. Runs embedded inside cerberus_main.py's
own process (a background thread), not as a separate invocation, so
every endpoint has live access to the actual running scheduler/
alert_manager/learning_mode rather than a stale copy.

Auth: if CERBERUS_API_SECRET is set, /api/* requests need an
X-API-Key header. /api/health skips auth (basic liveness check), and so
does /confirm/trust/<token> — but for a different reason: the signed
token itself is the credential there, since that link gets opened from
an email client, not the dashboard.

CORS is scoped to /api/*, any origin for now — this is meant as a
single-operator LAN tool, so if it's ever exposed beyond a trusted
network, tighten that to a specific origin.

Email trust confirmation is split into two routes on purpose:
GET /confirm/trust/<token> only renders a confirmation page and calls
verify_trust_token(), which has no side effects — it never marks a
token used. That matters because some email providers and corporate
gateways pre-fetch links before a human opens them, and a GET that
actually trusted the device would get silently triggered by that
prefetch. Only POST /confirm/trust/<token> calls
redeem_trust_token(), and that's protected against double-submission
by a UNIQUE constraint on token_id in device_store. Neither route
requires X-API-Key — the token itself works like a password-reset
link from any other service, and rejecting bad/expired/reused tokens
is cerberus_service's job, not this file's.

JSON error responses are always {"error": "..."} with a real status
code, never a raw stack trace. The two /confirm/trust routes are the
exception — they return styled HTML, since they're opened directly in
a browser from an email link rather than called via fetch().
"""

import logging
from functools import wraps
from typing import Optional

from flask import Flask, jsonify, request
from flask_cors import CORS

from cerberus.service.cerberus_service import CerberusService

logger = logging.getLogger("cerberus.api.server")


def create_app(service: CerberusService, api_secret: Optional[str] = None) -> Flask:
    """
    Build and return a configured Flask app.

    Args:
        service    : The SAME CerberusService instance cerberus_main.py
                     constructed — sharing live scheduler/alert_manager/
                     learning_mode references is the entire point.
        api_secret : Value of CERBERUS_API_SECRET. None/"" = no auth
                     enforced (matches config_loader's existing warning
                     behaviour rather than silently blocking everything).
                     Does NOT apply to /confirm/trust/<token> — those
                     routes are protected by the signed token itself,
                     not this secret (an email link can't carry a
                     dashboard API key, and shouldn't need to).

    Returns:
        Flask app, ready to run with app.run(...) or any WSGI server.
    """
    app = Flask("cerberus_api")

    # CORS scoped to /api/* — the only JSON routes that exist anyway,
    # but explicit is better than accidentally wide-opening something
    # else added later without thinking about it. /confirm/trust/<token>
    # is a plain browser navigation (not a fetch() call from the
    # frontend), so it doesn't need CORS headers at all.
    CORS(app, resources={r"/api/*": {"origins": "*"}})

    # ------------------------------------------------------------------
    # Auth
    # ------------------------------------------------------------------

    def _require_api_key(view_func):
        @wraps(view_func)
        def wrapped(*args, **kwargs):
            if not api_secret:
                return view_func(*args, **kwargs)  # auth disabled by config
            provided = request.headers.get("X-API-Key", "")
            if provided != api_secret:
                logger.warning(
                    f"[api] Unauthorized request to {request.path} "
                    f"from {request.remote_addr}"
                )
                return jsonify({"error": "Unauthorized — missing or invalid X-API-Key"}), 401
            return view_func(*args, **kwargs)
        return wrapped

    # ------------------------------------------------------------------
    # Error handling — never leak stack traces to the client
    # ------------------------------------------------------------------

    @app.errorhandler(Exception)
    def _handle_unexpected_error(e):
        logger.error(f"[api] Unhandled error on {request.path}: {e}")
        return jsonify({"error": "Internal server error"}), 500

    @app.errorhandler(404)
    def _handle_not_found(e):
        return jsonify({"error": "Not found"}), 404

    # ------------------------------------------------------------------
    # Root — friendly landing instead of a bare 404
    # ------------------------------------------------------------------

    @app.route("/", methods=["GET"])
    def root():
        """
        Unauthenticated on purpose, same reasoning as /api/health — this
        just tells a human (or browser) that the API is alive and where
        to look next. No device/network data is exposed here.
        """
        return jsonify({
            "service": "Cerberus v2 API",
            "status": "running",
            "docs": "All endpoints are under /api/ — see /api/health for a basic check.",
            "auth": "Required via X-API-Key header on /api/* routes" if api_secret else "Disabled",
        })

    # ------------------------------------------------------------------
    # Devices
    # ------------------------------------------------------------------

    @app.route("/api/devices", methods=["GET"])
    @_require_api_key
    def get_devices():
        """?trusted=true|false to filter. Omit for all devices."""
        trusted_param = request.args.get("trusted")
        trusted_only = None
        if trusted_param is not None:
            trusted_only = trusted_param.lower() in ("1", "true", "yes")
        devices = service.get_devices(trusted_only=trusted_only)
        return jsonify({"devices": devices, "count": len(devices)})

    @app.route("/api/devices/<mac>", methods=["GET"])
    @_require_api_key
    def get_device(mac: str):
        device = service.get_device(mac)
        if not device:
            return jsonify({"error": f"No device found for MAC {mac}"}), 404
        return jsonify(device)

    @app.route("/api/devices/<mac>/history", methods=["GET"])
    @_require_api_key
    def get_device_history(mac: str):
        limit = request.args.get("limit", default=20, type=int)
        history = service.get_device_history(mac, limit=limit)
        return jsonify({"mac": mac, "history": history, "count": len(history)})

    @app.route("/api/devices/<mac>/trust", methods=["POST"])
    @_require_api_key
    def trust_device(mac: str):
        ok = service.trust_device(mac)
        if not ok:
            return jsonify({"error": f"No device found for MAC {mac}"}), 404
        return jsonify({"mac": mac, "trusted": True})

    @app.route("/api/devices/<mac>/untrust", methods=["POST"])
    @_require_api_key
    def untrust_device(mac: str):
        ok = service.untrust_device(mac)
        if not ok:
            return jsonify({"error": f"No device found for MAC {mac}"}), 404
        return jsonify({"mac": mac, "trusted": False})

    @app.route("/api/devices/<mac>/label", methods=["POST"])
    @_require_api_key
    def label_device(mac: str):
        body = request.get_json(silent=True) or {}
        label = body.get("label", "")
        ok = service.label_device(mac, label)
        if not ok:
            return jsonify({"error": f"No device found for MAC {mac}"}), 404
        return jsonify({"mac": mac, "label": label})

    @app.route("/api/devices/<mac>/request-id", methods=["POST"])
    @_require_api_key
    def request_device_id(mac: str):
        """
        Dashboard-triggered — issues a private, single-use "identify
        yourself" link for one device, and returns the full shareable
        URL. The operator copies this link and sends it however they
        choose (text, WhatsApp, in person) — Cerberus never sends it
        anywhere itself. Building the full URL from request.host_url
        here (rather than a configured public_base_url, as the email
        Trust links need) works naturally since this route is only
        ever called from an active dashboard session already pointed
        at the right host.
        """
        result = service.request_identify_link(mac)
        if not result["success"]:
            status = 404 if result["reason"] == "device_not_found" else 400
            return jsonify({"error": result["reason"]}), status

        base = request.host_url.rstrip("/")
        link = f"{base}/confirm/identify/{result['token']}"
        return jsonify({
            "mac": result["mac"],
            "display_name": result["display_name"],
            "link": link,
            "expires_at": result["expires_at"],
        })

    @app.route("/api/devices/<mac>", methods=["DELETE"])
    @_require_api_key
    def delete_device(mac: str):
        ok = service.delete_device(mac)
        if not ok:
            return jsonify({"error": f"No device found for MAC {mac}"}), 404
        return jsonify({"mac": mac, "deleted": True})

    @app.route("/api/devices/counts", methods=["GET"])
    @_require_api_key
    def get_device_counts():
        return jsonify(service.get_device_counts())

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    @app.route("/api/alerts", methods=["GET"])
    @_require_api_key
    def get_alerts():
        limit = request.args.get("limit", default=50, type=int)
        alerts = service.get_recent_alerts(limit=limit)
        return jsonify({"alerts": alerts, "count": len(alerts)})

    @app.route("/api/alerts/<int:alert_id>", methods=["DELETE"])
    @_require_api_key
    def delete_alert(alert_id: int):
        ok = service.delete_alert(alert_id)
        if not ok:
            return jsonify({"error": f"No alert found with id {alert_id}"}), 404
        return jsonify({"id": alert_id, "deleted": True})

    @app.route("/api/alerts", methods=["DELETE"])
    @_require_api_key
    def clear_alerts():
        deleted = service.clear_alerts()
        return jsonify({"deleted": deleted})

    @app.route("/api/alerts/counts", methods=["GET"])
    @_require_api_key
    def get_alert_counts():
        return jsonify(service.get_alert_counts())

    @app.route("/api/alerts/manager-status", methods=["GET"])
    @_require_api_key
    def get_alert_manager_status():
        return jsonify(service.get_alert_manager_status())

    # ------------------------------------------------------------------
    # Learning mode
    # ------------------------------------------------------------------

    @app.route("/api/learning", methods=["GET"])
    @_require_api_key
    def get_learning_status():
        return jsonify(service.get_learning_mode_status())

    @app.route("/api/learning/start", methods=["POST"])
    @_require_api_key
    def start_learning():
        """
        Body (optional): {"hours": 2} to override window duration.
        Always force_restart=True — this is an explicit operator action
        (e.g. "I've moved to a new network location"), not something
        called automatically anywhere in this codebase.
        """
        body = request.get_json(silent=True) or {}
        hours = body.get("hours")
        ok = service.start_learning_mode(force_restart=True, duration_hours=hours)
        if not ok:
            return jsonify({"error": "No learning_mode attached to this service"}), 400
        return jsonify({"started": True, "duration_hours": hours})

    @app.route("/api/learning/stop", methods=["POST"])
    @_require_api_key
    def stop_learning():
        ok = service.stop_learning_mode()
        if not ok:
            return jsonify({"error": "No learning_mode attached to this service"}), 400
        return jsonify({"stopped": True})

    # ------------------------------------------------------------------
    # Scan status
    # ------------------------------------------------------------------

    @app.route("/api/scan/status", methods=["GET"])
    @_require_api_key
    def get_scan_status():
        return jsonify(service.get_scan_status())

    # ------------------------------------------------------------------
    # Settings
    # ------------------------------------------------------------------

    @app.route("/api/settings", methods=["GET"])
    @_require_api_key
    def get_settings():
        return jsonify(service.get_settings())

    @app.route("/api/settings", methods=["POST"])
    @_require_api_key
    def update_settings():
        """
        Body: {"scapy_interval": 90, "mdns_enabled": false, ...} — any
        subset of the editable whitelist. Rejected entirely (400, no
        partial write) if any key isn't in that whitelist — see
        cerberus_service.update_settings() / config_loader.py for the
        whitelist and the reasoning.
        """
        body = request.get_json(silent=True) or {}
        result = service.update_settings(body)
        if not result["success"]:
            return jsonify({"error": result["reason"]}), 400
        return jsonify(result["settings"])

    # ------------------------------------------------------------------
    # Combined snapshot — what the frontend dashboard will poll most
    # ------------------------------------------------------------------

    @app.route("/api/status", methods=["GET"])
    @_require_api_key
    def get_full_status():
        return jsonify(service.get_full_status())

    @app.route("/api/health", methods=["GET"])
    def health():
        """Unauthenticated on purpose — basic liveness check."""
        return jsonify({"status": "ok"})

    # ------------------------------------------------------------------
    # Email Trust confirmation — NOT under /api/*,
    # deliberately outside the X-API-Key requirement, meant to be
    # opened directly in a browser from an alert email's link.
    # ------------------------------------------------------------------

    @app.route("/confirm/trust/<token>", methods=["GET"])
    def confirm_trust_page(token: str):
        """
        Renders the confirmation page. NO side effects — see module
        docstring for why GET must never redeem the token itself.
        """
        check = service.verify_trust_token(token)
        html = _render_confirm_page(token, check)
        return html

    @app.route("/confirm/trust/<token>", methods=["POST"])
    def confirm_trust_submit(token: str):
        """
        The actual action — only reachable via the confirmation page's
        own form submission (a real click), never via the bare email
        link (which is a GET).
        """
        result = service.redeem_trust_token(token)
        html = _render_result_page(result)
        return html

    # ------------------------------------------------------------------
    # Device self-identification — also outside
    # /api/*, unauthenticated by design: the signed token bound to one
    # specific device IS the credential, same reasoning as the Trust
    # confirmation routes above. The operator triggers issuance from
    # the dashboard (POST /api/devices/<mac>/request-id, authenticated)
    # and shares the resulting link themselves — Cerberus never sends
    # it anywhere on its own.
    # ------------------------------------------------------------------

    @app.route("/confirm/identify/<token>", methods=["GET"])
    def confirm_identify_page(token: str):
        """
        Renders the "what's this device?" page. NO side effects —
        same GET-must-never-mutate reasoning as the Trust routes.
        """
        check = service.verify_identify_token(token)
        html = _render_identify_page(token, check)
        return html

    @app.route("/confirm/identify/<token>", methods=["POST"])
    def confirm_identify_submit(token: str):
        """
        The actual action — sets the device's label to the submitted
        name. Only reachable via the page's own form submission.
        """
        body = request.form if request.form else (request.get_json(silent=True) or {})
        name = body.get("name", "")
        result = service.redeem_identify_link(token, name)
        html = _render_identify_result_page(result)
        return html

    return app


def run_server(
    service: CerberusService,
    host: str = "0.0.0.0",
    port: int = 5000,
    api_secret: Optional[str] = None,
) -> None:
    """
    Blocking call — starts the Flask dev server. Intended to be called
    from a background thread inside cerberus_main.py.

    Flask's built-in dev server is acceptable here — Cerberus is a
    single-operator home/small-office tool, not a public-facing service.
    If this is ever exposed beyond a trusted LAN, put it behind a real
    WSGI server (gunicorn/waitress) and a reverse proxy.
    """
    app = create_app(service, api_secret=api_secret)
    logger.info(f"API server starting on http://{host}:{port}")
    # use_reloader=False is mandatory — Flask's reloader spawns a SECOND
    # process and would duplicate the embedded scheduler thread.
    app.run(host=host, port=port, debug=False, use_reloader=False)


# ---------------------------------------------------------------------------
# Private — HTML rendering for the Trust confirmation pages
#
# Self-contained (a real <style> block is fine here, unlike the email
# HTML in alert_manager.py — this is a normal web page opened in a
# browser, not an email client that strips <style> tags). Matches the
# dashboard's cyan/copper/coral HUD palette so the confirmation flow
# doesn't feel like a jarring detour from the rest of the product.
# ---------------------------------------------------------------------------

_PAGE_SHELL = """\
<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cerberus — Trust Confirmation</title>
<style>
  body {{
    margin: 0; padding: 0; min-height: 100vh;
    background: #080B10; color: #D7E1EA;
    font-family: -apple-system, 'Segoe UI', Arial, sans-serif;
    display: flex; align-items: center; justify-content: center;
  }}
  .card {{
    background: #0E141C; border: 1px solid #1C2733;
    max-width: 460px; width: calc(100% - 40px); margin: 20px;
    padding: 32px;
  }}
  .eyebrow {{
    color: #3FE0E8; font-family: monospace; font-size: 11px;
    letter-spacing: 0.15em; text-transform: uppercase; margin: 0 0 20px;
  }}
  h1 {{ font-size: 18px; margin: 0 0 16px; letter-spacing: 0.02em; }}
  p {{ font-size: 14px; line-height: 1.6; color: #7C8A9A; margin: 0 0 16px; }}
  table {{ width: 100%; border-collapse: collapse; margin-bottom: 20px; }}
  td {{ padding: 4px 0; font-size: 13px; }}
  td.label {{ color: #7C8A9A; width: 110px; }}
  td.value {{ color: #D7E1EA; font-family: monospace; }}
  button {{
    width: 100%; padding: 13px; border: none; cursor: pointer;
    font-weight: 700; font-size: 13px; letter-spacing: 0.05em;
    text-transform: uppercase; border-radius: 2px;
  }}
  .btn-confirm {{ background: #3FE0E8; color: #080B10; }}
  .status-ok {{ color: #3FE0E8; }}
  .status-warn {{ color: #E0913F; }}
  .status-error {{ color: #FF5D4A; }}
  input[type="text"] {{
    width: 100%; padding: 11px 12px; margin-bottom: 14px;
    background: #080B10; border: 1px solid #2E4152; color: #D7E1EA;
    font-family: -apple-system, 'Segoe UI', Arial, sans-serif;
    font-size: 14px; border-radius: 2px;
  }}
  input[type="text"]:focus {{ outline: 2px solid #3FE0E8; outline-offset: 1px; }}
  .device-hint {{
    font-size: 12px; color: #4A5866; font-family: monospace;
    margin: -10px 0 18px;
  }}
</style>
</head>
<body>
  <div class="card">
    <p class="eyebrow">// Cerberus — Network Sentinel</p>
    {content}
  </div>
</body>
</html>"""


def _render_confirm_page(token: str, check: dict) -> str:
    if not check["valid"]:
        reason = check["reason"]
        messages = {
            "unavailable": ("status-error", "Trust links are not enabled",
                             "This Cerberus instance has no link-signing secret configured."),
            "malformed": ("status-error", "Invalid link",
                          "This link is malformed and cannot be used."),
            "bad_signature": ("status-error", "Invalid link",
                               "This link's signature does not match — it may have been altered."),
            "expired": ("status-warn", "Link expired",
                        "This Trust link has expired. Open the Cerberus dashboard "
                        "to trust this device manually instead."),
        }
        cls, title, body = messages.get(
            reason, ("status-error", "Invalid link", "This link could not be verified.")
        )
        content = f'<h1 class="{cls}">{title}</h1><p>{body}</p>'
        return _PAGE_SHELL.format(content=content)

    device = check["device"]
    mac = check["mac"]
    display_name = (
        (device.get("label") or device.get("hostname") or device.get("vendor") or mac)
        if device else mac
    )

    if check["already_used"]:
        content = (
            '<h1 class="status-warn">Already confirmed</h1>'
            f'<p>This link has already been used. <strong>{display_name}</strong> '
            'should already be marked trusted — check the dashboard to confirm.</p>'
        )
        return _PAGE_SHELL.format(content=content)

    if not device:
        content = (
            '<h1 class="status-error">Device not found</h1>'
            f'<p>The device for MAC <code>{mac}</code> is no longer in Cerberus\'s '
            'records — it may have been removed.</p>'
        )
        return _PAGE_SHELL.format(content=content)

    rows = "".join([
        f'<tr><td class="label">Name</td><td class="value">{display_name}</td></tr>',
        f'<tr><td class="label">IP address</td><td class="value">{device.get("ip", "unknown")}</td></tr>',
        f'<tr><td class="label">MAC address</td><td class="value">{mac}</td></tr>',
        f'<tr><td class="label">Vendor</td><td class="value">{device.get("vendor") or "unknown"}</td></tr>',
    ])

    content = f"""\
<h1>Trust this device?</h1>
<table>{rows}</table>
<p>Marking this trusted stops future alerts for it and clears any active cooldown.</p>
<form method="POST" action="/confirm/trust/{token}">
  <button type="submit" class="btn-confirm">Confirm Trust</button>
</form>"""
    return _PAGE_SHELL.format(content=content)


def _render_result_page(result: dict) -> str:
    if result["success"]:
        content = (
            '<h1 class="status-ok">Device trusted</h1>'
            f'<p><strong>{result["display_name"]}</strong> has been marked trusted. '
            'You will no longer receive alerts for it unless it\'s untrusted again '
            'from the dashboard.</p>'
        )
        return _PAGE_SHELL.format(content=content)

    reason = result["reason"]
    display_name = result.get("display_name") or result.get("mac") or "this device"
    messages = {
        "unavailable": "Trust links are not enabled on this Cerberus instance.",
        "malformed": "This link is malformed and cannot be used.",
        "bad_signature": "This link's signature does not match — it may have been altered.",
        "expired": "This link has expired.",
        "already_used": f"This link was already used — {display_name} should already be trusted.",
        "device_not_found": f"The device for this link is no longer in Cerberus's records.",
        "trust_failed": f"Could not mark {display_name} trusted — please try from the dashboard.",
    }
    body = messages.get(reason, "This link could not be processed.")
    content = f'<h1 class="status-error">Could not confirm</h1><p>{body}</p>'
    return _PAGE_SHELL.format(content=content)


def _render_identify_page(token: str, check: dict) -> str:
    """
    Renders the "what's this device?" page. Deliberately does NOT ask
    the visitor anything about their own IP/MAC — the link already
    names the device via the token, so all they need to do is confirm
    it's theirs and type a name.
    """
    if not check["valid"]:
        reason = check["reason"]
        messages = {
            "unavailable": ("status-error", "Not available",
                             "Device identification links aren't enabled on this Cerberus instance."),
            "malformed": ("status-error", "Invalid link",
                           "This link is invalid or was meant for something else."),
            "bad_signature": ("status-error", "Invalid link",
                               "This link's signature does not match — it may have been altered."),
            "expired": ("status-warn", "Link expired",
                        "This request has expired. Ask whoever sent it for a new link."),
        }
        cls, title, body = messages.get(
            reason, ("status-error", "Invalid link", "This link could not be verified.")
        )
        content = f'<h1 class="{cls}">{title}</h1><p>{body}</p>'
        return _PAGE_SHELL.format(content=content)

    device = check["device"]
    mac = check["mac"]

    if check["already_used"]:
        content = (
            '<h1 class="status-warn">Already answered</h1>'
            '<p>This link has already been used to identify this device. '
            'If that name was wrong, ask the network operator to send a new link.</p>'
        )
        return _PAGE_SHELL.format(content=content)

    if not device:
        content = (
            '<h1 class="status-error">Device not found</h1>'
            f'<p>The device for MAC <code>{mac}</code> is no longer in Cerberus\'s '
            'records — it may have been removed.</p>'
        )
        return _PAGE_SHELL.format(content=content)

    # A light, non-identifying hint only — vendor, not personal data —
    # just enough for the person to recognize "oh, that's my phone."
    hint = device.get("vendor") or "unknown vendor"

    content = f"""\
<h1>Is this device yours?</h1>
<p class="device-hint">Detected vendor: {hint}</p>
<p>Someone managing this network wants to know whose device this is.
Type a name below — this only labels the device for the network admin;
it does not grant it any special access.</p>
<form method="POST" action="/confirm/identify/{token}">
  <input type="text" name="name" placeholder="e.g. Priya's Phone" maxlength="80" required autofocus />
  <button type="submit" class="btn-confirm">Submit</button>
</form>"""
    return _PAGE_SHELL.format(content=content)


def _render_identify_result_page(result: dict) -> str:
    if result["success"]:
        content = (
            '<h1 class="status-ok">Thanks!</h1>'
            f'<p>This device is now labeled <strong>{result["display_name"]}</strong> '
            'for the network admin.</p>'
        )
        return _PAGE_SHELL.format(content=content)

    reason = result["reason"]
    display_name = result.get("display_name") or result.get("mac") or "this device"
    messages = {
        "unavailable": "Device identification links aren't enabled on this Cerberus instance.",
        "malformed": "This link is invalid or was meant for something else.",
        "bad_signature": "This link's signature does not match — it may have been altered.",
        "expired": "This link has expired.",
        "already_used": f"This link was already used to identify {display_name}.",
        "device_not_found": "The device for this link is no longer in Cerberus's records.",
        "empty_name": "Please go back and type a name before submitting.",
        "label_failed": "Could not save the name — please try again.",
    }
    body = messages.get(reason, "This link could not be processed.")
    content = f'<h1 class="status-error">Could not save</h1><p>{body}</p>'
    return _PAGE_SHELL.format(content=content)


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile
    import os as _os

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    from cerberus.storage.device_store import DeviceStore

    with tempfile.TemporaryDirectory() as tmp:
        store = DeviceStore(_os.path.join(tmp, "test.db"))
        store.upsert({
            "mac": "aa:bb:cc:dd:ee:01", "ip": "192.168.1.10",
            "network": "192.168.1.0/24", "scanner": "scapy",
        })
        service = CerberusService(device_store=store)

        app = create_app(service, api_secret=None)
        client = app.test_client()

        r = client.get("/")
        assert r.status_code == 200
        print(f"[PASS] GET / → {r.get_json()}")

        r = client.get("/api/health")
        assert r.status_code == 200
        print(f"[PASS] GET /api/health → {r.get_json()}")

        r = client.get("/api/devices")
        assert r.status_code == 200
        assert r.get_json()["count"] == 1
        print(f"[PASS] GET /api/devices → {r.get_json()['count']} device(s)")

        r = client.get("/api/devices/aa:bb:cc:dd:ee:01")
        assert r.status_code == 200
        print(f"[PASS] GET /api/devices/<mac> → {r.get_json()['ip']}")

        r = client.get("/api/devices/ff:ff:ff:ff:ff:ff")
        assert r.status_code == 404
        print("[PASS] GET unknown MAC → 404")

        r = client.post("/api/devices/aa:bb:cc:dd:ee:01/trust")
        assert r.status_code == 200
        assert r.get_json()["trusted"] is True
        print("[PASS] POST trust → trusted=True")

        r = client.get("/api/status")
        assert r.status_code == 200
        body = r.get_json()
        assert "devices" in body and "learning_mode" in body
        print(f"[PASS] GET /api/status → keys: {list(body.keys())}")

        # CORS header check
        r = client.get("/api/health", headers={"Origin": "http://localhost:5173"})
        assert "Access-Control-Allow-Origin" in r.headers
        print(f"[PASS] CORS header present: {r.headers.get('Access-Control-Allow-Origin')}")

        store.close()
        print("\nAll assertions passed.")

        # --- Auth test, separate app instance with a secret set ---
        store2 = DeviceStore(_os.path.join(tempfile.mkdtemp(), "test2.db"))
        service2 = CerberusService(device_store=store2)
        app2 = create_app(service2, api_secret="supersecret123")
        client2 = app2.test_client()

        r = client2.get("/api/devices")
        assert r.status_code == 401
        print("[PASS] Auth enabled, no key → 401")

        r = client2.get("/api/devices", headers={"X-API-Key": "supersecret123"})
        assert r.status_code == 200
        print("[PASS] Auth enabled, correct key → 200")

        store2.close()
        print("All auth assertions passed.")

        # --- Trust confirmation flow ---
        from cerberus.utils.link_tokens import generate_token

        store3 = DeviceStore(_os.path.join(tempfile.mkdtemp(), "test3.db"))
        store3.upsert({
            "mac": "bb:cc:dd:ee:ff:99", "ip": "192.168.1.50",
            "network": "192.168.1.0/24", "scanner": "scapy",
            "hostname": "mystery-phone",
        })
        service3 = CerberusService(device_store=store3, link_secret="test-secret-123")
        app3 = create_app(service3, api_secret=None)  # /confirm/* ignores this anyway
        client3 = app3.test_client()

        token, token_id, expires_at = generate_token(
            mac="bb:cc:dd:ee:ff:99", purpose="trust",
            secret="test-secret-123", expiry_hours=1,
        )

        # GET must have no side effects
        r = client3.get(f"/confirm/trust/{token}")
        assert r.status_code == 200
        assert b"Trust this device" in r.data
        assert b"mystery-phone" in r.data
        print("[PASS] GET /confirm/trust/<token> renders confirmation page with device info")

        device_before = service3.get_device("bb:cc:dd:ee:ff:99")
        assert device_before["trusted"] is False
        print("[PASS] GET request had no side effect — device still untrusted")

        # POST actually redeems it
        r = client3.post(f"/confirm/trust/{token}")
        assert r.status_code == 200
        assert b"Device trusted" in r.data
        print("[PASS] POST /confirm/trust/<token> confirms trust")

        device_after = service3.get_device("bb:cc:dd:ee:ff:99")
        assert device_after["trusted"] is True
        print("[PASS] Device actually marked trusted in DB")

        # Second POST with same token must be rejected (single-use)
        r = client3.post(f"/confirm/trust/{token}")
        assert r.status_code == 200
        assert b"already been used" in r.data or b"already be trusted" in r.data
        print("[PASS] Replayed token rejected on second POST")

        # Bad token
        r = client3.get("/confirm/trust/not-a-real-token")
        assert r.status_code == 200
        assert b"Invalid link" in r.data
        print("[PASS] Malformed token shows 'Invalid link'")

        # No X-API-Key needed for /confirm/* even with auth enabled elsewhere
        service4 = CerberusService(device_store=store3, link_secret="test-secret-123")
        app4 = create_app(service4, api_secret="some-dashboard-secret")
        client4 = app4.test_client()
        token2, _, _ = generate_token(
            mac="bb:cc:dd:ee:ff:99", purpose="trust",
            secret="test-secret-123", expiry_hours=1,
        )
        r = client4.get(f"/confirm/trust/{token2}")  # no X-API-Key header
        assert r.status_code == 200
        assert b"Invalid link" not in r.data
        print("[PASS] /confirm/trust/<token> works without X-API-Key even when API auth is enabled")

        store3.close()
        print("\nAll Trust confirmation flow assertions passed.")