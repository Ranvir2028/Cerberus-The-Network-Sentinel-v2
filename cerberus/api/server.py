# deps: pip install Flask flask-cors
"""
api/server.py

Job: Flask app exposing service/cerberus_service.py as JSON HTTP
endpoints. Thin by design — every route handler is close to a one-line
call into service/, with HTTP/JSON translation being the only real work
this file does.

Design decision — embedded, not standalone:
  Runs INSIDE cerberus_main.py's own process (background thread), not
  as a separate invocation. This gives every endpoint genuinely live
  access to the actual running scheduler/alert_manager/learning_mode —
  see CerberusService construction in cerberus_main.py.

Auth:
  If CERBERUS_API_SECRET is set, every /api/* request must include
  header: X-API-Key: <the secret>. /api/health is intentionally
  unauthenticated (basic liveness check).

CORS (added this revision):
  Module 16's React frontend will run on its own dev server (different
  port — e.g. Vite on :5173) and call this API from the browser.
  Browsers block cross-origin requests by default, so without CORS
  headers, every fetch() call from the frontend would fail silently
  with a CORS error before the frontend is even built — better to add
  this now than debug it blind later. Scoped to /api/* only, allows
  any origin for now since this is a single-operator LAN tool; tighten
  to a specific origin if this is ever exposed beyond a trusted network.

Rules:
  - Every route is a thin dispatch into a CerberusService instance
    passed in at construction time. No business logic here.
  - Never imports storage/intelligence/alerts directly — only the seam.
  - All responses are JSON. Errors return {"error": "..."} with an
    appropriate HTTP status code, never a raw stack trace to the client.
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

    Returns:
        Flask app, ready to run with app.run(...) or any WSGI server.
    """
    app = Flask("cerberus_api")

    # CORS scoped to /api/* — the only routes that exist anyway, but
    # explicit is better than accidentally wide-opening something else
    # added later without thinking about it.
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