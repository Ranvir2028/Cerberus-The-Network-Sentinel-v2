#!/usr/bin/env python3
"""
run_dev.py — Cerberus v2 dev launcher.

Starts cerberus_main.py (backend) and the Vite frontend dev server
together, streams both logs to this one terminal, auto-installs
frontend deps if missing, opens the dashboard in your browser once
the frontend port is actually accepting connections, and shuts both
down cleanly on Ctrl+C.

Cross-platform: works identically on Windows, Linux, and macOS.

Usage:
    python run_dev.py
    python run_dev.py --backend-only     # skip the frontend
    python run_dev.py --frontend-only    # skip the backend
    python run_dev.py --no-browser       # don't auto-open the dashboard
"""

import argparse
import subprocess
import sys
import os
import socket
import threading
import time
import webbrowser

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
FRONTEND_DIR = os.path.join(ROOT_DIR, "frontend")
FRONTEND_HOST = "localhost"
FRONTEND_PORT = 5173
FRONTEND_URL = f"http://{FRONTEND_HOST}:{FRONTEND_PORT}"

IS_WINDOWS = os.name == "nt"


# ---------------------------------------------------------------------------
# Process streaming helpers
# ---------------------------------------------------------------------------

def _stream_output(process: subprocess.Popen, prefix: str) -> None:
    """Read a subprocess's stdout line-by-line and print with a prefix,
    so backend and frontend logs are distinguishable in one terminal."""
    for line in iter(process.stdout.readline, ""):
        if not line:
            break
        print(f"[{prefix}] {line}", end="")
    process.stdout.close()


def _start_process(cmd, cwd, prefix: str) -> subprocess.Popen:
    proc = subprocess.Popen(
        cmd,
        cwd=cwd,
        shell=IS_WINDOWS,   # needed on Windows to resolve npm.cmd correctly
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )
    t = threading.Thread(target=_stream_output, args=(proc, prefix), daemon=True)
    t.start()
    return proc


# ---------------------------------------------------------------------------
# Frontend dependency check
# ---------------------------------------------------------------------------

def _ensure_frontend_deps() -> bool:
    """Run npm install if node_modules is missing. Returns False on failure."""
    node_modules = os.path.join(FRONTEND_DIR, "node_modules")
    if os.path.isdir(node_modules):
        return True

    print("[launcher] frontend/node_modules not found — running npm install...")
    result = subprocess.run(
        ["npm", "install"],
        cwd=FRONTEND_DIR,
        shell=IS_WINDOWS,
    )
    if result.returncode != 0:
        print("[launcher] npm install failed — see output above.")
        return False
    print("[launcher] npm install complete.")
    return True


# ---------------------------------------------------------------------------
# Browser auto-open — polls the actual port instead of parsing log output
# (log-text matching is unreliable: ANSI color codes, buffering differences
# across OSes/npm versions can all cause a printed "ready" line to never
# be seen, even though the server is genuinely up)
# ---------------------------------------------------------------------------

def _wait_for_port(host: str, port: int, timeout: float = 30.0) -> bool:
    """Poll a TCP port until something accepts a connection, or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def _open_browser_when_ready() -> None:
    print(f"[launcher] Waiting for frontend on {FRONTEND_HOST}:{FRONTEND_PORT}...")
    if _wait_for_port(FRONTEND_HOST, FRONTEND_PORT, timeout=30):
        time.sleep(0.5)  # small buffer so the page loads cleanly
        print(f"[launcher] Opening {FRONTEND_URL} ...")
        webbrowser.open(FRONTEND_URL)
    else:
        print("[launcher] Frontend didn't come up within 30s — open it manually: "
              f"{FRONTEND_URL}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Cerberus v2 dev launcher")
    parser.add_argument("--backend-only", action="store_true")
    parser.add_argument("--frontend-only", action="store_true")
    parser.add_argument("--no-browser", action="store_true",
                        help="Don't auto-open the dashboard in your browser")
    args = parser.parse_args()

    run_backend = not args.frontend_only
    run_frontend = not args.backend_only

    processes = []

    print("=" * 60)
    print("  CERBERUS v2 — Dev Launcher")
    print("=" * 60)

    try:
        if run_backend:
            print("[launcher] Starting backend (cerberus_main.py)...")
            backend_cmd = [sys.executable, "cerberus_main.py"]
            backend = _start_process(backend_cmd, cwd=ROOT_DIR, prefix="BACKEND")
            processes.append(("backend", backend))

        frontend_started = False
        if run_frontend:
            if not os.path.isdir(FRONTEND_DIR):
                print(f"[launcher] WARNING: frontend/ not found at {FRONTEND_DIR} — skipping.")
            elif not _ensure_frontend_deps():
                print("[launcher] Skipping frontend due to failed npm install.")
            else:
                print("[launcher] Starting frontend (npm run dev)...")
                frontend = _start_process(
                    ["npm", "run", "dev"],
                    cwd=FRONTEND_DIR,
                    prefix="FRONTEND",
                )
                processes.append(("frontend", frontend))
                frontend_started = True

        if not processes:
            print("[launcher] Nothing to run — check your flags.")
            return

        print("[launcher] Running. Press Ctrl+C to stop.\n")

        if frontend_started and not args.no_browser:
            threading.Thread(target=_open_browser_when_ready, daemon=True).start()

        while True:
            for name, proc in processes:
                if proc.poll() is not None:
                    print(f"\n[launcher] {name} exited on its own "
                          f"(code {proc.returncode}) — shutting down.")
                    raise KeyboardInterrupt
            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[launcher] Stopping all processes...")
    finally:
        for name, proc in processes:
            if proc.poll() is None:
                print(f"[launcher] Terminating {name}...")
                proc.terminate()
                try:
                    proc.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    print(f"[launcher] {name} didn't stop in time — killing.")
                    proc.kill()
        print("[launcher] All processes stopped. Goodbye.")


if __name__ == "__main__":
    main()