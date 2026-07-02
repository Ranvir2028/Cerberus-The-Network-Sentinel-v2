# deps: pip install python-dotenv
"""
utils/config_loader.py

Job: load scan intervals, alert toggles, SMTP credentials, DB path,
learning-mode duration, and mDNS settings from environment variables
first, with a JSON file as fallback/defaults.

Rules:
  - Loads .env file automatically on first import (python-dotenv).
    The .env file lives at the project root (cerberus_v2/.env) and is
    loaded with override=True — this project's .env always wins over
    any stray system-wide environment variables.
  - Secrets (SMTP password, API keys) ONLY from env vars / .env —
    never from config.json, never hardcoded.
  - config.json holds non-secret settings (intervals, paths, toggles).
  - Validates required fields and raises ConfigError with clear message.
  - All other modules import get_config() — never read env vars themselves.
  - config.json is created with safe defaults on first run if absent.

Priority order per field:
  1. Environment variable / .env file  (CERBERUS_SMTP_PASSWORD, etc.)
  2. config/config.json value
  3. Built-in default

Usage:
    from cerberus.utils.config_loader import get_config, ConfigError

    cfg = get_config()
    db_path   = cfg.db_path
    smtp_pass = cfg.smtp_password   # from .env / env only
    interval  = cfg.scapy_interval
    mdns_on   = cfg.mdns_enabled
"""

import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv

logger = logging.getLogger("cerberus.utils.config_loader")

# ---------------------------------------------------------------------------
# .env loading — project-local, never system-wide
# ---------------------------------------------------------------------------
_ENV_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    ))),
    ".env"
)

if os.path.exists(_ENV_FILE):
    load_dotenv(_ENV_FILE, override=True)
    logger.debug(f".env loaded from {_ENV_FILE} (override=True)")
else:
    logger.debug(
        f"No .env file found at {_ENV_FILE} — "
        "using OS environment variables and config.json defaults only."
    )

# Path to config file relative to project root
_DEFAULT_CONFIG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.abspath(__file__)
    ))),
    "config", "config.json"
)

# Default config.json content written on first run
_DEFAULT_CONFIG = {
    "db_path":                    "data/devices.db",
    "log_file":                   "logs/cerberus.log",
    "log_level":                  "INFO",
    "scapy_interval":             60,
    "nmap_quick_interval":        180,
    "nmap_aggressive_interval":   360,
    "aggressive_workers":         4,
    "learning_mode_hours":        24,
    "alert_cooldown_minutes":     10,
    "email_alerts_enabled":       False,
    "smtp_host":                  "smtp.gmail.com",
    "smtp_port":                  587,
    "smtp_sender":                "",
    "smtp_recipients":            [],
    "api_host":                   "0.0.0.0",
    "api_port":                   5000,
    "api_enabled":                True,
    "mdns_enabled":               True,
    "mdns_interval":              120,
}


class ConfigError(Exception):
    """Raised when a required config value is missing or invalid."""
    pass


@dataclass
class CerberusConfig:
    """
    Fully resolved configuration for the entire Cerberus v2 system.
    Every field has a type, a default, and clear documentation.
    """
    # --- Paths ---
    db_path:    str = "data/devices.db"
    log_file:   str = "logs/cerberus.log"
    log_level:  str = "INFO"

    # --- Scan intervals (seconds) ---
    scapy_interval:            int = 60
    nmap_quick_interval:       int = 180
    nmap_aggressive_interval:  int = 360
    aggressive_workers:        int = 4

    # --- Intelligence ---
    learning_mode_hours:       int = 24

    # --- Alerts ---
    alert_cooldown_minutes:    int = 10
    email_alerts_enabled:      bool = False

    # --- SMTP (secrets from env only) ---
    smtp_host:       str           = "smtp.gmail.com"
    smtp_port:       int           = 587
    smtp_sender:     str           = ""
    smtp_password:   Optional[str] = None   # CERBERUS_SMTP_PASSWORD env var
    smtp_recipients: list          = field(default_factory=list)

    # --- API ---
    api_host:        str  = "0.0.0.0"
    api_port:        int  = 5000
    api_enabled:     bool = True
    api_secret_key:  Optional[str] = None   # CERBERUS_API_SECRET env var

    # --- mDNS discovery (Phase 3 hardening) ---
    mdns_enabled:    bool = True   # Set False to disable the mDNS worker entirely
    mdns_interval:   int  = 120    # Seconds between mDNS browse cycles


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_cached_config: Optional[CerberusConfig] = None


def get_config(
    config_file: Optional[str] = None,
    force_reload: bool = False,
) -> CerberusConfig:
    """
    Load and return the resolved Cerberus configuration.

    Cached after first call — call with force_reload=True to re-read
    (useful after editing config.json or .env at runtime).
    """
    global _cached_config
    if _cached_config is not None and not force_reload:
        return _cached_config

    if force_reload and os.path.exists(_ENV_FILE):
        load_dotenv(_ENV_FILE, override=True)

    config_path = config_file or _DEFAULT_CONFIG_FILE
    file_values = _load_json(config_path)
    _cached_config = _resolve(file_values)
    _validate(_cached_config)
    _log_summary(_cached_config)
    return _cached_config


def reset_config() -> None:
    """Clear cached config. Used in tests."""
    global _cached_config
    _cached_config = None


# ---------------------------------------------------------------------------
# Private — resolution
# ---------------------------------------------------------------------------

def _resolve(file_values: dict) -> CerberusConfig:
    """
    Merge file values + env vars into a CerberusConfig.
    Env vars always win over file values.
    """
    def _get(key: str, file_key: str, default, cast=str):
        """env var → file value → default, with type casting."""
        env_val = os.environ.get(key)
        if env_val is not None:
            try:
                if cast == bool:
                    return env_val.lower() in ("1", "true", "yes")
                return cast(env_val)
            except (ValueError, TypeError):
                logger.warning(
                    f"Env var {key}={env_val!r} could not be cast to "
                    f"{cast.__name__} — using file/default value."
                )
        return cast(file_values.get(file_key, default)) \
               if cast != bool \
               else bool(file_values.get(file_key, default))

    recipients_raw = file_values.get("smtp_recipients", [])
    env_recipients = os.environ.get("CERBERUS_SMTP_RECIPIENTS", "")
    if env_recipients:
        recipients = [r.strip() for r in env_recipients.split(",") if r.strip()]
    else:
        recipients = recipients_raw if isinstance(recipients_raw, list) else []

    return CerberusConfig(
        # Paths
        db_path   = _get("CERBERUS_DB_PATH",   "db_path",   "data/devices.db"),
        log_file  = _get("CERBERUS_LOG_FILE",  "log_file",  "logs/cerberus.log"),
        log_level = _get("CERBERUS_LOG_LEVEL", "log_level", "INFO").upper(),

        # Scan intervals
        scapy_interval           = _get("CERBERUS_SCAPY_INTERVAL",           "scapy_interval",           60,  int),
        nmap_quick_interval      = _get("CERBERUS_NMAP_QUICK_INTERVAL",      "nmap_quick_interval",      180, int),
        nmap_aggressive_interval = _get("CERBERUS_NMAP_AGGRESSIVE_INTERVAL", "nmap_aggressive_interval", 360, int),
        aggressive_workers       = _get("CERBERUS_AGGRESSIVE_WORKERS",       "aggressive_workers",       4,   int),

        # Intelligence
        learning_mode_hours = _get("CERBERUS_LEARNING_HOURS", "learning_mode_hours", 24, int),

        # Alerts
        alert_cooldown_minutes = _get("CERBERUS_ALERT_COOLDOWN", "alert_cooldown_minutes", 10,    int),
        email_alerts_enabled   = _get("CERBERUS_EMAIL_ALERTS",   "email_alerts_enabled",   False, bool),

        # SMTP — host/port/sender from file, password ONLY from env
        smtp_host       = _get("CERBERUS_SMTP_HOST",   "smtp_host",   "smtp.gmail.com"),
        smtp_port       = _get("CERBERUS_SMTP_PORT",   "smtp_port",   587, int),
        smtp_sender     = _get("CERBERUS_SMTP_SENDER", "smtp_sender", ""),
        smtp_password   = os.environ.get("CERBERUS_SMTP_PASSWORD"),   # env ONLY
        smtp_recipients = recipients,

        # API
        api_host       = _get("CERBERUS_API_HOST",    "api_host",    "0.0.0.0"),
        api_port       = _get("CERBERUS_API_PORT",    "api_port",    5000, int),
        api_enabled    = _get("CERBERUS_API_ENABLED", "api_enabled", True, bool),
        api_secret_key = os.environ.get("CERBERUS_API_SECRET"),       # env ONLY

        # mDNS
        mdns_enabled  = _get("CERBERUS_MDNS_ENABLED",  "mdns_enabled",  True, bool),
        mdns_interval = _get("CERBERUS_MDNS_INTERVAL", "mdns_interval", 120,  int),
    )


def _validate(cfg: CerberusConfig) -> None:
    """
    Raise ConfigError for any invalid/missing required combination.
    Warns (but does not raise) for non-critical issues.
    """
    if cfg.email_alerts_enabled:
        missing = []
        if not cfg.smtp_sender:
            missing.append("CERBERUS_SMTP_SENDER (or smtp_sender in config.json)")
        if not cfg.smtp_password:
            missing.append("CERBERUS_SMTP_PASSWORD (environment variable / .env)")
        if not cfg.smtp_recipients:
            missing.append("CERBERUS_SMTP_RECIPIENTS or smtp_recipients in config.json")
        if missing:
            raise ConfigError(
                "email_alerts_enabled=True but missing required settings:\n"
                + "\n".join(f"  - {m}" for m in missing)
            )

    if cfg.scapy_interval < 10:
        logger.warning(
            f"scapy_interval={cfg.scapy_interval}s is very low — "
            "may cause high CPU usage on large networks."
        )
    if cfg.nmap_aggressive_interval < cfg.nmap_quick_interval:
        logger.warning(
            "nmap_aggressive_interval < nmap_quick_interval — "
            "aggressive scan will run more often than quick scan. "
            "This is unusual."
        )
    if cfg.api_enabled and not cfg.api_secret_key:
        logger.warning(
            "API enabled but CERBERUS_API_SECRET not set. "
            "API has no authentication — only run on trusted networks."
        )
    if cfg.mdns_interval < 10:
        logger.warning(
            f"mdns_interval={cfg.mdns_interval}s is very low for mDNS browsing — "
            "10s+ recommended to avoid excessive multicast traffic."
        )


def _log_summary(cfg: CerberusConfig) -> None:
    """Log a clean summary of resolved config at startup."""
    logger.info("Configuration loaded:")
    logger.info(f"  .env file        : {_ENV_FILE} ({'found' if os.path.exists(_ENV_FILE) else 'not found'})")
    logger.info(f"  DB path          : {cfg.db_path}")
    logger.info(f"  Log file         : {cfg.log_file}")
    logger.info(f"  Log level        : {cfg.log_level}")
    logger.info(f"  Scapy interval   : {cfg.scapy_interval}s")
    logger.info(f"  Nmap quick       : {cfg.nmap_quick_interval}s")
    logger.info(f"  Nmap aggressive  : {cfg.nmap_aggressive_interval}s "
                f"({cfg.aggressive_workers} workers)")
    logger.info(f"  Learning mode    : {cfg.learning_mode_hours}h")
    logger.info(f"  Email alerts     : {'ON' if cfg.email_alerts_enabled else 'OFF'}")
    logger.info(f"  API              : {'ON' if cfg.api_enabled else 'OFF'} "
                f"at {cfg.api_host}:{cfg.api_port}")
    logger.info(f"  mDNS discovery   : {'ON' if cfg.mdns_enabled else 'OFF'} "
                f"(every {cfg.mdns_interval}s)")
    if cfg.smtp_password:
        logger.info("  SMTP password    : [set via .env]")
    if cfg.api_secret_key:
        logger.info("  API secret key   : [set via .env]")


# ---------------------------------------------------------------------------
# JSON file loader
# ---------------------------------------------------------------------------

def _load_json(config_path: str) -> dict:
    """Load config.json. Creates it with defaults if missing."""
    path = Path(config_path)

    if not path.exists():
        _write_default_config(path)
        return dict(_DEFAULT_CONFIG)

    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        logger.debug(f"Config loaded from {path}")
        return data
    except json.JSONDecodeError as e:
        logger.error(
            f"config.json parse error: {e} — using defaults. "
            f"Fix {path} to suppress this warning."
        )
        return {}
    except Exception as e:
        logger.error(f"Could not read config file {path}: {e} — using defaults.")
        return {}


def _write_default_config(path: Path) -> None:
    """Write default config.json on first run."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(_DEFAULT_CONFIG, f, indent=2)
        logger.info(
            f"Default config written to {path}. "
            "Edit it to customise Cerberus behaviour."
        )
    except Exception as e:
        logger.warning(f"Could not write default config to {path}: {e}")


# ---------------------------------------------------------------------------
# Standalone smoke-test
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    import tempfile

    logging.basicConfig(
        level=logging.DEBUG,
        format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    )

    with tempfile.TemporaryDirectory() as tmp:
        config_path = os.path.join(tmp, "config", "config.json")

        cfg = get_config(config_file=config_path)
        assert cfg.scapy_interval == 60
        assert cfg.mdns_enabled is True
        assert cfg.mdns_interval == 120
        assert os.path.exists(config_path)
        print("[PASS] First run: default config written and loaded, mDNS defaults correct")

        os.environ["CERBERUS_SCAPY_INTERVAL"] = "30"
        reset_config()
        cfg2 = get_config(config_file=config_path)
        assert cfg2.scapy_interval == 30
        print("[PASS] Env var override: scapy_interval=30")
        del os.environ["CERBERUS_SCAPY_INTERVAL"]

        os.environ["CERBERUS_MDNS_ENABLED"] = "false"
        reset_config()
        cfg3 = get_config(config_file=config_path)
        assert cfg3.mdns_enabled is False
        print("[PASS] Env var override: mdns_enabled=False")
        del os.environ["CERBERUS_MDNS_ENABLED"]

        os.environ["CERBERUS_SMTP_PASSWORD"] = "supersecret"
        reset_config()
        cfg4 = get_config(config_file=config_path)
        assert cfg4.smtp_password == "supersecret"
        print("[PASS] SMTP password from env only")
        del os.environ["CERBERUS_SMTP_PASSWORD"]

        os.environ["CERBERUS_EMAIL_ALERTS"] = "true"
        reset_config()
        try:
            cfg5 = get_config(config_file=config_path)
            print("[FAIL] Should have raised ConfigError")
        except Exception as e:
            if "missing required settings" in str(e):
                print(f"[PASS] ConfigError raised correctly: email alerts enabled without creds")
            else:
                print(f"[FAIL] Wrong error: {e}")
        del os.environ["CERBERUS_EMAIL_ALERTS"]

        reset_config()
        with open(config_path, "r") as f:
            data = json.load(f)
        data["nmap_aggressive_interval"] = 999
        with open(config_path, "w") as f:
            json.dump(data, f)
        cfg6 = get_config(config_file=config_path, force_reload=True)
        assert cfg6.nmap_aggressive_interval == 999
        print("[PASS] File value override: nmap_aggressive_interval=999")

        reset_config()
        print("\nAll assertions passed.")