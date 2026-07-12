# deps: pip install python-dotenv
"""
utils/config_loader.py

Job: load scan intervals, alert toggles, SMTP credentials, DB path,
learning-mode duration, mDNS settings, and (this revision) email
Trust/Block link-signing secret + router admin credentials from
environment variables first, with a JSON file as fallback/defaults.

Rules:
  - Loads .env file automatically on first import (python-dotenv).
    The .env file lives at the project root (cerberus_v2/.env) and is
    loaded with override=True — this project's .env always wins over
    any stray system-wide environment variables.
  - Secrets (SMTP password, API keys, link-signing secret, router
    credentials) ONLY from env vars / .env — never from config.json,
    never hardcoded.
  - config.json holds non-secret settings (intervals, paths, toggles).
  - Validates required fields and raises ConfigError with clear message.
  - All other modules import get_config() — never read env vars themselves.
  - config.json is created with safe defaults on first run if absent.

Priority order per field:
  1. Environment variable / .env file  (CERBERUS_SMTP_PASSWORD, etc.)
  2. config/config.json value
  3. Built-in default

Email Trust/Block links (this revision):
  CERBERUS_LINK_SECRET — signs the single-use Trust confirmation
    tokens embedded in alert emails (see utils/link_tokens.py). This
    is deliberately a SEPARATE secret from CERBERUS_API_SECRET: link
    tokens are short-lived (hours) and single-use, while the API key
    is long-lived and reusable — mixing the two would mean rotating
    one forces rotating the other for no reason. If unset, a random
    secret is generated at startup and logged as a warning — this
    still works for a single always-on process, but any previously
    emailed Trust links become invalid on restart, and multiple
    processes (e.g. CLI + main) would disagree on signatures. Set it
    explicitly in .env for anything beyond casual local testing.
  CERBERUS_ROUTER_USER / CERBERUS_ROUTER_PASSWORD — displayed
    (not auto-submitted) alongside the Block link in alert emails, so
    the user can manually log into their router's admin page. Same
    env-only rule as SMTP — never written to config.json.

Usage:
    from cerberus.utils.config_loader import get_config, ConfigError

    cfg = get_config()
    db_path   = cfg.db_path
    smtp_pass = cfg.smtp_password   # from .env / env only
    interval  = cfg.scapy_interval
    mdns_on   = cfg.mdns_enabled
    link_key  = cfg.link_secret
"""

import json
import logging
import os
import secrets as _secrets
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
    "link_token_expiry_hours":    72,
    "public_base_url":           "",
    "dhcp_enabled":               True,
    "dhcp_drain_interval":        60,
    "ssdp_enabled":               True,
    "ssdp_interval":              180,
    "llmnr_enabled":              True,
    "llmnr_interval":             90,
    "learning_mode_state_file":  "data/learning_mode.json",
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

    # --- Additional passive/active discovery sources (this revision) ---
    dhcp_enabled:        bool = True   # Continuous background DHCP hostname sniffer
    dhcp_drain_interval: int  = 60     # Seconds between draining accumulated sightings
    ssdp_enabled:        bool = True   # UPnP/SSDP device discovery
    ssdp_interval:       int  = 180    # Seconds between SSDP browse cycles
    llmnr_enabled:       bool = True   # LLMNR reverse hostname lookup
    llmnr_interval:      int  = 90     # Seconds between LLMNR resolve cycles

    # --- Learning mode state file (this revision) ---
    # Previously hardcoded identically as a literal string in BOTH
    # cerberus_main.py and cli/terminal.py — two places that had to be
    # kept manually in sync with no enforcement. Centralizing here
    # removes that duplication risk entirely.
    learning_mode_state_file: str = "data/learning_mode.json"

    # --- Email Trust/Block links (this revision) ---
    link_secret:             Optional[str] = None   # CERBERUS_LINK_SECRET env var
    link_token_expiry_hours: int           = 72      # Trust link validity window
    router_user:             Optional[str] = None   # CERBERUS_ROUTER_USER env var
    router_password:         Optional[str] = None   # CERBERUS_ROUTER_PASSWORD env var
    public_base_url:         str           = ""      # e.g. "http://192.168.1.50:5000" —
        # the address YOUR devices can actually reach this machine at.
        # api_host is typically "0.0.0.0" (a bind address, not a URL) so
        # it can't be used directly in email links. If left blank,
        # alert_manager.py falls back to "http://localhost:<api_port>",
        # which only works when opened on the SAME machine Cerberus runs
        # on — set this explicitly (e.g. your LAN IP) to open Trust links
        # from your phone or another device on the network.


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
# Editable settings (this revision) — for the dashboard's Settings page.
#
# Deliberately a WHITELIST, not "everything in CerberusConfig": secrets
# (smtp_password, api_secret_key, link_secret, router_user/password)
# are NEVER included here, in either direction — not readable as a
# value, not writable through this path. A settings UI, even behind
# the dashboard's own API auth, should never round-trip a secret back
# out over HTTP; that's what get_settings_status() below is for
# instead (configured/not-configured booleans only).
#
# Important limitation, stated here rather than left implicit: every
# key below is read ONCE at cerberus_main.py startup and baked into
# already-running scheduler threads/scanner objects. There is no live
# hot-reload mechanism — updating these writes config.json correctly,
# but the change only takes effect the NEXT time Cerberus is restarted.
# api/server.py's settings routes and the frontend Settings panel both
# surface this plainly rather than implying an instant effect.
# ---------------------------------------------------------------------------

_EDITABLE_CONFIG_KEYS = (
    "scapy_interval", "nmap_quick_interval", "nmap_aggressive_interval",
    "aggressive_workers",
    "mdns_enabled", "mdns_interval",
    "dhcp_enabled", "dhcp_drain_interval",
    "ssdp_enabled", "ssdp_interval",
    "llmnr_enabled", "llmnr_interval",
    "learning_mode_hours", "alert_cooldown_minutes",
    "email_alerts_enabled", "log_level",
)


def get_editable_settings(config_file: Optional[str] = None) -> dict:
    """Current values of every setting the dashboard's Settings page may edit."""
    cfg = get_config(config_file=config_file)
    return {k: getattr(cfg, k) for k in _EDITABLE_CONFIG_KEYS}


def get_settings_status(config_file: Optional[str] = None) -> dict:
    """
    Read-only configured/not-configured indicators for every secret —
    NEVER the secret value itself, in any form (not even partially
    masked). A settings UI has no legitimate need to see these values;
    "is this set or not" is all it needs to tell the operator whether
    a feature will actually work.
    """
    cfg = get_config(config_file=config_file)
    return {
        "smtp_configured":          bool(cfg.smtp_password),
        "api_secret_configured":    bool(cfg.api_secret_key),
        "link_secret_explicitly_set": bool(os.environ.get("CERBERUS_LINK_SECRET")),
        "router_credentials_configured": bool(cfg.router_user and cfg.router_password),
        "public_base_url_set":      bool(cfg.public_base_url),
    }


def update_editable_settings(updates: dict, config_file: Optional[str] = None) -> dict:
    """
    Merge `updates` into config.json, restricted to _EDITABLE_CONFIG_KEYS.

    Args:
        updates: {key: new_value} — every key MUST be in the whitelist.

    Returns:
        The merged dict of all editable settings after the write
        (same shape as get_editable_settings()).

    Raises:
        ValueError: if `updates` contains any key outside the
                    whitelist — this is the hard boundary that
                    guarantees a secret can never be smuggled into
                    config.json through the settings API, even by a
                    caller that (incorrectly) tries to.
    """
    unknown = set(updates.keys()) - set(_EDITABLE_CONFIG_KEYS)
    if unknown:
        raise ValueError(f"Not editable via settings: {', '.join(sorted(unknown))}")

    path = config_file or _DEFAULT_CONFIG_FILE
    current = _load_json(path)
    current.update(updates)
    _write_json(path, current)

    # Invalidate the cached config so the NEXT get_config() call (e.g.
    # the settings page re-reading its own values right after saving)
    # reflects the write immediately — running scheduler/scanner
    # objects still won't pick this up until an actual process restart,
    # per this section's limitation note above.
    reset_config()

    return {k: current.get(k, getattr(CerberusConfig(), k, None)) for k in _EDITABLE_CONFIG_KEYS}


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

    link_secret = os.environ.get("CERBERUS_LINK_SECRET")
    if not link_secret:
        # No secret configured — generate an ephemeral one so the
        # feature still works for a single always-on process, but warn
        # loudly since it means previously emailed links go stale on
        # restart and multiple processes won't agree on signatures.
        link_secret = _secrets.token_hex(32)
        logger.warning(
            "CERBERUS_LINK_SECRET not set in .env — generated a random "
            "ephemeral secret for this run. Trust-confirmation email "
            "links will stop working after a restart. Set "
            "CERBERUS_LINK_SECRET in .env for persistent link validity "
            "(generate one with: python -c \"import secrets; "
            "print(secrets.token_hex(32))\")."
        )

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

        # Additional discovery sources
        dhcp_enabled        = _get("CERBERUS_DHCP_ENABLED",        "dhcp_enabled",        True, bool),
        dhcp_drain_interval = _get("CERBERUS_DHCP_DRAIN_INTERVAL", "dhcp_drain_interval", 60,   int),
        ssdp_enabled        = _get("CERBERUS_SSDP_ENABLED",        "ssdp_enabled",        True, bool),
        ssdp_interval       = _get("CERBERUS_SSDP_INTERVAL",       "ssdp_interval",       180,  int),
        llmnr_enabled       = _get("CERBERUS_LLMNR_ENABLED",       "llmnr_enabled",       True, bool),
        llmnr_interval      = _get("CERBERUS_LLMNR_INTERVAL",      "llmnr_interval",      90,   int),

        # Learning mode state file
        learning_mode_state_file = _get(
            "CERBERUS_LEARNING_STATE_FILE", "learning_mode_state_file",
            "data/learning_mode.json",
        ),

        # Email Trust/Block links
        link_secret             = link_secret,                        # env ONLY (or ephemeral)
        link_token_expiry_hours = _get("CERBERUS_LINK_TOKEN_EXPIRY_HOURS", "link_token_expiry_hours", 72, int),
        router_user             = os.environ.get("CERBERUS_ROUTER_USER"),      # env ONLY
        router_password         = os.environ.get("CERBERUS_ROUTER_PASSWORD"),  # env ONLY
        public_base_url         = _get("CERBERUS_PUBLIC_URL", "public_base_url", "", str).rstrip("/"),
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
        if not cfg.router_user or not cfg.router_password:
            logger.warning(
                "email_alerts_enabled=True but CERBERUS_ROUTER_USER / "
                "CERBERUS_ROUTER_PASSWORD not set — alert emails' Block "
                "section will omit router login credentials."
            )
        if not cfg.public_base_url:
            logger.warning(
                f"CERBERUS_PUBLIC_URL not set — Trust links in emails will "
                f"default to http://localhost:{cfg.api_port}, which only "
                f"opens correctly on THIS machine. Set CERBERUS_PUBLIC_URL "
                f"to this machine's LAN IP (e.g. http://192.168.1.50:{cfg.api_port}) "
                f"to open Trust links from your phone or another device."
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
    if cfg.link_token_expiry_hours < 1:
        logger.warning(
            f"link_token_expiry_hours={cfg.link_token_expiry_hours} is very "
            "low — Trust confirmation links may expire before the operator "
            "sees the email."
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
    logger.info(f"  DHCP sniffing    : {'ON' if cfg.dhcp_enabled else 'OFF'} "
                f"(drained every {cfg.dhcp_drain_interval}s)")
    logger.info(f"  SSDP discovery   : {'ON' if cfg.ssdp_enabled else 'OFF'} "
                f"(every {cfg.ssdp_interval}s)")
    logger.info(f"  LLMNR discovery  : {'ON' if cfg.llmnr_enabled else 'OFF'} "
                f"(every {cfg.llmnr_interval}s)")
    logger.info(f"  Trust link expiry: {cfg.link_token_expiry_hours}h")
    logger.info(f"  Public base URL  : {cfg.public_base_url or f'(auto) http://localhost:{cfg.api_port}'}")
    if cfg.smtp_password:
        logger.info("  SMTP password    : [set via .env]")
    if cfg.api_secret_key:
        logger.info("  API secret key   : [set via .env]")
    if cfg.router_user:
        logger.info("  Router creds     : [set via .env]")


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


def _write_json(path, data: dict) -> None:
    """
    Write any dict to a config.json-shaped file. Generalized out of
    what used to be _write_default_config()'s hardcoded body, since
    update_editable_settings() (this revision) needs to write an
    arbitrary MERGED dict back, not just the original defaults.

    Accepts either a str or Path for `path` — coerced to Path
    immediately, since callers pass both (config_loader's internal
    Path usage vs. update_editable_settings() working with the plain
    str path callers pass in).
    """
    path = Path(path)
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.debug(f"Config written to {path}.")
    except Exception as e:
        logger.warning(f"Could not write config to {path}: {e}")


def _write_default_config(path: Path) -> None:
    """Write default config.json on first run."""
    _write_json(path, _DEFAULT_CONFIG)
    logger.info(f"Default config written to {path}. Edit it to customise Cerberus behaviour.")


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
        assert cfg.link_secret is not None  # ephemeral secret generated
        assert cfg.link_token_expiry_hours == 72
        assert os.path.exists(config_path)
        print("[PASS] First run: default config written and loaded, mDNS + link defaults correct")

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

        os.environ["CERBERUS_LINK_SECRET"] = "fixed-test-secret"
        reset_config()
        cfg_link = get_config(config_file=config_path)
        assert cfg_link.link_secret == "fixed-test-secret"
        print("[PASS] CERBERUS_LINK_SECRET honoured when set")
        del os.environ["CERBERUS_LINK_SECRET"]

        os.environ["CERBERUS_ROUTER_USER"] = "admin"
        os.environ["CERBERUS_ROUTER_PASSWORD"] = "routerpass"
        reset_config()
        cfg_router = get_config(config_file=config_path)
        assert cfg_router.router_user == "admin"
        assert cfg_router.router_password == "routerpass"
        print("[PASS] Router credentials from env only")
        del os.environ["CERBERUS_ROUTER_USER"]
        del os.environ["CERBERUS_ROUTER_PASSWORD"]

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