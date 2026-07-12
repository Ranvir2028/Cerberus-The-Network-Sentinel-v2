# deps: pip install requests
"""
utils/npcap_installer.py

Job: Windows only — checks for Npcap (the packet-capture driver
Scapy needs on Windows for raw ARP scanning), and silently installs it
if missing, with no user interaction required. On any non-Windows
platform, every function here is a fast, harmless no-op — Linux/macOS
don't need Npcap at all (they have native raw-socket support), and
this module must be safely IMPORTABLE on those platforms too, not just
"gated at call time" — see the critical fix below.

Non-interactive by design (this revision):
  Earlier versions of this module prompted the user with a menu
  (auto-install / manual / skip / exit) via input(). That's been
  removed entirely — Cerberus now handles this fully underneath, with
  no prompts: check → (if missing) silently download and install with
  recommended options → log the outcome → return whether scanning can
  proceed. This matters because Cerberus may eventually run
  non-interactively (a scheduled task, a background service, later a
  container) where a blocking input() call would hang forever with no
  way to respond to it.

Critical cross-platform fix (this revision):
  The previous version did `import winreg` UNCONDITIONALLY at module
  level. winreg is a WINDOWS-ONLY stdlib module — importing it on
  Linux/macOS raises ModuleNotFoundError immediately, which would
  crash the import of this ENTIRE module on any non-Windows machine,
  which in turn would crash cerberus_main.py's own import chain (it
  imports handle_npcap_installation from here) — breaking Cerberus
  completely on Linux/macOS, not just disabling the Npcap-specific
  functionality. This is fixed by importing winreg inside a try/except
  at module level, exactly like the existing cerberus_logger fallback
  pattern already used just below it. Every function that actually
  USES winreg is already gated behind is_windows() checks — the
  problem was purely the unconditional import itself, not the logic
  that consumes it.

Other fixes applied this revision:
  1. is_npcap_installed() had no return statement if none of its three
     detection methods succeeded — every caller does
     `installed, method = is_npcap_installed()`, which would raise
     TypeError (cannot unpack None) the moment Npcap genuinely wasn't
     found, which is exactly the case this function exists to detect.
     Fixed: falls through to an explicit `return False, "not detected"`.
  2. Duplicate `import subprocess` line removed.
  3. The `cerberus_logger` fallback import referenced a top-level
     module that doesn't exist in this project (the real logger lives
     at cerberus.utils.logger) — fixed to import from the correct path,
     with the same try/except fallback pattern preserved for safety.

Features:
    1) Checks if Npcap is already installed (multiple detection methods)
    2) Downloads the latest Npcap installer if missing
    3) Installs silently with recommended options
    4) Logs a clear warning and continues in limited-scanning mode if
       installation isn't possible (e.g. no admin rights) — never
       blocks Cerberus from starting entirely over this
    5) No user interaction required anywhere in this flow
"""

import os
import sys
import platform
import subprocess
import tempfile
import time
from typing import Optional, Tuple

import requests

try:
    import ctypes
except ImportError:
    ctypes = None  # Not expected to ever fail, but guarded for consistency

# winreg is WINDOWS-ONLY — see module docstring's "Critical cross-
# platform fix" above. This try/except is what makes this entire
# module safely importable on Linux/macOS.
try:
    import winreg
except ImportError:
    winreg = None

try:
    from scapy.all import conf
except ImportError:
    conf = None  # Scapy itself might not be installed yet at this point

try:
    from cerberus.utils.logger import get_logger
    logger = get_logger("cerberus.utils.npcap_installer")
    CERBERUS_LOGGER_AVAILABLE = True
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("cerberus.utils.npcap_installer")
    CERBERUS_LOGGER_AVAILABLE = False
    logger.warning("cerberus.utils.logger not found — using standard logging.")


# ========================= Npcap Installer Class =========================

class NpcapInstaller:
    """Npcap installer for Windows systems. Every method is a no-op-safe
    static method — no instance state, matching how it's called throughout."""

    NPCAP_DOWNLOAD_URL = "https://npcap.com/dist/npcap-1.79.exe"
    NPCAP_FILE_NAME = "npcap_installer.exe"

    # ------------------------- Platform Detection -------------------------

    @staticmethod
    def is_windows() -> bool:
        """Checks if running on Windows."""
        return platform.system() == "Windows"

    # ------------------------- Installation Detection -------------------------

    @staticmethod
    def is_npcap_installed() -> Tuple[bool, str]:
        """
        Check whether Npcap is installed, via several methods in order.

        Returns:
            Tuple[bool, str]: (is_installed, detection_method_or_reason).
            ALWAYS returns a 2-tuple — see module docstring fix #1 for
            why this matters (every caller unpacks this directly).
        """
        # Method 1: Scapy raw-socket functionality test
        if conf is not None:
            try:
                if hasattr(conf, "L2listen"):
                    test_socket = conf.L2listen()
                    test_socket.close()
                    logger.debug("Npcap detected via Scapy raw socket test.")
                    return True, "Scapy raw socket test"
            except Exception as e:
                logger.debug(f"Scapy test failed: {e}")

        # Method 2: Windows Registry
        if NpcapInstaller.is_windows() and winreg is not None:
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\Npcap", 0, winreg.KEY_READ
                )
                winreg.CloseKey(key)
                logger.debug("Npcap detected via Windows Registry.")
                return True, "Windows Registry"
            except OSError:
                logger.debug("Npcap not found in Registry.")

        # Method 3: Known installation paths
        npcap_paths = [
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap",
            r"C:\Windows\System32\Npcap",
        ]
        for path in npcap_paths:
            if os.path.exists(path):
                logger.debug(f"Npcap detected in file system: {path}")
                return True, f"File system: {path}"

        # FIX #1: explicit fallback — every caller unpacks a 2-tuple,
        # so falling off the end without returning anything (the
        # original bug) would raise TypeError right when Npcap is
        # genuinely absent, which is the exact case this exists to catch.
        logger.debug("Npcap not detected by any method.")
        return False, "not detected"

    # ------------------------- Privilege Check -------------------------

    @staticmethod
    def check_admin_rights() -> bool:
        """Returns True if running with Administrator (Windows) or root
        (Linux/macOS) privileges."""
        try:
            if NpcapInstaller.is_windows():
                if ctypes is None:
                    return False
                return ctypes.windll.shell32.IsUserAnAdmin() != 0
            else:
                return os.geteuid() == 0
        except Exception as e:
            logger.error(f"Admin rights check failed: {e}")
            return False

    # ------------------------- Download Management -------------------------

    @staticmethod
    def download_npcap(destination_folder: Optional[str] = None) -> Optional[str]:
        """
        Download the Npcap installer.

        Args:
            destination_folder: Save location (default: system temp dir).

        Returns:
            Path to the downloaded installer, or None on failure.
        """
        if destination_folder is None:
            destination_folder = tempfile.gettempdir()

        installer_path = os.path.join(destination_folder, NpcapInstaller.NPCAP_FILE_NAME)
        logger.info(f"Downloading Npcap from {NpcapInstaller.NPCAP_DOWNLOAD_URL} ...")

        try:
            response = requests.get(NpcapInstaller.NPCAP_DOWNLOAD_URL, stream=True, timeout=60)
            response.raise_for_status()

            with open(installer_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)

            logger.info(f"Npcap installer downloaded: {installer_path}")
            return installer_path

        except requests.exceptions.RequestException as e:
            logger.error(f"Npcap download failed: {e}")
            return None
        except Exception as e:
            logger.error(f"Unexpected download error: {e}")
            return None

    # ------------------------- Installation -------------------------

    @staticmethod
    def install_npcap(installer_path: str, silent: bool = True) -> Tuple[bool, str]:
        """
        Run the Npcap installer.

        Args:
            installer_path: Path to the downloaded installer.
            silent         : Use silent install flags with recommended options.

        Returns:
            Tuple[bool, str]: (success, message).
        """
        if not os.path.exists(installer_path):
            msg = f"Installer not found: {installer_path}"
            logger.error(msg)
            return False, msg

        try:
            if silent:
                cmd = [
                    installer_path,
                    "/S",
                    "winpcap_mode=yes",
                    "loopback_support=yes",
                    "admin_only=no",
                    "dot11_support=yes",
                    "dlt_null=yes",
                ]
            else:
                cmd = [installer_path]

            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                logger.info("Npcap installation completed successfully.")
                return True, "Installation successful"

            msg = f"Installer returned code {result.returncode}"
            if result.stderr:
                msg += f": {result.stderr}"
            logger.error(msg)
            return False, msg

        except subprocess.TimeoutExpired:
            msg = "Installation timed out after 5 minutes."
            logger.error(msg)
            return False, msg
        except Exception as e:
            msg = f"Installation error: {e}"
            logger.error(msg)
            return False, msg


# ========================= Non-interactive entry point =========================

def handle_npcap_installation() -> bool:
    """
    Non-interactive Npcap check and (if needed) silent install.
    Windows-only in effect — an instant no-op True on any other OS.

    No prompts, no input() calls anywhere in this flow. Suitable for
    both interactive terminal use and any future non-interactive
    launch context (scheduled task, service, container).

    Returns:
        True if scanning can proceed (Npcap present, not needed on this
        OS, or successfully installed). False if Npcap is missing and
        could not be installed (e.g. no admin rights, download failed) —
        the caller (cerberus_main.py) decides whether that's fatal.
    """
    if not NpcapInstaller.is_windows():
        logger.debug("Non-Windows platform — Npcap not required.")
        return True

    installed, method = NpcapInstaller.is_npcap_installed()
    if installed:
        logger.info(f"Npcap already installed (detected via: {method}).")
        return True

    logger.warning("Npcap not detected — attempting silent auto-install.")

    if not NpcapInstaller.check_admin_rights():
        logger.error(
            "Npcap is missing and Administrator privileges are required to "
            "install it. Re-run Cerberus as Administrator, or install Npcap "
            "manually from https://npcap.com/#download, then restart Cerberus."
        )
        return False

    installer_path = NpcapInstaller.download_npcap()
    if not installer_path:
        logger.error("Npcap download failed — cannot proceed with full scanning.")
        return False

    success, message = NpcapInstaller.install_npcap(installer_path, silent=True)

    try:
        os.remove(installer_path)
    except Exception as e:
        logger.debug(f"Could not remove temporary installer file: {e}")

    if success:
        logger.info(
            "Npcap installed successfully. A system reboot may occasionally "
            "be required before raw packet capture works — restart Cerberus "
            "(and reboot Windows if scanning still fails) if needed."
        )
        return True

    logger.error(f"Npcap installation failed: {message}")
    return False


# ========================= Standalone test =========================

if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("NPCAP INSTALLER — NON-INTERACTIVE TEST")
    print("=" * 60)
    print(f"Platform: {platform.system()}\n")

    result = handle_npcap_installation()

    print(f"\nResult: {'READY' if result else 'NOT AVAILABLE'}")
    print("=" * 60)