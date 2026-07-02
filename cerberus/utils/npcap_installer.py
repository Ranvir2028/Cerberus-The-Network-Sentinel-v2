"""
I build this module for the Npcap driver installation because windows dosent have any built in which send & recieve raw packets
so they needs to install Npcap manually by going to browser and then install it but, this script will do that work.

So, this is basically a Npcap Installer or say auto-installer which will be both a automatically or if you dont want, then it will guide you to install the Npcap.
Features:
    1} Checks if Npcap is already installed (multiple methods)
    2} Downloads latest Npcap installer
    3} Installs with recommended options
    4} Falls back to limited scanning if user skips
    5} Clean installation with progress feedback
"""
import os
import sys
import platform
import subprocess
import requests
import tempfile
import time
from typing import Optional, Tuple
import winreg
from scapy.all import conf
import ctypes

try:
    from cerberus.utils.logger import get_logger
    logger = get_logger("cerberus.utils.npcap_installer")
    CERBERUS_LOGGER_AVAILABLE = True
except ImportError:
    import logging
    logging.basicConfig(level=logging.INFO)
    logger = logging.getLogger("cerberus.utils.npcap_installer")
    CERBERUS_LOGGER_AVAILABLE = False
    logger.warning("cerberus.utils.logger not found, using standard logging.")

# ========================= Npcap Installer Class =========================

class NpcapInstaller:
    """
    This is a Npcap installer class for Windows systems.
    """

    NPCAP_DOWNLOAD_URL = "https://npcap.com/dist/npcap-1.79.exe"
    NPCAP_FILE_NAME = "npcap_installer.exe"

# ------------------------- Platform Detection -------------------------

    @staticmethod
    def is_windows() -> bool:
        """Checks if running on windows."""
        return platform.system() == "Windows"
    
    # ------------------------- Installation Detection -------------------------

    @staticmethod
    def is_npcap_installed() -> Tuple[bool, str]:
        """
        It is for checking if Npcap is installed or not i made some methods for it.
        
        :return: Tuple[bool, str]: (is_installed, detection_method)
        """
        # Method 1: Check Scapy functionality
        try:
            if hasattr(conf, 'L2listen'):
                # Try to create a raw socket (actual functionality test)
                test_socket = conf.L2listen()
                test_socket.close()
                logger.debug("Npcap detected via Scapy raw socket test.")
                return True, "Scapy raw socket test."
        except Exception as e:
            logger.debug(f"Scapy test failed: {e}.")
        
        # Method 2: Check Windows Registry
        try:
            if NpcapInstaller.is_windows():
                try:
                    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                                         r"SOFTWARE\Npcap", 
                                         0, 
                                         winreg.KEY_READ)
                    winreg.CloseKey(key)
                    logger.debug("Npcap detected via Windows Registry.")
                    return True, "Windows Registry."
                except WindowsError:
                    logger.debug("Npcap not found in Registry.")
        except ImportError as e:
            logger.debug(f"Registry check failed (non-Windows?): {e}.")
        
        # Method 3: Check installed files
        npcap_paths = [
            r"C:\Program Files\Npcap",
            r"C:\Program Files (x86)\Npcap",
            r"C:\Windows\System32\Npcap"
        ]
        for path in npcap_paths:
            if os.path.exists(path):
                logger.debug(f"Npcap detected in file system: {path}.")
                return True, f"File system: {path}."
            # No detection method found Npcap installed
            logger.debug("Npcap not detected by any method.")
            return False, "not detected"
    
    # ------------------------- Privilege Check -------------------------
    
    @staticmethod
    def check_admin_rights() -> bool:
        try:
            if NpcapInstaller.is_windows():
                is_admin = ctypes.windll.shell32.IsUserAnAdmin() != 0
                logger.debug(f"Admin rights check: {is_admin}.")
                return is_admin
            else:
                # Linux/macOS - check for root
                is_root = os.geteuid() == 0
                logger.debug(f"Root check (non-Windows): {is_root}.")
                return is_root
        except Exception as e:
            logger.error(f"Admin rights check failed: {e}.")
            return False

    # ------------------------- Download Management -------------------------

    @staticmethod
    def download_with_progress(url: str, destination: str) -> bool:
        """
        Download file with progress bar.
        
        :url: str: Parameter - URL to download from (type: string)
        :destination: str: Where to save the file (type: string)
        -> bool: Returns a boolean (True = success, False = failure)
        """
        
        try:
            logger.info(f"Downloading Npcap installer to: {destination}.")
            
            # It will be streaming download with progress bar
            # & also it is an HTTP Request Setup
            response = requests.get(url, stream=True, timeout=60)
            """
            stream=True: CRITICAL - downloads in chunks instead of all at once
            timeout=60: Waits max 60 seconds for server response
            Why stream=True matters:
            Without it: Downloads entire file into RAM first, then saves (bad for large files)
            With it: Downloads in pieces directly to disk (memory efficient)
            """
            # Below is for checking the response Status
            response.raise_for_status()    # Raises HTTPError, if one occurred.

            # Below is for getting the File Size
            total_size = int(response.headers.get('content-length', 0))
            """
            response.headers: HTTP response headers from server
            .get('content-length', 0): Gets file size in bytes, defaults to 0 if not provided
            int(...): Converts to integer
            Example: If file is 5MB → total_size = 5,242,880 bytes
            """
            # Setup Download Tracking
            block_size = 8192   # 8 × 1024 bytes = 8192 bytes
            downloaded = 0
            """
            block_size = 8192: Download in 8KB chunks (8 × 1024 bytes)
            Why 8192? Optimal balance between speed and memory
            downloaded = 0: Counter to track how much we've downloaded
            """
            
            with open(destination, 'wb') as file:
                """
                open(destination, 'wb'): Opens file in write-binary mode
                'wb' = WRITE BINARY (needed for executable files like .exe)
                with ...: Context manager - automatically closes file even if errors occur
                """

                for chunk in response.iter_content(chunk_size=block_size):
                    """
                    response.iter_content(): Generator that yields chunks of data
                    chunk_size=block_size: Each chunk is 8192 bytes
                    Visualize: File comes in 8KB pieces, like getting a pizza slice by slice
                    """
                    if chunk:
                        file.write(chunk)
                        downloaded += len(chunk)    # Updates our counter
                        # Example: After first chunk → downloaded = 8192 bytes
                        
                        # Progress Bar Logic: thoda sa dimag kharab kiya isne
                        if total_size > 0:
                            percent = (downloaded / total_size) * 100    # Calculates percentage: (8192 / 5,242,880) × 100 = 0.16%
                            bar_length = 40    # Our progress bar is 40 characters wide 
                            filled_length = int(bar_length * downloaded // total_size)    # How many of those 40 should be filled aur kitna ye bharega, {a // b does integer division directly (// : floor division)}
                            # Example: At 50% → filled_length = 20 (half the bar)
                            bar = ('█' * filled_length) + ('░' * (bar_length - filled_length))    # Creates the visual bar: '█' for filled, '░' for empty.
                            
                            sys.stdout.write(f'\r[{bar}] {percent:.1f}% ({downloaded/1e6:.1f}/{total_size/1e6:.1f} MB)')
                            """
                            sys.stdout: Print ka bhi basic version hai direct output show karta hai newline add karne ka kasht bhi nahi karta, par ye kisi-kisi chiz me bohot kaam deta hai toh zaruri hai bohot ye
                            \r: Carriage return - moves cursor to start of the current line, unlike \n which moves to the next line (Overwrites the previous output on the same line)
                            [bar]: The visual progress bar
                            {percent:.1f}%:  :.1f means format as float with 1 decimal place means Percentage with 1 decimal (e.g., "50.0%")
                            {downloaded/1e6:.1f}: Megabytes downloaded (divides bytes by 1,000,000)
                                Example:
                                        downloaded = 2,500,000  # 2.5 MB in bytes
                                        total_size = 5,000,000  # 5.0 MB in bytes
                                        # /1e6 converts bytes to megabytes
                                        f"{downloaded/1e6:.1f}"  # "2.5"
                                        f"{total_size/1e6:.1f}"  # "5.0"
                                        # Complete: "(2.5/5.0 MB)"
                                        Output: [████████████████████░░░░░░░░░░░░░░░░] 50.0% (2.5/5.0 MB)
                            """
                            sys.stdout.flush()    # Forces immediate display (otherwise Python buffers output)
            
            print()  # New line after progress
            logger.info(f"Npcap download complete: {destination}.")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Npcap download failed: {e}.")
            return False
        except Exception as e:
            logger.error(f"Unexpected download error: {e}.")
            return False
    
    @staticmethod
    def download_npcap(destination_folder: Optional[str] = None) -> Optional[str]:
        """
        Download Npcap installer.
        
        Args:
            destination_folder: Save location (default: temp)
            
        Returns:
            str: Path to installer or None if failed
        """
        if destination_folder is None:
            destination_folder = tempfile.gettempdir()
        
        installer_path = os.path.join(destination_folder, NpcapInstaller.NPCAP_FILE_NAME)
        
        logger.info(f"Initiating Npcap download from: {NpcapInstaller.NPCAP_DOWNLOAD_URL}.")
        
        # Download
        if NpcapInstaller.download_with_progress(NpcapInstaller.NPCAP_DOWNLOAD_URL, installer_path):
            logger.info(f"Npcap installer downloaded successfully: {installer_path}.")
            return installer_path
        else:
            logger.error("Npcap download failed.")
            return None
    
    # ------------------------- Installation -------------------------
    
    @staticmethod
    def install_npcap(installer_path: str, silent: bool = True) -> Tuple[bool, str]:
        """
        Install Npcap.
        
        Args:
            installer_path: Path to installer
            silent: Silent installation
            
        Returns:
            Tuple[bool, str]: (success, message)
        """
        if not os.path.exists(installer_path):
            error_msg = f"Installer not found: {installer_path}"
            logger.error(error_msg)
            return False, error_msg
        
        logger.info("Starting Npcap installation process...")
        
        try:
            if silent:
                # SILENT INSTALLATION WITH RECOMMENDED OPTIONS
                cmd = [
                    installer_path,
                    "/S",                    # Silent mode
                    "winpcap_mode=yes",      # WinPcap API compatibility
                    "loopback_support=yes",  # Enable loopback adapter
                    "admin_only=no",         # Allow non-admin capture
                    "dot11_support=yes",     # 802.11 wireless support
                    "dlt_null=yes"           # Raw packet support (CRITICAL!)
                ]
                logger.debug("Using silent installation with recommended options.")
            else:
                # Interactive installation
                cmd = [installer_path]
                logger.debug("Using interactive installation.")
            
            logger.debug(f"Installation command: {' '.join(cmd)}")
            
            # Run installer
            result = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=300  # 5 minute timeout
            )
            
            if result.returncode == 0:
                logger.info("Npcap installation completed successfully.")
                return True, "Installation successful."
            else:
                error_msg = f"Installer returned code {result.returncode}."
                if result.stderr:
                    error_msg += f": {result.stderr}"
                logger.error(error_msg)
                return False, error_msg
                
        except subprocess.TimeoutExpired:
            error_msg = "Installation timed out after 5 minutes."
            logger.error(error_msg)
            return False, error_msg
        except Exception as e:
            error_msg = f"Installation error: {e}."
            logger.error(error_msg)
            return False, error_msg
    
    # ------------------------- Complete Installation Flow -------------------------

    @staticmethod
    def install_if_needed(force_check: bool = False) -> Tuple[bool, str, bool]:
        """
        Complete installation flow.
        
        Args:
            force_check: Force re-check even if previously installed
            
        Returns:
            Tuple[bool, str, bool]: (installed, message, reboot_required)
        """
        # Only for Windows
        if not NpcapInstaller.is_windows():
            logger.info("Not Windows platform - Npcap not required.")
            return True, "Not Windows - Npcap not required.", False
        
        logger.info("Checking Npcap installation status...")
        
        # Check if already installed
        installed, method = NpcapInstaller.is_npcap_installed()
        if installed and not force_check:
            logger.info(f"Npcap already installed (detected via: {method}).")
            return True, f"Npcap already installed ({method}).", False
        
        # Check admin rights
        if not NpcapInstaller.check_admin_rights():
            logger.warning("Administrator privileges required for Npcap installation.")
            return False, "Administrator privileges required.", False
        
        # Download installer
        logger.info("Proceeding with Npcap download...")
        installer_path = NpcapInstaller.download_npcap()
        if not installer_path:
            logger.error("Failed to download Npcap installer.")
            return False, "Failed to download Npcap installer.", False
        
        # Install
        logger.info("Starting Npcap installation...")
        success, message = NpcapInstaller.install_npcap(installer_path, silent=True)
        
        # It will do the cleanup part like removing/deleting temporary files that was made during the installation.
        try:
            os.remove(installer_path)
            logger.debug("Cleaned up temporary installer file.")
        except Exception as e:
            logger.warning(f"Could not remove installer file: {e}.")
        
        if success:
            logger.info("Npcap installation completed successfully.")
            return True, "Npcap installed successfully.", True
        else:
            logger.error(f"Npcap installation failed: {message}.")
            return False, f"Installation failed: {message}.", False

# ========================= User Interface Functions =========================

def show_npcap_banner():
    """Display Npcap information banner."""
    print("\n" + "="*70)
    print("🎯 CERBERUS: THE NETWORK SENTINEL")
    print("="*70)
    print("\n📡 NETWORK SCANNING REQUIREMENTS")
    print("-"*70)
    print("\nCerberus requires Npcap for full network scanning capabilities.")
    print("\nNpcap is a Windows packet capture driver that allows:")
    print("  ✔️ Full device discovery (ARP scanning)")
    print("  ✔️ MAC address detection")
    print("  ✔️ Network traffic analysis")
    print("  ✔️ Professional-grade network monitoring")
    print("\nWithout Npcap, Cerberus will use limited Windows-native scanning.")
    print("="*70)
    
    # Log this event
    logger.info("Displayed Npcap installation banner to user.")

def prompt_user_for_installation() -> str:
    """
    Interactive prompt for user.
    
    Returns:
        str: User choice - 'auto', 'manual', 'skip', or 'exit'
    """
    print("\nPlease choose an option:")
    print("\n  1. 🚀 AUTO-INSTALL (Recommended)")
    print("     • Downloads and installs Npcap automatically.")
    print("     • Uses recommended settings.")
    print("     • Requires administrator rights.")
    
    print("\n  2. 📖 MANUAL INSTALL")
    print("     • Opens Npcap website in browser.")
    print("     • You download and run installer.")
    print("     • More control over installation.")
    
    print("\n  3. ⚡ SKIP & CONTINUE")
    print("     • Use limited Windows-native scanning.")
    print("     • May not detect all devices.")
    print("     • No installation required.")
    
    print("\n  4. ❌ EXIT")
    print("     • Close Cerberus.")
    
    print("\n" + "-"*70)
    
    while True:
        choice = input("\nYour choice (1/2/3/4): ").strip()
        
        if choice == "1":
            logger.info("User selected: Auto-install Npcap.")
            return "auto"
        elif choice == "2":
            logger.info("User selected: Manual Npcap installation.")
            return "manual"
        elif choice == "3":
            logger.info("User selected: Skip Npcap installation.")
            return "skip"
        elif choice == "4":
            logger.info("User selected: Exit Cerberus.")
            return "exit"
        else:
            print("Invalid choice. Please enter 1, 2, 3, or 4.")
            logger.warning(f"User entered invalid choice: {choice}")

def handle_npcap_installation() -> bool:
    """
    Non-interactive Npcap check — Windows-only. Auto-installs silently if
    missing and admin rights are available. No user prompts; logs the
    outcome and returns whether scanning can proceed.

    Returns:
        bool: True if Npcap is available (or not needed on this OS),
              False if missing and could not be auto-installed.
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
            "Npcap missing and administrator privileges are required to "
            "install it. Re-run Cerberus as Administrator, or install "
            "Npcap manually from https://npcap.com/#download."
        )
        return False

    installer_path = NpcapInstaller.download_npcap()
    if not installer_path:
        logger.error("Npcap download failed — cannot proceed with scanning.")
        return False

    success, message = NpcapInstaller.install_npcap(installer_path, silent=True)

    try:
        os.remove(installer_path)
    except Exception as e:
        logger.warning(f"Could not remove installer file: {e}")

    if success:
        logger.info(
            "Npcap installed successfully. A system reboot may be required "
            "before raw packet capture works — restart if scanning fails."
        )
        return True

    logger.error(f"Npcap installation failed: {message}")
    return False


# ========================= Command Line Interface =========================

def main():
    """Command-line entry point for testing."""
    if not CERBERUS_LOGGER_AVAILABLE:
        print("⚠️ cerberus.utils.logger not found - using basic logging")
    
    print("NPCAP INSTALLER - STANDALONE TEST MODE")
    print("="*70)
    
    success = handle_npcap_installation()
    
    if success:
        logger.info("Npcap installer test completed successfully")
        print("\n✅ TEST COMPLETE - NPCAP READY")
    else:
        logger.error("Npcap installer test failed")
        print("\n❌ TEST FAILED - NPCAP NOT AVAILABLE")
    
    print("\n" + "="*70)

# ========================= Module Initialization =========================

logger.info("Npcap installer module loaded successfully")


if __name__ == "__main__":
    main()