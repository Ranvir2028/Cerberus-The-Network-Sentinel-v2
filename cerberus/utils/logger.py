# Ye vala module updated hai colorama ka use karke ab thoda sa fancy lagega zarurat nahi thi par still bana diya maje ke liye.
"""
Logging setup Module to make and look the code clean.
Usage:
    import cerberus_logger

    logger = cerberus_logger.setup_logging()
"""
import colorama
import logging
import sys

# Add color support for console output
colorama.init()


class ColoredFormatter(logging.Formatter):
    """Custom formatter that adds colors to log level names."""
    
    COLORS = {
        'DEBUG': '\033[36m',    # Cyan
        'INFO': '\033[32m',     # Green
        'WARNING': '\033[33m',  # Yellow
        'ERROR': '\033[31m',    # Red
        'CRITICAL': '\033[35m', # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        record.levelname = f"{log_color}{record.levelname}{self.COLORS['RESET']}"
        return super().format(record)


def setup_logging(
        log_file="cerberus.log",
        level="INFO",
        silent_mode=False
):
    """
    Set up logging configuration with file and optional console output.
    
    Args:
        log_file (str): Name of the log file. Defaults to "cerberus.log"
        level (str): Log level (DEBUG, INFO, WARNING, ERROR, CRITICAL). Defaults to "INFO"
        silent_mode (bool): If True, don't show logs in console. If False, show in terminal. Defaults to False
    
    Returns:
        logging.Logger: Configured logger instance
    """
    level_map = {
        "DEBUG": logging.DEBUG,
        "INFO": logging.INFO,
        "WARNING": logging.WARNING,
        "ERROR": logging.ERROR,
        "CRITICAL": logging.CRITICAL
    }
    log_level = level_map.get(level.upper(), logging.INFO)

    # Format for log messages
    log_format = "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
    date_format = "%Y-%m-%d %H:%M:%S"
    
    # Regular formatter for file
    file_formatter = logging.Formatter(log_format, datefmt=date_format)
    
    handlers = []

    # File handler (always log to file)
    file_handler = logging.FileHandler(
        log_file,
        mode="a",  # Append mode
        encoding="utf-8"
    )
    file_handler.setFormatter(file_formatter)
    handlers.append(file_handler)

    # Console handler with colors
    if not silent_mode:
        console_handler = logging.StreamHandler(sys.stdout)
        colored_formatter = ColoredFormatter(log_format, datefmt=date_format)
        console_handler.setFormatter(colored_formatter)
        handlers.append(console_handler)

    # Configure root logger
    logging.basicConfig(
        level=log_level,
        handlers=handlers,
        force=True  # Override any existing configuration
    )

    logger = logging.getLogger("cerberus")
    logger.info(f"Logging initialized. Level: {level}, File: {log_file}")

    return logger


def get_logger(name):
    """
    Get a logger instance with the specified name.
    
    Args:
        name (str): Name for the logger
    
    Returns:
        logging.Logger: Logger instance
    """
    return logging.getLogger(name)