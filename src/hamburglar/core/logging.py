"""Logging configuration for Hamburglar.

This module provides logging setup using the Rich library for
beautiful console output with timestamps and source context.
"""

import logging
from typing import Optional

from rich.logging import RichHandler

# Module-level logger instance for Hamburglar
_logger: Optional[logging.Logger] = None

# Default format includes timestamp and source context
LOG_FORMAT = "%(message)s"
DATE_FORMAT = "[%X]"


def setup_logging(verbose: bool = False) -> logging.Logger:
    """Configure Python logging with Rich handler.

    Sets up logging for the Hamburglar application with appropriate
    log levels based on verbosity. Uses Rich for colored, formatted
    console output.

    Args:
        verbose: If True, set log level to DEBUG for detailed output.
                 If False, set log level to WARNING to show only
                 warnings and errors.

    Returns:
        A configured logger instance for use throughout the application.

    Example:
        >>> logger = setup_logging(verbose=True)
        >>> logger.debug("Detailed debug info")
        >>> logger.info("Processing file...")
        >>> logger.warning("File is very large")
        >>> logger.error("Failed to process file")
    """
    global _logger

    # Determine log level based on verbosity
    level = logging.DEBUG if verbose else logging.WARNING

    # Configure the Rich handler with timestamps and source context
    rich_handler = RichHandler(
        level=level,
        show_time=True,
        show_level=True,
        show_path=True,
        rich_tracebacks=True,
        markup=True,
    )
    rich_handler.setFormatter(logging.Formatter(LOG_FORMAT, datefmt=DATE_FORMAT))

    # Get or create the hamburglar logger
    logger = logging.getLogger("hamburglar")
    logger.setLevel(level)

    # Remove any existing handlers to avoid duplicates
    logger.handlers.clear()

    # Add the Rich handler
    logger.addHandler(rich_handler)

    # Prevent propagation to root logger to avoid duplicate messages
    logger.propagate = False

    # Store the logger for get_logger()
    _logger = logger

    return logger


def get_logger() -> logging.Logger:
    """Get the Hamburglar logger instance.

    Returns the previously configured logger, or sets up a default
    logger if setup_logging() has not been called.

    Returns:
        The Hamburglar logger instance.

    Example:
        >>> logger = get_logger()
        >>> logger.info("Using existing logger")
    """
    global _logger

    if _logger is None:
        # Set up with default (non-verbose) settings
        _logger = setup_logging(verbose=False)

    return _logger
