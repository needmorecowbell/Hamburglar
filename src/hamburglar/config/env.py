"""Environment variable mapping for Hamburglar configuration.

This module defines the environment variables that can be used to
configure Hamburglar and provides utilities for reading them.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

# Environment variable names
ENV_CONFIG_PATH = "HAMBURGLAR_CONFIG_PATH"
ENV_YARA_RULES = "HAMBURGLAR_YARA_RULES"
ENV_OUTPUT_FORMAT = "HAMBURGLAR_OUTPUT_FORMAT"
ENV_DB_PATH = "HAMBURGLAR_DB_PATH"
ENV_CONCURRENCY = "HAMBURGLAR_CONCURRENCY"
ENV_LOG_LEVEL = "HAMBURGLAR_LOG_LEVEL"
ENV_CATEGORIES = "HAMBURGLAR_CATEGORIES"
ENV_MAX_FILE_SIZE = "HAMBURGLAR_MAX_FILE_SIZE"
ENV_TIMEOUT = "HAMBURGLAR_TIMEOUT"
ENV_RECURSIVE = "HAMBURGLAR_RECURSIVE"
ENV_YARA_ENABLED = "HAMBURGLAR_YARA_ENABLED"
ENV_SAVE_TO_DB = "HAMBURGLAR_SAVE_TO_DB"
ENV_MIN_CONFIDENCE = "HAMBURGLAR_MIN_CONFIDENCE"
ENV_QUIET = "HAMBURGLAR_QUIET"
ENV_VERBOSE = "HAMBURGLAR_VERBOSE"


def _parse_bool(value: str) -> bool:
    """Parse a boolean from a string value.

    Args:
        value: String to parse.

    Returns:
        Boolean value.
    """
    return value.lower() in ("true", "1", "yes", "on", "enabled")


def _parse_int(value: str) -> int | None:
    """Parse an integer from a string value.

    Args:
        value: String to parse.

    Returns:
        Integer value or None if parsing fails.
    """
    try:
        return int(value)
    except ValueError:
        return None


def _parse_float(value: str) -> float | None:
    """Parse a float from a string value.

    Args:
        value: String to parse.

    Returns:
        Float value or None if parsing fails.
    """
    try:
        return float(value)
    except ValueError:
        return None


def _parse_list(value: str) -> list[str]:
    """Parse a list from a comma-separated string.

    Args:
        value: Comma-separated string.

    Returns:
        List of strings.
    """
    return [item.strip() for item in value.split(",") if item.strip()]


def get_env_overrides() -> dict[str, Any]:
    """Get configuration overrides from environment variables.

    Reads all supported environment variables and returns a dictionary
    of configuration values that can be merged with other config sources.

    Returns:
        Dictionary of configuration values from environment variables.
    """
    overrides: dict[str, Any] = {
        "scan": {},
        "detector": {},
        "output": {},
        "yara": {},
    }

    # HAMBURGLAR_CONFIG_PATH is handled separately (specifies config file location)

    # Scan settings
    if ENV_CONCURRENCY in os.environ:
        value = _parse_int(os.environ[ENV_CONCURRENCY])
        if value is not None:
            overrides["scan"]["concurrency"] = value

    if ENV_MAX_FILE_SIZE in os.environ:
        overrides["scan"]["max_file_size"] = os.environ[ENV_MAX_FILE_SIZE]

    if ENV_TIMEOUT in os.environ:
        timeout_value = _parse_float(os.environ[ENV_TIMEOUT])
        if timeout_value is not None:
            overrides["scan"]["timeout"] = timeout_value

    if ENV_RECURSIVE in os.environ:
        overrides["scan"]["recursive"] = _parse_bool(os.environ[ENV_RECURSIVE])

    # Detector settings
    if ENV_CATEGORIES in os.environ:
        overrides["detector"]["enabled_categories"] = _parse_list(os.environ[ENV_CATEGORIES])

    if ENV_MIN_CONFIDENCE in os.environ:
        overrides["detector"]["min_confidence"] = os.environ[ENV_MIN_CONFIDENCE].lower()

    # Output settings
    if ENV_OUTPUT_FORMAT in os.environ:
        overrides["output"]["format"] = os.environ[ENV_OUTPUT_FORMAT].lower()

    if ENV_DB_PATH in os.environ:
        overrides["output"]["db_path"] = Path(os.environ[ENV_DB_PATH])

    if ENV_SAVE_TO_DB in os.environ:
        overrides["output"]["save_to_db"] = _parse_bool(os.environ[ENV_SAVE_TO_DB])

    if ENV_QUIET in os.environ:
        overrides["output"]["quiet"] = _parse_bool(os.environ[ENV_QUIET])

    if ENV_VERBOSE in os.environ:
        overrides["output"]["verbose"] = _parse_bool(os.environ[ENV_VERBOSE])

    # YARA settings
    if ENV_YARA_RULES in os.environ:
        overrides["yara"]["rules_path"] = Path(os.environ[ENV_YARA_RULES])

    if ENV_YARA_ENABLED in os.environ:
        overrides["yara"]["enabled"] = _parse_bool(os.environ[ENV_YARA_ENABLED])

    # Log level
    if ENV_LOG_LEVEL in os.environ:
        overrides["log_level"] = os.environ[ENV_LOG_LEVEL].lower()

    # Clean up empty sections
    overrides = {k: v for k, v in overrides.items() if v}

    return overrides


def get_config_path_from_env() -> Path | None:
    """Get the config file path from environment variable.

    Returns:
        Path to config file if set, None otherwise.
    """
    if ENV_CONFIG_PATH in os.environ:
        path = Path(os.environ[ENV_CONFIG_PATH])
        if path.exists():
            return path
    return None


def get_env_var_docs() -> dict[str, str]:
    """Get documentation for all environment variables.

    Returns:
        Dictionary mapping variable names to descriptions.
    """
    return {
        ENV_CONFIG_PATH: "Path to configuration file",
        ENV_YARA_RULES: "Path to YARA rules directory",
        ENV_OUTPUT_FORMAT: "Output format (json, table, sarif, csv, html, markdown)",
        ENV_DB_PATH: "Path to SQLite database file",
        ENV_CONCURRENCY: "Number of concurrent file operations",
        ENV_LOG_LEVEL: "Logging level (debug, info, warning, error, critical)",
        ENV_CATEGORIES: "Comma-separated list of detector categories to enable",
        ENV_MAX_FILE_SIZE: "Maximum file size to scan (e.g., 10MB)",
        ENV_TIMEOUT: "Timeout in seconds for file scans",
        ENV_RECURSIVE: "Whether to scan directories recursively (true/false)",
        ENV_YARA_ENABLED: "Whether to enable YARA scanning (true/false)",
        ENV_SAVE_TO_DB: "Whether to save findings to database (true/false)",
        ENV_MIN_CONFIDENCE: "Minimum confidence level (low, medium, high)",
        ENV_QUIET: "Suppress non-essential output (true/false)",
        ENV_VERBOSE: "Enable verbose output (true/false)",
    }
