"""Configuration management for Hamburglar.

This module provides a robust configuration system with proper priority handling:

1. CLI arguments (highest priority)
2. Environment variables
3. Configuration file
4. Default values (lowest priority)

Example usage::

    from hamburglar.config import get_config, HamburglarConfig

    # Get the current configuration (loads from all sources)
    config = get_config()

    # Override with CLI arguments
    config = get_config(cli_args={"concurrency": 100})

    # Get specific settings
    print(config.scan.max_file_size)
    print(config.detector.enabled_categories)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, TypeVar

# Re-export schema classes
from hamburglar.config.schema import (
    DetectorSettings,
    HamburglarConfig,
    OutputSettings,
    ScanSettings,
    YaraSettings,
)

# Re-export loader classes
from hamburglar.config.loader import ConfigLoader

# Re-export environment variable utilities
from hamburglar.config.env import (
    ENV_CONFIG_PATH,
    ENV_YARA_RULES,
    ENV_OUTPUT_FORMAT,
    ENV_DB_PATH,
    ENV_CONCURRENCY,
    ENV_LOG_LEVEL,
    ENV_CATEGORIES,
    get_env_overrides,
)

__all__ = [
    # Schema classes
    "ScanSettings",
    "DetectorSettings",
    "OutputSettings",
    "YaraSettings",
    "HamburglarConfig",
    # Loader
    "ConfigLoader",
    # Environment variables
    "ENV_CONFIG_PATH",
    "ENV_YARA_RULES",
    "ENV_OUTPUT_FORMAT",
    "ENV_DB_PATH",
    "ENV_CONCURRENCY",
    "ENV_LOG_LEVEL",
    "ENV_CATEGORIES",
    "get_env_overrides",
    # Priority handling
    "ConfigPriority",
    "get_config",
    "load_config",
]


class ConfigPriority(str, Enum):
    """Configuration source priority levels.

    Higher priority sources override lower priority ones.
    """

    DEFAULT = "default"
    CONFIG_FILE = "config_file"
    ENVIRONMENT = "environment"
    CLI = "cli"


# Global configuration cache
_config_cache: HamburglarConfig | None = None
_config_sources: dict[str, ConfigPriority] = {}


def _merge_configs(
    base: dict[str, Any],
    override: dict[str, Any],
    source: ConfigPriority,
) -> tuple[dict[str, Any], dict[str, ConfigPriority]]:
    """Recursively merge configuration dictionaries.

    Args:
        base: The base configuration dictionary.
        override: The overriding configuration dictionary.
        source: The priority source for the override values.

    Returns:
        A tuple of (merged_config, sources_dict) where sources_dict
        tracks which priority each key came from.
    """
    result = base.copy()
    sources: dict[str, ConfigPriority] = {}

    for key, value in override.items():
        if value is None:
            continue

        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            # Recursively merge nested dicts
            merged, nested_sources = _merge_configs(result[key], value, source)
            result[key] = merged
            for nested_key, nested_source in nested_sources.items():
                sources[f"{key}.{nested_key}"] = nested_source
        else:
            result[key] = value
            sources[key] = source

    return result, sources


def load_config(
    config_path: Path | str | None = None,
    cli_args: dict[str, Any] | None = None,
    use_env: bool = True,
    use_file: bool = True,
) -> HamburglarConfig:
    """Load configuration with proper priority handling.

    Configuration is merged in the following order (later sources override earlier):
    1. Default values
    2. Configuration file (if found)
    3. Environment variables
    4. CLI arguments

    Args:
        config_path: Optional explicit path to a config file.
        cli_args: Optional dictionary of CLI argument overrides.
        use_env: Whether to apply environment variable overrides.
        use_file: Whether to look for and load config files.

    Returns:
        A fully merged HamburglarConfig instance.

    Raises:
        ConfigError: If the configuration is invalid.
    """
    global _config_cache, _config_sources

    # Start with defaults
    config_dict: dict[str, Any] = {}
    sources: dict[str, ConfigPriority] = {}

    # Layer 1: Defaults (implicit in HamburglarConfig)
    default_config = HamburglarConfig()
    config_dict = default_config.model_dump()

    # Layer 2: Configuration file
    if use_file:
        loader = ConfigLoader()
        file_path = config_path or loader.find_config_file()
        if file_path:
            file_config = loader.load(file_path)
            file_dict = file_config.model_dump(exclude_unset=True)
            config_dict, file_sources = _merge_configs(
                config_dict, file_dict, ConfigPriority.CONFIG_FILE
            )
            sources.update(file_sources)

    # Layer 3: Environment variables
    if use_env:
        env_overrides = get_env_overrides()
        if env_overrides:
            config_dict, env_sources = _merge_configs(
                config_dict, env_overrides, ConfigPriority.ENVIRONMENT
            )
            sources.update(env_sources)

    # Layer 4: CLI arguments (highest priority)
    if cli_args:
        cli_dict = _normalize_cli_args(cli_args)
        config_dict, cli_sources = _merge_configs(
            config_dict, cli_dict, ConfigPriority.CLI
        )
        sources.update(cli_sources)

    # Create the final config
    config = HamburglarConfig.model_validate(config_dict)

    # Cache the result
    _config_cache = config
    _config_sources = sources

    return config


def _normalize_cli_args(cli_args: dict[str, Any]) -> dict[str, Any]:
    """Normalize CLI arguments into nested config structure.

    Converts flat CLI argument names into nested config sections.

    Args:
        cli_args: Dictionary of CLI argument names to values.

    Returns:
        Nested configuration dictionary.
    """
    result: dict[str, Any] = {
        "scan": {},
        "detector": {},
        "output": {},
        "yara": {},
    }

    # Mapping of CLI arg names to config paths
    mappings = {
        # Scan settings
        "recursive": ("scan", "recursive"),
        "max_file_size": ("scan", "max_file_size"),
        "concurrency": ("scan", "concurrency"),
        "timeout": ("scan", "timeout"),
        # Detector settings
        "categories": ("detector", "enabled_categories"),
        "enabled_categories": ("detector", "enabled_categories"),
        "disabled_patterns": ("detector", "disabled_patterns"),
        "min_confidence": ("detector", "min_confidence"),
        "custom_patterns_path": ("detector", "custom_patterns_path"),
        # Output settings
        "format": ("output", "format"),
        "output_format": ("output", "format"),
        "output": ("output", "output_path"),
        "output_path": ("output", "output_path"),
        "save_to_db": ("output", "save_to_db"),
        "db_path": ("output", "db_path"),
        # YARA settings
        "yara": ("yara", "enabled"),
        "use_yara": ("yara", "enabled"),
        "yara_rules": ("yara", "rules_path"),
        "yara_rules_path": ("yara", "rules_path"),
        "yara_timeout": ("yara", "timeout"),
    }

    for arg_name, value in cli_args.items():
        if value is None:
            continue

        if arg_name in mappings:
            section, key = mappings[arg_name]
            result[section][key] = value
        else:
            # Unknown args go to the top level (for extension)
            result[arg_name] = value

    # Clean up empty sections
    return {k: v for k, v in result.items() if v}


def get_config(
    cli_args: dict[str, Any] | None = None,
    reload: bool = False,
) -> HamburglarConfig:
    """Get the current configuration, loading if necessary.

    This is the primary entry point for getting configuration.
    It uses caching to avoid reloading on every call.

    Args:
        cli_args: Optional CLI argument overrides.
        reload: If True, force reload from all sources.

    Returns:
        The current HamburglarConfig instance.
    """
    global _config_cache

    if _config_cache is None or reload or cli_args:
        return load_config(cli_args=cli_args)

    return _config_cache


def get_config_source(key: str) -> ConfigPriority | None:
    """Get the priority source for a configuration key.

    Useful for debugging which source a particular setting came from.

    Args:
        key: The configuration key (e.g., "scan.concurrency").

    Returns:
        The ConfigPriority that provided this value, or None if using default.
    """
    return _config_sources.get(key)


def reset_config() -> None:
    """Reset the configuration cache.

    Forces the next call to get_config() to reload from all sources.
    Primarily useful for testing.
    """
    global _config_cache, _config_sources
    _config_cache = None
    _config_sources = {}
