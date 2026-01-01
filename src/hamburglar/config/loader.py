"""Configuration file loading and discovery.

This module handles finding and loading configuration files from various
locations and formats (YAML, TOML, JSON).
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from hamburglar.core.exceptions import ConfigError

# Try to import YAML and TOML parsers
try:
    import yaml

    HAS_YAML = True
except ImportError:
    HAS_YAML = False

try:
    import tomllib  # Python 3.11+
    HAS_TOML = True
except ImportError:
    try:
        import tomli as tomllib  # type: ignore[import-not-found]
        HAS_TOML = True
    except ImportError:
        HAS_TOML = False


# Config file names to search for (in order of preference)
CONFIG_FILE_NAMES = [
    ".hamburglar.yml",
    ".hamburglar.yaml",
    ".hamburglar.toml",
    "hamburglar.config.json",
    ".hamburglarrc",
    ".hamburglarrc.json",
    ".hamburglarrc.yaml",
    ".hamburglarrc.yml",
]

# User-level config directories
USER_CONFIG_DIRS = [
    Path.home() / ".config" / "hamburglar",
    Path.home() / ".hamburglar",
]


class ConfigLoader:
    """Loads and parses configuration files.

    Handles automatic discovery of config files in project directories
    and user-level config directories. Supports YAML, TOML, and JSON
    formats.
    """

    def __init__(self, search_paths: list[Path] | None = None) -> None:
        """Initialize the config loader.

        Args:
            search_paths: Additional paths to search for config files.
        """
        self.search_paths = search_paths or []

    def find_config_file(self, start_path: Path | None = None) -> Path | None:
        """Find a configuration file by searching standard locations.

        Searches in the following order:
        1. The start_path directory (or cwd if not specified)
        2. Parent directories up to the root
        3. User config directories (~/.config/hamburglar, ~/.hamburglar)
        4. Any additional search_paths

        Args:
            start_path: Directory to start searching from.

        Returns:
            Path to the config file if found, None otherwise.
        """
        search_dirs: list[Path] = []

        # Start from given path or current directory
        if start_path:
            start = Path(start_path).resolve()
        else:
            start = Path.cwd()

        # Add the start directory and its parents
        current = start
        while current != current.parent:
            search_dirs.append(current)
            current = current.parent
        search_dirs.append(current)  # Add root

        # Add user config directories
        search_dirs.extend(USER_CONFIG_DIRS)

        # Add any additional search paths
        search_dirs.extend(self.search_paths)

        # Search for config files
        for search_dir in search_dirs:
            if not search_dir.exists():
                continue

            for config_name in CONFIG_FILE_NAMES:
                config_path = search_dir / config_name
                if config_path.exists() and config_path.is_file():
                    return config_path

        return None

    def load(self, path: Path | str) -> "HamburglarConfig":
        """Load configuration from a file.

        Args:
            path: Path to the configuration file.

        Returns:
            A HamburglarConfig instance.

        Raises:
            ConfigError: If the file cannot be loaded or parsed.
        """
        path = Path(path)

        if not path.exists():
            raise ConfigError(f"Configuration file not found: {path}")

        if not path.is_file():
            raise ConfigError(f"Configuration path is not a file: {path}")

        try:
            data = self._load_file(path)
        except Exception as e:
            raise ConfigError(f"Failed to parse config file {path}: {e}") from e

        return self._parse_config(data, path)

    def _load_file(self, path: Path) -> dict[str, Any]:
        """Load and parse a configuration file.

        Args:
            path: Path to the config file.

        Returns:
            Parsed configuration dictionary.

        Raises:
            ConfigError: If the file format is unsupported or parsing fails.
        """
        suffix = path.suffix.lower()
        content = path.read_text(encoding="utf-8")

        if suffix in (".yml", ".yaml"):
            return self._load_yaml(content, path)
        elif suffix == ".toml":
            return self._load_toml(content, path)
        elif suffix == ".json":
            return self._load_json(content, path)
        elif path.name.startswith(".hamburglarrc"):
            # Try to detect format from content
            return self._load_auto_detect(content, path)
        else:
            # Try JSON as fallback
            return self._load_json(content, path)

    def _load_yaml(self, content: str, path: Path) -> dict[str, Any]:
        """Load YAML content.

        Args:
            content: YAML string content.
            path: Path for error messages.

        Returns:
            Parsed dictionary.

        Raises:
            ConfigError: If YAML parsing fails or PyYAML is not installed.
        """
        if not HAS_YAML:
            raise ConfigError(
                f"YAML config file found ({path}) but PyYAML is not installed. "
                "Install it with: pip install pyyaml"
            )

        try:
            data = yaml.safe_load(content)
            if data is None:
                return {}
            if not isinstance(data, dict):
                raise ConfigError(f"Config file must contain a mapping, got: {type(data).__name__}")
            return data
        except yaml.YAMLError as e:
            raise ConfigError(f"Invalid YAML in {path}: {e}") from e

    def _load_toml(self, content: str, path: Path) -> dict[str, Any]:
        """Load TOML content.

        Args:
            content: TOML string content.
            path: Path for error messages.

        Returns:
            Parsed dictionary.

        Raises:
            ConfigError: If TOML parsing fails or parser is not available.
        """
        if not HAS_TOML:
            raise ConfigError(
                f"TOML config file found ({path}) but no TOML parser is available. "
                "Install tomli with: pip install tomli (Python < 3.11)"
            )

        try:
            return tomllib.loads(content)
        except Exception as e:
            raise ConfigError(f"Invalid TOML in {path}: {e}") from e

    def _load_json(self, content: str, path: Path) -> dict[str, Any]:
        """Load JSON content.

        Args:
            content: JSON string content.
            path: Path for error messages.

        Returns:
            Parsed dictionary.

        Raises:
            ConfigError: If JSON parsing fails.
        """
        try:
            data = json.loads(content)
            if not isinstance(data, dict):
                raise ConfigError(f"Config file must contain an object, got: {type(data).__name__}")
            return data
        except json.JSONDecodeError as e:
            raise ConfigError(f"Invalid JSON in {path}: {e}") from e

    def _load_auto_detect(self, content: str, path: Path) -> dict[str, Any]:
        """Auto-detect format and load content.

        Args:
            content: File content.
            path: Path for error messages.

        Returns:
            Parsed dictionary.

        Raises:
            ConfigError: If format cannot be detected or parsing fails.
        """
        content = content.strip()

        # Try JSON first (starts with {)
        if content.startswith("{"):
            return self._load_json(content, path)

        # Try YAML (has YAML indicators or is not TOML)
        if HAS_YAML:
            try:
                return self._load_yaml(content, path)
            except ConfigError:
                pass

        # Try TOML
        if HAS_TOML:
            try:
                return self._load_toml(content, path)
            except ConfigError:
                pass

        raise ConfigError(
            f"Could not detect format of {path}. "
            "Ensure it is valid YAML, TOML, or JSON."
        )

    def _parse_config(self, data: dict[str, Any], path: Path) -> "HamburglarConfig":
        """Parse configuration dictionary into HamburglarConfig.

        Args:
            data: Configuration dictionary.
            path: Path for error messages.

        Returns:
            HamburglarConfig instance.

        Raises:
            ConfigError: If validation fails.
        """
        from hamburglar.config.schema import HamburglarConfig

        try:
            return HamburglarConfig.model_validate(data)
        except Exception as e:
            raise ConfigError(
                f"Invalid configuration in {path}: {e}\n"
                "Run 'hamburglar config validate' for details."
            ) from e

    def validate_config_file(self, path: Path | str) -> list[str]:
        """Validate a configuration file and return any errors.

        Args:
            path: Path to the config file.

        Returns:
            List of validation error messages (empty if valid).
        """
        errors: list[str] = []
        path = Path(path)

        if not path.exists():
            return [f"File not found: {path}"]

        if not path.is_file():
            return [f"Not a file: {path}"]

        try:
            data = self._load_file(path)
        except ConfigError as e:
            return [str(e)]

        # Validate against schema
        from hamburglar.config.schema import HamburglarConfig
        from pydantic import ValidationError

        try:
            HamburglarConfig.model_validate(data)
        except ValidationError as e:
            for error in e.errors():
                loc = ".".join(str(x) for x in error["loc"])
                msg = error["msg"]
                errors.append(f"{loc}: {msg}")

        return errors


def get_default_config_content(format: str = "yaml") -> str:
    """Generate default configuration file content.

    Args:
        format: Output format ('yaml', 'toml', or 'json').

    Returns:
        Configuration file content as a string.
    """
    if format == "yaml":
        return _get_yaml_config()
    elif format == "toml":
        return _get_toml_config()
    elif format == "json":
        return _get_json_config()
    else:
        raise ValueError(f"Unknown format: {format}")


def _get_yaml_config() -> str:
    """Generate default YAML configuration."""
    return '''# Hamburglar Configuration
# See https://github.com/needmorecowbell/Hamburglar for documentation

# Scan settings
scan:
  # Scan directories recursively
  recursive: true

  # Maximum file size to scan (supports K, M, G suffixes)
  max_file_size: 10MB

  # Number of concurrent file operations
  concurrency: 50

  # Timeout for individual file scans (seconds)
  timeout: 30

  # Patterns to exclude from scanning
  blacklist:
    - .git
    - __pycache__
    - node_modules
    - .venv
    - venv
    - "*.pyc"

  # If non-empty, only scan files matching these patterns
  whitelist: []

# Detector settings
detector:
  # Categories to enable (empty = all)
  # Available: api_keys, credentials, crypto, network, private_keys, cloud, generic
  enabled_categories: []

  # Specific pattern names to disable
  disabled_patterns: []

  # Minimum confidence level (low, medium, high)
  min_confidence: low

  # Path to custom pattern definitions
  # custom_patterns_path: ./custom_patterns.yaml

# Output settings
output:
  # Output format (json, table, sarif, csv, html, markdown)
  format: table

  # Path to save output (null for stdout)
  output_path: null

  # Save findings to SQLite database
  save_to_db: false

  # Path to SQLite database
  # db_path: ~/.hamburglar/findings.db

# YARA settings
yara:
  # Enable YARA rule scanning
  enabled: false

  # Path to YARA rules directory
  # rules_path: ./rules

  # Timeout for YARA matching (seconds)
  timeout: 30

# Logging level (debug, info, warning, error, critical)
log_level: info
'''


def _get_toml_config() -> str:
    """Generate default TOML configuration."""
    return '''# Hamburglar Configuration
# See https://github.com/needmorecowbell/Hamburglar for documentation

[scan]
# Scan directories recursively
recursive = true

# Maximum file size to scan (supports K, M, G suffixes)
max_file_size = "10MB"

# Number of concurrent file operations
concurrency = 50

# Timeout for individual file scans (seconds)
timeout = 30

# Patterns to exclude from scanning
blacklist = [
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "*.pyc",
]

# If non-empty, only scan files matching these patterns
whitelist = []

[detector]
# Categories to enable (empty = all)
# Available: api_keys, credentials, crypto, network, private_keys, cloud, generic
enabled_categories = []

# Specific pattern names to disable
disabled_patterns = []

# Minimum confidence level (low, medium, high)
min_confidence = "low"

# Path to custom pattern definitions
# custom_patterns_path = "./custom_patterns.yaml"

[output]
# Output format (json, table, sarif, csv, html, markdown)
format = "table"

# Save findings to SQLite database
save_to_db = false

# Path to SQLite database
# db_path = "~/.hamburglar/findings.db"

[yara]
# Enable YARA rule scanning
enabled = false

# Timeout for YARA matching (seconds)
timeout = 30

# Path to YARA rules directory
# rules_path = "./rules"

# Logging level (debug, info, warning, error, critical)
log_level = "info"
'''


def _get_json_config() -> str:
    """Generate default JSON configuration."""
    import json

    config = {
        "scan": {
            "recursive": True,
            "max_file_size": "10MB",
            "concurrency": 50,
            "timeout": 30,
            "blacklist": [
                ".git",
                "__pycache__",
                "node_modules",
                ".venv",
                "venv",
                "*.pyc",
            ],
            "whitelist": [],
        },
        "detector": {
            "enabled_categories": [],
            "disabled_patterns": [],
            "min_confidence": "low",
        },
        "output": {
            "format": "table",
            "output_path": None,
            "save_to_db": False,
        },
        "yara": {
            "enabled": False,
            "timeout": 30,
        },
        "log_level": "info",
    }

    return json.dumps(config, indent=2)
