"""Configuration schema definitions using Pydantic Settings.

This module defines all configuration models for Hamburglar with proper
validation, defaults, and documentation.
"""

from __future__ import annotations

from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class LogLevel(str, Enum):
    """Logging levels."""

    DEBUG = "debug"
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"


class OutputFormatConfig(str, Enum):
    """Supported output formats for configuration."""

    JSON = "json"
    TABLE = "table"
    SARIF = "sarif"
    CSV = "csv"
    HTML = "html"
    MARKDOWN = "markdown"


class ScanSettings(BaseModel):
    """Settings for scan operations.

    Controls how files are discovered and processed during scanning.
    """

    recursive: bool = Field(
        default=True,
        description="Whether to scan directories recursively",
    )
    max_file_size: int = Field(
        default=10 * 1024 * 1024,  # 10 MB
        ge=0,
        description="Maximum file size in bytes to scan (0 for unlimited)",
    )
    concurrency: int = Field(
        default=50,
        ge=1,
        le=1000,
        description="Maximum number of concurrent file operations",
    )
    timeout: float = Field(
        default=30.0,
        ge=0,
        description="Timeout in seconds for individual file scans (0 for unlimited)",
    )
    blacklist: list[str] = Field(
        default_factory=lambda: [
            ".git",
            "__pycache__",
            "node_modules",
            ".venv",
            "venv",
            ".env",
            "*.pyc",
            "*.pyo",
        ],
        description="Patterns to exclude from scanning",
    )
    whitelist: list[str] = Field(
        default_factory=list,
        description="If non-empty, only scan files matching these patterns",
    )

    @field_validator("max_file_size", mode="before")
    @classmethod
    def parse_file_size(cls, v: Any) -> int:
        """Parse file size from string format (e.g., '10MB', '1G')."""
        if isinstance(v, str):
            v = v.strip().upper()
            multipliers = {
                "B": 1,
                "K": 1024,
                "KB": 1024,
                "M": 1024 * 1024,
                "MB": 1024 * 1024,
                "G": 1024 * 1024 * 1024,
                "GB": 1024 * 1024 * 1024,
            }
            for suffix, mult in sorted(multipliers.items(), key=lambda x: -len(x[0])):
                if v.endswith(suffix):
                    return int(float(v[: -len(suffix)]) * mult)
            return int(v)
        return int(v) if v is not None else 10 * 1024 * 1024


class DetectorSettings(BaseModel):
    """Settings for secret detection.

    Controls which detectors and patterns are used during scanning.
    """

    enabled_categories: list[str] = Field(
        default_factory=list,
        description="Pattern categories to enable (empty = all)",
    )
    disabled_patterns: list[str] = Field(
        default_factory=list,
        description="Specific pattern names to disable",
    )
    min_confidence: str = Field(
        default="low",
        description="Minimum confidence level for findings (low, medium, high)",
    )
    custom_patterns_path: Path | None = Field(
        default=None,
        description="Path to custom pattern definitions file",
    )

    @field_validator("min_confidence", mode="before")
    @classmethod
    def validate_confidence(cls, v: Any) -> str:
        """Validate confidence level."""
        if v is None:
            return "low"
        v = str(v).lower()
        valid = {"low", "medium", "high"}
        if v not in valid:
            raise ValueError(f"min_confidence must be one of: {', '.join(valid)}")
        return v

    @field_validator("enabled_categories", mode="before")
    @classmethod
    def parse_categories(cls, v: Any) -> list[str]:
        """Parse categories from string or list."""
        if v is None:
            return []
        if isinstance(v, str):
            return [c.strip() for c in v.split(",") if c.strip()]
        return list(v)


class OutputSettings(BaseModel):
    """Settings for output formatting and storage.

    Controls how scan results are formatted and saved.
    """

    format: OutputFormatConfig = Field(
        default=OutputFormatConfig.TABLE,
        description="Output format for scan results",
    )
    output_path: Path | None = Field(
        default=None,
        description="Path to save output file (None for stdout)",
    )
    save_to_db: bool = Field(
        default=False,
        description="Whether to save findings to SQLite database",
    )
    db_path: Path = Field(
        default_factory=lambda: Path.home() / ".hamburglar" / "findings.db",
        description="Path to SQLite database file",
    )
    quiet: bool = Field(
        default=False,
        description="Suppress non-essential output",
    )
    verbose: bool = Field(
        default=False,
        description="Enable verbose output",
    )

    @field_validator("format", mode="before")
    @classmethod
    def validate_format(cls, v: Any) -> OutputFormatConfig:
        """Validate and normalize output format."""
        if v is None:
            return OutputFormatConfig.TABLE
        if isinstance(v, OutputFormatConfig):
            return v
        v = str(v).lower()
        try:
            return OutputFormatConfig(v)
        except ValueError:
            valid = ", ".join(f.value for f in OutputFormatConfig)
            raise ValueError(f"format must be one of: {valid}")


class YaraSettings(BaseModel):
    """Settings for YARA rule scanning.

    Controls YARA rule loading and execution.
    """

    enabled: bool = Field(
        default=False,
        description="Whether to use YARA rules for detection",
    )
    rules_path: Path | None = Field(
        default=None,
        description="Path to YARA rules directory",
    )
    timeout: float = Field(
        default=30.0,
        ge=0,
        description="Timeout in seconds for YARA matching",
    )
    compiled_rules_path: Path | None = Field(
        default=None,
        description="Path to pre-compiled YARA rules",
    )

    @model_validator(mode="after")
    def validate_rules_path_if_enabled(self) -> "YaraSettings":
        """Warn if YARA is enabled but no rules path is set."""
        # Note: We don't raise an error here because rules_path might be
        # set later or use a default location
        return self


class HamburglarConfig(BaseSettings):
    """Main configuration for Hamburglar.

    Combines all settings sections into a single configuration object.
    This can be loaded from environment variables, config files, or
    constructed programmatically.
    """

    model_config = SettingsConfigDict(
        env_prefix="HAMBURGLAR_",
        env_nested_delimiter="__",
        case_sensitive=False,
        extra="ignore",
    )

    scan: ScanSettings = Field(
        default_factory=ScanSettings,
        description="Scan operation settings",
    )
    detector: DetectorSettings = Field(
        default_factory=DetectorSettings,
        description="Detection settings",
    )
    output: OutputSettings = Field(
        default_factory=OutputSettings,
        description="Output settings",
    )
    yara: YaraSettings = Field(
        default_factory=YaraSettings,
        description="YARA settings",
    )
    log_level: LogLevel = Field(
        default=LogLevel.INFO,
        description="Logging level",
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: Any) -> LogLevel:
        """Validate and normalize log level."""
        if v is None:
            return LogLevel.INFO
        if isinstance(v, LogLevel):
            return v
        v = str(v).lower()
        try:
            return LogLevel(v)
        except ValueError:
            valid = ", ".join(level.value for level in LogLevel)
            raise ValueError(f"log_level must be one of: {valid}")

    def to_scan_config(self, target_path: Path) -> "ScanConfig":
        """Convert to a ScanConfig for use with Scanner.

        Args:
            target_path: The path to scan.

        Returns:
            A ScanConfig instance with settings from this config.
        """
        from hamburglar.core.models import OutputFormat, ScanConfig

        # Map OutputFormatConfig to OutputFormat
        format_map = {
            OutputFormatConfig.JSON: OutputFormat.JSON,
            OutputFormatConfig.TABLE: OutputFormat.TABLE,
            OutputFormatConfig.SARIF: OutputFormat.SARIF,
            OutputFormatConfig.CSV: OutputFormat.CSV,
            OutputFormatConfig.HTML: OutputFormat.HTML,
            OutputFormatConfig.MARKDOWN: OutputFormat.MARKDOWN,
        }

        return ScanConfig(
            target_path=target_path,
            recursive=self.scan.recursive,
            use_yara=self.yara.enabled,
            yara_rules_path=self.yara.rules_path,
            output_format=format_map[self.output.format],
            blacklist=self.scan.blacklist,
            whitelist=self.scan.whitelist,
        )
