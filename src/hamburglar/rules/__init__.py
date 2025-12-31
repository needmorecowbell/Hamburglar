"""Hamburglar YARA rules package.

This package contains YARA rule files for detecting various file types
and patterns. The rules are used by the YaraDetector to identify
file signatures and patterns of interest.
"""

from pathlib import Path

# Path to the rules directory
RULES_DIR = Path(__file__).parent


def get_rules_path() -> Path:
    """Get the path to the bundled YARA rules directory.

    Returns:
        Path to the rules directory containing .yar files.
    """
    return RULES_DIR


def list_rules() -> list[Path]:
    """List all YARA rule files in the bundled rules directory.

    Returns:
        List of paths to .yar files.
    """
    return list(RULES_DIR.glob("*.yar"))
