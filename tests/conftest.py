"""Pytest fixtures for Hamburglar tests.

This module provides reusable fixtures for testing Hamburglar components,
including temporary directories with sample secrets, sample content, and
default configurations.
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Generator

import pytest

# Configure path before any hamburglar imports.
# This is needed because there's a legacy hamburglar.py file in the project root
# that shadows the hamburglar package. We need to ensure src/ is searched first.
def _configure_path() -> None:
    """Configure sys.path to prioritize the src directory."""
    src_path = str(Path(__file__).parent.parent / "src")
    # Remove any current working directory entries that might contain hamburglar.py
    cwd = str(Path.cwd())
    project_root = str(Path(__file__).parent.parent)

    # Insert src at position 0 so it's searched first
    if src_path in sys.path:
        sys.path.remove(src_path)
    sys.path.insert(0, src_path)

    # Remove any cached hamburglar module that might be the legacy file
    for key in list(sys.modules.keys()):
        if key == "hamburglar" or key.startswith("hamburglar."):
            del sys.modules[key]

_configure_path()

# Now import from the package
from hamburglar.core.models import ScanConfig


@pytest.fixture
def sample_content_with_secrets() -> str:
    """Return a string containing various fake secrets for testing.

    Includes an AWS key, email address, Bitcoin address, and RSA private key header.
    """
    return """
# Configuration file with various secrets for testing

# AWS API Key (fake - uses AWS example pattern)
aws_access_key_id = "AKIAIOSFODNN7EXAMPLE"
aws_secret_access_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# Contact information
admin_email = "admin@example.com"
support_email = "support@test.org"

# Cryptocurrency
bitcoin_wallet = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

# Private key
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy
-----END RSA PRIVATE KEY-----

# Generic API Key (test pattern - not a real key format)
api_key = "test_key_1234567890abcdefghijklmnop"

# GitHub Token (invalid format for testing - real tokens have specific checksums)
github_token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
"""


@pytest.fixture
def temp_directory(tmp_path: Path, sample_content_with_secrets: str) -> Generator[Path, None, None]:
    """Create a temporary directory with sample files containing fake secrets.

    Creates a directory structure with:
    - secrets.txt: File containing various fake secrets
    - config.py: Python config file with embedded secrets
    - clean.txt: File with no secrets
    - subdir/nested.txt: Nested file with secrets

    Args:
        tmp_path: pytest's tmp_path fixture for temporary directory
        sample_content_with_secrets: fixture providing sample secret content

    Yields:
        Path to the temporary directory
    """
    # Create main secrets file
    secrets_file = tmp_path / "secrets.txt"
    secrets_file.write_text(sample_content_with_secrets)

    # Create a Python config file with secrets
    config_file = tmp_path / "config.py"
    config_file.write_text('''
"""Configuration module."""

AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
DATABASE_URL = "postgresql://user:password@localhost/db"
ADMIN_EMAIL = "admin@company.com"
''')

    # Create a clean file with no secrets
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("""
This is a clean file with no secrets.
It contains only regular text content.
Nothing sensitive here.
""")

    # Create a subdirectory with nested files
    subdir = tmp_path / "subdir"
    subdir.mkdir()

    nested_file = subdir / "nested.txt"
    nested_file.write_text("""
# Nested configuration
api_endpoint = "https://api.example.com"
ethereum_address = "0x742d35Cc6634C0532925a3b844Bc9e7595f0bB2d"
heroku_api_key = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
""")

    yield tmp_path


@pytest.fixture
def scanner_config(tmp_path: Path) -> ScanConfig:
    """Return a default ScanConfig for testing.

    Args:
        tmp_path: pytest's tmp_path fixture for temporary directory

    Returns:
        ScanConfig with default settings pointing to tmp_path
    """
    return ScanConfig(target_path=tmp_path)


@pytest.fixture
def scanner_config_non_recursive(tmp_path: Path) -> ScanConfig:
    """Return a ScanConfig with recursive scanning disabled.

    Args:
        tmp_path: pytest's tmp_path fixture for temporary directory

    Returns:
        ScanConfig with recursive=False
    """
    return ScanConfig(target_path=tmp_path, recursive=False)


@pytest.fixture
def scanner_config_with_whitelist(tmp_path: Path) -> ScanConfig:
    """Return a ScanConfig with whitelist filtering enabled.

    Args:
        tmp_path: pytest's tmp_path fixture for temporary directory

    Returns:
        ScanConfig with whitelist set to only scan .py files
    """
    return ScanConfig(target_path=tmp_path, whitelist=["*.py"])


@pytest.fixture
def scanner_config_with_blacklist(tmp_path: Path) -> ScanConfig:
    """Return a ScanConfig with custom blacklist patterns.

    Args:
        tmp_path: pytest's tmp_path fixture for temporary directory

    Returns:
        ScanConfig with blacklist including subdir
    """
    return ScanConfig(target_path=tmp_path, blacklist=["subdir", "*.txt"])
