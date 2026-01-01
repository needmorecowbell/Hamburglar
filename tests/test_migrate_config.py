"""Tests for the migrate-config.py script.

Tests configuration migration from legacy ham.conf to new TOML format.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from textwrap import dedent

import pytest

# Import migration script functions
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from importlib import import_module

# Import the module without running main()
migrate_config = import_module("migrate-config")

parse_ham_conf = migrate_config.parse_ham_conf
generate_toml_config = migrate_config.generate_toml_config
run_non_interactive_migration = migrate_config.run_non_interactive_migration
find_ham_conf = migrate_config.find_ham_conf


class TestParseHamConf:
    """Tests for parsing legacy ham.conf files."""

    def test_parse_basic_mysql_section(self, tmp_path: Path) -> None:
        """Test parsing a basic ham.conf with MySQL section."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = hamman
            password = deadbeef
        """).strip()
        )

        result = parse_ham_conf(conf_file)

        assert "mysql" in result
        assert result["mysql"]["user"] == "hamman"
        assert result["mysql"]["password"] == "deadbeef"

    def test_parse_mysql_with_all_fields(self, tmp_path: Path) -> None:
        """Test parsing ham.conf with all MySQL fields."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = testuser
            password = testpass
            host = localhost
            database = fileSign
            port = 3306
        """).strip()
        )

        result = parse_ham_conf(conf_file)

        assert result["mysql"]["user"] == "testuser"
        assert result["mysql"]["password"] == "testpass"
        assert result["mysql"]["host"] == "localhost"
        assert result["mysql"]["database"] == "fileSign"
        assert result["mysql"]["port"] == "3306"

    def test_parse_case_insensitive_mysql(self, tmp_path: Path) -> None:
        """Test parsing with lowercase mysql section name."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mysql]
            user = lowercase
            password = secret
        """).strip()
        )

        result = parse_ham_conf(conf_file)

        assert "mysql" in result
        assert result["mysql"]["user"] == "lowercase"

    def test_parse_empty_file(self, tmp_path: Path) -> None:
        """Test parsing an empty ham.conf."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text("")

        result = parse_ham_conf(conf_file)

        assert result == {}

    def test_parse_unknown_sections(self, tmp_path: Path) -> None:
        """Test parsing ham.conf with unknown sections."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = hamman
            password = deadbeef

            [customSection]
            key1 = value1
            key2 = value2
        """).strip()
        )

        result = parse_ham_conf(conf_file)

        assert "mysql" in result
        assert "customSection" in result
        assert result["customSection"]["key1"] == "value1"
        assert result["customSection"]["key2"] == "value2"

    def test_parse_file_not_found(self, tmp_path: Path) -> None:
        """Test parsing nonexistent file returns empty dict (configparser behavior)."""
        conf_file = tmp_path / "nonexistent.conf"

        # configparser.read() silently ignores missing files
        result = parse_ham_conf(conf_file)
        assert result == {}

    def test_parse_invalid_syntax(self, tmp_path: Path) -> None:
        """Test parsing file with invalid INI syntax."""
        conf_file = tmp_path / "ham.conf"
        # This should still parse without errors (configparser is lenient)
        conf_file.write_text(
            dedent("""
            [mySql]
            user = hamman
        """).strip()
        )

        result = parse_ham_conf(conf_file)
        assert result["mysql"]["user"] == "hamman"


class TestGenerateTomlConfig:
    """Tests for TOML configuration generation."""

    def test_generate_default_config(self) -> None:
        """Test generating default TOML configuration."""
        legacy_config: dict = {}
        options = run_non_interactive_migration(legacy_config)

        result = generate_toml_config(legacy_config, options)

        assert "[scan]" in result
        assert "[detector]" in result
        assert "[output]" in result
        assert "[yara]" in result
        assert "log_level" in result

    def test_generate_config_with_mysql_warning(self) -> None:
        """Test that MySQL config adds migration notes."""
        legacy_config = {
            "mysql": {
                "user": "hamman",
                "password": "secret",
            }
        }
        options = run_non_interactive_migration(legacy_config)

        result = generate_toml_config(legacy_config, options)

        assert "MIGRATION NOTE" in result
        assert "MySQL Configuration" in result
        assert "user: hamman" in result
        assert "password: **********" in result  # Password hidden
        assert "secret" not in result  # Actual password not shown

    def test_generate_config_respects_options(self) -> None:
        """Test that options are reflected in generated config."""
        legacy_config: dict = {}
        options = {
            "recursive": False,
            "max_file_size": "50MB",
            "concurrency": 100,
            "timeout": 60,
            "blacklist": [".git", "vendor"],
            "whitelist": ["*.py", "*.js"],
            "enabled_categories": ["api_keys", "credentials"],
            "min_confidence": "high",
            "format": "json",
            "save_to_db": True,
            "quiet": True,
            "verbose": True,
            "yara_enabled": True,
            "yara_rules_path": "/custom/rules",
            "yara_timeout": 60,
            "log_level": "debug",
        }

        result = generate_toml_config(legacy_config, options)

        assert "recursive = false" in result
        assert 'max_file_size = "50MB"' in result
        assert "concurrency = 100" in result
        assert "timeout = 60" in result
        assert '".git"' in result
        assert '"vendor"' in result
        assert '"*.py"' in result
        assert '"*.js"' in result
        assert '"api_keys"' in result
        assert '"credentials"' in result
        assert 'min_confidence = "high"' in result
        assert 'format = "json"' in result
        assert "save_to_db = true" in result
        assert "quiet = true" in result
        assert "verbose = true" in result
        assert "enabled = true" in result
        assert 'rules_path = "/custom/rules"' in result
        assert 'log_level = "debug"' in result

    def test_generate_config_empty_whitelist(self) -> None:
        """Test that empty whitelist is rendered correctly."""
        legacy_config: dict = {}
        options = {
            "recursive": True,
            "max_file_size": "10MB",
            "concurrency": 50,
            "timeout": 30,
            "blacklist": [".git"],
            "whitelist": [],
            "enabled_categories": [],
            "min_confidence": "low",
            "format": "table",
            "save_to_db": False,
            "quiet": False,
            "verbose": False,
            "yara_enabled": False,
            "yara_rules_path": None,
            "yara_timeout": 30,
            "log_level": "info",
        }

        result = generate_toml_config(legacy_config, options)

        assert "whitelist = []" in result


class TestNonInteractiveMigration:
    """Tests for non-interactive migration mode."""

    def test_default_options(self) -> None:
        """Test that non-interactive mode returns sensible defaults."""
        legacy_config: dict = {}

        options = run_non_interactive_migration(legacy_config)

        assert options["recursive"] is True
        assert options["max_file_size"] == "10MB"
        assert options["concurrency"] == 50
        assert options["timeout"] == 30
        assert ".git" in options["blacklist"]
        assert "node_modules" in options["blacklist"]
        assert options["whitelist"] == []
        assert options["enabled_categories"] == []
        assert options["min_confidence"] == "low"
        assert options["format"] == "table"
        assert options["save_to_db"] is False
        assert options["yara_enabled"] is False
        assert options["log_level"] == "info"

    def test_mysql_enables_yara(self) -> None:
        """Test that MySQL config enables YARA as replacement."""
        legacy_config = {
            "mysql": {
                "user": "hamman",
                "password": "secret",
            }
        }

        options = run_non_interactive_migration(legacy_config)

        assert options["yara_enabled"] is True
        assert options["yara_rules_path"] == "./rules"


class TestFindHamConf:
    """Tests for ham.conf auto-discovery."""

    def test_find_in_current_directory(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test finding ham.conf in current directory."""
        monkeypatch.chdir(tmp_path)
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text("[mySql]\nuser = test")

        result = find_ham_conf()

        assert result == conf_file

    def test_find_hidden_in_current_directory(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test finding .ham.conf in current directory."""
        monkeypatch.chdir(tmp_path)
        conf_file = tmp_path / ".ham.conf"
        conf_file.write_text("[mySql]\nuser = test")

        result = find_ham_conf()

        assert result == conf_file

    def test_not_found(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test returning None when no ham.conf found."""
        monkeypatch.chdir(tmp_path)

        result = find_ham_conf()

        assert result is None


class TestCLI:
    """Tests for the CLI interface."""

    def test_help_output(self) -> None:
        """Test --help displays usage information."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "migrate-config.py"), "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "ham.conf" in result.stdout.lower() or "migrate" in result.stdout.lower()

    def test_dry_run_no_file_creation(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test --dry-run doesn't create files."""
        monkeypatch.chdir(tmp_path)

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                "--dry-run",
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "dry run" in result.stdout.lower() or "dry-run" in result.stdout.lower()
        assert not (tmp_path / ".hamburglar.toml").exists()

    def test_non_interactive_creates_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test non-interactive mode creates config file."""
        monkeypatch.chdir(tmp_path)

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        output_file = tmp_path / ".hamburglar.toml"
        assert output_file.exists()

        content = output_file.read_text()
        assert "[scan]" in content
        assert "[detector]" in content
        assert "[output]" in content

    def test_custom_output_path(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test --output writes to custom path."""
        monkeypatch.chdir(tmp_path)
        output_file = tmp_path / "custom" / "config.toml"

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                "--no-interactive",
                "--output",
                str(output_file),
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert output_file.exists()

    def test_migrate_from_ham_conf(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test migrating from an actual ham.conf file."""
        monkeypatch.chdir(tmp_path)

        # Create legacy config
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = hamman
            password = deadbeef
        """).strip()
        )

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(conf_file),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0

        output_file = tmp_path / ".hamburglar.toml"
        assert output_file.exists()

        content = output_file.read_text()
        # Should have YARA enabled as MySQL replacement
        assert "enabled = true" in content
        # Should have migration notes
        assert "MIGRATION NOTE" in content
        assert "user: hamman" in content

    def test_overwrite_requires_force(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that existing file requires --force."""
        monkeypatch.chdir(tmp_path)

        # Create existing config
        existing = tmp_path / ".hamburglar.toml"
        existing.write_text("existing content")

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "exists" in result.stdout.lower() or "force" in result.stdout.lower()
        # File should not be overwritten
        assert existing.read_text() == "existing content"

    def test_force_overwrites(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test that --force overwrites existing file."""
        monkeypatch.chdir(tmp_path)

        # Create existing config
        existing = tmp_path / ".hamburglar.toml"
        existing.write_text("existing content")

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                "--no-interactive",
                "--force",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert existing.read_text() != "existing content"
        assert "[scan]" in existing.read_text()

    def test_nonexistent_input_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test error when specified ham.conf doesn't exist."""
        monkeypatch.chdir(tmp_path)

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                "/nonexistent/ham.conf",
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        assert "not found" in result.stdout.lower() or "error" in result.stdout.lower()


class TestTomlValidity:
    """Tests that generated TOML is valid."""

    def test_generated_toml_is_valid(self) -> None:
        """Test that generated config parses as valid TOML."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found]

        legacy_config: dict = {}
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        # Should parse without error
        parsed = tomllib.loads(toml_content)

        assert "scan" in parsed
        assert "detector" in parsed
        assert "output" in parsed
        assert "yara" in parsed
        assert parsed["scan"]["recursive"] is True
        assert parsed["scan"]["max_file_size"] == "10MB"
        assert parsed["detector"]["min_confidence"] == "low"
        assert parsed["output"]["format"] == "table"

    def test_generated_toml_with_mysql_is_valid(self) -> None:
        """Test that config with MySQL migration notes is valid TOML."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found]

        legacy_config = {
            "mysql": {
                "user": "hamman",
                "password": "secret",
                "host": "localhost",
                "database": "fileSign",
            }
        }
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        # Should parse without error (comments are valid TOML)
        parsed = tomllib.loads(toml_content)

        assert parsed["yara"]["enabled"] is True
        assert parsed["yara"]["rules_path"] == "./rules"

    def test_generated_toml_with_special_characters(self) -> None:
        """Test that config with special patterns is valid TOML."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found]

        legacy_config: dict = {}
        options = {
            "recursive": True,
            "max_file_size": "10MB",
            "concurrency": 50,
            "timeout": 30,
            "blacklist": ["*.pyc", "**/__pycache__/**", "node_modules"],
            "whitelist": ["src/**/*.py", "tests/**/*.py"],
            "enabled_categories": [],
            "min_confidence": "low",
            "format": "table",
            "save_to_db": False,
            "quiet": False,
            "verbose": False,
            "yara_enabled": False,
            "yara_rules_path": None,
            "yara_timeout": 30,
            "log_level": "info",
        }
        toml_content = generate_toml_config(legacy_config, options)

        parsed = tomllib.loads(toml_content)

        assert "*.pyc" in parsed["scan"]["blacklist"]
        assert "**/__pycache__/**" in parsed["scan"]["blacklist"]
        assert "src/**/*.py" in parsed["scan"]["whitelist"]
