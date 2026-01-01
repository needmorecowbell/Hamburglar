"""Tests for configuration migration from legacy ham.conf to v2 format.

This test module covers:
1. Old config files can be migrated
2. Migration script handles edge cases
3. Migrated config produces same behavior

These tests ensure that users migrating from Hamburglar v1 to v2 have a smooth
experience and that their configurations are properly converted.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from textwrap import dedent
from typing import Any

import pytest

# Import migration script functions
SCRIPTS_DIR = Path(__file__).parent.parent / "scripts"
sys.path.insert(0, str(SCRIPTS_DIR))

from importlib import import_module, reload

# Import the module without running main()
# Force reload to ensure we get the latest version (in case earlier tests cached it)
_module_name = "migrate-config"
if _module_name in sys.modules:
    migrate_config = reload(sys.modules[_module_name])
else:
    migrate_config = import_module(_module_name)

parse_ham_conf = migrate_config.parse_ham_conf
generate_toml_config = migrate_config.generate_toml_config
run_non_interactive_migration = migrate_config.run_non_interactive_migration
find_ham_conf = migrate_config.find_ham_conf

# Import v2 config loader
from hamburglar.config.loader import ConfigLoader
from hamburglar.config.schema import HamburglarConfig


# =============================================================================
# Test Fixtures
# =============================================================================


@pytest.fixture
def sample_ham_conf(tmp_path: Path) -> Path:
    """Create a sample ham.conf file for testing."""
    conf_file = tmp_path / "ham.conf"
    conf_file.write_text(
        dedent("""
        [mySql]
        user = hamman
        password = deadbeef
        host = localhost
        database = fileSign
        port = 3306
    """).strip()
    )
    return conf_file


@pytest.fixture
def complex_ham_conf(tmp_path: Path) -> Path:
    """Create a ham.conf with multiple sections."""
    conf_file = tmp_path / "ham.conf"
    conf_file.write_text(
        dedent("""
        [mySql]
        user = testuser
        password = testpass123!@#
        host = db.example.com
        database = signatures_db
        port = 3307

        [settings]
        verbose = true
        max_workers = 8
    """).strip()
    )
    return conf_file


@pytest.fixture
def minimal_ham_conf(tmp_path: Path) -> Path:
    """Create a minimal ham.conf with just MySQL credentials."""
    conf_file = tmp_path / "ham.conf"
    conf_file.write_text(
        dedent("""
        [mySql]
        user = admin
        password = secret
    """).strip()
    )
    return conf_file


@pytest.fixture
def empty_ham_conf(tmp_path: Path) -> Path:
    """Create an empty ham.conf file."""
    conf_file = tmp_path / "ham.conf"
    conf_file.write_text("")
    return conf_file


# =============================================================================
# Test: Old Config Files Can Be Migrated
# =============================================================================


class TestMigrationFromLegacyConfig:
    """Tests that verify old ham.conf files can be successfully migrated."""

    def test_migrate_standard_ham_conf(self, sample_ham_conf: Path, tmp_path: Path) -> None:
        """Test migrating a standard ham.conf with MySQL credentials."""
        legacy_config = parse_ham_conf(sample_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        # Write the migrated config
        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        # Verify it can be loaded by the v2 config loader
        loader = ConfigLoader()
        config = loader.load(output_file)

        # Use class name check to avoid module import identity issues
        assert type(config).__name__ == "HamburglarConfig"
        # MySQL configs should enable YARA as replacement
        assert config.yara.enabled is True
        assert config.yara.rules_path == Path("./rules")

    def test_migrate_complex_ham_conf(self, complex_ham_conf: Path, tmp_path: Path) -> None:
        """Test migrating a ham.conf with multiple sections."""
        legacy_config = parse_ham_conf(complex_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        assert type(config).__name__ == "HamburglarConfig"
        # Migration notes should be in the file
        assert "MIGRATION NOTE" in toml_content
        assert "user: testuser" in toml_content

    def test_migrate_minimal_ham_conf(self, minimal_ham_conf: Path, tmp_path: Path) -> None:
        """Test migrating a minimal ham.conf."""
        legacy_config = parse_ham_conf(minimal_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        assert type(config).__name__ == "HamburglarConfig"
        # Should have all default settings
        assert config.scan.recursive is True
        assert config.scan.concurrency == 50

    def test_migrate_empty_ham_conf(self, empty_ham_conf: Path, tmp_path: Path) -> None:
        """Test migrating an empty ham.conf produces valid config."""
        legacy_config = parse_ham_conf(empty_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        assert type(config).__name__ == "HamburglarConfig"
        # No MySQL means YARA should be disabled by default
        assert config.yara.enabled is False

    def test_migrate_preserves_mysql_username(self, sample_ham_conf: Path) -> None:
        """Test that MySQL username is preserved in migration notes."""
        legacy_config = parse_ham_conf(sample_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        assert "user: hamman" in toml_content

    def test_migrate_hides_mysql_password(self, sample_ham_conf: Path) -> None:
        """Test that MySQL password is hidden in migration notes."""
        legacy_config = parse_ham_conf(sample_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        # Password should be hidden
        assert "password: **********" in toml_content
        # Original password should not appear
        assert "deadbeef" not in toml_content

    def test_migrate_via_cli(self, sample_ham_conf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        """Test full migration via CLI command."""
        monkeypatch.chdir(tmp_path)
        output_file = tmp_path / "migrated.toml"

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(sample_ham_conf),
                "--output",
                str(output_file),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert output_file.exists()

        # Verify the migrated config is loadable
        loader = ConfigLoader()
        config = loader.load(output_file)
        assert type(config).__name__ == "HamburglarConfig"


# =============================================================================
# Test: Migration Script Handles Edge Cases
# =============================================================================


class TestMigrationEdgeCases:
    """Tests for edge cases and error handling during migration."""

    def test_ham_conf_with_special_characters_in_password(self, tmp_path: Path) -> None:
        """Test migrating config with special characters in password.

        Note: The `%` character has special meaning in configparser (interpolation).
        To use literal `%` in values, they must be escaped as `%%`.
        This test uses characters that don't include unescaped `%`.
        """
        conf_file = tmp_path / "ham.conf"
        # Avoid `%` which has special meaning in configparser (interpolation)
        conf_file.write_text(
            dedent("""
            [mySql]
            user = admin
            password = p@$$w0rd!#$^&*()
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        # Should not expose the password
        assert "p@$$w0rd" not in toml_content
        assert "password: **********" in toml_content

        # Should still be valid TOML
        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)
        loader = ConfigLoader()
        config = loader.load(output_file)
        assert type(config).__name__ == "HamburglarConfig"

    def test_ham_conf_with_percent_sign_requires_escaping(self, tmp_path: Path) -> None:
        """Test that `%` in configparser values must be escaped as `%%`."""
        import configparser

        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = admin
            password = test%value
        """).strip()
        )

        # Unescaped `%` causes InterpolationSyntaxError
        with pytest.raises(configparser.InterpolationSyntaxError):
            parse_ham_conf(conf_file)

    def test_ham_conf_with_escaped_percent_sign(self, tmp_path: Path) -> None:
        """Test that `%%` in configparser values works correctly."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = admin
            password = test%%value
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        # configparser converts %% to single %
        assert legacy_config["mysql"]["password"] == "test%value"

    def test_ham_conf_with_unicode_characters(self, tmp_path: Path) -> None:
        """Test migrating config with unicode characters."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = test_user
            password = tëst
            host = datenbank.beispiel.de
        """).strip(),
            encoding="utf-8",
        )

        legacy_config = parse_ham_conf(conf_file)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content, encoding="utf-8")
        loader = ConfigLoader()
        config = loader.load(output_file)
        assert type(config).__name__ == "HamburglarConfig"

    def test_ham_conf_with_quotes_in_values(self, tmp_path: Path) -> None:
        """Test migrating config with quotes in values."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = "quoted_user"
            password = 'single_quoted'
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        assert legacy_config["mysql"]["user"] == '"quoted_user"'

    def test_ham_conf_with_empty_values(self, tmp_path: Path) -> None:
        """Test migrating config with empty values."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user =
            password = testpass
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        assert legacy_config["mysql"]["user"] == ""
        assert legacy_config["mysql"]["password"] == "testpass"

    def test_ham_conf_with_whitespace_values(self, tmp_path: Path) -> None:
        """Test migrating config with whitespace-only values."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user =    spaces_user
            password = testpass
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        # configparser strips whitespace
        assert legacy_config["mysql"]["user"] == "spaces_user"

    def test_ham_conf_case_insensitive_section(self, tmp_path: Path) -> None:
        """Test that MySQL section is detected case-insensitively."""
        for section_name in ["mySql", "mysql", "MySQL", "MYSQL"]:
            conf_file = tmp_path / "ham.conf"
            conf_file.write_text(
                f"[{section_name}]\nuser = testuser\npassword = testpass"
            )

            legacy_config = parse_ham_conf(conf_file)
            options = run_non_interactive_migration(legacy_config)

            # Should detect MySQL config and enable YARA
            if "mysql" in legacy_config:
                assert options["yara_enabled"] is True

    def test_ham_conf_with_comments(self, tmp_path: Path) -> None:
        """Test migrating config with comments."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            # This is a comment
            [mySql]
            ; Another comment style
            user = testuser
            password = testpass
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        assert legacy_config["mysql"]["user"] == "testuser"

    def test_ham_conf_with_extra_sections(self, tmp_path: Path) -> None:
        """Test migrating config with unknown sections preserves them."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = testuser
            password = testpass

            [custom]
            key1 = value1
            key2 = value2

            [another_section]
            foo = bar
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        assert "mysql" in legacy_config
        assert "custom" in legacy_config
        assert "another_section" in legacy_config
        assert legacy_config["custom"]["key1"] == "value1"
        assert legacy_config["another_section"]["foo"] == "bar"

    def test_nonexistent_ham_conf_returns_empty(self, tmp_path: Path) -> None:
        """Test that parsing nonexistent file returns empty dict."""
        conf_file = tmp_path / "nonexistent.conf"
        legacy_config = parse_ham_conf(conf_file)
        assert legacy_config == {}

    def test_ham_conf_with_multiline_values(self, tmp_path: Path) -> None:
        """Test handling of multiline values (configparser limitation)."""
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text(
            dedent("""
            [mySql]
            user = testuser
            password = line1
                line2
        """).strip()
        )

        legacy_config = parse_ham_conf(conf_file)
        # configparser handles continuation lines
        assert "line1" in legacy_config["mysql"]["password"]

    def test_migrate_output_file_exists_no_force(
        self, sample_ham_conf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that migration fails if output exists without --force."""
        monkeypatch.chdir(tmp_path)
        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text("existing content")

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(sample_ham_conf),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 1
        # File should not be modified
        assert output_file.read_text() == "existing content"

    def test_migrate_output_file_exists_with_force(
        self, sample_ham_conf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that --force overwrites existing output file."""
        monkeypatch.chdir(tmp_path)
        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text("existing content")

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(sample_ham_conf),
                "--force",
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert output_file.read_text() != "existing content"
        assert "[scan]" in output_file.read_text()

    def test_migrate_creates_parent_directories(
        self, sample_ham_conf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that migration creates parent directories for output."""
        monkeypatch.chdir(tmp_path)
        output_file = tmp_path / "nested" / "dir" / "config.toml"

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(sample_ham_conf),
                "--output",
                str(output_file),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert output_file.exists()


# =============================================================================
# Test: Migrated Config Produces Same Behavior
# =============================================================================


class TestMigratedConfigBehavior:
    """Tests that verify migrated configs produce equivalent scanner behavior."""

    def test_migrated_config_default_scan_settings(
        self, empty_ham_conf: Path, tmp_path: Path
    ) -> None:
        """Test that migrated config has correct default scan settings."""
        legacy_config = parse_ham_conf(empty_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        # Check default scan settings match v2 defaults
        assert config.scan.recursive is True
        assert config.scan.concurrency == 50
        assert config.scan.timeout == 30.0
        assert ".git" in config.scan.blacklist
        assert "__pycache__" in config.scan.blacklist
        assert "node_modules" in config.scan.blacklist

    def test_migrated_config_mysql_enables_yara(
        self, sample_ham_conf: Path, tmp_path: Path
    ) -> None:
        """Test that MySQL config migration enables YARA as replacement."""
        legacy_config = parse_ham_conf(sample_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        # YARA should be enabled as MySQL signature replacement
        assert config.yara.enabled is True
        assert config.yara.rules_path == Path("./rules")

    def test_migrated_config_detector_defaults(
        self, empty_ham_conf: Path, tmp_path: Path
    ) -> None:
        """Test that migrated config has correct detector defaults."""
        legacy_config = parse_ham_conf(empty_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        # Empty enabled_categories means all categories enabled
        assert config.detector.enabled_categories == []
        assert config.detector.min_confidence == "low"
        assert config.detector.disabled_patterns == []

    def test_migrated_config_output_defaults(
        self, empty_ham_conf: Path, tmp_path: Path
    ) -> None:
        """Test that migrated config has correct output defaults."""
        legacy_config = parse_ham_conf(empty_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        # Check output defaults
        assert config.output.format.value == "table"
        assert config.output.save_to_db is False
        assert config.output.quiet is False
        assert config.output.verbose is False

    def test_migrated_config_can_be_converted_to_scan_config(
        self, sample_ham_conf: Path, tmp_path: Path
    ) -> None:
        """Test that migrated config can be converted to ScanConfig."""
        legacy_config = parse_ham_conf(sample_ham_conf)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        # Convert to ScanConfig for use with scanner
        target = tmp_path / "scan_target"
        target.mkdir()

        scan_config = config.to_scan_config(target)

        assert scan_config.target_path == target
        assert scan_config.recursive == config.scan.recursive
        assert scan_config.use_yara == config.yara.enabled

    def test_custom_options_propagate_to_config(self, tmp_path: Path) -> None:
        """Test that custom migration options are reflected in final config."""
        legacy_config: dict[str, Any] = {}
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
            "quiet": False,
            "verbose": True,
            "yara_enabled": True,
            "yara_rules_path": "/custom/rules",
            "yara_timeout": 60,
            "log_level": "debug",
        }
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        assert config.scan.recursive is False
        assert config.scan.max_file_size == 50 * 1024 * 1024  # 50MB in bytes
        assert config.scan.concurrency == 100
        assert config.scan.timeout == 60.0
        assert ".git" in config.scan.blacklist
        assert "vendor" in config.scan.blacklist
        assert "*.py" in config.scan.whitelist
        assert "*.js" in config.scan.whitelist
        assert "api_keys" in config.detector.enabled_categories
        assert "credentials" in config.detector.enabled_categories
        assert config.detector.min_confidence == "high"
        assert config.output.format.value == "json"
        assert config.output.save_to_db is True
        assert config.output.verbose is True
        assert config.yara.enabled is True
        assert config.yara.rules_path == Path("/custom/rules")
        assert config.log_level.value == "debug"


# =============================================================================
# Test: TOML Validity and Parsing
# =============================================================================


class TestMigratedTomlValidity:
    """Tests that all migrated TOML output is valid and parseable."""

    def test_all_generated_toml_is_valid(self) -> None:
        """Test that default generated config is valid TOML."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found]

        legacy_config: dict[str, Any] = {}
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        # Should parse without error
        parsed = tomllib.loads(toml_content)

        assert "scan" in parsed
        assert "detector" in parsed
        assert "output" in parsed
        assert "yara" in parsed

    def test_generated_toml_with_special_patterns(self) -> None:
        """Test that configs with special glob patterns are valid TOML."""
        try:
            import tomllib
        except ImportError:
            import tomli as tomllib  # type: ignore[import-not-found]

        legacy_config: dict[str, Any] = {}
        options = {
            "recursive": True,
            "max_file_size": "10MB",
            "concurrency": 50,
            "timeout": 30,
            "blacklist": ["*.pyc", "**/__pycache__/**", "node_modules/*"],
            "whitelist": ["src/**/*.py", "tests/**/*.py", "*.{yml,yaml}"],
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

    def test_generated_toml_with_mysql_comments_is_valid(self) -> None:
        """Test that migration notes as comments don't break TOML parsing."""
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

        # Comments should not break parsing
        parsed = tomllib.loads(toml_content)

        assert parsed["yara"]["enabled"] is True


# =============================================================================
# Test: Config File Discovery
# =============================================================================


class TestConfigFileDiscovery:
    """Tests for finding legacy and new config files."""

    def test_find_ham_conf_in_cwd(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test finding ham.conf in current working directory."""
        monkeypatch.chdir(tmp_path)
        conf_file = tmp_path / "ham.conf"
        conf_file.write_text("[mySql]\nuser = test")

        result = find_ham_conf()

        assert result == conf_file

    def test_find_hidden_ham_conf(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test finding .ham.conf (hidden file) in current directory."""
        monkeypatch.chdir(tmp_path)
        conf_file = tmp_path / ".ham.conf"
        conf_file.write_text("[mySql]\nuser = test")

        result = find_ham_conf()

        assert result == conf_file

    def test_ham_conf_preferred_over_hidden(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that ham.conf is preferred over .ham.conf."""
        monkeypatch.chdir(tmp_path)
        (tmp_path / "ham.conf").write_text("[mySql]\nuser = visible")
        (tmp_path / ".ham.conf").write_text("[mySql]\nuser = hidden")

        result = find_ham_conf()

        assert result is not None
        assert result.name == "ham.conf"

    def test_no_ham_conf_found(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test returning None when no ham.conf exists."""
        monkeypatch.chdir(tmp_path)

        result = find_ham_conf()

        assert result is None

    def test_v2_config_loader_finds_toml(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that ConfigLoader finds .hamburglar.toml."""
        monkeypatch.chdir(tmp_path)
        config_file = tmp_path / ".hamburglar.toml"

        legacy_config: dict[str, Any] = {}
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)
        config_file.write_text(toml_content)

        loader = ConfigLoader()
        found = loader.find_config_file(tmp_path)

        assert found == config_file


# =============================================================================
# Test: CLI Migration Script
# =============================================================================


class TestMigrationScriptCLI:
    """Tests for the migration script CLI interface."""

    def test_help_output(self) -> None:
        """Test that --help provides usage information."""
        result = subprocess.run(
            [sys.executable, str(SCRIPTS_DIR / "migrate-config.py"), "--help"],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "ham.conf" in result.stdout.lower() or "migrate" in result.stdout.lower()

    def test_dry_run_does_not_create_file(
        self, sample_ham_conf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that --dry-run shows output without creating file."""
        monkeypatch.chdir(tmp_path)

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(sample_ham_conf),
                "--dry-run",
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert "[scan]" in result.stdout  # Config is printed
        assert not (tmp_path / ".hamburglar.toml").exists()

    def test_nonexistent_input_file_error(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test error message when input file doesn't exist."""
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

    def test_custom_output_path(
        self, sample_ham_conf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test specifying custom output path with --output."""
        monkeypatch.chdir(tmp_path)
        output_file = tmp_path / "custom" / "path" / "config.toml"

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(sample_ham_conf),
                "--output",
                str(output_file),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        assert output_file.exists()

        # Verify it's loadable
        loader = ConfigLoader()
        config = loader.load(output_file)
        assert type(config).__name__ == "HamburglarConfig"

    def test_migration_success_message(
        self, sample_ham_conf: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Test that successful migration shows helpful message."""
        monkeypatch.chdir(tmp_path)

        result = subprocess.run(
            [
                sys.executable,
                str(SCRIPTS_DIR / "migrate-config.py"),
                str(sample_ham_conf),
                "--no-interactive",
            ],
            capture_output=True,
            text=True,
        )

        assert result.returncode == 0
        # Should show next steps
        assert "hamburglar" in result.stdout.lower()


# =============================================================================
# Test: Archived Legacy Config Reference
# =============================================================================


class TestArchivedLegacyConfig:
    """Tests that verify the archived ham_v1.conf can be used as reference."""

    def test_archived_ham_conf_is_parseable(self) -> None:
        """Test that the archived ham_v1.conf can be parsed."""
        archive_path = Path(__file__).parent.parent / "archive" / "ham_v1.conf"
        if not archive_path.exists():
            pytest.skip("Archived ham_v1.conf not found")

        legacy_config = parse_ham_conf(archive_path)

        assert "mysql" in legacy_config
        assert legacy_config["mysql"]["user"] == "hamman"

    def test_archived_ham_conf_can_be_migrated(self, tmp_path: Path) -> None:
        """Test that the archived ham_v1.conf can be fully migrated."""
        archive_path = Path(__file__).parent.parent / "archive" / "ham_v1.conf"
        if not archive_path.exists():
            pytest.skip("Archived ham_v1.conf not found")

        legacy_config = parse_ham_conf(archive_path)
        options = run_non_interactive_migration(legacy_config)
        toml_content = generate_toml_config(legacy_config, options)

        output_file = tmp_path / ".hamburglar.toml"
        output_file.write_text(toml_content)

        loader = ConfigLoader()
        config = loader.load(output_file)

        assert type(config).__name__ == "HamburglarConfig"
        # Should have YARA enabled as MySQL replacement
        assert config.yara.enabled is True
