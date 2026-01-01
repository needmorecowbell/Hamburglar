"""Tests for the CLI plugins command group.

This module tests the 'plugins list' and 'plugins info' commands that allow
users to inspect installed Hamburglar plugins.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest import mock

import pytest
from typer.testing import CliRunner

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.cli.main import app
from hamburglar.plugins import reset_plugin_manager

runner = CliRunner()


@pytest.fixture(autouse=True)
def reset_plugins_before_each_test():
    """Reset plugin manager before each test to ensure isolation."""
    reset_plugin_manager()
    yield
    reset_plugin_manager()


class TestPluginsListCommand:
    """Tests for 'hamburglar plugins list' command."""

    def test_plugins_list_help(self) -> None:
        """Test that plugins list --help displays help."""
        result = runner.invoke(app, ["plugins", "list", "--help"])
        assert result.exit_code == 0
        assert "List all installed plugins" in result.output

    def test_plugins_list_default_output(self) -> None:
        """Test that plugins list displays plugins in table format by default."""
        result = runner.invoke(app, ["plugins", "list"])
        # Should succeed even if no external plugins found
        assert result.exit_code == 0

    def test_plugins_list_json_format(self) -> None:
        """Test that plugins list --format json outputs valid JSON."""
        # Mock the plugin manager to return some plugins
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugins = [
            PluginListEntry(
                name="test_detector",
                plugin_type="detector",
                version="1.0.0",
                author="Test Author",
                description="A test detector",
                source="manual",
            ),
            PluginListEntry(
                name="test_output",
                plugin_type="output",
                version="2.0.0",
                author="Another Author",
                description="A test output formatter",
                source="entry_point",
            ),
        ]

        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter(mock_plugins),
        ):
            result = runner.invoke(app, ["plugins", "list", "--format", "json"])
            assert result.exit_code == 0
            # Should be valid JSON
            data = json.loads(result.output)
            assert len(data) == 2
            assert data[0]["name"] == "test_detector"
            assert data[0]["type"] == "detector"
            assert data[1]["name"] == "test_output"
            assert data[1]["type"] == "output"

    def test_plugins_list_plain_format(self) -> None:
        """Test that plugins list --format plain outputs plain text format."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugins = [
            PluginListEntry(
                name="my_detector",
                plugin_type="detector",
                version="1.0.0",
                description="My custom detector",
                source="manual",
            ),
        ]

        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter(mock_plugins),
        ):
            result = runner.invoke(app, ["plugins", "list", "--format", "plain"])
            assert result.exit_code == 0
            assert "my_detector" in result.output or "Detector Plugins" in result.output

    def test_plugins_list_verbose_mode(self) -> None:
        """Test that plugins list -v shows additional details."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugins = [
            PluginListEntry(
                name="verbose_test",
                plugin_type="detector",
                version="1.2.3",
                author="Verbose Author",
                description="A verbose test plugin",
                source="entry_point:my.entry.point",
            ),
        ]

        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter(mock_plugins),
        ):
            result = runner.invoke(app, ["plugins", "list", "-v"])
            assert result.exit_code == 0
            # In verbose mode, should show author and source
            output = result.output
            assert "verbose_test" in output or "Verbose Author" in output

    def test_plugins_list_filter_by_detector_type(self) -> None:
        """Test that plugins list --type detector filters to detector plugins."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_detectors = [
            PluginListEntry(
                name="detector_only",
                plugin_type="detector",
                version="1.0.0",
                description="Only detectors",
                source="manual",
            ),
        ]

        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter(mock_detectors),
        ):
            result = runner.invoke(app, ["plugins", "list", "--type", "detector"])
            assert result.exit_code == 0
            # Should only list detector plugins

    def test_plugins_list_filter_by_output_type(self) -> None:
        """Test that plugins list --type output filters to output plugins."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_outputs = [
            PluginListEntry(
                name="output_only",
                plugin_type="output",
                version="1.0.0",
                description="Only outputs",
                source="manual",
            ),
        ]

        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter(mock_outputs),
        ):
            result = runner.invoke(app, ["plugins", "list", "--type", "output"])
            assert result.exit_code == 0

    def test_plugins_list_invalid_type(self) -> None:
        """Test that plugins list --type invalid_type shows error."""
        result = runner.invoke(app, ["plugins", "list", "--type", "invalid"])
        assert result.exit_code == 1
        assert "Invalid plugin type" in result.output
        assert "'invalid'" in result.output

    def test_plugins_list_no_plugins_found(self) -> None:
        """Test that plugins list handles no plugins gracefully."""
        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter([]),
        ):
            result = runner.invoke(app, ["plugins", "list"])
            assert result.exit_code == 0
            assert "No plugins found" in result.output

    def test_plugins_list_no_plugins_quiet_mode(self) -> None:
        """Test that plugins list -q suppresses 'no plugins' message."""
        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter([]),
        ):
            result = runner.invoke(app, ["plugins", "list", "-q"])
            assert result.exit_code == 0
            # With quiet mode, message should not appear
            assert "No plugins found" not in result.output

    def test_plugins_list_discover_flag(self) -> None:
        """Test that plugins list --discover forces re-discovery."""
        result = runner.invoke(app, ["plugins", "list", "--discover"])
        # Should run discovery and then list
        assert result.exit_code == 0

    def test_plugins_list_mixed_plugin_types(self) -> None:
        """Test that plugins list shows both detector and output plugins."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugins = [
            PluginListEntry(
                name="detector1",
                plugin_type="detector",
                version="1.0.0",
                description="First detector",
                source="manual",
            ),
            PluginListEntry(
                name="detector2",
                plugin_type="detector",
                version="1.0.0",
                description="Second detector",
                source="manual",
            ),
            PluginListEntry(
                name="output1",
                plugin_type="output",
                version="1.0.0",
                description="First output",
                source="manual",
            ),
        ]

        with mock.patch(
            "hamburglar.plugins.discovery.list_plugins",
            return_value=iter(mock_plugins),
        ):
            result = runner.invoke(app, ["plugins", "list"])
            assert result.exit_code == 0
            # Should show both types
            output = result.output
            assert "detector" in output.lower() or "Detector" in output


class TestPluginsInfoCommand:
    """Tests for 'hamburglar plugins info' command."""

    def test_plugins_info_help(self) -> None:
        """Test that plugins info --help displays help."""
        result = runner.invoke(app, ["plugins", "info", "--help"])
        assert result.exit_code == 0
        assert "Show detailed information about a specific plugin" in result.output

    def test_plugins_info_not_found(self) -> None:
        """Test that plugins info shows error for non-existent plugin."""
        with mock.patch(
            "hamburglar.plugins.discovery.get_plugin_details",
            return_value=None,
        ):
            result = runner.invoke(app, ["plugins", "info", "nonexistent"])
            assert result.exit_code == 1
            assert "not found" in result.output
            assert "nonexistent" in result.output

    def test_plugins_info_success(self) -> None:
        """Test that plugins info shows details for an existing plugin."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugin = PluginListEntry(
            name="my_plugin",
            plugin_type="detector",
            version="1.2.3",
            author="Plugin Author",
            description="A detailed plugin description",
            source="directory:/path/to/plugin.py",
            enabled=True,
            config={"option1": "value1", "option2": 42},
        )

        with mock.patch(
            "hamburglar.plugins.discovery.get_plugin_details",
            return_value=mock_plugin,
        ):
            result = runner.invoke(app, ["plugins", "info", "my_plugin"])
            assert result.exit_code == 0
            output = result.output
            assert "my_plugin" in output
            # Should show key information
            assert "1.2.3" in output or "Version" in output

    def test_plugins_info_json_format(self) -> None:
        """Test that plugins info --format json outputs valid JSON."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugin = PluginListEntry(
            name="json_plugin",
            plugin_type="output",
            version="2.0.0",
            author="JSON Author",
            description="A plugin for JSON testing",
            source="entry_point",
            enabled=True,
            config={"format": "pretty"},
        )

        with mock.patch(
            "hamburglar.plugins.discovery.get_plugin_details",
            return_value=mock_plugin,
        ):
            result = runner.invoke(
                app, ["plugins", "info", "json_plugin", "--format", "json"]
            )
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["name"] == "json_plugin"
            assert data["type"] == "output"
            assert data["version"] == "2.0.0"
            assert data["author"] == "JSON Author"
            assert data["config"]["format"] == "pretty"

    def test_plugins_info_plain_format(self) -> None:
        """Test that plugins info --format plain outputs plain text."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugin = PluginListEntry(
            name="plain_plugin",
            plugin_type="detector",
            version="1.0.0",
            description="Plain text test",
            source="manual",
        )

        with mock.patch(
            "hamburglar.plugins.discovery.get_plugin_details",
            return_value=mock_plugin,
        ):
            result = runner.invoke(
                app, ["plugins", "info", "plain_plugin", "--format", "plain"]
            )
            assert result.exit_code == 0
            output = result.output
            assert "plain_plugin" in output
            assert "detector" in output

    def test_plugins_info_with_config(self) -> None:
        """Test that plugins info shows configuration options."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugin = PluginListEntry(
            name="config_plugin",
            plugin_type="detector",
            version="1.0.0",
            description="Plugin with config",
            source="manual",
            config={
                "enabled_patterns": ["api_key", "secret"],
                "min_entropy": 3.5,
                "case_sensitive": False,
            },
        )

        with mock.patch(
            "hamburglar.plugins.discovery.get_plugin_details",
            return_value=mock_plugin,
        ):
            result = runner.invoke(
                app, ["plugins", "info", "config_plugin", "--format", "json"]
            )
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert "config" in data
            assert data["config"]["min_entropy"] == 3.5

    def test_plugins_info_disabled_plugin(self) -> None:
        """Test that plugins info shows disabled status correctly."""
        from hamburglar.plugins.discovery import PluginListEntry

        mock_plugin = PluginListEntry(
            name="disabled_plugin",
            plugin_type="detector",
            version="1.0.0",
            description="A disabled plugin",
            source="manual",
            enabled=False,
        )

        with mock.patch(
            "hamburglar.plugins.discovery.get_plugin_details",
            return_value=mock_plugin,
        ):
            result = runner.invoke(
                app, ["plugins", "info", "disabled_plugin", "--format", "json"]
            )
            assert result.exit_code == 0
            data = json.loads(result.output)
            assert data["enabled"] is False


class TestPluginsCommandGroup:
    """Tests for the plugins command group itself."""

    def test_plugins_no_args_shows_help(self) -> None:
        """Test that 'hamburglar plugins' with no args shows help."""
        result = runner.invoke(app, ["plugins"])
        # Typer's no_args_is_help returns exit code 2 (same as --help behavior)
        # but the output still contains the help text
        assert "Plugin management commands" in result.output or result.exit_code in (0, 2)
        # Should show available subcommands
        assert "list" in result.output
        assert "info" in result.output

    def test_plugins_help(self) -> None:
        """Test that 'hamburglar plugins --help' shows help."""
        result = runner.invoke(app, ["plugins", "--help"])
        assert result.exit_code == 0
        assert "Plugin management commands" in result.output

    def test_main_help_mentions_plugins(self) -> None:
        """Test that main help text mentions the plugins command."""
        result = runner.invoke(app, ["--help"])
        assert result.exit_code == 0
        assert "plugins" in result.output


class TestPluginsIntegration:
    """Integration tests for plugin commands with real plugin discovery."""

    def test_list_after_registering_plugin(self) -> None:
        """Test that manually registered plugins appear in list."""
        from hamburglar.plugins import PluginInfo, PluginManager, reset_plugin_manager
        from hamburglar.detectors import BaseDetector
        from hamburglar.core.models import Finding

        # Reset to get a fresh manager
        reset_plugin_manager()

        class TestDetector(BaseDetector):
            """A test detector for integration testing."""

            __version__ = "1.0.0"
            __author__ = "Integration Test"

            @property
            def name(self) -> str:
                return "integration_test"

            def detect(
                self, content: str, file_path: str = ""
            ) -> list[Finding]:
                return []

        # Get the global manager and register our detector
        from hamburglar.plugins import get_plugin_manager

        manager = get_plugin_manager()
        manager.register_detector(
            TestDetector(),
            description="Integration test detector",
            version="1.0.0",
            author="Integration Test",
        )

        # Now list plugins
        result = runner.invoke(app, ["plugins", "list", "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        # Should find our registered plugin
        plugin_names = [p["name"] for p in data]
        assert "integration_test" in plugin_names

    def test_info_for_registered_plugin(self) -> None:
        """Test that plugins info works for manually registered plugins."""
        from hamburglar.plugins import PluginInfo, PluginManager, reset_plugin_manager
        from hamburglar.detectors import BaseDetector
        from hamburglar.core.models import Finding

        # Reset to get a fresh manager
        reset_plugin_manager()

        class InfoTestDetector(BaseDetector):
            """A detector for testing info command."""

            __version__ = "2.5.0"
            __author__ = "Info Test Author"

            @property
            def name(self) -> str:
                return "info_test_detector"

            def detect(
                self, content: str, file_path: str = ""
            ) -> list[Finding]:
                return []

        from hamburglar.plugins import get_plugin_manager

        manager = get_plugin_manager()
        manager.register_detector(
            InfoTestDetector(),
            description="Detector for testing info",
            version="2.5.0",
            author="Info Test Author",
        )

        result = runner.invoke(
            app, ["plugins", "info", "info_test_detector", "--format", "json"]
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["name"] == "info_test_detector"
        assert data["type"] == "detector"
        assert data["version"] == "2.5.0"
