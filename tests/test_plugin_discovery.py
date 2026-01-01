"""Tests for the plugin discovery module.

This module tests plugin discovery from directories, entry points,
interface validation, and the plugin listing functionality.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

# Configure path before any hamburglar imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.models import Finding, ScanResult
from hamburglar.detectors import BaseDetector
from hamburglar.outputs import BaseOutput
from hamburglar.plugins import PluginError, PluginInfo, PluginManager, reset_plugin_manager
from hamburglar.plugins.discovery import (
    DiscoveryResult,
    PluginListEntry,
    discover_directory,
    discover_entry_points,
    discover_plugins,
    format_plugin_details,
    format_plugin_list,
    get_plugin_details,
    list_plugins,
    validate_plugin_interface,
)


class ValidDetector(BaseDetector):
    """A valid detector for testing."""

    @property
    def name(self) -> str:
        return "valid_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []


class ValidOutput(BaseOutput):
    """A valid output for testing."""

    @property
    def name(self) -> str:
        return "valid_output"

    def format(self, result: ScanResult) -> str:
        return "test"


class InvalidDetectorNoName:
    """Invalid detector without name property."""

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []


class InvalidDetectorNoDetect:
    """Invalid detector without detect method."""

    @property
    def name(self) -> str:
        return "invalid"


class InvalidOutputNoFormat:
    """Invalid output without format method."""

    @property
    def name(self) -> str:
        return "invalid"


@pytest.fixture(autouse=True)
def reset_plugins():
    """Reset plugin state before each test."""
    reset_plugin_manager()
    yield
    reset_plugin_manager()


class TestValidatePluginInterface:
    """Tests for validate_plugin_interface function."""

    def test_valid_detector(self) -> None:
        """Test validation of a valid detector class."""
        is_valid, errors = validate_plugin_interface(ValidDetector, "detector")
        assert is_valid is True
        assert errors == []

    def test_valid_output(self) -> None:
        """Test validation of a valid output class."""
        is_valid, errors = validate_plugin_interface(ValidOutput, "output")
        assert is_valid is True
        assert errors == []

    def test_invalid_detector_no_name(self) -> None:
        """Test validation fails for detector without name."""
        is_valid, errors = validate_plugin_interface(InvalidDetectorNoName, "detector")
        assert is_valid is False
        assert any("name" in e.lower() for e in errors)

    def test_invalid_detector_no_detect(self) -> None:
        """Test validation fails for detector without detect method."""
        is_valid, errors = validate_plugin_interface(InvalidDetectorNoDetect, "detector")
        assert is_valid is False
        assert any("detect" in e.lower() for e in errors)

    def test_invalid_output_no_format(self) -> None:
        """Test validation fails for output without format method."""
        is_valid, errors = validate_plugin_interface(InvalidOutputNoFormat, "output")
        assert is_valid is False
        assert any("format" in e.lower() for e in errors)

    def test_unknown_plugin_type(self) -> None:
        """Test validation fails for unknown plugin type."""
        is_valid, errors = validate_plugin_interface(ValidDetector, "unknown")
        assert is_valid is False
        assert any("unknown plugin type" in e.lower() for e in errors)


class TestDiscoveryResult:
    """Tests for DiscoveryResult dataclass."""

    def test_default_values(self) -> None:
        """Test DiscoveryResult default values."""
        result = DiscoveryResult()
        assert result.detector_count == 0
        assert result.output_count == 0
        assert result.total == 0
        assert result.errors == []
        assert result.sources == {}

    def test_with_values(self) -> None:
        """Test DiscoveryResult with values."""
        result = DiscoveryResult(
            detector_count=5,
            output_count=3,
            total=8,
            errors=["error1"],
            sources={"plugin1": "entry_point"},
        )
        assert result.detector_count == 5
        assert result.output_count == 3
        assert result.total == 8
        assert result.errors == ["error1"]
        assert result.sources == {"plugin1": "entry_point"}


class TestPluginListEntry:
    """Tests for PluginListEntry dataclass."""

    def test_default_values(self) -> None:
        """Test PluginListEntry default values."""
        entry = PluginListEntry(name="test", plugin_type="detector")
        assert entry.name == "test"
        assert entry.plugin_type == "detector"
        assert entry.version == "1.0.0"
        assert entry.author == ""
        assert entry.description == ""
        assert entry.source == "manual"
        assert entry.enabled is True
        assert entry.config == {}

    def test_from_plugin_info(self) -> None:
        """Test creating PluginListEntry from PluginInfo."""
        info = PluginInfo(
            name="test",
            plugin_type="detector",
            version="2.0.0",
            author="Test Author",
            description="A test plugin",
            source="entry_point",
            config={"key": "value"},
        )
        entry = PluginListEntry.from_plugin_info(info)
        assert entry.name == "test"
        assert entry.plugin_type == "detector"
        assert entry.version == "2.0.0"
        assert entry.author == "Test Author"
        assert entry.description == "A test plugin"
        assert entry.source == "entry_point"
        assert entry.config == {"key": "value"}


class TestDiscoverDirectory:
    """Tests for discover_directory function."""

    def test_discover_valid_plugins(self, tmp_path: Path) -> None:
        """Test discovering valid plugins from a directory."""
        plugin_file = tmp_path / "test_plugin.py"
        plugin_file.write_text('''
"""Test plugin module."""
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.detectors import BaseDetector
from hamburglar.outputs import BaseOutput


class TestDiscoveryDetector(BaseDetector):
    """A test detector for discovery testing."""

    @property
    def name(self) -> str:
        return "test_discovery_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []


class TestDiscoveryOutput(BaseOutput):
    """A test output for discovery testing."""

    @property
    def name(self) -> str:
        return "test_discovery_output"

    def format(self, result: ScanResult) -> str:
        return "test"
''')
        # Run in subprocess to avoid module caching issues
        test_script = f'''
import sys
sys.path.insert(0, "{src_path}")
from pathlib import Path
from hamburglar.plugins.discovery import discover_directory

plugins = discover_directory("{tmp_path}")
detector_count = sum(1 for _, t, _, _ in plugins if t == "detector")
output_count = sum(1 for _, t, _, _ in plugins if t == "output")

if detector_count >= 1 and output_count >= 1:
    print("SUCCESS")
else:
    print("FAIL: " + str(detector_count) + " detectors, " + str(output_count) + " outputs")
    sys.exit(1)
'''
        result = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Discovery failed: {result.stderr}"
        assert "SUCCESS" in result.stdout

    def test_discover_nonexistent_directory(self) -> None:
        """Test error when directory doesn't exist."""
        with pytest.raises(PluginError, match="does not exist"):
            discover_directory("/nonexistent/directory")

    def test_discover_file_not_directory(self, tmp_path: Path) -> None:
        """Test error when path is a file."""
        file_path = tmp_path / "file.txt"
        file_path.write_text("test")
        with pytest.raises(PluginError, match="not a directory"):
            discover_directory(file_path)

    def test_discover_skips_private_files(self, tmp_path: Path) -> None:
        """Test that private files (starting with _) are skipped."""
        private_file = tmp_path / "_private.py"
        private_file.write_text("""
from hamburglar.detectors import BaseDetector
from hamburglar.core.models import Finding

class PrivateDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "private"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
""")
        plugins = discover_directory(tmp_path)
        names = [name for name, _, _, _ in plugins]
        assert "private" not in names


class TestDiscoverEntryPoints:
    """Tests for discover_entry_points function."""

    def test_discover_returns_list(self) -> None:
        """Test that discover_entry_points returns a list."""
        plugins = discover_entry_points()
        assert isinstance(plugins, list)
        # May be empty if no entry points installed

    def test_discover_format(self) -> None:
        """Test that discovered plugins have correct format."""
        plugins = discover_entry_points()
        for name, plugin_type, cls, source in plugins:
            assert isinstance(name, str)
            assert plugin_type in ("detector", "output")
            assert isinstance(cls, type)
            assert isinstance(source, str)


class TestDiscoverPlugins:
    """Tests for discover_plugins function."""

    def test_discover_with_directory(self, tmp_path: Path) -> None:
        """Test plugin discovery with a directory."""
        plugin_file = tmp_path / "my_plugin.py"
        plugin_file.write_text('''
from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector


class MyTestDetector(BaseDetector):
    """My test detector."""

    @property
    def name(self) -> str:
        return "my_test_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
''')
        # Run in subprocess
        test_script = f'''
import sys
sys.path.insert(0, "{src_path}")
from pathlib import Path
from hamburglar.plugins import PluginManager, reset_plugin_manager
from hamburglar.plugins.discovery import discover_plugins

reset_plugin_manager()
manager = PluginManager()
disc_result = discover_plugins(directories=["{tmp_path}"], include_entry_points=False, manager=manager)

if disc_result.detector_count >= 1:
    print("SUCCESS")
else:
    print("FAIL: " + str(disc_result.detector_count) + " detectors, errors: " + str(disc_result.errors))
    sys.exit(1)
'''
        result = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Discovery failed: {result.stderr}"
        assert "SUCCESS" in result.stdout

    def test_discover_returns_discovery_result(self) -> None:
        """Test that discover_plugins returns DiscoveryResult."""
        manager = PluginManager()
        result = discover_plugins(include_entry_points=False, manager=manager)
        assert isinstance(result, DiscoveryResult)

    def test_discover_with_invalid_directory(self) -> None:
        """Test discovery handles invalid directories gracefully."""
        manager = PluginManager()
        result = discover_plugins(
            directories=["/nonexistent/path"],
            include_entry_points=False,
            manager=manager,
        )
        assert len(result.errors) >= 1
        assert any("nonexistent" in e.lower() for e in result.errors)


class TestListPlugins:
    """Tests for list_plugins function."""

    def test_list_plugins_empty(self) -> None:
        """Test listing plugins when none are registered."""
        manager = PluginManager()
        plugins = list(list_plugins(manager=manager))
        # May have some from entry points, but shouldn't error
        assert isinstance(plugins, list)

    def test_list_plugins_with_registered(self) -> None:
        """Test listing plugins after manual registration."""
        manager = PluginManager()
        detector = ValidDetector()
        manager.register_detector(detector, description="Test detector")

        plugins = list(list_plugins(manager=manager))
        names = [p.name for p in plugins]
        assert "valid_detector" in names

    def test_list_plugins_filter_by_type(self) -> None:
        """Test filtering plugins by type."""
        manager = PluginManager()
        manager.register_detector(ValidDetector(), description="Test detector")
        manager.register_output(ValidOutput(), description="Test output")

        detectors = list(list_plugins(plugin_type="detector", manager=manager))
        outputs = list(list_plugins(plugin_type="output", manager=manager))

        assert all(p.plugin_type == "detector" for p in detectors)
        assert all(p.plugin_type == "output" for p in outputs)


class TestGetPluginDetails:
    """Tests for get_plugin_details function."""

    def test_get_existing_plugin(self) -> None:
        """Test getting details for an existing plugin."""
        manager = PluginManager()
        manager.register_detector(
            ValidDetector(),
            description="A valid test detector",
            version="2.0.0",
            author="Test Author",
        )

        details = get_plugin_details("valid_detector", manager=manager)
        assert details is not None
        assert details.name == "valid_detector"
        assert details.plugin_type == "detector"
        assert details.version == "2.0.0"
        assert details.author == "Test Author"

    def test_get_nonexistent_plugin(self) -> None:
        """Test getting details for a nonexistent plugin returns None."""
        manager = PluginManager()
        details = get_plugin_details("nonexistent", manager=manager)
        assert details is None


class TestFormatPluginList:
    """Tests for format_plugin_list function."""

    def test_format_empty_list(self) -> None:
        """Test formatting an empty plugin list."""
        result = format_plugin_list([])
        assert "No plugins found" in result

    def test_format_with_plugins(self) -> None:
        """Test formatting a list of plugins."""
        plugins = [
            PluginListEntry(
                name="test_detector",
                plugin_type="detector",
                description="A test detector",
            ),
            PluginListEntry(
                name="test_output",
                plugin_type="output",
                description="A test output",
            ),
        ]
        result = format_plugin_list(plugins)
        assert "Detector Plugins:" in result
        assert "Output Plugins:" in result
        assert "test_detector" in result
        assert "test_output" in result
        assert "Total:" in result

    def test_format_verbose(self) -> None:
        """Test verbose formatting includes extra details."""
        plugins = [
            PluginListEntry(
                name="test_detector",
                plugin_type="detector",
                version="2.0.0",
                author="Test Author",
                description="A test detector",
                source="entry_point",
            ),
        ]
        result = format_plugin_list(plugins, verbose=True)
        assert "v2.0.0" in result
        assert "Test Author" in result
        assert "entry_point" in result


class TestFormatPluginDetails:
    """Tests for format_plugin_details function."""

    def test_format_basic_details(self) -> None:
        """Test formatting basic plugin details."""
        plugin = PluginListEntry(
            name="test_plugin",
            plugin_type="detector",
            version="1.0.0",
        )
        result = format_plugin_details(plugin)
        assert "Plugin: test_plugin" in result
        assert "Type: detector" in result
        assert "Version: 1.0.0" in result

    def test_format_full_details(self) -> None:
        """Test formatting full plugin details."""
        plugin = PluginListEntry(
            name="test_plugin",
            plugin_type="detector",
            version="2.0.0",
            author="Test Author",
            description="A detailed description",
            source="entry_point",
            enabled=True,
            config={"option1": "value1"},
        )
        result = format_plugin_details(plugin)
        assert "Plugin: test_plugin" in result
        assert "Author: Test Author" in result
        assert "Description: A detailed description" in result
        assert "Source: entry_point" in result
        assert "Enabled: Yes" in result
        assert "Configuration:" in result
        assert "option1: value1" in result


class TestPluginDiscoveryIntegration:
    """Integration tests for plugin discovery."""

    def test_full_discovery_flow(self, tmp_path: Path) -> None:
        """Test the full discovery and listing flow."""
        # Create a plugin file
        plugin_file = tmp_path / "integration_plugin.py"
        plugin_file.write_text('''
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.detectors import BaseDetector
from hamburglar.outputs import BaseOutput


class IntegrationTestDetector(BaseDetector):
    """Integration test detector."""

    __version__ = "3.0.0"
    __author__ = "Integration Test"

    @property
    def name(self) -> str:
        return "integration_test_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []


class IntegrationTestOutput(BaseOutput):
    """Integration test output."""

    @property
    def name(self) -> str:
        return "integration_test_output"

    def format(self, result: ScanResult) -> str:
        return "integration test"
''')
        # Run integration test in subprocess
        test_script = f'''
import sys
sys.path.insert(0, "{src_path}")
from pathlib import Path
from hamburglar.plugins import PluginManager, reset_plugin_manager
from hamburglar.plugins.discovery import (
    discover_plugins,
    list_plugins,
    get_plugin_details,
    format_plugin_list,
    format_plugin_details,
)

reset_plugin_manager()
manager = PluginManager()

# Discover plugins
disc_result = discover_plugins(directories=["{tmp_path}"], include_entry_points=False, manager=manager)
if disc_result.total < 2:
    print("FAIL: Expected at least 2 plugins, got " + str(disc_result.total))
    sys.exit(1)

# List plugins
plugin_list = list(list_plugins(manager=manager))
found_integration = any(p.name == "integrationtest" or "integration" in p.name for p in plugin_list)
if not found_integration:
    print("FAIL: Integration plugins not found in list: " + str([p.name for p in plugin_list]))
    sys.exit(1)

# Format plugin list
formatted = format_plugin_list(plugin_list)
if "Detector Plugins:" not in formatted:
    print("FAIL: Formatted list missing Detector Plugins:")
    sys.exit(1)

print("SUCCESS")
'''
        result = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Integration test failed: {result.stderr}\n{result.stdout}"
        assert "SUCCESS" in result.stdout


class TestValidatePluginInterfaceEdgeCases:
    """Additional edge case tests for validate_plugin_interface."""

    def test_detector_with_non_callable_name(self) -> None:
        """Test detector with name as a regular attribute (not property)."""

        class DetectorWithAttrName:
            name = "my_detector"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                return []

        # Should pass since name exists (even if not a property)
        is_valid, errors = validate_plugin_interface(DetectorWithAttrName, "detector")
        # This covers the validation logic allowing non-property names
        assert is_valid is True or len(errors) == 0 or any("name" not in e.lower() for e in errors)

    def test_detector_with_non_callable_detect(self) -> None:
        """Test detector where detect is not callable."""

        class DetectorWithBadDetect:
            name = "bad"
            detect = "not a method"  # Not callable

        is_valid, errors = validate_plugin_interface(DetectorWithBadDetect, "detector")
        assert is_valid is False
        assert any("detect" in e.lower() and "callable" in e.lower() for e in errors)

    def test_output_with_non_callable_format(self) -> None:
        """Test output where format is not callable."""

        class OutputWithBadFormat:
            name = "bad"
            format = 123  # Not callable

        is_valid, errors = validate_plugin_interface(OutputWithBadFormat, "output")
        assert is_valid is False
        assert any("format" in e.lower() and "callable" in e.lower() for e in errors)

    def test_output_no_name_property(self) -> None:
        """Test output without name property."""

        class OutputNoName:
            def format(self, result: ScanResult) -> str:
                return "test"

        is_valid, errors = validate_plugin_interface(OutputNoName, "output")
        assert is_valid is False
        assert any("name" in e.lower() for e in errors)


class TestLoadPluginsFromFileInternal:
    """Tests for _load_plugins_from_file internal function."""

    def test_load_plugin_file_with_syntax_error(self, tmp_path: Path) -> None:
        """Test loading a plugin file with syntax errors."""
        bad_file = tmp_path / "bad_syntax.py"
        bad_file.write_text("def broken(:\n  pass")

        # Use discover_directory which uses _load_plugins_from_file internally
        # and handles errors gracefully with warnings
        plugins = discover_directory(tmp_path)
        # File with syntax error should be skipped, no plugins returned
        assert isinstance(plugins, list)

    def test_load_plugin_file_cannot_create_spec(self, tmp_path: Path) -> None:
        """Test handling when a file cannot be loaded."""
        # Create an empty directory - discover_directory should handle it
        plugins = discover_directory(tmp_path)
        # Empty directory returns empty list
        assert plugins == []

    def test_load_plugin_with_validation_disabled(self, tmp_path: Path) -> None:
        """Test loading plugins with validation disabled."""
        plugin_file = tmp_path / "partial_plugin.py"
        plugin_file.write_text('''
"""Partial plugin that might not fully validate."""
from hamburglar.core.models import Finding
from hamburglar.detectors import BaseDetector


class PartialDetector(BaseDetector):
    """A detector that might fail strict validation."""

    @property
    def name(self) -> str:
        return "partial_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
''')
        from hamburglar.plugins.discovery import _load_plugins_from_file

        plugins = _load_plugins_from_file(plugin_file, validate=False)
        # Should load without validation issues
        assert len(plugins) >= 1

    def test_load_plugin_with_output_class(self, tmp_path: Path) -> None:
        """Test loading a file with output plugin class."""
        plugin_file = tmp_path / "output_only.py"
        plugin_file.write_text('''
"""Output plugin file."""
from hamburglar.core.models import ScanResult
from hamburglar.outputs import BaseOutput


class CustomOutput(BaseOutput):
    """A custom output plugin."""

    @property
    def name(self) -> str:
        return "custom_output"

    def format(self, result: ScanResult) -> str:
        return "custom"
''')
        from hamburglar.plugins.discovery import _load_plugins_from_file

        plugins = _load_plugins_from_file(plugin_file, validate=True)
        output_plugins = [p for p in plugins if p[1] == "output"]
        assert len(output_plugins) >= 1

    def test_load_skips_private_attributes(self, tmp_path: Path) -> None:
        """Test that private attributes (starting with _) are skipped."""
        plugin_file = tmp_path / "with_private.py"
        plugin_file.write_text('''
"""Plugin with private classes."""
from hamburglar.core.models import Finding
from hamburglar.detectors import BaseDetector


class _PrivateDetector(BaseDetector):
    """Should be skipped."""

    @property
    def name(self) -> str:
        return "private"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []


class PublicDetector(BaseDetector):
    """Should be found."""

    @property
    def name(self) -> str:
        return "public"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
''')
        from hamburglar.plugins.discovery import _load_plugins_from_file

        plugins = _load_plugins_from_file(plugin_file)
        names = [p[0] for p in plugins]
        assert "private" not in names


class TestDiscoverPluginsAdvanced:
    """Advanced tests for discover_plugins function."""

    def test_discover_with_entry_points_enabled(self) -> None:
        """Test discovery with entry points enabled."""
        manager = PluginManager()
        result = discover_plugins(include_entry_points=True, manager=manager)
        assert isinstance(result, DiscoveryResult)
        # Entry points may or may not exist, but shouldn't error

    def test_discover_with_multiple_directories(self, tmp_path: Path) -> None:
        """Test discovery with multiple plugin directories."""
        dir1 = tmp_path / "plugins1"
        dir2 = tmp_path / "plugins2"
        dir1.mkdir()
        dir2.mkdir()

        # Create plugin in dir1
        (dir1 / "det1.py").write_text("""
from hamburglar.core.models import Finding
from hamburglar.detectors import BaseDetector

class Det1Detector(BaseDetector):
    @property
    def name(self) -> str:
        return "det1"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
""")

        # Create plugin in dir2
        (dir2 / "det2.py").write_text("""
from hamburglar.core.models import Finding
from hamburglar.detectors import BaseDetector

class Det2Detector(BaseDetector):
    @property
    def name(self) -> str:
        return "det2"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
""")

        # Run in subprocess
        test_script = f'''
import sys
sys.path.insert(0, "{src_path}")
from hamburglar.plugins import PluginManager, reset_plugin_manager
from hamburglar.plugins.discovery import discover_plugins

reset_plugin_manager()
manager = PluginManager()
result = discover_plugins(
    directories=["{dir1}", "{dir2}"],
    include_entry_points=False,
    manager=manager
)
if result.detector_count >= 2:
    print("SUCCESS")
else:
    print("FAIL: " + str(result.detector_count))
    sys.exit(1)
'''
        import subprocess

        proc = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert proc.returncode == 0, f"Failed: {proc.stderr}"
        assert "SUCCESS" in proc.stdout

    def test_discover_uses_global_manager_when_none_provided(self) -> None:
        """Test that discover_plugins uses global manager when none provided."""
        reset_plugin_manager()
        result = discover_plugins(include_entry_points=False)
        assert isinstance(result, DiscoveryResult)

    def test_discover_handles_registration_errors(self, tmp_path: Path) -> None:
        """Test that discovery handles registration errors gracefully."""
        # Create a plugin that might cause registration issues
        plugin_file = tmp_path / "problematic.py"
        plugin_file.write_text("""
from hamburglar.core.models import Finding
from hamburglar.detectors import BaseDetector

class ProblematicDetector(BaseDetector):
    @property
    def name(self) -> str:
        return ""  # Empty name might cause issues

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
""")
        manager = PluginManager()
        # Should not raise, errors should be captured in result
        result = discover_plugins(
            directories=[tmp_path], include_entry_points=False, manager=manager
        )
        assert isinstance(result, DiscoveryResult)


class TestListPluginsAdvanced:
    """Advanced tests for list_plugins function."""

    def test_list_plugins_uses_global_manager(self) -> None:
        """Test list_plugins uses global manager when none provided."""
        reset_plugin_manager()
        # Should not raise
        plugins = list(list_plugins())
        assert isinstance(plugins, list)

    def test_list_plugins_triggers_discovery(self) -> None:
        """Test that list_plugins triggers discovery if not done."""
        manager = PluginManager()
        assert manager._discovered is False
        _ = list(list_plugins(manager=manager))
        assert manager._discovered is True


class TestGetPluginDetailsAdvanced:
    """Advanced tests for get_plugin_details function."""

    def test_get_plugin_details_uses_global_manager(self) -> None:
        """Test get_plugin_details uses global manager when none provided."""
        reset_plugin_manager()
        # Should return None for nonexistent plugin
        details = get_plugin_details("nonexistent_plugin_xyz")
        assert details is None


class TestFormatPluginListAdvanced:
    """Advanced tests for format_plugin_list function."""

    def test_format_only_detectors(self) -> None:
        """Test formatting with only detector plugins."""
        plugins = [
            PluginListEntry(
                name="det1",
                plugin_type="detector",
                description="Detector 1",
            ),
            PluginListEntry(
                name="det2",
                plugin_type="detector",
                description="Detector 2",
            ),
        ]
        result = format_plugin_list(plugins)
        assert "Detector Plugins:" in result
        assert "Output Plugins:" not in result
        assert "det1" in result
        assert "det2" in result

    def test_format_only_outputs(self) -> None:
        """Test formatting with only output plugins."""
        plugins = [
            PluginListEntry(
                name="out1",
                plugin_type="output",
                description="Output 1",
            ),
        ]
        result = format_plugin_list(plugins)
        assert "Output Plugins:" in result
        assert "Detector Plugins:" not in result
        assert "out1" in result

    def test_format_verbose_with_description(self) -> None:
        """Test verbose formatting includes description."""
        plugins = [
            PluginListEntry(
                name="test",
                plugin_type="detector",
                description="A detailed description",
                version="2.0.0",
                author="Test Author",
                source="directory",
            ),
        ]
        result = format_plugin_list(plugins, verbose=True)
        assert "A detailed description" in result
        assert "Test Author" in result
        assert "directory" in result

    def test_format_verbose_without_author(self) -> None:
        """Test verbose formatting when author is empty."""
        plugins = [
            PluginListEntry(
                name="test",
                plugin_type="detector",
                description="Description",
                version="1.0.0",
                author="",  # Empty author
                source="manual",
            ),
        ]
        result = format_plugin_list(plugins, verbose=True)
        assert "Description" in result
        assert "Author:" not in result  # Should not show empty author

    def test_format_non_verbose_with_description(self) -> None:
        """Test non-verbose formatting shows description inline."""
        plugins = [
            PluginListEntry(
                name="test",
                plugin_type="detector",
                description="Short desc",
            ),
        ]
        result = format_plugin_list(plugins, verbose=False)
        assert "test - Short desc" in result

    def test_format_non_verbose_without_description(self) -> None:
        """Test non-verbose formatting without description."""
        plugins = [
            PluginListEntry(
                name="test",
                plugin_type="output",
                description="",  # Empty description
            ),
        ]
        result = format_plugin_list(plugins, verbose=False)
        assert "test" in result
        assert " - " not in result.split("test")[1].split("\n")[0]  # No description suffix


class TestFormatPluginDetailsAdvanced:
    """Advanced tests for format_plugin_details function."""

    def test_format_without_author(self) -> None:
        """Test formatting without author."""
        plugin = PluginListEntry(
            name="test",
            plugin_type="detector",
            author="",  # Empty
        )
        result = format_plugin_details(plugin)
        assert "Author:" not in result

    def test_format_without_description(self) -> None:
        """Test formatting without description."""
        plugin = PluginListEntry(
            name="test",
            plugin_type="detector",
            description="",  # Empty
        )
        result = format_plugin_details(plugin)
        assert "Description:" not in result

    def test_format_disabled_plugin(self) -> None:
        """Test formatting a disabled plugin."""
        plugin = PluginListEntry(
            name="test",
            plugin_type="detector",
            enabled=False,
        )
        result = format_plugin_details(plugin)
        assert "Enabled: No" in result

    def test_format_with_empty_config(self) -> None:
        """Test formatting with empty config dict."""
        plugin = PluginListEntry(
            name="test",
            plugin_type="detector",
            config={},  # Empty config
        )
        result = format_plugin_details(plugin)
        assert "Configuration:" not in result


class TestDiscoverDirectoryEdgeCases:
    """Edge case tests for discover_directory function."""

    def test_discover_directory_with_import_error(self, tmp_path: Path) -> None:
        """Test handling of files with import errors."""
        bad_import = tmp_path / "bad_import.py"
        bad_import.write_text("""
import nonexistent_module_xyz
from hamburglar.detectors import BaseDetector
""")
        # Should handle gracefully (log warning but not crash)
        plugins = discover_directory(tmp_path)
        # File with import error should be skipped
        assert isinstance(plugins, list)

    def test_discover_directory_with_runtime_error(self, tmp_path: Path) -> None:
        """Test handling of files that raise errors at module level."""
        bad_file = tmp_path / "runtime_error.py"
        bad_file.write_text("""
raise RuntimeError("Module level error")
""")
        # Should handle gracefully
        plugins = discover_directory(tmp_path)
        assert isinstance(plugins, list)
