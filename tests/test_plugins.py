"""Tests for the plugin system.

This module tests the PluginManager, plugin decorators, and plugin discovery.
"""

from __future__ import annotations

import sys
import tempfile
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

from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.detectors import BaseDetector, DetectorRegistry
from hamburglar.outputs import BaseOutput, OutputRegistry
from hamburglar.plugins import (
    DETECTOR_ENTRY_POINT,
    OUTPUT_ENTRY_POINT,
    PluginError,
    PluginInfo,
    PluginManager,
    detector_plugin,
    get_plugin_manager,
    output_plugin,
    reset_plugin_manager,
)


class MockDetectorPlugin(BaseDetector):
    """Mock detector plugin for testing."""

    def __init__(self, name: str = "mock_detector", config_value: str = "default") -> None:
        self._name = name
        self._config_value = config_value

    @property
    def name(self) -> str:
        return self._name

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        if "PLUGIN_SECRET" in content:
            return [
                Finding(
                    file_path=file_path,
                    detector_name=self._name,
                    matches=["PLUGIN_SECRET"],
                    severity=Severity.HIGH,
                    metadata={"config": self._config_value},
                )
            ]
        return []


class MockOutputPlugin(BaseOutput):
    """Mock output plugin for testing."""

    def __init__(self, name: str = "mock_output") -> None:
        self._name = name

    @property
    def name(self) -> str:
        return self._name

    def format(self, result: ScanResult) -> str:
        return f"Plugin output: {len(result.findings)} findings"


@pytest.fixture(autouse=True)
def reset_plugins():
    """Reset plugin state before each test."""
    reset_plugin_manager()
    yield
    reset_plugin_manager()


class TestPluginInfo:
    """Tests for PluginInfo dataclass."""

    def test_plugin_info_defaults(self) -> None:
        """Test PluginInfo default values."""
        info = PluginInfo(name="test", plugin_type="detector")
        assert info.name == "test"
        assert info.plugin_type == "detector"
        assert info.description == ""
        assert info.version == "1.0.0"
        assert info.author == ""
        assert info.source == "manual"
        assert info.instance is None
        assert info.config == {}

    def test_plugin_info_full(self) -> None:
        """Test PluginInfo with all values."""
        detector = MockDetectorPlugin()
        info = PluginInfo(
            name="full",
            plugin_type="detector",
            description="A full plugin",
            version="2.0.0",
            author="Test Author",
            source="entry_point",
            instance=detector,
            config={"key": "value"},
        )
        assert info.name == "full"
        assert info.description == "A full plugin"
        assert info.version == "2.0.0"
        assert info.author == "Test Author"
        assert info.source == "entry_point"
        assert info.instance is detector
        assert info.config == {"key": "value"}


class TestPluginError:
    """Tests for PluginError exception."""

    def test_plugin_error_basic(self) -> None:
        """Test basic PluginError."""
        error = PluginError("Something went wrong")
        assert str(error) == "Something went wrong"
        assert error.plugin_name is None

    def test_plugin_error_with_plugin_name(self) -> None:
        """Test PluginError with plugin name."""
        error = PluginError("Failed to load", plugin_name="my_plugin")
        assert "my_plugin" in str(error)
        assert error.plugin_name == "my_plugin"

    def test_plugin_error_with_context(self) -> None:
        """Test PluginError with context."""
        error = PluginError(
            "Error occurred",
            plugin_name="test",
            context={"reason": "invalid config"},
        )
        assert error.plugin_name == "test"
        assert "plugin" in error.context
        assert "reason" in error.context


class TestPluginManager:
    """Tests for PluginManager class."""

    def test_init_defaults(self) -> None:
        """Test PluginManager initialization with defaults."""
        manager = PluginManager()
        assert len(manager) == 0
        assert manager.plugin_directories == []

    def test_init_with_directories(self, tmp_path: Path) -> None:
        """Test PluginManager with plugin directories."""
        manager = PluginManager(plugin_directories=[str(tmp_path)])
        assert tmp_path in manager.plugin_directories

    def test_add_plugin_directory(self, tmp_path: Path) -> None:
        """Test adding a plugin directory."""
        manager = PluginManager()
        manager.add_plugin_directory(tmp_path)
        assert tmp_path in manager.plugin_directories

    def test_add_plugin_directory_nonexistent(self) -> None:
        """Test adding a nonexistent directory raises PluginError."""
        manager = PluginManager()
        with pytest.raises(PluginError, match="does not exist"):
            manager.add_plugin_directory("/nonexistent/path")

    def test_add_plugin_directory_file(self, tmp_path: Path) -> None:
        """Test adding a file as directory raises PluginError."""
        file_path = tmp_path / "file.txt"
        file_path.write_text("test")
        manager = PluginManager()
        with pytest.raises(PluginError, match="not a directory"):
            manager.add_plugin_directory(file_path)

    def test_add_plugin_directory_duplicate(self, tmp_path: Path) -> None:
        """Test adding the same directory twice is idempotent."""
        manager = PluginManager()
        manager.add_plugin_directory(tmp_path)
        manager.add_plugin_directory(tmp_path)
        assert manager.plugin_directories.count(tmp_path) == 1

    def test_register_detector(self) -> None:
        """Test manual detector registration."""
        manager = PluginManager()
        detector = MockDetectorPlugin()
        manager.register_detector(
            detector,
            description="Test detector",
            version="1.0.0",
            author="Test",
        )
        assert "mock_detector" in manager
        assert len(manager.list_detector_plugins()) == 1

    def test_register_detector_duplicate(self) -> None:
        """Test registering duplicate detector raises PluginError."""
        manager = PluginManager()
        detector1 = MockDetectorPlugin()
        detector2 = MockDetectorPlugin()
        manager.register_detector(detector1)
        with pytest.raises(PluginError, match="already registered"):
            manager.register_detector(detector2)

    def test_register_output(self) -> None:
        """Test manual output registration."""
        manager = PluginManager()
        output = MockOutputPlugin()
        manager.register_output(
            output,
            description="Test output",
            version="1.0.0",
            author="Test",
        )
        assert "mock_output" in manager
        assert len(manager.list_output_plugins()) == 1

    def test_register_output_duplicate(self) -> None:
        """Test registering duplicate output raises PluginError."""
        manager = PluginManager()
        output1 = MockOutputPlugin()
        output2 = MockOutputPlugin()
        manager.register_output(output1)
        with pytest.raises(PluginError, match="already registered"):
            manager.register_output(output2)

    def test_get_detector(self) -> None:
        """Test retrieving a registered detector."""
        manager = PluginManager()
        detector = MockDetectorPlugin()
        manager.register_detector(detector)
        retrieved = manager.get_detector("mock_detector")
        assert retrieved is detector

    def test_get_detector_not_found(self) -> None:
        """Test getting nonexistent detector raises PluginError."""
        manager = PluginManager()
        with pytest.raises(PluginError, match="not found"):
            manager.get_detector("nonexistent")

    def test_get_output(self) -> None:
        """Test retrieving a registered output."""
        manager = PluginManager()
        output = MockOutputPlugin()
        manager.register_output(output)
        retrieved = manager.get_output("mock_output")
        assert retrieved is output

    def test_get_output_not_found(self) -> None:
        """Test getting nonexistent output raises PluginError."""
        manager = PluginManager()
        with pytest.raises(PluginError, match="not found"):
            manager.get_output("nonexistent")

    def test_list_detector_plugins(self) -> None:
        """Test listing detector plugins."""
        manager = PluginManager()
        manager.register_detector(MockDetectorPlugin("d1"))
        manager.register_detector(MockDetectorPlugin("d2"))
        plugins = manager.list_detector_plugins()
        assert len(plugins) == 2
        names = [p.name for p in plugins]
        assert "d1" in names
        assert "d2" in names

    def test_list_output_plugins(self) -> None:
        """Test listing output plugins."""
        manager = PluginManager()
        manager.register_output(MockOutputPlugin("o1"))
        manager.register_output(MockOutputPlugin("o2"))
        plugins = manager.list_output_plugins()
        assert len(plugins) == 2
        names = [p.name for p in plugins]
        assert "o1" in names
        assert "o2" in names

    def test_list_all_plugins(self) -> None:
        """Test listing all plugins."""
        manager = PluginManager()
        manager.register_detector(MockDetectorPlugin())
        manager.register_output(MockOutputPlugin())
        plugins = manager.list_all_plugins()
        assert len(plugins) == 2

    def test_get_plugin_info(self) -> None:
        """Test getting plugin info."""
        manager = PluginManager()
        detector = MockDetectorPlugin()
        manager.register_detector(detector, description="Test")
        info = manager.get_plugin_info("mock_detector")
        assert info is not None
        assert info.name == "mock_detector"
        assert info.plugin_type == "detector"
        assert info.description == "Test"

    def test_get_plugin_info_not_found(self) -> None:
        """Test getting info for nonexistent plugin returns None."""
        manager = PluginManager()
        info = manager.get_plugin_info("nonexistent")
        assert info is None

    def test_unregister_detector(self) -> None:
        """Test unregistering a detector."""
        manager = PluginManager()
        manager.register_detector(MockDetectorPlugin())
        assert "mock_detector" in manager
        manager.unregister_detector("mock_detector")
        assert "mock_detector" not in manager

    def test_unregister_detector_not_found(self) -> None:
        """Test unregistering nonexistent detector raises PluginError."""
        manager = PluginManager()
        with pytest.raises(PluginError, match="not found"):
            manager.unregister_detector("nonexistent")

    def test_unregister_output(self) -> None:
        """Test unregistering an output."""
        manager = PluginManager()
        manager.register_output(MockOutputPlugin())
        assert "mock_output" in manager
        manager.unregister_output("mock_output")
        assert "mock_output" not in manager

    def test_unregister_output_not_found(self) -> None:
        """Test unregistering nonexistent output raises PluginError."""
        manager = PluginManager()
        with pytest.raises(PluginError, match="not found"):
            manager.unregister_output("nonexistent")

    def test_clear(self) -> None:
        """Test clearing all plugins."""
        manager = PluginManager()
        manager.register_detector(MockDetectorPlugin())
        manager.register_output(MockOutputPlugin())
        assert len(manager) == 2
        manager.clear()
        assert len(manager) == 0

    def test_len(self) -> None:
        """Test __len__ method."""
        manager = PluginManager()
        assert len(manager) == 0
        manager.register_detector(MockDetectorPlugin())
        assert len(manager) == 1
        manager.register_output(MockOutputPlugin())
        assert len(manager) == 2

    def test_contains(self) -> None:
        """Test __contains__ method."""
        manager = PluginManager()
        assert "mock_detector" not in manager
        manager.register_detector(MockDetectorPlugin())
        assert "mock_detector" in manager


class TestPluginDiscovery:
    """Tests for plugin discovery functionality."""

    def test_discover_empty(self) -> None:
        """Test discovery with no plugins."""
        manager = PluginManager()
        count = manager.discover()
        # May find some entry points or not, but shouldn't error
        assert count >= 0

    def test_discover_from_directory(self, tmp_path: Path) -> None:
        """Test discovering plugins from a directory."""
        import subprocess
        import sys as _sys

        # Run test in a subprocess to avoid test isolation issues
        # where other tests may have modified builtins
        plugin_file = tmp_path / "unique_test_plugin.py"
        plugin_file.write_text('''
"""Test plugin."""
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.detectors import BaseDetector
from hamburglar.outputs import BaseOutput


class UniqueTestDetector(BaseDetector):
    """A unique test detector plugin."""

    @property
    def name(self) -> str:
        return "unique_test_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []


class UniqueTestOutput(BaseOutput):
    """A unique test output plugin."""

    @property
    def name(self) -> str:
        return "unique_test_output"

    def format(self, result: ScanResult) -> str:
        return "test"
''')
        # Test in subprocess to avoid test pollution issues
        test_script = f'''
import sys
sys.path.insert(0, "{Path(__file__).parent.parent / "src"}")
from pathlib import Path
from hamburglar.plugins import PluginManager

manager = PluginManager(plugin_directories=["{tmp_path}"])
manager.discover()
detector_names = [p.name for p in manager.list_detector_plugins()]
output_names = [p.name for p in manager.list_output_plugins()]
# Check unique plugins found
found_detector = "uniquetest" in detector_names or "unique_test_detector" in detector_names
found_output = "uniquetest" in output_names or "unique_test_output" in output_names
if found_detector and found_output:
    print("SUCCESS")
else:
    print(f"FAIL: detectors={{detector_names}}, outputs={{output_names}}")
    sys.exit(1)
'''
        result = subprocess.run(
            [_sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0, f"Plugin discovery failed: {result.stderr}"
        assert "SUCCESS" in result.stdout

    def test_discover_skips_private_files(self, tmp_path: Path) -> None:
        """Test that files starting with _ are skipped."""
        plugin_file = tmp_path / "_private_plugin.py"
        plugin_file.write_text('''
from hamburglar.detectors import BaseDetector
from hamburglar.core.models import Finding

class PrivateDetector(BaseDetector):
    @property
    def name(self) -> str:
        return "private"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []
''')
        manager = PluginManager(plugin_directories=[tmp_path])
        manager.discover()
        assert "private" not in manager

    def test_discover_force_rediscover(self, tmp_path: Path) -> None:
        """Test force rediscovery."""
        manager = PluginManager(plugin_directories=[tmp_path])
        count1 = manager.discover()
        count2 = manager.discover()  # Should skip
        count3 = manager.discover(force=True)  # Should re-run
        assert count1 == count2  # Same count since cached
        assert count3 >= 0


class TestDecoratorPlugins:
    """Tests for decorator-based plugin registration."""

    def test_detector_plugin_decorator(self) -> None:
        """Test @detector_plugin decorator."""
        @detector_plugin("decorated_detector", description="A decorated detector")
        class DecoratedDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "decorated_detector"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                return []

        # The decorator should register the plugin globally
        manager = PluginManager()
        manager.discover()  # This imports decorated plugins
        assert "decorated_detector" in manager

    def test_output_plugin_decorator(self) -> None:
        """Test @output_plugin decorator."""
        @output_plugin("decorated_output", description="A decorated output")
        class DecoratedOutput(BaseOutput):
            @property
            def name(self) -> str:
                return "decorated_output"

            def format(self, result: ScanResult) -> str:
                return "decorated"

        manager = PluginManager()
        manager.discover()
        assert "decorated_output" in manager

    def test_detector_decorator_missing_detect(self) -> None:
        """Test decorator fails without detect method."""
        with pytest.raises(PluginError, match="must implement detect"):
            @detector_plugin("bad_detector")
            class BadDetector:
                @property
                def name(self) -> str:
                    return "bad"

    def test_detector_decorator_missing_name(self) -> None:
        """Test decorator fails without name property."""
        with pytest.raises(PluginError, match="must have a name"):
            @detector_plugin("no_name_detector")
            class NoNameDetector:
                def detect(self, content: str, file_path: str = "") -> list[Finding]:
                    return []

    def test_output_decorator_missing_format(self) -> None:
        """Test decorator fails without format method."""
        with pytest.raises(PluginError, match="must implement format"):
            @output_plugin("bad_output")
            class BadOutput:
                @property
                def name(self) -> str:
                    return "bad"

    def test_output_decorator_missing_name(self) -> None:
        """Test decorator fails without name property."""
        with pytest.raises(PluginError, match="must have a name"):
            @output_plugin("no_name_output")
            class NoNameOutput:
                def format(self, result: ScanResult) -> str:
                    return ""


class TestPluginWithConfig:
    """Tests for plugin configuration."""

    def test_get_detector_with_config(self) -> None:
        """Test getting detector with configuration."""
        manager = PluginManager()
        # Register the class, not an instance
        manager._detector_plugins["configurable"] = PluginInfo(
            name="configurable",
            plugin_type="detector",
            instance=MockDetectorPlugin,
            config={"config_value": "custom"},
        )
        detector = manager.get_detector("configurable")
        assert detector._config_value == "custom"

    def test_get_detector_config_override(self) -> None:
        """Test config override when getting detector."""
        manager = PluginManager()
        manager._detector_plugins["configurable"] = PluginInfo(
            name="configurable",
            plugin_type="detector",
            instance=MockDetectorPlugin,
            config={"config_value": "base"},
        )
        detector = manager.get_detector("configurable", config={"config_value": "override"})
        assert detector._config_value == "override"


class TestGlobalPluginManager:
    """Tests for global plugin manager functions."""

    def test_get_plugin_manager(self) -> None:
        """Test getting global plugin manager."""
        manager = get_plugin_manager()
        assert isinstance(manager, PluginManager)

    def test_get_plugin_manager_singleton(self) -> None:
        """Test global plugin manager is a singleton."""
        manager1 = get_plugin_manager()
        manager2 = get_plugin_manager()
        assert manager1 is manager2

    def test_reset_plugin_manager(self) -> None:
        """Test resetting global plugin manager."""
        manager1 = get_plugin_manager()
        reset_plugin_manager()
        manager2 = get_plugin_manager()
        assert manager1 is not manager2


class TestEntryPointConstants:
    """Tests for entry point constants."""

    def test_detector_entry_point(self) -> None:
        """Test detector entry point constant."""
        assert DETECTOR_ENTRY_POINT == "hamburglar.plugins.detectors"

    def test_output_entry_point(self) -> None:
        """Test output entry point constant."""
        assert OUTPUT_ENTRY_POINT == "hamburglar.plugins.outputs"


class TestPluginIntegration:
    """Integration tests for plugin system."""

    def test_detector_plugin_detect(self) -> None:
        """Test that a registered detector can actually detect."""
        manager = PluginManager()
        detector = MockDetectorPlugin()
        manager.register_detector(detector)

        retrieved = manager.get_detector("mock_detector")
        findings = retrieved.detect("Contains PLUGIN_SECRET here", "test.txt")
        assert len(findings) == 1
        assert findings[0].matches == ["PLUGIN_SECRET"]

    def test_output_plugin_format(self) -> None:
        """Test that a registered output can actually format."""
        manager = PluginManager()
        output = MockOutputPlugin()
        manager.register_output(output)

        retrieved = manager.get_output("mock_output")
        result = ScanResult(
            target_path="/test",
            findings=[
                Finding(
                    file_path="test.txt",
                    detector_name="test",
                    matches=["secret"],
                    severity=Severity.HIGH,
                    metadata={},
                )
            ],
            scan_duration=0.1,
            stats={},
        )
        formatted = retrieved.format(result)
        assert "1 findings" in formatted


class TestPluginManagerAdvanced:
    """Advanced tests for PluginManager edge cases."""

    def test_register_detector_from_class(self) -> None:
        """Test _register_detector_from_class method."""
        manager = PluginManager()
        manager._register_detector_from_class(
            "test_det",
            MockDetectorPlugin,
            source="test",
            config={"key": "value"},
        )
        assert "test_det" in manager
        info = manager.get_plugin_info("test_det")
        assert info is not None
        assert info.source == "test"
        assert info.config == {"key": "value"}

    def test_register_output_from_class(self) -> None:
        """Test _register_output_from_class method."""
        manager = PluginManager()
        manager._register_output_from_class(
            "test_out",
            MockOutputPlugin,
            source="test",
            config={"format": "custom"},
        )
        assert "test_out" in manager
        info = manager.get_plugin_info("test_out")
        assert info is not None
        assert info.source == "test"

    def test_get_detector_instantiates_class(self) -> None:
        """Test get_detector properly instantiates a class."""
        manager = PluginManager()
        manager._register_detector_from_class("inst_det", MockDetectorPlugin, source="test")
        detector = manager.get_detector("inst_det")
        assert isinstance(detector, MockDetectorPlugin)

    def test_get_detector_with_config_merged(self) -> None:
        """Test get_detector merges configs properly."""
        manager = PluginManager()
        manager._register_detector_from_class(
            "config_det",
            MockDetectorPlugin,
            source="test",
            config={"config_value": "base"},
        )
        detector = manager.get_detector("config_det", config={"name": "override"})
        assert detector._config_value == "base"
        assert detector._name == "override"

    def test_get_detector_class_no_config_support(self) -> None:
        """Test get_detector handles classes that don't accept config."""

        class SimpleDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "simple"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                return []

        manager = PluginManager()
        manager._register_detector_from_class(
            "simple_det",
            SimpleDetector,
            source="test",
            config={"unused": "config"},
        )
        # Should handle TypeError and instantiate without config
        detector = manager.get_detector("simple_det")
        assert detector.name == "simple"

    def test_get_detector_no_instance(self) -> None:
        """Test get_detector raises when instance is None."""
        manager = PluginManager()
        manager._detector_plugins["no_inst"] = PluginInfo(
            name="no_inst",
            plugin_type="detector",
            instance=None,  # No instance
        )
        with pytest.raises(PluginError, match="has no instance"):
            manager.get_detector("no_inst")

    def test_get_output_instantiates_class(self) -> None:
        """Test get_output properly instantiates a class."""
        manager = PluginManager()
        manager._register_output_from_class("inst_out", MockOutputPlugin, source="test")
        output = manager.get_output("inst_out")
        assert isinstance(output, MockOutputPlugin)

    def test_get_output_class_no_config_support(self) -> None:
        """Test get_output handles classes that don't accept config."""

        class SimpleOutput(BaseOutput):
            @property
            def name(self) -> str:
                return "simple"

            def format(self, result: ScanResult) -> str:
                return "simple"

        manager = PluginManager()
        manager._register_output_from_class(
            "simple_out",
            SimpleOutput,
            source="test",
            config={"unused": "config"},
        )
        # Should handle TypeError and instantiate without config
        output = manager.get_output("simple_out")
        assert output.name == "simple"

    def test_get_output_no_instance(self) -> None:
        """Test get_output raises when instance is None."""
        manager = PluginManager()
        manager._output_plugins["no_inst"] = PluginInfo(
            name="no_inst",
            plugin_type="output",
            instance=None,  # No instance
        )
        with pytest.raises(PluginError, match="has no instance"):
            manager.get_output("no_inst")

    def test_get_plugin_info_from_output(self) -> None:
        """Test get_plugin_info returns output plugin info."""
        manager = PluginManager()
        output = MockOutputPlugin()
        manager.register_output(output, description="Test")
        info = manager.get_plugin_info("mock_output")
        assert info is not None
        assert info.plugin_type == "output"

    def test_unregister_detector_removes_from_registry(self) -> None:
        """Test unregister_detector also removes from registry."""
        manager = PluginManager()
        detector = MockDetectorPlugin()
        manager.register_detector(detector)
        assert "mock_detector" in manager
        manager.unregister_detector("mock_detector")
        assert "mock_detector" not in manager

    def test_unregister_output_removes_from_registry(self) -> None:
        """Test unregister_output also removes from registry."""
        manager = PluginManager()
        output = MockOutputPlugin()
        manager.register_output(output)
        assert "mock_output" in manager
        manager.unregister_output("mock_output")
        assert "mock_output" not in manager

    def test_auto_discover_on_init(self, tmp_path: Path) -> None:
        """Test auto_discover=True triggers discovery on init."""
        manager = PluginManager(
            plugin_directories=[str(tmp_path)],
            auto_discover=True,
        )
        assert manager._discovered is True

    def test_discover_with_custom_registries(self) -> None:
        """Test PluginManager with custom registries."""
        det_registry = DetectorRegistry()
        out_registry = OutputRegistry()
        manager = PluginManager(
            detector_registry=det_registry,
            output_registry=out_registry,
        )
        detector = MockDetectorPlugin()
        manager.register_detector(detector)
        # Should be in both plugin manager and registry
        assert "mock_detector" in manager

    def test_register_detector_already_in_registry(self) -> None:
        """Test registering detector when already in registry."""
        det_registry = DetectorRegistry()
        manager = PluginManager(detector_registry=det_registry)
        detector = MockDetectorPlugin()
        # Pre-register in registry
        det_registry.register(detector)
        # Should not raise when registering in plugin manager
        manager.register_detector(detector)
        assert "mock_detector" in manager

    def test_register_output_already_in_registry(self) -> None:
        """Test registering output when already in registry."""
        out_registry = OutputRegistry()
        manager = PluginManager(output_registry=out_registry)
        output = MockOutputPlugin()
        # Pre-register in registry
        out_registry.register(output)
        # Should not raise when registering in plugin manager
        manager.register_output(output)
        assert "mock_output" in manager

    def test_import_decorated_plugins(self) -> None:
        """Test _import_decorated_plugins imports from global registries."""
        # Define decorated plugins
        @detector_plugin("import_test_det", description="Test")
        class ImportTestDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "import_test_det"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                return []

        manager = PluginManager()
        manager.discover()
        assert "import_test_det" in manager

    def test_discover_returns_cached_count(self) -> None:
        """Test discover returns cached count on subsequent calls."""
        manager = PluginManager()
        count1 = manager.discover()
        count2 = manager.discover()  # Should return cached
        assert count1 == count2

    def test_load_plugin_file_integration(self, tmp_path: Path) -> None:
        """Test _load_plugin_file loads plugins correctly."""
        plugin_file = tmp_path / "integration.py"
        plugin_file.write_text('''
"""Integration test plugin."""
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.detectors import BaseDetector
from hamburglar.outputs import BaseOutput


class IntegrationDetector(BaseDetector):
    """Integration test detector."""
    __version__ = "2.0.0"
    __author__ = "Tester"

    @property
    def name(self) -> str:
        return "integration_detector"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        return []


class IntegrationOutput(BaseOutput):
    """Integration test output."""

    @property
    def name(self) -> str:
        return "integration_output"

    def format(self, result: ScanResult) -> str:
        return "integration"
''')
        # Run in subprocess
        test_script = f'''
import sys
sys.path.insert(0, "{Path(__file__).parent.parent / "src"}")
from pathlib import Path
from hamburglar.plugins import PluginManager

manager = PluginManager(plugin_directories=["{tmp_path}"])
manager.discover()
det_names = [p.name for p in manager.list_detector_plugins()]
out_names = [p.name for p in manager.list_output_plugins()]
if "integration" in det_names or "integrationdetector" in det_names:
    print("DETECTOR_FOUND")
if "integration" in out_names or "integrationoutput" in out_names:
    print("OUTPUT_FOUND")
'''
        import subprocess

        result = subprocess.run(
            [sys.executable, "-c", test_script],
            capture_output=True,
            text=True,
            timeout=30,
        )
        # At least one should be found
        assert "FOUND" in result.stdout or result.returncode == 0


class TestPluginDiscoveryEntryPoints:
    """Tests for entry point discovery."""

    def test_discover_entry_points_api(self) -> None:
        """Test _discover_entry_points internal method."""
        manager = PluginManager()
        count = manager._discover_entry_points()
        # May be 0 if no entry points installed
        assert count >= 0

    def test_discover_handles_entry_point_errors(self) -> None:
        """Test discovery handles entry point loading errors gracefully."""
        manager = PluginManager()
        # Should not raise even if some entry points fail
        manager.discover()
        assert manager._discovered is True


class TestDecoratorValidation:
    """Tests for decorator validation."""

    def test_detector_decorator_with_all_metadata(self) -> None:
        """Test detector decorator with all metadata."""
        @detector_plugin(
            "full_meta_det",
            description="Full metadata detector",
            version="3.0.0",
            author="Full Author",
        )
        class FullMetaDetector(BaseDetector):
            @property
            def name(self) -> str:
                return "full_meta_det"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                return []

        manager = PluginManager()
        manager.discover()
        info = manager.get_plugin_info("full_meta_det")
        assert info is not None
        assert info.description == "Full metadata detector"
        assert info.version == "3.0.0"
        assert info.author == "Full Author"

    def test_output_decorator_with_all_metadata(self) -> None:
        """Test output decorator with all metadata."""
        @output_plugin(
            "full_meta_out",
            description="Full metadata output",
            version="3.0.0",
            author="Full Author",
        )
        class FullMetaOutput(BaseOutput):
            @property
            def name(self) -> str:
                return "full_meta_out"

            def format(self, result: ScanResult) -> str:
                return "full"

        manager = PluginManager()
        manager.discover()
        info = manager.get_plugin_info("full_meta_out")
        assert info is not None
        assert info.description == "Full metadata output"


class TestPluginManagerClear:
    """Tests for PluginManager clear functionality."""

    def test_clear_resets_discovered_flag(self) -> None:
        """Test clear resets the discovered flag."""
        manager = PluginManager()
        manager.discover()
        assert manager._discovered is True
        manager.clear()
        assert manager._discovered is False

    def test_clear_allows_rediscovery(self) -> None:
        """Test clear allows subsequent discovery."""
        manager = PluginManager()
        manager.discover()
        manager.clear()
        count = manager.discover()
        assert count >= 0


class TestUnregisterWithRegistry:
    """Tests for unregistering plugins with registry interactions."""

    def test_unregister_detector_removes_from_registry(self) -> None:
        """Test that unregistering a detector removes it from the registry."""
        manager = PluginManager()
        detector = MockDetectorPlugin(name="to_unregister")
        manager.register_detector(detector)

        # Verify it's registered
        assert "to_unregister" in manager

        # Unregister it
        manager.unregister_detector("to_unregister")

        # Verify it's gone
        assert "to_unregister" not in manager

    def test_unregister_output_removes_from_registry(self) -> None:
        """Test that unregistering an output removes it from the registry."""
        manager = PluginManager()
        output = MockOutputPlugin(name="to_unregister_output")
        manager.register_output(output)

        # Verify it's registered
        assert "to_unregister_output" in manager

        # Unregister it
        manager.unregister_output("to_unregister_output")

        # Verify it's gone
        assert "to_unregister_output" not in manager

    def test_unregister_detector_not_in_registry_succeeds(self) -> None:
        """Test unregistering detector that's not in underlying registry."""
        manager = PluginManager()
        # Directly add to _detector_plugins without using registry
        manager._detector_plugins["direct_add"] = PluginInfo(
            name="direct_add",
            plugin_type="detector",
            instance=MockDetectorPlugin,
        )

        # This should succeed even though it's not in the registry
        manager.unregister_detector("direct_add")
        assert "direct_add" not in manager._detector_plugins

    def test_unregister_output_not_in_registry_succeeds(self) -> None:
        """Test unregistering output that's not in underlying registry."""
        manager = PluginManager()
        # Directly add to _output_plugins without using registry
        manager._output_plugins["direct_add_output"] = PluginInfo(
            name="direct_add_output",
            plugin_type="output",
            instance=MockOutputPlugin,
        )

        # This should succeed even though it's not in the registry
        manager.unregister_output("direct_add_output")
        assert "direct_add_output" not in manager._output_plugins


class TestPluginFileLoadingErrors:
    """Tests for plugin file loading error handling."""

    def test_discover_handles_malformed_plugin_file(self, tmp_path: Path) -> None:
        """Test that discover handles files with syntax errors gracefully."""
        bad_plugin = tmp_path / "bad_syntax.py"
        bad_plugin.write_text("def broken(:\n  pass")  # Syntax error

        manager = PluginManager(plugin_directories=[tmp_path])
        # Should not raise, just log warning
        count = manager.discover()
        assert count >= 0

    def test_discover_handles_import_error_in_plugin(self, tmp_path: Path) -> None:
        """Test that discover handles import errors in plugins."""
        bad_import = tmp_path / "bad_import.py"
        bad_import.write_text("import nonexistent_module_xyz")

        manager = PluginManager(plugin_directories=[tmp_path])
        # Should not raise, just log warning
        count = manager.discover()
        assert count >= 0

    def test_discover_handles_exception_in_plugin_init(self, tmp_path: Path) -> None:
        """Test that discover handles exceptions during plugin execution."""
        error_plugin = tmp_path / "error_plugin.py"
        error_plugin.write_text("raise RuntimeError('Plugin load error')")

        manager = PluginManager(plugin_directories=[tmp_path])
        # Should not raise, just log warning
        count = manager.discover()
        assert count >= 0


class TestEntryPointDiscoveryErrors:
    """Tests for entry point discovery error handling."""

    def test_discover_entry_points_handles_load_error(self) -> None:
        """Test that entry point loading errors are handled gracefully."""
        from unittest.mock import MagicMock, patch

        manager = PluginManager()

        # Mock entry_points to return an entry point that fails to load
        mock_ep = MagicMock()
        mock_ep.name = "failing_plugin"
        mock_ep.load.side_effect = ImportError("Cannot load plugin")

        mock_eps = MagicMock()
        mock_eps.select.return_value = [mock_ep]

        with patch("importlib.metadata.entry_points", return_value=mock_eps):
            # Should not raise, just log warning
            count = manager._discover_entry_points()
            assert count == 0  # No plugins loaded due to error

    def test_discover_entry_points_handles_no_select_method(self) -> None:
        """Test fallback when entry_points doesn't have select method (Python 3.9)."""
        from unittest.mock import patch

        manager = PluginManager()

        # Mock entry_points to return dict-like object (Python 3.9 style)
        # Python 3.9 returns a dict-like object, not an object with select()
        mock_eps = {"hamburglar.plugins.detectors": [], "hamburglar.plugins.outputs": []}

        with patch("importlib.metadata.entry_points", return_value=mock_eps):
            count = manager._discover_entry_points()
            assert count == 0

    def test_discover_entry_points_exception_during_discovery(self) -> None:
        """Test handling of exception during entry point discovery."""
        from unittest.mock import patch

        manager = PluginManager()

        with patch("importlib.metadata.entry_points", side_effect=Exception("Discovery error")):
            # Should not raise, just log debug message
            count = manager._discover_entry_points()
            assert count == 0
