"""Plugin system for Hamburglar.

This module provides a robust plugin architecture for extending Hamburglar
with custom detectors and output formatters without modifying the core codebase.

Plugins can be discovered from:
- Python entry points (installed packages)
- Configured plugin directories
- Explicit plugin registration

Example usage::

    from hamburglar.plugins import PluginManager, detector_plugin, output_plugin

    # Create a plugin manager
    manager = PluginManager()

    # Discover plugins from entry points and directories
    manager.discover()

    # List available plugins
    for plugin in manager.list_detector_plugins():
        print(f"Detector: {plugin.name}")

    # Use decorators to create plugins
    @detector_plugin("my_detector")
    class MyDetector(DetectorPlugin):
        def detect(self, content: str, file_path: str = "") -> list[Finding]:
            ...

    @output_plugin("my_output")
    class MyOutput(OutputPlugin):
        def format(self, result: ScanResult) -> str:
            ...
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, TypeVar

from hamburglar.core.exceptions import HamburglarError
from hamburglar.core.logging import get_logger
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.detectors import BaseDetector, DetectorRegistry, default_registry
from hamburglar.outputs import BaseOutput, OutputRegistry
from hamburglar.outputs import default_registry as output_default_registry

# Entry point group names for plugin discovery
DETECTOR_ENTRY_POINT = "hamburglar.plugins.detectors"
OUTPUT_ENTRY_POINT = "hamburglar.plugins.outputs"


class PluginError(HamburglarError):
    """Exception raised for plugin-related errors.

    This exception is raised when a plugin fails to load, register,
    or validate against required interfaces.

    Example:
        >>> raise PluginError("Plugin failed to load", context={"plugin": "my_plugin"})
    """

    def __init__(self, message: str, plugin_name: str | None = None, context: dict | None = None):
        """Initialize the plugin error.

        Args:
            message: Human-readable error message.
            plugin_name: Name of the plugin that caused the error.
            context: Optional dictionary of additional context.
        """
        ctx = context or {}
        if plugin_name:
            ctx["plugin"] = plugin_name
        super().__init__(message, ctx)
        self.plugin_name = plugin_name


@dataclass
class PluginInfo:
    """Information about a registered plugin.

    Attributes:
        name: Unique identifier for the plugin.
        plugin_type: Either "detector" or "output".
        description: Human-readable description of the plugin.
        version: Plugin version string.
        author: Plugin author name.
        source: Where the plugin was loaded from (entry_point, directory, manual).
        instance: The actual plugin instance.
        config: Plugin-specific configuration.
    """

    name: str
    plugin_type: str
    description: str = ""
    version: str = "1.0.0"
    author: str = ""
    source: str = "manual"
    instance: BaseDetector | BaseOutput | None = None
    config: dict[str, Any] = field(default_factory=dict)


# Type variable for plugin decorators
T = TypeVar("T", bound=type)


# Global plugin registries
_detector_plugins: dict[str, PluginInfo] = {}
_output_plugins: dict[str, PluginInfo] = {}


def detector_plugin(
    name: str,
    description: str = "",
    version: str = "1.0.0",
    author: str = "",
) -> Callable[[T], T]:
    """Decorator to register a class as a detector plugin.

    This decorator registers the decorated class as a detector plugin,
    making it discoverable by the PluginManager.

    Args:
        name: Unique identifier for the plugin.
        description: Human-readable description of what the detector finds.
        version: Plugin version string.
        author: Plugin author name.

    Returns:
        A decorator function that registers the class.

    Example:
        @detector_plugin("my_detector", description="Finds custom secrets")
        class MyDetector(DetectorPlugin):
            @property
            def name(self) -> str:
                return "my_detector"

            def detect(self, content: str, file_path: str = "") -> list[Finding]:
                # Detection logic here
                return []
    """

    def decorator(cls: T) -> T:
        # Validate the class implements required interface
        if not hasattr(cls, "detect") or not callable(cls.detect):
            raise PluginError(
                f"Detector plugin '{name}' must implement detect() method",
                plugin_name=name,
            )
        if not hasattr(cls, "name"):
            raise PluginError(
                f"Detector plugin '{name}' must have a name property",
                plugin_name=name,
            )

        # Store plugin info
        _detector_plugins[name] = PluginInfo(
            name=name,
            plugin_type="detector",
            description=description,
            version=version,
            author=author,
            source="decorator",
        )

        # Store reference to the class for later instantiation
        _detector_plugins[name].instance = cls  # type: ignore

        return cls

    return decorator


def output_plugin(
    name: str,
    description: str = "",
    version: str = "1.0.0",
    author: str = "",
) -> Callable[[T], T]:
    """Decorator to register a class as an output plugin.

    This decorator registers the decorated class as an output plugin,
    making it discoverable by the PluginManager.

    Args:
        name: Unique identifier for the plugin.
        description: Human-readable description of the output format.
        version: Plugin version string.
        author: Plugin author name.

    Returns:
        A decorator function that registers the class.

    Example:
        @output_plugin("my_output", description="Custom output format")
        class MyOutput(OutputPlugin):
            @property
            def name(self) -> str:
                return "my_output"

            def format(self, result: ScanResult) -> str:
                # Format logic here
                return ""
    """

    def decorator(cls: T) -> T:
        # Validate the class implements required interface
        if not hasattr(cls, "format") or not callable(cls.format):
            raise PluginError(
                f"Output plugin '{name}' must implement format() method",
                plugin_name=name,
            )
        if not hasattr(cls, "name"):
            raise PluginError(
                f"Output plugin '{name}' must have a name property",
                plugin_name=name,
            )

        # Store plugin info
        _output_plugins[name] = PluginInfo(
            name=name,
            plugin_type="output",
            description=description,
            version=version,
            author=author,
            source="decorator",
        )

        # Store reference to the class for later instantiation
        _output_plugins[name].instance = cls  # type: ignore

        return cls

    return decorator


class PluginManager:
    """Manager for discovering, loading, and managing plugins.

    The PluginManager handles plugin discovery from multiple sources:
    - Python entry points (pip-installed plugins)
    - Plugin directories (file-based plugins)
    - Decorator-registered plugins
    - Manual registration

    Example:
        manager = PluginManager()

        # Add custom plugin directories
        manager.add_plugin_directory("/path/to/plugins")

        # Discover all available plugins
        manager.discover()

        # Get a detector plugin instance
        detector = manager.get_detector("my_detector")

        # List all plugins
        for info in manager.list_detector_plugins():
            print(f"{info.name}: {info.description}")
    """

    def __init__(
        self,
        detector_registry: DetectorRegistry | None = None,
        output_registry: OutputRegistry | None = None,
        plugin_directories: list[str | Path] | None = None,
        auto_discover: bool = False,
    ) -> None:
        """Initialize the PluginManager.

        Args:
            detector_registry: Registry for detector plugins. Uses global default if None.
            output_registry: Registry for output plugins. Uses global default if None.
            plugin_directories: List of directories to search for plugins.
            auto_discover: If True, automatically discover plugins on initialization.
        """
        self._logger = get_logger()
        self._detector_registry = detector_registry or default_registry
        self._output_registry = output_registry or output_default_registry
        self._plugin_directories: list[Path] = []
        self._detector_plugins: dict[str, PluginInfo] = {}
        self._output_plugins: dict[str, PluginInfo] = {}
        self._discovered = False

        # Add any initial plugin directories
        if plugin_directories:
            for directory in plugin_directories:
                self.add_plugin_directory(directory)

        if auto_discover:
            self.discover()

    def add_plugin_directory(self, directory: str | Path) -> None:
        """Add a directory to search for plugins.

        Args:
            directory: Path to the plugin directory.

        Raises:
            PluginError: If the directory doesn't exist.
        """
        path = Path(directory)
        if not path.exists():
            raise PluginError(
                f"Plugin directory does not exist: {directory}",
                context={"directory": str(directory)},
            )
        if not path.is_dir():
            raise PluginError(
                f"Plugin path is not a directory: {directory}",
                context={"path": str(directory)},
            )
        if path not in self._plugin_directories:
            self._plugin_directories.append(path)
            self._logger.debug("Added plugin directory: %s", directory)

    def discover(self, force: bool = False) -> int:
        """Discover plugins from all sources.

        This method searches for plugins in:
        1. Python entry points
        2. Configured plugin directories
        3. Decorator-registered plugins

        Args:
            force: If True, re-discover even if already discovered.

        Returns:
            Total number of plugins discovered.
        """
        if self._discovered and not force:
            return len(self._detector_plugins) + len(self._output_plugins)

        total = 0

        # Discover from entry points
        total += self._discover_entry_points()

        # Discover from directories
        for directory in self._plugin_directories:
            total += self._discover_directory(directory)

        # Import decorator-registered plugins
        total += self._import_decorated_plugins()

        self._discovered = True
        self._logger.info(
            "Discovered %d plugins (%d detectors, %d outputs)",
            total,
            len(self._detector_plugins),
            len(self._output_plugins),
        )
        return total

    def _discover_entry_points(self) -> int:
        """Discover plugins from Python entry points.

        Returns:
            Number of plugins discovered from entry points.
        """
        count = 0

        # Discover detector plugins
        try:
            eps = importlib.metadata.entry_points()
            # Handle both Python 3.9 and 3.10+ entry_points API
            if hasattr(eps, "select"):
                detector_eps = eps.select(group=DETECTOR_ENTRY_POINT)
            else:
                detector_eps = eps.get(DETECTOR_ENTRY_POINT, [])

            for ep in detector_eps:
                try:
                    plugin_cls = ep.load()
                    self._register_detector_from_class(ep.name, plugin_cls, source="entry_point")
                    count += 1
                except Exception as e:
                    self._logger.warning("Failed to load detector plugin '%s': %s", ep.name, e)
        except Exception as e:
            self._logger.debug("Error discovering detector entry points: %s", e)

        # Discover output plugins
        try:
            eps = importlib.metadata.entry_points()
            if hasattr(eps, "select"):
                output_eps = eps.select(group=OUTPUT_ENTRY_POINT)
            else:
                output_eps = eps.get(OUTPUT_ENTRY_POINT, [])

            for ep in output_eps:
                try:
                    plugin_cls = ep.load()
                    self._register_output_from_class(ep.name, plugin_cls, source="entry_point")
                    count += 1
                except Exception as e:
                    self._logger.warning("Failed to load output plugin '%s': %s", ep.name, e)
        except Exception as e:
            self._logger.debug("Error discovering output entry points: %s", e)

        return count

    def _discover_directory(self, directory: Path) -> int:
        """Discover plugins from a directory.

        Loads Python files from the directory and looks for plugin classes.

        Args:
            directory: Path to the plugin directory.

        Returns:
            Number of plugins discovered from the directory.
        """
        count = 0

        for path in directory.glob("*.py"):
            if path.name.startswith("_"):
                continue

            try:
                count += self._load_plugin_file(path)
            except Exception as e:
                self._logger.warning("Failed to load plugin file '%s': %s", path, e)

        return count

    def _load_plugin_file(self, path: Path) -> int:
        """Load plugins from a Python file.

        Args:
            path: Path to the Python file.

        Returns:
            Number of plugins loaded from the file.
        """
        count = 0
        module_name = f"hamburglar_plugin_{path.stem}"

        # Load the module
        spec = importlib.util.spec_from_file_location(module_name, path)
        if spec is None or spec.loader is None:
            raise PluginError(f"Cannot load plugin file: {path}")

        module = importlib.util.module_from_spec(spec)
        sys.modules[module_name] = module

        try:
            spec.loader.exec_module(module)
        except Exception as e:
            del sys.modules[module_name]
            raise PluginError(f"Error executing plugin file: {path}") from e

        # Look for detector and output classes
        for attr_name in dir(module):
            attr = getattr(module, attr_name)
            if not isinstance(attr, type):
                continue

            # Check for detector plugins
            if (
                hasattr(attr, "detect")
                and hasattr(attr, "name")
                and attr is not BaseDetector
                and issubclass(attr, BaseDetector)
            ):
                try:
                    name = attr_name.lower().replace("detector", "")
                    self._register_detector_from_class(name, attr, source="directory")
                    count += 1
                except Exception as e:
                    self._logger.warning("Failed to register detector '%s': %s", attr_name, e)

            # Check for output plugins
            if (
                hasattr(attr, "format")
                and hasattr(attr, "name")
                and attr is not BaseOutput
                and issubclass(attr, BaseOutput)
            ):
                try:
                    name = attr_name.lower().replace("output", "")
                    self._register_output_from_class(name, attr, source="directory")
                    count += 1
                except Exception as e:
                    self._logger.warning("Failed to register output '%s': %s", attr_name, e)

        return count

    def _import_decorated_plugins(self) -> int:
        """Import plugins registered via decorators.

        Returns:
            Number of decorator-registered plugins imported.
        """
        count = 0

        # Import detector plugins
        for name, info in _detector_plugins.items():
            if name not in self._detector_plugins:
                self._detector_plugins[name] = info
                count += 1

        # Import output plugins
        for name, info in _output_plugins.items():
            if name not in self._output_plugins:
                self._output_plugins[name] = info
                count += 1

        return count

    def _register_detector_from_class(
        self, name: str, cls: type, source: str = "manual", config: dict | None = None
    ) -> None:
        """Register a detector plugin from a class.

        Args:
            name: Plugin name.
            cls: The detector class.
            source: Where the plugin came from.
            config: Optional plugin configuration.
        """
        # Get metadata from class if available
        description = getattr(cls, "__doc__", "") or ""
        version = getattr(cls, "__version__", "1.0.0")
        author = getattr(cls, "__author__", "")

        info = PluginInfo(
            name=name,
            plugin_type="detector",
            description=description.split("\n")[0] if description else "",
            version=version,
            author=author,
            source=source,
            instance=cls,  # type: ignore
            config=config or {},
        )
        self._detector_plugins[name] = info

    def _register_output_from_class(
        self, name: str, cls: type, source: str = "manual", config: dict | None = None
    ) -> None:
        """Register an output plugin from a class.

        Args:
            name: Plugin name.
            cls: The output class.
            source: Where the plugin came from.
            config: Optional plugin configuration.
        """
        # Get metadata from class if available
        description = getattr(cls, "__doc__", "") or ""
        version = getattr(cls, "__version__", "1.0.0")
        author = getattr(cls, "__author__", "")

        info = PluginInfo(
            name=name,
            plugin_type="output",
            description=description.split("\n")[0] if description else "",
            version=version,
            author=author,
            source=source,
            instance=cls,  # type: ignore
            config=config or {},
        )
        self._output_plugins[name] = info

    def register_detector(
        self,
        detector: BaseDetector,
        description: str = "",
        version: str = "1.0.0",
        author: str = "",
    ) -> None:
        """Manually register a detector plugin instance.

        Args:
            detector: The detector instance to register.
            description: Human-readable description.
            version: Plugin version.
            author: Plugin author.
        """
        name = detector.name
        if name in self._detector_plugins:
            raise PluginError(f"Detector plugin '{name}' is already registered", plugin_name=name)

        info = PluginInfo(
            name=name,
            plugin_type="detector",
            description=description or (detector.__doc__ or "").split("\n")[0],
            version=version,
            author=author,
            source="manual",
            instance=detector,
        )
        self._detector_plugins[name] = info

        # Also register with the detector registry
        try:
            self._detector_registry.register(detector)
        except ValueError:
            # Already registered in the registry, that's fine
            pass

    def register_output(
        self,
        output: BaseOutput,
        description: str = "",
        version: str = "1.0.0",
        author: str = "",
    ) -> None:
        """Manually register an output plugin instance.

        Args:
            output: The output formatter instance to register.
            description: Human-readable description.
            version: Plugin version.
            author: Plugin author.
        """
        name = output.name
        if name in self._output_plugins:
            raise PluginError(f"Output plugin '{name}' is already registered", plugin_name=name)

        info = PluginInfo(
            name=name,
            plugin_type="output",
            description=description or (output.__doc__ or "").split("\n")[0],
            version=version,
            author=author,
            source="manual",
            instance=output,
        )
        self._output_plugins[name] = info

        # Also register with the output registry
        try:
            self._output_registry.register(output)
        except ValueError:
            # Already registered in the registry, that's fine
            pass

    def get_detector(self, name: str, config: dict | None = None) -> BaseDetector:
        """Get a detector plugin instance by name.

        Args:
            name: The plugin name.
            config: Optional configuration to pass to the detector.

        Returns:
            A detector instance.

        Raises:
            PluginError: If the plugin is not found.
        """
        if name not in self._detector_plugins:
            raise PluginError(f"Detector plugin '{name}' not found", plugin_name=name)

        info = self._detector_plugins[name]
        instance = info.instance

        if instance is None:
            raise PluginError(f"Detector plugin '{name}' has no instance", plugin_name=name)

        # If it's a class, instantiate it
        if isinstance(instance, type):
            merged_config = {**info.config, **(config or {})}
            try:
                result = instance(**merged_config) if merged_config else instance()
            except TypeError:
                # Class doesn't accept config, try without it
                result = instance()
            if not isinstance(result, BaseDetector):
                raise PluginError(f"Plugin '{name}' did not return a BaseDetector", plugin_name=name)
            return result

        # It's already an instance - verify type
        if not isinstance(instance, BaseDetector):
            raise PluginError(f"Plugin '{name}' instance is not a BaseDetector", plugin_name=name)
        return instance

    def get_output(self, name: str, config: dict | None = None) -> BaseOutput:
        """Get an output plugin instance by name.

        Args:
            name: The plugin name.
            config: Optional configuration to pass to the output.

        Returns:
            An output formatter instance.

        Raises:
            PluginError: If the plugin is not found.
        """
        if name not in self._output_plugins:
            raise PluginError(f"Output plugin '{name}' not found", plugin_name=name)

        info = self._output_plugins[name]
        instance = info.instance

        if instance is None:
            raise PluginError(f"Output plugin '{name}' has no instance", plugin_name=name)

        # If it's a class, instantiate it
        if isinstance(instance, type):
            merged_config = {**info.config, **(config or {})}
            try:
                result = instance(**merged_config) if merged_config else instance()
            except TypeError:
                # Class doesn't accept config, try without it
                result = instance()
            if not isinstance(result, BaseOutput):
                raise PluginError(f"Plugin '{name}' did not return a BaseOutput", plugin_name=name)
            return result

        # It's already an instance - verify type
        if not isinstance(instance, BaseOutput):
            raise PluginError(f"Plugin '{name}' instance is not a BaseOutput", plugin_name=name)
        return instance

    def list_detector_plugins(self) -> list[PluginInfo]:
        """List all registered detector plugins.

        Returns:
            List of PluginInfo objects for detector plugins.
        """
        return list(self._detector_plugins.values())

    def list_output_plugins(self) -> list[PluginInfo]:
        """List all registered output plugins.

        Returns:
            List of PluginInfo objects for output plugins.
        """
        return list(self._output_plugins.values())

    def list_all_plugins(self) -> list[PluginInfo]:
        """List all registered plugins.

        Returns:
            List of all PluginInfo objects.
        """
        return self.list_detector_plugins() + self.list_output_plugins()

    def get_plugin_info(self, name: str) -> PluginInfo | None:
        """Get information about a specific plugin.

        Args:
            name: The plugin name.

        Returns:
            PluginInfo for the plugin, or None if not found.
        """
        if name in self._detector_plugins:
            return self._detector_plugins[name]
        if name in self._output_plugins:
            return self._output_plugins[name]
        return None

    def unregister_detector(self, name: str) -> None:
        """Unregister a detector plugin.

        Args:
            name: The plugin name to unregister.

        Raises:
            PluginError: If the plugin is not found.
        """
        if name not in self._detector_plugins:
            raise PluginError(f"Detector plugin '{name}' not found", plugin_name=name)

        del self._detector_plugins[name]

        # Also try to remove from the registry
        try:
            self._detector_registry.unregister(name)
        except KeyError:
            pass

    def unregister_output(self, name: str) -> None:
        """Unregister an output plugin.

        Args:
            name: The plugin name to unregister.

        Raises:
            PluginError: If the plugin is not found.
        """
        if name not in self._output_plugins:
            raise PluginError(f"Output plugin '{name}' not found", plugin_name=name)

        del self._output_plugins[name]

        # Also try to remove from the registry
        try:
            self._output_registry.unregister(name)
        except KeyError:
            pass

    def clear(self) -> None:
        """Clear all registered plugins.

        This does not affect the underlying detector/output registries.
        """
        self._detector_plugins.clear()
        self._output_plugins.clear()
        self._discovered = False

    @property
    def plugin_directories(self) -> list[Path]:
        """Get the list of plugin directories.

        Returns:
            List of plugin directory paths.
        """
        return self._plugin_directories.copy()

    def __len__(self) -> int:
        """Return the total number of registered plugins."""
        return len(self._detector_plugins) + len(self._output_plugins)

    def __contains__(self, name: str) -> bool:
        """Check if a plugin is registered by name."""
        return name in self._detector_plugins or name in self._output_plugins


def get_plugin_manager() -> PluginManager:
    """Get a global plugin manager instance.

    Returns:
        A PluginManager instance with auto-discovery enabled.
    """
    global _global_manager
    if _global_manager is None:
        _global_manager = PluginManager(auto_discover=True)
    return _global_manager


# Global plugin manager instance
_global_manager: PluginManager | None = None


def reset_plugin_manager() -> None:
    """Reset the global plugin manager.

    This is primarily useful for testing.
    """
    global _global_manager, _detector_plugins, _output_plugins
    _global_manager = None
    _detector_plugins.clear()
    _output_plugins.clear()


__all__ = [
    # Core classes
    "PluginManager",
    "PluginInfo",
    "PluginError",
    # Decorators
    "detector_plugin",
    "output_plugin",
    # Entry point constants
    "DETECTOR_ENTRY_POINT",
    "OUTPUT_ENTRY_POINT",
    # Global functions
    "get_plugin_manager",
    "reset_plugin_manager",
]
