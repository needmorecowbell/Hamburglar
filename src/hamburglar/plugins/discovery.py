"""Plugin discovery system for Hamburglar.

This module provides functionality for discovering and loading plugins from
multiple sources: Python entry points, configured directories, and explicit
registration. It also provides a plugin listing interface for CLI commands.

Example usage::

    from hamburglar.plugins.discovery import (
        discover_plugins,
        list_plugins,
        get_plugin_info,
        validate_plugin_interface,
    )

    # Discover all available plugins
    discovered = discover_plugins()
    print(f"Found {discovered.total} plugins")

    # List all plugins with details
    for plugin in list_plugins():
        print(f"{plugin.name}: {plugin.description}")

    # Validate a plugin class before loading
    is_valid, errors = validate_plugin_interface(MyDetectorClass, "detector")
"""

from __future__ import annotations

import importlib.metadata
import importlib.util
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from hamburglar.core.logging import get_logger
from hamburglar.detectors import BaseDetector
from hamburglar.outputs import BaseOutput
from hamburglar.plugins import (
    DETECTOR_ENTRY_POINT,
    OUTPUT_ENTRY_POINT,
    PluginError,
    PluginInfo,
    PluginManager,
    get_plugin_manager,
)

if TYPE_CHECKING:
    from collections.abc import Iterator


@dataclass
class DiscoveryResult:
    """Result of plugin discovery operation.

    Attributes:
        detector_count: Number of detector plugins discovered.
        output_count: Number of output plugins discovered.
        total: Total number of plugins discovered.
        errors: List of errors encountered during discovery.
        sources: Dictionary mapping plugin names to their sources.
    """

    detector_count: int = 0
    output_count: int = 0
    total: int = 0
    errors: list[str] = field(default_factory=list)
    sources: dict[str, str] = field(default_factory=dict)


@dataclass
class PluginListEntry:
    """Entry in a plugin listing.

    Provides all information needed to display a plugin in a list
    or detailed view.

    Attributes:
        name: The unique plugin name.
        plugin_type: Either "detector" or "output".
        version: Plugin version string.
        author: Plugin author name.
        description: Human-readable description.
        source: Where the plugin was loaded from.
        enabled: Whether the plugin is currently enabled.
        config: Plugin-specific configuration.
    """

    name: str
    plugin_type: str
    version: str = "1.0.0"
    author: str = ""
    description: str = ""
    source: str = "manual"
    enabled: bool = True
    config: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_plugin_info(cls, info: PluginInfo) -> PluginListEntry:
        """Create a PluginListEntry from a PluginInfo.

        Args:
            info: The PluginInfo to convert.

        Returns:
            A PluginListEntry with the same information.
        """
        return cls(
            name=info.name,
            plugin_type=info.plugin_type,
            version=info.version,
            author=info.author,
            description=info.description,
            source=info.source,
            config=info.config.copy(),
        )


def validate_plugin_interface(cls: type, plugin_type: str) -> tuple[bool, list[str]]:
    """Validate that a class implements the required plugin interface.

    Checks that the class has all required methods and properties for
    the specified plugin type.

    Args:
        cls: The class to validate.
        plugin_type: Either "detector" or "output".

    Returns:
        A tuple of (is_valid, list of error messages).

    Example:
        >>> is_valid, errors = validate_plugin_interface(MyDetector, "detector")
        >>> if not is_valid:
        ...     for error in errors:
        ...         print(f"Error: {error}")
    """
    errors: list[str] = []

    if plugin_type == "detector":
        # Check for name property
        if not hasattr(cls, "name"):
            errors.append("Missing 'name' property")
        elif not isinstance(getattr(cls, "name", None), property) and not callable(
            getattr(cls, "name", None)
        ):
            # Allow either property or method that returns string
            pass

        # Check for detect method
        if not hasattr(cls, "detect"):
            errors.append("Missing 'detect' method")
        elif not callable(cls.detect):
            errors.append("'detect' must be a callable method")

        # Check inheritance (optional but recommended)
        if not issubclass(cls, BaseDetector) and not errors:
            errors.append(
                f"Detector should inherit from BaseDetector (inherits from {cls.__bases__})"
            )
            # This is a warning, not a hard error - remove it
            errors.pop()

    elif plugin_type == "output":
        # Check for name property
        if not hasattr(cls, "name"):
            errors.append("Missing 'name' property")

        # Check for format method
        if not hasattr(cls, "format"):
            errors.append("Missing 'format' method")
        elif not callable(cls.format):
            errors.append("'format' must be a callable method")

        # Check inheritance (optional but recommended)
        if not issubclass(cls, BaseOutput) and not errors:
            errors.append(f"Output should inherit from BaseOutput (inherits from {cls.__bases__})")
            # This is a warning, not a hard error - remove it
            errors.pop()

    else:
        errors.append(f"Unknown plugin type: {plugin_type}")

    return len(errors) == 0, errors


def discover_entry_points() -> list[tuple[str, str, type, str]]:
    """Discover plugins from Python entry points.

    Searches for plugins registered via setuptools entry points under
    the hamburglar.plugins.detectors and hamburglar.plugins.outputs groups.

    Returns:
        List of tuples (name, plugin_type, class, group_name).
    """
    logger = get_logger()
    discovered: list[tuple[str, str, type, str]] = []

    eps = importlib.metadata.entry_points()

    # Handle both Python 3.9 and 3.10+ entry_points API
    if hasattr(eps, "select"):
        detector_eps = eps.select(group=DETECTOR_ENTRY_POINT)
        output_eps = eps.select(group=OUTPUT_ENTRY_POINT)
    else:
        detector_eps = eps.get(DETECTOR_ENTRY_POINT, [])
        output_eps = eps.get(OUTPUT_ENTRY_POINT, [])

    # Discover detector entry points
    for ep in detector_eps:
        try:
            plugin_cls = ep.load()
            is_valid, errors = validate_plugin_interface(plugin_cls, "detector")
            if is_valid:
                discovered.append((ep.name, "detector", plugin_cls, DETECTOR_ENTRY_POINT))
            else:
                logger.warning(
                    "Detector plugin '%s' failed validation: %s",
                    ep.name,
                    "; ".join(errors),
                )
        except Exception as e:
            logger.warning("Failed to load detector entry point '%s': %s", ep.name, e)

    # Discover output entry points
    for ep in output_eps:
        try:
            plugin_cls = ep.load()
            is_valid, errors = validate_plugin_interface(plugin_cls, "output")
            if is_valid:
                discovered.append((ep.name, "output", plugin_cls, OUTPUT_ENTRY_POINT))
            else:
                logger.warning(
                    "Output plugin '%s' failed validation: %s",
                    ep.name,
                    "; ".join(errors),
                )
        except Exception as e:
            logger.warning("Failed to load output entry point '%s': %s", ep.name, e)

    return discovered


def discover_directory(
    directory: Path | str, validate: bool = True
) -> list[tuple[str, str, type, str]]:
    """Discover plugins from a directory.

    Scans a directory for Python files and loads any classes that
    implement the detector or output plugin interfaces.

    Args:
        directory: Path to the directory to scan.
        validate: If True, validate plugins implement required interfaces.

    Returns:
        List of tuples (name, plugin_type, class, file_path).

    Raises:
        PluginError: If the directory doesn't exist or isn't accessible.
    """
    logger = get_logger()
    discovered: list[tuple[str, str, type, str]] = []
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

    for py_file in path.glob("*.py"):
        if py_file.name.startswith("_"):
            continue

        try:
            plugins = _load_plugins_from_file(py_file, validate)
            for name, plugin_type, cls in plugins:
                discovered.append((name, plugin_type, cls, str(py_file)))
        except Exception as e:
            logger.warning("Failed to load plugins from '%s': %s", py_file, e)

    return discovered


def _load_plugins_from_file(file_path: Path, validate: bool = True) -> list[tuple[str, str, type]]:
    """Load plugin classes from a Python file.

    Args:
        file_path: Path to the Python file.
        validate: If True, validate plugins implement required interfaces.

    Returns:
        List of tuples (name, plugin_type, class).
    """
    logger = get_logger()
    plugins: list[tuple[str, str, type]] = []
    module_name = f"hamburglar_plugin_{file_path.stem}"

    # Load the module
    spec = importlib.util.spec_from_file_location(module_name, file_path)
    if spec is None or spec.loader is None:
        raise PluginError(f"Cannot create spec for plugin file: {file_path}")

    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module

    try:
        spec.loader.exec_module(module)
    except Exception as e:
        del sys.modules[module_name]
        raise PluginError(f"Error executing plugin file: {file_path}") from e

    # Scan for detector and output classes
    for attr_name in dir(module):
        if attr_name.startswith("_"):
            continue

        attr = getattr(module, attr_name)
        if not isinstance(attr, type):
            continue

        # Skip base classes
        if attr in (BaseDetector, BaseOutput):
            continue

        # Check for detector plugins
        if hasattr(attr, "detect") and hasattr(attr, "name"):
            if validate:
                is_valid, errors = validate_plugin_interface(attr, "detector")
                if not is_valid:
                    logger.debug(
                        "Class '%s' in '%s' failed detector validation: %s",
                        attr_name,
                        file_path,
                        errors,
                    )
                    continue

            # Derive plugin name from class name
            name = attr_name.lower()
            if name.endswith("detector"):
                name = name[:-8]  # Remove 'detector' suffix
            plugins.append((name, "detector", attr))

        # Check for output plugins
        elif hasattr(attr, "format") and hasattr(attr, "name"):
            if validate:
                is_valid, errors = validate_plugin_interface(attr, "output")
                if not is_valid:
                    logger.debug(
                        "Class '%s' in '%s' failed output validation: %s",
                        attr_name,
                        file_path,
                        errors,
                    )
                    continue

            # Derive plugin name from class name
            name = attr_name.lower()
            if name.endswith("output"):
                name = name[:-6]  # Remove 'output' suffix
            plugins.append((name, "output", attr))

    return plugins


def discover_plugins(
    directories: list[Path | str] | None = None,
    include_entry_points: bool = True,
    manager: PluginManager | None = None,
) -> DiscoveryResult:
    """Discover plugins from all configured sources.

    This is the main entry point for plugin discovery. It searches for
    plugins in entry points and configured directories, validates them,
    and registers them with the plugin manager.

    Args:
        directories: Optional list of directories to search.
        include_entry_points: If True, search Python entry points.
        manager: Optional PluginManager to use. Uses global manager if None.

    Returns:
        A DiscoveryResult with counts and any errors.

    Example:
        >>> result = discover_plugins(directories=["/path/to/plugins"])
        >>> print(f"Found {result.total} plugins")
        >>> if result.errors:
        ...     print(f"Errors: {result.errors}")
    """
    logger = get_logger()
    result = DiscoveryResult()

    if manager is None:
        manager = get_plugin_manager()

    # Discover from entry points
    if include_entry_points:
        try:
            ep_plugins = discover_entry_points()
            for name, plugin_type, cls, source in ep_plugins:
                try:
                    if plugin_type == "detector":
                        manager._register_detector_from_class(name, cls, source="entry_point")
                        result.detector_count += 1
                    else:
                        manager._register_output_from_class(name, cls, source="entry_point")
                        result.output_count += 1
                    result.sources[name] = f"entry_point:{source}"
                except Exception as e:
                    result.errors.append(f"Failed to register {name}: {e}")
        except Exception as e:
            result.errors.append(f"Error discovering entry points: {e}")
            logger.warning("Entry point discovery failed: %s", e)

    # Discover from directories
    if directories:
        for directory in directories:
            try:
                dir_plugins = discover_directory(directory)
                for name, plugin_type, cls, file_path in dir_plugins:
                    try:
                        if plugin_type == "detector":
                            manager._register_detector_from_class(name, cls, source="directory")
                            result.detector_count += 1
                        else:
                            manager._register_output_from_class(name, cls, source="directory")
                            result.output_count += 1
                        result.sources[name] = f"directory:{file_path}"
                    except Exception as e:
                        result.errors.append(f"Failed to register {name}: {e}")
            except PluginError as e:
                result.errors.append(str(e))
                logger.warning("Directory discovery failed for '%s': %s", directory, e)

    result.total = result.detector_count + result.output_count
    logger.info(
        "Plugin discovery complete: %d detectors, %d outputs",
        result.detector_count,
        result.output_count,
    )

    return result


def list_plugins(
    plugin_type: str | None = None,
    manager: PluginManager | None = None,
) -> Iterator[PluginListEntry]:
    """List all registered plugins.

    Yields plugin information for all registered plugins, optionally
    filtered by type. This is intended for use by CLI commands.

    Args:
        plugin_type: If specified, only list plugins of this type
            ("detector" or "output").
        manager: Optional PluginManager to use. Uses global manager if None.

    Yields:
        PluginListEntry for each matching plugin.

    Example:
        >>> for plugin in list_plugins(plugin_type="detector"):
        ...     print(f"{plugin.name}: {plugin.description}")
    """
    if manager is None:
        manager = get_plugin_manager()

    # Ensure discovery has been run
    if not manager._discovered:
        manager.discover()

    if plugin_type is None or plugin_type == "detector":
        for info in manager.list_detector_plugins():
            yield PluginListEntry.from_plugin_info(info)

    if plugin_type is None or plugin_type == "output":
        for info in manager.list_output_plugins():
            yield PluginListEntry.from_plugin_info(info)


def get_plugin_details(name: str, manager: PluginManager | None = None) -> PluginListEntry | None:
    """Get detailed information about a specific plugin.

    Args:
        name: The plugin name to look up.
        manager: Optional PluginManager to use. Uses global manager if None.

    Returns:
        PluginListEntry with plugin details, or None if not found.

    Example:
        >>> details = get_plugin_details("my_detector")
        >>> if details:
        ...     print(f"Version: {details.version}")
        ...     print(f"Author: {details.author}")
    """
    if manager is None:
        manager = get_plugin_manager()

    info = manager.get_plugin_info(name)
    if info is None:
        return None

    return PluginListEntry.from_plugin_info(info)


def format_plugin_list(
    plugins: list[PluginListEntry] | Iterator[PluginListEntry],
    verbose: bool = False,
) -> str:
    """Format a list of plugins for display.

    Creates a human-readable string representation of a plugin list,
    suitable for CLI output.

    Args:
        plugins: List or iterator of PluginListEntry objects.
        verbose: If True, include additional details like author and source.

    Returns:
        Formatted string for display.

    Example:
        >>> plugins = list(list_plugins())
        >>> print(format_plugin_list(plugins, verbose=True))
    """
    lines: list[str] = []
    plugin_list = list(plugins)

    if not plugin_list:
        return "No plugins found."

    # Group by type
    detectors = [p for p in plugin_list if p.plugin_type == "detector"]
    outputs = [p for p in plugin_list if p.plugin_type == "output"]

    if detectors:
        lines.append("Detector Plugins:")
        lines.append("-" * 40)
        for p in sorted(detectors, key=lambda x: x.name):
            if verbose:
                lines.append(f"  {p.name} (v{p.version})")
                if p.description:
                    lines.append(f"    {p.description}")
                if p.author:
                    lines.append(f"    Author: {p.author}")
                lines.append(f"    Source: {p.source}")
            else:
                desc = f" - {p.description}" if p.description else ""
                lines.append(f"  {p.name}{desc}")
        lines.append("")

    if outputs:
        lines.append("Output Plugins:")
        lines.append("-" * 40)
        for p in sorted(outputs, key=lambda x: x.name):
            if verbose:
                lines.append(f"  {p.name} (v{p.version})")
                if p.description:
                    lines.append(f"    {p.description}")
                if p.author:
                    lines.append(f"    Author: {p.author}")
                lines.append(f"    Source: {p.source}")
            else:
                desc = f" - {p.description}" if p.description else ""
                lines.append(f"  {p.name}{desc}")
        lines.append("")

    # Summary
    lines.append(f"Total: {len(detectors)} detector(s), {len(outputs)} output(s)")

    return "\n".join(lines)


def format_plugin_details(plugin: PluginListEntry) -> str:
    """Format detailed information about a single plugin.

    Creates a human-readable string with all available information
    about a plugin.

    Args:
        plugin: The PluginListEntry to format.

    Returns:
        Formatted string for display.

    Example:
        >>> details = get_plugin_details("my_detector")
        >>> if details:
        ...     print(format_plugin_details(details))
    """
    lines: list[str] = [
        f"Plugin: {plugin.name}",
        f"Type: {plugin.plugin_type}",
        f"Version: {plugin.version}",
    ]

    if plugin.author:
        lines.append(f"Author: {plugin.author}")

    if plugin.description:
        lines.append(f"Description: {plugin.description}")

    lines.append(f"Source: {plugin.source}")
    lines.append(f"Enabled: {'Yes' if plugin.enabled else 'No'}")

    if plugin.config:
        lines.append("Configuration:")
        for key, value in plugin.config.items():
            lines.append(f"  {key}: {value}")

    return "\n".join(lines)


__all__ = [
    # Discovery
    "discover_plugins",
    "discover_entry_points",
    "discover_directory",
    "DiscoveryResult",
    # Listing
    "list_plugins",
    "get_plugin_details",
    "PluginListEntry",
    # Validation
    "validate_plugin_interface",
    # Formatting
    "format_plugin_list",
    "format_plugin_details",
]
