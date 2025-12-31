"""Output formatter classes for Hamburglar.

This module provides the base output interface and registry for managing
output formatters that render scan results in different formats.
"""

from abc import ABC, abstractmethod

from hamburglar.core.models import ScanResult


class BaseOutput(ABC):
    """Abstract base class for all output formatters.

    Subclasses must implement the `name` property and `format` method
    to provide specific formatting logic for different output types.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this output formatter.

        Returns:
            A string identifier for this formatter (e.g., 'json', 'table').
        """
        pass

    @abstractmethod
    def format(self, result: ScanResult) -> str:
        """Format a scan result for output.

        Args:
            result: The ScanResult to format.

        Returns:
            A formatted string representation of the scan result.
        """
        pass


class OutputRegistry:
    """Registry for managing and retrieving output formatter instances.

    The registry allows formatters to be registered by name and retrieved
    for rendering scan results in the desired format.
    """

    def __init__(self) -> None:
        """Initialize an empty output registry."""
        self._outputs: dict[str, BaseOutput] = {}

    def register(self, output: BaseOutput) -> None:
        """Register an output formatter instance.

        Args:
            output: The output formatter instance to register.

        Raises:
            ValueError: If a formatter with the same name is already registered.
        """
        if output.name in self._outputs:
            raise ValueError(f"Output formatter '{output.name}' is already registered")
        self._outputs[output.name] = output

    def unregister(self, name: str) -> None:
        """Remove an output formatter from the registry.

        Args:
            name: The name of the formatter to remove.

        Raises:
            KeyError: If no formatter with the given name is registered.
        """
        if name not in self._outputs:
            raise KeyError(f"Output formatter '{name}' is not registered")
        del self._outputs[name]

    def get(self, name: str) -> BaseOutput:
        """Retrieve an output formatter by name.

        Args:
            name: The name of the formatter to retrieve.

        Returns:
            The output formatter instance.

        Raises:
            KeyError: If no formatter with the given name is registered.
        """
        if name not in self._outputs:
            raise KeyError(f"Output formatter '{name}' is not registered")
        return self._outputs[name]

    def get_all(self) -> list[BaseOutput]:
        """Retrieve all registered output formatters.

        Returns:
            A list of all registered formatter instances.
        """
        return list(self._outputs.values())

    def list_names(self) -> list[str]:
        """List the names of all registered output formatters.

        Returns:
            A list of formatter names.
        """
        return list(self._outputs.keys())

    def __len__(self) -> int:
        """Return the number of registered output formatters."""
        return len(self._outputs)

    def __contains__(self, name: str) -> bool:
        """Check if an output formatter is registered by name."""
        return name in self._outputs


# Global registry instance for convenience
default_registry = OutputRegistry()
