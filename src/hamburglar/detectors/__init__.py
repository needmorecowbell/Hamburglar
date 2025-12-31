"""Detector classes for Hamburglar.

This module provides the base detector interface and registry for managing
detectors that identify sensitive information in file content.
"""

from abc import ABC, abstractmethod

from hamburglar.core.models import Finding


class BaseDetector(ABC):
    """Abstract base class for all detectors.

    Subclasses must implement the `name` property and `detect` method
    to provide specific detection logic for different types of sensitive data.
    """

    @property
    @abstractmethod
    def name(self) -> str:
        """Return the unique name of this detector.

        Returns:
            A string identifier for this detector (e.g., 'regex', 'yara').
        """
        pass

    @abstractmethod
    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect sensitive information in the given content.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed (for Finding metadata).

        Returns:
            A list of Finding objects for each detected item.
        """
        pass


class DetectorRegistry:
    """Registry for managing and retrieving detector instances.

    The registry allows detectors to be registered by name and retrieved
    individually or as a collection for scanning operations.
    """

    def __init__(self) -> None:
        """Initialize an empty detector registry."""
        self._detectors: dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        """Register a detector instance.

        Args:
            detector: The detector instance to register.

        Raises:
            ValueError: If a detector with the same name is already registered.
        """
        if detector.name in self._detectors:
            raise ValueError(f"Detector '{detector.name}' is already registered")
        self._detectors[detector.name] = detector

    def unregister(self, name: str) -> None:
        """Remove a detector from the registry.

        Args:
            name: The name of the detector to remove.

        Raises:
            KeyError: If no detector with the given name is registered.
        """
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' is not registered")
        del self._detectors[name]

    def get(self, name: str) -> BaseDetector:
        """Retrieve a detector by name.

        Args:
            name: The name of the detector to retrieve.

        Returns:
            The detector instance.

        Raises:
            KeyError: If no detector with the given name is registered.
        """
        if name not in self._detectors:
            raise KeyError(f"Detector '{name}' is not registered")
        return self._detectors[name]

    def get_all(self) -> list[BaseDetector]:
        """Retrieve all registered detectors.

        Returns:
            A list of all registered detector instances.
        """
        return list(self._detectors.values())

    def list_names(self) -> list[str]:
        """List the names of all registered detectors.

        Returns:
            A list of detector names.
        """
        return list(self._detectors.keys())

    def __len__(self) -> int:
        """Return the number of registered detectors."""
        return len(self._detectors)

    def __contains__(self, name: str) -> bool:
        """Check if a detector is registered by name."""
        return name in self._detectors


# Global registry instance for convenience
default_registry = DetectorRegistry()
