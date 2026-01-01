"""Optional iocextract integration for Hamburglar.

This module provides a wrapper around the iocextract library for extracting
Indicators of Compromise (IOCs) from text content. It includes:

- Wrapper functions around iocextract for URL, IP, email, hash, and YARA rule extraction
- A detector implementation that uses iocextract for detection
- Graceful fallback when iocextract is not installed

The iocextract library is optional and must be installed separately:
    pip install iocextract

Usage:
    from hamburglar.compat.ioc_extract import IOCExtractDetector, is_available

    if is_available():
        detector = IOCExtractDetector()
        findings = detector.detect(content, file_path)
    else:
        print("iocextract is not installed")

For legacy compatibility with original hamburglar.py -i flag:
    from hamburglar.compat.ioc_extract import extract_iocs_legacy

    results = extract_iocs_legacy(text)
    # Returns: {"urls": [...], "ips": [...], "emails": [...], "hashes": [...], "rules": [...]}
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from hamburglar.core.models import Finding, Severity
from hamburglar.detectors import BaseDetector

# Try to import iocextract
_IOCEXTRACT_AVAILABLE = False
_IMPORT_ERROR: str | None = None

try:
    import iocextract

    _IOCEXTRACT_AVAILABLE = True
except ImportError as e:
    _IMPORT_ERROR = str(e)
    iocextract = None  # type: ignore[assignment]


def is_available() -> bool:
    """Check if iocextract is available.

    Returns:
        True if iocextract is installed and can be imported, False otherwise.
    """
    return _IOCEXTRACT_AVAILABLE


def get_import_error() -> str | None:
    """Get the import error message if iocextract is not available.

    Returns:
        The error message if import failed, None if iocextract is available.
    """
    return _IMPORT_ERROR


class IOCExtractNotAvailable(ImportError):
    """Raised when iocextract is required but not installed."""

    def __init__(self, message: str | None = None) -> None:
        """Initialize the exception.

        Args:
            message: Optional custom message. If not provided, uses default.
        """
        if message is None:
            message = (
                "iocextract is not installed. "
                "Install it with: pip install iocextract"
            )
        super().__init__(message)


def _require_iocextract() -> None:
    """Raise an error if iocextract is not available.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    if not _IOCEXTRACT_AVAILABLE:
        raise IOCExtractNotAvailable()


# =============================================================================
# Wrapper functions around iocextract
# =============================================================================


def extract_urls(text: str, refang: bool = False) -> list[str]:
    """Extract URLs from text.

    Args:
        text: The text content to extract URLs from.
        refang: If True, convert defanged URLs to proper URLs.

    Returns:
        List of extracted URLs.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    return list(iocextract.extract_urls(text, refang=refang))


def extract_ips(text: str, refang: bool = False) -> list[str]:
    """Extract IP addresses from text.

    Args:
        text: The text content to extract IP addresses from.
        refang: If True, convert defanged IPs to proper IPs.

    Returns:
        List of extracted IP addresses.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    return list(iocextract.extract_ips(text, refang=refang))


def extract_emails(text: str, refang: bool = False) -> list[str]:
    """Extract email addresses from text.

    Args:
        text: The text content to extract emails from.
        refang: If True, convert defanged emails to proper emails.

    Returns:
        List of extracted email addresses.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    return list(iocextract.extract_emails(text, refang=refang))


def extract_hashes(text: str) -> list[str]:
    """Extract hash values (MD5, SHA1, SHA256, SHA512) from text.

    Args:
        text: The text content to extract hashes from.

    Returns:
        List of extracted hash values.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    return list(iocextract.extract_hashes(text))


def extract_yara_rules(text: str) -> list[str]:
    """Extract YARA rules from text.

    Args:
        text: The text content to extract YARA rules from.

    Returns:
        List of extracted YARA rule strings.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    return list(iocextract.extract_yara_rules(text))


def extract_ipv4s(text: str, refang: bool = False) -> list[str]:
    """Extract IPv4 addresses from text.

    Args:
        text: The text content to extract IPv4 addresses from.
        refang: If True, convert defanged IPs to proper IPs.

    Returns:
        List of extracted IPv4 addresses.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    if hasattr(iocextract, "extract_ipv4s"):
        return list(iocextract.extract_ipv4s(text, refang=refang))
    # Fallback to extract_ips if extract_ipv4s not available
    return list(iocextract.extract_ips(text, refang=refang))


def extract_ipv6s(text: str) -> list[str]:
    """Extract IPv6 addresses from text.

    Args:
        text: The text content to extract IPv6 addresses from.

    Returns:
        List of extracted IPv6 addresses.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    if hasattr(iocextract, "extract_ipv6s"):
        return list(iocextract.extract_ipv6s(text))
    return []


def extract_md5_hashes(text: str) -> list[str]:
    """Extract MD5 hashes from text.

    Args:
        text: The text content to extract MD5 hashes from.

    Returns:
        List of extracted MD5 hashes.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    if hasattr(iocextract, "extract_md5_hashes"):
        return list(iocextract.extract_md5_hashes(text))
    # Fallback: filter hashes by length (32 chars for MD5)
    all_hashes = list(iocextract.extract_hashes(text))
    return [h for h in all_hashes if len(h) == 32]


def extract_sha1_hashes(text: str) -> list[str]:
    """Extract SHA1 hashes from text.

    Args:
        text: The text content to extract SHA1 hashes from.

    Returns:
        List of extracted SHA1 hashes.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    if hasattr(iocextract, "extract_sha1_hashes"):
        return list(iocextract.extract_sha1_hashes(text))
    # Fallback: filter hashes by length (40 chars for SHA1)
    all_hashes = list(iocextract.extract_hashes(text))
    return [h for h in all_hashes if len(h) == 40]


def extract_sha256_hashes(text: str) -> list[str]:
    """Extract SHA256 hashes from text.

    Args:
        text: The text content to extract SHA256 hashes from.

    Returns:
        List of extracted SHA256 hashes.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    if hasattr(iocextract, "extract_sha256_hashes"):
        return list(iocextract.extract_sha256_hashes(text))
    # Fallback: filter hashes by length (64 chars for SHA256)
    all_hashes = list(iocextract.extract_hashes(text))
    return [h for h in all_hashes if len(h) == 64]


def extract_sha512_hashes(text: str) -> list[str]:
    """Extract SHA512 hashes from text.

    Args:
        text: The text content to extract SHA512 hashes from.

    Returns:
        List of extracted SHA512 hashes.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()
    if hasattr(iocextract, "extract_sha512_hashes"):
        return list(iocextract.extract_sha512_hashes(text))
    # Fallback: filter hashes by length (128 chars for SHA512)
    all_hashes = list(iocextract.extract_hashes(text))
    return [h for h in all_hashes if len(h) == 128]


# =============================================================================
# Legacy compatibility function (matches original hamburglar.py -i behavior)
# =============================================================================


def extract_iocs_legacy(text: str) -> dict[str, list[str]]:
    """Extract IOCs in the same format as original hamburglar.py -i flag.

    This function matches the behavior of the original _sniff_text function
    when args.ioc was True.

    Args:
        text: The text content to extract IOCs from.

    Returns:
        Dictionary with keys: "urls", "ips", "emails", "hashes", "rules"
        Only keys with non-empty lists are included.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()

    results: dict[str, list[str]] = {}

    urls = list(iocextract.extract_urls(text))
    ips = list(iocextract.extract_ips(text))
    emails = list(iocextract.extract_emails(text))
    hashes = list(iocextract.extract_hashes(text))
    rules = list(iocextract.extract_yara_rules(text))

    if urls:
        results["urls"] = urls
    if ips:
        results["ips"] = ips
    if emails:
        results["emails"] = emails
    if hashes:
        results["hashes"] = hashes
    if rules:
        results["rules"] = rules

    return results


def extract_all_iocs(text: str, refang: bool = False) -> dict[str, list[str]]:
    """Extract all IOC types from text.

    Unlike extract_iocs_legacy, this function always includes all keys
    even if the lists are empty.

    Args:
        text: The text content to extract IOCs from.
        refang: If True, convert defanged IOCs to proper format.

    Returns:
        Dictionary with all IOC types as keys.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """
    _require_iocextract()

    return {
        "urls": list(iocextract.extract_urls(text, refang=refang)),
        "ips": list(iocextract.extract_ips(text, refang=refang)),
        "emails": list(iocextract.extract_emails(text, refang=refang)),
        "hashes": list(iocextract.extract_hashes(text)),
        "yara_rules": list(iocextract.extract_yara_rules(text)),
    }


# =============================================================================
# IOC Detector implementation
# =============================================================================


class IOCExtractDetector(BaseDetector):
    """Detector that uses iocextract library to find Indicators of Compromise.

    This detector wraps the iocextract library to extract various IOC types
    from file content. Each IOC type is returned as a separate Finding.

    IOC types detected:
    - URLs (including defanged URLs like hxxp://)
    - IP addresses (both IPv4 and IPv6)
    - Email addresses
    - Hash values (MD5, SHA1, SHA256, SHA512)
    - YARA rules embedded in text

    Example:
        detector = IOCExtractDetector()
        findings = detector.detect(content, file_path)

        # With refanging enabled (converts hxxp:// to http://):
        detector = IOCExtractDetector(refang=True)

        # With specific IOC types only:
        detector = IOCExtractDetector(ioc_types=["urls", "ips"])

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed.
    """

    # Mapping of IOC types to their extraction functions and severity levels
    IOC_TYPES: dict[str, tuple[str, Severity]] = {
        "urls": ("extract_urls", Severity.LOW),
        "ips": ("extract_ips", Severity.LOW),
        "emails": ("extract_emails", Severity.LOW),
        "hashes": ("extract_hashes", Severity.MEDIUM),
        "yara_rules": ("extract_yara_rules", Severity.INFO),
    }

    def __init__(
        self,
        ioc_types: list[str] | None = None,
        refang: bool = False,
    ) -> None:
        """Initialize the IOCExtractDetector.

        Args:
            ioc_types: List of IOC types to extract. If None, all types are extracted.
                      Valid types: "urls", "ips", "emails", "hashes", "yara_rules"
            refang: If True, convert defanged IOCs to proper format
                   (e.g., hxxp:// -> http://).

        Raises:
            IOCExtractNotAvailable: If iocextract is not installed.
            ValueError: If an invalid IOC type is specified.
        """
        _require_iocextract()

        if ioc_types is None:
            self._ioc_types = list(self.IOC_TYPES.keys())
        else:
            # Validate IOC types
            invalid_types = set(ioc_types) - set(self.IOC_TYPES.keys())
            if invalid_types:
                raise ValueError(
                    f"Invalid IOC types: {invalid_types}. "
                    f"Valid types are: {list(self.IOC_TYPES.keys())}"
                )
            self._ioc_types = ioc_types

        self._refang = refang

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "iocextract"

    @property
    def ioc_types(self) -> list[str]:
        """Return the list of IOC types being extracted."""
        return self._ioc_types.copy()

    @property
    def refang(self) -> bool:
        """Return whether refanging is enabled."""
        return self._refang

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Detect IOCs in the given content.

        Args:
            content: The file content to analyze.
            file_path: The path to the file being analyzed.

        Returns:
            A list of Finding objects for each IOC type with matches.
        """
        findings: list[Finding] = []

        for ioc_type in self._ioc_types:
            func_name, severity = self.IOC_TYPES[ioc_type]

            # Get the extraction function
            extract_func = getattr(iocextract, func_name)

            # Extract IOCs (handle refang parameter for functions that support it)
            if ioc_type in ("urls", "ips", "emails"):
                matches = list(extract_func(content, refang=self._refang))
            else:
                matches = list(extract_func(content))

            if matches:
                # Deduplicate while preserving order
                unique_matches = list(dict.fromkeys(matches))

                findings.append(
                    Finding(
                        file_path=file_path,
                        detector_name=f"iocextract:{ioc_type}",
                        matches=unique_matches,
                        severity=severity,
                        metadata={
                            "ioc_type": ioc_type,
                            "match_count": len(unique_matches),
                            "refanged": self._refang if ioc_type in ("urls", "ips", "emails") else False,
                        },
                    )
                )

        return findings


# =============================================================================
# Fallback detector (when iocextract is not available)
# =============================================================================


class IOCExtractFallbackDetector(BaseDetector):
    """Fallback detector that returns no findings when iocextract is unavailable.

    This detector can be used as a drop-in replacement for IOCExtractDetector
    when iocextract is not installed. It logs a warning but does not fail.
    """

    def __init__(self, **kwargs: Any) -> None:
        """Initialize the fallback detector.

        All arguments are ignored.
        """
        pass

    @property
    def name(self) -> str:
        """Return the detector name."""
        return "iocextract-fallback"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Return empty findings list.

        Args:
            content: The file content (ignored).
            file_path: The path to the file (ignored).

        Returns:
            Empty list of findings.
        """
        return []


def get_detector(
    ioc_types: list[str] | None = None,
    refang: bool = False,
    fallback: bool = True,
) -> BaseDetector:
    """Get an IOC detector, with optional fallback if iocextract is not available.

    This is a convenience function that returns either an IOCExtractDetector
    (if iocextract is available) or a fallback detector (if not).

    Args:
        ioc_types: List of IOC types to extract. If None, all types are extracted.
        refang: If True, convert defanged IOCs to proper format.
        fallback: If True, return a fallback detector instead of raising an error
                 when iocextract is not available.

    Returns:
        Either IOCExtractDetector or IOCExtractFallbackDetector.

    Raises:
        IOCExtractNotAvailable: If iocextract is not installed and fallback is False.
    """
    if is_available():
        return IOCExtractDetector(ioc_types=ioc_types, refang=refang)
    elif fallback:
        return IOCExtractFallbackDetector()
    else:
        raise IOCExtractNotAvailable()


__all__ = [
    # Availability checking
    "is_available",
    "get_import_error",
    "IOCExtractNotAvailable",
    # Wrapper functions
    "extract_urls",
    "extract_ips",
    "extract_emails",
    "extract_hashes",
    "extract_yara_rules",
    "extract_ipv4s",
    "extract_ipv6s",
    "extract_md5_hashes",
    "extract_sha1_hashes",
    "extract_sha256_hashes",
    "extract_sha512_hashes",
    # Legacy compatibility
    "extract_iocs_legacy",
    "extract_all_iocs",
    # Detectors
    "IOCExtractDetector",
    "IOCExtractFallbackDetector",
    "get_detector",
]
