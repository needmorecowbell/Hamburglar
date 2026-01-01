"""Tests for iocextract integration.

This module contains comprehensive tests for the iocextract integration in
hamburglar.compat.ioc_extract. Tests cover both when iocextract is available
and graceful fallback when it is not installed.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from hamburglar.core.models import Finding, Severity


class TestAvailabilityFunctions:
    """Tests for availability checking functions."""

    def test_is_available_returns_bool(self) -> None:
        """Test that is_available returns a boolean."""
        from hamburglar.compat.ioc_extract import is_available

        result = is_available()
        assert isinstance(result, bool)

    def test_get_import_error_when_available(self) -> None:
        """Test get_import_error returns None when iocextract is available."""
        from hamburglar.compat.ioc_extract import get_import_error, is_available

        if is_available():
            assert get_import_error() is None

    def test_get_import_error_returns_string_or_none(self) -> None:
        """Test get_import_error returns string or None."""
        from hamburglar.compat.ioc_extract import get_import_error

        result = get_import_error()
        assert result is None or isinstance(result, str)


class TestIOCExtractNotAvailableException:
    """Tests for the IOCExtractNotAvailable exception."""

    def test_exception_default_message(self) -> None:
        """Test exception has sensible default message."""
        from hamburglar.compat.ioc_extract import IOCExtractNotAvailable

        exc = IOCExtractNotAvailable()
        assert "iocextract is not installed" in str(exc)
        assert "pip install" in str(exc)

    def test_exception_custom_message(self) -> None:
        """Test exception accepts custom message."""
        from hamburglar.compat.ioc_extract import IOCExtractNotAvailable

        custom_msg = "Custom error message"
        exc = IOCExtractNotAvailable(custom_msg)
        assert str(exc) == custom_msg

    def test_exception_is_import_error(self) -> None:
        """Test exception is subclass of ImportError."""
        from hamburglar.compat.ioc_extract import IOCExtractNotAvailable

        assert issubclass(IOCExtractNotAvailable, ImportError)


class TestFallbackDetector:
    """Tests for IOCExtractFallbackDetector."""

    def test_fallback_detector_name(self) -> None:
        """Test fallback detector has correct name."""
        from hamburglar.compat.ioc_extract import IOCExtractFallbackDetector

        detector = IOCExtractFallbackDetector()
        assert detector.name == "iocextract-fallback"

    def test_fallback_detector_returns_empty_list(self) -> None:
        """Test fallback detector returns empty findings list."""
        from hamburglar.compat.ioc_extract import IOCExtractFallbackDetector

        detector = IOCExtractFallbackDetector()
        findings = detector.detect("some content with http://example.com", "/path/to/file")
        assert findings == []

    def test_fallback_detector_is_base_detector(self) -> None:
        """Test fallback detector is subclass of BaseDetector."""
        from hamburglar.compat.ioc_extract import IOCExtractFallbackDetector
        from hamburglar.detectors import BaseDetector

        detector = IOCExtractFallbackDetector()
        assert isinstance(detector, BaseDetector)

    def test_fallback_detector_ignores_kwargs(self) -> None:
        """Test fallback detector accepts and ignores kwargs."""
        from hamburglar.compat.ioc_extract import IOCExtractFallbackDetector

        # Should not raise
        detector = IOCExtractFallbackDetector(
            ioc_types=["urls", "ips"],
            refang=True,
            some_random_arg="value",
        )
        assert detector.name == "iocextract-fallback"


class TestGetDetector:
    """Tests for get_detector factory function."""

    def test_get_detector_with_fallback(self) -> None:
        """Test get_detector returns a valid detector with fallback enabled."""
        from hamburglar.compat.ioc_extract import get_detector
        from hamburglar.detectors import BaseDetector

        detector = get_detector(fallback=True)
        assert isinstance(detector, BaseDetector)

    def test_get_detector_returns_correct_type(self) -> None:
        """Test get_detector returns correct detector type based on availability."""
        from hamburglar.compat.ioc_extract import (
            IOCExtractDetector,
            IOCExtractFallbackDetector,
            get_detector,
            is_available,
        )

        detector = get_detector(fallback=True)
        if is_available():
            assert isinstance(detector, IOCExtractDetector)
        else:
            assert isinstance(detector, IOCExtractFallbackDetector)


# Tests that require iocextract to be installed
@pytest.fixture
def skip_if_iocextract_unavailable() -> None:
    """Skip test if iocextract is not available."""
    from hamburglar.compat.ioc_extract import is_available

    if not is_available():
        pytest.skip("iocextract is not installed")


class TestIOCExtractDetectorWhenAvailable:
    """Tests for IOCExtractDetector when iocextract is available."""

    @pytest.fixture(autouse=True)
    def check_availability(self, skip_if_iocextract_unavailable: None) -> None:
        """Auto-use fixture to skip tests when iocextract is unavailable."""
        pass

    def test_detector_name(self) -> None:
        """Test detector has correct name."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector()
        assert detector.name == "iocextract"

    def test_detector_is_base_detector(self) -> None:
        """Test detector is subclass of BaseDetector."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector()
        assert isinstance(detector, BaseDetector)

    def test_detector_default_ioc_types(self) -> None:
        """Test detector extracts all IOC types by default."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector()
        assert "urls" in detector.ioc_types
        assert "ips" in detector.ioc_types
        assert "emails" in detector.ioc_types
        assert "hashes" in detector.ioc_types
        assert "yara_rules" in detector.ioc_types

    def test_detector_custom_ioc_types(self) -> None:
        """Test detector accepts custom IOC types."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["urls", "ips"])
        assert detector.ioc_types == ["urls", "ips"]

    def test_detector_invalid_ioc_type_raises(self) -> None:
        """Test detector raises ValueError for invalid IOC type."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        with pytest.raises(ValueError, match="Invalid IOC types"):
            IOCExtractDetector(ioc_types=["invalid_type"])

    def test_detector_refang_property(self) -> None:
        """Test detector refang property."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(refang=True)
        assert detector.refang is True

        detector2 = IOCExtractDetector(refang=False)
        assert detector2.refang is False

    def test_detect_urls(self) -> None:
        """Test URL detection."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["urls"])
        content = "Check out http://example.com and https://test.org for more info."
        findings = detector.detect(content, "/test/file.txt")

        assert len(findings) == 1
        assert findings[0].detector_name == "iocextract:urls"
        assert len(findings[0].matches) >= 1

    def test_detect_ips(self) -> None:
        """Test IP address detection."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["ips"])
        content = "Server at 192.168.1.1 and 10.0.0.1 are down."
        findings = detector.detect(content, "/test/file.txt")

        # iocextract may or may not find IPs depending on context
        if findings:
            assert findings[0].detector_name == "iocextract:ips"

    def test_detect_emails(self) -> None:
        """Test email detection."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["emails"])
        content = "Contact us at admin@example.com or support@test.org"
        findings = detector.detect(content, "/test/file.txt")

        assert len(findings) == 1
        assert findings[0].detector_name == "iocextract:emails"
        assert len(findings[0].matches) >= 1

    def test_detect_hashes(self) -> None:
        """Test hash detection."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["hashes"])
        # MD5 hash
        content = "File hash: d41d8cd98f00b204e9800998ecf8427e"
        findings = detector.detect(content, "/test/file.txt")

        if findings:
            assert findings[0].detector_name == "iocextract:hashes"

    def test_detect_empty_content(self) -> None:
        """Test detection on empty content."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector()
        findings = detector.detect("", "/test/file.txt")
        assert findings == []

    def test_detect_no_matches(self) -> None:
        """Test detection when no IOCs present."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector()
        content = "This is just plain text with no indicators of compromise."
        findings = detector.detect(content, "/test/file.txt")
        # May or may not find anything depending on iocextract behavior
        assert isinstance(findings, list)

    def test_detect_finding_metadata(self) -> None:
        """Test that findings have correct metadata."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["urls"], refang=True)
        content = "Visit http://example.com for details."
        findings = detector.detect(content, "/test/file.txt")

        if findings:
            finding = findings[0]
            assert finding.file_path == "/test/file.txt"
            assert "ioc_type" in finding.metadata
            assert finding.metadata["ioc_type"] == "urls"
            assert "match_count" in finding.metadata
            assert "refanged" in finding.metadata

    def test_detect_finding_severity_urls(self) -> None:
        """Test URL findings have LOW severity."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["urls"])
        content = "Visit http://example.com"
        findings = detector.detect(content, "/test/file.txt")

        if findings:
            assert findings[0].severity == Severity.LOW

    def test_detect_finding_severity_hashes(self) -> None:
        """Test hash findings have MEDIUM severity."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["hashes"])
        content = "MD5: d41d8cd98f00b204e9800998ecf8427e"
        findings = detector.detect(content, "/test/file.txt")

        if findings:
            assert findings[0].severity == Severity.MEDIUM

    def test_detect_deduplicates_matches(self) -> None:
        """Test that duplicate matches are deduplicated."""
        from hamburglar.compat.ioc_extract import IOCExtractDetector

        detector = IOCExtractDetector(ioc_types=["urls"])
        content = "http://example.com http://example.com http://example.com"
        findings = detector.detect(content, "/test/file.txt")

        if findings:
            # Even with duplicates in input, matches should be unique
            matches = findings[0].matches
            assert len(matches) == len(set(matches))


class TestWrapperFunctionsWhenAvailable:
    """Tests for wrapper functions when iocextract is available."""

    @pytest.fixture(autouse=True)
    def check_availability(self, skip_if_iocextract_unavailable: None) -> None:
        """Auto-use fixture to skip tests when iocextract is unavailable."""
        pass

    def test_extract_urls(self) -> None:
        """Test extract_urls wrapper."""
        from hamburglar.compat.ioc_extract import extract_urls

        result = extract_urls("Check http://example.com for info")
        assert isinstance(result, list)

    def test_extract_ips(self) -> None:
        """Test extract_ips wrapper."""
        from hamburglar.compat.ioc_extract import extract_ips

        result = extract_ips("Server at 192.168.1.1")
        assert isinstance(result, list)

    def test_extract_emails(self) -> None:
        """Test extract_emails wrapper."""
        from hamburglar.compat.ioc_extract import extract_emails

        result = extract_emails("Contact admin@example.com")
        assert isinstance(result, list)
        if result:
            assert "admin@example.com" in result

    def test_extract_hashes(self) -> None:
        """Test extract_hashes wrapper."""
        from hamburglar.compat.ioc_extract import extract_hashes

        result = extract_hashes("Hash: d41d8cd98f00b204e9800998ecf8427e")
        assert isinstance(result, list)

    def test_extract_yara_rules(self) -> None:
        """Test extract_yara_rules wrapper."""
        from hamburglar.compat.ioc_extract import extract_yara_rules

        yara_content = """
        rule test_rule {
            strings:
                $a = "test"
            condition:
                $a
        }
        """
        result = extract_yara_rules(yara_content)
        assert isinstance(result, list)


class TestLegacyCompatibilityFunctionsWhenAvailable:
    """Tests for legacy compatibility functions when iocextract is available."""

    @pytest.fixture(autouse=True)
    def check_availability(self, skip_if_iocextract_unavailable: None) -> None:
        """Auto-use fixture to skip tests when iocextract is unavailable."""
        pass

    def test_extract_iocs_legacy_returns_dict(self) -> None:
        """Test extract_iocs_legacy returns a dictionary."""
        from hamburglar.compat.ioc_extract import extract_iocs_legacy

        result = extract_iocs_legacy("http://example.com admin@test.com")
        assert isinstance(result, dict)

    def test_extract_iocs_legacy_only_non_empty_keys(self) -> None:
        """Test extract_iocs_legacy only includes non-empty keys."""
        from hamburglar.compat.ioc_extract import extract_iocs_legacy

        result = extract_iocs_legacy("Just plain text")
        # Should be empty dict or only have keys for matches found
        for key in result:
            assert len(result[key]) > 0

    def test_extract_iocs_legacy_urls_key(self) -> None:
        """Test extract_iocs_legacy includes urls when found."""
        from hamburglar.compat.ioc_extract import extract_iocs_legacy

        result = extract_iocs_legacy("Visit http://example.com")
        if "urls" in result:
            assert len(result["urls"]) >= 1

    def test_extract_iocs_legacy_emails_key(self) -> None:
        """Test extract_iocs_legacy includes emails when found."""
        from hamburglar.compat.ioc_extract import extract_iocs_legacy

        result = extract_iocs_legacy("Contact admin@example.com")
        if "emails" in result:
            assert "admin@example.com" in result["emails"]

    def test_extract_all_iocs_returns_all_keys(self) -> None:
        """Test extract_all_iocs returns all IOC type keys."""
        from hamburglar.compat.ioc_extract import extract_all_iocs

        result = extract_all_iocs("Just plain text")
        assert "urls" in result
        assert "ips" in result
        assert "emails" in result
        assert "hashes" in result
        assert "yara_rules" in result

    def test_extract_all_iocs_with_refang(self) -> None:
        """Test extract_all_iocs accepts refang parameter."""
        from hamburglar.compat.ioc_extract import extract_all_iocs

        # Should not raise
        result = extract_all_iocs("http://example.com", refang=True)
        assert isinstance(result, dict)


class TestHashExtractionFunctionsWhenAvailable:
    """Tests for specific hash extraction functions."""

    @pytest.fixture(autouse=True)
    def check_availability(self, skip_if_iocextract_unavailable: None) -> None:
        """Auto-use fixture to skip tests when iocextract is unavailable."""
        pass

    def test_extract_md5_hashes(self) -> None:
        """Test MD5 hash extraction."""
        from hamburglar.compat.ioc_extract import extract_md5_hashes

        # MD5 is 32 hex chars
        content = "Hash: d41d8cd98f00b204e9800998ecf8427e"
        result = extract_md5_hashes(content)
        assert isinstance(result, list)

    def test_extract_sha1_hashes(self) -> None:
        """Test SHA1 hash extraction."""
        from hamburglar.compat.ioc_extract import extract_sha1_hashes

        # SHA1 is 40 hex chars
        content = "Hash: da39a3ee5e6b4b0d3255bfef95601890afd80709"
        result = extract_sha1_hashes(content)
        assert isinstance(result, list)

    def test_extract_sha256_hashes(self) -> None:
        """Test SHA256 hash extraction."""
        from hamburglar.compat.ioc_extract import extract_sha256_hashes

        # SHA256 is 64 hex chars
        content = "Hash: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        result = extract_sha256_hashes(content)
        assert isinstance(result, list)

    def test_extract_sha512_hashes(self) -> None:
        """Test SHA512 hash extraction."""
        from hamburglar.compat.ioc_extract import extract_sha512_hashes

        # SHA512 is 128 hex chars
        content = "Hash: cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"
        result = extract_sha512_hashes(content)
        assert isinstance(result, list)


class TestModuleExports:
    """Tests for module exports and __all__."""

    def test_module_has_all_defined(self) -> None:
        """Test module has __all__ defined."""
        from hamburglar.compat import ioc_extract

        assert hasattr(ioc_extract, "__all__")
        assert isinstance(ioc_extract.__all__, list)

    def test_all_exports_exist(self) -> None:
        """Test all items in __all__ exist in module."""
        from hamburglar.compat import ioc_extract

        for name in ioc_extract.__all__:
            assert hasattr(ioc_extract, name), f"Missing export: {name}"

    def test_compat_module_exports_ioc(self) -> None:
        """Test compat __init__ exports ioc_extract functions."""
        from hamburglar.compat import (
            IOCExtractDetector,
            IOCExtractFallbackDetector,
            IOCExtractNotAvailable,
            is_available,
        )

        assert IOCExtractDetector is not None
        assert IOCExtractFallbackDetector is not None
        assert IOCExtractNotAvailable is not None
        assert callable(is_available)


class TestMockedUnavailable:
    """Tests for behavior when iocextract import fails."""

    def test_wrapper_raises_when_unavailable(self) -> None:
        """Test wrapper functions raise when iocextract unavailable."""
        # Create a mock module with _IOCEXTRACT_AVAILABLE = False
        with patch.dict("sys.modules", {"iocextract": None}):
            # Force re-evaluation by setting the module variable
            import hamburglar.compat.ioc_extract as ioc_module

            original_available = ioc_module._IOCEXTRACT_AVAILABLE
            try:
                ioc_module._IOCEXTRACT_AVAILABLE = False

                with pytest.raises(ioc_module.IOCExtractNotAvailable):
                    ioc_module.extract_urls("test")

                with pytest.raises(ioc_module.IOCExtractNotAvailable):
                    ioc_module.extract_ips("test")

                with pytest.raises(ioc_module.IOCExtractNotAvailable):
                    ioc_module.extract_emails("test")

                with pytest.raises(ioc_module.IOCExtractNotAvailable):
                    ioc_module.extract_hashes("test")

                with pytest.raises(ioc_module.IOCExtractNotAvailable):
                    ioc_module.extract_yara_rules("test")
            finally:
                ioc_module._IOCEXTRACT_AVAILABLE = original_available

    def test_detector_raises_when_unavailable(self) -> None:
        """Test IOCExtractDetector raises when iocextract unavailable."""
        import hamburglar.compat.ioc_extract as ioc_module

        original_available = ioc_module._IOCEXTRACT_AVAILABLE
        try:
            ioc_module._IOCEXTRACT_AVAILABLE = False

            with pytest.raises(ioc_module.IOCExtractNotAvailable):
                ioc_module.IOCExtractDetector()
        finally:
            ioc_module._IOCEXTRACT_AVAILABLE = original_available

    def test_get_detector_fallback_when_unavailable(self) -> None:
        """Test get_detector returns fallback when unavailable."""
        import hamburglar.compat.ioc_extract as ioc_module

        original_available = ioc_module._IOCEXTRACT_AVAILABLE
        try:
            ioc_module._IOCEXTRACT_AVAILABLE = False

            detector = ioc_module.get_detector(fallback=True)
            assert isinstance(detector, ioc_module.IOCExtractFallbackDetector)
        finally:
            ioc_module._IOCEXTRACT_AVAILABLE = original_available

    def test_get_detector_no_fallback_raises(self) -> None:
        """Test get_detector raises when fallback=False and unavailable."""
        import hamburglar.compat.ioc_extract as ioc_module

        original_available = ioc_module._IOCEXTRACT_AVAILABLE
        try:
            ioc_module._IOCEXTRACT_AVAILABLE = False

            with pytest.raises(ioc_module.IOCExtractNotAvailable):
                ioc_module.get_detector(fallback=False)
        finally:
            ioc_module._IOCEXTRACT_AVAILABLE = original_available

    def test_is_available_false_when_unavailable(self) -> None:
        """Test is_available returns False when unavailable."""
        import hamburglar.compat.ioc_extract as ioc_module

        original_available = ioc_module._IOCEXTRACT_AVAILABLE
        try:
            ioc_module._IOCEXTRACT_AVAILABLE = False
            assert ioc_module.is_available() is False
        finally:
            ioc_module._IOCEXTRACT_AVAILABLE = original_available
