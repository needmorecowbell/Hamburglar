"""Tests for file encoding handling in Hamburglar.

This module contains tests verifying that:
- The scanner handles UTF-8 files correctly
- The scanner handles Latin-1/ISO-8859-1 files
- The scanner handles files with mixed/broken encoding (doesn't crash)
- The scanner handles empty files gracefully
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hamburglar.core.models import ScanConfig
from hamburglar.core.scanner import Scanner
from hamburglar.detectors.regex_detector import RegexDetector


class TestUTF8FileHandling:
    """Tests that the scanner correctly handles UTF-8 encoded files."""

    @pytest.mark.asyncio
    async def test_standard_utf8_ascii_content(self, tmp_path: Path) -> None:
        """Test that standard ASCII content (valid UTF-8) is processed correctly."""
        test_file = tmp_path / "ascii.txt"
        content = "Contact us at admin@example.com for more info."
        test_file.write_text(content, encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "admin@example.com" in email_findings[0].matches

    @pytest.mark.asyncio
    async def test_utf8_with_accented_characters(self, tmp_path: Path) -> None:
        """Test that UTF-8 files with accented characters are processed."""
        test_file = tmp_path / "accents.txt"
        # Use ASCII-only email address since the email regex uses [A-Za-z0-9]
        content = """
        Café résumé with naïve approach.
        Contact: cafe.owner@example.com
        German greetings: Grüß Gott
        """
        test_file.write_text(content, encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "cafe.owner@example.com" in email_findings[0].matches

    @pytest.mark.asyncio
    async def test_utf8_with_unicode_symbols(self, tmp_path: Path) -> None:
        """Test that UTF-8 files with Unicode symbols are processed."""
        test_file = tmp_path / "symbols.txt"
        content = """
        Prices: €100, £50, ¥1000
        Math: ∑ ∏ √ ∞
        Contact: pricing@example.com
        AWS: AKIAIOSFODNN7EXAMPLE
        """
        test_file.write_text(content, encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    @pytest.mark.asyncio
    async def test_utf8_with_cjk_characters(self, tmp_path: Path) -> None:
        """Test that UTF-8 files with CJK characters are processed."""
        test_file = tmp_path / "cjk.txt"
        content = """
        日本語のテスト
        中文測試
        한국어 테스트
        AWS_KEY=AKIAIOSFODNN7EXAMPLE
        Email: test@example.com
        """
        test_file.write_text(content, encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(aws_findings) == 1
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_utf8_with_emoji(self, tmp_path: Path) -> None:
        """Test that UTF-8 files with emoji are processed without errors."""
        test_file = tmp_path / "emoji.txt"
        content = """
        🔐 Security Configuration 🔐
        ⚠️ Warning: Contains secrets!
        📧 Email: security@example.com
        🔑 API_KEY = AKIAIOSFODNN7EXAMPLE
        ✅ Configuration complete!
        """
        test_file.write_text(content, encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        assert len(email_findings) == 1
        assert len(aws_findings) == 1

    @pytest.mark.asyncio
    async def test_utf8_bom_file(self, tmp_path: Path) -> None:
        """Test that UTF-8 files with BOM are processed correctly."""
        test_file = tmp_path / "bom.txt"
        # Write UTF-8 with BOM
        content = "Contact: admin@example.com"
        with open(test_file, "wb") as f:
            f.write(b"\xef\xbb\xbf")  # UTF-8 BOM
            f.write(content.encode("utf-8"))

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestLatin1FileHandling:
    """Tests that the scanner correctly handles Latin-1/ISO-8859-1 encoded files."""

    @pytest.mark.asyncio
    async def test_latin1_basic_content(self, tmp_path: Path) -> None:
        """Test that Latin-1 encoded files are processed correctly."""
        test_file = tmp_path / "latin1.txt"
        content = "Contact: admin@example.com\nCopyright © 2024"
        # Write as Latin-1 (bytes 0x00-0xff map directly)
        test_file.write_bytes(content.encode("latin-1"))

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_latin1_with_extended_chars(self, tmp_path: Path) -> None:
        """Test Latin-1 files with characters outside ASCII range."""
        test_file = tmp_path / "latin1_extended.txt"
        # Latin-1 specific characters (not valid UTF-8)
        # Using bytes that are valid in Latin-1 but not as UTF-8 sequences
        content = b"Temp: 25\xb0C\nEmail: temp@example.com\nPrice: \xa3100"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "temp@example.com" in email_findings[0].matches

    @pytest.mark.asyncio
    async def test_latin1_windows_1252_compatible(self, tmp_path: Path) -> None:
        """Test handling of Windows-1252 compatible content (similar to Latin-1)."""
        test_file = tmp_path / "windows.txt"
        # Windows-1252 "smart quotes" and em-dash
        # Note: Some of these map differently in Windows-1252 vs Latin-1
        content = b'The "smart" quote\x97test\nEmail: smart@example.com'
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should still find the email
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_latin1_with_fractions(self, tmp_path: Path) -> None:
        """Test Latin-1 files with fraction characters."""
        test_file = tmp_path / "fractions.txt"
        # Latin-1 fractions: ½ (0xbd), ¼ (0xbc), ¾ (0xbe)
        content = b"Mix: \xbc cup + \xbd cup = \xbe cup\nRecipe: chef@example.com"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestMixedBrokenEncodingHandling:
    """Tests that the scanner handles mixed or broken encoding gracefully."""

    @pytest.mark.asyncio
    async def test_mixed_utf8_and_latin1(self, tmp_path: Path) -> None:
        """Test handling of files with mixed UTF-8 and Latin-1 content."""
        test_file = tmp_path / "mixed.txt"
        # Start with valid UTF-8, then add invalid bytes
        content = b"Valid UTF-8: Hello\n"
        content += b"Invalid sequence: \xff\xfe\n"  # Invalid UTF-8
        content += b"Email: mixed@example.com\n"
        content += b"AWS: AKIAIOSFODNN7EXAMPLE\n"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        # Should not crash, should fall back to Latin-1
        result = await scanner.scan()

        # Should still find the secrets
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        assert len(email_findings) == 1
        assert len(aws_findings) == 1

    @pytest.mark.asyncio
    async def test_invalid_utf8_sequences(self, tmp_path: Path) -> None:
        """Test handling of files with invalid UTF-8 sequences."""
        test_file = tmp_path / "invalid_utf8.txt"
        # Create content with invalid UTF-8 continuation bytes
        content = b"Text before\n"
        content += b"\x80\x81\x82\x83\n"  # Invalid UTF-8 (orphan continuation bytes)
        content += b"Secret: admin@example.com\n"
        content += b"More: \xc0\xc1\n"  # Invalid UTF-8 (overlong encoding starts)
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        # Should not crash
        result = await scanner.scan()

        # Should fall back to Latin-1 and find the email
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_truncated_utf8_multibyte(self, tmp_path: Path) -> None:
        """Test handling of truncated UTF-8 multibyte sequences."""
        test_file = tmp_path / "truncated.txt"
        # Valid UTF-8 followed by truncated multibyte sequence
        content = b"Normal text\n"
        content += b"Truncated: \xe2\x82"  # Incomplete € symbol (should be \xe2\x82\xac)
        content += b"\nEmail: truncated@example.com\n"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        # Should not crash
        result = await scanner.scan()

        # Should still find the email
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_null_bytes_in_text(self, tmp_path: Path) -> None:
        """Test handling of null bytes embedded in text files."""
        test_file = tmp_path / "nulls.txt"
        # Text with occasional null bytes (might indicate broken encoding)
        content = b"Text with\x00null\x00bytes\nEmail: null@example.com\n"
        # Pad with enough text to avoid binary detection
        content += b"This is normal text. " * 50
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should either process or skip (depending on binary detection)
        # Main goal is no crash
        assert result.stats["files_scanned"] + result.stats["files_skipped"] == 1

    @pytest.mark.asyncio
    async def test_all_byte_values(self, tmp_path: Path) -> None:
        """Test handling of file containing all possible byte values."""
        test_file = tmp_path / "all_bytes.txt"
        # Create content with all byte values 0-255
        # Put the secret at the beginning to ensure it's in the sample
        content = b"Email: allbytes@example.com\n"
        content += bytes(range(256))
        # Add more text to dilute binary content
        content += b"\nNormal text here. " * 100
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        # Should not crash regardless of outcome
        result = await scanner.scan()
        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_random_binary_with_text_sections(self, tmp_path: Path) -> None:
        """Test handling of file with random binary data and text sections."""
        test_file = tmp_path / "hybrid.dat"
        # Mix of binary garbage and readable text
        content = b"\x00\x01\x02\x03\x04\x05"
        content += b"READABLE SECTION: admin@example.com\n"
        content += b"\xff\xfe\xfd\xfc\xfb\xfa"
        content += b"ANOTHER SECTION: AKIAIOSFODNN7EXAMPLE\n"
        content += b"\x10\x11\x12\x13\x14\x15"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        # Should not crash - may be detected as binary and skipped
        result = await scanner.scan()
        assert isinstance(result.findings, list)


class TestEmptyFileHandling:
    """Tests that the scanner handles empty files gracefully."""

    @pytest.mark.asyncio
    async def test_completely_empty_file(self, tmp_path: Path) -> None:
        """Test scanning a completely empty file (0 bytes)."""
        test_file = tmp_path / "empty.txt"
        test_file.write_bytes(b"")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_whitespace_only_file(self, tmp_path: Path) -> None:
        """Test scanning a file with only whitespace."""
        test_file = tmp_path / "whitespace.txt"
        test_file.write_text("   \n\t\n   \n", encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_newlines_only_file(self, tmp_path: Path) -> None:
        """Test scanning a file with only newlines."""
        test_file = tmp_path / "newlines.txt"
        test_file.write_text("\n\n\n\n\n", encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_single_character_file(self, tmp_path: Path) -> None:
        """Test scanning a file with a single character."""
        test_file = tmp_path / "single.txt"
        test_file.write_text("x", encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_single_newline_file(self, tmp_path: Path) -> None:
        """Test scanning a file with a single newline."""
        test_file = tmp_path / "single_newline.txt"
        test_file.write_text("\n", encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        assert result.stats["files_scanned"] == 1
        assert len(result.findings) == 0


class TestEncodingFallbackBehavior:
    """Tests that encoding fallback works correctly."""

    @pytest.mark.asyncio
    async def test_utf8_fallback_still_finds_secrets(self, tmp_path: Path) -> None:
        """Test that files failing UTF-8 decode still get scanned via Latin-1 fallback."""
        test_file = tmp_path / "fallback.txt"
        # Content that will fail UTF-8 decoding but still contains secrets
        content = b"Email: test@example.com\nBad byte: \xff\n"
        content += b"AWS: AKIAIOSFODNN7EXAMPLE\n"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should find the email after fallback
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

        # Should also find the AWS key
        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    @pytest.mark.asyncio
    async def test_utf8_fallback_processes_entire_file(self, tmp_path: Path) -> None:
        """Test that Latin-1 fallback processes the entire file, not just valid parts."""
        test_file = tmp_path / "mixed_bytes.txt"
        # Invalid UTF-8 bytes scattered throughout
        content = b"Start: first@example.com\n"
        content += b"\xff\xfe Invalid bytes here \xff\xfe\n"
        content += b"Middle: second@example.com\n"
        content += b"\x80\x81\x82 More invalid bytes \x83\x84\n"
        content += b"End: third@example.com\n"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should find all three emails (may be in one finding or multiple)
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        all_matches = []
        for finding in email_findings:
            all_matches.extend(finding.matches)

        assert "first@example.com" in all_matches
        assert "second@example.com" in all_matches
        assert "third@example.com" in all_matches

    @pytest.mark.asyncio
    async def test_pure_utf8_no_fallback_needed(self, tmp_path: Path) -> None:
        """Test that pure UTF-8 files are processed directly without fallback."""
        test_file = tmp_path / "valid_utf8.txt"
        content = "Valid UTF-8 content: admin@example.com"
        test_file.write_text(content, encoding="utf-8")

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should find the email
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    @pytest.mark.asyncio
    async def test_latin1_encoded_secrets_found(self, tmp_path: Path) -> None:
        """Test that secrets in Latin-1 encoded files are found after fallback."""
        test_file = tmp_path / "latin1_secrets.txt"
        # Latin-1 encoded content with secrets
        content = "Copyright \xa9 2024\n".encode("latin-1")  # \xa9 is © in Latin-1
        content += b"API: AKIAIOSFODNN7EXAMPLE\n"
        content += b"Contact: admin@example.com\n"
        test_file.write_bytes(content)

        config = ScanConfig(target_path=test_file)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should find both secrets
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        assert len(email_findings) == 1
        assert len(aws_findings) == 1


class TestEncodingWithFixtures:
    """Tests using the test fixture files."""

    @pytest.mark.asyncio
    async def test_mixed_encoding_fixture(self) -> None:
        """Test that the mixed_encoding.txt fixture is processed correctly."""
        fixtures_path = Path(__file__).parent / "fixtures" / "mixed_encoding.txt"
        if not fixtures_path.exists():
            pytest.skip("mixed_encoding.txt fixture not found")

        config = ScanConfig(target_path=fixtures_path)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # The fixture should be processed without errors
        assert result.stats["files_scanned"] == 1
        assert result.stats["files_skipped"] == 0
        # No secrets in this fixture
        assert len(result.findings) == 0

    @pytest.mark.asyncio
    async def test_secret_file_fixture(self) -> None:
        """Test that the secret_file.txt fixture is processed correctly."""
        fixtures_path = Path(__file__).parent / "fixtures" / "secret_file.txt"
        if not fixtures_path.exists():
            pytest.skip("secret_file.txt fixture not found")

        config = ScanConfig(target_path=fixtures_path)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should find secrets
        assert result.stats["files_scanned"] == 1
        assert len(result.findings) > 0

        # Should find AWS keys
        aws_findings = [f for f in result.findings if "AWS" in f.detector_name]
        assert len(aws_findings) >= 1

        # Should find emails
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) >= 1

    @pytest.mark.asyncio
    async def test_clean_file_fixture(self) -> None:
        """Test that the clean_file.txt fixture produces no findings."""
        fixtures_path = Path(__file__).parent / "fixtures" / "clean_file.txt"
        if not fixtures_path.exists():
            pytest.skip("clean_file.txt fixture not found")

        config = ScanConfig(target_path=fixtures_path)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should process the file
        assert result.stats["files_scanned"] == 1

        # Should find no secrets
        assert len(result.findings) == 0


class TestEncodingWithMultipleFiles:
    """Tests encoding handling across multiple files in a directory."""

    @pytest.mark.asyncio
    async def test_directory_with_mixed_encodings(self, tmp_path: Path) -> None:
        """Test scanning a directory with files in different encodings."""
        # UTF-8 file
        utf8_file = tmp_path / "utf8.txt"
        utf8_file.write_text("UTF-8: admin@example.com", encoding="utf-8")

        # Latin-1 file
        latin1_file = tmp_path / "latin1.txt"
        latin1_file.write_bytes(b"Latin-1: \xe9\xe8\xe0\nEmail: latin@example.com")

        # ASCII file
        ascii_file = tmp_path / "ascii.txt"
        ascii_file.write_text("ASCII: ascii@example.com", encoding="ascii")

        config = ScanConfig(target_path=tmp_path, recursive=False)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # All 3 files should be processed
        assert result.stats["files_scanned"] == 3

        # Should find all 3 emails
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 3

    @pytest.mark.asyncio
    async def test_directory_with_some_encoding_errors(self, tmp_path: Path) -> None:
        """Test scanning continues even when some files have encoding issues."""
        # Good file
        good_file = tmp_path / "good.txt"
        good_file.write_text("Good: good@example.com", encoding="utf-8")

        # File with encoding issues (will fall back to latin-1)
        bad_file = tmp_path / "bad.txt"
        bad_file.write_bytes(b"\xff\xfe bad@example.com \xff\xfe")

        # Another good file
        good_file2 = tmp_path / "good2.txt"
        good_file2.write_text("Good2: good2@example.com", encoding="utf-8")

        config = ScanConfig(target_path=tmp_path, recursive=False)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # All files should be processed (with fallback for bad one)
        assert result.stats["files_scanned"] == 3

        # Should find emails from all files
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 3
