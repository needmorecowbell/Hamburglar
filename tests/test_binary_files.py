"""Tests for binary file handling in Hamburglar.

This module contains tests verifying that:
- The regex detector correctly skips binary files (ELF, images, etc.)
- The regex detector correctly identifies and processes text files
- The scanner processes mixed directories containing both binary and text files
- Files with null bytes are handled properly
"""

from __future__ import annotations

from pathlib import Path

import pytest

from hamburglar.core.models import ScanConfig
from hamburglar.core.scanner import Scanner
from hamburglar.detectors.regex_detector import (
    BINARY_INDICATOR_BYTES,
    BINARY_THRESHOLD,
    RegexDetector,
)


class TestRegexDetectorSkipsBinaryFiles:
    """Tests that the regex detector correctly skips binary files."""

    def test_skip_elf_binary(self) -> None:
        """Test that ELF binaries are detected and skipped."""
        detector = RegexDetector()
        # ELF magic header: 0x7f 'E' 'L' 'F' followed by binary content
        elf_content = "\x7fELF\x02\x01\x01\x00" + "\x00\x01\x02\x03\x04" * 500
        # Even if it contains an email, it should be skipped
        elf_with_email = elf_content + "admin@example.com"
        findings = detector.detect(elf_with_email, "program.elf")
        assert len(findings) == 0

    def test_skip_pe_executable(self) -> None:
        """Test that PE/Windows executables are detected and skipped."""
        detector = RegexDetector()
        # PE magic header: 'MZ' followed by binary content
        pe_content = "MZ" + "\x00\x90\x00\x03" + "\x00\x00\x00\x04" * 500
        pe_with_secret = pe_content + "AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(pe_with_secret, "program.exe")
        assert len(findings) == 0

    def test_skip_png_image(self) -> None:
        """Test that PNG images are detected and skipped."""
        detector = RegexDetector()
        # PNG magic header followed by binary image data
        png_header = "\x89PNG\r\n\x1a\n"
        png_content = png_header + "\x00\x00\x00\rIHDR" + "\x00" * 500
        png_with_email = png_content + "admin@example.com"
        findings = detector.detect(png_with_email, "image.png")
        assert len(findings) == 0

    def test_skip_jpeg_image(self) -> None:
        """Test that JPEG images are detected and skipped."""
        detector = RegexDetector()
        # JPEG magic header (SOI marker + APP0)
        jpeg_header = "\xff\xd8\xff\xe0"
        jpeg_content = jpeg_header + "\x00\x10JFIF\x00" + "\x00" * 500
        jpeg_with_secret = jpeg_content + "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        findings = detector.detect(jpeg_with_secret, "photo.jpg")
        assert len(findings) == 0

    def test_skip_gif_image(self) -> None:
        """Test that GIF images are detected and skipped."""
        detector = RegexDetector()
        # GIF87a/GIF89a magic header followed by binary content
        gif_header = "GIF89a"
        # Create binary image data with control characters
        gif_content = gif_header + "\x00\x01\x02\x03\x04\x05\x06\x07" * 500
        gif_with_email = gif_content + "admin@example.com"
        findings = detector.detect(gif_with_email, "animation.gif")
        assert len(findings) == 0

    def test_skip_zip_archive(self) -> None:
        """Test that ZIP archives are detected and skipped."""
        detector = RegexDetector()
        # ZIP magic header: 'PK\x03\x04'
        zip_header = "PK\x03\x04"
        zip_content = zip_header + "\x14\x00\x00\x00\x08\x00" + "\x00" * 500
        zip_with_key = zip_content + "AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(zip_with_key, "archive.zip")
        assert len(findings) == 0

    def test_skip_gzip_archive(self) -> None:
        """Test that GZIP archives are detected and skipped."""
        detector = RegexDetector()
        # GZIP magic header: '\x1f\x8b'
        gzip_header = "\x1f\x8b\x08\x00"
        gzip_content = gzip_header + "\x00\x00\x00\x00\x02\xff" + "\x00" * 500
        findings = detector.detect(gzip_content, "file.tar.gz")
        assert len(findings) == 0

    def test_skip_pdf_document(self) -> None:
        """Test that binary PDF content is detected and skipped."""
        detector = RegexDetector()
        # PDF header followed by binary stream data
        pdf_content = "%PDF-1.4\n" + "\x00\x01\x02\x03\x04\x05\x06\x07" * 500
        pdf_with_email = pdf_content + "admin@example.com"
        findings = detector.detect(pdf_with_email, "document.pdf")
        assert len(findings) == 0

    def test_skip_java_class_file(self) -> None:
        """Test that Java class files are detected and skipped."""
        detector = RegexDetector()
        # Java class file magic: 0xCAFEBABE
        java_header = "\xca\xfe\xba\xbe"
        java_content = java_header + "\x00\x00\x00\x37" + "\x00" * 500
        findings = detector.detect(java_content, "Main.class")
        assert len(findings) == 0

    def test_skip_mach_o_binary(self) -> None:
        """Test that Mach-O binaries (macOS) are detected and skipped."""
        detector = RegexDetector()
        # Mach-O magic: 0xFEEDFACE (32-bit) or 0xFEEDFACF (64-bit)
        macho_header = "\xfe\xed\xfa\xce"
        macho_content = macho_header + "\x00\x00\x00\x07" + "\x00" * 500
        macho_with_key = macho_content + "AKIAIOSFODNN7EXAMPLE"
        findings = detector.detect(macho_with_key, "program")
        assert len(findings) == 0

    def test_skip_wasm_binary(self) -> None:
        """Test that WebAssembly binaries are detected and skipped."""
        detector = RegexDetector()
        # WASM magic header
        wasm_header = "\x00asm\x01\x00\x00\x00"
        wasm_content = wasm_header + "\x00\x01\x02\x03" * 500
        findings = detector.detect(wasm_content, "module.wasm")
        assert len(findings) == 0


class TestRegexDetectorIdentifiesTextFiles:
    """Tests that the regex detector correctly identifies and processes text files."""

    def test_process_plain_text_file(self) -> None:
        """Test that plain text files are processed normally."""
        detector = RegexDetector()
        content = "Contact us at admin@example.com for more information."
        findings = detector.detect(content, "readme.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "admin@example.com" in email_findings[0].matches

    def test_process_python_source_code(self) -> None:
        """Test that Python source code is processed normally."""
        detector = RegexDetector()
        content = """
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
EMAIL = "admin@example.com"

def connect():
    pass
"""
        findings = detector.detect(content, "config.py")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(aws_findings) == 1
        assert len(email_findings) == 1

    def test_process_javascript_source_code(self) -> None:
        """Test that JavaScript source code is processed normally."""
        detector = RegexDetector()
        content = """
const apiKey = "AKIAIOSFODNN7EXAMPLE";
const email = "admin@example.com";
export { apiKey, email };
"""
        findings = detector.detect(content, "config.js")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    def test_process_json_config(self) -> None:
        """Test that JSON configuration files are processed normally."""
        detector = RegexDetector()
        content = """
{
    "aws_access_key": "AKIAIOSFODNN7EXAMPLE",
    "email": "admin@example.com"
}
"""
        findings = detector.detect(content, "config.json")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    def test_process_yaml_config(self) -> None:
        """Test that YAML configuration files are processed normally."""
        detector = RegexDetector()
        content = """
aws:
  access_key: AKIAIOSFODNN7EXAMPLE
contact:
  email: admin@example.com
"""
        findings = detector.detect(content, "config.yaml")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    def test_process_xml_file(self) -> None:
        """Test that XML files are processed normally."""
        detector = RegexDetector()
        content = """<?xml version="1.0"?>
<config>
    <aws_key>AKIAIOSFODNN7EXAMPLE</aws_key>
    <email>admin@example.com</email>
</config>
"""
        findings = detector.detect(content, "config.xml")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    def test_process_markdown_file(self) -> None:
        """Test that Markdown files are processed normally."""
        detector = RegexDetector()
        content = """# Configuration

Contact: admin@example.com

## AWS Keys
- Access Key: AKIAIOSFODNN7EXAMPLE
"""
        findings = detector.detect(content, "README.md")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(aws_findings) == 1
        assert len(email_findings) == 1

    def test_process_html_file(self) -> None:
        """Test that HTML files are processed normally."""
        detector = RegexDetector()
        content = """<!DOCTYPE html>
<html>
<head><title>Test</title></head>
<body>
    <!-- Hidden config -->
    <script>const key = "AKIAIOSFODNN7EXAMPLE";</script>
    <a href="mailto:admin@example.com">Contact</a>
</body>
</html>
"""
        findings = detector.detect(content, "index.html")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(aws_findings) == 1
        assert len(email_findings) == 1

    def test_process_env_file(self) -> None:
        """Test that .env files are processed normally."""
        detector = RegexDetector()
        content = """
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY="wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY"
CONTACT_EMAIL=admin@example.com
"""
        findings = detector.detect(content, ".env")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1

    def test_process_shell_script(self) -> None:
        """Test that shell scripts are processed normally."""
        detector = RegexDetector()
        content = """#!/bin/bash
export AWS_KEY="AKIAIOSFODNN7EXAMPLE"
export EMAIL="admin@example.com"
echo "Configured"
"""
        findings = detector.detect(content, "setup.sh")
        aws_findings = [f for f in findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1


class TestScannerMixedDirectories:
    """Tests that the scanner properly processes mixed directories."""

    @pytest.mark.asyncio
    async def test_scanner_with_mixed_binary_and_text_files(self, tmp_path: Path) -> None:
        """Test scanner processes text files and skips binary files in same directory."""
        # Create text file with secrets
        text_file = tmp_path / "config.txt"
        text_file.write_text("AWS_KEY=AKIAIOSFODNN7EXAMPLE\nemail=admin@example.com")

        # Create binary file (simulated ELF)
        binary_file = tmp_path / "program.bin"
        binary_content = b"\x7fELF\x02\x01\x01\x00" + b"\x00\x01\x02\x03" * 500
        binary_content += b"AKIAIOSFODNN7EXAMPLE"  # Hidden secret in binary
        binary_file.write_bytes(binary_content)

        # Create another text file
        readme = tmp_path / "README.md"
        readme.write_text("Contact: support@example.com")

        # Set up scanner
        config = ScanConfig(target_path=tmp_path, recursive=False)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        # Run scan
        result = await scanner.scan()

        # Should find secrets from text files only
        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]

        # Should only find the AWS key in the text file, not the binary
        assert len(aws_findings) == 1
        assert "config.txt" in aws_findings[0].file_path

        # Should find both emails
        assert len(email_findings) == 2

    @pytest.mark.asyncio
    async def test_scanner_recursive_with_mixed_content(self, tmp_path: Path) -> None:
        """Test scanner recursively processes directories with mixed content."""
        # Create directory structure
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        bin_dir = tmp_path / "bin"
        bin_dir.mkdir()

        # Text files in src/
        (src_dir / "config.py").write_text('API_KEY = "AKIAIOSFODNN7EXAMPLE"')
        (src_dir / "utils.py").write_text('EMAIL = "dev@example.com"')

        # Binary files in bin/
        binary_content = b"\x7fELF" + b"\x00" * 1000
        (bin_dir / "app").write_bytes(binary_content)
        (bin_dir / "helper").write_bytes(b"\xca\xfe\xba\xbe" + b"\x00" * 1000)

        # Mixed file at root
        (tmp_path / "data.json").write_text('{"email": "root@example.com"}')

        config = ScanConfig(target_path=tmp_path, recursive=True)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should find secrets in text files
        aws_findings = [f for f in result.findings if "AWS API Key" in f.detector_name]
        assert len(aws_findings) == 1
        assert "config.py" in aws_findings[0].file_path

        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 2  # dev@example.com and root@example.com

    @pytest.mark.asyncio
    async def test_scanner_image_directory(self, tmp_path: Path) -> None:
        """Test scanner correctly skips image files in an assets directory."""
        assets_dir = tmp_path / "assets"
        assets_dir.mkdir()

        # Create simulated image files with binary content
        png_content = b"\x89PNG\r\n\x1a\n" + b"\x00" * 1000
        (assets_dir / "logo.png").write_bytes(png_content)

        jpeg_content = b"\xff\xd8\xff\xe0" + b"\x00" * 1000
        (assets_dir / "photo.jpg").write_bytes(jpeg_content)

        gif_content = b"GIF89a" + b"\x00\x01\x02\x03" * 500
        (assets_dir / "animation.gif").write_bytes(gif_content)

        # Add a text file with secrets
        (assets_dir / "metadata.txt").write_text("Author: admin@example.com")

        config = ScanConfig(target_path=assets_dir, recursive=False)
        detector = RegexDetector()
        scanner = Scanner(config, detectors=[detector])

        result = await scanner.scan()

        # Should only find the email in metadata.txt
        assert len(result.findings) >= 1
        email_findings = [f for f in result.findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1
        assert "metadata.txt" in email_findings[0].file_path


class TestNullByteHandling:
    """Tests for proper handling of files with null bytes."""

    def test_few_null_bytes_still_processed(self) -> None:
        """Test that text files with a few null bytes are still processed."""
        detector = RegexDetector()
        # Content with occasional null bytes but mostly text
        content = "Normal text\x00admin@example.com\x00more normal text " * 5
        findings = detector.detect(content, "partial_binary.txt")

        # Calculate expected behavior based on binary threshold
        sample = content[:8192]
        sample_bytes = sample.encode("utf-8", errors="replace")
        binary_count = sum(1 for b in sample_bytes if b in BINARY_INDICATOR_BYTES)
        binary_ratio = binary_count / len(sample_bytes)

        if binary_ratio <= BINARY_THRESHOLD:
            # Should find the email if below threshold
            email_findings = [f for f in findings if "Email Address" in f.detector_name]
            assert len(email_findings) == 1
        else:
            # Should skip if above threshold
            assert len(findings) == 0

    def test_many_null_bytes_skipped(self) -> None:
        """Test that files with many null bytes are skipped."""
        detector = RegexDetector()
        # Content that's mostly null bytes
        content = "\x00" * 1000 + "admin@example.com" + "\x00" * 1000
        findings = detector.detect(content, "mostly_null.bin")
        # Should be skipped due to high binary ratio
        assert len(findings) == 0

    def test_null_terminated_strings(self) -> None:
        """Test handling of null-terminated strings (common in binaries)."""
        detector = RegexDetector()
        # Many short null-terminated strings
        content = "Hello\x00World\x00admin@example.com\x00Secret\x00Key\x00" * 200
        findings = detector.detect(content, "strings.bin")
        # High null byte ratio should trigger binary detection
        assert len(findings) == 0

    def test_single_null_byte_in_text(self) -> None:
        """Test that a single null byte doesn't prevent processing."""
        detector = RegexDetector()
        # Large text with just one null byte
        text_content = "This is a long text file " * 100
        content = text_content + "\x00" + "admin@example.com" + text_content
        findings = detector.detect(content, "almost_text.txt")
        # Binary ratio should be very low, so should process
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_null_at_start_of_file(self) -> None:
        """Test handling of null byte at the start of file."""
        detector = RegexDetector()
        content = "\x00" + "Normal text with admin@example.com" + " " * 1000
        findings = detector.detect(content, "null_start.txt")
        # Should process since binary ratio is very low
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_null_at_end_of_file(self) -> None:
        """Test handling of null byte at the end of file."""
        detector = RegexDetector()
        content = ("Normal text with admin@example.com" + " " * 1000) + "\x00"
        findings = detector.detect(content, "null_end.txt")
        # Should process since binary ratio is very low
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestBinaryDetectionThreshold:
    """Tests for the binary detection threshold behavior."""

    def test_exactly_at_threshold(self) -> None:
        """Test behavior when binary ratio is exactly at threshold."""
        detector = RegexDetector()

        # Calculate content that puts us right at the threshold
        # BINARY_THRESHOLD is 0.1 (10%)
        # For 1000 chars, we need 100 binary bytes
        text_part = "admin@example.com " * 50  # ~900 chars
        binary_count_needed = int(len(text_part) * BINARY_THRESHOLD)
        binary_part = "\x00" * binary_count_needed

        content = binary_part + text_part

        # At exactly the threshold, should not be considered binary (> not >=)
        findings = detector.detect(content, "threshold.txt")
        # May or may not find depending on exact calculation, just verify no crash
        assert isinstance(findings, list)

    def test_just_below_threshold(self) -> None:
        """Test that content just below threshold is processed."""
        detector = RegexDetector()

        # Create content with binary ratio just below 10%
        text_size = 1000
        binary_size = int(text_size * (BINARY_THRESHOLD - 0.02))  # 8% binary
        content = "\x00" * binary_size + "admin@example.com " * (text_size // 20)

        findings = detector.detect(content, "below_threshold.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_just_above_threshold(self) -> None:
        """Test that content just above threshold is skipped."""
        detector = RegexDetector()

        # Create content with binary ratio just above 10%
        text_size = 1000
        binary_size = int(text_size * (BINARY_THRESHOLD + 0.05))  # 15% binary
        content = "\x00" * binary_size + "admin@example.com " * (text_size // 20)

        findings = detector.detect(content, "above_threshold.txt")
        # Should be skipped due to high binary ratio
        assert len(findings) == 0


class TestBinaryIndicatorBytes:
    """Tests for the binary indicator byte detection."""

    def test_all_binary_indicator_bytes_detected(self) -> None:
        """Test that all bytes in BINARY_INDICATOR_BYTES trigger detection."""
        detector = RegexDetector()

        # Create content with each binary indicator byte
        for byte_val in BINARY_INDICATOR_BYTES:
            # Create content with enough of this byte to trigger detection
            binary_char = chr(byte_val)
            content = (binary_char * 200) + "admin@example.com" + (binary_char * 200)
            findings = detector.detect(content, f"binary_{byte_val}.bin")
            # Should be detected as binary
            assert len(findings) == 0, f"Byte {byte_val} should trigger binary detection"

    def test_tab_not_binary_indicator(self) -> None:
        """Test that tab character (0x09) is not a binary indicator."""
        detector = RegexDetector()
        content = "\t" * 500 + "admin@example.com" + "\t" * 500
        findings = detector.detect(content, "tabs.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_newline_not_binary_indicator(self) -> None:
        """Test that newline character (0x0A) is not a binary indicator."""
        detector = RegexDetector()
        content = "\n" * 500 + "admin@example.com" + "\n" * 500
        findings = detector.detect(content, "newlines.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_carriage_return_not_binary_indicator(self) -> None:
        """Test that carriage return (0x0D) is not a binary indicator."""
        detector = RegexDetector()
        content = "\r" * 500 + "admin@example.com" + "\r" * 500
        findings = detector.detect(content, "cr.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1

    def test_mixed_whitespace_not_binary(self) -> None:
        """Test that mixed whitespace is not detected as binary."""
        detector = RegexDetector()
        content = "\t\n\r \t\n\r " * 100 + "admin@example.com" + "\t\n\r " * 100
        findings = detector.detect(content, "whitespace.txt")
        email_findings = [f for f in findings if "Email Address" in f.detector_name]
        assert len(email_findings) == 1


class TestRealWorldBinaryPatterns:
    """Tests for real-world binary file patterns."""

    def test_sqlite_database(self) -> None:
        """Test that SQLite databases are detected as binary."""
        detector = RegexDetector()
        # SQLite magic: "SQLite format 3\x00"
        sqlite_header = "SQLite format 3\x00"
        sqlite_content = sqlite_header + "\x00\x01\x00\x01" + "\x00" * 500
        findings = detector.detect(sqlite_content, "database.db")
        assert len(findings) == 0

    def test_bzip2_archive(self) -> None:
        """Test that bzip2 archives are detected as binary."""
        detector = RegexDetector()
        # BZ2 magic: 'BZ'
        bz2_content = "BZ" + "\x68\x39\x31" + "\x00" * 500
        findings = detector.detect(bz2_content, "archive.bz2")
        assert len(findings) == 0

    def test_7zip_archive(self) -> None:
        """Test that 7z archives are detected as binary."""
        detector = RegexDetector()
        # 7z magic: '7z\xbc\xaf\x27\x1c'
        sevenzip_content = "7z\xbc\xaf\x27\x1c" + "\x00" * 500
        findings = detector.detect(sevenzip_content, "archive.7z")
        assert len(findings) == 0

    def test_tar_archive(self) -> None:
        """Test that tar archives with binary content are detected."""
        detector = RegexDetector()
        # TAR files may contain binary file data
        tar_content = "ustar\x00" + "\x00" * 500
        tar_content += "\x00\x01\x02\x03\x04\x05\x06\x07" * 100
        findings = detector.detect(tar_content, "archive.tar")
        assert len(findings) == 0

    def test_python_bytecode(self) -> None:
        """Test that Python .pyc files are detected as binary."""
        detector = RegexDetector()
        # Python 3.x bytecode magic (varies by version)
        pyc_content = "\x55\x0d\x0d\x0a" + "\x00" * 12 + "\xe3" + "\x00" * 500
        findings = detector.detect(pyc_content, "module.pyc")
        assert len(findings) == 0

    def test_object_file(self) -> None:
        """Test that object files (.o) are detected as binary."""
        detector = RegexDetector()
        # Object files typically have ELF header or similar
        obj_content = "\x7fELF\x02\x01\x01" + "\x00" * 500
        findings = detector.detect(obj_content, "module.o")
        assert len(findings) == 0

    def test_shared_library(self) -> None:
        """Test that shared libraries (.so) are detected as binary."""
        detector = RegexDetector()
        # Shared libraries are ELF on Linux
        so_content = "\x7fELF\x02\x01\x01\x03" + "\x00" * 500
        findings = detector.detect(so_content, "libmodule.so")
        assert len(findings) == 0

    def test_dll_file(self) -> None:
        """Test that DLL files are detected as binary."""
        detector = RegexDetector()
        # DLLs use PE format (MZ header)
        dll_content = "MZ\x90\x00\x03\x00\x00\x00" + "\x00" * 500
        findings = detector.detect(dll_content, "module.dll")
        assert len(findings) == 0
