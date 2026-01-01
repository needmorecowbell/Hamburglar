"""Tests for the AsyncFileReader class.

This module tests the async file reading functionality including:
- Async file reading works correctly
- Encoding detection works
- Large files are handled efficiently
- Binary file detection works
- Corrupt files don't crash reader
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

import pytest

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.file_reader import AsyncFileReader, FileInfo, FileType  # noqa: E402


class TestAsyncFileReaderBasic:
    """Test basic async file reading functionality."""

    @pytest.mark.asyncio
    async def test_read_text_file(self, tmp_path: Path) -> None:
        """Test reading a simple text file."""
        test_file = tmp_path / "test.txt"
        content = "Hello, World!\nThis is a test file."
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        assert result == content

    @pytest.mark.asyncio
    async def test_read_bytes_file(self, tmp_path: Path) -> None:
        """Test reading a file as bytes."""
        test_file = tmp_path / "test.bin"
        content = b"\x00\x01\x02\x03\xff\xfe\xfd"
        test_file.write_bytes(content)

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read_bytes()

        assert result == content

    @pytest.mark.asyncio
    async def test_read_empty_file(self, tmp_path: Path) -> None:
        """Test reading an empty file."""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("")

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        assert result == ""

    @pytest.mark.asyncio
    async def test_file_not_found(self, tmp_path: Path) -> None:
        """Test that FileNotFoundError is raised for missing files."""
        nonexistent = tmp_path / "nonexistent.txt"

        with pytest.raises(FileNotFoundError):
            async with AsyncFileReader(nonexistent) as reader:
                await reader.read()

    @pytest.mark.asyncio
    async def test_is_directory_error(self, tmp_path: Path) -> None:
        """Test that IsADirectoryError is raised when path is a directory."""
        with pytest.raises(IsADirectoryError):
            async with AsyncFileReader(tmp_path) as reader:
                await reader.read()


class TestAsyncContextManager:
    """Test async context manager interface."""

    @pytest.mark.asyncio
    async def test_context_manager_opens_file(self, tmp_path: Path) -> None:
        """Test that context manager opens the file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        assert not reader.is_open

        async with reader:
            assert reader.is_open

        assert not reader.is_open

    @pytest.mark.asyncio
    async def test_context_manager_closes_on_exception(self, tmp_path: Path) -> None:
        """Test that context manager closes file even on exception."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)

        with pytest.raises(RuntimeError):
            async with reader:
                assert reader.is_open
                raise RuntimeError("Test exception")

        assert not reader.is_open

    @pytest.mark.asyncio
    async def test_manual_open_close(self, tmp_path: Path) -> None:
        """Test manual open() and close() methods."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        assert not reader.is_open

        await reader.open()
        assert reader.is_open

        content = await reader.read()
        assert content == "content"

        await reader.close()
        assert not reader.is_open

    @pytest.mark.asyncio
    async def test_close_without_open(self, tmp_path: Path) -> None:
        """Test that close() is safe to call without opening."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        await reader.close()  # Should not raise


class TestEncodingDetection:
    """Test automatic encoding detection."""

    @pytest.mark.asyncio
    async def test_utf8_detection(self, tmp_path: Path) -> None:
        """Test that UTF-8 files are detected correctly."""
        test_file = tmp_path / "utf8.txt"
        content = "Hello, 世界! 🌍"  # Mix of ASCII, CJK, and emoji
        test_file.write_text(content, encoding="utf-8")

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()
            assert reader.file_info is not None
            assert reader.file_info.encoding in ("utf-8", "utf_8", "UTF-8")

        assert result == content

    @pytest.mark.asyncio
    async def test_latin1_detection(self, tmp_path: Path) -> None:
        """Test that Latin-1 encoded files are handled."""
        test_file = tmp_path / "latin1.txt"
        # Use Latin-1 specific characters
        content = "Héllo Wörld! Ñoño"
        test_file.write_bytes(content.encode("latin-1"))

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        # Should decode without error
        assert "llo" in result

    @pytest.mark.asyncio
    async def test_forced_encoding(self, tmp_path: Path) -> None:
        """Test forcing a specific encoding."""
        test_file = tmp_path / "forced.txt"
        content = "Test content"
        test_file.write_text(content, encoding="utf-8")

        async with AsyncFileReader(test_file, encoding="utf-8") as reader:
            assert reader.file_info is not None
            assert reader.file_info.encoding == "utf-8"
            result = await reader.read()

        assert result == content

    @pytest.mark.asyncio
    async def test_utf16_file(self, tmp_path: Path) -> None:
        """Test reading UTF-16 encoded file."""
        test_file = tmp_path / "utf16.txt"
        content = "Hello UTF-16 World!"
        test_file.write_bytes(content.encode("utf-16"))

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        # Should handle UTF-16 (may detect via BOM or charset-normalizer)
        assert "Hello" in result or "UTF-16" in result


class TestFileTypeDetection:
    """Test binary vs text file detection."""

    @pytest.mark.asyncio
    async def test_text_file_detection(self, tmp_path: Path) -> None:
        """Test that text files are detected as text."""
        test_file = tmp_path / "text.txt"
        test_file.write_text("This is plain text content.\nWith multiple lines.")

        async with AsyncFileReader(test_file) as reader:
            assert reader.file_info is not None
            assert reader.file_info.file_type == FileType.TEXT

    @pytest.mark.asyncio
    async def test_binary_file_detection(self, tmp_path: Path) -> None:
        """Test that binary files are detected as binary."""
        test_file = tmp_path / "binary.bin"
        # Create binary content with null bytes
        test_file.write_bytes(b"\x00\x01\x02\x03\xff\xfe\x00\xfd")

        async with AsyncFileReader(test_file) as reader:
            assert reader.file_info is not None
            assert reader.file_info.file_type == FileType.BINARY

    @pytest.mark.asyncio
    async def test_is_binary_class_method(self, tmp_path: Path) -> None:
        """Test the is_binary class method."""
        text_file = tmp_path / "text.txt"
        text_file.write_text("Hello world")

        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03")

        assert not await AsyncFileReader.is_binary(text_file)
        assert await AsyncFileReader.is_binary(binary_file)

    @pytest.mark.asyncio
    async def test_is_text_class_method(self, tmp_path: Path) -> None:
        """Test the is_text class method."""
        text_file = tmp_path / "text.txt"
        text_file.write_text("Hello world")

        binary_file = tmp_path / "binary.bin"
        binary_file.write_bytes(b"\x00\x01\x02\x03")

        assert await AsyncFileReader.is_text(text_file)
        assert not await AsyncFileReader.is_text(binary_file)

    @pytest.mark.asyncio
    async def test_detect_type_without_opening(self, tmp_path: Path) -> None:
        """Test that detect_type works without fully opening the file."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        file_type = await reader.detect_type()

        assert file_type == FileType.TEXT
        assert not reader.is_open  # Should not leave file open

    @pytest.mark.asyncio
    async def test_empty_file_is_text(self, tmp_path: Path) -> None:
        """Test that empty files are classified as text."""
        test_file = tmp_path / "empty.txt"
        test_file.write_text("")

        file_type = await AsyncFileReader(test_file).detect_type()
        assert file_type == FileType.TEXT


class TestChunkedReading:
    """Test chunked file reading functionality."""

    @pytest.mark.asyncio
    async def test_read_in_chunks(self, tmp_path: Path) -> None:
        """Test reading a file in chunks."""
        test_file = tmp_path / "large.txt"
        content = "x" * 10000  # 10KB of data
        test_file.write_text(content)

        async with AsyncFileReader(test_file, chunk_size=1000) as reader:
            chunks: list[bytes] = []
            async for chunk in reader.read_chunks():
                chunks.append(chunk)

        # Should have 10 chunks of 1000 bytes each
        assert len(chunks) == 10
        assert all(len(chunk) == 1000 for chunk in chunks)
        # Reassembled content should match original
        assert b"".join(chunks).decode("utf-8") == content

    @pytest.mark.asyncio
    async def test_read_text_chunks(self, tmp_path: Path) -> None:
        """Test reading a file as text chunks."""
        test_file = tmp_path / "text.txt"
        content = "Hello World! " * 100  # ~1300 bytes
        test_file.write_text(content)

        async with AsyncFileReader(test_file, chunk_size=500) as reader:
            text_chunks: list[str] = []
            async for chunk in reader.read_text_chunks():
                text_chunks.append(chunk)

        # Should have multiple chunks
        assert len(text_chunks) >= 2
        # All chunks should be strings
        assert all(isinstance(chunk, str) for chunk in text_chunks)

    @pytest.mark.asyncio
    async def test_read_chunk_method(self, tmp_path: Path) -> None:
        """Test reading individual chunks with read_chunk()."""
        test_file = tmp_path / "chunks.txt"
        content = "abcdefghij"  # 10 bytes
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            chunk1 = await reader.read_chunk(5)
            chunk2 = await reader.read_chunk(5)
            chunk3 = await reader.read_chunk(5)  # Should be empty at EOF

        assert chunk1 == b"abcde"
        assert chunk2 == b"fghij"
        assert chunk3 == b""

    @pytest.mark.asyncio
    async def test_custom_chunk_size_in_read_chunks(self, tmp_path: Path) -> None:
        """Test passing custom chunk size to read_chunks()."""
        test_file = tmp_path / "custom.txt"
        content = "x" * 100
        test_file.write_text(content)

        async with AsyncFileReader(test_file, chunk_size=50) as reader:
            # Override with smaller chunk size
            chunks: list[bytes] = []
            async for chunk in reader.read_chunks(chunk_size=10):
                chunks.append(chunk)

        assert len(chunks) == 10
        assert all(len(chunk) == 10 for chunk in chunks)


class TestMemoryMappedFiles:
    """Test memory-mapped file support for large files."""

    @pytest.mark.asyncio
    async def test_force_mmap(self, tmp_path: Path) -> None:
        """Test forcing memory-mapped mode."""
        test_file = tmp_path / "mmap.txt"
        content = "Memory mapped content"
        test_file.write_text(content)

        async with AsyncFileReader(test_file, use_mmap=True) as reader:
            result = await reader.read()

        assert result == content

    @pytest.mark.asyncio
    async def test_force_no_mmap(self, tmp_path: Path) -> None:
        """Test forcing regular file mode (no mmap)."""
        test_file = tmp_path / "regular.txt"
        content = "Regular file content"
        test_file.write_text(content)

        async with AsyncFileReader(test_file, use_mmap=False) as reader:
            result = await reader.read()

        assert result == content

    @pytest.mark.asyncio
    async def test_mmap_threshold(self, tmp_path: Path) -> None:
        """Test that mmap threshold controls automatic mmap usage."""
        test_file = tmp_path / "threshold.txt"
        content = "x" * 1000
        test_file.write_text(content)

        # With low threshold, should use mmap
        reader_mmap = AsyncFileReader(test_file, mmap_threshold=500)
        await reader_mmap.open()
        # Can't easily verify mmap is used, but verify it works
        result = await reader_mmap.read()
        await reader_mmap.close()
        assert result == content

        # With high threshold, should not use mmap
        reader_regular = AsyncFileReader(test_file, mmap_threshold=10000)
        await reader_regular.open()
        result = await reader_regular.read()
        await reader_regular.close()
        assert result == content

    @pytest.mark.asyncio
    async def test_mmap_with_chunks(self, tmp_path: Path) -> None:
        """Test chunked reading with memory-mapped files."""
        test_file = tmp_path / "mmap_chunks.txt"
        content = "Hello World! " * 1000
        test_file.write_text(content)

        async with AsyncFileReader(test_file, use_mmap=True, chunk_size=500) as reader:
            chunks: list[bytes] = []
            async for chunk in reader.read_chunks():
                chunks.append(chunk)

        reassembled = b"".join(chunks).decode("utf-8")
        assert reassembled == content


class TestSeekOperations:
    """Test seek operations."""

    @pytest.mark.asyncio
    async def test_seek_to_position(self, tmp_path: Path) -> None:
        """Test seeking to a specific position."""
        test_file = tmp_path / "seek.txt"
        content = "0123456789"
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            await reader.seek(5)
            data = await reader.read_chunk(5)

        assert data == b"56789"

    @pytest.mark.asyncio
    async def test_seek_from_end(self, tmp_path: Path) -> None:
        """Test seeking from end of file."""
        test_file = tmp_path / "seek_end.txt"
        content = "0123456789"
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            await reader.seek(-3, os.SEEK_END)
            data = await reader.read_chunk(3)

        assert data == b"789"

    @pytest.mark.asyncio
    async def test_seek_relative(self, tmp_path: Path) -> None:
        """Test relative seek from current position."""
        test_file = tmp_path / "seek_rel.txt"
        content = "0123456789"
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            await reader.read_chunk(3)  # Position at 3
            await reader.seek(2, os.SEEK_CUR)  # Move to 5
            data = await reader.read_chunk(2)

        assert data == b"56"


class TestFileInfo:
    """Test FileInfo data class."""

    @pytest.mark.asyncio
    async def test_file_info_attributes(self, tmp_path: Path) -> None:
        """Test that FileInfo contains correct attributes."""
        test_file = tmp_path / "info.txt"
        content = "Test content for file info"
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            info = reader.file_info

        assert info is not None
        assert info.path == test_file
        assert info.file_type == FileType.TEXT
        assert info.size == len(content.encode("utf-8"))
        assert info.encoding is not None
        assert info.encoding_confidence > 0

    @pytest.mark.asyncio
    async def test_file_info_for_binary(self, tmp_path: Path) -> None:
        """Test FileInfo for binary files."""
        test_file = tmp_path / "binary.bin"
        content = b"\x00\x01\x02\x03"
        test_file.write_bytes(content)

        async with AsyncFileReader(test_file) as reader:
            info = reader.file_info

        assert info is not None
        assert info.file_type == FileType.BINARY
        assert info.encoding is None
        assert info.size == 4


class TestConvenienceMethods:
    """Test class convenience methods."""

    @pytest.mark.asyncio
    async def test_read_file_class_method(self, tmp_path: Path) -> None:
        """Test the read_file class method."""
        test_file = tmp_path / "quick.txt"
        content = "Quick read content"
        test_file.write_text(content)

        result = await AsyncFileReader.read_file(test_file)

        assert result == content

    @pytest.mark.asyncio
    async def test_read_file_with_encoding(self, tmp_path: Path) -> None:
        """Test read_file with forced encoding."""
        test_file = tmp_path / "encoded.txt"
        content = "Encoded content"
        test_file.write_text(content, encoding="utf-8")

        result = await AsyncFileReader.read_file(test_file, encoding="utf-8")

        assert result == content

    @pytest.mark.asyncio
    async def test_read_file_bytes_class_method(self, tmp_path: Path) -> None:
        """Test the read_file_bytes class method."""
        test_file = tmp_path / "bytes.bin"
        content = b"Binary content bytes"
        test_file.write_bytes(content)

        result = await AsyncFileReader.read_file_bytes(test_file)

        assert result == content


class TestErrorHandling:
    """Test error handling scenarios."""

    @pytest.mark.asyncio
    async def test_read_without_open(self, tmp_path: Path) -> None:
        """Test that read() raises error when file not opened."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        with pytest.raises(RuntimeError, match="not open"):
            await reader.read()

    @pytest.mark.asyncio
    async def test_read_chunk_without_open(self, tmp_path: Path) -> None:
        """Test that read_chunk() raises error when file not opened."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        with pytest.raises(RuntimeError, match="not open"):
            await reader.read_chunk()

    @pytest.mark.asyncio
    async def test_seek_without_open(self, tmp_path: Path) -> None:
        """Test that seek() raises error when file not opened."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        with pytest.raises(RuntimeError, match="not open"):
            await reader.seek(0)

    @pytest.mark.asyncio
    async def test_read_chunks_without_open(self, tmp_path: Path) -> None:
        """Test that read_chunks() raises error when file not opened."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        with pytest.raises(RuntimeError, match="not open"):
            async for _ in reader.read_chunks():
                pass

    @pytest.mark.asyncio
    @pytest.mark.skipif(os.name == "nt", reason="Permission tests not reliable on Windows")
    async def test_permission_denied(self, tmp_path: Path) -> None:
        """Test handling of permission denied errors."""
        test_file = tmp_path / "protected.txt"
        test_file.write_text("protected content")
        original_mode = test_file.stat().st_mode
        test_file.chmod(0o000)

        try:
            with pytest.raises(PermissionError):
                async with AsyncFileReader(test_file) as reader:
                    await reader.read()
        finally:
            test_file.chmod(original_mode)

    @pytest.mark.asyncio
    async def test_open_already_open(self, tmp_path: Path) -> None:
        """Test that opening an already-open file returns file info."""
        test_file = tmp_path / "test.txt"
        test_file.write_text("content")

        reader = AsyncFileReader(test_file)
        await reader.open()
        info1 = reader.file_info

        # Second open should return the same info
        info2 = await reader.open()
        assert info1 == info2

        await reader.close()


class TestLargeFiles:
    """Test handling of large files."""

    @pytest.mark.asyncio
    async def test_large_file_read(self, tmp_path: Path) -> None:
        """Test reading a moderately large file."""
        test_file = tmp_path / "large.txt"
        # Create 1MB file
        content = "x" * (1024 * 1024)
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        assert len(result) == 1024 * 1024
        assert result == content

    @pytest.mark.asyncio
    async def test_large_file_chunks(self, tmp_path: Path) -> None:
        """Test chunked reading of large file."""
        test_file = tmp_path / "large_chunks.txt"
        size = 500 * 1024  # 500KB
        content = "y" * size
        test_file.write_text(content)

        async with AsyncFileReader(test_file, chunk_size=64 * 1024) as reader:
            total_bytes = 0
            async for chunk in reader.read_chunks():
                total_bytes += len(chunk)

        assert total_bytes == size


class TestConcurrency:
    """Test concurrent file operations."""

    @pytest.mark.asyncio
    async def test_multiple_readers_same_file(self, tmp_path: Path) -> None:
        """Test multiple readers on the same file."""
        test_file = tmp_path / "shared.txt"
        content = "Shared content"
        test_file.write_text(content)

        async def read_file() -> str:
            async with AsyncFileReader(test_file) as reader:
                return await reader.read()

        # Run multiple readers concurrently
        results = await asyncio.gather(
            read_file(),
            read_file(),
            read_file(),
        )

        assert all(r == content for r in results)

    @pytest.mark.asyncio
    async def test_concurrent_file_reads(self, tmp_path: Path) -> None:
        """Test reading multiple different files concurrently."""
        files = {}
        for i in range(5):
            path = tmp_path / f"file{i}.txt"
            content = f"Content of file {i}"
            path.write_text(content)
            files[path] = content

        async def read_file(path: Path) -> tuple[Path, str]:
            async with AsyncFileReader(path) as reader:
                return path, await reader.read()

        results = await asyncio.gather(
            *[read_file(path) for path in files.keys()]
        )

        for path, result in results:
            assert result == files[path]


class TestEdgeCases:
    """Test edge cases and special scenarios."""

    @pytest.mark.asyncio
    async def test_file_with_only_whitespace(self, tmp_path: Path) -> None:
        """Test reading file with only whitespace."""
        test_file = tmp_path / "whitespace.txt"
        content = "   \n\t\n   "
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        assert result == content

    @pytest.mark.asyncio
    async def test_file_with_unicode_name(self, tmp_path: Path) -> None:
        """Test reading file with unicode characters in name."""
        test_file = tmp_path / "тест_文件.txt"
        content = "Unicode filename content"
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        assert result == content

    @pytest.mark.asyncio
    async def test_very_long_line(self, tmp_path: Path) -> None:
        """Test reading file with very long line."""
        test_file = tmp_path / "longline.txt"
        content = "x" * 100000  # 100K character line
        test_file.write_text(content)

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        assert result == content

    @pytest.mark.asyncio
    async def test_mixed_line_endings(self, tmp_path: Path) -> None:
        """Test reading file with mixed line endings."""
        test_file = tmp_path / "mixed.txt"
        # Mix of Unix (\n), Windows (\r\n), and old Mac (\r) line endings
        content = b"line1\nline2\r\nline3\rline4"
        test_file.write_bytes(content)

        async with AsyncFileReader(test_file) as reader:
            result = await reader.read()

        assert "line1" in result
        assert "line4" in result

    @pytest.mark.asyncio
    async def test_high_bit_characters(self, tmp_path: Path) -> None:
        """Test reading file with high-bit characters."""
        test_file = tmp_path / "highbit.txt"
        content = bytes(range(128, 256))
        test_file.write_bytes(content)

        # Should not crash, may fall back to latin-1
        async with AsyncFileReader(test_file) as reader:
            info = reader.file_info
            # Should be detected as text or binary depending on content
            assert info is not None
