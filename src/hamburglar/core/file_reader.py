"""Async file reader module for Hamburglar.

This module provides the AsyncFileReader class which handles asynchronous
file reading with automatic encoding detection, memory-mapped file support
for large files, and binary vs text detection.
"""

from __future__ import annotations

import asyncio
import logging
import mmap
import os
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Self

logger = logging.getLogger(__name__)


class FileType(str, Enum):
    """File type classification."""

    TEXT = "text"
    BINARY = "binary"
    UNKNOWN = "unknown"


@dataclass
class FileInfo:
    """Information about a file's characteristics.

    Attributes:
        path: Path to the file.
        file_type: Whether the file is text, binary, or unknown.
        encoding: Detected encoding for text files (None for binary).
        size: File size in bytes.
        encoding_confidence: Confidence level (0-1) for encoding detection.
    """

    path: Path
    file_type: FileType
    encoding: str | None
    size: int
    encoding_confidence: float = 0.0


class AsyncFileReader:
    """Async file reader with encoding detection and memory-mapped file support.

    Provides asynchronous file reading with:
    - Configurable chunk size for reading
    - Automatic encoding detection using charset-normalizer
    - Memory-mapped file support for efficient large file handling
    - Async context manager interface for resource management
    - Binary vs text file detection

    Example:
        >>> async with AsyncFileReader(Path("file.txt")) as reader:
        ...     content = await reader.read()
        ...     print(f"Read {len(content)} characters")

        >>> # Or without context manager
        >>> reader = AsyncFileReader(Path("large_file.log"))
        >>> await reader.open()
        >>> async for chunk in reader.read_chunks():
        ...     process(chunk)
        >>> await reader.close()
    """

    DEFAULT_CHUNK_SIZE = 8192  # 8KB default chunk size
    DEFAULT_MMAP_THRESHOLD = 10 * 1024 * 1024  # 10MB threshold for mmap
    BINARY_DETECTION_SIZE = 8192  # Bytes to check for binary detection

    def __init__(
        self,
        path: Path,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        mmap_threshold: int = DEFAULT_MMAP_THRESHOLD,
        use_mmap: bool | None = None,
        encoding: str | None = None,
    ):
        """Initialize the async file reader.

        Args:
            path: Path to the file to read.
            chunk_size: Size of chunks when reading in chunks (default 8KB).
            mmap_threshold: File size threshold above which to use mmap
                          (default 10MB). Only used if use_mmap is None.
            use_mmap: Force memory-mapped mode on/off. If None, automatically
                     decide based on file size and mmap_threshold.
            encoding: Force a specific encoding. If None, auto-detect.
        """
        self.path = path
        self.chunk_size = chunk_size
        self.mmap_threshold = mmap_threshold
        self._forced_mmap = use_mmap
        self._forced_encoding = encoding

        # State
        self._file: any = None
        self._mmap: mmap.mmap | None = None
        self._file_info: FileInfo | None = None
        self._is_open = False
        self._position = 0

    @property
    def is_open(self) -> bool:
        """Check if the file is currently open."""
        return self._is_open

    @property
    def file_info(self) -> FileInfo | None:
        """Get file information (available after opening)."""
        return self._file_info

    async def __aenter__(self) -> Self:
        """Async context manager entry."""
        await self.open()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Async context manager exit."""
        await self.close()

    async def open(self) -> FileInfo:
        """Open the file for reading.

        Performs file type detection, encoding detection, and optionally
        sets up memory mapping for large files.

        Returns:
            FileInfo with detected file characteristics.

        Raises:
            FileNotFoundError: If the file does not exist.
            PermissionError: If the file cannot be read.
            OSError: For other file system errors.
        """
        if self._is_open:
            if self._file_info is not None:
                return self._file_info
            raise RuntimeError("File is already open but file_info is None")

        # Get file size and detect type/encoding in thread pool
        self._file_info = await asyncio.to_thread(self._analyze_file)

        # Open the file
        await self._open_file()
        self._is_open = True

        return self._file_info

    def _analyze_file(self) -> FileInfo:
        """Analyze file type and encoding (runs in thread pool).

        Returns:
            FileInfo with detected characteristics.
        """
        path = self.path

        if not path.exists():
            raise FileNotFoundError(f"File not found: {path}")

        if not path.is_file():
            raise IsADirectoryError(f"Path is not a file: {path}")

        size = path.stat().st_size

        # Detect file type by reading initial bytes
        file_type, encoding, confidence = self._detect_file_type_and_encoding(path, size)

        # Override encoding if forced
        if self._forced_encoding:
            encoding = self._forced_encoding
            confidence = 1.0

        return FileInfo(
            path=path,
            file_type=file_type,
            encoding=encoding,
            size=size,
            encoding_confidence=confidence,
        )

    def _detect_file_type_and_encoding(
        self, path: Path, size: int
    ) -> tuple[FileType, str | None, float]:
        """Detect if file is binary or text and determine encoding.

        Args:
            path: Path to the file.
            size: File size in bytes.

        Returns:
            Tuple of (FileType, encoding or None, confidence).
        """
        if size == 0:
            return FileType.TEXT, "utf-8", 1.0

        # Read a sample for detection
        sample_size = min(size, self.BINARY_DETECTION_SIZE)

        try:
            with open(path, "rb") as f:
                sample = f.read(sample_size)
        except OSError as e:
            logger.warning(f"Could not read file for type detection: {e}")
            return FileType.UNKNOWN, None, 0.0

        # Check for binary content (null bytes, etc.)
        if self._is_binary_content(sample):
            return FileType.BINARY, None, 1.0

        # Try to detect encoding
        encoding, confidence = self._detect_encoding(sample)

        return FileType.TEXT, encoding, confidence

    def _is_binary_content(self, data: bytes) -> bool:
        """Check if byte content appears to be binary.

        Args:
            data: Byte data to check.

        Returns:
            True if content appears to be binary.
        """
        if not data:
            return False

        # Check for Unicode BOMs - these indicate text encodings, not binary
        # UTF-16 LE: FF FE, UTF-16 BE: FE FF, UTF-8 BOM: EF BB BF, UTF-32: various
        if data.startswith(
            (b"\xff\xfe", b"\xfe\xff", b"\xef\xbb\xbf", b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")
        ):
            return False  # It's a Unicode text file

        # Check for null bytes - strong indicator of binary
        # However, UTF-16 uses null bytes, so this is handled by BOM check above
        if b"\x00" in data:
            # If there's a regular pattern of nulls (every other byte), might be UTF-16
            # Check if it looks like UTF-16 without BOM
            if self._looks_like_utf16(data):
                return False
            return True

        # Count control characters (excluding common text ones)
        # Exclude: tab (9), newline (10), carriage return (13)
        control_chars = sum(1 for byte in data if byte < 32 and byte not in (9, 10, 13))

        # If more than 10% control characters, likely binary
        threshold = len(data) * 0.1
        return control_chars > threshold

    def _looks_like_utf16(self, data: bytes) -> bool:
        """Check if data looks like UTF-16 encoded text.

        Args:
            data: Byte data to check.

        Returns:
            True if data appears to be UTF-16 encoded.
        """
        if len(data) < 4:
            return False

        # Check for alternating null bytes pattern typical of UTF-16 LE ASCII
        # In UTF-16 LE, ASCII characters are represented as char + 0x00
        null_at_odd = sum(1 for i in range(1, len(data), 2) if data[i] == 0)
        null_at_even = sum(1 for i in range(0, len(data), 2) if data[i] == 0)

        total_pairs = len(data) // 2
        if total_pairs == 0:
            return False

        # If most odd positions (LE) or even positions (BE) are null, likely UTF-16
        return (null_at_odd / total_pairs > 0.7) or (null_at_even / total_pairs > 0.7)

    def _detect_encoding(self, sample: bytes) -> tuple[str, float]:
        """Detect text encoding from sample bytes.

        Uses charset-normalizer if available, falls back to simple heuristics.

        Args:
            sample: Byte sample to analyze.

        Returns:
            Tuple of (encoding_name, confidence).
        """
        # Try charset-normalizer if available
        try:
            from charset_normalizer import from_bytes

            result = from_bytes(sample)
            best = result.best()
            if best is not None:
                return best.encoding, 1.0 - (best.chaos if hasattr(best, "chaos") else 0.0)
        except ImportError:
            logger.debug("charset-normalizer not available, using fallback detection")
        except Exception as e:
            logger.debug(f"charset-normalizer failed: {e}")

        # Fallback: try common encodings
        encodings_to_try = ["utf-8", "utf-16", "latin-1", "cp1252", "ascii"]

        for encoding in encodings_to_try:
            try:
                sample.decode(encoding)
                # UTF-8 is most common, give it higher confidence
                confidence = 0.9 if encoding == "utf-8" else 0.7
                return encoding, confidence
            except (UnicodeDecodeError, LookupError):
                continue

        # Last resort: latin-1 can decode any byte sequence
        return "latin-1", 0.5

    async def _open_file(self) -> None:
        """Open the file handle and optionally set up mmap."""
        if self._file_info is None:
            raise RuntimeError("File must be analyzed before opening")

        # Determine if we should use mmap
        use_mmap = self._should_use_mmap()

        await asyncio.to_thread(self._open_file_sync, use_mmap)

    def _should_use_mmap(self) -> bool:
        """Determine if memory-mapped I/O should be used."""
        if self._forced_mmap is not None:
            return self._forced_mmap

        if self._file_info is None:
            return False

        # Use mmap for large files
        return self._file_info.size >= self.mmap_threshold

    def _open_file_sync(self, use_mmap: bool) -> None:
        """Synchronously open the file (runs in thread pool)."""
        if self._file_info is None:
            raise RuntimeError("File info not available")

        self._file = open(self.path, "rb")

        if use_mmap and self._file_info.size > 0:
            try:
                self._mmap = mmap.mmap(
                    self._file.fileno(),
                    0,  # Map entire file
                    access=mmap.ACCESS_READ,
                )
                logger.debug(f"Using mmap for {self.path}")
            except (OSError, ValueError) as e:
                logger.debug(f"Could not mmap file: {e}")
                # Fall back to regular file reading
                self._mmap = None

    async def close(self) -> None:
        """Close the file and release resources."""
        if not self._is_open:
            return

        await asyncio.to_thread(self._close_sync)
        self._is_open = False
        self._position = 0

    def _close_sync(self) -> None:
        """Synchronously close file handles."""
        if self._mmap is not None:
            try:
                self._mmap.close()
            except Exception as e:
                logger.debug(f"Error closing mmap: {e}")
            self._mmap = None

        if self._file is not None:
            try:
                self._file.close()
            except Exception as e:
                logger.debug(f"Error closing file: {e}")
            self._file = None

    async def read(self) -> str:
        """Read the entire file as text.

        Returns:
            File contents as a string.

        Raises:
            RuntimeError: If file is not open.
            UnicodeDecodeError: If content cannot be decoded.
        """
        if not self._is_open:
            raise RuntimeError("File is not open. Call open() first.")

        if self._file_info is None:
            raise RuntimeError("File info not available")

        data = await asyncio.to_thread(self._read_all_sync)
        return self._decode(data)

    async def read_bytes(self) -> bytes:
        """Read the entire file as bytes.

        Returns:
            File contents as bytes.

        Raises:
            RuntimeError: If file is not open.
        """
        if not self._is_open:
            raise RuntimeError("File is not open. Call open() first.")

        return await asyncio.to_thread(self._read_all_sync)

    def _read_all_sync(self) -> bytes:
        """Synchronously read entire file content."""
        if self._mmap is not None:
            self._mmap.seek(0)
            return self._mmap.read()
        elif self._file is not None:
            self._file.seek(0)
            return self._file.read()
        else:
            raise RuntimeError("No file handle available")

    async def read_chunk(self, size: int | None = None) -> bytes:
        """Read a chunk of bytes from the current position.

        Args:
            size: Number of bytes to read. Defaults to chunk_size.

        Returns:
            Bytes read from file (may be less than size at EOF).

        Raises:
            RuntimeError: If file is not open.
        """
        if not self._is_open:
            raise RuntimeError("File is not open. Call open() first.")

        chunk_size = size or self.chunk_size
        data = await asyncio.to_thread(self._read_chunk_sync, chunk_size)
        self._position += len(data)
        return data

    def _read_chunk_sync(self, size: int) -> bytes:
        """Synchronously read a chunk from current position."""
        if self._mmap is not None:
            return self._mmap.read(size)
        elif self._file is not None:
            return self._file.read(size)
        else:
            raise RuntimeError("No file handle available")

    async def read_chunks(self, chunk_size: int | None = None):
        """Async generator that yields file content in chunks.

        Args:
            chunk_size: Size of each chunk. Defaults to self.chunk_size.

        Yields:
            Bytes chunks of the file.

        Raises:
            RuntimeError: If file is not open.
        """
        if not self._is_open:
            raise RuntimeError("File is not open. Call open() first.")

        size = chunk_size or self.chunk_size

        # Reset to start
        await self.seek(0)

        while True:
            chunk = await self.read_chunk(size)
            if not chunk:
                break
            yield chunk

    async def read_text_chunks(self, chunk_size: int | None = None):
        """Async generator that yields file content as decoded text chunks.

        Args:
            chunk_size: Size of each chunk in bytes. Defaults to self.chunk_size.

        Yields:
            Text strings decoded from byte chunks.

        Note:
            This may produce incorrect results for multi-byte encodings if
            a character spans chunk boundaries. For best results with
            multi-byte encodings, use read() for the full content.
        """
        async for chunk in self.read_chunks(chunk_size):
            yield self._decode(chunk)

    async def seek(self, position: int, whence: int = os.SEEK_SET) -> int:
        """Seek to a position in the file.

        Args:
            position: Position to seek to.
            whence: Reference point (os.SEEK_SET, os.SEEK_CUR, os.SEEK_END).

        Returns:
            New absolute position.

        Raises:
            RuntimeError: If file is not open.
        """
        if not self._is_open:
            raise RuntimeError("File is not open. Call open() first.")

        new_pos = await asyncio.to_thread(self._seek_sync, position, whence)
        self._position = new_pos
        return new_pos

    def _seek_sync(self, position: int, whence: int) -> int:
        """Synchronously seek in the file."""
        if self._mmap is not None:
            self._mmap.seek(position, whence)
            return self._mmap.tell()
        elif self._file is not None:
            self._file.seek(position, whence)
            return self._file.tell()
        else:
            raise RuntimeError("No file handle available")

    def _decode(self, data: bytes) -> str:
        """Decode bytes to string using detected or forced encoding.

        Args:
            data: Bytes to decode.

        Returns:
            Decoded string.
        """
        if self._file_info is None:
            encoding = "utf-8"
        else:
            encoding = self._file_info.encoding or "utf-8"

        try:
            return data.decode(encoding)
        except (UnicodeDecodeError, LookupError):
            # Fallback to latin-1 which can decode any byte sequence
            logger.debug(f"Failed to decode with {encoding}, falling back to latin-1")
            return data.decode("latin-1")

    async def detect_type(self) -> FileType:
        """Detect and return the file type.

        Can be called without opening the file.

        Returns:
            FileType indicating if file is text, binary, or unknown.
        """
        if self._file_info is not None:
            return self._file_info.file_type

        # Analyze without fully opening
        info = await asyncio.to_thread(self._analyze_file)
        return info.file_type

    @classmethod
    async def is_binary(cls, path: Path) -> bool:
        """Class method to check if a file is binary.

        Args:
            path: Path to the file to check.

        Returns:
            True if file appears to be binary.
        """
        reader = cls(path)
        file_type = await reader.detect_type()
        return file_type == FileType.BINARY

    @classmethod
    async def is_text(cls, path: Path) -> bool:
        """Class method to check if a file is text.

        Args:
            path: Path to the file to check.

        Returns:
            True if file appears to be text.
        """
        reader = cls(path)
        file_type = await reader.detect_type()
        return file_type == FileType.TEXT

    @classmethod
    async def read_file(
        cls,
        path: Path,
        encoding: str | None = None,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> str:
        """Convenience method to read a file in one call.

        Args:
            path: Path to the file to read.
            encoding: Force a specific encoding, or None for auto-detect.
            chunk_size: Chunk size for reading.

        Returns:
            File contents as string.
        """
        async with cls(path, chunk_size=chunk_size, encoding=encoding) as reader:
            return await reader.read()

    @classmethod
    async def read_file_bytes(
        cls,
        path: Path,
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> bytes:
        """Convenience method to read a file as bytes in one call.

        Args:
            path: Path to the file to read.
            chunk_size: Chunk size for reading.

        Returns:
            File contents as bytes.
        """
        async with cls(path, chunk_size=chunk_size) as reader:
            return await reader.read_bytes()
