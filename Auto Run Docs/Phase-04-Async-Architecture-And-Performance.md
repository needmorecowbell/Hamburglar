# Phase 04: Async Architecture and Performance

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase replaces the legacy threading model with modern async/await patterns using asyncio, dramatically improving performance and resource efficiency. It adds progress reporting, concurrent file processing with configurable limits, and streaming output for large scans. The result is a scanner that handles massive codebases efficiently while providing real-time feedback to users.

## Tasks

- [x] Create `src/hamburglar/core/async_scanner.py` with an `AsyncScanner` class that: uses `asyncio.to_thread()` for file I/O operations, implements `asyncio.Semaphore` for concurrent file limit (default 50), provides async generator for streaming results, tracks progress (files scanned, files remaining, current file), supports cancellation via `asyncio.Event`
  - **Completed:** Created `AsyncScanner` class with full async/await support including:
    - `asyncio.to_thread()` for non-blocking file I/O operations
    - `asyncio.Semaphore` with configurable concurrency limit (default 50)
    - `scan_stream()` async generator for streaming findings in real-time
    - `ScanProgress` dataclass tracking total_files, scanned_files, current_file, bytes_processed, findings_count, elapsed_time, files_remaining
    - `asyncio.Event`-based cancellation via `cancel()` method and `is_cancelled` property
    - Added 36 comprehensive tests in `tests/test_async_scanner.py` covering all functionality
    - All 1820 tests pass with 95% coverage

- [x] Create `src/hamburglar/core/file_reader.py` with an `AsyncFileReader` class that: reads files asynchronously with configurable chunk size, detects encoding automatically (chardet/charset-normalizer), handles memory-mapped files for large file support, provides async context manager interface, implements file type detection (binary vs text)
  - **Completed:** Created `AsyncFileReader` class with comprehensive async file reading capabilities:
    - `asyncio.to_thread()` for non-blocking file I/O operations in thread pool
    - Configurable chunk size (default 8KB) with `read_chunks()` async generator
    - Automatic encoding detection using charset-normalizer with fallback heuristics
    - Memory-mapped file support via `mmap` module for large files (configurable threshold, default 10MB)
    - Full async context manager interface (`async with AsyncFileReader(...) as reader`)
    - File type detection with `FileType` enum (TEXT, BINARY, UNKNOWN) and UTF-16 BOM handling
    - `FileInfo` dataclass with path, file_type, encoding, size, and encoding_confidence
    - Convenience class methods: `read_file()`, `read_file_bytes()`, `is_binary()`, `is_text()`
    - Added charset-normalizer>=3.0.0 to pyproject.toml dependencies
    - Created 50 comprehensive tests in `tests/test_file_reader.py`
    - All 1870 tests pass with 93% coverage

- [x] Create `src/hamburglar/core/progress.py` with a `ScanProgress` dataclass (total_files, scanned_files, current_file, bytes_processed, findings_count, elapsed_time) and `ProgressReporter` protocol for pluggable progress reporting
  - **Completed:** Created `progress.py` module with comprehensive progress tracking capabilities:
    - `ScanProgress` dataclass with all required fields plus computed properties:
      - `files_remaining` (auto-computed)
      - `percent_complete` property (0-100%)
      - `files_per_second` throughput calculation
      - `bytes_per_second` throughput calculation
      - `estimated_time_remaining` property
      - `to_dict()` method for serialization
    - `ProgressReporter` protocol with `@runtime_checkable` decorator for pluggable reporting:
      - `on_progress(progress: ScanProgress)` for progress updates
      - `on_start(total_files: int)` for scan start notification
      - `on_complete(progress: ScanProgress)` for scan completion
      - `on_error(error: str, file_path: str | None)` for error reporting
    - `NullProgressReporter` class for no-op reporting (avoids None checks)
    - `CallbackProgressReporter` class for backward compatibility with callback-based reporting
    - Refactored `async_scanner.py` to import `ScanProgress` from `progress.py` (avoiding duplication)
    - Exported all classes from `hamburglar.core` package `__init__.py`
    - Created 42 comprehensive tests in `tests/test_progress.py` covering all functionality
    - All 1912 tests pass with 93% overall coverage (progress.py at 96%)

- [x] Create `src/hamburglar/outputs/streaming.py` with a `StreamingOutput` class that: yields findings as they're discovered, supports NDJSON (newline-delimited JSON) format, provides async iterator interface, allows real-time piping to other tools
  - **Completed:** Created comprehensive streaming output module with:
    - `StreamingOutput` class extending `BaseOutput` with NDJSON (newline-delimited JSON) format
    - `format_finding()` method for single finding JSON serialization
    - `stream_findings()` async generator for real-time streaming of findings
    - `write_stream()` method for direct output to file-like objects with optional flushing
    - `collect_findings()` method for collecting findings with optional max limit
    - `NDJSONStreamWriter` class for buffered output with backpressure handling:
      - Configurable buffer size (default 100)
      - Async context manager interface
      - `asyncio.Lock` for thread-safe buffering
      - `asyncio.to_thread()` for non-blocking writes
    - `stream_to_ndjson()` convenience function for easy NDJSON streaming
    - Exported all classes from `hamburglar.outputs` package
    - Created 37 comprehensive tests in `tests/test_streaming.py` covering:
      - NDJSON format correctness (valid JSON, single-line, no trailing commas)
      - Real-time streaming behavior
      - Stream interruption support
      - Backpressure handling
      - Integration with AsyncScanner
    - All 1949 tests pass with 94% overall coverage (streaming.py at 99%)

- [ ] Update `src/hamburglar/cli/main.py` to: use `asyncio.run()` for the scan command, add `--concurrency/-j` option for parallel file limit (default 50), add `--stream` flag for streaming output mode, add rich progress bar using `rich.progress.Progress`, display real-time stats (files/sec, findings count)

- [ ] Create `src/hamburglar/core/file_filter.py` with a `FileFilter` class that: implements efficient glob pattern matching, supports gitignore-style patterns, caches compiled patterns for reuse, provides both sync and async interfaces

- [ ] Update `src/hamburglar/detectors/regex_detector.py` to: support async detect method, implement pattern caching (compile once), add timeout per-pattern to prevent catastrophic backtracking, batch pattern matching for efficiency

- [ ] Update `src/hamburglar/detectors/yara_detector.py` to: support async detect method via thread pool, implement rule caching, add scan timeout configuration, support streaming match results

- [ ] Create `src/hamburglar/core/stats.py` with a `ScanStats` class that tracks: total files scanned, total bytes processed, files skipped (and reasons), findings by detector, findings by severity, scan duration, files per second throughput

- [ ] Add memory profiling utilities in `src/hamburglar/core/profiling.py` with: optional memory tracking, peak memory usage reporting, per-detector timing stats, exportable performance report

- [ ] Create `tests/test_async_scanner.py` with tests for: async scanning produces same results as sync, concurrency limit is respected, cancellation works correctly, progress callbacks are called, streaming output works

- [ ] Create `tests/test_file_reader.py` with tests for: async file reading works correctly, encoding detection works, large files are handled efficiently, binary file detection works, corrupt files don't crash reader

- [ ] Create `tests/test_performance.py` with performance benchmarks: scan speed with 100 files, scan speed with 1000 files, memory usage stays bounded, concurrent scanning is faster than sequential

- [ ] Create `tests/test_streaming.py` with tests for: NDJSON output format is correct, findings stream as discovered, stream can be interrupted, backpressure is handled correctly

- [ ] Update all existing tests to work with async scanner (use pytest-asyncio fixtures)

- [ ] Add `--benchmark` CLI flag that runs a quick performance test and reports files/second throughput

- [ ] Run pytest and ensure all tests pass with maintained 95%+ coverage, including async tests
