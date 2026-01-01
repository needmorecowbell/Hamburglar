# Phase 10: Legacy Migration and Cleanup

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase completes the modernization by ensuring all functionality from the original hamburglar.py is preserved or improved, provides a migration path for existing users, and cleans up legacy code. Any remaining original features not yet ported are implemented, and the old code is archived for reference before removal.

## Tasks

- [x] Create `src/hamburglar/compat/` directory for backward compatibility utilities
  - Created `src/hamburglar/compat/` directory with `__init__.py` and `.gitkeep`
  - Module includes docstring describing purpose (legacy patterns, IOC extraction, migration helpers)

- [x] Create `src/hamburglar/compat/legacy_patterns.py` that imports ALL regex patterns from original hamburglar.py not yet included in the new pattern library, ensuring zero detection regression
  - Created comprehensive module with all 27 original regex patterns from `regexList` dictionary
  - Identified and added 13 legacy-only patterns not covered by new library (email, phone, site/URL, bitcoin URI, bitcoin xpub, bitcoin cash, dash, neo, facebook oauth, twitter oauth, generic secret legacy style, github legacy, heroku legacy)
  - Provides `LEGACY_REGEX_LIST` dictionary for drop-in replacement compatibility
  - Provides `LEGACY_ONLY_PATTERNS` list of Pattern objects for new detector system
  - Utility functions: `get_legacy_pattern_names()`, `get_legacy_pattern()`, `legacy_patterns_to_detector_format()`
  - Updated `src/hamburglar/compat/__init__.py` to export all legacy pattern utilities
  - Created comprehensive test suite in `tests/test_legacy_compat.py` with 73 tests covering all patterns

- [x] Audit original hamburglar.py `regexList` dictionary against new patterns, create list of any missing patterns, and add them to appropriate pattern modules
  - Audited all 27 patterns from original `regexList` dictionary against new pattern library
  - **Crypto patterns added to `crypto.py`:** BITCOIN_XPUB_KEY, BITCOIN_URI, BITCOIN_CASH_ADDRESS, DASH_ADDRESS, NEO_ADDRESS
  - **Generic patterns added to `generic.py`:** EMAIL_ADDRESS, PHONE_NUMBER_US, PHONE_NUMBER_INTL, URL_HTTP
  - **API patterns added to `api_keys.py`:** FACEBOOK_OAUTH_TOKEN, TWITTER_OAUTH_TOKEN, GITHUB_TOKEN_LEGACY, HEROKU_API_KEY_LEGACY, GENERIC_SECRET_LEGACY
  - Updated pattern collection counts in tests (crypto: 33→38, generic: 29→33, api_keys: 38→43)
  - All 4216 tests pass with no regressions

- [x] Create `src/hamburglar/utils/hexdump.py` with modernized hexdump functionality from original: `hexdump(file_path) -> str` function, same output format as original for compatibility, add optional color output using rich
  - Created `src/hamburglar/utils/` directory with `__init__.py` exporting hexdump function
  - Created `src/hamburglar/utils/hexdump.py` with:
    - `hexdump(file_path) -> str`: Main function matching original format (8-char hex offset, 16 bytes/line, ASCII column)
    - `hexdump_iter(file_path)`: Generator for memory-efficient streaming of large files
    - `hexdump_file(file_path, output)`: Direct file/stream output for efficiency
    - `hexdump_rich(file_path, console, highlight_patterns)`: Colorized output using Rich with:
      - Blue offset addresses, green printable bytes, yellow non-printable bytes
      - Optional pattern highlighting with custom colors
  - Created comprehensive test suite `tests/test_hexdump.py` with 28 tests covering:
    - Empty files, single bytes, full lines, partial lines
    - Binary/non-printable character handling
    - File errors (not found, permission denied, is directory)
    - Iterator and file output variants
    - Rich colorized output
    - Compatibility with original hamburglar.py format

- [x] Add `hexdump` command to CLI that: takes file path argument, outputs hex dump to stdout, supports `--output` to save to file, matches original `hamburglar.py -x` behavior
  - Added `hexdump` command to `src/hamburglar/cli/main.py`
  - Command takes a file path argument and outputs hex dump to stdout
  - Supports `--output` / `-o` flag to save to file
  - Supports `--color` / `--no-color` flag for colorized terminal output (using Rich)
  - Supports `--quiet` / `-q` flag to suppress informational messages
  - Proper error handling for non-existent files, directories, and permission errors
  - Created parent directories for output file if needed
  - Created comprehensive test suite `tests/test_cli_hexdump.py` with 22 tests covering:
    - Basic hexdump output, help display
    - Output to file with `--output` flag
    - Quiet mode, no-color mode
    - Error handling (file not found, directory, permission errors)
    - Format validation (offset padding, hex values, ASCII column)
    - Special file types (ELF, ZIP magic bytes)
    - Edge cases (empty files, single byte, partial lines)
  - All 590 CLI tests pass including the new hexdump tests

- [x] Create `src/hamburglar/compat/ioc_extract.py` with optional iocextract integration: wrapper around iocextract library, detector implementation using iocextract, graceful fallback when iocextract not installed
  - Created `src/hamburglar/compat/ioc_extract.py` with:
    - Wrapper functions: `extract_urls()`, `extract_ips()`, `extract_emails()`, `extract_hashes()`, `extract_yara_rules()`, plus specific hash type extractors (MD5, SHA1, SHA256, SHA512)
    - `IOCExtractDetector` class implementing BaseDetector interface for use with detector registry
    - `IOCExtractFallbackDetector` that returns empty findings when iocextract is unavailable
    - `get_detector()` factory function with optional fallback behavior
    - `extract_iocs_legacy()` function matching original hamburglar.py `-i` flag behavior
    - `extract_all_iocs()` for extracting all IOC types at once
    - `is_available()` and `get_import_error()` for availability checking
    - `IOCExtractNotAvailable` exception for proper error handling
  - Updated `src/hamburglar/compat/__init__.py` to export all iocextract utilities
  - Created comprehensive test suite `tests/test_ioc_extract.py` with 51 tests covering:
    - Availability checking functions (3 tests)
    - Exception handling (3 tests)
    - Fallback detector behavior (4 tests)
    - Factory function (2 tests)
    - Full detector functionality when iocextract available (16 tests, skipped when unavailable)
    - Wrapper functions when available (5 tests, skipped when unavailable)
    - Legacy compatibility functions (6 tests, skipped when unavailable)
    - Hash extraction functions (4 tests, skipped when unavailable)
    - Module exports validation (3 tests)
    - Mocked unavailability behavior (5 tests)
  - All 4286 tests pass (51 ioc_extract tests: 20 passed, 31 skipped due to iocextract not installed)

- [x] Add `--use-iocextract` flag to scan command that enables iocextract-based detection in addition to regex patterns (matching original `-i` flag behavior)
  - Added `--use-iocextract` / `-i` flag to `scan`, `scan-git`, and `scan-web` commands
  - When enabled, adds `IOCExtractDetector` to the list of detectors alongside regex patterns
  - Graceful error handling when iocextract is not installed (shows helpful install message)
  - Verbose mode shows "Loaded iocextract detector (URLs, IPs, emails, hashes, YARA rules)" message
  - Created comprehensive test suite `tests/test_cli_iocextract.py` with 21 tests covering:
    - Help output shows flag for all commands (3 tests)
    - Error handling when iocextract not installed (4 tests)
    - Scan works normally without flag (2 tests)
    - Integration with real library when available (5 tests, skipped when unavailable)
    - Mocked availability behavior (2 tests)
    - Dry-run compatibility (2 tests)
    - Compatibility with other flags (quiet, categories, min-confidence, stream) (4 tests)
  - All 4298 tests pass (64 skipped)

- [ ] Review original hamburglar.py for any features not yet implemented, document any intentionally removed features with rationale

- [ ] Create `MIGRATION.md` documenting: CLI flag changes (old flag -> new flag), output format changes, configuration changes, removed features and alternatives, new features available

- [ ] Create `scripts/migrate-config.py` that: converts old ham.conf to new YAML format, handles MySQL credential migration, provides interactive prompts for new options

- [ ] Archive original files: move hamburglar.py to `archive/hamburglar_v1.py`, move ham.conf to `archive/ham_v1.conf`, move utils/magic_sig_scraper.py to `archive/`, add README in archive explaining these are preserved for reference

- [ ] Update `.gitignore` to remove outdated entries, add new entries for modern tooling (.ruff_cache, .mypy_cache, etc.)

- [ ] Remove old requirements.txt (dependencies now in pyproject.toml)

- [ ] Create `tests/test_legacy_compat.py` with tests for: all original regex patterns still work, hexdump produces expected output, iocextract integration works when available, CLI flag compatibility where maintained

- [ ] Create `tests/test_migration.py` with tests for: old config files can be migrated, migration script handles edge cases, migrated config produces same behavior

- [ ] Run comprehensive test suite: all unit tests pass, all integration tests pass, coverage remains at or above 95%, no regressions in detection capability

- [ ] Run original hamburglar.py against test fixtures, run new hamburglar against same fixtures, verify new tool finds at least everything old tool found

- [ ] Update project version to 2.0.0 final in pyproject.toml and `__init__.py`

- [ ] Create git tag v2.0.0 (do not push, leave for user to review and push)

- [ ] Generate final summary report of modernization: lines of code comparison, test coverage achieved, features added, features preserved, performance improvements
