# Phase 01: Foundation and Working Prototype

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase establishes the modern project structure, updates all dependencies to secure versions, creates the modular architecture, and delivers a working CLI that can scan a directory and output findings. By the end of this phase, you will have a fully functional `hamburglar` command that installs via pip and produces real detection results—proving the modernization is on solid ground.

## Tasks

- [x] Create the new project structure with the following directories: `src/hamburglar/`, `src/hamburglar/core/`, `src/hamburglar/detectors/`, `src/hamburglar/outputs/`, `src/hamburglar/cli/`, and `tests/`
  - Created: `src/hamburglar/`, `src/hamburglar/core/`, `src/hamburglar/detectors/`, `src/hamburglar/outputs/`, `src/hamburglar/cli/`, `tests/`

- [x] Create `pyproject.toml` with project metadata, Python 3.11+ requirement (with 3.9+ compatibility), dependencies (typer, rich, yara-python, pydantic, pydantic-settings), dev dependencies (pytest, pytest-cov, pytest-asyncio, ruff, mypy), and console script entry point `hamburglar = "hamburglar.cli.main:app"`
  - Created `pyproject.toml` with hatchling build system, all required dependencies, dev extras, console script entry point, and tool configurations for pytest, mypy, and coverage

- [x] Create `src/hamburglar/__init__.py` with `__version__ = "2.0.0"` and package docstring describing Hamburglar as a static analysis tool for extracting sensitive information
  - Created `src/hamburglar/__init__.py` with module docstring describing Hamburglar as a static analysis tool for extracting sensitive information from files using regex and YARA rules, plus `__version__ = "2.0.0"`

- [x] Create `src/hamburglar/core/__init__.py` as empty package init
  - Created empty package init with minimal comment header

- [x] Create `src/hamburglar/core/models.py` with Pydantic models: `Finding` (file_path, detector_name, matches list, severity enum, metadata dict), `ScanResult` (target_path, findings list, scan_duration, stats dict), and `ScanConfig` (target_path, recursive bool, use_yara bool, yara_rules_path, output_format enum, blacklist list, whitelist list)
  - Created Pydantic models with all required fields plus `Severity` enum (CRITICAL/HIGH/MEDIUM/LOW/INFO) and `OutputFormat` enum (JSON/TABLE). Added sensible default blacklist patterns for common excludes (.git, __pycache__, node_modules, etc.)

- [x] Create `src/hamburglar/core/scanner.py` with a `Scanner` class that: takes a `ScanConfig`, has an async `scan()` method that walks directories respecting blacklist/whitelist, reads files, passes content to detectors, and returns a `ScanResult`
  - Created `Scanner` class with async `scan()` method that handles file discovery via `_discover_files()`, file reading via async `_read_file()`, and detector orchestration via `_scan_file()`. Supports blacklist/whitelist pattern matching with fnmatch, handles permission errors gracefully, provides UTF-8/latin-1 fallback for file encoding, and returns comprehensive stats in ScanResult.

- [x] Create `src/hamburglar/detectors/__init__.py` with a `BaseDetector` abstract class defining `name` property and `detect(content: str) -> list[Finding]` method, plus a `DetectorRegistry` class to register and retrieve detectors
  - Created `BaseDetector` ABC with abstract `name` property and `detect(content: str, file_path: str) -> list[Finding]` method. Created `DetectorRegistry` class with `register()`, `unregister()`, `get()`, `get_all()`, `list_names()` methods plus `__len__` and `__contains__` for convenience. Included a `default_registry` global instance for easy access.

- [x] Create `src/hamburglar/detectors/regex_detector.py` with a `RegexDetector` class that loads patterns from a config dict, iterates patterns against content, and returns `Finding` objects for matches. Include the top 20 most critical patterns from the original hamburglar.py: AWS keys, GitHub tokens, private keys (RSA, SSH, PGP), API keys (generic, Slack, Google), emails, IPv4, Bitcoin addresses, Ethereum addresses, URLs, and generic secrets
  - Created `RegexDetector` class with 20 pre-compiled patterns covering: AWS API Key/Secret, GitHub tokens (modern ghp_/gho_/etc and legacy), RSA/DSA/EC/OpenSSH/PGP private keys, Slack tokens/webhooks, Google OAuth, Heroku API, generic API keys/secrets, email, IPv4, URLs, Bitcoin, and Ethereum addresses. Supports custom patterns via constructor, add_pattern(), and remove_pattern() methods. Patterns are pre-compiled for performance and have appropriate severity levels assigned.

- [x] Create `src/hamburglar/detectors/yara_detector.py` with a `YaraDetector` class that compiles YARA rules from a directory path and returns `Finding` objects for rule matches
  - Created `YaraDetector` class that compiles YARA rules from a directory (recursively finds .yar/.yara files) or single file. Supports both string content via `detect()` and raw bytes via `detect_bytes()`. Extracts rule metadata (author, description, tags) into Finding metadata. Includes `reload_rules()` method for dynamic rule updates and optional `severity_mapping` parameter to customize severity per rule. Handles YARA errors gracefully and returns empty list on match failures.

- [x] Create `src/hamburglar/outputs/__init__.py` with a `BaseOutput` abstract class defining `format(result: ScanResult) -> str` method and an `OutputRegistry` class
  - Created `BaseOutput` ABC with abstract `name` property and `format(result: ScanResult) -> str` method. Created `OutputRegistry` class with `register()`, `unregister()`, `get()`, `get_all()`, `list_names()` methods plus `__len__` and `__contains__` for convenience. Follows the same pattern as DetectorRegistry. Included a `default_registry` global instance for easy access.

- [x] Create `src/hamburglar/outputs/json_output.py` with a `JsonOutput` class that serializes `ScanResult` to formatted JSON using Pydantic's `.model_dump_json(indent=2)`
  - Created `JsonOutput` class with `name` property returning "json" and `format(result)` method that serializes `ScanResult` using Pydantic's `model_dump_json(indent=2)` for human-readable output

- [x] Create `src/hamburglar/outputs/table_output.py` with a `TableOutput` class that uses `rich.table.Table` to create a console-friendly table showing file path, detector, match count, and severity for each finding
  - Created `TableOutput` class that renders `ScanResult` as a Rich table with columns for file path, detector name, match count, and severity. Includes color-coded severity levels (CRITICAL=bold red, HIGH=red, MEDIUM=yellow, LOW=blue, INFO=dim) and a comprehensive summary section showing scan duration, total findings, file statistics, and severity breakdown.

- [x] Create `src/hamburglar/cli/__init__.py` as empty package init
  - Created empty package init with minimal comment header matching the core/__init__.py style

- [x] Create `src/hamburglar/cli/main.py` with Typer app containing: `scan` command (positional path argument, --recursive/-r flag default True, --output/-o for output file, --format/-f choice of json/table default table, --yara/-y path to yara rules, --verbose/-v flag), version callback with `--version` flag, and rich console for styled output
  - Created `src/hamburglar/cli/main.py` with complete Typer CLI application. Implements `scan` command with all specified options: positional path argument (with exists/resolve_path validation), --recursive/-r flag (default True), --output/-o for file output, --format/-f choice (json/table, default table), --yara/-y for YARA rules path (with exists validation), --verbose/-v flag for detailed output. Includes --version callback at both app and command level. Uses Rich console for styled output with color-coded error messages and warnings. Initializes RegexDetector by default and YaraDetector when --yara is provided. Runs async Scanner.scan() and formats output using JsonOutput or TableOutput based on format selection.

- [x] Create `tests/__init__.py` as empty package init
  - Created empty package init with minimal comment header matching the style of core/__init__.py and cli/__init__.py

- [x] Create `tests/conftest.py` with pytest fixtures: `temp_directory` (creates temp dir with sample files containing fake secrets), `sample_content_with_secrets` (returns string with AWS key, email, Bitcoin address, RSA private key header), and `scanner_config` (returns default ScanConfig)
  - Created `tests/conftest.py` with all required fixtures plus bonus fixtures (`scanner_config_non_recursive`, `scanner_config_with_whitelist`, `scanner_config_with_blacklist`) for comprehensive testing. Added path configuration to handle legacy `hamburglar.py` shadowing issue. Also added `pythonpath = ["src"]` to `pyproject.toml` pytest configuration.

- [x] Create `tests/test_models.py` with tests for: Finding model creation and serialization, ScanResult with multiple findings, ScanConfig defaults and validation
  - Created comprehensive test suite with 26 tests covering: Severity enum values and string comparisons, OutputFormat enum values and string comparisons, Finding model creation (minimal/full), serialization (JSON/dict), empty matches, default severity. ScanResult creation, multiple findings, JSON serialization, empty findings. ScanConfig creation, defaults (including default blacklist patterns), path as string conversion, output format validation, custom/empty blacklist, whitelist patterns, and YARA configuration.

- [x] Create `tests/test_regex_detector.py` with tests for: detecting AWS API keys (AKIA pattern), detecting emails, detecting Bitcoin addresses, detecting RSA private key headers, returning empty list for clean content, handling binary content gracefully
  - Created comprehensive test suite with 44 tests across 10 test classes: TestRegexDetectorBasics (detector init/config), TestAWSKeyDetection (AKIA patterns + secret keys), TestEmailDetection (various email formats), TestBitcoinAddressDetection (addresses starting with 1 and 3), TestRSAPrivateKeyDetection (RSA/DSA/EC/OpenSSH/PGP key headers), TestCleanContent (empty/clean files), TestBinaryContentHandling (binary/unicode/mixed encoding), TestOtherPatterns (GitHub/Slack tokens, IPv4, Ethereum, URLs), TestPatternManagement (add/remove patterns), TestFindingMetadata (pattern metadata in findings), TestDeduplication (match deduplication). All tests pass.

- [x] Create `tests/test_scanner.py` with integration tests for: scanning a directory with secrets and finding them, respecting blacklist patterns, respecting whitelist when enabled, handling empty directories, handling permission errors gracefully
  - Created comprehensive integration test suite with 29 tests across 11 test classes: TestScannerWithSecrets (directory scanning, AWS keys, emails, private keys, single files, nested files), TestBlacklistPatterns (file exclusions, directory exclusions, multiple patterns, default .git and __pycache__ exclusions), TestWhitelistPatterns (include only matching files, multiple patterns, no matching files, whitelist + blacklist interaction), TestEmptyDirectories (empty dirs, dirs with only subdirs), TestNonRecursiveScanning (non-recursive mode), TestPermissionErrors (unreadable files/directories, nonexistent paths), TestScannerWithNoDetectors (no detectors, empty detector list), TestScannerWithMultipleDetectors (multiple detectors), TestScannerDetectorErrors (graceful error handling), TestScanResult (duration/stats), TestBinaryFileHandling (binary files, mixed content). All 29 tests pass.

- [x] Create `tests/test_cli.py` with CLI tests using Typer's CliRunner: test --version outputs version, test scan command with temp directory produces output, test --format json produces valid JSON, test --format table produces table output
  - Created comprehensive test suite with 27 tests across 9 test classes: TestVersionOutput (version flag tests), TestScanCommand (scan functionality, single files, nonexistent paths, recursive flag), TestJsonFormatOutput (JSON validity, required fields, findings structure, case-insensitivity), TestTableFormatOutput (table output, default format verification), TestInvalidFormat (error handling), TestVerboseFlag (verbose output), TestOutputFileOption (file output), TestEmptyDirectory (empty dir handling), TestHelpOutput (help information). All tests pass.

- [ ] Copy the existing `rules/` directory YARA files into the project structure at `src/hamburglar/rules/` and update `pyproject.toml` to include them as package data

- [ ] Create `.python-version` file containing `3.11` for pyenv compatibility

- [ ] Create `ruff.toml` with configuration: line-length 100, target Python 3.9, select rules (E, F, I, UP, B, SIM, TCH), ignore E501 for long regex patterns

- [ ] Run `pip install -e ".[dev]"` to install the package in development mode and verify the `hamburglar` command is available

- [ ] Run `pytest tests/ -v --cov=hamburglar --cov-report=term-missing` and ensure all tests pass with at least 80% coverage on the new code

- [ ] Run `hamburglar scan . --format table` from the project root to verify the CLI works end-to-end and produces output (it should detect patterns in the old hamburglar.py file itself)

- [ ] Run `ruff check src/` and `ruff format src/` to ensure code passes linting and is properly formatted
