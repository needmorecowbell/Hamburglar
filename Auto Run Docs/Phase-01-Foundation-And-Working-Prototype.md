# Phase 01: Foundation and Working Prototype

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

- [ ] Create `src/hamburglar/core/scanner.py` with a `Scanner` class that: takes a `ScanConfig`, has an async `scan()` method that walks directories respecting blacklist/whitelist, reads files, passes content to detectors, and returns a `ScanResult`

- [ ] Create `src/hamburglar/detectors/__init__.py` with a `BaseDetector` abstract class defining `name` property and `detect(content: str) -> list[Finding]` method, plus a `DetectorRegistry` class to register and retrieve detectors

- [ ] Create `src/hamburglar/detectors/regex_detector.py` with a `RegexDetector` class that loads patterns from a config dict, iterates patterns against content, and returns `Finding` objects for matches. Include the top 20 most critical patterns from the original hamburglar.py: AWS keys, GitHub tokens, private keys (RSA, SSH, PGP), API keys (generic, Slack, Google), emails, IPv4, Bitcoin addresses, Ethereum addresses, URLs, and generic secrets

- [ ] Create `src/hamburglar/detectors/yara_detector.py` with a `YaraDetector` class that compiles YARA rules from a directory path and returns `Finding` objects for rule matches

- [ ] Create `src/hamburglar/outputs/__init__.py` with a `BaseOutput` abstract class defining `format(result: ScanResult) -> str` method and an `OutputRegistry` class

- [ ] Create `src/hamburglar/outputs/json_output.py` with a `JsonOutput` class that serializes `ScanResult` to formatted JSON using Pydantic's `.model_dump_json(indent=2)`

- [ ] Create `src/hamburglar/outputs/table_output.py` with a `TableOutput` class that uses `rich.table.Table` to create a console-friendly table showing file path, detector, match count, and severity for each finding

- [ ] Create `src/hamburglar/cli/__init__.py` as empty package init

- [ ] Create `src/hamburglar/cli/main.py` with Typer app containing: `scan` command (positional path argument, --recursive/-r flag default True, --output/-o for output file, --format/-f choice of json/table default table, --yara/-y path to yara rules, --verbose/-v flag), version callback with `--version` flag, and rich console for styled output

- [ ] Create `tests/__init__.py` as empty package init

- [ ] Create `tests/conftest.py` with pytest fixtures: `temp_directory` (creates temp dir with sample files containing fake secrets), `sample_content_with_secrets` (returns string with AWS key, email, Bitcoin address, RSA private key header), and `scanner_config` (returns default ScanConfig)

- [ ] Create `tests/test_models.py` with tests for: Finding model creation and serialization, ScanResult with multiple findings, ScanConfig defaults and validation

- [ ] Create `tests/test_regex_detector.py` with tests for: detecting AWS API keys (AKIA pattern), detecting emails, detecting Bitcoin addresses, detecting RSA private key headers, returning empty list for clean content, handling binary content gracefully

- [ ] Create `tests/test_scanner.py` with integration tests for: scanning a directory with secrets and finding them, respecting blacklist patterns, respecting whitelist when enabled, handling empty directories, handling permission errors gracefully

- [ ] Create `tests/test_cli.py` with CLI tests using Typer's CliRunner: test --version outputs version, test scan command with temp directory produces output, test --format json produces valid JSON, test --format table produces table output

- [ ] Copy the existing `rules/` directory YARA files into the project structure at `src/hamburglar/rules/` and update `pyproject.toml` to include them as package data

- [ ] Create `.python-version` file containing `3.11` for pyenv compatibility

- [ ] Create `ruff.toml` with configuration: line-length 100, target Python 3.9, select rules (E, F, I, UP, B, SIM, TCH), ignore E501 for long regex patterns

- [ ] Run `pip install -e ".[dev]"` to install the package in development mode and verify the `hamburglar` command is available

- [ ] Run `pytest tests/ -v --cov=hamburglar --cov-report=term-missing` and ensure all tests pass with at least 80% coverage on the new code

- [ ] Run `hamburglar scan . --format table` from the project root to verify the CLI works end-to-end and produces output (it should detect patterns in the old hamburglar.py file itself)

- [ ] Run `ruff check src/` and `ruff format src/` to ensure code passes linting and is properly formatted
