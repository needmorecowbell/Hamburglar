# Phase 08: Configuration and Extensibility

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase implements a robust configuration system and plugin architecture, allowing users to customize Hamburglar's behavior without modifying code. Configuration can come from files, environment variables, or CLI arguments with proper precedence. The plugin system enables adding custom detectors and outputs without forking the project.

## Tasks

- [x] Create `src/hamburglar/config/__init__.py` with configuration loading priority: CLI arguments > environment variables > config file > defaults
  - Created comprehensive config module with `get_config()`, `load_config()`, `reset_config()` functions
  - Implemented `ConfigPriority` enum for tracking configuration sources
  - Added proper merging logic with `_merge_configs()` and `_normalize_cli_args()`
  - Also created supporting modules: `schema.py`, `loader.py`, `env.py`
  - Added `tests/test_config_loading.py` with 21 tests covering all priority scenarios

- [x] Create `src/hamburglar/config/schema.py` with Pydantic Settings models: `ScanSettings` (recursive, max_file_size, concurrency, timeout), `DetectorSettings` (enabled_categories, disabled_patterns, min_confidence, custom_patterns_path), `OutputSettings` (format, output_path, save_to_db, db_path), `YaraSettings` (rules_path, timeout, enabled), `HamburglarConfig` combining all settings
  - Already created as part of task 1; verified complete with all required models
  - Includes additional features: `LogLevel` enum, `OutputFormatConfig` enum, blacklist/whitelist in ScanSettings
  - Has validators for file size parsing, confidence levels, and format validation

- [x] Create `src/hamburglar/config/loader.py` with a `ConfigLoader` class that: searches for config files (.hamburglar.yml, .hamburglar.yaml, .hamburglar.toml, hamburglar.config.json), supports project-local and user-global configs (~/.config/hamburglar/), merges configs with proper precedence, validates config against schema, provides helpful error messages for invalid config
  - Already created as part of task 1; verified complete with all required features
  - Supports YAML, TOML, JSON formats with auto-detection for .hamburglarrc files
  - Includes `validate_config_file()` method and `get_default_config_content()` for generating templates

- [x] Create `src/hamburglar/config/env.py` with environment variable mapping: HAMBURGLAR_CONFIG_PATH, HAMBURGLAR_YARA_RULES, HAMBURGLAR_OUTPUT_FORMAT, HAMBURGLAR_DB_PATH, HAMBURGLAR_CONCURRENCY, HAMBURGLAR_LOG_LEVEL, HAMBURGLAR_CATEGORIES
  - Already created as part of task 1; verified complete with all required env vars
  - Also includes: HAMBURGLAR_MAX_FILE_SIZE, HAMBURGLAR_TIMEOUT, HAMBURGLAR_RECURSIVE, HAMBURGLAR_YARA_ENABLED, HAMBURGLAR_SAVE_TO_DB, HAMBURGLAR_MIN_CONFIDENCE, HAMBURGLAR_QUIET, HAMBURGLAR_VERBOSE

- [x] Create `src/hamburglar/plugins/__init__.py` with plugin system base: `PluginManager` class, `@detector_plugin` decorator, `@output_plugin` decorator, plugin discovery from entry points and directories
  - Implemented comprehensive `PluginManager` class with full lifecycle management
  - Added `@detector_plugin` and `@output_plugin` decorators with validation
  - Supports plugin discovery from Python entry points (`hamburglar.plugins.detectors`/`hamburglar.plugins.outputs`)
  - Supports plugin discovery from configured plugin directories
  - Added `PluginInfo` dataclass for plugin metadata
  - Added `PluginError` exception for plugin-related errors
  - Includes global `get_plugin_manager()` and `reset_plugin_manager()` functions
  - Created `tests/test_plugins.py` with 50 comprehensive tests covering all functionality

- [x] Create `src/hamburglar/plugins/discovery.py` with plugin discovery that: scans configured plugin directories, loads plugins from Python packages via entry points, validates plugins implement required interfaces, provides plugin listing command
  - Implemented `discover_plugins()` as the main entry point for all discovery sources
  - Added `discover_entry_points()` for Python package entry point discovery
  - Added `discover_directory()` for scanning plugin directories
  - Implemented `validate_plugin_interface()` for validating detector/output interfaces
  - Added `list_plugins()` and `get_plugin_details()` for plugin listing CLI support
  - Added `format_plugin_list()` and `format_plugin_details()` for formatted output
  - Created `DiscoveryResult` dataclass for discovery operation results
  - Created `PluginListEntry` dataclass for CLI listing display
  - Added `tests/test_plugin_discovery.py` with 30 comprehensive tests

- [x] Create `src/hamburglar/plugins/detector_plugin.py` with `DetectorPlugin` base class that: defines required interface (name, detect method), supports configuration via plugin config section, provides utility methods for pattern matching, integrates with the detector registry
  - Implemented `DetectorPlugin` abstract base class extending `BaseDetector`
  - Supports configuration via constructor kwargs with `config` property and `get_config()` method
  - Added utility methods: `match_pattern()`, `match_patterns()`, `match_literal()` for pattern matching
  - Added `compile_pattern()` with caching for efficient regex compilation
  - Added `create_finding()` helper for creating Finding objects
  - Added `should_scan_file()` for file extension filtering via `supported_extensions` property
  - Added `register()` and `unregister()` for detector registry integration
  - Includes metadata properties: `description`, `version`, `author`
  - Created `tests/test_detector_plugin.py` with 52 comprehensive tests at 98% coverage

- [x] Create `src/hamburglar/plugins/output_plugin.py` with `OutputPlugin` base class that: defines required interface (name, format method), supports configuration via plugin config section, integrates with the output registry
  - Implemented `OutputPlugin` abstract base class extending `BaseOutput`
  - Supports configuration via constructor kwargs with `config` property and `get_config()` method
  - Added utility methods: `format_finding()`, `format_result()`, `get_summary()` for structured output
  - Added `format_as_json()` and `format_as_lines()` convenience methods
  - Added `group_by_file()`, `group_by_severity()`, `group_by_detector()` for grouped output
  - Added `file_extension` property for output format extension hints
  - Added `register()` and `unregister()` for output registry integration
  - Includes metadata properties: `description`, `version`, `author`
  - Created `tests/test_output_plugin.py` with 53 comprehensive tests

- [x] Create example plugin `examples/plugins/custom_detector.py` that: demonstrates creating a custom detector, includes inline documentation, shows configuration usage, can be installed via pip or file copy
  - Implemented `CustomAPIKeyDetector` class extending `DetectorPlugin` with comprehensive inline documentation
  - Demonstrates configuration via constructor kwargs: min_key_length, check_entropy, min_entropy, key_prefixes, case_sensitive
  - Shows installation methods: file copy to plugin directory or pip entry points
  - Includes entropy-based filtering to reduce false positives
  - Demonstrates severity assessment based on key characteristics (production vs staging)
  - Shows usage of base class utility methods: match_pattern, match_patterns, match_literal, create_finding
  - Created `tests/test_example_custom_detector.py` with 22 comprehensive tests

- [x] Create example config file `examples/hamburglar.example.yml` with: all configuration options documented with comments, example custom patterns, example plugin configuration, common use case configurations
  - Created comprehensive 540+ line example configuration file with detailed documentation
  - Documented all configuration sections: scan, detector, output, yara, log_level, plugins
  - Included environment variable mappings and CLI override references for each option
  - Added comprehensive blacklist with 30+ common exclusion patterns
  - Added plugin configuration example for custom_api_keys detector
  - Included 6 common use case configuration examples:
    1. Quick security scan (high confidence only)
    2. CI/CD pipeline integration with SARIF output
    3. Comprehensive security audit with YARA
    4. Python project only scanning
    5. JavaScript/Node.js project scanning
    6. Pre-commit hook configuration
  - Added 3 tests in test_config_loading.py to validate example file

- [x] Update CLI to add `config` command group with: `config show` - displays current config with sources, `config init` - creates default config file in current directory, `config validate` - validates config file syntax
  - Added `config_app` Typer sub-application with three commands: `show`, `init`, `validate`
  - `config show`: Displays merged configuration from all sources in YAML/JSON/TOML format, with `--sources` flag to show where each setting came from
  - `config init`: Creates default config file (.hamburglar.yml/.toml/.json) with documented settings, supports `--force` to overwrite existing files
  - `config validate`: Validates config file syntax and schema, auto-detects config file if not specified
  - Created `tests/test_cli_config.py` with 31 comprehensive tests covering all subcommands and edge cases

- [x] Update CLI to add `plugins` command group with: `plugins list` - shows installed plugins, `plugins info <name>` - shows plugin details
  - Implemented `plugins_app` Typer sub-application with two commands: `list`, `info`
  - `plugins list`: Shows detector/output plugins in table/json/plain formats with `--type`, `--verbose`, `--discover`, `--quiet` options
  - `plugins info <name>`: Displays comprehensive plugin details in table/json/plain formats
  - Created `tests/test_cli_plugins.py` with 24 comprehensive tests covering all subcommands and edge cases

- [x] Update CLI to respect config file settings, with CLI args overriding config
  - Updated `scan`, `scan-git`, and `scan-web` commands to load configuration from config files
  - Added `--config` / `-C` option to all three commands to specify explicit config file path
  - Implemented priority: CLI args > environment variables > config file > defaults
  - Made options nullable (Optional[bool]/Optional[str]/etc.) to distinguish "not specified" from explicit values
  - Added `--no-yara` flag to scan command to explicitly disable YARA even if enabled in config
  - Updated `--recursive`, `--verbose`, `--quiet`, `--save-to-db` to use flag pairs (e.g., `--recursive/--no-recursive`)
  - Added `get_effective_config()` helper function for loading and merging configurations
  - All 3809 tests pass with the new implementation

- [x] Create `tests/test_config_loading.py` with tests for: config file is found and loaded, environment variables override config file, CLI args override environment variables, invalid config raises helpful error, missing config file uses defaults
  - File already existed from task 1 with 24 comprehensive tests covering all required scenarios
  - Test classes: TestConfigDefaults, TestConfigFileLoading, TestEnvironmentVariableOverrides, TestCLIArgumentOverrides, TestInvalidConfigHandling, TestConfigMerging, TestConfigLoader, TestGetConfig, TestFileSizeParsing, TestExampleConfigFile
  - All 24 tests pass successfully

- [x] Create `tests/test_config_schema.py` with tests for: all settings have proper types, defaults are applied correctly, validation catches invalid values, nested settings work correctly
  - Created comprehensive test file with 83 tests organized into 18 test classes
  - `TestLogLevelEnum`, `TestOutputFormatConfigEnum`: Tests for enum values
  - `TestScanSettingsTypes/Defaults/Validation`: Type checking, default values, validation for ScanSettings
  - `TestDetectorSettingsTypes/Defaults/Validation`: Type checking, default values, validation for DetectorSettings
  - `TestOutputSettingsTypes/Defaults/Validation`: Type checking, default values, validation for OutputSettings
  - `TestYaraSettingsTypes/Defaults/Validation`: Type checking, default values, validation for YaraSettings
  - `TestHamburglarConfigTypes/Defaults/Validation`: Type checking, default values, validation for main config
  - `TestNestedSettingsWork`: Tests for nested dict creation, partial dicts, pre-constructed objects, deeply nested validation
  - `TestToScanConfig`: Tests for the to_scan_config conversion method
  - `TestConfigExtraFields`: Tests that extra fields are ignored correctly
  - All 3869 tests pass with 83 new tests added

- [x] Create `tests/test_plugins.py` with tests for: plugin discovery finds installed plugins, detector plugin can be loaded and used, output plugin can be loaded and used, invalid plugin raises helpful error, plugin config is passed correctly
  - File already existed from task 5 with 50 comprehensive tests organized into 10 test classes
  - `TestPluginDiscovery`: Tests plugin discovery with 4 tests (empty, directory, skips private, force rediscover)
  - `TestPluginManager`: Tests plugin registration and retrieval with 26 tests
  - `TestPluginIntegration`: Tests that loaded detector/output plugins actually work
  - `TestDecoratorPlugins`: Tests invalid plugins raise helpful errors (missing detect/format/name)
  - `TestPluginWithConfig`: Tests plugin config is passed correctly (2 tests)
  - All 50 tests pass successfully

- [x] Create `tests/fixtures/configs/` with test config files in various formats (YAML, TOML, JSON)
  - Created 18 fixture config files covering valid, invalid, minimal, and empty configurations
  - **Valid configs**: `valid_basic.{yml,toml,json}` and `valid_full.{yml,toml,json}` with all settings
  - **Minimal configs**: `minimal.{yml,toml,json}` with only one setting to test default merging
  - **Empty configs**: `empty.{yml,toml,json}` to test all-defaults behavior
  - **Invalid syntax**: `invalid_syntax.{yml,toml,json}` to test error handling for malformed files
  - **Invalid values**: `invalid_values.{yml,toml,json}` to test schema validation errors
  - Added `README.md` documenting all fixture files and their expected behaviors
  - Created `tests/test_config_fixtures.py` with 40 tests validating all fixture files:
    - Tests loading configs successfully in all 3 formats
    - Tests validation passes for valid configs
    - Tests proper error handling for invalid configs
    - Tests consistency - equivalent configs in different formats produce identical results
  - All 3909 tests pass (40 new tests added)

- [ ] Add `pyyaml` and `tomli` (for Python < 3.11) to project dependencies

- [ ] Run pytest and ensure all tests pass with maintained 95%+ coverage
