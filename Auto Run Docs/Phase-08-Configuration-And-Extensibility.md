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

- [ ] Create `src/hamburglar/plugins/output_plugin.py` with `OutputPlugin` base class that: defines required interface (name, format method), supports configuration via plugin config section, integrates with the output registry

- [ ] Create example plugin `examples/plugins/custom_detector.py` that: demonstrates creating a custom detector, includes inline documentation, shows configuration usage, can be installed via pip or file copy

- [ ] Create example config file `examples/hamburglar.example.yml` with: all configuration options documented with comments, example custom patterns, example plugin configuration, common use case configurations

- [ ] Update CLI to add `config` command group with: `config show` - displays current config with sources, `config init` - creates default config file in current directory, `config validate` - validates config file syntax

- [ ] Update CLI to add `plugins` command group with: `plugins list` - shows installed plugins, `plugins info <name>` - shows plugin details

- [ ] Update CLI to respect config file settings, with CLI args overriding config

- [ ] Create `tests/test_config_loading.py` with tests for: config file is found and loaded, environment variables override config file, CLI args override environment variables, invalid config raises helpful error, missing config file uses defaults

- [ ] Create `tests/test_config_schema.py` with tests for: all settings have proper types, defaults are applied correctly, validation catches invalid values, nested settings work correctly

- [ ] Create `tests/test_plugins.py` with tests for: plugin discovery finds installed plugins, detector plugin can be loaded and used, output plugin can be loaded and used, invalid plugin raises helpful error, plugin config is passed correctly

- [ ] Create `tests/fixtures/configs/` with test config files in various formats (YAML, TOML, JSON)

- [ ] Add `pyyaml` and `tomli` (for Python < 3.11) to project dependencies

- [ ] Run pytest and ensure all tests pass with maintained 95%+ coverage
