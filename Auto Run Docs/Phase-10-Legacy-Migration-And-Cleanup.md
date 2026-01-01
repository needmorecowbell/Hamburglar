# Phase 10: Legacy Migration and Cleanup

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase completes the modernization by ensuring all functionality from the original hamburglar.py is preserved or improved, provides a migration path for existing users, and cleans up legacy code. Any remaining original features not yet ported are implemented, and the old code is archived for reference before removal.

## Tasks

- [x] Create `src/hamburglar/compat/` directory for backward compatibility utilities
  - Created `src/hamburglar/compat/` directory with `__init__.py` and `.gitkeep`
  - Module includes docstring describing purpose (legacy patterns, IOC extraction, migration helpers)

- [ ] Create `src/hamburglar/compat/legacy_patterns.py` that imports ALL regex patterns from original hamburglar.py not yet included in the new pattern library, ensuring zero detection regression

- [ ] Audit original hamburglar.py `regexList` dictionary against new patterns, create list of any missing patterns, and add them to appropriate pattern modules

- [ ] Create `src/hamburglar/utils/hexdump.py` with modernized hexdump functionality from original: `hexdump(file_path) -> str` function, same output format as original for compatibility, add optional color output using rich

- [ ] Add `hexdump` command to CLI that: takes file path argument, outputs hex dump to stdout, supports `--output` to save to file, matches original `hamburglar.py -x` behavior

- [ ] Create `src/hamburglar/compat/ioc_extract.py` with optional iocextract integration: wrapper around iocextract library, detector implementation using iocextract, graceful fallback when iocextract not installed

- [ ] Add `--use-iocextract` flag to scan command that enables iocextract-based detection in addition to regex patterns (matching original `-i` flag behavior)

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
