# Hamburglar v1 Archive

This directory contains the original Hamburglar v1 files, preserved for reference during and after the v2 migration.

## Archived Files

### hamburglar_v1.py
The original single-file Hamburglar implementation. Features included:
- 27 regex patterns for secret detection (AWS, GitHub, private keys, crypto addresses, etc.)
- Threading-based worker pool for file scanning
- Git repository scanning via shell commands
- Web URL scanning using newspaper3k library
- YARA rule support for file type identification
- MySQL-based magic signature detection (using external fileSign database)
- IOC extraction via iocextract library
- Hexdump output functionality

### ham_v1.conf
Original INI-style configuration file containing:
- MySQL database credentials for the magic signature detection feature

**Note:** This feature has been intentionally removed in v2. YARA rules provide superior file type identification without requiring external database setup.

### magic_sig_scraper_v1.py
Utility script that:
- Scraped file magic signatures from Wikipedia
- Stored them in a MySQL database for use with hamburglar.py's `compare_signature()` function

**Note:** This functionality has been replaced by the built-in YARA rules in the `rules/` directory.

## Migration to v2

See [MIGRATION.md](../MIGRATION.md) in the project root for:
- Complete CLI flag mapping (v1 to v2)
- Configuration migration guide (INI to TOML)
- Output format changes
- New features available in v2

## Why These Files Are Preserved

1. **Reference**: Developers can compare original implementations with new ones
2. **Regex patterns**: All 27 original patterns have been ported; this serves as verification source
3. **History**: Git history is preserved through `git mv` operations
4. **Migration support**: Users can review original behavior during transition

## Do Not Use These Files

These files are **not functional** in the v2 codebase:
- Dependencies like `newspaper3k` are no longer installed
- The MySQL-based signature detection requires external database setup
- Global state patterns are incompatible with the new async architecture

Use the new CLI commands instead:
```bash
# v2 equivalents
hamburglar scan <path>           # replaces: python hamburglar.py <path>
hamburglar scan-git <url>        # replaces: python hamburglar.py -g <url>
hamburglar scan-web <url>        # replaces: python hamburglar.py -w <url>
hamburglar hexdump <file>        # replaces: python hamburglar.py -x <file>
```
