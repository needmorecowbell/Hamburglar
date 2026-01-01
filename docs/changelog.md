# Changelog

All notable changes to Hamburglar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024

### Overview

Version 2.0.0 is a complete rewrite of Hamburglar with a new architecture, modern CLI, enhanced detection capabilities, and comprehensive documentation. This is a major release with breaking changes from 1.x.

### Added

- **New CLI powered by Typer**
  - Modern command-line interface with rich output
  - Subcommands: `scan`, `scan-git`, `scan-url`, `list-patterns`, `list-rules`, `config`, `history`
  - Shell completion support for bash, zsh, and fish
  - Colored output with progress indicators

- **Enhanced Detection Engine**
  - Regex-based pattern detection with 100+ patterns
  - YARA rule support for binary file detection
  - Entropy-based detection for encoded secrets
  - Categorized patterns: API keys, credentials, private keys, cloud, crypto, network

- **Multiple Output Formats**
  - Table (human-readable terminal output)
  - JSON (for programmatic processing)
  - CSV (for spreadsheet analysis)
  - HTML (rich reports)
  - Markdown (documentation-friendly)
  - SARIF (CI/CD integration)

- **Git Integration**
  - Scan remote repositories via URL
  - Scan local git repositories
  - Git history scanning to find secrets in past commits
  - Branch selection

- **Configuration System**
  - YAML, TOML, and JSON configuration file support
  - Environment variable configuration
  - Per-project and global configuration
  - Comprehensive configuration options

- **Plugin System**
  - Custom detector plugins
  - Custom output format plugins
  - Plugin discovery from multiple directories
  - Plugin configuration support

- **Scan History**
  - SQLite and JSON storage backends
  - View past scans
  - Export historical results
  - Compare scans over time

- **Async/Concurrent Architecture**
  - Parallel file scanning
  - Configurable thread count
  - Improved performance for large codebases

- **Comprehensive Documentation**
  - Installation guide
  - Quickstart tutorial
  - CLI reference
  - Configuration guide
  - Detector documentation
  - Output format guide
  - Plugin development guide
  - Contributing guidelines

### Changed

- Complete rewrite in modern Python (3.9+)
- Pydantic models for data validation
- Modular architecture with clear separation of concerns
- Standardized severity levels (critical, high, medium, low)
- Confidence scores for all findings
- Improved pattern accuracy and reduced false positives

### Breaking Changes

- **CLI Interface**: The command-line interface has completely changed
  - Old: `hamburglar -u URL` → New: `hamburglar scan-url URL`
  - Old: `hamburglar -p PATH` → New: `hamburglar scan PATH`
  - Old: `hamburglar -g REPO` → New: `hamburglar scan-git REPO`

- **Output Format**: JSON output structure has changed
  - Findings now include more metadata
  - Different field names and structure

- **Configuration**: Configuration file format has changed
  - Old INI-style `ham.conf` is no longer supported
  - Use YAML, TOML, or JSON configuration files

- **Python Version**: Requires Python 3.9+ (was 3.6+)

### Migration Guide

#### CLI Migration

| Old Command | New Command |
|-------------|-------------|
| `hamburglar -u https://example.com` | `hamburglar scan-url https://example.com` |
| `hamburglar -p /path/to/dir` | `hamburglar scan /path/to/dir` |
| `hamburglar -g https://github.com/user/repo` | `hamburglar scan-git https://github.com/user/repo` |
| `hamburglar -w wordlist.txt` | Use custom patterns in config |

#### Configuration Migration

Old `ham.conf`:
```ini
[paths]
wordlist = wordlist.txt

[options]
output = output.json
```

New `hamburglar.yml`:
```yaml
patterns:
  custom:
    - name: my_pattern
      pattern: "pattern_regex"
      severity: high

output:
  format: json
  file: output.json
```

#### Script Migration

Old Python usage:
```python
from hamburglar import Hamburglar
h = Hamburglar(url="https://example.com")
results = h.analyze()
```

New Python usage:
```python
from hamburglar import scan_url
results = scan_url("https://example.com")
for finding in results.findings:
    print(f"{finding.severity}: {finding.pattern_name}")
```

### Deprecated

- Legacy `ham.conf` configuration file (use YAML/TOML/JSON)
- Direct script execution (`python hamburglar.py`)

### Removed

- Python 3.6, 3.7, 3.8 support
- Old CLI interface
- Legacy pattern format
- Built-in wordlist functionality (replaced by pattern system)

## [1.x] - Previous Versions

For changes in version 1.x and earlier, see the [legacy changelog](https://github.com/needmorecowbell/Hamburglar/blob/v1/CHANGELOG.md).
