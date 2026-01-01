# Changelog

All notable changes to Hamburglar are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.0.0] - 2024

### Overview

Version 2.0.0 is a complete rewrite of Hamburglar with a modern architecture, async/await support, enhanced detection capabilities, and comprehensive documentation. This is a major release with breaking changes from 1.x.

### Added

#### New CLI powered by Typer
- Modern command-line interface with rich, colored output
- Main commands: `scan`, `scan-git`, `scan-web`, `history`, `report`
- Plugin management: `plugins list`, `plugins info`
- Configuration management: `config show`, `config init`, `config validate`
- Shell completion support for bash, zsh, and fish
- Progress indicators with spinners and status updates
- Exit codes: 0 (success with findings), 1 (error), 2 (no findings)

#### Enhanced Detection Engine
- **Regex-based pattern detection** with 160+ patterns across 7 categories:
  - `api_keys` (38 patterns): AWS, GitHub, GitLab, Stripe, Slack, Google, etc.
  - `credentials` (30 patterns): passwords, database connection strings
  - `crypto` (24 patterns): encryption keys, PGP/RSA/SSH keys
  - `cloud` (24 patterns): GCP, Azure, Alibaba Cloud credentials
  - `generic` (20 patterns): generic secrets and tokens
  - `network` (14 patterns): IPv4/IPv6, domains, URLs, emails
  - `private_keys` (10 patterns): various key formats
- **YARA rule support** for binary file detection with 19 built-in rules
- **Entropy-based detection** for encoded secrets (Shannon entropy)
- Severity levels: CRITICAL, HIGH, MEDIUM, LOW, INFO
- Confidence levels: HIGH, MEDIUM, LOW

#### Multiple Output Formats
- `table` - Human-readable terminal output with color-coded severity (default)
- `json` - Machine-readable JSON with full metadata
- `csv` - RFC 4180 compliant for spreadsheet analysis
- `html` - Standalone self-contained HTML reports
- `markdown` - GitHub-flavored Markdown with severity badges
- `sarif` - SARIF 2.1.0 for GitHub/GitLab/Azure DevOps integration
- `ndjson` - Streaming newline-delimited JSON

#### Git Integration
- Scan remote repositories via HTTPS or SSH URLs
- Scan local git repositories
- Git history scanning to find secrets in past commits
- Branch selection with `--branch` flag
- Configurable history depth with `--depth`
- Secret timeline tracking (when secrets were introduced/removed)

#### Web Scanning
- Fetch and scan web URLs for secrets
- HTML content extraction with BeautifulSoup
- JavaScript file scanning (inline and external)
- Link following with configurable depth
- Robots.txt parsing and respect
- Custom timeout and user agent support

#### Configuration System
- Multiple file formats: YAML, TOML, JSON
- Supported file names: `.hamburglar.yml`, `.hamburglar.yaml`, `.hamburglar.toml`, `hamburglar.config.json`, `.hamburglarrc`
- Hierarchical search: CWD → parent directories → `~/.config/hamburglar` → `~/.hamburglar`
- 15 environment variables with `HAMBURGLAR_` prefix
- Configuration validation with `config validate` command
- Per-project and global configuration support

#### Plugin System
- Custom detector plugins with full API access
- Custom output format plugins
- Four plugin discovery methods:
  - Python entry points (`hamburglar.plugins.detectors`, `hamburglar.plugins.outputs`)
  - Plugin directories (file-based Python modules)
  - Decorator registration (`@detector_plugin`, `@output_plugin`)
  - Manual registration via PluginManager
- Plugin configuration via YAML and environment variables

#### Scan History & Storage
- SQLite storage backend for persistent results
- View past scans with `history` command
- Generate reports from stored data with `report` command
- Filter by date range, severity, detector, file path
- Statistics aggregation (findings by severity, detector, file)

#### Async/Concurrent Architecture
- Fully async implementation with `asyncio`
- Parallel file scanning with configurable concurrency (default: 50)
- Semaphore-based concurrency control
- Streaming results as they're discovered
- Cancellation support

#### Python Library API
- High-level functions: `scan_directory()`, `scan_git()`, `scan_url()`
- Low-level `AsyncScanner` class for fine-grained control
- Pydantic models for data validation
- Type hints throughout

#### Docker Support
- Multi-stage Dockerfile for minimal image size
- Docker Compose configuration included
- Volume mounts for scanning local directories
- Pre-installed YARA rules

### Changed

- Complete rewrite in modern Python (3.9+)
- Pydantic v2 models for configuration and data validation
- Modular architecture with clear separation of concerns
- Standardized severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFO)
- Confidence scores for all findings
- Improved pattern accuracy and reduced false positives
- Rich console output with progress tracking

### Breaking Changes

#### CLI Interface
The command-line interface has completely changed:

| Old Command (1.x) | New Command (2.0) |
|-------------------|-------------------|
| `hamburglar -u https://example.com` | `hamburglar scan-web https://example.com` |
| `hamburglar -p /path/to/dir` | `hamburglar scan /path/to/dir` |
| `hamburglar -g https://github.com/user/repo` | `hamburglar scan-git https://github.com/user/repo` |
| `hamburglar -w wordlist.txt` | Use custom patterns in config file |

#### Output Format
JSON output structure has changed significantly:
- Findings now include more metadata (severity, confidence, detector name)
- Different field names and structure
- New `scan_id` and timestamp fields

#### Configuration
- Old INI-style `ham.conf` is **no longer supported**
- Use YAML, TOML, or JSON configuration files instead
- New configuration schema with sections: `scan`, `detector`, `output`, `yara`

#### Python Version
- Requires Python 3.9+ (was 3.6+)

#### Python API
```python
# Old usage (1.x)
from hamburglar import Hamburglar
h = Hamburglar(url="https://example.com")
results = h.analyze()

# New usage (2.0)
import asyncio
from hamburglar import scan_url
result = asyncio.run(scan_url("https://example.com"))
for finding in result.findings:
    print(f"{finding.severity}: {finding.detector_name}")
```

### Migration Guide

#### Step 1: Update Python Version
Ensure you have Python 3.9 or higher:
```bash
python --version  # Should be 3.9+
```

#### Step 2: Install New Version
```bash
pip install --upgrade hamburglar
```

#### Step 3: Update CLI Commands

| Task | Old Command | New Command |
|------|-------------|-------------|
| Scan directory | `hamburglar -p ./src` | `hamburglar scan ./src` |
| Scan URL | `hamburglar -u https://example.com` | `hamburglar scan-web https://example.com` |
| Scan git repo | `hamburglar -g https://github.com/user/repo` | `hamburglar scan-git https://github.com/user/repo` |
| JSON output | `hamburglar -p ./src -o output.json` | `hamburglar scan ./src --format json --output output.json` |

#### Step 4: Migrate Configuration

Old `ham.conf` (no longer supported):
```ini
[paths]
wordlist = wordlist.txt

[options]
output = output.json
```

New `.hamburglar.yml`:
```yaml
scan:
  recursive: true
  max_file_size: 10MB
  blacklist:
    - "*.log"
    - "node_modules"

detector:
  enabled_categories:
    - api_keys
    - credentials
    - private_keys
  min_confidence: medium

output:
  format: json
  output_path: results.json
```

#### Step 5: Update Python Scripts

```python
# Old (1.x)
from hamburglar import Hamburglar

def scan_code():
    h = Hamburglar(path="/path/to/code")
    return h.analyze()

# New (2.0)
import asyncio
from hamburglar import scan_directory

async def scan_code():
    result = await scan_directory("/path/to/code")
    return result

# Run with asyncio
result = asyncio.run(scan_code())
```

### Deprecated

- Legacy `ham.conf` configuration file format
- Direct script execution (`python hamburglar.py`)
- Synchronous scanning API

### Removed

- Python 3.6, 3.7, 3.8 support
- Old CLI interface (`-p`, `-u`, `-g` flags)
- Legacy pattern format
- Built-in wordlist functionality (replaced by pattern system)
- Old `Hamburglar` class API

## [1.x] - Previous Versions

For changes in version 1.x and earlier, see the [legacy releases](https://github.com/needmorecowbell/Hamburglar/releases).

---

## Upgrading

### From 1.x to 2.0

1. **Backup your configuration**: Save your `ham.conf` settings
2. **Update Python**: Ensure Python 3.9+ is installed
3. **Install v2.0**: `pip install --upgrade hamburglar`
4. **Create new config**: `hamburglar config init` to generate a template
5. **Migrate settings**: Transfer your old settings to the new YAML format
6. **Update scripts**: Migrate any Python scripts using the old API
7. **Test scans**: Run test scans to verify detection works as expected

### Need Help?

- [Documentation](https://github.com/needmorecowbell/Hamburglar/tree/master/docs)
- [Issue Tracker](https://github.com/needmorecowbell/Hamburglar/issues)
- [Discussions](https://github.com/needmorecowbell/Hamburglar/discussions)
