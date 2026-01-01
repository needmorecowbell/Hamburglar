# Hamburglar v1 to v2 Migration Guide

This guide helps users migrate from Hamburglar v1 (the original `hamburglar.py` script) to Hamburglar v2 (the modernized Python package).

## Quick Start

If you were running v1 like this:

```bash
# v1 - Old way
python hamburglar.py /path/to/scan

# v2 - New way
hamburglar scan /path/to/scan
```

## Table of Contents

1. [CLI Flag Changes](#cli-flag-changes)
2. [Output Format Changes](#output-format-changes)
3. [Configuration Changes](#configuration-changes)
4. [Removed Features](#removed-features)
5. [New Features](#new-features)
6. [Installation Changes](#installation-changes)
7. [Common Migration Scenarios](#common-migration-scenarios)

---

## CLI Flag Changes

### Command Structure Change

The biggest change is from a single-script approach to a subcommand-based CLI:

| v1 Usage | v2 Usage |
|----------|----------|
| `python hamburglar.py <path>` | `hamburglar scan <path>` |
| `python hamburglar.py -g <repo>` | `hamburglar scan-git <repo>` |
| `python hamburglar.py -w <url>` | `hamburglar scan-web <url>` |
| `python hamburglar.py -x <file>` | `hamburglar hexdump <file>` |

### Flag Mapping Reference

| v1 Flag | v2 Equivalent | Notes |
|---------|---------------|-------|
| `-g`, `--git` | `scan-git` command | Now a separate subcommand |
| `-w`, `--web` | `scan-web` command | Now a separate subcommand |
| `-x`, `--hexdump` | `hexdump` command | Now a separate subcommand with `--output` and `--color` options |
| `-v`, `--verbose` | `--verbose` | Same behavior, available on all commands |
| `-i`, `--ioc` | `--use-iocextract` / `-i` | Optional iocextract integration |
| `-o FILE`, `--out FILE` | `--output FILE` | Same behavior |
| `-y PATH`, `--yara PATH` | `--yara PATH` | Same behavior, path to YARA rules directory |
| *(hardcoded blacklist)* | `--blacklist-patterns` | Now configurable via CLI |
| *(hardcoded whitelist)* | `--whitelist-patterns` | Now configurable via CLI |
| *(not available)* | `--format FORMAT` | Choose output format (json, table, csv, html, markdown, sarif) |
| *(not available)* | `--categories` | Filter by pattern categories |
| *(not available)* | `--min-confidence` | Filter by confidence level |
| *(not available)* | `--stream` | Real-time streaming output |
| *(not available)* | `--dry-run` | Preview what would be scanned |
| *(not available)* | `--benchmark` | Performance profiling |
| *(not available)* | `--save-to-db` | Save to SQLite database |

### Detailed Examples

#### Basic Directory Scan

```bash
# v1
python hamburglar.py /path/to/project

# v2
hamburglar scan /path/to/project
```

#### Git Repository Scan

```bash
# v1
python hamburglar.py -g https://github.com/user/repo.git

# v2
hamburglar scan-git https://github.com/user/repo.git

# v2 with history analysis (new feature)
hamburglar scan-git https://github.com/user/repo.git --include-history
```

#### Web URL Scan

```bash
# v1
python hamburglar.py -w https://example.com/page.html

# v2
hamburglar scan-web https://example.com/page.html

# v2 with JavaScript extraction (new feature)
hamburglar scan-web https://example.com --include-scripts
```

#### Hexdump

```bash
# v1 (writes to <filename>.hexdump automatically)
python hamburglar.py -x /path/to/file

# v2 (outputs to stdout by default)
hamburglar hexdump /path/to/file

# v2 with file output
hamburglar hexdump /path/to/file --output dump.txt

# v2 with color output (new feature)
hamburglar hexdump /path/to/file --color
```

#### IOC Extraction

```bash
# v1
python hamburglar.py -i /path/to/scan

# v2
hamburglar scan /path/to/scan --use-iocextract
```

#### YARA Rule Scanning

```bash
# v1
python hamburglar.py -y /path/to/rules /path/to/scan

# v2
hamburglar scan /path/to/scan --yara /path/to/rules
```

#### Output to File

```bash
# v1
python hamburglar.py -o results.json /path/to/scan

# v2 (same behavior)
hamburglar scan /path/to/scan --output results.json

# v2 with format selection (new feature)
hamburglar scan /path/to/scan --output results.html --format html
```

---

## Output Format Changes

### JSON Output Format

The JSON output structure has been modernized:

#### v1 JSON Structure

```json
{
    "/path/to/file.txt": {
        "AWS API Key": ["AKIAIOSFODNN7EXAMPLE"],
        "GitHub": ["ghp_xxxxxxxxxxxx"]
    }
}
```

#### v2 JSON Structure

```json
{
    "scan_id": "uuid-here",
    "target": "/path/to/scan",
    "started_at": "2024-01-15T10:30:00Z",
    "completed_at": "2024-01-15T10:30:05Z",
    "duration_seconds": 5.2,
    "files_scanned": 42,
    "total_findings": 5,
    "findings": [
        {
            "file_path": "/path/to/file.txt",
            "pattern_name": "AWS_ACCESS_KEY_ID",
            "pattern_category": "api_keys",
            "matched_text": "AKIAIOSFODNN7EXAMPLE",
            "line_number": 15,
            "column": 8,
            "severity": "high",
            "confidence": "high",
            "context": "aws_access_key_id = AKIAIOSFODNN7EXAMPLE"
        }
    ]
}
```

### New Output Formats

v2 supports multiple output formats:

| Format | Extension | Description |
|--------|-----------|-------------|
| `table` | `.txt` | Rich console table (default) |
| `json` | `.json` | JSON with full metadata |
| `csv` | `.csv` | Spreadsheet-compatible |
| `html` | `.html` | Interactive HTML report |
| `markdown` | `.md` | GitHub-compatible markdown |
| `sarif` | `.sarif.json` | SARIF for IDE/CI integration |

---

## Configuration Changes

### From `ham.conf` to TOML Configuration

v1 used an INI-style `ham.conf` file for MySQL credentials:

```ini
# v1 ham.conf
[mySql]
user = hamman
password = deadbeef
```

v2 uses TOML configuration files with a hierarchical structure:

```toml
# v2 hamburglar.toml
[scan]
recursive = true
max_file_size = "10MB"
concurrency = 50
blacklist = [".git", "__pycache__", "node_modules"]
whitelist = []

[detector]
enabled_categories = []  # Empty means all
min_confidence = "low"
disabled_patterns = []

[output]
format = "table"
save_to_db = false
db_path = "~/.hamburglar/findings.db"
quiet = false
verbose = false

[yara]
enabled = false
rules_path = "./rules"
```

### Configuration File Locations

v2 searches for configuration in this order:

1. `--config` CLI argument
2. `./hamburglar.toml` (current directory)
3. `./.hamburglar.toml` (hidden in current directory)
4. `~/.config/hamburglar/config.toml` (user config directory)
5. `~/.hamburglar.toml` (home directory)

### Environment Variables

v2 supports environment variables with the `HAMBURGLAR_` prefix:

```bash
export HAMBURGLAR_SCAN__RECURSIVE=true
export HAMBURGLAR_OUTPUT__FORMAT=json
export HAMBURGLAR_DETECTOR__MIN_CONFIDENCE=high
```

### Blacklist/Whitelist Changes

v1 had hardcoded lists in `hamburglar.py`:

```python
# v1 - Hardcoded in hamburglar.py
blacklist = [
    ".git/objects/", ".git/index", "/node_modules/",
    "vendor/gems/", ".iso", ".bundle", ".png", ...
]
```

v2 provides configurable options:

```bash
# v2 - CLI flags
hamburglar scan /path --blacklist-patterns ".git,node_modules,*.min.js"
hamburglar scan /path --whitelist-patterns "*.py,*.js,*.yaml"
```

Or in config file:

```toml
[scan]
blacklist = [".git", "node_modules", "*.min.js"]
whitelist = ["*.py", "*.js", "*.yaml"]
```

---

## Removed Features

### MySQL Magic Signature Detection

**What it was:** v1 had functions (`compare_signature()`, `get_offset()`, `convert_to_regex()`) that queried a MySQL database containing file magic signatures to identify file types.

**Why removed:**
- Required setting up a MySQL database with specific schema
- Required maintaining a signature database
- Complex configuration with database credentials
- External dependency on MySQL server

**Alternative in v2:** YARA rules provide superior file type identification:
- The `rules/` directory contains ready-to-use magic signature rules
- No database required
- Rules for common formats: PNG, JPEG, GIF, PDF, executables, Office documents, etc.

```bash
# v2 - Use YARA rules for file type identification
hamburglar scan /path --yara ./rules
```

### newspaper3k Web Scraping

**What it was:** v1 used the `newspaper` library's `Article` class for web content extraction.

**Why removed:**
- newspaper3k is unmaintained
- Heavy dependencies
- Inconsistent HTML parsing

**Alternative in v2:** Modern `httpx` + `BeautifulSoup4`:
- More reliable HTTP handling
- Better JavaScript extraction with `--include-scripts`
- Configurable timeout and user agent

### Threading-based Worker Pool

**What it was:** v1 used Python's `threading` module with a fixed worker pool (`maxWorkers = 20`).

**Why removed:**
- Python's GIL limits threading effectiveness
- Manual thread management is error-prone
- No cancellation support

**Alternative in v2:** Async/await with `asyncio`:
- True concurrent I/O operations
- Configurable concurrency limits (`--concurrency`)
- Proper cancellation and timeout support
- Better memory efficiency

### Global Mutable State

**What it was:** v1 used global variables (`filestack`, `requestStack`, `cumulativeFindings`).

**Why removed:**
- Not thread-safe
- Prevents re-entrancy
- Makes testing difficult

**Alternative in v2:** Pydantic models with explicit data flow:
- `ScanResult` and `Finding` models
- Immutable data structures
- Full type safety

---

## New Features

### Pattern Categories

Filter scans by pattern category:

```bash
hamburglar scan /path --categories api_keys,credentials
```

Categories: `api_keys`, `cloud`, `credentials`, `crypto`, `database`, `generic`, `private_keys`

### Confidence Filtering

Filter by detection confidence:

```bash
hamburglar scan /path --min-confidence high
```

Levels: `low`, `medium`, `high`

### Multiple Output Formats

```bash
hamburglar scan /path --format sarif --output results.sarif.json
```

Formats: `table`, `json`, `csv`, `html`, `markdown`, `sarif`

### SQLite Database Storage

Persist findings for historical analysis:

```bash
hamburglar scan /path --save-to-db
hamburglar history  # View past scans
hamburglar report --since 2024-01-01  # Generate reports
```

### Git History Analysis

Scan git history for secrets that may have been removed:

```bash
hamburglar scan-git https://github.com/user/repo.git --include-history
```

### Real-time Streaming Output

See findings as they're discovered:

```bash
hamburglar scan /path --stream
```

### Doctor Command

Check system configuration and dependencies:

```bash
hamburglar doctor
hamburglar doctor --fix  # Auto-fix common issues
```

### Dry Run Mode

Preview what would be scanned:

```bash
hamburglar scan /path --dry-run
```

### Benchmark Mode

Performance profiling:

```bash
hamburglar scan /path --benchmark
```

### Plugin System

Create custom detectors and output formats. See `examples/plugins/` for examples.

---

## Installation Changes

### v1 Installation

```bash
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -r requirements.txt
python hamburglar.py --help
```

### v2 Installation

```bash
# From PyPI (when published)
pip install hamburglar

# From source
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -e .
hamburglar --help
```

### Dependencies

v1 required manually installing each dependency:
- `yara-python`
- `newspaper3k`
- `sqlalchemy`
- `pymysql`
- `iocextract` (optional)

v2 manages dependencies via `pyproject.toml`:
- Core: `typer`, `rich`, `yara-python`, `pydantic`
- Optional: `iocextract` (install separately if needed)

```bash
# Install iocextract for --use-iocextract flag
pip install iocextract
```

---

## Common Migration Scenarios

### Scenario 1: CI/CD Pipeline

**v1 Script:**
```bash
python hamburglar.py -o secrets.json .
if [ -s secrets.json ]; then exit 1; fi
```

**v2 Equivalent:**
```bash
hamburglar scan . --output secrets.json --format json --quiet
if [ -s secrets.json ]; then exit 1; fi
```

**Better v2 approach:**
```bash
# Use SARIF for CI integration
hamburglar scan . --format sarif --output results.sarif.json
# Or check exit code directly
hamburglar scan . --quiet && echo "No secrets found" || echo "Secrets found!"
```

### Scenario 2: Regular Codebase Scans

**v1 Script:**
```bash
python hamburglar.py -v /path/to/project -o $(date +%Y%m%d)_scan.json
```

**v2 Equivalent:**
```bash
hamburglar scan /path/to/project --verbose --save-to-db
hamburglar history --limit 10  # View recent scans
```

### Scenario 3: Git Repository Audit

**v1 Script:**
```bash
python hamburglar.py -g https://github.com/org/repo.git -y ./yara-rules
```

**v2 Equivalent:**
```bash
hamburglar scan-git https://github.com/org/repo.git --yara ./yara-rules --include-history
```

### Scenario 4: Web Application Scan

**v1 Script:**
```bash
python hamburglar.py -w https://example.com/api
```

**v2 Equivalent:**
```bash
hamburglar scan-web https://example.com/api --include-scripts --depth 2
```

---

## Getting Help

```bash
# General help
hamburglar --help

# Command-specific help
hamburglar scan --help
hamburglar scan-git --help
hamburglar scan-web --help

# System diagnostics
hamburglar doctor --verbose
```

For more information:
- Documentation: https://github.com/needmorecowbell/Hamburglar#readme
- Issues: https://github.com/needmorecowbell/Hamburglar/issues
