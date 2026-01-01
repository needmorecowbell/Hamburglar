# Configuration

Hamburglar uses a flexible configuration system that supports multiple file formats and sources. Configuration can be set via files, environment variables, or command-line arguments.

## Configuration File Location

Hamburglar searches for configuration files in the following locations (in order):

1. Current directory
2. Parent directories (up to filesystem root)
3. `~/.config/hamburglar/`
4. `~/.hamburglar/`

### Supported File Names

Configuration files are detected in this order of preference:

| File Name | Format |
|-----------|--------|
| `.hamburglar.yml` | YAML |
| `.hamburglar.yaml` | YAML |
| `.hamburglar.toml` | TOML |
| `hamburglar.config.json` | JSON |
| `.hamburglarrc` | Auto-detect (YAML/TOML/JSON) |
| `.hamburglarrc.json` | JSON |
| `.hamburglarrc.yaml` | YAML |
| `.hamburglarrc.yml` | YAML |

You can also specify a config file explicitly with the `--config` flag:

```bash
hamburglar scan --config /path/to/config.yml ./src
```

## Configuration Precedence

Configuration is merged from multiple sources in the following order (later sources override earlier ones):

1. **Default values** (lowest priority)
2. **Configuration file**
3. **Environment variables**
4. **CLI arguments** (highest priority)

This means CLI arguments always take precedence, allowing you to override any setting on a per-command basis.

## Configuration Options

### Scan Settings

Controls how files are discovered and processed during scanning.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `scan.recursive` | boolean | `true` | Scan directories recursively |
| `scan.max_file_size` | integer/string | `10485760` (10MB) | Maximum file size to scan. Accepts bytes or human-readable format (e.g., `10MB`, `1G`) |
| `scan.concurrency` | integer | `50` | Maximum concurrent file operations (1-1000) |
| `scan.timeout` | float | `30.0` | Timeout in seconds for individual file scans (0 for unlimited) |
| `scan.blacklist` | list[string] | see below | Patterns to exclude from scanning |
| `scan.whitelist` | list[string] | `[]` | If non-empty, only scan files matching these patterns |

**Default blacklist:**
```yaml
blacklist:
  - .git
  - __pycache__
  - node_modules
  - .venv
  - venv
  - .env
  - "*.pyc"
  - "*.pyo"
```

### Detector Settings

Controls which detectors and patterns are used during scanning.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `detector.enabled_categories` | list[string] | `[]` (all) | Pattern categories to enable. Empty means all categories are enabled |
| `detector.disabled_patterns` | list[string] | `[]` | Specific pattern names to disable |
| `detector.min_confidence` | string | `"low"` | Minimum confidence level for findings: `low`, `medium`, `high` |
| `detector.custom_patterns_path` | string/null | `null` | Path to custom pattern definitions file |

**Available categories:**
- `api_keys` - API keys and tokens
- `cloud` - Cloud provider credentials (AWS, GCP, Azure)
- `credentials` - Usernames, passwords, connection strings
- `crypto` - Cryptographic keys and secrets
- `generic` - Generic secret patterns
- `network` - Network credentials and URLs with embedded auth
- `private_keys` - SSH, PGP, and other private keys

### Output Settings

Controls how scan results are formatted and saved.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output.format` | string | `"table"` | Output format: `json`, `table`, `sarif`, `csv`, `html`, `markdown` |
| `output.output_path` | string/null | `null` | Path to save output file (null for stdout) |
| `output.save_to_db` | boolean | `false` | Save findings to SQLite database |
| `output.db_path` | string | `~/.hamburglar/findings.db` | Path to SQLite database file |
| `output.quiet` | boolean | `false` | Suppress non-essential output |
| `output.verbose` | boolean | `false` | Enable verbose output |

### YARA Settings

Controls YARA rule loading and execution.

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `yara.enabled` | boolean | `false` | Enable YARA rule scanning |
| `yara.rules_path` | string/null | `null` | Path to YARA rules directory or file |
| `yara.timeout` | float | `30.0` | Timeout in seconds for YARA matching |
| `yara.compiled_rules_path` | string/null | `null` | Path to pre-compiled YARA rules (for performance) |

### Global Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `log_level` | string | `"info"` | Logging level: `debug`, `info`, `warning`, `error`, `critical` |

## Environment Variables

All environment variables use the `HAMBURGLAR_` prefix.

| Variable | Maps To | Description |
|----------|---------|-------------|
| `HAMBURGLAR_CONFIG_PATH` | - | Path to configuration file |
| `HAMBURGLAR_CONCURRENCY` | `scan.concurrency` | Number of concurrent file operations |
| `HAMBURGLAR_MAX_FILE_SIZE` | `scan.max_file_size` | Maximum file size (e.g., `10MB`) |
| `HAMBURGLAR_TIMEOUT` | `scan.timeout` | Timeout in seconds for file scans |
| `HAMBURGLAR_RECURSIVE` | `scan.recursive` | Scan recursively (`true`/`false`) |
| `HAMBURGLAR_CATEGORIES` | `detector.enabled_categories` | Comma-separated list of categories |
| `HAMBURGLAR_MIN_CONFIDENCE` | `detector.min_confidence` | Minimum confidence level |
| `HAMBURGLAR_OUTPUT_FORMAT` | `output.format` | Output format |
| `HAMBURGLAR_DB_PATH` | `output.db_path` | Path to SQLite database |
| `HAMBURGLAR_SAVE_TO_DB` | `output.save_to_db` | Save to database (`true`/`false`) |
| `HAMBURGLAR_QUIET` | `output.quiet` | Suppress output (`true`/`false`) |
| `HAMBURGLAR_VERBOSE` | `output.verbose` | Verbose output (`true`/`false`) |
| `HAMBURGLAR_YARA_RULES` | `yara.rules_path` | Path to YARA rules |
| `HAMBURGLAR_YARA_ENABLED` | `yara.enabled` | Enable YARA (`true`/`false`) |
| `HAMBURGLAR_LOG_LEVEL` | `log_level` | Logging level |

**Boolean parsing:** Environment variables accept `true`, `1`, `yes`, `on`, `enabled` as true values. All other values are treated as false.

## Example Configurations

### YAML (Recommended)

```yaml
# .hamburglar.yml

# Scan settings
scan:
  recursive: true
  max_file_size: 10MB
  concurrency: 50
  timeout: 30
  blacklist:
    - .git
    - __pycache__
    - node_modules
    - .venv
    - venv
    - "*.pyc"
  whitelist: []

# Detector settings
detector:
  enabled_categories: []  # empty = all categories
  disabled_patterns: []
  min_confidence: low
  # custom_patterns_path: ./custom_patterns.yaml

# Output settings
output:
  format: table
  output_path: null  # stdout
  save_to_db: false
  # db_path: ~/.hamburglar/findings.db

# YARA settings
yara:
  enabled: false
  # rules_path: ./rules
  timeout: 30

# Logging
log_level: info
```

### TOML

```toml
# .hamburglar.toml

[scan]
recursive = true
max_file_size = "10MB"
concurrency = 50
timeout = 30
blacklist = [
    ".git",
    "__pycache__",
    "node_modules",
    ".venv",
    "venv",
    "*.pyc",
]
whitelist = []

[detector]
enabled_categories = []
disabled_patterns = []
min_confidence = "low"
# custom_patterns_path = "./custom_patterns.yaml"

[output]
format = "table"
save_to_db = false
# db_path = "~/.hamburglar/findings.db"

[yara]
enabled = false
timeout = 30
# rules_path = "./rules"

log_level = "info"
```

### JSON

```json
{
  "scan": {
    "recursive": true,
    "max_file_size": "10MB",
    "concurrency": 50,
    "timeout": 30,
    "blacklist": [
      ".git",
      "__pycache__",
      "node_modules",
      ".venv",
      "venv",
      "*.pyc"
    ],
    "whitelist": []
  },
  "detector": {
    "enabled_categories": [],
    "disabled_patterns": [],
    "min_confidence": "low"
  },
  "output": {
    "format": "table",
    "output_path": null,
    "save_to_db": false
  },
  "yara": {
    "enabled": false,
    "timeout": 30
  },
  "log_level": "info"
}
```

## Common Scenarios

### CI/CD Pipeline

For automated scanning in CI pipelines, use SARIF output with strict confidence:

```yaml
# .hamburglar.yml
scan:
  max_file_size: 5MB
  timeout: 10

detector:
  min_confidence: medium

output:
  format: sarif  # GitHub-compatible format
  quiet: true
```

### Large Repository

For scanning large repositories efficiently:

```yaml
# .hamburglar.yml
scan:
  max_file_size: 50MB
  concurrency: 100
  timeout: 60
  blacklist:
    - .git
    - node_modules
    - vendor
    - dist
    - build
    - "*.min.js"
    - "*.bundle.js"
```

### Security Audit

For thorough security audits with database tracking:

```yaml
# .hamburglar.yml
detector:
  min_confidence: low  # catch everything
  enabled_categories:
    - api_keys
    - credentials
    - private_keys
    - cloud

output:
  format: json
  save_to_db: true
  db_path: ./audit-findings.db

yara:
  enabled: true
  rules_path: ./yara-rules

log_level: debug
```

### Pre-commit Hook

Minimal config for fast pre-commit scanning:

```yaml
# .hamburglar.yml
scan:
  max_file_size: 1MB
  concurrency: 20
  timeout: 5

detector:
  min_confidence: high  # only high-confidence findings

output:
  quiet: true
```

### Specific File Types Only

Scan only specific file types:

```yaml
# .hamburglar.yml
scan:
  whitelist:
    - "*.py"
    - "*.js"
    - "*.ts"
    - "*.env"
    - "*.json"
    - "*.yml"
    - "*.yaml"
```

## Managing Configuration

### Initialize a Config File

```bash
# Create .hamburglar.yml in current directory
hamburglar config init

# Create TOML config
hamburglar config init --format toml

# Create in specific directory
hamburglar config init /path/to/project
```

### View Current Configuration

```bash
# Show merged configuration
hamburglar config show

# Show with sources (where each value came from)
hamburglar config show --sources

# Output as JSON
hamburglar config show --format json
```

### Validate Configuration

```bash
# Validate auto-detected config file
hamburglar config validate

# Validate specific file
hamburglar config validate .hamburglar.yml
```

## File Size Parsing

The `max_file_size` option accepts human-readable formats:

| Format | Bytes |
|--------|-------|
| `100` | 100 |
| `10K` or `10KB` | 10,240 |
| `10M` or `10MB` | 10,485,760 |
| `1G` or `1GB` | 1,073,741,824 |

## See Also

- [CLI Reference](cli-reference.md) - Command-line options
- [Detectors](detectors.md) - Detection patterns
- [Outputs](outputs.md) - Output formats
- [Plugins](plugins.md) - Plugin system
