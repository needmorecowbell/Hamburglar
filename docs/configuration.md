# Configuration

Hamburglar can be configured using configuration files, environment variables, or command-line options.

## Configuration File Location

Hamburglar searches for configuration files in the following order:

1. Path specified with `--config` option
2. `hamburglar.yml` or `hamburglar.yaml` in current directory
3. `hamburglar.toml` in current directory
4. `hamburglar.json` in current directory
5. `.hamburglar.yml` in current directory
6. `~/.config/hamburglar/config.yml`

## Configuration File Format

Hamburglar supports YAML, TOML, and JSON configuration files.

### YAML Example

```yaml
# hamburglar.yml

# Scanning options
scan:
  recursive: true
  max_file_size: 10485760  # 10MB in bytes
  threads: 4
  follow_symlinks: false

# File filtering
files:
  include:
    - "*.py"
    - "*.js"
    - "*.ts"
    - "*.json"
    - "*.yml"
    - "*.yaml"
  exclude:
    - "node_modules/**"
    - "*.min.js"
    - ".git/**"
    - "__pycache__/**"
    - "*.pyc"
    - "dist/**"
    - "build/**"

# Detection settings
detection:
  enable_regex: true
  enable_yara: true
  enable_entropy: true
  min_entropy: 4.5
  min_severity: low
  min_confidence: 0.5

# Pattern categories to enable
patterns:
  categories:
    - api_keys
    - credentials
    - private_keys
    - cloud
    - crypto
    - network
  # Custom patterns
  custom:
    - name: internal_api_key
      pattern: "INTERNAL-[A-Z0-9]{32}"
      severity: high
      description: "Internal API key"

# YARA rules
yara:
  enabled: true
  rules_dir: null  # Use built-in rules
  custom_rules: []

# Output settings
output:
  format: table
  file: null
  include_context: true
  context_lines: 3

# Storage settings
storage:
  enabled: true
  backend: sqlite  # sqlite or json
  path: ~/.hamburglar/history.db

# Plugin settings
plugins:
  enabled: true
  directories:
    - ~/.hamburglar/plugins
    - ./plugins
```

### TOML Example

```toml
# hamburglar.toml

[scan]
recursive = true
max_file_size = 10485760
threads = 4
follow_symlinks = false

[files]
include = ["*.py", "*.js", "*.ts"]
exclude = ["node_modules/**", "*.min.js"]

[detection]
enable_regex = true
enable_yara = true
enable_entropy = true
min_entropy = 4.5
min_severity = "low"
min_confidence = 0.5

[patterns]
categories = ["api_keys", "credentials", "private_keys"]

[output]
format = "table"
include_context = true
context_lines = 3
```

### JSON Example

```json
{
  "scan": {
    "recursive": true,
    "max_file_size": 10485760,
    "threads": 4
  },
  "files": {
    "include": ["*.py", "*.js"],
    "exclude": ["node_modules/**"]
  },
  "detection": {
    "enable_regex": true,
    "enable_yara": true,
    "min_severity": "low"
  }
}
```

## Configuration Options Reference

### Scan Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `scan.recursive` | bool | `true` | Scan directories recursively |
| `scan.max_file_size` | int | `10485760` | Maximum file size in bytes |
| `scan.threads` | int | `4` | Number of parallel threads |
| `scan.follow_symlinks` | bool | `false` | Follow symbolic links |
| `scan.timeout` | int | `300` | Scan timeout in seconds |

### File Filtering

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `files.include` | list | `["*"]` | File patterns to include |
| `files.exclude` | list | `[]` | File patterns to exclude |
| `files.binary` | bool | `false` | Scan binary files |

### Detection Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `detection.enable_regex` | bool | `true` | Enable regex pattern detection |
| `detection.enable_yara` | bool | `true` | Enable YARA rule detection |
| `detection.enable_entropy` | bool | `true` | Enable entropy detection |
| `detection.min_entropy` | float | `4.5` | Minimum entropy threshold |
| `detection.min_severity` | str | `"low"` | Minimum severity to report |
| `detection.min_confidence` | float | `0.5` | Minimum confidence threshold |

### Pattern Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `patterns.categories` | list | all | Pattern categories to enable |
| `patterns.custom` | list | `[]` | Custom pattern definitions |
| `patterns.disabled` | list | `[]` | Specific patterns to disable |

### YARA Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `yara.enabled` | bool | `true` | Enable YARA scanning |
| `yara.rules_dir` | str | `null` | Custom rules directory |
| `yara.custom_rules` | list | `[]` | Additional rule files |

### Output Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `output.format` | str | `"table"` | Default output format |
| `output.file` | str | `null` | Default output file |
| `output.include_context` | bool | `true` | Include code context |
| `output.context_lines` | int | `3` | Lines of context to show |
| `output.color` | bool | `true` | Enable colored output |

### Storage Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `storage.enabled` | bool | `true` | Enable scan history |
| `storage.backend` | str | `"sqlite"` | Storage backend |
| `storage.path` | str | `~/.hamburglar/history.db` | Storage file path |

### Plugin Settings

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `plugins.enabled` | bool | `true` | Enable plugin system |
| `plugins.directories` | list | `[]` | Plugin search directories |

## Environment Variables

All configuration options can be set via environment variables:

| Variable | Configuration Option |
|----------|---------------------|
| `HAMBURGLAR_CONFIG` | Configuration file path |
| `HAMBURGLAR_THREADS` | `scan.threads` |
| `HAMBURGLAR_MAX_FILE_SIZE` | `scan.max_file_size` |
| `HAMBURGLAR_MIN_SEVERITY` | `detection.min_severity` |
| `HAMBURGLAR_OUTPUT_FORMAT` | `output.format` |
| `HAMBURGLAR_NO_COLOR` | Disable colored output |
| `HAMBURGLAR_VERBOSE` | Enable verbose logging |
| `HAMBURGLAR_QUIET` | Suppress non-essential output |
| `HAMBURGLAR_NO_YARA` | Disable YARA scanning |
| `HAMBURGLAR_NO_ENTROPY` | Disable entropy detection |

## Configuration Precedence

Configuration is applied in the following order (later overrides earlier):

1. Built-in defaults
2. Configuration file
3. Environment variables
4. Command-line arguments

## Example Configurations

### Minimal CI Configuration

```yaml
# .hamburglar.yml
scan:
  threads: 2
detection:
  min_severity: high
output:
  format: sarif
```

### Comprehensive Security Audit

```yaml
# hamburglar.yml
scan:
  recursive: true
  threads: 8
files:
  exclude:
    - "*.lock"
    - "vendor/**"
detection:
  enable_regex: true
  enable_yara: true
  enable_entropy: true
  min_severity: low
  min_confidence: 0.3
output:
  format: html
  file: security-report.html
  include_context: true
  context_lines: 5
```

### Quick Local Scan

```yaml
# hamburglar.yml
scan:
  threads: 4
detection:
  min_severity: medium
output:
  format: table
  color: true
```

## See Also

- [CLI Reference](cli-reference.md) - Command-line options
- [Detectors](detectors.md) - Pattern configuration
- [Plugins](plugins.md) - Plugin configuration
