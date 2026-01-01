# CLI Reference

Complete command-line documentation for Hamburglar.

## Global Options

These options are available for all commands:

| Option | Description |
|--------|-------------|
| `--version` | Show version number and exit |
| `--help` | Show help message and exit |

## Commands

### scan

Scan a file or directory for sensitive information.

```bash
hamburglar scan [OPTIONS] PATH
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `PATH` | Path to file or directory to scan (must exist) |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-C` | auto-detect | Path to configuration file |
| `--recursive/--no-recursive`, `-r/-R` | from config or `True` | Scan directories recursively |
| `--output`, `-o` | stdout | Write output to file instead of stdout |
| `--output-dir` | - | Save output to directory with auto-generated filename. Cannot be used with `--output` |
| `--format`, `-f` | from config or `table` | Output format: json, table, sarif, csv, html, markdown |
| `--yara`, `-y` | - | Path to YARA rules directory or file |
| `--no-yara` | `False` | Disable YARA scanning even if enabled in config |
| `--verbose/--no-verbose`, `-v/-V` | from config or `False` | Enable verbose output |
| `--quiet/--no-quiet`, `-q/-Q` | from config or `False` | Suppress non-error output |
| `--categories`, `-c` | - | Enable only specific detector categories (comma-separated). Valid: api_keys, cloud, credentials, crypto, generic, network, private_keys |
| `--no-categories` | - | Disable specific detector categories (comma-separated) |
| `--min-confidence` | - | Minimum confidence level for findings: high, medium, low |
| `--concurrency`, `-j` | from config or `50` | Maximum number of files to scan concurrently (1-1000) |
| `--stream` | `False` | Stream findings as NDJSON (newline-delimited JSON) in real-time |
| `--benchmark` | `False` | Run a quick performance test and report throughput |
| `--save-to-db/--no-save-to-db` | from config or `False` | Save findings to SQLite database |
| `--db-path` | `~/.hamburglar/findings.db` | Custom path for SQLite database file |

**Examples:**

```bash
# Basic scan
hamburglar scan ./src

# Scan with specific output format
hamburglar scan ./src -f json -o findings.json

# Scan with category filter
hamburglar scan ./src --categories api_keys,cloud

# Stream findings in real-time
hamburglar scan ./src --stream

# Benchmark scan performance
hamburglar scan ./src --benchmark

# Scan with YARA rules
hamburglar scan ./src --yara ./rules/

# Save findings to database
hamburglar scan ./src --save-to-db
```

### scan-git

Scan a git repository for sensitive information, including commit history.

```bash
hamburglar scan-git [OPTIONS] TARGET
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `TARGET` | Git repository URL (HTTP/SSH) or local path to git directory |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-C` | auto-detect | Path to configuration file |
| `--depth`, `-d` | all commits | Number of commits to scan from history |
| `--branch`, `-b` | current/default branch | Specific branch to scan |
| `--include-history/--no-history` | `True` | Scan commit history for removed secrets |
| `--clone-dir` | temporary directory | Directory to clone repository into |
| `--output`, `-o` | stdout | Write output to file instead of stdout |
| `--output-dir` | - | Save output to directory with auto-generated filename |
| `--format`, `-f` | from config or `table` | Output format: json, table, sarif, csv, html, markdown |
| `--verbose/--no-verbose`, `-v/-V` | from config or `False` | Enable verbose output |
| `--quiet/--no-quiet`, `-q/-Q` | from config or `False` | Suppress non-error output |
| `--stream` | `False` | Stream findings as NDJSON in real-time |
| `--categories`, `-c` | - | Enable only specific detector categories (comma-separated) |
| `--no-categories` | - | Disable specific detector categories (comma-separated) |
| `--min-confidence` | - | Minimum confidence level for findings: high, medium, low |
| `--save-to-db/--no-save-to-db` | from config or `False` | Save findings to SQLite database |
| `--db-path` | `~/.hamburglar/findings.db` | Custom path for SQLite database file |

**Examples:**

```bash
# Scan remote repository
hamburglar scan-git https://github.com/user/repo

# Scan local repository
hamburglar scan-git /path/to/local/repo

# Scan specific branch
hamburglar scan-git https://github.com/user/repo -b develop

# Scan with depth limit
hamburglar scan-git git@github.com:user/repo.git --depth 100

# Skip commit history
hamburglar scan-git ./my-repo --no-history --format json
```

### scan-web

Scan a web URL for sensitive information.

```bash
hamburglar scan-web [OPTIONS] URL
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `URL` | URL to scan for secrets |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--config`, `-C` | auto-detect | Path to configuration file |
| `--depth`, `-d` | `1` | Maximum depth for following links (0 = only starting URL) |
| `--include-scripts/--no-scripts` | `True` | Extract and scan JavaScript files |
| `--user-agent`, `-u` | default user agent | Custom user agent string for HTTP requests |
| `--timeout`, `-t` | `30.0` | Timeout for HTTP requests in seconds (1.0-300.0) |
| `--auth`, `-a` | - | Basic auth credentials in format 'username:password' |
| `--respect-robots/--ignore-robots` | `True` | Respect robots.txt rules |
| `--output`, `-o` | stdout | Write output to file instead of stdout |
| `--output-dir` | - | Save output to directory with auto-generated filename |
| `--format`, `-f` | from config or `table` | Output format: json, table, sarif, csv, html, markdown |
| `--verbose/--no-verbose`, `-v/-V` | from config or `False` | Enable verbose output |
| `--quiet/--no-quiet`, `-q/-Q` | from config or `False` | Suppress non-error output |
| `--stream` | `False` | Stream findings as NDJSON in real-time |
| `--categories`, `-c` | - | Enable only specific detector categories (comma-separated) |
| `--no-categories` | - | Disable specific detector categories (comma-separated) |
| `--min-confidence` | - | Minimum confidence level for findings: high, medium, low |
| `--save-to-db/--no-save-to-db` | from config or `False` | Save findings to SQLite database |
| `--db-path` | `~/.hamburglar/findings.db` | Custom path for SQLite database file |

**Examples:**

```bash
# Scan a URL
hamburglar scan-web https://example.com

# Scan with deeper crawl
hamburglar scan-web https://example.com --depth 2

# Skip JavaScript files
hamburglar scan-web https://example.com --no-scripts

# Custom timeout and user agent
hamburglar scan-web https://example.com --timeout 60 --user-agent "MyBot/1.0"

# With authentication
hamburglar scan-web https://example.com --auth user:pass
```

### history

Query stored findings from the database.

```bash
hamburglar history [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--output`, `-o` | stdout | Write output to file instead of stdout |
| `--format`, `-f` | `table` | Output format: json, table, sarif, csv, html, markdown |
| `--since`, `-s` | - | Show findings since date/time. ISO format (YYYY-MM-DD) or relative (1d, 7d, 24h, 2w, 1m) |
| `--until` | - | Show findings until date/time. Same format as `--since` |
| `--severity` | - | Filter by severity level(s), comma-separated: critical, high, medium, low, info |
| `--detector`, `-d` | - | Filter by detector name (exact match) |
| `--path`, `-p` | - | Filter by file path (prefix match) |
| `--target`, `-t` | - | Filter by scan target path (prefix match) |
| `--limit`, `-n` | - | Maximum number of findings to show |
| `--stats` | `False` | Show statistics summary instead of findings |
| `--db-path` | `~/.hamburglar/findings.db` | Path to SQLite database file |
| `--verbose`, `-v` | `False` | Enable verbose output |
| `--quiet`, `-q` | `False` | Suppress non-error output |

**Examples:**

```bash
# Show all findings
hamburglar history

# Findings from last 7 days
hamburglar history --since 7d

# High/critical only
hamburglar history --severity high,critical

# Filter by detector
hamburglar history --detector aws_key

# Show statistics summary
hamburglar history --stats

# Export as JSON
hamburglar history --format json -o out.json
```

### report

Generate a summary report from the database.

```bash
hamburglar report [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--output`, `-o` | stdout | Write report to file instead of stdout |
| `--format`, `-f` | `html` | Output format: html, markdown |
| `--since`, `-s` | - | Include findings since date/time |
| `--until` | - | Include findings until date/time |
| `--title`, `-t` | "Hamburglar Security Report" | Custom report title |
| `--top`, `-n` | `15` | Number of items to show in 'top' lists (1-100) |
| `--db-path` | `~/.hamburglar/findings.db` | Path to SQLite database file |
| `--verbose`, `-v` | `False` | Enable verbose output |
| `--quiet`, `-q` | `False` | Suppress non-error output |

**Examples:**

```bash
# HTML report to stdout
hamburglar report

# Save HTML report to file
hamburglar report -o report.html

# Save Markdown report
hamburglar report -f markdown -o r.md

# Report for last 7 days
hamburglar report --since 7d

# Show top 20 items in lists
hamburglar report --top 20
```

## Command Groups

### plugins

Plugin management commands.

```bash
hamburglar plugins [SUBCOMMAND]
```

#### plugins list

List all installed plugins.

```bash
hamburglar plugins list [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--type`, `-t` | - | Filter by plugin type: detector, output |
| `--verbose`, `-v` | `False` | Show detailed information including author and source |
| `--format`, `-f` | `table` | Output format: table, json, plain |
| `--discover`, `-d` | `False` | Force plugin discovery before listing |
| `--quiet`, `-q` | `False` | Suppress informational messages |

**Examples:**

```bash
# List all plugins
hamburglar plugins list

# List detector plugins only
hamburglar plugins list --type detector

# JSON output
hamburglar plugins list -f json

# Verbose with details
hamburglar plugins list -v
```

#### plugins info

Show detailed information about a specific plugin.

```bash
hamburglar plugins info [OPTIONS] NAME
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `NAME` | Name of the plugin to show details for |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--format`, `-f` | `table` | Output format: table, json, plain |

**Examples:**

```bash
# Show plugin info
hamburglar plugins info my-plugin

# JSON output
hamburglar plugins info my-plugin -f json
```

### config

Configuration management commands.

```bash
hamburglar config [SUBCOMMAND]
```

#### config show

Display current configuration with sources.

```bash
hamburglar config show [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--sources`, `-s` | `False` | Show which source each setting came from |
| `--format`, `-f` | `yaml` | Output format: yaml, json, toml |
| `--quiet`, `-q` | `False` | Suppress informational messages |

**Examples:**

```bash
# Show current config (YAML)
hamburglar config show

# Show config as JSON
hamburglar config show -f json

# Show config with sources
hamburglar config show --sources
```

#### config init

Create a default config file in the current directory.

```bash
hamburglar config init [OPTIONS] [PATH]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `PATH` | Directory to create config file in (default: current directory) |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--format`, `-f` | `yaml` | Config file format: yaml, json, toml |
| `--force` | `False` | Overwrite existing config file |
| `--quiet`, `-q` | `False` | Suppress informational messages |

**Examples:**

```bash
# Create config file
hamburglar config init

# Create in specific directory
hamburglar config init /path/to/dir

# Create TOML config
hamburglar config init -f toml

# Overwrite existing
hamburglar config init --force
```

#### config validate

Validate configuration file syntax and values.

```bash
hamburglar config validate [OPTIONS] [PATH]
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `PATH` | Path to config file to validate (default: auto-detect) |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--quiet`, `-q` | `False` | Only show errors, no success message |
| `--verbose`, `-v` | `False` | Show detailed validation information |

**Examples:**

```bash
# Validate auto-detected config
hamburglar config validate

# Validate specific file
hamburglar config validate .hamburglar.yml
```

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success (findings found) |
| `1` | Error occurred during execution |
| `2` | Success, no findings found |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HAMBURGLAR_CONFIG` | Path to default configuration file |
| `HAMBURGLAR_NO_COLOR` | Disable colored output |
| `HAMBURGLAR_VERBOSE` | Enable verbose output |

## Configuration Precedence

Configuration is loaded from (in priority order, highest first):

1. CLI arguments (`--format`, `--recursive`, etc.)
2. Environment variables (`HAMBURGLAR_*`)
3. Config file (`.hamburglar.yml`, `.hamburglar.yaml`, `.hamburglar.toml`, `hamburglar.config.json`)
4. Built-in defaults

Config files are searched in:
1. Current directory
2. `~/.config/hamburglar/`

## See Also

- [Configuration](configuration.md) - Configuration file options
- [Detectors](detectors.md) - Detection patterns
- [Outputs](outputs.md) - Output formats
- [Plugins](plugins.md) - Plugin system
