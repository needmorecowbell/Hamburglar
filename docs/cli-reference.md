# CLI Reference

Complete command-line documentation for Hamburglar.

## Global Options

These options are available for all commands:

| Option | Description |
|--------|-------------|
| `--version` | Show version number and exit |
| `--help` | Show help message and exit |
| `--verbose`, `-v` | Increase output verbosity |
| `--quiet`, `-q` | Suppress non-essential output |
| `--config`, `-c` | Path to configuration file |

## Commands

### scan

Scan files or directories for secrets.

```bash
hamburglar scan [OPTIONS] PATH...
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `PATH` | One or more paths to scan (files or directories) |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--recursive`, `-r` | `True` | Scan directories recursively |
| `--include` | `*` | File patterns to include (can be repeated) |
| `--exclude` | - | File patterns to exclude (can be repeated) |
| `--max-file-size` | `10MB` | Maximum file size to scan |
| `--output-format`, `-f` | `table` | Output format: table, json, csv, html, markdown, sarif |
| `--output`, `-o` | - | Output file path (stdout if not specified) |
| `--min-severity` | `low` | Minimum severity to report: low, medium, high, critical |
| `--no-yara` | `False` | Disable YARA rule scanning |
| `--no-entropy` | `False` | Disable entropy-based detection |
| `--threads`, `-t` | `4` | Number of threads for parallel scanning |
| `--dry-run` | `False` | Show what would be scanned without scanning |

**Examples:**

```bash
# Basic scan
hamburglar scan ./src

# Scan with exclusions
hamburglar scan ./src --exclude "*.test.js" --exclude "node_modules"

# JSON output to file
hamburglar scan ./src -f json -o findings.json

# Only high/critical findings
hamburglar scan ./src --min-severity high
```

### scan-git

Scan a git repository for secrets.

```bash
hamburglar scan-git [OPTIONS] REPOSITORY
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `REPOSITORY` | Git repository URL or local path |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--branch`, `-b` | `HEAD` | Branch to scan |
| `--history` | `False` | Scan commit history |
| `--max-commits` | `1000` | Maximum commits to scan in history |
| `--since` | - | Only scan commits after this date |
| `--until` | - | Only scan commits before this date |
| `--output-format`, `-f` | `table` | Output format |
| `--output`, `-o` | - | Output file path |
| `--min-severity` | `low` | Minimum severity to report |

**Examples:**

```bash
# Scan remote repository
hamburglar scan-git https://github.com/user/repo

# Scan specific branch
hamburglar scan-git https://github.com/user/repo -b develop

# Scan with history
hamburglar scan-git ./my-repo --history --max-commits 500
```

### scan-url

Scan web content for secrets.

```bash
hamburglar scan-url [OPTIONS] URL...
```

**Arguments:**

| Argument | Description |
|----------|-------------|
| `URL` | One or more URLs to scan |

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--follow-redirects` | `True` | Follow HTTP redirects |
| `--max-depth` | `1` | Maximum crawl depth |
| `--timeout` | `30` | Request timeout in seconds |
| `--output-format`, `-f` | `table` | Output format |
| `--output`, `-o` | - | Output file path |
| `--min-severity` | `low` | Minimum severity to report |

**Examples:**

```bash
# Scan a URL
hamburglar scan-url https://example.com/config.js

# Scan multiple URLs
hamburglar scan-url https://api.example.com/v1 https://api.example.com/v2
```

### list-patterns

List all available detection patterns.

```bash
hamburglar list-patterns [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--category` | - | Filter by category |
| `--format` | `table` | Output format: table, json |

**Examples:**

```bash
# List all patterns
hamburglar list-patterns

# List API key patterns
hamburglar list-patterns --category api_keys

# JSON output
hamburglar list-patterns --format json
```

### list-rules

List all available YARA rules.

```bash
hamburglar list-rules [OPTIONS]
```

**Options:**

| Option | Default | Description |
|--------|---------|-------------|
| `--format` | `table` | Output format: table, json |

### config

Manage configuration.

```bash
hamburglar config [SUBCOMMAND]
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `show` | Display current configuration |
| `init` | Create a new configuration file |
| `validate` | Validate a configuration file |

**Examples:**

```bash
# Show current config
hamburglar config show

# Create config file
hamburglar config init --output hamburglar.yml

# Validate config
hamburglar config validate hamburglar.yml
```

### history

View and manage scan history.

```bash
hamburglar history [SUBCOMMAND]
```

**Subcommands:**

| Subcommand | Description |
|------------|-------------|
| `list` | List past scans |
| `show <scan-id>` | Show details of a specific scan |
| `export <scan-id>` | Export scan results |
| `clear` | Clear scan history |

**Examples:**

```bash
# List recent scans
hamburglar history list

# Show specific scan
hamburglar history show abc123

# Export to JSON
hamburglar history export abc123 --format json -o results.json
```

### doctor

Check system configuration and dependencies.

```bash
hamburglar doctor
```

This command checks:
- Python version compatibility
- Required dependencies installed
- YARA installation status
- Configuration file validity
- Plugin availability

## Exit Codes

| Code | Description |
|------|-------------|
| `0` | Success, no findings |
| `1` | Success with findings |
| `2` | Error during execution |
| `3` | Invalid configuration |
| `4` | Invalid arguments |

## Shell Completion

Install shell completions:

```bash
# Bash
hamburglar --install-completion bash

# Zsh
hamburglar --install-completion zsh

# Fish
hamburglar --install-completion fish
```

After installation, restart your shell or source the completion script.

## Environment Variables

| Variable | Description |
|----------|-------------|
| `HAMBURGLAR_CONFIG` | Path to default configuration file |
| `HAMBURGLAR_NO_COLOR` | Disable colored output |
| `HAMBURGLAR_VERBOSE` | Enable verbose output |

## See Also

- [Configuration](configuration.md) - Configuration file options
- [Detectors](detectors.md) - Detection patterns
- [Outputs](outputs.md) - Output formats
