# Quickstart Guide

Get up and running with Hamburglar in minutes.

## Basic Scanning

### Scan a Directory

The most common use case is scanning a local directory:

```bash
hamburglar scan /path/to/your/code
```

Example output:
```
Finding: AWS Access Key
  File: src/config.py
  Line: 42
  Pattern: aws_access_key_id
  Severity: high
  Confidence: 0.95

Finding: Generic API Key
  File: .env.example
  Line: 5
  Pattern: api_key_generic
  Severity: medium
  Confidence: 0.80

Scan completed: 2 findings in 150 files
```

### Scan a Single File

```bash
hamburglar scan /path/to/file.py
```

### Filtering Files

File filtering is configured via configuration files rather than CLI flags. See [Configuration](configuration.md) for setting up `whitelist` and `blacklist` patterns.

## Scanning Git Repositories

### Scan a Remote Repository

```bash
hamburglar scan-git https://github.com/user/repo
```

### Scan a Local Repository

```bash
hamburglar scan-git /path/to/local/repo
```

### Scan Git History

History scanning is enabled by default. To limit the number of commits scanned:

```bash
hamburglar scan-git https://github.com/user/repo --depth 100
```

To skip history and scan only the current state:

```bash
hamburglar scan-git https://github.com/user/repo --no-history
```

## Scanning URLs

Scan web content for exposed secrets:

```bash
hamburglar scan-web https://example.com/config.js
```

## Output Formats

### JSON Output

```bash
hamburglar scan /path/to/code --format json
```

Save to file:

```bash
hamburglar scan /path/to/code --format json --output findings.json
```

### CSV Output

```bash
hamburglar scan /path/to/code --format csv --output findings.csv
```

### HTML Report

Generate a human-readable HTML report:

```bash
hamburglar scan /path/to/code --format html --output report.html
```

### SARIF Output (CI/CD)

For GitHub Advanced Security integration:

```bash
hamburglar scan /path/to/code --format sarif --output results.sarif
```

## Common Use Cases

### Pre-Commit Check

Scan staged files before committing:

```bash
hamburglar scan $(git diff --cached --name-only)
```

### CI/CD Pipeline

```yaml
# GitHub Actions example
- name: Scan for secrets
  run: |
    pip install hamburglar
    hamburglar scan . --format sarif --output results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: results.sarif
```

### Docker Containers

Scan a Docker image's filesystem:

```bash
docker run -v /path/to/code:/data hamburglar/hamburglar scan /data
```

## Interpreting Results

### Severity Levels

- **critical**: Highly sensitive secrets (private keys, database credentials)
- **high**: API keys, tokens, passwords
- **medium**: Potential secrets requiring verification
- **low**: Lower confidence matches or less sensitive data
- **info**: Informational findings

### Confidence Scores

- **0.90-1.00**: Very high confidence, likely a real secret
- **0.70-0.89**: High confidence, should be investigated
- **0.50-0.69**: Medium confidence, may be a false positive
- **Below 0.50**: Low confidence, review manually

### Filtering by Confidence

```bash
# Only show high confidence findings
hamburglar scan /path/to/code --min-confidence high
```

## Next Steps

- [CLI Reference](cli-reference.md) - All available commands and options
- [Configuration](configuration.md) - Create a configuration file
- [Detectors](detectors.md) - Understand detection patterns
- [Outputs](outputs.md) - Learn about output formats
