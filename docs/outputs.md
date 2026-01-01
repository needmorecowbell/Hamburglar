# Output Formats

Hamburglar supports multiple output formats for different use cases.

## Available Formats

| Format | Best For | Extension |
|--------|----------|-----------|
| `table` | Human reading in terminal | - |
| `json` | Programmatic processing | `.json` |
| `csv` | Spreadsheet analysis | `.csv` |
| `html` | Reports and sharing | `.html` |
| `markdown` | Documentation | `.md` |
| `sarif` | CI/CD integration | `.sarif` |

## Table Output

The default format for terminal display:

```bash
hamburglar scan /path/to/code
```

Example output:
```
┌─────────────────────────────────────────────────────────────────┐
│ Hamburglar Scan Results                                         │
├─────────────────────────────────────────────────────────────────┤
│ Files scanned: 150 | Findings: 3 | Duration: 2.5s               │
└─────────────────────────────────────────────────────────────────┘

┌──────────────────────────────────────────────────────────────────┐
│ Finding 1: AWS Access Key                                        │
├──────────────────────────────────────────────────────────────────┤
│ File:       src/config.py:42                                     │
│ Pattern:    aws_access_key_id                                    │
│ Severity:   HIGH                                                 │
│ Confidence: 0.95                                                 │
├──────────────────────────────────────────────────────────────────┤
│   40 │ # AWS Configuration                                       │
│   41 │ aws_config = {                                            │
│ > 42 │     "access_key": "AKIAIOSFODNN7EXAMPLE",                 │
│   43 │     "secret_key": os.environ.get("AWS_SECRET"),           │
│   44 │ }                                                         │
└──────────────────────────────────────────────────────────────────┘
```

## JSON Output

Structured data for programmatic processing:

```bash
hamburglar scan /path/to/code --output-format json
```

Example output:
```json
{
  "scan_id": "abc123",
  "timestamp": "2024-01-15T10:30:00Z",
  "duration_seconds": 2.5,
  "files_scanned": 150,
  "total_findings": 3,
  "findings": [
    {
      "id": "finding-001",
      "pattern_name": "aws_access_key_id",
      "pattern_category": "api_keys",
      "severity": "high",
      "confidence": 0.95,
      "file_path": "src/config.py",
      "line_number": 42,
      "column_start": 18,
      "column_end": 38,
      "matched_content": "AKIAIOSFODNN7EXAMPLE",
      "context": {
        "before": ["# AWS Configuration", "aws_config = {"],
        "line": "    \"access_key\": \"AKIAIOSFODNN7EXAMPLE\",",
        "after": ["    \"secret_key\": os.environ.get(\"AWS_SECRET\"),", "}"]
      }
    }
  ],
  "summary": {
    "by_severity": {
      "critical": 0,
      "high": 2,
      "medium": 1,
      "low": 0
    },
    "by_category": {
      "api_keys": 2,
      "credentials": 1
    }
  }
}
```

### JSON Lines

For streaming large results:

```bash
hamburglar scan /path/to/code --output-format jsonl
```

Each finding is a separate JSON line.

## CSV Output

Tabular data for spreadsheet analysis:

```bash
hamburglar scan /path/to/code --output-format csv --output findings.csv
```

Example output:
```csv
id,pattern_name,category,severity,confidence,file_path,line_number,matched_content
finding-001,aws_access_key_id,api_keys,high,0.95,src/config.py,42,AKIAIOSFODNN7EXAMPLE
finding-002,password_assignment,credentials,high,0.85,src/database.py,15,password123
finding-003,generic_api_key,generic,medium,0.70,config.json,8,abcd1234efgh5678
```

### CSV Options

Customize CSV output:

```yaml
# hamburglar.yml
output:
  csv:
    delimiter: ","
    quoting: "minimal"
    include_context: false
```

## HTML Output

Generate rich HTML reports:

```bash
hamburglar scan /path/to/code --output-format html --output report.html
```

Features:
- Interactive severity filtering
- Syntax-highlighted code snippets
- Sortable findings table
- Summary statistics
- Export to PDF (via browser)

### HTML Customization

```yaml
# hamburglar.yml
output:
  html:
    title: "Security Scan Report"
    theme: "light"  # light or dark
    include_stats: true
    include_context: true
    context_lines: 5
```

## Markdown Output

Documentation-friendly format:

```bash
hamburglar scan /path/to/code --output-format markdown --output findings.md
```

Example output:
```markdown
# Hamburglar Scan Report

**Scan Date:** 2024-01-15 10:30:00
**Files Scanned:** 150
**Total Findings:** 3

## Summary

| Severity | Count |
|----------|-------|
| Critical | 0 |
| High | 2 |
| Medium | 1 |
| Low | 0 |

## Findings

### 1. AWS Access Key (HIGH)

- **File:** `src/config.py:42`
- **Pattern:** aws_access_key_id
- **Confidence:** 95%

```python
# AWS Configuration
aws_config = {
    "access_key": "AKIAIOSFODNN7EXAMPLE",  # <-- Finding
    "secret_key": os.environ.get("AWS_SECRET"),
}
```
```

## SARIF Output

Static Analysis Results Interchange Format for CI/CD:

```bash
hamburglar scan /path/to/code --output-format sarif --output results.sarif
```

### GitHub Advanced Security Integration

Upload SARIF results to GitHub:

```yaml
# .github/workflows/security.yml
name: Security Scan

on: [push, pull_request]

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Hamburglar
        run: pip install hamburglar

      - name: Run scan
        run: hamburglar scan . --output-format sarif --output results.sarif

      - name: Upload SARIF
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: results.sarif
```

### GitLab SAST Integration

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  script:
    - pip install hamburglar
    - hamburglar scan . --output-format sarif --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

## Database Storage

Store results in SQLite for historical analysis:

```yaml
# hamburglar.yml
storage:
  enabled: true
  backend: sqlite
  path: ~/.hamburglar/history.db
```

Query history:

```bash
# List past scans
hamburglar history list

# Export specific scan
hamburglar history export abc123 --format json
```

### JSON File Storage

Alternative file-based storage:

```yaml
# hamburglar.yml
storage:
  enabled: true
  backend: json
  path: ~/.hamburglar/history/
```

## Integration Examples

### Piping to jq

```bash
hamburglar scan /path/to/code -f json | jq '.findings[] | select(.severity == "critical")'
```

### Email Report

```bash
hamburglar scan /path/to/code -f html -o report.html
mail -s "Security Report" -a report.html team@example.com < /dev/null
```

### Slack Notification

```bash
COUNT=$(hamburglar scan /path/to/code -f json | jq '.total_findings')
curl -X POST -H 'Content-type: application/json' \
  --data "{\"text\":\"Security scan found $COUNT findings\"}" \
  $SLACK_WEBHOOK_URL
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit

RESULTS=$(hamburglar scan $(git diff --cached --name-only) -f json)
CRITICAL=$(echo $RESULTS | jq '.summary.by_severity.critical')

if [ "$CRITICAL" -gt 0 ]; then
  echo "Critical secrets detected! Commit blocked."
  exit 1
fi
```

## See Also

- [CLI Reference](cli-reference.md) - Output options
- [Configuration](configuration.md) - Output configuration
- [Plugins](plugins.md) - Custom output plugins
