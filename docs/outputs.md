# Output Formats

Hamburglar provides multiple output formats for different workflows. Each format is designed for specific use cases, from terminal display to CI/CD integration.

## Available Formats

| Format | Extension | Best For |
|--------|-----------|----------|
| `table` | `.txt` | Terminal display (default) |
| `json` | `.json` | Programmatic processing |
| `csv` | `.csv` | Spreadsheet analysis |
| `html` | `.html` | Interactive reports |
| `markdown` | `.md` | GitHub PRs and documentation |
| `sarif` | `.sarif.json` | CI/CD and security tools |
| `ndjson` | (streaming) | Real-time processing |

## Specifying Output Format

Use the `--format` (or `-f`) option with any scan command:

```bash
# Terminal table (default)
hamburglar scan /path/to/code

# JSON output
hamburglar scan /path/to/code --format json

# Save to file
hamburglar scan /path/to/code --format html --output report.html

# Save to directory with auto-generated filename
hamburglar scan /path/to/code --format sarif --output-dir ./reports
```

Auto-generated filenames follow the pattern:
`hamburglar_{scan_type}_{target_name}_{timestamp}{extension}`

## Table Output

The default format optimized for terminal display using the Rich library.

```bash
hamburglar scan /path/to/code
```

**Features:**
- Color-coded severity levels (critical: bold red, high: red, medium: yellow, low: blue, info: dim)
- Summary statistics (duration, findings count, files scanned/skipped/errors)
- 120-character width optimized for terminal viewing
- File path, detector name, match count, and severity columns
- Progress bar during scanning

**Example output:**
```
┌──────────────────────────────────────────────────────────────────────────────┐
│ File Path                          │ Detector     │ Matches │ Severity       │
├──────────────────────────────────────────────────────────────────────────────┤
│ src/config.py                      │ aws_access_k │       2 │ HIGH           │
│ .env.example                       │ password_ass │       1 │ MEDIUM         │
│ scripts/deploy.sh                  │ private_key  │       1 │ CRITICAL       │
└──────────────────────────────────────────────────────────────────────────────┘

Scan completed in 2.5s | 3 findings | 150 files scanned | 2 skipped | 0 errors
Severity: 1 critical, 1 high, 1 medium, 0 low, 0 info
```

## JSON Output

Structured JSON for programmatic processing.

```bash
hamburglar scan /path/to/code --format json
hamburglar scan /path/to/code --format json --output results.json
```

**Features:**
- Complete finding details with metadata
- Pydantic model serialization
- 2-space indentation for readability
- Compatible with `jq` and other JSON tools

**Example output:**
```json
{
  "target_path": "/path/to/code",
  "scan_duration": 2.5,
  "findings": [
    {
      "file_path": "src/config.py",
      "detector_name": "aws_access_key_id",
      "severity": "high",
      "matches": ["AKIAIOSFODNN7EXAMPLE"],
      "metadata": {
        "line": 42,
        "context": "    \"access_key\": \"AKIAIOSFODNN7EXAMPLE\","
      }
    }
  ],
  "stats": {
    "files_scanned": 150,
    "files_skipped": 2,
    "errors": 0
  }
}
```

### Processing with jq

```bash
# Extract critical findings only
hamburglar scan . --format json | jq '.findings[] | select(.severity == "critical")'

# Count findings by severity
hamburglar scan . --format json | jq '.findings | group_by(.severity) | map({severity: .[0].severity, count: length})'

# Get unique detectors triggered
hamburglar scan . --format json | jq '[.findings[].detector_name] | unique'
```

## CSV Output

RFC 4180 compliant CSV for spreadsheet import and data analysis.

```bash
hamburglar scan /path/to/code --format csv --output findings.csv
```

**Features:**
- RFC 4180 compliant (CRLF line endings, QUOTE_MINIMAL)
- Header row included by default
- Compatible with Excel, Google Sheets, and data analysis tools
- Each match generates a separate row

**CSV Columns:**
- `file` - Path to the file
- `detector` - Name of the detector that matched
- `match` - The matched content
- `severity` - Severity level
- `line_number` - Line number of the match
- `context` - Surrounding code context

**Example output:**
```csv
file,detector,match,severity,line_number,context
src/config.py,aws_access_key_id,AKIAIOSFODNN7EXAMPLE,high,42,"access_key: AKIA..."
.env.example,password_assignment,password123,medium,15,"PASSWORD=password123"
```

### CSV Configuration

Configure CSV output in your configuration file:

```yaml
# .hamburglar.yml
output:
  csv:
    delimiter: ","        # Field separator (default: ,)
    include_headers: true # Include header row (default: true)
```

### Importing to Spreadsheets

1. **Excel:** File → Open → Select CSV file → Use comma delimiter
2. **Google Sheets:** File → Import → Upload → Select CSV file
3. **Python pandas:** `df = pd.read_csv('findings.csv')`

## HTML Output

Self-contained HTML reports for sharing and review.

```bash
hamburglar scan /path/to/code --format html --output report.html
```

**Features:**
- Fully self-contained (no external CSS/JS dependencies)
- Collapsible file sections
- Severity color coding (critical: red, high: orange, medium: yellow, low: blue, info: gray)
- Summary statistics dashboard
- Syntax-highlighted code snippets
- Files sorted by highest severity
- Responsive design for desktop and mobile

**Report Sections:**
- **Header:** Title and scan timestamp
- **Summary:** Total findings, matches, files affected/scanned/skipped, errors, duration
- **Findings:** Grouped by file with collapsible details for each finding

### HTML Customization

Configure the report title:

```yaml
# .hamburglar.yml
output:
  html:
    title: "Security Scan Report - My Project"
```

### Viewing Reports

```bash
# Generate and open report
hamburglar scan . --format html --output report.html && open report.html

# On Linux
hamburglar scan . --format html --output report.html && xdg-open report.html
```

## Markdown Output

GitHub-flavored Markdown for PR comments and documentation.

```bash
hamburglar scan /path/to/code --format markdown --output findings.md
```

**Features:**
- GitHub-flavored Markdown syntax
- Collapsible `<details>` sections for organization
- Emoji severity indicators
- Summary table with metrics
- Relative file path links for GitHub navigation
- Code blocks with syntax highlighting

**Emoji Severity Indicators:**
- :rotating_light: Critical
- :warning: High
- :large_orange_diamond: Medium
- :small_blue_diamond: Low
- :information_source: Info

**Example output:**
```markdown
# Hamburglar Scan Report

<details>
<summary>📊 Summary</summary>

| Metric | Value |
|--------|-------|
| Total Findings | 3 |
| Files Affected | 2 |
| Scan Duration | 2.5s |

| Severity | Count |
|----------|-------|
| Critical | 1 |
| High | 1 |
| Medium | 1 |

</details>

## Findings

### :rotating_light: src/config.py

**aws_access_key_id** (high) - Line 42

```python
    "access_key": "AKIAIOSFODNN7EXAMPLE",
```
```

### Markdown Configuration

Configure base path for relative links:

```yaml
# .hamburglar.yml
output:
  markdown:
    title: "Security Findings"
    base_path: "/src"  # Strip this prefix from file paths
```

## SARIF Output

Static Analysis Results Interchange Format (SARIF 2.1.0) for security tool integration.

```bash
hamburglar scan /path/to/code --format sarif --output results.sarif.json
```

**Features:**
- SARIF 2.1.0 schema compliant
- Tool information with version and documentation URI
- Rule definitions for each detector
- Security severity scores for prioritization
- Fingerprints for finding deduplication (SHA256 hash)
- Location information with line/column details
- Match redaction for safety (shows first/last 4 characters only)
- URI base ID support (%SRCROOT%)

**Severity Mapping:**

| Hamburglar | SARIF Level | Security Score |
|------------|-------------|----------------|
| Critical | error | 9.0 |
| High | error | 7.0 |
| Medium | warning | 5.0 |
| Low | note | 3.0 |
| Info | note | 1.0 |

### GitHub Advanced Security Integration

Upload SARIF results to GitHub Code Scanning:

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

      - name: Run security scan
        run: hamburglar scan . --format sarif --output results.sarif.json --quiet

      - name: Upload SARIF to GitHub
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: results.sarif.json
```

### GitLab SAST Integration

```yaml
# .gitlab-ci.yml
security_scan:
  stage: test
  image: python:3.11
  script:
    - pip install hamburglar
    - hamburglar scan . --format sarif --output gl-sast-report.sarif.json --quiet
  artifacts:
    reports:
      sast: gl-sast-report.sarif.json
```

### Azure DevOps Integration

```yaml
# azure-pipelines.yml
- task: PythonScript@0
  inputs:
    scriptSource: 'inline'
    script: |
      pip install hamburglar
      hamburglar scan . --format sarif --output $(Build.ArtifactStagingDirectory)/results.sarif.json --quiet

- task: PublishBuildArtifacts@1
  inputs:
    PathtoPublish: '$(Build.ArtifactStagingDirectory)/results.sarif.json'
    ArtifactName: 'CodeAnalysisLogs'
```

## Streaming Output (NDJSON)

Newline-Delimited JSON for real-time processing of findings as they're discovered.

```bash
hamburglar scan /path/to/code --stream
```

**Features:**
- Real-time output as findings are discovered
- Each finding is a complete JSON object on its own line
- Memory efficient for large scans
- Pipeline-friendly (easy to pipe to other tools)
- No progress bar (maintains NDJSON purity)
- Summary displayed to stderr in verbose mode

**Example output:**
```json
{"file_path":"src/config.py","detector_name":"aws_access_key_id","severity":"high","matches":["AKIAIOSFODNN7EXAMPLE"],"metadata":{"line":42}}
{"file_path":".env","detector_name":"password_assignment","severity":"medium","matches":["secret123"],"metadata":{"line":5}}
```

### Real-time Processing Examples

```bash
# Filter critical findings in real-time
hamburglar scan . --stream | jq -c 'select(.severity == "critical")'

# Count findings as they arrive
hamburglar scan . --stream | wc -l

# Log findings to file while displaying count
hamburglar scan . --stream | tee findings.ndjson | wc -l

# Process with custom script
hamburglar scan . --stream | while read -r finding; do
  severity=$(echo "$finding" | jq -r '.severity')
  if [ "$severity" = "critical" ]; then
    echo "ALERT: Critical finding detected!"
    echo "$finding" | jq .
  fi
done
```

## Database Storage

Store findings in SQLite for historical analysis and trend tracking.

### Enabling Database Storage

```bash
# Save scan results to database
hamburglar scan /path/to/code --save-to-db

# Specify custom database path
hamburglar scan /path/to/code --save-to-db --db-path ./my-findings.db
```

**Default database location:** `~/.hamburglar/findings.db`

### Configuration File Setup

```yaml
# .hamburglar.yml
output:
  save_to_db: true
  db_path: ~/.hamburglar/findings.db
```

### Querying Historical Findings

Use the `history` command to query stored findings:

```bash
# Show all historical findings
hamburglar history

# Filter by time range
hamburglar history --since 7d          # Last 7 days
hamburglar history --since 2024-01-01  # Since specific date
hamburglar history --until 2024-06-30  # Until specific date

# Filter by severity
hamburglar history --severity high,critical

# Filter by detector
hamburglar history --detector aws_access_key_id

# Filter by file path
hamburglar history --path src/

# Filter by scan target
hamburglar history --target /path/to/repo

# Show statistics summary
hamburglar history --stats

# Export to file
hamburglar history --format json --output historical-findings.json

# Limit results
hamburglar history --limit 100
```

### Database Schema

The SQLite database contains three main tables:

**scans** - Scan metadata
- `scan_id` - Unique identifier (UUID)
- `target_path` - Path that was scanned
- `scan_duration` - Time taken in seconds
- `stats_json` - Scan statistics
- `stored_at` - Timestamp

**findings** - Individual findings
- `finding_id` - Auto-increment ID
- `scan_id` - Reference to parent scan
- `file_path` - File where finding occurred
- `detector_name` - Detector that matched
- `severity` - Severity level
- `matches_json` - Matched content
- `metadata_json` - Additional metadata
- `line_number` - Line number
- `context` - Code context

**detectors** - Unique detector registry
- `detector_id` - Auto-increment ID
- `name` - Detector name
- `description` - Detector description

### Direct Database Queries

```bash
# Connect to database
sqlite3 ~/.hamburglar/findings.db

# List recent scans
SELECT scan_id, target_path, stored_at FROM scans ORDER BY stored_at DESC LIMIT 10;

# Count findings by severity
SELECT severity, COUNT(*) FROM findings GROUP BY severity;

# Find most common detectors
SELECT detector_name, COUNT(*) as count FROM findings GROUP BY detector_name ORDER BY count DESC;

# Get findings for specific file
SELECT * FROM findings WHERE file_path LIKE '%config%';
```

## Integration Examples

### Pre-commit Hook

Block commits containing secrets:

```bash
#!/bin/bash
# .git/hooks/pre-commit

# Get staged files
STAGED_FILES=$(git diff --cached --name-only --diff-filter=ACM)

if [ -z "$STAGED_FILES" ]; then
  exit 0
fi

# Scan staged files
RESULT=$(echo "$STAGED_FILES" | xargs hamburglar scan --format json 2>/dev/null)
CRITICAL=$(echo "$RESULT" | jq '[.findings[] | select(.severity == "critical")] | length')

if [ "$CRITICAL" -gt 0 ]; then
  echo "ERROR: Critical secrets detected in staged files!"
  echo "$RESULT" | jq '.findings[] | select(.severity == "critical") | "\(.file_path): \(.detector_name)"'
  exit 1
fi

exit 0
```

### Slack Notification

```bash
#!/bin/bash
# Send findings summary to Slack

RESULT=$(hamburglar scan /path/to/code --format json)
TOTAL=$(echo "$RESULT" | jq '.findings | length')
CRITICAL=$(echo "$RESULT" | jq '[.findings[] | select(.severity == "critical")] | length')
HIGH=$(echo "$RESULT" | jq '[.findings[] | select(.severity == "high")] | length')

curl -X POST -H 'Content-type: application/json' \
  --data "{
    \"text\": \"Security Scan Results\",
    \"attachments\": [{
      \"color\": \"$([ $CRITICAL -gt 0 ] && echo 'danger' || echo 'warning')\",
      \"fields\": [
        {\"title\": \"Total Findings\", \"value\": \"$TOTAL\", \"short\": true},
        {\"title\": \"Critical\", \"value\": \"$CRITICAL\", \"short\": true},
        {\"title\": \"High\", \"value\": \"$HIGH\", \"short\": true}
      ]
    }]
  }" \
  "$SLACK_WEBHOOK_URL"
```

### Email Report

```bash
# Generate HTML report and email
hamburglar scan /path/to/code --format html --output /tmp/report.html

mail -s "Security Scan Report" \
  -a "Content-Type: text/html" \
  -A /tmp/report.html \
  security-team@example.com < /dev/null
```

### CI/CD Pipeline with Exit Codes

```bash
#!/bin/bash
# fail-on-critical.sh

hamburglar scan . --format json --output results.json
EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
  # Findings were found, check for critical
  CRITICAL=$(jq '[.findings[] | select(.severity == "critical")] | length' results.json)
  if [ "$CRITICAL" -gt 0 ]; then
    echo "Pipeline failed: $CRITICAL critical findings"
    exit 1
  fi
  echo "Scan complete with findings (no critical)"
  exit 0
elif [ $EXIT_CODE -eq 2 ]; then
  echo "No findings detected"
  exit 0
else
  echo "Scan error occurred"
  exit 1
fi
```

## Output Configuration Reference

All output settings can be configured in `.hamburglar.yml`:

```yaml
output:
  # Default output format
  format: table  # json, table, sarif, csv, html, markdown

  # File output path (null = stdout)
  output_path: null

  # Database storage
  save_to_db: false
  db_path: ~/.hamburglar/findings.db

  # Verbosity
  quiet: false   # Suppress non-essential output
  verbose: false # Enable detailed output
```

Environment variables:

| Variable | Description |
|----------|-------------|
| `HAMBURGLAR_OUTPUT_FORMAT` | Default output format |
| `HAMBURGLAR_DB_PATH` | Database file path |
| `HAMBURGLAR_SAVE_TO_DB` | Enable database storage (true/false) |
| `HAMBURGLAR_QUIET` | Suppress output (true/false) |
| `HAMBURGLAR_VERBOSE` | Enable verbose output (true/false) |

## See Also

- [CLI Reference](cli-reference.md) - Complete command-line options
- [Configuration](configuration.md) - Full configuration guide
- [Plugins](plugins.md) - Creating custom output plugins
