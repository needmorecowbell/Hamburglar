# Phase 06: Output Formats and Integrations

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase adds multiple output formats to make Hamburglar's findings consumable by other tools and workflows. SARIF output enables integration with GitHub Advanced Security and other code scanning tools. CSV enables spreadsheet analysis. The optional database backend allows centralizing findings across multiple scans for trend analysis and reporting.

## Tasks

- [x] Create `src/hamburglar/outputs/sarif.py` with a `SarifOutput` class that: generates SARIF 2.1.0 compliant JSON, maps findings to SARIF result objects, includes rule definitions for each detector, adds file location information with line numbers, includes severity mapping (error/warning/note), adds Hamburglar as the tool driver, validates output against SARIF schema
  - **Completed:** Added `SarifOutput` class with full SARIF 2.1.0 compliance, severity-to-level mapping (CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note), security-severity scores, fingerprints for deduplication, and support for line numbers, columns, and end lines.

- [x] Create `src/hamburglar/outputs/csv_output.py` with a `CsvOutput` class that: generates RFC 4180 compliant CSV, includes headers (file, detector, match, severity, line_number, context), escapes special characters properly, supports configurable delimiter, handles Unicode content correctly
  - **Completed:** Added `CsvOutput` class with full RFC 4180 compliance including CRLF line endings, proper quoting of fields with special characters (commas, newlines, quotes), configurable delimiter (comma by default), optional headers, and full Unicode support including emojis.

- [ ] Create `src/hamburglar/outputs/html_output.py` with an `HtmlOutput` class that: generates standalone HTML report, includes summary statistics, groups findings by file and severity, includes collapsible sections for each file, syntax highlights matched content, adds severity color coding, is viewable without external dependencies

- [ ] Create `src/hamburglar/outputs/markdown_output.py` with a `MarkdownOutput` class that: generates GitHub-flavored markdown, includes summary table, uses collapsible details for findings, links to file locations (relative paths), suitable for PR comments or issue creation

- [ ] Create `src/hamburglar/storage/__init__.py` with `BaseStorage` abstract class defining: `save_scan(result: ScanResult)`, `get_scans(filter)`, `get_findings(filter)`, `get_statistics()`

- [ ] Create `src/hamburglar/storage/sqlite.py` with a `SqliteStorage` class that: creates SQLite database with schema (scans, findings, detectors tables), stores scan results with full finding details, supports querying by date range, file path, detector, severity, generates aggregate statistics, handles concurrent access safely

- [ ] Create `src/hamburglar/storage/json_file.py` with a `JsonFileStorage` class that: appends scan results to a JSON lines file, supports reading historical scans, provides simple file-based persistence, useful for CI/CD pipelines

- [ ] Update CLI `--format` option to support: json, table, sarif, csv, html, markdown

- [ ] Add CLI `--output-dir` option that: saves output to specified directory, auto-names files based on target and timestamp, creates directory if it doesn't exist

- [ ] Add CLI `--save-to-db` option that: saves findings to SQLite database (default: ~/.hamburglar/findings.db), creates database if it doesn't exist, supports custom database path

- [ ] Create CLI `history` command that: queries stored findings from database, supports filters (--since, --severity, --detector, --path), outputs in any supported format, shows scan statistics over time

- [ ] Create CLI `report` command that: generates summary report from database, shows most common finding types, shows files with most findings, shows trend over time, outputs as HTML or markdown

- [x] Create `tests/test_sarif_output.py` with tests for: SARIF output is valid JSON, SARIF schema validation passes, findings are correctly mapped, rule definitions are included, file locations are correct
  - **Completed:** Added 52 comprehensive tests covering valid JSON output, schema compliance, findings mapping, rule definitions, file locations, severity mapping, fingerprints, message formatting, and registry integration. 100% code coverage achieved.

- [x] Create `tests/test_csv_output.py` with tests for: CSV is RFC compliant, headers are correct, special characters are escaped, Unicode is handled correctly, delimiter is configurable
  - **Completed:** Added 48 comprehensive tests covering RFC 4180 compliance (CRLF line endings, proper quoting), header inclusion/exclusion, special character escaping, Unicode handling, delimiter configuration, field value extraction, multiple matches handling, empty results, and registry integration. 100% code coverage achieved.

- [ ] Create `tests/test_html_output.py` with tests for: HTML is valid and well-formed, summary statistics are included, findings are grouped correctly, no external dependencies required

- [ ] Create `tests/test_sqlite_storage.py` with tests for: database is created correctly, scans are saved and retrieved, findings can be queried, statistics are accurate, concurrent access works

- [ ] Create `tests/test_history_command.py` with tests for: history command works with empty db, filters work correctly, output formats work

- [ ] Run pytest and ensure all tests pass with maintained 95%+ coverage
