# Phase 06: Output Formats and Integrations

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase adds multiple output formats to make Hamburglar's findings consumable by other tools and workflows. SARIF output enables integration with GitHub Advanced Security and other code scanning tools. CSV enables spreadsheet analysis. The optional database backend allows centralizing findings across multiple scans for trend analysis and reporting.

## Tasks

- [x] Create `src/hamburglar/outputs/sarif.py` with a `SarifOutput` class that: generates SARIF 2.1.0 compliant JSON, maps findings to SARIF result objects, includes rule definitions for each detector, adds file location information with line numbers, includes severity mapping (error/warning/note), adds Hamburglar as the tool driver, validates output against SARIF schema
  - **Completed:** Added `SarifOutput` class with full SARIF 2.1.0 compliance, severity-to-level mapping (CRITICAL/HIGH→error, MEDIUM→warning, LOW/INFO→note), security-severity scores, fingerprints for deduplication, and support for line numbers, columns, and end lines.

- [x] Create `src/hamburglar/outputs/csv_output.py` with a `CsvOutput` class that: generates RFC 4180 compliant CSV, includes headers (file, detector, match, severity, line_number, context), escapes special characters properly, supports configurable delimiter, handles Unicode content correctly
  - **Completed:** Added `CsvOutput` class with full RFC 4180 compliance including CRLF line endings, proper quoting of fields with special characters (commas, newlines, quotes), configurable delimiter (comma by default), optional headers, and full Unicode support including emojis.

- [x] Create `src/hamburglar/outputs/html_output.py` with an `HtmlOutput` class that: generates standalone HTML report, includes summary statistics, groups findings by file and severity, includes collapsible sections for each file, syntax highlights matched content, adds severity color coding, is viewable without external dependencies
  - **Completed:** Added `HtmlOutput` class that generates self-contained HTML reports with inline CSS (no external dependencies). Features include: summary statistics with stat cards (total findings, matches, files affected, files scanned), severity breakdown badges, findings grouped by file with collapsible `<details>` sections, files and findings sorted by severity (critical first), severity color coding with configurable colors, syntax highlighting for matched content in `<code>` blocks, context display in `<pre>` blocks, line number display, XSS prevention via proper HTML escaping, full Unicode support including emojis, responsive design with mobile-friendly CSS, and Hamburglar attribution in footer.

- [x] Create `src/hamburglar/outputs/markdown_output.py` with a `MarkdownOutput` class that: generates GitHub-flavored markdown, includes summary table, uses collapsible details for findings, links to file locations (relative paths), suitable for PR comments or issue creation
  - **Completed:** Added `MarkdownOutput` class that generates GitHub-flavored Markdown reports with: summary table (total findings, matches, files affected, files scanned, duration), severity breakdown table with emoji indicators, collapsible `<details>` sections for grouping findings by file, relative file path links with configurable `base_path`, severity ordering (critical first), line number display, code fences for context, backtick inline code for matches, Markdown character escaping to prevent formatting issues, custom title support, and Hamburglar attribution in footer. Added 72 comprehensive tests achieving 100% code coverage.

- [x] Create `src/hamburglar/storage/__init__.py` with `BaseStorage` abstract class defining: `save_scan(result: ScanResult)`, `get_scans(filter)`, `get_findings(filter)`, `get_statistics()`
  - **Completed:** Added `BaseStorage` abstract class with four abstract methods (`save_scan`, `get_scans`, `get_findings`, `get_statistics`) plus context manager support and `close()` method. Also added: `ScanFilter` and `FindingFilter` dataclasses for query filtering with support for date range, path, severity, detector, pagination (limit/offset); `StoredScan` dataclass wrapping ScanResult with storage metadata (scan_id, stored_at); `ScanStatistics` dataclass for aggregate statistics (totals, breakdowns by severity/detector/date, averages); `StorageError` exception with backend and operation context; `StorageRegistry` for managing storage backend instances; `default_registry` global instance. Added 66 comprehensive tests achieving 95% code coverage.

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

- [x] Create `tests/test_html_output.py` with tests for: HTML is valid and well-formed, summary statistics are included, findings are grouped correctly, no external dependencies required
  - **Completed:** Added 63 comprehensive tests covering: valid HTML structure (DOCTYPE, html/head/body tags, charset, viewport), no external dependencies (no external CSS/JS/fonts), summary statistics (findings count, files scanned, duration, severity breakdown), finding grouping by file with collapsible sections, severity ordering, severity color coding, match highlighting, line number display, XSS prevention (HTML entity escaping), Unicode handling (including emojis), custom title support, BaseOutput interface compliance, OutputRegistry integration, and edge cases (empty matches, missing metadata, long content, many findings). 100% code coverage achieved.

- [ ] Create `tests/test_sqlite_storage.py` with tests for: database is created correctly, scans are saved and retrieved, findings can be queried, statistics are accurate, concurrent access works

- [ ] Create `tests/test_history_command.py` with tests for: history command works with empty db, filters work correctly, output formats work

- [ ] Run pytest and ensure all tests pass with maintained 95%+ coverage
