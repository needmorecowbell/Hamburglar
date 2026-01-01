# Phase 05: Git Repository and Web Scanning

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase implements the git repository and web URL scanning modes from the original Hamburglar, but with modern async architecture and enhanced capabilities. Git scanning now examines commit history for secrets that may have been removed, while web scanning extracts and analyzes content from URLs. Both modes integrate seamlessly with the existing detector framework.

## Tasks

- [x] Create `src/hamburglar/scanners/__init__.py` with `BaseScanner` abstract class defining async `scan()` method and `scanner_type` property
  - Created BaseScanner ABC with abstract `scan()` method and `scanner_type` property
  - Includes default `scan_stream()` implementation, `cancel()`, `is_cancelled`, and `_report_progress()` helper
  - Added comprehensive test suite in `tests/test_base_scanner.py` (15 tests)

- [x] Create `src/hamburglar/scanners/directory.py` by refactoring the existing `AsyncScanner` into this module, implementing `BaseScanner` interface
  - Created DirectoryScanner class implementing BaseScanner abstract class
  - Features: async file discovery, configurable concurrency (default 50), progress tracking, cancellation support, streaming output
  - Added `scanner_type` property returning "directory"
  - Exported from `hamburglar.scanners` module
  - Comprehensive test suite with 52 tests covering all functionality
  - Test coverage at 92% for the new module, overall project at 94%+

- [x] Create `src/hamburglar/scanners/git.py` with a `GitScanner` class that: clones repositories to temp directory (supports HTTP/SSH URLs), extracts all commits using `git log --all -p`, scans current HEAD files, scans commit diffs for removed secrets, scans commit messages for sensitive info, cleans up temp directory after scan, supports local git directories (not just URLs)
  - Created GitScanner class implementing BaseScanner interface
  - Features: clones remote repos (HTTP/HTTPS/SSH/git protocols) to temp directories, scans local git directories
  - Scans current HEAD files for secrets, commit diffs for removed secrets, commit messages for sensitive info
  - Options: include_history, depth, branch, clone_dir
  - Async implementation with progress tracking and cancellation support
  - Automatic cleanup of temp directories after scan
  - Comprehensive test suite with 55 tests covering all functionality
  - Exported from `hamburglar.scanners` module
  - Test coverage at 95% for git.py, overall project at 94%+

- [x] Create `src/hamburglar/scanners/git_history.py` with a `GitHistoryScanner` class that: parses git log output efficiently, identifies files changed per commit, detects secrets that were added then removed, tracks secret lifetime (first seen, last seen commits), generates timeline of secret exposure
  - Created GitHistoryScanner class implementing BaseScanner interface
  - Efficient commit parsing with `_get_commit_list()` and `_get_commit_info()` methods
  - Diff parsing with `_parse_diff_output()` extracting additions and deletions per file with line numbers
  - SecretTimeline dataclass tracks: secret_hash, secret_preview, first_seen, last_seen, is_removed, exposure_duration, affected_files
  - SecretOccurrence dataclass tracks: commit_hash, author, date, file_path, line_type (+/-), line_number
  - Automatic detection of removed secrets based on last occurrence being a deletion
  - Exposure duration calculated in seconds between first addition and last removal
  - Helper methods: get_secret_timelines(), get_removed_secrets(), get_active_secrets(), generate_timeline_report()
  - Scans commit messages for secrets alongside diff content
  - Comprehensive test suite with 51 tests in tests/test_git_history.py
  - Exported from hamburglar.scanners module
  - Test coverage at 93% for git_history.py, overall project at 94.02%

- [x] Create `src/hamburglar/scanners/web.py` with a `WebScanner` class that: fetches URL content with configurable user agent, extracts text from HTML using BeautifulSoup, follows links to configurable depth (default 1), respects robots.txt, extracts and scans JavaScript files, extracts and scans inline scripts, handles common encodings
  - Created WebScanner class implementing BaseScanner interface
  - Features: async HTTP fetching with httpx, HTML text extraction using BeautifulSoup, inline script scanning, external JavaScript file scanning
  - URL normalization (removes fragments, handles trailing slashes), same-domain link filtering
  - Configurable options: depth (default 1), include_scripts (default True), user_agent (default Hamburglar user agent), timeout (default 30s), respect_robots_txt (default True)
  - Robots.txt parsing with support for Disallow, Allow (takes precedence), and Crawl-delay directives
  - Progress tracking, cancellation support, streaming output via scan_stream()
  - Error handling for timeouts, HTTP status errors, request errors, and encoding issues
  - Comprehensive test suite with 59 tests in tests/test_web_scanner.py
  - Exported from hamburglar.scanners module
  - Test coverage at 92% for web.py, overall project at 94%

- [x] Create `src/hamburglar/core/http_client.py` with an async HTTP client using httpx that: supports rate limiting, handles redirects, supports authentication (basic, bearer), has configurable timeout, implements retry logic with backoff, caches responses optionally
  - Created comprehensive async HTTP client with httpx backend
  - AuthConfig with AuthType enum supporting NONE, BASIC, and BEARER authentication
  - RateLimitConfig with token bucket algorithm (RateLimiter class) for request throttling
  - RetryConfig with exponential backoff (configurable base_delay, max_delay, exponential_base, retry_on_status codes)
  - CacheConfig with in-memory ResponseCache supporting TTL, max_entries, and automatic eviction
  - HttpClientConfig combining all settings: timeout, user_agent, follow_redirects, max_redirects, verify_ssl
  - HttpClient class with async context manager, get/post/head methods, cache_size property, clear_cache method
  - HttpClientError exception with url and status_code context
  - HttpResponse dataclass with content, status_code, headers, url, from_cache fields
  - Comprehensive test suite with 71 tests in tests/test_http_client.py
  - Test coverage at 98% for http_client.py, overall project at 94.13%

- [x] Update CLI with `scan-git` command: positional URL/path argument, `--depth` for commit history depth (default all), `--branch` to scan specific branch, `--include-history` flag to scan historical commits, `--clone-dir` to specify clone location
  - Added `scan-git` command to CLI in `src/hamburglar/cli/main.py`
  - Options: `--depth/-d` for commit history depth, `--branch/-b` for specific branch, `--include-history/--no-history` for history scanning (default: enabled), `--clone-dir` for custom clone directory
  - Supports all standard options: `--format`, `--output`, `--verbose`, `--quiet`, `--stream`, `--categories`, `--no-categories`, `--min-confidence`
  - Rich progress bar showing current file/commit being scanned and findings count
  - Streaming mode outputs NDJSON for real-time finding processing
  - Comprehensive test suite with 24 tests in `tests/test_cli_git.py`
  - All 2636 tests pass (94%+ coverage maintained)

- [x] Update CLI with `scan-web` command: positional URL argument, `--depth` for link follow depth (default 1), `--include-scripts` to scan JS files, `--user-agent` for custom user agent, `--timeout` for request timeout, `--auth` for basic auth credentials
  - Added `scan-web` command to CLI in `src/hamburglar/cli/main.py`
  - Options: `--depth/-d` for link following depth (default 1), `--include-scripts/--no-scripts` for JavaScript scanning (default enabled), `--user-agent/-u` for custom user agent, `--timeout/-t` for HTTP timeout (default 30s), `--auth/-a` for basic auth credentials (username:password format), `--respect-robots/--ignore-robots` for robots.txt compliance
  - Supports all standard options: `--format`, `--output`, `--verbose`, `--quiet`, `--stream`, `--categories`, `--no-categories`, `--min-confidence`
  - Rich progress bar showing current URL being scanned and findings count
  - Streaming mode outputs NDJSON for real-time finding processing
  - Comprehensive test suite with 27 tests in `tests/test_cli_web.py`
  - All 2665 tests pass (coverage at 91% for CLI additions)

- [ ] Create `src/hamburglar/core/models.py` updates: add `GitFinding` subclass with commit_hash, author, date, file_path_at_commit, add `WebFinding` subclass with url, element_type (script/text/attribute), add `SecretTimeline` model for tracking secret history

- [ ] Create `tests/fixtures/git/` directory with a test git repository (initialized via fixture) containing: current files with secrets, historical commits with removed secrets, commit messages with secrets

- [ ] Create `tests/test_git_scanner.py` with tests for: cloning public repository works, scanning local git directory works, current HEAD secrets are found, historical secrets are found, commit message secrets are found, cleanup happens after scan, invalid URL raises appropriate error

- [ ] Create `tests/test_git_history.py` with tests for: commit parsing works correctly, diff parsing extracts additions and deletions, secret timeline is built correctly, removed secrets are flagged appropriately

- [ ] Create `tests/test_web_scanner.py` with tests for: basic URL fetch and scan works (mock HTTP), HTML text extraction works, JavaScript extraction works, link following respects depth limit, robots.txt is respected, timeout handling works

- [ ] Create `tests/test_http_client.py` with tests for: basic GET request works, rate limiting works, retry logic works, authentication headers are sent, redirects are followed

- [ ] Add `httpx` and `beautifulsoup4` to project dependencies in pyproject.toml

- [ ] Run pytest and ensure all tests pass with maintained 95%+ coverage
