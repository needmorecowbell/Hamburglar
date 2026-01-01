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

- [ ] Create `src/hamburglar/scanners/git.py` with a `GitScanner` class that: clones repositories to temp directory (supports HTTP/SSH URLs), extracts all commits using `git log --all -p`, scans current HEAD files, scans commit diffs for removed secrets, scans commit messages for sensitive info, cleans up temp directory after scan, supports local git directories (not just URLs)

- [ ] Create `src/hamburglar/scanners/git_history.py` with a `GitHistoryScanner` class that: parses git log output efficiently, identifies files changed per commit, detects secrets that were added then removed, tracks secret lifetime (first seen, last seen commits), generates timeline of secret exposure

- [ ] Create `src/hamburglar/scanners/web.py` with a `WebScanner` class that: fetches URL content with configurable user agent, extracts text from HTML using BeautifulSoup, follows links to configurable depth (default 1), respects robots.txt, extracts and scans JavaScript files, extracts and scans inline scripts, handles common encodings

- [ ] Create `src/hamburglar/core/http_client.py` with an async HTTP client using httpx that: supports rate limiting, handles redirects, supports authentication (basic, bearer), has configurable timeout, implements retry logic with backoff, caches responses optionally

- [ ] Update CLI with `scan-git` command: positional URL/path argument, `--depth` for commit history depth (default all), `--branch` to scan specific branch, `--include-history` flag to scan historical commits, `--clone-dir` to specify clone location

- [ ] Update CLI with `scan-web` command: positional URL argument, `--depth` for link follow depth (default 1), `--include-scripts` to scan JS files, `--user-agent` for custom user agent, `--timeout` for request timeout, `--auth` for basic auth credentials

- [ ] Create `src/hamburglar/core/models.py` updates: add `GitFinding` subclass with commit_hash, author, date, file_path_at_commit, add `WebFinding` subclass with url, element_type (script/text/attribute), add `SecretTimeline` model for tracking secret history

- [ ] Create `tests/fixtures/git/` directory with a test git repository (initialized via fixture) containing: current files with secrets, historical commits with removed secrets, commit messages with secrets

- [ ] Create `tests/test_git_scanner.py` with tests for: cloning public repository works, scanning local git directory works, current HEAD secrets are found, historical secrets are found, commit message secrets are found, cleanup happens after scan, invalid URL raises appropriate error

- [ ] Create `tests/test_git_history.py` with tests for: commit parsing works correctly, diff parsing extracts additions and deletions, secret timeline is built correctly, removed secrets are flagged appropriately

- [ ] Create `tests/test_web_scanner.py` with tests for: basic URL fetch and scan works (mock HTTP), HTML text extraction works, JavaScript extraction works, link following respects depth limit, robots.txt is respected, timeout handling works

- [ ] Create `tests/test_http_client.py` with tests for: basic GET request works, rate limiting works, retry logic works, authentication headers are sent, redirects are followed

- [ ] Add `httpx` and `beautifulsoup4` to project dependencies in pyproject.toml

- [ ] Run pytest and ensure all tests pass with maintained 95%+ coverage
