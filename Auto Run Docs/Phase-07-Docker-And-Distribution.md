# Phase 07: Docker and Distribution

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase packages Hamburglar for distribution via PyPI and Docker, making it easy to install and integrate into any workflow. The Docker image enables consistent execution across environments and easy integration with Docker Compose for multi-tool setups. PyPI publishing allows simple `pip install hamburglar` installation.

## Tasks

- [x] Create `Dockerfile` with multi-stage build: builder stage installs dependencies and builds wheel, runtime stage uses python:3.11-slim, copies only necessary files, creates non-root user for security, sets up YARA with rules included, exposes volume mount point at /data for scanning targets, sets ENTRYPOINT to hamburglar command
  - Created multi-stage Dockerfile with builder (compiles dependencies, builds wheel) and runtime stages
  - Runtime uses python:3.11-slim with libyara-dev and git for git scanning
  - Non-root `hamburglar` user (uid/gid 1000) for security
  - Volume mounts at /data (scan targets) and /output (results)
  - YARA rules included via wheel package data
  - Healthcheck using `hamburglar --version`
  - Note: Docker build not tested due to socket permissions - requires elevated access

- [ ] Create `docker-compose.yml` with: hamburglar service using the Dockerfile, volume mounts for target directories and output, optional MySQL service for centralized storage (commented out by default), environment variables for configuration, example usage comments

- [ ] Create `.dockerignore` file excluding: __pycache__, *.pyc, .git, .pytest_cache, .mypy_cache, .ruff_cache, *.egg-info, dist/, build/, .env, tests/ (for production image)

- [ ] Update `pyproject.toml` with complete PyPI metadata: description, long_description from README, author and maintainer info, project URLs (homepage, repository, documentation), classifiers (Development Status, License, Programming Language versions, Topic), keywords for discoverability

- [ ] Create `MANIFEST.in` to include: YARA rules directory, LICENSE file, README.md, any data files needed at runtime

- [ ] Update `src/hamburglar/__init__.py` to expose main API classes: Scanner, ScanConfig, ScanResult, Finding for library usage

- [ ] Create `src/hamburglar/api.py` with high-level API functions: `scan_directory(path, **options) -> ScanResult`, `scan_git(url, **options) -> ScanResult`, `scan_url(url, **options) -> ScanResult` for simple library usage

- [ ] Create `scripts/docker-build.sh` that: builds Docker image with proper tags, runs basic smoke test, optionally pushes to registry

- [ ] Create `scripts/publish.sh` that: runs tests, builds wheel and sdist, checks with twine, uploads to PyPI (or TestPyPI with --test flag)

- [ ] Create GitHub Actions workflow `.github/workflows/test.yml` that: runs on push and PR, tests on Python 3.9, 3.10, 3.11, 3.12, runs pytest with coverage, uploads coverage report, runs ruff linting, runs mypy type checking

- [ ] Create GitHub Actions workflow `.github/workflows/release.yml` that: triggers on version tag (v*), builds and tests, builds Docker image, pushes to Docker Hub, publishes to PyPI, creates GitHub release with changelog

- [ ] Create GitHub Actions workflow `.github/workflows/docker.yml` that: builds Docker image on push to main, pushes to GitHub Container Registry, tags with commit SHA and latest

- [ ] Create `tests/test_docker.py` with tests for: Docker image builds successfully (requires docker), container runs and produces output, volume mounts work correctly, non-root user is used (marked as integration tests, skipped if docker unavailable)

- [ ] Create `tests/test_api.py` with tests for: high-level scan_directory function works, scan_git function works, scan_url function works, options are passed through correctly, library usage pattern works

- [ ] Create `README.md` updates with: installation instructions (pip, docker, from source), quick start examples, CLI usage documentation, library usage examples, Docker usage examples, Docker Compose integration example, link to full documentation

- [ ] Run pytest including new integration tests and ensure all pass

- [ ] Build Docker image locally and verify `docker run hamburglar --version` works

- [ ] Build wheel with `python -m build` and verify it installs correctly in clean virtualenv
