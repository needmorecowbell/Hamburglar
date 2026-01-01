"""Git repository scanner module for Hamburglar.

This module provides the GitScanner class which handles scanning git repositories
for secrets and sensitive information. It can scan both remote repositories
(cloned to temp directories) and local git directories.

The scanner examines:
- Current HEAD files for secrets
- Commit history (diffs) for secrets that may have been removed
- Commit messages for sensitive information
"""

import asyncio
import logging
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, AsyncIterator

from hamburglar.core.exceptions import ScanError
from hamburglar.core.models import Finding, ScanResult
from hamburglar.core.progress import ScanProgress
from hamburglar.scanners import BaseScanner, ProgressCallback

if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector

logger = logging.getLogger(__name__)


class GitScanner(BaseScanner):
    """Git repository scanner that scans repositories for secrets.

    The GitScanner can clone remote repositories (HTTP/SSH URLs) to a temp
    directory or scan local git directories. It examines:

    - Current HEAD files for secrets
    - Commit history (diffs) for secrets that were added then removed
    - Commit messages for sensitive information

    Attributes:
        target: Git repository URL (HTTP/SSH) or local path to git directory.
        clone_dir: Optional directory to clone repository into. If not provided,
                   a temporary directory is used and cleaned up after scan.
        include_history: Whether to scan commit history for removed secrets.
        depth: Number of commits to examine (None for all history).
        branch: Specific branch to scan (None for current/default branch).
    """

    def __init__(
        self,
        target: str,
        detectors: list["BaseDetector"] | None = None,
        progress_callback: ProgressCallback | None = None,
        clone_dir: Path | None = None,
        include_history: bool = True,
        depth: int | None = None,
        branch: str | None = None,
    ):
        """Initialize the git scanner.

        Args:
            target: Git repository URL (HTTP/SSH) or local path to git directory.
            detectors: List of detector instances to use for scanning.
                      If None, no detections will be performed.
            progress_callback: Optional callback function for progress updates.
            clone_dir: Optional directory to clone repository into.
                      If not provided, a temporary directory is used.
            include_history: Whether to scan commit history. Defaults to True.
            depth: Number of commits to examine. None for all history.
            branch: Specific branch to scan. None for current/default branch.
        """
        super().__init__(detectors=detectors, progress_callback=progress_callback)
        self.target = target
        self.clone_dir = clone_dir
        self.include_history = include_history
        self.depth = depth
        self.branch = branch

        # Internal state
        self._cancel_event = asyncio.Event()
        self._temp_dir: tempfile.TemporaryDirectory | None = None
        self._repo_path: Path | None = None

        # Progress tracking
        self._start_time: float = 0.0
        self._files_scanned: int = 0
        self._commits_scanned: int = 0
        self._findings_count: int = 0
        self._current_item: str = ""
        self._errors: list[str] = []

    @property
    def scanner_type(self) -> str:
        """Return the type identifier for this scanner.

        Returns:
            'git' - identifies this as a git repository scanner.
        """
        return "git"

    @property
    def is_cancelled(self) -> bool:
        """Check if the scan has been cancelled.

        Returns:
            True if cancellation has been requested, False otherwise.
        """
        return self._cancel_event.is_set()

    def cancel(self) -> None:
        """Request cancellation of the ongoing scan.

        This sets the cancellation event, which will cause the scan to
        stop processing and return partial results.
        """
        self._cancel_event.set()
        logger.info("Git scan cancellation requested")

    def _reset(self) -> None:
        """Reset the scanner state for a new scan."""
        self._cancel_event.clear()
        self._start_time = 0.0
        self._files_scanned = 0
        self._commits_scanned = 0
        self._findings_count = 0
        self._current_item = ""
        self._errors = []
        self._repo_path = None

    def _get_progress(self) -> ScanProgress:
        """Get the current scan progress.

        Returns:
            ScanProgress dataclass with current scan statistics.
        """
        return ScanProgress(
            total_files=0,  # We don't know total upfront for git
            scanned_files=self._files_scanned,
            current_file=self._current_item,
            bytes_processed=0,
            findings_count=self._findings_count,
            elapsed_time=time.time() - self._start_time if self._start_time else 0.0,
        )

    def _report_progress_internal(self) -> None:
        """Report progress via callback if one is configured."""
        if self.progress_callback is not None:
            try:
                self.progress_callback(self._get_progress())
            except Exception as e:
                logger.debug(f"Progress callback error: {e}")

    def _is_remote_url(self, target: str) -> bool:
        """Check if the target is a remote URL.

        Args:
            target: The target string to check.

        Returns:
            True if it's a remote URL, False if it's a local path.
        """
        # Check for common git URL patterns
        remote_patterns = [
            r"^https?://",  # HTTP/HTTPS
            r"^git://",  # Git protocol
            r"^ssh://",  # SSH protocol
            r"^git@",  # SSH shorthand (git@github.com:user/repo)
        ]
        return any(re.match(pattern, target) for pattern in remote_patterns)

    async def _run_git_command(
        self,
        args: list[str],
        cwd: Path | None = None,
        check: bool = True,
    ) -> tuple[int, str, str]:
        """Run a git command asynchronously.

        Args:
            args: Git command arguments (without 'git' prefix).
            cwd: Working directory for the command.
            check: Whether to raise on non-zero exit code.

        Returns:
            Tuple of (return_code, stdout, stderr).

        Raises:
            ScanError: If check=True and command fails.
        """
        cmd = ["git"] + args
        logger.debug(f"Running git command: {' '.join(cmd)}")

        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd,
            )
            stdout, stderr = await process.communicate()

            stdout_str = stdout.decode("utf-8", errors="replace")
            stderr_str = stderr.decode("utf-8", errors="replace")

            if check and process.returncode != 0:
                raise ScanError(
                    f"Git command failed: {' '.join(cmd)}",
                    context={"stderr": stderr_str, "returncode": process.returncode},
                )

            return process.returncode or 0, stdout_str, stderr_str

        except FileNotFoundError:
            raise ScanError(
                "Git is not installed or not in PATH",
                context={"command": " ".join(cmd)},
            )

    async def _clone_repository(self, target: str, dest: Path) -> None:
        """Clone a remote repository.

        Args:
            target: Remote repository URL.
            dest: Destination directory for the clone.

        Raises:
            ScanError: If cloning fails.
        """
        self._current_item = f"Cloning {target}"
        self._report_progress_internal()

        clone_args = ["clone"]

        # Add depth if specified
        if self.depth is not None:
            clone_args.extend(["--depth", str(self.depth)])

        # Add branch if specified
        if self.branch is not None:
            clone_args.extend(["--branch", self.branch])

        clone_args.extend([target, str(dest)])

        try:
            await self._run_git_command(clone_args)
            logger.info(f"Successfully cloned {target} to {dest}")
        except ScanError as e:
            raise ScanError(
                f"Failed to clone repository: {target}",
                context={"original_error": str(e)},
            )

    async def _get_repo_files(self, repo_path: Path) -> list[Path]:
        """Get list of files tracked by git in the repository.

        Args:
            repo_path: Path to the git repository.

        Returns:
            List of paths to tracked files.
        """
        _, stdout, _ = await self._run_git_command(
            ["ls-files", "-z"],
            cwd=repo_path,
        )

        files = []
        for file_path in stdout.split("\0"):
            if file_path.strip():
                full_path = repo_path / file_path
                if full_path.is_file():
                    files.append(full_path)

        return files

    async def _read_file(self, file_path: Path) -> str | None:
        """Read file contents.

        Args:
            file_path: Path to the file to read.

        Returns:
            File contents as string, or None if reading failed.
        """

        def _read_sync() -> str | None:
            try:
                try:
                    return file_path.read_text(encoding="utf-8")
                except UnicodeDecodeError:
                    logger.debug(
                        f"UTF-8 decode failed for {file_path}, falling back to latin-1"
                    )
                    return file_path.read_text(encoding="latin-1")
            except PermissionError:
                logger.warning(f"Permission denied reading file: {file_path}")
                self._errors.append(f"Permission denied: {file_path}")
                return None
            except OSError as e:
                logger.error(f"Error reading file {file_path}: {e}")
                self._errors.append(f"Error reading {file_path}: {e}")
                return None

        return await asyncio.to_thread(_read_sync)

    async def _scan_content(
        self, content: str, source: str, context: dict | None = None
    ) -> list[Finding]:
        """Scan content with all detectors.

        Args:
            content: Content to scan.
            source: Source identifier (file path, commit info, etc.).
            context: Additional context to add to findings.

        Returns:
            List of findings from all detectors.
        """
        findings: list[Finding] = []

        for detector in self.detectors:
            if self.is_cancelled:
                break
            try:
                detector_findings = detector.detect(content, source)
                # Add context to findings if provided
                if context:
                    for finding in detector_findings:
                        finding.metadata.update(context)
                findings.extend(detector_findings)
                self._findings_count += len(detector_findings)
            except Exception as e:
                logger.error(f"Detector {detector.name} failed on {source}: {e}")
                self._errors.append(f"Detector {detector.name} error on {source}: {e}")

        return findings

    async def _scan_current_files(self, repo_path: Path) -> list[Finding]:
        """Scan current HEAD files for secrets.

        Args:
            repo_path: Path to the git repository.

        Returns:
            List of findings from current files.
        """
        findings: list[Finding] = []

        files = await self._get_repo_files(repo_path)
        logger.info(f"Scanning {len(files)} files at HEAD")

        for file_path in files:
            if self.is_cancelled:
                break

            self._current_item = str(file_path.relative_to(repo_path))
            self._report_progress_internal()

            content = await self._read_file(file_path)
            if content is None:
                continue

            self._files_scanned += 1
            file_findings = await self._scan_content(
                content,
                str(file_path.relative_to(repo_path)),
                context={"source_type": "current_file", "commit": "HEAD"},
            )
            findings.extend(file_findings)

        return findings

    async def _get_commit_log(self, repo_path: Path) -> list[dict]:
        """Get commit log with diffs.

        Args:
            repo_path: Path to the git repository.

        Returns:
            List of commit dictionaries with hash, author, date, message, and diff.
        """
        log_args = [
            "log",
            "--all",
            "-p",  # Show patch/diff
            "--format=COMMIT_START%n%H%n%an%n%aI%n%s%n%b%nCOMMIT_BODY_END",
        ]

        if self.depth is not None:
            log_args.extend(["-n", str(self.depth)])

        if self.branch is not None:
            log_args.append(self.branch)

        _, stdout, _ = await self._run_git_command(log_args, cwd=repo_path)

        commits = []
        current_commit: dict | None = None
        current_diff_lines: list[str] = []
        in_body = False

        for line in stdout.split("\n"):
            if line == "COMMIT_START":
                # Save previous commit if exists
                if current_commit is not None:
                    current_commit["diff"] = "\n".join(current_diff_lines)
                    commits.append(current_commit)
                current_commit = {}
                current_diff_lines = []
                in_body = False
            elif current_commit is not None:
                if "hash" not in current_commit:
                    current_commit["hash"] = line.strip()
                elif "author" not in current_commit:
                    current_commit["author"] = line.strip()
                elif "date" not in current_commit:
                    current_commit["date"] = line.strip()
                elif "subject" not in current_commit:
                    current_commit["subject"] = line.strip()
                elif not in_body:
                    if line == "COMMIT_BODY_END":
                        in_body = True
                    else:
                        current_commit.setdefault("body", []).append(line)
                else:
                    current_diff_lines.append(line)

        # Save last commit
        if current_commit is not None:
            current_commit["diff"] = "\n".join(current_diff_lines)
            commits.append(current_commit)

        return commits

    async def _scan_commit_history(self, repo_path: Path) -> list[Finding]:
        """Scan commit history for secrets.

        Args:
            repo_path: Path to the git repository.

        Returns:
            List of findings from commit history.
        """
        findings: list[Finding] = []

        self._current_item = "Fetching commit history"
        self._report_progress_internal()

        commits = await self._get_commit_log(repo_path)
        logger.info(f"Scanning {len(commits)} commits")

        for commit in commits:
            if self.is_cancelled:
                break

            commit_hash = commit.get("hash", "unknown")[:8]
            self._current_item = f"Commit {commit_hash}"
            self._report_progress_internal()
            self._commits_scanned += 1

            context = {
                "source_type": "commit_history",
                "commit_hash": commit.get("hash", ""),
                "author": commit.get("author", ""),
                "date": commit.get("date", ""),
            }

            # Scan commit message (subject + body)
            message = commit.get("subject", "")
            body = commit.get("body", [])
            if body:
                message += "\n" + "\n".join(body)

            if message.strip():
                message_findings = await self._scan_content(
                    message,
                    f"commit:{commit_hash}:message",
                    context={**context, "content_type": "commit_message"},
                )
                findings.extend(message_findings)

            # Scan diff for secrets (especially removed lines)
            diff = commit.get("diff", "")
            if diff.strip():
                diff_findings = await self._scan_content(
                    diff,
                    f"commit:{commit_hash}:diff",
                    context={**context, "content_type": "commit_diff"},
                )
                findings.extend(diff_findings)

        return findings

    async def _setup_repository(self) -> Path:
        """Set up the repository for scanning.

        Returns:
            Path to the repository directory.

        Raises:
            ScanError: If repository setup fails.
        """
        if self._is_remote_url(self.target):
            # Clone remote repository
            if self.clone_dir is not None:
                repo_path = self.clone_dir
                repo_path.mkdir(parents=True, exist_ok=True)
            else:
                self._temp_dir = tempfile.TemporaryDirectory(prefix="hamburglar_git_")
                repo_path = Path(self._temp_dir.name)

            await self._clone_repository(self.target, repo_path)
            return repo_path
        else:
            # Use local path
            local_path = Path(self.target)
            if not local_path.exists():
                raise ScanError(
                    f"Local path does not exist: {self.target}",
                    path=self.target,
                )

            # Check if it's a git repository
            git_dir = local_path / ".git"
            if not git_dir.exists():
                raise ScanError(
                    f"Not a git repository: {self.target}",
                    path=self.target,
                )

            return local_path

    def _cleanup(self) -> None:
        """Clean up temporary directory if one was created."""
        if self._temp_dir is not None:
            try:
                self._temp_dir.cleanup()
                logger.debug("Cleaned up temporary clone directory")
            except Exception as e:
                logger.warning(f"Failed to cleanup temp directory: {e}")
            finally:
                self._temp_dir = None

    async def scan(self) -> ScanResult:
        """Execute the scan operation.

        Clones the repository (if remote), scans current files, and optionally
        scans commit history for secrets.

        Returns:
            ScanResult containing all findings and scan statistics.

        Raises:
            ScanError: If the repository cannot be accessed or cloned.
        """
        self._reset()
        self._start_time = time.time()

        try:
            # Set up repository (clone if remote, verify if local)
            self._repo_path = await self._setup_repository()

            all_findings: list[Finding] = []

            # Scan current HEAD files
            if not self.is_cancelled:
                head_findings = await self._scan_current_files(self._repo_path)
                all_findings.extend(head_findings)

            # Scan commit history if enabled
            if self.include_history and not self.is_cancelled:
                history_findings = await self._scan_commit_history(self._repo_path)
                all_findings.extend(history_findings)

            scan_duration = time.time() - self._start_time
            logger.info(
                f"Git scan complete: {self._files_scanned} files, "
                f"{self._commits_scanned} commits, {len(all_findings)} findings"
                + (" (cancelled)" if self.is_cancelled else "")
            )

            return ScanResult(
                target_path=self.target,
                findings=all_findings,
                scan_duration=scan_duration,
                stats={
                    "files_scanned": self._files_scanned,
                    "commits_scanned": self._commits_scanned,
                    "total_findings": len(all_findings),
                    "cancelled": self.is_cancelled,
                    "errors": self._errors,
                    "is_remote": self._is_remote_url(self.target),
                    "include_history": self.include_history,
                },
            )

        finally:
            # Always cleanup temp directory
            self._cleanup()

    async def scan_stream(self) -> AsyncIterator[Finding]:
        """Execute the scan and stream findings as they're discovered.

        This is an async generator that yields findings as they're found,
        allowing for real-time processing of results.

        Yields:
            Finding objects as they're discovered during the scan.

        Raises:
            ScanError: If the repository cannot be accessed or cloned.
        """
        self._reset()
        self._start_time = time.time()

        try:
            # Set up repository
            self._repo_path = await self._setup_repository()

            # Stream findings from current files
            if not self.is_cancelled:
                files = await self._get_repo_files(self._repo_path)
                for file_path in files:
                    if self.is_cancelled:
                        break

                    self._current_item = str(file_path.relative_to(self._repo_path))
                    self._report_progress_internal()

                    content = await self._read_file(file_path)
                    if content is None:
                        continue

                    self._files_scanned += 1
                    for finding in await self._scan_content(
                        content,
                        str(file_path.relative_to(self._repo_path)),
                        context={"source_type": "current_file", "commit": "HEAD"},
                    ):
                        yield finding

            # Stream findings from commit history
            if self.include_history and not self.is_cancelled:
                commits = await self._get_commit_log(self._repo_path)
                for commit in commits:
                    if self.is_cancelled:
                        break

                    commit_hash = commit.get("hash", "unknown")[:8]
                    self._current_item = f"Commit {commit_hash}"
                    self._report_progress_internal()
                    self._commits_scanned += 1

                    context = {
                        "source_type": "commit_history",
                        "commit_hash": commit.get("hash", ""),
                        "author": commit.get("author", ""),
                        "date": commit.get("date", ""),
                    }

                    # Scan commit message
                    message = commit.get("subject", "")
                    body = commit.get("body", [])
                    if body:
                        message += "\n" + "\n".join(body)

                    if message.strip():
                        for finding in await self._scan_content(
                            message,
                            f"commit:{commit_hash}:message",
                            context={**context, "content_type": "commit_message"},
                        ):
                            yield finding

                    # Scan diff
                    diff = commit.get("diff", "")
                    if diff.strip():
                        for finding in await self._scan_content(
                            diff,
                            f"commit:{commit_hash}:diff",
                            context={**context, "content_type": "commit_diff"},
                        ):
                            yield finding

            logger.info(
                f"Git stream scan complete: {self._files_scanned} files, "
                f"{self._commits_scanned} commits"
            )

        finally:
            self._cleanup()

    def get_stats(self) -> dict:
        """Get current scan statistics.

        Returns:
            Dictionary with current scan statistics.
        """
        return {
            "files_scanned": self._files_scanned,
            "commits_scanned": self._commits_scanned,
            "findings_count": self._findings_count,
            "elapsed_time": time.time() - self._start_time if self._start_time else 0.0,
            "cancelled": self.is_cancelled,
            "errors": self._errors,
        }
