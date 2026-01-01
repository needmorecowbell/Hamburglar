"""Git history scanner module for Hamburglar.

This module provides the GitHistoryScanner class which provides detailed analysis
of git repository history, tracking secrets through their lifecycle in commits.

The scanner:
- Parses git log output efficiently
- Identifies files changed per commit
- Detects secrets that were added then removed
- Tracks secret lifetime (first seen, last seen commits)
- Generates timeline of secret exposure
"""

import asyncio
import logging
import re
import time
from collections.abc import AsyncIterator
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import TYPE_CHECKING

from hamburglar.core.exceptions import ScanError
from hamburglar.core.models import Finding, ScanResult, Severity
from hamburglar.core.progress import ScanProgress
from hamburglar.scanners import BaseScanner, ProgressCallback

if TYPE_CHECKING:
    from hamburglar.detectors import BaseDetector

logger = logging.getLogger(__name__)


@dataclass
class SecretOccurrence:
    """Represents a single occurrence of a secret in a commit.

    Attributes:
        commit_hash: The commit hash where the secret was found.
        author: The author of the commit.
        date: The date of the commit.
        file_path: The file path at the time of the commit.
        line_type: Whether this was an addition ('+') or removal ('-').
        line_number: Optional line number in the diff.
    """

    commit_hash: str
    author: str
    date: str
    file_path: str
    line_type: str  # '+' for addition, '-' for removal
    line_number: int | None = None


@dataclass
class SecretTimeline:
    """Tracks the lifecycle of a secret through git history.

    Attributes:
        secret_hash: A hash of the secret value (for grouping without storing the secret).
        secret_preview: A preview of the secret (first and last few chars).
        detector_name: The detector that found this secret.
        severity: The severity of the finding.
        first_seen: The commit where this secret was first introduced.
        last_seen: The commit where this secret was last seen.
        is_removed: Whether the secret has been removed from the current HEAD.
        occurrences: List of all occurrences of this secret in history.
        exposure_duration: Time between first introduction and removal (if removed).
        affected_files: Set of files where this secret appeared.
    """

    secret_hash: str
    secret_preview: str
    detector_name: str
    severity: Severity
    first_seen: SecretOccurrence | None = None
    last_seen: SecretOccurrence | None = None
    is_removed: bool = False
    occurrences: list[SecretOccurrence] = field(default_factory=list)
    exposure_duration: float | None = None  # Duration in seconds
    affected_files: set[str] = field(default_factory=set)

    def add_occurrence(self, occurrence: SecretOccurrence) -> None:
        """Add an occurrence and update first/last seen."""
        self.occurrences.append(occurrence)
        self.affected_files.add(occurrence.file_path)

        # Update first_seen (earliest addition)
        if occurrence.line_type == "+":
            if self.first_seen is None or occurrence.date < self.first_seen.date:
                self.first_seen = occurrence

        # Update last_seen (latest occurrence of any type)
        if self.last_seen is None or occurrence.date > self.last_seen.date:
            self.last_seen = occurrence

        # Check if removed (last occurrence is a removal)
        if self.last_seen.line_type == "-":
            self.is_removed = True
            if self.first_seen and self.last_seen:
                try:
                    first_dt = datetime.fromisoformat(self.first_seen.date.replace("Z", "+00:00"))
                    last_dt = datetime.fromisoformat(self.last_seen.date.replace("Z", "+00:00"))
                    self.exposure_duration = (last_dt - first_dt).total_seconds()
                except (ValueError, TypeError):
                    pass


@dataclass
class CommitInfo:
    """Information about a single commit.

    Attributes:
        hash: The full commit hash.
        short_hash: The short commit hash (8 chars).
        author: The author name.
        email: The author email.
        date: The commit date in ISO format.
        subject: The commit subject line.
        body: The commit body (additional message lines).
        files_changed: List of files changed in this commit.
        additions: Dict of file paths to added lines.
        deletions: Dict of file paths to deleted lines.
    """

    hash: str
    short_hash: str = ""
    author: str = ""
    email: str = ""
    date: str = ""
    subject: str = ""
    body: list[str] = field(default_factory=list)
    files_changed: list[str] = field(default_factory=list)
    additions: dict[str, list[tuple[int, str]]] = field(default_factory=dict)
    deletions: dict[str, list[tuple[int, str]]] = field(default_factory=dict)

    def __post_init__(self):
        if not self.short_hash and self.hash:
            self.short_hash = self.hash[:8]


class GitHistoryScanner(BaseScanner):
    """Git history scanner that provides detailed secret lifecycle analysis.

    The GitHistoryScanner performs deep analysis of git repository history to:
    - Parse git log output efficiently
    - Identify files changed per commit
    - Detect secrets that were added then removed
    - Track secret lifetime (first seen, last seen commits)
    - Generate timeline of secret exposure

    Unlike GitScanner which provides a simpler scan of history, this scanner
    focuses on tracking the complete lifecycle of each discovered secret.

    Attributes:
        repo_path: Path to the git repository (must be local, not a URL).
        depth: Number of commits to examine (None for all history).
        branch: Specific branch to scan (None for current/default branch).
    """

    def __init__(
        self,
        repo_path: str | Path,
        detectors: list["BaseDetector"] | None = None,
        progress_callback: ProgressCallback | None = None,
        depth: int | None = None,
        branch: str | None = None,
    ):
        """Initialize the git history scanner.

        Args:
            repo_path: Path to the local git repository directory.
            detectors: List of detector instances to use for scanning.
                      If None, no detections will be performed.
            progress_callback: Optional callback function for progress updates.
            depth: Number of commits to examine. None for all history.
            branch: Specific branch to scan. None for current/default branch.
        """
        super().__init__(detectors=detectors, progress_callback=progress_callback)
        self.repo_path = Path(repo_path)
        self.depth = depth
        self.branch = branch

        # Internal state
        self._cancel_event = asyncio.Event()
        self._start_time: float = 0.0
        self._commits_parsed: int = 0
        self._secrets_tracked: int = 0
        self._findings_count: int = 0
        self._current_item: str = ""
        self._errors: list[str] = []

        # Secret tracking
        self._secret_timelines: dict[str, SecretTimeline] = {}

    @property
    def scanner_type(self) -> str:
        """Return the type identifier for this scanner.

        Returns:
            'git_history' - identifies this as a git history scanner.
        """
        return "git_history"

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
        logger.info("Git history scan cancellation requested")

    def _reset(self) -> None:
        """Reset the scanner state for a new scan."""
        self._cancel_event.clear()
        self._start_time = 0.0
        self._commits_parsed = 0
        self._secrets_tracked = 0
        self._findings_count = 0
        self._current_item = ""
        self._errors = []
        self._secret_timelines = {}

    def _get_progress(self) -> ScanProgress:
        """Get the current scan progress.

        Returns:
            ScanProgress dataclass with current scan statistics.
        """
        return ScanProgress(
            total_files=0,
            scanned_files=self._commits_parsed,
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
                cwd=cwd or self.repo_path,
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

    async def _validate_repository(self) -> None:
        """Validate that the path is a valid git repository.

        Raises:
            ScanError: If the path is not a valid git repository.
        """
        if not self.repo_path.exists():
            raise ScanError(
                f"Path does not exist: {self.repo_path}",
                path=str(self.repo_path),
            )

        git_dir = self.repo_path / ".git"
        if not git_dir.exists():
            raise ScanError(
                f"Not a git repository: {self.repo_path}",
                path=str(self.repo_path),
            )

    async def _get_commit_list(self) -> list[str]:
        """Get list of commit hashes to analyze.

        Returns:
            List of commit hashes from newest to oldest.
        """
        log_args = ["log", "--format=%H"]

        if self.depth is not None:
            log_args.extend(["-n", str(self.depth)])

        if self.branch is not None:
            log_args.append(self.branch)
        else:
            log_args.append("--all")

        _, stdout, _ = await self._run_git_command(log_args)
        return [h.strip() for h in stdout.strip().split("\n") if h.strip()]

    async def _get_commit_info(self, commit_hash: str) -> CommitInfo:
        """Get detailed information about a commit.

        Args:
            commit_hash: The commit hash to get info for.

        Returns:
            CommitInfo dataclass with commit details.
        """
        # Get commit metadata
        format_str = "%H%n%an%n%ae%n%aI%n%s"
        _, stdout, _ = await self._run_git_command(
            ["show", "-s", f"--format={format_str}", commit_hash]
        )

        lines = stdout.strip().split("\n")
        commit_info = CommitInfo(
            hash=lines[0] if len(lines) > 0 else commit_hash,
            author=lines[1] if len(lines) > 1 else "",
            email=lines[2] if len(lines) > 2 else "",
            date=lines[3] if len(lines) > 3 else "",
            subject=lines[4] if len(lines) > 4 else "",
        )

        # Get commit body
        _, body_out, _ = await self._run_git_command(["show", "-s", "--format=%b", commit_hash])
        commit_info.body = [line for line in body_out.strip().split("\n") if line.strip()]

        return commit_info

    def _parse_diff_output(
        self, diff_output: str
    ) -> tuple[dict[str, list[tuple[int, str]]], dict[str, list[tuple[int, str]]]]:
        """Parse git diff output to extract additions and deletions.

        Args:
            diff_output: Raw git diff output.

        Returns:
            Tuple of (additions, deletions) where each is a dict mapping
            file paths to list of (line_number, content) tuples.
        """
        additions: dict[str, list[tuple[int, str]]] = {}
        deletions: dict[str, list[tuple[int, str]]] = {}

        current_file: str | None = None
        current_line_add = 0
        current_line_del = 0

        # Pattern for file path in diff
        file_pattern = re.compile(r"^diff --git a/(.+) b/(.+)$")
        # Pattern for hunk header
        hunk_pattern = re.compile(r"^@@ -(\d+)(?:,\d+)? \+(\d+)(?:,\d+)? @@")

        for line in diff_output.split("\n"):
            # Check for new file
            file_match = file_pattern.match(line)
            if file_match:
                current_file = file_match.group(2)
                if current_file not in additions:
                    additions[current_file] = []
                if current_file not in deletions:
                    deletions[current_file] = []
                continue

            # Check for hunk header
            hunk_match = hunk_pattern.match(line)
            if hunk_match:
                current_line_del = int(hunk_match.group(1))
                current_line_add = int(hunk_match.group(2))
                continue

            # Process diff lines
            if current_file is not None:
                if line.startswith("+") and not line.startswith("+++"):
                    additions[current_file].append((current_line_add, line[1:]))
                    current_line_add += 1
                elif line.startswith("-") and not line.startswith("---"):
                    deletions[current_file].append((current_line_del, line[1:]))
                    current_line_del += 1
                elif not line.startswith("\\"):  # Ignore "\ No newline at end of file"
                    current_line_add += 1
                    current_line_del += 1

        return additions, deletions

    async def _get_commit_diff(
        self, commit_hash: str
    ) -> tuple[dict[str, list[tuple[int, str]]], dict[str, list[tuple[int, str]]]]:
        """Get the diff for a specific commit.

        Args:
            commit_hash: The commit hash to get diff for.

        Returns:
            Tuple of (additions, deletions) dicts.
        """
        # Use --first-parent to handle merge commits better
        _, diff_output, _ = await self._run_git_command(
            ["show", "--format=", "-p", commit_hash],
            check=False,  # Some commits may have no diff
        )

        return self._parse_diff_output(diff_output)

    def _hash_secret(self, secret: str) -> str:
        """Create a hash of the secret for tracking.

        Args:
            secret: The secret string.

        Returns:
            A hash string for the secret.
        """
        import hashlib

        return hashlib.sha256(secret.encode()).hexdigest()[:16]

    def _create_secret_preview(self, secret: str) -> str:
        """Create a preview of the secret (for display without full exposure).

        Args:
            secret: The secret string.

        Returns:
            A preview showing first 3 and last 3 chars.
        """
        if len(secret) <= 10:
            return "*" * len(secret)
        return f"{secret[:3]}...{secret[-3:]}"

    async def _scan_line(
        self,
        content: str,
        file_path: str,
        line_number: int,
        commit_info: CommitInfo,
        line_type: str,
    ) -> list[Finding]:
        """Scan a single line with all detectors and track secrets.

        Args:
            content: The line content to scan.
            file_path: The file path this line is from.
            line_number: The line number in the file.
            commit_info: Information about the commit.
            line_type: '+' for addition, '-' for deletion.

        Returns:
            List of findings from detectors.
        """
        findings: list[Finding] = []

        for detector in self.detectors:
            if self.is_cancelled:
                break
            try:
                detector_findings = detector.detect(content, file_path)

                for finding in detector_findings:
                    self._findings_count += 1

                    # Track secret timeline for each match
                    for match in finding.matches:
                        secret_hash = self._hash_secret(match)

                        if secret_hash not in self._secret_timelines:
                            self._secret_timelines[secret_hash] = SecretTimeline(
                                secret_hash=secret_hash,
                                secret_preview=self._create_secret_preview(match),
                                detector_name=finding.detector_name,
                                severity=finding.severity,
                            )
                            self._secrets_tracked += 1

                        occurrence = SecretOccurrence(
                            commit_hash=commit_info.hash,
                            author=commit_info.author,
                            date=commit_info.date,
                            file_path=file_path,
                            line_type=line_type,
                            line_number=line_number,
                        )
                        self._secret_timelines[secret_hash].add_occurrence(occurrence)

                    # Add context to finding
                    finding.metadata.update(
                        {
                            "source_type": "commit_history",
                            "commit_hash": commit_info.hash,
                            "commit_short": commit_info.short_hash,
                            "author": commit_info.author,
                            "date": commit_info.date,
                            "line_type": "addition" if line_type == "+" else "deletion",
                            "line_number": line_number,
                            "file_path_at_commit": file_path,
                        }
                    )
                    findings.append(finding)

            except Exception as e:
                logger.error(f"Detector {detector.name} failed on {file_path}: {e}")
                self._errors.append(f"Detector {detector.name} error: {e}")

        return findings

    async def _analyze_commit(self, commit_hash: str) -> list[Finding]:
        """Analyze a single commit for secrets.

        Args:
            commit_hash: The commit hash to analyze.

        Returns:
            List of findings from this commit.
        """
        findings: list[Finding] = []

        self._current_item = f"Analyzing {commit_hash[:8]}"
        self._report_progress_internal()

        try:
            commit_info = await self._get_commit_info(commit_hash)
            additions, deletions = await self._get_commit_diff(commit_hash)

            # Scan additions (secrets being added)
            for file_path, lines in additions.items():
                if self.is_cancelled:
                    break
                for line_num, content in lines:
                    if content.strip():
                        line_findings = await self._scan_line(
                            content, file_path, line_num, commit_info, "+"
                        )
                        findings.extend(line_findings)

            # Scan deletions (secrets being removed)
            for file_path, lines in deletions.items():
                if self.is_cancelled:
                    break
                for line_num, content in lines:
                    if content.strip():
                        line_findings = await self._scan_line(
                            content, file_path, line_num, commit_info, "-"
                        )
                        findings.extend(line_findings)

            # Also scan commit message
            full_message = commit_info.subject
            if commit_info.body:
                full_message += "\n" + "\n".join(commit_info.body)

            if full_message.strip():
                for detector in self.detectors:
                    if self.is_cancelled:
                        break
                    try:
                        msg_findings = detector.detect(
                            full_message, f"commit:{commit_hash[:8]}:message"
                        )
                        for finding in msg_findings:
                            finding.metadata.update(
                                {
                                    "source_type": "commit_message",
                                    "commit_hash": commit_info.hash,
                                    "commit_short": commit_info.short_hash,
                                    "author": commit_info.author,
                                    "date": commit_info.date,
                                }
                            )
                            findings.append(finding)
                            self._findings_count += 1
                    except Exception as e:
                        logger.error(f"Detector {detector.name} failed on commit message: {e}")

            self._commits_parsed += 1

        except ScanError:
            raise
        except Exception as e:
            logger.error(f"Error analyzing commit {commit_hash[:8]}: {e}")
            self._errors.append(f"Error analyzing commit {commit_hash[:8]}: {e}")

        return findings

    def get_secret_timelines(self) -> list[SecretTimeline]:
        """Get all tracked secret timelines.

        Returns:
            List of SecretTimeline objects for all discovered secrets.
        """
        return list(self._secret_timelines.values())

    def get_removed_secrets(self) -> list[SecretTimeline]:
        """Get secrets that have been removed from the repository.

        Returns:
            List of SecretTimeline objects for secrets that were removed.
        """
        return [t for t in self._secret_timelines.values() if t.is_removed]

    def get_active_secrets(self) -> list[SecretTimeline]:
        """Get secrets that are still present in the repository.

        Returns:
            List of SecretTimeline objects for secrets still present.
        """
        return [t for t in self._secret_timelines.values() if not t.is_removed]

    async def scan(self) -> ScanResult:
        """Execute the scan operation.

        Analyzes git history to find and track secrets through their lifecycle.

        Returns:
            ScanResult containing all findings and scan statistics.

        Raises:
            ScanError: If the repository cannot be accessed.
        """
        self._reset()
        self._start_time = time.time()

        await self._validate_repository()

        self._current_item = "Getting commit list"
        self._report_progress_internal()

        commit_hashes = await self._get_commit_list()
        logger.info(f"Analyzing {len(commit_hashes)} commits")

        all_findings: list[Finding] = []

        for commit_hash in commit_hashes:
            if self.is_cancelled:
                break

            commit_findings = await self._analyze_commit(commit_hash)
            all_findings.extend(commit_findings)

        scan_duration = time.time() - self._start_time

        # Build timeline summary
        removed_secrets = self.get_removed_secrets()
        active_secrets = self.get_active_secrets()

        logger.info(
            f"Git history scan complete: {self._commits_parsed} commits, "
            f"{self._secrets_tracked} unique secrets, {len(all_findings)} findings"
            + (" (cancelled)" if self.is_cancelled else "")
        )

        return ScanResult(
            target_path=str(self.repo_path),
            findings=all_findings,
            scan_duration=scan_duration,
            stats={
                "commits_parsed": self._commits_parsed,
                "total_commits": len(commit_hashes),
                "unique_secrets": self._secrets_tracked,
                "removed_secrets": len(removed_secrets),
                "active_secrets": len(active_secrets),
                "total_findings": len(all_findings),
                "cancelled": self.is_cancelled,
                "errors": self._errors,
            },
        )

    async def scan_stream(self) -> AsyncIterator[Finding]:
        """Execute the scan and stream findings as they're discovered.

        This is an async generator that yields findings as they're found,
        allowing for real-time processing of results.

        Yields:
            Finding objects as they're discovered during the scan.

        Raises:
            ScanError: If the repository cannot be accessed.
        """
        self._reset()
        self._start_time = time.time()

        await self._validate_repository()

        commit_hashes = await self._get_commit_list()
        logger.info(f"Streaming analysis of {len(commit_hashes)} commits")

        for commit_hash in commit_hashes:
            if self.is_cancelled:
                break

            for finding in await self._analyze_commit(commit_hash):
                yield finding

        logger.info(
            f"Git history stream complete: {self._commits_parsed} commits, "
            f"{self._secrets_tracked} unique secrets"
        )

    def get_stats(self) -> dict:
        """Get current scan statistics.

        Returns:
            Dictionary with current scan statistics.
        """
        return {
            "commits_parsed": self._commits_parsed,
            "secrets_tracked": self._secrets_tracked,
            "findings_count": self._findings_count,
            "elapsed_time": time.time() - self._start_time if self._start_time else 0.0,
            "cancelled": self.is_cancelled,
            "errors": self._errors,
        }

    def generate_timeline_report(self) -> str:
        """Generate a human-readable timeline report.

        Returns:
            A formatted string report of all secret timelines.
        """
        lines = ["=" * 60, "SECRET TIMELINE REPORT", "=" * 60, ""]

        timelines = self.get_secret_timelines()
        if not timelines:
            lines.append("No secrets found in repository history.")
            return "\n".join(lines)

        # Group by status
        active = self.get_active_secrets()
        removed = self.get_removed_secrets()

        if active:
            lines.append(f"ACTIVE SECRETS ({len(active)}):")
            lines.append("-" * 40)
            for timeline in active:
                lines.append(self._format_timeline(timeline))
            lines.append("")

        if removed:
            lines.append(f"REMOVED SECRETS ({len(removed)}):")
            lines.append("-" * 40)
            for timeline in removed:
                lines.append(self._format_timeline(timeline))
            lines.append("")

        lines.append("=" * 60)
        lines.append(f"Total unique secrets: {len(timelines)}")
        lines.append(f"Active: {len(active)}, Removed: {len(removed)}")

        return "\n".join(lines)

    def _format_timeline(self, timeline: SecretTimeline) -> str:
        """Format a single timeline for display.

        Args:
            timeline: The SecretTimeline to format.

        Returns:
            A formatted string representation.
        """
        lines = [
            f"  Secret: {timeline.secret_preview}",
            f"  Detector: {timeline.detector_name}",
            f"  Severity: {timeline.severity.value}",
            f"  Status: {'REMOVED' if timeline.is_removed else 'ACTIVE'}",
        ]

        if timeline.first_seen:
            lines.append(
                f"  First seen: {timeline.first_seen.commit_hash[:8]} "
                f"({timeline.first_seen.date}) in {timeline.first_seen.file_path}"
            )

        if timeline.last_seen:
            action = "Removed" if timeline.is_removed else "Last seen"
            lines.append(
                f"  {action}: {timeline.last_seen.commit_hash[:8]} "
                f"({timeline.last_seen.date}) in {timeline.last_seen.file_path}"
            )

        if timeline.exposure_duration is not None:
            days = timeline.exposure_duration / 86400
            lines.append(f"  Exposure duration: {days:.1f} days")

        if timeline.affected_files:
            lines.append(f"  Affected files: {', '.join(timeline.affected_files)}")

        lines.append("")
        return "\n".join(lines)
