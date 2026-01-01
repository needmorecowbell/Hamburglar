"""Shared pytest fixtures for git repository testing.

This module provides reusable git repository fixtures for testing git and
git history scanning functionality. All fixtures create temporary git
repositories with various configurations:

- git_repo_base: A simple git repository with basic setup
- git_repo_with_current_secret: Repository with secrets in current HEAD
- git_repo_with_removed_secret: Repository with secrets that were removed
- git_repo_with_commit_message_secret: Repository with secrets in commit messages
- git_repo_full: Complete repository with all scenarios for comprehensive testing

All repositories are created in pytest's tmp_path and automatically cleaned up.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest


def _init_git_repo(repo_path: Path) -> None:
    """Initialize a git repository with standard configuration.

    Args:
        repo_path: Path where the repository should be created
    """
    repo_path.mkdir(exist_ok=True)
    subprocess.run(["git", "init"], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@example.com"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "config", "user.name", "Test User"],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )


def _git_commit(repo_path: Path, message: str) -> None:
    """Create a git commit with the given message.

    Args:
        repo_path: Path to the git repository
        message: Commit message
    """
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", message],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )


@pytest.fixture
def git_repo_base(tmp_path: Path) -> Path:
    """Create a basic git repository with a clean file.

    Creates a minimal git repository suitable for testing basic
    git operations without any secrets.

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "git_repo_base"
    _init_git_repo(repo_path)

    readme = repo_path / "README.md"
    readme.write_text("# Test Repository\n\nThis is a clean test repository.\n")
    _git_commit(repo_path, "Initial commit")

    return repo_path


@pytest.fixture
def git_repo_with_current_secret(tmp_path: Path) -> Path:
    """Create a git repository with secrets in the current HEAD.

    Creates a repository containing:
    - config.py: File with AWS key and GitHub token in current HEAD

    This fixture tests detection of secrets that are currently present
    in the working tree.

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "git_repo_current_secret"
    _init_git_repo(repo_path)

    # Create file with secrets
    config_file = repo_path / "config.py"
    config_file.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'API_TOKEN = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"\n'
    )
    _git_commit(repo_path, "Add config with secrets")

    return repo_path


@pytest.fixture
def git_repo_with_removed_secret(tmp_path: Path) -> Path:
    """Create a git repository with secrets that were added then removed.

    Creates a repository with the following commit history:
    1. Initial commit with a secret (AWS key)
    2. Second commit adding a clean file
    3. Third commit removing the secret

    This fixture tests detection of secrets in git history that
    are no longer present in the current HEAD.

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "git_repo_removed_secret"
    _init_git_repo(repo_path)

    # Commit 1: Add secret
    secrets_file = repo_path / "secrets.txt"
    secrets_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    _git_commit(repo_path, "Initial commit with secret")

    # Commit 2: Add clean file
    clean_file = repo_path / "clean.txt"
    clean_file.write_text("This is a clean file without secrets.\n")
    _git_commit(repo_path, "Add clean file")

    # Commit 3: Remove the secret
    secrets_file.write_text("# Secret removed\n")
    _git_commit(repo_path, "Remove the secret")

    return repo_path


@pytest.fixture
def git_repo_with_commit_message_secret(tmp_path: Path) -> Path:
    """Create a git repository with secrets in commit messages.

    Creates a repository where:
    - A secret appears in a commit message body (not just the subject)

    This fixture tests detection of secrets that were accidentally
    included in git commit messages.

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "git_repo_commit_msg_secret"
    _init_git_repo(repo_path)

    # Create clean file
    readme = repo_path / "README.md"
    readme.write_text("# Test Repository\n")

    # Commit with secret in message body
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "commit",
            "-m",
            "Add README\n\nNote: Old key was AKIAIOSFODNN7EXAMPLE",
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path


@pytest.fixture
def git_repo_full(tmp_path: Path) -> Path:
    """Create a comprehensive git repository with all secret scenarios.

    Creates a repository combining all scenarios for comprehensive testing:
    1. Initial commit with a secret (AWS key)
    2. Second commit adding another secret (GitHub token)
    3. Third commit removing the first secret
    4. Fourth commit with a secret in the commit message

    This fixture is suitable for testing:
    - Current file secret detection
    - Historical secret detection
    - Removed secret detection
    - Commit message secret detection
    - Secret timeline generation

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "git_repo_full"
    _init_git_repo(repo_path)

    # Commit 1: Add first secret
    config_file = repo_path / "config.py"
    config_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _git_commit(repo_path, "Add initial config")

    # Commit 2: Add second secret
    config_file.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    )
    _git_commit(repo_path, "Add API token")

    # Commit 3: Remove first secret
    config_file.write_text(
        '# AWS_KEY removed for security\n'
        'API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    )
    _git_commit(repo_path, "Remove AWS key")

    # Commit 4: Add README with secret in commit message
    readme = repo_path / "README.md"
    readme.write_text("# Project README\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "commit",
            "-m",
            "Add README\n\nNote: Old key was AKIAIOSFODNN7EXAMPLE",
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path


@pytest.fixture
def git_repo_simple(tmp_path: Path) -> Path:
    """Create a simple git repository with one commit containing a secret.

    Creates a minimal repository with:
    - Single commit with a secret in config.py

    Useful for basic tests that don't need complex history.

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "git_repo_simple"
    _init_git_repo(repo_path)

    config_file = repo_path / "config.py"
    config_file.write_text('SECRET_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _git_commit(repo_path, "Initial commit")

    return repo_path


@pytest.fixture
def git_repo_with_history(tmp_path: Path) -> Path:
    """Create a git repository with history tracking scenarios.

    Alias for git_repo_full - creates a repository suitable for
    testing git history scanning and secret timeline generation.

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "git_repo_with_history"
    _init_git_repo(repo_path)

    # Commit 1: Add first secret
    secrets_file = repo_path / "config.py"
    secrets_file.write_text('AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    _git_commit(repo_path, "Add initial config")

    # Commit 2: Add second secret
    secrets_file.write_text(
        'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'
        'API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    )
    _git_commit(repo_path, "Add API token")

    # Commit 3: Remove first secret
    secrets_file.write_text(
        '# AWS_KEY removed for security\n'
        'API_TOKEN = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"\n'
    )
    _git_commit(repo_path, "Remove AWS key")

    # Commit 4: Add a commit message with a secret
    readme = repo_path / "README.md"
    readme.write_text("# Project README\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "commit",
            "-m",
            "Add README\n\nNote: Old key was AKIAIOSFODNN7EXAMPLE",
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path


@pytest.fixture
def git_repo(tmp_path: Path) -> Path:
    """Create a test git repository with multiple scenarios.

    Alias for backwards compatibility - creates the same repository
    as git_repo_with_removed_secret plus a commit with secret in message.

    This fixture maintains compatibility with existing tests.

    Returns:
        Path to the repository
    """
    repo_path = tmp_path / "test_repo"
    _init_git_repo(repo_path)

    # Create initial file with secret
    secrets_file = repo_path / "secrets.txt"
    secrets_file.write_text('aws_key = "AKIAIOSFODNN7EXAMPLE"\n')
    _git_commit(repo_path, "Initial commit with secret")

    # Create another file without secrets
    clean_file = repo_path / "clean.txt"
    clean_file.write_text("This is a clean file without secrets.\n")
    _git_commit(repo_path, "Add clean file")

    # Remove the secret from the file
    secrets_file.write_text("# Secret removed\n")
    _git_commit(repo_path, "Remove the secret")

    # Add a commit with secret in message
    readme = repo_path / "README.md"
    readme.write_text("# Test Repository\n")
    subprocess.run(["git", "add", "."], cwd=repo_path, check=True, capture_output=True)
    subprocess.run(
        [
            "git",
            "commit",
            "-m",
            "Add README\n\nNote: Old key was AKIAIOSFODNN7EXAMPLE",
        ],
        cwd=repo_path,
        check=True,
        capture_output=True,
    )

    return repo_path
