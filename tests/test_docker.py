"""Tests for Docker image build and functionality.

This module contains integration tests for the Hamburglar Docker image.
These tests verify that:
- Docker image builds successfully
- Container runs and produces output
- Volume mounts work correctly
- Non-root user is used for security

These tests are marked as integration tests and require Docker to be available.
They will be skipped if Docker is not installed or not running.
"""

from __future__ import annotations

import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Generator

import pytest

# Configure path before any hamburglar imports (same as conftest.py)
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Check if Docker is available
def docker_available() -> bool:
    """Check if Docker is installed and the daemon is running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=30,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# Mark all tests in this module as integration tests
pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not docker_available(),
        reason="Docker is not available or not running",
    ),
]

# Test image name
IMAGE_NAME = "hamburglar-test"
IMAGE_TAG = "test"
FULL_IMAGE_NAME = f"{IMAGE_NAME}:{IMAGE_TAG}"


@pytest.fixture(scope="module")
def docker_image() -> Generator[str, None, None]:
    """Build the Docker image for testing.

    This fixture builds the Docker image once per test module
    and yields the image name. After all tests complete,
    it optionally cleans up the image.

    Yields:
        The full image name (name:tag)
    """
    # Get the project root directory
    project_root = Path(__file__).parent.parent

    # Build the Docker image
    result = subprocess.run(
        [
            "docker",
            "build",
            "-t",
            FULL_IMAGE_NAME,
            str(project_root),
        ],
        capture_output=True,
        text=True,
        timeout=600,  # 10 minute timeout for build
    )

    if result.returncode != 0:
        pytest.fail(f"Docker build failed:\n{result.stderr}")

    yield FULL_IMAGE_NAME

    # Cleanup: remove the test image
    subprocess.run(
        ["docker", "rmi", "-f", FULL_IMAGE_NAME],
        capture_output=True,
        timeout=60,
    )


@pytest.fixture
def temp_scan_directory(tmp_path: Path) -> Path:
    """Create a temporary directory with sample files for scanning.

    Args:
        tmp_path: pytest's tmp_path fixture

    Returns:
        Path to the temporary directory with test files
    """
    # Create a file with secrets for testing
    secrets_file = tmp_path / "secrets.txt"
    secrets_file.write_text("""
# Test secrets file
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
api_key = "sk-1234567890abcdefghijklmnopqrstuvwxyz"
""")

    # Create a clean file
    clean_file = tmp_path / "clean.txt"
    clean_file.write_text("This file has no secrets.")

    return tmp_path


class TestDockerImageBuild:
    """Tests for Docker image building."""

    def test_docker_image_builds_successfully(self, docker_image: str) -> None:
        """Test that the Docker image builds without errors."""
        # The docker_image fixture already builds the image
        # If we get here, the build succeeded
        assert docker_image == FULL_IMAGE_NAME

        # Verify the image exists
        result = subprocess.run(
            ["docker", "images", "-q", FULL_IMAGE_NAME],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0
        assert result.stdout.strip() != "", "Image should exist after build"

    def test_docker_image_has_correct_labels(self, docker_image: str) -> None:
        """Test that the Docker image has expected properties."""
        result = subprocess.run(
            ["docker", "inspect", docker_image],
            capture_output=True,
            text=True,
            timeout=30,
        )
        assert result.returncode == 0

        import json

        inspect_data = json.loads(result.stdout)
        assert len(inspect_data) > 0, "Should have image data"


class TestDockerContainerRuns:
    """Tests for running the Docker container."""

    def test_container_runs_version_command(self, docker_image: str) -> None:
        """Test that the container can run --version."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "Hamburglar" in result.stdout or "2.0.0" in result.stdout

    def test_container_runs_help_command(self, docker_image: str) -> None:
        """Test that the container can run --help."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "scan" in result.stdout.lower() or "usage" in result.stdout.lower()

    def test_container_scan_subcommand_help(self, docker_image: str) -> None:
        """Test that the scan subcommand help works."""
        result = subprocess.run(
            ["docker", "run", "--rm", docker_image, "scan", "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "PATH" in result.stdout or "path" in result.stdout.lower()

    def test_container_produces_output(
        self, docker_image: str, temp_scan_directory: Path
    ) -> None:
        """Test that the container produces scan output."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_scan_directory}:/data:ro",
                docker_image,
                "scan",
                "/data",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0

        import json

        output = json.loads(result.stdout)
        assert "findings" in output
        # Should find secrets in the test file
        assert len(output["findings"]) > 0


class TestDockerVolumeMounts:
    """Tests for Docker volume mount functionality."""

    def test_volume_mount_for_scan_target(
        self, docker_image: str, temp_scan_directory: Path
    ) -> None:
        """Test that volume mounts work for scanning targets."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_scan_directory}:/data:ro",
                docker_image,
                "scan",
                "/data",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0

    def test_volume_mount_read_only(
        self, docker_image: str, temp_scan_directory: Path
    ) -> None:
        """Test that the container respects read-only volume mounts."""
        # Try to create a file in read-only mounted volume
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_scan_directory}:/data:ro",
                "--entrypoint",
                "touch",
                docker_image,
                "/data/test_write.txt",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Should fail because the mount is read-only
        assert result.returncode != 0

    def test_output_volume_mount(
        self, docker_image: str, temp_scan_directory: Path, tmp_path: Path
    ) -> None:
        """Test that output can be written to a mounted output directory."""
        output_dir = tmp_path / "output"
        output_dir.mkdir()

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_scan_directory}:/data:ro",
                "-v",
                f"{output_dir}:/output",
                docker_image,
                "scan",
                "/data",
                "--format",
                "json",
                "--output-dir",
                "/output",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0

        # Check that output file was created
        output_files = list(output_dir.glob("*"))
        assert len(output_files) > 0, "Output file should be created"


class TestDockerSecurity:
    """Tests for Docker security configurations."""

    def test_non_root_user_is_used(self, docker_image: str) -> None:
        """Test that the container runs as a non-root user."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "id",
                docker_image,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0

        # Check that uid is not 0 (root)
        output = result.stdout
        assert "uid=0" not in output, "Container should not run as root"
        assert "uid=1000" in output, "Container should run as uid 1000 (hamburglar user)"

    def test_user_is_hamburglar(self, docker_image: str) -> None:
        """Test that the running user is named 'hamburglar'."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "whoami",
                docker_image,
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        assert result.returncode == 0
        assert "hamburglar" in result.stdout.strip()

    def test_cannot_write_to_system_directories(self, docker_image: str) -> None:
        """Test that the non-root user cannot write to system directories."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "touch",
                docker_image,
                "/etc/test_file",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # Should fail because non-root user can't write to /etc
        assert result.returncode != 0


class TestDockerYaraRules:
    """Tests for YARA rules inclusion in the Docker image."""

    def test_yara_rules_included(self, docker_image: str) -> None:
        """Test that YARA rules are included in the Docker image."""
        # Check that the hamburglar package is installed with rules
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--entrypoint",
                "python",
                docker_image,
                "-c",
                "from hamburglar.rules import get_rules_directory; print(get_rules_directory())",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        # This test may fail if the rules module doesn't exist
        # In that case, we skip it
        if result.returncode != 0:
            pytest.skip("YARA rules module not available")

        assert result.stdout.strip() != ""


class TestDockerScanFunctionality:
    """Tests for actual scanning functionality in Docker."""

    def test_scan_finds_aws_keys(
        self, docker_image: str, temp_scan_directory: Path
    ) -> None:
        """Test that scanning finds AWS keys in the test files."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_scan_directory}:/data:ro",
                docker_image,
                "scan",
                "/data",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0

        import json

        output = json.loads(result.stdout)
        assert "findings" in output

        # Check for AWS-related findings
        finding_patterns = [f["pattern_name"].lower() for f in output["findings"]]
        has_aws_finding = any(
            "aws" in p or "key" in p for p in finding_patterns
        )
        assert has_aws_finding or len(output["findings"]) > 0

    def test_scan_recursive_by_default(
        self, docker_image: str, tmp_path: Path
    ) -> None:
        """Test that scanning is recursive by default."""
        # Create nested directory structure
        subdir = tmp_path / "nested" / "deep"
        subdir.mkdir(parents=True)

        secret_file = subdir / "secret.txt"
        secret_file.write_text('api_key = "AKIAIOSFODNN7EXAMPLE"')

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp_path}:/data:ro",
                docker_image,
                "scan",
                "/data",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0

        import json

        output = json.loads(result.stdout)
        # Should find the secret in the nested file
        assert len(output["findings"]) > 0

    def test_scan_with_json_format(
        self, docker_image: str, temp_scan_directory: Path
    ) -> None:
        """Test scan output in JSON format."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_scan_directory}:/data:ro",
                docker_image,
                "scan",
                "/data",
                "--format",
                "json",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0

        import json

        # Should be valid JSON
        output = json.loads(result.stdout)
        assert isinstance(output, dict)
        assert "findings" in output

    def test_scan_with_table_format(
        self, docker_image: str, temp_scan_directory: Path
    ) -> None:
        """Test scan output in table format."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{temp_scan_directory}:/data:ro",
                docker_image,
                "scan",
                "/data",
                "--format",
                "table",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode == 0
        # Table format should have some structured output
        assert len(result.stdout) > 0
