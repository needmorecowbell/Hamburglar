#!/usr/bin/env bash
#
# publish.sh - Build and publish Hamburglar to PyPI
#
# Usage:
#   ./scripts/publish.sh              # Build only (dry run)
#   ./scripts/publish.sh --upload     # Build and upload to PyPI
#   ./scripts/publish.sh --test       # Build and upload to TestPyPI
#   ./scripts/publish.sh --skip-tests # Skip running tests before build
#
# Environment variables:
#   PYPI_TOKEN      - PyPI API token for authentication
#   TEST_PYPI_TOKEN - TestPyPI API token for authentication
#

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
UPLOAD=false
USE_TEST_PYPI=false
SKIP_TESTS=false
VERBOSE=false

# Helper functions
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

usage() {
    cat << EOF
Usage: $(basename "$0") [OPTIONS]

Build and publish Hamburglar to PyPI.

Options:
    -u, --upload        Upload to PyPI after building
    -t, --test          Upload to TestPyPI instead of PyPI
    --skip-tests        Skip running tests before build
    -v, --verbose       Enable verbose output
    -h, --help          Show this help message

Environment Variables:
    PYPI_TOKEN          PyPI API token (for --upload)
    TEST_PYPI_TOKEN     TestPyPI API token (for --test)

Examples:
    $(basename "$0")                      # Build only (dry run)
    $(basename "$0") --upload             # Build and upload to PyPI
    $(basename "$0") --test               # Build and upload to TestPyPI
    $(basename "$0") --test --skip-tests  # Quick test upload
    $(basename "$0") --upload --verbose   # Verbose upload to PyPI

The script will:
  1. Run tests (unless --skip-tests)
  2. Clean previous build artifacts
  3. Build wheel and source distribution
  4. Check packages with twine
  5. Upload to PyPI/TestPyPI (if --upload or --test)
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -u|--upload)
                UPLOAD=true
                shift
                ;;
            -t|--test)
                UPLOAD=true
                USE_TEST_PYPI=true
                shift
                ;;
            --skip-tests)
                SKIP_TESTS=true
                shift
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done
}

# Check prerequisites
check_prerequisites() {
    log_info "Checking prerequisites..."

    # Check Python
    if ! command -v python3 &> /dev/null; then
        log_error "Python 3 is not installed or not in PATH"
        exit 1
    fi

    local python_version
    python_version=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
    log_info "Using Python ${python_version}"

    # Check for required packages
    local missing_packages=()

    if ! python3 -c "import build" &> /dev/null; then
        missing_packages+=("build")
    fi

    if ! python3 -c "import twine" &> /dev/null; then
        missing_packages+=("twine")
    fi

    if [[ ${#missing_packages[@]} -gt 0 ]]; then
        log_error "Missing required packages: ${missing_packages[*]}"
        log_info "Install with: pip install ${missing_packages[*]}"
        exit 1
    fi

    # Check for pyproject.toml
    if [[ ! -f "${PROJECT_ROOT}/pyproject.toml" ]]; then
        log_error "pyproject.toml not found in ${PROJECT_ROOT}"
        exit 1
    fi

    # Check for API token if uploading
    if [[ "${UPLOAD}" == "true" ]]; then
        if [[ "${USE_TEST_PYPI}" == "true" ]]; then
            if [[ -z "${TEST_PYPI_TOKEN:-}" ]]; then
                log_warning "TEST_PYPI_TOKEN not set - you may be prompted for credentials"
            fi
        else
            if [[ -z "${PYPI_TOKEN:-}" ]]; then
                log_warning "PYPI_TOKEN not set - you may be prompted for credentials"
            fi
        fi
    fi

    log_success "Prerequisites check passed"
}

# Run tests
run_tests() {
    if [[ "${SKIP_TESTS}" == "true" ]]; then
        log_warning "Skipping tests (--skip-tests flag set)"
        return 0
    fi

    log_info "Running tests..."

    cd "${PROJECT_ROOT}"

    if ! python3 -m pytest tests/ -v --tb=short; then
        log_error "Tests failed - aborting publish"
        exit 1
    fi

    log_success "All tests passed"
}

# Clean previous build artifacts
clean_build() {
    log_info "Cleaning previous build artifacts..."

    cd "${PROJECT_ROOT}"

    rm -rf dist/ build/ src/*.egg-info

    log_success "Build artifacts cleaned"
}

# Build wheel and source distribution
build_package() {
    log_info "Building wheel and source distribution..."

    cd "${PROJECT_ROOT}"

    local build_args=("-m" "build")

    if [[ "${VERBOSE}" == "true" ]]; then
        build_args+=("--verbose")
    fi

    if python3 "${build_args[@]}"; then
        log_success "Package built successfully"
    else
        log_error "Package build failed"
        exit 1
    fi

    # List built artifacts
    log_info "Built artifacts:"
    ls -la dist/
}

# Check packages with twine
check_package() {
    log_info "Checking packages with twine..."

    cd "${PROJECT_ROOT}"

    if python3 -m twine check dist/*; then
        log_success "Package check passed"
    else
        log_error "Package check failed - fix issues before uploading"
        exit 1
    fi
}

# Upload to PyPI or TestPyPI
upload_package() {
    if [[ "${UPLOAD}" != "true" ]]; then
        log_info "Dry run complete - use --upload or --test to publish"
        return 0
    fi

    cd "${PROJECT_ROOT}"

    local upload_args=("-m" "twine" "upload")

    if [[ "${VERBOSE}" == "true" ]]; then
        upload_args+=("--verbose")
    fi

    if [[ "${USE_TEST_PYPI}" == "true" ]]; then
        log_info "Uploading to TestPyPI..."
        upload_args+=("--repository" "testpypi")

        if [[ -n "${TEST_PYPI_TOKEN:-}" ]]; then
            upload_args+=("--username" "__token__" "--password" "${TEST_PYPI_TOKEN}")
        fi
    else
        log_info "Uploading to PyPI..."

        if [[ -n "${PYPI_TOKEN:-}" ]]; then
            upload_args+=("--username" "__token__" "--password" "${PYPI_TOKEN}")
        fi
    fi

    upload_args+=("dist/*")

    if python3 "${upload_args[@]}"; then
        log_success "Package uploaded successfully"
    else
        log_error "Package upload failed"
        exit 1
    fi
}

# Extract and display version from pyproject.toml
get_version() {
    local version
    version=$(python3 -c "
import tomllib
with open('${PROJECT_ROOT}/pyproject.toml', 'rb') as f:
    data = tomllib.load(f)
    print(data['project']['version'])
")
    echo "${version}"
}

# Print summary
print_summary() {
    local version
    version=$(get_version)

    echo ""
    log_info "Package Summary:"
    echo "  Name:    hamburglar"
    echo "  Version: ${version}"
    echo ""

    if [[ "${UPLOAD}" == "true" ]]; then
        if [[ "${USE_TEST_PYPI}" == "true" ]]; then
            log_success "Package uploaded to TestPyPI!"
            echo ""
            echo "  Install with:"
            echo "    pip install --index-url https://test.pypi.org/simple/ hamburglar==${version}"
            echo ""
            echo "  View at:"
            echo "    https://test.pypi.org/project/hamburglar/${version}/"
        else
            log_success "Package uploaded to PyPI!"
            echo ""
            echo "  Install with:"
            echo "    pip install hamburglar==${version}"
            echo ""
            echo "  View at:"
            echo "    https://pypi.org/project/hamburglar/${version}/"
        fi
    else
        log_info "Ready to upload. Run with --upload (PyPI) or --test (TestPyPI)"
    fi

    echo ""
}

# Main function
main() {
    parse_args "$@"

    echo ""
    log_info "Hamburglar Publish Script"
    echo "=========================="
    echo ""

    check_prerequisites
    run_tests
    clean_build
    build_package
    check_package
    upload_package
    print_summary

    log_success "Publish script completed successfully!"
}

main "$@"
