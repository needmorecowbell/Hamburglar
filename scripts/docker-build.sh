#!/usr/bin/env bash
#
# docker-build.sh - Build and optionally push Hamburglar Docker image
#
# Usage:
#   ./scripts/docker-build.sh              # Build with default tag
#   ./scripts/docker-build.sh --tag 2.0.0  # Build with specific version tag
#   ./scripts/docker-build.sh --push       # Build and push to registry
#   ./scripts/docker-build.sh --test-only  # Only run smoke tests on existing image
#   ./scripts/docker-build.sh --no-cache   # Build without Docker cache
#
# Environment variables:
#   DOCKER_REGISTRY  - Registry to push to (default: docker.io)
#   DOCKER_IMAGE     - Image name (default: needmorecowbell/hamburglar)
#   DOCKER_TAG       - Tag to use (default: latest)
#

set -euo pipefail

# Configuration with defaults
DOCKER_REGISTRY="${DOCKER_REGISTRY:-docker.io}"
DOCKER_IMAGE="${DOCKER_IMAGE:-needmorecowbell/hamburglar}"
DOCKER_TAG="${DOCKER_TAG:-latest}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Flags
PUSH=false
TEST_ONLY=false
NO_CACHE=""
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

Build Hamburglar Docker image with smoke tests.

Options:
    -t, --tag TAG       Version tag for the image (default: latest)
    -p, --push          Push image to registry after build
    -n, --no-cache      Build without Docker cache
    --test-only         Only run smoke tests on existing image
    -v, --verbose       Enable verbose output
    -h, --help          Show this help message

Environment Variables:
    DOCKER_REGISTRY     Registry to push to (default: docker.io)
    DOCKER_IMAGE        Image name (default: needmorecowbell/hamburglar)
    DOCKER_TAG          Default tag (default: latest)

Examples:
    $(basename "$0")                        # Build with latest tag
    $(basename "$0") --tag 2.0.0            # Build with version tag
    $(basename "$0") --tag 2.0.0 --push     # Build and push to registry
    $(basename "$0") --no-cache             # Fresh build without cache
    $(basename "$0") --test-only            # Only test existing image
EOF
}

# Parse command line arguments
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -t|--tag)
                DOCKER_TAG="$2"
                shift 2
                ;;
            -p|--push)
                PUSH=true
                shift
                ;;
            -n|--no-cache)
                NO_CACHE="--no-cache"
                shift
                ;;
            --test-only)
                TEST_ONLY=true
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

    if ! command -v docker &> /dev/null; then
        log_error "Docker is not installed or not in PATH"
        exit 1
    fi

    if ! docker info &> /dev/null; then
        log_error "Docker daemon is not running or you don't have permission to access it"
        exit 1
    fi

    if [[ ! -f "${PROJECT_ROOT}/Dockerfile" ]]; then
        log_error "Dockerfile not found in ${PROJECT_ROOT}"
        exit 1
    fi

    log_success "Prerequisites check passed"
}

# Build the Docker image
build_image() {
    local full_image="${DOCKER_IMAGE}:${DOCKER_TAG}"

    log_info "Building Docker image: ${full_image}"

    cd "${PROJECT_ROOT}"

    local build_args=(
        "build"
        "-t" "${full_image}"
        "-f" "Dockerfile"
    )

    # Add latest tag if building a version tag
    if [[ "${DOCKER_TAG}" != "latest" ]]; then
        build_args+=("-t" "${DOCKER_IMAGE}:latest")
    fi

    # Add no-cache flag if requested
    if [[ -n "${NO_CACHE}" ]]; then
        build_args+=("${NO_CACHE}")
    fi

    # Add build context
    build_args+=(".")

    if [[ "${VERBOSE}" == "true" ]]; then
        log_info "Running: docker ${build_args[*]}"
    fi

    if docker "${build_args[@]}"; then
        log_success "Docker image built successfully: ${full_image}"
    else
        log_error "Docker build failed"
        exit 1
    fi
}

# Run smoke tests on the built image
run_smoke_tests() {
    local full_image="${DOCKER_IMAGE}:${DOCKER_TAG}"

    log_info "Running smoke tests on ${full_image}..."

    # Test 1: Check version command
    log_info "Test 1: Checking --version command..."
    if docker run --rm "${full_image}" --version > /dev/null 2>&1; then
        log_success "Version command works"
    else
        log_error "Version command failed"
        exit 1
    fi

    # Test 2: Check help command
    log_info "Test 2: Checking --help command..."
    if docker run --rm "${full_image}" --help > /dev/null 2>&1; then
        log_success "Help command works"
    else
        log_error "Help command failed"
        exit 1
    fi

    # Test 3: Check that non-root user is used
    log_info "Test 3: Checking container runs as non-root user..."
    local user_id
    user_id=$(docker run --rm --entrypoint id "${full_image}" -u)
    if [[ "${user_id}" != "0" ]]; then
        log_success "Container runs as non-root user (uid: ${user_id})"
    else
        log_warning "Container runs as root user - security concern"
    fi

    # Test 4: Check scan subcommand exists
    log_info "Test 4: Checking scan subcommand..."
    if docker run --rm "${full_image}" scan --help > /dev/null 2>&1; then
        log_success "Scan subcommand available"
    else
        log_error "Scan subcommand not available"
        exit 1
    fi

    # Test 5: Verify YARA rules are included
    log_info "Test 5: Checking YARA rules are included..."
    if docker run --rm --entrypoint find "${full_image}" /opt/venv -name "*.yar" | head -1 | grep -q ".yar"; then
        log_success "YARA rules are included in the image"
    else
        log_warning "YARA rules may not be included (non-critical)"
    fi

    # Test 6: Test volume mount points exist
    log_info "Test 6: Checking volume mount points..."
    if docker run --rm --entrypoint ls "${full_image}" -la /data /output > /dev/null 2>&1; then
        log_success "Volume mount points /data and /output exist"
    else
        log_error "Volume mount points not properly configured"
        exit 1
    fi

    log_success "All smoke tests passed!"
}

# Push image to registry
push_image() {
    local full_image="${DOCKER_IMAGE}:${DOCKER_TAG}"

    log_info "Pushing image to registry: ${full_image}"

    if docker push "${full_image}"; then
        log_success "Pushed ${full_image}"
    else
        log_error "Failed to push ${full_image}"
        exit 1
    fi

    # Also push latest if we built a version tag
    if [[ "${DOCKER_TAG}" != "latest" ]]; then
        log_info "Pushing latest tag..."
        if docker push "${DOCKER_IMAGE}:latest"; then
            log_success "Pushed ${DOCKER_IMAGE}:latest"
        else
            log_error "Failed to push latest tag"
            exit 1
        fi
    fi
}

# Print image details
print_image_info() {
    local full_image="${DOCKER_IMAGE}:${DOCKER_TAG}"

    log_info "Image details:"
    echo ""
    docker images "${DOCKER_IMAGE}" --format "table {{.Repository}}\t{{.Tag}}\t{{.Size}}\t{{.CreatedAt}}"
    echo ""

    log_info "To run the image:"
    echo "  docker run --rm -v /path/to/scan:/data ${full_image} scan /data"
    echo ""

    if [[ "${PUSH}" == "false" ]]; then
        log_info "To push to registry:"
        echo "  docker push ${full_image}"
        echo ""
    fi
}

# Main function
main() {
    parse_args "$@"

    echo ""
    log_info "Hamburglar Docker Build Script"
    echo "================================="
    echo ""

    check_prerequisites

    if [[ "${TEST_ONLY}" == "true" ]]; then
        run_smoke_tests
    else
        build_image
        run_smoke_tests

        if [[ "${PUSH}" == "true" ]]; then
            push_image
        fi

        print_image_info
    fi

    log_success "Build completed successfully!"
}

main "$@"
