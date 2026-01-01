# Hamburglar Dockerfile
# Multi-stage build for optimal image size and security

# =============================================================================
# Stage 1: Builder - Install dependencies and build wheel
# =============================================================================
FROM python:3.11-slim AS builder

# Install build dependencies for yara-python
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    libffi-dev \
    libyara-dev \
    pkg-config \
    git \
    && rm -rf /var/lib/apt/lists/*

# Create virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install build tools
RUN pip install --no-cache-dir --upgrade pip build wheel

# Copy project files
WORKDIR /build
COPY pyproject.toml ./
COPY README.md ./
COPY LICENSE ./
COPY src/ ./src/

# Build the wheel
RUN python -m build --wheel --outdir /build/dist

# Install the wheel and dependencies
RUN pip install --no-cache-dir /build/dist/*.whl

# =============================================================================
# Stage 2: Runtime - Minimal image for running hamburglar
# =============================================================================
FROM python:3.11-slim AS runtime

# Install runtime dependencies for YARA
RUN apt-get update && apt-get install -y --no-install-recommends \
    libyara-dev \
    git \
    && rm -rf /var/lib/apt/lists/* \
    && apt-get clean

# Create non-root user for security
RUN groupadd --gid 1000 hamburglar \
    && useradd --uid 1000 --gid 1000 --create-home --shell /bin/bash hamburglar

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set up data directory for scanning targets
RUN mkdir -p /data && chown hamburglar:hamburglar /data
VOLUME ["/data"]

# Set up output directory
RUN mkdir -p /output && chown hamburglar:hamburglar /output
VOLUME ["/output"]

# Switch to non-root user
USER hamburglar
WORKDIR /data

# Set default environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD hamburglar --version || exit 1

# Default entrypoint
ENTRYPOINT ["hamburglar"]

# Default command (show help)
CMD ["--help"]
