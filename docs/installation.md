# Installation

This guide covers all the ways to install Hamburglar.

## System Requirements

- **Python**: 3.9 or higher
- **Operating Systems**: Linux, macOS, Windows
- **Memory**: Minimum 512MB RAM (more recommended for large scans)

## pip Installation (Recommended)

The easiest way to install Hamburglar is via pip:

```bash
pip install hamburglar
```

### Upgrading

```bash
pip install --upgrade hamburglar
```

## Docker Installation

Hamburglar is available as a Docker image:

```bash
docker pull hamburglar/hamburglar
```

Run a scan using Docker:

```bash
# Scan a local directory
docker run -v /path/to/scan:/data hamburglar/hamburglar scan /data

# Scan a git repository
docker run hamburglar/hamburglar scan-git https://github.com/user/repo
```

Using Docker Compose:

```yaml
version: '3.8'
services:
  hamburglar:
    image: hamburglar/hamburglar
    volumes:
      - ./code:/data:ro
    command: scan /data
```

## Building from Source

Clone the repository and install in development mode:

```bash
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -e .
```

## Development Setup

For development, install with development dependencies:

```bash
git clone https://github.com/needmorecowbell/Hamburglar.git
cd Hamburglar
pip install -e ".[dev]"
```

This includes:
- **pytest**: Testing framework
- **pytest-cov**: Coverage reporting
- **pytest-asyncio**: Async test support
- **ruff**: Linting and formatting
- **mypy**: Type checking
- **mkdocs**: Documentation site generator
- **mkdocs-material**: Material theme for MkDocs
- **mkdocs-minify-plugin**: HTML minification for production builds

Run tests to verify the installation:

```bash
pytest
```

## Optional Dependencies

Hamburglar includes all required dependencies by default. The core dependencies are:

| Package | Purpose |
|---------|---------|
| `typer` | CLI framework |
| `rich` | Terminal formatting and output |
| `pydantic` | Data validation and settings |
| `yara-python` | YARA rule support for binary file detection |
| `pyyaml` | YAML configuration file support |
| `tomli` | TOML configuration file support (Python < 3.11 only) |
| `charset-normalizer` | Text encoding detection |

For development, install with dev dependencies:

```bash
pip install hamburglar[dev]
```

### YARA Installation Notes

YARA requires native libraries. If you encounter issues:

**Ubuntu/Debian:**
```bash
sudo apt-get install libyara-dev
pip install yara-python
```

**macOS:**
```bash
brew install yara
pip install yara-python
```

**Windows:**
Pre-built wheels are available for most Python versions.

## Verifying Installation

After installation, verify Hamburglar is working:

```bash
hamburglar --version
hamburglar --help
```

You should see the version number and available commands.

## Next Steps

- Follow the [Quickstart Guide](quickstart.md) to run your first scan
- See [Configuration](configuration.md) for customization options
- Check [CLI Reference](cli-reference.md) for all available commands
