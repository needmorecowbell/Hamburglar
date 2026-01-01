# Hamburglar

> A blazing-fast secret scanner for files, directories, git repositories, and URLs.

[![PyPI version](https://badge.fury.io/py/hamburglar.svg)](https://badge.fury.io/py/hamburglar)
[![Docker Image](https://img.shields.io/docker/v/hamburglar/hamburglar?label=docker)](https://hub.docker.com/r/hamburglar/hamburglar)
[![Coverage](https://img.shields.io/badge/coverage-90%25-brightgreen)](https://github.com/needmorecowbell/Hamburglar)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

## Overview

Hamburglar is a powerful, extensible secret scanning tool designed to detect sensitive information such as API keys, passwords, private keys, and other credentials in your codebase. It helps security teams and developers identify potential security risks before they become vulnerabilities.

## Key Features

- **Multi-Source Scanning**: Scan local files, directories, git repositories (including commit history), and web URLs
- **Comprehensive Detection**: Regex patterns, YARA rules, and entropy-based detection
- **High Performance**: Async/concurrent architecture for fast scanning of large codebases
- **Multiple Output Formats**: JSON, CSV, HTML, Markdown, SARIF, and table output
- **Plugin System**: Extend functionality with custom detectors and output formats
- **Configurable**: YAML, TOML, or JSON configuration files
- **CI/CD Ready**: SARIF output for GitHub Advanced Security integration

## Quick Install

```bash
pip install hamburglar
```

Or with Docker:

```bash
docker pull hamburglar/hamburglar
```

## Quick Start

```bash
# Scan a directory
hamburglar scan /path/to/code

# Scan a git repository
hamburglar scan-git https://github.com/user/repo

# Scan with JSON output
hamburglar scan /path/to/code --format json
```

See the [Quickstart Guide](quickstart.md) for more examples.

## Documentation

- [Installation](installation.md) - Detailed installation instructions
- [Quickstart](quickstart.md) - Get started quickly
- [CLI Reference](cli-reference.md) - Complete command-line documentation
- [Configuration](configuration.md) - Configuration options and files
- [Detectors](detectors.md) - Detection patterns and YARA rules
- [Outputs](outputs.md) - Output format reference
- [Plugins](plugins.md) - Creating custom plugins
- [Contributing](contributing.md) - How to contribute

## License

Hamburglar is released under the [MIT License](https://opensource.org/licenses/MIT).
