# Plugins

Hamburglar features a flexible plugin architecture that allows you to extend its capabilities with custom detectors and output formatters without modifying the core codebase.

## Plugin Architecture Overview

Hamburglar supports two types of plugins:

1. **Detector Plugins** - Custom pattern detectors for finding specific types of sensitive data
2. **Output Plugins** - Custom formatters for presenting scan results

### Plugin Discovery

Plugins can be loaded from multiple sources, in order of precedence:

| Source | Description | Use Case |
|--------|-------------|----------|
| **Entry Points** | Pip-installable packages with `hamburglar.plugins.*` entry points | Distributing plugins via PyPI |
| **Plugin Directories** | Python files in configured directories | Local/private plugins |
| **Decorators** | Classes decorated with `@detector_plugin` or `@output_plugin` | Quick prototyping |
| **Manual Registration** | Programmatically registered instances | Runtime plugin loading |

### Plugin Manager

The `PluginManager` class handles all plugin lifecycle operations:

```python
from hamburglar.plugins import PluginManager

# Create a manager with custom directories
manager = PluginManager(
    plugin_directories=["/path/to/plugins"],
    auto_discover=True  # Discover plugins on initialization
)

# Or add directories later
manager.add_plugin_directory("/another/path")
manager.discover()

# List all plugins
for plugin in manager.list_all_plugins():
    print(f"{plugin.name} v{plugin.version}: {plugin.description}")
```

## Creating a Detector Plugin

Detector plugins extend the `DetectorPlugin` base class to find custom patterns in files.

### Basic Structure

```python
from hamburglar.plugins.detector_plugin import DetectorPlugin
from hamburglar.core.models import Finding, Severity

class MySecretDetector(DetectorPlugin):
    """Detects my organization's custom secrets."""

    # Plugin metadata
    __version__ = "1.0.0"
    __author__ = "Your Name"

    @property
    def name(self) -> str:
        """Unique identifier for this detector."""
        return "my_secrets"

    @property
    def description(self) -> str:
        """Human-readable description."""
        return "Detects custom secret patterns"

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        """Main detection logic."""
        # Your detection logic here
        return []
```

### Required Properties and Methods

| Member | Type | Description |
|--------|------|-------------|
| `name` | property | Unique identifier for the detector |
| `detect(content, file_path)` | method | Returns list of `Finding` objects |

### Optional Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `description` | str | docstring | Human-readable description |
| `version` | str | `"1.0.0"` | Plugin version |
| `author` | str | `""` | Author name |
| `supported_extensions` | list[str] \| None | `None` | File extensions to scan (None = all) |

### Utility Methods

The `DetectorPlugin` base class provides several utility methods:

#### Pattern Matching

```python
# Match a single pattern
findings = self.match_pattern(
    content=content,
    file_path=file_path,
    pattern=r'API_KEY\s*=\s*["\'](\w+)["\']',
    severity=Severity.HIGH,
    flags=re.IGNORECASE
)

# Match multiple patterns
findings = self.match_patterns(
    content=content,
    file_path=file_path,
    patterns=[
        r'API_KEY\s*=\s*["\'](\w+)["\']',
        r'SECRET\s*=\s*["\'](\w+)["\']',
    ],
    severity=Severity.HIGH
)

# Match literal strings
findings = self.match_literal(
    content=content,
    file_path=file_path,
    literal="password123",
    severity=Severity.CRITICAL,
    case_sensitive=False
)
```

#### Creating Findings

```python
finding = self.create_finding(
    file_path=file_path,
    matches=["API_KEY=secret123"],
    severity=Severity.HIGH,
    metadata={
        "line": 42,
        "context": "Found in configuration section"
    }
)
```

#### Configuration Access

```python
def __init__(self, **config):
    super().__init__(**config)
    # Access configuration with defaults
    self.min_length = self.get_config("min_length", 16)
    self.check_entropy = self.get_config("check_entropy", True)
```

#### File Filtering

```python
@property
def supported_extensions(self) -> list[str]:
    return [".py", ".js", ".env", ".yml"]

def detect(self, content: str, file_path: str = "") -> list[Finding]:
    # This check happens automatically when you use supported_extensions
    if not self.should_scan_file(file_path):
        return []
    # ... detection logic
```

### Complete Detector Example

Here's a comprehensive example of a custom API key detector:

```python
"""Custom API Key Detector Plugin for Hamburglar."""

from __future__ import annotations

import math
import re
from typing import Any

from hamburglar.core.models import Finding, Severity
from hamburglar.plugins.detector_plugin import DetectorPlugin


class CustomAPIKeyDetector(DetectorPlugin):
    """Detects custom organization-specific API keys and tokens.

    Configuration Options:
        min_key_length: Minimum length for detected keys (default: 16)
        check_entropy: Whether to validate key entropy (default: True)
        min_entropy: Minimum entropy threshold (default: 3.0)
        key_prefixes: List of prefixes to search for
    """

    __version__ = "1.0.0"
    __author__ = "Your Organization"

    DEFAULT_PATTERNS = [
        r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
        r'["\']?Bearer\s+([A-Za-z0-9_\-\.]{20,})["\']?',
        r'(?:secret|token)\s*[=:]\s*["\']([A-Za-z0-9_\-]{12,})["\']',
    ]

    def __init__(self, **config: Any) -> None:
        super().__init__(**config)
        self._min_key_length = self.get_config("min_key_length", 16)
        self._check_entropy = self.get_config("check_entropy", True)
        self._min_entropy = self.get_config("min_entropy", 3.0)
        self._key_prefixes = self.get_config(
            "key_prefixes",
            ["ACME_", "MYORG_", "PROD_", "STAGING_"]
        )

    @property
    def name(self) -> str:
        return "custom_api_keys"

    @property
    def description(self) -> str:
        return "Detects custom organization API keys and tokens"

    @property
    def supported_extensions(self) -> list[str] | None:
        return [".py", ".js", ".ts", ".json", ".yaml", ".yml", ".env"]

    def detect(self, content: str, file_path: str = "") -> list[Finding]:
        if not self.should_scan_file(file_path):
            return []

        findings: list[Finding] = []

        # Detect keys with configured prefixes
        for prefix in self._key_prefixes:
            pattern = rf"({re.escape(prefix)}[A-Za-z0-9_\-]{{8,}})"
            for match in re.finditer(pattern, content, re.IGNORECASE):
                key = match.group(1)

                if len(key) < self._min_key_length:
                    continue

                if self._check_entropy:
                    entropy = self._calculate_entropy(key)
                    if entropy < self._min_entropy:
                        continue

                findings.append(self.create_finding(
                    file_path=file_path,
                    matches=[key],
                    severity=self._assess_severity(prefix),
                    metadata={
                        "prefix": prefix,
                        "key_length": len(key),
                        "detection_method": "prefix_match"
                    }
                ))

        # Detect keys matching common patterns
        for pattern in self.DEFAULT_PATTERNS:
            pattern_findings = self.match_pattern(
                content=content,
                file_path=file_path,
                pattern=pattern,
                severity=Severity.HIGH,
                flags=re.IGNORECASE
            )

            for finding in pattern_findings:
                if finding.matches:
                    key = finding.matches[0]
                    if len(key) >= self._min_key_length:
                        if not self._check_entropy or self._has_sufficient_entropy(key):
                            findings.append(finding)

        return findings

    def _calculate_entropy(self, text: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not text:
            return 0.0
        freq: dict[str, int] = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        length = len(text)
        return -sum(
            (count / length) * math.log2(count / length)
            for count in freq.values()
        )

    def _has_sufficient_entropy(self, text: str) -> bool:
        return self._calculate_entropy(text) >= self._min_entropy

    def _assess_severity(self, prefix: str) -> Severity:
        if any(p in prefix.upper() for p in ["PROD", "LIVE", "MASTER"]):
            return Severity.CRITICAL
        if any(p in prefix.upper() for p in ["STAGING", "DEV", "TEST"]):
            return Severity.MEDIUM
        return Severity.HIGH
```

## Creating an Output Plugin

Output plugins extend the `OutputPlugin` base class to format scan results.

### Basic Structure

```python
from hamburglar.plugins.output_plugin import OutputPlugin
from hamburglar.core.models import ScanResult

class MyCustomOutput(OutputPlugin):
    """Formats results in a custom format."""

    __version__ = "1.0.0"
    __author__ = "Your Name"

    @property
    def name(self) -> str:
        """Unique identifier for this formatter."""
        return "my_format"

    @property
    def description(self) -> str:
        """Human-readable description."""
        return "Custom output format"

    @property
    def file_extension(self) -> str:
        """Default file extension for output."""
        return ".txt"

    def format(self, result: ScanResult) -> str:
        """Main formatting logic."""
        # Your formatting logic here
        return ""
```

### Required Properties and Methods

| Member | Type | Description |
|--------|------|-------------|
| `name` | property | Unique identifier for the formatter |
| `format(result)` | method | Returns formatted string |

### Optional Properties

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `description` | str | docstring | Human-readable description |
| `version` | str | `"1.0.0"` | Plugin version |
| `author` | str | `""` | Author name |
| `file_extension` | str | `".txt"` | Default output file extension |

### Utility Methods

#### Formatting Helpers

```python
# Format a single finding as a dictionary
finding_dict = self.format_finding(finding, include_metadata=True)

# Format entire result as a dictionary
result_dict = self.format_result(
    result,
    include_metadata=True,
    include_summary=True
)

# Get summary statistics
summary = self.get_summary(result)
# Returns: {
#     "total_findings": 42,
#     "files_scanned": 100,
#     "target_path": "/path/to/scan",
#     "scan_duration": 1.5,
#     "by_severity": {"high": 10, "medium": 20, "low": 12},
#     "by_detector": {"api_keys": 15, "passwords": 27}
# }
```

#### Built-in Formats

```python
# Format as JSON
json_output = self.format_as_json(result, include_metadata=True, indent=2)

# Format as simple text lines
text_output = self.format_as_lines(result, separator="\n", include_severity=True)
```

#### Grouping Methods

```python
# Group findings by file path
by_file = self.group_by_file(result)
# Returns: {"/path/file.py": [finding1, finding2], ...}

# Group findings by severity
by_severity = self.group_by_severity(result)
# Returns: {Severity.HIGH: [finding1], Severity.MEDIUM: [finding2], ...}

# Group findings by detector
by_detector = self.group_by_detector(result)
# Returns: {"api_keys": [finding1, finding2], ...}
```

### Complete Output Example

Here's a comprehensive example of a custom XML output formatter:

```python
"""Custom XML Output Plugin for Hamburglar."""

from __future__ import annotations

from typing import Any
from xml.etree import ElementTree as ET

from hamburglar.core.models import ScanResult
from hamburglar.plugins.output_plugin import OutputPlugin


class XMLOutput(OutputPlugin):
    """Formats scan results as XML.

    Configuration Options:
        pretty_print: Whether to format with indentation (default: True)
        include_metadata: Whether to include finding metadata (default: False)
    """

    __version__ = "1.0.0"
    __author__ = "Your Organization"

    def __init__(self, **config: Any) -> None:
        super().__init__(**config)
        self._pretty_print = self.get_config("pretty_print", True)
        self._include_metadata = self.get_config("include_metadata", False)

    @property
    def name(self) -> str:
        return "xml"

    @property
    def description(self) -> str:
        return "XML output format"

    @property
    def file_extension(self) -> str:
        return ".xml"

    def format(self, result: ScanResult) -> str:
        root = ET.Element("scan_result")

        # Add summary
        summary = self.get_summary(result)
        summary_elem = ET.SubElement(root, "summary")
        for key, value in summary.items():
            if isinstance(value, dict):
                sub_elem = ET.SubElement(summary_elem, key)
                for k, v in value.items():
                    item = ET.SubElement(sub_elem, "item")
                    item.set("name", k)
                    item.text = str(v)
            else:
                elem = ET.SubElement(summary_elem, key)
                elem.text = str(value)

        # Add findings
        findings_elem = ET.SubElement(root, "findings")
        for finding in result.findings:
            finding_elem = ET.SubElement(findings_elem, "finding")
            finding_elem.set("severity", finding.severity.value)
            finding_elem.set("detector", finding.detector_name)

            path_elem = ET.SubElement(finding_elem, "file_path")
            path_elem.text = finding.file_path

            matches_elem = ET.SubElement(finding_elem, "matches")
            for match in finding.matches:
                match_elem = ET.SubElement(matches_elem, "match")
                match_elem.text = match

            if self._include_metadata and finding.metadata:
                meta_elem = ET.SubElement(finding_elem, "metadata")
                for key, value in finding.metadata.items():
                    item = ET.SubElement(meta_elem, key)
                    item.text = str(value)

        if self._pretty_print:
            ET.indent(root)

        return ET.tostring(root, encoding="unicode", xml_declaration=True)
```

## Plugin Configuration

### Configuration File

Configure plugins in your `.hamburglar.yml` or `hamburglar.yml`:

```yaml
plugins:
  # Directories to search for plugins
  directories:
    - /path/to/plugins
    - ~/.hamburglar/plugins

  # Plugin-specific configuration
  config:
    custom_api_keys:
      min_key_length: 20
      check_entropy: true
      min_entropy: 3.5
      key_prefixes:
        - "MYORG_"
        - "INTERNAL_"

    xml:
      pretty_print: true
      include_metadata: true
```

### Environment Variables

```bash
# Add plugin directories (colon-separated)
export HAMBURGLAR_PLUGIN_DIRS="/path/to/plugins:/another/path"
```

### Configuration Precedence

Configuration values are merged in this order (later values override earlier):

1. Plugin class defaults
2. Configuration file (`plugins.config.<plugin_name>`)
3. Runtime configuration (passed to `get_detector()` or `get_output()`)

## Installing Plugins

### Method 1: File-Based Plugins (Simplest)

1. Create your plugin file (e.g., `my_detector.py`)
2. Place it in a plugin directory
3. Configure the directory:

```yaml
plugins:
  directories:
    - /path/to/your/plugins
```

### Method 2: Entry Points (For Distribution)

For pip-installable plugins, add entry points to your `pyproject.toml`:

```toml
[project]
name = "my-hamburglar-plugins"
version = "1.0.0"

[project.entry-points."hamburglar.plugins.detectors"]
my_detector = "my_package.detectors:MyDetectorClass"
custom_api_keys = "my_package.detectors:CustomAPIKeyDetector"

[project.entry-points."hamburglar.plugins.outputs"]
xml = "my_package.outputs:XMLOutput"
custom_html = "my_package.outputs:CustomHTMLOutput"
```

Then install your package:

```bash
pip install my-hamburglar-plugins
```

### Method 3: Decorator Registration

For quick prototyping, use decorators:

```python
from hamburglar.plugins import detector_plugin, output_plugin
from hamburglar.plugins.detector_plugin import DetectorPlugin
from hamburglar.plugins.output_plugin import OutputPlugin

@detector_plugin(
    "my_detector",
    description="Detects custom patterns",
    version="1.0.0",
    author="Your Name"
)
class MyDetector(DetectorPlugin):
    @property
    def name(self) -> str:
        return "my_detector"

    def detect(self, content, file_path=""):
        return []

@output_plugin(
    "my_output",
    description="Custom output format",
    version="1.0.0"
)
class MyOutput(OutputPlugin):
    @property
    def name(self) -> str:
        return "my_output"

    def format(self, result):
        return ""
```

### Method 4: Manual Registration

For runtime plugin loading:

```python
from hamburglar.plugins import PluginManager

manager = PluginManager()

# Register an instance
detector = MyDetector(min_length=20)
manager.register_detector(
    detector,
    description="My custom detector",
    version="1.0.0"
)

# Use the plugin
det = manager.get_detector("my_detector", config={"min_length": 16})
```

## Verifying Plugin Installation

### Using the CLI

```bash
# List all plugins
hamburglar plugins list

# Get detailed info about a specific plugin
hamburglar plugins info custom_api_keys
```

Example output:

```
Detector Plugins:
  custom_api_keys  v1.0.0  Detects custom organization API keys

Output Plugins:
  xml              v1.0.0  XML output format
```

### Programmatically

```python
from hamburglar.plugins import get_plugin_manager

manager = get_plugin_manager()

# List all plugins
for plugin in manager.list_all_plugins():
    print(f"{plugin.plugin_type}: {plugin.name} v{plugin.version}")
    print(f"  Description: {plugin.description}")
    print(f"  Author: {plugin.author}")
    print(f"  Source: {plugin.source}")

# Check if a plugin exists
if "custom_api_keys" in manager:
    info = manager.get_plugin_info("custom_api_keys")
    print(f"Found: {info.name}")
```

## Publishing Plugins

### Package Structure

```
my-hamburglar-plugins/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── my_plugins/
│       ├── __init__.py
│       ├── detectors/
│       │   ├── __init__.py
│       │   └── custom_detector.py
│       └── outputs/
│           ├── __init__.py
│           └── xml_output.py
└── tests/
    ├── test_detectors.py
    └── test_outputs.py
```

### pyproject.toml Example

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "my-hamburglar-plugins"
version = "1.0.0"
description = "Custom plugins for Hamburglar"
readme = "README.md"
license = "MIT"
authors = [
    { name = "Your Name", email = "your@email.com" }
]
dependencies = [
    "hamburglar>=2.0.0",
]

[project.entry-points."hamburglar.plugins.detectors"]
custom_api_keys = "my_plugins.detectors:CustomAPIKeyDetector"

[project.entry-points."hamburglar.plugins.outputs"]
xml = "my_plugins.outputs:XMLOutput"
```

### Testing Your Plugin

```python
import pytest
from hamburglar.core.models import Severity

from my_plugins.detectors import CustomAPIKeyDetector


class TestCustomAPIKeyDetector:
    def test_detects_prefixed_keys(self):
        detector = CustomAPIKeyDetector(
            key_prefixes=["TEST_"],
            check_entropy=False
        )

        content = 'API_KEY = "TEST_abc123xyz789secret"'
        findings = detector.detect(content, "config.py")

        assert len(findings) == 1
        assert "TEST_" in findings[0].matches[0]

    def test_filters_low_entropy(self):
        detector = CustomAPIKeyDetector(
            check_entropy=True,
            min_entropy=3.0
        )

        # Low entropy - repeated characters
        content = 'KEY = "TEST_AAAAAAAAAAAAAAAA"'
        findings = detector.detect(content, "test.py")

        assert len(findings) == 0

    def test_respects_file_extensions(self):
        detector = CustomAPIKeyDetector()

        # Should scan .py files
        findings = detector.detect('TEST_key123456789', "config.py")
        assert len(findings) >= 0  # May or may not find, but should try

        # Should skip .exe files
        assert not detector.should_scan_file("program.exe")
```

### Publishing to PyPI

```bash
# Build the package
python -m build

# Upload to PyPI
python -m twine upload dist/*
```

## Best Practices

### Detector Plugins

1. **Use entropy checks** to filter false positives
2. **Limit file extensions** when your patterns are file-type specific
3. **Provide meaningful metadata** in findings for debugging
4. **Cache compiled patterns** using `compile_pattern()`
5. **Assess severity appropriately** based on context

### Output Plugins

1. **Use utility methods** like `format_result()` and `group_by_*()`
2. **Include summaries** for quick result overview
3. **Specify the correct file extension** for your format
4. **Handle empty results** gracefully

### General

1. **Set metadata** (`__version__`, `__author__`) for plugin identification
2. **Write docstrings** - they become the plugin description
3. **Accept configuration** via constructor kwargs
4. **Write tests** for your plugins
5. **Document configuration options** in the class docstring

## See Also

- [Detectors](detectors.md) - Built-in detection patterns
- [Outputs](outputs.md) - Built-in output formats
- [Configuration](configuration.md) - Configuration options
