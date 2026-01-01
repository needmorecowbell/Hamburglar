# Plugins

Hamburglar's plugin system allows you to extend functionality with custom detectors and output formats.

## Plugin Architecture

Hamburglar supports two types of plugins:

1. **Detector Plugins**: Add custom pattern matching logic
2. **Output Plugins**: Add custom output formats

Plugins are Python modules that implement specific interfaces and are discovered automatically from configured directories.

## Plugin Discovery

Hamburglar searches for plugins in:

1. Built-in plugins (included with Hamburglar)
2. User plugins directory: `~/.hamburglar/plugins/`
3. Project plugins: `./plugins/` in current directory
4. Custom directories specified in configuration

Configure plugin directories:

```yaml
# hamburglar.yml
plugins:
  enabled: true
  directories:
    - ~/.hamburglar/plugins
    - ./plugins
    - /path/to/shared/plugins
```

## Creating a Detector Plugin

### Basic Structure

Create a Python file in your plugins directory:

```python
# ~/.hamburglar/plugins/my_detector.py

from hamburglar.plugins.detector_plugin import DetectorPlugin
from hamburglar.core.models import Finding, Severity

class MyCustomDetector(DetectorPlugin):
    """Detector for my company's internal secrets."""

    name = "my_custom_detector"
    description = "Detects MyCompany internal secrets"
    version = "1.0.0"

    def __init__(self):
        super().__init__()
        self.patterns = [
            {
                "name": "mycompany_api_key",
                "pattern": r"MYCO-[A-Z0-9]{32}",
                "severity": Severity.HIGH,
                "description": "MyCompany API Key",
            },
            {
                "name": "mycompany_internal_url",
                "pattern": r"https://internal\.mycompany\.com/[^\s]+",
                "severity": Severity.MEDIUM,
                "description": "Internal URL",
            },
        ]

    def detect(self, content: str, file_path: str = None) -> list[Finding]:
        """Run detection on content."""
        findings = []

        for pattern_def in self.patterns:
            import re
            for match in re.finditer(pattern_def["pattern"], content):
                finding = Finding(
                    pattern_name=pattern_def["name"],
                    pattern_category="custom",
                    severity=pattern_def["severity"],
                    confidence=0.9,
                    file_path=file_path,
                    line_number=content[:match.start()].count('\n') + 1,
                    column_start=match.start(),
                    column_end=match.end(),
                    matched_content=match.group(),
                    description=pattern_def["description"],
                )
                findings.append(finding)

        return findings

# Register the plugin
def register():
    return MyCustomDetector()
```

### Detector Plugin Interface

```python
class DetectorPlugin:
    """Base class for detector plugins."""

    # Required attributes
    name: str           # Unique plugin identifier
    description: str    # Human-readable description
    version: str        # Semantic version

    def detect(self, content: str, file_path: str = None) -> list[Finding]:
        """
        Run detection on content.

        Args:
            content: File content to analyze
            file_path: Path to the file (optional)

        Returns:
            List of Finding objects
        """
        raise NotImplementedError

    def configure(self, config: dict) -> None:
        """
        Configure the plugin with custom settings.

        Args:
            config: Plugin configuration dictionary
        """
        pass

    def supports_file(self, file_path: str) -> bool:
        """
        Check if this detector should run on a file.

        Args:
            file_path: Path to the file

        Returns:
            True if detector should process this file
        """
        return True
```

### Advanced Detector Example

```python
# ~/.hamburglar/plugins/entropy_secrets.py

import math
from collections import Counter

from hamburglar.plugins.detector_plugin import DetectorPlugin
from hamburglar.core.models import Finding, Severity


class EntropySecretsDetector(DetectorPlugin):
    """Detect high-entropy strings that may be secrets."""

    name = "entropy_secrets"
    description = "Detects high-entropy strings"
    version = "1.0.0"

    def __init__(self):
        super().__init__()
        self.min_length = 20
        self.min_entropy = 4.5
        self.excluded_extensions = {'.md', '.txt', '.rst'}

    def configure(self, config: dict) -> None:
        self.min_length = config.get('min_length', 20)
        self.min_entropy = config.get('min_entropy', 4.5)

    def supports_file(self, file_path: str) -> bool:
        if not file_path:
            return True
        return not any(file_path.endswith(ext)
                      for ext in self.excluded_extensions)

    def calculate_entropy(self, data: str) -> float:
        """Calculate Shannon entropy of a string."""
        if not data:
            return 0.0

        counter = Counter(data)
        length = len(data)
        entropy = 0.0

        for count in counter.values():
            probability = count / length
            entropy -= probability * math.log2(probability)

        return entropy

    def detect(self, content: str, file_path: str = None) -> list[Finding]:
        findings = []

        # Find potential secrets (alphanumeric sequences)
        import re
        pattern = r'[A-Za-z0-9+/=]{' + str(self.min_length) + r',}'

        for match in re.finditer(pattern, content):
            candidate = match.group()
            entropy = self.calculate_entropy(candidate)

            if entropy >= self.min_entropy:
                line_num = content[:match.start()].count('\n') + 1

                finding = Finding(
                    pattern_name="high_entropy_string",
                    pattern_category="entropy",
                    severity=Severity.MEDIUM,
                    confidence=min(0.5 + (entropy - 4.0) / 4, 0.95),
                    file_path=file_path,
                    line_number=line_num,
                    column_start=match.start(),
                    column_end=match.end(),
                    matched_content=candidate[:50] + "..." if len(candidate) > 50 else candidate,
                    description=f"High entropy string (entropy: {entropy:.2f})",
                    metadata={"entropy": entropy},
                )
                findings.append(finding)

        return findings


def register():
    return EntropySecretsDetector()
```

## Creating an Output Plugin

### Basic Structure

```python
# ~/.hamburglar/plugins/my_output.py

from hamburglar.plugins.output_plugin import OutputPlugin
from hamburglar.core.models import ScanResult


class XMLOutput(OutputPlugin):
    """Output scan results as XML."""

    name = "xml"
    description = "XML output format"
    version = "1.0.0"
    file_extension = ".xml"

    def format(self, result: ScanResult) -> str:
        """Format scan results as XML string."""
        lines = ['<?xml version="1.0" encoding="UTF-8"?>']
        lines.append('<scan_result>')
        lines.append(f'  <scan_id>{result.scan_id}</scan_id>')
        lines.append(f'  <files_scanned>{result.files_scanned}</files_scanned>')
        lines.append('  <findings>')

        for finding in result.findings:
            lines.append('    <finding>')
            lines.append(f'      <pattern>{finding.pattern_name}</pattern>')
            lines.append(f'      <severity>{finding.severity.value}</severity>')
            lines.append(f'      <file>{finding.file_path}</file>')
            lines.append(f'      <line>{finding.line_number}</line>')
            lines.append('    </finding>')

        lines.append('  </findings>')
        lines.append('</scan_result>')

        return '\n'.join(lines)

    def write(self, result: ScanResult, output_path: str) -> None:
        """Write results to file."""
        content = self.format(result)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)


def register():
    return XMLOutput()
```

### Output Plugin Interface

```python
class OutputPlugin:
    """Base class for output plugins."""

    # Required attributes
    name: str            # Format name (used in --output-format)
    description: str     # Human-readable description
    version: str         # Semantic version
    file_extension: str  # Default file extension

    def format(self, result: ScanResult) -> str:
        """
        Format scan results as string.

        Args:
            result: ScanResult object

        Returns:
            Formatted string output
        """
        raise NotImplementedError

    def write(self, result: ScanResult, output_path: str) -> None:
        """
        Write results to file.

        Args:
            result: ScanResult object
            output_path: Path to output file
        """
        content = self.format(result)
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(content)

    def configure(self, config: dict) -> None:
        """Configure the plugin."""
        pass
```

### Streaming Output Example

```python
# ~/.hamburglar/plugins/streaming_json.py

import json

from hamburglar.plugins.output_plugin import OutputPlugin
from hamburglar.core.models import ScanResult, Finding


class StreamingJSONOutput(OutputPlugin):
    """Stream findings as JSON lines for large scans."""

    name = "jsonl"
    description = "JSON Lines streaming format"
    version = "1.0.0"
    file_extension = ".jsonl"

    def format_finding(self, finding: Finding) -> str:
        """Format a single finding as JSON."""
        return json.dumps({
            "pattern": finding.pattern_name,
            "severity": finding.severity.value,
            "file": finding.file_path,
            "line": finding.line_number,
            "content": finding.matched_content,
        })

    def format(self, result: ScanResult) -> str:
        """Format all findings as JSON lines."""
        lines = [self.format_finding(f) for f in result.findings]
        return '\n'.join(lines)

    def stream(self, finding: Finding, output_file) -> None:
        """Stream a single finding to output."""
        line = self.format_finding(finding)
        output_file.write(line + '\n')
        output_file.flush()


def register():
    return StreamingJSONOutput()
```

## Plugin Configuration

Configure plugins in your configuration file:

```yaml
# hamburglar.yml
plugins:
  enabled: true
  directories:
    - ~/.hamburglar/plugins

  # Plugin-specific configuration
  config:
    my_custom_detector:
      enabled: true
      custom_option: value

    entropy_secrets:
      min_length: 25
      min_entropy: 5.0

    xml:
      pretty_print: true
      include_context: false
```

## Publishing Plugins

### Package Structure

```
my-hamburglar-plugin/
├── pyproject.toml
├── README.md
├── LICENSE
├── src/
│   └── my_plugin/
│       ├── __init__.py
│       └── detector.py
└── tests/
    └── test_detector.py
```

### pyproject.toml

```toml
[build-system]
requires = ["hatchling"]
build-backend = "hatchling.build"

[project]
name = "hamburglar-my-plugin"
version = "1.0.0"
description = "Custom detector for Hamburglar"
requires-python = ">=3.9"
dependencies = ["hamburglar>=2.0.0"]

[project.entry-points."hamburglar.plugins"]
my_detector = "my_plugin.detector:register"
```

### Publishing to PyPI

```bash
# Build
python -m build

# Upload to PyPI
python -m twine upload dist/*
```

Users can then install with:

```bash
pip install hamburglar-my-plugin
```

## Best Practices

1. **Keep plugins focused**: One detector/output per plugin
2. **Handle errors gracefully**: Don't crash the scan
3. **Test thoroughly**: Include unit tests
4. **Document patterns**: Explain what each pattern detects
5. **Version your plugins**: Use semantic versioning
6. **Minimize dependencies**: Keep external requirements minimal

## See Also

- [Detectors](detectors.md) - Built-in detection patterns
- [Outputs](outputs.md) - Built-in output formats
- [Configuration](configuration.md) - Configuration options
