# Test Configuration Fixtures

This directory contains test configuration files in various formats for testing
the Hamburglar configuration loading system.

## File Categories

### Valid Configurations

- `valid_basic.{yml,toml,json}` - Basic valid configs with common settings
- `valid_full.{yml,toml,json}` - Complete configs with all settings specified
- `minimal.{yml,toml,json}` - Minimal configs with only one setting changed
- `empty.{yml,toml,json}` - Empty configs that should use all defaults

### Invalid Configurations

- `invalid_syntax.{yml,toml,json}` - Files with syntax errors in each format
- `invalid_values.{yml,toml,json}` - Valid syntax but invalid schema values

## Usage in Tests

```python
from pathlib import Path

FIXTURES_DIR = Path(__file__).parent / "fixtures" / "configs"

# Load a valid config
config_path = FIXTURES_DIR / "valid_basic.yml"

# Test error handling
invalid_path = FIXTURES_DIR / "invalid_syntax.yml"
```

## Expected Behaviors

### valid_basic configs
- `scan.concurrency`: 25
- `scan.max_file_size`: 5MB (5242880 bytes)
- `detector.min_confidence`: "medium"
- `output.format`: "json"

### valid_full configs
- All settings are non-default values
- Tests that all config options can be loaded correctly

### minimal configs
- Only `scan.concurrency: 10` is set
- All other values should use defaults

### empty configs
- All values should use defaults

### invalid_syntax configs
- Should raise ConfigError with syntax-related message

### invalid_values configs
- Should raise ConfigError with validation-related message
