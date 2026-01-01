# Detectors

Hamburglar uses multiple detection methods to identify secrets and sensitive information in your codebase. This page covers all detection methods, pattern categories, severity levels, confidence scoring, and how to add custom patterns.

## Detection Methods

Hamburglar provides three complementary detection approaches:

### Regex Pattern Detection

The primary detection method uses regular expressions to match known patterns for secrets, credentials, and sensitive data. This is the fastest and most reliable method for detecting secrets with well-defined formats.

The regex detector:
- Uses pre-compiled patterns for optimal performance
- Supports 196+ built-in patterns across 7 categories
- Provides configurable timeout protection (default 5 seconds)
- Filters binary content automatically
- Supports async/batch processing

### Entropy Detection

High-entropy strings often indicate encoded or encrypted secrets. The entropy detector uses Shannon entropy calculation to identify strings with unusually high randomness.

Features:
- Default entropy threshold: 4.5 bits per character
- High-confidence threshold: 5.0 bits per character
- Base64 and hex encoding detection
- False positive filtering (UUIDs, version strings, common words)
- Context-aware detection for increased accuracy

Entropy ranges:
| Entropy Value | Interpretation |
|---------------|----------------|
| ~3.5-4.0 | Normal text |
| ~4.5-5.0 | Random strings (likely secrets) |
| ~5.5-6.0 | Cryptographic keys |

### YARA Rules

YARA rules are used for binary file analysis and complex pattern matching. They're particularly useful for detecting file signatures, embedded files, and binary-specific patterns.

Features:
- 19 built-in rule files for common file types
- Rule caching for performance
- Configurable timeout (default 60 seconds)
- Support for custom rule directories
- Async streaming detection

## Pattern Categories

Hamburglar organizes detection patterns into seven categories:

### API Keys (`api_keys`) - 38 Patterns

Patterns for detecting API keys and tokens from various services:

| Pattern Name | Description | Severity | Confidence |
|-------------|-------------|----------|------------|
| `aws_access_key_id` | AWS Access Key ID (AKIA prefix) | critical | high |
| `aws_secret_key` | AWS Secret Access Key | critical | high |
| `github_token` | GitHub Personal Access Token (ghp_) | critical | high |
| `github_oauth_token` | GitHub OAuth Token (gho_) | critical | high |
| `github_user_to_server_token` | GitHub User-to-Server Token (ghu_) | critical | high |
| `github_server_to_server_token` | GitHub Server-to-Server Token (ghs_) | critical | high |
| `github_refresh_token` | GitHub Refresh Token (ghr_) | critical | high |
| `gitlab_token` | GitLab Personal Access Token (glpat-) | critical | high |
| `gitlab_runner_token` | GitLab Runner Registration Token | high | high |
| `slack_token` | Slack OAuth Token (xox[pboa]-) | critical | high |
| `slack_webhook` | Slack Webhook URL | high | high |
| `google_api_key` | Google API Key (AIza prefix) | high | high |
| `stripe_secret_key` | Stripe Live Secret Key (sk_live_) | critical | high |
| `stripe_restricted_key` | Stripe Restricted API Key (rk_live_) | high | high |
| `stripe_publishable_key` | Stripe Publishable Key (pk_live_) | medium | high |
| `twilio_account_sid` | Twilio Account SID (AC prefix) | high | high |
| `sendgrid_api_key` | SendGrid API Key (SG.) | critical | high |
| `mailgun_api_key` | Mailgun API Key (key-) | critical | high |
| `mailchimp_api_key` | Mailchimp API Key | high | high |
| `npm_token` | NPM Access Token (npm_) | critical | high |
| `pypi_token` | PyPI API Token | critical | high |
| `nuget_api_key` | NuGet API Key (oy2) | critical | high |
| `heroku_api_key` | Heroku API Key (UUID format) | high | low |
| `digitalocean_token` | DigitalOcean Personal Access Token (dop_v1_) | critical | high |
| `datadog_api_key` | Datadog API Key | high | high |
| `new_relic_api_key` | New Relic API Key (NRAK-) | high | high |

### Credentials (`credentials`) - 30 Patterns

Patterns for passwords, authentication tokens, and database credentials:

| Pattern Name | Description | Severity | Confidence |
|-------------|-------------|----------|------------|
| `password_assignment` | Password variable assignment | critical | medium |
| `secret_assignment` | Secret value assignment | high | medium |
| `postgres_connection_string` | PostgreSQL connection with credentials | critical | high |
| `mysql_connection_string` | MySQL connection with credentials | critical | high |
| `mongodb_connection_string` | MongoDB connection with credentials | critical | high |
| `redis_connection_string` | Redis connection string | high | medium |
| `mssql_connection_string` | SQL Server connection with credentials | critical | high |
| `jdbc_connection_string` | JDBC connection with password | critical | high |
| `http_basic_auth` | HTTP Basic Auth header | critical | high |
| `http_bearer_token` | HTTP Bearer token | high | medium |
| `jwt_token` | JSON Web Token | high | high |
| `jwt_token_assignment` | JWT assigned to variable | critical | high |
| `oauth_token` | OAuth access/refresh token | critical | medium |
| `oauth_client_secret` | OAuth client secret | critical | medium |
| `url_with_credentials` | URL containing username:password | critical | high |
| `env_secret_key` | .env file secret key | high | medium |
| `env_database_url` | .env database URL | critical | high |
| `env_password` | .env password field | critical | high |
| `docker_registry_auth` | Docker registry credentials | critical | high |
| `session_secret` | Session signing secret | high | medium |
| `ldap_credentials` | LDAP connection with credentials | critical | high |

### Private Keys (`private_keys`) - 16 Patterns

Patterns for cryptographic private keys and certificates:

| Pattern Name | Description | Severity | Confidence |
|-------------|-------------|----------|------------|
| `rsa_private_key` | RSA Private Key (PKCS#1 format) | critical | high |
| `openssh_private_key` | OpenSSH Private Key (modern format) | critical | high |
| `ec_private_key` | EC Private Key (SEC1 format) | critical | high |
| `dsa_private_key` | DSA Private Key | critical | high |
| `pgp_private_key` | PGP Private Key Block | critical | high |
| `pkcs8_private_key` | PKCS#8 Private Key (unencrypted) | critical | high |
| `pkcs8_encrypted_private_key` | PKCS#8 Encrypted Private Key | high | high |
| `ssh_private_key_generic` | Generic SSH private key header | critical | high |
| `ssh2_private_key` | SSH.com format private key | critical | high |
| `putty_private_key` | PuTTY PPK format private key | critical | high |
| `x509_certificate` | X.509 Certificate | medium | high |
| `ssl_private_key` | SSL/TLS private key | critical | high |
| `private_key_assignment` | Private key assigned to variable | critical | high |
| `private_key_path` | File path to private key | high | medium |

### Cloud Providers (`cloud`) - 24 Patterns

Patterns for cloud provider credentials:

| Pattern Name | Description | Severity | Confidence |
|-------------|-------------|----------|------------|
| `azure_storage_key` | Azure Storage Account Key | critical | high |
| `azure_connection_string` | Azure Connection String | critical | high |
| `azure_sas_token` | Azure Shared Access Signature | high | high |
| `gcp_service_account_key` | GCP Service Account Key (JSON) | critical | high |
| `gcp_api_key` | GCP API Key | high | high |
| `gcp_oauth_token` | GCP OAuth Token | critical | high |
| `aws_session_token` | AWS Session Token | critical | high |
| `aws_mws_key` | Amazon MWS Auth Token | critical | high |
| `alibaba_access_key` | Alibaba Cloud Access Key | high | high |
| `ibm_cloud_api_key` | IBM Cloud API Key | high | high |

### Cryptocurrency (`crypto`) - 33 Patterns

Patterns for cryptocurrency addresses and private keys:

| Pattern Name | Description | Severity | Confidence |
|-------------|-------------|----------|------------|
| `bitcoin_address_p2pkh` | Bitcoin Legacy Address (1...) | medium | medium |
| `bitcoin_address_p2sh` | Bitcoin P2SH Address (3...) | medium | medium |
| `bitcoin_address_bech32` | Bitcoin Bech32 Address (bc1...) | medium | high |
| `bitcoin_private_key_wif` | Bitcoin WIF Private Key | critical | high |
| `ethereum_address` | Ethereum Address (0x...) | medium | high |
| `ethereum_private_key` | Ethereum Private Key | critical | high |
| `monero_address` | Monero Address | medium | high |
| `ripple_address` | Ripple/XRP Address | medium | medium |
| `litecoin_address` | Litecoin Address | medium | medium |
| `dogecoin_address` | Dogecoin Address | low | medium |
| `mnemonic_phrase_12` | BIP39 12-word Mnemonic | critical | medium |
| `mnemonic_phrase_24` | BIP39 24-word Mnemonic | critical | medium |

### Network (`network`) - 26 Patterns

Patterns for network-related sensitive data:

| Pattern Name | Description | Severity | Confidence |
|-------------|-------------|----------|------------|
| `ipv4_address` | IPv4 Address | low | high |
| `ipv6_address` | IPv6 Address | low | high |
| `private_ip_10` | Private IP (10.x.x.x) | medium | high |
| `private_ip_172` | Private IP (172.16-31.x.x) | medium | high |
| `private_ip_192` | Private IP (192.168.x.x) | medium | high |
| `mac_address` | MAC Address | low | high |
| `internal_url` | Internal URL pattern | medium | medium |
| `email_address` | Email Address | low | high |

### Generic (`generic`) - 29 Patterns

General-purpose patterns for detecting secrets:

| Pattern Name | Description | Severity | Confidence |
|-------------|-------------|----------|------------|
| `generic_api_key` | Generic API key pattern | high | low |
| `generic_secret` | Generic secret pattern | high | low |
| `generic_password` | Generic password pattern | high | low |
| `generic_token` | Generic token pattern | medium | low |
| `base64_high_entropy` | High-entropy Base64 string | medium | low |
| `hex_high_entropy` | High-entropy hex string | medium | low |

## Severity Levels

Hamburglar uses five severity levels to prioritize findings:

| Level | Description | Action Required | Examples |
|-------|-------------|-----------------|----------|
| `critical` | Immediate security risk | Rotate immediately | Private keys, AWS credentials, database passwords |
| `high` | Significant security risk | Investigate promptly | API keys, OAuth tokens, webhook URLs |
| `medium` | Moderate security risk | Review and assess | Generic secrets, internal URLs, encrypted keys |
| `low` | Informational findings | Monitor | IP addresses, email addresses, public keys |
| `info` | Context/reference only | Optional review | URLs, version strings |

## Confidence Levels

Confidence indicates how likely a match is a true positive:

| Level | Description | False Positive Rate |
|-------|-------------|---------------------|
| `high` | Very specific patterns with distinctive prefixes | <5% |
| `medium` | Good format match, some context needed | 5-30% |
| `low` | Generic patterns, manual review recommended | 30%+ |

**High confidence patterns** have distinctive formats:
- AWS keys with `AKIA` prefix
- GitHub tokens with `ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` prefixes
- Stripe keys with `sk_live_`, `pk_live_`, `rk_live_` prefixes
- SendGrid with `SG.` prefix

**Medium confidence patterns** match well-known formats but may have edge cases:
- JWT tokens (eyJ... format)
- Database connection strings
- OAuth tokens in variable assignments

**Low confidence patterns** are generic and require context:
- Generic API key assignments
- UUID-format keys (like Heroku)
- High-entropy strings without context

## Adding Custom Patterns

### Via Configuration File

Add custom patterns in your `hamburglar.yml` or `.hamburglar.yaml`:

```yaml
detector:
  custom_patterns_path: ./custom_patterns.yaml
```

Then create `custom_patterns.yaml`:

```yaml
patterns:
  - name: internal_api_key
    regex: 'INTERNAL_[A-Z0-9]{32}'
    severity: HIGH
    category: API_KEYS
    description: Internal organization API key
    confidence: high

  - name: custom_db_password
    regex: 'db_pass(?:word)?=["\']([^"\']+)["\']'
    severity: CRITICAL
    category: CREDENTIALS
    description: Custom database password pattern
    confidence: medium
```

### Via JSON File

```json
{
  "patterns": [
    {
      "name": "internal_api_key",
      "regex": "INTERNAL_[A-Z0-9]{32}",
      "severity": "HIGH",
      "category": "API_KEYS",
      "description": "Internal organization API key",
      "confidence": "high"
    }
  ]
}
```

### Custom Pattern Fields

| Field | Required | Type | Description |
|-------|----------|------|-------------|
| `name` | Yes | string | Unique pattern identifier |
| `regex` | Yes | string | Regular expression pattern |
| `severity` | Yes | string | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `category` | No | string | `API_KEYS`, `CREDENTIALS`, `PRIVATE_KEYS`, `CLOUD`, `CRYPTO`, `NETWORK`, or `GENERIC` |
| `description` | No | string | Human-readable description |
| `confidence` | No | string | `high`, `medium`, or `low` (default: `medium`) |

### Programmatic Pattern Addition

```python
from hamburglar.detectors.regex_detector import RegexDetector
from hamburglar.core.models import Severity

detector = RegexDetector(use_expanded_patterns=True)

# Add a custom pattern at runtime
detector.add_pattern(
    name="internal_key",
    pattern=r"INTERNAL_[0-9a-zA-Z]{32}",
    severity=Severity.HIGH,
    description="Internal organization key",
    category="api_keys",
    confidence="high"
)

# Remove a pattern
detector.remove_pattern("internal_key")
```

### Disabling Built-in Patterns

Disable specific patterns via configuration:

```yaml
detector:
  disabled_patterns:
    - email_address
    - ipv4_address
    - generic_api_key
```

Or exclude entire categories:

```yaml
detector:
  disabled_categories:
    - network
    - generic
```

## YARA Rules

### Built-in Rules

Hamburglar includes 19 YARA rule files for detecting file types:

| Rule File | Purpose |
|-----------|---------|
| `apple.yar` | Apple-specific file formats |
| `audio.yar` | Audio files (MP3, WAV, FLAC, etc.) |
| `compressed.yar` | Archives (ZIP, RAR, 7z, GZIP, etc.) |
| `crypto.yar` | Cryptocurrency-related files |
| `executables.yar` | Executable files (PE, ELF, Mach-O) |
| `gif.yar` | GIF image files |
| `gps.yar` | GPS/location data files |
| `jpeg.yar` | JPEG image files |
| `mem_dumps.yar` | Memory dump files |
| `office.yar` | Office documents (DOC, DOCX, XLS, etc.) |
| `pdf.yar` | PDF documents |
| `png.yar` | PNG image files |
| `skype.yar` | Skype data files |
| `sqlite.yar` | SQLite database files |
| `vcard.yar` | vCard contact files |
| `vector.yar` | Vector graphics (SVG, EPS, etc.) |
| `video.yar` | Video files (MP4, AVI, MKV, etc.) |
| `vmware.yar` | VMware virtual machine files |
| `win_reg.yar` | Windows Registry files |

### Custom YARA Rules

Add custom YARA rules in your configuration:

```yaml
yara:
  enabled: true
  rules_path: /path/to/custom/rules
  # Or a single file:
  # rules_path: /path/to/my_rules.yar
```

Example custom YARA rule:

```yara
rule MyCustomSecret
{
    meta:
        description = "Detects my custom secret format"
        author = "Security Team"
        severity = "high"

    strings:
        $secret = /MYSECRET-[A-Z0-9]{32}/

    condition:
        $secret
}

rule EncryptedConfig
{
    meta:
        description = "Detects encrypted configuration files"
        severity = "medium"

    strings:
        $header = { 45 4E 43 52 59 50 54 }  // "ENCRYPT"
        $magic = { 00 01 02 03 }

    condition:
        $header at 0 or $magic at 0
}
```

### YARA Severity Mapping

Map YARA rule names to severity levels:

```python
from hamburglar.detectors.yara_detector import YaraDetector
from hamburglar.core.models import Severity

severity_map = {
    "malware_pattern": Severity.CRITICAL,
    "suspicious_binary": Severity.HIGH,
    "encrypted_config": Severity.MEDIUM,
    "pdf_file": Severity.LOW,
}

detector = YaraDetector(
    rules_path="/path/to/rules",
    severity_mapping=severity_map
)
```

## Entropy Detection

Configure entropy-based detection:

```yaml
detector:
  entropy:
    enabled: true
    threshold: 4.5          # Minimum entropy to flag
    high_threshold: 5.0     # Threshold for high-confidence findings
    min_length: 16          # Minimum string length
    max_length: 256         # Maximum string length
    require_context: false  # Require secret-related keywords
```

### Entropy Detector Options

| Option | Default | Description |
|--------|---------|-------------|
| `entropy_threshold` | 4.5 | Minimum Shannon entropy to consider |
| `high_entropy_threshold` | 5.0 | Threshold for high-confidence findings |
| `min_string_length` | 16 | Minimum string length to analyze |
| `max_string_length` | 256 | Maximum string length to analyze |
| `require_context` | false | Only report with secret-related context |
| `exclude_base64` | false | Exclude base64-encoded strings |
| `exclude_hex` | false | Exclude hex-encoded strings |

### False Positive Exclusions

The entropy detector automatically excludes:
- UUIDs (8-4-4-4-12 hex format)
- MD5 hashes (32 hex characters)
- Version strings (v1.0.0)
- File paths
- Import statements
- Common programming keywords
- Lorem ipsum text
- Git commit SHAs
- Test/example values

## See Also

- [Configuration](configuration.md) - Full configuration options
- [CLI Reference](cli-reference.md) - Command-line options for filtering detectors
- [Plugins](plugins.md) - Creating custom detector plugins
- [Outputs](outputs.md) - Configuring output formats for findings
