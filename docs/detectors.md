# Detectors

Hamburglar uses multiple detection methods to identify secrets and sensitive information.

## Detection Methods

### Regex Pattern Detection

The primary detection method uses regular expressions to match known patterns for secrets, credentials, and sensitive data.

### YARA Rules

YARA rules are used for binary file analysis and complex pattern matching. They're particularly useful for detecting embedded files and specific file signatures.

### Entropy Detection

High-entropy strings often indicate encoded or encrypted secrets. Hamburglar can detect strings with unusually high entropy that may be API keys or tokens.

## Pattern Categories

### API Keys (`api_keys`)

Patterns for detecting API keys from various services:

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `aws_access_key_id` | AWS Access Key ID | high |
| `aws_secret_access_key` | AWS Secret Access Key | critical |
| `github_token` | GitHub Personal Access Token | high |
| `github_oauth` | GitHub OAuth Token | high |
| `gitlab_token` | GitLab Personal Access Token | high |
| `slack_token` | Slack API Token | high |
| `slack_webhook` | Slack Webhook URL | medium |
| `stripe_api_key` | Stripe API Key | high |
| `stripe_secret_key` | Stripe Secret Key | critical |
| `twilio_api_key` | Twilio API Key | high |
| `sendgrid_api_key` | SendGrid API Key | high |
| `mailgun_api_key` | Mailgun API Key | high |
| `google_api_key` | Google API Key | high |
| `firebase_api_key` | Firebase API Key | medium |
| `heroku_api_key` | Heroku API Key | high |

### Credentials (`credentials`)

Patterns for passwords, usernames, and authentication data:

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `password_assignment` | Password variable assignment | high |
| `password_url` | Password in URL | critical |
| `basic_auth_header` | Basic Auth header | high |
| `bearer_token` | Bearer token in header | high |
| `jwt_token` | JSON Web Token | high |
| `database_url` | Database connection string | critical |
| `mongodb_uri` | MongoDB connection URI | critical |
| `postgres_uri` | PostgreSQL connection URI | critical |
| `mysql_uri` | MySQL connection URI | critical |
| `redis_uri` | Redis connection URI | high |

### Private Keys (`private_keys`)

Patterns for cryptographic private keys:

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `rsa_private_key` | RSA Private Key | critical |
| `dsa_private_key` | DSA Private Key | critical |
| `ec_private_key` | EC Private Key | critical |
| `openssh_private_key` | OpenSSH Private Key | critical |
| `pgp_private_key` | PGP Private Key Block | critical |
| `putty_private_key` | PuTTY Private Key | critical |
| `pkcs8_private_key` | PKCS#8 Private Key | critical |

### Cloud Providers (`cloud`)

Patterns for cloud provider credentials:

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `azure_storage_key` | Azure Storage Account Key | critical |
| `azure_connection_string` | Azure Connection String | critical |
| `gcp_service_account` | GCP Service Account Key | critical |
| `gcp_api_key` | GCP API Key | high |
| `digitalocean_token` | DigitalOcean API Token | high |
| `ibm_cloud_key` | IBM Cloud API Key | high |
| `alibaba_access_key` | Alibaba Cloud Access Key | high |

### Cryptocurrency (`crypto`)

Patterns for cryptocurrency-related data:

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `bitcoin_private_key` | Bitcoin Private Key (WIF) | critical |
| `ethereum_private_key` | Ethereum Private Key | critical |
| `bitcoin_address` | Bitcoin Address | low |
| `ethereum_address` | Ethereum Address | low |
| `mnemonic_phrase` | BIP39 Mnemonic Phrase | critical |

### Network (`network`)

Patterns for network-related sensitive data:

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `private_ip` | Private IP Address | low |
| `internal_url` | Internal URL | low |
| `email_address` | Email Address | low |
| `ipv4_address` | IPv4 Address | low |
| `ipv6_address` | IPv6 Address | low |

### Generic (`generic`)

General-purpose patterns:

| Pattern Name | Description | Severity |
|-------------|-------------|----------|
| `generic_api_key` | Generic API key pattern | medium |
| `generic_secret` | Generic secret pattern | medium |
| `base64_encoded` | Base64 encoded content | low |
| `hex_encoded` | Hex encoded content | low |

## Severity Levels

| Level | Description | Examples |
|-------|-------------|----------|
| `critical` | Immediate security risk | Private keys, database credentials |
| `high` | Significant security risk | API keys, tokens |
| `medium` | Moderate security risk | Generic secrets, internal URLs |
| `low` | Informational | IP addresses, email addresses |

## Confidence Scores

Confidence scores indicate how likely a match is a real secret:

| Score Range | Interpretation |
|------------|----------------|
| 0.90 - 1.00 | Very high confidence, likely a real secret |
| 0.70 - 0.89 | High confidence, investigate |
| 0.50 - 0.69 | Medium confidence, may be false positive |
| 0.00 - 0.49 | Low confidence, manual review needed |

Factors affecting confidence:
- Pattern specificity
- Context (variable names, file types)
- Entropy of matched content
- Known test/example patterns

## Adding Custom Patterns

### Via Configuration File

```yaml
# hamburglar.yml
patterns:
  custom:
    - name: my_internal_key
      pattern: "MYAPP-[A-Z0-9]{24}"
      severity: high
      confidence: 0.9
      description: "Internal application API key"

    - name: internal_database
      pattern: "postgres://internal\\.mycompany\\.com"
      severity: critical
      confidence: 0.95
      description: "Internal database connection"
```

### Custom Pattern Fields

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Unique pattern identifier |
| `pattern` | Yes | Regular expression pattern |
| `severity` | Yes | low, medium, high, or critical |
| `confidence` | No | Default confidence score (0.0-1.0) |
| `description` | No | Human-readable description |
| `category` | No | Category for grouping |
| `flags` | No | Regex flags (e.g., `i` for case-insensitive) |

### Disabling Patterns

Disable specific patterns in configuration:

```yaml
patterns:
  disabled:
    - generic_api_key
    - email_address
```

## YARA Rules

### Built-in Rules

Hamburglar includes YARA rules for detecting:

- Executable files (PE, ELF, Mach-O)
- Office documents (DOC, DOCX, XLS, XLSX)
- PDF files
- Compressed archives (ZIP, RAR, 7z, GZIP)
- Image files (JPEG, PNG, GIF)
- Audio files (MP3, WAV, FLAC)
- Video files (MP4, AVI, MKV)
- Database files (SQLite)
- Cryptocurrency wallets
- Memory dumps
- VMware files

### Custom YARA Rules

Add custom YARA rules:

```yaml
# hamburglar.yml
yara:
  enabled: true
  custom_rules:
    - /path/to/my_rules.yar
    - /path/to/more_rules/
```

Example YARA rule:

```yara
rule MyCustomSecret
{
    meta:
        description = "Detects my custom secret format"
        severity = "high"

    strings:
        $secret = /MYSECRET-[A-Z0-9]{32}/

    condition:
        $secret
}
```

## Entropy Detection

Configure entropy-based detection:

```yaml
detection:
  enable_entropy: true
  min_entropy: 4.5  # Shannon entropy threshold
```

Higher entropy values indicate more randomness:
- Normal text: ~3.5-4.0
- Random strings: ~4.5-5.0
- Cryptographic keys: ~5.5-6.0

## See Also

- [Configuration](configuration.md) - Full configuration options
- [Plugins](plugins.md) - Creating custom detector plugins
- [CLI Reference](cli-reference.md) - Command-line options
