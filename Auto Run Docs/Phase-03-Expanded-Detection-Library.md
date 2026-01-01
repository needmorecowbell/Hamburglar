# Phase 03: Expanded Detection Library

> **Branch Directive:** All work for this phase MUST be done on the `claude-overhaul` branch. Push commits to `origin/claude-overhaul` only. Do NOT push to `master` or `main`.

This phase dramatically expands Hamburglar's detection capabilities by porting all original regex patterns, adding new high-value patterns from the security community, and organizing detectors into logical categories. The result is a comprehensive detection library that catches API keys, secrets, credentials, and sensitive data across dozens of services and formats—making Hamburglar a serious tool for secret scanning.

## Tasks

- [x] Create `src/hamburglar/detectors/patterns/` directory for organizing pattern definitions

- [x] Create `src/hamburglar/detectors/patterns/__init__.py` with `PatternCategory` enum (CREDENTIALS, API_KEYS, CRYPTO, NETWORK, PRIVATE_KEYS, CLOUD, GENERIC) and `Pattern` dataclass (name, regex, severity, category, description, confidence)
  - Implemented `PatternCategory` enum with 7 categories: CREDENTIALS, API_KEYS, CRYPTO, NETWORK, PRIVATE_KEYS, CLOUD, GENERIC
  - Implemented `Confidence` enum with 3 levels: HIGH, MEDIUM, LOW
  - Implemented `Pattern` dataclass with fields: name, regex, severity, category, description, confidence
  - Added `to_dict()` method for compatibility with RegexDetector
  - Created comprehensive test suite in `tests/test_pattern_models.py` with 20 tests

- [x] Create `src/hamburglar/detectors/patterns/api_keys.py` with patterns for: AWS Access Key ID, AWS Secret Key, GitHub Token (ghp_, gho_, ghu_, ghs_, ghr_), GitHub OAuth, GitLab Token, Slack Token, Slack Webhook, Google API Key, Google OAuth, Stripe API Key (sk_live_, rk_live_), Stripe Publishable Key, Twilio Account SID, Twilio Auth Token, SendGrid API Key, Mailgun API Key, Mailchimp API Key, NPM Token, PyPI Token, NuGet API Key, Heroku API Key, DigitalOcean Token, Datadog API Key, New Relic Key
  - Implemented 38 API key patterns covering all specified services
  - Each pattern includes: name, regex, severity, category, description, and confidence level
  - Patterns organized with appropriate severity levels (CRITICAL for live secrets, HIGH for sensitive keys)
  - Created comprehensive test suite `tests/test_patterns_api_keys.py` with 159 tests (2+ positive and 2+ negative cases per pattern)
  - All patterns validated with both positive matches and negative rejection cases

- [x] Create `src/hamburglar/detectors/patterns/cloud.py` with patterns for: Azure Storage Key, Azure Connection String, Azure SAS Token, GCP Service Account Key (JSON structure detection), GCP API Key, AWS Session Token, AWS ARN, Firebase URL, Firebase API Key, Cloudflare API Key, Alibaba Cloud Access Key, IBM Cloud API Key, Oracle Cloud OCID
  - Implemented 24 cloud provider credential patterns covering all specified services plus additional patterns
  - Azure: Storage Key, Connection String, SAS Token, AD Client Secret, Subscription Key
  - GCP: Service Account Key (JSON structure), API Key, OAuth Client Secret
  - AWS: Session Token, ARN, MWS Key (additional to api_keys.py)
  - Firebase: URL, API Key, Config object detection
  - Cloudflare: API Key, API Token, Origin CA Key
  - Alibaba Cloud: Access Key ID, Secret Key
  - IBM Cloud: API Key, COS HMAC Key
  - Oracle Cloud: OCID, API Key, Tenancy OCID
  - Each pattern includes severity level, confidence rating, and description

- [x] Create `src/hamburglar/detectors/patterns/private_keys.py` with patterns for: RSA Private Key (BEGIN RSA PRIVATE KEY), OpenSSH Private Key (BEGIN OPENSSH PRIVATE KEY), EC Private Key (BEGIN EC PRIVATE KEY), DSA Private Key, PGP Private Key Block, PKCS#8 Private Key, Encrypted Private Key, SSH Private Key (various formats), X.509 Certificate, SSL/TLS Private Key
  - Implemented 16 private key patterns covering all specified formats plus additional patterns
  - RSA, OpenSSH, EC, DSA, PGP, PKCS#8 (unencrypted and encrypted) private keys
  - SSH generic header detection, SSH2 format, PuTTY PPK format
  - X.509 Certificate and Certificate Request (CSR) detection
  - SSL/TLS private key context detection, private key variable assignments
  - Private key file path detection (id_rsa, id_ecdsa, id_ed25519, etc.)
  - AWS EC2 key pair name detection
  - Each pattern includes severity level, confidence rating, and description

- [x] Create `src/hamburglar/detectors/patterns/credentials.py` with patterns for: Generic Password Assignment (password = , passwd:, pwd:), Database Connection Strings (postgres://, mysql://, mongodb://), HTTP Basic Auth Header, JWT Token (eyJ prefix), Bearer Token, OAuth Token, API Token generic patterns, Credentials in URLs (user:pass@host), .env file patterns (KEY=value), Docker registry auth
  - Implemented 30 credential detection patterns covering all specified types plus additional patterns
  - Password patterns: password, passwd, pwd, secret assignment detection
  - Database connection strings: PostgreSQL, MySQL, MongoDB, Redis, MSSQL, JDBC, generic DB connections
  - HTTP authentication: Basic Auth header, Bearer Token header
  - JWT tokens: standalone detection and variable assignment patterns
  - OAuth patterns: oauth_token, client_secret, refresh_token
  - API tokens: api_token, auth_token, access_token
  - URL credentials: user:pass@host in HTTP/FTP URLs
  - .env patterns: SECRET_KEY, DATABASE_URL, PASSWORD environment variables
  - Docker registry: auth field and docker config.json structure detection
  - Session/cookie: session_secret, cookie_secret patterns
  - LDAP: credentials in LDAP URLs and bind password assignments
  - Each pattern includes severity level, confidence rating, and description

- [x] Create `src/hamburglar/detectors/patterns/crypto.py` with patterns for: Bitcoin Address (1, 3, bc1 prefixes), Ethereum Address (0x prefix + 40 hex), Monero Address, Litecoin Address, Dogecoin Address, Ripple Address, Bitcoin Private Key (WIF format), Ethereum Private Key, Cryptocurrency Seed Phrases (12/24 word detection)
  - Implemented 33 cryptocurrency detection patterns covering all specified types plus additional patterns
  - Bitcoin: P2PKH (1), P2SH (3), Bech32 (bc1), Bech32m/Taproot (bc1p) addresses; WIF private keys (compressed/uncompressed)
  - Ethereum: Address (0x + 40 hex), Private key with context, Raw private key (0x + 64 hex)
  - Monero: Standard, Integrated, and Subaddress formats
  - Litecoin: Legacy (L), P2SH (M), Bech32 (ltc1) addresses
  - Dogecoin: Standard (D) and P2SH (9) addresses
  - Ripple (XRP): Classic (r) and X-address formats
  - Additional: Cardano Shelley, Solana addresses
  - Seed phrases: 12-word, 24-word, and generic patterns with context detection
  - Hardware wallets: Trezor passphrase, Ledger recovery phrase detection
  - Exchange API keys: Binance, Coinbase, Kraken
  - Blockchain explorer keys: Etherscan, Infura, Alchemy
  - Each pattern includes severity level, confidence rating, and description

- [x] Create `src/hamburglar/detectors/patterns/network.py` with patterns for: IPv4 Address, IPv6 Address, Private IP Ranges (10.x, 172.16-31.x, 192.168.x), MAC Address, URL with credentials, Internal hostnames, S3 Bucket URLs, Azure Blob URLs, GCS URLs, Localhost references with ports
  - Implemented 26 network detection patterns covering all specified types plus additional patterns
  - IPv4: Standard address and address with port patterns
  - Private IP Ranges: 10.x.x.x (Class A), 172.16-31.x.x (Class B), 192.168.x.x (Class C)
  - IPv6: Full address and compressed notation formats
  - MAC Address: Standard colon/hyphen format and Cisco dot notation
  - Internal hostnames: .local, .internal, .private, .corp, .intranet, .lan, .home suffixes
  - Cloud storage URLs: S3 (virtual-hosted, path-style, ARN), Azure Blob/Storage, GCS (path, virtual, gsutil)
  - Localhost: localhost, 127.0.0.1, [::1] with optional ports and paths
  - URL credentials: HTTP and FTP URLs with embedded user:pass
  - Container patterns: Kubernetes service URLs, Docker host.docker.internal
  - Created comprehensive test suite `tests/test_patterns_network.py` with 120 tests
  - Each pattern has 2+ positive and 2+ negative test cases

- [x] Create `src/hamburglar/detectors/patterns/generic.py` with patterns for: Generic API Key (api[_-]?key), Generic Secret (secret[_-]?key), Generic Token (token =), Hardcoded Password patterns, Base64 encoded secrets (high entropy detection), Hex encoded secrets (32+ chars), UUID patterns, Hash patterns (MD5, SHA1, SHA256 formats)
  - Implemented 29 generic detection patterns covering all specified types plus additional patterns
  - API Keys: generic_api_key, generic_api_key_inline
  - Secrets: generic_secret_key, generic_secret
  - Tokens: generic_token, generic_token_bearer
  - Passwords: hardcoded_password (with common prefixes), hardcoded_password_quoted, default_password
  - Base64: base64_encoded_secret, base64_long_string (64+ chars)
  - Hex: hex_encoded_secret (32+ chars), hex_string_64 (256-bit keys)
  - UUIDs: uuid_v4, uuid_generic, uuid_with_context
  - Hashes: MD5, SHA1, SHA256, SHA512, bcrypt, argon2
  - Keys: private_key_inline, encryption_key, signing_key, master_key, root_key, ssh_key_passphrase
  - Entropy: high_entropy_string pattern for alphanumeric secrets
  - Created comprehensive test suite `tests/test_patterns_generic.py` with 130 tests
  - Each pattern has 2+ positive and 2+ negative test cases
  - All patterns validated with severity, confidence, and category metadata

- [x] Update `src/hamburglar/detectors/regex_detector.py` to: import all pattern modules, register patterns by category, support enabling/disabling categories, support custom pattern files (JSON/YAML), add confidence scoring based on pattern specificity
  - Imported all 7 pattern modules: api_keys, cloud, credentials, crypto, generic, network, private_keys
  - Added `ALL_PATTERN_CATEGORIES` dict mapping `PatternCategory` enums to pattern lists
  - Added `get_all_patterns()` and `get_patterns_by_category()` helper functions
  - Added `use_expanded_patterns` flag to use the full pattern library (200+ patterns)
  - Added `enabled_categories` parameter to filter by specific categories
  - Added `disabled_categories` parameter to exclude specific categories
  - Added `min_confidence` parameter to filter by confidence level (HIGH > MEDIUM > LOW)
  - Added `custom_pattern_files` parameter to load patterns from JSON/YAML files
  - Added `load_patterns_from_file()` function supporting JSON and YAML pattern files
  - Extended findings metadata to include `category` and `confidence` fields
  - Added query methods: `get_enabled_categories()`, `get_disabled_categories()`, `get_min_confidence()`, `get_pattern_count()`, `get_patterns_by_category()`, `get_patterns_by_confidence()`
  - Extended `add_pattern()` to accept category and confidence parameters
  - Created comprehensive test suite `tests/test_regex_detector_expanded.py` with 38 tests covering all new features
  - All 1629 tests pass

- [x] Create `src/hamburglar/detectors/entropy_detector.py` with an `EntropyDetector` class that: calculates Shannon entropy of strings, identifies high-entropy strings that may be secrets, supports configurable entropy thresholds, excludes known false positives (UUIDs, hashes in comments)
  - Implemented `EntropyDetector` class with Shannon entropy calculation
  - Configurable entropy thresholds (default 4.5, high 5.0)
  - Base64 and hex encoding detection with optional exclusion filters
  - False positive exclusion for: UUIDs, MD5 hashes, version strings, file paths, import statements, hash algorithm names, lorem ipsum, test values, repeated characters, sequential patterns
  - Context-aware detection with `require_context` option to require secret-related keywords
  - Severity determination based on entropy level, encoding type, and context
  - Rich metadata including entropy value, encoding type, context snippet
  - `analyze_string()` utility method for debugging and testing
  - Configurable min/max string length bounds (default 16-256 chars)
  - Max file size limit with warning for large files

- [x] Create `tests/fixtures/patterns/` directory with test files containing real-world-like examples for each pattern category
  - Created `tests/fixtures/patterns/` directory with 7 fixture files plus README
  - `api_keys.txt`: 100+ lines with AWS, GitHub, GitLab, Slack, Google, Stripe, Twilio, SendGrid, Mailgun, Mailchimp, NPM, PyPI, NuGet, Heroku, DigitalOcean, Datadog, New Relic examples
  - `cloud.txt`: Azure (Storage Key, Connection String, SAS Token, AD Secret), GCP (Service Account, API Key, OAuth), AWS (Session Token, ARN, MWS), Firebase, Cloudflare, Alibaba, IBM, Oracle examples
  - `private_keys.txt`: RSA, OpenSSH, EC, DSA, PGP, PKCS#8, SSH2, PuTTY, X.509 cert/CSR, SSL/TLS, key path patterns (all intentionally fake/invalid)
  - `credentials.txt`: Password assignments, DB connection strings (Postgres, MySQL, MongoDB, Redis, MSSQL, JDBC), HTTP Basic/Bearer auth, JWT tokens, OAuth, API tokens, URL credentials, .env patterns, Docker auth, LDAP
  - `crypto.txt`: Bitcoin (P2PKH, P2SH, Bech32, Taproot, WIF keys), Ethereum, Monero, Litecoin, Dogecoin, Ripple, Cardano, Solana addresses; seed phrases; Binance/Coinbase/Kraken API keys; Etherscan/Infura/Alchemy keys
  - `network.txt`: IPv4/IPv6 addresses, private IP ranges (10.x, 172.16-31.x, 192.168.x), MAC addresses, internal hostnames, S3/Azure/GCS URLs, localhost patterns, Kubernetes/Docker networking
  - `generic.txt`: Generic API keys, secrets, tokens, hardcoded passwords, Base64/hex encoded secrets, UUIDs, hash patterns (MD5, SHA1, SHA256, SHA512, bcrypt, argon2), encryption/signing keys
  - `README.md`: Documentation explaining fixture purpose, file descriptions, security notice (all values fake/invalid), usage guidelines
  - All 1707 tests pass after adding fixtures

- [x] Create `tests/test_patterns_api_keys.py` with at least 2 positive and 2 negative test cases for each API key pattern (use fake but realistic-looking patterns)
  - Created as part of the api_keys.py implementation above

- [x] Create `tests/test_patterns_cloud.py` with at least 2 positive and 2 negative test cases for each cloud pattern
  - Created comprehensive test suite with 104 tests covering all 24 cloud patterns
  - Each pattern has 2+ positive and 2+ negative test cases
  - Tests validate pattern matching, metadata properties, and collection integrity

- [x] Create `tests/test_patterns_private_keys.py` with at least 2 positive and 2 negative test cases for each private key pattern
  - Created comprehensive test suite with 95 tests covering all 16 private key patterns
  - Each pattern has 2+ positive and 2+ negative test cases
  - Tests validate pattern matching, metadata properties, and collection integrity
  - Uses intentionally fake/example key content to avoid triggering secret scanners

- [x] Create `tests/test_patterns_credentials.py` with at least 2 positive and 2 negative test cases for each credential pattern
  - Created comprehensive test suite with 129 tests covering all 30 credential patterns
  - Each pattern has 2+ positive and 2+ negative test cases
  - Tests organized by pattern category (passwords, databases, HTTP auth, JWT, OAuth, API tokens, etc.)
  - Collection tests verify pattern count, categories, descriptions, regex validity, and unique names

- [x] Create `tests/test_patterns_crypto.py` with at least 2 positive and 2 negative test cases for each cryptocurrency pattern
  - Created comprehensive test suite with 145 tests covering all 33 cryptocurrency patterns
  - Each pattern has 2+ positive and 2+ negative test cases
  - Tests organized by cryptocurrency type (Bitcoin, Ethereum, Monero, Litecoin, etc.)
  - Collection tests verify pattern count, categories, descriptions, regex validity, and unique names
  - Severity validation tests ensure private keys and seed phrases are CRITICAL

- [x] Create `tests/test_entropy_detector.py` with tests for: high entropy strings are detected, low entropy strings are ignored, base64 detection works, hex string detection works, configurable thresholds work
  - Created comprehensive test suite with 78 tests covering all entropy detector functionality
  - `TestShannonEntropy`: 9 tests for entropy calculation (empty, single char, two char, low/medium/high entropy, max entropy, hex, base64)
  - `TestBase64Detection`: 6 tests for base64 encoding detection (valid, padding, invalid chars, length validation)
  - `TestHexDetection`: 6 tests for hex encoding detection (lowercase, uppercase, mixed case, invalid)
  - `TestFalsePositiveDetection`: 12 tests for false positive exclusion (UUIDs, MD5, versions, paths, imports, hash names, etc.)
  - `TestSecretContext`: 7 tests for secret context detection (password, secret, token, api_key, credential, encryption)
  - `TestEntropyDetectorInit`: 5 tests for initialization options
  - `TestEntropyDetectorDetection`: 13 tests for detection functionality (base64, hex, context, exclusions, limits)
  - `TestEntropyDetectorSeverity`: 4 tests for severity level assignment
  - `TestEntropyDetectorMetadata`: 5 tests for finding metadata
  - `TestEntropyDetectorAnalyzeString`: 5 tests for analyze_string utility
  - `TestConfigurableThresholds`: 2 tests for threshold configuration
  - `TestEntropyDetectorIntegration`: 4 tests for realistic scenarios
  - All 1707 tests pass (78 new + 1629 existing)

- [x] Update CLI to add `--categories/-c` option to enable/disable detector categories (e.g., `--categories api_keys,cloud` or `--no-categories generic`)
  - Added `--categories/-c` option to enable specific detector categories (comma-separated)
  - Added `--no-categories` option to exclude specific detector categories
  - Valid categories: api_keys, cloud, credentials, crypto, generic, network, private_keys
  - Categories are case-insensitive for user convenience
  - Added `parse_categories()` helper function for CLI parsing with validation
  - Verbose mode shows enabled/excluded categories and pattern count
  - When using category filters, the expanded pattern library is automatically enabled
  - Created comprehensive test suite `tests/test_cli_categories.py` with 27 tests covering:
    - `parse_categories()` function behavior (8 tests)
    - Help output verification (3 tests)
    - `--categories` option functionality (6 tests)
    - `--no-categories` option functionality (4 tests)
    - Combination of both options (2 tests)
    - Verbose output (1 test)
    - Integration with other CLI options (3 tests)
  - All 1734 tests pass (27 new + 1707 existing)

- [x] Update CLI to add `--min-confidence` option to filter findings by confidence level (high, medium, low)
  - Added `--min-confidence` option accepting values: high, medium, low
  - Case-insensitive parsing with whitespace trimming for user convenience
  - Added `parse_confidence()` helper function for CLI parsing with validation
  - Added `VALID_CONFIDENCE_LEVELS` mapping for enum lookup
  - When using confidence filter, the expanded pattern library is automatically enabled
  - Verbose mode shows the minimum confidence level being used
  - Created comprehensive test suite `tests/test_cli_min_confidence.py` with 26 tests covering:
    - `parse_confidence()` function behavior (8 tests)
    - Help output verification (2 tests)
    - `--min-confidence` option functionality (6 tests)
    - Verbose output (2 tests)
    - Integration with other CLI options (6 tests)
    - Pattern filtering verification (2 tests)
  - All 1760 tests pass (26 new + 1734 existing)

- [x] Run pytest and ensure all new pattern tests pass with maintained 95%+ coverage
  - All 1784 tests pass (24 new tests added in `tests/test_phase03_coverage.py`)
  - Test coverage increased to **96.85%** (above the 95% threshold)
  - New tests cover edge cases in: EntropyDetector, RegexDetector pattern loading, YaraDetector error handling, and CLI category parsing
  - Tests cover: hex exclusion filter, severity determination, finding type detection, common word false positives, base64 validation, YAML pattern loading errors, JSON pattern loading, missing fields in patterns, custom file loading errors, expanded pattern merging, regex timeout in chunked processing, YARA availability checks, YARA compilation errors, rule state handling
