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

- [ ] Create `src/hamburglar/detectors/patterns/generic.py` with patterns for: Generic API Key (api[_-]?key), Generic Secret (secret[_-]?key), Generic Token (token =), Hardcoded Password patterns, Base64 encoded secrets (high entropy detection), Hex encoded secrets (32+ chars), UUID patterns, Hash patterns (MD5, SHA1, SHA256 formats)

- [ ] Update `src/hamburglar/detectors/regex_detector.py` to: import all pattern modules, register patterns by category, support enabling/disabling categories, support custom pattern files (JSON/YAML), add confidence scoring based on pattern specificity

- [ ] Create `src/hamburglar/detectors/entropy_detector.py` with an `EntropyDetector` class that: calculates Shannon entropy of strings, identifies high-entropy strings that may be secrets, supports configurable entropy thresholds, excludes known false positives (UUIDs, hashes in comments)

- [ ] Create `tests/fixtures/patterns/` directory with test files containing real-world-like examples for each pattern category

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

- [ ] Create `tests/test_entropy_detector.py` with tests for: high entropy strings are detected, low entropy strings are ignored, base64 detection works, hex string detection works, configurable thresholds work

- [ ] Update CLI to add `--categories/-c` option to enable/disable detector categories (e.g., `--categories api_keys,cloud` or `--no-categories generic`)

- [ ] Update CLI to add `--min-confidence` option to filter findings by confidence level (high, medium, low)

- [ ] Run pytest and ensure all new pattern tests pass with maintained 95%+ coverage
