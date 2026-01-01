# Pattern Test Fixtures

This directory contains test fixture files with realistic-looking examples for each pattern category in Hamburglar's detection library. **All values are intentionally FAKE and non-functional.**

## Purpose

These fixtures serve as integration tests for the pattern detection system. Each file contains multiple examples of secrets matching the patterns defined in `src/hamburglar/detectors/patterns/`.

## Files

| File | Description | Pattern Module |
|------|-------------|----------------|
| `api_keys.txt` | API keys from AWS, GitHub, Stripe, Twilio, etc. | `patterns/api_keys.py` |
| `cloud.txt` | Cloud provider credentials (Azure, GCP, AWS, Firebase, etc.) | `patterns/cloud.py` |
| `private_keys.txt` | Private keys (RSA, OpenSSH, EC, PGP, PKCS#8, etc.) | `patterns/private_keys.py` |
| `credentials.txt` | Passwords, database URLs, JWT tokens, OAuth | `patterns/credentials.py` |
| `crypto.txt` | Cryptocurrency addresses, seed phrases, exchange keys | `patterns/crypto.py` |
| `network.txt` | IP addresses, MAC addresses, cloud URLs, hostnames | `patterns/network.py` |
| `generic.txt` | Generic secrets, tokens, hashes, UUIDs | `patterns/generic.py` |

## Security Notice

**WARNING:** All secrets in these files are intentionally:
- Fake/invalid (will not authenticate anywhere)
- Malformed (checksums are wrong for crypto addresses)
- Truncated (private keys are incomplete)
- Example values only (e.g., `AKIAIOSFODNN7EXAMPLE` is AWS's documented example)

**DO NOT** use any of these values for real authentication or storage.

## Usage

These fixtures can be used for:

1. **Integration testing** - Verify the full detection pipeline works
2. **Regression testing** - Ensure pattern changes don't break detection
3. **Benchmarking** - Measure detection performance on realistic data
4. **Documentation** - Show examples of what each pattern detects

## Pattern Coverage

Each file aims to cover:
- Multiple variations of each pattern type
- Different contexts (inline, JSON, environment variable, etc.)
- Edge cases and format variations
- Both high-confidence and low-confidence matches
