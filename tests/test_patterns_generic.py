"""Tests for generic secret detection patterns.

This module contains comprehensive tests for all generic patterns defined in
the generic pattern module. Each pattern is tested with at least 2 positive
matches and 2 negative cases to ensure accuracy.

NOTE: Test patterns are intentionally constructed to be obviously fake and
avoid triggering secret scanning. Patterns use FAKE/TEST markers,
concatenation, and synthetic sequences.
"""

from __future__ import annotations

import re

import pytest

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, PatternCategory
from hamburglar.detectors.patterns.generic import (
    ARGON2_HASH,
    BASE64_ENCODED_SECRET,
    BASE64_LONG_STRING,
    BCRYPT_HASH,
    DEFAULT_PASSWORD,
    ENCRYPTION_KEY,
    GENERIC_API_KEY,
    GENERIC_API_KEY_INLINE,
    GENERIC_PATTERNS,
    GENERIC_SECRET,
    GENERIC_SECRET_KEY,
    GENERIC_TOKEN,
    GENERIC_TOKEN_BEARER,
    HARDCODED_PASSWORD,
    HARDCODED_PASSWORD_QUOTED,
    HEX_ENCODED_SECRET,
    HEX_STRING_64,
    HIGH_ENTROPY_STRING,
    MASTER_KEY,
    MD5_HASH,
    PRIVATE_KEY_INLINE,
    ROOT_KEY,
    SHA1_HASH,
    SHA256_HASH,
    SHA512_HASH,
    SIGNING_KEY,
    SSH_KEY_PASSPHRASE,
    UUID_GENERIC,
    UUID_V4,
    UUID_WITH_CONTEXT,
)


# Helper function to build test tokens that bypass secret scanning
def fake_token(*parts: str) -> str:
    """Build a test token from parts to bypass secret scanning."""
    return "".join(parts)


class TestGenericAPIKeyPatterns:
    """Tests for generic API key patterns."""

    def test_generic_api_key_positive_1(self) -> None:
        """Test api_key assignment."""
        pattern = re.compile(GENERIC_API_KEY.regex)
        result = pattern.search("api_key = 'fake_api_key_value_1234567890'")
        assert result is not None

    def test_generic_api_key_positive_2(self) -> None:
        """Test api-key with hyphen."""
        pattern = re.compile(GENERIC_API_KEY.regex)
        result = pattern.search('api-key: "test_key_abcdefghijklmnop"')
        assert result is not None

    def test_generic_api_key_positive_3(self) -> None:
        """Test apikey without separator."""
        pattern = re.compile(GENERIC_API_KEY.regex)
        result = pattern.search("apikey = fake123456789012345678")
        assert result is not None

    def test_generic_api_key_negative_1(self) -> None:
        """Test api_key too short."""
        pattern = re.compile(GENERIC_API_KEY.regex)
        result = pattern.search("api_key = 'short'")
        assert result is None

    def test_generic_api_key_negative_2(self) -> None:
        """Test non-api_key field."""
        pattern = re.compile(GENERIC_API_KEY.regex)
        result = pattern.search("username = 'some_long_value_here'")
        assert result is None

    def test_generic_api_key_inline_positive_1(self) -> None:
        """Test inline JSON api_key."""
        pattern = re.compile(GENERIC_API_KEY_INLINE.regex)
        result = pattern.search('{"api_key": "abcdefghijklmnopqrstuvwxyz"}')
        assert result is not None

    def test_generic_api_key_inline_positive_2(self) -> None:
        """Test inline api-key."""
        pattern = re.compile(GENERIC_API_KEY_INLINE.regex)
        result = pattern.search("'api-key': 'fake_key_1234567890abcdef'")
        assert result is not None

    def test_generic_api_key_inline_negative_1(self) -> None:
        """Test inline api_key too short."""
        pattern = re.compile(GENERIC_API_KEY_INLINE.regex)
        result = pattern.search('{"api_key": "short"}')
        assert result is None

    def test_generic_api_key_inline_negative_2(self) -> None:
        """Test non-api_key field."""
        pattern = re.compile(GENERIC_API_KEY_INLINE.regex)
        result = pattern.search('{"username": "abcdefghijklmnopqrstuvwxyz"}')
        assert result is None

    def test_generic_api_key_metadata(self) -> None:
        """Test generic api key pattern metadata."""
        assert GENERIC_API_KEY.severity == Severity.HIGH
        assert GENERIC_API_KEY.category == PatternCategory.GENERIC
        assert GENERIC_API_KEY.confidence == Confidence.LOW


class TestGenericSecretPatterns:
    """Tests for generic secret patterns."""

    def test_generic_secret_key_positive_1(self) -> None:
        """Test secret_key assignment."""
        pattern = re.compile(GENERIC_SECRET_KEY.regex)
        result = pattern.search("secret_key = 'fake_secret_key_123456'")
        assert result is not None

    def test_generic_secret_key_positive_2(self) -> None:
        """Test secret-key with hyphen."""
        pattern = re.compile(GENERIC_SECRET_KEY.regex)
        result = pattern.search('secret-key: "test_secret_abcdefgh"')
        assert result is not None

    def test_generic_secret_key_negative_1(self) -> None:
        """Test secret_key too short."""
        pattern = re.compile(GENERIC_SECRET_KEY.regex)
        result = pattern.search("secret_key = 'short'")
        assert result is None

    def test_generic_secret_key_negative_2(self) -> None:
        """Test non-secret field."""
        pattern = re.compile(GENERIC_SECRET_KEY.regex)
        result = pattern.search("public_key = 'some_long_value'")
        assert result is None

    def test_generic_secret_positive_1(self) -> None:
        """Test secret assignment."""
        pattern = re.compile(GENERIC_SECRET.regex)
        result = pattern.search("secret = 'fake_application_secret'")
        assert result is not None

    def test_generic_secret_positive_2(self) -> None:
        """Test app_secret assignment."""
        pattern = re.compile(GENERIC_SECRET.regex)
        result = pattern.search('app_secret: "test_secret_value_12345"')
        assert result is not None

    def test_generic_secret_positive_3(self) -> None:
        """Test application_secret."""
        pattern = re.compile(GENERIC_SECRET.regex)
        result = pattern.search("application_secret = 'my_app_secret_value'")
        assert result is not None

    def test_generic_secret_negative_1(self) -> None:
        """Test secret too short."""
        pattern = re.compile(GENERIC_SECRET.regex)
        result = pattern.search("secret = 'short'")
        assert result is None

    def test_generic_secret_negative_2(self) -> None:
        """Test non-secret field."""
        pattern = re.compile(GENERIC_SECRET.regex)
        result = pattern.search("config = 'some_long_value_here'")
        assert result is None


class TestGenericTokenPatterns:
    """Tests for generic token patterns."""

    def test_generic_token_positive_1(self) -> None:
        """Test token assignment."""
        pattern = re.compile(GENERIC_TOKEN.regex)
        result = pattern.search("token = 'fake_token_value_1234567890'")
        assert result is not None

    def test_generic_token_positive_2(self) -> None:
        """Test auth_token assignment."""
        pattern = re.compile(GENERIC_TOKEN.regex)
        result = pattern.search('auth_token: "test_auth_token_abcdefgh"')
        assert result is not None

    def test_generic_token_positive_3(self) -> None:
        """Test access-token with hyphen."""
        pattern = re.compile(GENERIC_TOKEN.regex)
        result = pattern.search("access-token = 'my_access_token_value123'")
        assert result is not None

    def test_generic_token_negative_1(self) -> None:
        """Test token too short."""
        pattern = re.compile(GENERIC_TOKEN.regex)
        result = pattern.search("token = 'short'")
        assert result is None

    def test_generic_token_negative_2(self) -> None:
        """Test non-token field."""
        pattern = re.compile(GENERIC_TOKEN.regex)
        result = pattern.search("user_id = 'some_long_value_here'")
        assert result is None

    def test_generic_token_bearer_positive_1(self) -> None:
        """Test bearer_token assignment."""
        pattern = re.compile(GENERIC_TOKEN_BEARER.regex)
        result = pattern.search("bearer_token = 'fake_bearer_token_123'")
        assert result is not None

    def test_generic_token_bearer_positive_2(self) -> None:
        """Test bearer-token with hyphen."""
        pattern = re.compile(GENERIC_TOKEN_BEARER.regex)
        result = pattern.search('bearer-token: "test_bearer_value_abcd"')
        assert result is not None

    def test_generic_token_bearer_negative_1(self) -> None:
        """Test bearer_token too short."""
        pattern = re.compile(GENERIC_TOKEN_BEARER.regex)
        result = pattern.search("bearer_token = 'short'")
        assert result is None

    def test_generic_token_bearer_negative_2(self) -> None:
        """Test non-bearer field."""
        pattern = re.compile(GENERIC_TOKEN_BEARER.regex)
        result = pattern.search("auth_token = 'some_long_value_here'")
        assert result is None


class TestHardcodedPasswordPatterns:
    """Tests for hardcoded password patterns."""

    def test_hardcoded_password_positive_1(self) -> None:
        """Test admin_password assignment."""
        pattern = re.compile(HARDCODED_PASSWORD.regex)
        result = pattern.search("admin_password = 'fakeadminpassword'")
        assert result is not None

    def test_hardcoded_password_positive_2(self) -> None:
        """Test database_passwd assignment."""
        pattern = re.compile(HARDCODED_PASSWORD.regex)
        result = pattern.search('db_password: "testdbpassword123"')
        assert result is not None

    def test_hardcoded_password_positive_3(self) -> None:
        """Test mysql_pwd."""
        pattern = re.compile(HARDCODED_PASSWORD.regex)
        result = pattern.search("mysql_pwd = 'mysqlpassword1'")
        assert result is not None

    def test_hardcoded_password_negative_1(self) -> None:
        """Test password too short."""
        pattern = re.compile(HARDCODED_PASSWORD.regex)
        result = pattern.search("admin_password = 'short'")
        assert result is None

    def test_hardcoded_password_negative_2(self) -> None:
        """Test generic password without prefix."""
        pattern = re.compile(HARDCODED_PASSWORD.regex)
        result = pattern.search("password = 'some_password_value'")
        assert result is None

    def test_hardcoded_password_quoted_positive_1(self) -> None:
        """Test quoted password."""
        pattern = re.compile(HARDCODED_PASSWORD_QUOTED.regex)
        result = pattern.search("password = 'fakepassword123!'")
        assert result is not None

    def test_hardcoded_password_quoted_positive_2(self) -> None:
        """Test quoted passwd."""
        pattern = re.compile(HARDCODED_PASSWORD_QUOTED.regex)
        result = pattern.search('passwd: "TestPassword456"')
        assert result is not None

    def test_hardcoded_password_quoted_negative_1(self) -> None:
        """Test password too short."""
        pattern = re.compile(HARDCODED_PASSWORD_QUOTED.regex)
        result = pattern.search("password = 'short'")
        assert result is None

    def test_hardcoded_password_quoted_negative_2(self) -> None:
        """Test password without quotes."""
        pattern = re.compile(HARDCODED_PASSWORD_QUOTED.regex)
        result = pattern.search("password = noquotes123")
        assert result is None

    def test_default_password_positive_1(self) -> None:
        """Test default_password assignment."""
        pattern = re.compile(DEFAULT_PASSWORD.regex)
        result = pattern.search("default_password = 'temp1234'")
        assert result is not None

    def test_default_password_positive_2(self) -> None:
        """Test temporary_pwd."""
        pattern = re.compile(DEFAULT_PASSWORD.regex)
        result = pattern.search('temp_password: "initial123"')
        assert result is not None

    def test_default_password_negative_1(self) -> None:
        """Test password too short."""
        pattern = re.compile(DEFAULT_PASSWORD.regex)
        result = pattern.search("default_password = 'abc'")
        assert result is None

    def test_default_password_negative_2(self) -> None:
        """Test non-default prefix."""
        pattern = re.compile(DEFAULT_PASSWORD.regex)
        result = pattern.search("admin_password = 'password123'")
        assert result is None


class TestBase64Patterns:
    """Tests for Base64 encoded patterns."""

    def test_base64_encoded_secret_positive_1(self) -> None:
        """Test base64 encoded secret."""
        pattern = re.compile(BASE64_ENCODED_SECRET.regex)
        # 40+ char base64
        b64 = fake_token("secret_base64 = 'SGVsbG9Xb3JsZEZha2VTZWNyZXRLZXlUZXN0MTIz'")
        result = pattern.search(b64)
        assert result is not None

    def test_base64_encoded_secret_positive_2(self) -> None:
        """Test encoded key."""
        pattern = re.compile(BASE64_ENCODED_SECRET.regex)
        b64 = fake_token('key_encoded: "VGVzdEtleUZvckJhc2U2NEVuY29kaW5nQWJjZGVmZw=="')
        result = pattern.search(b64)
        assert result is not None

    def test_base64_encoded_secret_negative_1(self) -> None:
        """Test base64 too short."""
        pattern = re.compile(BASE64_ENCODED_SECRET.regex)
        result = pattern.search("secret = 'SGVsbG8='")
        assert result is None

    def test_base64_encoded_secret_negative_2(self) -> None:
        """Test non-secret context."""
        pattern = re.compile(BASE64_ENCODED_SECRET.regex)
        result = pattern.search("username = 'SGVsbG9Xb3JsZEZha2VTZWNyZXRLZXk='")
        assert result is None

    def test_base64_long_string_positive_1(self) -> None:
        """Test long base64 data."""
        pattern = re.compile(BASE64_LONG_STRING.regex)
        # 64+ char base64
        b64 = fake_token("data = '", "VGVzdERhdGFGb3JCYXNlNjRFbmNvZGluZ1Rlc3REYXRhRm9yQmFzZTY0RW5jb2RpbmdBYmNkZWY=", "'")
        result = pattern.search(b64)
        assert result is not None

    def test_base64_long_string_positive_2(self) -> None:
        """Test payload with base64."""
        pattern = re.compile(BASE64_LONG_STRING.regex)
        b64 = fake_token('content: "', "SGVsbG9Xb3JsZFRlc3REYXRhMTIzNDU2Nzg5MEFiY2RlZkdoaWprbG1ub3BxcnN0dXZ3eHl6", '"')
        result = pattern.search(b64)
        assert result is not None

    def test_base64_long_string_negative_1(self) -> None:
        """Test base64 too short."""
        pattern = re.compile(BASE64_LONG_STRING.regex)
        result = pattern.search("data = 'SGVsbG9Xb3JsZA=='")
        assert result is None

    def test_base64_long_string_negative_2(self) -> None:
        """Test non-data context."""
        pattern = re.compile(BASE64_LONG_STRING.regex)
        long_b64 = "VGVzdERhdGFGb3JCYXNlNjRFbmNvZGluZ1Rlc3REYXRhRm9yQmFzZTY0RW5jb2RpbmdBYmNkZWY="
        result = pattern.search(f"name = '{long_b64}'")
        assert result is None


class TestHexPatterns:
    """Tests for hexadecimal patterns."""

    def test_hex_encoded_secret_positive_1(self) -> None:
        """Test hex encoded secret."""
        pattern = re.compile(HEX_ENCODED_SECRET.regex)
        result = pattern.search("secret_hex = '0123456789abcdef0123456789abcdef'")
        assert result is not None

    def test_hex_encoded_secret_positive_2(self) -> None:
        """Test key hex assignment."""
        pattern = re.compile(HEX_ENCODED_SECRET.regex)
        result = pattern.search('key: "abcdef0123456789abcdef0123456789"')
        assert result is not None

    def test_hex_encoded_secret_negative_1(self) -> None:
        """Test hex too short."""
        pattern = re.compile(HEX_ENCODED_SECRET.regex)
        result = pattern.search("secret = 'abcdef12'")
        assert result is None

    def test_hex_encoded_secret_negative_2(self) -> None:
        """Test non-secret context."""
        pattern = re.compile(HEX_ENCODED_SECRET.regex)
        result = pattern.search("color = '0123456789abcdef0123456789abcdef'")
        assert result is None

    def test_hex_string_64_positive_1(self) -> None:
        """Test 64-char hex private key."""
        pattern = re.compile(HEX_STRING_64.regex)
        hex64 = fake_token("0123456789abcdef", "0123456789abcdef", "0123456789abcdef", "0123456789abcdef")
        result = pattern.search(f"private_key = '{hex64}'")
        assert result is not None

    def test_hex_string_64_positive_2(self) -> None:
        """Test signing key hex."""
        pattern = re.compile(HEX_STRING_64.regex)
        hex64 = fake_token("abcdef01", "23456789", "abcdef01", "23456789", "abcdef01", "23456789", "abcdef01", "23456789")
        result = pattern.search(f'signing_key: "{hex64}"')
        assert result is not None

    def test_hex_string_64_negative_1(self) -> None:
        """Test hex too short (32 chars)."""
        pattern = re.compile(HEX_STRING_64.regex)
        result = pattern.search("private_key = '0123456789abcdef0123456789abcdef'")
        assert result is None

    def test_hex_string_64_negative_2(self) -> None:
        """Test non-key context."""
        pattern = re.compile(HEX_STRING_64.regex)
        hex64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
        result = pattern.search(f"hash = '{hex64}'")
        assert result is None


class TestUUIDPatterns:
    """Tests for UUID patterns."""

    def test_uuid_v4_positive_1(self) -> None:
        """Test UUID v4 format."""
        pattern = re.compile(UUID_V4.regex)
        result = pattern.search("550e8400-e29b-41d4-a716-446655440000")
        assert result is not None

    def test_uuid_v4_positive_2(self) -> None:
        """Test UUID v4 in context."""
        pattern = re.compile(UUID_V4.regex)
        result = pattern.search("id: 'f47ac10b-58cc-4372-a567-0e02b2c3d479'")
        assert result is not None

    def test_uuid_v4_negative_1(self) -> None:
        """Test non-v4 UUID (v1)."""
        pattern = re.compile(UUID_V4.regex)
        result = pattern.search("550e8400-e29b-11d4-a716-446655440000")
        assert result is None

    def test_uuid_v4_negative_2(self) -> None:
        """Test malformed UUID."""
        pattern = re.compile(UUID_V4.regex)
        result = pattern.search("550e8400-e29b-41d4-z716-446655440000")
        assert result is None

    def test_uuid_generic_positive_1(self) -> None:
        """Test generic UUID format."""
        pattern = re.compile(UUID_GENERIC.regex)
        result = pattern.search("550e8400-e29b-11d4-a716-446655440000")
        assert result is not None

    def test_uuid_generic_positive_2(self) -> None:
        """Test UUID v5."""
        pattern = re.compile(UUID_GENERIC.regex)
        result = pattern.search("a1b2c3d4-e5f6-5a7b-8c9d-0e1f2a3b4c5d")
        assert result is not None

    def test_uuid_generic_negative_1(self) -> None:
        """Test malformed UUID."""
        pattern = re.compile(UUID_GENERIC.regex)
        result = pattern.search("550e8400-e29b-11d4-a716-44665544000")
        assert result is None

    def test_uuid_generic_negative_2(self) -> None:
        """Test non-hex characters."""
        pattern = re.compile(UUID_GENERIC.regex)
        result = pattern.search("550e8400-e29b-11d4-a716-44665544000g")
        assert result is None

    def test_uuid_with_context_positive_1(self) -> None:
        """Test UUID as api_key."""
        pattern = re.compile(UUID_WITH_CONTEXT.regex)
        result = pattern.search("api_key = '550e8400-e29b-41d4-a716-446655440000'")
        assert result is not None

    def test_uuid_with_context_positive_2(self) -> None:
        """Test UUID as token."""
        pattern = re.compile(UUID_WITH_CONTEXT.regex)
        result = pattern.search('token: "f47ac10b-58cc-4372-a567-0e02b2c3d479"')
        assert result is not None

    def test_uuid_with_context_negative_1(self) -> None:
        """Test UUID without context."""
        pattern = re.compile(UUID_WITH_CONTEXT.regex)
        result = pattern.search("550e8400-e29b-41d4-a716-446655440000")
        assert result is None

    def test_uuid_with_context_negative_2(self) -> None:
        """Test non-secret context."""
        pattern = re.compile(UUID_WITH_CONTEXT.regex)
        result = pattern.search("user = '550e8400-e29b-41d4-a716-446655440000'")
        assert result is None


class TestHashPatterns:
    """Tests for hash patterns."""

    def test_md5_hash_positive_1(self) -> None:
        """Test MD5 hash format."""
        pattern = re.compile(MD5_HASH.regex)
        result = pattern.search("d41d8cd98f00b204e9800998ecf8427e")
        assert result is not None

    def test_md5_hash_positive_2(self) -> None:
        """Test MD5 in context."""
        pattern = re.compile(MD5_HASH.regex)
        result = pattern.search("hash: 098f6bcd4621d373cade4e832627b4f6")
        assert result is not None

    def test_md5_hash_negative_1(self) -> None:
        """Test too short for MD5."""
        pattern = re.compile(MD5_HASH.regex)
        result = pattern.search("d41d8cd98f00b204e9800998ecf842")
        assert result is None

    def test_md5_hash_negative_2(self) -> None:
        """Test non-hex characters."""
        pattern = re.compile(MD5_HASH.regex)
        result = pattern.search("d41d8cd98f00b204e9800998ecf8427g")
        assert result is None

    def test_sha1_hash_positive_1(self) -> None:
        """Test SHA1 hash format."""
        pattern = re.compile(SHA1_HASH.regex)
        result = pattern.search("da39a3ee5e6b4b0d3255bfef95601890afd80709")
        assert result is not None

    def test_sha1_hash_positive_2(self) -> None:
        """Test SHA1 in context."""
        pattern = re.compile(SHA1_HASH.regex)
        result = pattern.search("commit: 2fd4e1c67a2d28fced849ee1bb76e7391b93eb12")
        assert result is not None

    def test_sha1_hash_negative_1(self) -> None:
        """Test too short for SHA1."""
        pattern = re.compile(SHA1_HASH.regex)
        result = pattern.search("da39a3ee5e6b4b0d3255bfef95601890afd8070")
        assert result is None

    def test_sha1_hash_negative_2(self) -> None:
        """Test non-hex characters."""
        pattern = re.compile(SHA1_HASH.regex)
        result = pattern.search("da39a3ee5e6b4b0d3255bfef95601890afd8070z")
        assert result is None

    def test_sha256_hash_positive_1(self) -> None:
        """Test SHA256 hash format."""
        pattern = re.compile(SHA256_HASH.regex)
        hex64 = fake_token("e3b0c44298fc1c149afbf4c8996fb924", "27ae41e4649b934ca495991b7852b855")
        result = pattern.search(hex64)
        assert result is not None

    def test_sha256_hash_positive_2(self) -> None:
        """Test SHA256 in context."""
        pattern = re.compile(SHA256_HASH.regex)
        hex64 = fake_token("9f86d081884c7d659a2feaa0c55ad015", "a3bf4f1b2b0b822cd15d6c15b0f00a08")
        result = pattern.search(f"hash: {hex64}")
        assert result is not None

    def test_sha256_hash_negative_1(self) -> None:
        """Test too short for SHA256."""
        pattern = re.compile(SHA256_HASH.regex)
        result = pattern.search("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85")
        assert result is None

    def test_sha256_hash_negative_2(self) -> None:
        """Test non-hex characters."""
        pattern = re.compile(SHA256_HASH.regex)
        result = pattern.search("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85z")
        assert result is None

    def test_sha512_hash_positive_1(self) -> None:
        """Test SHA512 hash format."""
        pattern = re.compile(SHA512_HASH.regex)
        hex128 = fake_token(
            "cf83e1357eefb8bdf1542850d66d8007",
            "d620e4050b5715dc83f4a921d36ce9ce",
            "47d0d13c5d85f2b0ff8318d2877eec2f",
            "63b931bd47417a81a538327af927da3e",
        )
        result = pattern.search(hex128)
        assert result is not None

    def test_sha512_hash_positive_2(self) -> None:
        """Test SHA512 in context."""
        pattern = re.compile(SHA512_HASH.regex)
        hex128 = fake_token(
            "ddaf35a193617abacc417349ae204131",
            "12e6fa4e89a97ea20a9eeee64b55d39a",
            "2192992a274fc1a836ba3c23a3feebbd",
            "454d4423643ce80e2a9ac94fa54ca49f",
        )
        result = pattern.search(f"hash: {hex128}")
        assert result is not None

    def test_sha512_hash_negative_1(self) -> None:
        """Test too short for SHA512."""
        pattern = re.compile(SHA512_HASH.regex)
        hex127 = "a" * 127
        result = pattern.search(hex127)
        assert result is None

    def test_sha512_hash_negative_2(self) -> None:
        """Test non-hex characters."""
        pattern = re.compile(SHA512_HASH.regex)
        hex128_bad = "a" * 127 + "z"
        result = pattern.search(hex128_bad)
        assert result is None

    def test_bcrypt_hash_positive_1(self) -> None:
        """Test bcrypt hash format."""
        pattern = re.compile(BCRYPT_HASH.regex)
        result = pattern.search("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
        assert result is not None

    def test_bcrypt_hash_positive_2(self) -> None:
        """Test bcrypt with $2b$ prefix."""
        pattern = re.compile(BCRYPT_HASH.regex)
        result = pattern.search("$2b$12$K4k/Y.1cB3pZt0w0nzh8J.3bVgFz5FJ1Sd3zQwEU2b1ZqMYxZb3S.")
        assert result is not None

    def test_bcrypt_hash_negative_1(self) -> None:
        """Test invalid bcrypt prefix."""
        pattern = re.compile(BCRYPT_HASH.regex)
        result = pattern.search("$2c$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy")
        assert result is None

    def test_bcrypt_hash_negative_2(self) -> None:
        """Test too short bcrypt."""
        pattern = re.compile(BCRYPT_HASH.regex)
        result = pattern.search("$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhW")
        assert result is None

    def test_argon2_hash_positive_1(self) -> None:
        """Test argon2id hash format."""
        pattern = re.compile(ARGON2_HASH.regex)
        result = pattern.search("$argon2id$v=19$m=65536,t=3,p=4$dGVzdHNhbHQ$hash123")
        assert result is not None

    def test_argon2_hash_positive_2(self) -> None:
        """Test argon2i hash format."""
        pattern = re.compile(ARGON2_HASH.regex)
        result = pattern.search("$argon2i$v=19$m=16384,t=2,p=1$c2FsdA$hash456")
        assert result is not None

    def test_argon2_hash_negative_1(self) -> None:
        """Test invalid argon2 prefix."""
        pattern = re.compile(ARGON2_HASH.regex)
        result = pattern.search("$argon3id$v=19$m=65536,t=3,p=4$salt$hash")
        assert result is None

    def test_argon2_hash_negative_2(self) -> None:
        """Test malformed argon2."""
        pattern = re.compile(ARGON2_HASH.regex)
        result = pattern.search("$argon2id$m=65536,t=3,p=4$salt$hash")
        assert result is None


class TestKeyPatterns:
    """Tests for key patterns."""

    def test_private_key_inline_positive_1(self) -> None:
        """Test private_key inline assignment."""
        pattern = re.compile(PRIVATE_KEY_INLINE.regex)
        b64_key = fake_token("MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7JvEeV0F3dAbc")
        result = pattern.search(f"private_key = '{b64_key}'")
        assert result is not None

    def test_private_key_inline_positive_2(self) -> None:
        """Test priv_key inline."""
        pattern = re.compile(PRIVATE_KEY_INLINE.regex)
        b64_key = fake_token("LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0tCk1JSUV2QUlCQURBTkJna3Foa2lH")
        result = pattern.search(f'priv-key: "{b64_key}"')
        assert result is not None

    def test_private_key_inline_negative_1(self) -> None:
        """Test too short key."""
        pattern = re.compile(PRIVATE_KEY_INLINE.regex)
        result = pattern.search("private_key = 'short'")
        assert result is None

    def test_private_key_inline_negative_2(self) -> None:
        """Test non-private key context."""
        pattern = re.compile(PRIVATE_KEY_INLINE.regex)
        result = pattern.search("public_key = 'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC7JvEeV0F3dA=='")
        assert result is None

    def test_encryption_key_positive_1(self) -> None:
        """Test encryption_key assignment."""
        pattern = re.compile(ENCRYPTION_KEY.regex)
        result = pattern.search("encryption_key = 'fake_aes_key_1234567890'")
        assert result is not None

    def test_encryption_key_positive_2(self) -> None:
        """Test aes_key assignment."""
        pattern = re.compile(ENCRYPTION_KEY.regex)
        result = pattern.search('aes_key: "test_encryption_key_value"')
        assert result is not None

    def test_encryption_key_negative_1(self) -> None:
        """Test too short key."""
        pattern = re.compile(ENCRYPTION_KEY.regex)
        result = pattern.search("encryption_key = 'short'")
        assert result is None

    def test_encryption_key_negative_2(self) -> None:
        """Test non-encryption context."""
        pattern = re.compile(ENCRYPTION_KEY.regex)
        result = pattern.search("api_key = 'some_long_value_here'")
        assert result is None

    def test_signing_key_positive_1(self) -> None:
        """Test signing_key assignment."""
        pattern = re.compile(SIGNING_KEY.regex)
        result = pattern.search("signing_key = 'fake_signing_key_12345'")
        assert result is not None

    def test_signing_key_positive_2(self) -> None:
        """Test signature_secret."""
        pattern = re.compile(SIGNING_KEY.regex)
        result = pattern.search('sign_secret: "test_sign_secret_value"')
        assert result is not None

    def test_signing_key_negative_1(self) -> None:
        """Test too short key."""
        pattern = re.compile(SIGNING_KEY.regex)
        result = pattern.search("signing_key = 'short'")
        assert result is None

    def test_signing_key_negative_2(self) -> None:
        """Test non-signing context."""
        pattern = re.compile(SIGNING_KEY.regex)
        result = pattern.search("api_secret = 'some_long_value'")
        assert result is None

    def test_master_key_positive_1(self) -> None:
        """Test master_key assignment."""
        pattern = re.compile(MASTER_KEY.regex)
        result = pattern.search("master_key = 'fake_master_key_123'")
        assert result is not None

    def test_master_key_positive_2(self) -> None:
        """Test master_secret."""
        pattern = re.compile(MASTER_KEY.regex)
        result = pattern.search('master_password: "test_master_pwd"')
        assert result is not None

    def test_master_key_negative_1(self) -> None:
        """Test too short."""
        pattern = re.compile(MASTER_KEY.regex)
        result = pattern.search("master_key = 'short'")
        assert result is None

    def test_master_key_negative_2(self) -> None:
        """Test non-master context."""
        pattern = re.compile(MASTER_KEY.regex)
        result = pattern.search("admin_key = 'some_long_value'")
        assert result is None

    def test_root_key_positive_1(self) -> None:
        """Test root_key assignment."""
        pattern = re.compile(ROOT_KEY.regex)
        result = pattern.search("root_key = 'fake_root_key_123456'")
        assert result is not None

    def test_root_key_positive_2(self) -> None:
        """Test root_password."""
        pattern = re.compile(ROOT_KEY.regex)
        result = pattern.search('root_secret: "test_root_secret_value"')
        assert result is not None

    def test_root_key_negative_1(self) -> None:
        """Test too short."""
        pattern = re.compile(ROOT_KEY.regex)
        result = pattern.search("root_key = 'short'")
        assert result is None

    def test_root_key_negative_2(self) -> None:
        """Test non-root context."""
        pattern = re.compile(ROOT_KEY.regex)
        result = pattern.search("admin_secret = 'some_long_value'")
        assert result is None

    def test_ssh_key_passphrase_positive_1(self) -> None:
        """Test ssh_passphrase."""
        pattern = re.compile(SSH_KEY_PASSPHRASE.regex)
        result = pattern.search("ssh_passphrase = 'fake_ssh_pass123'")
        assert result is not None

    def test_ssh_key_passphrase_positive_2(self) -> None:
        """Test key_password."""
        pattern = re.compile(SSH_KEY_PASSPHRASE.regex)
        result = pattern.search('key_password: "test_key_password"')
        assert result is not None

    def test_ssh_key_passphrase_negative_1(self) -> None:
        """Test too short."""
        pattern = re.compile(SSH_KEY_PASSPHRASE.regex)
        result = pattern.search("ssh_passphrase = 'abc'")
        assert result is None

    def test_ssh_key_passphrase_negative_2(self) -> None:
        """Test non-ssh context."""
        pattern = re.compile(SSH_KEY_PASSPHRASE.regex)
        result = pattern.search("user_password = 'somepassword'")
        assert result is None


class TestHighEntropyPattern:
    """Tests for high entropy string pattern."""

    def test_high_entropy_string_positive_1(self) -> None:
        """Test long alphanumeric secret."""
        pattern = re.compile(HIGH_ENTROPY_STRING.regex)
        result = pattern.search("secret = 'abcdefghijklmnopqrst1234567890'")
        assert result is not None

    def test_high_entropy_string_positive_2(self) -> None:
        """Test long alphanumeric key."""
        pattern = re.compile(HIGH_ENTROPY_STRING.regex)
        result = pattern.search('key: "AbCdEfGhIjKlMnOpQrStUv"')
        assert result is not None

    def test_high_entropy_string_negative_1(self) -> None:
        """Test too short."""
        pattern = re.compile(HIGH_ENTROPY_STRING.regex)
        result = pattern.search("secret = 'short'")
        assert result is None

    def test_high_entropy_string_negative_2(self) -> None:
        """Test non-secret context."""
        pattern = re.compile(HIGH_ENTROPY_STRING.regex)
        result = pattern.search("username = 'abcdefghijklmnopqrst1234'")
        assert result is None


class TestGenericPatternsCollection:
    """Tests for the GENERIC_PATTERNS collection."""

    def test_all_patterns_in_collection(self) -> None:
        """Test that all defined patterns are in the collection."""
        assert len(GENERIC_PATTERNS) == 29

    def test_all_patterns_are_generic_category(self) -> None:
        """Test that all patterns have GENERIC category."""
        for pattern in GENERIC_PATTERNS:
            assert pattern.category == PatternCategory.GENERIC

    def test_all_patterns_have_descriptions(self) -> None:
        """Test that all patterns have descriptions."""
        for pattern in GENERIC_PATTERNS:
            assert pattern.description != ""

    def test_all_patterns_have_valid_regex(self) -> None:
        """Test that all patterns have valid regex."""
        import re as regex_module

        for pattern in GENERIC_PATTERNS:
            try:
                regex_module.compile(pattern.regex)
            except regex_module.error as e:
                pytest.fail(f"Pattern {pattern.name} has invalid regex: {e}")

    def test_all_patterns_have_unique_names(self) -> None:
        """Test that all patterns have unique names."""
        names = [p.name for p in GENERIC_PATTERNS]
        assert len(names) == len(set(names))

    def test_patterns_to_dict_compatible(self) -> None:
        """Test that all patterns can be converted to dict format."""
        for pattern in GENERIC_PATTERNS:
            data = pattern.to_dict()
            assert "pattern" in data
            assert "severity" in data
            assert "description" in data
            assert "category" in data
            assert "confidence" in data

    def test_critical_patterns_severity(self) -> None:
        """Test that sensitive patterns have correct severity."""
        critical_patterns = [
            HARDCODED_PASSWORD,
            HEX_STRING_64,
            PRIVATE_KEY_INLINE,
            ENCRYPTION_KEY,
            SIGNING_KEY,
            MASTER_KEY,
            ROOT_KEY,
        ]
        for pattern in critical_patterns:
            assert pattern.severity == Severity.CRITICAL, f"{pattern.name} should be CRITICAL"

    def test_hash_patterns_low_severity(self) -> None:
        """Test that hash patterns have LOW severity."""
        hash_patterns = [MD5_HASH, SHA1_HASH, SHA256_HASH, SHA512_HASH]
        for pattern in hash_patterns:
            assert pattern.severity == Severity.LOW, f"{pattern.name} should be LOW"

    def test_uuid_patterns_low_severity(self) -> None:
        """Test that UUID patterns have LOW severity."""
        assert UUID_V4.severity == Severity.LOW
        assert UUID_GENERIC.severity == Severity.LOW
        assert UUID_WITH_CONTEXT.severity == Severity.MEDIUM  # Context-based is higher
