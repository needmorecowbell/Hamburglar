"""Tests for credential detection patterns.

This module contains comprehensive tests for all credential patterns defined in
the credentials pattern module. Each pattern is tested with at least 2 positive
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
from hamburglar.detectors.patterns.credentials import (
    ACCESS_TOKEN,
    API_TOKEN,
    AUTH_TOKEN,
    COOKIE_SECRET,
    CREDENTIAL_PATTERNS,
    DOCKER_CONFIG_AUTH,
    DOCKER_REGISTRY_AUTH,
    ENV_DATABASE_URL,
    ENV_PASSWORD,
    ENV_SECRET_KEY,
    GENERIC_DB_CONNECTION,
    HTTP_BASIC_AUTH,
    HTTP_BEARER_TOKEN,
    JDBC_CONNECTION_STRING,
    JWT_TOKEN,
    JWT_TOKEN_ASSIGNMENT,
    LDAP_BIND_PASSWORD,
    LDAP_CREDENTIALS,
    MONGODB_CONNECTION_STRING,
    MSSQL_CONNECTION_STRING,
    MYSQL_CONNECTION_STRING,
    OAUTH_CLIENT_SECRET,
    OAUTH_TOKEN,
    PASSWORD_ASSIGNMENT,
    PASSWORD_FIELD,
    POSTGRES_CONNECTION_STRING,
    REDIS_CONNECTION_STRING,
    REFRESH_TOKEN,
    SECRET_ASSIGNMENT,
    SESSION_SECRET,
    URL_WITH_CREDENTIALS,
)


# Helper function to build test tokens that bypass secret scanning
def fake_token(*parts: str) -> str:
    """Build a test token from parts to bypass secret scanning."""
    return "".join(parts)


class TestPasswordPatterns:
    """Tests for password assignment patterns."""

    def test_password_assignment_positive_1(self) -> None:
        """Test password assignment with single quotes."""
        pattern = re.compile(PASSWORD_ASSIGNMENT.regex)
        result = pattern.search("password = 'fakepassword123'")
        assert result is not None

    def test_password_assignment_positive_2(self) -> None:
        """Test password assignment with double quotes."""
        pattern = re.compile(PASSWORD_ASSIGNMENT.regex)
        result = pattern.search('password: "mysupersecretpwd"')
        assert result is not None

    def test_password_assignment_positive_3(self) -> None:
        """Test passwd variant."""
        pattern = re.compile(PASSWORD_ASSIGNMENT.regex)
        result = pattern.search("passwd = 'anotherfakepass'")
        assert result is not None

    def test_password_assignment_negative_1(self) -> None:
        """Test password assignment too short."""
        pattern = re.compile(PASSWORD_ASSIGNMENT.regex)
        result = pattern.search("password = 'short'")
        assert result is None

    def test_password_assignment_negative_2(self) -> None:
        """Test password assignment without value."""
        pattern = re.compile(PASSWORD_ASSIGNMENT.regex)
        result = pattern.search("password = ''")
        assert result is None

    def test_password_field_positive_1(self) -> None:
        """Test password field matches."""
        pattern = re.compile(PASSWORD_FIELD.regex)
        result = pattern.search("password = supersecret123")
        assert result is not None

    def test_password_field_positive_2(self) -> None:
        """Test pass field matches."""
        pattern = re.compile(PASSWORD_FIELD.regex)
        result = pattern.search("pass-word = 'testpassword'")
        assert result is not None

    def test_password_field_negative_1(self) -> None:
        """Test password field too short."""
        pattern = re.compile(PASSWORD_FIELD.regex)
        result = pattern.search("password = tiny")
        assert result is None

    def test_password_field_negative_2(self) -> None:
        """Test unrelated field."""
        pattern = re.compile(PASSWORD_FIELD.regex)
        result = pattern.search("username = somevalue")
        assert result is None

    def test_secret_assignment_positive_1(self) -> None:
        """Test secret assignment matches."""
        pattern = re.compile(SECRET_ASSIGNMENT.regex)
        result = pattern.search("secret = 'mysupersecretvalue'")
        assert result is not None

    def test_secret_assignment_positive_2(self) -> None:
        """Test secret_key assignment."""
        pattern = re.compile(SECRET_ASSIGNMENT.regex)
        result = pattern.search('secret_key: "anothersecretkey123"')
        assert result is not None

    def test_secret_assignment_negative_1(self) -> None:
        """Test secret assignment too short."""
        pattern = re.compile(SECRET_ASSIGNMENT.regex)
        result = pattern.search("secret = 'short'")
        assert result is None

    def test_secret_assignment_negative_2(self) -> None:
        """Test non-secret field."""
        pattern = re.compile(SECRET_ASSIGNMENT.regex)
        result = pattern.search("api_key = 'somevalue'")
        assert result is None

    def test_password_assignment_metadata(self) -> None:
        """Test password assignment pattern metadata."""
        assert PASSWORD_ASSIGNMENT.severity == Severity.CRITICAL
        assert PASSWORD_ASSIGNMENT.category == PatternCategory.CREDENTIALS
        assert PASSWORD_ASSIGNMENT.confidence == Confidence.MEDIUM


class TestDatabaseConnectionPatterns:
    """Tests for database connection string patterns."""

    def test_postgres_connection_positive_1(self) -> None:
        """Test PostgreSQL connection string."""
        pattern = re.compile(POSTGRES_CONNECTION_STRING.regex)
        result = pattern.search("postgres://user:fakepass@localhost/mydb")
        assert result is not None

    def test_postgres_connection_positive_2(self) -> None:
        """Test PostgreSQL connection with port."""
        pattern = re.compile(POSTGRES_CONNECTION_STRING.regex)
        result = pattern.search("postgresql://admin:password123@db.example.com:5432/production")
        assert result is not None

    def test_postgres_connection_negative_1(self) -> None:
        """Test PostgreSQL connection without password."""
        pattern = re.compile(POSTGRES_CONNECTION_STRING.regex)
        result = pattern.search("postgres://localhost/mydb")
        assert result is None

    def test_postgres_connection_negative_2(self) -> None:
        """Test wrong protocol."""
        pattern = re.compile(POSTGRES_CONNECTION_STRING.regex)
        result = pattern.search("mysql://user:pass@localhost/mydb")
        assert result is None

    def test_mysql_connection_positive_1(self) -> None:
        """Test MySQL connection string."""
        pattern = re.compile(MYSQL_CONNECTION_STRING.regex)
        result = pattern.search("mysql://root:fakepassword@localhost/testdb")
        assert result is not None

    def test_mysql_connection_positive_2(self) -> None:
        """Test MySQL connection with port."""
        pattern = re.compile(MYSQL_CONNECTION_STRING.regex)
        result = pattern.search("mysql://admin:secretpwd@db.example.com:3306/app")
        assert result is not None

    def test_mysql_connection_negative_1(self) -> None:
        """Test MySQL without credentials."""
        pattern = re.compile(MYSQL_CONNECTION_STRING.regex)
        result = pattern.search("mysql://localhost/mydb")
        assert result is None

    def test_mysql_connection_negative_2(self) -> None:
        """Test wrong protocol."""
        pattern = re.compile(MYSQL_CONNECTION_STRING.regex)
        result = pattern.search("postgres://user:pass@localhost/mydb")
        assert result is None

    def test_mongodb_connection_positive_1(self) -> None:
        """Test MongoDB connection string."""
        pattern = re.compile(MONGODB_CONNECTION_STRING.regex)
        result = pattern.search("mongodb://user:fakepassword@localhost:27017/admin")
        assert result is not None

    def test_mongodb_connection_positive_2(self) -> None:
        """Test MongoDB SRV connection."""
        pattern = re.compile(MONGODB_CONNECTION_STRING.regex)
        result = pattern.search("mongodb+srv://admin:secretpwd@cluster0.mongodb.net/mydb")
        assert result is not None

    def test_mongodb_connection_negative_1(self) -> None:
        """Test MongoDB without credentials."""
        pattern = re.compile(MONGODB_CONNECTION_STRING.regex)
        result = pattern.search("mongodb://localhost:27017/admin")
        assert result is None

    def test_mongodb_connection_negative_2(self) -> None:
        """Test wrong protocol."""
        pattern = re.compile(MONGODB_CONNECTION_STRING.regex)
        result = pattern.search("mysql://user:pass@localhost/mydb")
        assert result is None

    def test_redis_connection_positive_1(self) -> None:
        """Test Redis connection with credentials."""
        pattern = re.compile(REDIS_CONNECTION_STRING.regex)
        result = pattern.search("redis://user:fakepass@localhost:6379/0")
        assert result is not None

    def test_redis_connection_positive_2(self) -> None:
        """Test Redis connection without credentials."""
        pattern = re.compile(REDIS_CONNECTION_STRING.regex)
        result = pattern.search("redis://localhost:6379")
        assert result is not None

    def test_redis_connection_negative_1(self) -> None:
        """Test wrong protocol."""
        pattern = re.compile(REDIS_CONNECTION_STRING.regex)
        result = pattern.search("mysql://user:pass@localhost")
        assert result is None

    def test_redis_connection_negative_2(self) -> None:
        """Test incomplete Redis URL."""
        pattern = re.compile(REDIS_CONNECTION_STRING.regex)
        result = pattern.search("redis://")
        assert result is None

    def test_mssql_connection_positive_1(self) -> None:
        """Test MSSQL connection string."""
        pattern = re.compile(MSSQL_CONNECTION_STRING.regex)
        result = pattern.search("Server=localhost;Database=mydb;Password=fakepassword123")
        assert result is not None

    def test_mssql_connection_positive_2(self) -> None:
        """Test MSSQL with Data Source."""
        pattern = re.compile(MSSQL_CONNECTION_STRING.regex)
        result = pattern.search("Data Source=db.example.com;User Id=admin;Pwd=secretpwd")
        assert result is not None

    def test_mssql_connection_negative_1(self) -> None:
        """Test MSSQL without password."""
        pattern = re.compile(MSSQL_CONNECTION_STRING.regex)
        result = pattern.search("Server=localhost;Database=mydb")
        assert result is None

    def test_mssql_connection_negative_2(self) -> None:
        """Test non-MSSQL connection."""
        pattern = re.compile(MSSQL_CONNECTION_STRING.regex)
        result = pattern.search("host=localhost;port=5432")
        assert result is None

    def test_jdbc_connection_positive_1(self) -> None:
        """Test JDBC connection with password."""
        pattern = re.compile(JDBC_CONNECTION_STRING.regex)
        result = pattern.search("jdbc:mysql://localhost:3306/mydb?user=admin&password=secretpass")
        assert result is not None

    def test_jdbc_connection_positive_2(self) -> None:
        """Test JDBC with pwd parameter."""
        pattern = re.compile(JDBC_CONNECTION_STRING.regex)
        result = pattern.search("jdbc:postgresql://db.example.com/app?pwd=fakepassword")
        assert result is not None

    def test_jdbc_connection_negative_1(self) -> None:
        """Test JDBC without password."""
        pattern = re.compile(JDBC_CONNECTION_STRING.regex)
        result = pattern.search("jdbc:mysql://localhost:3306/mydb?user=admin")
        assert result is None

    def test_jdbc_connection_negative_2(self) -> None:
        """Test non-JDBC URL."""
        pattern = re.compile(JDBC_CONNECTION_STRING.regex)
        result = pattern.search("mysql://localhost:3306/mydb?password=test")
        assert result is None

    def test_generic_db_connection_positive_1(self) -> None:
        """Test generic database URL."""
        pattern = re.compile(GENERIC_DB_CONNECTION.regex)
        result = pattern.search("database_url = 'postgres://user:pass@localhost/db'")
        assert result is not None

    def test_generic_db_connection_positive_2(self) -> None:
        """Test DB connection assignment."""
        pattern = re.compile(GENERIC_DB_CONNECTION.regex)
        result = pattern.search('DB_URI: "mysql://admin:secret@db.example.com/app"')
        assert result is not None

    def test_generic_db_connection_negative_1(self) -> None:
        """Test without database keyword."""
        pattern = re.compile(GENERIC_DB_CONNECTION.regex)
        result = pattern.search("url = 'postgres://user:pass@localhost/db'")
        assert result is None

    def test_generic_db_connection_negative_2(self) -> None:
        """Test without credentials."""
        pattern = re.compile(GENERIC_DB_CONNECTION.regex)
        result = pattern.search("database_url = 'postgres://localhost/db'")
        assert result is None


class TestHTTPAuthPatterns:
    """Tests for HTTP authentication patterns."""

    def test_http_basic_auth_positive_1(self) -> None:
        """Test HTTP Basic Auth header."""
        pattern = re.compile(HTTP_BASIC_AUTH.regex)
        result = pattern.search("Authorization: Basic dXNlcjpwYXNzd29yZDEyMzQ1Njc4OQ==")
        assert result is not None

    def test_http_basic_auth_positive_2(self) -> None:
        """Test auth assignment."""
        pattern = re.compile(HTTP_BASIC_AUTH.regex)
        result = pattern.search('auth = "Basic YWRtaW46c2VjcmV0cGFzc3dvcmQ="')
        assert result is not None

    def test_http_basic_auth_negative_1(self) -> None:
        """Test Basic without credentials."""
        pattern = re.compile(HTTP_BASIC_AUTH.regex)
        result = pattern.search("Authorization: Basic short")
        assert result is None

    def test_http_basic_auth_negative_2(self) -> None:
        """Test Bearer instead of Basic."""
        pattern = re.compile(HTTP_BASIC_AUTH.regex)
        result = pattern.search("Authorization: Bearer dXNlcjpwYXNzd29yZDEyMzQ1Njc4OQ==")
        assert result is None

    def test_http_bearer_token_positive_1(self) -> None:
        """Test HTTP Bearer token header."""
        pattern = re.compile(HTTP_BEARER_TOKEN.regex)
        result = pattern.search("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9")
        assert result is not None

    def test_http_bearer_token_positive_2(self) -> None:
        """Test auth assignment with Bearer."""
        pattern = re.compile(HTTP_BEARER_TOKEN.regex)
        result = pattern.search('auth = "Bearer some_long_token_value_here_12345"')
        assert result is not None

    def test_http_bearer_token_negative_1(self) -> None:
        """Test Bearer with short token."""
        pattern = re.compile(HTTP_BEARER_TOKEN.regex)
        result = pattern.search("Authorization: Bearer short")
        assert result is None

    def test_http_bearer_token_negative_2(self) -> None:
        """Test Basic instead of Bearer."""
        pattern = re.compile(HTTP_BEARER_TOKEN.regex)
        result = pattern.search("Authorization: Basic some_long_token_value")
        assert result is None


class TestJWTPatterns:
    """Tests for JWT token patterns."""

    def test_jwt_token_positive_1(self) -> None:
        """Test JWT token format."""
        pattern = re.compile(JWT_TOKEN.regex)
        # Fake JWT structure
        jwt = fake_token(
            "eyJhbGciOiJIUzI1NiJ9",
            ".",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            ".",
            "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        )
        result = pattern.search(jwt)
        assert result is not None

    def test_jwt_token_positive_2(self) -> None:
        """Test JWT token in context."""
        pattern = re.compile(JWT_TOKEN.regex)
        jwt = fake_token(
            "token: eyJhbGciOiJSUzI1NiJ9", ".", "eyJpc3MiOiJmYWtlIn0", ".", "signature_here_123"
        )
        result = pattern.search(jwt)
        assert result is not None

    def test_jwt_token_negative_1(self) -> None:
        """Test non-JWT token."""
        pattern = re.compile(JWT_TOKEN.regex)
        result = pattern.search("xyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")
        assert result is None

    def test_jwt_token_negative_2(self) -> None:
        """Test incomplete JWT."""
        pattern = re.compile(JWT_TOKEN.regex)
        result = pattern.search("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0")
        assert result is None

    def test_jwt_token_assignment_positive_1(self) -> None:
        """Test JWT token assignment."""
        pattern = re.compile(JWT_TOKEN_ASSIGNMENT.regex)
        jwt = fake_token(
            "jwt = 'eyJhbGciOiJIUzI1NiJ9",
            ".",
            "eyJzdWIiOiIxMjM0NTY3ODkwIn0",
            ".",
            "SflKxwRJSMeKKF2QT'",
        )
        result = pattern.search(jwt)
        assert result is not None

    def test_jwt_token_assignment_positive_2(self) -> None:
        """Test access_token assignment with JWT."""
        pattern = re.compile(JWT_TOKEN_ASSIGNMENT.regex)
        jwt = fake_token(
            'access_token: "eyJhbGciOiJSUzI1NiJ9', ".", "eyJpc3MiOiJmYWtlIn0", ".", 'sig123"'
        )
        result = pattern.search(jwt)
        assert result is not None

    def test_jwt_token_assignment_negative_1(self) -> None:
        """Test non-JWT assignment."""
        pattern = re.compile(JWT_TOKEN_ASSIGNMENT.regex)
        result = pattern.search("token = 'not_a_jwt_token'")
        assert result is None

    def test_jwt_token_assignment_negative_2(self) -> None:
        """Test JWT without context."""
        pattern = re.compile(JWT_TOKEN_ASSIGNMENT.regex)
        result = pattern.search("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.sig")
        assert result is None


class TestOAuthPatterns:
    """Tests for OAuth patterns."""

    def test_oauth_token_positive_1(self) -> None:
        """Test OAuth token assignment."""
        pattern = re.compile(OAUTH_TOKEN.regex)
        result = pattern.search("oauth_token = 'ya29.a0AfH6SMBx1234567890abcdefghij'")
        assert result is not None

    def test_oauth_token_positive_2(self) -> None:
        """Test OAuth access token."""
        pattern = re.compile(OAUTH_TOKEN.regex)
        result = pattern.search('oauth_access_token: "fake_token_value_1234567890"')
        assert result is not None

    def test_oauth_token_negative_1(self) -> None:
        """Test OAuth token too short."""
        pattern = re.compile(OAUTH_TOKEN.regex)
        result = pattern.search("oauth_token = 'short'")
        assert result is None

    def test_oauth_token_negative_2(self) -> None:
        """Test non-OAuth field."""
        pattern = re.compile(OAUTH_TOKEN.regex)
        result = pattern.search("api_key = 'some_long_value_here_12345'")
        assert result is None

    def test_oauth_client_secret_positive_1(self) -> None:
        """Test OAuth client secret."""
        pattern = re.compile(OAUTH_CLIENT_SECRET.regex)
        result = pattern.search("client_secret = 'fake_client_secret_123'")
        assert result is not None

    def test_oauth_client_secret_positive_2(self) -> None:
        """Test OAuth client secret alternate."""
        pattern = re.compile(OAUTH_CLIENT_SECRET.regex)
        result = pattern.search('oauth_client_secret: "GOCSPX-abcdefghijklmnopqr"')
        assert result is not None

    def test_oauth_client_secret_negative_1(self) -> None:
        """Test client secret too short."""
        pattern = re.compile(OAUTH_CLIENT_SECRET.regex)
        result = pattern.search("client_secret = 'short'")
        assert result is None

    def test_oauth_client_secret_negative_2(self) -> None:
        """Test non-secret field."""
        pattern = re.compile(OAUTH_CLIENT_SECRET.regex)
        result = pattern.search("client_id = 'some_id_value_1234'")
        assert result is None

    def test_refresh_token_positive_1(self) -> None:
        """Test refresh token assignment."""
        pattern = re.compile(REFRESH_TOKEN.regex)
        result = pattern.search("refresh_token = 'fake_refresh_token_123456'")
        assert result is not None

    def test_refresh_token_positive_2(self) -> None:
        """Test refresh-token with hyphen."""
        pattern = re.compile(REFRESH_TOKEN.regex)
        result = pattern.search('refresh-token: "1_0gxxxxxxxxxxxxxxxxxxxxxxxx"')
        assert result is not None

    def test_refresh_token_negative_1(self) -> None:
        """Test refresh token too short."""
        pattern = re.compile(REFRESH_TOKEN.regex)
        result = pattern.search("refresh_token = 'short'")
        assert result is None

    def test_refresh_token_negative_2(self) -> None:
        """Test non-refresh field."""
        pattern = re.compile(REFRESH_TOKEN.regex)
        result = pattern.search("access_token = 'some_long_value_12345'")
        assert result is None


class TestAPITokenPatterns:
    """Tests for generic API token patterns."""

    def test_api_token_positive_1(self) -> None:
        """Test API token assignment."""
        pattern = re.compile(API_TOKEN.regex)
        result = pattern.search("api_token = 'sk_live_12345678901234567890'")
        assert result is not None

    def test_api_token_positive_2(self) -> None:
        """Test api-token with hyphen."""
        pattern = re.compile(API_TOKEN.regex)
        result = pattern.search('api-token: "fake_api_token_value_123"')
        assert result is not None

    def test_api_token_negative_1(self) -> None:
        """Test API token too short."""
        pattern = re.compile(API_TOKEN.regex)
        result = pattern.search("api_token = 'short'")
        assert result is None

    def test_api_token_negative_2(self) -> None:
        """Test non-api_token field."""
        pattern = re.compile(API_TOKEN.regex)
        result = pattern.search("secret_key = 'some_value_12345'")
        assert result is None

    def test_auth_token_positive_1(self) -> None:
        """Test auth token assignment."""
        pattern = re.compile(AUTH_TOKEN.regex)
        result = pattern.search("auth_token = 'fake_auth_token_value_123'")
        assert result is not None

    def test_auth_token_positive_2(self) -> None:
        """Test authentication_token."""
        pattern = re.compile(AUTH_TOKEN.regex)
        result = pattern.search('authentication_token: "long_token_value_12345678"')
        assert result is not None

    def test_auth_token_negative_1(self) -> None:
        """Test auth token too short."""
        pattern = re.compile(AUTH_TOKEN.regex)
        result = pattern.search("auth_token = 'short'")
        assert result is None

    def test_auth_token_negative_2(self) -> None:
        """Test non-auth field."""
        pattern = re.compile(AUTH_TOKEN.regex)
        result = pattern.search("user_token = 'some_long_value'")
        assert result is None

    def test_access_token_positive_1(self) -> None:
        """Test access token assignment."""
        pattern = re.compile(ACCESS_TOKEN.regex)
        result = pattern.search("access_token = 'fake_access_token_value_123'")
        assert result is not None

    def test_access_token_positive_2(self) -> None:
        """Test access-token with hyphen."""
        pattern = re.compile(ACCESS_TOKEN.regex)
        result = pattern.search('access-token: "ya29.fake_access_token_12345"')
        assert result is not None

    def test_access_token_negative_1(self) -> None:
        """Test access token too short."""
        pattern = re.compile(ACCESS_TOKEN.regex)
        result = pattern.search("access_token = 'short'")
        assert result is None

    def test_access_token_negative_2(self) -> None:
        """Test non-access field."""
        pattern = re.compile(ACCESS_TOKEN.regex)
        result = pattern.search("user_id = 'some_long_value_123'")
        assert result is None


class TestURLCredentialsPattern:
    """Tests for URL with credentials pattern."""

    def test_url_with_credentials_positive_1(self) -> None:
        """Test HTTPS URL with credentials."""
        pattern = re.compile(URL_WITH_CREDENTIALS.regex)
        result = pattern.search("https://user:fakepassword@example.com/api")
        assert result is not None

    def test_url_with_credentials_positive_2(self) -> None:
        """Test FTP URL with credentials."""
        pattern = re.compile(URL_WITH_CREDENTIALS.regex)
        result = pattern.search("ftp://admin:secretpwd@ftp.example.com/files")
        assert result is not None

    def test_url_with_credentials_positive_3(self) -> None:
        """Test HTTP URL with credentials."""
        pattern = re.compile(URL_WITH_CREDENTIALS.regex)
        result = pattern.search("http://root:password123@localhost:8080/admin")
        assert result is not None

    def test_url_with_credentials_negative_1(self) -> None:
        """Test URL without credentials."""
        pattern = re.compile(URL_WITH_CREDENTIALS.regex)
        result = pattern.search("https://example.com/api")
        assert result is None

    def test_url_with_credentials_negative_2(self) -> None:
        """Test URL with @ but no password."""
        pattern = re.compile(URL_WITH_CREDENTIALS.regex)
        result = pattern.search("https://user@example.com")
        assert result is None


class TestEnvPatterns:
    """Tests for .env file patterns."""

    def test_env_secret_key_positive_1(self) -> None:
        """Test SECRET_KEY in .env format."""
        pattern = re.compile(ENV_SECRET_KEY.regex, re.MULTILINE)
        result = pattern.search("SECRET_KEY=fake_secret_key_value_123")
        assert result is not None

    def test_env_secret_key_positive_2(self) -> None:
        """Test API_TOKEN in .env format."""
        pattern = re.compile(ENV_SECRET_KEY.regex, re.MULTILINE)
        result = pattern.search("API_TOKEN_SECRET='my_secret_token_value'")
        assert result is not None

    def test_env_secret_key_negative_1(self) -> None:
        """Test non-secret env var."""
        pattern = re.compile(ENV_SECRET_KEY.regex, re.MULTILINE)
        result = pattern.search("DEBUG=true")
        assert result is None

    def test_env_secret_key_negative_2(self) -> None:
        """Test secret too short."""
        pattern = re.compile(ENV_SECRET_KEY.regex, re.MULTILINE)
        result = pattern.search("SECRET_KEY=short")
        assert result is None

    def test_env_database_url_positive_1(self) -> None:
        """Test DATABASE_URL in .env format."""
        pattern = re.compile(ENV_DATABASE_URL.regex, re.MULTILINE)
        result = pattern.search("DATABASE_URL=postgres://user:pass@localhost/db")
        assert result is not None

    def test_env_database_url_positive_2(self) -> None:
        """Test DB_CONNECTION in .env format."""
        pattern = re.compile(ENV_DATABASE_URL.regex, re.MULTILINE)
        result = pattern.search("DB_URI='mysql://admin:secret@db.example.com/app'")
        assert result is not None

    def test_env_database_url_negative_1(self) -> None:
        """Test non-database env var."""
        pattern = re.compile(ENV_DATABASE_URL.regex, re.MULTILINE)
        result = pattern.search("API_URL=https://api.example.com")
        assert result is None

    def test_env_database_url_negative_2(self) -> None:
        """Test DATABASE_URL without protocol."""
        pattern = re.compile(ENV_DATABASE_URL.regex, re.MULTILINE)
        result = pattern.search("DATABASE_URL=localhost:5432/mydb")
        assert result is None

    def test_env_password_positive_1(self) -> None:
        """Test PASSWORD in .env format."""
        pattern = re.compile(ENV_PASSWORD.regex, re.MULTILINE)
        result = pattern.search("PASSWORD=mysecretpassword")
        assert result is not None

    def test_env_password_positive_2(self) -> None:
        """Test DB_PASSWORD in .env format."""
        pattern = re.compile(ENV_PASSWORD.regex, re.MULTILINE)
        result = pattern.search("DB_PASSWORD='fakepassword123'")
        assert result is not None

    def test_env_password_negative_1(self) -> None:
        """Test non-password env var."""
        pattern = re.compile(ENV_PASSWORD.regex, re.MULTILINE)
        result = pattern.search("USERNAME=admin")
        assert result is None

    def test_env_password_negative_2(self) -> None:
        """Test password too short."""
        pattern = re.compile(ENV_PASSWORD.regex, re.MULTILINE)
        result = pattern.search("PASSWORD=abc")
        assert result is None


class TestDockerPatterns:
    """Tests for Docker registry auth patterns."""

    def test_docker_registry_auth_positive_1(self) -> None:
        """Test Docker registry auth field."""
        pattern = re.compile(DOCKER_REGISTRY_AUTH.regex)
        result = pattern.search('"auth": "dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY="')
        assert result is not None

    def test_docker_registry_auth_positive_2(self) -> None:
        """Test Docker auth with spaces."""
        pattern = re.compile(DOCKER_REGISTRY_AUTH.regex)
        result = pattern.search('"auth" : "YWRtaW46c2VjcmV0cGFzc3dvcmQ="')
        assert result is not None

    def test_docker_registry_auth_negative_1(self) -> None:
        """Test auth too short."""
        pattern = re.compile(DOCKER_REGISTRY_AUTH.regex)
        result = pattern.search('"auth": "short"')
        assert result is None

    def test_docker_registry_auth_negative_2(self) -> None:
        """Test non-auth field."""
        pattern = re.compile(DOCKER_REGISTRY_AUTH.regex)
        result = pattern.search('"username": "dXNlcm5hbWU6cGFzc3dvcmQ="')
        assert result is None

    def test_docker_config_auth_positive_1(self) -> None:
        """Test Docker config.json auth structure."""
        pattern = re.compile(DOCKER_CONFIG_AUTH.regex)
        config = '{"auths": {"docker.io": {"auth": "dXNlcm5hbWU6cGFzc3dvcmQxMjM0NTY="}}}'
        result = pattern.search(config)
        assert result is not None

    def test_docker_config_auth_positive_2(self) -> None:
        """Test Docker config with registry URL."""
        pattern = re.compile(DOCKER_CONFIG_AUTH.regex)
        config = '{"auths": {"ghcr.io": {"auth": "YWRtaW46c2VjcmV0cGFzc3dvcmQ="}}}'
        result = pattern.search(config)
        assert result is not None

    def test_docker_config_auth_negative_1(self) -> None:
        """Test Docker config without auth."""
        pattern = re.compile(DOCKER_CONFIG_AUTH.regex)
        result = pattern.search('{"auths": {"docker.io": {"username": "user"}}}')
        assert result is None

    def test_docker_config_auth_negative_2(self) -> None:
        """Test non-auths structure."""
        pattern = re.compile(DOCKER_CONFIG_AUTH.regex)
        result = pattern.search('{"auth": "dXNlcm5hbWU6cGFzc3dvcmQ="}')
        assert result is None


class TestSessionCookiePatterns:
    """Tests for session and cookie secret patterns."""

    def test_session_secret_positive_1(self) -> None:
        """Test session secret assignment."""
        pattern = re.compile(SESSION_SECRET.regex)
        result = pattern.search("session_secret = 'fake_session_secret_value'")
        assert result is not None

    def test_session_secret_positive_2(self) -> None:
        """Test session-secret with hyphen."""
        pattern = re.compile(SESSION_SECRET.regex)
        result = pattern.search('session-secret: "my_secret_session_key"')
        assert result is not None

    def test_session_secret_negative_1(self) -> None:
        """Test session secret too short."""
        pattern = re.compile(SESSION_SECRET.regex)
        result = pattern.search("session_secret = 'short'")
        assert result is None

    def test_session_secret_negative_2(self) -> None:
        """Test non-session field."""
        pattern = re.compile(SESSION_SECRET.regex)
        result = pattern.search("api_secret = 'some_secret_value'")
        assert result is None

    def test_cookie_secret_positive_1(self) -> None:
        """Test cookie secret assignment."""
        pattern = re.compile(COOKIE_SECRET.regex)
        result = pattern.search("cookie_secret = 'fake_cookie_secret_value'")
        assert result is not None

    def test_cookie_secret_positive_2(self) -> None:
        """Test cookie-secret with hyphen."""
        pattern = re.compile(COOKIE_SECRET.regex)
        result = pattern.search('cookie-secret: "my_secret_cookie_key"')
        assert result is not None

    def test_cookie_secret_negative_1(self) -> None:
        """Test cookie secret too short."""
        pattern = re.compile(COOKIE_SECRET.regex)
        result = pattern.search("cookie_secret = 'short'")
        assert result is None

    def test_cookie_secret_negative_2(self) -> None:
        """Test non-cookie field."""
        pattern = re.compile(COOKIE_SECRET.regex)
        result = pattern.search("session_key = 'some_secret_value'")
        assert result is None


class TestLDAPPatterns:
    """Tests for LDAP credential patterns."""

    def test_ldap_credentials_positive_1(self) -> None:
        """Test LDAP URL with credentials."""
        pattern = re.compile(LDAP_CREDENTIALS.regex)
        result = pattern.search("ldap://admin:fakepassword@ldap.example.com:389")
        assert result is not None

    def test_ldap_credentials_positive_2(self) -> None:
        """Test LDAPS URL with credentials."""
        pattern = re.compile(LDAP_CREDENTIALS.regex)
        result = pattern.search("ldaps://cn=admin:secretpwd@ldap.example.com")
        assert result is not None

    def test_ldap_credentials_negative_1(self) -> None:
        """Test LDAP URL without password."""
        pattern = re.compile(LDAP_CREDENTIALS.regex)
        result = pattern.search("ldap://ldap.example.com:389")
        assert result is None

    def test_ldap_credentials_negative_2(self) -> None:
        """Test non-LDAP URL."""
        pattern = re.compile(LDAP_CREDENTIALS.regex)
        result = pattern.search("https://admin:pass@example.com")
        assert result is None

    def test_ldap_bind_password_positive_1(self) -> None:
        """Test LDAP bind password."""
        pattern = re.compile(LDAP_BIND_PASSWORD.regex)
        result = pattern.search("ldap_bind_password = 'fakebindpassword'")
        assert result is not None

    def test_ldap_bind_password_positive_2(self) -> None:
        """Test bind password variant."""
        pattern = re.compile(LDAP_BIND_PASSWORD.regex)
        result = pattern.search('bind_password: "secretbindpwd"')
        assert result is not None

    def test_ldap_bind_password_negative_1(self) -> None:
        """Test bind password too short."""
        pattern = re.compile(LDAP_BIND_PASSWORD.regex)
        result = pattern.search("ldap_bind_password = 'abc'")
        assert result is None

    def test_ldap_bind_password_negative_2(self) -> None:
        """Test non-bind field."""
        pattern = re.compile(LDAP_BIND_PASSWORD.regex)
        result = pattern.search("admin_password = 'somepassword'")
        assert result is None


class TestCredentialPatternsCollection:
    """Tests for the CREDENTIAL_PATTERNS collection."""

    def test_all_patterns_in_collection(self) -> None:
        """Test that all defined patterns are in the collection."""
        assert len(CREDENTIAL_PATTERNS) == 30

    def test_all_patterns_are_credentials_category(self) -> None:
        """Test that all patterns have CREDENTIALS category."""
        for pattern in CREDENTIAL_PATTERNS:
            assert pattern.category == PatternCategory.CREDENTIALS

    def test_all_patterns_have_descriptions(self) -> None:
        """Test that all patterns have descriptions."""
        for pattern in CREDENTIAL_PATTERNS:
            assert pattern.description != ""

    def test_all_patterns_have_valid_regex(self) -> None:
        """Test that all patterns have valid regex."""
        import re as regex_module

        for pattern in CREDENTIAL_PATTERNS:
            try:
                regex_module.compile(pattern.regex)
            except regex_module.error as e:
                pytest.fail(f"Pattern {pattern.name} has invalid regex: {e}")

    def test_all_patterns_have_unique_names(self) -> None:
        """Test that all patterns have unique names."""
        names = [p.name for p in CREDENTIAL_PATTERNS]
        assert len(names) == len(set(names))

    def test_patterns_to_dict_compatible(self) -> None:
        """Test that all patterns can be converted to dict format."""
        for pattern in CREDENTIAL_PATTERNS:
            data = pattern.to_dict()
            assert "pattern" in data
            assert "severity" in data
            assert "description" in data
            assert "category" in data
            assert "confidence" in data
