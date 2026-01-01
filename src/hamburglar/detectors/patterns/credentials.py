"""Credential detection patterns.

This module contains patterns for detecting credentials, passwords, authentication
tokens, database connection strings, and other sensitive authentication data.
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory

# Generic Password Assignment Patterns
PASSWORD_ASSIGNMENT = Pattern(
    name="password_assignment",
    regex=r"(?i)(?:password|passwd|pwd)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="Password Assignment - hardcoded password value in code or config",
    confidence=Confidence.MEDIUM,
)

PASSWORD_FIELD = Pattern(
    name="password_field",
    regex=r"(?i)(?:password|passwd|pwd|pass)[_-]?(?:word)?['\"]?\s*[:=]\s*['\"]?[^\s'\"]{8,}['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="Password Field - potential password field with value",
    confidence=Confidence.LOW,
)

SECRET_ASSIGNMENT = Pattern(
    name="secret_assignment",
    regex=r"(?i)(?:secret|secret_key|secretkey)['\"]?\s*[:=]\s*['\"]([^'\"]{8,})['\"]",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="Secret Assignment - hardcoded secret value in code or config",
    confidence=Confidence.MEDIUM,
)


# Database Connection String Patterns
POSTGRES_CONNECTION_STRING = Pattern(
    name="postgres_connection_string",
    regex=r"postgres(?:ql)?://[^:]+:[^@]+@[^/]+(?:/[^\s\"']+)?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="PostgreSQL Connection String - database connection with credentials",
    confidence=Confidence.HIGH,
)

MYSQL_CONNECTION_STRING = Pattern(
    name="mysql_connection_string",
    regex=r"mysql://[^:]+:[^@]+@[^/]+(?:/[^\s\"']+)?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="MySQL Connection String - database connection with credentials",
    confidence=Confidence.HIGH,
)

MONGODB_CONNECTION_STRING = Pattern(
    name="mongodb_connection_string",
    regex=r"mongodb(?:\+srv)?://[^:]+:[^@]+@[^\s\"']+",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="MongoDB Connection String - database connection with credentials",
    confidence=Confidence.HIGH,
)

REDIS_CONNECTION_STRING = Pattern(
    name="redis_connection_string",
    regex=r"redis://(?:[^:]+:[^@]+@)?[^/]+(?:/[0-9]+)?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="Redis Connection String - cache/database connection",
    confidence=Confidence.MEDIUM,
)

MSSQL_CONNECTION_STRING = Pattern(
    name="mssql_connection_string",
    regex=r"(?i)(?:Server|Data Source)=[^;]+;.*(?:Password|Pwd)=[^;]+",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="MSSQL Connection String - SQL Server connection with credentials",
    confidence=Confidence.HIGH,
)

JDBC_CONNECTION_STRING = Pattern(
    name="jdbc_connection_string",
    regex=r"jdbc:[a-z]+://[^?]+\?.*(?:password|pwd)=[^&\s]+",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="JDBC Connection String - Java database connection with credentials",
    confidence=Confidence.HIGH,
)

GENERIC_DB_CONNECTION = Pattern(
    name="generic_db_connection",
    regex=r"(?i)(?:database|db)[_-]?(?:url|uri|connection|conn)['\"]?\s*[:=]\s*['\"]?[a-z]+://[^:]+:[^@]+@",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="Generic Database Connection - database URL with embedded credentials",
    confidence=Confidence.HIGH,
)


# HTTP Authentication Patterns
HTTP_BASIC_AUTH = Pattern(
    name="http_basic_auth",
    regex=r"(?i)(?:Authorization|auth)['\"]?\s*[:=]\s*['\"]?Basic\s+[A-Za-z0-9+/=]{20,}['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="HTTP Basic Auth Header - Base64 encoded username:password",
    confidence=Confidence.HIGH,
)

HTTP_BEARER_TOKEN = Pattern(
    name="http_bearer_token",
    regex=r"(?i)(?:Authorization|auth)['\"]?\s*[:=]\s*['\"]?Bearer\s+[A-Za-z0-9_.-]{20,}['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="HTTP Bearer Token - authentication token in header",
    confidence=Confidence.MEDIUM,
)


# JWT Token Pattern
JWT_TOKEN = Pattern(
    name="jwt_token",
    regex=r"eyJ[A-Za-z0-9_-]*\.eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="JWT Token - JSON Web Token (may contain sensitive claims)",
    confidence=Confidence.HIGH,
)

JWT_TOKEN_ASSIGNMENT = Pattern(
    name="jwt_token_assignment",
    regex=r"(?i)(?:jwt|token|access_token|id_token)['\"]?\s*[:=]\s*['\"]?(eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+)['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="JWT Token Assignment - JWT token assigned to variable",
    confidence=Confidence.HIGH,
)


# OAuth Patterns
OAUTH_TOKEN = Pattern(
    name="oauth_token",
    regex=r"(?i)oauth[_-]?(?:access)?[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{20,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="OAuth Token - OAuth access or refresh token",
    confidence=Confidence.MEDIUM,
)

OAUTH_CLIENT_SECRET = Pattern(
    name="oauth_client_secret",
    regex=r"(?i)(?:oauth|client)[_-]?(?:client)?[_-]?secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{16,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="OAuth Client Secret - client secret for OAuth authentication",
    confidence=Confidence.MEDIUM,
)

REFRESH_TOKEN = Pattern(
    name="refresh_token",
    regex=r"(?i)refresh[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{20,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="Refresh Token - OAuth or API refresh token",
    confidence=Confidence.MEDIUM,
)


# Generic API Token Patterns
API_TOKEN = Pattern(
    name="api_token",
    regex=r"(?i)api[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{20,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="API Token - generic API authentication token",
    confidence=Confidence.MEDIUM,
)

AUTH_TOKEN = Pattern(
    name="auth_token",
    regex=r"(?i)(?:auth|authentication)[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{20,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="Auth Token - generic authentication token",
    confidence=Confidence.MEDIUM,
)

ACCESS_TOKEN = Pattern(
    name="access_token",
    regex=r"(?i)access[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_.-]{20,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="Access Token - generic access token",
    confidence=Confidence.MEDIUM,
)


# URL with Credentials Pattern
URL_WITH_CREDENTIALS = Pattern(
    name="url_with_credentials",
    regex=r"(?:https?|ftp)://[^:]+:[^@]+@[^\s\"']+",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="URL with Credentials - URL containing embedded username:password",
    confidence=Confidence.HIGH,
)


# .env File Patterns
ENV_SECRET_KEY = Pattern(
    name="env_secret_key",
    regex=r"^(?:SECRET|API|AUTH|TOKEN)[_A-Z]*[_-]?(?:KEY|TOKEN|SECRET|PASSWORD)['\"]?\s*=\s*['\"]?([^\s'\"]{8,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description=".env Secret Key - sensitive key defined in environment file",
    confidence=Confidence.MEDIUM,
)

ENV_DATABASE_URL = Pattern(
    name="env_database_url",
    regex=r"^(?:DATABASE|DB)[_-]?(?:URL|URI|CONNECTION)['\"]?\s*=\s*['\"]?([a-z]+://[^\s'\"]+)['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description=".env Database URL - database connection string in environment file",
    confidence=Confidence.HIGH,
)

ENV_PASSWORD = Pattern(
    name="env_password",
    regex=r"^[A-Z_]*PASSWORD['\"]?\s*=\s*['\"]?([^\s'\"]{4,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description=".env Password - password defined in environment file",
    confidence=Confidence.HIGH,
)


# Docker Registry Auth
DOCKER_REGISTRY_AUTH = Pattern(
    name="docker_registry_auth",
    regex=r'"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="Docker Registry Auth - Base64 encoded registry credentials",
    confidence=Confidence.HIGH,
)

DOCKER_CONFIG_AUTH = Pattern(
    name="docker_config_auth",
    regex=r'"auths"\s*:\s*\{[^}]*"[^"]+"\s*:\s*\{[^}]*"auth"\s*:\s*"[A-Za-z0-9+/=]{20,}"',
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="Docker Config Auth - Docker config.json with registry credentials",
    confidence=Confidence.HIGH,
)


# Session and Cookie Patterns
SESSION_SECRET = Pattern(
    name="session_secret",
    regex=r"(?i)session[_-]?secret['\"]?\s*[:=]\s*['\"]?([^\s'\"]{16,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="Session Secret - secret used for session signing",
    confidence=Confidence.MEDIUM,
)

COOKIE_SECRET = Pattern(
    name="cookie_secret",
    regex=r"(?i)cookie[_-]?secret['\"]?\s*[:=]\s*['\"]?([^\s'\"]{16,})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CREDENTIALS,
    description="Cookie Secret - secret used for cookie signing",
    confidence=Confidence.MEDIUM,
)


# LDAP Credentials
LDAP_CREDENTIALS = Pattern(
    name="ldap_credentials",
    regex=r"ldaps?://[^:]+:[^@]+@[^\s\"']+",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="LDAP Credentials - LDAP connection with embedded credentials",
    confidence=Confidence.HIGH,
)

LDAP_BIND_PASSWORD = Pattern(
    name="ldap_bind_password",
    regex=r"(?i)(?:ldap|bind)[_-]?(?:bind)?[_-]?(?:password|pwd|passwd)['\"]?\s*[:=]\s*['\"]?([^\s'\"]{4,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CREDENTIALS,
    description="LDAP Bind Password - LDAP bind password",
    confidence=Confidence.HIGH,
)


# Collect all patterns for easy import
CREDENTIAL_PATTERNS: list[Pattern] = [
    # Password patterns
    PASSWORD_ASSIGNMENT,
    PASSWORD_FIELD,
    SECRET_ASSIGNMENT,
    # Database connection strings
    POSTGRES_CONNECTION_STRING,
    MYSQL_CONNECTION_STRING,
    MONGODB_CONNECTION_STRING,
    REDIS_CONNECTION_STRING,
    MSSQL_CONNECTION_STRING,
    JDBC_CONNECTION_STRING,
    GENERIC_DB_CONNECTION,
    # HTTP authentication
    HTTP_BASIC_AUTH,
    HTTP_BEARER_TOKEN,
    # JWT tokens
    JWT_TOKEN,
    JWT_TOKEN_ASSIGNMENT,
    # OAuth patterns
    OAUTH_TOKEN,
    OAUTH_CLIENT_SECRET,
    REFRESH_TOKEN,
    # API tokens
    API_TOKEN,
    AUTH_TOKEN,
    ACCESS_TOKEN,
    # URL credentials
    URL_WITH_CREDENTIALS,
    # .env patterns
    ENV_SECRET_KEY,
    ENV_DATABASE_URL,
    ENV_PASSWORD,
    # Docker registry
    DOCKER_REGISTRY_AUTH,
    DOCKER_CONFIG_AUTH,
    # Session/cookie
    SESSION_SECRET,
    COOKIE_SECRET,
    # LDAP
    LDAP_CREDENTIALS,
    LDAP_BIND_PASSWORD,
]

__all__ = [
    "CREDENTIAL_PATTERNS",
    # Password patterns
    "PASSWORD_ASSIGNMENT",
    "PASSWORD_FIELD",
    "SECRET_ASSIGNMENT",
    # Database connection strings
    "POSTGRES_CONNECTION_STRING",
    "MYSQL_CONNECTION_STRING",
    "MONGODB_CONNECTION_STRING",
    "REDIS_CONNECTION_STRING",
    "MSSQL_CONNECTION_STRING",
    "JDBC_CONNECTION_STRING",
    "GENERIC_DB_CONNECTION",
    # HTTP authentication
    "HTTP_BASIC_AUTH",
    "HTTP_BEARER_TOKEN",
    # JWT tokens
    "JWT_TOKEN",
    "JWT_TOKEN_ASSIGNMENT",
    # OAuth patterns
    "OAUTH_TOKEN",
    "OAUTH_CLIENT_SECRET",
    "REFRESH_TOKEN",
    # API tokens
    "API_TOKEN",
    "AUTH_TOKEN",
    "ACCESS_TOKEN",
    # URL credentials
    "URL_WITH_CREDENTIALS",
    # .env patterns
    "ENV_SECRET_KEY",
    "ENV_DATABASE_URL",
    "ENV_PASSWORD",
    # Docker registry
    "DOCKER_REGISTRY_AUTH",
    "DOCKER_CONFIG_AUTH",
    # Session/cookie
    "SESSION_SECRET",
    "COOKIE_SECRET",
    # LDAP
    "LDAP_CREDENTIALS",
    "LDAP_BIND_PASSWORD",
]
