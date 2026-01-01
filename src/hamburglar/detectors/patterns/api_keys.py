"""API key detection patterns.

This module contains patterns for detecting API keys and tokens from various
services including cloud providers, development platforms, and third-party services.
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory

# AWS Patterns
AWS_ACCESS_KEY_ID = Pattern(
    name="aws_access_key_id",
    regex=r"AKIA[0-9A-Z]{16}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="AWS Access Key ID - provides programmatic access to AWS services",
    confidence=Confidence.HIGH,
)

AWS_SECRET_KEY = Pattern(
    name="aws_secret_key",
    regex=r"(?i)aws(.{0,20})?(?:secret|_secret)[_-]?(?:access)?[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z/+=]{40})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="AWS Secret Access Key - used with Access Key ID to authenticate AWS API calls",
    confidence=Confidence.HIGH,
)

# GitHub Patterns
GITHUB_TOKEN = Pattern(
    name="github_token",
    regex=r"ghp_[0-9a-zA-Z]{36}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="GitHub Personal Access Token - provides authenticated access to GitHub APIs",
    confidence=Confidence.HIGH,
)

GITHUB_OAUTH_TOKEN = Pattern(
    name="github_oauth_token",
    regex=r"gho_[0-9a-zA-Z]{36}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="GitHub OAuth Token - temporary token for OAuth authentication",
    confidence=Confidence.HIGH,
)

GITHUB_USER_TO_SERVER_TOKEN = Pattern(
    name="github_user_to_server_token",
    regex=r"ghu_[0-9a-zA-Z]{36}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="GitHub User-to-Server Token - used for GitHub App authentication",
    confidence=Confidence.HIGH,
)

GITHUB_SERVER_TO_SERVER_TOKEN = Pattern(
    name="github_server_to_server_token",
    regex=r"ghs_[0-9a-zA-Z]{36}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="GitHub Server-to-Server Token - used for GitHub App installation authentication",
    confidence=Confidence.HIGH,
)

GITHUB_REFRESH_TOKEN = Pattern(
    name="github_refresh_token",
    regex=r"ghr_[0-9a-zA-Z]{36}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="GitHub Refresh Token - used to refresh OAuth tokens",
    confidence=Confidence.HIGH,
)

GITHUB_OAUTH_CLIENT_SECRET = Pattern(
    name="github_oauth_client_secret",
    regex=r"(?i)github[_-]?(?:oauth)?[_-]?(?:client)?[_-]?secret['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z]{40})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="GitHub OAuth Client Secret - used for OAuth application authentication",
    confidence=Confidence.MEDIUM,
)

# GitLab Patterns
GITLAB_TOKEN = Pattern(
    name="gitlab_token",
    regex=r"glpat-[0-9a-zA-Z_-]{20,}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="GitLab Personal Access Token - provides authenticated access to GitLab APIs",
    confidence=Confidence.HIGH,
)

GITLAB_RUNNER_TOKEN = Pattern(
    name="gitlab_runner_token",
    regex=r"GR1348941[0-9a-zA-Z_-]{20,}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="GitLab Runner Registration Token - used to register CI/CD runners",
    confidence=Confidence.HIGH,
)

# Slack Patterns
SLACK_TOKEN = Pattern(
    name="slack_token",
    regex=r"xox[pboa]-[0-9]{10,13}-[0-9]{10,13}(?:-[0-9]{10,13})?-[a-zA-Z0-9]{24,32}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Slack OAuth Token - provides access to Slack workspace APIs",
    confidence=Confidence.HIGH,
)

SLACK_WEBHOOK = Pattern(
    name="slack_webhook",
    regex=r"https://hooks\.slack\.com/services/T[a-zA-Z0-9_]{8,10}/B[a-zA-Z0-9_]{8,12}/[a-zA-Z0-9_]{24}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Slack Webhook URL - allows posting messages to Slack channels",
    confidence=Confidence.HIGH,
)

# Google Patterns
GOOGLE_API_KEY = Pattern(
    name="google_api_key",
    regex=r"AIza[0-9A-Za-z_-]{35}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Google API Key - provides access to various Google APIs",
    confidence=Confidence.HIGH,
)

GOOGLE_OAUTH_CLIENT_SECRET = Pattern(
    name="google_oauth_client_secret",
    regex=r'"client_secret"\s*:\s*"([a-zA-Z0-9_-]{24})"',
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Google OAuth Client Secret - used for OAuth 2.0 authentication",
    confidence=Confidence.MEDIUM,
)

# Stripe Patterns
STRIPE_SECRET_KEY = Pattern(
    name="stripe_secret_key",
    regex=r"sk_live_[0-9a-zA-Z]{24,99}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Stripe Live Secret Key - provides full access to live Stripe account",
    confidence=Confidence.HIGH,
)

STRIPE_RESTRICTED_KEY = Pattern(
    name="stripe_restricted_key",
    regex=r"rk_live_[0-9a-zA-Z]{24,99}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Stripe Restricted API Key - limited access to live Stripe account",
    confidence=Confidence.HIGH,
)

STRIPE_PUBLISHABLE_KEY = Pattern(
    name="stripe_publishable_key",
    regex=r"pk_live_[0-9a-zA-Z]{24,99}",
    severity=Severity.MEDIUM,
    category=PatternCategory.API_KEYS,
    description="Stripe Publishable Key - public key for client-side Stripe integration",
    confidence=Confidence.HIGH,
)

STRIPE_TEST_SECRET_KEY = Pattern(
    name="stripe_test_secret_key",
    regex=r"sk_test_[0-9a-zA-Z]{24,99}",
    severity=Severity.LOW,
    category=PatternCategory.API_KEYS,
    description="Stripe Test Secret Key - test mode API key",
    confidence=Confidence.HIGH,
)

# Twilio Patterns
TWILIO_ACCOUNT_SID = Pattern(
    name="twilio_account_sid",
    regex=r"AC[0-9a-fA-F]{32}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Twilio Account SID - identifies Twilio account",
    confidence=Confidence.HIGH,
)

TWILIO_AUTH_TOKEN = Pattern(
    name="twilio_auth_token",
    regex=r"(?i)twilio[_-]?auth[_-]?token['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F]{32})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Twilio Auth Token - authentication token for Twilio API",
    confidence=Confidence.MEDIUM,
)

# SendGrid Pattern
SENDGRID_API_KEY = Pattern(
    name="sendgrid_api_key",
    regex=r"SG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="SendGrid API Key - provides access to SendGrid email services",
    confidence=Confidence.HIGH,
)

# Mailgun Pattern
MAILGUN_API_KEY = Pattern(
    name="mailgun_api_key",
    regex=r"(?i)mailgun[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?(key-[0-9a-zA-Z]{32})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Mailgun API Key - provides access to Mailgun email services",
    confidence=Confidence.HIGH,
)

MAILGUN_KEY_DIRECT = Pattern(
    name="mailgun_key_direct",
    regex=r"key-[0-9a-zA-Z]{32}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Mailgun API Key - direct key format detection",
    confidence=Confidence.MEDIUM,
)

# Mailchimp Pattern
MAILCHIMP_API_KEY = Pattern(
    name="mailchimp_api_key",
    regex=r"[0-9a-f]{32}-us[0-9]{1,2}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Mailchimp API Key - provides access to Mailchimp marketing services",
    confidence=Confidence.HIGH,
)

# NPM Token
NPM_TOKEN = Pattern(
    name="npm_token",
    regex=r"npm_[0-9a-zA-Z]{36}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="NPM Access Token - provides authenticated access to NPM registry",
    confidence=Confidence.HIGH,
)

NPM_TOKEN_LEGACY = Pattern(
    name="npm_token_legacy",
    regex=r"(?i)//registry\.npmjs\.org/:_authToken=([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="NPM Legacy Auth Token - legacy format NPM authentication token",
    confidence=Confidence.HIGH,
)

# PyPI Token
PYPI_TOKEN = Pattern(
    name="pypi_token",
    regex=r"pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="PyPI API Token - provides authenticated access to Python Package Index",
    confidence=Confidence.HIGH,
)

# NuGet API Key
NUGET_API_KEY = Pattern(
    name="nuget_api_key",
    regex=r"oy2[a-z0-9]{43}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="NuGet API Key - provides authenticated access to NuGet package registry",
    confidence=Confidence.HIGH,
)

# Heroku API Key
HEROKU_API_KEY = Pattern(
    name="heroku_api_key",
    regex=r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Heroku API Key - UUID format API key for Heroku platform",
    confidence=Confidence.LOW,  # UUID format is generic, context needed
)

HEROKU_API_KEY_CONTEXT = Pattern(
    name="heroku_api_key_context",
    regex=r"(?i)heroku[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="Heroku API Key - API key with Heroku context",
    confidence=Confidence.HIGH,
)

# DigitalOcean Token
DIGITALOCEAN_TOKEN = Pattern(
    name="digitalocean_token",
    regex=r"dop_v1_[0-9a-f]{64}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="DigitalOcean Personal Access Token - provides access to DigitalOcean APIs",
    confidence=Confidence.HIGH,
)

DIGITALOCEAN_OAUTH_TOKEN = Pattern(
    name="digitalocean_oauth_token",
    regex=r"doo_v1_[0-9a-f]{64}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="DigitalOcean OAuth Token - OAuth-based access to DigitalOcean APIs",
    confidence=Confidence.HIGH,
)

DIGITALOCEAN_REFRESH_TOKEN = Pattern(
    name="digitalocean_refresh_token",
    regex=r"dor_v1_[0-9a-f]{64}",
    severity=Severity.CRITICAL,
    category=PatternCategory.API_KEYS,
    description="DigitalOcean Refresh Token - used to refresh OAuth tokens",
    confidence=Confidence.HIGH,
)

# Datadog API Key
DATADOG_API_KEY = Pattern(
    name="datadog_api_key",
    regex=r"(?i)datadog[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Datadog API Key - provides access to Datadog monitoring APIs",
    confidence=Confidence.HIGH,
)

DATADOG_APP_KEY = Pattern(
    name="datadog_app_key",
    regex=r"(?i)datadog[_-]?(?:app|application)[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{40})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="Datadog Application Key - used for Datadog application authentication",
    confidence=Confidence.HIGH,
)

# New Relic Key
NEW_RELIC_LICENSE_KEY = Pattern(
    name="new_relic_license_key",
    regex=r"(?i)new[_-]?relic[_-]?(?:license)?[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{40})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="New Relic License Key - authentication key for New Relic monitoring",
    confidence=Confidence.HIGH,
)

NEW_RELIC_API_KEY = Pattern(
    name="new_relic_api_key",
    regex=r"NRAK-[0-9A-Z]{27}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="New Relic API Key - provides access to New Relic REST APIs",
    confidence=Confidence.HIGH,
)

NEW_RELIC_INSIGHTS_KEY = Pattern(
    name="new_relic_insights_key",
    regex=r"NRI[IQ]-[0-9A-Za-z_-]{32}",
    severity=Severity.HIGH,
    category=PatternCategory.API_KEYS,
    description="New Relic Insights Key - used for New Relic Insights API access",
    confidence=Confidence.HIGH,
)


# Collect all patterns for easy import
API_KEY_PATTERNS: list[Pattern] = [
    AWS_ACCESS_KEY_ID,
    AWS_SECRET_KEY,
    GITHUB_TOKEN,
    GITHUB_OAUTH_TOKEN,
    GITHUB_USER_TO_SERVER_TOKEN,
    GITHUB_SERVER_TO_SERVER_TOKEN,
    GITHUB_REFRESH_TOKEN,
    GITHUB_OAUTH_CLIENT_SECRET,
    GITLAB_TOKEN,
    GITLAB_RUNNER_TOKEN,
    SLACK_TOKEN,
    SLACK_WEBHOOK,
    GOOGLE_API_KEY,
    GOOGLE_OAUTH_CLIENT_SECRET,
    STRIPE_SECRET_KEY,
    STRIPE_RESTRICTED_KEY,
    STRIPE_PUBLISHABLE_KEY,
    STRIPE_TEST_SECRET_KEY,
    TWILIO_ACCOUNT_SID,
    TWILIO_AUTH_TOKEN,
    SENDGRID_API_KEY,
    MAILGUN_API_KEY,
    MAILGUN_KEY_DIRECT,
    MAILCHIMP_API_KEY,
    NPM_TOKEN,
    NPM_TOKEN_LEGACY,
    PYPI_TOKEN,
    NUGET_API_KEY,
    HEROKU_API_KEY,
    HEROKU_API_KEY_CONTEXT,
    DIGITALOCEAN_TOKEN,
    DIGITALOCEAN_OAUTH_TOKEN,
    DIGITALOCEAN_REFRESH_TOKEN,
    DATADOG_API_KEY,
    DATADOG_APP_KEY,
    NEW_RELIC_LICENSE_KEY,
    NEW_RELIC_API_KEY,
    NEW_RELIC_INSIGHTS_KEY,
]

__all__ = [
    "API_KEY_PATTERNS",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_KEY",
    "GITHUB_TOKEN",
    "GITHUB_OAUTH_TOKEN",
    "GITHUB_USER_TO_SERVER_TOKEN",
    "GITHUB_SERVER_TO_SERVER_TOKEN",
    "GITHUB_REFRESH_TOKEN",
    "GITHUB_OAUTH_CLIENT_SECRET",
    "GITLAB_TOKEN",
    "GITLAB_RUNNER_TOKEN",
    "SLACK_TOKEN",
    "SLACK_WEBHOOK",
    "GOOGLE_API_KEY",
    "GOOGLE_OAUTH_CLIENT_SECRET",
    "STRIPE_SECRET_KEY",
    "STRIPE_RESTRICTED_KEY",
    "STRIPE_PUBLISHABLE_KEY",
    "STRIPE_TEST_SECRET_KEY",
    "TWILIO_ACCOUNT_SID",
    "TWILIO_AUTH_TOKEN",
    "SENDGRID_API_KEY",
    "MAILGUN_API_KEY",
    "MAILGUN_KEY_DIRECT",
    "MAILCHIMP_API_KEY",
    "NPM_TOKEN",
    "NPM_TOKEN_LEGACY",
    "PYPI_TOKEN",
    "NUGET_API_KEY",
    "HEROKU_API_KEY",
    "HEROKU_API_KEY_CONTEXT",
    "DIGITALOCEAN_TOKEN",
    "DIGITALOCEAN_OAUTH_TOKEN",
    "DIGITALOCEAN_REFRESH_TOKEN",
    "DATADOG_API_KEY",
    "DATADOG_APP_KEY",
    "NEW_RELIC_LICENSE_KEY",
    "NEW_RELIC_API_KEY",
    "NEW_RELIC_INSIGHTS_KEY",
]
