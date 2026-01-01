"""Cloud provider credential detection patterns.

This module contains patterns for detecting cloud provider credentials and tokens
from Azure, GCP, AWS, Firebase, Cloudflare, Alibaba Cloud, IBM Cloud, and Oracle Cloud.
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory

# Azure Patterns
AZURE_STORAGE_KEY = Pattern(
    name="azure_storage_key",
    regex=r"(?i)(?:DefaultEndpointsProtocol|AccountKey)\s*=\s*([A-Za-z0-9+/=]{86,88})",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Azure Storage Account Key - provides full access to Azure storage account",
    confidence=Confidence.HIGH,
)

AZURE_CONNECTION_STRING = Pattern(
    name="azure_connection_string",
    regex=r"(?i)DefaultEndpointsProtocol=https?;AccountName=[a-z0-9]+;AccountKey=[A-Za-z0-9+/=]{86,88}",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Azure Storage Connection String - complete connection string with credentials",
    confidence=Confidence.HIGH,
)

AZURE_SAS_TOKEN = Pattern(
    name="azure_sas_token",
    regex=r"(?:sv=[\d-]+&(?:ss=[a-z]+&)?(?:srt=[a-z]+&)?(?:sp=[a-z]+&)?(?:se=[\dT:Z-]+&)?(?:st=[\dT:Z-]+&)?(?:spr=https?(?:,https?)?&)?(?:sig=[A-Za-z0-9%+/=]+))",
    severity=Severity.HIGH,
    category=PatternCategory.CLOUD,
    description="Azure SAS Token - Shared Access Signature for limited access to Azure resources",
    confidence=Confidence.HIGH,
)

AZURE_AD_CLIENT_SECRET = Pattern(
    name="azure_ad_client_secret",
    regex=r"(?i)(?:azure|aad|client)[_-]?(?:client)?[_-]?secret['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9~._-]{34,40})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Azure AD Client Secret - used for Azure AD application authentication",
    confidence=Confidence.MEDIUM,
)

AZURE_SUBSCRIPTION_KEY = Pattern(
    name="azure_subscription_key",
    regex=r"(?i)(?:ocp-apim-subscription-key|azure[_-]?subscription[_-]?key)['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CLOUD,
    description="Azure API Management Subscription Key - provides access to Azure APIs",
    confidence=Confidence.HIGH,
)


# GCP Patterns
GCP_SERVICE_ACCOUNT_KEY = Pattern(
    name="gcp_service_account_key",
    regex=r'"type"\s*:\s*"service_account"[^}]*"private_key"\s*:\s*"-----BEGIN (?:RSA )?PRIVATE KEY-----',
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="GCP Service Account Key - JSON key file for Google Cloud service account",
    confidence=Confidence.HIGH,
)

GCP_API_KEY = Pattern(
    name="gcp_api_key",
    regex=r"AIza[0-9A-Za-z_-]{35}",
    severity=Severity.HIGH,
    category=PatternCategory.CLOUD,
    description="GCP API Key - provides access to Google Cloud APIs",
    confidence=Confidence.HIGH,
)

GCP_OAUTH_CLIENT_SECRET = Pattern(
    name="gcp_oauth_client_secret",
    regex=r'(?i)"client_secret"\s*:\s*"(GOCSPX-[a-zA-Z0-9_-]{28})"',
    severity=Severity.HIGH,
    category=PatternCategory.CLOUD,
    description="GCP OAuth Client Secret - used for Google OAuth 2.0 authentication",
    confidence=Confidence.HIGH,
)


# AWS Patterns (additional to api_keys.py)
AWS_SESSION_TOKEN = Pattern(
    name="aws_session_token",
    regex=r"(?i)aws[_-]?session[_-]?token['\"]?\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{100,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="AWS Session Token - temporary credentials for AWS API access",
    confidence=Confidence.HIGH,
)

AWS_ARN = Pattern(
    name="aws_arn",
    regex=r"arn:aws:[a-z0-9-]+:[a-z0-9-]*:[0-9]*:[a-zA-Z0-9-_/:.]+",
    severity=Severity.LOW,
    category=PatternCategory.CLOUD,
    description="AWS ARN - Amazon Resource Name identifying AWS resources",
    confidence=Confidence.HIGH,
)

AWS_MWS_KEY = Pattern(
    name="aws_mws_key",
    regex=r"amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="AWS MWS Key - Amazon Marketplace Web Service authentication key",
    confidence=Confidence.HIGH,
)


# Firebase Patterns
FIREBASE_URL = Pattern(
    name="firebase_url",
    regex=r"https://[a-z0-9-]+\.firebaseio\.com",
    severity=Severity.MEDIUM,
    category=PatternCategory.CLOUD,
    description="Firebase URL - Firebase Realtime Database URL",
    confidence=Confidence.HIGH,
)

FIREBASE_API_KEY = Pattern(
    name="firebase_api_key",
    regex=r"AIza[0-9A-Za-z_-]{35}",
    severity=Severity.MEDIUM,
    category=PatternCategory.CLOUD,
    description="Firebase API Key - provides access to Firebase services",
    confidence=Confidence.MEDIUM,
)

FIREBASE_CONFIG = Pattern(
    name="firebase_config",
    regex=r'(?i)(?:firebase|fire)[_-]?(?:config|options)[^{]*\{[^}]*apiKey["\']?\s*:\s*["\']?AIza[0-9A-Za-z_-]{35}',
    severity=Severity.HIGH,
    category=PatternCategory.CLOUD,
    description="Firebase Configuration - Firebase config object with API key",
    confidence=Confidence.HIGH,
)


# Cloudflare Patterns
CLOUDFLARE_API_KEY = Pattern(
    name="cloudflare_api_key",
    regex=r"(?i)cloudflare[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-f]{37})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Cloudflare API Key - provides access to Cloudflare account",
    confidence=Confidence.HIGH,
)

CLOUDFLARE_API_TOKEN = Pattern(
    name="cloudflare_api_token",
    regex=r"(?i)cloudflare[_-]?(?:api)?[_-]?token['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{40})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Cloudflare API Token - scoped token for Cloudflare API access",
    confidence=Confidence.HIGH,
)

CLOUDFLARE_ORIGIN_CA_KEY = Pattern(
    name="cloudflare_origin_ca_key",
    regex=r"v1\.0-[0-9a-f]{24}-[0-9a-f]{146,150}",
    severity=Severity.HIGH,
    category=PatternCategory.CLOUD,
    description="Cloudflare Origin CA Key - used for Cloudflare origin certificates",
    confidence=Confidence.HIGH,
)


# Alibaba Cloud Patterns
ALIBABA_ACCESS_KEY_ID = Pattern(
    name="alibaba_access_key_id",
    regex=r"LTAI[0-9A-Za-z]{12,20}",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Alibaba Cloud Access Key ID - identifies Alibaba Cloud account",
    confidence=Confidence.HIGH,
)

ALIBABA_SECRET_KEY = Pattern(
    name="alibaba_secret_key",
    regex=r"(?i)(?:alibaba|aliyun)[_-]?(?:secret)?[_-]?(?:access)?[_-]?key['\"]?\s*[:=]\s*['\"]?([0-9a-zA-Z]{30})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Alibaba Cloud Secret Access Key - used with Access Key ID for authentication",
    confidence=Confidence.HIGH,
)


# IBM Cloud Patterns
IBM_CLOUD_API_KEY = Pattern(
    name="ibm_cloud_api_key",
    regex=r"(?i)ibm[_-]?(?:cloud)?[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9_-]{44})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="IBM Cloud API Key - provides programmatic access to IBM Cloud services",
    confidence=Confidence.HIGH,
)

IBM_COS_HMAC_KEY = Pattern(
    name="ibm_cos_hmac_key",
    regex=r"(?i)(?:ibm[_-]?)?cos[_-]?(?:hmac)?[_-]?(?:access)?[_-]?key[_-]?(?:id)?['\"]?\s*[:=]\s*['\"]?([0-9a-f]{32})['\"]?",
    severity=Severity.HIGH,
    category=PatternCategory.CLOUD,
    description="IBM Cloud Object Storage HMAC Key - used for S3-compatible API access",
    confidence=Confidence.MEDIUM,
)


# Oracle Cloud Patterns
ORACLE_OCID = Pattern(
    name="oracle_ocid",
    regex=r"ocid1\.[a-z]+\.[a-z0-9]+\.[a-z0-9-]*\.[a-z0-9]{60}",
    severity=Severity.MEDIUM,
    category=PatternCategory.CLOUD,
    description="Oracle Cloud OCID - Oracle Cloud Identifier for resources",
    confidence=Confidence.HIGH,
)

ORACLE_API_KEY = Pattern(
    name="oracle_api_key",
    regex=r"(?i)oracle[_-]?(?:cloud)?[_-]?(?:api)?[_-]?key['\"]?\s*[:=]\s*['\"]?([a-zA-Z0-9/+=]{40,})['\"]?",
    severity=Severity.CRITICAL,
    category=PatternCategory.CLOUD,
    description="Oracle Cloud API Key - provides access to Oracle Cloud Infrastructure APIs",
    confidence=Confidence.MEDIUM,
)

ORACLE_TENANCY_OCID = Pattern(
    name="oracle_tenancy_ocid",
    regex=r"ocid1\.tenancy\.[a-z0-9]+\.[a-z0-9-]*\.[a-z0-9]{60}",
    severity=Severity.MEDIUM,
    category=PatternCategory.CLOUD,
    description="Oracle Cloud Tenancy OCID - identifies Oracle Cloud tenancy",
    confidence=Confidence.HIGH,
)


# Collect all patterns for easy import
CLOUD_PATTERNS: list[Pattern] = [
    # Azure
    AZURE_STORAGE_KEY,
    AZURE_CONNECTION_STRING,
    AZURE_SAS_TOKEN,
    AZURE_AD_CLIENT_SECRET,
    AZURE_SUBSCRIPTION_KEY,
    # GCP
    GCP_SERVICE_ACCOUNT_KEY,
    GCP_API_KEY,
    GCP_OAUTH_CLIENT_SECRET,
    # AWS
    AWS_SESSION_TOKEN,
    AWS_ARN,
    AWS_MWS_KEY,
    # Firebase
    FIREBASE_URL,
    FIREBASE_API_KEY,
    FIREBASE_CONFIG,
    # Cloudflare
    CLOUDFLARE_API_KEY,
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_ORIGIN_CA_KEY,
    # Alibaba
    ALIBABA_ACCESS_KEY_ID,
    ALIBABA_SECRET_KEY,
    # IBM
    IBM_CLOUD_API_KEY,
    IBM_COS_HMAC_KEY,
    # Oracle
    ORACLE_OCID,
    ORACLE_API_KEY,
    ORACLE_TENANCY_OCID,
]

__all__ = [
    "CLOUD_PATTERNS",
    # Azure
    "AZURE_STORAGE_KEY",
    "AZURE_CONNECTION_STRING",
    "AZURE_SAS_TOKEN",
    "AZURE_AD_CLIENT_SECRET",
    "AZURE_SUBSCRIPTION_KEY",
    # GCP
    "GCP_SERVICE_ACCOUNT_KEY",
    "GCP_API_KEY",
    "GCP_OAUTH_CLIENT_SECRET",
    # AWS
    "AWS_SESSION_TOKEN",
    "AWS_ARN",
    "AWS_MWS_KEY",
    # Firebase
    "FIREBASE_URL",
    "FIREBASE_API_KEY",
    "FIREBASE_CONFIG",
    # Cloudflare
    "CLOUDFLARE_API_KEY",
    "CLOUDFLARE_API_TOKEN",
    "CLOUDFLARE_ORIGIN_CA_KEY",
    # Alibaba
    "ALIBABA_ACCESS_KEY_ID",
    "ALIBABA_SECRET_KEY",
    # IBM
    "IBM_CLOUD_API_KEY",
    "IBM_COS_HMAC_KEY",
    # Oracle
    "ORACLE_OCID",
    "ORACLE_API_KEY",
    "ORACLE_TENANCY_OCID",
]
