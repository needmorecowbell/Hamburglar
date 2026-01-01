"""Network-related detection patterns.

This module contains patterns for detecting network-related information including
IP addresses, MAC addresses, internal hostnames, cloud storage URLs, and localhost
references that may expose sensitive infrastructure details.
"""

from hamburglar.core.models import Severity
from hamburglar.detectors.patterns import Confidence, Pattern, PatternCategory

# IPv4 Address Patterns
IPV4_ADDRESS = Pattern(
    name="ipv4_address",
    regex=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="IPv4 Address - standard IPv4 address format",
    confidence=Confidence.HIGH,
)

IPV4_WITH_PORT = Pattern(
    name="ipv4_with_port",
    regex=r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?):[0-9]{1,5}\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="IPv4 Address with Port - IP:port format indicating service endpoint",
    confidence=Confidence.HIGH,
)


# Private IP Range Patterns (RFC 1918)
PRIVATE_IP_10 = Pattern(
    name="private_ip_10",
    regex=r"\b10\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){2}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="Private IP (10.x.x.x) - Class A private network address",
    confidence=Confidence.HIGH,
)

PRIVATE_IP_172 = Pattern(
    name="private_ip_172",
    regex=r"\b172\.(?:1[6-9]|2[0-9]|3[01])\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="Private IP (172.16-31.x.x) - Class B private network address",
    confidence=Confidence.HIGH,
)

PRIVATE_IP_192 = Pattern(
    name="private_ip_192",
    regex=r"\b192\.168\.(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){1}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="Private IP (192.168.x.x) - Class C private network address",
    confidence=Confidence.HIGH,
)


# IPv6 Address Pattern
IPV6_ADDRESS = Pattern(
    name="ipv6_address",
    regex=r"\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="IPv6 Address - full IPv6 address format",
    confidence=Confidence.HIGH,
)

IPV6_COMPRESSED = Pattern(
    name="ipv6_compressed",
    regex=r"\b(?:[0-9a-fA-F]{1,4}:){2,7}:|:(?::[0-9a-fA-F]{1,4}){2,7}\b|(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="IPv6 Address (Compressed) - compressed IPv6 format with :: notation",
    confidence=Confidence.MEDIUM,
)


# MAC Address Pattern
MAC_ADDRESS = Pattern(
    name="mac_address",
    regex=r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="MAC Address - hardware address in standard format",
    confidence=Confidence.HIGH,
)

MAC_ADDRESS_CISCO = Pattern(
    name="mac_address_cisco",
    regex=r"\b(?:[0-9a-fA-F]{4}\.){2}[0-9a-fA-F]{4}\b",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="MAC Address (Cisco format) - hardware address in Cisco notation",
    confidence=Confidence.HIGH,
)


# Internal Hostname Patterns
INTERNAL_HOSTNAME = Pattern(
    name="internal_hostname",
    regex=r"(?i)\b(?:(?:dev|stag(?:e|ing)?|prod(?:uction)?|test|qa|uat|int(?:ernal)?|priv(?:ate)?|corp|internal)[.-])?[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:local|internal|private|corp|intranet|lan|home)\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="Internal Hostname - hostname with internal domain suffix",
    confidence=Confidence.HIGH,
)

INTERNAL_DOMAIN = Pattern(
    name="internal_domain",
    regex=r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:local|internal|private|corp|intranet|lan|home|localdomain)\b",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="Internal Domain - domain with internal suffix",
    confidence=Confidence.MEDIUM,
)


# Cloud Storage URL Patterns
S3_BUCKET_URL = Pattern(
    name="s3_bucket_url",
    regex=r"(?i)(?:https?://)?[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]\.s3(?:[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-[0-9]+)?\.amazonaws\.com(?:/[^\s\"']*)?",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="S3 Bucket URL - Amazon S3 bucket URL (virtual-hosted style)",
    confidence=Confidence.HIGH,
)

S3_BUCKET_PATH_STYLE = Pattern(
    name="s3_bucket_path_style",
    regex=r"(?i)(?:https?://)?s3(?:[.-](?:us|eu|ap|sa|ca|me|af)-[a-z]+-[0-9]+)?\.amazonaws\.com/[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?:/[^\s\"']*)?",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="S3 Bucket URL (Path Style) - Amazon S3 bucket URL (path style)",
    confidence=Confidence.HIGH,
)

S3_ARN_BUCKET = Pattern(
    name="s3_arn_bucket",
    regex=r"arn:aws:s3:::[a-z0-9][a-z0-9.-]{1,61}[a-z0-9](?:/[^\s\"']*)?",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="S3 Bucket ARN - Amazon S3 bucket Amazon Resource Name",
    confidence=Confidence.HIGH,
)

AZURE_BLOB_URL = Pattern(
    name="azure_blob_url",
    regex=r"(?i)(?:https?://)?[a-z0-9][a-z0-9-]{2,62}\.blob\.core\.windows\.net(?:/[^\s\"']*)?",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="Azure Blob URL - Azure Blob Storage URL",
    confidence=Confidence.HIGH,
)

AZURE_STORAGE_URL = Pattern(
    name="azure_storage_url",
    regex=r"(?i)(?:https?://)?[a-z0-9][a-z0-9-]{2,62}\.(?:blob|file|queue|table)\.core\.windows\.net(?:/[^\s\"']*)?",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="Azure Storage URL - Azure Storage services URL",
    confidence=Confidence.HIGH,
)

GCS_BUCKET_URL = Pattern(
    name="gcs_bucket_url",
    regex=r"(?i)(?:https?://)?storage\.googleapis\.com/[a-z0-9][a-z0-9._-]{1,61}[a-z0-9](?:/[^\s\"']*)?",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="GCS Bucket URL - Google Cloud Storage URL",
    confidence=Confidence.HIGH,
)

GCS_BUCKET_URL_VIRTUAL = Pattern(
    name="gcs_bucket_url_virtual",
    regex=r"(?i)(?:https?://)?[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]\.storage\.googleapis\.com(?:/[^\s\"']*)?",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="GCS Bucket URL (Virtual) - Google Cloud Storage virtual-hosted URL",
    confidence=Confidence.HIGH,
)

GCS_GSUTIL = Pattern(
    name="gcs_gsutil",
    regex=r"gs://[a-z0-9][a-z0-9._-]{1,61}[a-z0-9](?:/[^\s\"']*)?",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="GCS gsutil URL - Google Cloud Storage gsutil format",
    confidence=Confidence.HIGH,
)


# Localhost Patterns
LOCALHOST_URL = Pattern(
    name="localhost_url",
    regex=r"(?i)(?:https?://)?localhost(?::[0-9]{1,5})?(?:/[^\s\"']*)?",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="Localhost URL - localhost reference with optional port",
    confidence=Confidence.HIGH,
)

LOCALHOST_IP = Pattern(
    name="localhost_ip",
    regex=r"(?:https?://)?127\.0\.0\.1(?::[0-9]{1,5})?(?:/[^\s\"']*)?",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="Localhost IP - 127.0.0.1 loopback address with optional port",
    confidence=Confidence.HIGH,
)

LOCALHOST_IPV6 = Pattern(
    name="localhost_ipv6",
    regex=r"(?:https?://)?\[::1\](?::[0-9]{1,5})?(?:/[^\s\"']*)?",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="Localhost IPv6 - IPv6 loopback address with optional port",
    confidence=Confidence.HIGH,
)


# URL with Credentials Pattern (more specific than credentials.py)
URL_CREDENTIALS_HTTP = Pattern(
    name="url_credentials_http",
    regex=r"https?://[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.-]+(?::[0-9]{1,5})?(?:/[^\s\"']*)?",
    severity=Severity.CRITICAL,
    category=PatternCategory.NETWORK,
    description="HTTP URL with Credentials - URL containing embedded username:password",
    confidence=Confidence.HIGH,
)

URL_CREDENTIALS_FTP = Pattern(
    name="url_credentials_ftp",
    regex=r"ftp://[^:@\s]+:[^:@\s]+@[a-zA-Z0-9.-]+(?::[0-9]{1,5})?(?:/[^\s\"']*)?",
    severity=Severity.CRITICAL,
    category=PatternCategory.NETWORK,
    description="FTP URL with Credentials - FTP URL with embedded credentials",
    confidence=Confidence.HIGH,
)


# Kubernetes and Docker Network Patterns
K8S_SERVICE_URL = Pattern(
    name="k8s_service_url",
    regex=r"(?i)\b[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.(?:default|kube-system|kube-public|kube-node-lease|[a-z0-9-]+)\.svc(?:\.cluster\.local)?\b",
    severity=Severity.MEDIUM,
    category=PatternCategory.NETWORK,
    description="Kubernetes Service URL - K8s internal service DNS name",
    confidence=Confidence.HIGH,
)

DOCKER_INTERNAL_HOST = Pattern(
    name="docker_internal_host",
    regex=r"(?i)\bhost\.docker\.internal\b",
    severity=Severity.LOW,
    category=PatternCategory.NETWORK,
    description="Docker Internal Host - Docker host.docker.internal reference",
    confidence=Confidence.HIGH,
)


# Collect all patterns for easy import
NETWORK_PATTERNS: list[Pattern] = [
    # IPv4 patterns
    IPV4_ADDRESS,
    IPV4_WITH_PORT,
    # Private IP ranges
    PRIVATE_IP_10,
    PRIVATE_IP_172,
    PRIVATE_IP_192,
    # IPv6 patterns
    IPV6_ADDRESS,
    IPV6_COMPRESSED,
    # MAC address patterns
    MAC_ADDRESS,
    MAC_ADDRESS_CISCO,
    # Internal hostname patterns
    INTERNAL_HOSTNAME,
    INTERNAL_DOMAIN,
    # Cloud storage URLs
    S3_BUCKET_URL,
    S3_BUCKET_PATH_STYLE,
    S3_ARN_BUCKET,
    AZURE_BLOB_URL,
    AZURE_STORAGE_URL,
    GCS_BUCKET_URL,
    GCS_BUCKET_URL_VIRTUAL,
    GCS_GSUTIL,
    # Localhost patterns
    LOCALHOST_URL,
    LOCALHOST_IP,
    LOCALHOST_IPV6,
    # URL with credentials
    URL_CREDENTIALS_HTTP,
    URL_CREDENTIALS_FTP,
    # Container patterns
    K8S_SERVICE_URL,
    DOCKER_INTERNAL_HOST,
]

__all__ = [
    "NETWORK_PATTERNS",
    # IPv4 patterns
    "IPV4_ADDRESS",
    "IPV4_WITH_PORT",
    # Private IP ranges
    "PRIVATE_IP_10",
    "PRIVATE_IP_172",
    "PRIVATE_IP_192",
    # IPv6 patterns
    "IPV6_ADDRESS",
    "IPV6_COMPRESSED",
    # MAC address patterns
    "MAC_ADDRESS",
    "MAC_ADDRESS_CISCO",
    # Internal hostname patterns
    "INTERNAL_HOSTNAME",
    "INTERNAL_DOMAIN",
    # Cloud storage URLs
    "S3_BUCKET_URL",
    "S3_BUCKET_PATH_STYLE",
    "S3_ARN_BUCKET",
    "AZURE_BLOB_URL",
    "AZURE_STORAGE_URL",
    "GCS_BUCKET_URL",
    "GCS_BUCKET_URL_VIRTUAL",
    "GCS_GSUTIL",
    # Localhost patterns
    "LOCALHOST_URL",
    "LOCALHOST_IP",
    "LOCALHOST_IPV6",
    # URL with credentials
    "URL_CREDENTIALS_HTTP",
    "URL_CREDENTIALS_FTP",
    # Container patterns
    "K8S_SERVICE_URL",
    "DOCKER_INTERNAL_HOST",
]
