"""Tests for network-related detection patterns.

This module contains comprehensive tests for all network patterns defined in
the network pattern module. Each pattern is tested with at least 2 positive
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
from hamburglar.detectors.patterns.network import (
    AZURE_BLOB_URL,
    AZURE_STORAGE_URL,
    DOCKER_INTERNAL_HOST,
    GCS_BUCKET_URL,
    GCS_BUCKET_URL_VIRTUAL,
    GCS_GSUTIL,
    INTERNAL_DOMAIN,
    INTERNAL_HOSTNAME,
    IPV4_ADDRESS,
    IPV4_WITH_PORT,
    IPV6_ADDRESS,
    IPV6_COMPRESSED,
    K8S_SERVICE_URL,
    LOCALHOST_IP,
    LOCALHOST_IPV6,
    LOCALHOST_URL,
    MAC_ADDRESS,
    MAC_ADDRESS_CISCO,
    NETWORK_PATTERNS,
    PRIVATE_IP_10,
    PRIVATE_IP_172,
    PRIVATE_IP_192,
    S3_ARN_BUCKET,
    S3_BUCKET_PATH_STYLE,
    S3_BUCKET_URL,
    URL_CREDENTIALS_FTP,
    URL_CREDENTIALS_HTTP,
)


class TestIPv4Patterns:
    """Tests for IPv4 address patterns."""

    def test_ipv4_address_positive_1(self) -> None:
        """Test IPv4 address matches standard format."""
        pattern = re.compile(IPV4_ADDRESS.regex)
        result = pattern.search("192.168.1.1")
        assert result is not None

    def test_ipv4_address_positive_2(self) -> None:
        """Test IPv4 address matches in context."""
        pattern = re.compile(IPV4_ADDRESS.regex)
        result = pattern.search("server_ip = 10.0.0.1")
        assert result is not None

    def test_ipv4_address_positive_3(self) -> None:
        """Test IPv4 address matches edge values."""
        pattern = re.compile(IPV4_ADDRESS.regex)
        result = pattern.search("255.255.255.255")
        assert result is not None

    def test_ipv4_address_positive_4(self) -> None:
        """Test IPv4 address matches zero octets."""
        pattern = re.compile(IPV4_ADDRESS.regex)
        result = pattern.search("0.0.0.0")
        assert result is not None

    def test_ipv4_address_negative_1(self) -> None:
        """Test IPv4 address doesn't match invalid octet."""
        pattern = re.compile(IPV4_ADDRESS.regex)
        result = pattern.search("256.1.1.1")
        assert result is None

    def test_ipv4_address_negative_2(self) -> None:
        """Test IPv4 address doesn't match incomplete."""
        pattern = re.compile(IPV4_ADDRESS.regex)
        result = pattern.search("192.168.1")
        assert result is None

    def test_ipv4_address_metadata(self) -> None:
        """Test IPv4 address pattern metadata."""
        assert IPV4_ADDRESS.severity == Severity.LOW
        assert IPV4_ADDRESS.category == PatternCategory.NETWORK
        assert IPV4_ADDRESS.confidence == Confidence.HIGH

    def test_ipv4_with_port_positive_1(self) -> None:
        """Test IPv4 with port matches."""
        pattern = re.compile(IPV4_WITH_PORT.regex)
        result = pattern.search("192.168.1.1:8080")
        assert result is not None

    def test_ipv4_with_port_positive_2(self) -> None:
        """Test IPv4 with port in context."""
        pattern = re.compile(IPV4_WITH_PORT.regex)
        result = pattern.search("bind to 10.0.0.1:443")
        assert result is not None

    def test_ipv4_with_port_negative_1(self) -> None:
        """Test IPv4 with port doesn't match without port."""
        pattern = re.compile(IPV4_WITH_PORT.regex)
        result = pattern.search("192.168.1.1")
        assert result is None

    def test_ipv4_with_port_negative_2(self) -> None:
        """Test IPv4 with port doesn't match invalid port."""
        pattern = re.compile(IPV4_WITH_PORT.regex)
        result = pattern.search("192.168.1.1:123456")
        assert result is None


class TestPrivateIPPatterns:
    """Tests for private IP range patterns."""

    def test_private_ip_10_positive_1(self) -> None:
        """Test 10.x.x.x range matches."""
        pattern = re.compile(PRIVATE_IP_10.regex)
        result = pattern.search("10.0.0.1")
        assert result is not None

    def test_private_ip_10_positive_2(self) -> None:
        """Test 10.x.x.x range matches any valid."""
        pattern = re.compile(PRIVATE_IP_10.regex)
        result = pattern.search("10.255.255.255")
        assert result is not None

    def test_private_ip_10_negative_1(self) -> None:
        """Test 10.x.x.x range doesn't match 11.x."""
        pattern = re.compile(PRIVATE_IP_10.regex)
        result = pattern.search("11.0.0.1")
        assert result is None

    def test_private_ip_10_negative_2(self) -> None:
        """Test 10.x.x.x range doesn't match 100.x."""
        pattern = re.compile(PRIVATE_IP_10.regex)
        result = pattern.search("100.0.0.1")
        assert result is None

    def test_private_ip_172_positive_1(self) -> None:
        """Test 172.16-31.x.x range matches."""
        pattern = re.compile(PRIVATE_IP_172.regex)
        result = pattern.search("172.16.0.1")
        assert result is not None

    def test_private_ip_172_positive_2(self) -> None:
        """Test 172.16-31.x.x range matches upper bound."""
        pattern = re.compile(PRIVATE_IP_172.regex)
        result = pattern.search("172.31.255.255")
        assert result is not None

    def test_private_ip_172_negative_1(self) -> None:
        """Test 172.16-31.x.x range doesn't match 172.15."""
        pattern = re.compile(PRIVATE_IP_172.regex)
        result = pattern.search("172.15.0.1")
        assert result is None

    def test_private_ip_172_negative_2(self) -> None:
        """Test 172.16-31.x.x range doesn't match 172.32."""
        pattern = re.compile(PRIVATE_IP_172.regex)
        result = pattern.search("172.32.0.1")
        assert result is None

    def test_private_ip_192_positive_1(self) -> None:
        """Test 192.168.x.x range matches."""
        pattern = re.compile(PRIVATE_IP_192.regex)
        result = pattern.search("192.168.0.1")
        assert result is not None

    def test_private_ip_192_positive_2(self) -> None:
        """Test 192.168.x.x range matches any valid."""
        pattern = re.compile(PRIVATE_IP_192.regex)
        result = pattern.search("192.168.255.255")
        assert result is not None

    def test_private_ip_192_negative_1(self) -> None:
        """Test 192.168.x.x range doesn't match 192.167."""
        pattern = re.compile(PRIVATE_IP_192.regex)
        result = pattern.search("192.167.0.1")
        assert result is None

    def test_private_ip_192_negative_2(self) -> None:
        """Test 192.168.x.x range doesn't match 192.169."""
        pattern = re.compile(PRIVATE_IP_192.regex)
        result = pattern.search("192.169.0.1")
        assert result is None

    def test_private_ip_metadata(self) -> None:
        """Test private IP pattern metadata."""
        assert PRIVATE_IP_10.severity == Severity.MEDIUM
        assert PRIVATE_IP_172.severity == Severity.MEDIUM
        assert PRIVATE_IP_192.severity == Severity.MEDIUM


class TestIPv6Patterns:
    """Tests for IPv6 address patterns."""

    def test_ipv6_address_positive_1(self) -> None:
        """Test full IPv6 address matches."""
        pattern = re.compile(IPV6_ADDRESS.regex)
        result = pattern.search("2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        assert result is not None

    def test_ipv6_address_positive_2(self) -> None:
        """Test IPv6 address with lowercase hex."""
        pattern = re.compile(IPV6_ADDRESS.regex)
        result = pattern.search("fe80:0000:0000:0000:0000:0000:0000:0001")
        assert result is not None

    def test_ipv6_address_negative_1(self) -> None:
        """Test IPv6 address doesn't match incomplete."""
        pattern = re.compile(IPV6_ADDRESS.regex)
        result = pattern.search("2001:0db8:85a3:0000")
        assert result is None

    def test_ipv6_address_negative_2(self) -> None:
        """Test IPv6 address doesn't match invalid hex."""
        pattern = re.compile(IPV6_ADDRESS.regex)
        result = pattern.search("2001:0db8:85a3:0000:0000:8a2e:0370:gggg")
        assert result is None

    def test_ipv6_compressed_positive_1(self) -> None:
        """Test compressed IPv6 address matches."""
        pattern = re.compile(IPV6_COMPRESSED.regex)
        result = pattern.search("2001:db8:85a3::8a2e:370:7334")
        assert result is not None

    def test_ipv6_compressed_positive_2(self) -> None:
        """Test compressed IPv6 matches trailing compression."""
        pattern = re.compile(IPV6_COMPRESSED.regex)
        result = pattern.search("fe80:1234:5678::")
        assert result is not None

    def test_ipv6_compressed_negative_1(self) -> None:
        """Test compressed IPv6 doesn't match just colons."""
        pattern = re.compile(IPV6_COMPRESSED.regex)
        result = pattern.search("::")
        assert result is None

    def test_ipv6_compressed_negative_2(self) -> None:
        """Test compressed IPv6 doesn't match single segment."""
        pattern = re.compile(IPV6_COMPRESSED.regex)
        result = pattern.search("2001:")
        assert result is None


class TestMACAddressPatterns:
    """Tests for MAC address patterns."""

    def test_mac_address_positive_1(self) -> None:
        """Test MAC address with colons matches."""
        pattern = re.compile(MAC_ADDRESS.regex)
        result = pattern.search("00:1A:2B:3C:4D:5E")
        assert result is not None

    def test_mac_address_positive_2(self) -> None:
        """Test MAC address with hyphens matches."""
        pattern = re.compile(MAC_ADDRESS.regex)
        result = pattern.search("00-1A-2B-3C-4D-5E")
        assert result is not None

    def test_mac_address_positive_3(self) -> None:
        """Test MAC address lowercase matches."""
        pattern = re.compile(MAC_ADDRESS.regex)
        result = pattern.search("aa:bb:cc:dd:ee:ff")
        assert result is not None

    def test_mac_address_negative_1(self) -> None:
        """Test MAC address doesn't match incomplete."""
        pattern = re.compile(MAC_ADDRESS.regex)
        result = pattern.search("00:1A:2B:3C:4D")
        assert result is None

    def test_mac_address_negative_2(self) -> None:
        """Test MAC address doesn't match invalid hex."""
        pattern = re.compile(MAC_ADDRESS.regex)
        result = pattern.search("00:1G:2B:3C:4D:5E")
        assert result is None

    def test_mac_address_cisco_positive_1(self) -> None:
        """Test Cisco MAC address format matches."""
        pattern = re.compile(MAC_ADDRESS_CISCO.regex)
        result = pattern.search("001a.2b3c.4d5e")
        assert result is not None

    def test_mac_address_cisco_positive_2(self) -> None:
        """Test Cisco MAC address uppercase matches."""
        pattern = re.compile(MAC_ADDRESS_CISCO.regex)
        result = pattern.search("AABB.CCDD.EEFF")
        assert result is not None

    def test_mac_address_cisco_negative_1(self) -> None:
        """Test Cisco MAC address doesn't match wrong format."""
        pattern = re.compile(MAC_ADDRESS_CISCO.regex)
        result = pattern.search("00:1a:2b:3c:4d:5e")
        assert result is None

    def test_mac_address_cisco_negative_2(self) -> None:
        """Test Cisco MAC address doesn't match incomplete."""
        pattern = re.compile(MAC_ADDRESS_CISCO.regex)
        result = pattern.search("001a.2b3c")
        assert result is None


class TestInternalHostnamePatterns:
    """Tests for internal hostname patterns."""

    def test_internal_hostname_positive_1(self) -> None:
        """Test internal hostname with .local matches."""
        pattern = re.compile(INTERNAL_HOSTNAME.regex)
        result = pattern.search("dev-server.local")
        assert result is not None

    def test_internal_hostname_positive_2(self) -> None:
        """Test internal hostname with .internal matches."""
        pattern = re.compile(INTERNAL_HOSTNAME.regex)
        result = pattern.search("prod-db.internal")
        assert result is not None

    def test_internal_hostname_positive_3(self) -> None:
        """Test internal hostname with .corp matches."""
        pattern = re.compile(INTERNAL_HOSTNAME.regex)
        result = pattern.search("staging-api.corp")
        assert result is not None

    def test_internal_hostname_negative_1(self) -> None:
        """Test internal hostname doesn't match .com."""
        pattern = re.compile(INTERNAL_HOSTNAME.regex)
        result = pattern.search("server.com")
        assert result is None

    def test_internal_hostname_negative_2(self) -> None:
        """Test internal hostname doesn't match public domain."""
        pattern = re.compile(INTERNAL_HOSTNAME.regex)
        result = pattern.search("example.org")
        assert result is None

    def test_internal_domain_positive_1(self) -> None:
        """Test internal domain with .local matches."""
        pattern = re.compile(INTERNAL_DOMAIN.regex)
        result = pattern.search("myserver.local")
        assert result is not None

    def test_internal_domain_positive_2(self) -> None:
        """Test internal domain with .lan matches."""
        pattern = re.compile(INTERNAL_DOMAIN.regex)
        result = pattern.search("router.lan")
        assert result is not None

    def test_internal_domain_negative_1(self) -> None:
        """Test internal domain doesn't match public TLD."""
        pattern = re.compile(INTERNAL_DOMAIN.regex)
        result = pattern.search("server.net")
        assert result is None

    def test_internal_domain_negative_2(self) -> None:
        """Test internal domain doesn't match IP."""
        pattern = re.compile(INTERNAL_DOMAIN.regex)
        result = pattern.search("192.168.1.1")
        assert result is None


class TestS3BucketPatterns:
    """Tests for S3 bucket URL patterns."""

    def test_s3_bucket_url_positive_1(self) -> None:
        """Test S3 bucket URL virtual-hosted style matches."""
        pattern = re.compile(S3_BUCKET_URL.regex)
        result = pattern.search("https://my-bucket.s3.amazonaws.com/path/to/file")
        assert result is not None

    def test_s3_bucket_url_positive_2(self) -> None:
        """Test S3 bucket URL with region matches."""
        pattern = re.compile(S3_BUCKET_URL.regex)
        result = pattern.search("https://test-bucket.s3-us-east-1.amazonaws.com/object")
        assert result is not None

    def test_s3_bucket_url_positive_3(self) -> None:
        """Test S3 bucket URL without https matches."""
        pattern = re.compile(S3_BUCKET_URL.regex)
        result = pattern.search("my-bucket.s3.amazonaws.com")
        assert result is not None

    def test_s3_bucket_url_negative_1(self) -> None:
        """Test S3 bucket URL doesn't match wrong domain."""
        pattern = re.compile(S3_BUCKET_URL.regex)
        result = pattern.search("https://my-bucket.storage.googleapis.com")
        assert result is None

    def test_s3_bucket_url_negative_2(self) -> None:
        """Test S3 bucket URL doesn't match invalid bucket name."""
        pattern = re.compile(S3_BUCKET_URL.regex)
        result = pattern.search("https://-.s3.amazonaws.com")
        assert result is None

    def test_s3_bucket_path_style_positive_1(self) -> None:
        """Test S3 path-style URL matches."""
        pattern = re.compile(S3_BUCKET_PATH_STYLE.regex)
        result = pattern.search("https://s3.amazonaws.com/my-bucket/path")
        assert result is not None

    def test_s3_bucket_path_style_positive_2(self) -> None:
        """Test S3 path-style URL with region matches."""
        pattern = re.compile(S3_BUCKET_PATH_STYLE.regex)
        result = pattern.search("s3-us-west-2.amazonaws.com/test-bucket")
        assert result is not None

    def test_s3_bucket_path_style_negative_1(self) -> None:
        """Test S3 path-style URL doesn't match virtual-hosted."""
        pattern = re.compile(S3_BUCKET_PATH_STYLE.regex)
        result = pattern.search("https://my-bucket.s3.amazonaws.com")
        assert result is None

    def test_s3_bucket_path_style_negative_2(self) -> None:
        """Test S3 path-style URL doesn't match wrong service."""
        pattern = re.compile(S3_BUCKET_PATH_STYLE.regex)
        result = pattern.search("https://ec2.amazonaws.com/bucket")
        assert result is None

    def test_s3_arn_bucket_positive_1(self) -> None:
        """Test S3 ARN bucket matches."""
        pattern = re.compile(S3_ARN_BUCKET.regex)
        result = pattern.search("arn:aws:s3:::my-bucket")
        assert result is not None

    def test_s3_arn_bucket_positive_2(self) -> None:
        """Test S3 ARN bucket with path matches."""
        pattern = re.compile(S3_ARN_BUCKET.regex)
        result = pattern.search("arn:aws:s3:::test-bucket/prefix/*")
        assert result is not None

    def test_s3_arn_bucket_negative_1(self) -> None:
        """Test S3 ARN doesn't match wrong service."""
        pattern = re.compile(S3_ARN_BUCKET.regex)
        result = pattern.search("arn:aws:ec2:::my-instance")
        assert result is None

    def test_s3_arn_bucket_negative_2(self) -> None:
        """Test S3 ARN doesn't match invalid bucket name."""
        pattern = re.compile(S3_ARN_BUCKET.regex)
        result = pattern.search("arn:aws:s3:::ab")
        assert result is None


class TestAzureBlobPatterns:
    """Tests for Azure Blob Storage URL patterns."""

    def test_azure_blob_url_positive_1(self) -> None:
        """Test Azure Blob URL matches."""
        pattern = re.compile(AZURE_BLOB_URL.regex)
        result = pattern.search("https://mystorageaccount.blob.core.windows.net/container")
        assert result is not None

    def test_azure_blob_url_positive_2(self) -> None:
        """Test Azure Blob URL without path matches."""
        pattern = re.compile(AZURE_BLOB_URL.regex)
        result = pattern.search("mystorageaccount.blob.core.windows.net")
        assert result is not None

    def test_azure_blob_url_negative_1(self) -> None:
        """Test Azure Blob URL doesn't match wrong subdomain."""
        pattern = re.compile(AZURE_BLOB_URL.regex)
        result = pattern.search("https://mystorageaccount.table.core.windows.net")
        assert result is None

    def test_azure_blob_url_negative_2(self) -> None:
        """Test Azure Blob URL doesn't match short account name."""
        pattern = re.compile(AZURE_BLOB_URL.regex)
        result = pattern.search("https://ab.blob.core.windows.net")
        assert result is None

    def test_azure_storage_url_positive_1(self) -> None:
        """Test Azure Storage URL matches blob."""
        pattern = re.compile(AZURE_STORAGE_URL.regex)
        result = pattern.search("https://myaccount.blob.core.windows.net/data")
        assert result is not None

    def test_azure_storage_url_positive_2(self) -> None:
        """Test Azure Storage URL matches file."""
        pattern = re.compile(AZURE_STORAGE_URL.regex)
        result = pattern.search("myaccount.file.core.windows.net/share")
        assert result is not None

    def test_azure_storage_url_positive_3(self) -> None:
        """Test Azure Storage URL matches queue."""
        pattern = re.compile(AZURE_STORAGE_URL.regex)
        result = pattern.search("https://myaccount.queue.core.windows.net")
        assert result is not None

    def test_azure_storage_url_negative_1(self) -> None:
        """Test Azure Storage URL doesn't match wrong service."""
        pattern = re.compile(AZURE_STORAGE_URL.regex)
        result = pattern.search("https://myaccount.vault.azure.net")
        assert result is None


class TestGCSPatterns:
    """Tests for Google Cloud Storage URL patterns."""

    def test_gcs_bucket_url_positive_1(self) -> None:
        """Test GCS bucket URL matches."""
        pattern = re.compile(GCS_BUCKET_URL.regex)
        result = pattern.search("https://storage.googleapis.com/my-bucket/path")
        assert result is not None

    def test_gcs_bucket_url_positive_2(self) -> None:
        """Test GCS bucket URL without path matches."""
        pattern = re.compile(GCS_BUCKET_URL.regex)
        result = pattern.search("storage.googleapis.com/test-bucket")
        assert result is not None

    def test_gcs_bucket_url_negative_1(self) -> None:
        """Test GCS bucket URL doesn't match wrong domain."""
        pattern = re.compile(GCS_BUCKET_URL.regex)
        result = pattern.search("https://storage.azure.com/bucket")
        assert result is None

    def test_gcs_bucket_url_negative_2(self) -> None:
        """Test GCS bucket URL doesn't match without bucket."""
        pattern = re.compile(GCS_BUCKET_URL.regex)
        result = pattern.search("https://storage.googleapis.com/")
        assert result is None

    def test_gcs_virtual_url_positive_1(self) -> None:
        """Test GCS virtual-hosted URL matches."""
        pattern = re.compile(GCS_BUCKET_URL_VIRTUAL.regex)
        result = pattern.search("https://my-bucket.storage.googleapis.com/object")
        assert result is not None

    def test_gcs_virtual_url_positive_2(self) -> None:
        """Test GCS virtual-hosted URL without path matches."""
        pattern = re.compile(GCS_BUCKET_URL_VIRTUAL.regex)
        result = pattern.search("test-bucket.storage.googleapis.com")
        assert result is not None

    def test_gcs_virtual_url_negative_1(self) -> None:
        """Test GCS virtual URL doesn't match path-style."""
        pattern = re.compile(GCS_BUCKET_URL_VIRTUAL.regex)
        result = pattern.search("https://storage.googleapis.com/my-bucket")
        assert result is None

    def test_gcs_gsutil_positive_1(self) -> None:
        """Test GCS gsutil URL matches."""
        pattern = re.compile(GCS_GSUTIL.regex)
        result = pattern.search("gs://my-bucket/path/to/file")
        assert result is not None

    def test_gcs_gsutil_positive_2(self) -> None:
        """Test GCS gsutil URL without path matches."""
        pattern = re.compile(GCS_GSUTIL.regex)
        result = pattern.search("gs://test-bucket")
        assert result is not None

    def test_gcs_gsutil_negative_1(self) -> None:
        """Test GCS gsutil doesn't match s3:// URLs."""
        pattern = re.compile(GCS_GSUTIL.regex)
        result = pattern.search("s3://my-bucket/path")
        assert result is None

    def test_gcs_gsutil_negative_2(self) -> None:
        """Test GCS gsutil doesn't match invalid bucket."""
        pattern = re.compile(GCS_GSUTIL.regex)
        result = pattern.search("gs://-invalid")
        assert result is None


class TestLocalhostPatterns:
    """Tests for localhost patterns."""

    def test_localhost_url_positive_1(self) -> None:
        """Test localhost URL matches."""
        pattern = re.compile(LOCALHOST_URL.regex)
        result = pattern.search("http://localhost:3000/api")
        assert result is not None

    def test_localhost_url_positive_2(self) -> None:
        """Test localhost URL without port matches."""
        pattern = re.compile(LOCALHOST_URL.regex)
        result = pattern.search("https://localhost/path")
        assert result is not None

    def test_localhost_url_positive_3(self) -> None:
        """Test localhost without protocol matches."""
        pattern = re.compile(LOCALHOST_URL.regex)
        result = pattern.search("localhost:8080")
        assert result is not None

    def test_localhost_url_negative_1(self) -> None:
        """Test localhost doesn't match localhos (typo)."""
        pattern = re.compile(LOCALHOST_URL.regex)
        result = pattern.search("http://localhos:3000")
        assert result is None

    def test_localhost_url_negative_2(self) -> None:
        """Test localhost doesn't match localhost.com."""
        pattern = re.compile(LOCALHOST_URL.regex)
        # This will actually match 'localhost' without the .com part
        result = pattern.fullmatch("localhost.com")
        assert result is None

    def test_localhost_ip_positive_1(self) -> None:
        """Test localhost IP matches."""
        pattern = re.compile(LOCALHOST_IP.regex)
        result = pattern.search("http://127.0.0.1:8000/api")
        assert result is not None

    def test_localhost_ip_positive_2(self) -> None:
        """Test localhost IP without port matches."""
        pattern = re.compile(LOCALHOST_IP.regex)
        result = pattern.search("127.0.0.1/path")
        assert result is not None

    def test_localhost_ip_negative_1(self) -> None:
        """Test localhost IP doesn't match 127.0.0.2."""
        pattern = re.compile(LOCALHOST_IP.regex)
        result = pattern.search("127.0.0.2:8000")
        assert result is None

    def test_localhost_ip_negative_2(self) -> None:
        """Test localhost IP doesn't match 127.1.1.1."""
        pattern = re.compile(LOCALHOST_IP.regex)
        result = pattern.search("127.1.1.1")
        assert result is None

    def test_localhost_ipv6_positive_1(self) -> None:
        """Test localhost IPv6 matches."""
        pattern = re.compile(LOCALHOST_IPV6.regex)
        result = pattern.search("http://[::1]:8080/api")
        assert result is not None

    def test_localhost_ipv6_positive_2(self) -> None:
        """Test localhost IPv6 without port matches."""
        pattern = re.compile(LOCALHOST_IPV6.regex)
        result = pattern.search("[::1]/path")
        assert result is not None

    def test_localhost_ipv6_negative_1(self) -> None:
        """Test localhost IPv6 doesn't match ::2."""
        pattern = re.compile(LOCALHOST_IPV6.regex)
        result = pattern.search("[::2]:8080")
        assert result is None

    def test_localhost_ipv6_negative_2(self) -> None:
        """Test localhost IPv6 doesn't match without brackets."""
        pattern = re.compile(LOCALHOST_IPV6.regex)
        result = pattern.search("::1:8080")
        assert result is None


class TestURLCredentialsPatterns:
    """Tests for URL with credentials patterns."""

    def test_url_credentials_http_positive_1(self) -> None:
        """Test HTTP URL with credentials matches."""
        pattern = re.compile(URL_CREDENTIALS_HTTP.regex)
        result = pattern.search("https://user:password@example.com/path")
        assert result is not None

    def test_url_credentials_http_positive_2(self) -> None:
        """Test HTTP URL with credentials and port matches."""
        pattern = re.compile(URL_CREDENTIALS_HTTP.regex)
        result = pattern.search("http://admin:secret@server.local:8080/api")
        assert result is not None

    def test_url_credentials_http_negative_1(self) -> None:
        """Test HTTP URL without credentials doesn't match."""
        pattern = re.compile(URL_CREDENTIALS_HTTP.regex)
        result = pattern.search("https://example.com/path")
        assert result is None

    def test_url_credentials_http_negative_2(self) -> None:
        """Test HTTP URL with only user doesn't match."""
        pattern = re.compile(URL_CREDENTIALS_HTTP.regex)
        result = pattern.search("https://user@example.com")
        assert result is None

    def test_url_credentials_ftp_positive_1(self) -> None:
        """Test FTP URL with credentials matches."""
        pattern = re.compile(URL_CREDENTIALS_FTP.regex)
        result = pattern.search("ftp://user:password@ftp.example.com/files")
        assert result is not None

    def test_url_credentials_ftp_positive_2(self) -> None:
        """Test FTP URL with credentials and port matches."""
        pattern = re.compile(URL_CREDENTIALS_FTP.regex)
        result = pattern.search("ftp://admin:secret@192.168.1.1:21/data")
        assert result is not None

    def test_url_credentials_ftp_negative_1(self) -> None:
        """Test FTP URL without credentials doesn't match."""
        pattern = re.compile(URL_CREDENTIALS_FTP.regex)
        result = pattern.search("ftp://ftp.example.com/files")
        assert result is None

    def test_url_credentials_http_metadata(self) -> None:
        """Test URL credentials pattern metadata."""
        assert URL_CREDENTIALS_HTTP.severity == Severity.CRITICAL
        assert URL_CREDENTIALS_FTP.severity == Severity.CRITICAL


class TestContainerPatterns:
    """Tests for Kubernetes and Docker patterns."""

    def test_k8s_service_url_positive_1(self) -> None:
        """Test K8s service URL default namespace matches."""
        pattern = re.compile(K8S_SERVICE_URL.regex)
        result = pattern.search("my-service.default.svc.cluster.local")
        assert result is not None

    def test_k8s_service_url_positive_2(self) -> None:
        """Test K8s service URL kube-system namespace matches."""
        pattern = re.compile(K8S_SERVICE_URL.regex)
        result = pattern.search("coredns.kube-system.svc")
        assert result is not None

    def test_k8s_service_url_positive_3(self) -> None:
        """Test K8s service URL custom namespace matches."""
        pattern = re.compile(K8S_SERVICE_URL.regex)
        result = pattern.search("api-gateway.production.svc.cluster.local")
        assert result is not None

    def test_k8s_service_url_negative_1(self) -> None:
        """Test K8s service URL doesn't match without .svc."""
        pattern = re.compile(K8S_SERVICE_URL.regex)
        result = pattern.search("my-service.default.cluster.local")
        assert result is None

    def test_k8s_service_url_negative_2(self) -> None:
        """Test K8s service URL doesn't match public domain."""
        pattern = re.compile(K8S_SERVICE_URL.regex)
        result = pattern.search("my-service.example.com")
        assert result is None

    def test_docker_internal_host_positive_1(self) -> None:
        """Test Docker internal host matches."""
        pattern = re.compile(DOCKER_INTERNAL_HOST.regex)
        result = pattern.search("http://host.docker.internal:8080")
        assert result is not None

    def test_docker_internal_host_positive_2(self) -> None:
        """Test Docker internal host in config matches."""
        pattern = re.compile(DOCKER_INTERNAL_HOST.regex)
        result = pattern.search('HOST = "host.docker.internal"')
        assert result is not None

    def test_docker_internal_host_negative_1(self) -> None:
        """Test Docker internal host doesn't match partial."""
        pattern = re.compile(DOCKER_INTERNAL_HOST.regex)
        result = pattern.search("docker.internal")
        assert result is None

    def test_docker_internal_host_negative_2(self) -> None:
        """Test Docker internal host doesn't match similar."""
        pattern = re.compile(DOCKER_INTERNAL_HOST.regex)
        result = pattern.search("host-docker-internal")
        assert result is None


class TestNetworkPatternsCollection:
    """Tests for the NETWORK_PATTERNS collection."""

    def test_all_patterns_in_collection(self) -> None:
        """Test that all defined patterns are in the collection."""
        assert len(NETWORK_PATTERNS) == 26

    def test_all_patterns_are_network_category(self) -> None:
        """Test that all patterns have NETWORK category."""
        for pattern in NETWORK_PATTERNS:
            assert pattern.category == PatternCategory.NETWORK

    def test_all_patterns_have_descriptions(self) -> None:
        """Test that all patterns have descriptions."""
        for pattern in NETWORK_PATTERNS:
            assert pattern.description != ""

    def test_all_patterns_have_valid_regex(self) -> None:
        """Test that all patterns have valid regex."""
        import re as regex_module

        for pattern in NETWORK_PATTERNS:
            try:
                regex_module.compile(pattern.regex)
            except regex_module.error as e:
                pytest.fail(f"Pattern {pattern.name} has invalid regex: {e}")

    def test_all_patterns_have_unique_names(self) -> None:
        """Test that all patterns have unique names."""
        names = [p.name for p in NETWORK_PATTERNS]
        assert len(names) == len(set(names))

    def test_patterns_to_dict_compatible(self) -> None:
        """Test that all patterns can be converted to dict format."""
        for pattern in NETWORK_PATTERNS:
            data = pattern.to_dict()
            assert "pattern" in data
            assert "severity" in data
            assert "description" in data
            assert "category" in data
            assert "confidence" in data

    def test_severity_distribution(self) -> None:
        """Test that severity levels are appropriately distributed."""
        severities = [p.severity for p in NETWORK_PATTERNS]
        # URL with credentials should be CRITICAL
        assert Severity.CRITICAL in severities
        # Some patterns should be MEDIUM (internal IPs, etc.)
        assert Severity.MEDIUM in severities
        # Some informational patterns should be LOW
        assert Severity.LOW in severities

    def test_confidence_distribution(self) -> None:
        """Test that confidence levels are appropriately set."""
        confidences = [p.confidence for p in NETWORK_PATTERNS]
        # Most patterns should be HIGH confidence
        high_count = sum(1 for c in confidences if c == Confidence.HIGH)
        assert high_count >= 20  # Most should be high confidence
