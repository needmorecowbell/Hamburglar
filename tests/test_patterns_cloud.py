"""Tests for cloud provider credential detection patterns.

This module contains comprehensive tests for all cloud patterns defined in
the cloud pattern module. Each pattern is tested with at least 2 positive
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
from hamburglar.detectors.patterns.cloud import (
    ALIBABA_ACCESS_KEY_ID,
    ALIBABA_SECRET_KEY,
    AWS_ARN,
    AWS_MWS_KEY,
    AWS_SESSION_TOKEN,
    AZURE_AD_CLIENT_SECRET,
    AZURE_CONNECTION_STRING,
    AZURE_SAS_TOKEN,
    AZURE_STORAGE_KEY,
    AZURE_SUBSCRIPTION_KEY,
    CLOUD_PATTERNS,
    CLOUDFLARE_API_KEY,
    CLOUDFLARE_API_TOKEN,
    CLOUDFLARE_ORIGIN_CA_KEY,
    FIREBASE_API_KEY,
    FIREBASE_CONFIG,
    FIREBASE_URL,
    GCP_API_KEY,
    GCP_OAUTH_CLIENT_SECRET,
    GCP_SERVICE_ACCOUNT_KEY,
    IBM_CLOUD_API_KEY,
    IBM_COS_HMAC_KEY,
    ORACLE_API_KEY,
    ORACLE_OCID,
    ORACLE_TENANCY_OCID,
)


# Helper function to build test tokens that bypass secret scanning
def fake_token(*parts: str) -> str:
    """Build a test token from parts to bypass secret scanning."""
    return "".join(parts)


class TestAzurePatterns:
    """Tests for Azure credential patterns."""

    def test_azure_storage_key_positive_1(self) -> None:
        """Test Azure Storage Key matches valid key in context."""
        pattern = re.compile(AZURE_STORAGE_KEY.regex)
        # 88 base64 chars
        test_str = fake_token(
            "AccountKey=",
            "ABCDEFGHIJKLMNOP",
            "QRSTUVWXYZ012345",
            "abcdefghijklmnop",
            "qrstuvwxyz012345",
            "ABCDEFGHIJKLMNOP",
            "QRSTUVWXYZ==",
        )
        result = pattern.search(test_str)
        assert result is not None

    def test_azure_storage_key_positive_2(self) -> None:
        """Test Azure Storage Key with DefaultEndpointsProtocol."""
        pattern = re.compile(AZURE_STORAGE_KEY.regex)
        # 88 base64 chars
        test_str = fake_token(
            "DefaultEndpointsProtocol=https;AccountKey=",
            "abcdefghijklmnop",
            "ABCDEFGHIJKLMNOP",
            "0123456789012345",
            "abcdefghijklmnop",
            "ABCDEFGHIJKLMNOP",
            "0123456789==",
        )
        result = pattern.search(test_str)
        assert result is not None

    def test_azure_storage_key_negative_1(self) -> None:
        """Test Azure Storage Key doesn't match short key."""
        pattern = re.compile(AZURE_STORAGE_KEY.regex)
        result = pattern.search("AccountKey=shortkey")
        assert result is None

    def test_azure_storage_key_negative_2(self) -> None:
        """Test Azure Storage Key doesn't match without context."""
        pattern = re.compile(AZURE_STORAGE_KEY.regex)
        # Just 88 chars without context
        result = pattern.search(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123=="
        )
        assert result is None

    def test_azure_storage_key_metadata(self) -> None:
        """Test Azure Storage Key pattern metadata."""
        assert AZURE_STORAGE_KEY.severity == Severity.CRITICAL
        assert AZURE_STORAGE_KEY.category == PatternCategory.CLOUD
        assert AZURE_STORAGE_KEY.confidence == Confidence.HIGH

    def test_azure_connection_string_positive_1(self) -> None:
        """Test Azure Connection String matches complete string."""
        pattern = re.compile(AZURE_CONNECTION_STRING.regex)
        test_str = fake_token(
            "DefaultEndpointsProtocol=https;AccountName=teststorage;AccountKey=",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123==",
        )
        result = pattern.search(test_str)
        assert result is not None

    def test_azure_connection_string_positive_2(self) -> None:
        """Test Azure Connection String with http."""
        pattern = re.compile(AZURE_CONNECTION_STRING.regex)
        # AccountName must be lowercase per Azure requirements
        test_str = fake_token(
            "DefaultEndpointsProtocol=http;AccountName=mystorageaccount;AccountKey=",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789012345678901234567890123==",
        )
        result = pattern.search(test_str)
        assert result is not None

    def test_azure_connection_string_negative_1(self) -> None:
        """Test Azure Connection String doesn't match incomplete."""
        pattern = re.compile(AZURE_CONNECTION_STRING.regex)
        result = pattern.search("DefaultEndpointsProtocol=https;AccountName=test")
        assert result is None

    def test_azure_connection_string_negative_2(self) -> None:
        """Test Azure Connection String doesn't match wrong protocol."""
        pattern = re.compile(AZURE_CONNECTION_STRING.regex)
        result = pattern.search("DefaultEndpointsProtocol=ftp;AccountName=test;AccountKey=abc123")
        assert result is None

    def test_azure_sas_token_positive_1(self) -> None:
        """Test Azure SAS Token matches valid token."""
        pattern = re.compile(AZURE_SAS_TOKEN.regex)
        test_str = fake_token(
            "sv=2020-08-04&ss=bfqt&srt=sco&sp=rwdlacuptfx&se=2023-12-31T23:59:59Z&",
            "st=2023-01-01T00:00:00Z&spr=https&sig=FAKE0signature0value0here0000000000000000%3D",
        )
        result = pattern.search(test_str)
        assert result is not None

    def test_azure_sas_token_positive_2(self) -> None:
        """Test Azure SAS Token matches minimal token."""
        pattern = re.compile(AZURE_SAS_TOKEN.regex)
        test_str = "sv=2021-06-08&sig=FAKEsignature%2B%2F%3D"
        result = pattern.search(test_str)
        assert result is not None

    def test_azure_sas_token_negative_1(self) -> None:
        """Test Azure SAS Token doesn't match without sig."""
        pattern = re.compile(AZURE_SAS_TOKEN.regex)
        result = pattern.search("sv=2020-08-04&ss=bfqt&srt=sco")
        assert result is None

    def test_azure_sas_token_negative_2(self) -> None:
        """Test Azure SAS Token doesn't match empty sig."""
        pattern = re.compile(AZURE_SAS_TOKEN.regex)
        result = pattern.search("sv=2020-08-04&sig=")
        assert result is None

    def test_azure_ad_client_secret_positive_1(self) -> None:
        """Test Azure AD Client Secret matches."""
        pattern = re.compile(AZURE_AD_CLIENT_SECRET.regex)
        result = pattern.search("azure_client_secret = 'abc123DEF456ghi789JKL012mno345PQR~-'")
        assert result is not None

    def test_azure_ad_client_secret_positive_2(self) -> None:
        """Test Azure AD Client Secret alternate format."""
        pattern = re.compile(AZURE_AD_CLIENT_SECRET.regex)
        result = pattern.search('AAD_CLIENT_SECRET: "FAKE.secret~value_here-12345678901234"')
        assert result is not None

    def test_azure_ad_client_secret_negative_1(self) -> None:
        """Test Azure AD Client Secret too short."""
        pattern = re.compile(AZURE_AD_CLIENT_SECRET.regex)
        result = pattern.search("azure_client_secret = 'short'")
        assert result is None

    def test_azure_ad_client_secret_negative_2(self) -> None:
        """Test Azure AD Client Secret no context."""
        pattern = re.compile(AZURE_AD_CLIENT_SECRET.regex)
        result = pattern.search("secret = 'abc123DEF456ghi789JKL012mno345PQR~-'")
        assert result is None

    def test_azure_subscription_key_positive_1(self) -> None:
        """Test Azure Subscription Key matches."""
        pattern = re.compile(AZURE_SUBSCRIPTION_KEY.regex)
        result = pattern.search("Ocp-Apim-Subscription-Key: 1234567890abcdef1234567890abcdef")
        assert result is not None

    def test_azure_subscription_key_positive_2(self) -> None:
        """Test Azure Subscription Key alternate format."""
        pattern = re.compile(AZURE_SUBSCRIPTION_KEY.regex)
        result = pattern.search('azure_subscription_key = "abcdef1234567890abcdef1234567890"')
        assert result is not None

    def test_azure_subscription_key_negative_1(self) -> None:
        """Test Azure Subscription Key too short."""
        pattern = re.compile(AZURE_SUBSCRIPTION_KEY.regex)
        result = pattern.search("azure_subscription_key = 'short'")
        assert result is None

    def test_azure_subscription_key_negative_2(self) -> None:
        """Test Azure Subscription Key no context."""
        pattern = re.compile(AZURE_SUBSCRIPTION_KEY.regex)
        result = pattern.search("key = '1234567890abcdef1234567890abcdef'")
        assert result is None


class TestGCPPatterns:
    """Tests for Google Cloud Platform patterns."""

    def test_gcp_service_account_key_positive_1(self) -> None:
        """Test GCP Service Account Key matches JSON structure."""
        pattern = re.compile(GCP_SERVICE_ACCOUNT_KEY.regex)
        test_str = '{"type": "service_account", "project_id": "test", "private_key": "-----BEGIN PRIVATE KEY-----'
        result = pattern.search(test_str)
        assert result is not None

    def test_gcp_service_account_key_positive_2(self) -> None:
        """Test GCP Service Account Key with RSA format."""
        pattern = re.compile(GCP_SERVICE_ACCOUNT_KEY.regex)
        test_str = '{"type" : "service_account", "private_key" : "-----BEGIN RSA PRIVATE KEY-----'
        result = pattern.search(test_str)
        assert result is not None

    def test_gcp_service_account_key_negative_1(self) -> None:
        """Test GCP Service Account Key wrong type."""
        pattern = re.compile(GCP_SERVICE_ACCOUNT_KEY.regex)
        result = pattern.search(
            '{"type": "user_account", "private_key": "-----BEGIN PRIVATE KEY-----'
        )
        assert result is None

    def test_gcp_service_account_key_negative_2(self) -> None:
        """Test GCP Service Account Key no private_key."""
        pattern = re.compile(GCP_SERVICE_ACCOUNT_KEY.regex)
        result = pattern.search('{"type": "service_account", "project_id": "test"}')
        assert result is None

    def test_gcp_api_key_positive_1(self) -> None:
        """Test GCP API Key matches."""
        pattern = re.compile(GCP_API_KEY.regex)
        result = pattern.search("AIzaSyDaFAKEKEY123456789012345678901abc")
        assert result is not None

    def test_gcp_api_key_positive_2(self) -> None:
        """Test GCP API Key in context."""
        pattern = re.compile(GCP_API_KEY.regex)
        result = pattern.search("api_key: AIzaSyCdefghijklmnopqrstuvwxyz123456789")
        assert result is not None

    def test_gcp_api_key_negative_1(self) -> None:
        """Test GCP API Key wrong prefix."""
        pattern = re.compile(GCP_API_KEY.regex)
        result = pattern.search("AIzyWrongPrefix1234567890abcdefghijk")
        assert result is None

    def test_gcp_api_key_negative_2(self) -> None:
        """Test GCP API Key too short."""
        pattern = re.compile(GCP_API_KEY.regex)
        result = pattern.search("AIzaSyDshort")
        assert result is None

    def test_gcp_oauth_secret_positive_1(self) -> None:
        """Test GCP OAuth Client Secret matches."""
        pattern = re.compile(GCP_OAUTH_CLIENT_SECRET.regex)
        # GOCSPX- followed by exactly 28 chars
        result = pattern.search('"client_secret": "GOCSPX-abcdefghijklmnop12345678901a"')
        assert result is not None

    def test_gcp_oauth_secret_positive_2(self) -> None:
        """Test GCP OAuth Client Secret with spaces."""
        pattern = re.compile(GCP_OAUTH_CLIENT_SECRET.regex)
        # GOCSPX- followed by exactly 28 chars
        result = pattern.search('"client_secret" : "GOCSPX-ABCDEFGHIJKLMNOP12345678901A"')
        assert result is not None

    def test_gcp_oauth_secret_negative_1(self) -> None:
        """Test GCP OAuth Client Secret wrong prefix."""
        pattern = re.compile(GCP_OAUTH_CLIENT_SECRET.regex)
        result = pattern.search('"client_secret": "WRONG-abcdefghijklmnopqrstuvwx"')
        assert result is None

    def test_gcp_oauth_secret_negative_2(self) -> None:
        """Test GCP OAuth Client Secret too short."""
        pattern = re.compile(GCP_OAUTH_CLIENT_SECRET.regex)
        result = pattern.search('"client_secret": "GOCSPX-short"')
        assert result is None


class TestAWSAdditionalPatterns:
    """Tests for additional AWS patterns."""

    def test_aws_session_token_positive_1(self) -> None:
        """Test AWS Session Token matches."""
        pattern = re.compile(AWS_SESSION_TOKEN.regex)
        # 100+ chars for session token
        test_str = fake_token(
            "aws_session_token = '",
            "A" * 50,
            "B" * 50,
            "C" * 50,
            "'",
        )
        result = pattern.search(test_str)
        assert result is not None

    def test_aws_session_token_positive_2(self) -> None:
        """Test AWS Session Token alternate format."""
        pattern = re.compile(AWS_SESSION_TOKEN.regex)
        test_str = fake_token(
            'AWS_SESSION_TOKEN: "',
            "x" * 100,
            "y" * 50,
            '"',
        )
        result = pattern.search(test_str)
        assert result is not None

    def test_aws_session_token_negative_1(self) -> None:
        """Test AWS Session Token no context."""
        pattern = re.compile(AWS_SESSION_TOKEN.regex)
        result = pattern.search("session_token = '" + "A" * 100 + "'")
        assert result is None

    def test_aws_session_token_negative_2(self) -> None:
        """Test AWS Session Token too short."""
        pattern = re.compile(AWS_SESSION_TOKEN.regex)
        result = pattern.search("aws_session_token = 'shorttoken'")
        assert result is None

    def test_aws_arn_positive_1(self) -> None:
        """Test AWS ARN matches S3 bucket."""
        pattern = re.compile(AWS_ARN.regex)
        result = pattern.search("arn:aws:s3:::my-bucket-name")
        assert result is not None

    def test_aws_arn_positive_2(self) -> None:
        """Test AWS ARN matches IAM role."""
        pattern = re.compile(AWS_ARN.regex)
        result = pattern.search("arn:aws:iam::123456789012:role/MyRole")
        assert result is not None

    def test_aws_arn_positive_3(self) -> None:
        """Test AWS ARN matches Lambda function."""
        pattern = re.compile(AWS_ARN.regex)
        result = pattern.search("arn:aws:lambda:us-east-1:123456789012:function:my-function")
        assert result is not None

    def test_aws_arn_negative_1(self) -> None:
        """Test AWS ARN wrong prefix."""
        pattern = re.compile(AWS_ARN.regex)
        result = pattern.search("arn:gcp:s3:::my-bucket")
        assert result is None

    def test_aws_arn_negative_2(self) -> None:
        """Test AWS ARN incomplete format."""
        pattern = re.compile(AWS_ARN.regex)
        result = pattern.search("arn:aws:")
        assert result is None

    def test_aws_mws_key_positive_1(self) -> None:
        """Test AWS MWS Key matches."""
        pattern = re.compile(AWS_MWS_KEY.regex)
        result = pattern.search("amzn.mws.12345678-1234-1234-1234-123456789012")
        assert result is not None

    def test_aws_mws_key_positive_2(self) -> None:
        """Test AWS MWS Key in context."""
        pattern = re.compile(AWS_MWS_KEY.regex)
        result = pattern.search("MWS_KEY=amzn.mws.abcdef12-3456-7890-abcd-ef1234567890")
        assert result is not None

    def test_aws_mws_key_negative_1(self) -> None:
        """Test AWS MWS Key wrong prefix."""
        pattern = re.compile(AWS_MWS_KEY.regex)
        result = pattern.search("amazon.mws.12345678-1234-1234-1234-123456789012")
        assert result is None

    def test_aws_mws_key_negative_2(self) -> None:
        """Test AWS MWS Key invalid UUID."""
        pattern = re.compile(AWS_MWS_KEY.regex)
        result = pattern.search("amzn.mws.not-a-valid-uuid")
        assert result is None


class TestFirebasePatterns:
    """Tests for Firebase patterns."""

    def test_firebase_url_positive_1(self) -> None:
        """Test Firebase URL matches."""
        pattern = re.compile(FIREBASE_URL.regex)
        result = pattern.search("https://my-project-123.firebaseio.com")
        assert result is not None

    def test_firebase_url_positive_2(self) -> None:
        """Test Firebase URL in config."""
        pattern = re.compile(FIREBASE_URL.regex)
        result = pattern.search('databaseURL: "https://test-app.firebaseio.com"')
        assert result is not None

    def test_firebase_url_negative_1(self) -> None:
        """Test Firebase URL wrong domain."""
        pattern = re.compile(FIREBASE_URL.regex)
        result = pattern.search("https://my-project.firebase.com")
        assert result is None

    def test_firebase_url_negative_2(self) -> None:
        """Test Firebase URL http (should still work)."""
        pattern = re.compile(FIREBASE_URL.regex)
        # HTTP URLs don't match the https pattern
        result = pattern.search("http://my-project.firebaseio.com")
        assert result is None

    def test_firebase_api_key_positive_1(self) -> None:
        """Test Firebase API Key matches."""
        pattern = re.compile(FIREBASE_API_KEY.regex)
        result = pattern.search("AIzaSyDaFAKEKEY123456789012345678901abc")
        assert result is not None

    def test_firebase_api_key_positive_2(self) -> None:
        """Test Firebase API Key in config."""
        pattern = re.compile(FIREBASE_API_KEY.regex)
        result = pattern.search('apiKey: "AIzaSyCdefghijklmnopqrstuvwxyz123456789"')
        assert result is not None

    def test_firebase_api_key_negative_1(self) -> None:
        """Test Firebase API Key wrong prefix."""
        pattern = re.compile(FIREBASE_API_KEY.regex)
        result = pattern.search("AIzBWrongPrefix12345678901234567890abc")
        assert result is None

    def test_firebase_api_key_negative_2(self) -> None:
        """Test Firebase API Key too short."""
        pattern = re.compile(FIREBASE_API_KEY.regex)
        result = pattern.search("AIzaSyDshort")
        assert result is None

    def test_firebase_config_positive_1(self) -> None:
        """Test Firebase Config matches."""
        pattern = re.compile(FIREBASE_CONFIG.regex)
        test_str = 'firebaseConfig = { apiKey: "AIzaSyDaFAKEKEY123456789012345678901abc"'
        result = pattern.search(test_str)
        assert result is not None

    def test_firebase_config_positive_2(self) -> None:
        """Test Firebase Config alternate format."""
        pattern = re.compile(FIREBASE_CONFIG.regex)
        test_str = 'firebase_options: {apiKey: "AIzaSyCdefghijklmnopqrstuvwxyz123456789"'
        result = pattern.search(test_str)
        assert result is not None

    def test_firebase_config_negative_1(self) -> None:
        """Test Firebase Config no apiKey."""
        pattern = re.compile(FIREBASE_CONFIG.regex)
        result = pattern.search("firebaseConfig = { projectId: 'test-project' }")
        assert result is None

    def test_firebase_config_negative_2(self) -> None:
        """Test Firebase Config no firebase keyword."""
        pattern = re.compile(FIREBASE_CONFIG.regex)
        result = pattern.search('config = { apiKey: "AIzaSyDaFAKEKEY123456789012345678901abc"')
        assert result is None


class TestCloudflarePatterns:
    """Tests for Cloudflare patterns."""

    def test_cloudflare_api_key_positive_1(self) -> None:
        """Test Cloudflare API Key matches."""
        pattern = re.compile(CLOUDFLARE_API_KEY.regex)
        # 37 hex chars
        result = pattern.search("cloudflare_api_key = '1234567890abcdef1234567890abcdef12345'")
        assert result is not None

    def test_cloudflare_api_key_positive_2(self) -> None:
        """Test Cloudflare API Key alternate format."""
        pattern = re.compile(CLOUDFLARE_API_KEY.regex)
        result = pattern.search('CLOUDFLARE_KEY: "abcdef1234567890abcdef1234567890abcde"')
        assert result is not None

    def test_cloudflare_api_key_negative_1(self) -> None:
        """Test Cloudflare API Key no context."""
        pattern = re.compile(CLOUDFLARE_API_KEY.regex)
        result = pattern.search("api_key = '1234567890abcdef1234567890abcdef12345'")
        assert result is None

    def test_cloudflare_api_key_negative_2(self) -> None:
        """Test Cloudflare API Key too short."""
        pattern = re.compile(CLOUDFLARE_API_KEY.regex)
        result = pattern.search("cloudflare_api_key = 'short'")
        assert result is None

    def test_cloudflare_api_token_positive_1(self) -> None:
        """Test Cloudflare API Token matches."""
        pattern = re.compile(CLOUDFLARE_API_TOKEN.regex)
        # 40 chars
        result = pattern.search("cloudflare_api_token = 'abcdefghijklmnopqrstuvwxyz01234567890123'")
        assert result is not None

    def test_cloudflare_api_token_positive_2(self) -> None:
        """Test Cloudflare API Token alternate format."""
        pattern = re.compile(CLOUDFLARE_API_TOKEN.regex)
        # 40 chars token
        result = pattern.search('CLOUDFLARE_TOKEN: "ABCDEFGHIJKLMNOPQRSTUVWXYZ-_123456789012"')
        assert result is not None

    def test_cloudflare_api_token_negative_1(self) -> None:
        """Test Cloudflare API Token no context."""
        pattern = re.compile(CLOUDFLARE_API_TOKEN.regex)
        result = pattern.search("api_token = 'abcdefghijklmnopqrstuvwxyz01234567890123'")
        assert result is None

    def test_cloudflare_api_token_negative_2(self) -> None:
        """Test Cloudflare API Token too short."""
        pattern = re.compile(CLOUDFLARE_API_TOKEN.regex)
        result = pattern.search("cloudflare_api_token = 'short'")
        assert result is None

    def test_cloudflare_origin_ca_key_positive_1(self) -> None:
        """Test Cloudflare Origin CA Key matches."""
        pattern = re.compile(CLOUDFLARE_ORIGIN_CA_KEY.regex)
        # v1.0- + 24 hex + - + 146-150 hex
        test_str = fake_token("v1.0-", "0" * 24, "-", "a" * 146)
        result = pattern.search(test_str)
        assert result is not None

    def test_cloudflare_origin_ca_key_positive_2(self) -> None:
        """Test Cloudflare Origin CA Key in config."""
        pattern = re.compile(CLOUDFLARE_ORIGIN_CA_KEY.regex)
        test_str = fake_token('key = "v1.0-', "abcdef" * 4, "-", "0123456789" * 15, '"')
        result = pattern.search(test_str)
        assert result is not None

    def test_cloudflare_origin_ca_key_negative_1(self) -> None:
        """Test Cloudflare Origin CA Key wrong version."""
        pattern = re.compile(CLOUDFLARE_ORIGIN_CA_KEY.regex)
        test_str = "v2.0-" + "0" * 24 + "-" + "a" * 146
        result = pattern.search(test_str)
        assert result is None

    def test_cloudflare_origin_ca_key_negative_2(self) -> None:
        """Test Cloudflare Origin CA Key too short."""
        pattern = re.compile(CLOUDFLARE_ORIGIN_CA_KEY.regex)
        result = pattern.search("v1.0-abcdef-short")
        assert result is None


class TestAlibabaPatterns:
    """Tests for Alibaba Cloud patterns."""

    def test_alibaba_access_key_id_positive_1(self) -> None:
        """Test Alibaba Access Key ID matches."""
        pattern = re.compile(ALIBABA_ACCESS_KEY_ID.regex)
        result = pattern.search("LTAI1234567890abcdef")
        assert result is not None

    def test_alibaba_access_key_id_positive_2(self) -> None:
        """Test Alibaba Access Key ID in context."""
        pattern = re.compile(ALIBABA_ACCESS_KEY_ID.regex)
        result = pattern.search("access_key_id = 'LTAIabcdefghijklmnop'")
        assert result is not None

    def test_alibaba_access_key_id_negative_1(self) -> None:
        """Test Alibaba Access Key ID wrong prefix."""
        pattern = re.compile(ALIBABA_ACCESS_KEY_ID.regex)
        result = pattern.search("LTAK1234567890abcdef")
        assert result is None

    def test_alibaba_access_key_id_negative_2(self) -> None:
        """Test Alibaba Access Key ID too short."""
        pattern = re.compile(ALIBABA_ACCESS_KEY_ID.regex)
        result = pattern.search("LTAIshort")
        assert result is None

    def test_alibaba_secret_key_positive_1(self) -> None:
        """Test Alibaba Secret Key matches."""
        pattern = re.compile(ALIBABA_SECRET_KEY.regex)
        result = pattern.search("alibaba_secret_key = 'ABCDEFghij1234567890klmnopqrst'")
        assert result is not None

    def test_alibaba_secret_key_positive_2(self) -> None:
        """Test Alibaba Secret Key alternate format."""
        pattern = re.compile(ALIBABA_SECRET_KEY.regex)
        result = pattern.search('ALIYUN_SECRET_ACCESS_KEY: "abcdefghijklmnopqrstuvwxyz1234"')
        assert result is not None

    def test_alibaba_secret_key_negative_1(self) -> None:
        """Test Alibaba Secret Key no context."""
        pattern = re.compile(ALIBABA_SECRET_KEY.regex)
        result = pattern.search("secret_key = 'ABCDEFghij1234567890klmnopqrst'")
        assert result is None

    def test_alibaba_secret_key_negative_2(self) -> None:
        """Test Alibaba Secret Key too short."""
        pattern = re.compile(ALIBABA_SECRET_KEY.regex)
        result = pattern.search("alibaba_secret_key = 'short'")
        assert result is None


class TestIBMPatterns:
    """Tests for IBM Cloud patterns."""

    def test_ibm_cloud_api_key_positive_1(self) -> None:
        """Test IBM Cloud API Key matches."""
        pattern = re.compile(IBM_CLOUD_API_KEY.regex)
        # 44 chars
        result = pattern.search(
            "ibm_cloud_api_key = 'abcdefghijklmnopqrstuvwxyz123456789012345678'"
        )
        assert result is not None

    def test_ibm_cloud_api_key_positive_2(self) -> None:
        """Test IBM Cloud API Key alternate format."""
        pattern = re.compile(IBM_CLOUD_API_KEY.regex)
        # 44 chars token
        result = pattern.search('IBM_API_KEY: "ABCDEFGHIJ-KLMNOPQRST_UVWXYZ1234567890123456"')
        assert result is not None

    def test_ibm_cloud_api_key_negative_1(self) -> None:
        """Test IBM Cloud API Key no context."""
        pattern = re.compile(IBM_CLOUD_API_KEY.regex)
        result = pattern.search("api_key = 'abcdefghijklmnopqrstuvwxyz123456789012345678'")
        assert result is None

    def test_ibm_cloud_api_key_negative_2(self) -> None:
        """Test IBM Cloud API Key too short."""
        pattern = re.compile(IBM_CLOUD_API_KEY.regex)
        result = pattern.search("ibm_cloud_api_key = 'short'")
        assert result is None

    def test_ibm_cos_hmac_key_positive_1(self) -> None:
        """Test IBM COS HMAC Key matches."""
        pattern = re.compile(IBM_COS_HMAC_KEY.regex)
        # 32 hex chars
        result = pattern.search("ibm_cos_hmac_access_key_id = '1234567890abcdef1234567890abcdef'")
        assert result is not None

    def test_ibm_cos_hmac_key_positive_2(self) -> None:
        """Test IBM COS HMAC Key alternate format."""
        pattern = re.compile(IBM_COS_HMAC_KEY.regex)
        result = pattern.search('COS_ACCESS_KEY: "abcdef1234567890abcdef1234567890"')
        assert result is not None

    def test_ibm_cos_hmac_key_negative_1(self) -> None:
        """Test IBM COS HMAC Key no context."""
        pattern = re.compile(IBM_COS_HMAC_KEY.regex)
        result = pattern.search("access_key = '1234567890abcdef1234567890abcdef'")
        assert result is None

    def test_ibm_cos_hmac_key_negative_2(self) -> None:
        """Test IBM COS HMAC Key too short."""
        pattern = re.compile(IBM_COS_HMAC_KEY.regex)
        result = pattern.search("cos_access_key = 'short'")
        assert result is None


class TestOraclePatterns:
    """Tests for Oracle Cloud patterns."""

    def test_oracle_ocid_positive_1(self) -> None:
        """Test Oracle OCID matches user."""
        pattern = re.compile(ORACLE_OCID.regex)
        test_str = "ocid1.user.oc1..aaaa" + "b" * 56
        result = pattern.search(test_str)
        assert result is not None

    def test_oracle_ocid_positive_2(self) -> None:
        """Test Oracle OCID matches compartment."""
        pattern = re.compile(ORACLE_OCID.regex)
        test_str = "ocid1.compartment.oc1..aaaa" + "c" * 56
        result = pattern.search(test_str)
        assert result is not None

    def test_oracle_ocid_negative_1(self) -> None:
        """Test Oracle OCID wrong prefix."""
        pattern = re.compile(ORACLE_OCID.regex)
        result = pattern.search("ocid2.user.oc1..aaaa" + "b" * 56)
        assert result is None

    def test_oracle_ocid_negative_2(self) -> None:
        """Test Oracle OCID too short."""
        pattern = re.compile(ORACLE_OCID.regex)
        result = pattern.search("ocid1.user.oc1..short")
        assert result is None

    def test_oracle_api_key_positive_1(self) -> None:
        """Test Oracle API Key matches."""
        pattern = re.compile(ORACLE_API_KEY.regex)
        # 40+ chars
        result = pattern.search("oracle_cloud_api_key = 'abcdefghijklmnopqrstuvwxyz1234567890ABCD'")
        assert result is not None

    def test_oracle_api_key_positive_2(self) -> None:
        """Test Oracle API Key alternate format."""
        pattern = re.compile(ORACLE_API_KEY.regex)
        result = pattern.search('ORACLE_API_KEY: "ABCDEFGHIJKLMNOPQRSTUVWXYZ/+1234567890abc="')
        assert result is not None

    def test_oracle_api_key_negative_1(self) -> None:
        """Test Oracle API Key no context."""
        pattern = re.compile(ORACLE_API_KEY.regex)
        result = pattern.search("api_key = 'abcdefghijklmnopqrstuvwxyz1234567890ABCD'")
        assert result is None

    def test_oracle_api_key_negative_2(self) -> None:
        """Test Oracle API Key too short."""
        pattern = re.compile(ORACLE_API_KEY.regex)
        result = pattern.search("oracle_api_key = 'short'")
        assert result is None

    def test_oracle_tenancy_ocid_positive_1(self) -> None:
        """Test Oracle Tenancy OCID matches."""
        pattern = re.compile(ORACLE_TENANCY_OCID.regex)
        test_str = "ocid1.tenancy.oc1..aaaa" + "b" * 56
        result = pattern.search(test_str)
        assert result is not None

    def test_oracle_tenancy_ocid_positive_2(self) -> None:
        """Test Oracle Tenancy OCID in context."""
        pattern = re.compile(ORACLE_TENANCY_OCID.regex)
        test_str = "tenancy_ocid = 'ocid1.tenancy.oc1..aaaa" + "c" * 56 + "'"
        result = pattern.search(test_str)
        assert result is not None

    def test_oracle_tenancy_ocid_negative_1(self) -> None:
        """Test Oracle Tenancy OCID wrong resource type."""
        pattern = re.compile(ORACLE_TENANCY_OCID.regex)
        result = pattern.search("ocid1.user.oc1..aaaa" + "b" * 56)
        assert result is None

    def test_oracle_tenancy_ocid_negative_2(self) -> None:
        """Test Oracle Tenancy OCID too short."""
        pattern = re.compile(ORACLE_TENANCY_OCID.regex)
        result = pattern.search("ocid1.tenancy.oc1..short")
        assert result is None


class TestCloudPatternsCollection:
    """Tests for the CLOUD_PATTERNS collection."""

    def test_all_patterns_in_collection(self) -> None:
        """Test that all defined patterns are in the collection."""
        assert len(CLOUD_PATTERNS) == 24

    def test_all_patterns_are_cloud_category(self) -> None:
        """Test that all patterns have CLOUD category."""
        for pattern in CLOUD_PATTERNS:
            assert pattern.category == PatternCategory.CLOUD

    def test_all_patterns_have_descriptions(self) -> None:
        """Test that all patterns have descriptions."""
        for pattern in CLOUD_PATTERNS:
            assert pattern.description != ""

    def test_all_patterns_have_valid_regex(self) -> None:
        """Test that all patterns have valid regex."""
        import re as regex_module

        for pattern in CLOUD_PATTERNS:
            try:
                regex_module.compile(pattern.regex)
            except regex_module.error as e:
                pytest.fail(f"Pattern {pattern.name} has invalid regex: {e}")

    def test_all_patterns_have_unique_names(self) -> None:
        """Test that all patterns have unique names."""
        names = [p.name for p in CLOUD_PATTERNS]
        assert len(names) == len(set(names))

    def test_patterns_to_dict_compatible(self) -> None:
        """Test that all patterns can be converted to dict format."""
        for pattern in CLOUD_PATTERNS:
            data = pattern.to_dict()
            assert "pattern" in data
            assert "severity" in data
            assert "description" in data
            assert "category" in data
            assert "confidence" in data
