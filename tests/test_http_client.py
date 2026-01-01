"""Tests for the async HTTP client module.

This module tests the HTTP client functionality including:
- Basic GET request works
- Rate limiting works
- Retry logic works
- Authentication headers are sent
- Redirects are followed
- Caching works correctly
- Error handling
"""

from __future__ import annotations

import asyncio
import sys
import time
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

# Configure path before any hamburglar imports
src_path = str(Path(__file__).parent.parent / "src")
if src_path in sys.path:
    sys.path.remove(src_path)
sys.path.insert(0, src_path)

# Clear any cached modules
for key in list(sys.modules.keys()):
    if key == "hamburglar" or key.startswith("hamburglar."):
        del sys.modules[key]

from hamburglar.core.http_client import (  # noqa: E402
    AuthConfig,
    AuthType,
    CacheConfig,
    CacheEntry,
    HttpClient,
    HttpClientConfig,
    HttpClientError,
    HttpResponse,
    RateLimitConfig,
    RateLimiter,
    ResponseCache,
    RetryConfig,
)


class TestAuthConfig:
    """Test AuthConfig dataclass."""

    def test_default_auth_type(self):
        """Test default auth type is NONE."""
        config = AuthConfig()
        assert config.auth_type == AuthType.NONE

    def test_basic_auth_to_httpx_auth(self):
        """Test basic auth conversion to httpx."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            username="user",
            password="pass",
        )
        auth = config.to_httpx_auth()
        assert auth is not None
        # httpx.BasicAuth stores credentials internally

    def test_bearer_auth_returns_none_for_httpx(self):
        """Test bearer auth returns None for httpx auth (uses headers instead)."""
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            token="my-token",
        )
        auth = config.to_httpx_auth()
        assert auth is None

    def test_bearer_auth_headers(self):
        """Test bearer auth returns correct headers."""
        config = AuthConfig(
            auth_type=AuthType.BEARER,
            token="my-token",
        )
        headers = config.get_headers()
        assert headers == {"Authorization": "Bearer my-token"}

    def test_no_auth_headers(self):
        """Test no auth returns empty headers."""
        config = AuthConfig()
        headers = config.get_headers()
        assert headers == {}

    def test_basic_auth_headers(self):
        """Test basic auth returns empty headers (uses httpx auth instead)."""
        config = AuthConfig(
            auth_type=AuthType.BASIC,
            username="user",
            password="pass",
        )
        headers = config.get_headers()
        assert headers == {}

    def test_basic_auth_without_credentials(self):
        """Test basic auth without credentials returns None."""
        config = AuthConfig(auth_type=AuthType.BASIC)
        auth = config.to_httpx_auth()
        assert auth is None


class TestRateLimitConfig:
    """Test RateLimitConfig dataclass."""

    def test_default_disabled(self):
        """Test rate limiting is disabled by default."""
        config = RateLimitConfig()
        assert config.is_enabled is False

    def test_enabled_when_positive(self):
        """Test rate limiting is enabled with positive rate."""
        config = RateLimitConfig(requests_per_second=1.0)
        assert config.is_enabled is True


class TestRetryConfig:
    """Test RetryConfig dataclass."""

    def test_default_values(self):
        """Test default retry configuration."""
        config = RetryConfig()
        assert config.max_retries == 3
        assert config.base_delay == 0.5
        assert config.max_delay == 30.0

    def test_get_delay_exponential(self):
        """Test exponential backoff calculation."""
        config = RetryConfig(base_delay=1.0, exponential_base=2.0)
        assert config.get_delay(0) == 1.0
        assert config.get_delay(1) == 2.0
        assert config.get_delay(2) == 4.0

    def test_get_delay_capped(self):
        """Test delay is capped at max_delay."""
        config = RetryConfig(base_delay=1.0, max_delay=5.0, exponential_base=2.0)
        assert config.get_delay(0) == 1.0
        assert config.get_delay(1) == 2.0
        assert config.get_delay(2) == 4.0
        assert config.get_delay(3) == 5.0  # Capped at max_delay
        assert config.get_delay(10) == 5.0  # Still capped


class TestCacheEntry:
    """Test CacheEntry dataclass."""

    def test_not_expired(self):
        """Test entry is not expired when within TTL."""
        entry = CacheEntry(
            content="test",
            status_code=200,
            headers={},
            timestamp=time.time(),
            ttl=300.0,
        )
        assert entry.is_expired is False

    def test_expired(self):
        """Test entry is expired when past TTL."""
        entry = CacheEntry(
            content="test",
            status_code=200,
            headers={},
            timestamp=time.time() - 400,  # 400 seconds ago
            ttl=300.0,  # 5 minute TTL
        )
        assert entry.is_expired is True


class TestHttpResponse:
    """Test HttpResponse dataclass."""

    def test_create_response(self):
        """Test creating an HTTP response."""
        response = HttpResponse(
            content="Hello",
            status_code=200,
            headers={"Content-Type": "text/html"},
            url="https://example.com",
        )
        assert response.content == "Hello"
        assert response.status_code == 200
        assert response.from_cache is False

    def test_from_cache_flag(self):
        """Test from_cache flag."""
        response = HttpResponse(
            content="Cached",
            status_code=200,
            headers={},
            url="https://example.com",
            from_cache=True,
        )
        assert response.from_cache is True


class TestHttpClientConfig:
    """Test HttpClientConfig dataclass."""

    def test_default_values(self):
        """Test default configuration values."""
        config = HttpClientConfig()
        assert config.timeout == 30.0
        assert "Hamburglar" in config.user_agent
        assert config.follow_redirects is True
        assert config.max_redirects == 10
        assert config.verify_ssl is True

    def test_custom_values(self):
        """Test custom configuration values."""
        config = HttpClientConfig(
            timeout=60.0,
            user_agent="Custom Agent",
            follow_redirects=False,
            verify_ssl=False,
        )
        assert config.timeout == 60.0
        assert config.user_agent == "Custom Agent"
        assert config.follow_redirects is False
        assert config.verify_ssl is False


class TestRateLimiter:
    """Test RateLimiter class."""

    @pytest.mark.asyncio
    async def test_acquire_without_waiting(self):
        """Test acquiring token when tokens are available."""
        limiter = RateLimiter(requests_per_second=10.0, burst_size=5)
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        # Should be nearly instant
        assert elapsed < 0.1

    @pytest.mark.asyncio
    async def test_acquire_with_waiting(self):
        """Test acquiring token when waiting is required."""
        limiter = RateLimiter(requests_per_second=10.0, burst_size=1)
        # Exhaust tokens
        await limiter.acquire()

        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start

        # Should wait approximately 0.1 seconds (1/10 RPS)
        assert elapsed >= 0.05  # Allow some tolerance

    @pytest.mark.asyncio
    async def test_token_refill(self):
        """Test that tokens refill over time."""
        limiter = RateLimiter(requests_per_second=10.0, burst_size=2)

        # Use both tokens
        await limiter.acquire()
        await limiter.acquire()

        # Wait for tokens to refill
        await asyncio.sleep(0.15)

        # Should be able to acquire without significant wait
        start = time.monotonic()
        await limiter.acquire()
        elapsed = time.monotonic() - start
        assert elapsed < 0.05


class TestResponseCache:
    """Test ResponseCache class."""

    @pytest.mark.asyncio
    async def test_cache_miss(self):
        """Test cache miss returns None."""
        cache = ResponseCache()
        result = await cache.get("GET", "https://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_hit(self):
        """Test cache hit returns entry."""
        cache = ResponseCache()
        response = HttpResponse(
            content="Hello",
            status_code=200,
            headers={"X-Test": "value"},
            url="https://example.com",
        )
        await cache.set("GET", "https://example.com", response)

        result = await cache.get("GET", "https://example.com")
        assert result is not None
        assert result.content == "Hello"
        assert result.status_code == 200

    @pytest.mark.asyncio
    async def test_cache_expired_entry(self):
        """Test expired cache entry returns None."""
        cache = ResponseCache(default_ttl=0.1)  # Very short TTL
        response = HttpResponse(
            content="Hello",
            status_code=200,
            headers={},
            url="https://example.com",
        )
        await cache.set("GET", "https://example.com", response)

        # Wait for expiration
        await asyncio.sleep(0.15)

        result = await cache.get("GET", "https://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_different_urls(self):
        """Test different URLs are cached separately."""
        cache = ResponseCache()

        response1 = HttpResponse(
            content="Page 1",
            status_code=200,
            headers={},
            url="https://example.com/1",
        )
        response2 = HttpResponse(
            content="Page 2",
            status_code=200,
            headers={},
            url="https://example.com/2",
        )

        await cache.set("GET", "https://example.com/1", response1)
        await cache.set("GET", "https://example.com/2", response2)

        result1 = await cache.get("GET", "https://example.com/1")
        result2 = await cache.get("GET", "https://example.com/2")

        assert result1 is not None
        assert result1.content == "Page 1"
        assert result2 is not None
        assert result2.content == "Page 2"

    @pytest.mark.asyncio
    async def test_cache_eviction(self):
        """Test cache evicts old entries when full."""
        cache = ResponseCache(max_entries=2)

        for i in range(3):
            response = HttpResponse(
                content=f"Page {i}",
                status_code=200,
                headers={},
                url=f"https://example.com/{i}",
            )
            await cache.set("GET", f"https://example.com/{i}", response)
            await asyncio.sleep(0.01)  # Ensure different timestamps

        # Oldest entry should be evicted
        assert cache.size <= 2

    @pytest.mark.asyncio
    async def test_cache_clear(self):
        """Test clearing the cache."""
        cache = ResponseCache()
        response = HttpResponse(
            content="Hello",
            status_code=200,
            headers={},
            url="https://example.com",
        )
        await cache.set("GET", "https://example.com", response)

        await cache.clear()

        assert cache.size == 0
        result = await cache.get("GET", "https://example.com")
        assert result is None

    @pytest.mark.asyncio
    async def test_cache_size_property(self):
        """Test cache size property."""
        cache = ResponseCache()
        assert cache.size == 0

        response = HttpResponse(
            content="Hello",
            status_code=200,
            headers={},
            url="https://example.com",
        )
        await cache.set("GET", "https://example.com", response)

        assert cache.size == 1


class TestHttpClientError:
    """Test HttpClientError exception."""

    def test_error_with_message(self):
        """Test error with message only."""
        error = HttpClientError("Something went wrong")
        assert str(error) == "Something went wrong"

    def test_error_with_url(self):
        """Test error with URL."""
        error = HttpClientError("Failed", url="https://example.com")
        assert "https://example.com" in str(error)

    def test_error_with_status_code(self):
        """Test error with status code."""
        error = HttpClientError("Failed", status_code=404)
        assert "404" in str(error)

    def test_error_with_all_fields(self):
        """Test error with all fields."""
        error = HttpClientError(
            "Request failed",
            url="https://example.com",
            status_code=500,
        )
        error_str = str(error)
        assert "Request failed" in error_str
        assert "https://example.com" in error_str
        assert "500" in error_str


class TestHttpClientBasic:
    """Test basic HttpClient functionality."""

    def test_init_with_defaults(self):
        """Test initialization with default config."""
        client = HttpClient()
        assert client.config is not None
        assert client.config.timeout == 30.0

    def test_init_with_custom_config(self):
        """Test initialization with custom config."""
        config = HttpClientConfig(timeout=60.0)
        client = HttpClient(config)
        assert client.config.timeout == 60.0

    def test_init_with_rate_limit(self):
        """Test initialization with rate limiting."""
        config = HttpClientConfig(rate_limit=RateLimitConfig(requests_per_second=2.0))
        client = HttpClient(config)
        assert client._rate_limiter is not None

    def test_init_without_rate_limit(self):
        """Test initialization without rate limiting."""
        config = HttpClientConfig()
        client = HttpClient(config)
        assert client._rate_limiter is None

    def test_init_with_cache(self):
        """Test initialization with caching."""
        config = HttpClientConfig(cache=CacheConfig(enabled=True))
        client = HttpClient(config)
        assert client._cache is not None

    def test_init_without_cache(self):
        """Test initialization without caching."""
        config = HttpClientConfig()
        client = HttpClient(config)
        assert client._cache is None

    def test_cache_size_without_cache(self):
        """Test cache_size returns 0 when caching disabled."""
        client = HttpClient()
        assert client.cache_size == 0


class TestHttpClientRequests:
    """Test HTTP client request methods."""

    @pytest.mark.asyncio
    async def test_get_request(self):
        """Test basic GET request works."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Hello World"
            mock_response.headers = {"Content-Type": "text/html"}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                response = await client.get("https://example.com")

            assert response.status_code == 200
            assert response.content == "Hello World"
            mock_client.request.assert_called_once()

    @pytest.mark.asyncio
    async def test_post_request(self):
        """Test POST request works."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.text = '{"id": 1}'
            mock_response.headers = {"Content-Type": "application/json"}
            mock_response.url = "https://example.com/api"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                response = await client.post(
                    "https://example.com/api",
                    content='{"name": "test"}',
                )

            assert response.status_code == 201
            assert response.content == '{"id": 1}'

    @pytest.mark.asyncio
    async def test_head_request(self):
        """Test HEAD request works."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = ""
            mock_response.headers = {"Content-Length": "1234"}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                response = await client.head("https://example.com")

            assert response.status_code == 200


class TestHttpClientRetry:
    """Test HTTP client retry logic."""

    @pytest.mark.asyncio
    async def test_retry_on_status_code(self):
        """Test retry on retriable status codes."""
        config = HttpClientConfig(
            retry=RetryConfig(
                max_retries=2,
                base_delay=0.01,  # Short delay for testing
                retry_on_status=(503,),
            )
        )
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            # First call returns 503, second returns 200
            mock_response_503 = MagicMock()
            mock_response_503.status_code = 503
            mock_response_503.text = "Service Unavailable"
            mock_response_503.headers = {}
            mock_response_503.url = "https://example.com"

            mock_response_200 = MagicMock()
            mock_response_200.status_code = 200
            mock_response_200.text = "OK"
            mock_response_200.headers = {}
            mock_response_200.url = "https://example.com"

            mock_client.request = AsyncMock(side_effect=[mock_response_503, mock_response_200])

            async with client:
                response = await client.get("https://example.com")

            assert response.status_code == 200
            assert mock_client.request.call_count == 2

    @pytest.mark.asyncio
    async def test_retry_on_timeout(self):
        """Test retry on timeout."""
        import httpx

        config = HttpClientConfig(
            retry=RetryConfig(
                max_retries=2,
                base_delay=0.01,
            )
        )
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"

            # First call times out, second succeeds
            mock_client.request = AsyncMock(
                side_effect=[httpx.TimeoutException("timeout"), mock_response]
            )

            async with client:
                response = await client.get("https://example.com")

            assert response.status_code == 200
            assert mock_client.request.call_count == 2

    @pytest.mark.asyncio
    async def test_max_retries_exceeded_timeout(self):
        """Test error raised when max retries exceeded on timeout."""
        import httpx

        config = HttpClientConfig(
            retry=RetryConfig(
                max_retries=1,
                base_delay=0.01,
            )
        )
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            # All calls timeout
            mock_client.request = AsyncMock(side_effect=httpx.TimeoutException("timeout"))

            async with client:
                with pytest.raises(HttpClientError) as exc_info:
                    await client.get("https://example.com")

            assert "timed out" in str(exc_info.value)

    @pytest.mark.asyncio
    async def test_max_retries_exceeded_request_error(self):
        """Test error raised when max retries exceeded on request error."""
        import httpx

        config = HttpClientConfig(
            retry=RetryConfig(
                max_retries=1,
                base_delay=0.01,
            )
        )
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            # All calls fail with request error
            mock_client.request = AsyncMock(side_effect=httpx.RequestError("Connection failed"))

            async with client:
                with pytest.raises(HttpClientError) as exc_info:
                    await client.get("https://example.com")

            assert "failed" in str(exc_info.value).lower()


class TestHttpClientAuthentication:
    """Test HTTP client authentication."""

    @pytest.mark.asyncio
    async def test_basic_auth_headers_sent(self):
        """Test basic auth is sent with request."""
        config = HttpClientConfig(
            auth=AuthConfig(
                auth_type=AuthType.BASIC,
                username="user",
                password="pass",
            )
        )
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get("https://example.com")

            # Check that auth was passed to httpx.AsyncClient
            call_kwargs = mock_client_class.call_args.kwargs
            assert call_kwargs.get("auth") is not None

    @pytest.mark.asyncio
    async def test_bearer_auth_headers_sent(self):
        """Test bearer auth headers are sent with request."""
        config = HttpClientConfig(
            auth=AuthConfig(
                auth_type=AuthType.BEARER,
                token="my-secret-token",
            )
        )
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get("https://example.com")

            # Check that bearer token is in headers
            call_kwargs = mock_client_class.call_args.kwargs
            headers = call_kwargs.get("headers", {})
            assert headers.get("Authorization") == "Bearer my-secret-token"


class TestHttpClientRedirects:
    """Test HTTP client redirect handling."""

    @pytest.mark.asyncio
    async def test_redirects_followed(self):
        """Test redirects are followed by default."""
        config = HttpClientConfig(follow_redirects=True)
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Final page"
            mock_response.headers = {}
            mock_response.url = "https://example.com/final"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                response = await client.get("https://example.com/redirect")

            assert response.url == "https://example.com/final"

            # Verify follow_redirects was passed to httpx
            call_kwargs = mock_client_class.call_args.kwargs
            assert call_kwargs.get("follow_redirects") is True

    @pytest.mark.asyncio
    async def test_redirects_not_followed(self):
        """Test redirects are not followed when disabled."""
        config = HttpClientConfig(follow_redirects=False)
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 302
            mock_response.text = ""
            mock_response.headers = {"Location": "/new-location"}
            mock_response.url = "https://example.com/redirect"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                response = await client.get("https://example.com/redirect")

            assert response.status_code == 302

            # Verify follow_redirects was passed as False
            call_kwargs = mock_client_class.call_args.kwargs
            assert call_kwargs.get("follow_redirects") is False


class TestHttpClientCaching:
    """Test HTTP client caching."""

    @pytest.mark.asyncio
    async def test_cache_stores_response(self):
        """Test successful GET responses are cached."""
        config = HttpClientConfig(cache=CacheConfig(enabled=True))
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Cached content"
            mock_response.headers = {"X-Test": "value"}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                # First request
                response1 = await client.get("https://example.com")
                # Second request should be cached
                response2 = await client.get("https://example.com")

            assert response1.from_cache is False
            assert response2.from_cache is True
            assert response2.content == "Cached content"
            # Only one actual request should be made
            assert mock_client.request.call_count == 1

    @pytest.mark.asyncio
    async def test_cache_bypass(self):
        """Test cache can be bypassed."""
        config = HttpClientConfig(cache=CacheConfig(enabled=True))
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "Fresh content"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                # First request
                await client.get("https://example.com")
                # Second request bypasses cache
                response = await client.get("https://example.com", use_cache=False)

            assert response.from_cache is False
            # Two actual requests should be made
            assert mock_client.request.call_count == 2

    @pytest.mark.asyncio
    async def test_post_not_cached(self):
        """Test POST requests are not cached."""
        config = HttpClientConfig(cache=CacheConfig(enabled=True))
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 201
            mock_response.text = '{"id": 1}'
            mock_response.headers = {}
            mock_response.url = "https://example.com/api"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.post("https://example.com/api", content="data")
                await client.post("https://example.com/api", content="data")

            # Both requests should be made (no caching for POST)
            assert mock_client.request.call_count == 2


class TestHttpClientRateLimit:
    """Test HTTP client rate limiting."""

    @pytest.mark.asyncio
    async def test_rate_limit_applied(self):
        """Test rate limiting is applied to requests."""
        config = HttpClientConfig(rate_limit=RateLimitConfig(requests_per_second=5.0, burst_size=1))
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                start = time.monotonic()
                # Make 3 requests with rate limit of 5/sec
                await client.get("https://example.com/1")
                await client.get("https://example.com/2")
                await client.get("https://example.com/3")
                elapsed = time.monotonic() - start

            # With 5 RPS and burst of 1, 3 requests should take ~0.4 seconds
            # (first is instant, second waits 0.2s, third waits 0.2s)
            # Allow tolerance for timing variations
            assert elapsed >= 0.15  # At least some delay should occur


class TestHttpClientContextManager:
    """Test HTTP client context manager."""

    @pytest.mark.asyncio
    async def test_context_manager(self):
        """Test async context manager properly opens and closes client."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            async with client:
                assert client._client is not None

            mock_client.aclose.assert_called_once()

    @pytest.mark.asyncio
    async def test_close_without_open(self):
        """Test closing client that was never opened."""
        config = HttpClientConfig()
        client = HttpClient(config)

        # Should not raise
        await client.close()


class TestHttpClientUserAgent:
    """Test HTTP client user agent."""

    @pytest.mark.asyncio
    async def test_default_user_agent(self):
        """Test default user agent is set."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get("https://example.com")

            call_kwargs = mock_client_class.call_args.kwargs
            headers = call_kwargs.get("headers", {})
            assert "Hamburglar" in headers.get("User-Agent", "")

    @pytest.mark.asyncio
    async def test_custom_user_agent(self):
        """Test custom user agent is set."""
        config = HttpClientConfig(user_agent="Custom Bot/1.0")
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get("https://example.com")

            call_kwargs = mock_client_class.call_args.kwargs
            headers = call_kwargs.get("headers", {})
            assert headers.get("User-Agent") == "Custom Bot/1.0"


class TestHttpClientSSL:
    """Test HTTP client SSL verification."""

    @pytest.mark.asyncio
    async def test_ssl_verify_enabled(self):
        """Test SSL verification is enabled by default."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get("https://example.com")

            call_kwargs = mock_client_class.call_args.kwargs
            assert call_kwargs.get("verify") is True

    @pytest.mark.asyncio
    async def test_ssl_verify_disabled(self):
        """Test SSL verification can be disabled."""
        config = HttpClientConfig(verify_ssl=False)
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get("https://example.com")

            call_kwargs = mock_client_class.call_args.kwargs
            assert call_kwargs.get("verify") is False


class TestHttpClientTextDecoding:
    """Test HTTP client text decoding."""

    @pytest.mark.asyncio
    async def test_text_decoding_fallback(self):
        """Test fallback to bytes decoding when text fails."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            # Simulate text decoding failure
            type(mock_response).text = property(
                lambda self: (_ for _ in ()).throw(UnicodeDecodeError("utf-8", b"", 0, 1, "test"))
            )
            mock_response.content = b"Fallback content"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                response = await client.get("https://example.com")

            assert response.content == "Fallback content"


class TestHttpClientQueryParams:
    """Test HTTP client query parameters."""

    @pytest.mark.asyncio
    async def test_get_with_params(self):
        """Test GET request with query parameters."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com?foo=bar"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get(
                    "https://example.com",
                    params={"foo": "bar", "baz": "qux"},
                )

            call_kwargs = mock_client.request.call_args.kwargs
            assert call_kwargs.get("params") == {"foo": "bar", "baz": "qux"}


class TestHttpClientHeaders:
    """Test HTTP client custom headers."""

    @pytest.mark.asyncio
    async def test_get_with_custom_headers(self):
        """Test GET request with custom headers."""
        config = HttpClientConfig()
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get(
                    "https://example.com",
                    headers={"X-Custom": "value"},
                )

            call_kwargs = mock_client.request.call_args.kwargs
            assert call_kwargs.get("headers") == {"X-Custom": "value"}


class TestResponseCacheAdvanced:
    """Advanced tests for ResponseCache."""

    @pytest.mark.asyncio
    async def test_cache_key_with_auth_headers(self):
        """Test cache key includes authorization headers."""
        cache = ResponseCache()

        response1 = HttpResponse(
            content="User 1 data",
            status_code=200,
            headers={},
            url="https://example.com",
        )
        response2 = HttpResponse(
            content="User 2 data",
            status_code=200,
            headers={},
            url="https://example.com",
        )

        # Cache with different auth headers
        await cache.set(
            "GET", "https://example.com", response1, headers={"Authorization": "Bearer token1"}
        )
        await cache.set(
            "GET", "https://example.com", response2, headers={"Authorization": "Bearer token2"}
        )

        # Both should be cached separately
        result1 = await cache.get(
            "GET", "https://example.com", headers={"Authorization": "Bearer token1"}
        )
        result2 = await cache.get(
            "GET", "https://example.com", headers={"Authorization": "Bearer token2"}
        )

        assert result1 is not None
        assert result1.content == "User 1 data"
        assert result2 is not None
        assert result2.content == "User 2 data"

    @pytest.mark.asyncio
    async def test_cache_key_with_accept_headers(self):
        """Test cache key includes accept headers."""
        cache = ResponseCache()

        response1 = HttpResponse(
            content='{"data": "json"}',
            status_code=200,
            headers={},
            url="https://example.com",
        )
        response2 = HttpResponse(
            content="<html>data</html>",
            status_code=200,
            headers={},
            url="https://example.com",
        )

        # Cache with different accept headers
        await cache.set(
            "GET", "https://example.com", response1, headers={"Accept": "application/json"}
        )
        await cache.set("GET", "https://example.com", response2, headers={"Accept": "text/html"})

        result1 = await cache.get(
            "GET", "https://example.com", headers={"Accept": "application/json"}
        )
        result2 = await cache.get("GET", "https://example.com", headers={"Accept": "text/html"})

        assert result1 is not None
        assert result1.content == '{"data": "json"}'
        assert result2 is not None
        assert result2.content == "<html>data</html>"

    @pytest.mark.asyncio
    async def test_evict_expired_removes_old_entries(self):
        """Test that _evict_expired removes old entries."""
        cache = ResponseCache(default_ttl=0.01)  # Very short TTL

        response = HttpResponse(
            content="Old data",
            status_code=200,
            headers={},
            url="https://example.com",
        )
        await cache.set("GET", "https://example.com", response)

        # Wait for expiration
        await asyncio.sleep(0.02)

        # Trigger eviction by setting a new entry (at capacity 1)
        cache.max_entries = 1
        new_response = HttpResponse(
            content="New data",
            status_code=200,
            headers={},
            url="https://example.com/new",
        )
        await cache.set("GET", "https://example.com/new", new_response)

        # Expired entry should have been evicted
        old_result = await cache.get("GET", "https://example.com")
        assert old_result is None

    @pytest.mark.asyncio
    async def test_evict_oldest_on_empty_cache(self):
        """Test _evict_oldest on empty cache doesn't fail."""
        cache = ResponseCache(max_entries=1)
        # This should not raise - evicting from empty cache
        cache._evict_oldest(1)
        assert cache.size == 0


class TestHttpClientClearCache:
    """Test HTTP client cache clearing."""

    @pytest.mark.asyncio
    async def test_clear_cache_with_caching_enabled(self):
        """Test clear_cache when caching is enabled."""
        config = HttpClientConfig(cache=CacheConfig(enabled=True))
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                await client.get("https://example.com")
                assert client.cache_size == 1
                client.clear_cache()
                # Give the async task time to complete
                await asyncio.sleep(0.01)
                assert client.cache_size == 0

    def test_clear_cache_without_caching(self):
        """Test clear_cache when caching is disabled."""
        config = HttpClientConfig()
        client = HttpClient(config)
        # Should not raise
        client.clear_cache()

    @pytest.mark.asyncio
    async def test_cache_size_with_caching_enabled(self):
        """Test cache_size property when caching is enabled."""
        config = HttpClientConfig(cache=CacheConfig(enabled=True))
        client = HttpClient(config)

        with patch("httpx.AsyncClient") as mock_client_class:
            mock_client = MagicMock()
            mock_client_class.return_value = mock_client
            mock_client.aclose = AsyncMock()

            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = "OK"
            mock_response.headers = {}
            mock_response.url = "https://example.com"
            mock_client.request = AsyncMock(return_value=mock_response)

            async with client:
                assert client.cache_size == 0
                await client.get("https://example.com")
                assert client.cache_size == 1
                await client.get("https://example.com/2")
                assert client.cache_size == 2


class TestHttpxImportError:
    """Test behavior when httpx is not available."""

    def test_import_error_when_httpx_unavailable(self):
        """Test ImportError is raised when httpx is not available."""
        # Reimport to get fresh reference

        import hamburglar.core.http_client as http_client_module

        # Save original value
        original_value = http_client_module.HTTPX_AVAILABLE

        try:
            # Temporarily set to False
            http_client_module.HTTPX_AVAILABLE = False

            # Create the client directly from the module
            with pytest.raises(ImportError) as exc_info:
                http_client_module.HttpClient()

            assert "httpx" in str(exc_info.value)
        finally:
            # Restore original value
            http_client_module.HTTPX_AVAILABLE = original_value
