"""Async HTTP client module for Hamburglar.

This module provides a robust async HTTP client built on httpx with
advanced features including rate limiting, retry logic with exponential
backoff, authentication support, and optional response caching.

The client is designed for web scraping and API access patterns typical
in security scanning operations.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Any

try:
    import httpx

    HTTPX_AVAILABLE = True
except ImportError:
    HTTPX_AVAILABLE = False

if TYPE_CHECKING:
    from collections.abc import Mapping

logger = logging.getLogger(__name__)


class AuthType(str, Enum):
    """Authentication types supported by the HTTP client."""

    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"


@dataclass
class AuthConfig:
    """Authentication configuration.

    Attributes:
        auth_type: Type of authentication (none, basic, bearer).
        username: Username for basic auth.
        password: Password for basic auth.
        token: Token for bearer auth.
    """

    auth_type: AuthType = AuthType.NONE
    username: str | None = None
    password: str | None = None
    token: str | None = None

    def to_httpx_auth(self) -> httpx.BasicAuth | None:
        """Convert to httpx auth object for basic auth.

        Returns:
            httpx.BasicAuth for basic auth, None otherwise.
        """
        if self.auth_type == AuthType.BASIC and self.username and self.password:
            return httpx.BasicAuth(self.username, self.password)
        return None

    def get_headers(self) -> dict[str, str]:
        """Get authentication headers.

        Returns:
            Dictionary of auth headers (for bearer token).
        """
        if self.auth_type == AuthType.BEARER and self.token:
            return {"Authorization": f"Bearer {self.token}"}
        return {}


@dataclass
class RateLimitConfig:
    """Rate limiting configuration.

    Attributes:
        requests_per_second: Maximum requests per second (0 = unlimited).
        burst_size: Maximum burst size for rate limiting.
    """

    requests_per_second: float = 0.0  # 0 = unlimited
    burst_size: int = 1

    @property
    def is_enabled(self) -> bool:
        """Check if rate limiting is enabled."""
        return self.requests_per_second > 0


@dataclass
class RetryConfig:
    """Retry configuration with exponential backoff.

    Attributes:
        max_retries: Maximum number of retry attempts.
        base_delay: Base delay between retries in seconds.
        max_delay: Maximum delay between retries in seconds.
        exponential_base: Base for exponential backoff calculation.
        retry_on_status: HTTP status codes to retry on.
    """

    max_retries: int = 3
    base_delay: float = 0.5
    max_delay: float = 30.0
    exponential_base: float = 2.0
    retry_on_status: tuple[int, ...] = (429, 500, 502, 503, 504)

    def get_delay(self, attempt: int) -> float:
        """Calculate delay for a retry attempt.

        Args:
            attempt: The retry attempt number (0-indexed).

        Returns:
            Delay in seconds for this retry attempt.
        """
        delay = self.base_delay * (self.exponential_base**attempt)
        return min(delay, self.max_delay)


@dataclass
class CacheEntry:
    """A cached HTTP response entry.

    Attributes:
        content: Response content.
        status_code: HTTP status code.
        headers: Response headers.
        timestamp: When the entry was cached.
        ttl: Time-to-live in seconds.
    """

    content: str
    status_code: int
    headers: dict[str, str]
    timestamp: float
    ttl: float

    @property
    def is_expired(self) -> bool:
        """Check if this cache entry has expired."""
        return time.time() - self.timestamp > self.ttl


@dataclass
class CacheConfig:
    """Cache configuration.

    Attributes:
        enabled: Whether caching is enabled.
        default_ttl: Default time-to-live in seconds.
        max_entries: Maximum number of cached entries.
    """

    enabled: bool = False
    default_ttl: float = 300.0  # 5 minutes
    max_entries: int = 1000


@dataclass
class HttpResponse:
    """HTTP response wrapper.

    Attributes:
        content: Response content as text.
        status_code: HTTP status code.
        headers: Response headers.
        url: Final URL after redirects.
        from_cache: Whether response came from cache.
    """

    content: str
    status_code: int
    headers: dict[str, str]
    url: str
    from_cache: bool = False


@dataclass
class HttpClientConfig:
    """Complete HTTP client configuration.

    Attributes:
        timeout: Request timeout in seconds.
        user_agent: User agent string.
        follow_redirects: Whether to follow redirects.
        max_redirects: Maximum number of redirects to follow.
        auth: Authentication configuration.
        rate_limit: Rate limiting configuration.
        retry: Retry configuration.
        cache: Cache configuration.
        verify_ssl: Whether to verify SSL certificates.
    """

    timeout: float = 30.0
    user_agent: str = (
        "Hamburglar/2.0 (Security Scanner; +https://github.com/needmorecowbell/Hamburglar)"
    )
    follow_redirects: bool = True
    max_redirects: int = 10
    auth: AuthConfig = field(default_factory=AuthConfig)
    rate_limit: RateLimitConfig = field(default_factory=RateLimitConfig)
    retry: RetryConfig = field(default_factory=RetryConfig)
    cache: CacheConfig = field(default_factory=CacheConfig)
    verify_ssl: bool = True


class RateLimiter:
    """Token bucket rate limiter for HTTP requests.

    Implements a token bucket algorithm for rate limiting with
    support for burst traffic.
    """

    def __init__(self, requests_per_second: float, burst_size: int = 1):
        """Initialize the rate limiter.

        Args:
            requests_per_second: Maximum requests per second.
            burst_size: Maximum burst size (tokens in bucket).
        """
        self.requests_per_second = requests_per_second
        self.burst_size = burst_size
        self.tokens = float(burst_size)
        self.last_update = time.monotonic()
        self._lock = asyncio.Lock()

    async def acquire(self) -> None:
        """Acquire a token, waiting if necessary.

        This method blocks until a token is available according
        to the rate limit configuration.
        """
        async with self._lock:
            now = time.monotonic()
            elapsed = now - self.last_update
            self.last_update = now

            # Add tokens based on elapsed time
            self.tokens = min(
                self.burst_size,
                self.tokens + elapsed * self.requests_per_second,
            )

            if self.tokens < 1:
                # Calculate wait time needed
                wait_time = (1 - self.tokens) / self.requests_per_second
                await asyncio.sleep(wait_time)
                self.tokens = 0
            else:
                self.tokens -= 1


class ResponseCache:
    """In-memory response cache with TTL support.

    Caches HTTP responses to reduce redundant requests,
    with automatic expiration based on TTL.
    """

    def __init__(self, max_entries: int = 1000, default_ttl: float = 300.0):
        """Initialize the response cache.

        Args:
            max_entries: Maximum number of entries to cache.
            default_ttl: Default time-to-live in seconds.
        """
        self.max_entries = max_entries
        self.default_ttl = default_ttl
        self._cache: dict[str, CacheEntry] = {}
        self._lock = asyncio.Lock()

    @staticmethod
    def _make_key(method: str, url: str, headers: dict[str, str] | None = None) -> str:
        """Generate a cache key for a request.

        Args:
            method: HTTP method.
            url: Request URL.
            headers: Request headers.

        Returns:
            Cache key string.
        """
        key_parts = [method.upper(), url]
        if headers:
            # Include relevant headers in key
            for header in sorted(headers.keys()):
                if header.lower() in ("authorization", "accept"):
                    key_parts.append(f"{header}:{headers[header]}")
        key_string = "|".join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()

    async def get(
        self, method: str, url: str, headers: dict[str, str] | None = None
    ) -> CacheEntry | None:
        """Get a cached response if available and not expired.

        Args:
            method: HTTP method.
            url: Request URL.
            headers: Request headers.

        Returns:
            Cached entry if available and not expired, None otherwise.
        """
        async with self._lock:
            key = self._make_key(method, url, headers)
            entry = self._cache.get(key)

            if entry is None:
                return None

            if entry.is_expired:
                del self._cache[key]
                return None

            return entry

    async def set(
        self,
        method: str,
        url: str,
        response: HttpResponse,
        headers: dict[str, str] | None = None,
        ttl: float | None = None,
    ) -> None:
        """Cache a response.

        Args:
            method: HTTP method.
            url: Request URL.
            response: Response to cache.
            headers: Request headers.
            ttl: Time-to-live in seconds (uses default if not specified).
        """
        async with self._lock:
            # Evict expired entries if at capacity
            if len(self._cache) >= self.max_entries:
                self._evict_expired()

            # If still at capacity, evict oldest entries
            if len(self._cache) >= self.max_entries:
                # Evict at least 1 entry, or 25% of max_entries
                count_to_evict = max(1, self.max_entries // 4)
                self._evict_oldest(count_to_evict)

            key = self._make_key(method, url, headers)
            self._cache[key] = CacheEntry(
                content=response.content,
                status_code=response.status_code,
                headers=response.headers,
                timestamp=time.time(),
                ttl=ttl if ttl is not None else self.default_ttl,
            )

    def _evict_expired(self) -> int:
        """Remove all expired entries.

        Returns:
            Number of entries evicted.
        """
        expired_keys = [key for key, entry in self._cache.items() if entry.is_expired]
        for key in expired_keys:
            del self._cache[key]
        return len(expired_keys)

    def _evict_oldest(self, count: int) -> None:
        """Evict the oldest entries.

        Args:
            count: Number of entries to evict.
        """
        if not self._cache:
            return

        # Sort by timestamp and remove oldest
        sorted_keys = sorted(
            self._cache.keys(),
            key=lambda k: self._cache[k].timestamp,
        )

        for key in sorted_keys[:count]:
            del self._cache[key]

    async def clear(self) -> None:
        """Clear all cached entries."""
        async with self._lock:
            self._cache.clear()

    @property
    def size(self) -> int:
        """Get current cache size."""
        return len(self._cache)


class HttpClientError(Exception):
    """Base exception for HTTP client errors.

    Attributes:
        message: Error message.
        url: URL that caused the error.
        status_code: HTTP status code if applicable.
    """

    def __init__(self, message: str, url: str | None = None, status_code: int | None = None):
        """Initialize the error.

        Args:
            message: Error message.
            url: URL that caused the error.
            status_code: HTTP status code if applicable.
        """
        self.message = message
        self.url = url
        self.status_code = status_code
        super().__init__(message)

    def __str__(self) -> str:
        """Return string representation."""
        parts = [self.message]
        if self.url:
            parts.append(f"url={self.url}")
        if self.status_code:
            parts.append(f"status={self.status_code}")
        return " ".join(parts)


class HttpClient:
    """Async HTTP client with advanced features.

    An HTTP client built on httpx with support for:
    - Rate limiting with token bucket algorithm
    - Retry logic with exponential backoff
    - Basic and bearer token authentication
    - Response caching with TTL
    - Redirect handling
    - Configurable timeouts

    Example:
        >>> config = HttpClientConfig(
        ...     timeout=30.0,
        ...     rate_limit=RateLimitConfig(requests_per_second=2.0),
        ...     retry=RetryConfig(max_retries=3),
        ... )
        >>> async with HttpClient(config) as client:
        ...     response = await client.get("https://example.com")
        ...     print(response.content)
    """

    def __init__(self, config: HttpClientConfig | None = None):
        """Initialize the HTTP client.

        Args:
            config: Client configuration. Uses defaults if not specified.

        Raises:
            ImportError: If httpx is not installed.
        """
        if not HTTPX_AVAILABLE:
            raise ImportError("HttpClient requires httpx. Install it with: pip install httpx")

        self.config = config or HttpClientConfig()
        self._client: httpx.AsyncClient | None = None

        # Initialize rate limiter if configured
        self._rate_limiter: RateLimiter | None = None
        if self.config.rate_limit.is_enabled:
            self._rate_limiter = RateLimiter(
                self.config.rate_limit.requests_per_second,
                self.config.rate_limit.burst_size,
            )

        # Initialize cache if configured
        self._cache: ResponseCache | None = None
        if self.config.cache.enabled:
            self._cache = ResponseCache(
                max_entries=self.config.cache.max_entries,
                default_ttl=self.config.cache.default_ttl,
            )

    async def __aenter__(self) -> HttpClient:
        """Enter async context and create the client."""
        await self._ensure_client()
        return self

    async def __aexit__(self, *args: Any) -> None:
        """Exit async context and close the client."""
        await self.close()

    async def _ensure_client(self) -> httpx.AsyncClient:
        """Ensure the httpx client is created.

        Returns:
            The httpx AsyncClient instance.
        """
        if self._client is None:
            # Build headers
            headers = {"User-Agent": self.config.user_agent}
            headers.update(self.config.auth.get_headers())

            self._client = httpx.AsyncClient(
                timeout=self.config.timeout,
                headers=headers,
                follow_redirects=self.config.follow_redirects,
                max_redirects=self.config.max_redirects,
                verify=self.config.verify_ssl,
                auth=self.config.auth.to_httpx_auth(),
            )

        return self._client

    async def close(self) -> None:
        """Close the HTTP client and release resources."""
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    async def _request(
        self,
        method: str,
        url: str,
        headers: dict[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        content: str | bytes | None = None,
        use_cache: bool = True,
    ) -> HttpResponse:
        """Execute an HTTP request with retry and rate limiting.

        Args:
            method: HTTP method (GET, POST, etc.).
            url: Request URL.
            headers: Additional request headers.
            params: Query parameters.
            content: Request body content.
            use_cache: Whether to use cached response if available.

        Returns:
            HttpResponse with the result.

        Raises:
            HttpClientError: If the request fails after all retries.
        """
        # Check cache first for GET requests
        if use_cache and self._cache is not None and method.upper() == "GET":
            cached = await self._cache.get(method, url, headers)
            if cached is not None:
                logger.debug(f"Cache hit for {url}")
                return HttpResponse(
                    content=cached.content,
                    status_code=cached.status_code,
                    headers=cached.headers,
                    url=url,
                    from_cache=True,
                )

        client = await self._ensure_client()
        last_error: Exception | None = None

        for attempt in range(self.config.retry.max_retries + 1):
            try:
                # Apply rate limiting
                if self._rate_limiter is not None:
                    await self._rate_limiter.acquire()

                # Make the request
                response = await client.request(
                    method=method,
                    url=url,
                    headers=headers,
                    params=params,
                    content=content,
                )

                # Check if we should retry based on status code
                if (
                    response.status_code in self.config.retry.retry_on_status
                    and attempt < self.config.retry.max_retries
                ):
                    delay = self.config.retry.get_delay(attempt)
                    logger.debug(
                        f"Retrying {url} after {delay:.2f}s "
                        f"(status {response.status_code}, attempt {attempt + 1})"
                    )
                    await asyncio.sleep(delay)
                    continue

                # Build response
                try:
                    content_text = response.text
                except Exception:
                    content_text = response.content.decode("utf-8", errors="replace")

                http_response = HttpResponse(
                    content=content_text,
                    status_code=response.status_code,
                    headers=dict(response.headers),
                    url=str(response.url),
                    from_cache=False,
                )

                # Cache successful GET responses
                if (
                    self._cache is not None
                    and method.upper() == "GET"
                    and 200 <= response.status_code < 300
                ):
                    await self._cache.set(method, url, http_response, headers)

                return http_response

            except httpx.TimeoutException as e:
                last_error = e
                if attempt < self.config.retry.max_retries:
                    delay = self.config.retry.get_delay(attempt)
                    logger.debug(
                        f"Timeout for {url}, retrying after {delay:.2f}s (attempt {attempt + 1})"
                    )
                    await asyncio.sleep(delay)
                else:
                    raise HttpClientError(
                        f"Request timed out after {self.config.retry.max_retries + 1} attempts",
                        url=url,
                    ) from e

            except httpx.RequestError as e:
                last_error = e
                if attempt < self.config.retry.max_retries:
                    delay = self.config.retry.get_delay(attempt)
                    logger.debug(
                        f"Request error for {url}: {e}, retrying after {delay:.2f}s "
                        f"(attempt {attempt + 1})"
                    )
                    await asyncio.sleep(delay)
                else:
                    raise HttpClientError(
                        f"Request failed after {self.config.retry.max_retries + 1} attempts: {e}",
                        url=url,
                    ) from e

        # Should not reach here, but just in case
        raise HttpClientError(
            f"Request failed after {self.config.retry.max_retries + 1} attempts",
            url=url,
        ) from last_error

    async def get(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: Mapping[str, str] | None = None,
        use_cache: bool = True,
    ) -> HttpResponse:
        """Execute a GET request.

        Args:
            url: Request URL.
            headers: Additional request headers.
            params: Query parameters.
            use_cache: Whether to use cached response if available.

        Returns:
            HttpResponse with the result.

        Raises:
            HttpClientError: If the request fails.
        """
        return await self._request("GET", url, headers=headers, params=params, use_cache=use_cache)

    async def post(
        self,
        url: str,
        content: str | bytes | None = None,
        headers: dict[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        """Execute a POST request.

        Args:
            url: Request URL.
            content: Request body content.
            headers: Additional request headers.
            params: Query parameters.

        Returns:
            HttpResponse with the result.

        Raises:
            HttpClientError: If the request fails.
        """
        return await self._request(
            "POST", url, headers=headers, params=params, content=content, use_cache=False
        )

    async def head(
        self,
        url: str,
        headers: dict[str, str] | None = None,
        params: Mapping[str, str] | None = None,
    ) -> HttpResponse:
        """Execute a HEAD request.

        Args:
            url: Request URL.
            headers: Additional request headers.
            params: Query parameters.

        Returns:
            HttpResponse with the result.

        Raises:
            HttpClientError: If the request fails.
        """
        return await self._request("HEAD", url, headers=headers, params=params, use_cache=False)

    def clear_cache(self) -> None:
        """Clear the response cache.

        This method schedules cache clearing but returns immediately.
        For async code, use `await client._cache.clear()` directly.
        """
        if self._cache is not None:
            asyncio.create_task(self._cache.clear())

    @property
    def cache_size(self) -> int:
        """Get current cache size.

        Returns:
            Number of cached entries, 0 if caching is disabled.
        """
        if self._cache is not None:
            return self._cache.size
        return 0
