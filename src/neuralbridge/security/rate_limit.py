"""
NeuralBridge - Token Bucket Rate Limiter with Redis Backend.

This module provides a flexible and high-performance rate limiting solution
for the NeuralBridge enterprise middleware. It uses a token bucket algorithm
implemented on top of Redis for distributed rate limiting.

Features:
- Token bucket algorithm for smooth request handling.
- Redis backend for distributed and scalable rate limiting.
- Per-adapter, per-user, and global rate limiting scopes.
- Dynamic rate limit configuration from strings (e.g., "100/minute").
- IP allowlisting for trusted sources.
- Geofencing support (placeholder for extension).
- FastAPI middleware for easy integration.
"""

from __future__ import annotations

import time
from typing import Any

import redis.asyncio as redis
import structlog
from fastapi import Request, Response
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint

from neuralbridge.config import get_settings

logger = structlog.get_logger(__name__)



class RateLimitConfig(BaseModel):
    """
    Pydantic model for representing rate limit configurations.

    Attributes:
        limit: The number of requests allowed.
        period: The time period in seconds.
    """

    limit: int = Field(..., description="The number of requests allowed.")
    period: int = Field(..., description="The time period in seconds.")

    @classmethod
    def from_string(cls, rate_string: str) -> RateLimitConfig:
        """
        Parse a rate limit string like '100/minute' into a RateLimitConfig object.

        Args:
            rate_string: The rate limit string to parse.

        Returns:
            A RateLimitConfig object.

        Raises:
            ValueError: If the rate limit string is invalid.
        """
        try:
            parts = rate_string.split("/")
            if len(parts) != 2:
                raise ValueError("Invalid rate limit string format. Expected 'limit/period'.")

            limit = int(parts[0])
            period_str = parts[1].lower()

            if period_str == "second":
                period = 1
            elif period_str == "minute":
                period = 60
            elif period_str == "hour":
                period = 3600
            elif period_str == "day":
                period = 86400
            else:
                raise ValueError(f"Invalid time period: {period_str}")

            return cls(limit=limit, period=period)
        except (ValueError, IndexError) as e:
            logger.error("invalid_rate_limit_string", rate_string=rate_string, error=str(e))
            raise ValueError(f"Invalid rate limit string: {rate_string}") from e


class RateLimiter:
    """
    A token bucket rate limiter that uses Redis as a backend.

    This class implements the token bucket algorithm for rate limiting. It stores
    the token bucket state in Redis, making it suitable for distributed systems.
    """

    def __init__(self, redis_client: redis.Redis, config: RateLimitConfig):
        """
        Initialize the RateLimiter.

        Args:
            redis_client: An asynchronous Redis client instance.
            config: The rate limit configuration.
        """
        self.redis = redis_client
        self.config = config

    async def is_allowed(self, key: str) -> bool:
        """
        Check if a request is allowed under the rate limit for a given key.

        This method implements the token bucket algorithm.

        Args:
            key: The key to rate limit against (e.g., user ID, IP address).

        Returns:
            True if the request is allowed, False otherwise.
        """
        now = time.time()
        bucket_key = f"rate_limit:{key}"

        async with self.redis.pipeline(transaction=True) as pipe:
            pipe.hgetall(bucket_key)
            await pipe.execute()

            bucket_state = (await pipe.execute())[0]

            if not bucket_state:
                tokens: float = float(self.config.limit - 1)
                last_refill: float = float(now)
                await self.redis.hmset(bucket_key, {"tokens": tokens, "last_refill": last_refill})
                return True

            last_refill = float(bucket_state.get(b"last_refill", now))
            tokens = float(bucket_state.get(b"tokens", self.config.limit))

            time_passed = now - last_refill
            refill_amount = time_passed * (self.config.limit / self.config.period)

            tokens = min(float(self.config.limit), tokens + refill_amount)
            last_refill = float(now)

            if tokens >= 1:
                tokens -= 1
                await self.redis.hmset(bucket_key, {"tokens": tokens, "last_refill": last_refill})
                return True
            else:
                return False


async def check_rate_limit(
    request: Request,
    redis_client: redis.Redis,
    config: RateLimitConfig,
    user_id: str | None = None,
    adapter_id: str | None = None,
) -> bool:
    """
    Check if a request is within the rate limits.

    This function checks rate limits based on user, adapter, and IP address.
    It also supports IP allowlisting and geofencing (placeholder).

    Args:
        request: The incoming FastAPI request.
        redis_client: An asynchronous Redis client instance.
        config: The rate limit configuration.
        user_id: The ID of the user making the request.
        adapter_id: The ID of the adapter being used.

    Returns:
        True if the request is allowed, False otherwise.
    """
    settings = get_settings()
    client_ip = request.client.host if request.client else "unknown"

    # 1. IP Allowlisting
    if client_ip in getattr(settings, "rate_limit_ip_allowlist", []):
        logger.debug("ip_allowlisted", client_ip=client_ip)
        return True

    # 2. Geofencing (Placeholder)
    # Here you could add logic to check the client's location based on IP
    # and apply different rate limits or block the request.
    # For example, using a GeoIP database.

    rate_limiter = RateLimiter(redis_client, config)

    # 3. Per-User Rate Limiting
    if user_id:
        if not await rate_limiter.is_allowed(f"user:{user_id}"):
            logger.warning("rate_limit_exceeded", scope="user", user_id=user_id)
            return False

    # 4. Per-Adapter Rate Limiting
    if adapter_id:
        if not await rate_limiter.is_allowed(f"adapter:{adapter_id}"):
            logger.warning("rate_limit_exceeded", scope="adapter", adapter_id=adapter_id)
            return False

    # 5. Global Rate Limiting (by IP)
    if not await rate_limiter.is_allowed(f"ip:{client_ip}"):
        logger.warning("rate_limit_exceeded", scope="global", client_ip=client_ip)
        return False

    return True


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for automatic rate limiting.

    This middleware intercepts all incoming requests and applies rate limiting
    based on the configured settings.
    """

    def __init__(self, app: Any, redis_client: redis.Redis) -> None:
        super().__init__(app)
        self.redis_client = redis_client
        settings = get_settings()
        self.default_config = RateLimitConfig.from_string(settings.rate_limit_default)

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """
        Dispatch method for the middleware.

        Args:
            request: The incoming request.
            call_next: The next middleware or request handler.

        Returns:
            The response from the next middleware or request handler.
        """
        user_id = request.state.user.id if hasattr(request.state, "user") else None
        adapter_id = request.headers.get("X-Adapter-ID")

        allowed = await check_rate_limit(
            request,
            self.redis_client,
            self.default_config,
            user_id=user_id,
            adapter_id=adapter_id,
        )

        if not allowed:
            return Response(content="Too Many Requests", status_code=429)

        response = await call_next(request)
        return response
