
"""
NeuralBridge — Cost Optimization Engine: Response Cache.

This module provides a Redis-backed asynchronous cache for adapter responses,
reducing latency and redundant API calls for repeated prompts.

Features:
- Async Redis integration for non-blocking operations.
- Automatic cache key generation from request metadata.
- Time-to-live (TTL) management for expiring stale entries.
- Cache hit/miss statistics for performance monitoring.
- Invalidation mechanism to manually purge entries.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any

import redis.asyncio as redis
import structlog
from pydantic import BaseModel, Field

from neuralbridge.config import get_settings

logger = structlog.get_logger(__name__)
settings = get_settings()


class CacheStats(BaseModel):
    """Performance metrics for the response cache."""

    hits: int = Field(default=0, description="Number of cache hits.")
    misses: int = Field(default=0, description="Number of cache misses.")


class ResponseCache:
    """
    An asynchronous Redis-based cache for storing and retrieving adapter responses.

    This class connects to the Redis instance defined in the application settings
    and provides methods to get, set, and invalidate cached responses. It is
    designed to work seamlessly within an async application, preventing I/O
    blocking.

    Attributes:
        redis_client (redis.Redis): The asynchronous Redis client instance.
        ttl (int): The default time-to-live for cache entries, in seconds.
        stats (CacheStats): An object tracking cache hits and misses.
    """

    def __init__(self, redis_url: str = settings.redis_url, ttl: int = settings.redis_cache_ttl):
        """
        Initializes the ResponseCache instance.

        Args:
            redis_url (str): The connection URL for the Redis server.
            ttl (int): The default time-to-live for new cache entries in seconds.
        """
        try:
            self.redis_client = redis.from_url(redis_url, encoding="utf-8", decode_responses=True)
            self.ttl = ttl
            self.stats = CacheStats()
            logger.info("ResponseCache initialized successfully.", redis_url=redis_url, default_ttl=ttl)
        except Exception as e:
            logger.error("Failed to initialize ResponseCache.", error=str(e), exc_info=True)
            raise

    async def generate_cache_key(self, adapter: str, model: str, prompt: str, **kwargs: Any) -> str:
        """
        Generates a consistent, unique cache key for a given request.

        The key is an SHA-256 hash of a JSON object containing the adapter name,
        model, prompt, and any other relevant request parameters. This ensures that
        identical requests produce the same key.

        Args:
            adapter (str): The name of the adapter handling the request.
            model (str): The specific model being queried.
            prompt (str): The user-provided prompt.
            **kwargs: Additional parameters that affect the response (e.g., temperature).

        Returns:
            str: A unique SHA-256 hash representing the request.
        """
        if not all([adapter, model, prompt]):
            raise ValueError("Adapter, model, and prompt must be provided to generate a cache key.")

        payload = {
            "adapter": adapter,
            "model": model,
            "prompt": prompt,
            **kwargs,
        }
        # Sort keys to ensure consistent hash
        serialized_payload = json.dumps(payload, sort_keys=True)
        return f"nb_cache:{hashlib.sha256(serialized_payload.encode()).hexdigest()}"

    async def get(self, key: str) -> Any | None:
        """
        Retrieves a response from the cache.

        If the key exists, the corresponding value is deserialized from JSON and
        returned. If not, the cache miss counter is incremented.

        Args:
            key (str): The cache key to look up.

        Returns:
            Optional[Any]: The cached response data, or None if not found.
        """
        try:
            cached_response = await self.redis_client.get(key)
            if cached_response:
                self.stats.hits += 1
                logger.debug("Cache hit.", key=key)
                return json.loads(cached_response)
            else:
                self.stats.misses += 1
                logger.debug("Cache miss.", key=key)
                return None
        except Exception as e:
            logger.error("Failed to get from cache.", key=key, error=str(e), exc_info=True)
            return None

    async def set(self, key: str, value: Any, ttl: int | None = None) -> None:
        """
        Stores a response in the cache with a specified TTL.

        The response data is serialized to a JSON string before being stored.

        Args:
            key (str): The cache key under which to store the response.
            value (Any): The response data to cache.
            ttl (Optional[int]): The time-to-live for this entry in seconds. If not
                                 provided, the default TTL is used.
        """
        if not key or value is None:
            logger.warning("Attempted to set cache with empty key or null value.")
            return

        try:
            serialized_value = json.dumps(value)
            await self.redis_client.set(key, serialized_value, ex=ttl or self.ttl)
            logger.debug("Cache set.", key=key, ttl=ttl or self.ttl)
        except TypeError as e:
            logger.error("Failed to serialize value for caching.", key=key, error=str(e), exc_info=True)
            raise
        except Exception as e:
            logger.error("Failed to set cache.", key=key, error=str(e), exc_info=True)
            raise

    async def invalidate(self, key: str) -> None:
        """
        Removes a specific entry from the cache.

        Args:
            key (str): The cache key to delete.
        """
        try:
            await self.redis_client.delete(key)
            logger.info("Cache invalidated for key.", key=key)
        except Exception as e:
            logger.error("Failed to invalidate cache.", key=key, error=str(e), exc_info=True)

    async def get_stats(self) -> CacheStats:
        """
        Returns the current cache hit/miss statistics.

        Returns:
            CacheStats: An object containing the total number of hits and misses.
        """
        return self.stats

    async def close(self) -> None:
        """Closes the connection to the Redis server."""
        try:
            await self.redis_client.close()
            logger.info("Redis connection closed.")
        except Exception as e:
            logger.error("Failed to close Redis connection.", error=str(e), exc_info=True)


async def main() -> None:
    """Example usage of the ResponseCache."""
    logger.info("Running ResponseCache example...")
    cache = ResponseCache()

    # 1. Generate a cache key
    cache_key = await cache.generate_cache_key(
        adapter="openai", model="gpt-4", prompt="Tell me a joke.", temperature=0.7
    )
    logger.info("Generated cache key.", key=cache_key)

    # 2. First request: cache miss
    response = await cache.get(cache_key)
    logger.info("First request (miss):", response=response)

    # 3. Store a response
    mock_response = {"answer": "Why don't scientists trust atoms? Because they make up everything!"}
    await cache.set(cache_key, mock_response)
    logger.info("Stored mock response in cache.")

    # 4. Second request: cache hit
    response = await cache.get(cache_key)
    logger.info("Second request (hit):", response=response)

    # 5. Invalidate the cache
    await cache.invalidate(cache_key)
    response = await cache.get(cache_key)
    logger.info("Third request (after invalidation):", response=response)

    # 6. Get stats
    stats = await cache.get_stats()
    logger.info("Final cache stats:", hits=stats.hits, misses=stats.misses)

    await cache.close()

if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
