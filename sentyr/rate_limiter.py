"""Distributed rate limiting using Redis.

Provides scalable rate limiting that works across multiple API instances:
- Sliding window algorithm for accurate rate limiting
- Redis-based for horizontal scalability
- Graceful fallback to in-memory limiting
- Configurable per-client and global limits
"""

import time
from datetime import datetime
from typing import Optional
from collections import defaultdict
from sentyr.logger import get_logger

logger = get_logger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available for distributed rate limiting")


class RedisRateLimiter:
    """Redis-based distributed rate limiter using sliding window algorithm."""

    def __init__(
        self,
        redis_host: str = "localhost",
        redis_port: int = 6379,
        redis_db: int = 1,
        redis_password: Optional[str] = None,
        max_requests: int = 100,
        window_seconds: int = 60
    ):
        """
        Initialize Redis rate limiter.

        Args:
            redis_host: Redis server host
            redis_port: Redis server port
            redis_db: Redis database number
            redis_password: Redis password (if authentication is enabled)
            max_requests: Maximum requests allowed per window
            window_seconds: Time window in seconds
        """
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.use_redis = False

        if REDIS_AVAILABLE:
            try:
                self.redis_client = redis.Redis(
                    host=redis_host,
                    port=redis_port,
                    db=redis_db,
                    password=redis_password,
                    decode_responses=False,
                    socket_timeout=2,
                    socket_connect_timeout=2
                )

                # Test connection
                self.redis_client.ping()
                self.use_redis = True
                logger.info("Redis rate limiter initialized successfully")

            except Exception as e:
                logger.warning(f"Failed to initialize Redis rate limiter: {e}. Using in-memory fallback.")
                self.use_redis = False

        # Fallback to in-memory rate limiting
        if not self.use_redis:
            self.in_memory_store = defaultdict(list)
            logger.info("Using in-memory rate limiter (not suitable for multi-instance deployment)")

    async def is_allowed(self, client_ip: str) -> bool:
        """
        Check if request from client is allowed based on rate limit.

        Args:
            client_ip: Client IP address

        Returns:
            True if request is allowed, False if rate limit exceeded
        """
        if self.use_redis:
            return await self._is_allowed_redis(client_ip)
        else:
            return self._is_allowed_memory(client_ip)

    async def _is_allowed_redis(self, client_ip: str) -> bool:
        """Check rate limit using Redis sliding window."""
        try:
            key = f"rate_limit:{client_ip}"
            current_time = int(time.time())
            window_start = current_time - self.window_seconds

            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()

            # Remove old entries outside the window
            pipe.zremrangebyscore(key, 0, window_start)

            # Add current request
            pipe.zadd(key, {str(current_time): current_time})

            # Count requests in window
            pipe.zcard(key)

            # Set expiry on key
            pipe.expire(key, self.window_seconds + 10)

            # Execute pipeline
            results = pipe.execute()

            # Get count from results (index 2)
            request_count = results[2]

            # Check if allowed
            allowed = request_count <= self.max_requests

            if not allowed:
                logger.warning(
                    f"Rate limit exceeded for {client_ip}: "
                    f"{request_count}/{self.max_requests} requests in {self.window_seconds}s"
                )

            return allowed

        except Exception as e:
            logger.error(f"Error in Redis rate limiter: {e}. Allowing request.")
            # On error, allow request (fail open)
            return True

    def _is_allowed_memory(self, client_ip: str) -> bool:
        """Check rate limit using in-memory storage."""
        current_time = time.time()
        window_start = current_time - self.window_seconds

        # Clean old requests
        self.in_memory_store[client_ip] = [
            req_time for req_time in self.in_memory_store[client_ip]
            if req_time > window_start
        ]

        # Check rate limit
        request_count = len(self.in_memory_store[client_ip])

        if request_count >= self.max_requests:
            logger.warning(
                f"Rate limit exceeded for {client_ip}: "
                f"{request_count}/{self.max_requests} requests in {self.window_seconds}s"
            )
            return False

        # Record request
        self.in_memory_store[client_ip].append(current_time)

        return True

    async def get_remaining(self, client_ip: str) -> int:
        """
        Get remaining requests for client in current window.

        Args:
            client_ip: Client IP address

        Returns:
            Number of remaining requests
        """
        if self.use_redis:
            return await self._get_remaining_redis(client_ip)
        else:
            return self._get_remaining_memory(client_ip)

    async def _get_remaining_redis(self, client_ip: str) -> int:
        """Get remaining requests using Redis."""
        try:
            key = f"rate_limit:{client_ip}"
            current_time = int(time.time())
            window_start = current_time - self.window_seconds

            # Count requests in current window
            request_count = self.redis_client.zcount(key, window_start, current_time)

            return max(0, self.max_requests - request_count)

        except Exception as e:
            logger.error(f"Error getting remaining requests: {e}")
            return self.max_requests

    def _get_remaining_memory(self, client_ip: str) -> int:
        """Get remaining requests using in-memory storage."""
        current_time = time.time()
        window_start = current_time - self.window_seconds

        # Clean and count
        self.in_memory_store[client_ip] = [
            req_time for req_time in self.in_memory_store[client_ip]
            if req_time > window_start
        ]

        request_count = len(self.in_memory_store[client_ip])
        return max(0, self.max_requests - request_count)

    async def reset(self, client_ip: str) -> None:
        """
        Reset rate limit for a specific client.

        Args:
            client_ip: Client IP address
        """
        if self.use_redis:
            try:
                key = f"rate_limit:{client_ip}"
                self.redis_client.delete(key)
                logger.info(f"Reset rate limit for {client_ip}")
            except Exception as e:
                logger.error(f"Error resetting rate limit: {e}")
        else:
            if client_ip in self.in_memory_store:
                del self.in_memory_store[client_ip]
                logger.info(f"Reset rate limit for {client_ip}")

    def get_stats(self) -> dict:
        """Get rate limiter statistics."""
        if self.use_redis:
            try:
                # Count all rate limit keys
                keys = self.redis_client.keys("rate_limit:*")
                total_clients = len(keys) if keys else 0

                return {
                    "backend": "redis",
                    "max_requests": self.max_requests,
                    "window_seconds": self.window_seconds,
                    "active_clients": total_clients,
                    "healthy": True
                }
            except Exception as e:
                return {
                    "backend": "redis",
                    "error": str(e),
                    "healthy": False
                }
        else:
            return {
                "backend": "memory",
                "max_requests": self.max_requests,
                "window_seconds": self.window_seconds,
                "active_clients": len(self.in_memory_store),
                "healthy": True
            }
