"""Redis-based caching system for improved performance.

This module provides high-performance caching using Redis with:
- Sub-millisecond cache operations
- Automatic TTL management
- Connection pooling
- Graceful fallback to file-based cache
- Compression support for large objects
"""

import json
import hashlib
import zlib
from typing import Optional, Dict, Any
from datetime import datetime, timedelta
from sentyr.models import SecurityEvent, AnalysisResult
from sentyr.config import SentyrConfig
from sentyr.logger import get_logger

logger = get_logger(__name__)

try:
    import redis
    from redis.connection import ConnectionPool
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not available. Install with: pip install redis")


class RedisAnalysisCache:
    """Redis-based caching system for analysis results."""

    def __init__(self, config: SentyrConfig):
        self.config = config
        self.ttl_seconds = 24 * 3600  # 24 hours
        self.compression_threshold = 1024  # Compress if > 1KB

        # Try to initialize Redis connection
        self.redis_client = None
        self.use_redis = False

        if REDIS_AVAILABLE:
            try:
                # Create connection pool for better performance
                pool = ConnectionPool(
                    host=getattr(config, 'redis_host', 'localhost'),
                    port=getattr(config, 'redis_port', 6379),
                    db=getattr(config, 'redis_db', 0),
                    password=getattr(config, 'redis_password', None),
                    decode_responses=False,  # We handle encoding
                    max_connections=20,
                    socket_timeout=5,
                    socket_connect_timeout=5
                )

                self.redis_client = redis.Redis(connection_pool=pool)

                # Test connection
                self.redis_client.ping()
                self.use_redis = True
                logger.info("Redis cache initialized successfully")

            except Exception as e:
                logger.warning(f"Failed to initialize Redis: {e}. Falling back to file-based cache.")
                self.use_redis = False

        # Fallback to file-based cache
        if not self.use_redis:
            from sentyr.cache import AnalysisCache
            self.file_cache = AnalysisCache(config)
            logger.info("Using file-based cache as fallback")

    def _generate_cache_key(self, event: SecurityEvent) -> str:
        """Generate unique cache key for event."""
        cache_data = {
            "event_id": event.event_id,
            "source": event.source_system,
            "title": event.title,
            "description": event.description[:100],
            "severity": event.severity.value,
            "category": event.category.value,
        }

        cache_str = json.dumps(cache_data, sort_keys=True)
        key_hash = hashlib.sha256(cache_str.encode()).hexdigest()
        return f"sentyr:analysis:{key_hash}"

    def _compress_data(self, data: bytes) -> bytes:
        """Compress data if it exceeds threshold."""
        if len(data) > self.compression_threshold:
            return zlib.compress(data, level=6)
        return data

    def _decompress_data(self, data: bytes) -> bytes:
        """Decompress data if it was compressed."""
        try:
            # Try to decompress - if it fails, it wasn't compressed
            return zlib.decompress(data)
        except zlib.error:
            return data

    def get(self, event: SecurityEvent) -> Optional[AnalysisResult]:
        """Retrieve cached analysis if available and not expired."""
        if not self.use_redis:
            return self.file_cache.get(event)

        try:
            cache_key = self._generate_cache_key(event)
            cached_data = self.redis_client.get(cache_key)

            if not cached_data:
                return None

            # Decompress if needed
            cached_data = self._decompress_data(cached_data)

            # Parse JSON
            data_dict = json.loads(cached_data.decode('utf-8'))

            # Return analysis result
            return AnalysisResult(**data_dict["result"])

        except Exception as e:
            logger.error(f"Error retrieving from Redis cache: {e}")
            return None

    def set(self, event: SecurityEvent, result: AnalysisResult) -> None:
        """Cache analysis result."""
        if not self.use_redis:
            return self.file_cache.set(event, result)

        try:
            cache_key = self._generate_cache_key(event)

            cache_data = {
                "cached_at": datetime.utcnow().isoformat(),
                "event_id": event.event_id,
                "result": json.loads(result.model_dump_json())
            }

            # Serialize to JSON
            json_data = json.dumps(cache_data, default=str).encode('utf-8')

            # Compress if beneficial
            compressed_data = self._compress_data(json_data)

            # Store with TTL
            self.redis_client.setex(
                cache_key,
                self.ttl_seconds,
                compressed_data
            )

            # Log compression savings
            if len(compressed_data) < len(json_data):
                savings = (1 - len(compressed_data) / len(json_data)) * 100
                logger.debug(f"Compressed cache entry: {savings:.1f}% savings")

        except Exception as e:
            logger.error(f"Error storing to Redis cache: {e}")

    def clear_expired(self) -> int:
        """Clear expired cache entries (Redis handles this automatically with TTL)."""
        if not self.use_redis:
            return self.file_cache.clear_expired()

        # Redis automatically expires keys with TTL
        logger.info("Redis handles expiration automatically via TTL")
        return 0

    def clear_all(self) -> int:
        """Clear all cache entries."""
        if not self.use_redis:
            return self.file_cache.clear_all()

        try:
            # Find all sentyr cache keys
            keys = self.redis_client.keys("sentyr:analysis:*")

            if keys:
                cleared = self.redis_client.delete(*keys)
                logger.info(f"Cleared {cleared} cache entries from Redis")
                return cleared

            return 0

        except Exception as e:
            logger.error(f"Error clearing Redis cache: {e}")
            return 0

    def get_stats(self) -> Dict[str, Any]:
        """Get cache statistics."""
        if not self.use_redis:
            return self.file_cache.get_stats()

        try:
            # Get Redis info
            info = self.redis_client.info("stats")
            memory_info = self.redis_client.info("memory")

            # Count sentyr keys
            keys = self.redis_client.keys("sentyr:analysis:*")
            total_entries = len(keys) if keys else 0

            # Calculate approximate total size
            total_size = 0
            if keys:
                # Sample some keys to estimate average size
                sample_size = min(100, len(keys))
                sample_keys = keys[:sample_size]

                for key in sample_keys:
                    val = self.redis_client.get(key)
                    if val:
                        total_size += len(val)

                # Extrapolate to all keys
                if sample_size > 0:
                    avg_size = total_size / sample_size
                    total_size = int(avg_size * len(keys))

            return {
                "cache_type": "redis",
                "total_entries": total_entries,
                "total_size_bytes": total_size,
                "total_size_mb": round(total_size / (1024 * 1024), 2),
                "ttl_seconds": self.ttl_seconds,
                "redis_used_memory_mb": round(memory_info.get("used_memory", 0) / (1024 * 1024), 2),
                "redis_connected_clients": info.get("connected_clients", 0),
                "redis_total_commands": info.get("total_commands_processed", 0),
            }

        except Exception as e:
            logger.error(f"Error getting Redis stats: {e}")
            return {
                "cache_type": "redis",
                "error": str(e)
            }

    def health_check(self) -> Dict[str, Any]:
        """Check Redis connection health."""
        if not self.use_redis:
            return {
                "healthy": True,
                "backend": "file",
                "message": "Using file-based cache"
            }

        try:
            # Ping Redis
            response_time_start = datetime.utcnow()
            self.redis_client.ping()
            response_time = (datetime.utcnow() - response_time_start).total_seconds() * 1000

            return {
                "healthy": True,
                "backend": "redis",
                "response_time_ms": round(response_time, 2),
                "message": "Redis connection healthy"
            }

        except Exception as e:
            return {
                "healthy": False,
                "backend": "redis",
                "error": str(e),
                "message": "Redis connection failed"
            }
