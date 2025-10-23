#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Redis Data Operations Plugin for PlugPipe
Provides Redis-based data storage and operations for other plugins
Follows sqlite_manager foundation pattern with PlugPipe compliance
"""

import json
import logging
import os
import time
import hashlib
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union, Tuple
from dataclasses import dataclass, asdict
import asyncio

# Completely isolated Redis plugin - no PlugPipe internal imports to prevent circular dependency
def get_plugpipe_path(path):
    """Standalone path helper - no external dependencies"""
    return f"/mnt/c/Project/PlugPipe/{path}"

# FIXED: Standalone input sanitizer with plugin-compatible interface
class StandaloneInputSanitizer:
    """Standalone input sanitizer with plugin-compatible interface to prevent circular dependency"""

    def process(self, ctx, cfg):
        """Plugin-compatible interface for sanitization"""
        try:
            operation = cfg.get('operation', 'sanitize')
            data = cfg.get('data')

            if operation == 'sanitize':
                sanitized_data = self._basic_sanitize(data)
                return {
                    'success': True,
                    'sanitized_data': sanitized_data,
                    'operation': 'sanitize'
                }
            else:
                return {
                    'success': False,
                    'error': f'Unsupported operation: {operation}'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _basic_sanitize(self, data: Any) -> Any:
        """Basic input sanitization without external plugin dependencies"""
        if isinstance(data, str):
            # Basic SQL injection and XSS prevention
            dangerous_patterns = ['<script', '--', 'DROP ', 'DELETE ', 'UPDATE ', 'INSERT ']
            data_lower = data.lower()
            for pattern in dangerous_patterns:
                if pattern.lower() in data_lower:
                    raise ValueError(f"Potentially dangerous input detected: {pattern}")
            return data[:1000]  # Limit string length
        elif isinstance(data, dict):
            return {k: self._basic_sanitize(v) for k, v in data.items() if len(str(k)) < 100}
        elif isinstance(data, list):
            return [self._basic_sanitize(item) for item in data[:100]]  # Limit list size
        else:
            return data

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "redis_data_operations",
    "version": "1.0.0",
    "description": "Redis data operations manager for high-performance storage",
    "author": "PlugPipe",
    "tags": ["database", "storage", "redis", "cache", "performance"],
    "external_dependencies": ["redis"],
    "schema_validation": True
}

@dataclass
class RedisRecord:
    """Standard Redis record structure"""
    key: str
    value: Optional[Dict[str, Any]] = None
    ttl: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

class RedisDataManager:
    """Redis data manager with connection pooling and security integration"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

        # Validate and sanitize configuration
        self._validate_config()

        self.redis_url = self.config.get('redis_url', os.getenv('REDIS_URL', 'redis://localhost:6379/1'))
        self.key_prefix = self.config.get('key_prefix', 'plugpipe:')
        self.default_ttl = self.config.get('default_ttl', 3600)  # 1 hour default

        # Load universal input sanitizer using pp() discovery
        self.universal_sanitizer = self._load_universal_sanitizer()

        # Redis client will be initialized on first use
        self.redis_client = None
        self._connection_pool = None

    def _load_universal_sanitizer(self):
        """FIXED: Use standalone sanitizer with plugin-compatible interface."""
        # Use standalone sanitizer instead of pp('universal_input_sanitizer') to prevent circular dependency
        logger.info("✅ Using standalone input sanitizer with plugin-compatible interface (no external plugin dependency)")
        return StandaloneInputSanitizer()

    def _validate_config(self):
        """Validate configuration using universal input sanitizer if available"""
        if not self.config:
            return

        # FIXED: Use standalone sanitizer with proper interface
        if hasattr(self, 'universal_sanitizer') and self.universal_sanitizer:
            try:
                sanitized_result = self.universal_sanitizer.process({}, {
                    'operation': 'sanitize',
                    'data': self.config
                })
                if sanitized_result.get('success'):
                    self.config = sanitized_result.get('sanitized_data', self.config)
                    logger.debug("✅ Configuration sanitized successfully")
            except Exception as e:
                logger.warning(f"Config sanitization failed: {e}")

    def _ensure_connection(self):
        """Ensure Redis connection is established"""
        if self.redis_client is None:
            try:
                import redis
                self.redis_client = redis.from_url(self.redis_url, decode_responses=True)
                # Test connection
                self.redis_client.ping()
                logger.info(f"✅ Connected to Redis: {self.redis_url}")
            except ImportError:
                logger.error("❌ Redis library not available - install with: pip install redis")
                raise RuntimeError("Redis dependency missing")
            except Exception as e:
                logger.error(f"❌ Failed to connect to Redis: {e}")
                raise RuntimeError(f"Redis connection failed: {e}")

    def _make_key(self, key: str) -> str:
        """Create prefixed Redis key"""
        return f"{self.key_prefix}{key}"

    def store(self, key: str, data: Dict[str, Any], ttl: Optional[int] = None) -> bool:
        """Store data in Redis with optional TTL"""
        try:
            self._ensure_connection()

            # FIXED: Sanitize input data with proper interface
            if self.universal_sanitizer:
                try:
                    sanitized_result = self.universal_sanitizer.process({}, {
                        'operation': 'sanitize',
                        'data': data
                    })
                    if sanitized_result.get('success'):
                        data = sanitized_result.get('sanitized_data', data)
                        logger.debug("✅ Data sanitized before storage")
                except Exception as e:
                    logger.warning(f"Data sanitization failed: {e}")

            # Create record
            record = RedisRecord(
                key=key,
                value=data,
                ttl=ttl or self.default_ttl,
                created_at=datetime.utcnow().isoformat(),
                updated_at=datetime.utcnow().isoformat()
            )

            redis_key = self._make_key(key)
            serialized_data = json.dumps(asdict(record))

            if ttl or self.default_ttl:
                self.redis_client.setex(redis_key, ttl or self.default_ttl, serialized_data)
            else:
                self.redis_client.set(redis_key, serialized_data)

            logger.debug(f"✅ Stored data with key: {key}")
            return True

        except Exception as e:
            logger.error(f"❌ Failed to store data: {e}")
            return False

    def retrieve(self, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve data from Redis"""
        try:
            self._ensure_connection()

            redis_key = self._make_key(key)
            serialized_data = self.redis_client.get(redis_key)

            if serialized_data:
                record_data = json.loads(serialized_data)
                record = RedisRecord(**record_data)
                logger.debug(f"✅ Retrieved data with key: {key}")
                return record.value
            else:
                logger.debug(f"🔍 No data found for key: {key}")
                return None

        except Exception as e:
            logger.error(f"❌ Failed to retrieve data: {e}")
            return None

    def delete(self, key: str) -> bool:
        """Delete data from Redis"""
        try:
            self._ensure_connection()

            redis_key = self._make_key(key)
            result = self.redis_client.delete(redis_key)

            if result:
                logger.debug(f"✅ Deleted data with key: {key}")
                return True
            else:
                logger.debug(f"🔍 No data to delete for key: {key}")
                return False

        except Exception as e:
            logger.error(f"❌ Failed to delete data: {e}")
            return False

    def exists(self, key: str) -> bool:
        """Check if key exists in Redis"""
        try:
            self._ensure_connection()
            redis_key = self._make_key(key)
            return bool(self.redis_client.exists(redis_key))
        except Exception as e:
            logger.error(f"❌ Failed to check key existence: {e}")
            return False

    def list_keys(self, pattern: str = "*") -> List[str]:
        """List keys matching pattern"""
        try:
            self._ensure_connection()
            redis_pattern = self._make_key(pattern)
            raw_keys = self.redis_client.keys(redis_pattern)

            # Remove prefix from keys
            keys = [key.replace(self.key_prefix, '') for key in raw_keys]
            return keys

        except Exception as e:
            logger.error(f"❌ Failed to list keys: {e}")
            return []

    def bulk_store(self, data_dict: Dict[str, Dict[str, Any]], ttl: Optional[int] = None) -> int:
        """Store multiple key-value pairs"""
        success_count = 0
        for key, data in data_dict.items():
            if self.store(key, data, ttl):
                success_count += 1
        return success_count

    def bulk_retrieve(self, keys: List[str]) -> Dict[str, Optional[Dict[str, Any]]]:
        """Retrieve multiple keys"""
        results = {}
        for key in keys:
            results[key] = self.retrieve(key)
        return results

    def health_check(self) -> Dict[str, Any]:
        """Check Redis connection health"""
        try:
            self._ensure_connection()
            self.redis_client.ping()

            # Get basic Redis info
            info = self.redis_client.info()

            return {
                'status': 'healthy',
                'redis_version': info.get('redis_version', 'unknown'),
                'connected_clients': info.get('connected_clients', 0),
                'used_memory_human': info.get('used_memory_human', 'unknown'),
                'connection_url': self.redis_url.split('@')[-1] if '@' in self.redis_url else self.redis_url
            }
        except Exception as e:
            return {
                'status': 'unhealthy',
                'error': str(e),
                'connection_url': self.redis_url.split('@')[-1] if '@' in self.redis_url else self.redis_url
            }


# PlugPipe Plugin Interface
async def process(ctx, cfg):
    """Main plugin entry point for Redis data operations"""
    start_time = datetime.utcnow()

    try:
        if cfg is None:
            return {
                'success': False,
                'error': 'Configuration cannot be None - must provide valid dictionary',
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

        operation = cfg.get('operation', 'health_check')

        # Initialize Redis manager
        redis_config = cfg.get('redis_config', {})
        manager = RedisDataManager(redis_config)

        if operation == 'store':
            key = cfg.get('key')
            data = cfg.get('data')
            ttl = cfg.get('ttl')

            if not key or data is None:
                return {
                    'success': False,
                    'error': 'Missing required parameters: key and data',
                    'execution_time': (datetime.utcnow() - start_time).total_seconds()
                }

            success = manager.store(key, data, ttl)
            return {
                'success': success,
                'operation': 'store',
                'key': key,
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

        elif operation == 'retrieve':
            key = cfg.get('key')
            if not key:
                return {
                    'success': False,
                    'error': 'Missing required parameter: key',
                    'execution_time': (datetime.utcnow() - start_time).total_seconds()
                }

            data = manager.retrieve(key)
            return {
                'success': data is not None,
                'operation': 'retrieve',
                'key': key,
                'data': data,
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

        elif operation == 'delete':
            key = cfg.get('key')
            if not key:
                return {
                    'success': False,
                    'error': 'Missing required parameter: key',
                    'execution_time': (datetime.utcnow() - start_time).total_seconds()
                }

            success = manager.delete(key)
            return {
                'success': success,
                'operation': 'delete',
                'key': key,
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

        elif operation == 'list_keys':
            pattern = cfg.get('pattern', '*')
            keys = manager.list_keys(pattern)
            return {
                'success': True,
                'operation': 'list_keys',
                'keys': keys,
                'count': len(keys),
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

        elif operation == 'bulk_store':
            data_dict = cfg.get('data_dict', {})
            ttl = cfg.get('ttl')

            success_count = manager.bulk_store(data_dict, ttl)
            return {
                'success': success_count > 0,
                'operation': 'bulk_store',
                'stored_count': success_count,
                'total_count': len(data_dict),
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

        elif operation == 'health_check':
            health = manager.health_check()
            return {
                'success': health.get('status') == 'healthy',
                'operation': 'health_check',
                'health': health,
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'supported_operations': ['store', 'retrieve', 'delete', 'list_keys', 'bulk_store', 'health_check'],
                'execution_time': (datetime.utcnow() - start_time).total_seconds()
            }

    except Exception as e:
        logger.error(f"Redis data operations failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation': operation if 'operation' in locals() else 'unknown',
            'execution_time': (datetime.utcnow() - start_time).total_seconds()
        }


if __name__ == "__main__":
    # Direct testing
    import asyncio

    async def test():
        config = {
            'operation': 'health_check',
            'redis_config': {
                'redis_url': 'redis://localhost:6379/1'
            }
        }

        result = await process({}, config)
        print(json.dumps(result, indent=2))

    asyncio.run(test())