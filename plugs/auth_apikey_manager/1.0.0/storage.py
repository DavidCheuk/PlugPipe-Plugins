# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Production storage implementation for API Key Manager Plug.

This module provides concrete implementations for API key storage and rate limiting,
using production-ready database and Redis integrations.
"""

import json
import logging
import sqlite3
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path
import aiosqlite
import time

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False

logger = logging.getLogger(__name__)


class APIKeyStorage:
    """Production-ready storage backend for API keys."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize storage backend."""
        self.config = config or {}
        self.storage_type = self.config.get("storage_type", "sqlite")
        self.database_path = self.config.get("database_path", "/tmp/plugpipe_apikeys.db")
        
        # Redis configuration for rate limiting
        self.redis_config = self.config.get("redis_config", {})
        self.redis_host = self.redis_config.get("host", "localhost")
        self.redis_port = self.redis_config.get("port", 6379)
        self.redis_db = self.redis_config.get("db", 0)
        self.redis_password = self.redis_config.get("password")
        
        # Initialize storage
        self.db_initialized = False
        self.redis_client = None
        
    async def initialize(self):
        """Initialize storage backends."""
        if not self.db_initialized:
            await self._initialize_database()
            self.db_initialized = True
        
        if REDIS_AVAILABLE and not self.redis_client:
            await self._initialize_redis()
    
    async def _initialize_database(self):
        """Initialize SQLite database with API key schema."""
        try:
            # Ensure directory exists
            db_path = Path(self.database_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiosqlite.connect(self.database_path) as db:
                # Create API keys table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS api_keys (
                        id TEXT PRIMARY KEY,
                        user_id TEXT NOT NULL,
                        name TEXT NOT NULL,
                        key_hash TEXT NOT NULL,
                        permissions TEXT NOT NULL,  -- JSON array
                        rate_limit_per_hour INTEGER DEFAULT 1000,
                        expires_at TEXT,  -- ISO timestamp
                        created_at TEXT NOT NULL,
                        last_used TEXT,
                        usage_count INTEGER DEFAULT 0,
                        is_active BOOLEAN DEFAULT 1,
                        revoked_at TEXT,
                        metadata TEXT  -- JSON object
                    )
                """)
                
                # Create usage tracking table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS api_key_usage (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        key_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        endpoint TEXT,
                        ip_address TEXT,
                        success BOOLEAN DEFAULT 1,
                        error_message TEXT,
                        FOREIGN KEY (key_id) REFERENCES api_keys (id)
                    )
                """)
                
                # Create indexes for performance
                await db.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_api_keys_active ON api_keys(is_active)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_usage_key_id ON api_key_usage(key_id)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_usage_timestamp ON api_key_usage(timestamp)")
                
                await db.commit()
                
            logger.info(f"Initialized API key database at {self.database_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise
    
    async def _initialize_redis(self):
        """Initialize Redis connection for rate limiting."""
        try:
            self.redis_client = redis.Redis(
                host=self.redis_host,
                port=self.redis_port,
                db=self.redis_db,
                password=self.redis_password,
                decode_responses=True
            )
            
            # Test connection
            await self.redis_client.ping()
            logger.info(f"Connected to Redis at {self.redis_host}:{self.redis_port}")
            
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {str(e)}. Rate limiting will use fallback.")
            self.redis_client = None
    
    async def store_api_key_record(self, key_record: Dict[str, Any]) -> bool:
        """Store API key record in database."""
        try:
            await self.initialize()
            
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    INSERT INTO api_keys (
                        id, user_id, name, key_hash, permissions, rate_limit_per_hour,
                        expires_at, created_at, last_used, usage_count, is_active, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    key_record["id"],
                    key_record["user_id"],
                    key_record["name"],
                    key_record["key_hash"],
                    json.dumps(key_record["permissions"]),
                    key_record["rate_limit_per_hour"],
                    key_record.get("expires_at"),
                    key_record["created_at"],
                    key_record.get("last_used"),
                    key_record["usage_count"],
                    key_record["is_active"],
                    json.dumps(key_record.get("metadata", {}))
                ))
                
                await db.commit()
                
            logger.debug(f"Stored API key record: {key_record['id']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to store API key record: {str(e)}")
            return False
    
    async def find_api_key_record_by_hash(self, key_hash: str) -> Optional[Dict[str, Any]]:
        """Find API key record by hash (for validation)."""
        try:
            await self.initialize()
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute("""
                    SELECT * FROM api_keys 
                    WHERE key_hash = ? AND is_active = 1
                """, (key_hash,)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        columns = [description[0] for description in cursor.description]
                        record = dict(zip(columns, row))
                        
                        # Parse JSON fields
                        record["permissions"] = json.loads(record["permissions"])
                        record["metadata"] = json.loads(record.get("metadata", "{}"))
                        record["is_active"] = bool(record["is_active"])
                        
                        return record
                        
            return None
            
        except Exception as e:
            logger.error(f"Failed to find API key record: {str(e)}")
            return None
    
    async def get_api_key_record_by_id(self, key_id: str) -> Optional[Dict[str, Any]]:
        """Get API key record by ID."""
        try:
            await self.initialize()
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute("""
                    SELECT * FROM api_keys WHERE id = ?
                """, (key_id,)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        columns = [description[0] for description in cursor.description]
                        record = dict(zip(columns, row))
                        
                        # Parse JSON fields
                        record["permissions"] = json.loads(record["permissions"])
                        record["metadata"] = json.loads(record.get("metadata", "{}"))
                        record["is_active"] = bool(record["is_active"])
                        
                        return record
                        
            return None
            
        except Exception as e:
            logger.error(f"Failed to get API key record: {str(e)}")
            return None
    
    async def update_api_key_record(self, key_record: Dict[str, Any]) -> bool:
        """Update API key record in database."""
        try:
            await self.initialize()
            
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    UPDATE api_keys SET
                        name = ?, permissions = ?, rate_limit_per_hour = ?,
                        expires_at = ?, last_used = ?, usage_count = ?,
                        is_active = ?, revoked_at = ?, metadata = ?
                    WHERE id = ?
                """, (
                    key_record["name"],
                    json.dumps(key_record["permissions"]),
                    key_record["rate_limit_per_hour"],
                    key_record.get("expires_at"),
                    key_record.get("last_used"),
                    key_record["usage_count"],
                    key_record["is_active"],
                    key_record.get("revoked_at"),
                    json.dumps(key_record.get("metadata", {})),
                    key_record["id"]
                ))
                
                await db.commit()
                
            logger.debug(f"Updated API key record: {key_record['id']}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update API key record: {str(e)}")
            return False
    
    async def check_rate_limit(self, key_id: str, rate_limit_per_hour: int) -> bool:
        """Check if API key is within rate limits using Redis or fallback."""
        try:
            await self.initialize()
            
            if self.redis_client:
                return await self._check_redis_rate_limit(key_id, rate_limit_per_hour)
            else:
                return await self._check_database_rate_limit(key_id, rate_limit_per_hour)
                
        except Exception as e:
            logger.error(f"Rate limit check error: {str(e)}")
            return True  # Allow request on error
    
    async def _check_redis_rate_limit(self, key_id: str, rate_limit_per_hour: int) -> bool:
        """Check rate limit using Redis sliding window."""
        try:
            current_time = int(time.time())
            window_start = current_time - 3600  # 1 hour window
            
            redis_key = f"rate_limit:{key_id}"
            
            # Use Redis pipeline for atomic operations
            pipe = self.redis_client.pipeline()
            
            # Remove old entries
            pipe.zremrangebyscore(redis_key, 0, window_start)
            
            # Count current requests
            pipe.zcard(redis_key)
            
            # Add current request
            pipe.zadd(redis_key, {str(current_time): current_time})
            
            # Set expiry
            pipe.expire(redis_key, 3600)
            
            results = await pipe.execute()
            current_count = results[1]  # Count after cleanup
            
            return current_count < rate_limit_per_hour
            
        except Exception as e:
            logger.error(f"Redis rate limit check error: {str(e)}")
            return True  # Allow on error
    
    async def _check_database_rate_limit(self, key_id: str, rate_limit_per_hour: int) -> bool:
        """Fallback rate limit check using database."""
        try:
            one_hour_ago = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute("""
                    SELECT COUNT(*) FROM api_key_usage 
                    WHERE key_id = ? AND timestamp > ? AND success = 1
                """, (key_id, one_hour_ago)) as cursor:
                    row = await cursor.fetchone()
                    current_count = row[0] if row else 0
                    
            return current_count < rate_limit_per_hour
            
        except Exception as e:
            logger.error(f"Database rate limit check error: {str(e)}")
            return True  # Allow on error
    
    async def update_key_usage(self, key_id: str, endpoint: str = None, ip_address: str = None, 
                              success: bool = True, error_message: str = None):
        """Update API key usage statistics."""
        try:
            await self.initialize()
            
            now = datetime.now(timezone.utc).isoformat()
            
            # Update last_used and usage_count in api_keys table
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    UPDATE api_keys 
                    SET last_used = ?, usage_count = usage_count + 1
                    WHERE id = ?
                """, (now, key_id))
                
                # Insert usage record
                await db.execute("""
                    INSERT INTO api_key_usage (key_id, timestamp, endpoint, ip_address, success, error_message)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (key_id, now, endpoint, ip_address, success, error_message))
                
                await db.commit()
                
        except Exception as e:
            logger.error(f"Failed to update key usage: {str(e)}")
    
    async def get_user_api_keys(self, user_id: str, include_inactive: bool = False) -> List[Dict[str, Any]]:
        """Get all API keys for a user."""
        try:
            await self.initialize()
            
            query = "SELECT * FROM api_keys WHERE user_id = ?"
            params = [user_id]
            
            if not include_inactive:
                query += " AND is_active = 1"
            
            query += " ORDER BY created_at DESC"
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    results = []
                    for row in rows:
                        record = dict(zip(columns, row))
                        
                        # Parse JSON fields
                        record["permissions"] = json.loads(record["permissions"])
                        record["metadata"] = json.loads(record.get("metadata", "{}"))
                        record["is_active"] = bool(record["is_active"])
                        
                        # Remove sensitive data
                        record.pop("key_hash", None)
                        
                        results.append(record)
                    
                    return results
                    
        except Exception as e:
            logger.error(f"Failed to get user API keys: {str(e)}")
            return []
    
    async def get_usage_statistics(self, key_id: str, days: int = 30) -> Dict[str, Any]:
        """Get usage statistics for an API key."""
        try:
            await self.initialize()
            
            start_date = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
            
            async with aiosqlite.connect(self.database_path) as db:
                # Total usage count
                async with db.execute("""
                    SELECT COUNT(*) FROM api_key_usage 
                    WHERE key_id = ? AND timestamp > ?
                """, (key_id, start_date)) as cursor:
                    total_requests = (await cursor.fetchone())[0]
                
                # Success rate
                async with db.execute("""
                    SELECT 
                        COUNT(*) as total,
                        SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful
                    FROM api_key_usage 
                    WHERE key_id = ? AND timestamp > ?
                """, (key_id, start_date)) as cursor:
                    row = await cursor.fetchone()
                    total, successful = row
                    success_rate = (successful / total * 100) if total > 0 else 0
                
                # Daily usage
                async with db.execute("""
                    SELECT 
                        DATE(timestamp) as date,
                        COUNT(*) as requests
                    FROM api_key_usage 
                    WHERE key_id = ? AND timestamp > ?
                    GROUP BY DATE(timestamp)
                    ORDER BY date DESC
                """, (key_id, start_date)) as cursor:
                    daily_usage = await cursor.fetchall()
                
                return {
                    "total_requests": total_requests,
                    "success_rate": round(success_rate, 2),
                    "daily_usage": [{"date": row[0], "requests": row[1]} for row in daily_usage],
                    "period_days": days
                }
                
        except Exception as e:
            logger.error(f"Failed to get usage statistics: {str(e)}")
            return {}
    
    async def cleanup_expired_keys(self):
        """Clean up expired API keys."""
        try:
            await self.initialize()
            
            now = datetime.now(timezone.utc).isoformat()
            
            async with aiosqlite.connect(self.database_path) as db:
                # Deactivate expired keys
                result = await db.execute("""
                    UPDATE api_keys 
                    SET is_active = 0, revoked_at = ?
                    WHERE expires_at IS NOT NULL AND expires_at < ? AND is_active = 1
                """, (now, now))
                
                await db.commit()
                
                if result.rowcount > 0:
                    logger.info(f"Deactivated {result.rowcount} expired API keys")
                    
        except Exception as e:
            logger.error(f"Failed to cleanup expired keys: {str(e)}")
    
    async def close(self):
        """Close storage connections."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
        
        # SQLite connections are closed automatically with context managers
        logger.info("Closed API key storage connections")