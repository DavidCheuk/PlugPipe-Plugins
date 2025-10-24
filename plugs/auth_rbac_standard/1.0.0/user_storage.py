# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Production user management storage for RBAC Standard Plug.

This module provides concrete implementations for user role management,
using production-ready database integrations.
"""

import json
import logging
import sqlite3
import asyncio
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional, List
from pathlib import Path
import aiosqlite
from enum import Enum
import sys
import os

# SECURITY FIX: Add PlugPipe Universal Input Sanitizer for SQL injection prevention
try:
    # Add project root to path for plugin discovery
    sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))
    from shares.loader import pp
    UNIVERSAL_SANITIZER_AVAILABLE = True
except ImportError:
    UNIVERSAL_SANITIZER_AVAILABLE = False

try:
    import redis.asyncio as redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False

logger = logging.getLogger(__name__)


class UserRole(str, Enum):
    """Standard user roles in hierarchical order."""
    ADMIN = "admin"
    DEVELOPER = "developer"
    USER = "user"
    GUEST = "guest"


class UserManagementStorage:
    """Production-ready storage backend for user management and RBAC."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize user management storage backend."""
        self.config = config or {}
        self.storage_type = self.config.get("storage_type", "sqlite")
        self.database_path = self.config.get("database_path", "/tmp/plugpipe_users.db")
        
        # Redis configuration for caching
        self.redis_config = self.config.get("redis_config", {})
        self.redis_host = self.redis_config.get("host", "localhost")
        self.redis_port = self.redis_config.get("port", 6379)
        self.redis_db = self.redis_config.get("db", 1)  # Different DB than API keys
        self.redis_password = self.redis_config.get("password")
        
        # Cache configuration
        self.cache_ttl = self.config.get("cache_ttl", 300)  # 5 minutes
        self.enable_caching = self.config.get("enable_caching", True)
        
        # Initialize storage
        self.db_initialized = False
        self.redis_client = None
        
    async def initialize(self):
        """Initialize storage backends."""
        if not self.db_initialized:
            await self._initialize_database()
            self.db_initialized = True
        
        if REDIS_AVAILABLE and self.enable_caching and not self.redis_client:
            await self._initialize_redis()
    
    async def _initialize_database(self):
        """Initialize SQLite database with user management schema."""
        try:
            # Ensure directory exists
            db_path = Path(self.database_path)
            db_path.parent.mkdir(parents=True, exist_ok=True)
            
            async with aiosqlite.connect(self.database_path) as db:
                # Create users table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS users (
                        id TEXT PRIMARY KEY,
                        username TEXT UNIQUE NOT NULL,
                        email TEXT UNIQUE,
                        display_name TEXT,
                        role TEXT NOT NULL DEFAULT 'user',
                        organization_id TEXT,
                        project_ids TEXT,  -- JSON array
                        team_ids TEXT,     -- JSON array
                        additional_permissions TEXT,  -- JSON array
                        denied_permissions TEXT,      -- JSON array
                        custom_context TEXT,          -- JSON object
                        is_active BOOLEAN DEFAULT 1,
                        created_at TEXT NOT NULL,
                        updated_at TEXT,
                        last_login TEXT,
                        metadata TEXT  -- JSON object
                    )
                """)
                
                # Create role assignments table (for historical tracking)
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS role_assignments (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        user_id TEXT NOT NULL,
                        role TEXT NOT NULL,
                        assigned_by TEXT,
                        assigned_at TEXT NOT NULL,
                        expires_at TEXT,
                        reason TEXT,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (user_id) REFERENCES users (id)
                    )
                """)
                
                # Create organizations table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS organizations (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        description TEXT,
                        settings TEXT,  -- JSON object
                        created_at TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 1
                    )
                """)
                
                # Create projects table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS projects (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        organization_id TEXT,
                        description TEXT,
                        settings TEXT,  -- JSON object
                        created_at TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (organization_id) REFERENCES organizations (id)
                    )
                """)
                
                # Create teams table
                await db.execute("""
                    CREATE TABLE IF NOT EXISTS teams (
                        id TEXT PRIMARY KEY,
                        name TEXT NOT NULL,
                        organization_id TEXT,
                        project_id TEXT,
                        description TEXT,
                        settings TEXT,  -- JSON object
                        created_at TEXT NOT NULL,
                        is_active BOOLEAN DEFAULT 1,
                        FOREIGN KEY (organization_id) REFERENCES organizations (id),
                        FOREIGN KEY (project_id) REFERENCES projects (id)
                    )
                """)
                
                # Create indexes for performance
                await db.execute("CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_users_org ON users(organization_id)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_role_assignments_user ON role_assignments(user_id)")
                await db.execute("CREATE INDEX IF NOT EXISTS idx_role_assignments_active ON role_assignments(is_active)")
                
                await db.commit()
                
            logger.info(f"Initialized user management database at {self.database_path}")
            
        except Exception as e:
            logger.error(f"Failed to initialize database: {str(e)}")
            raise
    
    async def _initialize_redis(self):
        """Initialize Redis connection for caching."""
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
            logger.info(f"Connected to Redis for user caching at {self.redis_host}:{self.redis_port}")
            
        except Exception as e:
            logger.warning(f"Failed to connect to Redis: {str(e)}. User caching will be disabled.")
            self.redis_client = None
    
    async def create_user(self, user_data: Dict[str, Any]) -> bool:
        """Create a new user record."""
        try:
            await self.initialize()
            
            now = datetime.now(timezone.utc).isoformat()
            
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    INSERT INTO users (
                        id, username, email, display_name, role, organization_id,
                        project_ids, team_ids, additional_permissions, denied_permissions,
                        custom_context, is_active, created_at, metadata
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """, (
                    user_data["id"],
                    user_data["username"],
                    user_data.get("email"),
                    user_data.get("display_name"),
                    user_data.get("role", "user"),
                    user_data.get("organization_id"),
                    json.dumps(user_data.get("project_ids", [])),
                    json.dumps(user_data.get("team_ids", [])),
                    json.dumps(user_data.get("additional_permissions", [])),
                    json.dumps(user_data.get("denied_permissions", [])),
                    json.dumps(user_data.get("custom_context", {})),
                    user_data.get("is_active", True),
                    now,
                    json.dumps(user_data.get("metadata", {}))
                ))
                
                await db.commit()
                
            # Clear cache for this user
            await self._clear_user_cache(user_data["id"])
            
            logger.info(f"Created user: {user_data['username']} ({user_data['id']})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create user: {str(e)}")
            return False
    
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user record by ID with caching."""
        try:
            # Check cache first
            if self.enable_caching:
                cached_user = await self._get_cached_user(user_id)
                if cached_user:
                    return cached_user
            
            await self.initialize()
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute("""
                    SELECT * FROM users WHERE id = ? AND is_active = 1
                """, (user_id,)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        columns = [description[0] for description in cursor.description]
                        user_record = dict(zip(columns, row))
                        
                        # Parse JSON fields
                        user_record["project_ids"] = json.loads(user_record.get("project_ids", "[]"))
                        user_record["team_ids"] = json.loads(user_record.get("team_ids", "[]"))
                        user_record["additional_permissions"] = json.loads(user_record.get("additional_permissions", "[]"))
                        user_record["denied_permissions"] = json.loads(user_record.get("denied_permissions", "[]"))
                        user_record["custom_context"] = json.loads(user_record.get("custom_context", "{}"))
                        user_record["metadata"] = json.loads(user_record.get("metadata", "{}"))
                        user_record["is_active"] = bool(user_record["is_active"])
                        
                        # Cache the result
                        if self.enable_caching:
                            await self._cache_user(user_id, user_record)
                        
                        return user_record
                        
            return None
            
        except Exception as e:
            logger.error(f"Failed to get user by ID: {str(e)}")
            return None
    
    async def get_user_by_username(self, username: str) -> Optional[Dict[str, Any]]:
        """Get user record by username."""
        try:
            await self.initialize()
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute("""
                    SELECT * FROM users WHERE username = ? AND is_active = 1
                """, (username,)) as cursor:
                    row = await cursor.fetchone()
                    
                    if row:
                        columns = [description[0] for description in cursor.description]
                        user_record = dict(zip(columns, row))
                        
                        # Parse JSON fields
                        user_record["project_ids"] = json.loads(user_record.get("project_ids", "[]"))
                        user_record["team_ids"] = json.loads(user_record.get("team_ids", "[]"))
                        user_record["additional_permissions"] = json.loads(user_record.get("additional_permissions", "[]"))
                        user_record["denied_permissions"] = json.loads(user_record.get("denied_permissions", "[]"))
                        user_record["custom_context"] = json.loads(user_record.get("custom_context", "{}"))
                        user_record["metadata"] = json.loads(user_record.get("metadata", "{}"))
                        user_record["is_active"] = bool(user_record["is_active"])
                        
                        return user_record
                        
            return None
            
        except Exception as e:
            logger.error(f"Failed to get user by username: {str(e)}")
            return None
    
    async def assign_role(self, user_id: str, role: str, assigned_by: str = None, 
                         reason: str = None, expires_at: str = None) -> bool:
        """Assign role to user with audit trail."""
        try:
            await self.initialize()
            
            now = datetime.now(timezone.utc).isoformat()
            
            async with aiosqlite.connect(self.database_path) as db:
                # Update user role
                await db.execute("""
                    UPDATE users SET role = ?, updated_at = ? WHERE id = ?
                """, (role, now, user_id))
                
                # Record role assignment
                await db.execute("""
                    INSERT INTO role_assignments (
                        user_id, role, assigned_by, assigned_at, expires_at, reason, is_active
                    ) VALUES (?, ?, ?, ?, ?, ?, 1)
                """, (user_id, role, assigned_by, now, expires_at, reason))
                
                await db.commit()
                
            # Clear cache for this user
            await self._clear_user_cache(user_id)
            
            logger.info(f"Assigned role {role} to user {user_id} by {assigned_by}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to assign role: {str(e)}")
            return False
    
    async def update_user(self, user_id: str, updates: Dict[str, Any]) -> bool:
        """
        Update user record with SQL injection prevention.
        SECURITY FIX: Uses Universal Input Sanitizer for field validation.
        """
        try:
            await self.initialize()
            
            now = datetime.now(timezone.utc).isoformat()
            updates["updated_at"] = now
            
            # SECURITY FIX: Validate and sanitize update fields using Universal Input Sanitizer
            sanitized_updates = await self._sanitize_update_fields(updates)
            if not sanitized_updates:
                logger.error("Update failed: Invalid or unsafe field names detected")
                return False
            
            # Use parameterized queries with validated field names
            set_clauses = []
            values = []
            
            for field, value in sanitized_updates.items():
                if field in ["project_ids", "team_ids", "additional_permissions", 
                           "denied_permissions", "custom_context", "metadata"]:
                    value = json.dumps(value)
                set_clauses.append(f"{field} = ?")  # Now safe - field names validated
                values.append(value)
            
            values.append(user_id)
            
            async with aiosqlite.connect(self.database_path) as db:
                # SECURITY FIX: Field names now validated, query is safe
                await db.execute(f"""
                    UPDATE users SET {', '.join(set_clauses)} WHERE id = ?
                """, values)
                
                await db.commit()
                
            # Clear cache for this user
            await self._clear_user_cache(user_id)
            
            logger.debug(f"Updated user {user_id} with sanitized fields")
            return True
            
        except Exception as e:
            logger.error(f"Failed to update user: {str(e)}")
            return False
    
    
    async def get_role_history(self, user_id: str) -> List[Dict[str, Any]]:
        """Get role assignment history for a user."""
        try:
            await self.initialize()
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute("""
                    SELECT * FROM role_assignments 
                    WHERE user_id = ? 
                    ORDER BY assigned_at DESC
                """, (user_id,)) as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    results = []
                    for row in rows:
                        record = dict(zip(columns, row))
                        record["is_active"] = bool(record["is_active"])
                        results.append(record)
                    
                    return results
                    
        except Exception as e:
            logger.error(f"Failed to get role history: {str(e)}")
            return []
    
    async def create_organization(self, org_data: Dict[str, Any]) -> bool:
        """Create organization."""
        try:
            await self.initialize()
            
            now = datetime.now(timezone.utc).isoformat()
            
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    INSERT INTO organizations (id, name, description, settings, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?)
                """, (
                    org_data["id"],
                    org_data["name"],
                    org_data.get("description"),
                    json.dumps(org_data.get("settings", {})),
                    now,
                    org_data.get("is_active", True)
                ))
                
                await db.commit()
                
            logger.info(f"Created organization: {org_data['name']} ({org_data['id']})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create organization: {str(e)}")
            return False
    
    async def create_project(self, project_data: Dict[str, Any]) -> bool:
        """Create project."""
        try:
            await self.initialize()
            
            now = datetime.now(timezone.utc).isoformat()
            
            async with aiosqlite.connect(self.database_path) as db:
                await db.execute("""
                    INSERT INTO projects (id, name, organization_id, description, settings, created_at, is_active)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                """, (
                    project_data["id"],
                    project_data["name"],
                    project_data.get("organization_id"),
                    project_data.get("description"),
                    json.dumps(project_data.get("settings", {})),
                    now,
                    project_data.get("is_active", True)
                ))
                
                await db.commit()
                
            logger.info(f"Created project: {project_data['name']} ({project_data['id']})")
            return True
            
        except Exception as e:
            logger.error(f"Failed to create project: {str(e)}")
            return False
    
    async def _get_cached_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user from cache."""
        if not self.redis_client:
            return None
        
        try:
            cached_data = await self.redis_client.get(f"user:{user_id}")
            if cached_data:
                return json.loads(cached_data)
        except Exception as e:
            logger.error(f"Cache retrieval error: {str(e)}")
        
        return None
    
    async def _cache_user(self, user_id: str, user_data: Dict[str, Any]):
        """Cache user data."""
        if not self.redis_client:
            return
        
        try:
            await self.redis_client.setex(
                f"user:{user_id}", 
                self.cache_ttl, 
                json.dumps(user_data, default=str)
            )
        except Exception as e:
            logger.error(f"Cache storage error: {str(e)}")
    
    async def _sanitize_update_fields(self, updates: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """
        SECURITY FIX: Sanitize and validate database field names to prevent SQL injection.
        Uses Universal Input Sanitizer plugin for comprehensive validation.
        """
        # Define allowed database columns to prevent SQL injection
        ALLOWED_COLUMNS = {
            'username', 'email', 'display_name', 'role', 'organization_id',
            'project_ids', 'team_ids', 'additional_permissions', 'denied_permissions',
            'custom_context', 'is_active', 'updated_at', 'last_login', 'metadata'
        }
        
        # First, validate against allowed columns (whitelist approach)
        for field_name in updates.keys():
            if field_name not in ALLOWED_COLUMNS:
                logger.warning(f"Rejected unexpected field in user update: {field_name}")
                return None
        
        # Use Universal Input Sanitizer for additional SQL injection validation
        if UNIVERSAL_SANITIZER_AVAILABLE:
            try:
                sanitizer = pp('security/universal_input_sanitizer')
                
                # Validate field names for SQL injection patterns
                field_validation_input = ' '.join(updates.keys())
                result = sanitizer.process({
                    'input_data': field_validation_input,
                    'sanitization_types': ['sql_injection']
                })
                
                if result.get('success'):
                    overall_assessment = result.get('overall_assessment', {})
                    if not overall_assessment.get('is_safe', True):
                        threats = overall_assessment.get('total_threats', 0)
                        logger.error(f"SQL injection threats detected in update fields: {threats}")
                        return None
                else:
                    logger.warning("Universal Input Sanitizer validation failed, using fallback validation")
                    
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error: {e}, using fallback validation")
        
        # Additional field name validation (fallback)
        for field_name in updates.keys():
            # Basic SQL injection pattern detection
            dangerous_patterns = [';', '--', '/*', '*/', 'DROP', 'DELETE', 'INSERT', 
                                'UPDATE', 'SELECT', 'UNION', 'OR 1=1', "'", '"']
            field_upper = field_name.upper()
            
            if any(pattern in field_upper for pattern in dangerous_patterns):
                logger.error(f"Dangerous SQL pattern detected in field: {field_name}")
                return None
            
            # Ensure field names are alphanumeric with underscores only
            if not field_name.replace('_', '').isalnum():
                logger.error(f"Invalid field name format: {field_name}")
                return None
        
        logger.debug(f"Successfully validated {len(updates)} update fields")
        return updates
    
    async def _clear_user_cache(self, user_id: str):
        """Clear user from cache."""
        if not self.redis_client:
            return
        
        try:
            await self.redis_client.delete(f"user:{user_id}")
        except Exception as e:
            logger.error(f"Cache clear error: {str(e)}")
    
    async def get_users_by_role(self, role: str, organization_id: str = None) -> List[Dict[str, Any]]:
        """
        Get all users with a specific role with SQL injection prevention.
        SECURITY FIX: Validates role parameter using Universal Input Sanitizer.
        """
        try:
            # SECURITY FIX: Validate role parameter to prevent SQL injection
            if not await self._validate_sql_parameter(role, 'role'):
                logger.error(f"Invalid role parameter rejected: {role}")
                return []
            
            if organization_id and not await self._validate_sql_parameter(organization_id, 'organization_id'):
                logger.error(f"Invalid organization_id parameter rejected: {organization_id}")
                return []
            
            await self.initialize()
            
            query = "SELECT * FROM users WHERE role = ? AND is_active = 1"
            params = [role]
            
            if organization_id:
                query += " AND organization_id = ?"
                params.append(organization_id)
            
            async with aiosqlite.connect(self.database_path) as db:
                async with db.execute(query, params) as cursor:
                    rows = await cursor.fetchall()
                    columns = [description[0] for description in cursor.description]
                    
                    results = []
                    for row in rows:
                        user_record = dict(zip(columns, row))
                        
                        # Parse JSON fields
                        user_record["project_ids"] = json.loads(user_record.get("project_ids", "[]"))
                        user_record["team_ids"] = json.loads(user_record.get("team_ids", "[]"))
                        user_record["additional_permissions"] = json.loads(user_record.get("additional_permissions", "[]"))
                        user_record["denied_permissions"] = json.loads(user_record.get("denied_permissions", "[]"))
                        user_record["custom_context"] = json.loads(user_record.get("custom_context", "{}"))
                        user_record["metadata"] = json.loads(user_record.get("metadata", "{}"))
                        user_record["is_active"] = bool(user_record["is_active"])
                        
                        results.append(user_record)
                    
                    return results
                    
        except Exception as e:
            logger.error(f"Failed to get users by role: {str(e)}")
            return []
    
    async def _validate_sql_parameter(self, value: str, param_type: str) -> bool:
        """
        SECURITY FIX: Validate SQL parameters using Universal Input Sanitizer.
        """
        if not value or not isinstance(value, str):
            return False
            
        # Use Universal Input Sanitizer for SQL injection validation
        if UNIVERSAL_SANITIZER_AVAILABLE:
            try:
                sanitizer = pp('security/universal_input_sanitizer')
                result = sanitizer.process({
                    'input_data': value,
                    'sanitization_types': ['sql_injection']
                })
                
                if result.get('success'):
                    overall_assessment = result.get('overall_assessment', {})
                    is_safe = overall_assessment.get('is_safe', False)
                    if not is_safe:
                        threats = overall_assessment.get('total_threats', 0)
                        logger.warning(f"SQL injection threats detected in {param_type}: {threats}")
                    return is_safe
                else:
                    logger.warning(f"Universal Input Sanitizer validation failed for {param_type}")
                    return False
                    
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error for {param_type}: {e}")
        
        # Fallback validation
        dangerous_patterns = [';', '--', '/*', '*/', 'DROP', 'DELETE', 'INSERT', 
                            'UPDATE', 'SELECT', 'UNION', 'OR 1=1', "'", '"', '<', '>']
        value_upper = value.upper()
        
        for pattern in dangerous_patterns:
            if pattern in value_upper:
                logger.error(f"Dangerous SQL pattern '{pattern}' detected in {param_type}: {value}")
                return False
        
        return True
    
    async def close(self):
        """Close storage connections."""
        if self.redis_client:
            await self.redis_client.close()
            self.redis_client = None
        
        # SQLite connections are closed automatically with context managers
        logger.info("Closed user management storage connections (SQL injection-protected)")