#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
SQLite Database Plugin for PlugPipe Registry

Kubernetes-native SQLite database plugin that provides persistent storage
for the PlugPipe registry system. Designed for local development, testing,
and lightweight deployments.

Key Features:
- Kubernetes PersistentVolume integration
- ACID transactions for plugin metadata
- Fast local development setup
- Easy backup and migration
- No external dependencies
"""

import sqlite3
import time
import json
import asyncio
import logging
import os
import hashlib
import re
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from pathlib import Path
# Optional async SQLite import - fallback to sync if unavailable
try:
    import aiosqlite
    AIOSQLITE_AVAILABLE = True
except ImportError:
    AIOSQLITE_AVAILABLE = False
    aiosqlite = None

# Import PlugPipe loader for Universal Input Sanitizer discovery
try:
    import sys
    from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
    from shares.loader import pp
except ImportError:
    def pp(plugin_name):
        return None

logger = logging.getLogger(__name__)


class SQLiteDatabasePlugin:
    """
    SQLite database plugin for PlugPipe registry storage.
    
    Provides persistent storage with ACID compliance while being
    lightweight and perfect for Kubernetes local development.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.db_config = config.get('database', config.get('database_config', {}))

        # Load Universal Input Sanitizer
        self.universal_sanitizer = self._load_universal_sanitizer()

        # Database file configuration - support both test and production paths
        self.db_path = self.db_config.get('file_path', '/data/plugpipe_registry.db')
        self.backup_enabled = self.db_config.get('backup_enabled', True)
        self.backup_interval = self.db_config.get('backup_interval_hours', 24)

        # Kubernetes configuration
        self.k8s_config = self.db_config.get('kubernetes', {})
        self.persistent_volume = self.k8s_config.get('persistent_volume', 'plugpipe-sqlite-pv')
        self.mount_path = self.k8s_config.get('mount_path', '/data')

        # Connection settings
        self.connection_pool_size = self.db_config.get('connection_pool_size', 10)
        self.timeout_seconds = self.db_config.get('timeout_seconds', 30)
        self.connection_timeout = self.timeout_seconds  # Alias for backward compatibility

        # Plugin metadata
        self.plugin_id = f"sqlite_db_{hashlib.md5(self.db_path.encode()).hexdigest()[:8]}"
        self.initialized = False
        
        # Ensure database directory exists (only if not in Kubernetes default path during testing)
        try:
            if not self.db_path.startswith('/data') or os.access('/data', os.W_OK):
                os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        except PermissionError:
            logger.warning(f"Cannot create directory for {self.db_path}, using plugin directory")
            # Fallback to local directory for testing
            if '/data/' in self.db_path:
                fallback_path = self.db_path.replace('/data/', './test_data/')
                os.makedirs(os.path.dirname(fallback_path), exist_ok=True)
                self.db_path = fallback_path
        
        logger.info(f"SQLite Database Plugin initialized: {self.plugin_id}")

    def _load_universal_sanitizer(self):
        """Load Universal Input Sanitizer plugin using pp() discovery."""
        try:
            sanitizer_plugin = pp('universal_input_sanitizer')
            if sanitizer_plugin:
                logger.info("✅ Universal Input Sanitizer plugin loaded")
                return sanitizer_plugin
        except Exception as e:
            logger.warning(f"Universal Input Sanitizer plugin not available: {e}")
            logger.warning("⚠️  Input validation will use fallback validation only")
        return None

    def _validate_input(self, input_data: str, input_type: str) -> Dict[str, Any]:
        """Validate input using Universal Input Sanitizer with fallback."""
        if self.universal_sanitizer and input_data:
            try:
                logger.debug(f"Validating {input_type} with Universal Input Sanitizer: {input_data[:50]}...")
                result = self.universal_sanitizer.process({}, {
                    'input_data': input_data,
                    'sanitization_types': ['sql_injection', 'xss', 'path_traversal', 'command_injection']
                })

                # CRITICAL FIX: Check if sanitizer found threats FIRST
                if not result.get('is_safe', False):  # Default to unsafe if not explicitly safe
                    logger.warning(f"Universal sanitizer blocked unsafe {input_type}: {result.get('threats_detected', [])}")
                    return {'is_safe': False, 'threats_detected': result.get('threats_detected', ['Unknown threat detected']), 'processing_time_ms': (time.time() - start_time) * 1000}

                # Only if explicitly marked as safe AND successful processing, accept the input
                if result.get('is_safe', False) and result.get('success', False):
                    return {'is_safe': True, 'sanitized_input': result.get('sanitized_output', input_data), 'processing_time_ms': (time.time() - start_time) * 1000}

                # If result is unclear or processing failed, use fallback validation
                logger.debug(f"Universal sanitizer result unclear for {input_type}, using fallback validation")

            except Exception as e:
                logger.debug(f"Universal sanitizer error: {e}")
                # Fall through to fallback validation

        # Fallback validation
        return self._fallback_validation(input_data, input_type)

    def _fallback_validation(self, input_data: str, input_type: str) -> Dict[str, Any]:
        """Fallback input validation when Universal Input Sanitizer unavailable."""
        if not isinstance(input_data, str):
            input_data = str(input_data)

        # Allow empty strings and basic alphanumeric content
        if not input_data or input_data.isalnum() or input_data.replace('_', '').replace('-', '').isalnum():
            return {'is_safe': True, 'sanitized_input': input_data, 'processing_time_ms': (time.time() - start_time) * 1000}

        # Check for dangerous patterns
        dangerous_patterns = [
            r';\s*DROP\s+TABLE',      # SQL injection
            r';\s*DELETE\s+FROM',     # SQL injection
            r';\s*INSERT\s+INTO',     # SQL injection
            r';\s*UPDATE\s+',         # SQL injection
            r'UNION\s+SELECT',        # SQL injection
            r'OR\s+1\s*=\s*1',       # SQL injection
            r'\'.*\'.*OR.*\'.*\'',    # SQL injection
            r'\'.*OR.*\'.*=.*\'',     # SQL injection (broader pattern)
            r'\'.*;',                 # SQL injection with semicolon
            r'DROP\s+TABLE',          # SQL injection without semicolon
            r'DELETE\s+FROM',         # SQL injection without semicolon
            r'\.\./',                 # Path traversal
            r'[;&|`$]',              # Command injection
            r'<script',              # XSS
            r'javascript:',          # XSS
            r'vbscript:',            # XSS
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                return {'is_safe': False, 'threats_detected': [f'Dangerous pattern detected in {input_type}: {pattern}'], 'processing_time_ms': (time.time() - start_time) * 1000}

        # Length validation
        if len(input_data) > 1000:
            return {'is_safe': False, 'threats_detected': [f'Input too long for {input_type}'], 'processing_time_ms': (time.time() - start_time) * 1000}

        return {'is_safe': True, 'sanitized_input': input_data, 'processing_time_ms': (time.time() - start_time) * 1000}

    def initialize(self) -> bool:
        """Initialize database connection and schema."""
        try:
            # Create database connection using sync sqlite3
            with sqlite3.connect(self.db_path, timeout=self.connection_timeout) as db:
                # Enable WAL mode for better concurrent access
                db.execute("PRAGMA journal_mode=WAL;")

                # Enable foreign keys
                db.execute("PRAGMA foreign_keys=ON;")

                # Create schema
                self._create_schema(db)

                # Create indexes for performance
                self._create_indexes(db)

                db.commit()

            self.initialized = True
            logger.info(f"SQLite database initialized successfully: {self.db_path}")
            return True

        except Exception as e:
            logger.error(f"Failed to initialize SQLite database: {e}")
            return False
    
    def _create_schema(self, db: sqlite3.Connection):
        """Create database schema for plugin registry."""
        
        # Plugins table - stores plugin metadata
        db.execute("""
            CREATE TABLE IF NOT EXISTS plugins (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                version TEXT NOT NULL,
                owner TEXT NOT NULL,
                status TEXT NOT NULL,
                description TEXT,
                category TEXT,
                type TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                metadata_json TEXT NOT NULL,
                content_hash TEXT,
                UNIQUE(name, version)
            )
        """)
        
        # Plugin dependencies table
        db.execute("""
            CREATE TABLE IF NOT EXISTS plugin_dependencies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id INTEGER NOT NULL,
                dependency_name TEXT NOT NULL,
                dependency_version TEXT,
                dependency_type TEXT DEFAULT 'runtime',
                FOREIGN KEY (plugin_id) REFERENCES plugins (id) ON DELETE CASCADE
            )
        """)
        
        # Plugin capabilities table
        db.execute("""
            CREATE TABLE IF NOT EXISTS plugin_capabilities (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id INTEGER NOT NULL,
                capability TEXT NOT NULL,
                FOREIGN KEY (plugin_id) REFERENCES plugins (id) ON DELETE CASCADE
            )
        """)
        
        # Plugin tags table
        db.execute("""
            CREATE TABLE IF NOT EXISTS plugin_tags (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                plugin_id INTEGER NOT NULL,
                tag TEXT NOT NULL,
                FOREIGN KEY (plugin_id) REFERENCES plugins (id) ON DELETE CASCADE
            )
        """)
        
        # Registry metadata table
        db.execute("""
            CREATE TABLE IF NOT EXISTS registry_metadata (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    def _create_indexes(self, db: sqlite3.Connection):
        """Create database indexes for performance."""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_plugins_name ON plugins(name);",
            "CREATE INDEX IF NOT EXISTS idx_plugins_owner ON plugins(owner);",
            "CREATE INDEX IF NOT EXISTS idx_plugins_category ON plugins(category);",
            "CREATE INDEX IF NOT EXISTS idx_plugins_status ON plugins(status);",
            "CREATE INDEX IF NOT EXISTS idx_plugins_created_at ON plugins(created_at);",
            "CREATE INDEX IF NOT EXISTS idx_plugin_capabilities_capability ON plugin_capabilities(capability);",
            "CREATE INDEX IF NOT EXISTS idx_plugin_tags_tag ON plugin_tags(tag);",
        ]
        
        for index_sql in indexes:
            db.execute(index_sql)
    
    def store_plugin(self, plugin_metadata: Dict[str, Any]) -> bool:
        """Store plugin metadata in the database."""
        try:
            with sqlite3.connect(self.db_path, timeout=self.connection_timeout) as db:
                # Extract core fields
                name = plugin_metadata.get('name')
                version = plugin_metadata.get('version')
                owner = plugin_metadata.get('owner', 'unknown')
                status = plugin_metadata.get('status', 'unknown')
                description = plugin_metadata.get('description', '')
                category = plugin_metadata.get('category', 'general')
                plugin_type = plugin_metadata.get('type', 'plugin')

                if not name or not version:
                    raise ValueError("Plugin name and version are required")

                # Validate critical fields with Universal Input Sanitizer
                name_validation = self._validate_input(str(name), 'plugin_name')
                if not name_validation['is_safe']:
                    raise ValueError(f"Invalid plugin name rejected: {name_validation['threats_detected']}")
                name = name_validation['sanitized_input']

                version_validation = self._validate_input(str(version), 'plugin_version')
                if not version_validation['is_safe']:
                    raise ValueError(f"Invalid plugin version rejected: {version_validation['threats_detected']}")
                version = version_validation['sanitized_input']

                owner_validation = self._validate_input(str(owner), 'plugin_owner')
                if not owner_validation['is_safe']:
                    raise ValueError(f"Invalid plugin owner rejected: {owner_validation['threats_detected']}")
                owner = owner_validation['sanitized_input']

                # Validate other fields
                category_validation = self._validate_input(str(category), 'plugin_category')
                if not category_validation['is_safe']:
                    logger.warning(f"Invalid plugin category, using 'general': {category_validation['threats_detected']}")
                    category = 'general'
                else:
                    category = category_validation['sanitized_input']
                
                # Create content hash
                content_hash = hashlib.sha256(json.dumps(plugin_metadata, sort_keys=True).encode()).hexdigest()
                
                # Store plugin
                cursor = db.execute("""
                    INSERT OR REPLACE INTO plugins 
                    (name, version, owner, status, description, category, type, metadata_json, content_hash, updated_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (name, version, owner, status, description, category, plugin_type, 
                      json.dumps(plugin_metadata), content_hash))
                
                plugin_id = cursor.lastrowid
                
                # Clear existing related data
                db.execute("DELETE FROM plugin_dependencies WHERE plugin_id = ?", (plugin_id,))
                db.execute("DELETE FROM plugin_capabilities WHERE plugin_id = ?", (plugin_id,))
                db.execute("DELETE FROM plugin_tags WHERE plugin_id = ?", (plugin_id,))
                
                # Store capabilities
                capabilities = plugin_metadata.get('capabilities', [])
                for capability in capabilities:
                    db.execute("""
                        INSERT INTO plugin_capabilities (plugin_id, capability) VALUES (?, ?)
                    """, (plugin_id, capability))
                
                # Store tags
                tags = plugin_metadata.get('tags', [])
                for tag in tags:
                    db.execute("""
                        INSERT INTO plugin_tags (plugin_id, tag) VALUES (?, ?)
                    """, (plugin_id, tag))
                
                # Store dependencies (from SBOM if available)
                sbom = plugin_metadata.get('sbom', {})
                if isinstance(sbom, dict):
                    components = sbom.get('components', [])
                    for component in components:
                        if isinstance(component, dict):
                            db.execute("""
                                INSERT INTO plugin_dependencies 
                                (plugin_id, dependency_name, dependency_version, dependency_type)
                                VALUES (?, ?, ?, ?)
                            """, (plugin_id, component.get('name', ''), 
                                  component.get('version', ''), component.get('type', 'library')))
                
                db.commit()
                logger.info(f"Stored plugin: {name}@{version}")
                return True
                
        except Exception as e:
            logger.error(f"Failed to store plugin {plugin_metadata.get('name', 'unknown')}: {e}")
            return False
    
    def get_plugin(self, name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve plugin metadata by name and version."""
        try:
            # Validate input parameters
            name_validation = self._validate_input(str(name), 'plugin_name')
            if not name_validation['is_safe']:
                logger.error(f"Invalid plugin name rejected: {name_validation['threats_detected']}")
                return None
            name = name_validation['sanitized_input']

            if version:
                version_validation = self._validate_input(str(version), 'plugin_version')
                if not version_validation['is_safe']:
                    logger.error(f"Invalid plugin version rejected: {version_validation['threats_detected']}")
                    return None
                version = version_validation['sanitized_input']

            with sqlite3.connect(self.db_path, timeout=self.connection_timeout) as db:
                if version:
                    cursor = db.execute("""
                        SELECT metadata_json FROM plugins
                        WHERE name = ? AND version = ?
                    """, (name, version))
                else:
                    # Get latest version if no version specified
                    cursor = db.execute("""
                        SELECT metadata_json FROM plugins
                        WHERE name = ?
                        ORDER BY created_at DESC LIMIT 1
                    """, (name,))
                
                row = cursor.fetchone()
                if row:
                    return json.loads(row[0])
                return None
                
        except Exception as e:
            logger.error(f"Failed to get plugin {name}@{version}: {e}")
            return None
    
    def search_plugins(self, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Search plugins by query with optional filters."""
        try:
            # Validate search query
            if query:
                query_validation = self._validate_input(str(query), 'search_query')
                if not query_validation['is_safe']:
                    logger.error(f"Invalid search query rejected: {query_validation['threats_detected']}")
                    return []
                query = query_validation['sanitized_input']

            # Validate filters
            validated_filters = {}
            if filters:
                for key, value in filters.items():
                    key_validation = self._validate_input(str(key), 'filter_key')
                    if not key_validation['is_safe']:
                        logger.warning(f"Invalid filter key rejected: {key}: {key_validation['threats_detected']}")
                        continue

                    value_validation = self._validate_input(str(value), 'filter_value')
                    if not value_validation['is_safe']:
                        logger.warning(f"Invalid filter value rejected: {value}: {value_validation['threats_detected']}")
                        continue

                    validated_filters[key_validation['sanitized_input']] = value_validation['sanitized_input']

            with sqlite3.connect(self.db_path, timeout=self.connection_timeout) as db:
                # Build search query
                where_conditions = []
                params = []

                if query:
                    where_conditions.append("""
                        (name LIKE ? OR description LIKE ? OR owner LIKE ?)
                    """)
                    query_param = f"%{query}%"
                    params.extend([query_param, query_param, query_param])
                
                if validated_filters:
                    if validated_filters.get('category'):
                        where_conditions.append("category = ?")
                        params.append(validated_filters['category'])

                    if validated_filters.get('status'):
                        where_conditions.append("status = ?")
                        params.append(validated_filters['status'])

                    if validated_filters.get('owner'):
                        where_conditions.append("owner = ?")
                        params.append(validated_filters['owner'])
                
                where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
                
                cursor = db.execute(f"""
                    SELECT metadata_json FROM plugins 
                    WHERE {where_clause}
                    ORDER BY created_at DESC
                    LIMIT 100
                """, params)
                
                rows = cursor.fetchall()
                return [json.loads(row[0]) for row in rows]
                
        except Exception as e:
            logger.error(f"Failed to search plugins: {e}")
            return []
    
    def list_plugins(self, limit: int = 50, offset: int = 0, filters: Optional[Dict[str, Any]] = None) -> Tuple[List[Dict[str, Any]], int]:
        """List plugins with pagination."""
        try:
            with sqlite3.connect(self.db_path, timeout=self.connection_timeout) as db:
                # Build filter conditions
                where_conditions = []
                params = []
                
                if filters:
                    if filters.get('category'):
                        where_conditions.append("category = ?")
                        params.append(filters['category'])
                    
                    if filters.get('status'):
                        where_conditions.append("status = ?")
                        params.append(filters['status'])
                
                where_clause = " AND ".join(where_conditions) if where_conditions else "1=1"
                
                # Get total count
                count_cursor = db.execute(f"SELECT COUNT(*) FROM plugins WHERE {where_clause}", params)
                total_count = (count_cursor.fetchone())[0]
                
                # Get plugins with pagination
                cursor = db.execute(f"""
                    SELECT metadata_json FROM plugins 
                    WHERE {where_clause}
                    ORDER BY created_at DESC
                    LIMIT ? OFFSET ?
                """, params + [limit, offset])
                
                rows = cursor.fetchall()
                plugins = [json.loads(row[0]) for row in rows]
                
                return plugins, total_count
                
        except Exception as e:
            logger.error(f"Failed to list plugins: {e}")
            return [], 0
    
    def delete_plugin(self, name: str, version: str) -> bool:
        """Delete a plugin from the database."""
        try:
            # Validate input parameters
            name_validation = self._validate_input(str(name), 'plugin_name')
            if not name_validation['is_safe']:
                logger.error(f"Invalid plugin name rejected: {name_validation['threats_detected']}")
                return False
            name = name_validation['sanitized_input']

            version_validation = self._validate_input(str(version), 'plugin_version')
            if not version_validation['is_safe']:
                logger.error(f"Invalid plugin version rejected: {version_validation['threats_detected']}")
                return False
            version = version_validation['sanitized_input']

            with sqlite3.connect(self.db_path, timeout=self.connection_timeout) as db:
                cursor = db.execute("""
                    DELETE FROM plugins WHERE name = ? AND version = ?
                """, (name, version))
                
                db.commit()
                
                if cursor.rowcount > 0:
                    logger.info(f"Deleted plugin: {name}@{version}")
                    return True
                else:
                    logger.warning(f"Plugin not found for deletion: {name}@{version}")
                    return False
                
        except Exception as e:
            logger.error(f"Failed to delete plugin {name}@{version}: {e}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Perform database health check."""
        try:
            with sqlite3.connect(self.db_path, timeout=self.connection_timeout) as db:
                # Check database connectivity
                cursor = db.execute("SELECT COUNT(*) FROM plugins")
                plugin_count = (cursor.fetchone())[0]
                
                # Get database file size
                db_size = os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0
                
                # Check disk space
                disk_usage = os.statvfs(os.path.dirname(self.db_path))
                free_space = disk_usage.f_frsize * disk_usage.f_bavail
                
                return {
                    'plugin_id': self.plugin_id,
                    'database_type': 'sqlite',
                    'healthy': True,
                    'initialized': self.initialized,
                    'database_path': self.db_path,
                    'plugin_count': plugin_count,
                    'database_size_bytes': db_size,
                    'free_disk_space_bytes': free_space,
                    'kubernetes': {
                        'persistent_volume': self.persistent_volume,
                        'mount_path': self.mount_path
                    , 'processing_time_ms': (time.time() - start_time) * 1000},
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }
                
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'plugin_id': self.plugin_id,
                'database_type': 'sqlite',
                'healthy': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            , 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def backup_database(self, backup_path: Optional[str] = None) -> bool:
        """Create database backup."""
        try:
            if not backup_path:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{self.db_path}.backup_{timestamp}"
            
            # Use SQLite backup API
            with sqlite3.connect(self.db_path) as source_db:
                with sqlite3.connect(backup_path) as backup_db:
                    source_db.backup(backup_db)
            
            logger.info(f"Database backup created: {backup_path}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to backup database: {e}")
            return False
    
    def migrate_from_yaml(self, yaml_plugin_directory: str) -> Dict[str, Any]:
        """Migrate plugins from YAML backend to SQLite."""
        try:
            import yaml
            migration_results = {
                'total_found': 0,
                'successful': 0,
                'failed': 0,
                'errors': []
            }
            
            yaml_path = Path(yaml_plugin_directory)
            if not yaml_path.exists():
                raise ValueError(f"YAML directory not found: {yaml_plugin_directory}")
            
            # Find all plug.yaml files
            for plug_yaml in yaml_path.rglob("plug.yaml"):
                migration_results['total_found'] += 1
                
                try:
                    with open(plug_yaml, 'r') as f:
                        plugin_data = yaml.safe_load(f)
                    
                    # Store in database
                    success = self.store_plugin(plugin_data)
                    if success:
                        migration_results['successful'] += 1
                    else:
                        migration_results['failed'] += 1
                        migration_results['errors'].append(f"Failed to store: {plug_yaml}")
                        
                except Exception as e:
                    migration_results['failed'] += 1
                    migration_results['errors'].append(f"Error processing {plug_yaml}: {str(e)}")
            
            logger.info(f"Migration completed: {migration_results['successful']} successful, {migration_results['failed']} failed")
            return migration_results
            
        except Exception as e:
            logger.error(f"Migration failed: {e}")
            return {'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}


# Plugin entry point
def process(ctx, cfg):
    """
    PlugPipe plugin entry point for SQLite Database.
    
    Args:
        ctx: Plugin context with logger, metrics, etc.
        cfg: Plugin configuration
    
    Returns:
        dict: Plugin response with database instance and capabilities
    """
    start_time = time.time()

    logger = ctx.get('logger') if ctx and ctx.get('logger') else logging.getLogger(__name__)
    
    try:
        # Handle specific operations if requested
        operation = cfg.get('operation')
        if operation:
            # Use sync operations for SQLite
            return process_sync_operations(ctx, cfg)
        
        # Create SQLite database plugin
        sqlite_plugin = SQLiteDatabasePlugin(cfg)
        
        # Initialize database
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            initialization_success = loop.run_until_complete(sqlite_plugin.initialize())
        finally:
            loop.close()
        
        if not initialization_success:
            return {
                'success': False,
                'error': 'Database initialization failed',
                'database': None,
                'capabilities': [],
                'status': 'failed'
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        
        return {
            'success': True,
            'database': sqlite_plugin,
            'capabilities': [
                'store_plugin',
                'get_plugin',
                'search_plugins',
                'list_plugins',
                'delete_plugin',
                'health_check',
                'backup_database',
                'migrate_from_yaml'
            ],
            'database_type': 'sqlite',
            'plugin_id': sqlite_plugin.plugin_id,
            'status': 'ready',
            'kubernetes_native': True,
            'message': 'SQLite Database Plugin initialized successfully'
        , 'processing_time_ms': (time.time() - start_time) * 1000}
        
    except Exception as e:
        error_msg = f"SQLite Database Plugin initialization failed: {e}"
        if logger:
            logger.error(error_msg)
        
        return {
            'success': False,
            'error': str(e),
            'database': None,
            'capabilities': [],
            'status': 'failed'
        , 'processing_time_ms': (time.time() - start_time) * 1000}


def process_sync_operations(ctx, cfg):
    """
    Async version of process function for specific database operations.
    
    Args:
        ctx: Plugin context
        cfg: Plugin configuration with operation specified
    
    Returns:
        dict: Operation result
    """
    logger = ctx.get('logger') if ctx and ctx.get('logger') else logging.getLogger(__name__)
    
    try:
        # Create and initialize plugin
        sqlite_plugin = SQLiteDatabasePlugin(cfg)
        sqlite_plugin.initialize()
        
        # Get operation
        operation = cfg.get('operation')
        
        if operation == 'health_check':
            health_status = sqlite_plugin.health_check()
            return {
                'success': True,
                'operation_completed': 'health_check',
                'health_status': health_status
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        elif operation == 'store_plugin':
            plugin_metadata = cfg.get('plugin_metadata', {})
            result = sqlite_plugin.store_plugin(plugin_metadata)
            return {
                'success': result,
                'operation_completed': 'store_plugin',
                'result': result
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        elif operation == 'get_plugin':
            name = cfg.get('name')
            version = cfg.get('version')
            result = sqlite_plugin.get_plugin(name, version)
            return {
                'success': result is not None,
                'operation_completed': 'get_plugin',
                'result': result
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        elif operation == 'search_plugins':
            query = cfg.get('query', '')
            filters = cfg.get('filters', {})
            result = sqlite_plugin.search_plugins(query, filters)
            return {
                'success': True,
                'operation_completed': 'search_plugins',
                'result': result
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        elif operation == 'list_plugins':
            result = sqlite_plugin.list_plugins()
            return {
                'success': True,
                'operation_completed': 'list_plugins',
                'result': result
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        elif operation == 'delete_plugin':
            name = cfg.get('name')
            version = cfg.get('version')
            result = sqlite_plugin.delete_plugin(name, version)
            return {
                'success': result,
                'operation_completed': 'delete_plugin',
                'result': result
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'processing_time_ms': (time.time() - start_time) * 1000,
                'operation_completed': operation
            }
            
    except Exception as e:
        logger.error(f"SQLite operation failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation_completed': operation if 'operation' in locals() else 'unknown'
        , 'processing_time_ms': (time.time() - start_time) * 1000}


# Plugin metadata for discovery
plug_metadata = {
    "name": "SQLite Database Plugin",
    "version": "1.0.0",
    "description": "Kubernetes-native SQLite database plugin for PlugPipe registry storage",
    "author": "PlugPipe Core Team",
    "category": "database",
    "type": "storage",
    "capabilities": [
        "store_plugin",
        "get_plugin", 
        "search_plugins",
        "list_plugins",
        "delete_plugin",
        "health_check",
        "backup_database",
        "migrate_from_yaml"
    ],
    "enterprise_ready": True,
    "production_ready": True,
    "kubernetes_native": True,
    "implementation": "sqlite_aiosqlite"
}