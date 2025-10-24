#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
SQLite Manager Plugin for PlugPipe
Provides persistent storage and database operations for other plugins
"""

import sqlite3
import json
import logging
import os
import time
import re
from datetime import datetime
from typing import Dict, Any, List, Optional, Union
from contextlib import contextmanager
from dataclasses import dataclass, asdict
import hashlib

# Import PlugPipe loader for plugin discovery
try:
    import sys
    from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
    from shares.loader import pp
except ImportError:
    def pp(plugin_name):
        return None

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "sqlite_manager",
    "version": "1.0.0",
    "description": "SQLite database manager for persistent storage",
    "author": "PlugPipe",
    "tags": ["database", "storage", "sqlite", "persistence"],
    "external_dependencies": [],  # SQLite is built into Python
    "schema_validation": True
}

@dataclass
class DatabaseRecord:
    """Standard database record structure"""
    id: Optional[int] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    data: Optional[Dict[str, Any]] = None

class SQLiteManager:
    """SQLite database manager with connection pooling and transaction support"""

    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}

        # Validate and sanitize configuration
        self._validate_config()

        self.db_path = self.config.get('db_path', get_plugpipe_path("data/plugpipe_security.db"))
        self.auto_commit = self.config.get('auto_commit', True)

        # Load universal input sanitizer
        self.universal_sanitizer = self._load_universal_sanitizer()

        # Ensure directory exists
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

        # Initialize database
        self._initialize_db()

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

    def _validate_config(self):
        """Validate configuration parameters for security"""
        # Strictly reject None configuration
        if self.config is None:
            raise ValueError("Configuration cannot be None - must provide valid dictionary")

        if not isinstance(self.config, dict):
            raise ValueError("Configuration must be a dictionary")

        # Validate db_path
        db_path = self.config.get('db_path', '')
        if db_path and not self._is_safe_path(db_path):
            raise ValueError(f"Invalid database path: {db_path}")

        # Validate auto_commit
        auto_commit = self.config.get('auto_commit')
        if auto_commit is not None and not isinstance(auto_commit, bool):
            raise ValueError("auto_commit must be a boolean")

    def _is_safe_path(self, path: str) -> bool:
        """Validate database path for security"""
        if not path or not isinstance(path, str):
            return False

        # Check for obvious path traversal attempts
        if '..' in path:
            return False

        # Reject paths outside allowed directories (except /tmp for testing)
        allowed_dirs = [
            get_plugpipe_path("data/"),
            '/tmp/',  # Allow /tmp for testing
            '/var/lib/',  # Allow standard data directories
            '/home/',  # Allow user directories
        ]

        if not any(path.startswith(allowed_dir) for allowed_dir in allowed_dirs):
            return False

        # Must end with .db extension
        if not path.endswith('.db'):
            return False

        # Allow alphanumeric, underscores, hyphens, dots, and forward slashes
        safe_pattern = r'^[/a-zA-Z0-9._-]+\.db$'
        return bool(re.match(safe_pattern, path))

    def _validate_input(self, input_data: str, input_type: str) -> Dict[str, Any]:
        """Validate input using Universal Input Sanitizer with fallback"""
        # Always attempt Universal Input Sanitizer first for non-empty strings
        if self.universal_sanitizer and input_data:
            try:
                logger.debug(f"Validating {input_type} with Universal Input Sanitizer: {input_data[:50]}...")
                result = self.universal_sanitizer.process({
                    'input_data': input_data,
                    'sanitization_types': ['sql_injection']  # Only use supported types
                }, {})

                if not result.get('is_safe', False):
                    logger.warning(f"Input validation failed for {input_type}: {result.get('threats_detected', [])}")
                    return {'is_safe': False, 'threats_detected': result.get('threats_detected', []), 'processing_time_ms': (time.time() - start_time) * 1000}

                return {'is_safe': True, 'sanitized_input': result.get('sanitized_output', input_data), 'processing_time_ms': (time.time() - start_time) * 1000}
            except Exception as e:
                logger.debug(f"Universal sanitizer error: {e}")
                # Fall through to fallback validation on error

        # Fallback validation
        return self._fallback_validation(input_data, input_type)

    def _fallback_validation(self, input_data: str, input_type: str) -> Dict[str, Any]:
        """Fallback input validation when Universal Input Sanitizer unavailable"""
        if not isinstance(input_data, str):
            input_data = str(input_data)

        # Allow empty strings and basic alphanumeric content
        if not input_data or input_data.isalnum() or input_data.replace('_', '').isalnum():
            return {'is_safe': True, 'sanitized_input': input_data, 'processing_time_ms': (time.time() - start_time) * 1000}

        # SQL injection patterns (only check for obvious attacks)
        dangerous_patterns = [
            r'(\bDROP\s+TABLE\b|\bDELETE\s+FROM\b|\bTRUNCATE\b)',
            r'(\bUNION\s+SELECT\b|\bOR\s+1\s*=\s*1)',
            r'[;\']\s*(-{2}|/\*)',  # Comment injection
            r'\b(EXEC|EVAL|SYSTEM)\s*\('  # Command injection
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                return {'is_safe': False, 'threats_detected': [f'SQL injection pattern detected in {input_type}'], 'processing_time_ms': (time.time() - start_time) * 1000}

        # Length validation
        if len(input_data) > 10000:  # Reasonable limit
            return {'is_safe': False, 'threats_detected': [f'Input too long for {input_type}'], 'processing_time_ms': (time.time() - start_time) * 1000}

        return {'is_safe': True, 'sanitized_input': input_data, 'processing_time_ms': (time.time() - start_time) * 1000}
    
    @contextmanager
    def get_connection(self):
        """Context manager for database connections"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row  # Enable dict-like access
        try:
            yield conn
            if self.auto_commit:
                conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()
    
    def _initialize_db(self):
        """Initialize database with standard tables"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Generic key-value store
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS kv_store (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Attack database table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS attack_database (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    attack_id TEXT UNIQUE NOT NULL,
                    category TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    source TEXT,
                    protocol_format TEXT DEFAULT 'raw',
                    wrapped_payload TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    hash TEXT UNIQUE
                )
            ''')
            
            # Test results table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS test_results (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    test_run_id TEXT NOT NULL,
                    attack_id TEXT NOT NULL,
                    blocked BOOLEAN NOT NULL,
                    detection_reason TEXT,
                    active_plugins TEXT,
                    ai_enabled BOOLEAN DEFAULT FALSE,
                    response_time_ms REAL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (attack_id) REFERENCES attack_database(attack_id)
                )
            ''')
            
            # Plugin metadata table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plugin_metadata (
                    plugin_name TEXT PRIMARY KEY,
                    ai_enabled BOOLEAN DEFAULT FALSE,
                    ai_details TEXT,
                    last_status_check TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    config TEXT
                )
            ''')
            
            conn.commit()
    
    def store_key_value(self, key: str, value: Any) -> bool:
        """Store key-value pair with input validation"""
        try:
            # Validate key - ensure string conversion and validation
            key_str = str(key) if key is not None else ''
            logger.debug(f"Validating key for storage: {key_str}")

            key_validation = self._validate_input(key_str, 'key')
            if not key_validation['is_safe']:
                logger.error(f"Invalid key rejected: {key_validation['threats_detected']}")
                return False

            with self.get_connection() as conn:
                cursor = conn.cursor()
                value_json = json.dumps(value) if not isinstance(value, str) else value
                cursor.execute('''
                    INSERT OR REPLACE INTO kv_store (key, value, updated_at)
                    VALUES (?, ?, CURRENT_TIMESTAMP)
                ''', (key_str, value_json))
                return True
        except Exception as e:
            logger.error(f"Failed to store key-value {key}: {e}")
            return False
    
    def get_key_value(self, key: str, default: Any = None) -> Any:
        """Get value by key with input validation"""
        try:
            # Validate key
            key_validation = self._validate_input(str(key), 'key')
            if not key_validation['is_safe']:
                logger.error(f"Invalid key rejected: {key_validation['threats_detected']}")
                return default

            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('SELECT value FROM kv_store WHERE key = ?', (key,))
                row = cursor.fetchone()
                if row:
                    try:
                        return json.loads(row['value'])
                    except json.JSONDecodeError:
                        return row['value']
                return default
        except Exception as e:
            logger.error(f"Failed to get key-value {key}: {e}")
            return default
    
    def delete_key(self, key: str) -> bool:
        """Delete key-value pair"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('DELETE FROM kv_store WHERE key = ?', (key,))
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"Failed to delete key {key}: {e}")
            return False
    
    def store_attack(self, attack_data: Dict[str, Any]) -> bool:
        """Store attack data in database"""
        try:
            # Generate hash for deduplication
            payload_hash = hashlib.sha256(
                (attack_data.get('payload', '') + attack_data.get('category', '')).encode()
            ).hexdigest()[:16]
            
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO attack_database 
                    (attack_id, category, payload, severity, description, source, 
                     protocol_format, wrapped_payload, hash)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    attack_data.get('id', ''),
                    attack_data.get('category', ''),
                    attack_data.get('payload', ''),
                    attack_data.get('severity', ''),
                    attack_data.get('description', ''),
                    attack_data.get('source', ''),
                    attack_data.get('protocol_format', 'raw'),
                    attack_data.get('wrapped_payload', ''),
                    payload_hash
                ))
                return True
        except Exception as e:
            logger.error(f"Failed to store attack: {e}")
            return False
    
    def get_attacks(self, category: str = None, limit: int = None) -> List[Dict[str, Any]]:
        """Get attacks from database with input validation"""
        try:
            # Validate category if provided
            if category:
                category_validation = self._validate_input(str(category), 'category')
                if not category_validation['is_safe']:
                    logger.error(f"Invalid category rejected: {category_validation['threats_detected']}")
                    return []

            # Validate limit
            if limit is not None:
                if not isinstance(limit, int) or limit < 1 or limit > 10000:
                    logger.error("Invalid limit: must be integer between 1 and 10000")
                    return []

            with self.get_connection() as conn:
                cursor = conn.cursor()
                if category:
                    query = 'SELECT * FROM attack_database WHERE category = ?'
                    params = (category,)
                else:
                    query = 'SELECT * FROM attack_database'
                    params = ()

                if limit:
                    query += ' LIMIT ?'
                    if category:
                        params = params + (limit,)
                    else:
                        params = (limit,)

                cursor.execute(query, params)
                rows = cursor.fetchall()

                return [dict(row) for row in rows]
        except Exception as e:
            logger.error(f"Failed to get attacks: {e}")
            return []
    
    def store_test_result(self, result_data: Dict[str, Any]) -> bool:
        """Store test result"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO test_results 
                    (test_run_id, attack_id, blocked, detection_reason, active_plugins,
                     ai_enabled, response_time_ms)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                ''', (
                    result_data.get('test_run_id', ''),
                    result_data.get('attack_id', ''),
                    result_data.get('blocked', False),
                    result_data.get('detection_reason', ''),
                    result_data.get('active_plugins', ''),
                    result_data.get('ai_enabled', False),
                    result_data.get('response_time_ms', 0.0)
                ))
                return True
        except Exception as e:
            logger.error(f"Failed to store test result: {e}")
            return False
    
    def get_database_stats(self) -> Dict[str, Any]:
        """Get database statistics"""
        try:
            with self.get_connection() as conn:
                cursor = conn.cursor()
                
                # Attack count by category
                cursor.execute('''
                    SELECT category, COUNT(*) as count 
                    FROM attack_database 
                    GROUP BY category
                ''')
                attack_stats = {row['category']: row['count'] for row in cursor.fetchall()}
                
                # Total counts
                cursor.execute('SELECT COUNT(*) as total FROM attack_database')
                total_attacks = cursor.fetchone()['total']
                
                cursor.execute('SELECT COUNT(*) as total FROM test_results')
                total_results = cursor.fetchone()['total']
                
                return {
                    'total_attacks': total_attacks,
                    'total_test_results': total_results,
                    'attacks_by_category': attack_stats,
                    'db_path': self.db_path,
                    'db_size_bytes': os.path.getsize(self.db_path) if os.path.exists(self.db_path) else 0,
                    'processing_time_ms': (time.time() - start_time) * 1000
                }
        except Exception as e:
            logger.error(f"Failed to get database stats: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}


def process(plugin_ctx: Dict[str, Any], user_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point with comprehensive input validation and error handling"""
    start_time = time.time()

    try:
        # Validate input contexts
        if not isinstance(plugin_ctx, dict):
            return {'status': 'error', 'error': 'Invalid plugin_ctx: must be dictionary', 'processing_time_ms': (time.time() - start_time) * 1000}

        if not isinstance(user_ctx, dict):
            return {'status': 'error', 'error': 'Invalid user_ctx: must be dictionary', 'processing_time_ms': (time.time() - start_time) * 1000}

        operation = user_ctx.get('operation', 'get_stats')
        config = user_ctx.get('config')

        # Validate configuration before proceeding
        if config is None:
            return {
                'status': 'error',
                'error': 'Configuration cannot be None - must provide valid dictionary',
                'execution_time': time.time() - start_time
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        if not isinstance(config, dict):
            return {
                'status': 'error',
                'error': 'Configuration must be a dictionary',
                'execution_time': time.time() - start_time
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        # Validate operation
        valid_operations = [
            'store_kv', 'get_kv', 'store_attack', 'get_attacks',
            'store_test_result', 'get_stats'
        ]

        if operation not in valid_operations:
            return {
                'status': 'error',
                'error': f'Invalid operation: {operation}',
                'processing_time_ms': (time.time() - start_time) * 1000,
                'available_operations': valid_operations
            }

        # Initialize SQLite manager with error handling
        try:
            sqlite_mgr = SQLiteManager(config)
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Failed to initialize SQLite manager: {e}',
                'processing_time_ms': (time.time() - start_time) * 1000,
                'execution_time': time.time() - start_time
            }
        
        if operation == 'store_kv':
            key = user_ctx.get('key')
            value = user_ctx.get('value')
            if not key:
                return {'status': 'error', 'error': 'Key is required', 'processing_time_ms': (time.time() - start_time) * 1000}
            
            success = sqlite_mgr.store_key_value(key, value)
            return {
                'status': 'success' if success else 'error',
                'operation': operation,
                'key': key,
                'stored': success
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        
        elif operation == 'get_kv':
            key = user_ctx.get('key')
            default = user_ctx.get('default')
            if not key:
                return {'status': 'error', 'error': 'Key is required', 'processing_time_ms': (time.time() - start_time) * 1000}
            
            value = sqlite_mgr.get_key_value(key, default)
            return {
                'status': 'success',
                'operation': operation,
                'key': key,
                'value': value
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        
        elif operation == 'store_attack':
            attack_data = user_ctx.get('attack_data')
            if not attack_data:
                return {'status': 'error', 'error': 'Attack data is required', 'processing_time_ms': (time.time() - start_time) * 1000}
            
            success = sqlite_mgr.store_attack(attack_data)
            return {
                'status': 'success' if success else 'error',
                'operation': operation,
                'stored': success
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        
        elif operation == 'get_attacks':
            category = user_ctx.get('category')
            limit = user_ctx.get('limit')
            
            attacks = sqlite_mgr.get_attacks(category, limit)
            return {
                'status': 'success',
                'operation': operation,
                'attacks': attacks,
                'count': len(attacks)
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        
        elif operation == 'store_test_result':
            result_data = user_ctx.get('result_data')
            if not result_data:
                return {'status': 'error', 'error': 'Result data is required', 'processing_time_ms': (time.time() - start_time) * 1000}
            
            success = sqlite_mgr.store_test_result(result_data)
            return {
                'status': 'success' if success else 'error',
                'operation': operation,
                'stored': success
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        
        elif operation == 'get_stats':
            stats = sqlite_mgr.get_database_stats()
            return {
                'status': 'success',
                'operation': operation,
                'stats': stats,
                'execution_time': time.time() - start_time
            , 'processing_time_ms': (time.time() - start_time) * 1000}
        
        else:
            return {
                'status': 'error',
                'error': f'Unknown operation: {operation}',
                'processing_time_ms': (time.time() - start_time) * 1000,
                'available_operations': [
                    'store_kv', 'get_kv', 'store_attack', 'get_attacks',
                    'store_test_result', 'get_stats'
                ]
            }
            
    except Exception as e:
        logger.error(f"SQLite manager plugin failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'execution_time': time.time() - start_time
        , 'processing_time_ms': (time.time() - start_time) * 1000}


if __name__ == "__main__":
    # Test the plugin
    import asyncio
    
    async def test_plugin():
        # Test basic operations
        result = process({}, {'operation': 'get_stats'})
        print(f"Stats: {result}")
        
        # Test key-value storage
        result = process({}, {
            'operation': 'store_kv',
            'key': 'test_key',
            'value': {'test': 'data', 'timestamp': time.time()}
        })
        print(f"Store KV: {result}")
        
        result = process({}, {'operation': 'get_kv', 'key': 'test_key'})
        print(f"Get KV: {result}")
    
    asyncio.run(test_plugin())