#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Database Adapter Plugin - Universal Database Interface

Provides abstract, generic database operations over ANY database technology:
- SQLite (via sqlite_manager)
- PostgreSQL (via factory)
- MongoDB (via factory)
- MySQL (future)
- Redis (future)

Follows PlugPipe principles:
- REUSE EVERYTHING: Delegates to existing database plugins via pp_instance()
- ABSTRACTION: No hardcoded database technology
- INSTANCE ISOLATION: Uses pp_instance() for isolated database instances

Usage:
    from shares.loader import pp_instance

    # Create isolated database instance for auth
    db = pp_instance('database_adapter', 'auth_users', {
        'backend': 'sqlite',
        'db_path': '/path/to/users.db'
    })

    # Execute SQL
    result = db.process({'action': 'execute', 'sql': 'INSERT INTO ...', 'params': (...)})

    # Query data
    result = db.process({'action': 'query', 'sql': 'SELECT * FROM users WHERE username = ?', 'params': ('admin',)})
"""

import sys
import os
import logging
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

# Import PlugPipe loader for plugin discovery
try:
    from shares.plugpipe_path_helper import setup_plugpipe_environment
    setup_plugpipe_environment()
    from shares.loader import pp_instance
except ImportError:
    def pp_instance(plugin_name, instance_name, config):
        return None

logger = logging.getLogger(__name__)


class DatabaseAdapter:
    """
    Universal database adapter that works with any database plugin.

    Provides unified SQL/NoSQL interface by delegating to appropriate
    database plugins via pp_instance().
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.backend = config.get('backend', 'sqlite')
        self.plugin = None

        # Initialize backend plugin
        self._initialize_backend()

    def _initialize_backend(self):
        """Initialize appropriate database plugin based on backend type"""
        try:
            if self.backend == 'sqlite':
                # Use sqlite_manager plugin via pp_instance()
                instance_name = self.config.get('instance_name', 'default')
                self.plugin = pp_instance(
                    'sqlite_manager',
                    name=instance_name,
                    config={'db_path': self.config.get('db_path')}
                )
            elif self.backend in ['postgresql', 'postgres']:
                # Use factory plugin with PostgreSQL backend via pp_instance()
                instance_name = self.config.get('instance_name', 'default')
                self.plugin = pp_instance(
                    'factory',
                    name=instance_name,
                    config={
                        'database_factory': {
                            'primary_database': 'postgresql'
                        },
                        'databases': {
                            'postgresql': self.config.get('connection', {})
                        }
                    }
                )
            elif self.backend == 'mongodb':
                # Use factory plugin with MongoDB backend via pp_instance()
                instance_name = self.config.get('instance_name', 'default')
                self.plugin = pp_instance(
                    'factory',
                    name=instance_name,
                    config={
                        'database_factory': {
                            'primary_database': 'mongodb'
                        },
                        'databases': {
                            'mongodb': self.config.get('connection', {})
                        }
                    }
                )
            else:
                logger.error(f"Unsupported database backend: {self.backend}")

            if self.plugin:
                logger.info(f"✅ Database adapter initialized with {self.backend} backend")
            else:
                logger.warning(f"⚠️  Database adapter plugin not available for {self.backend}")

        except Exception as e:
            logger.error(f"Failed to initialize database adapter: {e}")

    def execute(self, sql: str, params: Tuple = ()) -> Dict[str, Any]:
        """
        Execute SQL statement (INSERT, UPDATE, DELETE, CREATE TABLE, etc.)

        Args:
            sql: SQL statement to execute
            params: Parameters for parameterized queries (prevents SQL injection)

        Returns:
            {'success': bool, 'rows_affected': int, 'error': str}
        """
        if not self.plugin:
            return {'success': False, 'error': 'Database plugin not initialized'}

        try:
            # For SQLite backend, use direct SQLite operations
            if self.backend == 'sqlite':
                import sqlite3
                db_path = self.config.get('db_path')
                conn = sqlite3.connect(db_path)
                cursor = conn.cursor()
                cursor.execute(sql, params)
                rows_affected = cursor.rowcount
                conn.commit()
                conn.close()

                return {
                    'success': True,
                    'rows_affected': rows_affected,
                    'backend': self.backend
                }
            else:
                # For other backends, delegate to plugin
                result = self.plugin.process({
                    'action': 'execute',
                    'sql': sql,
                    'params': params
                })
                return result

        except Exception as e:
            logger.error(f"Database execute error: {e}")
            return {'success': False, 'error': str(e)}

    def query(self, sql: str, params: Tuple = ()) -> Dict[str, Any]:
        """
        Query database (SELECT statements)

        Args:
            sql: SELECT SQL statement
            params: Parameters for parameterized queries

        Returns:
            {'success': bool, 'data': List[Dict], 'count': int, 'error': str}
        """
        if not self.plugin:
            return {'success': False, 'error': 'Database plugin not initialized', 'data': []}

        try:
            # For SQLite backend, use direct SQLite operations
            if self.backend == 'sqlite':
                import sqlite3
                db_path = self.config.get('db_path')
                conn = sqlite3.connect(db_path)
                conn.row_factory = sqlite3.Row
                cursor = conn.cursor()
                cursor.execute(sql, params)
                rows = cursor.fetchall()
                conn.close()

                data = [dict(row) for row in rows]

                return {
                    'success': True,
                    'data': data,
                    'count': len(data),
                    'backend': self.backend
                }
            else:
                # For other backends, delegate to plugin
                result = self.plugin.process({
                    'action': 'query',
                    'sql': sql,
                    'params': params
                })
                return result

        except Exception as e:
            logger.error(f"Database query error: {e}")
            return {'success': False, 'error': str(e), 'data': []}

    def create_table(self, table_name: str, schema: Dict[str, str]) -> Dict[str, Any]:
        """
        Create table with given schema

        Args:
            table_name: Name of table to create
            schema: Dict of column_name: column_type

        Returns:
            {'success': bool, 'table': str, 'error': str}
        """
        try:
            # Build CREATE TABLE SQL
            columns = []
            for col_name, col_type in schema.items():
                columns.append(f"{col_name} {col_type}")

            sql = f"CREATE TABLE IF NOT EXISTS {table_name} ({', '.join(columns)})"

            result = self.execute(sql)
            if result.get('success'):
                result['table'] = table_name

            return result

        except Exception as e:
            logger.error(f"Create table error: {e}")
            return {'success': False, 'error': str(e)}


# PlugPipe Plugin Interface
async def process(ctx, cfg):
    """
    Main plugin entry point

    Supported actions:
    - execute: Execute SQL statement (INSERT, UPDATE, DELETE, etc.)
    - query: Query data (SELECT)
    - create_table: Create table with schema
    - health_check: Check database connection

    Example:
        {
            'action': 'query',
            'sql': 'SELECT * FROM users WHERE username = ?',
            'params': ('admin',)
        }
    """
    try:
        action = cfg.get('action', 'query')

        # Initialize adapter (from config or ctx)
        adapter_config = cfg.get('config', {})
        adapter = DatabaseAdapter(adapter_config)

        if action == 'execute':
            sql = cfg.get('sql', '')
            params = cfg.get('params', ())
            result = adapter.execute(sql, params)
            return {
                'success': result.get('success', False),
                'rows_affected': result.get('rows_affected', 0),
                'error': result.get('error'),
                'action': 'execute'
            }

        elif action == 'query':
            sql = cfg.get('sql', '')
            params = cfg.get('params', ())
            result = adapter.query(sql, params)
            return {
                'success': result.get('success', False),
                'data': result.get('data', []),
                'count': result.get('count', 0),
                'error': result.get('error'),
                'action': 'query'
            }

        elif action == 'create_table':
            table_name = cfg.get('table', '')
            schema = cfg.get('schema', {})
            result = adapter.create_table(table_name, schema)
            return {
                'success': result.get('success', False),
                'table': result.get('table'),
                'error': result.get('error'),
                'action': 'create_table'
            }

        elif action == 'health_check':
            return {
                'success': adapter.plugin is not None,
                'backend': adapter.backend,
                'plugin_available': adapter.plugin is not None,
                'action': 'health_check'
            }

        else:
            return {
                'success': False,
                'error': f'Unknown action: {action}',
                'supported_actions': ['execute', 'query', 'create_table', 'health_check']
            }

    except Exception as e:
        logger.error(f"Database adapter error: {e}")
        return {
            'success': False,
            'error': str(e),
            'action': cfg.get('action', 'unknown')
        }


# Plugin metadata
PLUGIN_METADATA = {
    "name": "database_adapter",
    "version": "1.0.0",
    "description": "Universal database adapter providing abstract interface over any database technology",
    "author": "PlugPipe Core Team",
    "category": "database",
    "type": "adapter",
    "capabilities": [
        "sql_execution",
        "sql_query",
        "table_creation",
        "backend_abstraction",
        "instance_isolation"
    ],
    "supported_backends": ["sqlite", "postgresql", "mongodb"],
    "uses_pp_instance": True,
    "delegates_to": ["sqlite_manager", "factory"]
}
