#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Database Factory Plugin for PlugPipe Registry

Orchestrates multiple database plugins (SQLite, PostgreSQL, MongoDB) and provides
a unified database interface. Enables seamless database switching, failover, and
multi-database scenarios.

Key Features:
- Dynamic database plugin loading and management
- Unified database interface abstraction
- Database switching with zero downtime
- Health monitoring across all database instances
- Kubernetes-native deployment support
- Configuration-driven database selection
"""

import asyncio
import time
import logging
import os
import json
import importlib.util
import re
from typing import Dict, List, Any, Optional, Union
from datetime import datetime, timezone
from pathlib import Path
from abc import ABC, abstractmethod
import yaml

# Import PlugPipe loader for plugin discovery
try:
    import sys
    from shares.plugpipe_path_helper import setup_plugpipe_environment, get_plugpipe_path; setup_plugpipe_environment()
    from shares.loader import pp
except ImportError:
    def pp(plugin_name):
        return None
    def get_plugpipe_path(path):
        return f"/mnt/c/Project/PlugPipe/{path}"

logger = logging.getLogger(__name__)


class DatabasePluginInterface(ABC):
    """
    Abstract interface that all database plugins must implement.
    Provides the contract for database operations.
    """

    @abstractmethod
    def store_plugin(self, plugin_metadata: Dict[str, Any]) -> bool:
        """Store plugin metadata in database."""
        raise NotImplementedError("Subclasses must implement store_plugin")

    @abstractmethod
    def get_plugin(self, name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve plugin metadata from database."""
        raise NotImplementedError("Subclasses must implement get_plugin")

    @abstractmethod
    def search_plugins(self, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Search plugins in database."""
        raise NotImplementedError("Subclasses must implement search_plugins")

    @abstractmethod
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all plugins in database."""
        raise NotImplementedError("Subclasses must implement list_plugins")

    @abstractmethod
    def delete_plugin(self, name: str, version: Optional[str] = None) -> bool:
        """Delete plugin from database."""
        raise NotImplementedError("Subclasses must implement delete_plugin")

    @abstractmethod
    def health_check(self) -> Dict[str, Any]:
        """Check database health and return metrics."""
        raise NotImplementedError("Subclasses must implement health_check")


class DatabaseFactoryPlugin:
    """
    Database Factory Plugin that orchestrates multiple database plugins.
    
    Provides a unified interface for database operations while managing
    multiple database backends. Supports configuration-driven database
    selection and seamless switching.
    """
    
    def __init__(self, config: Dict[str, Any]):
        # Validate configuration
        self._validate_config(config)

        self.config = config
        self.factory_config = config.get('database_factory', {})

        # Load universal input sanitizer
        self.universal_sanitizer = self._load_universal_sanitizer()
        
        # Factory configuration
        self.primary_database = self.factory_config.get('primary_database', 'sqlite')
        self.fallback_databases = self.factory_config.get('fallback_databases', [])
        self.enable_failover = self.factory_config.get('enable_failover', True)
        self.health_check_interval = self.factory_config.get('health_check_interval', 30)
        
        # Database plugin configurations
        self.database_configs = config.get('databases', {})
        
        # Kubernetes configuration
        self.k8s_config = self.factory_config.get('kubernetes', {})
        self.namespace = self.k8s_config.get('namespace', 'plugpipe')
        
        # Factory metadata
        self.factory_id = f"db_factory_{hash(str(config)) % 100000}"
        self.initialized = False
        
        # Database plugin instances
        self.database_plugins: Dict[str, Any] = {}
        self.active_database = None
        self.plugin_paths = {
            'sqlite': get_plugpipe_path("plugs/database/sqlite/1.0.0"),
            'postgresql': get_plugpipe_path("plugs/database/postgresql/1.0.0"),  # Future
            'mongodb': get_plugpipe_path("plugs/database/mongodb/1.0.0")  # Future
        }
        
        logger.info(f"Database Factory Plugin initialized: {self.factory_id}")

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

    def _validate_config(self, config: Dict[str, Any]):
        """Validate configuration parameters for security"""
        if not isinstance(config, dict):
            raise ValueError("Configuration must be a dictionary")

        # Validate database factory config
        factory_config = config.get('database_factory', {})
        if factory_config and not isinstance(factory_config, dict):
            raise ValueError("database_factory configuration must be a dictionary")

        # Validate primary database
        primary_db = factory_config.get('primary_database', 'sqlite')
        if not self._is_valid_database_type(primary_db):
            raise ValueError(f"Invalid primary database type: {primary_db}")

        # Validate fallback databases
        fallback_dbs = factory_config.get('fallback_databases', [])
        if not isinstance(fallback_dbs, list):
            raise ValueError("fallback_databases must be a list")

        for db_type in fallback_dbs:
            if not self._is_valid_database_type(db_type):
                raise ValueError(f"Invalid fallback database type: {db_type}")

    def _is_valid_database_type(self, db_type: str) -> bool:
        """Validate database type for security"""
        if not isinstance(db_type, str):
            return False

        # Only allow known database types
        valid_types = {'sqlite', 'postgresql', 'mongodb'}
        return db_type in valid_types

    def _validate_input(self, input_data: str, input_type: str) -> Dict[str, Any]:
        """Validate input using Universal Input Sanitizer with fallback"""
        if self.universal_sanitizer and input_data:
            try:
                logger.debug(f"Validating {input_type} with Universal Input Sanitizer: {input_data[:50]}...")
                result = self.universal_sanitizer.process({
                    'input_data': input_data,
                    'sanitization_types': ['sql_injection', 'path_traversal']
                }, {})

                if not result.get('is_safe', False):
                    logger.warning(f"Input validation failed for {input_type}: {result.get('threats_detected', [])}")
                    return {'is_safe': False, 'threats_detected': result.get('threats_detected', [])}

                return {'is_safe': True, 'sanitized_input': result.get('sanitized_output', input_data)}
            except Exception as e:
                logger.debug(f"Universal sanitizer error: {e}")
                # Fall through to fallback validation

        # Fallback validation
        return self._fallback_validation(input_data, input_type)

    def _fallback_validation(self, input_data: str, input_type: str) -> Dict[str, Any]:
        """Fallback input validation when Universal Input Sanitizer unavailable"""
        if not isinstance(input_data, str):
            input_data = str(input_data)

        # Allow empty strings and basic alphanumeric content
        if not input_data or input_data.isalnum() or input_data.replace('_', '').isalnum():
            return {'is_safe': True, 'sanitized_input': input_data}

        # Check for dangerous patterns
        dangerous_patterns = [
            r'\.\./',  # Path traversal
            r'[;&|`$]',  # Command injection
            r'<script',  # XSS
            r'DROP\s+TABLE',  # SQL injection
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, input_data, re.IGNORECASE):
                return {'is_safe': False, 'threats_detected': [f'Dangerous pattern detected in {input_type}']}

        # Length validation
        if len(input_data) > 1000:
            return {'is_safe': False, 'threats_detected': [f'Input too long for {input_type}']}

        return {'is_safe': True, 'sanitized_input': input_data}

    # =============================================
    # DATABASE SECURITY HARDENING METHODS
    # =============================================

    def _validate_database_connection_string(self, connection_string: str) -> Dict[str, Any]:
        """Validate database connection string for security vulnerabilities."""
        if not isinstance(connection_string, str):
            return {'is_valid': False, 'errors': ['Connection string must be a string']}

        validation_result = {
            'is_valid': True,
            'sanitized_connection': connection_string,
            'errors': [],
            'security_issues': []
        }

        # Block dangerous connection string patterns
        dangerous_patterns = [
            r'password\s*=\s*["\']?\s*["\']?',  # Empty passwords in key=value format
            r'://[^:]*:@',  # Empty passwords in URL format (user:@host)
            r'ssl\s*=\s*false',  # Unencrypted connections
            r'trust_server_certificate\s*=\s*true',  # Certificate validation bypass
            r'[;&|`$]',  # Command injection characters
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, connection_string, re.IGNORECASE):
                validation_result['is_valid'] = False
                validation_result['errors'].append(f'Dangerous pattern detected in connection string')
                return validation_result

        # Require SSL for PostgreSQL/MySQL connections
        if any(db_type in connection_string.lower() for db_type in ['postgresql', 'mysql', 'mariadb']):
            if 'ssl' not in connection_string.lower() and 'sslmode' not in connection_string.lower():
                validation_result['security_issues'].append('SSL/TLS encryption not explicitly configured')

        return validation_result

    def _validate_database_query(self, query: str) -> Dict[str, Any]:
        """Validate database query for SQL injection and dangerous operations."""
        if not isinstance(query, str):
            return {'is_valid': False, 'errors': ['Query must be a string']}

        validation_result = {
            'is_valid': True,
            'sanitized_query': query,
            'errors': [],
            'security_issues': []
        }

        # Block dangerous SQL operations
        dangerous_operations = [
            r'\bDROP\s+TABLE\b',
            r'\bDROP\s+DATABASE\b',
            r'\bTRUNCATE\b',
            r'\bDELETE\s+FROM\s+\w+\s*;?\s*$',  # DELETE without WHERE
            r'\bGRANT\b',
            r'\bREVOKE\b',
            r'\bALTER\s+USER\b',
            r'\bCREATE\s+USER\b',
            r'\bSHUTDOWN\b',
            r'--',  # SQL comments
            r'/\*.*\*/',  # SQL block comments
            r';\s*\w+',  # Multiple statements
            r'\bunion\s+select\b',  # Union-based injection
            r'\bor\s+1\s*=\s*1\b',  # Classic injection
        ]

        for pattern in dangerous_operations:
            if re.search(pattern, query, re.IGNORECASE):
                validation_result['is_valid'] = False
                validation_result['errors'].append(f'Dangerous SQL operation detected: {pattern}')
                return validation_result

        # Check for potential SQL injection patterns
        injection_patterns = [
            r"'.*'.*'",  # Quote manipulation
            r'"\s*or\s*"',  # OR injection in quotes
            r'\bwhere\s+\w+\s*=\s*\w+\s+or\s+',  # WHERE clause manipulation
        ]

        for pattern in injection_patterns:
            if re.search(pattern, query, re.IGNORECASE):
                validation_result['security_issues'].append('Potential SQL injection pattern detected')

        # Length validation
        if len(query) > 10000:
            validation_result['is_valid'] = False
            validation_result['errors'].append('Query too long (>10000 characters)')

        return validation_result

    def _validate_database_credentials(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Validate database credentials for security compliance."""
        if not isinstance(credentials, dict):
            return {'is_valid': False, 'errors': ['Credentials must be a dictionary']}

        validation_result = {
            'is_valid': True,
            'sanitized_credentials': credentials.copy(),
            'errors': [],
            'security_issues': []
        }

        # Check for required fields
        required_fields = ['username']
        for field in required_fields:
            if field not in credentials:
                validation_result['errors'].append(f'Missing required credential field: {field}')

        # Validate username
        username = credentials.get('username', '')
        if not isinstance(username, str) or len(username) < 1:
            validation_result['is_valid'] = False
            validation_result['errors'].append('Username must be a non-empty string')

        # Block dangerous usernames
        dangerous_usernames = {'root', 'admin', 'administrator', 'sa', 'postgres', 'mysql'}
        if username.lower() in dangerous_usernames:
            validation_result['security_issues'].append(f'High-privilege username detected: {username}')

        # Validate password if present
        password = credentials.get('password', '')
        if password:
            if len(password) < 8:
                validation_result['security_issues'].append('Password too short (recommended: 8+ characters)')

            # Remove password from sanitized output for security
            validation_result['sanitized_credentials']['password'] = '[REDACTED]'

        # Validate host
        host = credentials.get('host', '')
        if host:
            # Block localhost variations for production
            localhost_patterns = ['localhost', '127.0.0.1', '::1', '0.0.0.0']
            if host in localhost_patterns:
                validation_result['security_issues'].append('Localhost connection detected - ensure appropriate for environment')

        return validation_result

    def _validate_database_table_name(self, table_name: str) -> str:
        """Validate and sanitize database table name."""
        if not isinstance(table_name, str):
            logger.error(f"Invalid table name type: {type(table_name)}")
            return 'plugins'

        # Only allow alphanumeric, underscore, and basic characters
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]{0,62}$', table_name):
            logger.error(f"Invalid table name format: {table_name}")
            return 'plugins'

        # Block SQL reserved words
        sql_reserved_words = {
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'table', 'database', 'index', 'view', 'trigger', 'procedure',
            'function', 'grant', 'revoke', 'commit', 'rollback', 'union',
            'where', 'order', 'group', 'having', 'join', 'from', 'into'
        }

        if table_name.lower() in sql_reserved_words:
            logger.error(f"Table name conflicts with SQL reserved word: {table_name}")
            return 'plugins'

        return table_name

    def _validate_database_column_name(self, column_name: str) -> str:
        """Validate and sanitize database column name."""
        if not isinstance(column_name, str):
            logger.error(f"Invalid column name type: {type(column_name)}")
            return 'data'

        # Only allow alphanumeric and underscore
        if not re.match(r'^[a-zA-Z][a-zA-Z0-9_]{0,62}$', column_name):
            logger.error(f"Invalid column name format: {column_name}")
            return 'data'

        # Block SQL reserved words (same list as tables)
        sql_reserved_words = {
            'select', 'insert', 'update', 'delete', 'drop', 'create', 'alter',
            'table', 'database', 'index', 'view', 'trigger', 'procedure',
            'function', 'grant', 'revoke', 'commit', 'rollback', 'union',
            'where', 'order', 'group', 'having', 'join', 'from', 'into'
        }

        if column_name.lower() in sql_reserved_words:
            logger.error(f"Column name conflicts with SQL reserved word: {column_name}")
            return 'data'

        return column_name

    def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Validate and sanitize input using database-specific validation."""
        if context == 'database_query':
            if isinstance(data, str):
                return self._validate_database_query(data)
            else:
                return {'is_valid': False, 'errors': ['Database query must be a string']}

        elif context == 'database_connection':
            if isinstance(data, str):
                return self._validate_database_connection_string(data)
            else:
                return {'is_valid': False, 'errors': ['Connection string must be a string']}

        elif context == 'database_credentials':
            if isinstance(data, dict):
                return self._validate_database_credentials(data)
            else:
                return {'is_valid': False, 'errors': ['Credentials must be a dictionary']}

        elif context == 'table_name':
            if isinstance(data, str):
                sanitized = self._validate_database_table_name(data)
                return {'is_valid': True, 'sanitized_value': sanitized}
            else:
                return {'is_valid': False, 'errors': ['Table name must be a string']}

        elif context == 'column_name':
            if isinstance(data, str):
                sanitized = self._validate_database_column_name(data)
                return {'is_valid': True, 'sanitized_value': sanitized}
            else:
                return {'is_valid': False, 'errors': ['Column name must be a string']}

        # Default to general validation using Universal Input Sanitizer
        return self._validate_input(str(data), context)

    def initialize(self) -> bool:
        """Initialize database factory and load configured database plugins."""
        try:
            # Load primary database plugin
            success = self._load_database_plugin(self.primary_database)
            if not success:
                logger.error(f"Failed to load primary database: {self.primary_database}")
                return False
            
            # Load fallback database plugins
            for db_type in self.fallback_databases:
                self._load_database_plugin(db_type)
            
            # Set active database to primary
            self.active_database = self.primary_database
            
            # Verify active database is working
            if self.active_database not in self.database_plugins:
                logger.error("No working database plugins available")
                return False
            
            self.initialized = True
            logger.info(f"Database Factory initialized with {len(self.database_plugins)} database plugins")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Database Factory: {e}")
            return False
    
    def _load_database_plugin(self, db_type: str) -> bool:
        """Load a specific database plugin."""
        try:
            # Check if plugin path exists
            plugin_path = self.plugin_paths.get(db_type)
            if not plugin_path or not os.path.exists(plugin_path):
                logger.warning(f"Database plugin path not found: {db_type} at {plugin_path}")
                return False
            
            # Load plugin module
            plugin_module = self._import_plugin_module(db_type, plugin_path)
            if not plugin_module:
                return False
            
            # Get database plugin class based on type
            plugin_class = self._get_plugin_class(plugin_module, db_type)
            if not plugin_class:
                return False
            
            # Create plugin instance with configuration
            db_config = self.database_configs.get(db_type, {})
            plugin_instance = plugin_class(db_config)
            
            # Initialize the plugin
            init_success = plugin_instance.initialize()
            if not init_success:
                logger.error(f"Failed to initialize {db_type} database plugin")
                return False
            
            # Store plugin instance
            self.database_plugins[db_type] = plugin_instance
            logger.info(f"Successfully loaded {db_type} database plugin")
            return True
            
        except Exception as e:
            logger.error(f"Failed to load {db_type} database plugin: {e}")
            return False
    
    def _import_plugin_module(self, db_type: str, plugin_path: str):
        """Import database plugin module."""
        try:
            main_file = os.path.join(plugin_path, 'main.py')
            spec = importlib.util.spec_from_file_location(f"{db_type}_main", main_file)
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            return plugin_module
        except Exception as e:
            logger.error(f"Failed to import {db_type} plugin module: {e}")
            return None
    
    def _get_plugin_class(self, plugin_module, db_type: str):
        """Get the appropriate plugin class from module."""
        class_mapping = {
            'sqlite': 'SQLiteDatabasePlugin',
            'postgresql': 'PostgreSQLDatabasePlugin',
            'mongodb': 'MongoDBDatabasePlugin'
        }
        
        class_name = class_mapping.get(db_type)
        if not class_name or not hasattr(plugin_module, class_name):
            logger.error(f"Plugin class {class_name} not found in {db_type} module")
            return None
        
        return getattr(plugin_module, class_name)
    
    def _get_active_plugin(self):
        """Get the currently active database plugin with failover."""
        # Try active database first
        if self.active_database in self.database_plugins:
            plugin = self.database_plugins[self.active_database]
            # Quick health check
            try:
                health = plugin.health_check()
                if health.get('healthy', False):
                    return plugin
            except Exception as e:
                logger.warning(f"Active database {self.active_database} health check failed: {e}")
        
        # If primary is down and failover is enabled, try fallback databases
        if self.enable_failover:
            for db_type in self.fallback_databases:
                if db_type in self.database_plugins:
                    try:
                        plugin = self.database_plugins[db_type]
                        health = plugin.health_check()
                        if health.get('healthy', False):
                            logger.info(f"Switching to fallback database: {db_type}")
                            self.active_database = db_type
                            return plugin
                    except Exception as e:
                        logger.warning(f"Fallback database {db_type} health check failed: {e}")
        
        # No healthy database available
        logger.error("No healthy database plugins available")
        return None
    
    # Unified Database Interface Implementation
    
    def store_plugin(self, plugin_metadata: Dict[str, Any]) -> bool:
        """Store plugin metadata using active database."""
        plugin = self._get_active_plugin()
        if not plugin:
            return False
        
        try:
            return plugin.store_plugin(plugin_metadata)
        except Exception as e:
            logger.error(f"Failed to store plugin: {e}")
            return False
    
    def get_plugin(self, name: str, version: Optional[str] = None) -> Optional[Dict[str, Any]]:
        """Retrieve plugin metadata using active database."""
        plugin = self._get_active_plugin()
        if not plugin:
            return None
        
        try:
            return plugin.get_plugin(name, version)
        except Exception as e:
            logger.error(f"Failed to get plugin {name}: {e}")
            return None
    
    def search_plugins(self, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """Search plugins using active database."""
        plugin = self._get_active_plugin()
        if not plugin:
            return []
        
        try:
            return plugin.search_plugins(query, filters)
        except Exception as e:
            logger.error(f"Failed to search plugins: {e}")
            return []
    
    def list_plugins(self) -> List[Dict[str, Any]]:
        """List all plugins using active database."""
        plugin = self._get_active_plugin()
        if not plugin:
            return []
        
        try:
            return plugin.list_plugins()
        except Exception as e:
            logger.error(f"Failed to list plugins: {e}")
            return []
    
    def delete_plugin(self, name: str, version: Optional[str] = None) -> bool:
        """Delete plugin using active database."""
        plugin = self._get_active_plugin()
        if not plugin:
            return False
        
        try:
            return plugin.delete_plugin(name, version)
        except Exception as e:
            logger.error(f"Failed to delete plugin {name}: {e}")
            return False
    
    def health_check(self) -> Dict[str, Any]:
        """Comprehensive health check across all database plugins."""
        try:
            health_results = {
                'factory_id': self.factory_id,
                'factory_healthy': True,
                'active_database': self.active_database,
                'initialized': self.initialized,
                'total_databases': len(self.database_plugins),
                'healthy_databases': 0,
                'database_status': {},
                'failover_enabled': self.enable_failover,
                'kubernetes': {
                    'namespace': self.namespace
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
            
            # Check each database plugin
            for db_type, plugin in self.database_plugins.items():
                try:
                    db_health = plugin.health_check()
                    is_healthy = db_health.get('healthy', False)
                    
                    health_results['database_status'][db_type] = {
                        'healthy': is_healthy,
                        'plugin_count': db_health.get('plugin_count', 0),
                        'database_size_bytes': db_health.get('database_size_bytes', 0),
                        'is_active': (db_type == self.active_database)
                    }
                    
                    if is_healthy:
                        health_results['healthy_databases'] += 1
                        
                except Exception as e:
                    health_results['database_status'][db_type] = {
                        'healthy': False,
                        'error': str(e),
                        'is_active': (db_type == self.active_database)
                    }
            
            # Factory is healthy if at least one database is healthy
            health_results['factory_healthy'] = health_results['healthy_databases'] > 0
            
            return health_results
            
        except Exception as e:
            logger.error(f"Factory health check failed: {e}")
            return {
                'factory_id': self.factory_id,
                'factory_healthy': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
    
    # Factory Management Operations
    
    def switch_database(self, target_database: str) -> bool:
        """Switch active database to target database."""
        try:
            # Validate input
            if not isinstance(target_database, str):
                logger.error("Target database must be a string")
                return False

            validation_result = self._validate_input(target_database, 'target_database')
            if not validation_result['is_safe']:
                logger.error(f"Invalid target database rejected: {validation_result['threats_detected']}")
                return False

            target_database = validation_result['sanitized_input']

            if target_database not in self.database_plugins:
                logger.error(f"Target database {target_database} not available")
                return False
            
            # Health check target database
            plugin = self.database_plugins[target_database]
            health = plugin.health_check()
            
            if not health.get('healthy', False):
                logger.error(f"Target database {target_database} is not healthy")
                return False
            
            # Switch active database
            old_database = self.active_database
            self.active_database = target_database
            
            logger.info(f"Successfully switched database from {old_database} to {target_database}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to switch database to {target_database}: {e}")
            return False
    
    def add_database(self, db_type: str, config: Dict[str, Any]) -> bool:
        """Add a new database plugin to the factory."""
        try:
            # Update database configurations
            self.database_configs[db_type] = config
            
            # Load the new database plugin
            success = self._load_database_plugin(db_type)
            if success:
                logger.info(f"Successfully added {db_type} database to factory")
                
                # Add to fallback databases if not already there
                if db_type not in self.fallback_databases and db_type != self.primary_database:
                    self.fallback_databases.append(db_type)
                
            return success
            
        except Exception as e:
            logger.error(f"Failed to add {db_type} database: {e}")
            return False
    
    def remove_database(self, db_type: str) -> bool:
        """Remove a database plugin from the factory."""
        try:
            if db_type == self.active_database:
                logger.error(f"Cannot remove active database {db_type}")
                return False
            
            if db_type in self.database_plugins:
                del self.database_plugins[db_type]
                logger.info(f"Removed {db_type} database from factory")
            
            # Remove from fallback databases
            if db_type in self.fallback_databases:
                self.fallback_databases.remove(db_type)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to remove {db_type} database: {e}")
            return False
    
    def get_factory_status(self) -> Dict[str, Any]:
        """Get comprehensive factory status."""
        return {
            'factory_id': self.factory_id,
            'initialized': self.initialized,
            'primary_database': self.primary_database,
            'active_database': self.active_database,
            'available_databases': list(self.database_plugins.keys()),
            'fallback_databases': self.fallback_databases,
            'failover_enabled': self.enable_failover,
            'total_databases': len(self.database_plugins),
            'kubernetes_namespace': self.namespace
        }


def _handle_operation_sync(plugin_ctx: Dict[str, Any], user_ctx: Dict[str, Any], operation: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Sync version of operation handling to avoid async bypass.

    Args:
        plugin_ctx: Plugin context
        user_ctx: User configuration with operation specified
        operation: The operation to perform
        cfg: Configuration dictionary

    Returns:
        dict: Operation result
    """
    start_time = time.time()
    logger = plugin_ctx.get('logger') if plugin_ctx and plugin_ctx.get('logger') else logging.getLogger(__name__)

    try:
        # Create and initialize factory
        factory_plugin = DatabaseFactoryPlugin(cfg)
        init_success = factory_plugin.initialize()

        if not init_success:
            return {
                'success': False,
                'error': 'Factory initialization failed',
                'processing_time_ms': (time.time() - start_time) * 1000
            }

        if operation == 'health_check':
            # Convert async to sync by calling the sync method
            health_status = _sync_health_check(factory_plugin)
            return {
                'success': True,
                'operation_completed': 'health_check',
                'health_status': health_status,
                'processing_time_ms': (time.time() - start_time) * 1000
            }
        elif operation == 'switch_database':
            target_db = cfg.get('target_database')
            # Convert async to sync
            result = _sync_switch_database(factory_plugin, target_db)
            return {
                'success': result,
                'operation_completed': 'switch_database',
                'result': result,
                'active_database': factory_plugin.active_database,
                'processing_time_ms': (time.time() - start_time) * 1000
            }
        elif operation == 'get_status':
            status = factory_plugin.get_factory_status()
            return {
                'success': True,
                'operation_completed': 'get_status',
                'factory_status': status,
                'processing_time_ms': (time.time() - start_time) * 1000
            }
        else:
            return {
                'success': False,
                'error': f'Unsupported operation: {operation}',
                'processing_time_ms': (time.time() - start_time) * 1000
            }

    except Exception as e:
        logger.error(f"Database Factory operation failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation_completed': operation,
            'processing_time_ms': (time.time() - start_time) * 1000
        }


def _sync_health_check(factory_plugin) -> Dict[str, Any]:
    """Sync wrapper for health check operation."""
    try:
        # Call the sync version of health check methods
        health_results = {
            'factory_id': factory_plugin.factory_id,
            'factory_healthy': True,
            'active_database': factory_plugin.active_database,
            'initialized': factory_plugin.initialized,
            'total_databases': len(factory_plugin.database_plugins),
            'healthy_databases': 0,
            'database_status': {},
            'failover_enabled': factory_plugin.enable_failover,
            'kubernetes': {
                'namespace': factory_plugin.namespace
            },
            'timestamp': datetime.now(timezone.utc).isoformat()
        }

        # Check each database plugin with sync calls
        for db_type, plugin in factory_plugin.database_plugins.items():
            try:
                # Use sync health check if available
                if hasattr(plugin, 'health_check'):
                    db_health = plugin.health_check()
                    is_healthy = db_health.get('healthy', False)

                    health_results['database_status'][db_type] = {
                        'healthy': is_healthy,
                        'plugin_count': db_health.get('plugin_count', 0),
                        'database_size_bytes': db_health.get('database_size_bytes', 0),
                        'is_active': (db_type == factory_plugin.active_database)
                    }

                    if is_healthy:
                        health_results['healthy_databases'] += 1
                else:
                    health_results['database_status'][db_type] = {
                        'healthy': False,
                        'error': 'No health_check method available',
                        'is_active': (db_type == factory_plugin.active_database)
                    }

            except Exception as e:
                health_results['database_status'][db_type] = {
                    'healthy': False,
                    'error': str(e),
                    'is_active': (db_type == factory_plugin.active_database)
                }

        # Factory is healthy if at least one database is healthy
        health_results['factory_healthy'] = health_results['healthy_databases'] > 0

        return health_results

    except Exception as e:
        logger.error(f"Factory health check failed: {e}")
        return {
            'factory_id': factory_plugin.factory_id,
            'factory_healthy': False,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


def _sync_switch_database(factory_plugin, target_database: str) -> bool:
    """Sync wrapper for database switching operation."""
    try:
        # Validate input
        if not isinstance(target_database, str):
            logger.error("Target database must be a string")
            return False

        if target_database not in factory_plugin.database_plugins:
            logger.error(f"Target database {target_database} not available")
            return False

        # Health check target database
        plugin = factory_plugin.database_plugins[target_database]
        if hasattr(plugin, 'health_check'):
            health = plugin.health_check()

            if not health.get('healthy', False):
                logger.error(f"Target database {target_database} is not healthy")
                return False

        # Switch active database
        old_database = factory_plugin.active_database
        factory_plugin.active_database = target_database

        logger.info(f"Successfully switched database from {old_database} to {target_database}")
        return True

    except Exception as e:
        logger.error(f"Failed to switch database to {target_database}: {e}")
        return False


# Plugin entry point
def process(plugin_ctx: Dict[str, Any], user_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    PlugPipe plugin entry point for Database Factory.

    Args:
        plugin_ctx: Plugin context with logger, metrics, etc.
        user_ctx: User configuration and operation parameters

    Returns:
        dict: Plugin response with factory instance and capabilities
    """
    start_time = datetime.now(timezone.utc)

    try:
        # Validate input contexts first before accessing them
        if not isinstance(plugin_ctx, dict):
            return {'success': False, 'error': 'Invalid plugin_ctx: must be dictionary'}

        if not isinstance(user_ctx, dict):
            return {'success': False, 'error': 'Invalid user_ctx: must be dictionary'}

        # Now safe to access plugin_ctx
        logger = plugin_ctx.get('logger') if plugin_ctx and plugin_ctx.get('logger') else logging.getLogger(__name__)

        # Get operation and configuration
        operation = user_ctx.get('operation')
        cfg = user_ctx.get('config', {})

        # Validate operation if specified
        if operation and not isinstance(operation, str):
            return {'success': False, 'error': 'Operation must be a string'}

        valid_operations = [
            'health_check', 'switch_database', 'get_status',
            'store_plugin', 'get_plugin', 'search_plugins',
            'list_plugins', 'delete_plugin'
        ]

        if operation and operation not in valid_operations:
            return {
                'success': False,
                'error': f'Invalid operation: {operation}',
                
                'available_operations': valid_operations
            }

        # Handle specific operations
        if operation:
            # Use sync version instead of calling async directly
            return _handle_operation_sync(plugin_ctx, user_ctx, operation, cfg)

        # Create Database Factory Plugin
        try:
            factory_plugin = DatabaseFactoryPlugin(cfg)
        except Exception as e:
            return {
                'success': False,
                'error': f'Factory configuration validation failed: {e}',
                
                'factory': None,
                'capabilities': [],
                'status': 'failed'
            }

        # Initialize factory
        initialization_success = factory_plugin.initialize()

        if not initialization_success:
            return {
                'success': False,
                'error': 'Database Factory initialization failed',
                'factory': None,
                'capabilities': [],
                'status': 'failed'
            }

        return {
            'success': True,
            'factory': factory_plugin,
            'capabilities': [
                'unified_database_interface',
                'database_switching',
                'database_failover',
                'multi_database_support',
                'health_monitoring',
                'factory_management'
            ],
            'factory_type': 'database',
            'factory_id': factory_plugin.factory_id,
            'status': 'ready',
            'active_database': factory_plugin.active_database,
            'kubernetes_native': True,
            'message': 'Database Factory Plugin initialized successfully',
            'execution_time': (datetime.now(timezone.utc) - start_time).total_seconds()
        }

    except Exception as e:
        error_msg = f"Database Factory Plugin initialization failed: {e}"
        if logger:
            logger.error(error_msg)

        return {
            'success': False,
            'error': str(e),
            'factory': None,
            'capabilities': [],
            'status': 'failed',
            'execution_time': (datetime.now(timezone.utc) - start_time).total_seconds()
        }


async def process_async(plugin_ctx: Dict[str, Any], user_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Async version of process function for specific factory operations.

    Args:
        plugin_ctx: Plugin context
        user_ctx: User configuration with operation specified

    Returns:
        dict: Operation result
    """
    start_time = datetime.now(timezone.utc)
    logger = plugin_ctx.get('logger') if plugin_ctx and plugin_ctx.get('logger') else logging.getLogger(__name__)

    try:
        # Get configuration and operation
        cfg = user_ctx.get('config', {})
        operation = user_ctx.get('operation')

        # Create and initialize factory
        factory_plugin = DatabaseFactoryPlugin(cfg)
        factory_plugin.initialize()
        
        if operation == 'health_check':
            health_status = factory_plugin.health_check()
            return {
                'success': True,
                'operation_completed': 'health_check',
                'health_status': health_status
            }
        elif operation == 'switch_database':
            target_db = cfg.get('target_database')
            result = factory_plugin.switch_database(target_db)
            return {
                'success': result,
                'operation_completed': 'switch_database',
                'result': result,
                'active_database': factory_plugin.active_database
            }
        elif operation == 'get_status':
            status = factory_plugin.get_factory_status()
            return {
                'success': True,
                'operation_completed': 'get_status',
                'factory_status': status
            }
        elif operation in ['store_plugin', 'get_plugin', 'search_plugins', 'list_plugins', 'delete_plugin']:
            # Delegate to unified database interface
            if operation == 'store_plugin':
                plugin_metadata = cfg.get('plugin_metadata', {})
                result = factory_plugin.store_plugin(plugin_metadata)
            elif operation == 'get_plugin':
                name = cfg.get('name')
                version = cfg.get('version')
                result = factory_plugin.get_plugin(name, version)
            elif operation == 'search_plugins':
                query = cfg.get('query', '')
                filters = cfg.get('filters', {})
                result = factory_plugin.search_plugins(query, filters)
            elif operation == 'list_plugins':
                result = factory_plugin.list_plugins()
            elif operation == 'delete_plugin':
                name = cfg.get('name')
                version = cfg.get('version')
                result = factory_plugin.delete_plugin(name, version)
            
            return {
                'success': True,
                'operation_completed': operation,
                'result': result,
                'execution_time': (datetime.now(timezone.utc) - start_time).total_seconds()
            }
        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                
                'operation_completed': operation,
                'execution_time': (datetime.now(timezone.utc) - start_time).total_seconds()
            }

    except Exception as e:
        logger.error(f"Database Factory operation failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation_completed': operation if 'operation' in locals() else 'unknown',
            'execution_time': (datetime.now(timezone.utc) - start_time).total_seconds()
        }


# Plugin metadata for discovery
plug_metadata = {
    "name": "Database Factory Plugin",
    "version": "1.0.0",
    "description": "Orchestrates multiple database plugins and provides unified database interface",
    "author": "PlugPipe Core Team",
    "category": "database",
    "type": "factory",
    "capabilities": [
        "unified_database_interface",
        "database_switching", 
        "database_failover",
        "multi_database_support",
        "health_monitoring",
        "factory_management"
    ],
    "supported_databases": ["sqlite", "postgresql", "mongodb"],
    "kubernetes_native": True,
    "production_ready": True,
    "enterprise_ready": True
}


if __name__ == "__main__":
    # Direct execution for testing
    import sys
    config = {
        'database_factory': {
            'primary_database': 'sqlite',
            'fallback_databases': [],
            'enable_failover': True,
            'namespace': 'plugpipe'
        },
        'databases': {
            'sqlite': {
                'database': {
                    'file_path': './test_factory.db'
                }
            }
        }
    }
    
    # Test factory initialization
    result = process({}, config)
    print(json.dumps(result, indent=2, default=str))