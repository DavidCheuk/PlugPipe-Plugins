#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enhanced Error Database Logger Plugin

Provides database logging capabilities for the enhanced error messaging system,
extending beyond pipe_runs to persistent database storage with rich querying
and analytics capabilities.

Features:
- Database logging for enhanced error messages
- Error pattern analytics and trending
- Searchable error history
- Performance metrics storage
- Integration with existing debugging system
- Multi-database support (SQLite, PostgreSQL, MySQL)
"""

import sqlite3
import time
import json
import os
import logging
import asyncio
import re
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from pathlib import Path
import hashlib

# Import PlugPipe components
import sys
from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
from shares.loader import pp

logger = logging.getLogger(__name__)

@dataclass
class ErrorLogEntry:
    """Structured error log entry for database storage."""
    error_id: str
    timestamp: str
    severity: str
    step_id: str
    pipeline_name: str
    execution_id: str
    error_type: str
    error_message: str
    user_friendly_message: str
    stack_trace: str
    suggested_actions: List[str]
    related_plugs: List[str]
    technical_details: Dict[str, Any]
    environment_info: Dict[str, Any]
    context: Dict[str, Any]

class EnhancedErrorDatabaseLogger:
    """Database logger for enhanced error messages with analytics capabilities."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)

        # Load Universal Input Sanitizer
        self.sanitizer_plugin = self._load_universal_sanitizer()

        # Validate configuration
        validated_config = self._validate_configuration(config)
        if not validated_config['is_safe']:
            raise ValueError(f"Configuration validation failed: {validated_config['threats_detected']}")

        # Database configuration with security validation
        db_config = config.get('database', {})
        self.db_type = self._validate_input(db_config.get('type', 'sqlite'), 'db_type')['sanitized_input']
        self.db_path = self._validate_path(db_config.get('path', 'enhanced_errors.db'))
        self.db_host = self._validate_input(db_config.get('host', 'localhost'), 'hostname')['sanitized_input']
        self.db_port = int(db_config.get('port', 5432))
        self.db_name = self._validate_input(db_config.get('database', 'plugpipe_errors'), 'db_name')['sanitized_input']
        self.db_user = self._validate_input(db_config.get('user', 'postgres'), 'username')['sanitized_input']
        self.db_password = db_config.get('password', '')  # Keep password as-is

        # Initialize database
        self._initialize_database()

    def _load_universal_sanitizer(self):
        """Load Universal Input Sanitizer plugin using pp() discovery."""
        try:
            sanitizer_plugin = pp('universal_input_sanitizer')
            if sanitizer_plugin:
                logger.info("✅ Universal Input Sanitizer plugin loaded")
                return sanitizer_plugin
        except Exception as e:
            logger.warning(f"⚠️ Universal Input Sanitizer not available: {e}")
        return None

    def _validate_input(self, input_value: Any, context: str = 'general') -> Dict[str, Any]:
        """Validate and sanitize input using Universal Input Sanitizer."""
        if self.sanitizer_plugin:
            try:
                # Use Universal Input Sanitizer
                sanitizer_config = {
                    'input_data': input_value,
                    'context': context,
                    'security_level': 'high'
                }

                result = self.sanitizer_plugin.process({}, sanitizer_config)
                if result.get('success'):
                    # Extract safety assessment from overall_assessment if available
                    overall_assessment = result.get('overall_assessment', {})
                    is_safe = overall_assessment.get('is_safe', result.get('is_safe', False))

                    return {
                        'is_safe': is_safe,
                        'sanitized_input': result.get('sanitized_input', input_value),
                        'threats_detected': result.get('threats_detected', [])
                    , 'processing_time_ms': (time.time() - start_time) * 1000}
            except Exception as e:
                logger.warning(f"Universal Input Sanitizer error: {e}")

        # Fallback validation
        return self._fallback_validation(input_value, context)

    def _fallback_validation(self, input_value: Any, context: str = 'general') -> Dict[str, Any]:
        """Fallback validation when Universal Input Sanitizer is not available."""
        try:
            if input_value is None:
                return {'is_safe': True, 'sanitized_input': '', 'threats_detected': [], 'processing_time_ms': (time.time() - start_time) * 1000}

            input_str = str(input_value)
            threats = []

            # SQL injection patterns
            sql_patterns = [
                r'(\b(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC|EXECUTE)\b)',
                r'(;|\|\||&&)',
                r'(\bUNION\b.*\bSELECT\b)',
                r'(\'.*\'.*OR.*\'.*\')',
                r'(\b(OR|AND)\b.*=.*)'
            ]

            for pattern in sql_patterns:
                if re.search(pattern, input_str, re.IGNORECASE):
                    threats.append('sql_injection')
                    break

            # Path traversal patterns
            path_patterns = [r'\.\./', r'\.\.\x5c', r'%2e%2e%2f', r'%2e%2e%5c']
            for pattern in path_patterns:
                if re.search(pattern, input_str, re.IGNORECASE):
                    threats.append('path_traversal')
                    break

            # Command injection patterns
            cmd_patterns = [r'[;&|`$]', r'\$\(', r'`.*`']
            for pattern in cmd_patterns:
                if re.search(pattern, input_str):
                    threats.append('command_injection')
                    break

            # Clean input based on context
            if context == 'db_type':
                allowed_types = ['sqlite', 'postgresql', 'mysql']
                sanitized = input_str.lower() if input_str.lower() in allowed_types else 'sqlite'
            elif context in ['hostname', 'db_name', 'username']:
                # Remove special characters, keep alphanumeric, dots, underscores, hyphens
                sanitized = re.sub(r'[^a-zA-Z0-9._-]', '', input_str)
            else:
                # General sanitization
                sanitized = re.sub(r'[<>\'";\\&|`$]', '', input_str)

            is_safe = len(threats) == 0 and len(sanitized) > 0

            return {
                'is_safe': is_safe,
                'sanitized_input': sanitized,
                'threats_detected': threats
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        except Exception as e:
            logger.error(f"Fallback validation error: {e}")
            return {
                'is_safe': False,
                'sanitized_input': '',
                'threats_detected': ['validation_error']
            , 'processing_time_ms': (time.time() - start_time) * 1000}

    def _validate_query_filters(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize query filters to prevent injection attacks."""
        sanitized = {}

        for key, value in filters.items():
            if key in ['execution_id', 'step_id', 'severity', 'pipeline_name']:
                # Additional strict filtering for SQL injection patterns
                str_value = str(value)
                dangerous_patterns = [
                    '; DELETE', '; DROP', '; INSERT', '; UPDATE', '; EXEC', '; EXECUTE',
                    '--', '/*', '*/',
                    "' OR '", "' AND '", "' UNION",
                    '" OR "', '" AND "', '" UNION',
                    'OR 1=1', 'AND 1=1', 'UNION SELECT', '../'
                ]

                # Check for dangerous patterns (case insensitive)
                is_dangerous = any(pattern.lower() in str_value.lower() for pattern in dangerous_patterns)

                if not is_dangerous:
                    # Use Universal Input Sanitizer validation
                    validation_result = self._validate_input(str_value, 'filter_value')
                    if validation_result['is_safe']:
                        sanitized[key] = validation_result['sanitized_input']
                # If dangerous, simply omit the filter

            elif key == 'since':
                # Validate timestamp format strictly
                if isinstance(value, str) and re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', value):
                    sanitized[key] = value

            elif key == 'limit':
                # Validate and clamp limit
                try:
                    limit = int(value)
                    # Clamp to reasonable range
                    sanitized[key] = max(1, min(limit, 1000))
                except (ValueError, TypeError):
                    sanitized[key] = 100

        return sanitized

    def _validate_configuration(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate configuration for security compliance."""
        try:
            # First check if config is a dictionary
            if not isinstance(config, dict):
                return {
                    'is_safe': False,
                    'sanitized_input': {},
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'threats_detected': ['invalid_config_type']
                }

            # Skip string validation for configuration objects - they can contain complex data
            # Instead do basic security checks
            config_str = str(config)
            threats = []

            # Check for obvious security threats in config
            dangerous_patterns = [
                'DROP TABLE', 'DELETE FROM', 'INSERT INTO',
                '<script>', 'javascript:', '../../',
                'rm -rf', 'eval(', 'exec('
            ]

            for pattern in dangerous_patterns:
                if pattern.lower() in config_str.lower():
                    threats.append(f'dangerous_pattern_{pattern.lower().replace(" ", "_")}')

            # For configurations, we're more lenient unless there are obvious threats
            is_safe = len(threats) == 0

            return {
                'is_safe': is_safe,
                'sanitized_input': config,
                'threats_detected': threats
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        except Exception as e:
            logger.error(f"Configuration validation error: {e}")
            return {
                'is_safe': False,
                'sanitized_input': {},
                'processing_time_ms': (time.time() - start_time) * 1000,
                'threats_detected': ['validation_error']
            }

    def _validate_path(self, path: str) -> str:
        """Validate and sanitize file paths."""
        try:
            # Basic path validation for obvious threats
            if not isinstance(path, str) or not path:
                return 'enhanced_errors.db'

            # Check for path traversal attempts
            if '..' in path or path.startswith('/etc/') or path.startswith('/usr/') or path.startswith('/bin/'):
                logger.warning(f"Suspicious path detected: {path}")
                return 'enhanced_errors.db'

            # Resolve path
            resolved_path = os.path.abspath(path)

            # Ensure path doesn't escape expected directories
            allowed_dirs = [
                '/tmp',
                '/var/tmp',
                os.getcwd(),
                get_plugpipe_path("data"),
                get_plugpipe_path("logs")
            ]

            is_allowed = False
            for allowed_dir in allowed_dirs:
                try:
                    if resolved_path.startswith(os.path.abspath(allowed_dir)):
                        is_allowed = True
                        break
                except Exception:
                    continue

            if not is_allowed:
                logger.warning(f"Path {resolved_path} not in allowed directories")
                return 'enhanced_errors.db'

            return resolved_path

        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return 'enhanced_errors.db'

    def _validate_error_data(self, error_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate error data for security and format compliance."""
        try:
            if not isinstance(error_data, dict):
                return {
                    'is_safe': False,
                    'sanitized_data': {},
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'threats_detected': ['invalid_data_type']
                }

            sanitized_data = {}
            threats = []

            # Validate and sanitize each field
            for field, value in error_data.items():
                field_validation = self._validate_input(field, 'field_name')

                if not field_validation['is_safe']:
                    threats.extend(field_validation['threats_detected'])
                    continue

                # Apply strict filtering for SQL injection patterns in values
                str_value = str(value)

                # More precise SQL injection detection patterns
                dangerous_patterns = [
                    '; DELETE', '; DROP', '; INSERT', '; UPDATE', '; EXEC', '; EXECUTE',
                    '--', '/*', '*/',
                    "' OR '", "' AND '", "' UNION",
                    '" OR "', '" AND "', '" UNION',
                    'OR 1=1', 'AND 1=1', 'UNION SELECT'
                ]

                # Check for dangerous patterns (case insensitive) with more context
                is_dangerous = any(pattern.lower() in str_value.lower() for pattern in dangerous_patterns)

                if is_dangerous:
                    # Skip dangerous values entirely
                    threats.append('sql_injection_attempt')
                    continue

                value_validation = self._validate_input(str_value, 'error_data')

                if not value_validation['is_safe']:
                    threats.extend(value_validation['threats_detected'])
                    continue

                sanitized_data[field_validation['sanitized_input']] = value_validation['sanitized_input']

            return {
                'is_safe': len(threats) == 0,
                'sanitized_data': sanitized_data,
                'threats_detected': threats
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        except Exception as e:
            logger.error(f"Error data validation failed: {e}")
            return {
                'is_safe': False,
                'sanitized_data': {},
                'processing_time_ms': (time.time() - start_time) * 1000,
                'threats_detected': ['validation_error']
            }

    def _validate_filters(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Validate query filters for security compliance."""
        try:
            if not isinstance(filters, dict):
                return {
                    'is_safe': False,
                    'sanitized_filters': {},
                'processing_time_ms': (time.time() - start_time) * 1000,
                    'threats_detected': ['invalid_filter_type']
                }

            sanitized_filters = {}
            threats = []

            # Allowed filter fields
            allowed_fields = [
                'execution_id', 'step_id', 'severity', 'since', 'limit',
                'pipeline_name', 'error_type'
            ]

            for field, value in filters.items():
                if field not in allowed_fields:
                    threats.append(f'invalid_filter_field_{field}')
                    continue

                field_validation = self._validate_input(str(value), f'filter_{field}')
                if not field_validation['is_safe']:
                    threats.extend(field_validation['threats_detected'])
                    continue

                sanitized_filters[field] = field_validation['sanitized_input']

            return {
                'is_safe': len(threats) == 0,
                'sanitized_filters': sanitized_filters,
                'threats_detected': threats
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        except Exception as e:
            logger.error(f"Filter validation failed: {e}")
            return {
                'is_safe': False,
                'sanitized_filters': {},
                'processing_time_ms': (time.time() - start_time) * 1000,
                'threats_detected': ['validation_error']
            }

    def _validate_metrics_data(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Validate metrics data for security compliance."""
        try:
            if not isinstance(metrics_data, dict):
                return {
                    'is_safe': False,
                    'sanitized_data': {},
                'processing_time_ms': (time.time() - start_time) * 1000,
                    'threats_detected': ['invalid_metrics_type']
                }

            sanitized_data = {}
            threats = []

            # Validate and sanitize each field
            for field, value in metrics_data.items():
                field_validation = self._validate_input(field, 'field_name')
                value_validation = self._validate_input(str(value), 'metrics_data')

                if not field_validation['is_safe']:
                    threats.extend(field_validation['threats_detected'])
                    continue

                if not value_validation['is_safe']:
                    threats.extend(value_validation['threats_detected'])
                    continue

                sanitized_data[field_validation['sanitized_input']] = value_validation['sanitized_input']

            return {
                'is_safe': len(threats) == 0,
                'sanitized_data': sanitized_data,
                'threats_detected': threats
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        except Exception as e:
            logger.error(f"Metrics data validation failed: {e}")
            return {
                'is_safe': False,
                'sanitized_data': {},
                'processing_time_ms': (time.time() - start_time) * 1000,
                'threats_detected': ['validation_error']
            }

    # Async wrapper methods
    async def _async_log_enhanced_error(self, error_data: Dict[str, Any]) -> Dict[str, Any]:
        """Async wrapper for log_enhanced_error."""
        return self.log_enhanced_error(error_data)

    async def _async_query_errors(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Async wrapper for query_errors."""
        return self.query_errors(filters)

    async def _async_log_execution_metrics(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Async wrapper for log_execution_metrics."""
        return self.log_execution_metrics(metrics_data)

    async def _async_get_performance_analytics(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Async wrapper for get_performance_analytics."""
        return self.get_performance_analytics(filters)

    async def _async_health_check(self) -> Dict[str, Any]:
        """Async wrapper for health_check."""
        return self._health_check()

    def _initialize_database(self):
        """Initialize the database and create necessary tables."""
        if self.db_type == 'sqlite':
            self._initialize_sqlite()
        elif self.db_type == 'postgresql':
            self._initialize_postgresql()
        else:
            raise ValueError(f"Unsupported database type: {self.db_type}")
    
    def _initialize_sqlite(self):
        """Initialize SQLite database for error logging."""
        try:
            # Ensure directory exists
            db_dir = Path(self.db_path).parent
            db_dir.mkdir(parents=True, exist_ok=True)
            
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS enhanced_errors (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        error_id TEXT UNIQUE NOT NULL,
                        timestamp TEXT NOT NULL,
                        severity TEXT NOT NULL,
                        step_id TEXT NOT NULL,
                        pipeline_name TEXT NOT NULL,
                        execution_id TEXT NOT NULL,
                        error_type TEXT NOT NULL,
                        error_message TEXT NOT NULL,
                        user_friendly_message TEXT,
                        stack_trace TEXT,
                        suggested_actions TEXT,  -- JSON array
                        related_plugs TEXT,     -- JSON array
                        technical_details TEXT, -- JSON object
                        environment_info TEXT,  -- JSON object
                        context TEXT,           -- JSON object
                        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS error_patterns (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        pattern_hash TEXT UNIQUE NOT NULL,
                        pattern_type TEXT NOT NULL,
                        error_pattern TEXT NOT NULL,
                        occurrence_count INTEGER DEFAULT 1,
                        first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
                        common_solutions TEXT,  -- JSON array
                        impact_score REAL DEFAULT 0.0
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS execution_metrics (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        execution_id TEXT NOT NULL,
                        pipeline_name TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        total_steps INTEGER,
                        successful_steps INTEGER,
                        failed_steps INTEGER,
                        execution_duration REAL,
                        success_rate REAL,
                        performance_grade TEXT,
                        bottlenecks TEXT,        -- JSON array
                        optimization_suggestions TEXT -- JSON array
                    )
                ''')
                
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS step_performance (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        execution_id TEXT NOT NULL,
                        step_id TEXT NOT NULL,
                        timestamp TEXT NOT NULL,
                        execution_time REAL,
                        status TEXT,
                        attempts INTEGER DEFAULT 1,
                        data_size INTEGER DEFAULT 0,
                        memory_usage REAL,
                        cpu_usage REAL
                    )
                ''')
                
                # Create indexes for better query performance
                conn.execute('CREATE INDEX IF NOT EXISTS idx_error_id ON enhanced_errors(error_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_execution_id ON enhanced_errors(execution_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_step_id ON enhanced_errors(step_id)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_timestamp ON enhanced_errors(timestamp)')
                conn.execute('CREATE INDEX IF NOT EXISTS idx_severity ON enhanced_errors(severity)')
                
                conn.commit()
                self.logger.info("SQLite database initialized successfully")
                
        except Exception as e:
            self.logger.error(f"Failed to initialize SQLite database: {e}")
            raise
    
    def _initialize_postgresql(self):
        """Initialize PostgreSQL database for error logging."""
        try:
            import psycopg2
            
            conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
            
            with conn.cursor() as cursor:
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS enhanced_errors (
                        id SERIAL PRIMARY KEY,
                        error_id VARCHAR(255) UNIQUE NOT NULL,
                        timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
                        severity VARCHAR(50) NOT NULL,
                        step_id VARCHAR(255) NOT NULL,
                        pipeline_name VARCHAR(255) NOT NULL,
                        execution_id VARCHAR(255) NOT NULL,
                        error_type VARCHAR(255) NOT NULL,
                        error_message TEXT NOT NULL,
                        user_friendly_message TEXT,
                        stack_trace TEXT,
                        suggested_actions JSONB,
                        related_plugs JSONB,
                        technical_details JSONB,
                        environment_info JSONB,
                        context JSONB,
                        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Additional PostgreSQL-specific optimizations
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_enhanced_errors_execution_id ON enhanced_errors(execution_id)')
                cursor.execute('CREATE INDEX IF NOT EXISTS idx_enhanced_errors_timestamp ON enhanced_errors(timestamp)')
                
            conn.commit()
            conn.close()
            self.logger.info("PostgreSQL database initialized successfully")
            
        except Exception as e:
            self.logger.error(f"Failed to initialize PostgreSQL database: {e}")
            raise
    
    def log_enhanced_error(self, error_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log enhanced error to database."""
        try:
            if self.db_type == 'sqlite':
                return self._log_to_sqlite(error_data)
            elif self.db_type == 'postgresql':
                return self._log_to_postgresql(error_data)
            else:
                return {'success': False, 'error': f'Unsupported database type: {self.db_type}', 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            self.logger.error(f"Failed to log enhanced error: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _log_to_sqlite(self, error_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log enhanced error to SQLite database."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                # Ensure required fields have defaults
                timestamp = error_data.get('timestamp')
                if not timestamp:
                    timestamp = datetime.now(timezone.utc).isoformat()

                conn.execute('''
                    INSERT OR REPLACE INTO enhanced_errors (
                        error_id, timestamp, severity, step_id, pipeline_name,
                        execution_id, error_type, error_message, user_friendly_message,
                        stack_trace, suggested_actions, related_plugs, technical_details,
                        environment_info, context
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    error_data.get('error_id', f'auto_{int(datetime.now().timestamp() * 1000)}'),
                    timestamp,
                    error_data.get('severity', 'medium'),
                    error_data.get('step_id', 'unknown'),
                    error_data.get('pipeline_name', 'unknown'),
                    error_data.get('execution_id', 'unknown'),
                    error_data.get('error_type', 'UnknownError'),
                    error_data.get('error_message', ''),
                    error_data.get('user_friendly_message', ''),
                    error_data.get('stack_trace', ''),
                    json.dumps(error_data.get('suggested_actions', [])),
                    json.dumps(error_data.get('related_plugs', [])),
                    json.dumps(error_data.get('technical_details', {})),
                    json.dumps(error_data.get('environment_info', {})),
                    json.dumps(error_data.get('context', {}))
                ))
                
                # Update error patterns for analytics
                self._update_error_patterns(conn, error_data)
                
                conn.commit()
                
                return {
                    'success': True,
                    'message': 'Enhanced error logged to database successfully',
                    'error_id': error_data.get('error_id'),
                    'database_type': 'sqlite'
                , 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            self.logger.error(f"SQLite logging failed: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _log_to_postgresql(self, error_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log enhanced error to PostgreSQL database."""
        try:
            import psycopg2
            import psycopg2.extras
            
            conn = psycopg2.connect(
                host=self.db_host,
                port=self.db_port,
                database=self.db_name,
                user=self.db_user,
                password=self.db_password
            )
            
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cursor:
                cursor.execute('''
                    INSERT INTO enhanced_errors (
                        error_id, timestamp, severity, step_id, pipeline_name,
                        execution_id, error_type, error_message, user_friendly_message,
                        stack_trace, suggested_actions, related_plugs, technical_details,
                        environment_info, context
                    ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                    ON CONFLICT (error_id) DO UPDATE SET
                        timestamp = EXCLUDED.timestamp,
                        severity = EXCLUDED.severity
                ''', (
                    error_data.get('error_id'),
                    error_data.get('timestamp'),
                    error_data.get('severity'),
                    error_data.get('step_id'),
                    error_data.get('pipeline_name', 'unknown'),
                    error_data.get('execution_id', 'unknown'),
                    error_data.get('error_type', 'UnknownError'),
                    error_data.get('error_message', ''),
                    error_data.get('user_friendly_message', ''),
                    error_data.get('stack_trace', ''),
                    json.dumps(error_data.get('suggested_actions', [])),
                    json.dumps(error_data.get('related_plugs', [])),
                    json.dumps(error_data.get('technical_details', {})),
                    json.dumps(error_data.get('environment_info', {})),
                    json.dumps(error_data.get('context', {}))
                ))
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'message': 'Enhanced error logged to PostgreSQL successfully',
                'error_id': error_data.get('error_id'),
                'database_type': 'postgresql'
            , 'processing_time_ms': (time.time() - start_time) * 1000}
            
        except Exception as e:
            self.logger.error(f"PostgreSQL logging failed: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _update_error_patterns(self, conn, error_data: Dict[str, Any]):
        """Update error patterns for analytics and trending."""
        try:
            error_pattern = f"{error_data.get('error_type', 'Unknown')}:{error_data.get('step_id', 'unknown')}"
            pattern_hash = hashlib.md5(error_pattern.encode()).hexdigest()
            
            # Check if pattern exists
            cursor = conn.execute(
                'SELECT occurrence_count FROM error_patterns WHERE pattern_hash = ?',
                (pattern_hash,)
            )
            result = cursor.fetchone()
            
            if result:
                # Update existing pattern
                conn.execute('''
                    UPDATE error_patterns 
                    SET occurrence_count = occurrence_count + 1,
                        last_seen = CURRENT_TIMESTAMP,
                        impact_score = (occurrence_count + 1) * ?
                    WHERE pattern_hash = ?
                ''', (self._calculate_severity_weight(error_data.get('severity', 'low')), pattern_hash))
            else:
                # Insert new pattern
                conn.execute('''
                    INSERT INTO error_patterns (
                        pattern_hash, pattern_type, error_pattern, occurrence_count,
                        first_seen, last_seen, common_solutions, impact_score
                    ) VALUES (?, ?, ?, 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP, ?, ?)
                ''', (
                    pattern_hash,
                    error_data.get('error_type', 'Unknown'),
                    error_pattern,
                    json.dumps(error_data.get('suggested_actions', [])),
                    self._calculate_severity_weight(error_data.get('severity', 'low'))
                ))
                
        except Exception as e:
            self.logger.warning(f"Failed to update error patterns: {e}")
    
    def _calculate_severity_weight(self, severity: str) -> float:
        """Calculate severity weight for impact scoring."""
        weights = {
            'critical': 5.0,
            'high': 3.0,
            'medium': 2.0,
            'low': 1.0,
            'trace': 0.5
        }
        return weights.get(severity.lower(), 1.0)
    
    def query_errors(self, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Query enhanced errors with filtering and analytics."""
        try:
            filters = filters or {}
            
            if self.db_type == 'sqlite':
                return self._query_sqlite_errors(filters)
            elif self.db_type == 'postgresql':
                return self._query_postgresql_errors(filters)
            else:
                return {'success': False, 'error': f'Unsupported database type: {self.db_type}', 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            self.logger.error(f"Failed to query errors: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _query_sqlite_errors(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Query SQLite database for enhanced errors."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # Validate and sanitize filters before use
                sanitized_filters = self._validate_query_filters(filters)

                # Build query based on sanitized filters
                where_clauses = []
                params = []

                if sanitized_filters.get('execution_id'):
                    where_clauses.append('execution_id = ?')
                    params.append(sanitized_filters['execution_id'])

                if sanitized_filters.get('step_id'):
                    where_clauses.append('step_id = ?')
                    params.append(sanitized_filters['step_id'])

                if sanitized_filters.get('severity'):
                    where_clauses.append('severity = ?')
                    params.append(sanitized_filters['severity'])
                
                if sanitized_filters.get('since'):
                    where_clauses.append('timestamp >= ?')
                    params.append(sanitized_filters['since'])

                where_clause = ' AND '.join(where_clauses) if where_clauses else '1=1'

                # Main query
                query = f'''
                    SELECT * FROM enhanced_errors
                    WHERE {where_clause}
                    ORDER BY timestamp DESC
                    LIMIT ?
                '''
                params.append(sanitized_filters.get('limit', 100))
                
                cursor = conn.execute(query, params)
                errors = [dict(row) for row in cursor.fetchall()]
                
                # Convert JSON fields back to objects
                for error in errors:
                    try:
                        error['suggested_actions'] = json.loads(error['suggested_actions'] or '[]')
                        error['related_plugs'] = json.loads(error['related_plugs'] or '[]')
                        error['technical_details'] = json.loads(error['technical_details'] or '{}')
                        error['environment_info'] = json.loads(error['environment_info'] or '{}')
                        error['context'] = json.loads(error['context'] or '{}')
                    except json.JSONDecodeError:
                        pass  # Keep as string if JSON parsing fails
                
                # Get analytics data
                analytics = self._get_error_analytics(conn, filters)
                
                return {
                    'success': True,
                    'errors': errors,
                    'total_count': len(errors),
                    'analytics': analytics,
                    'filters_applied': sanitized_filters
                , 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            self.logger.error(f"SQLite query failed: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _get_error_analytics(self, conn, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Get analytics data for errors."""
        try:
            analytics = {}
            
            # Error distribution by severity
            cursor = conn.execute('''
                SELECT severity, COUNT(*) as count 
                FROM enhanced_errors 
                GROUP BY severity
            ''')
            analytics['severity_distribution'] = dict(cursor.fetchall())
            
            # Top error patterns
            cursor = conn.execute('''
                SELECT error_pattern, occurrence_count, impact_score
                FROM error_patterns 
                ORDER BY impact_score DESC 
                LIMIT 10
            ''')
            analytics['top_error_patterns'] = [
                {
                    'pattern': row[0],
                    'occurrences': row[1],
                    'impact_score': row[2]
                }
                for row in cursor.fetchall()
            ]
            
            # Error trends (last 7 days)
            cursor = conn.execute('''
                SELECT DATE(timestamp) as date, COUNT(*) as count
                FROM enhanced_errors 
                WHERE timestamp >= datetime('now', '-7 days')
                GROUP BY DATE(timestamp)
                ORDER BY date
            ''')
            analytics['error_trends'] = [
                {'date': row[0], 'count': row[1]}
                for row in cursor.fetchall()
            ]
            
            return analytics
            
        except Exception as e:
            self.logger.warning(f"Failed to get error analytics: {e}")
            return {'error': 'Unknown', 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def log_execution_metrics(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log execution metrics for performance analysis."""
        try:
            if self.db_type == 'sqlite':
                return self._log_metrics_sqlite(metrics_data)
            else:
                return {'success': False, 'error': 'Metrics logging not implemented for this database type', 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            self.logger.error(f"Failed to log execution metrics: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _log_metrics_sqlite(self, metrics_data: Dict[str, Any]) -> Dict[str, Any]:
        """Log execution metrics to SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO execution_metrics (
                        execution_id, pipeline_name, timestamp, total_steps,
                        successful_steps, failed_steps, execution_duration,
                        success_rate, performance_grade, bottlenecks,
                        optimization_suggestions
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    metrics_data.get('execution_id'),
                    metrics_data.get('pipeline_name'),
                    metrics_data.get('timestamp'),
                    metrics_data.get('total_steps', 0),
                    metrics_data.get('successful_steps', 0),
                    metrics_data.get('failed_steps', 0),
                    metrics_data.get('execution_duration', 0.0),
                    metrics_data.get('success_rate', 0.0),
                    metrics_data.get('performance_grade', 'N/A'),
                    json.dumps(metrics_data.get('bottlenecks', [])),
                    json.dumps(metrics_data.get('optimization_suggestions', []))
                ))
                
                conn.commit()
                
                return {
                    'success': True,
                    'message': 'Execution metrics logged successfully'
                , 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def get_performance_analytics(self, filters: Dict[str, Any] = None) -> Dict[str, Any]:
        """Get performance analytics from logged metrics."""
        try:
            filters = filters or {}
            
            if self.db_type == 'sqlite':
                return self._get_performance_analytics_sqlite(filters)
            else:
                return {'success': False, 'error': 'Performance analytics not implemented for this database type', 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            self.logger.error(f"Failed to get performance analytics: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _get_performance_analytics_sqlite(self, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Get performance analytics from SQLite."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row
                
                # Performance trends
                cursor = conn.execute('''
                    SELECT 
                        DATE(timestamp) as date,
                        AVG(success_rate) as avg_success_rate,
                        AVG(execution_duration) as avg_duration,
                        COUNT(*) as executions
                    FROM execution_metrics
                    WHERE timestamp >= datetime('now', '-30 days')
                    GROUP BY DATE(timestamp)
                    ORDER BY date
                ''')
                
                performance_trends = [dict(row) for row in cursor.fetchall()]
                
                # Top performing pipelines
                cursor = conn.execute('''
                    SELECT 
                        pipeline_name,
                        AVG(success_rate) as avg_success_rate,
                        AVG(execution_duration) as avg_duration,
                        performance_grade,
                        COUNT(*) as executions
                    FROM execution_metrics
                    GROUP BY pipeline_name
                    ORDER BY avg_success_rate DESC, avg_duration ASC
                    LIMIT 10
                ''')
                
                top_pipelines = [dict(row) for row in cursor.fetchall()]
                
                return {
                    'success': True,
                    'performance_trends': performance_trends,
                    'top_pipelines': top_pipelines
                , 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}

    def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Main process function following PlugPipe contract."""
        try:
            # Validate input contexts
            if not isinstance(ctx, dict):
                return {'success': False, 'error': 'Invalid ctx: must be dictionary', 'processing_time_ms': (time.time() - start_time) * 1000}

            if not isinstance(cfg, dict):
                return {'success': False, 'error': 'Invalid cfg: must be dictionary', 'processing_time_ms': (time.time() - start_time) * 1000}

            # Get and validate action
            action = ctx.get('action', 'log_error')
            action_validation = self._validate_input(action, 'action')
            if not action_validation['is_safe']:
                return {
                    'success': False,
                    'error': f'Invalid action: {action_validation["threats_detected"]}',
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }

            action = action_validation['sanitized_input']

            # Process based on action
            if action == 'log_error':
                error_data = ctx.get('error_data', {})
                # Validate error data
                if error_data:
                    error_validation = self._validate_error_data(error_data)
                    if not error_validation['is_safe']:
                        return {
                            'success': False,
                            'error': f'Invalid error data: {error_validation["threats_detected"]}',
                            'processing_time_ms': (time.time() - start_time) * 1000,
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        }
                    error_data = error_validation['sanitized_data']

                return self._async_log_enhanced_error(error_data)

            elif action == 'query_errors':
                filters = ctx.get('filters', {})
                # Validate filters
                if filters:
                    filter_validation = self._validate_filters(filters)
                    if not filter_validation['is_safe']:
                        return {
                            'success': False,
                            'error': f'Invalid filters: {filter_validation["threats_detected"]}',
                            'processing_time_ms': (time.time() - start_time) * 1000,
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        }
                    filters = filter_validation['sanitized_filters']

                return self._async_query_errors(filters)

            elif action == 'log_metrics':
                metrics_data = ctx.get('metrics_data', {})
                # Validate metrics data
                if metrics_data:
                    metrics_validation = self._validate_metrics_data(metrics_data)
                    if not metrics_validation['is_safe']:
                        return {
                            'success': False,
                            'error': f'Invalid metrics data: {metrics_validation["threats_detected"]}',
                            'processing_time_ms': (time.time() - start_time) * 1000,
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        }
                    metrics_data = metrics_validation['sanitized_data']

                return self._async_log_execution_metrics(metrics_data)

            elif action == 'get_analytics':
                filters = ctx.get('filters', {})
                # Validate filters
                if filters:
                    filter_validation = self._validate_filters(filters)
                    if not filter_validation['is_safe']:
                        return {
                            'success': False,
                            'error': f'Invalid filters: {filter_validation["threats_detected"]}',
                            'processing_time_ms': (time.time() - start_time) * 1000,
                            'timestamp': datetime.now(timezone.utc).isoformat()
                        }
                    filters = filter_validation['sanitized_filters']

                return self._async_get_performance_analytics(filters)

            elif action == 'health_check':
                return self._async_health_check()

            else:
                return {
                    'success': False,
                    'error': f'Unknown action: {action}',
                    'processing_time_ms': (time.time() - start_time) * 1000,
                    'available_actions': [
                        'log_error', 'query_errors', 'log_metrics',
                        'get_analytics', 'health_check'
                    ],
                    'timestamp': datetime.now(timezone.utc).isoformat()
                }

        except Exception as e:
            logger.error(f"Enhanced Error Database Logger failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            , 'processing_time_ms': (time.time() - start_time) * 1000}
    
    def _health_check(self) -> Dict[str, Any]:
        """Perform health check on the database."""
        try:
            if self.db_type == 'sqlite':
                with sqlite3.connect(self.db_path, timeout=5.0) as conn:
                    cursor = conn.execute('SELECT COUNT(*) FROM enhanced_errors')
                    total_errors = cursor.fetchone()[0]
                    
                    cursor = conn.execute('SELECT COUNT(*) FROM error_patterns')
                    total_patterns = cursor.fetchone()[0]
                    
                    return {
                        'success': True,
                        'database_type': 'sqlite',
                        'database_path': self.db_path,
                        'total_errors': total_errors,
                        'total_patterns': total_patterns,
                        'status': 'healthy'
                    , 'processing_time_ms': (time.time() - start_time) * 1000}
            else:
                return {
                    'success': True,
                    'database_type': self.db_type,
                    'status': 'healthy'
                , 'processing_time_ms': (time.time() - start_time) * 1000}
                
        except Exception as e:
            return {
                'success': False,
                'error': str(e),
                'status': 'unhealthy'
            , 'processing_time_ms': (time.time() - start_time) * 1000}

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "enhanced_error_logger",
    "version": "1.0.0",
    "description": "Database logging for enhanced error messages with analytics and querying capabilities",
    "owner": "PlugPipe Core Team",
    "status": "production",
    "category": "database",
    "tags": ["database", "logging", "error-tracking", "analytics", "debugging"],
    "capabilities": [
        "database_error_logging",
        "error_pattern_analytics", 
        "performance_metrics_storage",
        "error_querying",
        "trend_analysis",
        "multi_database_support"
    ]
}

# Async process function for PlugPipe contract
def process(plugin_ctx: Dict[str, Any], user_ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Async entry point for Enhanced Error Database Logger.

    Args:
        plugin_ctx: Plugin execution context
        user_ctx: User configuration and action details

    Returns:
        Dict containing operation results and status
    """
    start_time = datetime.now(timezone.utc)

    try:
        # Validate input contexts first before accessing them
        if not isinstance(plugin_ctx, dict):
            return {'success': False, 'error': 'Invalid plugin_ctx: must be dictionary', 'processing_time_ms': (time.time() - start_time) * 1000}

        if not isinstance(user_ctx, dict):
            return {'success': False, 'error': 'Invalid user_ctx: must be dictionary', 'processing_time_ms': (time.time() - start_time) * 1000}

        # Now safe to access plugin_ctx
        logger = plugin_ctx.get('logger') if plugin_ctx and plugin_ctx.get('logger') else logging.getLogger(__name__)

        # Get configuration from user_ctx
        config = user_ctx.get('config', {})

        # Validate operation if specified
        action = user_ctx.get('action', 'log_error')
        if action and not isinstance(action, str):
            return {'success': False, 'error': 'Action must be a string', 'processing_time_ms': (time.time() - start_time) * 1000}

        valid_actions = [
            'log_error', 'query_errors', 'log_metrics',
            'get_analytics', 'health_check'
        ]

        if action and action not in valid_actions:
            return {
                'success': False,
                'error': f'Invalid action: {action}',
                'processing_time_ms': (time.time() - start_time) * 1000,
                'available_actions': valid_actions,
                'timestamp': start_time.isoformat()
            }

        # Create logger instance with validated config
        logger_instance = EnhancedErrorDatabaseLogger(config)

        # Create context for logger processing
        logger_ctx = {
            'action': action,
            'error_data': user_ctx.get('error_data', {}),
            'filters': user_ctx.get('filters', {}),
            'metrics_data': user_ctx.get('metrics_data', {}),
            'logger': logger
        }

        # Process the request
        result = logger_instance.process(logger_ctx, config)

        # Add timing information
        end_time = datetime.now(timezone.utc)
        result['processing_time'] = (end_time - start_time).total_seconds()
        result['timestamp'] = end_time.isoformat()

        return result

    except Exception as e:
        logger.error(f"Enhanced Error Database Logger failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': datetime.now(timezone.utc).isoformat()
        , 'processing_time_ms': (time.time() - start_time) * 1000}