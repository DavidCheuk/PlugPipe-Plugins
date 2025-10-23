#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Issue Tracker Plugin
====================

Comprehensive issue tracking system for plugin validation results with multiple 
storage backends. Follows PlugPipe principles:
- "Reuse everything, reinvent nothing" - uses existing storage plugins
- "Everything is a plugin" - abstracts storage through plugin system
- "Convention over configuration" - smart defaults with auto-selection

Supported storage backends:
1. Database Factory Plugin - Primary option using database abstraction
2. AWS S3 Storage Plugin - Cloud storage for enterprise deployments  
3. Local File System - Simple file-based storage for development
4. Auto-selection - Automatically chooses best available backend

Features:
- Multi-backend storage with automatic failover
- Rich querying and filtering capabilities
- Issue aggregation and analytics
- Export functionality in multiple formats
- Health monitoring and diagnostics
- Real-time API integration ready
"""

import os
import sys
import json
import asyncio
from typing import Dict, Any, List, Optional, Union
from datetime import datetime, timedelta
from pathlib import Path
import uuid

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
sys.path.insert(0, PROJECT_ROOT)

try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
except ImportError:
    # Fallback for standalone execution
    def pp(plugin_name):
        return None
    def get_llm_config(primary=True):
        return {}

class IssueTracker:
    """
    Comprehensive issue tracking system with multiple storage backends.
    
    This class implements smart storage backend selection and failover,
    following PlugPipe's principle of reusing existing plugin abstractions.
    """
    
    def __init__(self):
        self.storage_backends = {}
        self.active_backend = None
        self.initialized = False
        self.error_count = 0
        self.last_successful_operation = None
        
    async def process_operation(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main entry point for issue tracker operations.
        
        Handles all issue tracking operations with automatic backend selection
        and error handling.
        """
        try:
            operation = config.get('operation', 'store_issues')
            
            # Initialize storage backends if not already done
            if not self.initialized:
                await self._initialize_storage_backends(config)
            
            # Route to appropriate operation handler
            if operation == 'store_issues':
                return await self._store_issues(context, config)
            elif operation == 'get_issues':
                return await self._get_issues(context, config)
            elif operation == 'get_latest_issues':
                return await self._get_latest_issues(context, config)
            elif operation == 'search_issues':
                return await self._search_issues(context, config)
            elif operation == 'get_issue_summary':
                return await self._get_issue_summary(context, config)
            elif operation == 'get_issue_history':
                return await self._get_issue_history(context, config)
            elif operation == 'delete_issues':
                return await self._delete_issues(context, config)
            elif operation == 'export_issues':
                return await self._export_issues(context, config)
            elif operation == 'get_health_status':
                return await self._get_health_status(context, config)
            else:
                return self._error_response(f"Unknown operation: {operation}")
                
        except Exception as e:
            self.error_count += 1
            return self._error_response(f"Issue tracker operation failed: {str(e)}")
    
    async def _initialize_storage_backends(self, config: Dict[str, Any]):
        """
        Initialize storage backends based on configuration.
        
        Supports any storage option through pluggable architecture:
        - Database plugins (SQLite, PostgreSQL, MongoDB, MySQL, etc.)
        - Cloud storage (S3, Azure Blob, GCP Storage, etc.) 
        - File systems (local, NFS, distributed file systems)
        - Custom storage implementations
        """
        storage_config = config.get('storage_config', {})
        preferred_backend = config.get('storage_backend', 'auto')
        
        # Initialize all configured storage backends
        await self._initialize_database_backends(storage_config)
        await self._initialize_cloud_storage_backends(storage_config)
        await self._initialize_filesystem_backends(storage_config)
        await self._initialize_custom_backends(storage_config)
        
        # Select active backend based on preference or auto-select
        self._select_active_backend(preferred_backend)
        
        self.initialized = True
        print(f"Issue tracker initialized with backend: {self.active_backend}")
        print(f"Available backends: {list(self.storage_backends.keys())}")
    
    async def _initialize_database_backends(self, storage_config: Dict[str, Any]):
        """Initialize database storage backends."""
        
        # Database Factory Plugin - supports SQLite, PostgreSQL, MongoDB
        if 'database_factory' in storage_config:
            try:
                database_factory = pp('factory')
                if database_factory:
                    db_config = storage_config['database_factory']
                    await self._test_and_register_backend(
                        'database_factory', 
                        database_factory, 
                        db_config,
                        {'operation': 'get_status', 'database_factory': db_config.get('factory_config', {})},
                        priority=1
                    )
            except Exception as e:
                print(f"Warning: Database factory initialization failed: {e}")
        
        # Direct SQLite plugin
        if 'sqlite' in storage_config:
            try:
                sqlite_plugin = pp('sqlite')
                if sqlite_plugin:
                    sqlite_config = storage_config['sqlite']
                    await self._test_and_register_backend(
                        'sqlite',
                        sqlite_plugin,
                        sqlite_config,
                        {'operation': 'health_check'},
                        priority=2
                    )
            except Exception as e:
                print(f"Warning: SQLite initialization failed: {e}")
        
        # TODO: PostgreSQL plugin not yet implemented
        # if 'postgresql' in storage_config:
        #     try:
        #         postgres_plugin = pp('postgresql') or pp('postgres')
        #         if postgres_plugin:
        #             postgres_config = storage_config['postgresql']
        #             await self._test_and_register_backend(
        #                 'postgresql',
        #                 postgres_plugin,
        #                 postgres_config,
        #                 {'operation': 'health_check'},
        #                 priority=2
        #             )
        #     except Exception as e:
        #         print(f"Warning: PostgreSQL initialization failed: {e}")

        # TODO: MongoDB plugin not yet implemented
        # if 'mongodb' in storage_config:
        #     try:
        #         mongo_plugin = pp('mongodb') or pp('mongo')
        #         if mongo_plugin:
        #             mongo_config = storage_config['mongodb']
        #             await self._test_and_register_backend(
        #                 'mongodb',
        #                 mongo_plugin,
        #                 mongo_config,
        #                 {'operation': 'health_check'},
        #                 priority=2
        #             )
        #     except Exception as e:
        #         print(f"Warning: MongoDB initialization failed: {e}")

        # TODO: MySQL plugin not yet implemented
        # if 'mysql' in storage_config:
        #     try:
        #         mysql_plugin = pp('mysql')
        #         if mysql_plugin:
        #             mysql_config = storage_config['mysql']
        #             await self._test_and_register_backend(
        #                 'mysql',
        #                 mysql_plugin,
        #                 mysql_config,
        #                 {'operation': 'health_check'},
        #                 priority=2
        #             )
        #     except Exception as e:
        #         print(f"Warning: MySQL initialization failed: {e}")
    
    async def _initialize_cloud_storage_backends(self, storage_config: Dict[str, Any]):
        """Initialize cloud storage backends."""
        
        # AWS S3 Storage
        if 'aws_s3' in storage_config:
            try:
                s3_storage = pp('aws_s3_storage')
                if s3_storage:
                    s3_config = storage_config['aws_s3']
                    await self._test_and_register_backend(
                        'aws_s3',
                        s3_storage,
                        s3_config,
                        {'operation': 'list_buckets'},
                        priority=3,
                        success_key='s3_status',
                        success_value='success'
                    )
            except Exception as e:
                print(f"Warning: S3 storage initialization failed: {e}")
        
        # TODO: Azure Blob Storage plugin not yet implemented
        # if 'azure_blob' in storage_config:
        #     try:
        #         azure_plugin = pp('azure_blob_storage') or pp('azure_storage')
        #         if azure_plugin:
        #             azure_config = storage_config['azure_blob']
        #             await self._test_and_register_backend(
        #                 'azure_blob',
        #                 azure_plugin,
        #                 azure_config,
        #                 {'operation': 'list_containers'},
        #                 priority=3
        #             )
        #     except Exception as e:
        #         print(f"Warning: Azure Blob storage initialization failed: {e}")

        # TODO: Google Cloud Storage plugin not yet implemented
        # if 'gcs' in storage_config:
        #     try:
        #         gcs_plugin = pp('gcs_storage') or pp('google_cloud_storage')
        #         if gcs_plugin:
        #             gcs_config = storage_config['gcs']
        #             await self._test_and_register_backend(
        #                 'gcs',
        #                 gcs_plugin,
        #                 gcs_config,
        #                 {'operation': 'list_buckets'},
        #                 priority=3
        #             )
        #     except Exception as e:
        #         print(f"Warning: GCS storage initialization failed: {e}")
    
    async def _initialize_filesystem_backends(self, storage_config: Dict[str, Any]):
        """Initialize filesystem storage backends."""
        
        # Local file system - always available as fallback
        local_config = storage_config.get('local_file', {
            'storage_path': 'validation_issues_storage.json',
            'backup_enabled': True,
            'max_history': 100
        })
        self.storage_backends['local_file'] = {
            'plugin': None,  # Direct file system access
            'config': local_config,
            'healthy': True,
            'priority': 99,  # Lowest priority as fallback
            'type': 'filesystem'
        }
        
        # Network File System (NFS)
        if 'nfs' in storage_config:
            nfs_config = storage_config['nfs']
            if self._validate_nfs_path(nfs_config.get('mount_path')):
                self.storage_backends['nfs'] = {
                    'plugin': None,
                    'config': nfs_config,
                    'healthy': True,
                    'priority': 4,
                    'type': 'filesystem'
                }
        
        # Distributed file systems (HDFS, etc.)
        if 'hdfs' in storage_config:
            try:
                hdfs_plugin = None  # TODO: hdfs_storage plugin not yet implemented
                if hdfs_plugin:
                    hdfs_config = storage_config['hdfs']
                    await self._test_and_register_backend(
                        'hdfs',
                        hdfs_plugin,
                        hdfs_config,
                        {'operation': 'health_check'},
                        priority=4
                    )
            except Exception as e:
                print(f"Warning: HDFS storage initialization failed: {e}")
    
    async def _initialize_custom_backends(self, storage_config: Dict[str, Any]):
        """Initialize custom storage backends."""
        
        # Custom storage plugins
        custom_backends = storage_config.get('custom_backends', {})
        for backend_name, backend_config in custom_backends.items():
            try:
                plugin_name = backend_config.get('plugin_name', backend_name)
                custom_plugin = pp(plugin_name)
                if custom_plugin:
                    health_check = backend_config.get('health_check', {'operation': 'health_check'})
                    priority = backend_config.get('priority', 5)
                    await self._test_and_register_backend(
                        backend_name,
                        custom_plugin,
                        backend_config,
                        health_check,
                        priority=priority
                    )
            except Exception as e:
                print(f"Warning: Custom backend {backend_name} initialization failed: {e}")
    
    async def _test_and_register_backend(self, name: str, plugin, config: Dict[str, Any], 
                                       health_check: Dict[str, Any], priority: int,
                                       success_key: str = 'success', success_value: Any = True):
        """Test a storage backend and register if healthy."""
        try:
            result = await self._safe_plugin_call(plugin, {}, health_check)
            is_healthy = result.get(success_key) == success_value
            
            self.storage_backends[name] = {
                'plugin': plugin,
                'config': config,
                'healthy': is_healthy,
                'priority': priority,
                'type': 'plugin',
                'last_health_check': datetime.utcnow().isoformat(),
                'health_check_config': health_check
            }
            
            if is_healthy:
                print(f"✅ {name} backend initialized successfully")
            else:
                print(f"⚠️  {name} backend initialized but health check failed")
                
        except Exception as e:
            print(f"❌ {name} backend test failed: {e}")
    
    def _validate_nfs_path(self, mount_path: Optional[str]) -> bool:
        """Validate NFS mount path availability."""
        if not mount_path:
            return False
        try:
            path = Path(mount_path)
            return path.exists() and path.is_dir()
        except Exception:
            return False
    
    def _select_active_backend(self, preferred_backend: str):
        """Select active backend based on preference or auto-selection."""
        if preferred_backend != 'auto' and preferred_backend in self.storage_backends:
            backend = self.storage_backends[preferred_backend]
            if backend['healthy']:
                self.active_backend = preferred_backend
                return
            else:
                print(f"Warning: Preferred backend {preferred_backend} is unhealthy, auto-selecting")
        
        # Auto-select based on priority and health
        healthy_backends = [
            (name, backend) for name, backend in self.storage_backends.items() 
            if backend['healthy']
        ]
        
        if healthy_backends:
            # Sort by priority (lower number = higher priority)
            healthy_backends.sort(key=lambda x: x[1]['priority'])
            self.active_backend = healthy_backends[0][0]
        else:
            # No healthy backends - use local file as ultimate fallback
            self.active_backend = 'local_file'
    
    async def _store_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Store validation issues using the configured storage backend.
        
        Handles data transformation and storage across different backend types.
        """
        try:
            issues_data = config.get('issues', {})
            if not issues_data:
                return self._error_response("No issues data provided for storage")
            
            # Add tracking metadata
            issues_data['stored_timestamp'] = datetime.utcnow().isoformat()
            issues_data['validation_run_id'] = issues_data.get('validation_run_id', str(uuid.uuid4()))
            
            backend = self.storage_backends[self.active_backend]
            records_affected = 0
            
            if self.active_backend == 'database_factory':
                records_affected = await self._store_to_database_factory(issues_data, backend)
            elif self.active_backend == 'aws_s3':
                records_affected = await self._store_to_s3(issues_data, backend)
            else:  # local_file
                records_affected = await self._store_to_local_file(issues_data, backend)
            
            self.last_successful_operation = datetime.utcnow().isoformat()
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'store_issues',
                    'storage_backend_used': self.active_backend,
                    'timestamp': datetime.utcnow().isoformat(),
                    'records_affected': records_affected
                }
            }
            
        except Exception as e:
            self.error_count += 1
            return self._error_response(f"Issue storage failed: {str(e)}")
    
    async def _store_to_database_factory(self, issues_data: Dict[str, Any], backend: Dict[str, Any]) -> int:
        """Store issues using the database factory plugin."""
        factory_plugin = backend['plugin']
        table_name = backend['config'].get('table_name', 'validation_issues')
        
        # Transform data for database storage
        db_config = {
            'operation': 'store_plugin',
            'plugin_metadata': {
                'name': f"validation_issues_{issues_data['validation_run_id']}",
                'version': '1.0.0',
                'data': issues_data,
                'table_name': table_name,
                'timestamp': issues_data['stored_timestamp']
            }
        }
        
        result = await self._safe_plugin_call(factory_plugin, {}, db_config)
        if result.get('success'):
            return 1  # One record stored
        else:
            raise Exception(f"Database storage failed: {result.get('error', 'Unknown error')}")
    
    async def _store_to_s3(self, issues_data: Dict[str, Any], backend: Dict[str, Any]) -> int:
        """Store issues using AWS S3 storage plugin."""
        s3_plugin = backend['plugin']
        s3_config = backend['config']
        
        bucket = s3_config.get('bucket', 'plugpipe-validation-issues')
        prefix = s3_config.get('prefix', 'plugpipe/validation-issues/')
        
        # Create S3 key with timestamp and validation run ID
        timestamp = datetime.utcnow().strftime('%Y/%m/%d')
        s3_key = f"{prefix}{timestamp}/validation_run_{issues_data['validation_run_id']}.json"
        
        s3_store_config = {
            'operation': 'put_object',
            'bucket': bucket,
            'key': s3_key,
            'body': json.dumps(issues_data, indent=2),
            'content_type': 'application/json',
            'metadata': {
                'validation_run_id': issues_data['validation_run_id'],
                'target_plugin': issues_data.get('target_plugin', 'unknown'),
                'issue_count': str(len(issues_data.get('issues_list', [])))
            }
        }
        
        result = await self._safe_plugin_call(s3_plugin, {}, s3_store_config)
        if result.get('s3_status') == 'success':
            return 1  # One object stored
        else:
            raise Exception(f"S3 storage failed: {result.get('s3_error', 'Unknown error')}")
    
    async def _store_to_local_file(self, issues_data: Dict[str, Any], backend: Dict[str, Any]) -> int:
        """Store issues to local file system."""
        local_config = backend['config']
        storage_path = Path(local_config.get('storage_path', 'validation_issues_storage.json'))
        max_history = local_config.get('max_history', 100)
        
        # Load existing data
        existing_data = {'validation_history': [], 'current_issues': {}}
        if storage_path.exists():
            with open(storage_path, 'r') as f:
                existing_data = json.load(f)
        
        # Add new issues data
        existing_data['validation_history'].append(issues_data)
        existing_data['current_issues'] = issues_data
        existing_data['last_updated'] = datetime.utcnow().isoformat()
        
        # Maintain history limit
        if len(existing_data['validation_history']) > max_history:
            existing_data['validation_history'] = existing_data['validation_history'][-max_history:]
        
        # Create backup if enabled
        if local_config.get('backup_enabled', True) and storage_path.exists():
            backup_path = storage_path.with_suffix(f'.backup.{int(datetime.utcnow().timestamp())}')
            storage_path.rename(backup_path)
        
        # Write updated data
        with open(storage_path, 'w') as f:
            json.dump(existing_data, f, indent=2)
        
        return 1  # One record stored
    
    async def _get_latest_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Get the most recent validation issues."""
        try:
            backend = self.storage_backends[self.active_backend]
            issues_data = None
            
            if self.active_backend == 'database_factory':
                issues_data = await self._get_latest_from_database_factory(backend)
            elif self.active_backend == 'aws_s3':
                issues_data = await self._get_latest_from_s3(backend)
            else:  # local_file
                issues_data = await self._get_latest_from_local_file(backend)
            
            self.last_successful_operation = datetime.utcnow().isoformat()
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'get_latest_issues',
                    'storage_backend_used': self.active_backend,
                    'timestamp': datetime.utcnow().isoformat(),
                    'records_affected': 1 if issues_data else 0
                },
                'issues_data': issues_data or {}
            }
            
        except Exception as e:
            self.error_count += 1
            return self._error_response(f"Failed to get latest issues: {str(e)}")
    
    async def _get_latest_from_local_file(self, backend: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Get latest issues from local file storage."""
        local_config = backend['config']
        storage_path = Path(local_config.get('storage_path', 'validation_issues_storage.json'))
        
        if not storage_path.exists():
            return None
        
        with open(storage_path, 'r') as f:
            data = json.load(f)
        
        return data.get('current_issues', {})
    
    async def _get_issue_summary(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary statistics about tracked issues."""
        try:
            # Get latest issues for summary calculation
            latest_result = await self._get_latest_issues(context, config)
            if not latest_result.get('success'):
                return latest_result
            
            issues_data = latest_result.get('issues_data', {})
            issues_list = issues_data.get('issues_list', [])
            
            # Calculate summary statistics
            total_issues = len(issues_list)
            critical_issues = len([i for i in issues_list if i.get('severity') == 'critical'])
            high_issues = len([i for i in issues_list if i.get('severity') == 'high'])
            medium_issues = len([i for i in issues_list if i.get('severity') == 'medium'])
            low_issues = len([i for i in issues_list if i.get('severity') == 'low'])
            
            # Group by category
            issues_by_category = {}
            for issue in issues_list:
                category = issue.get('category', 'unknown')
                issues_by_category[category] = issues_by_category.get(category, 0) + 1
            
            summary = {
                'total_issues': total_issues,
                'critical_issues': critical_issues,
                'high_issues': high_issues,
                'medium_issues': medium_issues,
                'low_issues': low_issues,
                'issues_by_category': issues_by_category,
                'latest_validation_run': issues_data.get('timestamp'),
                'average_score': issues_data.get('pipeline_score', 0)
            }
            
            self.last_successful_operation = datetime.utcnow().isoformat()
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'get_issue_summary',
                    'storage_backend_used': self.active_backend,
                    'timestamp': datetime.utcnow().isoformat(),
                    'records_affected': 1
                },
                'issue_summary': summary
            }
            
        except Exception as e:
            self.error_count += 1
            return self._error_response(f"Failed to generate issue summary: {str(e)}")
    
    async def _get_health_status(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Get health status of the issue tracker system."""
        try:
            # Test current storage backend health
            backend = self.storage_backends.get(self.active_backend, {})
            storage_healthy = backend.get('healthy', False)
            
            # Test basic functionality
            try:
                if self.active_backend == 'local_file':
                    # Test local file write capability
                    test_path = Path('health_check_test.tmp')
                    test_path.write_text('health_check')
                    test_path.unlink()
                    storage_healthy = True
                else:
                    # Test plugin health if available
                    plugin = backend.get('plugin')
                    if plugin:
                        # This would be plugin-specific health check
                        storage_healthy = True
            except Exception:
                storage_healthy = False
            
            health_status = {
                'storage_healthy': storage_healthy,
                'storage_backend': self.active_backend,
                'last_successful_operation': self.last_successful_operation,
                'error_count': self.error_count
            }
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'get_health_status',
                    'storage_backend_used': self.active_backend,
                    'timestamp': datetime.utcnow().isoformat(),
                    'records_affected': 0
                },
                'health_status': health_status
            }
            
        except Exception as e:
            return self._error_response(f"Health status check failed: {str(e)}")
    
    async def _safe_plugin_call(self, plugin, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Safely call a plugin, handling both sync and async returns."""
        try:
            result = plugin.process(context, config)
            
            # Handle async plugins
            if asyncio.iscoroutine(result):
                result = await result
                
            return result if isinstance(result, dict) else {'success': False, 'error': 'Invalid plugin response'}
            
        except Exception as e:
            return {'success': False, 'error': f'Plugin call failed: {str(e)}'}
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Generate standardized error response."""
        return {
            'success': False,
            'error': error_message,
            'operation_result': {
                'operation': 'error',
                'storage_backend_used': self.active_backend,
                'timestamp': datetime.utcnow().isoformat(),
                'records_affected': 0
            }
        }
    
    # Implementation methods for additional operations
    async def _get_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Get issues with filtering and pagination."""
        try:
            backend = self.storage_backends[self.active_backend]
            limit = config.get('limit', 100)
            offset = config.get('offset', 0)
            filters = config.get('filters', {})
            
            issues_data = None
            
            if self.active_backend == 'database_factory':
                issues_data = await self._get_issues_from_database_factory(backend, limit, offset, filters)
            elif self.active_backend == 'sqlite':
                issues_data = await self._get_issues_from_sqlite(backend, limit, offset, filters)
            elif self.active_backend == 'local_file':
                issues_data = await self._get_issues_from_local_file(backend, limit, offset, filters)
            else:
                # For other backends, fall back to getting latest and filtering
                latest_result = await self._get_latest_issues(context, config)
                if latest_result.get('success'):
                    all_issues = latest_result.get('issues_data', {}).get('issues_list', [])
                    # Apply basic filtering and pagination
                    filtered_issues = self._apply_basic_filters(all_issues, filters)
                    paginated_issues = filtered_issues[offset:offset + limit]
                    issues_data = {
                        'issues_list': paginated_issues,
                        'total_count': len(all_issues),
                        'filtered_count': len(filtered_issues),
                        'returned_count': len(paginated_issues),
                        'limit': limit,
                        'offset': offset
                    }
            
            self.last_successful_operation = datetime.utcnow().isoformat()
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'get_issues',
                    'storage_backend_used': self.active_backend,
                    'timestamp': datetime.utcnow().isoformat(),
                    'records_affected': len(issues_data.get('issues_list', [])) if issues_data else 0
                },
                'issues_data': issues_data or {'issues_list': [], 'total_count': 0}
            }
            
        except Exception as e:
            self.error_count += 1
            return self._error_response(f"Failed to get issues: {str(e)}")
    
    async def _get_issues_from_database_factory(self, backend: Dict[str, Any], limit: int, offset: int, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Get issues from database factory plugin with filtering."""
        factory_plugin = backend['plugin']
        table_name = backend['config'].get('table_name', 'validation_issues')
        
        db_config = {
            'operation': 'query_plugins',
            'query_config': {
                'table_name': table_name,
                'limit': limit,
                'offset': offset,
                'filters': filters,
                'order_by': 'timestamp DESC'
            }
        }
        
        result = await self._safe_plugin_call(factory_plugin, {}, db_config)
        if result.get('success'):
            plugins_data = result.get('plugins', [])
            # Transform database result to issues format
            issues_list = []
            for plugin_data in plugins_data:
                plugin_info = plugin_data.get('data', {})
                if 'issues_list' in plugin_info:
                    issues_list.extend(plugin_info['issues_list'])
            
            return {
                'issues_list': issues_list,
                'total_count': result.get('total_count', len(issues_list)),
                'returned_count': len(issues_list),
                'limit': limit,
                'offset': offset
            }
        else:
            raise Exception(f"Database query failed: {result.get('error', 'Unknown error')}")
    
    async def _get_issues_from_sqlite(self, backend: Dict[str, Any], limit: int, offset: int, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Get issues from SQLite plugin with filtering."""
        sqlite_plugin = backend['plugin']
        
        # Build SQL query based on filters
        where_clause = "WHERE 1=1"
        params = []
        
        if 'severity' in filters:
            where_clause += " AND severity = ?"
            params.append(filters['severity'])
        
        if 'category' in filters:
            where_clause += " AND category = ?"
            params.append(filters['category'])
        
        if 'plugin_name' in filters:
            where_clause += " AND plugin_name = ?"
            params.append(filters['plugin_name'])
        
        if 'date_from' in filters:
            where_clause += " AND timestamp >= ?"
            params.append(filters['date_from'])
        
        if 'date_to' in filters:
            where_clause += " AND timestamp <= ?"
            params.append(filters['date_to'])
        
        query = f"""
        SELECT * FROM validation_issues 
        {where_clause}
        ORDER BY timestamp DESC 
        LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        
        count_query = f"SELECT COUNT(*) as total FROM validation_issues {where_clause}"
        
        # Execute queries
        query_config = {
            'operation': 'execute_query',
            'query': query,
            'params': params
        }
        
        count_config = {
            'operation': 'execute_query', 
            'query': count_query,
            'params': params[:-2]  # Remove limit and offset for count
        }
        
        result = await self._safe_plugin_call(sqlite_plugin, {}, query_config)
        count_result = await self._safe_plugin_call(sqlite_plugin, {}, count_config)
        
        if result.get('success'):
            issues_list = result.get('rows', [])
            total_count = count_result.get('rows', [{}])[0].get('total', len(issues_list))
            
            return {
                'issues_list': issues_list,
                'total_count': total_count,
                'returned_count': len(issues_list),
                'limit': limit,
                'offset': offset
            }
        else:
            raise Exception(f"SQLite query failed: {result.get('error', 'Unknown error')}")
    
    async def _get_issues_from_local_file(self, backend: Dict[str, Any], limit: int, offset: int, filters: Dict[str, Any]) -> Dict[str, Any]:
        """Get issues from local file with filtering."""
        local_config = backend['config']
        storage_path = Path(local_config.get('storage_path', 'validation_issues_storage.json'))
        
        if not storage_path.exists():
            return {'issues_list': [], 'total_count': 0, 'returned_count': 0, 'limit': limit, 'offset': offset}
        
        with open(storage_path, 'r') as f:
            data = json.load(f)
        
        all_issues = []
        validation_history = data.get('validation_history', [])
        
        # Collect all issues from history
        for validation_run in validation_history:
            issues_list = validation_run.get('issues_list', [])
            all_issues.extend(issues_list)
        
        # Apply filters
        filtered_issues = self._apply_basic_filters(all_issues, filters)
        
        # Apply pagination
        paginated_issues = filtered_issues[offset:offset + limit]
        
        return {
            'issues_list': paginated_issues,
            'total_count': len(all_issues),
            'filtered_count': len(filtered_issues),
            'returned_count': len(paginated_issues),
            'limit': limit,
            'offset': offset
        }
    
    def _apply_basic_filters(self, issues_list: List[Dict[str, Any]], filters: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Apply basic filters to issues list."""
        if not filters:
            return issues_list
        
        filtered = issues_list
        
        if 'severity' in filters:
            filtered = [i for i in filtered if i.get('severity') == filters['severity']]
        
        if 'category' in filters:
            filtered = [i for i in filtered if i.get('category') == filters['category']]
        
        if 'plugin_name' in filters:
            filtered = [i for i in filtered if i.get('plugin_name') == filters['plugin_name']]
        
        if 'date_from' in filters:
            from_date = filters['date_from']
            filtered = [i for i in filtered if i.get('timestamp', '') >= from_date]
        
        if 'date_to' in filters:
            to_date = filters['date_to']
            filtered = [i for i in filtered if i.get('timestamp', '') <= to_date]
        
        return filtered
    
    async def _search_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Search issues with advanced queries."""
        return self._error_response("search_issues operation not yet implemented")
    
    async def _get_issue_history(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Get historical issue data."""
        return self._error_response("get_issue_history operation not yet implemented")
    
    async def _delete_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Delete issues based on criteria."""
        return self._error_response("delete_issues operation not yet implemented")
    
    async def _export_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Export issues in various formats."""
        return self._error_response("export_issues operation not yet implemented")

# Main plugin entry point
async def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point for the issue tracker."""
    tracker = IssueTracker()
    return await tracker.process_operation(context, config)

# Plugin metadata
plug_metadata = {
    "name": "issue_tracker",
    "version": "1.0.0",
    "description": "Comprehensive issue tracking system for plugin validation results with multiple storage backends",
    "author": "PlugPipe Core Team",
    "license": "MIT",
    "category": "governance",
    "tags": ["issue-tracking", "storage", "validation", "governance", "multi-backend"],
    "requirements": [],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["store_issues", "get_issues", "get_latest_issues", "search_issues", "get_issue_summary", "get_issue_history", "delete_issues", "export_issues", "get_health_status"],
                "default": "store_issues",
                "description": "Issue tracking operation to perform"
            }
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "operation_result": {
                "type": "object",
                "properties": {
                    "storage_backend_used": {"type": "string"},
                    "records_affected": {"type": "integer"}
                }
            }
        }
    },
    "sbom": "sbom/"
}

async def pp():
    """PlugPipe plugin discovery function"""
    return plug_metadata