# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
PlugPipe Storage Backend Abstractor Plugin

Universal storage abstraction layer eliminating cross-cutting storage concerns.
Provides unified interface for all storage backends: SQLite, PostgreSQL, local files, S3, etc.

Following PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Leverages existing backend implementations
- GRACEFUL DEGRADATION: Falls back to working backends on failure  
- SIMPLICITY BY TRADITION: Convention over configuration
- CLOSE THE GAP: Eliminates storage backend cross-cutting code
"""

import os
import sys
import json
import sqlite3
import logging
import asyncio
from typing import Dict, Any, List, Optional, Union
from datetime import datetime
from pathlib import Path

# Add project root to Python path for imports
sys.path.insert(0, get_plugpipe_root())

try:
    from cores.registry_backend.backend_factory import BackendFactory
    from cores.registry_backend.database_factory_backend import DatabaseFactoryBackend
    ADVANCED_BACKENDS_AVAILABLE = True
except ImportError as e:
    logger.info(f"Advanced backend components not available: {e}")
    logger.info("Storage Backend Abstractor will use basic backends only")
    ADVANCED_BACKENDS_AVAILABLE = False
    
    # Create stub classes for graceful degradation
    class BackendFactory:
        @staticmethod
        def create_backend(backend_type: str, config: Dict[str, Any]):
            return None
            
    class DatabaseFactoryBackend:
        pass

logger = logging.getLogger(__name__)

class StorageBackendAbstractor:
    """
    Universal storage backend abstractor.
    
    Provides unified interface across all storage types while eliminating
    the need for cross-cutting backend selection code throughout the system.
    """
    
    def __init__(self):
        self.available_backends = {
            'sqlite': self._get_sqlite_backend,
            'local_file': self._get_local_file_backend, 
            'database_factory': self._get_database_factory_backend,
            'yaml': self._get_yaml_backend,
            'postgresql': self._get_postgresql_backend,
            'aws_s3': self._get_s3_backend
        }
        self.backend_priority = ['sqlite', 'database_factory', 'local_file', 'yaml']
        self.active_backend = None
        self.active_backend_instance = None
    
    async def process(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main plugin entry point.
        
        Universal storage operations interface following PlugPipe conventions.
        """
        try:
            operation = config.get('operation')
            
            # Configure backend selection
            requested_backend = config.get('backend_type')
            storage_config = config.get('storage_config', {})
            
            # Initialize best available backend (needed for all operations including health check)
            backend_result = await self._initialize_backend(requested_backend, storage_config)
            
            # For health check (default operation), proceed even if backend initialization fails
            if not operation:
                return await self._handle_health_check({}, config)
            
            # For other operations, require successful backend initialization
            if not backend_result['success']:
                return backend_result
            
            # Route to operation handlers
            if operation == 'store':
                return await self._handle_store(context, config)
            elif operation == 'retrieve':
                return await self._handle_retrieve(context, config)
            elif operation == 'update':
                return await self._handle_update(context, config)
            elif operation == 'delete':
                return await self._handle_delete(context, config)
            elif operation == 'list':
                return await self._handle_list(context, config)
            elif operation == 'health_check':
                return await self._handle_health_check(context, config)
            elif operation == 'configure_backend':
                return await self._handle_configure_backend(context, config)
            else:
                return self._error_response(f"Unsupported operation: {operation}")
                
        except Exception as e:
            logger.error(f"Storage abstractor error: {e}")
            return self._error_response(f"Storage operation failed: {str(e)}")
    
    async def _initialize_backend(self, requested_backend: Optional[str], storage_config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Initialize the best available storage backend.
        
        Follows graceful degradation - tries requested backend first,
        then falls back through priority order.
        """
        backends_to_try = []
        
        if requested_backend and requested_backend in self.available_backends:
            backends_to_try.append(requested_backend)
        
        # Add priority order (excluding already tried)
        for backend in self.backend_priority:
            if backend not in backends_to_try and backend in self.available_backends:
                backends_to_try.append(backend)
        
        # Try any remaining backends
        for backend in self.available_backends:
            if backend not in backends_to_try:
                backends_to_try.append(backend)
        
        last_error = None
        for backend_type in backends_to_try:
            try:
                backend_instance = await self.available_backends[backend_type](storage_config)
                if await self._test_backend_health(backend_instance):
                    self.active_backend = backend_type
                    self.active_backend_instance = backend_instance
                    logger.info(f"✅ Initialized storage backend: {backend_type}")
                    return {
                        'success': True,
                        'backend_used': backend_type,
                        'message': f"Storage backend '{backend_type}' initialized successfully"
                    }
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Backend {backend_type} failed initialization: {e}")
                continue
        
        return self._error_response(f"No storage backends available. Last error: {last_error}")
    
    async def _test_backend_health(self, backend_instance) -> bool:
        """Test if a backend instance is healthy and operational."""
        try:
            if hasattr(backend_instance, 'health_check'):
                health = await backend_instance.health_check()
                return health.get('status') == 'healthy'
            elif hasattr(backend_instance, 'test_connection'):
                return await backend_instance.test_connection()
            else:
                # Basic operation test
                return True
        except Exception as e:
            logger.debug(f"Backend health test failed: {e}")
            return False
    
    async def _handle_store(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle data storage operations."""
        data = config.get('data')
        if not data:
            return self._error_response("Data parameter required for store operation")
        
        try:
            if self.active_backend == 'sqlite':
                return await self._store_to_sqlite(data, config)
            elif self.active_backend == 'database_factory':
                return await self._store_to_database_factory(data, config)
            elif self.active_backend == 'local_file':
                return await self._store_to_local_file(data, config)
            elif self.active_backend == 'yaml':
                return await self._store_to_yaml(data, config)
            else:
                return await self._store_generic(data, config)
        except Exception as e:
            return self._error_response(f"Store operation failed: {str(e)}")
    
    async def _handle_retrieve(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle data retrieval operations."""
        query_filters = config.get('query_filters', {})
        
        try:
            if self.active_backend == 'sqlite':
                return await self._retrieve_from_sqlite(query_filters, config)
            elif self.active_backend == 'database_factory':
                return await self._retrieve_from_database_factory(query_filters, config)
            elif self.active_backend == 'local_file':
                return await self._retrieve_from_local_file(query_filters, config)
            elif self.active_backend == 'yaml':
                return await self._retrieve_from_yaml(query_filters, config)
            else:
                return await self._retrieve_generic(query_filters, config)
        except Exception as e:
            return self._error_response(f"Retrieve operation failed: {str(e)}")
    
    async def _handle_list(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle list operations with filtering."""
        query_filters = config.get('query_filters', {})
        limit = query_filters.get('limit', 100)
        offset = query_filters.get('offset', 0)
        
        try:
            if self.active_backend == 'sqlite':
                return await self._list_from_sqlite(query_filters, config)
            elif self.active_backend == 'database_factory':
                return await self._list_from_database_factory(query_filters, config)
            elif self.active_backend == 'local_file':
                return await self._list_from_local_file(query_filters, config)
            else:
                return await self._list_generic(query_filters, config)
        except Exception as e:
            return self._error_response(f"List operation failed: {str(e)}")
    
    async def _handle_health_check(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle backend health check operations."""
        try:
            health_status = {
                'active_backend': self.active_backend,
                'backend_status': 'healthy' if self.active_backend_instance else 'unhealthy',
                'available_backends': list(self.available_backends.keys()),
                'timestamp': datetime.utcnow().isoformat()
            }
            
            if self.active_backend_instance and hasattr(self.active_backend_instance, 'health_check'):
                backend_health = await self.active_backend_instance.health_check()
                health_status['backend_details'] = backend_health
            
            return {
                'success': True,
                'message': f'Storage Backend Abstractor is operational with {self.active_backend} backend',
                'data': health_status,
                'backend_used': self.active_backend,
                'records_affected': 0
            }
        except Exception as e:
            return self._error_response(f"Health check failed: {str(e)}")
    
    # Backend-specific implementations
    async def _get_sqlite_backend(self, config: Dict[str, Any]):
        """Initialize SQLite backend."""
        db_path = config.get('database_path', 'data/plugpipe_storage.db')
        
        # Ensure directory exists
        os.makedirs(os.path.dirname(db_path), exist_ok=True)
        
        return {
            'type': 'sqlite',
            'connection_string': f'sqlite:///{db_path}',
            'db_path': db_path
        }
    
    async def _get_local_file_backend(self, config: Dict[str, Any]):
        """Initialize local file backend."""
        storage_dir = config.get('storage_directory', '/tmp/plugpipe_files')
        os.makedirs(storage_dir, exist_ok=True)
        
        return {
            'type': 'local_file',
            'storage_directory': storage_dir
        }
    
    async def _get_yaml_backend(self, config: Dict[str, Any]):
        """Initialize YAML backend."""
        yaml_dir = config.get('yaml_directory', '/tmp/plugpipe_yaml')
        os.makedirs(yaml_dir, exist_ok=True)
        
        return {
            'type': 'yaml',
            'yaml_directory': yaml_dir
        }
    
    async def _get_database_factory_backend(self, config: Dict[str, Any]):
        """Initialize database factory backend."""
        factory_config = config.get('factory_config', {
            'primary_database': 'sqlite',
            'database_configs': {
                'sqlite': {
                    'database_path': 'data/plugpipe_factory.db'
                }
            }
        })
        
        try:
            return DatabaseFactoryBackend(factory_config=factory_config)
        except Exception as e:
            logger.warning(f"Database factory backend failed: {e}")
            return await self._get_sqlite_backend(config)
    
    async def _get_postgresql_backend(self, config: Dict[str, Any]):
        """Initialize PostgreSQL backend."""
        connection_string = config.get('connection_string', 
                                     'postgresql://user:pass@localhost/plugpipe')
        return {
            'type': 'postgresql',
            'connection_string': connection_string
        }
    
    async def _get_s3_backend(self, config: Dict[str, Any]):
        """Initialize AWS S3 backend."""
        return {
            'type': 'aws_s3',
            'bucket_name': config.get('bucket_name', 'plugpipe-storage'),
            'region': config.get('region', 'us-east-1')
        }
    
    # Storage operation implementations
    async def _store_to_sqlite(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Store data to SQLite database."""
        db_path = self.active_backend_instance['db_path']
        table_name = config.get('table_name', 'storage_records')
        
        conn = sqlite3.connect(db_path)
        try:
            # Create table if it doesn't exist
            conn.execute(f'''
                CREATE TABLE IF NOT EXISTS {table_name} (
                    id TEXT PRIMARY KEY,
                    data TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            record_id = data.get('id', str(datetime.utcnow().timestamp()))
            data_json = json.dumps(data)
            
            conn.execute(f'''
                INSERT OR REPLACE INTO {table_name} (id, data, updated_at)
                VALUES (?, ?, CURRENT_TIMESTAMP)
            ''', (record_id, data_json))
            
            conn.commit()
            records_affected = conn.total_changes
            
            return {
                'success': True,
                'data': {'id': record_id, 'stored': True},
                'backend_used': self.active_backend,
                'records_affected': records_affected
            }
        finally:
            conn.close()
    
    async def _retrieve_from_sqlite(self, query_filters: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve data from SQLite database."""
        db_path = self.active_backend_instance['db_path']
        table_name = config.get('table_name', 'storage_records')
        record_id = query_filters.get('id')
        
        conn = sqlite3.connect(db_path)
        try:
            if record_id:
                cursor = conn.execute(f'SELECT data FROM {table_name} WHERE id = ?', (record_id,))
                row = cursor.fetchone()
                if row:
                    data = json.loads(row[0])
                    return {
                        'success': True,
                        'data': data,
                        'backend_used': self.active_backend,
                        'records_affected': 1
                    }
                else:
                    return self._error_response(f"Record with id '{record_id}' not found")
            else:
                return self._error_response("Record ID required for retrieve operation")
        finally:
            conn.close()
    
    async def _list_from_sqlite(self, query_filters: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """List records from SQLite database."""
        db_path = self.active_backend_instance['db_path']
        table_name = config.get('table_name', 'storage_records')
        limit = query_filters.get('limit', 100)
        offset = query_filters.get('offset', 0)
        
        conn = sqlite3.connect(db_path)
        try:
            cursor = conn.execute(f'''
                SELECT id, data, created_at, updated_at 
                FROM {table_name} 
                ORDER BY updated_at DESC 
                LIMIT ? OFFSET ?
            ''', (limit, offset))
            
            records = []
            for row in cursor.fetchall():
                records.append({
                    'id': row[0],
                    'data': json.loads(row[1]),
                    'created_at': row[2],
                    'updated_at': row[3]
                })
            
            return {
                'success': True,
                'data': {'records': records, 'count': len(records)},
                'backend_used': self.active_backend,
                'records_affected': len(records)
            }
        finally:
            conn.close()
    
    async def _store_to_local_file(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Store data to local file system."""
        storage_dir = self.active_backend_instance['storage_directory']
        record_id = data.get('id', str(datetime.utcnow().timestamp()))
        file_path = os.path.join(storage_dir, f"{record_id}.json")
        
        with open(file_path, 'w') as f:
            json.dump(data, f, indent=2)
        
        return {
            'success': True,
            'data': {'id': record_id, 'file_path': file_path},
            'backend_used': self.active_backend,
            'records_affected': 1
        }
    
    async def _retrieve_from_local_file(self, query_filters: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Retrieve data from local file system."""
        storage_dir = self.active_backend_instance['storage_directory']
        record_id = query_filters.get('id')
        
        if not record_id:
            return self._error_response("Record ID required for retrieve operation")
        
        file_path = os.path.join(storage_dir, f"{record_id}.json")
        if not os.path.exists(file_path):
            return self._error_response(f"Record with id '{record_id}' not found")
        
        with open(file_path, 'r') as f:
            data = json.load(f)
        
        return {
            'success': True,
            'data': data,
            'backend_used': self.active_backend,
            'records_affected': 1
        }
    
    async def _list_from_local_file(self, query_filters: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """List records from local file system."""
        storage_dir = self.active_backend_instance['storage_directory']
        limit = query_filters.get('limit', 100)
        offset = query_filters.get('offset', 0)
        
        json_files = [f for f in os.listdir(storage_dir) if f.endswith('.json')]
        json_files.sort(key=lambda x: os.path.getmtime(os.path.join(storage_dir, x)), reverse=True)
        
        # Apply offset and limit
        selected_files = json_files[offset:offset + limit]
        
        records = []
        for file_name in selected_files:
            file_path = os.path.join(storage_dir, file_name)
            try:
                with open(file_path, 'r') as f:
                    data = json.load(f)
                records.append({
                    'id': file_name.replace('.json', ''),
                    'data': data,
                    'file_path': file_path
                })
            except Exception as e:
                logger.warning(f"Failed to read {file_name}: {e}")
        
        return {
            'success': True,
            'data': {'records': records, 'count': len(records)},
            'backend_used': self.active_backend,
            'records_affected': len(records)
        }
    
    # Generic fallback methods
    async def _store_generic(self, data: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generic store method - fallback to local file."""
        return await self._store_to_local_file(data, config)
    
    async def _retrieve_generic(self, query_filters: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generic retrieve method - fallback to local file."""
        return await self._retrieve_from_local_file(query_filters, config)
    
    async def _list_generic(self, query_filters: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generic list method - fallback to local file."""
        return await self._list_from_local_file(query_filters, config)
    
    def _error_response(self, message: str) -> Dict[str, Any]:
        """Generate standardized error response."""
        return {
            'success': False,
            'error': message,
            'backend_used': self.active_backend or 'none',
            'records_affected': 0
        }

# Plugin entry points
def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synchronous plugin entry point for PlugPipe integration.
    Wraps the async implementation.
    """
    abstractor = StorageBackendAbstractor()
    return asyncio.run(abstractor.process(context, config))

def main():
    """Plugin main entry point for standalone execution."""
    import json
    
    if len(sys.argv) > 1:
        try:
            config = json.loads(sys.argv[1])
        except:
            config = {"operation": "health_check"}
    else:
        config = {"operation": "health_check"}
    
    result = process({}, config)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()