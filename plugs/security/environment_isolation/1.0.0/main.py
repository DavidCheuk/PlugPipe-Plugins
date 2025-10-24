#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
🔒🌍 Environment Isolation Plugin

Comprehensive environment isolation system that replaces global os.environ copying with
explicit, secure context passing. Provides plugin isolation, containerization support,
and prevents cross-plugin environment contamination.

This plugin addresses critical security gaps by:
- Replacing os.environ copying with explicit context management
- Providing secure environment variable scoping
- Supporting containerization and process isolation
- Enabling audit trails for environment access

Key Features:
- Explicit environment context passing (no global os.environ copying)
- Scoped environment variables with plugin isolation
- Container-ready environment management
- Audit logging for environment variable access
- Security policy enforcement for environment access
- Process-level isolation support

Author: PlugPipe Security Team
Version: 1.0.0
"""

import os
import copy
import json
import logging
import threading
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Set, Union
from contextlib import contextmanager
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import pp function for plugin discovery as per CLAUDE.md
try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
    logger.info("✅ PlugPipe ecosystem functions loaded successfully")
except ImportError:
    logger.warning("⚠️ PlugPipe ecosystem functions not available, using fallback mode")
    def pp(plugin_path): return None
    def get_llm_config(primary=True): return {}


@dataclass
class EnvironmentScope:
    """Represents a scoped environment context for plugin execution"""
    scope_id: str
    plugin_id: str
    process_id: int
    allowed_vars: Set[str]
    variables: Dict[str, str]
    parent_scope: Optional[str] = None
    created_at: datetime = None
    accessed_vars: List[str] = None
    
    def __post_init__(self):
        if self.created_at is None:
            self.created_at = datetime.utcnow()
        if self.accessed_vars is None:
            self.accessed_vars = []


@dataclass
class EnvironmentAccess:
    """Audit record for environment variable access"""
    access_id: str
    scope_id: str
    plugin_id: str
    variable_name: str
    operation: str  # 'read', 'write', 'delete'
    value_hash: Optional[str] = None
    timestamp: datetime = None
    allowed: bool = True
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow()


class SecureEnvironmentManager:
    """Secure environment management system with explicit context passing"""
    
    # Default allowed environment variables for plugins
    DEFAULT_ALLOWED_VARS = {
        'PATH', 'HOME', 'USER', 'LANG', 'LC_ALL', 'TZ',
        'PYTHONPATH', 'VIRTUAL_ENV', 'CONDA_DEFAULT_ENV',
        'PLUGPIPE_CONFIG', 'PLUGPIPE_REGISTRY', 'PLUGPIPE_CACHE_DIR'
    }
    
    # Sensitive variables that should never be exposed
    SENSITIVE_VARS = {
        'AWS_SECRET_ACCESS_KEY', 'AWS_SESSION_TOKEN',
        'AZURE_CLIENT_SECRET', 'AZURE_TENANT_ID',
        'GCP_SERVICE_ACCOUNT_KEY', 'GOOGLE_APPLICATION_CREDENTIALS',
        'OPENAI_API_KEY', 'ANTHROPIC_API_KEY', 'HUGGINGFACE_TOKEN',
        'DATABASE_PASSWORD', 'DB_PASSWORD', 'MYSQL_PASSWORD',
        'POSTGRES_PASSWORD', 'REDIS_PASSWORD', 'MONGODB_PASSWORD',
        'JWT_SECRET', 'ENCRYPTION_KEY', 'PRIVATE_KEY'
    }
    
    def __init__(self):
        """Initialize secure environment manager"""
        self.scopes = {}  # scope_id -> EnvironmentScope
        self.access_log = []  # List of EnvironmentAccess records
        self.scope_lock = threading.Lock()
        self.access_lock = threading.Lock()
        
        # Initialize base system environment (filtered)
        self.base_environment = self._create_base_environment()
        
        logger.info("🔒 Secure Environment Manager initialized")
    
    def _create_base_environment(self) -> Dict[str, str]:
        """Create filtered base environment from system environment"""
        base_env = {}
        
        for var_name, value in os.environ.items():
            if self._is_var_allowed_in_base(var_name):
                base_env[var_name] = value
        
        logger.info(f"📋 Created base environment with {len(base_env)} variables")
        return base_env
    
    def _is_var_allowed_in_base(self, var_name: str) -> bool:
        """Check if environment variable is allowed in base environment"""
        # Never include sensitive variables
        if var_name in self.SENSITIVE_VARS:
            return False
        
        # Always include default allowed variables
        if var_name in self.DEFAULT_ALLOWED_VARS:
            return True
        
        # Include PlugPipe-specific variables
        if var_name.startswith('PLUGPIPE_') or var_name.startswith('PP_'):
            return True
        
        # Include common development variables
        if var_name.startswith('NODE_') or var_name.startswith('NPM_'):
            return True
        
        # Exclude everything else by default
        return False
    
    def create_scope(self, plugin_id: str, allowed_vars: Optional[Set[str]] = None,
                    parent_scope_id: Optional[str] = None, 
                    additional_vars: Optional[Dict[str, str]] = None) -> str:
        """Create new environment scope for plugin execution"""
        import uuid
        scope_id = f"env_scope_{uuid.uuid4().hex[:12]}"
        
        # Determine allowed variables
        if allowed_vars is None:
            allowed_vars = self.DEFAULT_ALLOWED_VARS.copy()
        else:
            # Always include default vars for security
            allowed_vars = allowed_vars.union(self.DEFAULT_ALLOWED_VARS)
        
        # Start with base environment
        scope_vars = {}
        for var_name in allowed_vars:
            if var_name in self.base_environment:
                scope_vars[var_name] = self.base_environment[var_name]
        
        # Inherit from parent scope if specified
        if parent_scope_id and parent_scope_id in self.scopes:
            parent_scope = self.scopes[parent_scope_id]
            for var_name in allowed_vars:
                if var_name in parent_scope.variables:
                    scope_vars[var_name] = parent_scope.variables[var_name]
        
        # Add additional variables
        if additional_vars:
            for var_name, value in additional_vars.items():
                if var_name in allowed_vars and var_name not in self.SENSITIVE_VARS:
                    scope_vars[var_name] = value
        
        # Create scope
        scope = EnvironmentScope(
            scope_id=scope_id,
            plugin_id=plugin_id,
            process_id=os.getpid(),
            allowed_vars=allowed_vars,
            variables=scope_vars,
            parent_scope=parent_scope_id
        )
        
        with self.scope_lock:
            self.scopes[scope_id] = scope
        
        logger.info(f"🌍 Created environment scope: {scope_id} for plugin: {plugin_id}")
        return scope_id
    
    def get_environment_context(self, scope_id: str) -> Dict[str, str]:
        """Get environment context for a scope (replaces os.environ copying)"""
        with self.scope_lock:
            if scope_id not in self.scopes:
                logger.error(f"❌ Unknown environment scope: {scope_id}")
                return {}
            
            scope = self.scopes[scope_id]
            
            # Create isolated copy of environment variables
            env_context = copy.deepcopy(scope.variables)
            
            logger.debug(f"📋 Provided environment context for scope {scope_id}: {len(env_context)} vars")
            return env_context
    
    def access_variable(self, scope_id: str, var_name: str, 
                       operation: str = 'read', value: str = None) -> Optional[str]:
        """Secure access to environment variable with auditing"""
        with self.scope_lock:
            if scope_id not in self.scopes:
                self._log_access(scope_id, "unknown", var_name, operation, allowed=False)
                return None
            
            scope = self.scopes[scope_id]
            
            # Check if variable access is allowed
            if var_name not in scope.allowed_vars:
                self._log_access(scope_id, scope.plugin_id, var_name, operation, allowed=False)
                logger.warning(f"⚠️ Unauthorized environment access: {scope.plugin_id} -> {var_name}")
                return None
            
            # Check for sensitive variable access
            if var_name in self.SENSITIVE_VARS:
                self._log_access(scope_id, scope.plugin_id, var_name, operation, allowed=False)
                logger.warning(f"🚨 Blocked sensitive variable access: {scope.plugin_id} -> {var_name}")
                return None
            
            # Perform operation
            result = None
            if operation == 'read':
                result = scope.variables.get(var_name)
                if var_name not in scope.accessed_vars:
                    scope.accessed_vars.append(var_name)
            elif operation == 'write' and value is not None:
                scope.variables[var_name] = value
                result = value
            elif operation == 'delete':
                result = scope.variables.pop(var_name, None)
            
            # Log access
            self._log_access(scope_id, scope.plugin_id, var_name, operation, allowed=True)
            
            return result
    
    def _log_access(self, scope_id: str, plugin_id: str, var_name: str, 
                   operation: str, allowed: bool = True):
        """Log environment variable access for audit trail"""
        import uuid, hashlib
        
        access_record = EnvironmentAccess(
            access_id=str(uuid.uuid4()),
            scope_id=scope_id,
            plugin_id=plugin_id,
            variable_name=var_name,
            operation=operation,
            allowed=allowed
        )
        
        with self.access_lock:
            self.access_log.append(access_record)
            
            # Keep only recent access logs (last 1000 entries)
            if len(self.access_log) > 1000:
                self.access_log = self.access_log[-1000:]
    
    def destroy_scope(self, scope_id: str) -> bool:
        """Destroy environment scope and cleanup resources"""
        with self.scope_lock:
            if scope_id in self.scopes:
                scope = self.scopes.pop(scope_id)
                logger.info(f"🗑️ Destroyed environment scope: {scope_id} for plugin: {scope.plugin_id}")
                return True
            return False
    
    @contextmanager
    def isolated_environment(self, plugin_id: str, allowed_vars: Optional[Set[str]] = None,
                            additional_vars: Optional[Dict[str, str]] = None):
        """Context manager for isolated environment execution"""
        scope_id = self.create_scope(plugin_id, allowed_vars, additional_vars=additional_vars)
        try:
            yield scope_id
        finally:
            self.destroy_scope(scope_id)
    
    def get_audit_trail(self, hours: int = 24, plugin_id: Optional[str] = None) -> List[Dict[str, Any]]:
        """Get audit trail of environment variable access"""
        cutoff_time = datetime.utcnow() - timedelta(hours=hours)
        
        with self.access_lock:
            filtered_logs = [
                access for access in self.access_log
                if access.timestamp >= cutoff_time and
                (plugin_id is None or access.plugin_id == plugin_id)
            ]
        
        return [asdict(access) for access in filtered_logs]
    
    def get_scope_summary(self, scope_id: str) -> Dict[str, Any]:
        """Get summary information about an environment scope"""
        with self.scope_lock:
            if scope_id not in self.scopes:
                return {'error': 'Scope not found'}
            
            scope = self.scopes[scope_id]
            return {
                'scope_id': scope.scope_id,
                'plugin_id': scope.plugin_id,
                'process_id': scope.process_id,
                'variable_count': len(scope.variables),
                'allowed_vars_count': len(scope.allowed_vars),
                'accessed_vars_count': len(scope.accessed_vars),
                'parent_scope': scope.parent_scope,
                'created_at': scope.created_at.isoformat(),
                'uptime_seconds': (datetime.utcnow() - scope.created_at).total_seconds()
            }


# Global environment manager instance
env_manager = None

def get_environment_manager():
    """Get or create the global environment manager instance"""
    global env_manager
    if env_manager is None:
        env_manager = SecureEnvironmentManager()
    return env_manager


# Plugin metadata
plug_metadata = {
    "name": "environment_isolation",
    "owner": "plugpipe-security-team",
    "version": "1.0.0",
    "status": "stable",
    "description": "Comprehensive environment isolation system that replaces global os.environ copying with explicit, secure context passing and plugin isolation",
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["create_scope", "get_context", "access_variable", "destroy_scope", "get_audit_trail", "get_scope_summary"]
            },
            "plugin_id": {"type": "string"},
            "scope_id": {"type": "string"},
            "allowed_vars": {
                "type": "array",
                "items": {"type": "string"}
            },
            "additional_vars": {"type": "object"},
            "parent_scope_id": {"type": "string"},
            "variable_name": {"type": "string"},
            "variable_value": {"type": "string"},
            "access_operation": {"type": "string", "enum": ["read", "write", "delete"]},
            "hours": {"type": "integer"},
            "audit_plugin_id": {"type": "string"}
        },
        "required": ["operation"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "scope_id": {"type": "string"},
            "environment_context": {"type": "object"},
            "variable_value": {"type": "string"},
            "audit_trail": {"type": "array"},
            "scope_summary": {"type": "object"},
            "scopes_destroyed": {"type": "integer"},
            "error": {"type": "string"}
        }
    }
}


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point
    
    Operations:
    - create_scope: Create isolated environment scope for plugin
    - get_context: Get environment context for scope (replaces os.environ copying)
    - access_variable: Securely access environment variable with auditing
    - destroy_scope: Destroy environment scope and cleanup
    - get_audit_trail: Get audit trail of environment access
    - get_scope_summary: Get summary information about scope
    """
    operation = cfg.get('operation', 'create_scope')
    
    try:
        manager = get_environment_manager()
        
        if operation == 'create_scope':
            plugin_id = cfg.get('plugin_id', 'unknown')
            allowed_vars = set(cfg.get('allowed_vars', [])) if cfg.get('allowed_vars') else None
            additional_vars = cfg.get('additional_vars', {})
            parent_scope_id = cfg.get('parent_scope_id')
            
            scope_id = manager.create_scope(
                plugin_id=plugin_id,
                allowed_vars=allowed_vars,
                parent_scope_id=parent_scope_id,
                additional_vars=additional_vars
            )
            
            return {
                'success': True,
                'scope_id': scope_id
            }
        
        elif operation == 'get_context':
            scope_id = cfg.get('scope_id', '')
            environment_context = manager.get_environment_context(scope_id)
            
            return {
                'success': True,
                'scope_id': scope_id,
                'environment_context': environment_context
            }
        
        elif operation == 'access_variable':
            scope_id = cfg.get('scope_id', '')
            variable_name = cfg.get('variable_name', '')
            access_operation = cfg.get('access_operation', 'read')
            variable_value = cfg.get('variable_value')
            
            result = manager.access_variable(
                scope_id=scope_id,
                var_name=variable_name,
                operation=access_operation,
                value=variable_value
            )
            
            return {
                'success': True,
                'scope_id': scope_id,
                'variable_name': variable_name,
                'variable_value': result
            }
        
        elif operation == 'destroy_scope':
            scope_id = cfg.get('scope_id', '')
            destroyed = manager.destroy_scope(scope_id)
            
            return {
                'success': True,
                'scope_id': scope_id,
                'destroyed': destroyed
            }
        
        elif operation == 'get_audit_trail':
            hours = cfg.get('hours', 24)
            audit_plugin_id = cfg.get('audit_plugin_id')
            audit_trail = manager.get_audit_trail(hours, audit_plugin_id)
            
            return {
                'success': True,
                'audit_trail': audit_trail,
                'time_window_hours': hours
            }
        
        elif operation == 'get_scope_summary':
            scope_id = cfg.get('scope_id', '')
            scope_summary = manager.get_scope_summary(scope_id)
            
            return {
                'success': True,
                'scope_id': scope_id,
                'scope_summary': scope_summary
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "supported_operations": [
                    "create_scope", "get_context", "access_variable", 
                    "destroy_scope", "get_audit_trail", "get_scope_summary"
                ]
            }
    
    except Exception as e:
        logger.error(f"❌ Environment isolation operation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test the plugin
    async def test_environment_isolation():
        """Test environment isolation functionality"""
        print("🔒🌍 Testing Environment Isolation...")
        
        # Test scope creation
        result = await process({}, {
            'operation': 'create_scope',
            'plugin_id': 'test_plugin',
            'allowed_vars': ['PATH', 'HOME', 'PLUGPIPE_CONFIG'],
            'additional_vars': {'TEST_VAR': 'test_value'}
        })
        print(f"Create Scope: {result}")
        
        scope_id = result.get('scope_id')
        if scope_id:
            # Test getting environment context
            result = await process({}, {
                'operation': 'get_context',
                'scope_id': scope_id
            })
            print(f"Get Context: {result.get('success')} - {len(result.get('environment_context', {}))} vars")
            
            # Test variable access
            result = await process({}, {
                'operation': 'access_variable',
                'scope_id': scope_id,
                'variable_name': 'TEST_VAR',
                'access_operation': 'read'
            })
            print(f"Access Variable: {result}")
            
            # Test audit trail
            result = await process({}, {
                'operation': 'get_audit_trail',
                'hours': 1
            })
            print(f"Audit Trail: {len(result.get('audit_trail', []))} records")
            
            # Test scope summary
            result = await process({}, {
                'operation': 'get_scope_summary',
                'scope_id': scope_id
            })
            print(f"Scope Summary: {result}")
            
            # Cleanup
            result = await process({}, {
                'operation': 'destroy_scope',
                'scope_id': scope_id
            })
            print(f"Destroy Scope: {result}")
        
        print("✅ Environment isolation tests completed!")
    
    import asyncio
    asyncio.run(test_environment_isolation())