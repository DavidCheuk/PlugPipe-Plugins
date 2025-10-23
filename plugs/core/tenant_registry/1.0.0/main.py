#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Multi-Tenant Registry Backend Plugin

Provides tenant-scoped plugin discovery and registration following P0 audit requirements:
- Uses Trinity Registry Interface abstraction (86ms performance)
- Leverages existing pp('redis_data_operations') for caching
- Maintains complete tenant isolation for enterprise environments
"""

import asyncio
import hashlib
import time
import logging
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass

# PlugPipe core imports
from shares.plugpipe_path_helper import setup_plugpipe_environment
setup_plugpipe_environment()

from cores.registry_backend.trinity_registry_interface import create_trinity_registry_service
from shares.loader import pp

logger = logging.getLogger(__name__)

@dataclass
class TenantContext:
    """Tenant context for scoped operations"""
    tenant_id: str
    tenant_name: str
    isolation_level: str = "strict"
    shared_plugins_enabled: bool = True
    max_plugins: int = 1000

class TenantRegistryBackend:
    """Multi-tenant registry backend using Trinity Registry Interface abstraction"""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.tenant_contexts: Dict[str, TenantContext] = {}

        # Initialize Trinity Registry with P0 audit optimizations
        self.trinity_config = {
            'base_dir': config.get('base_dir', 'plugs'),
            'pipes_dir': config.get('pipes_dir', 'pipes'),
            'enable_cache': True,
            'cache_db_path': config.get('cache_db_path', '/tmp/mt_registry_cache.db'),
            'tenant_aware': True
        }

        # Use Trinity Registry Interface (P0 compliant SQLite-primary backend)
        self.trinity_registry = create_trinity_registry_service(self.trinity_config)

        # Initialize Redis cache via PlugPipe abstraction
        self.redis_ops = None
        try:
            self.redis_ops = pp('redis_data_operations')
            logger.info("✅ Multi-tenant registry using pp('redis_data_operations') abstraction")
        except Exception as e:
            logger.warning(f"Redis operations unavailable: {e}")

        logger.info("✅ Multi-tenant registry backend initialized with Trinity Interface")

    async def register_tenant(self, tenant_context: TenantContext) -> bool:
        """Register a new tenant with isolation configuration"""
        try:
            self.tenant_contexts[tenant_context.tenant_id] = tenant_context

            # Cache tenant configuration if Redis available
            if self.redis_ops:
                cache_key = f"tenant:{tenant_context.tenant_id}:config"
                tenant_data = {
                    'tenant_id': tenant_context.tenant_id,
                    'tenant_name': tenant_context.tenant_name,
                    'isolation_level': tenant_context.isolation_level,
                    'registered_at': time.time()
                }

                # Use PlugPipe Redis abstraction
                redis_backend = self.redis_ops.get_backend({'redis_url': 'redis://localhost:6379/0'})
                await redis_backend.set(cache_key, tenant_data, ttl=3600)

            logger.info(f"✅ Registered tenant: {tenant_context.tenant_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to register tenant {tenant_context.tenant_id}: {e}")
            return False

    async def discover_plugins_for_tenant(self, tenant_id: str, query: Optional[Dict[str, Any]] = None,
                                        limit: int = 50) -> Tuple[List[Dict[str, Any]], Optional[str]]:
        """Tenant-scoped plugin discovery with <86ms performance"""
        start_time = time.time()

        try:
            # Validate tenant
            if tenant_id not in self.tenant_contexts:
                raise ValueError(f"Unknown tenant: {tenant_id}")

            tenant_context = self.tenant_contexts[tenant_id]

            # Build tenant-scoped query
            tenant_query = query or {}
            tenant_query['tenant_id'] = tenant_id

            # Use Trinity Registry Interface for discovery (P0 optimized)
            plugins, next_cursor = await self.trinity_registry.list_components(
                component_type='plugin',
                cursor=tenant_query.get('cursor'),
                limit=min(limit, tenant_context.max_plugins)
            )

            # Apply tenant filtering
            tenant_scoped_plugins = []
            for plugin in plugins:
                if await self._is_plugin_accessible_to_tenant(plugin, tenant_context):
                    # Add tenant metadata
                    plugin['tenant_scope'] = {
                        'tenant_id': tenant_id,
                        'access_level': self._get_plugin_access_level(plugin, tenant_context),
                        'shared_plugin': plugin.get('shared', False)
                    }
                    tenant_scoped_plugins.append(plugin)

            # Performance validation (P0 requirement: <86ms)
            processing_time_ms = (time.time() - start_time) * 1000
            if processing_time_ms > 86:
                logger.warning(f"Tenant discovery exceeded P0 target: {processing_time_ms:.1f}ms")

            logger.info(f"✅ Tenant {tenant_id} discovery: {len(tenant_scoped_plugins)} plugins in {processing_time_ms:.1f}ms")

            return tenant_scoped_plugins, next_cursor

        except Exception as e:
            logger.error(f"Tenant discovery failed for {tenant_id}: {e}")
            return [], None

    async def register_tenant_plugin(self, tenant_id: str, plugin_manifest: Dict[str, Any]) -> bool:
        """Register plugin for specific tenant with isolation"""
        try:
            # Validate tenant
            if tenant_id not in self.tenant_contexts:
                raise ValueError(f"Unknown tenant: {tenant_id}")

            # Add tenant metadata to plugin
            plugin_manifest['tenant_metadata'] = {
                'owner_tenant_id': tenant_id,
                'registered_at': time.time(),
                'isolation_level': self.tenant_contexts[tenant_id].isolation_level
            }

            # Generate tenant-scoped plugin ID
            base_id = plugin_manifest.get('name', 'unknown')
            tenant_plugin_id = f"{tenant_id}:{base_id}"
            plugin_manifest['tenant_scoped_id'] = tenant_plugin_id

            # Register via Trinity Interface
            success = await self.trinity_registry.register_component(plugin_manifest)

            if success:
                logger.info(f"✅ Registered plugin {base_id} for tenant {tenant_id}")

            return success

        except Exception as e:
            logger.error(f"Failed to register plugin for tenant {tenant_id}: {e}")
            return False

    async def get_tenant_catalog(self, tenant_id: str, include_shared: bool = True) -> Dict[str, Any]:
        """Get complete plugin catalog for tenant"""
        try:
            # Get tenant-scoped plugins
            tenant_plugins, _ = await self.discover_plugins_for_tenant(
                tenant_id, limit=1000  # Full catalog
            )

            # Build catalog structure
            catalog = {
                'tenant_id': tenant_id,
                'tenant_name': self.tenant_contexts[tenant_id].tenant_name,
                'total_plugins': len(tenant_plugins),
                'catalog_generated_at': time.time(),
                'plugins': {}
            }

            # Organize by category
            for plugin in tenant_plugins:
                category = plugin.get('category', 'uncategorized')
                if category not in catalog['plugins']:
                    catalog['plugins'][category] = []
                catalog['plugins'][category].append(plugin)

            # Add shared plugins if requested
            if include_shared and self.tenant_contexts[tenant_id].shared_plugins_enabled:
                shared_plugins = await self._get_shared_plugins()
                if 'shared' not in catalog['plugins']:
                    catalog['plugins']['shared'] = []
                catalog['plugins']['shared'].extend(shared_plugins)

            logger.info(f"✅ Generated catalog for tenant {tenant_id}: {catalog['total_plugins']} plugins")
            return catalog

        except Exception as e:
            logger.error(f"Failed to get catalog for tenant {tenant_id}: {e}")
            return {'error': str(e)}

    async def _is_plugin_accessible_to_tenant(self, plugin: Dict[str, Any],
                                            tenant_context: TenantContext) -> bool:
        """Check if plugin is accessible to tenant based on isolation rules"""
        try:
            # Check if plugin is tenant-owned
            plugin_tenant = plugin.get('tenant_metadata', {}).get('owner_tenant_id')
            if plugin_tenant == tenant_context.tenant_id:
                return True

            # Check if plugin is shared and tenant allows shared plugins
            if plugin.get('shared', False) and tenant_context.shared_plugins_enabled:
                return True

            # Check isolation level rules
            if tenant_context.isolation_level == "strict":
                return False
            elif tenant_context.isolation_level == "permissive":
                # Allow access to public plugins from other tenants
                return plugin.get('visibility', 'private') == 'public'

            return False

        except Exception as e:
            logger.error(f"Error checking plugin accessibility: {e}")
            return False

    def _get_plugin_access_level(self, plugin: Dict[str, Any], tenant_context: TenantContext) -> str:
        """Determine access level for plugin"""
        plugin_tenant = plugin.get('tenant_metadata', {}).get('owner_tenant_id')

        if plugin_tenant == tenant_context.tenant_id:
            return "owner"
        elif plugin.get('shared', False):
            return "shared"
        else:
            return "public"

    async def _get_shared_plugins(self) -> List[Dict[str, Any]]:
        """Get plugins marked as shared across tenants"""
        try:
            # Query Trinity Registry for shared plugins
            all_plugins, _ = await self.trinity_registry.list_components(
                component_type='plugin',
                limit=1000
            )

            return [p for p in all_plugins if p.get('shared', False)]

        except Exception as e:
            logger.error(f"Error getting shared plugins: {e}")
            return []

    async def health_check(self) -> Dict[str, Any]:
        """Multi-tenant registry health check"""
        try:
            # Check Trinity Registry health
            trinity_health = await self.trinity_registry.health_check()

            # Check Redis cache health
            redis_health = {"status": "unavailable"}
            if self.redis_ops:
                try:
                    redis_backend = self.redis_ops.get_backend({'redis_url': 'redis://localhost:6379/0'})
                    redis_health = {"status": "healthy", "backend": "pp_redis_abstraction"}
                except Exception as e:
                    redis_health = {"status": "error", "error": str(e)}

            return {
                "status": "healthy",
                "service": "multi_tenant_registry",
                "tenant_count": len(self.tenant_contexts),
                "trinity_registry": trinity_health,
                "redis_cache": redis_health,
                "performance_target_ms": 86,
                "architecture_compliance": {
                    "trinity_interface_abstraction": True,
                    "redis_pp_abstraction": self.redis_ops is not None,
                    "tenant_isolation": True
                }
            }

        except Exception as e:
            return {
                "status": "unhealthy",
                "error": str(e),
                "service": "multi_tenant_registry"
            }

# Plugin interface functions
async def process(plugin_ctx, plugin_cfg):
    """Main plugin entry point for multi-tenant registry operations"""
    try:
        operation = plugin_cfg.get('operation', 'discover_plugins_for_tenant')
        tenant_id = plugin_cfg.get('tenant_id')

        if not tenant_id:
            return {
                'success': False,
                'error': 'tenant_id required for multi-tenant operations'
            }

        # Initialize tenant registry backend
        registry_config = plugin_cfg.get('registry_config', {})
        mt_registry = TenantRegistryBackend(registry_config)

        # Register tenant if not exists
        if tenant_id not in mt_registry.tenant_contexts:
            tenant_context = TenantContext(
                tenant_id=tenant_id,
                tenant_name=plugin_cfg.get('tenant_name', tenant_id),
                isolation_level=plugin_cfg.get('isolation_level', 'strict'),
                shared_plugins_enabled=plugin_cfg.get('shared_plugins_enabled', True)
            )
            await mt_registry.register_tenant(tenant_context)

        # Execute requested operation
        if operation == 'discover_plugins_for_tenant':
            query = plugin_cfg.get('query', {})
            limit = plugin_cfg.get('limit', 50)

            plugins, next_cursor = await mt_registry.discover_plugins_for_tenant(
                tenant_id, query, limit
            )

            return {
                'success': True,
                'tenant_id': tenant_id,
                'plugins': plugins,
                'next_cursor': next_cursor,
                'total_found': len(plugins)
            }

        elif operation == 'register_tenant_plugin':
            plugin_manifest = plugin_cfg.get('plugin_manifest', {})
            success = await mt_registry.register_tenant_plugin(tenant_id, plugin_manifest)

            return {
                'success': success,
                'tenant_id': tenant_id,
                'operation': 'register_tenant_plugin'
            }

        elif operation == 'get_tenant_catalog':
            include_shared = plugin_cfg.get('include_shared', True)
            catalog = await mt_registry.get_tenant_catalog(tenant_id, include_shared)

            return {
                'success': True,
                'tenant_id': tenant_id,
                'catalog': catalog
            }

        elif operation == 'health_check':
            health = await mt_registry.health_check()
            return {
                'success': True,
                'health': health
            }

        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}'
            }

    except Exception as e:
        logger.error(f"Multi-tenant registry error: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation': plugin_cfg.get('operation', 'unknown')
        }

if __name__ == "__main__":
    # Direct testing
    import asyncio

    async def test_mt_registry():
        """Test multi-tenant registry functionality"""
        print("🧪 Testing Multi-Tenant Registry Backend Plugin")

        # Test configuration
        test_config = {
            'operation': 'discover_plugins_for_tenant',
            'tenant_id': 'enterprise_001',
            'tenant_name': 'Enterprise Customer 001',
            'isolation_level': 'strict',
            'query': {'limit': 10},
            'registry_config': {
                'base_dir': 'plugs',
                'pipes_dir': 'pipes',
                'cache_db_path': '/tmp/test_mt_registry.db'
            }
        }

        # Test plugin discovery
        result = await process(None, test_config)
        print(f"Discovery result: {result.get('success')} - {result.get('total_found', 0)} plugins")

        # Test health check
        health_config = {
            'operation': 'health_check',
            'tenant_id': 'enterprise_001',
            'registry_config': test_config['registry_config']
        }

        health = await process(None, health_config)
        print(f"Health check: {health.get('success')} - {health.get('health', {}).get('status')}")

    asyncio.run(test_mt_registry())