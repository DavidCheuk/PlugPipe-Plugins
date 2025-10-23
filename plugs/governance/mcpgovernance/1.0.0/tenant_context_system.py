#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Tenant Context System for PlugPipe P0 Multi-Tenant Security
Implements basic tenant isolation infrastructure
"""

from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from enum import Enum
import asyncio

class AccessLevel(Enum):
    READ = "read"
    WRITE = "write"
    ADMIN = "admin"

@dataclass
class TenantContext:
    """Tenant security context for API operations"""
    tenant_id: str
    user_id: Optional[str] = None
    access_level: AccessLevel = AccessLevel.READ
    permissions: List[str] = None

    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []

    def has_permission(self, operation: str) -> bool:
        """Check if tenant has permission for specific operation"""
        if self.access_level == AccessLevel.ADMIN:
            return True
        return operation in self.permissions

    def can_access_plugin(self, plugin_id: str, plugin_owner: str = None) -> bool:
        """Check if tenant can access specific plugin"""
        # Basic implementation - can be extended with more sophisticated rules
        if self.access_level == AccessLevel.ADMIN:
            return True

        # For now, tenants can only access their own plugins
        if plugin_owner:
            return plugin_owner == self.tenant_id

        # Default to deny access if no owner information
        return False

class TenantContextExtractor:
    """Extract tenant context from HTTP headers"""

    @staticmethod
    def extract_from_headers(headers: Dict[str, str]) -> Optional[TenantContext]:
        """Extract tenant context from HTTP request headers"""
        tenant_id = headers.get('X-Tenant-ID') or headers.get('x-tenant-id')
        if not tenant_id:
            return None

        user_id = headers.get('X-User-ID') or headers.get('x-user-id')
        auth_header = headers.get('Authorization') or headers.get('authorization')

        # Basic access level determination
        access_level = AccessLevel.READ
        if auth_header and 'admin' in auth_header.lower():
            access_level = AccessLevel.ADMIN
        elif auth_header and 'write' in auth_header.lower():
            access_level = AccessLevel.WRITE

        return TenantContext(
            tenant_id=tenant_id,
            user_id=user_id,
            access_level=access_level
        )

    @staticmethod
    def extract_from_request_dict(request_data: Dict[str, Any]) -> Optional[TenantContext]:
        """Extract tenant context from request data dictionary"""
        if 'headers' in request_data:
            return TenantContextExtractor.extract_from_headers(request_data['headers'])
        return None

class TenantAwareRegistryService:
    """Tenant-aware wrapper for registry service operations"""

    def __init__(self, base_registry_service):
        self.base_registry = base_registry_service

    async def list_plugs_for_tenant(self, tenant_context: TenantContext, **kwargs) -> tuple:
        """List plugins filtered by tenant access"""
        if not tenant_context:
            raise ValueError("Tenant context required")

        # Get all plugins from base registry
        all_plugins, cursor = await self.base_registry.list_plugs(**kwargs)

        # Filter plugins based on tenant access
        filtered_plugins = []
        for plugin in all_plugins:
            plugin_owner = plugin.get('owner') or plugin.get('tenant_id')
            if tenant_context.can_access_plugin(plugin.get('id', ''), plugin_owner):
                filtered_plugins.append(plugin)

        return filtered_plugins, cursor

    async def get_plugin_for_tenant(self, tenant_context: TenantContext, plugin_id: str) -> Optional[Dict[str, Any]]:
        """Get plugin only if tenant has access"""
        if not tenant_context:
            raise ValueError("Tenant context required")

        plugin = await self.base_registry.get_plugin_by_id(plugin_id)
        if not plugin:
            return None

        plugin_owner = plugin.get('owner') or plugin.get('tenant_id')
        if not tenant_context.can_access_plugin(plugin_id, plugin_owner):
            return None  # Tenant doesn't have access

        return plugin

    async def search_plugs_for_tenant(self, tenant_context: TenantContext, query: str, **kwargs) -> tuple:
        """Search plugins filtered by tenant access"""
        if not tenant_context:
            raise ValueError("Tenant context required")

        # Get search results from base registry
        all_results, cursor = await self.base_registry.search_plugs(query, **kwargs)

        # Filter results based on tenant access
        filtered_results = []
        for plugin in all_results:
            plugin_owner = plugin.get('owner') or plugin.get('tenant_id')
            if tenant_context.can_access_plugin(plugin.get('id', ''), plugin_owner):
                filtered_results.append(plugin)

        return filtered_results, cursor

def create_tenant_aware_registry(base_registry):
    """Factory function to create tenant-aware registry service"""
    return TenantAwareRegistryService(base_registry)

async def test_tenant_context_system():
    """Test the tenant context system functionality"""
    print("🧪 Testing Tenant Context System...")

    # Test TenantContext
    tenant_ctx = TenantContext(
        tenant_id="tenant-alpha",
        user_id="user-123",
        access_level=AccessLevel.READ
    )

    print(f"✅ Tenant Context: {tenant_ctx.tenant_id}")
    print(f"✅ Access Level: {tenant_ctx.access_level.value}")
    print(f"✅ Can access own plugin: {tenant_ctx.can_access_plugin('plugin-1', 'tenant-alpha')}")
    print(f"❌ Can access other plugin: {tenant_ctx.can_access_plugin('plugin-2', 'tenant-beta')}")

    # Test TenantContextExtractor
    headers = {
        'X-Tenant-ID': 'tenant-alpha',
        'X-User-ID': 'user-123',
        'Authorization': 'Bearer admin-token'
    }

    extracted_ctx = TenantContextExtractor.extract_from_headers(headers)
    print(f"✅ Extracted Context: {extracted_ctx.tenant_id if extracted_ctx else 'None'}")
    print(f"✅ Extracted Access Level: {extracted_ctx.access_level.value if extracted_ctx else 'None'}")

    print("🎯 Tenant Context System Test Complete")

if __name__ == "__main__":
    asyncio.run(test_tenant_context_system())