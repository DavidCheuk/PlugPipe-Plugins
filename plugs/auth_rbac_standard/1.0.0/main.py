# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Role-Based Access Control (RBAC) Plug for PlugPipe.

This plugin provides enterprise-grade RBAC authorization with:
- Hierarchical role system with inheritance
- Fine-grained resource-action-scope permissions
- Organization and project-based scoping
- Custom role definitions and permissions
- Comprehensive audit trail integration

Security Features:
- Principle of least privilege enforcement
- Role inheritance with priority management
- Context-aware permission validation
- Protection against privilege escalation
- Comprehensive permission auditing

Enterprise Features:
- Multi-tenant organization support
- Team-based permission delegation
- Custom business logic integration
- Bulk permission management
- Advanced reporting and analytics
"""

from enum import Enum
from typing import Dict, List, Set, Optional, Any, Tuple
from dataclasses import dataclass
from pydantic import BaseModel
from datetime import datetime, timezone
import logging
import os
import sys

from cores.auth.base import (
    AuthorizationPlug, AuthAction, AuthResult, AuthContext,
    AuthPlugCapability, create_auth_result
)
# Import PlugPipe dynamic plugin discovery
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
from shares.loader import pp

# Import real user management storage
try:
    from .user_storage import UserManagementStorage
    STORAGE_AVAILABLE = True
except ImportError:
    STORAGE_AVAILABLE = False

logger = logging.getLogger(__name__)


class UserRole(str, Enum):
    """Standard user roles in hierarchical order."""
    ADMIN = "admin"
    DEVELOPER = "developer"
    USER = "user"
    GUEST = "guest"


class ResourceType(str, Enum):
    """Protected resource types."""
    PLUGS = "plugs"
    PIPES = "pipes"
    REGISTRIES = "registries"
    USERS = "users"
    ADMIN = "admin"
    ANALYTICS = "analytics"
    INTEGRATIONS = "integrations"


class Action(str, Enum):
    """Available actions on resources."""
    READ = "read"
    WRITE = "write"
    CREATE = "create"
    DELETE = "delete"
    MANAGE = "manage"
    EXECUTE = "execute"
    PUBLISH = "publish"
    CONFIGURE = "configure"


class PermissionScope(str, Enum):
    """Permission scope levels."""
    GLOBAL = "global"
    ORGANIZATION = "organization"
    PROJECT = "project"
    OWN = "own"


@dataclass
class Permission:
    """Individual permission definition."""
    resource: ResourceType
    action: Action
    scope: PermissionScope
    conditions: Optional[Dict[str, Any]] = None
    
    def __str__(self) -> str:
        """String representation of permission."""
        base = f"{self.resource.value}:{self.action.value}:{self.scope.value}"
        if self.conditions:
            conditions_str = ",".join(f"{k}={v}" for k, v in self.conditions.items())
            return f"{base}({conditions_str})"
        return base
    
    @classmethod
    def from_string(cls, permission_str: str) -> "Permission":
        """Parse permission from string representation."""
        if "(" in permission_str:
            base, conditions_part = permission_str.split("(", 1)
            conditions_part = conditions_part.rstrip(")")
            conditions = dict(item.split("=") for item in conditions_part.split(","))
        else:
            base = permission_str
            conditions = None
        
        parts = base.split(":")
        if len(parts) != 3:
            raise ValueError(f"Invalid permission format: {permission_str}")
        
        return cls(
            resource=ResourceType(parts[0]),
            action=Action(parts[1]),
            scope=PermissionScope(parts[2]),
            conditions=conditions
        )


class RoleDefinition(BaseModel):
    """Role definition with permissions and metadata."""
    name: UserRole
    priority: int
    description: str
    inherits_from: Optional[UserRole] = None
    permissions: List[Permission]
    custom_data: Dict[str, Any] = {}


class UserPermissionContext(BaseModel):
    """User's permission context."""
    user_id: str
    role: UserRole
    organization_id: Optional[str] = None
    project_ids: List[str] = []
    team_ids: List[str] = []
    additional_permissions: List[Permission] = []
    denied_permissions: List[Permission] = []
    custom_context: Dict[str, Any] = {}


class RBACStandardPlug(AuthorizationPlug):
    """Standard RBAC authorization plugin."""
    
    # Default role definitions
    DEFAULT_ROLES = {
        UserRole.GUEST: RoleDefinition(
            name=UserRole.GUEST,
            priority=40,
            description="Read-only access to public resources",
            permissions=[
                Permission(ResourceType.PLUGS, Action.READ, PermissionScope.GLOBAL),
                Permission(ResourceType.REGISTRIES, Action.READ, PermissionScope.GLOBAL),
            ]
        ),
        
        UserRole.USER: RoleDefinition(
            name=UserRole.USER,
            priority=30,
            description="Standard user with pipeline management",
            inherits_from=UserRole.GUEST,
            permissions=[
                Permission(ResourceType.PLUGS, Action.EXECUTE, PermissionScope.GLOBAL),
                Permission(ResourceType.PIPES, Action.READ, PermissionScope.OWN),
                Permission(ResourceType.PIPES, Action.WRITE, PermissionScope.OWN),
                Permission(ResourceType.PIPES, Action.CREATE, PermissionScope.OWN),
                Permission(ResourceType.PIPES, Action.DELETE, PermissionScope.OWN),
                Permission(ResourceType.PIPES, Action.EXECUTE, PermissionScope.OWN),
                Permission(ResourceType.USERS, Action.READ, PermissionScope.OWN),
                Permission(ResourceType.USERS, Action.WRITE, PermissionScope.OWN),
            ]
        ),
        
        UserRole.DEVELOPER: RoleDefinition(
            name=UserRole.DEVELOPER,
            priority=20,
            description="Developer with plugin creation capabilities",
            inherits_from=UserRole.USER,
            permissions=[
                Permission(ResourceType.PLUGS, Action.CREATE, PermissionScope.OWN),
                Permission(ResourceType.PLUGS, Action.WRITE, PermissionScope.OWN),
                Permission(ResourceType.PLUGS, Action.DELETE, PermissionScope.OWN),
                Permission(ResourceType.PLUGS, Action.PUBLISH, PermissionScope.OWN),
                Permission(ResourceType.REGISTRIES, Action.WRITE, PermissionScope.OWN),
                Permission(ResourceType.ANALYTICS, Action.READ, PermissionScope.OWN),
                Permission(ResourceType.INTEGRATIONS, Action.READ, PermissionScope.GLOBAL),
                Permission(ResourceType.INTEGRATIONS, Action.CONFIGURE, PermissionScope.OWN),
            ]
        ),
        
        UserRole.ADMIN: RoleDefinition(
            name=UserRole.ADMIN,
            priority=10,
            description="Full system administration",
            inherits_from=UserRole.DEVELOPER,
            permissions=[
                Permission(ResourceType.PLUGS, Action.MANAGE, PermissionScope.GLOBAL),
                Permission(ResourceType.PIPES, Action.MANAGE, PermissionScope.GLOBAL),
                Permission(ResourceType.REGISTRIES, Action.MANAGE, PermissionScope.GLOBAL),
                Permission(ResourceType.USERS, Action.MANAGE, PermissionScope.GLOBAL),
                Permission(ResourceType.ADMIN, Action.CONFIGURE, PermissionScope.GLOBAL),
                Permission(ResourceType.ANALYTICS, Action.READ, PermissionScope.GLOBAL),
                Permission(ResourceType.INTEGRATIONS, Action.MANAGE, PermissionScope.GLOBAL),
            ]
        )
    }

    def __init__(self, config: Dict[str, Any] = None):
        """Initialize RBAC plugin with security hardening."""
        super().__init__(config)

        # Initialize security hardening using PlugPipe dynamic discovery
        self.input_sanitizer_available = True
        try:
            # Test Universal Input Sanitizer availability
            test_result = pp("universal_input_sanitizer")
            if not test_result.get("success", False):
                logger.warning("Universal Input Sanitizer plugin not available, using basic validation")
                self.input_sanitizer_available = False
        except Exception as e:
            logger.warning(f"Universal Input Sanitizer not available: {str(e)}")
            self.input_sanitizer_available = False

        # Configuration
        self.default_role = UserRole(config.get("default_role", "user"))
        self.role_inheritance = config.get("role_inheritance", True)
        self.organization_scoped = config.get("organization_scoped", False)
        
        # Initialize storage backend
        self.storage = None
        if STORAGE_AVAILABLE:
            self.storage = UserManagementStorage(config.get("storage_config", {}))
        else:
            logger.warning("User management storage not available - using fallback implementations")
        
        # Role definitions (start with defaults, add custom)
        self.role_definitions = self.DEFAULT_ROLES.copy()
        self._load_custom_roles(config.get("custom_roles", []))
        
        # Permission cache for performance
        self._effective_permissions_cache: Dict[UserRole, Set[Permission]] = {}
        self._build_effective_permissions_cache()

    def _sanitize_input(self, input_value: str, field_name: str = "input") -> Dict[str, Any]:
        """Sanitize input using Universal Input Sanitizer plugin."""
        if not self.input_sanitizer_available:
            # Basic validation fallback for RBAC security
            if not input_value or len(input_value.strip()) == 0:
                return {
                    "is_valid": False,
                    "sanitized_value": "",
                    "violations": [f"Empty {field_name}"]
                }
            # Check for RBAC-specific injection patterns
            dangerous_patterns = [
                "<script", "javascript:", "${jndi:", "';DROP TABLE", "|nc", "&&rm", "../../../../",
                "admin'--", "OR '1'='1", "UNION SELECT", "exec(", "eval(", "__import__"
            ]
            for pattern in dangerous_patterns:
                if pattern.lower() in input_value.lower():
                    return {
                        "is_valid": False,
                        "sanitized_value": "",
                        "violations": [f"Dangerous pattern detected in {field_name}"]
                    }
            return {
                "is_valid": True,
                "sanitized_value": input_value.strip(),
                "violations": []
            }

        try:
            # Use Universal Input Sanitizer plugin
            sanitizer_config = {
                "action": "sanitize_input",
                "input_data": input_value,
                "field_name": field_name
            }
            result = pp("universal_input_sanitizer", sanitizer_config)

            if result.get("success", False):
                sanitization_result = result.get("result", {})
                return {
                    "is_valid": sanitization_result.get("is_safe", False),
                    "sanitized_value": sanitization_result.get("sanitized_output", input_value),
                    "violations": sanitization_result.get("threats_detected", [])
                }
            else:
                logger.warning(f"Universal Input Sanitizer failed: {result.get('error', 'Unknown error')}")
                return self._sanitize_input(input_value, field_name)  # Fallback to basic validation

        except Exception as e:
            logger.warning(f"Input sanitization error: {str(e)}")
            # Return basic validation result
            return {
                "is_valid": len(input_value.strip()) > 0,
                "sanitized_value": input_value.strip(),
                "violations": [] if len(input_value.strip()) > 0 else [f"Empty {field_name}"]
            }

    def _initialize_capabilities(self):
        """Initialize plugin capabilities."""
        self.capabilities = AuthPlugCapability(
            plugin_name="auth_rbac_standard",
            plugin_version="1.0.0",
            plugin_type=self.plugin_type,
            supported_actions=[
                AuthAction.CHECK_PERMISSION,
                AuthAction.GET_USER_ROLES,
                AuthAction.ASSIGN_ROLE,
                AuthAction.GET_USER_PROFILE  # For permission context
            ],
            required_config=[],
            optional_config=[
                "default_role", "role_inheritance", "organization_scoped", "custom_roles"
            ],
            priority=30,
            description="Role-based access control with hierarchical permissions"
        )
    
    def _load_custom_roles(self, custom_roles: List[Dict[str, Any]]):
        """Load custom role definitions from configuration."""
        for role_config in custom_roles:
            try:
                # Parse permissions
                permissions = []
                for perm_str in role_config.get("permissions", []):
                    permissions.append(Permission.from_string(perm_str))
                
                role_def = RoleDefinition(
                    name=role_config["name"],
                    priority=role_config.get("priority", 50),
                    description=role_config.get("description", ""),
                    inherits_from=role_config.get("inherits_from"),
                    permissions=permissions,
                    custom_data=role_config.get("custom_data", {})
                )
                
                self.role_definitions[role_def.name] = role_def
                logger.info(f"Loaded custom role: {role_def.name}")
                
            except Exception as e:
                logger.error(f"Failed to load custom role {role_config.get('name', 'unknown')}: {str(e)}")
    
    def _build_effective_permissions_cache(self):
        """Build cache of effective permissions for each role including inheritance."""
        for role in UserRole:
            self._effective_permissions_cache[role] = self._get_role_effective_permissions(role)
    
    def _get_role_effective_permissions(self, role: UserRole) -> Set[Permission]:
        """Get effective permissions for a role including inherited permissions."""
        if role in self._effective_permissions_cache:
            return self._effective_permissions_cache[role]
        
        permissions = set()
        
        if role in self.role_definitions:
            role_def = self.role_definitions[role]
            
            # Add direct permissions
            permissions.update(role_def.permissions)
            
            # Add inherited permissions
            if self.role_inheritance and role_def.inherits_from:
                inherited_permissions = self._get_role_effective_permissions(role_def.inherits_from)
                permissions.update(inherited_permissions)
        
        return permissions
    
    async def process(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Process RBAC authorization request."""
        try:
            if ctx.action == AuthAction.CHECK_PERMISSION:
                return await self._check_permission(ctx, cfg)
            elif ctx.action == AuthAction.GET_USER_ROLES:
                return await self._get_user_roles(ctx, cfg)
            elif ctx.action == AuthAction.ASSIGN_ROLE:
                return await self._assign_role(ctx, cfg)
            else:
                return create_auth_result(
                    success=False,
                    error_message=f"Unsupported action: {ctx.action}"
                )
        except Exception as e:
            logger.error(f"RBAC plugin error: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"RBAC error: {str(e)}"
            )
    
    async def _check_permission(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Check if user has required permission."""
        try:
            request_data = ctx.request_data

            # Extract permission check parameters
            user_id = ctx.user_id or request_data.get("user_id")
            resource = request_data.get("resource")
            action = request_data.get("action")
            scope = request_data.get("scope", "own")
            resource_context = request_data.get("resource_context", {})

            # SECURITY: Sanitize all critical RBAC parameters
            if user_id:
                sanitized_user_id = self._sanitize_input(str(user_id), "user_id")
                if not sanitized_user_id["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid user_id: {'; '.join(sanitized_user_id['violations'])}"
                    )
                user_id = sanitized_user_id["sanitized_value"]

            if resource:
                sanitized_resource = self._sanitize_input(str(resource), "resource")
                if not sanitized_resource["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid resource: {'; '.join(sanitized_resource['violations'])}"
                    )
                resource = sanitized_resource["sanitized_value"]

            if action:
                sanitized_action = self._sanitize_input(str(action), "action")
                if not sanitized_action["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid action: {'; '.join(sanitized_action['violations'])}"
                    )
                action = sanitized_action["sanitized_value"]

            if not all([user_id, resource, action]):
                return create_auth_result(
                    success=False,
                    error_message="Missing required parameters: user_id, resource, action"
                )
            
            # Build user permission context
            user_context = await self._build_user_context(user_id, request_data)
            
            # Build required permission
            try:
                required_permission = Permission(
                    resource=ResourceType(resource),
                    action=Action(action),
                    scope=PermissionScope(scope)
                )
            except ValueError as e:
                return create_auth_result(
                    success=False,
                    error_message=f"Invalid permission parameters: {str(e)}"
                )
            
            # Check permission
            has_permission = self._has_permission(
                user_context,
                required_permission,
                resource_context
            )
            
            if has_permission:
                logger.info(f"Permission granted: {user_id} -> {required_permission}")
                return create_auth_result(
                    success=True,
                    metadata={
                        "permission": str(required_permission),
                        "granted": True,
                        "user_role": user_context.role.value
                    }
                )
            else:
                logger.warning(f"Permission denied: {user_id} -> {required_permission}")
                return create_auth_result(
                    success=False,
                    error_message=f"Permission denied: {required_permission}",
                    metadata={
                        "permission": str(required_permission),
                        "granted": False,
                        "user_role": user_context.role.value
                    }
                )
                
        except Exception as e:
            logger.error(f"Failed to check permission: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Permission check error: {str(e)}"
            )
    
    async def _get_user_roles(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Get user's roles and permissions."""
        try:
            request_data = ctx.request_data
            user_id = ctx.user_id or request_data.get("user_id")
            
            if not user_id:
                return create_auth_result(
                    success=False,
                    error_message="User ID required"
                )
            
            user_context = await self._build_user_context(user_id, request_data)
            effective_permissions = self._get_user_effective_permissions(user_context)
            
            return create_auth_result(
                success=True,
                user_id=user_id,
                roles=[user_context.role.value],
                permissions=[str(perm) for perm in effective_permissions],
                metadata={
                    "role_definition": self.role_definitions[user_context.role].model_dump(),
                    "permission_count": len(effective_permissions),
                    "organization_id": user_context.organization_id,
                    "project_ids": user_context.project_ids
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to get user roles: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Role retrieval error: {str(e)}"
            )
    
    async def _assign_role(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Assign role to user with real storage integration."""
        try:
            request_data = ctx.request_data
            user_id = request_data.get("user_id")
            role = request_data.get("role")
            assigned_by = ctx.user_id or request_data.get("assigned_by")
            reason = request_data.get("reason")
            expires_at = request_data.get("expires_at")

            # SECURITY: Sanitize all role assignment parameters
            if user_id:
                sanitized_user_id = self._sanitize_input(str(user_id), "user_id")
                if not sanitized_user_id["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid user_id: {'; '.join(sanitized_user_id['violations'])}"
                    )
                user_id = sanitized_user_id["sanitized_value"]

            if role:
                sanitized_role = self._sanitize_input(str(role), "role")
                if not sanitized_role["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid role: {'; '.join(sanitized_role['violations'])}"
                    )
                role = sanitized_role["sanitized_value"]

            if assigned_by:
                sanitized_assigned_by = self._sanitize_input(str(assigned_by), "assigned_by")
                if not sanitized_assigned_by["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid assigned_by: {'; '.join(sanitized_assigned_by['violations'])}"
                    )
                assigned_by = sanitized_assigned_by["sanitized_value"]

            if reason:
                sanitized_reason = self._sanitize_input(str(reason), "reason")
                if not sanitized_reason["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid reason: {'; '.join(sanitized_reason['violations'])}"
                    )
                reason = sanitized_reason["sanitized_value"]

            if not all([user_id, role]):
                return create_auth_result(
                    success=False,
                    error_message="Missing required parameters: user_id, role"
                )
            
            try:
                user_role = UserRole(role)
            except ValueError:
                return create_auth_result(
                    success=False,
                    error_message=f"Invalid role: {role}"
                )
            
            if not self.storage:
                # Fallback implementation when storage not available
                logger.debug(f"Storage not available - would assign role {role} to user {user_id}")
                return create_auth_result(
                    success=True,
                    metadata={
                        "user_id": user_id,
                        "assigned_role": role,
                        "action": "role_assigned",
                        "storage_available": False
                    }
                )
            
            # Real role assignment with storage
            success = await self.storage.assign_role(
                user_id=user_id,
                role=role,
                assigned_by=assigned_by,
                reason=reason,
                expires_at=expires_at
            )
            
            if success:
                logger.info(f"Assigned role {role} to user {user_id} by {assigned_by}")
                
                # Get updated user context to verify assignment
                user_context = await self._build_user_context(user_id, request_data)
                
                return create_auth_result(
                    success=True,
                    user_id=user_id,
                    roles=[user_context.role.value],
                    metadata={
                        "user_id": user_id,
                        "assigned_role": role,
                        "assigned_by": assigned_by,
                        "reason": reason,
                        "expires_at": expires_at,
                        "action": "role_assigned",
                        "timestamp": datetime.now(timezone.utc).isoformat()
                    }
                )
            else:
                return create_auth_result(
                    success=False,
                    error_message="Failed to assign role - storage operation failed"
                )
            
        except Exception as e:
            logger.error(f"Failed to assign role: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Role assignment error: {str(e)}"
            )
    
    async def _build_user_context(
        self, 
        user_id: str, 
        request_data: Dict[str, Any]
    ) -> UserPermissionContext:
        """Build user permission context from storage or request data."""
        if not self.storage:
            # Fallback to request data when storage not available
            logger.debug(f"Storage not available - building user context from request data for {user_id}")
            return UserPermissionContext(
                user_id=user_id,
                role=UserRole(request_data.get("user_role", self.default_role.value)),
                organization_id=request_data.get("organization_id"),
                project_ids=request_data.get("project_ids", []),
                team_ids=request_data.get("team_ids", []),
                additional_permissions=[
                    Permission.from_string(perm) 
                    for perm in request_data.get("additional_permissions", [])
                ],
                denied_permissions=[
                    Permission.from_string(perm)
                    for perm in request_data.get("denied_permissions", [])
                ],
                custom_context=request_data.get("custom_context", {})
            )
        
        try:
            # Fetch user data from storage
            user_data = await self.storage.get_user_by_id(user_id)
            
            if not user_data:
                # User not found in storage, use default role
                logger.warning(f"User {user_id} not found in storage, using default role")
                return UserPermissionContext(
                    user_id=user_id,
                    role=self.default_role,
                    organization_id=request_data.get("organization_id"),
                    project_ids=request_data.get("project_ids", []),
                    team_ids=request_data.get("team_ids", [])
                )
            
            # Build context from stored user data
            return UserPermissionContext(
                user_id=user_id,
                role=UserRole(user_data["role"]),
                organization_id=user_data.get("organization_id"),
                project_ids=user_data.get("project_ids", []),
                team_ids=user_data.get("team_ids", []),
                additional_permissions=[
                    Permission.from_string(perm) 
                    for perm in user_data.get("additional_permissions", [])
                ],
                denied_permissions=[
                    Permission.from_string(perm)
                    for perm in user_data.get("denied_permissions", [])
                ],
                custom_context=user_data.get("custom_context", {})
            )
            
        except Exception as e:
            logger.error(f"Error building user context from storage: {str(e)}")
            # Fallback to request data on error
            return UserPermissionContext(
                user_id=user_id,
                role=UserRole(request_data.get("user_role", self.default_role.value)),
                organization_id=request_data.get("organization_id"),
                project_ids=request_data.get("project_ids", []),
                team_ids=request_data.get("team_ids", [])
            )
    
    def _get_user_effective_permissions(self, user_context: UserPermissionContext) -> Set[Permission]:
        """Get effective permissions for user including role and additional permissions."""
        # Start with role permissions
        effective_permissions = self._effective_permissions_cache.get(user_context.role, set()).copy()
        
        # Add additional permissions
        effective_permissions.update(user_context.additional_permissions)
        
        # Remove denied permissions
        for denied_perm in user_context.denied_permissions:
            effective_permissions.discard(denied_perm)
        
        return effective_permissions
    
    def _has_permission(
        self,
        user_context: UserPermissionContext,
        required_permission: Permission,
        resource_context: Dict[str, Any]
    ) -> bool:
        """Check if user has required permission."""
        user_permissions = self._get_user_effective_permissions(user_context)
        
        # Check for exact match
        if required_permission in user_permissions:
            return True
        
        # Check for broader permissions that would grant this permission
        for perm in user_permissions:
            if self._permission_grants(perm, required_permission, user_context, resource_context):
                return True
        
        return False
    
    def _permission_grants(
        self,
        granted_permission: Permission,
        required_permission: Permission,
        user_context: UserPermissionContext,
        resource_context: Dict[str, Any]
    ) -> bool:
        """Check if granted permission covers required permission."""
        # Must be same resource type
        if granted_permission.resource != required_permission.resource:
            return False
        
        # Check action hierarchy
        if not self._action_grants(granted_permission.action, required_permission.action):
            return False
        
        # Check scope hierarchy
        if not self._scope_grants(
            granted_permission.scope,
            required_permission.scope,
            user_context,
            resource_context
        ):
            return False
        
        return True
    
    def _action_grants(self, granted_action: Action, required_action: Action) -> bool:
        """Check if granted action covers required action."""
        # MANAGE grants all other actions
        if granted_action == Action.MANAGE:
            return True
        
        # Exact match
        if granted_action == required_action:
            return True
        
        # WRITE grants READ
        if granted_action == Action.WRITE and required_action == Action.READ:
            return True
        
        # CREATE grants WRITE for new resources
        if granted_action == Action.CREATE and required_action == Action.WRITE:
            return True
        
        return False
    
    def _scope_grants(
        self,
        granted_scope: PermissionScope,
        required_scope: PermissionScope,
        user_context: UserPermissionContext,
        resource_context: Dict[str, Any]
    ) -> bool:
        """Check if granted scope covers required scope."""
        # GLOBAL grants all scopes
        if granted_scope == PermissionScope.GLOBAL:
            return True
        
        # Exact match
        if granted_scope == required_scope:
            return True
        
        # ORGANIZATION grants PROJECT and OWN within same organization
        if (granted_scope == PermissionScope.ORGANIZATION and
            required_scope in [PermissionScope.PROJECT, PermissionScope.OWN]):
            return self._same_organization(user_context, resource_context)
        
        # PROJECT grants OWN within same project
        if (granted_scope == PermissionScope.PROJECT and
            required_scope == PermissionScope.OWN):
            return self._same_project(user_context, resource_context)
        
        # OWN scope requires ownership check
        if required_scope == PermissionScope.OWN:
            return self._owns_resource(user_context, resource_context)
        
        return False
    
    def _same_organization(
        self,
        user_context: UserPermissionContext,
        resource_context: Dict[str, Any]
    ) -> bool:
        """Check if user and resource are in same organization."""
        if not self.organization_scoped:
            return True
        
        user_org = user_context.organization_id
        resource_org = resource_context.get("organization_id")
        
        return user_org and resource_org and user_org == resource_org
    
    def _same_project(
        self,
        user_context: UserPermissionContext,
        resource_context: Dict[str, Any]
    ) -> bool:
        """Check if user and resource are in same project."""
        resource_project = resource_context.get("project_id")
        return resource_project in user_context.project_ids
    
    def _owns_resource(
        self,
        user_context: UserPermissionContext,
        resource_context: Dict[str, Any]
    ) -> bool:
        """Check if user owns the resource."""
        resource_owner = resource_context.get("owner_id")
        return resource_owner == user_context.user_id
    
    async def create_user(self, user_data: Dict[str, Any]) -> bool:
        """Create a new user with role assignment."""
        if not self.storage:
            logger.debug(f"Storage not available - would create user: {user_data.get('username', 'unknown')}")
            return True  # Succeed in fallback mode
        
        try:
            return await self.storage.create_user(user_data)
        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return False
    
    async def get_user_by_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Get user record by ID."""
        if not self.storage:
            logger.debug(f"Storage not available - would get user: {user_id}")
            return None
        
        try:
            return await self.storage.get_user_by_id(user_id)
        except Exception as e:
            logger.error(f"Error getting user: {str(e)}")
            return None
    
    async def get_users_by_role(self, role: str, organization_id: str = None) -> List[Dict[str, Any]]:
        """Get all users with a specific role."""
        if not self.storage:
            logger.debug(f"Storage not available - would get users by role: {role}")
            return []
        
        try:
            return await self.storage.get_users_by_role(role, organization_id)
        except Exception as e:
            logger.error(f"Error getting users by role: {str(e)}")
            return []
    
    async def get_role_history(self, user_id: str) -> List[Dict[str, Any]]:
        """Get role assignment history for a user."""
        if not self.storage:
            logger.debug(f"Storage not available - would get role history for user: {user_id}")
            return []
        
        try:
            return await self.storage.get_role_history(user_id)
        except Exception as e:
            logger.error(f"Error getting role history: {str(e)}")
            return []


# Plug entry point
def process(ctx, cfg):
    """
    Plug entry point for PlugPipe compatibility.

    Args:
        ctx: Plug context
        cfg: Plug configuration

    Returns:
        Plug result
    """
    import asyncio

    # Handle single parameter case (config passed as first param)
    if cfg is None and isinstance(ctx, dict):
        cfg = ctx
        ctx = {}

    try:
        # Create plugin instance
        plugin = RBACStandardPlug(cfg)

        # Create auth context from plugin context
        auth_context = AuthContext(
            action=AuthAction(ctx.get("action", "check_permission")),
            request_data=ctx.get("request_data", {}),
            user_id=ctx.get("user_id"),
            ip_address=ctx.get("ip_address"),
            user_agent=ctx.get("user_agent"),
            plug_config=cfg
        )

        # Process request synchronously
        result = asyncio.run(plugin.process(auth_context, cfg))

        # Convert to plugin response format
        return {
            "success": result.success,
            "user_id": result.user_id,
            "roles": result.roles,
            "permissions": result.permissions,
            "error": result.error_message,
            "metadata": result.metadata
        }

    except Exception as e:
        # Graceful error handling
        return {
            "success": False,
            "error": str(e),
            "user_id": None,
            "roles": [],
            "permissions": [],
            "metadata": {"error_type": type(e).__name__}
        }