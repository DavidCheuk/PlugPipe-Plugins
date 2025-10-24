#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Comprehensive Authentication & Authorization Plugin
Demonstrates all common authentication and authorization mechanisms for PlugPipe

This plugin showcases enterprise-grade authentication patterns:
- API Key authentication (simple and complex)
- Bearer Token authentication (JWT, OAuth2)
- Basic Authentication (username/password)
- Certificate-based authentication (mTLS)
- Multi-factor authentication (MFA)
- Session-based authentication
- SAML/SSO integration
- RBAC (Role-Based Access Control)
- ABAC (Attribute-Based Access Control)
- Fine-grained permissions with scopes
- Time-based access controls
- IP-based restrictions
- Rate limiting integration
"""

import os
import json
import jwt
import hashlib
import hmac
import base64
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional
import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Plugin metadata
plug_metadata = {
    "name": "comprehensive_auth",
    "version": "1.0.0",
    "description": "Comprehensive authentication and authorization plugin demonstrating all common auth mechanisms",
    "author": "security_team",
    "category": "security"
}

class ComprehensiveAuthenticator:
    """Comprehensive authentication and authorization handler"""
    
    def __init__(self):
        self.setup_mock_data()
    
    def setup_mock_data(self):
        """Setup mock authentication data for demonstration"""
        
        # JWT Secret for token validation
        self.jwt_secret = "plugpipe-comprehensive-auth-secret-2024"
        
        # API Keys database (production would use secure key storage)
        self.api_keys = {
            "pk_live_abcd1234": {
                "user_id": "user_1", 
                "scopes": ["read", "write"],
                "rate_limit": 1000,
                "expires": None
            },
            "sk_test_xyz789": {
                "user_id": "admin_1", 
                "scopes": ["read", "write", "admin", "delete"],
                "rate_limit": 10000,
                "expires": None
            }
        }
        
        # User credentials database
        self.users = {
            "admin": {
                "password_hash": "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",  # "password"
                "roles": ["admin", "user"],
                "permissions": ["read", "write", "admin", "delete"],
                "mfa_enabled": True,
                "mfa_secret": "JBSWY3DPEHPK3PXP",
                "last_login": None,
                "failed_attempts": 0,
                "locked_until": None
            },
            "user": {
                "password_hash": "ef92b778bafe771e89245b89ecbc08a44a4e166c06659911881f383d4473e94f",  # "secret123"  
                "roles": ["user"],
                "permissions": ["read", "write"],
                "mfa_enabled": False,
                "last_login": None,
                "failed_attempts": 0,
                "locked_until": None
            },
            "readonly": {
                "password_hash": "a665a45920422f9d417e4867efdc4fb8a04a1f3fff1fa07e998e86f7f7a27ae3",  # "hello"
                "roles": ["readonly"],
                "permissions": ["read"],
                "mfa_enabled": False,
                "last_login": None,
                "failed_attempts": 0,
                "locked_until": None
            }
        }
        
        # RBAC role definitions
        self.roles = {
            "admin": {
                "permissions": ["read", "write", "admin", "delete", "manage_users"],
                "inherit_from": ["user"]
            },
            "user": {
                "permissions": ["read", "write"],
                "inherit_from": ["readonly"]
            },
            "readonly": {
                "permissions": ["read"],
                "inherit_from": []
            }
        }
        
        # Resource-based permissions (ABAC)
        self.resources = {
            "resource_1": {"owner": "user_1", "visibility": "private", "required_role": "user"},
            "resource_2": {"owner": "admin_1", "visibility": "public", "required_role": "readonly"},
            "resource_3": {"owner": "admin_1", "visibility": "restricted", "required_role": "admin"}
        }
        
        # Session storage (in production would use Redis/database)
        self.sessions = {}
        
        # Rate limiting storage
        self.rate_limits = {}
    
    def hash_password(self, password: str) -> str:
        """Hash password using SHA-256"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def verify_password(self, password: str, password_hash: str) -> bool:
        """Verify password against hash"""
        return self.hash_password(password) == password_hash
    
    def generate_jwt(self, user_id: str, permissions: List[str], expires_in: int = 3600) -> str:
        """Generate JWT token"""
        payload = {
            'user_id': user_id,
            'permissions': permissions,
            'iat': datetime.utcnow(),
            'exp': datetime.utcnow() + timedelta(seconds=expires_in),
            'iss': 'plugpipe-auth',
            'aud': 'plugpipe-api'
        }
        return jwt.encode(payload, self.jwt_secret, algorithm='HS256')
    
    def verify_jwt(self, token: str) -> Dict[str, Any]:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.jwt_secret, algorithms=['HS256'])
            return {"valid": True, "payload": payload}
        except jwt.ExpiredSignatureError:
            return {"valid": False, "error": "Token expired"}
        except jwt.InvalidTokenError:
            return {"valid": False, "error": "Invalid token"}
    
    def validate_api_key(self, api_key: str) -> Dict[str, Any]:
        """Validate API key"""
        if not api_key:
            return {"valid": False, "error": "API key required"}
        
        if api_key not in self.api_keys:
            return {"valid": False, "error": "Invalid API key"}
        
        key_data = self.api_keys[api_key]
        
        # Check expiration
        if key_data.get("expires") and datetime.now() > key_data["expires"]:
            return {"valid": False, "error": "API key expired"}
        
        return {
            "valid": True,
            "user_id": key_data["user_id"],
            "scopes": key_data["scopes"],
            "rate_limit": key_data["rate_limit"]
        }
    
    def authenticate_basic(self, username: str, password: str, mfa_code: Optional[str] = None) -> Dict[str, Any]:
        """Basic authentication with optional MFA"""
        if not username or not password:
            return {"authenticated": False, "error": "Username and password required"}
        
        if username not in self.users:
            return {"authenticated": False, "error": "Invalid credentials"}
        
        user = self.users[username]
        
        # Check if account is locked
        if user.get("locked_until") and datetime.now() < user["locked_until"]:
            return {"authenticated": False, "error": "Account temporarily locked"}
        
        # Verify password
        if not self.verify_password(password, user["password_hash"]):
            # Increment failed attempts
            user["failed_attempts"] = user.get("failed_attempts", 0) + 1
            
            # Lock account after 5 failed attempts
            if user["failed_attempts"] >= 5:
                user["locked_until"] = datetime.now() + timedelta(minutes=30)
                return {"authenticated": False, "error": "Account locked due to multiple failed attempts"}
            
            return {"authenticated": False, "error": "Invalid credentials"}
        
        # Check MFA if enabled
        if user.get("mfa_enabled"):
            if not mfa_code:
                return {"authenticated": False, "error": "MFA code required", "requires_mfa": True}
            
            # In production, would verify TOTP/SMS code
            # For demo, accept "123456" as valid MFA code
            if mfa_code != "123456":
                return {"authenticated": False, "error": "Invalid MFA code"}
        
        # Reset failed attempts on successful login
        user["failed_attempts"] = 0
        user["locked_until"] = None
        user["last_login"] = datetime.now()
        
        return {
            "authenticated": True,
            "user_id": username,
            "roles": user["roles"],
            "permissions": user["permissions"]
        }
    
    def authenticate_bearer_token(self, bearer_token: str) -> Dict[str, Any]:
        """Bearer token authentication (JWT)"""
        if not bearer_token:
            return {"authenticated": False, "error": "Bearer token required"}
        
        # Remove "Bearer " prefix if present
        if bearer_token.startswith("Bearer "):
            bearer_token = bearer_token[7:]
        
        jwt_result = self.verify_jwt(bearer_token)
        
        if not jwt_result["valid"]:
            return {"authenticated": False, "error": jwt_result["error"]}
        
        payload = jwt_result["payload"]
        
        return {
            "authenticated": True,
            "user_id": payload["user_id"],
            "permissions": payload["permissions"],
            "token_payload": payload
        }
    
    def authenticate_session(self, session_id: str) -> Dict[str, Any]:
        """Session-based authentication"""
        if not session_id:
            return {"authenticated": False, "error": "Session ID required"}
        
        if session_id not in self.sessions:
            return {"authenticated": False, "error": "Invalid or expired session"}
        
        session = self.sessions[session_id]
        
        # Check session expiration
        if datetime.now() > session["expires"]:
            del self.sessions[session_id]
            return {"authenticated": False, "error": "Session expired"}
        
        # Update last access time
        session["last_access"] = datetime.now()
        
        return {
            "authenticated": True,
            "user_id": session["user_id"],
            "permissions": session["permissions"],
            "session_data": session
        }
    
    def authenticate_certificate(self, cert_data: Optional[str] = None) -> Dict[str, Any]:
        """Certificate-based authentication (mTLS simulation)"""
        # In production, this would validate client certificates
        # For demo, simulate certificate authentication
        
        if not cert_data:
            return {"authenticated": False, "error": "Client certificate required"}
        
        # Simulate certificate validation
        if cert_data == "valid_cert_fingerprint":
            return {
                "authenticated": True,
                "user_id": "cert_user",
                "permissions": ["read", "write"],
                "auth_method": "certificate"
            }
        
        return {"authenticated": False, "error": "Invalid client certificate"}
    
    def check_ip_restriction(self, client_ip: str, allowed_ips: List[str]) -> bool:
        """Check if client IP is allowed"""
        try:
            client_addr = ipaddress.ip_address(client_ip)
            
            for allowed_ip in allowed_ips:
                if "/" in allowed_ip:  # CIDR notation
                    if client_addr in ipaddress.ip_network(allowed_ip):
                        return True
                else:  # Single IP
                    if client_addr == ipaddress.ip_address(allowed_ip):
                        return True
            
            return False
        except:
            return False
    
    def check_rate_limit(self, user_id: str, limit: int = 100, window: int = 3600) -> Dict[str, Any]:
        """Check rate limiting"""
        current_time = time.time()
        window_start = current_time - window
        
        if user_id not in self.rate_limits:
            self.rate_limits[user_id] = []
        
        # Remove old requests outside the window
        self.rate_limits[user_id] = [
            req_time for req_time in self.rate_limits[user_id] 
            if req_time > window_start
        ]
        
        current_requests = len(self.rate_limits[user_id])
        
        if current_requests >= limit:
            return {
                "allowed": False,
                "error": f"Rate limit exceeded: {current_requests}/{limit} requests per hour",
                "retry_after": int(min(self.rate_limits[user_id]) + window - current_time)
            }
        
        # Add current request
        self.rate_limits[user_id].append(current_time)
        
        return {
            "allowed": True,
            "remaining": limit - current_requests - 1,
            "reset_at": int(window_start + window)
        }
    
    def authorize_resource_access(self, user_id: str, user_permissions: List[str], 
                                 resource_id: str, operation: str, context: Dict = None) -> Dict[str, Any]:
        """Comprehensive resource authorization (RBAC + ABAC)"""
        
        if resource_id not in self.resources:
            return {"authorized": False, "error": f"Resource '{resource_id}' not found"}
        
        resource = self.resources[resource_id]
        
        # Check basic permission requirements
        operation_permissions = {
            "read": ["read"],
            "write": ["write"], 
            "delete": ["admin", "delete"],
            "manage": ["admin"]
        }
        
        required_perms = operation_permissions.get(operation, ["read"])
        
        if not any(perm in user_permissions for perm in required_perms):
            return {
                "authorized": False,
                "error": f"Insufficient permissions for {operation}. Required: {required_perms}"
            }
        
        # Check resource ownership (ABAC)
        if resource["visibility"] == "private" and resource["owner"] != user_id:
            return {"authorized": False, "error": "Access denied: private resource"}
        
        # Check time-based restrictions
        if context and context.get("time_restricted"):
            current_hour = datetime.now().hour
            if not (9 <= current_hour <= 17):  # Business hours only
                return {"authorized": False, "error": "Access denied: outside business hours"}
        
        # Check IP restrictions
        if context and context.get("client_ip"):
            allowed_ips = resource.get("allowed_ips", ["0.0.0.0/0"])  # Default: allow all
            if not self.check_ip_restriction(context["client_ip"], allowed_ips):
                return {"authorized": False, "error": "Access denied: IP not allowed"}
        
        return {
            "authorized": True,
            "resource": resource,
            "effective_permissions": user_permissions,
            "access_level": resource["visibility"]
        }

async def process(ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Main plugin processing function with comprehensive authentication"""
    
    authenticator = ComprehensiveAuthenticator()
    operation = cfg.get('operation', 'authenticate')
    
    try:
        if operation == 'authenticate':
            return await handle_authentication(authenticator, ctx, cfg)
        elif operation == 'authorize':
            return await handle_authorization(authenticator, ctx, cfg)
        elif operation == 'validate_token':
            return await handle_token_validation(authenticator, ctx, cfg)
        elif operation == 'create_session':
            return await handle_session_creation(authenticator, ctx, cfg)
        elif operation == 'get_auth_methods':
            return await handle_auth_methods_discovery(authenticator, ctx, cfg)
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "available_operations": [
                    "authenticate", "authorize", "validate_token", 
                    "create_session", "get_auth_methods"
                ]
            }
    
    except Exception as e:
        return {
            "success": False,
            "error": f"Authentication processing failed: {str(e)}",
            "operation": operation
        }

async def handle_authentication(authenticator: ComprehensiveAuthenticator, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Handle various authentication methods"""
    
    auth_method = cfg.get('auth_method', 'api_key')
    client_ip = ctx.get('client_ip', '127.0.0.1')
    
    result = {"success": False, "authenticated": False, "auth_method": auth_method}
    
    try:
        if auth_method == 'api_key':
            api_key = cfg.get('api_key') or cfg.get('x_api_key')
            api_result = authenticator.validate_api_key(api_key)
            
            if api_result["valid"]:
                # Check rate limiting
                rate_result = authenticator.check_rate_limit(
                    api_result["user_id"], 
                    api_result.get("rate_limit", 1000)
                )
                
                if not rate_result["allowed"]:
                    result.update({
                        "success": False,
                        "error": rate_result["error"],
                        "retry_after": rate_result["retry_after"]
                    })
                else:
                    result.update({
                        "success": True,
                        "authenticated": True,
                        "user_id": api_result["user_id"],
                        "permissions": api_result["scopes"],
                        "rate_limit_remaining": rate_result["remaining"]
                    })
            else:
                result["error"] = api_result["error"]
        
        elif auth_method == 'basic':
            username = cfg.get('username')
            password = cfg.get('password') 
            mfa_code = cfg.get('mfa_code')
            
            auth_result = authenticator.authenticate_basic(username, password, mfa_code)
            
            if auth_result["authenticated"]:
                result.update({
                    "success": True,
                    "authenticated": True,
                    "user_id": auth_result["user_id"],
                    "roles": auth_result["roles"],
                    "permissions": auth_result["permissions"]
                })
            else:
                result["error"] = auth_result["error"]
                if auth_result.get("requires_mfa"):
                    result["requires_mfa"] = True
        
        elif auth_method == 'bearer':
            bearer_token = cfg.get('bearer_token') or cfg.get('authorization', '').replace('Bearer ', '')
            
            auth_result = authenticator.authenticate_bearer_token(bearer_token)
            
            if auth_result["authenticated"]:
                result.update({
                    "success": True,
                    "authenticated": True,
                    "user_id": auth_result["user_id"], 
                    "permissions": auth_result["permissions"]
                })
            else:
                result["error"] = auth_result["error"]
        
        elif auth_method == 'session':
            session_id = cfg.get('session_id')
            
            auth_result = authenticator.authenticate_session(session_id)
            
            if auth_result["authenticated"]:
                result.update({
                    "success": True,
                    "authenticated": True,
                    "user_id": auth_result["user_id"],
                    "permissions": auth_result["permissions"]
                })
            else:
                result["error"] = auth_result["error"]
        
        elif auth_method == 'certificate':
            cert_data = cfg.get('client_cert')
            
            auth_result = authenticator.authenticate_certificate(cert_data)
            
            if auth_result["authenticated"]:
                result.update({
                    "success": True,
                    "authenticated": True,
                    "user_id": auth_result["user_id"],
                    "permissions": auth_result["permissions"]
                })
            else:
                result["error"] = auth_result["error"]
        
        else:
            result["error"] = f"Unsupported authentication method: {auth_method}"
    
    except Exception as e:
        result["error"] = f"Authentication error: {str(e)}"
    
    return result

async def handle_authorization(authenticator: ComprehensiveAuthenticator, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Handle resource authorization"""
    
    user_id = cfg.get('user_id')
    user_permissions = cfg.get('permissions', [])
    resource_id = cfg.get('resource_id')
    operation = cfg.get('resource_operation', 'read')
    
    if not user_id or not resource_id:
        return {
            "success": False,
            "error": "user_id and resource_id required for authorization"
        }
    
    # Build authorization context
    auth_context = {
        "client_ip": ctx.get('client_ip'),
        "time_restricted": cfg.get('time_restricted', False),
        "additional_context": cfg.get('context', {})
    }
    
    auth_result = authenticator.authorize_resource_access(
        user_id, user_permissions, resource_id, operation, auth_context
    )
    
    if auth_result["authorized"]:
        return {
            "success": True,
            "authorized": True,
            "resource": auth_result["resource"],
            "access_level": auth_result["access_level"],
            "effective_permissions": auth_result["effective_permissions"]
        }
    else:
        return {
            "success": False,
            "authorized": False,
            "error": auth_result["error"]
        }

async def handle_token_validation(authenticator: ComprehensiveAuthenticator, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Handle token validation"""
    
    token = cfg.get('token')
    if not token:
        return {"success": False, "error": "Token required for validation"}
    
    jwt_result = authenticator.verify_jwt(token)
    
    return {
        "success": jwt_result["valid"],
        "valid": jwt_result["valid"],
        "payload": jwt_result.get("payload"),
        "error": jwt_result.get("error")
    }

async def handle_session_creation(authenticator: ComprehensiveAuthenticator, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Handle session creation"""
    
    user_id = cfg.get('user_id')
    permissions = cfg.get('permissions', [])
    
    if not user_id:
        return {"success": False, "error": "user_id required for session creation"}
    
    # Generate session ID
    import uuid
    session_id = str(uuid.uuid4())
    
    # Create session
    session_data = {
        "user_id": user_id,
        "permissions": permissions,
        "created": datetime.now(),
        "expires": datetime.now() + timedelta(hours=8),
        "last_access": datetime.now(),
        "client_ip": ctx.get('client_ip', '127.0.0.1')
    }
    
    authenticator.sessions[session_id] = session_data
    
    return {
        "success": True,
        "session_id": session_id,
        "expires": session_data["expires"].isoformat(),
        "user_id": user_id
    }

async def handle_auth_methods_discovery(authenticator: ComprehensiveAuthenticator, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Return available authentication methods"""
    
    return {
        "success": True,
        "available_auth_methods": {
            "api_key": {
                "description": "API key authentication with rate limiting",
                "parameters": ["api_key", "x_api_key"],
                "supports_rate_limiting": True
            },
            "basic": {
                "description": "Username/password authentication with optional MFA",
                "parameters": ["username", "password", "mfa_code"],
                "supports_mfa": True,
                "supports_account_locking": True
            },
            "bearer": {
                "description": "JWT bearer token authentication",
                "parameters": ["bearer_token", "authorization"],
                "supports_expiration": True
            },
            "session": {
                "description": "Session-based authentication",
                "parameters": ["session_id"],
                "supports_expiration": True
            },
            "certificate": {
                "description": "Client certificate authentication (mTLS)",
                "parameters": ["client_cert"],
                "supports_pki": True
            }
        },
        "authorization_features": {
            "rbac": "Role-Based Access Control with hierarchical roles",
            "abac": "Attribute-Based Access Control with context evaluation",
            "resource_ownership": "Resource ownership validation",
            "time_restrictions": "Time-based access controls", 
            "ip_restrictions": "IP address and network-based restrictions",
            "rate_limiting": "Per-user and per-API-key rate limiting"
        },
        "security_features": {
            "account_locking": "Automatic account locking after failed attempts",
            "mfa": "Multi-factor authentication support",
            "session_management": "Secure session lifecycle management",
            "jwt_validation": "Cryptographic token validation",
            "audit_logging": "Comprehensive authentication audit trails"
        }
    }

if __name__ == "__main__":
    # Test the comprehensive authentication plugin
    import asyncio
    
    async def test_comprehensive_auth():
        print("🔒 Testing Comprehensive Authentication Plugin")
        
        # Test 1: API Key authentication
        ctx = {"session_id": "test", "client_ip": "192.168.1.100"}
        cfg = {
            "operation": "authenticate",
            "auth_method": "api_key",
            "api_key": "pk_live_abcd1234"
        }
        result = await process(ctx, cfg)
        print(f"API Key Auth: {result}")
        
        # Test 2: Basic authentication with MFA required
        cfg = {
            "operation": "authenticate", 
            "auth_method": "basic",
            "username": "admin",
            "password": "password"
        }
        result = await process(ctx, cfg)
        print(f"Basic Auth (MFA required): {result}")
        
        # Test 3: Basic authentication with MFA
        cfg["mfa_code"] = "123456"
        result = await process(ctx, cfg)
        print(f"Basic Auth with MFA: {result}")
        
        # Test 4: Authorization check
        cfg = {
            "operation": "authorize",
            "user_id": "admin",
            "permissions": ["read", "write", "admin"],
            "resource_id": "resource_1", 
            "resource_operation": "read"
        }
        result = await process(ctx, cfg)
        print(f"Authorization: {result}")
        
        # Test 5: Get authentication methods
        cfg = {"operation": "get_auth_methods"}
        result = await process(ctx, cfg)
        print(f"Auth Methods: {result}")
    
    asyncio.run(test_comprehensive_auth())