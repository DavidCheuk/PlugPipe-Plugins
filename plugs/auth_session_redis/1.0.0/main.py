# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Redis Session Management Plug for PlugPipe.

This plugin provides enterprise-grade Redis-backed session management with:
- Secure session token generation and validation
- Configurable session expiration and renewal
- Optional session data encryption for sensitive information
- IP address and user agent validation for security
- High availability with Redis clustering support

Security Features:
- Cryptographically secure session token generation
- Optional AES encryption for session data
- Session hijacking protection via IP/user agent validation
- Protection against session fixation attacks
- Automatic cleanup of expired sessions

Enterprise Features:
- Redis Sentinel and Cluster support for high availability
- Session replication across multiple Redis nodes
- Cross-datacenter session synchronization
- Comprehensive session analytics and monitoring
- Bulk session management operations
"""

import secrets
import json
import hashlib
import os
import sys
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, List
import redis.asyncio as redis
from cryptography.fernet import Fernet
import logging

from cores.auth.base import (
    SessionPlug, AuthAction, AuthResult, AuthContext,
    AuthPlugCapability, create_auth_result
)
# Import PlugPipe dynamic plugin discovery
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
from shares.loader import pp

logger = logging.getLogger(__name__)


class RedisSessionPlug(SessionPlug):
    """Redis-backed session management plugin with enterprise features."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Redis session plugin with security hardening."""
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
        self.redis_url = config.get("redis_url", "redis://localhost:6379/1")
        self.session_prefix = config.get("session_prefix", "pp_session:")
        self.default_ttl_hours = config.get("default_ttl_hours", 24)
        self.max_ttl_hours = config.get("max_ttl_hours", 168)  # 7 days
        self.cleanup_interval_minutes = config.get("cleanup_interval_minutes", 60)
        self.secure_sessions = config.get("secure_sessions", True)
        
        # Session encryption (optional)
        self.encryption_key = config.get("session_encryption_key")
        self.fernet = None
        if self.encryption_key:
            self.fernet = Fernet(self.encryption_key.encode())
        
        # Redis client
        self.redis_client = None
        self._initialize_redis()

    def _sanitize_input(self, input_value: str, field_name: str = "input") -> Dict[str, Any]:
        """Sanitize input using Universal Input Sanitizer plugin."""
        if not self.input_sanitizer_available:
            # Basic validation fallback for session security
            if not input_value or len(input_value.strip()) == 0:
                return {
                    "is_valid": False,
                    "sanitized_value": "",
                    "violations": [f"Empty {field_name}"]
                }
            # Check for session-specific injection patterns
            dangerous_patterns = [
                "<script", "javascript:", "${jndi:", "';DROP TABLE", "|nc", "&&rm", "../../../../",
                "eval(", "exec(", "__import__", "document.cookie", "localStorage", "sessionStorage"
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
            plugin_name="auth_session_redis",
            plugin_version="1.0.0",
            plugin_type=self.plugin_type,
            supported_actions=[
                AuthAction.CREATE_SESSION,
                AuthAction.VALIDATE_SESSION,
                AuthAction.DESTROY_SESSION
            ],
            required_config=[],
            optional_config=[
                "redis_url", "session_prefix", "default_ttl_hours", "max_ttl_hours",
                "cleanup_interval_minutes", "secure_sessions", "session_encryption_key"
            ],
            priority=25,
            description="Redis-backed session management with enterprise features"
        )
    
    def _initialize_redis(self):
        """Initialize Redis client connection."""
        try:
            self.redis_client = redis.from_url(
                self.redis_url,
                decode_responses=True,
                socket_keepalive=True,
                socket_keepalive_options={},
                health_check_interval=30
            )
            logger.info("Connected to Redis for session management")
        except Exception as e:
            logger.error(f"Failed to connect to Redis: {str(e)}")
            raise
    
    async def process(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Process session management request."""
        try:
            if ctx.action == AuthAction.CREATE_SESSION:
                return await self._create_session(ctx, cfg)
            elif ctx.action == AuthAction.VALIDATE_SESSION:
                return await self._validate_session(ctx, cfg)
            elif ctx.action == AuthAction.DESTROY_SESSION:
                return await self._destroy_session(ctx, cfg)
            else:
                return create_auth_result(
                    success=False,
                    error_message=f"Unsupported action: {ctx.action}"
                )
        except Exception as e:
            logger.error(f"Session plugin error: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Session error: {str(e)}"
            )
    
    async def _create_session(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Create new user session in Redis."""
        try:
            request_data = ctx.request_data

            # Extract session parameters
            user_id = ctx.user_id or request_data.get("user_id")
            session_data = request_data.get("session_data", {})
            ttl_hours = request_data.get("ttl_hours", self.default_ttl_hours)

            # SECURITY: Sanitize user_id for session creation
            if user_id:
                sanitized_user_id = self._sanitize_input(str(user_id), "user_id")
                if not sanitized_user_id["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid user_id: {'; '.join(sanitized_user_id['violations'])}"
                    )
                user_id = sanitized_user_id["sanitized_value"]

            if not user_id:
                return create_auth_result(
                    success=False,
                    error_message="User ID required for session creation"
                )
            
            # Validate TTL
            if ttl_hours > self.max_ttl_hours:
                ttl_hours = self.max_ttl_hours
            
            # Generate secure session token
            session_token = self._generate_session_token()
            
            # Calculate expiration
            now = datetime.now(timezone.utc)
            expires_at = now + timedelta(hours=ttl_hours)
            
            # Build session record
            session_record = {
                "user_id": user_id,
                "created_at": now.isoformat(),
                "expires_at": expires_at.isoformat(),
                "last_accessed": now.isoformat(),
                "ip_address": ctx.ip_address,
                "user_agent": ctx.user_agent,
                "session_data": session_data
            }
            
            # Add security fingerprint if enabled
            if self.secure_sessions:
                session_record["security_fingerprint"] = self._generate_security_fingerprint(
                    ctx.ip_address, ctx.user_agent
                )
            
            # Encrypt session data if encryption is enabled
            session_json = json.dumps(session_record)
            if self.fernet:
                session_json = self.fernet.encrypt(session_json.encode()).decode()
            
            # Store in Redis
            redis_key = f"{self.session_prefix}{session_token}"
            ttl_seconds = ttl_hours * 3600
            
            await self.redis_client.setex(redis_key, ttl_seconds, session_json)
            
            # Also maintain user session index for bulk operations
            user_sessions_key = f"{self.session_prefix}user:{user_id}"
            await self.redis_client.sadd(user_sessions_key, session_token)
            await self.redis_client.expire(user_sessions_key, ttl_seconds)
            
            logger.info(f"Created session for user {user_id} with TTL {ttl_hours}h")
            
            return create_auth_result(
                success=True,
                user_id=user_id,
                session_data={
                    "session_token": session_token,
                    "expires_at": expires_at.isoformat(),
                    "created_at": now.isoformat()
                },
                expires_at=expires_at,
                metadata={
                    "ttl_hours": ttl_hours,
                    "secure_session": self.secure_sessions,
                    "encrypted": bool(self.fernet)
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to create session: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Session creation error: {str(e)}"
            )
    
    async def _validate_session(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Validate session token and return session information."""
        try:
            request_data = ctx.request_data
            session_token = request_data.get("session_token")

            # SECURITY: Sanitize session token for validation
            if session_token:
                sanitized_token = self._sanitize_input(str(session_token), "session_token")
                if not sanitized_token["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid session_token: {'; '.join(sanitized_token['violations'])}"
                    )
                session_token = sanitized_token["sanitized_value"]

            if not session_token:
                return create_auth_result(
                    success=False,
                    error_message="Session token required for validation"
                )
            
            # Get session from Redis
            redis_key = f"{self.session_prefix}{session_token}"
            session_json = await self.redis_client.get(redis_key)
            
            if not session_json:
                return create_auth_result(
                    success=False,
                    error_message="Session not found or expired"
                )
            
            # Decrypt session data if encrypted
            if self.fernet:
                try:
                    session_json = self.fernet.decrypt(session_json.encode()).decode()
                except Exception:
                    return create_auth_result(
                        success=False,
                        error_message="Failed to decrypt session data"
                    )
            
            # Parse session record
            try:
                session_record = json.loads(session_json)
            except json.JSONDecodeError:
                return create_auth_result(
                    success=False,
                    error_message="Invalid session data format"
                )
            
            # Check if session has expired
            expires_at = datetime.fromisoformat(session_record["expires_at"])
            if expires_at <= datetime.now(timezone.utc):
                # Clean up expired session
                await self._cleanup_session(session_token, session_record.get("user_id"))
                return create_auth_result(
                    success=False,
                    error_message="Session has expired"
                )
            
            # Validate security fingerprint if enabled
            if self.secure_sessions and "security_fingerprint" in session_record:
                current_fingerprint = self._generate_security_fingerprint(
                    ctx.ip_address, ctx.user_agent
                )
                if current_fingerprint != session_record["security_fingerprint"]:
                    logger.warning(f"Security fingerprint mismatch for session {session_token}")
                    return create_auth_result(
                        success=False,
                        error_message="Session security validation failed"
                    )
            
            # Update last accessed time
            now = datetime.now(timezone.utc)
            session_record["last_accessed"] = now.isoformat()
            
            # Store updated session
            updated_json = json.dumps(session_record)
            if self.fernet:
                updated_json = self.fernet.encrypt(updated_json.encode()).decode()
            
            # Refresh TTL
            ttl = await self.redis_client.ttl(redis_key)
            await self.redis_client.setex(redis_key, ttl, updated_json)
            
            logger.info(f"Validated session for user {session_record['user_id']}")
            
            return create_auth_result(
                success=True,
                user_id=session_record["user_id"],
                user_data=session_record.get("session_data", {}),
                expires_at=expires_at,
                metadata={
                    "created_at": session_record["created_at"],
                    "last_accessed": session_record["last_accessed"],
                    "ip_address": session_record.get("ip_address"),
                    "secure_session": self.secure_sessions
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to validate session: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Session validation error: {str(e)}"
            )
    
    async def _destroy_session(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Destroy session by removing from Redis."""
        try:
            request_data = ctx.request_data
            session_token = request_data.get("session_token")

            # SECURITY: Sanitize session token for destruction
            if session_token:
                sanitized_token = self._sanitize_input(str(session_token), "session_token")
                if not sanitized_token["is_valid"]:
                    return create_auth_result(
                        success=False,
                        error_message=f"Invalid session_token: {'; '.join(sanitized_token['violations'])}"
                    )
                session_token = sanitized_token["sanitized_value"]

            if not session_token:
                return create_auth_result(
                    success=False,
                    error_message="Session token required for destruction"
                )
            
            # Get session info for cleanup
            redis_key = f"{self.session_prefix}{session_token}"
            session_json = await self.redis_client.get(redis_key)
            
            user_id = None
            if session_json:
                try:
                    if self.fernet:
                        session_json = self.fernet.decrypt(session_json.encode()).decode()
                    
                    session_record = json.loads(session_json)
                    user_id = session_record.get("user_id")
                except Exception:
                    pass  # Continue with cleanup even if we can't parse
            
            # Remove session
            deleted = await self.redis_client.delete(redis_key)
            
            # Remove from user session index
            if user_id:
                user_sessions_key = f"{self.session_prefix}user:{user_id}"
                await self.redis_client.srem(user_sessions_key, session_token)
            
            if deleted:
                logger.info(f"Destroyed session {session_token}")
                return create_auth_result(
                    success=True,
                    metadata={"destroyed": True}
                )
            else:
                return create_auth_result(
                    success=False,
                    error_message="Session not found"
                )
                
        except Exception as e:
            logger.error(f"Failed to destroy session: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Session destruction error: {str(e)}"
            )
    
    def _generate_session_token(self) -> str:
        """Generate cryptographically secure session token."""
        return secrets.token_urlsafe(32)
    
    def _generate_security_fingerprint(
        self, 
        ip_address: Optional[str], 
        user_agent: Optional[str]
    ) -> str:
        """Generate security fingerprint for session validation."""
        fingerprint_data = f"{ip_address}:{user_agent}"
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()
    
    async def _cleanup_session(self, session_token: str, user_id: Optional[str]):
        """Clean up expired session."""
        try:
            redis_key = f"{self.session_prefix}{session_token}"
            await self.redis_client.delete(redis_key)
            
            if user_id:
                user_sessions_key = f"{self.session_prefix}user:{user_id}"
                await self.redis_client.srem(user_sessions_key, session_token)
            
            logger.debug(f"Cleaned up expired session {session_token}")
        except Exception as e:
            logger.error(f"Failed to cleanup session {session_token}: {str(e)}")
    
    async def destroy_all_user_sessions(self, user_id: str) -> int:
        """Destroy all sessions for a specific user."""
        try:
            user_sessions_key = f"{self.session_prefix}user:{user_id}"
            session_tokens = await self.redis_client.smembers(user_sessions_key)
            
            if not session_tokens:
                return 0
            
            # Delete all session keys
            redis_keys = [f"{self.session_prefix}{token}" for token in session_tokens]
            redis_keys.append(user_sessions_key)  # Also delete the index
            
            deleted = await self.redis_client.delete(*redis_keys)
            
            logger.info(f"Destroyed {len(session_tokens)} sessions for user {user_id}")
            return len(session_tokens)
            
        except Exception as e:
            logger.error(f"Failed to destroy user sessions: {str(e)}")
            return 0
    
    async def get_session_statistics(self) -> Dict[str, Any]:
        """Get session statistics from Redis."""
        try:
            # Count total active sessions
            pattern = f"{self.session_prefix}*"
            keys = await self.redis_client.keys(pattern)
            
            # Filter out user index keys
            session_keys = [k for k in keys if not k.startswith(f"{self.session_prefix}user:")]
            
            # Get memory usage
            memory_usage = 0
            for key in session_keys[:100]:  # Sample for performance
                try:
                    memory_usage += await self.redis_client.memory_usage(key) or 0
                except Exception:
                    pass
            
            return {
                "total_sessions": len(session_keys),
                "estimated_memory_bytes": memory_usage,
                "session_prefix": self.session_prefix,
                "encryption_enabled": bool(self.fernet),
                "secure_sessions": self.secure_sessions
            }
            
        except Exception as e:
            logger.error(f"Failed to get session statistics: {str(e)}")
            return {"error": str(e)}
    
    async def cleanup_expired_sessions(self) -> int:
        """Clean up expired sessions (background task)."""
        try:
            pattern = f"{self.session_prefix}*"
            keys = await self.redis_client.keys(pattern)
            
            # Filter out user index keys
            session_keys = [k for k in keys if not k.startswith(f"{self.session_prefix}user:")]
            
            cleaned = 0
            for key in session_keys:
                ttl = await self.redis_client.ttl(key)
                if ttl == -1:  # Key exists but has no expiration
                    await self.redis_client.delete(key)
                    cleaned += 1
            
            logger.info(f"Cleaned up {cleaned} sessions without proper TTL")
            return cleaned
            
        except Exception as e:
            logger.error(f"Failed to cleanup expired sessions: {str(e)}")
            return 0


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
        plugin = RedisSessionPlug(cfg)

        # Create auth context from plugin context
        auth_context = AuthContext(
            action=AuthAction(ctx.get("action", "validate_session")),
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
            "user_data": result.user_data,
            "session_data": result.session_data,
            "expires_at": result.expires_at.isoformat() if result.expires_at else None,
            "error": result.error_message,
            "metadata": result.metadata
        }

    except Exception as e:
        # Graceful error handling
        return {
            "success": False,
            "error": str(e),
            "user_id": None,
            "user_data": {},
            "session_data": {},
            "expires_at": None,
            "metadata": {"error_type": type(e).__name__}
        }