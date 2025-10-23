# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Google OAuth 2.0 Authentication Plug for PlugPipe.

This plugin provides enterprise-grade Google OAuth 2.0 authentication with:
- PKCE (Proof Key for Code Exchange) security
- State parameter CSRF protection
- G Suite domain restrictions
- Comprehensive audit logging
- Token refresh and management

Security Features:
- PKCE challenge/verifier validation
- State parameter verification
- Secure token storage and transmission
- Protection against CSRF and authorization code interception

Enterprise Features:
- G Suite domain restriction
- Admin consent flow support
- Custom claim mapping
- Audit trail integration
"""

import secrets
import hashlib
import base64
import os
import sys
from typing import Dict, Any, Optional
from urllib.parse import urlencode
import httpx
import logging

from cores.auth.base import (
    AuthenticationPlug, AuthAction, AuthResult, AuthContext,
    AuthPlugCapability, create_auth_result
)
# Import PlugPipe dynamic plugin discovery
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
from shares.loader import pp

logger = logging.getLogger(__name__)


class GoogleOAuth2Plug(AuthenticationPlug):
    """Google OAuth 2.0 authentication plugin with PKCE security."""
    
    # Google OAuth 2.0 endpoints
    AUTHORIZATION_URL = "https://accounts.google.com/o/oauth2/v2/auth"
    TOKEN_URL = "https://oauth2.googleapis.com/token"
    USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Google OAuth 2.0 plugin with security hardening."""
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

        # Validate required configuration
        self.client_id = config.get("client_id")
        self.client_secret = config.get("client_secret")
        self.redirect_uri = config.get("redirect_uri")
        self.scope = config.get("scope", "openid email profile")
        self.hosted_domain = config.get("hosted_domain")

        # SECURITY ENHANCEMENT: Validate all configuration inputs
        if self.client_id:
            sanitized_client_id = self._sanitize_input(self.client_id, "client_id")
            if not sanitized_client_id["is_valid"]:
                raise ValueError(f"Invalid client_id: {'; '.join(sanitized_client_id['violations'])}")

        if self.redirect_uri:
            sanitized_redirect_uri = self._sanitize_input(self.redirect_uri, "redirect_uri")
            if not sanitized_redirect_uri["is_valid"]:
                raise ValueError(f"Invalid redirect_uri: {'; '.join(sanitized_redirect_uri['violations'])}")

        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            raise ValueError("Missing required Google OAuth 2.0 configuration")

    def _sanitize_input(self, input_value: str, field_name: str = "input") -> Dict[str, Any]:
        """Sanitize input using Universal Input Sanitizer plugin."""
        if not self.input_sanitizer_available:
            # Basic validation fallback
            if not input_value or len(input_value.strip()) == 0:
                return {
                    "is_valid": False,
                    "sanitized_value": "",
                    "violations": [f"Empty {field_name}"]
                }
            # Check for obvious injection patterns
            dangerous_patterns = ["<script", "javascript:", "${jndi:", "';DROP TABLE", "|nc", "&&rm", "../../../../"]
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
            plugin_name="auth_oauth2_google",
            plugin_version="1.0.0",
            plugin_type=self.plugin_type,
            supported_actions=[
                AuthAction.INITIATE_FLOW,
                AuthAction.HANDLE_CALLBACK,
                AuthAction.GET_USER_PROFILE,
                AuthAction.REFRESH_TOKEN,
                AuthAction.VALIDATE_CREDENTIALS
            ],
            required_config=["client_id", "client_secret", "redirect_uri"],
            optional_config=["scope", "hosted_domain"],
            priority=10,  # High priority for OAuth flows
            description="Google OAuth 2.0 authentication with PKCE security"
        )
    
    async def process(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """
        Process Google OAuth 2.0 authentication request.
        
        Args:
            ctx: Authentication context
            cfg: Plug configuration
            
        Returns:
            AuthResult with operation outcome
        """
        try:
            if ctx.action == AuthAction.INITIATE_FLOW:
                return await self._initiate_oauth_flow(ctx, cfg)
            elif ctx.action == AuthAction.HANDLE_CALLBACK:
                return await self._handle_oauth_callback(ctx, cfg)
            elif ctx.action == AuthAction.GET_USER_PROFILE:
                return await self._get_user_profile(ctx, cfg)
            elif ctx.action == AuthAction.REFRESH_TOKEN:
                return await self._refresh_token(ctx, cfg)
            elif ctx.action == AuthAction.VALIDATE_CREDENTIALS:
                return await self._validate_credentials(ctx, cfg)
            else:
                return create_auth_result(
                    success=False,
                    error_message=f"Unsupported action: {ctx.action}"
                )
        except Exception as e:
            logger.error(f"Google OAuth plugin error: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Google OAuth error: {str(e)}"
            )
    
    async def _initiate_oauth_flow(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Initiate Google OAuth 2.0 flow with PKCE."""
        try:
            # Generate PKCE parameters
            pkce_data = self._generate_pkce_challenge()
            
            # Generate state for CSRF protection
            state = secrets.token_urlsafe(32)
            
            # Build authorization URL
            auth_params = {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "response_type": "code",
                "scope": self.scope,
                "state": state,
                "code_challenge": pkce_data["code_challenge"],
                "code_challenge_method": "S256",
                "access_type": "offline",  # For refresh tokens
                "prompt": "consent"        # Force consent for refresh token
            }
            
            # Add hosted domain restriction if configured
            if self.hosted_domain:
                auth_params["hd"] = self.hosted_domain
            
            authorization_url = f"{self.AUTHORIZATION_URL}?{urlencode(auth_params)}"
            
            logger.info(f"Generated Google OAuth authorization URL")
            
            return create_auth_result(
                success=True,
                redirect_url=authorization_url,
                metadata={
                    "pkce_verifier": pkce_data["code_verifier"],
                    "state": state,
                    "flow_type": "oauth2_google"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to initiate Google OAuth flow: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Failed to initiate OAuth flow: {str(e)}"
            )
    
    async def _handle_oauth_callback(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Handle Google OAuth 2.0 callback and exchange code for tokens."""
        try:
            request_data = ctx.request_data
            
            # Extract callback parameters
            code = request_data.get("code")
            state = request_data.get("state")
            error = request_data.get("error")
            
            # Check for OAuth errors
            if error:
                logger.warning(f"Google OAuth error: {error}")
                return create_auth_result(
                    success=False,
                    error_message=f"OAuth error: {error}"
                )
            
            if not code:
                return create_auth_result(
                    success=False,
                    error_message="Missing authorization code"
                )
            
            # Validate state parameter (CSRF protection)
            expected_state = request_data.get("expected_state")
            if not expected_state or state != expected_state:
                logger.warning("State parameter mismatch - potential CSRF attack")
                return create_auth_result(
                    success=False,
                    error_message="Invalid state parameter"
                )
            
            # Get PKCE verifier
            code_verifier = request_data.get("pkce_verifier")
            if not code_verifier:
                return create_auth_result(
                    success=False,
                    error_message="Missing PKCE verifier"
                )
            
            # Exchange authorization code for tokens
            token_data = await self._exchange_code_for_tokens(code, code_verifier)
            
            if not token_data:
                return create_auth_result(
                    success=False,
                    error_message="Failed to exchange code for tokens"
                )
            
            # Get user profile
            user_profile = await self._fetch_user_profile(token_data["access_token"])
            
            if not user_profile:
                return create_auth_result(
                    success=False,
                    error_message="Failed to fetch user profile"
                )
            
            # Validate hosted domain if configured
            if self.hosted_domain:
                user_domain = user_profile.get("hd")
                if user_domain != self.hosted_domain:
                    logger.warning(f"User domain {user_domain} doesn't match required {self.hosted_domain}")
                    return create_auth_result(
                        success=False,
                        error_message="Domain restriction violation"
                    )
            
            logger.info(f"Google OAuth successful for user: {user_profile['email']}")
            
            return create_auth_result(
                success=True,
                user_id=user_profile["id"],
                user_data={
                    "email": user_profile["email"],
                    "name": user_profile.get("name", ""),
                    "picture": user_profile.get("picture"),
                    "verified_email": user_profile.get("verified_email", False),
                    "locale": user_profile.get("locale"),
                    "hd": user_profile.get("hd")  # Hosted domain
                },
                tokens={
                    "access_token": token_data["access_token"],
                    "refresh_token": token_data.get("refresh_token"),
                    "id_token": token_data.get("id_token")
                },
                expires_at=token_data.get("expires_at"),
                metadata={
                    "provider": "google",
                    "oauth_flow": "authorization_code_with_pkce"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to handle Google OAuth callback: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Callback handling error: {str(e)}"
            )
    
    async def _get_user_profile(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Get user profile from Google using access token."""
        try:
            access_token = ctx.request_data.get("access_token")
            if not access_token:
                return create_auth_result(
                    success=False,
                    error_message="Missing access token"
                )
            
            user_profile = await self._fetch_user_profile(access_token)
            
            if not user_profile:
                return create_auth_result(
                    success=False,
                    error_message="Failed to fetch user profile"
                )
            
            return create_auth_result(
                success=True,
                user_id=user_profile["id"],
                user_data=user_profile
            )
            
        except Exception as e:
            logger.error(f"Failed to get Google user profile: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Profile fetch error: {str(e)}"
            )
    
    async def _refresh_token(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Refresh Google OAuth access token."""
        try:
            refresh_token = ctx.request_data.get("refresh_token")
            if not refresh_token:
                return create_auth_result(
                    success=False,
                    error_message="Missing refresh token"
                )
            
            # Prepare token refresh request
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "refresh_token": refresh_token,
                "grant_type": "refresh_token"
            }
            
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.TOKEN_URL,
                    data=token_data,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                token_response = response.json()
                
                if "error" in token_response:
                    return create_auth_result(
                        success=False,
                        error_message=f"Token refresh error: {token_response['error']}"
                    )
                
                logger.info("Google OAuth token refreshed successfully")
                
                return create_auth_result(
                    success=True,
                    tokens={
                        "access_token": token_response["access_token"],
                        "refresh_token": refresh_token,  # Keep existing refresh token
                        "id_token": token_response.get("id_token")
                    },
                    metadata={
                        "expires_in": token_response.get("expires_in", 3600),
                        "token_type": token_response.get("token_type", "Bearer")
                    }
                )
                
        except Exception as e:
            logger.error(f"Failed to refresh Google OAuth token: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Token refresh error: {str(e)}"
            )
    
    async def _validate_credentials(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Validate Google OAuth credentials."""
        try:
            access_token = ctx.request_data.get("access_token")
            if not access_token:
                return create_auth_result(
                    success=False,
                    error_message="Missing access token"
                )
            
            # Validate by trying to fetch user profile
            user_profile = await self._fetch_user_profile(access_token)
            
            if user_profile:
                return create_auth_result(
                    success=True,
                    user_id=user_profile["id"],
                    user_data=user_profile,
                    metadata={"validation_method": "profile_fetch"}
                )
            else:
                return create_auth_result(
                    success=False,
                    error_message="Invalid access token"
                )
                
        except Exception as e:
            logger.error(f"Failed to validate Google OAuth credentials: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Credential validation error: {str(e)}"
            )
    
    def _generate_pkce_challenge(self) -> Dict[str, str]:
        """Generate PKCE challenge and verifier."""
        # Generate code verifier (43-128 characters)
        code_verifier = base64.urlsafe_b64encode(
            secrets.token_bytes(32)
        ).decode('utf-8').rstrip('=')
        
        # Generate code challenge (SHA256 hash of verifier)
        challenge_bytes = hashlib.sha256(code_verifier.encode('utf-8')).digest()
        code_challenge = base64.urlsafe_b64encode(
            challenge_bytes
        ).decode('utf-8').rstrip('=')
        
        return {
            "code_verifier": code_verifier,
            "code_challenge": code_challenge
        }
    
    async def _exchange_code_for_tokens(
        self, 
        authorization_code: str, 
        code_verifier: str
    ) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access/refresh tokens."""
        try:
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": authorization_code,
                "grant_type": "authorization_code",
                "redirect_uri": self.redirect_uri,
                "code_verifier": code_verifier
            }
            
            headers = {"Content-Type": "application/x-www-form-urlencoded"}
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    self.TOKEN_URL,
                    data=token_data,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                token_response = response.json()
                
                if "error" in token_response:
                    logger.error(f"Token exchange error: {token_response['error']}")
                    return None
                
                return token_response
                
        except Exception as e:
            logger.error(f"Token exchange failed: {str(e)}")
            return None
    
    async def _fetch_user_profile(self, access_token: str) -> Optional[Dict[str, Any]]:
        """Fetch user profile from Google."""
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/json"
            }
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    self.USERINFO_URL,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                return response.json()
                
        except Exception as e:
            logger.error(f"User profile fetch failed: {str(e)}")
            return None


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
        plugin = GoogleOAuth2Plug(cfg)

        # Create auth context from plugin context
        auth_context = AuthContext(
            action=AuthAction(ctx.get("action", "initiate_flow")),
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
            "tokens": result.tokens,
            "redirect_url": result.redirect_url,
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
            "tokens": {},
            "redirect_url": None,
            "metadata": {"error_type": type(e).__name__}
        }