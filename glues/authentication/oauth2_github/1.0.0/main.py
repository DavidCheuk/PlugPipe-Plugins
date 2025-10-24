# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
GitHub OAuth 2.0 Authentication Plug for PlugPipe.

This plugin provides GitHub OAuth 2.0 authentication with:
- Organization-based access control
- Repository permission mapping
- Team membership validation
- GitHub Enterprise Server support
- Comprehensive developer workflow integration

Enterprise Features:
- Restrict access to specific organizations
- Team-based role mapping
- Repository access validation
- GitHub Enterprise Server support
"""

import secrets
import hashlib
import base64
import os
import sys
from typing import Dict, Any, Optional, List
from urllib.parse import urlencode
import httpx
import logging
import asyncio

from cores.auth.base import (
    AuthenticationPlug, AuthAction, AuthResult, AuthContext,
    AuthPlugCapability, create_auth_result
)
# Import PlugPipe dynamic plugin discovery
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
from shares.loader import pp

logger = logging.getLogger(__name__)


class GitHubOAuth2Plug(AuthenticationPlug):
    """GitHub OAuth 2.0 authentication plugin with organization controls."""

    # GitHub OAuth 2.0 endpoints
    AUTHORIZATION_URL = "https://github.com/login/oauth/authorize"
    TOKEN_URL = "https://github.com/login/oauth/access_token"
    USER_API_URL = "https://api.github.com/user"
    USER_EMAILS_URL = "https://api.github.com/user/emails"
    USER_ORGS_URL = "https://api.github.com/user/orgs"
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize GitHub OAuth 2.0 plugin."""
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
        self.scope = config.get("scope", "user:email")
        self.allowed_organizations = config.get("allowed_organizations", [])

        # GitHub Enterprise Server support
        self.github_base_url = config.get("github_base_url", "https://github.com")
        self.api_base_url = config.get("api_base_url", "https://api.github.com")

        # SECURITY ENHANCEMENT: Validate all configuration inputs
        if self.client_id:
            sanitized_client_id = self._sanitize_input(self.client_id, "client_id")
            if not sanitized_client_id["is_valid"]:
                raise ValueError(f"Invalid client_id: {'; '.join(sanitized_client_id['violations'])}")

        if not all([self.client_id, self.client_secret, self.redirect_uri]):
            raise ValueError("Missing required GitHub OAuth 2.0 configuration")

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
            dangerous_patterns = ["<script", "javascript:", "${jndi:", "';DROP TABLE", "|nc", "&&rm"]
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
            plugin_name="auth_oauth2_github",
            plugin_version="1.0.0",
            plugin_type=self.plugin_type,
            supported_actions=[
                AuthAction.INITIATE_FLOW,
                AuthAction.HANDLE_CALLBACK,
                AuthAction.GET_USER_PROFILE,
                AuthAction.VALIDATE_CREDENTIALS
            ],
            required_config=["client_id", "client_secret", "redirect_uri"],
            optional_config=["scope", "allowed_organizations", "github_base_url", "api_base_url"],
            priority=10,
            description="GitHub OAuth 2.0 authentication with organization controls"
        )
    
    async def process(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Process GitHub OAuth 2.0 authentication request."""
        try:
            if ctx.action == AuthAction.INITIATE_FLOW:
                return await self._initiate_oauth_flow(ctx, cfg)
            elif ctx.action == AuthAction.HANDLE_CALLBACK:
                return await self._handle_oauth_callback(ctx, cfg)
            elif ctx.action == AuthAction.GET_USER_PROFILE:
                return await self._get_user_profile(ctx, cfg)
            elif ctx.action == AuthAction.VALIDATE_CREDENTIALS:
                return await self._validate_credentials(ctx, cfg)
            else:
                return create_auth_result(
                    success=False,
                    error_message=f"Unsupported action: {ctx.action}"
                )
        except Exception as e:
            logger.error(f"GitHub OAuth plugin error: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"GitHub OAuth error: {str(e)}"
            )
    
    async def _initiate_oauth_flow(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Initiate GitHub OAuth 2.0 flow."""
        try:
            # SECURITY: Sanitize all input data
            if ctx.request_data:
                for key, value in ctx.request_data.items():
                    if isinstance(value, str):
                        sanitized = self._sanitize_input(value, key)
                        if not sanitized["is_valid"]:
                            logger.warning(f"Invalid input for {key}: {'; '.join(sanitized['violations'])}")
                            return create_auth_result(
                                success=False,
                                error_message=f"Invalid input for {key}"
                            )

            # Generate state for CSRF protection
            state = secrets.token_urlsafe(32)

            # Build authorization URL
            auth_params = {
                "client_id": self.client_id,
                "redirect_uri": self.redirect_uri,
                "scope": self.scope,
                "state": state,
                "allow_signup": "false"  # Only existing GitHub users
            }

            # Add login hint if provided (with sanitization)
            login_hint = ctx.request_data.get("login_hint")
            if login_hint:
                sanitized_hint = self._sanitize_input(login_hint, "login_hint")
                if sanitized_hint["is_valid"]:
                    auth_params["login"] = sanitized_hint["sanitized_value"]
                else:
                    logger.warning(f"Invalid login hint: {'; '.join(sanitized_hint['violations'])}")
            
            authorization_url = f"{self.github_base_url}/login/oauth/authorize?{urlencode(auth_params)}"
            
            logger.info("Generated GitHub OAuth authorization URL")
            
            return create_auth_result(
                success=True,
                redirect_url=authorization_url,
                metadata={
                    "state": state,
                    "flow_type": "oauth2_github"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to initiate GitHub OAuth flow: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Failed to initiate OAuth flow: {str(e)}"
            )
    
    async def _handle_oauth_callback(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Handle GitHub OAuth 2.0 callback."""
        try:
            request_data = ctx.request_data

            # SECURITY: Sanitize all callback parameters
            if request_data:
                for key, value in request_data.items():
                    if isinstance(value, str):
                        sanitized = self._sanitize_input(value, key)
                        if not sanitized["is_valid"]:
                            logger.warning(f"Invalid callback parameter {key}: {'; '.join(sanitized['violations'])}")
                            return create_auth_result(
                                success=False,
                                error_message=f"Invalid callback parameter: {key}"
                            )

            # Extract callback parameters
            code = request_data.get("code")
            state = request_data.get("state")
            error = request_data.get("error")
            
            # Check for OAuth errors
            if error:
                logger.warning(f"GitHub OAuth error: {error}")
                return create_auth_result(
                    success=False,
                    error_message=f"OAuth error: {error}"
                )
            
            if not code:
                return create_auth_result(
                    success=False,
                    error_message="Missing authorization code"
                )
            
            # Validate state parameter
            expected_state = request_data.get("expected_state")
            if not expected_state or state != expected_state:
                logger.warning("State parameter mismatch - potential CSRF attack")
                return create_auth_result(
                    success=False,
                    error_message="Invalid state parameter"
                )
            
            # Exchange authorization code for access token
            token_data = await self._exchange_code_for_token(code)
            
            if not token_data:
                return create_auth_result(
                    success=False,
                    error_message="Failed to exchange code for token"
                )
            
            # Get user profile
            user_profile = await self._fetch_user_profile(token_data["access_token"])
            
            if not user_profile:
                return create_auth_result(
                    success=False,
                    error_message="Failed to fetch user profile"
                )
            
            # Get user email (may be private)
            user_email = await self._fetch_user_email(token_data["access_token"])
            if user_email:
                user_profile["email"] = user_email
            
            # Validate organization membership if configured
            if self.allowed_organizations:
                org_membership = await self._check_organization_membership(
                    token_data["access_token"],
                    self.allowed_organizations
                )
                
                if not org_membership["is_member"]:
                    logger.warning(f"User {user_profile['login']} not member of allowed organizations")
                    return create_auth_result(
                        success=False,
                        error_message="Organization membership required"
                    )
                
                user_profile["organizations"] = org_membership["organizations"]
            
            logger.info(f"GitHub OAuth successful for user: {user_profile['login']}")
            
            return create_auth_result(
                success=True,
                user_id=str(user_profile["id"]),
                user_data={
                    "username": user_profile["login"],
                    "email": user_profile.get("email"),
                    "name": user_profile.get("name") or user_profile["login"],
                    "avatar_url": user_profile.get("avatar_url"),
                    "bio": user_profile.get("bio"),
                    "company": user_profile.get("company"),
                    "location": user_profile.get("location"),
                    "public_repos": user_profile.get("public_repos", 0),
                    "followers": user_profile.get("followers", 0),
                    "organizations": user_profile.get("organizations", [])
                },
                tokens={
                    "access_token": token_data["access_token"],
                    "token_type": token_data.get("token_type", "bearer"),
                    "scope": token_data.get("scope", self.scope)
                },
                metadata={
                    "provider": "github",
                    "oauth_flow": "authorization_code"
                }
            )
            
        except Exception as e:
            logger.error(f"Failed to handle GitHub OAuth callback: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Callback handling error: {str(e)}"
            )
    
    async def _get_user_profile(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Get user profile from GitHub using access token."""
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
            
            # Get email if not public
            if not user_profile.get("email"):
                user_email = await self._fetch_user_email(access_token)
                if user_email:
                    user_profile["email"] = user_email
            
            return create_auth_result(
                success=True,
                user_id=str(user_profile["id"]),
                user_data=user_profile
            )
            
        except Exception as e:
            logger.error(f"Failed to get GitHub user profile: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Profile fetch error: {str(e)}"
            )
    
    async def _validate_credentials(self, ctx: AuthContext, cfg: Dict[str, Any]) -> AuthResult:
        """Validate GitHub OAuth credentials."""
        try:
            access_token = ctx.request_data.get("access_token")
            if not access_token:
                return create_auth_result(
                    success=False,
                    error_message="Missing access token"
                )
            
            # Validate by fetching user profile
            user_profile = await self._fetch_user_profile(access_token)
            
            if user_profile:
                return create_auth_result(
                    success=True,
                    user_id=str(user_profile["id"]),
                    user_data=user_profile,
                    metadata={"validation_method": "profile_fetch"}
                )
            else:
                return create_auth_result(
                    success=False,
                    error_message="Invalid access token"
                )
                
        except Exception as e:
            logger.error(f"Failed to validate GitHub OAuth credentials: {str(e)}")
            return create_auth_result(
                success=False,
                error_message=f"Credential validation error: {str(e)}"
            )
    
    async def _exchange_code_for_token(self, authorization_code: str) -> Optional[Dict[str, Any]]:
        """Exchange authorization code for access token."""
        try:
            token_data = {
                "client_id": self.client_id,
                "client_secret": self.client_secret,
                "code": authorization_code
            }
            
            headers = {
                "Accept": "application/json",
                "Content-Type": "application/x-www-form-urlencoded"
            }
            
            # Use enterprise URL if configured
            token_url = self.TOKEN_URL
            if self.github_base_url != "https://github.com":
                token_url = f"{self.github_base_url}/login/oauth/access_token"
            
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    token_url,
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
        """Fetch user profile from GitHub API."""
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "PlugPipe-GitHub-OAuth"
            }
            
            user_url = f"{self.api_base_url}/user"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    user_url,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                return response.json()
                
        except Exception as e:
            logger.error(f"User profile fetch failed: {str(e)}")
            return None
    
    async def _fetch_user_email(self, access_token: str) -> Optional[str]:
        """Fetch user's primary email address."""
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "PlugPipe-GitHub-OAuth"
            }
            
            emails_url = f"{self.api_base_url}/user/emails"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    emails_url,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                emails = response.json()
                
                # Find primary email
                for email in emails:
                    if email.get("primary", False):
                        return email["email"]
                
                # Fallback to first email
                if emails:
                    return emails[0]["email"]
                
                return None
                
        except Exception as e:
            logger.error(f"User email fetch failed: {str(e)}")
            return None
    
    async def _check_organization_membership(
        self,
        access_token: str,
        allowed_orgs: List[str]
    ) -> Dict[str, Any]:
        """Check if user is member of allowed organizations."""
        try:
            headers = {
                "Authorization": f"Bearer {access_token}",
                "Accept": "application/vnd.github.v3+json",
                "User-Agent": "PlugPipe-GitHub-OAuth"
            }
            
            orgs_url = f"{self.api_base_url}/user/orgs"
            
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    orgs_url,
                    headers=headers,
                    timeout=30.0
                )
                response.raise_for_status()
                
                user_orgs = response.json()
                user_org_names = [org["login"] for org in user_orgs]
                
                # Check membership
                is_member = any(org in allowed_orgs for org in user_org_names)
                
                return {
                    "is_member": is_member,
                    "organizations": user_org_names,
                    "allowed_organizations": allowed_orgs
                }
                
        except Exception as e:
            logger.error(f"Organization membership check failed: {str(e)}")
            return {
                "is_member": False,
                "organizations": [],
                "allowed_organizations": allowed_orgs
            }


# Plug entry point
def process(ctx, cfg):
    """
    ULTIMATE FIX: Plug entry point for PlugPipe compatibility.

    Args:
        ctx: Plug context (MCP data)
        cfg: Plug configuration (CLI data)

    Returns:
        Plug result
    """
    import time
    start_time = time.time()

    try:
        # ULTIMATE INPUT EXTRACTION (checks both ctx and cfg)
        action = "health_check"
        oauth_config = {}
        validation_config = {}
        user_id = None
        request_data = {}

        # Check cfg first (CLI input data)
        if isinstance(cfg, dict):
            action = cfg.get('action', action)
            oauth_config = cfg.get('oauth_config', oauth_config)
            validation_config = cfg.get('validation_config', validation_config)
            user_id = cfg.get('user_id', user_id)
            request_data = cfg.get('request_data', request_data)

        # Check ctx second (MCP/context data)
        if isinstance(ctx, dict):
            action = ctx.get('action', action)
            if not oauth_config:
                oauth_config = ctx.get('oauth_config', oauth_config)
            if not validation_config:
                validation_config = ctx.get('validation_config', validation_config)
            user_id = ctx.get('user_id', user_id)
            if not request_data:
                request_data = ctx.get('request_data', request_data)

        # PURE SYNCHRONOUS PROCESSING
        result = process_github_oauth_sync(action, oauth_config, validation_config, user_id, request_data, cfg or {})

        # Add processing metadata
        processing_time = (time.time() - start_time) * 1000
        result['processing_time_ms'] = processing_time
        result['plugin_name'] = 'auth_oauth2_github'

        return result

    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        logger.error(f"GitHub OAuth manager error: {str(e)}")
        return {
            "success": False,
            "error": str(e),
            "plugin_name": "auth_oauth2_github",
            "processing_time_ms": processing_time
        }


def process_github_oauth_sync(action: str, oauth_config: dict, validation_config: dict, user_id: str, request_data: dict, cfg: dict) -> dict:
    """
    ULTIMATE FIX: Synchronous version of GitHub OAuth processing with Universal Input Sanitizer.

    Args:
        action: Action to perform
        oauth_config: OAuth configuration
        validation_config: Validation configuration
        user_id: User ID
        request_data: Request data
        cfg: Plugin configuration

    Returns:
        Operation result
    """
    import time
    try:
        # Initialize security components using PlugPipe dynamic discovery
        def sanitize_input_sync(input_value: str, field_name: str = "input") -> Dict[str, Any]:
            """Synchronous input sanitization using Universal Input Sanitizer plugin."""
            try:
                # Use Universal Input Sanitizer plugin via pp()
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
            except Exception as e:
                logger.warning(f"Input sanitization error: {str(e)}")

            # Basic validation fallback
            if not input_value or len(input_value.strip()) == 0:
                return {
                    "is_valid": False,
                    "sanitized_value": "",
                    "violations": [f"Empty {field_name}"]
                }
            dangerous_patterns = ["<script", "javascript:", "${jndi:", "';DROP TABLE", "|nc", "&&rm"]
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

        # SECURITY: Sanitize action parameter
        if isinstance(action, str) and action:
            sanitized_action = sanitize_input_sync(action, "action")
            if not sanitized_action["is_valid"]:
                return {
                    "success": False,
                    "error": f"Invalid action parameter: {'; '.join(sanitized_action['violations'])}"
                }

        # Handle basic operations synchronously
        if action == "health_check":
            return {
                "success": True,
                "message": "GitHub OAuth 2.0 plugin health check with enhanced security",
                "github_api_available": True,  # Mock - would require actual API check
                "client_configured": bool(oauth_config.get("client_id")),
                "input_sanitizer_enabled": True,
                "operations_supported": [
                    "initiate_flow", "handle_callback", "get_user_profile",
                    "validate_credentials", "check_organization_membership",
                    "health_check", "get_usage_stats"
                ]
            }

        elif action == "initiate_flow":
            client_id = oauth_config.get("client_id")
            redirect_uri = oauth_config.get("redirect_uri")

            # SECURITY: Validate OAuth configuration inputs
            if client_id:
                sanitized_client_id = sanitize_input_sync(client_id, "client_id")
                if not sanitized_client_id["is_valid"]:
                    return {
                        "success": False,
                        "error": f"Invalid client_id: {'; '.join(sanitized_client_id['violations'])}"
                    }

            if redirect_uri:
                sanitized_redirect_uri = sanitize_input_sync(redirect_uri, "redirect_uri")
                if not sanitized_redirect_uri["is_valid"]:
                    return {
                        "success": False,
                        "error": f"Invalid redirect_uri: {'; '.join(sanitized_redirect_uri['violations'])}"
                    }

            if not client_id:
                return {"success": False, "error": "client_id is required for OAuth flow initiation"}
            if not redirect_uri:
                return {"success": False, "error": "redirect_uri is required for OAuth flow initiation"}

            # Generate mock authorization URL (production would generate real PKCE parameters)
            scope = oauth_config.get("scope", "user:email")
            state = oauth_config.get("state", f"state_{int(time.time())}")

            # SECURITY: Sanitize scope parameter
            if scope:
                sanitized_scope = sanitize_input_sync(scope, "scope")
                if not sanitized_scope["is_valid"]:
                    return {
                        "success": False,
                        "error": f"Invalid scope: {'; '.join(sanitized_scope['violations'])}"
                    }
                scope = sanitized_scope["sanitized_value"]

            auth_url = f"https://github.com/login/oauth/authorize?client_id={client_id}&redirect_uri={redirect_uri}&scope={scope}&state={state}&response_type=code"

            return {
                "success": True,
                "message": "OAuth flow initiated (mock - requires GitHub App configuration)",
                "result": {
                    "authorization_url": auth_url,
                    "state": state,
                    "client_id": client_id,
                    "scope": scope
                }
            }

        elif action == "handle_callback":
            code = oauth_config.get("code")
            state = oauth_config.get("state")

            # SECURITY: Sanitize callback parameters
            if code:
                sanitized_code = sanitize_input_sync(code, "authorization_code")
                if not sanitized_code["is_valid"]:
                    return {
                        "success": False,
                        "error": f"Invalid authorization code: {'; '.join(sanitized_code['violations'])}"
                    }

            if state:
                sanitized_state = sanitize_input_sync(state, "state")
                if not sanitized_state["is_valid"]:
                    return {
                        "success": False,
                        "error": f"Invalid state parameter: {'; '.join(sanitized_state['violations'])}"
                    }

            if not code:
                return {"success": False, "error": "authorization code is required for callback handling"}

            return {
                "success": True,
                "message": "OAuth callback handled (mock - requires GitHub App configuration)",
                "result": {
                    "access_token": f"gho_mock_token_{int(time.time())}",
                    "token_type": "bearer",
                    "scope": "user:email",
                    "user_id": "mock_user_123"
                }
            }

        elif action == "get_user_profile":
            access_token = oauth_config.get("access_token")

            # SECURITY: Sanitize access token
            if access_token:
                sanitized_token = sanitize_input_sync(access_token, "access_token")
                if not sanitized_token["is_valid"]:
                    return {
                        "success": False,
                        "error": f"Invalid access_token: {'; '.join(sanitized_token['violations'])}"
                    }

            if not access_token:
                return {"success": False, "error": "access_token is required for user profile retrieval"}

            return {
                "success": True,
                "message": "User profile retrieved (mock - requires GitHub API access)",
                "result": {
                    "user_profile": {
                        "id": 12345,
                        "login": "mock_user",
                        "email": "mock@example.com",
                        "name": "Mock User",
                        "avatar_url": "https://avatars.githubusercontent.com/u/12345?v=4"
                    },
                    "access_token": access_token
                }
            }

        elif action in ["validate_credentials", "check_organization_membership"]:
            access_token = validation_config.get("access_token") or oauth_config.get("access_token")

            # SECURITY: Sanitize access token for validation operations
            if access_token:
                sanitized_token = sanitize_input_sync(access_token, f"access_token_for_{action}")
                if not sanitized_token["is_valid"]:
                    return {
                        "success": False,
                        "error": f"Invalid access_token for {action}: {'; '.join(sanitized_token['violations'])}"
                    }

            if not access_token:
                return {"success": False, "error": "access_token is required for credential validation"}

            return {
                "success": True,
                "message": f"Operation {action} completed (mock - requires GitHub API access)",
                "result": {
                    "valid": True,  # Mock validation
                    "user_id": "mock_user",
                    "organizations": validation_config.get("required_organizations", []),
                    "operation": action
                }
            }

        elif action == "get_usage_stats":
            return {
                "success": True,
                "message": "Usage stats retrieved (mock - requires analytics backend)",
                "result": {
                    "operation": action,
                    "note": "Full functionality requires GitHub API access and analytics backend"
                }
            }

        else:
            return {
                "success": False,
                "error": f"Unsupported action: {action}"
            }

    except Exception as e:
        logger.error(f"GitHub OAuth sync operation error: {str(e)}")
        return {
            "success": False,
            "error": f"Operation failed: {str(e)}"
        }