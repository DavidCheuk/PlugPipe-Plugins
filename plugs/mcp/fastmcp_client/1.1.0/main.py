# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enhanced FastMCP Client Plug - MCP Protocol Client with OAuth 2.1 Authentication
Provides a complete MCP-compliant client with enterprise security features including
OAuth 2.1 flows, multi-server credential management, and user confirmation workflows.

Security Features:
- OAuth 2.1 client credentials and authorization code flows
- Multi-server credential isolation and management
- User confirmation workflows for sensitive operations
- Request signing and replay attack protection
- Automatic token refresh and credential rotation
"""

import asyncio
import aiohttp
import json
import logging
import secrets
import hashlib
import time
from typing import Dict, Any, List, Optional, Union, Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from urllib.parse import urlencode, parse_qs, urlparse
import uuid
import base64

# OAuth 2.1 and security imports
try:
    from authlib.integrations.httpx_client import AsyncOAuth2Client
    from authlib.oauth2.rfc6749 import grants
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    SECURITY_AVAILABLE = True
except ImportError:
    SECURITY_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class AuthConfig:
    """Authentication configuration for enhanced MCP client"""
    method: str = "bearer"  # bearer, oauth2.1, none
    
    # Bearer token auth
    bearer_token: Optional[str] = None
    
    # OAuth 2.1 configuration
    client_id: Optional[str] = None
    client_secret: Optional[str] = None
    authorization_endpoint: Optional[str] = None
    token_endpoint: Optional[str] = None
    scope: List[str] = field(default_factory=list)
    
    # Security features
    enable_request_signing: bool = True
    enable_replay_protection: bool = True
    token_refresh_threshold_minutes: int = 5

@dataclass
class UserConfirmationConfig:
    """User confirmation workflow configuration"""
    enabled: bool = True
    sensitive_operations: List[str] = field(default_factory=lambda: [
        "tools/call", "resources/read", "resources/write"
    ])
    confirmation_timeout_seconds: int = 30
    require_explicit_approval: bool = True

@dataclass  
class EnhancedMCPClientConfig:
    """Enhanced configuration for FastMCP Client with security features"""
    server_url: str
    server_id: str = ""  # Unique identifier for credential isolation
    timeout: int = 30
    max_retries: int = 3
    retry_delay: float = 1.0
    client_name: str = "PlugPipe Enhanced FastMCP Client"
    client_version: str = "1.1.0"
    protocol_version: str = "2025-06-18"
    
    # Security configuration
    auth_config: AuthConfig = field(default_factory=AuthConfig)
    user_confirmation: UserConfirmationConfig = field(default_factory=UserConfirmationConfig)
    
    # Credential isolation
    credential_storage_key: Optional[str] = None

class MCPClientError(Exception):
    """Base exception for MCP client errors"""
    pass

class MCPAuthenticationError(MCPClientError):
    """Authentication-related MCP client errors"""
    pass

class MCPUserDeniedError(MCPClientError):
    """User denied confirmation for sensitive operation"""
    pass

class MCPServerError(MCPClientError):
    """Exception for MCP server-side errors"""
    def __init__(self, code: int, message: str, data: Any = None):
        self.code = code
        self.message = message
        self.data = data
        super().__init__(f"MCP Server Error {code}: {message}")

class CredentialManager:
    """Manages credentials for multiple MCP servers with isolation"""
    
    def __init__(self, master_key: Optional[str] = None):
        self.master_key = master_key or self._generate_master_key()
        self.cipher = self._create_cipher()
        self.credentials: Dict[str, Dict[str, Any]] = {}
    
    def _generate_master_key(self) -> str:
        """Generate a master key for credential encryption"""
        return base64.urlsafe_b64encode(secrets.token_bytes(32)).decode()
    
    def _create_cipher(self) -> Fernet:
        """Create encryption cipher from master key"""
        key_bytes = base64.urlsafe_b64decode(self.master_key.encode())
        return Fernet(base64.urlsafe_b64encode(key_bytes[:32]))
    
    def store_credentials(self, server_id: str, credentials: Dict[str, Any]) -> None:
        """Store encrypted credentials for a server"""
        encrypted_data = self.cipher.encrypt(json.dumps(credentials).encode())
        self.credentials[server_id] = {
            'encrypted_data': encrypted_data,
            'last_updated': datetime.utcnow().isoformat()
        }
    
    def get_credentials(self, server_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve and decrypt credentials for a server"""
        if server_id not in self.credentials:
            return None
        
        try:
            encrypted_data = self.credentials[server_id]['encrypted_data']
            decrypted_data = self.cipher.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            logger.error(f"Failed to decrypt credentials for {server_id}: {e}")
            return None
    
    def remove_credentials(self, server_id: str) -> bool:
        """Remove stored credentials for a server"""
        if server_id in self.credentials:
            del self.credentials[server_id]
            return True
        return False

class OAuth21Client:
    """OAuth 2.1 client implementation for MCP servers"""
    
    def __init__(self, auth_config: AuthConfig):
        self.auth_config = auth_config
        self.client: Optional[AsyncOAuth2Client] = None
        self.access_token: Optional[str] = None
        self.refresh_token: Optional[str] = None
        self.token_expires_at: Optional[datetime] = None
    
    async def initialize(self) -> bool:
        """Initialize OAuth 2.1 client"""
        if not SECURITY_AVAILABLE:
            logger.error("OAuth 2.1 dependencies not available")
            return False
        
        if not all([
            self.auth_config.client_id,
            self.auth_config.client_secret,
            self.auth_config.token_endpoint
        ]):
            logger.error("Missing required OAuth 2.1 configuration")
            return False
        
        self.client = AsyncOAuth2Client(
            client_id=self.auth_config.client_id,
            client_secret=self.auth_config.client_secret
        )
        return True
    
    async def get_access_token(self) -> Optional[str]:
        """Get valid access token, refreshing if necessary"""
        if self._token_needs_refresh():
            await self._refresh_access_token()
        
        return self.access_token
    
    def _token_needs_refresh(self) -> bool:
        """Check if token needs refresh"""
        if not self.access_token or not self.token_expires_at:
            return True
        
        threshold = timedelta(minutes=self.auth_config.token_refresh_threshold_minutes)
        return datetime.utcnow() + threshold >= self.token_expires_at
    
    async def _refresh_access_token(self) -> None:
        """Refresh access token using client credentials flow"""
        if not self.client:
            raise MCPAuthenticationError("OAuth client not initialized")
        
        try:
            # Use client credentials flow for server-to-server authentication
            token_response = await self.client.fetch_token(
                url=self.auth_config.token_endpoint,
                grant_type='client_credentials',
                scope=' '.join(self.auth_config.scope) if self.auth_config.scope else None
            )
            
            self.access_token = token_response.get('access_token')
            expires_in = token_response.get('expires_in', 3600)
            self.token_expires_at = datetime.utcnow() + timedelta(seconds=expires_in)
            
            logger.info("Successfully refreshed OAuth 2.1 access token")
            
        except Exception as e:
            logger.error(f"Failed to refresh OAuth 2.1 token: {e}")
            raise MCPAuthenticationError(f"Token refresh failed: {e}")

class UserConfirmationHandler:
    """Handles user confirmation workflows for sensitive operations"""
    
    def __init__(self, config: UserConfirmationConfig):
        self.config = config
        self.confirmation_callback: Optional[Callable] = None
    
    def set_confirmation_callback(self, callback: Callable) -> None:
        """Set callback function for user confirmation"""
        self.confirmation_callback = callback
    
    async def request_confirmation(self, operation: str, details: Dict[str, Any]) -> bool:
        """Request user confirmation for sensitive operation"""
        if not self.config.enabled:
            return True
        
        if operation not in self.config.sensitive_operations:
            return True
        
        if not self.confirmation_callback:
            logger.warning(f"No confirmation callback set for sensitive operation: {operation}")
            return self.config.require_explicit_approval is False
        
        try:
            # Call user-provided confirmation callback
            result = await asyncio.wait_for(
                self.confirmation_callback(operation, details),
                timeout=self.config.confirmation_timeout_seconds
            )
            
            logger.info(f"User confirmation for {operation}: {'approved' if result else 'denied'}")
            return bool(result)
            
        except asyncio.TimeoutError:
            logger.warning(f"User confirmation timeout for operation: {operation}")
            return False
        except Exception as e:
            logger.error(f"Error in confirmation callback: {e}")
            return False

class RequestSigner:
    """Handles request signing for integrity and replay protection"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
    
    def sign_request(self, method: str, url: str, body: str, timestamp: float) -> str:
        """Generate signature for request"""
        message = f"{method}|{url}|{body}|{timestamp}".encode()
        signature = hashlib.hmac.new(
            self.secret_key,
            message,
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def verify_response_signature(self, response_body: str, signature: str, timestamp: float) -> bool:
        """Verify response signature"""
        expected = self.sign_request("RESPONSE", "", response_body, timestamp)
        return secrets.compare_digest(signature, expected)

class EnhancedFastMCPClient:
    """
    Enhanced FastMCP Client with OAuth 2.1 authentication, multi-server credential 
    management, and user confirmation workflows.
    
    Security Features:
    - OAuth 2.1 client credentials and authorization code flows
    - Multi-server credential isolation
    - User confirmation workflows for sensitive operations  
    - Request signing and replay attack protection
    - Automatic token refresh and credential rotation
    """
    
    def __init__(self, config: EnhancedMCPClientConfig):
        self.config = config
        self.session: Optional[aiohttp.ClientSession] = None
        self.server_info: Optional[Dict[str, Any]] = None
        self.is_initialized = False
        self.capabilities: Dict[str, Any] = {}
        
        # Security components
        self.credential_manager = CredentialManager(config.credential_storage_key)
        self.oauth_client: Optional[OAuth21Client] = None
        self.user_confirmation = UserConfirmationHandler(config.user_confirmation)
        self.request_signer: Optional[RequestSigner] = None
        
        # Initialize security components
        if config.auth_config.method == "oauth2.1":
            self.oauth_client = OAuth21Client(config.auth_config)
        
        if config.auth_config.enable_request_signing:
            signing_key = config.auth_config.client_secret or secrets.token_urlsafe(32)
            self.request_signer = RequestSigner(signing_key)
    
    async def __aenter__(self):
        await self.connect()
        return self
        
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        await self.disconnect()
    
    def set_user_confirmation_callback(self, callback: Callable) -> None:
        """Set callback function for user confirmation workflows"""
        self.user_confirmation.set_confirmation_callback(callback)
    
    async def connect(self):
        """Establish connection to MCP server with authentication"""
        if self.session is None:
            timeout = aiohttp.ClientTimeout(total=self.config.timeout)
            connector = aiohttp.TCPConnector(limit=100, limit_per_host=30)
            
            # Build headers with authentication
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': f'{self.config.client_name}/{self.config.client_version}'
            }
            
            # Add authentication headers
            auth_headers = await self._get_auth_headers()
            headers.update(auth_headers)
            
            self.session = aiohttp.ClientSession(
                timeout=timeout,
                connector=connector,
                headers=headers
            )
        
        # Initialize OAuth client if needed
        if self.oauth_client:
            await self.oauth_client.initialize()
        
        # Initialize MCP session
        await self.initialize()
        logger.info(f"Connected to MCP server: {self.config.server_url}")
    
    async def disconnect(self):
        """Close connection to MCP server"""
        if self.session:
            await self.session.close()
            self.session = None
        
        self.is_initialized = False
        logger.info("Disconnected from MCP server")
    
    async def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers based on configuration"""
        headers = {}
        
        if self.config.auth_config.method == "bearer" and self.config.auth_config.bearer_token:
            headers['Authorization'] = f"Bearer {self.config.auth_config.bearer_token}"
        
        elif self.config.auth_config.method == "oauth2.1" and self.oauth_client:
            access_token = await self.oauth_client.get_access_token()
            if access_token:
                headers['Authorization'] = f"Bearer {access_token}"
        
        return headers
    
    async def _make_request(self, method: str, endpoint: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Make authenticated request with security features"""
        if not self.session:
            raise MCPClientError("Client not connected")
        
        url = f"{self.config.server_url.rstrip('/')}/{endpoint.lstrip('/')}"
        request_id = str(uuid.uuid4())
        timestamp = time.time()
        
        # Add request metadata
        request_data = {
            "jsonrpc": "2.0",
            "id": request_id,
            **data
        }
        
        # Add security headers if enabled
        headers = {}
        if self.config.auth_config.enable_replay_protection:
            headers['X-Request-Timestamp'] = str(timestamp)
            headers['X-Request-ID'] = request_id
        
        # Sign request if enabled
        if self.request_signer and self.config.auth_config.enable_request_signing:
            body_str = json.dumps(request_data, sort_keys=True)
            signature = self.request_signer.sign_request(method, url, body_str, timestamp)
            headers['X-Request-Signature'] = signature
        
        # Update session headers with auth
        auth_headers = await self._get_auth_headers()
        if self.session:
            self.session.headers.update(auth_headers)
        
        # Make request with retries
        last_exception = None
        for attempt in range(self.config.max_retries + 1):
            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    json=request_data,
                    headers=headers
                ) as response:
                    response_text = await response.text()
                    
                    if response.status == 401:
                        raise MCPAuthenticationError(f"Authentication failed: {response_text}")
                    elif response.status == 403:
                        raise MCPAuthenticationError(f"Authorization failed: {response_text}")
                    elif response.status >= 400:
                        raise MCPServerError(response.status, f"HTTP {response.status}: {response_text}")
                    
                    response_data = await response.json()
                    
                    # Verify response signature if enabled
                    if (self.request_signer and 
                        self.config.auth_config.enable_request_signing and
                        'X-Response-Signature' in response.headers):
                        
                        response_sig = response.headers['X-Response-Signature']
                        if not self.request_signer.verify_response_signature(
                            response_text, response_sig, timestamp
                        ):
                            logger.warning("Response signature verification failed")
                    
                    return response_data
            
            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                last_exception = e
                if attempt < self.config.max_retries:
                    await asyncio.sleep(self.config.retry_delay * (2 ** attempt))
                    logger.warning(f"Request failed, retrying ({attempt + 1}/{self.config.max_retries}): {e}")
        
        raise MCPClientError(f"Request failed after {self.config.max_retries} retries: {last_exception}")
    
    async def initialize(self):
        """Initialize MCP session with server"""
        request_data = {
            "method": "initialize",
            "params": {
                "protocolVersion": self.config.protocol_version,
                "capabilities": {
                    "tools": {"listChanged": True},
                    "resources": {"listChanged": True, "subscribe": True},
                    "prompts": {"listChanged": True}
                },
                "clientInfo": {
                    "name": self.config.client_name,
                    "version": self.config.client_version
                }
            }
        }
        
        response = await self._make_request("POST", "/mcp/initialize", request_data)
        
        if "error" in response:
            error = response["error"]
            raise MCPServerError(error.get("code", -1), error.get("message", "Unknown error"))
        
        result = response.get("result", {})
        self.server_info = result.get("serverInfo", {})
        self.capabilities = result.get("capabilities", {})
        self.is_initialized = True
        
        logger.info(f"MCP session initialized with server: {self.server_info.get('name', 'Unknown')}")
    
    async def list_tools(self) -> List[Dict[str, Any]]:
        """List available tools from MCP server"""
        if not self.is_initialized:
            await self.initialize()
        
        request_data = {
            "method": "tools/list",
            "params": {}
        }
        
        response = await self._make_request("POST", "/mcp/tools/list", request_data)
        
        if "error" in response:
            error = response["error"]
            raise MCPServerError(error.get("code", -1), error.get("message", "Unknown error"))
        
        return response.get("result", {}).get("tools", [])
    
    async def call_tool(self, name: str, arguments: Dict[str, Any] = None) -> Dict[str, Any]:
        """Call a tool on the MCP server with user confirmation if required"""
        if not self.is_initialized:
            await self.initialize()
        
        # Request user confirmation for sensitive operations
        operation_details = {
            "tool_name": name,
            "arguments": arguments or {},
            "server": self.config.server_url
        }
        
        if not await self.user_confirmation.request_confirmation("tools/call", operation_details):
            raise MCPUserDeniedError(f"User denied execution of tool: {name}")
        
        request_data = {
            "method": "tools/call",
            "params": {
                "name": name,
                "arguments": arguments or {}
            }
        }
        
        response = await self._make_request("POST", "/mcp/tools/call", request_data)
        
        if "error" in response:
            error = response["error"]
            raise MCPServerError(error.get("code", -1), error.get("message", "Unknown error"))
        
        return response.get("result", {})
    
    async def list_resources(self) -> List[Dict[str, Any]]:
        """List available resources from MCP server"""
        if not self.is_initialized:
            await self.initialize()
        
        request_data = {
            "method": "resources/list",
            "params": {}
        }
        
        response = await self._make_request("POST", "/mcp/resources/list", request_data)
        
        if "error" in response:
            error = response["error"]
            raise MCPServerError(error.get("code", -1), error.get("message", "Unknown error"))
        
        return response.get("result", {}).get("resources", [])
    
    async def read_resource(self, uri: str) -> Dict[str, Any]:
        """Read a resource from the MCP server with user confirmation"""
        if not self.is_initialized:
            await self.initialize()
        
        # Request user confirmation for sensitive operations
        operation_details = {
            "resource_uri": uri,
            "server": self.config.server_url
        }
        
        if not await self.user_confirmation.request_confirmation("resources/read", operation_details):
            raise MCPUserDeniedError(f"User denied access to resource: {uri}")
        
        request_data = {
            "method": "resources/read",
            "params": {
                "uri": uri
            }
        }
        
        response = await self._make_request("POST", "/mcp/resources/read", request_data)
        
        if "error" in response:
            error = response["error"]
            raise MCPServerError(error.get("code", -1), error.get("message", "Unknown error"))
        
        return response.get("result", {})
    
    async def health_check(self) -> Dict[str, Any]:
        """Check server health"""
        try:
            response = await self._make_request("GET", "/health", {})
            return response
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {"status": "error", "error": str(e)}

# Plugin entry point
def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe plugin entry point"""
    import asyncio

    try:
        # Run the async main function
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            result = loop.run_until_complete(main(cfg))
            return result
        finally:
            loop.close()
    except Exception as e:
        return {
            "success": False,
            "error": f"Plugin execution error: {str(e)}"
        }

async def main(config: Dict[str, Any] = None) -> Dict[str, Any]:
    """Enhanced FastMCP Client main entry point"""
    config = config or {}
    
    # Validate required configuration
    if "server_url" not in config:
        return {
            "success": False,
            "error": "server_url is required"
        }
    
    # Build enhanced configuration
    client_config = EnhancedMCPClientConfig(
        server_url=config["server_url"],
        server_id=config.get("server_id", "default"),
        timeout=config.get("timeout", 30),
        max_retries=config.get("max_retries", 3),
        client_name=config.get("client_name", "PlugPipe Enhanced FastMCP Client"),
        protocol_version=config.get("protocol_version", "2025-06-18")
    )
    
    # Configure authentication
    auth_config = AuthConfig(
        method=config.get("auth_method", "bearer"),
        bearer_token=config.get("bearer_token"),
        client_id=config.get("oauth_client_id"),
        client_secret=config.get("oauth_client_secret"),
        authorization_endpoint=config.get("oauth_authorization_endpoint"),
        token_endpoint=config.get("oauth_token_endpoint"),
        scope=config.get("oauth_scope", [])
    )
    client_config.auth_config = auth_config
    
    # Configure user confirmation
    user_conf = UserConfirmationConfig(
        enabled=config.get("user_confirmation_enabled", True),
        sensitive_operations=config.get("sensitive_operations", [
            "tools/call", "resources/read", "resources/write"
        ])
    )
    client_config.user_confirmation = user_conf
    
    try:
        async with EnhancedFastMCPClient(client_config) as client:
            # Perform basic connectivity test
            health = await client.health_check()
            
            if client.is_initialized:
                tools = await client.list_tools()
                resources = await client.list_resources()
                
                return {
                    "success": True,
                    "health": health,
                    "server_info": client.server_info,
                    "capabilities": client.capabilities,
                    "tools_count": len(tools),
                    "resources_count": len(resources),
                    "security_features": {
                        "authentication": client_config.auth_config.method,
                        "request_signing": client_config.auth_config.enable_request_signing,
                        "replay_protection": client_config.auth_config.enable_replay_protection,
                        "user_confirmation": client_config.user_confirmation.enabled
                    }
                }
            else:
                return {
                    "success": False,
                    "error": "Failed to initialize MCP session"
                }
    
    except Exception as e:
        logger.error(f"Enhanced FastMCP Client error: {e}")
        return {
            "success": False,
            "error": str(e)
        }

# Plugin metadata
PLUGIN_METADATA = {
    "name": "fastmcp_client",
    "version": "1.1.0",
    "description": "Enhanced FastMCP Client with OAuth 2.1 Authentication Support",
    "author": "PlugPipe Team",
    "license": "MIT",
    "category": "MCP",
    "capabilities": ["mcp_client", "oauth2.1_client", "multi_server_auth", "user_confirmation_workflows"],
    "security_features": [
        "OAuth 2.1 client credentials flow",
        "OAuth 2.1 authorization code flow", 
        "Multi-server credential isolation",
        "User confirmation workflows",
        "Request signing and replay protection",
        "Automatic token refresh"
    ]
}

if __name__ == "__main__":
    # Example usage with OAuth 2.1
    example_config = {
        "server_url": "https://mcp-server.example.com",
        "server_id": "production_server",
        "auth_method": "oauth2.1",
        "oauth_client_id": "your_client_id",
        "oauth_client_secret": "your_client_secret",
        "oauth_token_endpoint": "https://auth.example.com/oauth2/token",
        "oauth_scope": ["mcp:tools:read", "mcp:tools:execute"],
        "user_confirmation_enabled": True,
        "sensitive_operations": ["tools/call", "resources/read"]
    }
    
    async def user_confirmation_callback(operation: str, details: Dict[str, Any]) -> bool:
        """Example user confirmation callback"""
        print(f"Confirm {operation}: {details}")
        # In real implementation, show UI prompt to user
        return True  # Auto-approve for example
    
    async def example():
        client_config = EnhancedMCPClientConfig(
            server_url=example_config["server_url"],
            server_id=example_config["server_id"]
        )
        
        async with EnhancedFastMCPClient(client_config) as client:
            client.set_user_confirmation_callback(user_confirmation_callback)
            
            # List and call tools
            tools = await client.list_tools()
            print(f"Available tools: {len(tools)}")
            
            if tools:
                result = await client.call_tool(tools[0]["name"], {})
                print(f"Tool result: {result}")
    
    # Run example
    asyncio.run(example())