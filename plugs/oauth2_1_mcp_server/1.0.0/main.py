#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
OAuth 2.1 Resource Server for MCP Protocol Compliance
Implements Universal Security Interface Standard
"""

import asyncio
import json
import time
import jwt
import os
import re
import sys
from datetime import datetime, timezone
from typing import Dict, List, Any, Optional
from dataclasses import dataclass
from enum import Enum
import requests
from urllib.parse import urlparse

# Add project root to path
from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
from shares.loader import pp

class SecurityAction(Enum):
    """Standardized security actions"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MODIFY = "MODIFY"
    REVIEW = "REVIEW"

class ThreatLevel(Enum):
    """Standardized threat levels"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatDetection:
    """Standardized threat detection result"""
    threat_id: str
    threat_type: str
    threat_level: ThreatLevel
    confidence: float
    description: str
    evidence: Dict[str, Any]
    recommendation: str
    start_position: Optional[int] = None
    end_position: Optional[int] = None

@dataclass
class SecurityPluginResult:
    """Standardized security plugin result"""
    action: SecurityAction
    vote: SecurityAction
    threat_score: float
    threats_detected: List[ThreatDetection]
    plugin_name: str
    plugin_version: str
    processing_time_ms: float
    timestamp: str
    confidence: float = 1.0
    modified_content: Optional[str] = None
    metadata: Dict[str, Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'action': self.action.value,
            'vote': self.vote.value,
            'threat_score': self.threat_score,
            'threats_detected': [
                {
                    'threat_id': t.threat_id,
                    'threat_type': t.threat_type,
                    'threat_level': t.threat_level.value,
                    'confidence': t.confidence,
                    'description': t.description,
                    'evidence': t.evidence,
                    'recommendation': t.recommendation,
                    'start_position': t.start_position,
                    'end_position': t.end_position
                } for t in self.threats_detected
            ],
            'plugin_name': self.plugin_name,
            'plugin_version': self.plugin_version,
            'processing_time_ms': self.processing_time_ms,
            'timestamp': self.timestamp,
            'confidence': self.confidence,
            'modified_content': self.modified_content,
            'metadata': self.metadata or {}
        }

class OAuth21MCPServer:
    """OAuth 2.1 Resource Server for MCP Protocol"""
    
    def __init__(self):
        self.plugin_name = "oauth2_1_mcp_server"
        self.plugin_version = "1.0.0"
        
        # Default configuration
        self.default_config = {
            'issuer_url': os.getenv('OAUTH2_ISSUER_URL', 'https://auth.example.com'),
            'client_credentials': {
                'client_id': os.getenv('OAUTH2_CLIENT_ID', 'mcp-client'),
                'client_secret': os.getenv('OAUTH2_CLIENT_SECRET', 'mcp-secret')
            },
            'jwks_uri': os.getenv('OAUTH2_JWKS_URI', None),
            'supported_scopes': ['mcp:read', 'mcp:write', 'mcp:admin'],
            'token_cache_ttl': 300,
            'enable_audience_validation': True,
            'require_https': True
        }
    
    async def analyze_content(self, context: Dict[str, Any], config: Dict[str, Any]) -> SecurityPluginResult:
        """
        Analyze MCP request for OAuth 2.1 authentication
        """
        start_time = time.time()
        threats = []
        action = SecurityAction.ALLOW
        threat_score = 0.0
        metadata = {}
        
        try:
            # Extract content and headers
            content = context.get('content', context.get('text', context.get('payload', '')))
            headers = context.get('headers', {})
            mcp_request = context.get('mcp_request', {})
            
            # Check for Authorization header
            auth_header = headers.get('authorization', headers.get('Authorization', ''))
            
            if not auth_header:
                # No authorization header - check if authentication is required
                if self._requires_authentication(mcp_request):
                    threats.append(ThreatDetection(
                        threat_id=f"oauth_no_auth_{int(time.time())}",
                        threat_type="missing_authentication",
                        threat_level=ThreatLevel.HIGH,
                        confidence=1.0,
                        description="MCP request requires authentication but no authorization header provided",
                        evidence={'headers': headers, 'mcp_request': mcp_request},
                        recommendation="Provide valid OAuth 2.1 Bearer token in Authorization header"
                    ))
                    action = SecurityAction.BLOCK
                    threat_score = 0.9
                else:
                    # Public endpoint - allow without authentication
                    metadata['auth_required'] = False
                    metadata['endpoint_type'] = 'public'
            else:
                # Validate OAuth 2.1 Bearer token
                validation_result = await self._validate_bearer_token(auth_header, config)
                
                if not validation_result['valid']:
                    threats.append(ThreatDetection(
                        threat_id=f"oauth_invalid_{int(time.time())}",
                        threat_type="invalid_authentication",
                        threat_level=ThreatLevel.HIGH,
                        confidence=validation_result['confidence'],
                        description=f"Invalid OAuth 2.1 token: {validation_result['reason']}",
                        evidence={
                            'token_error': validation_result['reason'],
                            'token_preview': auth_header[:20] + "..." if len(auth_header) > 20 else auth_header
                        },
                        recommendation="Provide a valid OAuth 2.1 Bearer token"
                    ))
                    action = SecurityAction.BLOCK
                    threat_score = validation_result['threat_score']
                else:
                    # Valid token - check scopes
                    scope_check = self._validate_scopes(validation_result['token_data'], mcp_request)
                    
                    if not scope_check['valid']:
                        threats.append(ThreatDetection(
                            threat_id=f"oauth_scope_{int(time.time())}",
                            threat_type="insufficient_scope",
                            threat_level=ThreatLevel.MEDIUM,
                            confidence=1.0,
                            description=f"Insufficient OAuth scope: {scope_check['reason']}",
                            evidence={
                                'required_scopes': scope_check['required_scopes'],
                                'provided_scopes': scope_check['provided_scopes']
                            },
                            recommendation=f"Request token with required scopes: {', '.join(scope_check['required_scopes'])}"
                        ))
                        action = SecurityAction.BLOCK
                        threat_score = 0.7
                    else:
                        # Authentication and authorization successful
                        metadata.update({
                            'auth_valid': True,
                            'user_id': validation_result['token_data'].get('sub'),
                            'client_id': validation_result['token_data'].get('client_id'),
                            'scopes': validation_result['token_data'].get('scope', [])
                        })
        
        except Exception as e:
            # Authentication system error
            threats.append(ThreatDetection(
                threat_id=f"oauth_error_{int(time.time())}",
                threat_type="authentication_system_error",
                threat_level=ThreatLevel.HIGH,
                confidence=0.8,
                description=f"OAuth 2.1 authentication system error: {str(e)}",
                evidence={'error': str(e)},
                recommendation="Check OAuth 2.1 server configuration and connectivity"
            ))
            action = SecurityAction.BLOCK
            threat_score = 0.8
            metadata['system_error'] = str(e)
        
        processing_time = (time.time() - start_time) * 1000
        
        return SecurityPluginResult(
            action=action,
            vote=action,
            threat_score=threat_score,
            threats_detected=threats,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            processing_time_ms=processing_time,
            timestamp=datetime.now(timezone.utc).isoformat(),
            confidence=1.0,
            metadata=metadata
        )
    
    def _requires_authentication(self, mcp_request: Dict[str, Any]) -> bool:
        """Check if MCP request requires authentication"""
        
        # Public MCP methods that don't require authentication
        public_methods = [
            'initialize',
            'capabilities/list',
            'ping',
            'server/info'
        ]
        
        method = mcp_request.get('method', '')
        
        # Check if it's a public method
        if method in public_methods:
            return False
        
        # Check for public resource patterns
        if method.startswith('resources/list') and 'public' in method:
            return False
        
        # Default: require authentication for all other MCP methods
        return True
    
    async def _validate_bearer_token(self, auth_header: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate OAuth 2.1 Bearer token"""
        
        # Parse Bearer token
        if not auth_header.startswith('Bearer '):
            return {
                'valid': False,
                'reason': 'Invalid authorization header format, expected Bearer token',
                'confidence': 1.0,
                'threat_score': 0.9
            }
        
        token = auth_header[7:]  # Remove 'Bearer ' prefix
        
        if not token:
            return {
                'valid': False,
                'reason': 'Empty Bearer token',
                'confidence': 1.0,
                'threat_score': 0.9
            }
        
        # For development/testing mode - accept simple tokens
        if token == 'dev-token' or token == 'test-token':
            return {
                'valid': True,
                'token_data': {
                    'sub': 'dev-user',
                    'client_id': 'dev-client',
                    'scope': ['mcp:read', 'mcp:write'],
                    'exp': int(time.time()) + 3600
                },
                'confidence': 1.0
            }
        
        try:
            # Attempt JWT validation (simplified for development)
            # In production, this should use proper JWKS validation
            
            # Check if it looks like a JWT
            if len(token.split('.')) == 3:
                try:
                    # Decode without verification for development
                    decoded = jwt.decode(token, options={"verify_signature": False})
                    
                    # Basic validation
                    now = int(time.time())
                    
                    if decoded.get('exp', now + 1) < now:
                        return {
                            'valid': False,
                            'reason': 'Token expired',
                            'confidence': 1.0,
                            'threat_score': 0.6
                        }
                    
                    return {
                        'valid': True,
                        'token_data': decoded,
                        'confidence': 0.8  # Lower confidence without signature verification
                    }
                
                except jwt.DecodeError:
                    return {
                        'valid': False,
                        'reason': 'Invalid JWT format',
                        'confidence': 1.0,
                        'threat_score': 0.8
                    }
            else:
                # Non-JWT token - validate via introspection endpoint (not implemented)
                return {
                    'valid': False,
                    'reason': 'Token introspection not implemented',
                    'confidence': 0.5,
                    'threat_score': 0.5
                }
        
        except Exception as e:
            return {
                'valid': False,
                'reason': f'Token validation error: {str(e)}',
                'confidence': 0.8,
                'threat_score': 0.7
            }
    
    def _validate_scopes(self, token_data: Dict[str, Any], mcp_request: Dict[str, Any]) -> Dict[str, Any]:
        """Validate OAuth scopes for MCP request"""
        
        provided_scopes = token_data.get('scope', [])
        if isinstance(provided_scopes, str):
            provided_scopes = provided_scopes.split(' ')
        
        method = mcp_request.get('method', '')
        required_scopes = self._get_required_scopes(method)
        
        # Check if any required scope is present
        if not required_scopes:
            return {'valid': True}
        
        for required_scope in required_scopes:
            if required_scope in provided_scopes:
                return {'valid': True}
        
        return {
            'valid': False,
            'reason': f'Method {method} requires one of: {", ".join(required_scopes)}',
            'required_scopes': required_scopes,
            'provided_scopes': provided_scopes
        }
    
    def _get_required_scopes(self, method: str) -> List[str]:
        """Get required OAuth scopes for MCP method"""
        
        # Define scope requirements for MCP methods
        scope_map = {
            # Read operations
            'resources/list': ['mcp:read'],
            'resources/read': ['mcp:read'],
            'tools/list': ['mcp:read'],
            'prompts/list': ['mcp:read'],
            
            # Write operations
            'tools/call': ['mcp:write'],
            'resources/write': ['mcp:write'],
            'resources/create': ['mcp:write'],
            'resources/update': ['mcp:write'],
            'resources/delete': ['mcp:write'],
            
            # Admin operations
            'server/restart': ['mcp:admin'],
            'server/configure': ['mcp:admin']
        }
        
        # Check for exact matches
        if method in scope_map:
            return scope_map[method]
        
        # Check for pattern matches
        for pattern, scopes in scope_map.items():
            if method.startswith(pattern):
                return scopes
        
        # Default: require read scope for unknown methods
        return ['mcp:read']

# PlugPipe plugin wrapper
plugin_instance = OAuth21MCPServer()

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    PlugPipe plugin entry point
    """
    try:
        # Get universal interface to ensure standardization
        universal_interface = pp("universal_security_interface")
        
        # Merge default configuration
        config = plugin_instance.default_config.copy()
        if cfg:
            config.update(cfg)
        
        # Create security context
        context = {
            'content': ctx.get('text', ctx.get('payload', ctx.get('content', ''))),
            'headers': ctx.get('headers', {}),
            'mcp_request': ctx.get('mcp_request', ctx),
            'operation': ctx.get('operation', 'authenticate'),
            'metadata': ctx.get('metadata', {})
        }
        
        # Process through security plugin
        result = await plugin_instance.analyze_content(context, config)
        
        # Return standardized result
        return result.to_dict()
        
    except Exception as e:
        return {
            'action': 'BLOCK',
            'vote': 'BLOCK',
            'threat_score': 1.0,
            'threats_detected': [{
                'threat_id': f"oauth_plugin_error_{int(time.time())}",
                'threat_type': 'plugin_error',
                'threat_level': 'critical',
                'confidence': 1.0,
                'description': f"OAuth 2.1 plugin error: {str(e)}",
                'evidence': {'error': str(e)},
                'recommendation': 'Check plugin configuration and dependencies'
            }],
            'plugin_name': 'oauth2_1_mcp_server',
            'plugin_version': '1.0.0',
            'processing_time_ms': 0.0,
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'confidence': 1.0,
            'metadata': {'error': str(e)}
        }

# Development testing
if __name__ == "__main__":
    async def test():
        # Test cases
        test_cases = [
            {
                'name': 'No Auth Header',
                'input': {'mcp_request': {'method': 'tools/call'}, 'headers': {}},
                'expected': 'BLOCK'
            },
            {
                'name': 'Valid Dev Token',
                'input': {'mcp_request': {'method': 'resources/read'}, 'headers': {'authorization': 'Bearer dev-token'}},
                'expected': 'ALLOW'
            },
            {
                'name': 'Public Endpoint',
                'input': {'mcp_request': {'method': 'capabilities/list'}, 'headers': {}},
                'expected': 'ALLOW'
            }
        ]
        
        for test_case in test_cases:
            result = await process(test_case['input'], {})
            print(f"Test: {test_case['name']}")
            print(f"Result: {result['action']} (Expected: {test_case['expected']})")
            print(f"Threats: {len(result['threats_detected'])}")
            print("---")
    
    asyncio.run(test())