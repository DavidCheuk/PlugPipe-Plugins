#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Dynamic Format Transformer Plugin
Dynamically transforms raw attack payloads into appropriate protocol formats during testing
"""

import json
import logging
import time
import hashlib
from typing import Dict, Any, List, Optional
from enum import Enum
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Plugin metadata
PLUGIN_METADATA = {
    "name": "dynamic_format_transformer",
    "version": "1.0.0", 
    "description": "Dynamic protocol format transformer for attack payloads during testing",
    "author": "PlugPipe Security",
    "tags": ["security", "format-transformer", "mcp", "http", "websocket", "dynamic"],
    "external_dependencies": [],
    "schema_validation": True
}

class ProtocolFormat(Enum):
    """Supported protocol formats"""
    RAW = "raw"
    MCP = "mcp"
    HTTP = "http"
    WEBSOCKET = "websocket"
    GRAPHQL = "graphql"
    GRPC = "grpc"
    REST_API = "rest_api"

@dataclass
class TransformResult:
    """Result of dynamic format transformation"""
    original_payload: str
    target_format: ProtocolFormat
    transformed_payload: str
    metadata: Dict[str, Any]

class DynamicFormatTransformer:
    """Dynamic format transformer that wraps payloads during testing"""
    
    def __init__(self):
        self.plugin_name = "dynamic_format_transformer"
        
    def detect_best_format(self, payload: str, category: str, target_protocol: str = "auto") -> ProtocolFormat:
        """Dynamically detect the best format for testing this payload"""
        
        # If target protocol is specified, use it
        if target_protocol != "auto":
            try:
                return ProtocolFormat(target_protocol.lower())
            except ValueError:
                pass
        
        # Auto-detect based on payload and category
        if category == "mcp_protocol_abuse":
            return ProtocolFormat.MCP
        elif category in ["xss", "sql_injection", "csrf", "auth_bypass"]:
            return ProtocolFormat.HTTP
        elif category == "prompt_injection":
            return ProtocolFormat.WEBSOCKET
        elif "api" in category.lower():
            return ProtocolFormat.GRAPHQL
        else:
            return ProtocolFormat.RAW
    
    def transform_to_mcp(self, payload: str, category: str, attack_id: str) -> str:
        """Transform payload to MCP JSON-RPC format dynamically"""
        
        # Choose method based on category
        if category == "sql_injection":
            return json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/call",
                "params": {
                    "name": "mysql",
                    "arguments": ["-e", payload]
                },
                "id": attack_id
            }, indent=None)
        
        elif category == "command_injection":
            return json.dumps({
                "jsonrpc": "2.0",
                "method": "tools/call", 
                "params": {
                    "name": "bash",
                    "arguments": ["-c", payload]
                },
                "id": attack_id
            }, indent=None)
        
        elif category == "prompt_injection":
            return json.dumps({
                "jsonrpc": "2.0",
                "method": "sampling/createMessage",
                "params": {
                    "messages": [
                        {
                            "role": "user",
                            "content": payload
                        }
                    ]
                },
                "id": attack_id
            }, indent=None)
        
        elif category == "path_traversal":
            return json.dumps({
                "jsonrpc": "2.0",
                "method": "resources/read",
                "params": {
                    "uri": f"file://{payload}"
                },
                "id": attack_id  
            }, indent=None)
        
        elif category == "secret_exposure":
            return json.dumps({
                "jsonrpc": "2.0",
                "method": "resources/read", 
                "params": {
                    "uri": f"data:text/plain,{payload}"
                },
                "id": attack_id
            }, indent=None)
        
        else:
            # Generic completion wrapper
            return json.dumps({
                "jsonrpc": "2.0",
                "method": "completion/complete",
                "params": {
                    "ref": {
                        "uri": "context://user_input"
                    },
                    "argument": {
                        "name": "query",
                        "value": payload
                    }
                },
                "id": attack_id
            }, indent=None)
    
    def transform_to_http(self, payload: str, category: str, attack_id: str) -> str:
        """Transform payload to HTTP request format dynamically"""
        
        if category == "sql_injection":
            json_body = json.dumps({"query": payload})
            return f"""POST /api/search HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: {len(json_body)}
X-Test-ID: {attack_id}

{json_body}"""
        
        elif category == "xss":
            form_body = f"comment={payload}"
            return f"""POST /submit HTTP/1.1
Host: target.com
Content-Type: application/x-www-form-urlencoded
Content-Length: {len(form_body)}
X-Test-ID: {attack_id}

{form_body}"""
        
        elif category == "auth_bypass":
            json_body = json.dumps({"username": payload, "password": "test"})
            return f"""POST /login HTTP/1.1
Host: target.com
Content-Type: application/json
Content-Length: {len(json_body)}
X-Test-ID: {attack_id}

{json_body}"""
        
        else:
            # Generic GET request
            return f"""GET /search?q={payload} HTTP/1.1
Host: target.com
User-Agent: Attack-Test/{attack_id}
Accept: application/json"""
    
    def transform_to_websocket(self, payload: str, category: str, attack_id: str) -> str:
        """Transform payload to WebSocket message format dynamically"""
        
        if category == "prompt_injection":
            return json.dumps({
                "type": "chat_message",
                "message": payload,
                "user_id": "test_user",
                "test_id": attack_id
            })
        
        elif category == "xss":
            return json.dumps({
                "type": "update_content",
                "content": payload,
                "element_id": "main_content",
                "test_id": attack_id
            })
        
        else:
            return json.dumps({
                "type": "generic_message", 
                "payload": payload,
                "test_id": attack_id
            })
    
    def transform_to_graphql(self, payload: str, category: str, attack_id: str) -> str:
        """Transform payload to GraphQL query format dynamically"""
        
        if category == "sql_injection":
            return json.dumps({
                "query": f"query {{ user(id: \"{payload}\") {{ name email }} }}",
                "variables": {},
                "operationName": f"TestQuery_{attack_id}"
            })
        
        elif category == "auth_bypass":
            return json.dumps({
                "query": "mutation { login(username: $username, password: $password) { token } }",
                "variables": {
                    "username": payload,
                    "password": "test123"
                },
                "operationName": f"LoginMutation_{attack_id}"
            })
        
        else:
            return json.dumps({
                "query": f"query {{ search(term: \"{payload}\") {{ results }} }}",
                "variables": {},
                "operationName": f"SearchQuery_{attack_id}"
            })
    
    def transform_payload(self, 
                         payload: str, 
                         category: str,
                         target_format: str = "auto",
                         attack_id: str = None) -> TransformResult:
        """Dynamically transform payload to target format during testing"""
        
        if not attack_id:
            attack_id = hashlib.md5(payload.encode()).hexdigest()[:8]
        
        # Detect best format
        detected_format = self.detect_best_format(payload, category, target_format)
        
        # Transform based on detected format
        if detected_format == ProtocolFormat.MCP:
            transformed = self.transform_to_mcp(payload, category, attack_id)
        elif detected_format == ProtocolFormat.HTTP:
            transformed = self.transform_to_http(payload, category, attack_id)
        elif detected_format == ProtocolFormat.WEBSOCKET:
            transformed = self.transform_to_websocket(payload, category, attack_id)
        elif detected_format == ProtocolFormat.GRAPHQL:
            transformed = self.transform_to_graphql(payload, category, attack_id)
        else:
            transformed = payload  # Keep raw
        
        return TransformResult(
            original_payload=payload,
            target_format=detected_format,
            transformed_payload=transformed,
            metadata={
                "category": category,
                "attack_id": attack_id,
                "transformation_method": f"transform_to_{detected_format.value}",
                "payload_length": len(payload),
                "transformed_length": len(transformed)
            }
        )
    
    def batch_transform(self, 
                       attack_list: List[Dict[str, Any]], 
                       target_format: str = "auto") -> List[TransformResult]:
        """Batch transform multiple attacks dynamically"""
        
        results = []
        for attack in attack_list:
            result = self.transform_payload(
                payload=attack.get('payload', ''),
                category=attack.get('category', ''),
                target_format=target_format,
                attack_id=attack.get('id', '')
            )
            results.append(result)
        
        return results


def process(ctx, cfg) -> Dict[str, Any]:
    """ULTIMATE FIX: Main plugin entry point - now synchronous with dual parameter handling"""
    start_time = time.time()
    
    try:
        # ULTIMATE FIX: Check BOTH ctx and cfg for input data
        text = ""
        operation = "transform"
        target_format = "mcp"
        
        # Check cfg first (CLI input data)
        if isinstance(cfg, dict):
            text = cfg.get('text') or cfg.get('payload') or cfg.get('content') or cfg.get('input')
            operation = cfg.get('operation', operation)
            target_format = cfg.get('target_format', target_format)
        
        # Check ctx second (MCP/context data)
        if not text and isinstance(ctx, dict):
            text = ctx.get('text') or ctx.get('payload') or ctx.get('input')
            operation = ctx.get('operation', operation)
            target_format = ctx.get('target_format', target_format)
            
            # Handle MCP nested structure
            if 'original_request' in ctx:
                orig = ctx['original_request']
                if isinstance(orig, dict) and 'params' in orig:
                    params = orig['params']
                    if isinstance(params, dict):
                        text = params.get('text') or params.get('payload') or str(params)
        
        # String fallback
        if not text and isinstance(cfg, str):
            text = cfg
        
        # Error handling with debug info
        if not text:
            return {
                "status": "error",
                "error": "No input data found for transformation",
                "debug": {
                    "ctx_type": type(ctx).__name__,
                    "cfg_type": type(cfg).__name__,
                    "ctx_keys": list(ctx.keys()) if isinstance(ctx, dict) else None,
                    "cfg_keys": list(cfg.keys()) if isinstance(cfg, dict) else None
                },
                "expected_params": ["text", "payload", "content"],
                "processing_time_ms": (time.time() - start_time) * 1000
            }
        
        # Initialize transformer
        transformer = DynamicFormatTransformer()
        
        # Universal Security Interface compliance for threat detection
        if operation == 'analyze':
            # Treat text analysis as transformation with threat detection
            result = transformer.transform_payload(text, 'generic', target_format, f"analysis_{int(time.time())}")
            
            # Check if transformation reveals threats (e.g., malicious patterns)
            threats_detected = []
            if any(pattern in text.lower() for pattern in ['inject', 'bypass', 'override', 'malicious']):
                threats_detected.append({
                    "threat_type": "suspicious_payload",
                    "confidence": 0.7,
                    "reason": "Potentially malicious transformation payload detected"
                })
            
            # Calculate threat score for Universal Security Interface
            max_threat_score = max((t.get('confidence', 0.0) for t in threats_detected), default=0.0)
            action = "BLOCK" if len(threats_detected) > 0 else "ALLOW"
            
            return {
                "status": "success",
                "operation": operation,
                # Universal Security Interface fields
                "action": action,
                "threat_score": max_threat_score,
                "threats_detected": threats_detected,
                "plugin_name": "dynamic_format_transformer",
                "confidence": max_threat_score if threats_detected else 0.8,
                "processing_time_ms": (time.time() - start_time) * 1000,
                # Plugin-specific fields
                "transformation_result": {
                    'original_payload': result.original_payload,
                    'target_format': result.target_format.value,
                    'transformed_payload': result.transformed_payload,
                    'metadata': result.metadata
                }
            }
        
        elif operation == 'transform':
            # Single payload transformation - use text as payload
            if not text:
                return {
                    'status': 'error',
                    'error': 'Text/payload is required for transformation',
                    'processing_time_ms': (time.time() - start_time) * 1000
                }
            
            # Get additional parameters from cfg/ctx
            category = 'generic'
            attack_id = f"transform_{int(time.time())}"
            
            if isinstance(cfg, dict):
                category = cfg.get('category', category)
                attack_id = cfg.get('attack_id', attack_id)
            elif isinstance(ctx, dict):
                category = ctx.get('category', category)
                attack_id = ctx.get('attack_id', attack_id)
            
            result = transformer.transform_payload(text, category, target_format, attack_id)
            
            return {
                'status': 'success',
                'operation': operation,
                'result': {
                    'original_payload': result.original_payload,
                    'target_format': result.target_format.value,
                    'transformed_payload': result.transformed_payload,
                    'metadata': result.metadata
                },
                'processing_time_ms': (time.time() - start_time) * 1000
            }
        
        elif operation == 'batch_transform':
            # Batch transformation - get attack list from input
            attack_list = []
            if isinstance(cfg, dict):
                attack_list = cfg.get('attacks', [])
            elif isinstance(ctx, dict):
                attack_list = ctx.get('attacks', [])
            
            if not attack_list:
                return {
                    'status': 'error',
                    'error': 'Attack list is required for batch transformation',
                    'processing_time_ms': (time.time() - start_time) * 1000
                }
            
            results = transformer.batch_transform(attack_list, target_format)
            
            return {
                'status': 'success',
                'operation': operation,
                'results': [
                    {
                        'original_payload': r.original_payload,
                        'target_format': r.target_format.value,
                        'transformed_payload': r.transformed_payload,
                        'metadata': r.metadata
                    } for r in results
                ],
                'total_transformed': len(results),
                'processing_time_ms': (time.time() - start_time) * 1000
            }
        
        elif operation == 'detect_format':
            # Format detection only - use text as payload
            category = 'generic'
            target_protocol = 'auto'
            
            if isinstance(cfg, dict):
                category = cfg.get('category', category)
                target_protocol = cfg.get('target_protocol', target_protocol)
            elif isinstance(ctx, dict):
                category = ctx.get('category', category)
                target_protocol = ctx.get('target_protocol', target_protocol)
            
            detected_format = transformer.detect_best_format(text, category, target_protocol)
            
            return {
                'status': 'success',
                'operation': operation,
                'detected_format': detected_format.value,
                'payload': text,
                'category': category,
                'processing_time_ms': (time.time() - start_time) * 1000
            }
        
        else:
            return {
                'status': 'error',
                'error': f'Unknown operation: {operation}',
                'available_operations': ['analyze', 'transform', 'batch_transform', 'detect_format'],
                'processing_time_ms': (time.time() - start_time) * 1000
            }
            
    except Exception as e:
        logger.error(f"Dynamic format transformer failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'plugin_name': 'dynamic_format_transformer',
            'processing_time_ms': (time.time() - start_time) * 1000
        }


if __name__ == "__main__":
    # Test the dynamic transformer
    import asyncio
    
    async def test_dynamic_transformer():
        # Test single transformation
        result = await process({}, {
            'operation': 'transform',
            'payload': "admin'--",
            'category': 'sql_injection',
            'target_format': 'mcp'
        })
        print(f"Single transform: {result}")
        
        # Test batch transformation
        attacks = [
            {'id': 'SQL_001', 'payload': "admin'--", 'category': 'sql_injection'},
            {'id': 'XSS_001', 'payload': '<script>alert(1)</script>', 'category': 'xss'},
            {'id': 'CMD_001', 'payload': '; cat /etc/passwd', 'category': 'command_injection'}
        ]
        
        result = await process({}, {
            'operation': 'batch_transform',
            'attacks': attacks,
            'target_format': 'auto'
        })
        print(f"Batch transform: {len(result.get('results', []))} transformed")
    
    asyncio.run(test_dynamic_transformer())