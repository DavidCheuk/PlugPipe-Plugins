# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
MCP Guardian - Layered Universal Security Architecture
Enterprise Security Proxy with Category-Aware Multi-Action Voting

This version implements proper layered security architecture where:
- Each security layer processes requests sequentially
- Multi-action voting only occurs within plugin categories (not globally)  
- Different security concerns (auth, threats, data, infrastructure) are handled distinctly

Author: PlugPipe Security Team
Version: 1.0.0_layered_universal
"""

import asyncio
import json
import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, asdict
from enum import Enum

# Import PlugPipe core functionality
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../../..'))
from shares.loader import pp

# Import Universal Security Interface
try:
    from shares.security.universal_security_plugin_interface import (
        SecurityAction, ThreatLevel, SecurityPluginResult, 
        SecurityPluginContext, ThreatDetection
    )
    UNIVERSAL_INTERFACE_AVAILABLE = True
except ImportError:
    # Fallback definitions if universal interface not available
    class SecurityAction(Enum):
        ALLOW = "ALLOW"
        BLOCK = "BLOCK"
        MODIFY = "MODIFY"
        REVIEW = "REVIEW"
    
    class ThreatLevel(Enum):
        NONE = "none"
        LOW = "low"
        MEDIUM = "medium"
        HIGH = "high"
        CRITICAL = "critical"
        
    UNIVERSAL_INTERFACE_AVAILABLE = False

import structlog


class SecurityLevel(str, Enum):
    """Security level enumeration"""
    BASIC = "basic"
    STANDARD = "standard" 
    ENTERPRISE = "enterprise"


class SecurityLayer(str, Enum):
    """Security layer enumeration for layered processing"""
    AUTHENTICATION = "authentication"
    THREAT_PROTECTION = "threat_protection"
    DATA_PROTECTION = "data_protection"
    INFRASTRUCTURE = "infrastructure"


@dataclass
class LayeredSecurityResult:
    """Result from a specific security layer"""
    layer: SecurityLayer
    action: SecurityAction
    threat_score: float = 0.0
    threats_detected: List[Dict[str, Any]] = None
    plugin_results: Dict[str, Any] = None
    layer_decision: str = ""
    processing_time_ms: float = 0.0
    
    def __post_init__(self):
        if self.threats_detected is None:
            self.threats_detected = []
        if self.plugin_results is None:
            self.plugin_results = {}


@dataclass
class SecurityContext:
    """Security context for request processing - Universal Interface Compatible"""
    request_id: str
    tenant_id: Optional[str]
    user_id: Optional[str]
    client_id: Optional[str]
    scopes: List[str]
    timestamp: float
    source_ip: str
    user_agent: str
    original_request: Dict[str, Any]
    security_level: SecurityLevel
    
    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
    
    def to_universal_context(self) -> Dict[str, Any]:
        """Convert to universal security plugin context format"""
        # Extract content from MCP request
        content = ""
        if isinstance(self.original_request, dict):
            if 'params' in self.original_request and 'payload' in self.original_request['params']:
                content = str(self.original_request['params']['payload'])
            elif 'payload' in self.original_request:
                content = str(self.original_request['payload'])
            elif 'body' in self.original_request:
                content = str(self.original_request['body'])
            else:
                content = str(self.original_request)
        
        return {
            'content': content,
            'operation': 'analyze_security',
            'content_type': 'mcp_request',
            'source_ip': self.source_ip,
            'user_id': self.user_id,
            'request_id': self.request_id,
            'text': content,  # Legacy compatibility
            'payload': content,  # Legacy compatibility
            'metadata': {
                'tenant_id': self.tenant_id,
                'client_id': self.client_id,
                'scopes': self.scopes,
                'security_level': self.security_level.value,
                'timestamp': self.timestamp,
                'user_agent': self.user_agent,
                'original_request': self.original_request
            }
        }


@dataclass 
class UniversalLayeredSecurityResult:
    """Final universal format security result from layered processing"""
    action: SecurityAction
    modified_request: Optional[Dict[str, Any]] = None
    threats_detected: List[Dict[str, Any]] = None
    threat_score: float = 0.0
    layer_results: Dict[SecurityLayer, LayeredSecurityResult] = None
    audit_data: Dict[str, Any] = None
    response_time_ms: float = 0.0
    blocking_layer: Optional[SecurityLayer] = None
    
    def __post_init__(self):
        if self.threats_detected is None:
            self.threats_detected = []
        if self.layer_results is None:
            self.layer_results = {}
        if self.audit_data is None:
            self.audit_data = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with universal format"""
        result = asdict(self)
        # Convert enums to strings
        result['action'] = self.action.value if hasattr(self.action, 'value') else str(self.action)
        if self.blocking_layer:
            result['blocking_layer'] = self.blocking_layer.value
        
        # Convert layer_results 
        if self.layer_results:
            layer_dict = {}
            for layer, layer_result in self.layer_results.items():
                layer_dict[layer.value] = {
                    'action': layer_result.action.value if hasattr(layer_result.action, 'value') else str(layer_result.action),
                    'threat_score': layer_result.threat_score,
                    'threats_detected': layer_result.threats_detected,
                    'plugin_results': layer_result.plugin_results,
                    'layer_decision': layer_result.layer_decision,
                    'processing_time_ms': layer_result.processing_time_ms
                }
            result['layer_results'] = layer_dict
        
        return result


class LayeredUniversalSecurityOrchestrator:
    """Layered Universal Interface Security Plugin Orchestrator"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.security_level = SecurityLevel(config.get('security_profile', 'standard'))
        self.logger = structlog.get_logger(__name__)
        self.plugin_timeout = config.get('plugin_timeout', 30)
        
        # Load universal security interface
        self.universal_interface = None
        try:
            self.universal_interface = pp("universal_security_interface")
            if self.universal_interface:
                self.logger.info("Universal Security Interface loaded successfully")
            else:
                self.logger.warning("Universal Security Interface not available")
        except Exception as e:
            self.logger.error(f"Failed to load Universal Security Interface: {e}")
        
        # Load security plugins organized by layers
        self.security_layers = self._load_layered_security_plugins()
        
    def _load_layered_security_plugins(self) -> Dict[SecurityLayer, List[str]]:
        """Load security plugins organized by security layers per enterprise architecture"""
        
        # Define security layers per enterprise architecture
        layer_plugins = {
            SecurityLayer.AUTHENTICATION: [
                "oauth2_1_mcp_server",      # OAuth 2.1 Resource Server
                "mcp_security_policy_engine", # RBAC/ABAC Policy Engine  
                "auth_oauth2_google"        # Google OAuth Enterprise
            ],
            
            SecurityLayer.THREAT_PROTECTION: [
                "open_appsec", # OWASP LLM01 Primary Defense
                "llm_guard",                    # LLM Security Toolkit
                "garak_scanner"                 # LLM Vulnerability Scanner
            ],
            
            SecurityLayer.DATA_PROTECTION: [
                "presidio_dlp",                 # PII/DLP Detection
                "cyberpig_ai"                # Secret/Credential Detection
            ],
            
            SecurityLayer.INFRASTRUCTURE: [
                "mcp_security_middleware",      # Security Orchestration
                "enhanced_mcp_schema_validation" # MCP Protocol Validation
            ]
        }
        
        # Filter plugins by availability and log results
        available_layers = {}
        for layer, plugin_list in layer_plugins.items():
            available_plugins = []
            for plugin_name in plugin_list:
                try:
                    plugin_wrapper = pp(plugin_name)
                    if plugin_wrapper is not None:
                        available_plugins.append(plugin_name)
                        self.logger.debug(f"Loaded {layer.value} plugin: {plugin_name}")
                    else:
                        self.logger.warning(f"{layer.value} plugin not available: {plugin_name}")
                except Exception as e:
                    self.logger.error(f"Failed to load {layer.value} plugin {plugin_name}: {str(e)}")
            
            available_layers[layer] = available_plugins
            self.logger.info(f"{layer.value}: {len(available_plugins)}/{len(plugin_list)} plugins available")
        
        total_available = sum(len(plugins) for plugins in available_layers.values())
        total_documented = sum(len(plugins) for plugins in layer_plugins.values())
        self.logger.info(f"Layered MCP Guardian loaded {total_available}/{total_documented} security plugins across {len(available_layers)} layers")
        
        return available_layers

    async def execute_layered_security_pipeline(self, context: SecurityContext) -> UniversalLayeredSecurityResult:
        """Execute the layered security pipeline with category-aware voting"""
        start_time = time.time()
        
        result = UniversalLayeredSecurityResult(
            action=SecurityAction.ALLOW,
            threat_score=0.0,
            layer_results={},
            audit_data={
                "request_id": context.request_id,
                "tenant_id": context.tenant_id,
                "timestamp": context.timestamp,
                "security_level": context.security_level.value,
                "universal_interface_enabled": UNIVERSAL_INTERFACE_AVAILABLE,
                "layered_architecture": True
            }
        )
        
        try:
            # Convert to universal context format
            universal_context = context.to_universal_context()
            
            self.logger.info(f"Starting layered security evaluation across {len(self.security_layers)} security layers")
            
            # Process each security layer SEQUENTIALLY (not concurrently)
            for layer in [SecurityLayer.AUTHENTICATION, SecurityLayer.THREAT_PROTECTION, 
                         SecurityLayer.DATA_PROTECTION, SecurityLayer.INFRASTRUCTURE]:
                
                if layer not in self.security_layers or not self.security_layers[layer]:
                    self.logger.warning(f"Security layer {layer.value} has no available plugins")
                    continue
                
                layer_result = await self._process_security_layer(layer, universal_context)
                result.layer_results[layer] = layer_result
                
                # Accumulate threats and scores across layers
                result.threats_detected.extend(layer_result.threats_detected)
                result.threat_score = max(result.threat_score, layer_result.threat_score)
                
                # CRITICAL: Authentication/Authorization layers block immediately
                if layer == SecurityLayer.AUTHENTICATION and layer_result.action == SecurityAction.BLOCK:
                    result.action = SecurityAction.BLOCK
                    result.blocking_layer = layer
                    self.logger.info(f"REQUEST BLOCKED BY AUTHENTICATION LAYER: {layer_result.layer_decision}")
                    break
                
                # Other layers can influence final decision but don't immediately block
                elif layer_result.action == SecurityAction.BLOCK:
                    if result.action != SecurityAction.BLOCK:  # First block decision
                        result.action = SecurityAction.BLOCK
                        result.blocking_layer = layer
                        # Continue processing other layers for comprehensive audit
                
                elif layer_result.action == SecurityAction.MODIFY:
                    if result.action == SecurityAction.ALLOW:  # Escalate to MODIFY
                        result.action = SecurityAction.MODIFY
                        
                elif layer_result.action == SecurityAction.REVIEW:
                    if result.action in [SecurityAction.ALLOW]:  # Escalate to REVIEW
                        result.action = SecurityAction.REVIEW
            
            # Final decision logic based on layered results
            layer_count = len([lr for lr in result.layer_results.values() if lr.plugin_results])
            if layer_count == 0:
                result.action = SecurityAction.BLOCK
                result.audit_data["error"] = "No security layers processed successfully"
                
            self.logger.info(f"Layered security decision: {result.action.value} (processed {layer_count} layers)")
                
        except asyncio.TimeoutError:
            self.logger.error("Layered security pipeline timeout")
            result.action = SecurityAction.BLOCK
            result.audit_data["timeout"] = True
            
        except Exception as e:
            self.logger.error(f"Layered security pipeline error: {str(e)}")
            result.action = SecurityAction.BLOCK
            result.audit_data["error"] = str(e)
        
        result.response_time_ms = (time.time() - start_time) * 1000
        return result

    async def _process_security_layer(self, layer: SecurityLayer, universal_context: Dict[str, Any]) -> LayeredSecurityResult:
        """Process a single security layer with category-aware multi-action voting"""
        layer_start_time = time.time()
        
        layer_plugins = self.security_layers.get(layer, [])
        if not layer_plugins:
            return LayeredSecurityResult(
                layer=layer,
                action=SecurityAction.ALLOW,
                layer_decision=f"No plugins available in {layer.value} layer"
            )
        
        self.logger.info(f"Processing {layer.value} layer with {len(layer_plugins)} plugins: {layer_plugins}")
        
        # Execute all plugins in this layer CONCURRENTLY (same security category)
        plugin_tasks = []
        for plugin_name in layer_plugins:
            task = self._execute_plugin_universal(plugin_name, universal_context)
            plugin_tasks.append(task)
        
        plugin_results = await asyncio.wait_for(
            asyncio.gather(*plugin_tasks, return_exceptions=True),
            timeout=self.plugin_timeout
        )
        
        # CATEGORY-AWARE VOTING: Multi-action voting within this security layer only
        layer_result = self._aggregate_layer_results(layer, layer_plugins, plugin_results)
        layer_result.processing_time_ms = (time.time() - layer_start_time) * 1000
        
        self.logger.info(f"{layer.value} layer decision: {layer_result.action.value} - {layer_result.layer_decision}")
        
        return layer_result

    def _aggregate_layer_results(self, layer: SecurityLayer, plugin_names: List[str], plugin_results: List[Any]) -> LayeredSecurityResult:
        """Aggregate results within a single security layer using category-aware voting"""
        
        # Count votes within this security category only
        block_votes = 0
        allow_votes = 0
        modify_votes = 0
        review_votes = 0
        failed_plugins = 0
        threat_scores = []
        all_threats = []
        high_confidence_blocks = []
        layer_plugin_results = {}
        
        for i, plugin_result in enumerate(plugin_results):
            plugin_name = plugin_names[i]
            
            if isinstance(plugin_result, Exception):
                failed_plugins += 1
                layer_plugin_results[plugin_name] = {"status": "error", "error": str(plugin_result)}
                continue
            
            if not isinstance(plugin_result, dict):
                failed_plugins += 1
                continue
            
            # Parse plugin result with universal format
            parsed_result = self._parse_universal_plugin_result(plugin_result, plugin_name)
            layer_plugin_results[plugin_name] = parsed_result
            
            action = parsed_result.get('action', 'ALLOW')
            threat_score = parsed_result.get('threat_score', 0.0)
            confidence = parsed_result.get('confidence', 0.0)
            threats = parsed_result.get('threats_detected', [])
            
            # Category-specific voting (only within this layer)
            if action == 'BLOCK':
                block_votes += 1
                if confidence > 0.8:
                    high_confidence_blocks.append(plugin_name)
            elif action == 'ALLOW':
                allow_votes += 1
            elif action == 'MODIFY':
                modify_votes += 1
            elif action == 'REVIEW':
                review_votes += 1
            
            threat_scores.append(threat_score)
            all_threats.extend(threats)
        
        # Layer-specific decision logic
        total_voting_plugins = len(plugin_results) - failed_plugins
        avg_threat_score = sum(threat_scores) / max(1, len(threat_scores))
        
        # AUTHENTICATION LAYER: Strict - any block = block entire request
        if layer == SecurityLayer.AUTHENTICATION:
            if block_votes > 0:
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.BLOCK,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=f"Authentication failure: {block_votes} authentication plugins blocked request"
                )
            elif total_voting_plugins == 0:
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.BLOCK,
                    threat_score=1.0,
                    plugin_results=layer_plugin_results,
                    layer_decision="No authentication plugins available - failing secure"
                )
            else:
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.ALLOW,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=f"Authentication successful: {allow_votes} plugins approved access"
                )
        
        # OTHER LAYERS: Category-aware voting within layer
        else:
            if len(high_confidence_blocks) >= 1:  # High confidence block in this category
                decision = f"High confidence threat detected in {layer.value}: {high_confidence_blocks}"
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.BLOCK,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=decision
                )
            
            elif block_votes > allow_votes:  # Majority block in this category
                decision = f"Majority {layer.value} threats detected: {block_votes} block vs {allow_votes} allow votes"
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.BLOCK,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=decision
                )
            
            elif modify_votes > 0 and avg_threat_score > 0.3:
                decision = f"{layer.value} content modification required: {modify_votes} plugins suggest modification"
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.MODIFY,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=decision
                )
            
            elif review_votes > 0 and avg_threat_score > 0.2:
                decision = f"{layer.value} human review recommended: {review_votes} plugins suggest review"
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.REVIEW,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=decision
                )
            
            elif avg_threat_score > 0.1:
                decision = f"{layer.value} threat score threshold exceeded: {avg_threat_score:.3f} > 0.1"
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.BLOCK,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=decision
                )
            
            else:
                decision = f"{layer.value} layer clear: no significant threats detected"
                return LayeredSecurityResult(
                    layer=layer,
                    action=SecurityAction.ALLOW,
                    threat_score=avg_threat_score,
                    threats_detected=all_threats,
                    plugin_results=layer_plugin_results,
                    layer_decision=decision
                )

    async def _execute_plugin_universal(self, plugin_name: str, universal_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute individual security plugin with universal interface format"""
        try:
            # Load plugin with validation
            plugin_wrapper = pp(plugin_name)
            if plugin_wrapper is None:
                raise Exception(f"Plugin {plugin_name} not found")
            if not hasattr(plugin_wrapper, "process"):
                raise Exception(f"Plugin {plugin_name} missing process method")
            
            # Universal interface wrapper for legacy plugins
            if self.universal_interface:
                try:
                    wrap_result = await self.universal_interface.process({
                        'operation': 'wrap_legacy_plugin',
                        'plugin_name': plugin_name,
                        'context': universal_context
                    }, {})
                    
                    if wrap_result.get('status') == 'completed':
                        return wrap_result.get('result', {})
                except Exception as e:
                    self.logger.debug(f"Universal wrapper failed for {plugin_name}, using direct execution: {e}")
            
            # Direct plugin execution with universal context
            plugin_cfg = {}
            
            # Execute with async handling
            if asyncio.iscoroutinefunction(plugin_wrapper.process):
                plugin_result = await plugin_wrapper.process(universal_context, plugin_cfg)
            else:
                plugin_result = plugin_wrapper.process(universal_context, plugin_cfg)
            
            # Ensure universal format compliance
            return self._ensure_universal_format(plugin_result, plugin_name)
            
        except Exception as e:
            self.logger.error(f"Universal plugin execution failed for {plugin_name}: {str(e)}")
            return {
                "status": "error", 
                "error": str(e), 
                "action": "ALLOW",  # Fail open for individual plugin errors
                "threat_score": 0.0,
                "plugin_name": plugin_name
            }

    def _ensure_universal_format(self, plugin_result: Dict[str, Any], plugin_name: str) -> Dict[str, Any]:
        """Ensure plugin result follows universal format"""
        if not isinstance(plugin_result, dict):
            plugin_result = {"raw_result": plugin_result}
        
        # Normalize action field
        action = plugin_result.get('action', 'ALLOW')
        if action not in ['ALLOW', 'BLOCK', 'MODIFY', 'REVIEW']:
            # Map legacy actions
            if (plugin_result.get('status') == 'blocked' or 
                plugin_result.get('blocked', False) or
                plugin_result.get('status') == 'error'):
                action = 'BLOCK'
            else:
                action = 'ALLOW'
        
        # Normalize threat score
        threat_score = plugin_result.get('threat_score', 0.0)
        if not isinstance(threat_score, (int, float)):
            threat_score = 0.0
        
        # Extract threats detected
        threats_detected = plugin_result.get('threats_detected', [])
        if not isinstance(threats_detected, list):
            threats_detected = []
        
        # Ensure universal format fields
        universal_result = {
            'action': action,
            'threat_score': float(threat_score),
            'threats_detected': threats_detected,
            'confidence': plugin_result.get('confidence', 0.5),
            'plugin_name': plugin_name,
            'plugin_version': plugin_result.get('plugin_version', '1.0.0'),
            'processing_time_ms': plugin_result.get('processing_time_ms', 0.0),
            'status': plugin_result.get('status', 'completed'),
            'raw_result': plugin_result  # Preserve original for debugging
        }
        
        return universal_result

    def _parse_universal_plugin_result(self, plugin_result: Dict[str, Any], plugin_name: str) -> Dict[str, Any]:
        """Parse plugin result to extract universal format fields"""
        if plugin_result.get('status') == 'error':
            return {
                'action': 'ALLOW',  # Fail open on plugin errors
                'threat_score': 0.0,
                'threats_detected': [],
                'confidence': 0.0,
                'plugin_name': plugin_name,
                'error': plugin_result.get('error', 'Unknown error')
            }
        
        return self._ensure_universal_format(plugin_result, plugin_name)


# Main MCP Guardian implementation with Layered Universal Interface
class MCPGuardianLayeredUniversal:
    """MCP Guardian with Layered Universal Security Interface Integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = structlog.get_logger(__name__)
        
        # Initialize layered universal security orchestrator
        self.orchestrator = LayeredUniversalSecurityOrchestrator(config)
        
        total_plugins = sum(len(plugins) for plugins in self.orchestrator.security_layers.values())
        self.logger.info(f"MCP Guardian Layered Universal initialized with {total_plugins} security plugins across {len(self.orchestrator.security_layers)} layers")

    async def process_request(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming MCP request through layered universal security pipeline"""
        request_id = f"req_{int(time.time() * 1000000)}"
        
        try:
            # Create security context
            security_context = SecurityContext(
                request_id=request_id,
                tenant_id=context.get('tenant_id'),
                user_id=context.get('user_id'),
                client_id=context.get('client_id'),
                scopes=context.get('scopes', []),
                timestamp=time.time(),
                source_ip=context.get('source_ip', 'unknown'),
                user_agent=context.get('user_agent', 'unknown'),
                original_request=context,
                security_level=SecurityLevel(self.config.get('security_profile', 'standard'))
            )
            
            # Execute layered universal security pipeline
            security_result = await self.orchestrator.execute_layered_security_pipeline(security_context)
            
            # Log layered security decision
            self.logger.info(
                "Layered universal security decision",
                request_id=request_id,
                action=security_result.action.value,
                threat_score=security_result.threat_score,
                threats=len(security_result.threats_detected),
                blocking_layer=security_result.blocking_layer.value if security_result.blocking_layer else None,
                layers_processed=len(security_result.layer_results),
                layered_architecture=True
            )
            
            # Return layered universal format result
            result = security_result.to_dict()
            result.update({
                "request_id": request_id,
                "universal_format": True,
                "layered_architecture": True,
                "mcp_guardian_action": security_result.action.value,
                "processing_time_ms": security_result.response_time_ms
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Layered Universal MCP Guardian processing error: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "action": "BLOCK",
                "mcp_guardian_action": "BLOCK",
                "request_id": request_id,
                "universal_format": True,
                "layered_architecture": True
            }


# Plugin wrapper for PlugPipe integration
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe async entry point for MCP Guardian Layered Universal"""
    try:
        # Initialize MCP Guardian with layered universal interface
        guardian = MCPGuardianLayeredUniversal(cfg)
        
        # Process request through layered universal security pipeline
        result = await guardian.process_request(ctx)
        
        return {
            "status": "completed",
            **result
        }
        
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "universal_interface": True,
            "layered_architecture": True,
            "mcp_guardian_action": "BLOCK",
            "action": "BLOCK"
        }


if __name__ == "__main__":
    # Test the layered universal interface integration
    import asyncio
    
    async def test_layered_universal():
        config = {
            'security_profile': 'standard',
            'plugin_timeout': 10
        }
        
        # Test with API key (should trigger data protection layer)
        test_context = {
            'jsonrpc': '2.0',
            'params': {
                'payload': 'sk-1234567890abcdef1234567890abcdef'  # API key for testing
            }
        }
        
        result = await process(test_context, config)
        print("Layered Universal MCP Guardian Test Results:")
        print(f"Status: {result.get('status')}")
        print(f"Action: {result.get('mcp_guardian_action')}")
        print(f"Layered Architecture: {result.get('layered_architecture')}")
        print(f"Universal Format: {result.get('universal_format')}")
        print(f"Threat Score: {result.get('threat_score', 0)}")
        print(f"Blocking Layer: {result.get('blocking_layer')}")
        
        # Show layer-by-layer results
        layer_results = result.get('layer_results', {})
        print(f"\nLayer Results:")
        for layer_name, layer_data in layer_results.items():
            print(f"  {layer_name}: {layer_data.get('action')} - {layer_data.get('layer_decision')}")
    
    asyncio.run(test_layered_universal())