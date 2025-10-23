# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
MCP Guardian - Universal Security Interface Enhanced Version
Enterprise Security Proxy for Model Context Protocol with Universal Interface Integration

This version integrates the Universal Security Interface Standard to ensure
consistent format handling across all security plugins.

Author: PlugPipe Security Team
Version: 1.0.0_universal
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
class UniversalSecurityResult:
    """Universal format security result"""
    action: SecurityAction
    modified_request: Optional[Dict[str, Any]] = None
    threats_detected: List[Dict[str, Any]] = None
    threat_score: float = 0.0
    plugin_results: Dict[str, Any] = None
    audit_data: Dict[str, Any] = None
    response_time_ms: float = 0.0
    
    def __post_init__(self):
        if self.threats_detected is None:
            self.threats_detected = []
        if self.plugin_results is None:
            self.plugin_results = {}
        if self.audit_data is None:
            self.audit_data = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with universal format"""
        result = asdict(self)
        # Convert enum to string
        result['action'] = self.action.value if hasattr(self.action, 'value') else str(self.action)
        return result


class UniversalSecurityPluginOrchestrator:
    """Universal Interface Enhanced Security Plugin Orchestrator"""
    
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
        
        # Load security plugins with enhanced monitoring
        self.security_plugins = self._load_security_plugins()
        
    def _load_security_plugins(self) -> List[str]:
        """Load security plugins per MCP Guardian enterprise architecture"""
        # Load documented security plugins
        documented_plugins = [
            "cyberpig_ai", "presidio_dlp", "open_appsec", 
            "llm_guard", "garak_scanner", "mcp_security_middleware",
            "enhanced_mcp_schema_validation", "mcp_security_policy_engine",
            "oauth2_1_mcp_server", "auth_oauth2_google"
        ]
        
        # Filter out plugins that aren't available (graceful degradation)
        available_plugins = []
        for plugin_name in documented_plugins:
            try:
                plugin_wrapper = pp(plugin_name)
                if plugin_wrapper is not None:
                    available_plugins.append(plugin_name)
                    self.logger.debug(f"Loaded security plugin: {plugin_name}")
                else:
                    self.logger.warning(f"Security plugin not available: {plugin_name}")
            except Exception as e:
                self.logger.error(f"Failed to load plugin {plugin_name}: {str(e)}")
        
        self.logger.info(f"MCP Guardian Universal loaded {len(available_plugins)}/{len(documented_plugins)} security plugins")
        return available_plugins

    async def execute_security_pipeline(self, context: SecurityContext) -> UniversalSecurityResult:
        """Execute the security pipeline with universal interface format"""
        start_time = time.time()
        
        result = UniversalSecurityResult(
            action=SecurityAction.ALLOW,
            threat_score=0.0,
            plugin_results={},
            audit_data={
                "request_id": context.request_id,
                "tenant_id": context.tenant_id,
                "timestamp": context.timestamp,
                "security_level": context.security_level.value,
                "universal_interface_enabled": UNIVERSAL_INTERFACE_AVAILABLE
            }
        )
        
        try:
            # SECURITY HARDENING: Validate plugin count
            if not self.security_plugins:
                self.logger.warning("No security plugins loaded - failing secure")
                result.action = SecurityAction.BLOCK
                result.audit_data["error"] = "No security plugins available"
                return result
            
            # Convert to universal context format
            universal_context = context.to_universal_context()
            
            # UNIVERSAL INTERFACE: Execute plugins CONCURRENTLY with universal format
            self.logger.info(f"Starting universal interface concurrent evaluation with ALL {len(self.security_plugins)} plugins")
            
            # Create tasks for ALL security plugins to evaluate the same request
            plugin_tasks = []
            for plugin_name in self.security_plugins:
                self.logger.debug(f"Creating universal evaluation task for plugin: {plugin_name}")
                task = self._execute_plugin_universal(plugin_name, universal_context)
                plugin_tasks.append(task)
            
            # Wait for ALL plugins to complete evaluation (concurrent processing)
            plugin_results = await asyncio.wait_for(
                asyncio.gather(*plugin_tasks, return_exceptions=True),
                timeout=self.plugin_timeout
            )
            
            self.logger.info(f"Universal interface concurrent evaluation completed: {len(plugin_results)}/{len(self.security_plugins)} plugins processed")
            
            # UNIVERSAL FORMAT: Process ALL plugin results with standardized voting
            total_threat_score = 0.0
            failed_plugins = 0
            block_votes = 0
            allow_votes = 0
            modify_votes = 0
            review_votes = 0
            plugin_scores = []
            high_confidence_blocks = []
            all_threats = []
            
            for i, plugin_result in enumerate(plugin_results):
                plugin_name = self.security_plugins[i]
                
                if isinstance(plugin_result, Exception):
                    self.logger.error(f"Plugin {plugin_name} failed: {str(plugin_result)}")
                    failed_plugins += 1
                    result.plugin_results[plugin_name] = {"status": "error", "error": str(plugin_result)}
                    continue
                
                if not isinstance(plugin_result, dict):
                    self.logger.error(f"Plugin {plugin_name} returned invalid result type")
                    failed_plugins += 1
                    continue
                
                # UNIVERSAL FORMAT: Parse universal interface results
                parsed_result = self._parse_universal_plugin_result(plugin_result, plugin_name)
                result.plugin_results[plugin_name] = parsed_result
                
                # Extract universal format fields
                action = parsed_result.get('action', 'ALLOW')
                threat_score = parsed_result.get('threat_score', 0.0)
                threats = parsed_result.get('threats_detected', [])
                confidence = parsed_result.get('confidence', 0.0)
                
                # Vote counting with universal actions
                if action == 'BLOCK':
                    block_votes += 1
                    if confidence > 0.8:  # High confidence threshold
                        high_confidence_blocks.append(plugin_name)
                elif action == 'ALLOW':
                    allow_votes += 1
                elif action == 'MODIFY':
                    modify_votes += 1
                elif action == 'REVIEW':
                    review_votes += 1
                
                # Accumulate threat information
                plugin_scores.append(threat_score)
                total_threat_score += threat_score
                all_threats.extend(threats)
                
                self.logger.debug(f"Plugin {plugin_name} universal result: {action} (score: {threat_score}, confidence: {confidence})")
            
            # UNIVERSAL DECISION ENGINE: Enhanced voting with multiple actions
            total_voting_plugins = len(plugin_results) - failed_plugins
            
            if total_voting_plugins > 0:
                result.threat_score = total_threat_score / total_voting_plugins
                result.threats_detected = all_threats
            
            # Enhanced decision logic with universal actions
            if len(high_confidence_blocks) >= 2:  # Multiple high-confidence blocks
                result.action = SecurityAction.BLOCK
                self.logger.info(f"HIGH CONFIDENCE BLOCK: {len(high_confidence_blocks)} plugins with >80% confidence")
                
            elif block_votes > allow_votes and block_votes >= len(self.security_plugins) * 0.3:  # 30% consensus
                result.action = SecurityAction.BLOCK
                self.logger.info(f"MAJORITY BLOCK: {block_votes} block votes vs {allow_votes} allow votes")
                
            elif modify_votes > 0 and result.threat_score > 0.3:  # Modification needed
                result.action = SecurityAction.MODIFY
                self.logger.info(f"MODIFICATION REQUIRED: {modify_votes} modify votes")
                
            elif review_votes > 0 and result.threat_score > 0.2:  # Human review
                result.action = SecurityAction.REVIEW
                self.logger.info(f"HUMAN REVIEW: {review_votes} review votes")
                
            elif result.threat_score > 0.1:  # Score-based blocking
                result.action = SecurityAction.BLOCK
                self.logger.info(f"SCORE-BASED BLOCK: {result.threat_score:.3f} > 0.1")
            
            elif total_voting_plugins < len(self.security_plugins) * 0.7:  # Insufficient coverage
                result.action = SecurityAction.BLOCK
                self.logger.info(f"INSUFFICIENT PLUGIN COVERAGE BLOCK: {total_voting_plugins}/{len(self.security_plugins)}")
            
            else:
                result.action = SecurityAction.ALLOW
                self.logger.info(f"CONSENSUS ALLOW: No significant threats detected")
            
            # Store enhanced voting audit data
            result.audit_data.update({
                "plugin_votes": {
                    "block": block_votes, 
                    "allow": allow_votes, 
                    "modify": modify_votes,
                    "review": review_votes,
                    "failed": failed_plugins
                },
                "total_plugins": len(self.security_plugins),
                "voting_plugins": total_voting_plugins,
                "high_confidence_blocks": len(high_confidence_blocks),
                "decision_criteria": result.action.value,
                "universal_interface_used": True
            })
                
        except asyncio.TimeoutError:
            self.logger.error("Security pipeline timeout")
            result.action = SecurityAction.BLOCK
            result.audit_data["timeout"] = True
            
        except Exception as e:
            self.logger.error(f"Security pipeline error: {str(e)}")
            result.action = SecurityAction.BLOCK
            result.audit_data["error"] = str(e)
        
        result.response_time_ms = (time.time() - start_time) * 1000
        return result

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
                    # Attempt to wrap legacy plugin with universal interface
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


# Main MCP Guardian implementation with Universal Interface
class MCPGuardianUniversal:
    """MCP Guardian with Universal Security Interface Integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = structlog.get_logger(__name__)
        
        # Initialize universal security orchestrator
        self.orchestrator = UniversalSecurityPluginOrchestrator(config)
        
        self.logger.info(f"MCP Guardian Universal initialized with {len(self.orchestrator.security_plugins)} security plugins")

    async def process_request(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Process incoming MCP request through universal security pipeline"""
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
            
            # Execute universal security pipeline
            security_result = await self.orchestrator.execute_security_pipeline(security_context)
            
            # Log security decision with universal format
            self.logger.info(
                "Universal security decision",
                request_id=request_id,
                action=security_result.action.value,
                threat_score=security_result.threat_score,
                threats=len(security_result.threats_detected),
                universal_interface=True
            )
            
            # Return universal format result
            result = security_result.to_dict()
            result.update({
                "request_id": request_id,
                "universal_format": True,
                "mcp_guardian_action": security_result.action.value,
                "processing_time_ms": security_result.response_time_ms
            })
            
            return result
            
        except Exception as e:
            self.logger.error(f"Universal MCP Guardian processing error: {str(e)}")
            return {
                "status": "error",
                "error": str(e),
                "action": "BLOCK",
                "mcp_guardian_action": "BLOCK",
                "request_id": request_id,
                "universal_format": True
            }


# Plugin wrapper for PlugPipe integration
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe async entry point for MCP Guardian Universal"""
    try:
        # Initialize MCP Guardian with universal interface
        guardian = MCPGuardianUniversal(cfg)
        
        # Process request through universal security pipeline
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
            "mcp_guardian_action": "BLOCK",
            "action": "BLOCK"
        }


if __name__ == "__main__":
    # Test the universal interface integration
    import asyncio
    
    async def test_universal():
        config = {
            'security_profile': 'standard',
            'plugin_timeout': 10
        }
        
        test_context = {
            'jsonrpc': '2.0',
            'params': {
                'payload': 'sk-1234567890abcdef1234567890abcdef'  # API key for testing
            }
        }
        
        result = await process(test_context, config)
        print("Universal MCP Guardian Test Results:")
        print(f"Status: {result.get('status')}")
        print(f"Action: {result.get('mcp_guardian_action')}")
        print(f"Universal Format: {result.get('universal_format')}")
        print(f"Threat Score: {result.get('threat_score', 0)}")
        print(f"Plugins Processed: {len(result.get('plugin_results', {}))}")
        print(f"Universal Interface Used: {result.get('universal_interface_used')}")
    
    asyncio.run(test_universal())