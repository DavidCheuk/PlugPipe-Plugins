#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
MCP Security Middleware
Centralized security orchestration for all MCP operations
Following PlugPipe's "REUSE EVERYTHING, REINVENT NOTHING" principle.
"""

import asyncio
import json
import logging
import sys
import os
import time
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass
from enum import Enum
import uuid

# Add parent directory to path for plugin imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

class PipelineMode(Enum):
    """Security pipeline modes"""
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"

class SecurityStage(Enum):
    """Security pipeline stages"""
    AUTHENTICATION = "authentication"
    RATE_LIMITING = "rate_limiting"
    INPUT_VALIDATION = "input_validation"
    AUTHORIZATION = "authorization"
    AUDIT_LOGGING = "audit_logging"

class CircuitBreakerState(Enum):
    """Circuit breaker states"""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"

@dataclass
class SecurityStageConfig:
    """Configuration for a security stage"""
    order: int
    plugins: List[str]
    required: bool
    bypass_allowed: bool
    enabled: bool = True

@dataclass
class SecurityRequest:
    """MCP security request context"""
    request_id: str
    user_id: str
    client_id: Optional[str]
    mcp_endpoint: str
    request_data: Dict[str, Any]
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    session_id: Optional[str] = None
    correlation_id: Optional[str] = None

@dataclass
class SecurityResponse:
    """MCP security response"""
    allowed: bool
    stage_results: Dict[SecurityStage, Dict[str, Any]]
    total_time_ms: float
    final_reason: str
    correlation_id: str
    errors: List[str] = None

@dataclass
class CircuitBreaker:
    """Circuit breaker for security plugins"""
    failure_count: int = 0
    last_failure_time: Optional[datetime] = None
    state: CircuitBreakerState = CircuitBreakerState.CLOSED
    half_open_requests: int = 0

class MCPSecurityMiddleware:
    """
    MCP Security Middleware
    Orchestrates all security plugins in a unified pipeline
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Pipeline configuration
        pipeline_config = config.get('security_pipeline_config', {})
        self.pipeline_mode = PipelineMode(pipeline_config.get('mode', 'production'))
        self.fail_secure_mode = config.get('fail_secure_mode', True)
        self.bypass_prevention = config.get('bypass_prevention', True)
        self.correlation_enabled = config.get('correlation_enabled', True)
        
        # Security stage configurations
        self.stage_configs = {
            SecurityStage.AUTHENTICATION: SecurityStageConfig(1, ["oauth2_1_mcp_server"], True, False),
            SecurityStage.RATE_LIMITING: SecurityStageConfig(2, ["ai_rate_limiter_mcp_integration"], False, True),
            SecurityStage.INPUT_VALIDATION: SecurityStageConfig(3, ["ai_prompt_injection_guardian"], True, False),
            SecurityStage.AUTHORIZATION: SecurityStageConfig(4, ["mcp_security_policy_engine"], True, False),
            SecurityStage.AUDIT_LOGGING: SecurityStageConfig(5, ["enhanced_mcp_audit_integration"], True, False)
        }
        
        # Security plugin instances
        self.security_plugins = {}
        
        # Circuit breakers for each plugin
        self.circuit_breakers: Dict[str, CircuitBreaker] = {}
        
        # Performance monitoring
        self.performance_metrics = {
            'total_requests': 0,
            'allowed_requests': 0,
            'denied_requests': 0,
            'error_requests': 0,
            'average_latency_ms': 0.0
        }
        
        # Security event correlation
        self.correlation_cache: Dict[str, List[Dict[str, Any]]] = {}
        
    async def initialize_security_plugins(self):
        """Initialize all security plugins"""
        
        # Initialize authentication plugin
        try:
            from oauth2_1_mcp_server.main import OAuth21MCPServer
            self.security_plugins['oauth2_1_mcp_server'] = OAuth21MCPServer({})
            self.logger.info("Initialized OAuth 2.1 MCP Server")
        except ImportError:
            self.logger.warning("OAuth 2.1 MCP Server not available")
            
        # Initialize rate limiting plugin
        try:
            from ai_rate_limiter_mcp_integration.main import MCPRateLimiterIntegration
            self.security_plugins['ai_rate_limiter_mcp_integration'] = MCPRateLimiterIntegration({})
            self.logger.info("Initialized AI Rate Limiter MCP Integration")
        except ImportError:
            self.logger.warning("AI Rate Limiter MCP Integration not available")
            
        # Initialize prompt injection guardian
        try:
            from ai_prompt_injection_guardian.main import AIPromptInjectionGuardian
            self.security_plugins['ai_prompt_injection_guardian'] = AIPromptInjectionGuardian({})
            self.logger.info("Initialized AI Prompt Injection Guardian")
        except ImportError:
            self.logger.warning("AI Prompt Injection Guardian not available")
            
        # Initialize policy engine
        try:
            from mcp_security_policy_engine.main import MCPSecurityPolicyEngine
            self.security_plugins['mcp_security_policy_engine'] = MCPSecurityPolicyEngine({})
            self.logger.info("Initialized MCP Security Policy Engine")
        except ImportError:
            self.logger.warning("MCP Security Policy Engine not available")
            
        # Initialize audit integration
        try:
            from enhanced_mcp_audit_integration.main import EnhancedMCPAuditIntegration
            self.security_plugins['enhanced_mcp_audit_integration'] = EnhancedMCPAuditIntegration({})
            self.logger.info("Initialized Enhanced MCP Audit Integration")
        except ImportError:
            self.logger.warning("Enhanced MCP Audit Integration not available")
            
        # Initialize circuit breakers for all plugins
        for plugin_name in self.security_plugins.keys():
            self.circuit_breakers[plugin_name] = CircuitBreaker()
            
    async def process_security_request(self, request: SecurityRequest) -> SecurityResponse:
        """
        Process MCP request through complete security pipeline
        
        Args:
            request: MCP security request context
            
        Returns:
            Security response with stage results
        """
        
        start_time = time.time()
        correlation_id = request.correlation_id or str(uuid.uuid4())
        stage_results = {}
        errors = []
        
        # Update metrics
        self.performance_metrics['total_requests'] += 1
        
        try:
            # Process each security stage in order
            stages_ordered = sorted(
                [(stage, config) for stage, config in self.stage_configs.items() if config.enabled],
                key=lambda x: x[1].order
            )
            
            for stage, stage_config in stages_ordered:
                stage_start = time.time()
                
                # Execute stage
                stage_result = await self._execute_security_stage(
                    stage, stage_config, request, correlation_id
                )
                
                stage_time_ms = (time.time() - stage_start) * 1000
                stage_result['execution_time_ms'] = stage_time_ms
                stage_results[stage] = stage_result
                
                # Check if stage blocked the request
                if not stage_result.get('allowed', False):
                    if stage_config.required and not (stage_config.bypass_allowed and self._bypass_authorized(request)):
                        # Required stage blocked request
                        total_time_ms = (time.time() - start_time) * 1000
                        
                        # Record denial
                        await self._record_security_event('request_denied', {
                            'request_id': request.request_id,
                            'stage': stage.value,
                            'reason': stage_result.get('reason', 'Security policy violation'),
                            'correlation_id': correlation_id
                        })
                        
                        self.performance_metrics['denied_requests'] += 1
                        
                        return SecurityResponse(
                            allowed=False,
                            stage_results=stage_results,
                            total_time_ms=total_time_ms,
                            final_reason=f"Blocked by {stage.value}: {stage_result.get('reason', 'Security policy violation')}",
                            correlation_id=correlation_id,
                            errors=errors
                        )
                        
                # Handle stage errors
                if stage_result.get('error'):
                    errors.append(f"{stage.value}: {stage_result['error']}")
                    
                    if self.fail_secure_mode and stage_config.required:
                        # Fail secure - block on errors
                        total_time_ms = (time.time() - start_time) * 1000
                        
                        self.performance_metrics['error_requests'] += 1
                        
                        return SecurityResponse(
                            allowed=False,
                            stage_results=stage_results,
                            total_time_ms=total_time_ms,
                            final_reason=f"Security error in {stage.value}: {stage_result['error']}",
                            correlation_id=correlation_id,
                            errors=errors
                        )
                        
            # All stages passed
            total_time_ms = (time.time() - start_time) * 1000
            
            # Record success
            await self._record_security_event('request_allowed', {
                'request_id': request.request_id,
                'stages_processed': len(stage_results),
                'total_time_ms': total_time_ms,
                'correlation_id': correlation_id
            })
            
            self.performance_metrics['allowed_requests'] += 1
            self._update_average_latency(total_time_ms)
            
            return SecurityResponse(
                allowed=True,
                stage_results=stage_results,
                total_time_ms=total_time_ms,
                final_reason="All security stages passed",
                correlation_id=correlation_id,
                errors=errors if errors else None
            )
            
        except Exception as e:
            self.logger.error(f"Security pipeline error for request {request.request_id}: {e}")
            
            total_time_ms = (time.time() - start_time) * 1000
            self.performance_metrics['error_requests'] += 1
            
            if self.fail_secure_mode:
                return SecurityResponse(
                    allowed=False,
                    stage_results=stage_results,
                    total_time_ms=total_time_ms,
                    final_reason=f"Security pipeline error: {str(e)}",
                    correlation_id=correlation_id,
                    errors=[str(e)]
                )
            else:
                return SecurityResponse(
                    allowed=True,
                    stage_results=stage_results,
                    total_time_ms=total_time_ms,
                    final_reason=f"Allowed despite error (fail-open mode): {str(e)}",
                    correlation_id=correlation_id,
                    errors=[str(e)]
                )
                
    async def _execute_security_stage(self, stage: SecurityStage, stage_config: SecurityStageConfig,
                                    request: SecurityRequest, correlation_id: str) -> Dict[str, Any]:
        """Execute a specific security stage"""
        
        stage_results = {
            'stage': stage.value,
            'allowed': True,
            'reason': f"{stage.value} stage passed",
            'plugins_executed': [],
            'correlation_id': correlation_id
        }
        
        # Execute each plugin in the stage
        for plugin_name in stage_config.plugins:
            plugin_result = await self._execute_security_plugin(
                plugin_name, stage, request, correlation_id
            )
            
            stage_results['plugins_executed'].append({
                'plugin': plugin_name,
                'result': plugin_result
            })
            
            # Check plugin result
            if not plugin_result.get('allowed', True):
                stage_results['allowed'] = False
                stage_results['reason'] = plugin_result.get('reason', f"{plugin_name} blocked request")
                break
                
            # Handle plugin errors
            if plugin_result.get('error'):
                stage_results['error'] = plugin_result['error']
                if stage_config.required and self.fail_secure_mode:
                    stage_results['allowed'] = False
                    stage_results['reason'] = f"{plugin_name} error: {plugin_result['error']}"
                    break
                    
        return stage_results
        
    async def _execute_security_plugin(self, plugin_name: str, stage: SecurityStage,
                                     request: SecurityRequest, correlation_id: str) -> Dict[str, Any]:
        """Execute a specific security plugin"""
        
        plugin = self.security_plugins.get(plugin_name)
        circuit_breaker = self.circuit_breakers.get(plugin_name)
        
        if not plugin:
            return {
                'allowed': True,
                'reason': f"Plugin {plugin_name} not available",
                'error': f"Plugin {plugin_name} not loaded"
            }
            
        # Check circuit breaker
        if circuit_breaker and not self._check_circuit_breaker(circuit_breaker, plugin_name):
            return {
                'allowed': False if self.fail_secure_mode else True,
                'reason': f"Plugin {plugin_name} circuit breaker open",
                'error': "Circuit breaker open"
            }
            
        try:
            # Execute plugin based on stage
            if stage == SecurityStage.AUTHENTICATION:
                result = await self._execute_authentication_plugin(plugin, request)
            elif stage == SecurityStage.RATE_LIMITING:
                result = await self._execute_rate_limiting_plugin(plugin, request)
            elif stage == SecurityStage.INPUT_VALIDATION:
                result = await self._execute_input_validation_plugin(plugin, request)
            elif stage == SecurityStage.AUTHORIZATION:
                result = await self._execute_authorization_plugin(plugin, request)
            elif stage == SecurityStage.AUDIT_LOGGING:
                result = await self._execute_audit_plugin(plugin, request, correlation_id)
            else:
                result = {'allowed': True, 'reason': f"Unknown stage {stage.value}"}
                
            # Update circuit breaker on success
            if circuit_breaker:
                self._record_success(circuit_breaker)
                
            return result
            
        except Exception as e:
            self.logger.error(f"Plugin {plugin_name} execution failed: {e}")
            
            # Update circuit breaker on failure
            if circuit_breaker:
                self._record_failure(circuit_breaker)
                
            return {
                'allowed': False if self.fail_secure_mode else True,
                'reason': f"Plugin {plugin_name} execution failed",
                'error': str(e)
            }
            
    async def _execute_authentication_plugin(self, plugin: Any, request: SecurityRequest) -> Dict[str, Any]:
        """Execute authentication plugin"""
        
        # Mock authentication check - would call actual plugin method
        auth_request = {
            'user_id': request.user_id,
            'client_id': request.client_id,
            'endpoint': request.mcp_endpoint
        }
        
        # Simulate authentication result
        if request.user_id and request.user_id != 'anonymous':
            return {
                'allowed': True,
                'reason': 'Authentication successful',
                'user_id': request.user_id,
                'roles': ['user']  # Would come from actual authentication
            }
        else:
            return {
                'allowed': False,
                'reason': 'Authentication required'
            }
            
    async def _execute_rate_limiting_plugin(self, plugin: Any, request: SecurityRequest) -> Dict[str, Any]:
        """Execute rate limiting plugin"""
        
        # Mock rate limiting check
        rate_request = {
            'operation': 'check_mcp_limit',
            'client_id': request.user_id,
            'endpoint': request.mcp_endpoint,
            'estimated_cost': 0.1
        }
        
        # Simulate rate limiting (would use actual plugin)
        return {
            'allowed': True,
            'reason': 'Within rate limits',
            'remaining_quota': 95
        }
        
    async def _execute_input_validation_plugin(self, plugin: Any, request: SecurityRequest) -> Dict[str, Any]:
        """Execute input validation plugin"""
        
        # Mock input validation
        validation_request = {
            'operation': 'analyze_prompt',
            'text': str(request.request_data),
            'mcp_endpoint': request.mcp_endpoint
        }
        
        # Simulate validation (would use actual plugin)
        return {
            'allowed': True,
            'reason': 'Input validation passed',
            'threat_level': 'low',
            'confidence': 0.1
        }
        
    async def _execute_authorization_plugin(self, plugin: Any, request: SecurityRequest) -> Dict[str, Any]:
        """Execute authorization plugin"""
        
        # Mock authorization check
        authz_request = {
            'operation': 'evaluate_authorization',
            'user_id': request.user_id,
            'user_roles': ['user'],
            'mcp_endpoint': request.mcp_endpoint,
            'tool_name': request.request_data.get('tool_name')
        }
        
        # Simulate authorization (would use actual plugin)
        return {
            'allowed': True,
            'reason': 'Authorization granted',
            'policy_engine': 'rbac_standard',
            'confidence': 0.8
        }
        
    async def _execute_audit_plugin(self, plugin: Any, request: SecurityRequest, correlation_id: str) -> Dict[str, Any]:
        """Execute audit logging plugin"""
        
        # Mock audit logging
        audit_event = {
            'operation': 'log_audit_event',
            'event_type': 'mcp_tool_execution',
            'user_id': request.user_id,
            'mcp_endpoint': request.mcp_endpoint,
            'correlation_id': correlation_id,
            'event_data': request.request_data
        }
        
        # Simulate audit logging (would use actual plugin)
        return {
            'allowed': True,
            'reason': 'Event logged successfully',
            'event_id': str(uuid.uuid4())
        }
        
    def _check_circuit_breaker(self, circuit_breaker: CircuitBreaker, plugin_name: str) -> bool:
        """Check circuit breaker state"""
        
        now = datetime.utcnow()
        
        if circuit_breaker.state == CircuitBreakerState.CLOSED:
            return True
        elif circuit_breaker.state == CircuitBreakerState.OPEN:
            # Check if timeout has passed
            if (circuit_breaker.last_failure_time and 
                now - circuit_breaker.last_failure_time > timedelta(seconds=60)):
                circuit_breaker.state = CircuitBreakerState.HALF_OPEN
                circuit_breaker.half_open_requests = 0
                self.logger.info(f"Circuit breaker for {plugin_name} moved to HALF_OPEN")
                return True
            return False
        elif circuit_breaker.state == CircuitBreakerState.HALF_OPEN:
            if circuit_breaker.half_open_requests < 3:
                circuit_breaker.half_open_requests += 1
                return True
            return False
            
        return False
        
    def _record_success(self, circuit_breaker: CircuitBreaker):
        """Record successful plugin execution"""
        
        if circuit_breaker.state == CircuitBreakerState.HALF_OPEN:
            circuit_breaker.state = CircuitBreakerState.CLOSED
            circuit_breaker.failure_count = 0
            circuit_breaker.half_open_requests = 0
        elif circuit_breaker.state == CircuitBreakerState.CLOSED:
            circuit_breaker.failure_count = max(0, circuit_breaker.failure_count - 1)
            
    def _record_failure(self, circuit_breaker: CircuitBreaker):
        """Record failed plugin execution"""
        
        circuit_breaker.failure_count += 1
        circuit_breaker.last_failure_time = datetime.utcnow()
        
        if circuit_breaker.failure_count >= 5:
            circuit_breaker.state = CircuitBreakerState.OPEN
            
    def _bypass_authorized(self, request: SecurityRequest) -> bool:
        """Check if security bypass is authorized"""
        
        if not self.bypass_prevention:
            return False
            
        # Only allow bypass in development mode
        if self.pipeline_mode == PipelineMode.DEVELOPMENT:
            return request.user_id in ['admin', 'developer']
            
        return False
        
    async def _record_security_event(self, event_type: str, event_data: Dict[str, Any]):
        """Record security event for correlation and monitoring"""
        
        if not self.correlation_enabled:
            return
            
        correlation_id = event_data.get('correlation_id', 'unknown')
        
        event = {
            'timestamp': datetime.utcnow().isoformat(),
            'event_type': event_type,
            'data': event_data
        }
        
        if correlation_id not in self.correlation_cache:
            self.correlation_cache[correlation_id] = []
            
        self.correlation_cache[correlation_id].append(event)
        
        # Limit cache size
        if len(self.correlation_cache[correlation_id]) > 100:
            self.correlation_cache[correlation_id] = self.correlation_cache[correlation_id][-50:]
            
    def _update_average_latency(self, latency_ms: float):
        """Update average latency metric"""
        
        current_avg = self.performance_metrics['average_latency_ms']
        total_requests = self.performance_metrics['total_requests']
        
        # Moving average
        self.performance_metrics['average_latency_ms'] = (
            (current_avg * (total_requests - 1) + latency_ms) / total_requests
        )
        
    async def get_security_metrics(self) -> Dict[str, Any]:
        """Get security middleware metrics"""
        
        # Circuit breaker status
        circuit_breaker_status = {}
        for plugin_name, cb in self.circuit_breakers.items():
            circuit_breaker_status[plugin_name] = {
                'state': cb.state.value,
                'failure_count': cb.failure_count,
                'last_failure': cb.last_failure_time.isoformat() if cb.last_failure_time else None
            }
            
        return {
            'performance_metrics': self.performance_metrics,
            'circuit_breaker_status': circuit_breaker_status,
            'pipeline_mode': self.pipeline_mode.value,
            'active_stages': len([s for s in self.stage_configs.values() if s.enabled]),
            'loaded_plugins': list(self.security_plugins.keys()),
            'correlation_cache_size': len(self.correlation_cache)
        }
        
    async def get_correlation_events(self, correlation_id: str) -> List[Dict[str, Any]]:
        """Get correlated security events for a request"""
        
        return self.correlation_cache.get(correlation_id, [])

def process(context: dict, config: dict = None) -> dict:
    """
    PlugPipe standard process function for MCP Security Middleware
    
    Args:
        context: Input context with operation and parameters
        config: Plugin configuration
        
    Returns:
        Result dictionary with success status
    """
    try:
        operation = context.get('operation', 'get_status')
        
        # Initialize middleware
        middleware = MCPSecurityMiddleware(config or {})
        
        if operation == 'get_status':
            return {
                'success': True,
                'operation': operation,
                'pipeline_mode': middleware.pipeline_mode.value,
                'fail_secure_mode': middleware.fail_secure_mode,
                'bypass_prevention': middleware.bypass_prevention,
                'correlation_enabled': middleware.correlation_enabled,
                'active_stages': len([s for s in middleware.stage_configs.values() if s.enabled]),
                'loaded_plugins': list(middleware.security_plugins.keys())
            }
            
        elif operation == 'process_security_request':
            # Create security request from context
            security_request = SecurityRequest(
                request_id=context.get('request_id', str(uuid.uuid4())),
                user_id=context.get('user_id', 'test_user'),
                client_id=context.get('client_id'),
                mcp_endpoint=context.get('mcp_endpoint', 'tools/call'),
                request_data=context.get('request_data', {}),
                source_ip=context.get('source_ip'),
                user_agent=context.get('user_agent'),
                session_id=context.get('session_id'),
                correlation_id=context.get('correlation_id')
            )
            
            # For testing, simulate security processing
            return {
                'success': True,
                'operation': operation,
                'request_id': security_request.request_id,
                'user_id': security_request.user_id,
                'allowed': True,  # Simulated result
                'reason': 'Simulated security check passed',
                'total_time_ms': 42.0,  # Simulated timing
                'stage_results': {
                    'authentication': {'success': True, 'simulated': True},
                    'authorization': {'success': True, 'simulated': True},
                    'input_validation': {'success': True, 'simulated': True}
                }
            }
            
        elif operation == 'get_security_metrics':
            return {
                'success': True,
                'operation': operation,
                'metrics': {
                    'performance_metrics': middleware.performance_metrics,
                    'pipeline_mode': middleware.pipeline_mode.value,
                    'active_stages': len([s for s in middleware.stage_configs.values() if s.enabled]),
                    'loaded_plugins': list(middleware.security_plugins.keys()),
                    'correlation_cache_size': len(middleware.correlation_cache)
                }
            }
            
        else:
            return {
                'success': False,
                'operation': operation,
                'error': f'Unknown operation: {operation}. Available: get_status, process_security_request, get_security_metrics'
            }
            
    except Exception as e:
        return {
            'success': False,
            'operation': context.get('operation', 'unknown'),
            'error': str(e)
        }

def main(input_json=None):
    """Main plugin entry point"""
    
    # Read configuration
    config = {}
    if len(sys.argv) > 1 and not input_json:
        try:
            with open(sys.argv[1], 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}", file=sys.stderr)
    
    # Read input
    try:
        if input_json:
            input_data = json.loads(input_json)
        else:
            input_data = json.load(sys.stdin)
    except Exception as e:
        result = {
            'success': False,
            'error': f'Invalid JSON input: {e}'
        }
        print(json.dumps(result))
        return result
    
    # Use the process function for synchronous processing
    try:
        result = process(input_data, config)
        print(json.dumps(result))
        return result
    except Exception as e:
        result = {
            'success': False,
            'operation': input_data.get('operation', 'unknown'),
            'error': str(e)
        }
        print(json.dumps(result))
        return result

if __name__ == '__main__':
    main()