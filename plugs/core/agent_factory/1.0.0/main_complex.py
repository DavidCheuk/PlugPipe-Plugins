#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Core Agent Factory Plugin

Production-ready agent factory implementation as a PlugPipe plugin.
This plugin provides comprehensive agent lifecycle management with enterprise-grade
robustness, health monitoring, and failure recovery mechanisms.

Key Features:
- Agent creation and lifecycle management
- Template registration and validation
- Health monitoring and circuit breakers
- Fallback and recovery mechanisms
- Rate limiting and resource management
- Performance monitoring and metrics
- Enterprise compliance and audit trails
"""

import asyncio
import logging
import time
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import asdict

# Import the core agent factory implementation
import sys
import os

# Add the cores path for importing
cores_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../cores'))
sys.path.insert(0, cores_path)

from cores.agents.agent_factory_core import CoreAgentFactory, AgentInstance, AgentPerformanceMonitor
from cores.agents.agent_types import AgentTemplate, AgentStatus
from cores.agents.agent_health_monitor import get_agent_health_monitor
from cores.agents.agent_fallback_manager import get_agent_fallback_manager
from cores.agents.ai_rate_limiter import get_ai_rate_limiter


class PluginAgentFactory:
    """
    Plugin-based implementation of the agent factory
    
    This class wraps the core agent factory with plugin-specific functionality
    and provides the interface expected by the PlugPipe plugin system.
    """
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger, metrics_collector: Any):
        self.config = config
        self.logger = logger
        self.metrics = metrics_collector
        
        # Initialize core factory
        self.core_factory = CoreAgentFactory()
        
        # Initialize production-ready components
        self.health_monitor = get_agent_health_monitor()
        self.fallback_manager = get_agent_fallback_manager()
        self.rate_limiter = get_ai_rate_limiter()
        
        # Plugin-specific state
        self.plugin_id = f"agent_factory_plugin_{uuid.uuid4().hex[:8]}"
        self.created_at = datetime.now()
        self.total_agents_created = 0
        self.total_operations = 0
        self.health_status = "healthy"

        # FTHAD IMPLEMENTATION: Success rate tracking
        self.successful_operations = 0
        self.failed_operations = 0
        self.operation_history = []  # Keep last 100 operations for detailed metrics
        self.last_error_time = None
        self.consecutive_failures = 0
        
        self.logger.info(f"Plugin Agent Factory initialized: {self.plugin_id}")

    def _record_operation_result(self, operation_type: str, success: bool, error_message: str = None):
        """FTHAD IMPLEMENTATION: Record operation results for success rate calculation"""
        timestamp = datetime.now()

        if success:
            self.successful_operations += 1
            self.consecutive_failures = 0
        else:
            self.failed_operations += 1
            self.last_error_time = timestamp
            self.consecutive_failures += 1

        # Record operation in history (keep last 100)
        operation_record = {
            'type': operation_type,
            'success': success,
            'timestamp': timestamp,
            'error': error_message
        }

        self.operation_history.append(operation_record)
        if len(self.operation_history) > 100:
            self.operation_history.pop(0)

        # Log significant events
        if not success:
            self.logger.warning(f"Operation {operation_type} failed: {error_message}")
        if self.consecutive_failures >= 5:
            self.logger.error(f"High failure rate detected: {self.consecutive_failures} consecutive failures")

    def _calculate_success_metrics(self) -> Dict[str, Any]:
        """FTHAD IMPLEMENTATION: Calculate comprehensive success rate metrics"""
        total_ops = self.successful_operations + self.failed_operations

        if total_ops == 0:
            return {
                'success_rate': 0.0,
                'error_rate': 0.0,
                'total_operations': 0,
                'recent_success_rate': 0.0
            }

        # Overall success rate
        success_rate = (self.successful_operations / total_ops) * 100
        error_rate = (self.failed_operations / total_ops) * 100

        # Recent success rate (last 20 operations)
        recent_ops = self.operation_history[-20:] if len(self.operation_history) >= 20 else self.operation_history
        recent_success_count = sum(1 for op in recent_ops if op['success'])
        recent_success_rate = (recent_success_count / len(recent_ops)) * 100 if recent_ops else 0.0

        return {
            'success_rate': round(success_rate, 2),
            'error_rate': round(error_rate, 2),
            'total_operations': total_ops,
            'successful_operations': self.successful_operations,
            'failed_operations': self.failed_operations,
            'recent_success_rate': round(recent_success_rate, 2),
            'consecutive_failures': self.consecutive_failures,
            'last_error_time': self.last_error_time.isoformat() if self.last_error_time else None
        }

    async def create_agent(self, template_id: str, config: Dict[str, Any],
                          agent_id: Optional[str] = None) -> Optional[AgentInstance]:
        """Create agent with production robustness features"""
        start_time = time.time()
        self.total_operations += 1
        
        try:
            # Rate limiting check
            rate_check = await self.rate_limiter.check_rate_limit(
                agent_id=agent_id or f"temp_{template_id}",
                provider="agent_factory",
                estimated_cost=0.01  # Small cost for agent creation
            )
            
            if not rate_check.allowed:
                self.logger.warning(f"Agent creation rate limited: {rate_check.reason}")
                return None
            
            # Health check before creating agent
            factory_health = await self.health_monitor.get_agent_health("agent_factory")
            if factory_health and factory_health.status != "healthy":
                self.logger.warning("Factory health degraded, using fallback")
                return await self._create_agent_with_fallback(template_id, config, agent_id)
            
            # Create agent using core factory
            agent = await self.core_factory.create_agent(template_id, config, agent_id)
            
            if agent:
                self.total_agents_created += 1

                # FTHAD IMPLEMENTATION: Record successful operation
                self._record_operation_result("create_agent", True)

                # Record successful usage
                from cores.agents.ai_rate_limiter import AIUsageRecord
                usage = AIUsageRecord(
                    timestamp=datetime.now(),
                    agent_id=agent.agent_id,
                    provider="agent_factory",
                    model="agent_creation",
                    requests=1,
                    input_tokens=0,
                    output_tokens=0,
                    cost=0.01
                )
                await self.rate_limiter.record_usage(usage)
                
                # Start monitoring the new agent
                await self.health_monitor.start_monitoring_agent(agent.agent_id)
                
                execution_time = time.time() - start_time
                self.logger.info(f"Created agent {agent.agent_id} in {execution_time:.2f}s")
                
                return agent
            else:
                # FTHAD IMPLEMENTATION: Record failed operation
                self._record_operation_result("create_agent", False, f"Failed to create agent for template {template_id}")
                self.logger.error(f"Failed to create agent for template {template_id}")
                return None

        except Exception as e:
            # FTHAD IMPLEMENTATION: Record exception-based failure
            self._record_operation_result("create_agent", False, f"Agent creation failed: {str(e)}")
            self.logger.error(f"Agent creation failed: {e}")
            # Try fallback creation
            return await self._create_agent_with_fallback(template_id, config, agent_id)
    
    async def _create_agent_with_fallback(self, template_id: str, config: Dict[str, Any], 
                                        agent_id: Optional[str]) -> Optional[AgentInstance]:
        """Create agent using fallback mechanisms"""
        try:
            task_context = {
                'template_id': template_id,
                'config': config,
                'agent_id': agent_id,
                'priority': 'high',
                'retry_count': 3
            }
            
            result = await self.fallback_manager.execute_with_fallback(
                task_context, 
                self.core_factory.create_agent
            )
            
            return result
            
        except Exception as e:
            self.logger.error(f"Fallback agent creation failed: {e}")
            return None
    
    def register_template(self, template: AgentTemplate) -> bool:
        """Register agent template with validation"""
        try:
            success = self.core_factory.register_template(template)
            if success:
                # FTHAD IMPLEMENTATION: Record successful template registration
                self._record_operation_result("register_template", True)
                self.logger.info(f"Registered template: {template.template_id}")
            else:
                # FTHAD IMPLEMENTATION: Record failed template registration
                self._record_operation_result("register_template", False, f"Failed to register template {template.template_id}")
            return success
        except Exception as e:
            # FTHAD IMPLEMENTATION: Record exception-based failure
            self._record_operation_result("register_template", False, f"Template registration failed: {str(e)}")
            self.logger.error(f"Template registration failed: {e}")
            return False
    
    def list_agents(self, status_filter: Optional[AgentStatus] = None) -> List[Dict[str, Any]]:
        """List agents with plugin metadata"""
        try:
            agents = self.core_factory.list_agents(status_filter)
            
            # Add plugin-specific metadata
            for agent in agents:
                agent['factory_type'] = 'plugin'
                agent['plugin_id'] = self.plugin_id
                agent['created_via_plugin'] = True
            
            return agents
            
        except Exception as e:
            self.logger.error(f"Agent listing failed: {e}")
            return []
    
    def get_agent(self, agent_id: str) -> Optional[AgentInstance]:
        """Get agent instance by ID"""
        return self.core_factory.get_agent(agent_id)
    
    async def destroy_agent(self, agent_id: str) -> bool:
        """Destroy agent with cleanup"""
        try:
            # Stop health monitoring
            await self.health_monitor.stop_monitoring_agent(agent_id)
            
            # Destroy via core factory
            success = await self.core_factory.destroy_agent(agent_id)
            
            if success:
                self.logger.info(f"Destroyed agent: {agent_id}")
            
            return success
            
        except Exception as e:
            self.logger.error(f"Agent destruction failed: {e}")
            return False
    
    def get_templates(self) -> List[Dict[str, Any]]:
        """Get available templates"""
        return self.core_factory.get_templates()
    
    async def scale_agents(self, template_id: str, target_count: int) -> List[str]:
        """Scale agents with rate limiting"""
        new_agents = []
        
        try:
            current_agents = [
                agent['agent_id'] for agent in self.list_agents()
                if agent.get('template_id') == template_id
            ]
            
            current_count = len(current_agents)
            
            if target_count > current_count:
                # Scale up with rate limiting
                for i in range(target_count - current_count):
                    agent = await self.create_agent(template_id, {})
                    if agent:
                        new_agents.append(agent.agent_id)
                    else:
                        # Rate limited or other failure
                        break
            
            elif target_count < current_count:
                # Scale down
                agents_to_remove = current_agents[target_count:]
                for agent_id in agents_to_remove:
                    await self.destroy_agent(agent_id)
            
            return new_agents
            
        except Exception as e:
            self.logger.error(f"Agent scaling failed: {e}")
            return new_agents
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        try:
            uptime = (datetime.now() - self.created_at).total_seconds()
            
            # Get component health
            health_monitor_status = await self.health_monitor.get_system_health()
            fallback_manager_status = self.fallback_manager.get_status()
            rate_limiter_status = self.rate_limiter.get_usage_statistics()
            
            return {
                'plugin_id': self.plugin_id,
                'factory_type': 'plugin',
                'healthy': self.health_status == "healthy",
                'uptime_seconds': uptime,
                'total_agents_created': self.total_agents_created,
                'total_operations': self.total_operations,
                'active_agents': len(self.list_agents()),
                'registered_templates': len(self.get_templates()),
                'components': {
                    'health_monitor': health_monitor_status,
                    'fallback_manager': fallback_manager_status,
                    'rate_limiter': rate_limiter_status
                },
                'performance': {
                    'avg_operations_per_minute': self.total_operations / max(uptime / 60, 1),
                    **self._calculate_success_metrics()  # FTHAD IMPLEMENTATION: Actual success rate calculation
                }
            }
            
        except Exception as e:
            self.logger.error(f"Health status check failed: {e}")
            return {
                'plugin_id': self.plugin_id,
                'healthy': False,
                'error': str(e)
            }
    
    async def shutdown(self):
        """Gracefully shutdown the plugin factory"""
        try:
            self.logger.info("Shutting down plugin agent factory")
            
            # Stop all agent monitoring
            agents = self.list_agents()
            for agent in agents:
                await self.health_monitor.stop_monitoring_agent(agent['agent_id'])
            
            # Shutdown all agents
            for agent in agents:
                await self.destroy_agent(agent['agent_id'])
            
            self.health_status = "shutdown"
            self.logger.info("Plugin agent factory shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Shutdown failed: {e}")


# Plugin entry point
def process(ctx, cfg):
    """
    PlugPipe plugin entry point

    Args:
        ctx: Plugin context with logger, metrics, etc.
        cfg: Plugin configuration

    Returns:
        dict: Plugin response with factory instance and capabilities
    """

    # FTHAD SECURITY HARDENING: Input validation and sanitization
    # Validate context parameter
    if not isinstance(ctx, dict):
        return {
            'status': 'error',
            'error': 'Invalid context parameter type - must be dictionary',
            'security_hardening': 'Context type validation failed'
        }

    # Validate config parameter
    if not isinstance(cfg, dict):
        return {
            'status': 'error',
            'error': 'Invalid config parameter type - must be dictionary',
            'security_hardening': 'Config type validation failed'
        }

    # Validate required context fields
    if 'logger' in ctx and ctx['logger'] is not None:
        if not hasattr(ctx['logger'], 'info'):
            return {
                'status': 'error',
                'error': 'Invalid logger object - missing required methods',
                'security_hardening': 'Logger validation failed'
            }

    # Sanitize config to prevent injection attacks
    safe_config = {}
    for key, value in cfg.items():
        if not isinstance(key, str):
            return {
                'status': 'error',
                'error': f'Config key must be string, got {type(key)}',
                'security_hardening': 'Config key type validation failed'
            }

        # Prevent dangerous config keys
        if key.startswith('_') or '..' in key or '/' in key:
            return {
                'status': 'error',
                'error': f'Invalid config key: {key}',
                'security_hardening': 'Config key sanitization failed'
            }

        safe_config[key] = value

    # Validate config size to prevent DoS
    MAX_CONFIG_SIZE = 1024 * 1024  # 1MB limit
    config_size = len(str(safe_config))
    if config_size > MAX_CONFIG_SIZE:
        return {
            'status': 'error',
            'error': f'Config exceeds maximum size of {MAX_CONFIG_SIZE} bytes',
            'security_hardening': 'Config size validation failed'
        }

    logger = ctx.get('logger', logging.getLogger(__name__))
    metrics = ctx.get('metrics', None)

    try:
        # Create plugin agent factory
        plugin_factory = PluginAgentFactory(
            config=safe_config,
            logger=logger,
            metrics_collector=metrics
        )
        
        # Register with bridge if available
        try:
            from cores.agents.agent_factory_bridge import get_agent_factory_bridge
            bridge = get_agent_factory_bridge()
            bridge.register_plugin_factory(plugin_factory)
            logger.info("Plugin factory registered with bridge")
        except Exception as e:
            logger.warning(f"Failed to register with bridge: {e}")
        
        return {
            'success': True,
            'factory': plugin_factory,
            'capabilities': [
                'agent_creation',
                'agent_lifecycle_management', 
                'template_management',
                'health_monitoring',
                'fallback_management',
                'rate_limiting',
                'performance_monitoring'
            ],
            'factory_type': 'plugin',
            'plugin_id': plugin_factory.plugin_id,
            'status': 'ready',
            'health_endpoint': plugin_factory.get_health_status,
            'message': 'Core Agent Factory Plugin initialized successfully'
        }
        
    except Exception as e:
        logger.error(f"Plugin initialization failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'factory': None,
            'capabilities': [],
            'status': 'failed'
        }


# Plugin metadata for discovery
plug_metadata = {
    "name": "Core Agent Factory",
    "version": "1.0.0",
    "description": "Production-ready core agent factory with comprehensive lifecycle management",
    "author": "PlugPipe Core Team",
    "category": "core",
    "type": "infrastructure",
    "capabilities": [
        "agent_creation",
        "agent_lifecycle_management",
        "template_management", 
        "health_monitoring",
        "fallback_management",
        "rate_limiting"
    ],
    "enterprise_ready": True,
    "production_ready": True
}