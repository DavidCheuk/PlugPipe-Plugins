#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Full System Integration Orchestrator Plugin

Complete enterprise system integration orchestrator that coordinates ALL available
PlugPipe integration plugins to provide comprehensive system-to-system connectivity.

Following PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Orchestrates existing integration plugins
- GRACEFUL DEGRADATION: Functions with subset of available integration plugins
- SIMPLICITY BY TRADITION: Standard orchestration patterns
- DEFAULT TO CREATING PLUGINS: Coordinates plugins, doesn't reimplement

This plugin serves as the central integration hub that orchestrates:
🔗 Enterprise Systems: Salesforce CRM, GitHub, API integrations
☁️ Cloud Platforms: AWS, Azure, GCP factory plugins
💬 Communication: Slack messaging, notification systems
💾 Data Storage: Database factory, S3, file storage plugins
🔐 Security: Policy engines, access controls, compliance
🎯 Orchestration: Task queues, workflow engines, execution contexts

Key Features:
🌐 Universal Integration Hub - Coordinates all integration plugins
🔄 Dynamic Service Discovery - Auto-detects available integration plugins
📊 Health Monitoring - Real-time status of all integrated systems
⚡ Load Balancing - Distributes requests across available services
🛡️ Circuit Breaker - Isolates failed integrations to maintain stability
📈 Analytics & Metrics - Comprehensive integration performance tracking
🔧 Configuration Management - Centralized config for all integrations
"""

import asyncio
import logging
import time
import json
from typing import Dict, List, Any, Optional, Tuple, Union
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from enum import Enum
import importlib.util
from collections import defaultdict

logger = logging.getLogger(__name__)

class IntegrationType(Enum):
    """Types of system integrations."""
    ENTERPRISE = "enterprise"
    CLOUD = "cloud" 
    COMMUNICATION = "communication"
    DATABASE = "database"
    STORAGE = "storage"
    API = "api"
    SECURITY = "security"
    ORCHESTRATION = "orchestration"
    MONITORING = "monitoring"

class IntegrationStatus(Enum):
    """Integration service status."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    DISABLED = "disabled"
    UNKNOWN = "unknown"

@dataclass
class IntegrationService:
    """Integration service configuration and status."""
    plugin_name: str
    integration_type: IntegrationType
    status: IntegrationStatus = IntegrationStatus.UNKNOWN
    last_health_check: Optional[datetime] = None
    response_time: float = 0.0
    success_rate: float = 0.0
    error_count: int = 0
    total_requests: int = 0
    config: Dict[str, Any] = field(default_factory=dict)
    capabilities: List[str] = field(default_factory=list)

@dataclass
class IntegrationRequest:
    """Standard integration request format."""
    integration_type: IntegrationType
    operation: str
    data: Dict[str, Any]
    routing_preferences: Dict[str, Any] = field(default_factory=dict)
    timeout: float = 30.0
    retry_count: int = 3
    require_healthy: bool = True

class FullSystemIntegrationOrchestrator:
    """Complete system integration orchestrator using existing PlugPipe plugins."""
    
    def __init__(self, config: Dict[str, Any]):
        """Initialize the integration orchestrator."""
        self.config = config
        self.services: Dict[str, IntegrationService] = {}
        self.service_plugins: Dict[str, Any] = {}
        self.circuit_breakers: Dict[str, bool] = {}
        
        # Performance tracking
        self.metrics: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        self.global_stats = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "average_response_time": 0.0
        }
        
        # Configuration
        self.health_check_interval = config.get('health_check_interval', 300)  # 5 minutes
        self.circuit_breaker_threshold = config.get('circuit_breaker_threshold', 0.5)
        self.max_retry_count = config.get('max_retry_count', 3)
        self.enable_load_balancing = config.get('enable_load_balancing', True)
        
        # Flag to track initialization
        self._initialized = False
        self._health_monitoring_started = False
        
        logger.info("Full System Integration Orchestrator initialized")
    
    async def _ensure_initialized(self):
        """Ensure the orchestrator is properly initialized with async services."""
        if not self._initialized:
            try:
                await self._discover_integration_services()
                self._initialized = True
                
                # Start health monitoring in background if not already started
                if not self._health_monitoring_started:
                    try:
                        asyncio.create_task(self._start_health_monitoring_loop())
                        self._health_monitoring_started = True
                    except RuntimeError:
                        # No event loop running, skip health monitoring
                        logger.warning("No event loop available for health monitoring")
                        
            except Exception as e:
                logger.error(f"Failed to initialize orchestrator: {e}")
                # Continue with empty services for graceful degradation
                self._initialized = True
    
    async def _discover_integration_services(self):
        """Discover and initialize available integration plugins."""
        try:
            # Define known integration plugins to orchestrate
            integration_plugins = {
                # Enterprise Systems
                'salesforce_crm': IntegrationType.ENTERPRISE,
                'github_integration': IntegrationType.ENTERPRISE,
                'slack_messaging': IntegrationType.COMMUNICATION,
                'stripe_payments': IntegrationType.ENTERPRISE,
                
                # Cloud Platforms  
                'aws_factory': IntegrationType.CLOUD,
                'azure_factory': IntegrationType.CLOUD,
                'gcp_factory': IntegrationType.CLOUD,
                
                # Data & Storage
                'database_factory_plugin': IntegrationType.DATABASE,
                'sqlite_database_plugin': IntegrationType.DATABASE,
                'aws_s3_storage': IntegrationType.STORAGE,
                
                # API & Integration
                'api2mcp_factory': IntegrationType.API,
                'openapi_parser': IntegrationType.API,
                'fastmcp_client': IntegrationType.API,
                'fastmcp_server': IntegrationType.API,
                
                # Security & Policy
                'security_orchestrator': IntegrationType.SECURITY,
                'opa_policy': IntegrationType.SECURITY,
                'opa_policy_enterprise': IntegrationType.SECURITY,
                'llm_guard': IntegrationType.SECURITY,
                
                # Orchestration & Management
                'agent_workflow_manager': IntegrationType.ORCHESTRATION,
                'task_queue_orchestrator': IntegrationType.ORCHESTRATION,
                'execution_engine': IntegrationType.ORCHESTRATION,
                'modular_orchestrator': IntegrationType.ORCHESTRATION,
                'kubernetes_plugin': IntegrationType.ORCHESTRATION,
                
                # Monitoring & Compliance
                'ecosystem_monitor': IntegrationType.MONITORING,
                'defectdojo_integration': IntegrationType.MONITORING,
            }
            
            # Attempt to load each integration plugin
            for plugin_name, integration_type in integration_plugins.items():
                try:
                    # Load plugin module
                    plugin_path = f"plugs/{self._get_plugin_category(plugin_name)}/{plugin_name}/1.0.0/main.py"
                    plugin_module = await self._load_plugin_module(plugin_path, plugin_name)
                    
                    if plugin_module:
                        service = IntegrationService(
                            plugin_name=plugin_name,
                            integration_type=integration_type,
                            status=IntegrationStatus.HEALTHY,
                            capabilities=getattr(plugin_module.plug_metadata, 'capabilities', [])
                        )
                        
                        self.services[plugin_name] = service
                        self.service_plugins[plugin_name] = plugin_module
                        self.circuit_breakers[plugin_name] = False
                        
                        logger.info(f"Discovered integration service: {plugin_name} ({integration_type.value})")
                    
                except Exception as e:
                    logger.warning(f"Could not load integration plugin {plugin_name}: {e}")
            
            logger.info(f"Integration orchestrator discovered {len(self.services)} services")
            
        except Exception as e:
            logger.error(f"Error during service discovery: {e}")
    
    async def _load_plugin_module(self, plugin_path: str, plugin_name: str):
        """Load plugin module dynamically."""
        try:
            spec = importlib.util.spec_from_file_location(
                f"{plugin_name}_plugin",
                plugin_path
            )
            if spec and spec.loader:
                plugin_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(plugin_module)
                return plugin_module
        except Exception as e:
            logger.debug(f"Failed to load {plugin_name}: {e}")
        return None
    
    def _get_plugin_category(self, plugin_name: str) -> str:
        """Map plugin names to their likely categories."""
        category_mappings = {
            'salesforce_crm': 'crm',
            'github_integration': 'version_control', 
            'slack_messaging': 'communication',
            'stripe_payments': 'payments',
            'aws_factory': 'cloud',
            'azure_factory': 'cloud',
            'gcp_factory': 'cloud',
            'database_factory_plugin': 'database',
            'sqlite_database_plugin': 'database',
            'aws_s3_storage': 'storage',
            'api2mcp_factory': 'integration',
            'openapi_parser': 'integration',
            'fastmcp_client': 'mcp',
            'fastmcp_server': 'mcp',
            'security_orchestrator': 'security',
            'opa_policy': 'uncategorized',
            'opa_policy_enterprise': 'uncategorized',
            'llm_guard': 'security',
            'agent_workflow_manager': 'orchestration',
            'task_queue_orchestrator': 'orchestration',
            'execution_engine': 'orchestration',
            'modular_orchestrator': 'orchestration',
            'kubernetes_plugin': 'orchestration',
            'ecosystem_monitor': 'compliance',
            'defectdojo_integration': 'security',
        }
        return category_mappings.get(plugin_name, 'integration')
    
    async def _start_health_monitoring_loop(self):
        """Start continuous health monitoring of integration services."""
        while True:
            try:
                await self._perform_health_checks()
                await asyncio.sleep(self.health_check_interval)
            except Exception as e:
                logger.error(f"Health monitoring error: {e}")
                await asyncio.sleep(60)
    
    async def _perform_health_checks(self):
        """Perform health checks on all integration services."""
        for service_name, service in self.services.items():
            try:
                start_time = time.time()
                
                # Attempt a lightweight health check
                if service_name in self.service_plugins:
                    plugin = self.service_plugins[service_name]
                    if hasattr(plugin, 'process'):
                        # Try a status/health check operation
                        result = await plugin.process({'action': 'status'}, {})
                        
                        response_time = time.time() - start_time
                        service.response_time = response_time
                        service.last_health_check = datetime.now(timezone.utc)
                        
                        if result.get('success', False):
                            service.status = IntegrationStatus.HEALTHY
                            self.circuit_breakers[service_name] = False
                        else:
                            service.status = IntegrationStatus.DEGRADED
                            service.error_count += 1
                    
            except Exception as e:
                logger.warning(f"Health check failed for {service_name}: {e}")
                service.status = IntegrationStatus.FAILED
                service.error_count += 1
                
                # Open circuit breaker if too many failures
                if service.error_count > 5:
                    self.circuit_breakers[service_name] = True
    
    async def execute_integration(self, request: IntegrationRequest) -> Dict[str, Any]:
        """Execute integration request using appropriate service."""
        await self._ensure_initialized()
        start_time = time.time()
        self.global_stats["total_requests"] += 1
        
        try:
            # Find suitable services for the integration type
            suitable_services = [
                service for service in self.services.values()
                if service.integration_type == request.integration_type
                and (not request.require_healthy or service.status == IntegrationStatus.HEALTHY)
                and not self.circuit_breakers.get(service.plugin_name, False)
            ]
            
            if not suitable_services:
                return {
                    'success': False,
                    'error': f'No healthy services available for {request.integration_type.value}',
                    'fallback_options': await self._get_fallback_options(request.integration_type)
                }
            
            # Select service (load balancing if enabled)
            selected_service = self._select_service(suitable_services, request)
            
            # Execute request with retries
            for attempt in range(request.retry_count + 1):
                try:
                    plugin = self.service_plugins[selected_service.plugin_name]
                    
                    # Execute the integration request
                    result = await asyncio.wait_for(
                        plugin.process(request.data, {}),
                        timeout=request.timeout
                    )
                    
                    # Update metrics
                    execution_time = time.time() - start_time
                    await self._record_metrics(selected_service.plugin_name, execution_time, True)
                    
                    self.global_stats["successful_requests"] += 1
                    
                    return {
                        'success': True,
                        'result': result,
                        'service_used': selected_service.plugin_name,
                        'execution_time': execution_time,
                        'attempt': attempt + 1
                    }
                    
                except asyncio.TimeoutError:
                    logger.warning(f"Timeout on {selected_service.plugin_name}, attempt {attempt + 1}")
                    if attempt == request.retry_count:
                        break
                    await asyncio.sleep(2 ** attempt)  # Exponential backoff
                    
                except Exception as e:
                    logger.error(f"Integration error on {selected_service.plugin_name}: {e}")
                    selected_service.error_count += 1
                    
                    if attempt == request.retry_count:
                        break
                    
                    # Try different service on retry
                    remaining_services = [s for s in suitable_services if s != selected_service]
                    if remaining_services:
                        selected_service = remaining_services[0]
            
            # All attempts failed
            execution_time = time.time() - start_time
            await self._record_metrics(selected_service.plugin_name, execution_time, False)
            
            self.global_stats["failed_requests"] += 1
            
            return {
                'success': False,
                'error': 'All integration attempts failed',
                'service_attempted': selected_service.plugin_name,
                'attempts': request.retry_count + 1
            }
            
        except Exception as e:
            logger.error(f"Integration orchestration error: {e}")
            return {
                'success': False,
                'error': str(e),
                'orchestration_failure': True
            }
    
    def _select_service(self, services: List[IntegrationService], request: IntegrationRequest) -> IntegrationService:
        """Select best service for request (load balancing logic)."""
        if not self.enable_load_balancing:
            return services[0]
        
        # Simple load balancing based on success rate and response time
        best_service = services[0]
        best_score = 0
        
        for service in services:
            # Calculate score based on success rate and response time
            success_rate = service.success_rate if service.success_rate > 0 else 0.5
            response_penalty = min(service.response_time / 10.0, 1.0)  # Normalize to 0-1
            score = success_rate - response_penalty
            
            if score > best_score:
                best_score = score
                best_service = service
        
        return best_service
    
    async def _get_fallback_options(self, integration_type: IntegrationType) -> List[str]:
        """Get fallback options when primary services are unavailable."""
        fallback_services = []
        
        # Find services of the same type that might work in degraded mode
        for service in self.services.values():
            if (service.integration_type == integration_type 
                and service.status != IntegrationStatus.FAILED):
                fallback_services.append(service.plugin_name)
        
        return fallback_services
    
    async def _record_metrics(self, service_name: str, execution_time: float, success: bool):
        """Record performance metrics for a service."""
        metric = {
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'execution_time': execution_time,
            'success': success
        }
        
        self.metrics[service_name].append(metric)
        
        # Keep only last 1000 metrics per service
        if len(self.metrics[service_name]) > 1000:
            self.metrics[service_name] = self.metrics[service_name][-1000:]
        
        # Update service success rate
        service = self.services[service_name]
        service.total_requests += 1
        if success:
            service.success_rate = ((service.success_rate * (service.total_requests - 1)) + 1) / service.total_requests
        else:
            service.success_rate = (service.success_rate * (service.total_requests - 1)) / service.total_requests
    
    async def get_system_status(self) -> Dict[str, Any]:
        """Get comprehensive system integration status."""
        await self._ensure_initialized()
        service_status = {}
        
        for name, service in self.services.items():
            service_status[name] = {
                'type': service.integration_type.value,
                'status': service.status.value,
                'response_time': service.response_time,
                'success_rate': service.success_rate,
                'error_count': service.error_count,
                'total_requests': service.total_requests,
                'circuit_breaker_open': self.circuit_breakers.get(name, False),
                'last_health_check': service.last_health_check.isoformat() if service.last_health_check else None,
                'capabilities': service.capabilities
            }
        
        return {
            'system_health': 'healthy' if all(
                s.status == IntegrationStatus.HEALTHY for s in self.services.values()
            ) else 'degraded',
            'total_services': len(self.services),
            'healthy_services': len([s for s in self.services.values() if s.status == IntegrationStatus.HEALTHY]),
            'failed_services': len([s for s in self.services.values() if s.status == IntegrationStatus.FAILED]),
            'global_stats': self.global_stats,
            'services': service_status
        }

# Global orchestrator instance
integration_orchestrator = None

async def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point for full system integration orchestration."""
    global integration_orchestrator
    
    try:
        action = context.get('action', 'status')
        
        if integration_orchestrator is None:
            integration_orchestrator = FullSystemIntegrationOrchestrator(config)
            # Give it a moment to discover services
            await asyncio.sleep(1)
        
        if action == 'execute':
            # Execute integration request
            request_data = context.get('request', {})
            
            integration_request = IntegrationRequest(
                integration_type=IntegrationType(request_data.get('integration_type', 'api')),
                operation=request_data.get('operation', 'status'),
                data=request_data.get('data', {}),
                routing_preferences=request_data.get('routing_preferences', {}),
                timeout=request_data.get('timeout', 30.0),
                retry_count=request_data.get('retry_count', 3),
                require_healthy=request_data.get('require_healthy', True)
            )
            
            result = await integration_orchestrator.execute_integration(integration_request)
            
            return {
                'success': result['success'],
                'message': 'Integration request executed',
                'orchestration_result': result
            }
        
        elif action == 'status':
            # Get system status
            status = await integration_orchestrator.get_system_status()
            
            return {
                'success': True,
                'message': 'Full system integration status',
                'system_status': status,
                'orchestrator': 'full_system_integration'
            }
        
        elif action == 'list_services':
            # List available integration services
            services = {
                name: {
                    'type': service.integration_type.value,
                    'status': service.status.value,
                    'capabilities': service.capabilities
                }
                for name, service in integration_orchestrator.services.items()
            }
            
            return {
                'success': True,
                'message': 'Available integration services',
                'services': services,
                'total_services': len(services)
            }
        
        else:
            return {
                'success': False,
                'error': f'Unknown action: {action}',
                'available_actions': ['execute', 'status', 'list_services']
            }
            
    except Exception as e:
        logger.error(f"Full system integration orchestrator error: {e}")
        return {
            'success': False,
            'error': str(e),
            'message': 'Full System Integration Orchestrator encountered an error'
        }

# Plugin metadata
plug_metadata = {
    "name": "integration_full_system",
    "version": "1.0.0",
    "description": "Complete enterprise system integration orchestrator coordinating ALL available PlugPipe integration plugins",
    "author": "PlugPipe Integration Team",
    "tags": ["integration", "orchestration", "enterprise", "full-system"],
    "category": "integration",
    "status": "stable",
    "capabilities": [
        "universal_integration_hub", "service_discovery", "health_monitoring", 
        "load_balancing", "circuit_breaker", "performance_analytics",
        "graceful_degradation", "multi_cloud", "enterprise_systems"
    ]
}
