#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Self-Contained Agent Factory Plugin

This version has NO external dependencies and can be used by any external system.
All required code is bundled within this single file.
"""

import asyncio
import logging
import time
import uuid
from typing import Dict, List, Any, Optional
from datetime import datetime
from dataclasses import dataclass
from enum import Enum


# === BUNDLED TYPES (from agent_types.py) ===

class AgentStatus(Enum):
    """Agent lifecycle status"""
    INITIALIZING = "initializing"
    READY = "ready"
    IDLE = "idle"
    ACTIVE = "active"
    BUSY = "busy"
    PAUSED = "paused"
    STOPPING = "stopping"
    STOPPED = "stopped"
    ERROR = "error"
    FAILED = "failed"


@dataclass
class AgentTemplate:
    """Basic agent template"""
    template_id: str
    name: str
    description: str
    version: str = "1.0.0"
    default_config: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.default_config is None:
            self.default_config = {}


@dataclass
class AgentPerformanceMetrics:
    """Performance metrics for agents"""
    agent_id: str
    uptime_seconds: float = 0.0
    tasks_completed: int = 0
    tasks_failed: int = 0
    average_response_time: float = 0.0
    error_rate: float = 0.0
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    last_activity: Optional[datetime] = None


# === BUNDLED AGENT INSTANCE ===

class AgentInstance:
    """Self-contained agent instance"""
    
    def __init__(self, agent_id: str, template: AgentTemplate, config: Dict[str, Any]):
        self.agent_id = agent_id
        self.template = template
        self.config = config
        self.status = AgentStatus.INITIALIZING
        self.created_at = datetime.now()
        self.metrics = AgentPerformanceMetrics(agent_id=agent_id)
        self.logger = logging.getLogger(f"agent.{agent_id}")
        
    async def initialize(self) -> bool:
        """Initialize the agent"""
        try:
            self.logger.info(f"Initializing agent {self.agent_id}")
            
            # Simple validation
            if not self.config:
                self.config = {}
            
            self.status = AgentStatus.READY
            self.logger.info(f"Agent {self.agent_id} initialized successfully")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to initialize agent {self.agent_id}: {e}")
            self.status = AgentStatus.ERROR
            return False
    
    def get_health_status(self) -> Dict[str, Any]:
        """Get agent health status"""
        return {
            'agent_id': self.agent_id,
            'status': self.status.value,
            'uptime_seconds': (datetime.now() - self.created_at).total_seconds(),
            'template_id': self.template.template_id,
            'healthy': self.status in [AgentStatus.READY, AgentStatus.IDLE]
        }


# === BUNDLED CORE FACTORY ===

class StandaloneAgentFactory:
    """Completely self-contained agent factory"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.templates: Dict[str, AgentTemplate] = {}
        self.active_agents: Dict[str, AgentInstance] = {}
        self.agent_registry: Dict[str, Dict[str, Any]] = {}
        
        self.logger.info("Standalone agent factory initialized")
    
    def register_template(self, template: AgentTemplate) -> bool:
        """Register an agent template"""
        try:
            self.templates[template.template_id] = template
            self.logger.info(f"Registered agent template: {template.template_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to register template: {e}")
            return False
    
    async def create_agent(self, template_id: str, config: Dict[str, Any], 
                          agent_id: Optional[str] = None) -> Optional[AgentInstance]:
        """Create a new agent instance from a template"""
        try:
            # Generate unique agent ID if not provided
            if not agent_id:
                agent_id = f"agent_{template_id}_{uuid.uuid4().hex[:8]}"
            
            # Check if agent already exists
            if agent_id in self.active_agents:
                self.logger.warning(f"Agent {agent_id} already exists")
                return self.active_agents[agent_id]
            
            # Get template (create a mock one if not found for testing)
            template = self.templates.get(template_id)
            if not template:
                template = AgentTemplate(
                    template_id=template_id,
                    name=f"Mock Template {template_id}",
                    description="Auto-generated template for testing"
                )
                self.logger.warning(f"Template {template_id} not found, using mock template")
            
            # Merge configs
            merged_config = {**template.default_config, **config}
            
            # Create agent instance
            agent = AgentInstance(agent_id, template, merged_config)
            
            # Initialize agent
            if await agent.initialize():
                self.active_agents[agent_id] = agent
                self.agent_registry[agent_id] = {
                    'template_id': template_id,
                    'created_at': agent.created_at.isoformat(),
                    'status': agent.status.value
                }
                
                self.logger.info(f"Created agent {agent_id} from template {template_id}")
                return agent
            else:
                self.logger.error(f"Failed to initialize agent {agent_id}")
                return None
                
        except Exception as e:
            self.logger.error(f"Failed to create agent: {e}")
            return None
    
    async def destroy_agent(self, agent_id: str) -> bool:
        """Destroy an agent instance"""
        try:
            if agent_id not in self.active_agents:
                self.logger.warning(f"Agent {agent_id} not found")
                return False
            
            agent = self.active_agents[agent_id]
            agent.status = AgentStatus.STOPPED
            
            # Remove from registry
            del self.active_agents[agent_id]
            del self.agent_registry[agent_id]
            
            self.logger.info(f"Destroyed agent {agent_id}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to destroy agent {agent_id}: {e}")
            return False
    
    def get_agent(self, agent_id: str) -> Optional[AgentInstance]:
        """Get an agent instance by ID"""
        return self.active_agents.get(agent_id)
    
    def list_agents(self, status_filter: Optional[AgentStatus] = None) -> List[Dict[str, Any]]:
        """List all agents, optionally filtered by status"""
        agents = []
        for agent_id, agent in self.active_agents.items():
            if status_filter is None or agent.status == status_filter:
                agents.append({
                    'agent_id': agent_id,
                    'template_id': agent.template.template_id,
                    'status': agent.status.value,
                    'created_at': agent.created_at.isoformat(),
                    'uptime_seconds': (datetime.now() - agent.created_at).total_seconds()
                })
        return agents
    
    def get_templates(self) -> List[Dict[str, Any]]:
        """Get list of available templates"""
        templates = []
        for template in self.templates.values():
            templates.append({
                'template_id': template.template_id,
                'name': template.name,
                'description': template.description,
                'version': template.version
            })
        return templates
    
    async def scale_agents(self, template_id: str, target_count: int) -> List[str]:
        """Scale agents of a specific template to target count"""
        current_agents = [
            agent_id for agent_id, info in self.agent_registry.items()
            if info['template_id'] == template_id
        ]
        
        current_count = len(current_agents)
        new_agent_ids = []
        
        if target_count > current_count:
            # Scale up
            for i in range(target_count - current_count):
                agent = await self.create_agent(template_id, {})
                if agent:
                    new_agent_ids.append(agent.agent_id)
        
        elif target_count < current_count:
            # Scale down
            agents_to_remove = current_agents[target_count:]
            for agent_id in agents_to_remove:
                await self.destroy_agent(agent_id)
        
        return new_agent_ids
    
    def get_factory_status(self) -> Dict[str, Any]:
        """Get factory status"""
        return {
            'factory_type': 'standalone',
            'total_templates': len(self.templates),
            'active_agents': len(self.active_agents),
            'status': 'healthy',
            'self_contained': True
        }
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get comprehensive health status"""
        return {
            'factory_id': 'standalone_agent_factory',
            'healthy': True,
            'total_agents_created': len(self.active_agents),
            'total_operations': len(self.active_agents) + len(self.templates),
            'active_agents': len(self.active_agents),
            'registered_templates': len(self.templates),
            'status': 'ready'
        }


# === PLUGIN WRAPPER ===

class StandalonePluginAgentFactory:
    """Plugin wrapper for the standalone agent factory"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger, metrics_collector: Any):
        self.config = config
        self.logger = logger or logging.getLogger(__name__)
        self.metrics = metrics_collector
        
        # Initialize standalone factory
        self.factory = StandaloneAgentFactory()
        
        # Plugin-specific state
        self.plugin_id = f"standalone_agent_factory_{uuid.uuid4().hex[:8]}"
        self.created_at = datetime.now()
        self.total_agents_created = 0
        self.total_operations = 0
        self.health_status = "healthy"
        
        self.logger.info(f"Standalone Plugin Agent Factory initialized: {self.plugin_id}")
    
    async def create_agent(self, template_id: str, config: Dict[str, Any], 
                          agent_id: Optional[str] = None) -> Optional[AgentInstance]:
        """Create agent using standalone factory"""
        self.total_operations += 1
        
        agent = await self.factory.create_agent(template_id, config, agent_id)
        if agent:
            self.total_agents_created += 1
            self.logger.info(f"Created agent {agent.agent_id}")
        
        return agent
    
    def register_template(self, template: AgentTemplate) -> bool:
        """Register agent template"""
        return self.factory.register_template(template)
    
    def list_agents(self, status_filter: Optional[AgentStatus] = None) -> List[Dict[str, Any]]:
        """List agents with plugin metadata"""
        agents = self.factory.list_agents(status_filter)
        
        # Add plugin-specific metadata
        for agent in agents:
            agent['factory_type'] = 'standalone'
            agent['plugin_id'] = self.plugin_id
            agent['created_via_plugin'] = True
        
        return agents
    
    def get_agent(self, agent_id: str) -> Optional[AgentInstance]:
        """Get agent instance by ID"""
        return self.factory.get_agent(agent_id)
    
    async def destroy_agent(self, agent_id: str) -> bool:
        """Destroy agent"""
        return await self.factory.destroy_agent(agent_id)
    
    def get_templates(self) -> List[Dict[str, Any]]:
        """Get available templates"""
        return self.factory.get_templates()
    
    async def scale_agents(self, template_id: str, target_count: int) -> List[str]:
        """Scale agents"""
        return await self.factory.scale_agents(template_id, target_count)
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get plugin health status"""
        uptime = (datetime.now() - self.created_at).total_seconds()
        
        return {
            'plugin_id': self.plugin_id,
            'factory_type': 'standalone',
            'healthy': self.health_status == "healthy",
            'uptime_seconds': uptime,
            'total_agents_created': self.total_agents_created,
            'total_operations': self.total_operations,
            'active_agents': len(self.list_agents()),
            'registered_templates': len(self.get_templates()),
            'self_contained': True,
            'external_dependencies': None,
            'status': 'ready'
        }


# === PLUGIN ENTRY POINT ===

def process(ctx, cfg):
    """
    PlugPipe plugin entry point - Standalone version
    
    This version works anywhere with zero external dependencies!
    """
    logger = ctx.get('logger') if ctx and ctx.get('logger') else logging.getLogger(__name__)
    metrics = ctx.get('metrics') if ctx else None
    
    try:
        # Create standalone plugin agent factory
        plugin_factory = StandalonePluginAgentFactory(
            config=cfg,
            logger=logger,
            metrics_collector=metrics
        )
        
        logger.info("Standalone agent factory plugin loaded successfully")
        
        return {
            'success': True,
            'factory': plugin_factory,
            'capabilities': [
                'agent_creation',
                'agent_lifecycle_management', 
                'template_management',
                'scaling',
                'health_monitoring'
            ],
            'factory_type': 'standalone',
            'plugin_id': plugin_factory.plugin_id,
            'status': 'ready',
            'self_contained': True,
            'external_dependencies': None,
            'health_endpoint': plugin_factory.get_health_status,
            'message': 'Standalone Agent Factory Plugin - Zero Dependencies!'
        }
        
    except Exception as e:
        error_msg = f"Standalone plugin initialization failed: {e}"
        if logger:
            logger.error(error_msg)
        else:
            print(error_msg)
        return {
            'success': False,
            'error': str(e),
            'factory': None,
            'capabilities': [],
            'status': 'failed'
        }


# === PLUGIN METADATA ===

plug_metadata = {
    "name": "Standalone Agent Factory",
    "version": "1.0.0",
    "description": "Self-contained agent factory with zero external dependencies",
    "author": "PlugPipe Core Team",
    "category": "core",
    "type": "infrastructure",
    "capabilities": [
        "agent_creation",
        "agent_lifecycle_management",
        "template_management",
        "scaling",
        "health_monitoring"
    ],
    "dependencies": [],
    "external_dependencies": None,
    "self_contained": True,
    "portable": True,
    "enterprise_ready": True,
    "production_ready": True
}


# === CONVENIENCE EXPORTS ===

__all__ = [
    'process', 
    'plug_metadata',
    'StandaloneAgentFactory',
    'StandalonePluginAgentFactory', 
    'AgentInstance',
    'AgentTemplate',
    'AgentStatus'
]


# === DEMO/TEST FUNCTIONALITY ===

async def demo_standalone_usage():
    """Demo how to use the standalone agent factory"""
    
    # Create factory
    factory = StandaloneAgentFactory()
    
    # Create a template
    template = AgentTemplate(
        template_id="demo_template",
        name="Demo Agent Template",
        description="A simple demo template"
    )
    
    # Register template
    factory.register_template(template)
    
    # Create agents
    agent1 = await factory.create_agent("demo_template", {"param": "value1"})
    agent2 = await factory.create_agent("demo_template", {"param": "value2"})
    
    # List agents
    agents = factory.list_agents()
    print(f"Created {len(agents)} agents")
    
    # Get status
    status = factory.get_factory_status()
    print(f"Factory status: {status}")
    
    return factory


if __name__ == "__main__":
    # Demo usage
    print("🚀 Standalone Agent Factory Demo")
    asyncio.run(demo_standalone_usage())