#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Agent Type Definitions and Enums

Core type system for the PlugPipe AI Agent Framework, defining
agent capabilities, status, communication protocols, and metrics.
"""

import enum
import time
from typing import Dict, List, Any, Optional, Union
from dataclasses import dataclass, field
from datetime import datetime


class AgentCapability(enum.Enum):
    """Agent capability types"""
    WEB_SEARCH = "web_search"
    FACT_CHECKING = "fact_checking"
    CITATION_VALIDATION = "citation_validation"
    CONSISTENCY_CHECKING = "consistency_checking"
    DOMAIN_EXPERTISE = "domain_expertise"
    HALLUCINATION_DETECTION = "hallucination_detection"
    CONTENT_GENERATION = "content_generation"
    DATA_ANALYSIS = "data_analysis"
    SEMANTIC_ANALYSIS = "semantic_analysis"
    REAL_TIME_VERIFICATION = "real_time_verification"


class AgentStatus(enum.Enum):
    """Agent lifecycle status"""
    INITIALIZING = "initializing"
    READY = "ready"
    ACTIVE = "active"
    BUSY = "busy"
    IDLE = "idle"
    ERROR = "error"
    STOPPING = "stopping"
    STOPPED = "stopped"
    TERMINATED = "terminated"


class AgentPriority(enum.Enum):
    """Agent execution priority"""
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


class CommunicationProtocol(enum.Enum):
    """Inter-agent communication protocols"""
    DIRECT_CALL = "direct_call"
    MESSAGE_QUEUE = "message_queue"
    EVENT_DRIVEN = "event_driven"
    REST_API = "rest_api"
    WEBSOCKET = "websocket"
    PLUGIN_INTERFACE = "plugin_interface"


@dataclass
class AgentPerformanceMetrics:
    """Agent performance and health metrics"""
    agent_id: str
    tasks_completed: int = 0
    tasks_failed: int = 0
    average_response_time: float = 0.0
    last_activity: Optional[datetime] = None
    cpu_usage: float = 0.0
    memory_usage: float = 0.0
    accuracy_score: float = 0.0
    confidence_score: float = 0.0
    uptime_seconds: float = 0.0
    error_rate: float = 0.0
    
    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage"""
        total_tasks = self.tasks_completed + self.tasks_failed
        if total_tasks == 0:
            return 0.0
        return (self.tasks_completed / total_tasks) * 100.0
    
    def update_task_completion(self, success: bool, response_time: float):
        """Update metrics after task completion"""
        if success:
            self.tasks_completed += 1
        else:
            self.tasks_failed += 1
        
        # Update rolling average response time
        total_tasks = self.tasks_completed + self.tasks_failed
        if total_tasks == 1:
            self.average_response_time = response_time
        else:
            self.average_response_time = (
                (self.average_response_time * (total_tasks - 1) + response_time) / total_tasks
            )
        
        self.last_activity = datetime.now()
        self.error_rate = (self.tasks_failed / total_tasks) * 100.0


@dataclass
class AgentCapabilityRequirement:
    """Defines what capabilities an agent needs"""
    capability: AgentCapability
    required: bool = True
    minimum_performance: float = 0.0
    configuration: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AgentResourceLimits:
    """Resource constraints for agent execution"""
    max_memory_mb: int = 512
    max_cpu_percent: float = 50.0
    max_execution_time_seconds: int = 300
    max_concurrent_tasks: int = 5
    max_network_requests_per_minute: int = 100
    max_storage_mb: int = 100


@dataclass
class AgentCommunicationConfig:
    """Agent communication configuration"""
    protocol: CommunicationProtocol
    endpoint: Optional[str] = None
    timeout_seconds: int = 30
    retry_attempts: int = 3
    compression_enabled: bool = False
    encryption_enabled: bool = True
    authentication_required: bool = True


@dataclass
class AgentTask:
    """Represents a task assigned to an agent"""
    task_id: str
    agent_id: str
    task_type: str
    priority: AgentPriority
    payload: Dict[str, Any]
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: str = "pending"
    result: Optional[Any] = None
    error: Optional[str] = None
    
    @property
    def execution_time(self) -> Optional[float]:
        """Calculate task execution time in seconds"""
        if self.started_at and self.completed_at:
            return (self.completed_at - self.started_at).total_seconds()
        return None
    
    def mark_started(self):
        """Mark task as started"""
        self.started_at = datetime.now()
        self.status = "running"
    
    def mark_completed(self, result: Any = None):
        """Mark task as completed successfully"""
        self.completed_at = datetime.now()
        self.status = "completed"
        self.result = result
    
    def mark_failed(self, error: str):
        """Mark task as failed"""
        self.completed_at = datetime.now()
        self.status = "failed"
        self.error = error


@dataclass
class AgentCoordinationEvent:
    """Event for inter-agent coordination"""
    event_id: str
    source_agent_id: str
    target_agent_id: Optional[str]  # None for broadcast
    event_type: str
    payload: Dict[str, Any]
    timestamp: datetime
    priority: AgentPriority = AgentPriority.MEDIUM
    requires_response: bool = False
    response_timeout_seconds: int = 30


class AgentSecurityLevel(enum.Enum):
    """Agent security isolation levels"""
    MINIMAL = "minimal"      # Basic process isolation
    STANDARD = "standard"    # Container-like isolation
    STRICT = "strict"        # Full sandbox isolation
    ENTERPRISE = "enterprise" # Enterprise-grade security


@dataclass
class AgentSecurityContext:
    """Security context for agent execution"""
    security_level: AgentSecurityLevel
    allowed_network_hosts: List[str] = field(default_factory=list)
    allowed_file_paths: List[str] = field(default_factory=list)
    environment_variables: Dict[str, str] = field(default_factory=dict)
    resource_limits: AgentResourceLimits = field(default_factory=AgentResourceLimits)
    audit_logging: bool = True
    encryption_required: bool = True


class AgentSpecializationType(enum.Enum):
    """Types of agent specialization"""
    DOMAIN_EXPERT = "domain_expert"        # Medical, Legal, Financial expertise
    TASK_SPECIALIST = "task_specialist"    # Web search, fact-checking, etc.
    INTEGRATION_BRIDGE = "integration_bridge"  # Connect different systems
    ORCHESTRATION_CONTROLLER = "orchestration_controller"  # Manage other agents
    DATA_PROCESSOR = "data_processor"      # Process and transform data
    SECURITY_VALIDATOR = "security_validator"  # Security and compliance
    PERFORMANCE_OPTIMIZER = "performance_optimizer"  # Optimize operations


@dataclass
class AgentTemplate:
    """Template for creating agents with specific capabilities"""
    template_id: str
    name: str
    description: str
    version: str
    specialization: AgentSpecializationType
    capabilities: List[AgentCapabilityRequirement]
    default_config: Dict[str, Any] = field(default_factory=dict)
    resource_limits: AgentResourceLimits = field(default_factory=AgentResourceLimits)
    security_context: AgentSecurityContext = field(default_factory=lambda: AgentSecurityContext(AgentSecurityLevel.STANDARD))
    communication_protocols: List[CommunicationProtocol] = field(default_factory=list)
    dependencies: List[str] = field(default_factory=list)  # Required plugins or other agents
    performance_targets: Dict[str, float] = field(default_factory=dict)
    
    def validate_requirements(self) -> List[str]:
        """Validate template requirements and return any issues"""
        issues = []
        
        if not self.name:
            issues.append("Template name is required")
        
        if not self.capabilities:
            issues.append("Template must define at least one capability")
        
        # Check for conflicting capabilities
        capability_types = [cap.capability for cap in self.capabilities]
        if len(capability_types) != len(set(capability_types)):
            issues.append("Template contains duplicate capabilities")
        
        return issues
    
    def estimate_resource_usage(self) -> AgentResourceLimits:
        """Estimate resource usage based on capabilities"""
        base_memory = 128
        base_cpu = 10.0
        
        # Adjust based on capabilities
        for cap_req in self.capabilities:
            if cap_req.capability == AgentCapability.WEB_SEARCH:
                base_memory += 64
                base_cpu += 5.0
            elif cap_req.capability == AgentCapability.SEMANTIC_ANALYSIS:
                base_memory += 256
                base_cpu += 15.0
            elif cap_req.capability == AgentCapability.DOMAIN_EXPERTISE:
                base_memory += 512
                base_cpu += 20.0
        
        return AgentResourceLimits(
            max_memory_mb=min(base_memory, self.resource_limits.max_memory_mb),
            max_cpu_percent=min(base_cpu, self.resource_limits.max_cpu_percent)
        )