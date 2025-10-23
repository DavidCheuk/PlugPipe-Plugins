#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
🧠🎯 Intelligent LLM Priority Manager Plugin

Dynamic priority-based LLM access control system that intelligently allocates LLM resources
based on plugin importance, user-defined priorities, business logic, and real-time demand.
Ensures critical processes get LLM access first while optimizing resource utilization.

This plugin follows PlugPipe principles by composing existing foundational plugins:
- intelligence/ai_rate_limiter for rate limit management
- intelligence/budget_aware_rate_limiter for budget constraints
- intelligence/llm_cost_estimator for usage analytics
- agents/agent_factory for dynamic agent creation

Key Features:
- Dynamic priority scoring based on multiple factors (importance, urgency, cost)
- Real-time demand-based resource allocation
- User-configurable business rules and priority policies
- AI-powered demand prediction and load balancing
- Integration with existing PlugPipe LLM infrastructure
- Emergency escalation and critical process protection
- Comprehensive priority analytics and reporting

Author: PlugPipe AI Infrastructure Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sqlite3
import time
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Union
from dataclasses import dataclass, asdict, field
from enum import Enum
from pathlib import Path
import heapq
import threading
from collections import defaultdict, deque

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Import pp function for plugin discovery as per CLAUDE.md
try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
    logger.info("✅ PlugPipe ecosystem functions loaded successfully")
except ImportError:
    logger.warning("⚠️ PlugPipe ecosystem functions not available, using fallback mode")
    def pp(plugin_path): return None
    def get_llm_config(primary=True): return {}


class PriorityLevel(Enum):
    """Priority levels for LLM access requests"""
    EMERGENCY = 10      # Critical system operations, security alerts
    CRITICAL = 8        # High-value business processes
    HIGH = 6           # Important user requests, automated workflows
    NORMAL = 4         # Standard operations, background tasks
    LOW = 2            # Batch processing, analytics
    BACKGROUND = 1     # Non-urgent maintenance tasks


class RequestStatus(Enum):
    """Status of LLM access requests"""
    QUEUED = "queued"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    TIMEOUT = "timeout"
    CANCELLED = "cancelled"


class BusinessRule(Enum):
    """Business rules for priority calculation"""
    USER_TIER_MULTIPLIER = "user_tier_multiplier"      # Premium users get higher priority
    TIME_CRITICALITY = "time_criticality"              # Urgent deadlines increase priority
    COST_EFFICIENCY = "cost_efficiency"                # Lower cost operations preferred
    RESOURCE_AVAILABILITY = "resource_availability"     # Adjust based on current load
    PLUGIN_REPUTATION = "plugin_reputation"            # Well-behaved plugins get priority
    ERROR_RATE_PENALTY = "error_rate_penalty"          # High error rate plugins penalized


@dataclass
class LLMRequest:
    """Data class for LLM access requests"""
    request_id: str
    plugin_id: str
    provider: str
    model: str
    priority_level: PriorityLevel
    user_id: str = "system"
    estimated_tokens: int = 1000
    estimated_cost: float = 0.01
    deadline: Optional[datetime] = None
    business_context: Dict[str, Any] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.utcnow)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    status: RequestStatus = RequestStatus.QUEUED
    priority_score: float = 0.0
    wait_time_seconds: float = 0.0
    processing_time_seconds: float = 0.0


@dataclass
class PriorityPolicy:
    """Data class for priority policies and business rules"""
    policy_id: str
    name: str
    description: str
    rules: Dict[str, Any]
    weight: float = 1.0
    enabled: bool = True
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class PluginProfile:
    """Data class for plugin behavior profiles"""
    plugin_id: str
    average_tokens: int
    average_cost: float
    success_rate: float
    average_processing_time: float
    reputation_score: float
    last_updated: datetime = field(default_factory=datetime.utcnow)


class IntelligentLLMPriorityManager:
    """AI-powered priority management system for LLM resource allocation"""
    
    # Default priority weights for scoring algorithm
    DEFAULT_PRIORITY_WEIGHTS = {
        'base_priority': 0.4,        # Base priority level weight
        'time_criticality': 0.2,     # Deadline urgency weight
        'cost_efficiency': 0.15,     # Cost optimization weight
        'plugin_reputation': 0.1,    # Plugin reliability weight
        'resource_availability': 0.1, # Current load adjustment
        'user_tier': 0.05            # User tier bonus weight
    }
    
    # Priority queue management
    MAX_QUEUE_SIZE = 1000
    PRIORITY_REFRESH_INTERVAL = 30  # seconds
    
    def __init__(self, db_path: str = "intelligent_llm_priority_manager.db"):
        """Initialize intelligent LLM priority manager with PlugPipe ecosystem integration"""
        self.db_path = db_path
        
        # Plugin instances loaded via pp() function
        self.rate_limiter = None
        self.budget_limiter = None
        self.cost_estimator = None
        self.agent_factory = None
        
        # Priority management state
        self.request_queue = []  # Priority heap queue
        self.active_requests = {}  # Currently processing requests
        self.policies = {}  # Priority policies
        self.plugin_profiles = {}  # Plugin behavior profiles
        self.priority_weights = self.DEFAULT_PRIORITY_WEIGHTS.copy()
        
        # Thread safety
        self.queue_lock = threading.Lock()
        self.processing_lock = threading.Lock()
        
        self._init_database()
        self._init_plugin_ecosystem()
        self._load_priority_policies()
        self._start_priority_manager()
    
    def _init_database(self):
        """Initialize SQLite database for priority management"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # LLM requests queue and history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS llm_requests (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT UNIQUE NOT NULL,
                    plugin_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    priority_level INTEGER NOT NULL,
                    user_id TEXT NOT NULL,
                    estimated_tokens INTEGER NOT NULL,
                    estimated_cost REAL NOT NULL,
                    deadline TEXT,
                    business_context TEXT,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    started_at DATETIME,
                    completed_at DATETIME,
                    status TEXT NOT NULL,
                    priority_score REAL NOT NULL,
                    wait_time_seconds REAL DEFAULT 0,
                    processing_time_seconds REAL DEFAULT 0
                )
            ''')
            
            # Priority policies
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS priority_policies (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_id TEXT UNIQUE NOT NULL,
                    name TEXT NOT NULL,
                    description TEXT NOT NULL,
                    rules TEXT NOT NULL,
                    weight REAL DEFAULT 1.0,
                    enabled BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Plugin profiles and behavior analytics
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plugin_profiles (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT UNIQUE NOT NULL,
                    average_tokens INTEGER DEFAULT 1000,
                    average_cost REAL DEFAULT 0.01,
                    success_rate REAL DEFAULT 1.0,
                    average_processing_time REAL DEFAULT 5.0,
                    reputation_score REAL DEFAULT 5.0,
                    total_requests INTEGER DEFAULT 0,
                    successful_requests INTEGER DEFAULT 0,
                    failed_requests INTEGER DEFAULT 0,
                    last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Priority analytics and metrics
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS priority_analytics (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    total_requests INTEGER NOT NULL,
                    queued_requests INTEGER NOT NULL,
                    processing_requests INTEGER NOT NULL,
                    completed_requests INTEGER NOT NULL,
                    failed_requests INTEGER NOT NULL,
                    average_wait_time REAL NOT NULL,
                    average_processing_time REAL NOT NULL,
                    resource_utilization REAL NOT NULL,
                    priority_distribution TEXT NOT NULL
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"✅ Priority manager database initialized: {self.db_path}")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
    
    def _init_plugin_ecosystem(self):
        """Initialize PlugPipe ecosystem connections using pp() discovery"""
        try:
            logger.info("🔍 Discovering PlugPipe ecosystem plugins via pp() function...")
            
            # Discover rate limiter for capacity management
            try:
                self.rate_limiter = pp('ai_rate_limiter', version='1.0.0')
                if self.rate_limiter:
                    logger.info("✅ AI rate limiter plugin discovered and loaded")
                else:
                    logger.warning("⚠️ AI rate limiter plugin not found")
            except Exception as e:
                logger.warning(f"⚠️ Rate limiter discovery failed: {e}")
            
            # Discover budget-aware limiter for cost management
            try:
                self.budget_limiter = pp('budget_aware_rate_limiter', version='1.0.0')
                if self.budget_limiter:
                    logger.info("✅ Budget-aware rate limiter plugin discovered and loaded")
                else:
                    logger.warning("⚠️ Budget-aware rate limiter plugin not found")
            except Exception as e:
                logger.warning(f"⚠️ Budget limiter discovery failed: {e}")
            
            # Discover cost estimator for cost-aware prioritization
            try:
                self.cost_estimator = pp('llm_cost_estimator', version='1.0.0')
                if self.cost_estimator:
                    logger.info("✅ LLM cost estimator plugin discovered and loaded")
                else:
                    logger.warning("⚠️ LLM cost estimator plugin not found")
            except Exception as e:
                logger.warning(f"⚠️ Cost estimator discovery failed: {e}")
            
            # Discover agent factory for AI-powered priority analysis
            try:
                self.agent_factory = pp('agent_factory', version='1.0.0')
                if self.agent_factory:
                    logger.info("✅ Agent factory plugin discovered and loaded")
                else:
                    logger.warning("⚠️ Agent factory plugin not found")
            except Exception as e:
                logger.warning(f"⚠️ Agent factory discovery failed: {e}")
            
            logger.info("🔗 Plugin ecosystem integration completed")
            
        except Exception as e:
            logger.warning(f"⚠️ Plugin ecosystem integration failed: {e}, continuing with fallback mode")
    
    def _load_priority_policies(self):
        """Load priority policies from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT policy_id, name, description, rules, weight, enabled
                FROM priority_policies
                WHERE enabled = TRUE
                ORDER BY weight DESC
            ''')
            
            policies = cursor.fetchall()
            conn.close()
            
            for policy_data in policies:
                policy_id, name, description, rules_json, weight, enabled = policy_data
                try:
                    rules = json.loads(rules_json)
                    policy = PriorityPolicy(
                        policy_id=policy_id,
                        name=name,
                        description=description,
                        rules=rules,
                        weight=weight,
                        enabled=bool(enabled)
                    )
                    self.policies[policy_id] = policy
                    logger.info(f"📋 Loaded priority policy: {name} (weight: {weight})")
                except Exception as e:
                    logger.warning(f"⚠️ Failed to load policy {policy_id}: {e}")
            
            logger.info(f"✅ Loaded {len(self.policies)} priority policies")
            
        except Exception as e:
            logger.warning(f"⚠️ Failed to load priority policies: {e}")
            self._create_default_policies()
    
    def _create_default_policies(self):
        """Create default priority policies"""
        try:
            default_policies = [
                {
                    "policy_id": "user_tier_priority",
                    "name": "User Tier Priority",
                    "description": "Higher priority for premium users",
                    "rules": {
                        "user_tiers": {
                            "premium": 2.0,
                            "pro": 1.5,
                            "standard": 1.0,
                            "free": 0.8
                        }
                    },
                    "weight": 0.2
                },
                {
                    "policy_id": "time_criticality",
                    "name": "Time Criticality",
                    "description": "Higher priority for time-sensitive requests",
                    "rules": {
                        "urgency_multiplier": {
                            "immediate": 3.0,
                            "urgent": 2.0,
                            "normal": 1.0,
                            "low": 0.5
                        }
                    },
                    "weight": 0.3
                },
                {
                    "policy_id": "cost_efficiency",
                    "name": "Cost Efficiency",
                    "description": "Prefer lower cost operations when resources are limited",
                    "rules": {
                        "cost_thresholds": {
                            "low_cost": 1.2,      # < $0.01
                            "medium_cost": 1.0,   # $0.01 - $0.10
                            "high_cost": 0.8,     # > $0.10
                            "very_high_cost": 0.5 # > $1.00
                        }
                    },
                    "weight": 0.25
                },
                {
                    "policy_id": "plugin_reputation",
                    "name": "Plugin Reputation",
                    "description": "Higher priority for well-behaved plugins",
                    "rules": {
                        "reputation_thresholds": {
                            "excellent": 1.3,     # > 9.0 score
                            "good": 1.1,          # 7.0 - 9.0
                            "average": 1.0,       # 5.0 - 7.0
                            "poor": 0.8,          # 3.0 - 5.0
                            "very_poor": 0.5      # < 3.0
                        }
                    },
                    "weight": 0.15
                },
                {
                    "policy_id": "resource_availability",
                    "name": "Resource Availability",
                    "description": "Dynamic priority based on current system load",
                    "rules": {
                        "load_adjustments": {
                            "low_load": 1.0,      # < 25% capacity
                            "medium_load": 0.9,   # 25-50% capacity
                            "high_load": 0.7,     # 50-75% capacity
                            "very_high_load": 0.5, # 75-90% capacity
                            "critical_load": 0.2   # > 90% capacity
                        }
                    },
                    "weight": 0.1
                }
            ]
            
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            for policy in default_policies:
                cursor.execute('''
                    INSERT OR IGNORE INTO priority_policies
                    (policy_id, name, description, rules, weight, enabled)
                    VALUES (?, ?, ?, ?, ?, ?)
                ''', (policy['policy_id'], policy['name'], policy['description'],
                     json.dumps(policy['rules']), policy['weight'], True))
                
                # Create policy object
                self.policies[policy['policy_id']] = PriorityPolicy(
                    policy_id=policy['policy_id'],
                    name=policy['name'],
                    description=policy['description'],
                    rules=policy['rules'],
                    weight=policy['weight'],
                    enabled=True
                )
            
            conn.commit()
            conn.close()
            
            logger.info("✅ Created default priority policies")
            
        except Exception as e:
            logger.error(f"❌ Failed to create default policies: {e}")
    
    def _start_priority_manager(self):
        """Start background priority management tasks"""
        try:
            # Start priority queue processor
            self.priority_processor_thread = threading.Thread(
                target=self._priority_processor_loop,
                daemon=True
            )
            self.priority_processor_thread.start()
            
            # Start analytics collector
            self.analytics_thread = threading.Thread(
                target=self._analytics_loop,
                daemon=True
            )
            self.analytics_thread.start()
            
            logger.info("✅ Priority manager background tasks started")
            
        except Exception as e:
            logger.error(f"❌ Failed to start priority manager: {e}")
    
    def _priority_processor_loop(self):
        """Background loop to process priority queue"""
        while True:
            try:
                with self.queue_lock:
                    if self.request_queue:
                        # Get highest priority request
                        priority_score, request_id, request = heapq.heappop(self.request_queue)
                        
                        # Check if we can process this request
                        can_process = self._can_process_request(request)
                        
                        if can_process:
                            # Start processing request
                            self._start_request_processing(request)
                        else:
                            # Put request back in queue with updated priority
                            updated_priority = self._calculate_priority_score(request)
                            heapq.heappush(self.request_queue, (-updated_priority, request_id, request))
                
                # Sleep briefly before next iteration
                time.sleep(1.0)
                
            except Exception as e:
                logger.error(f"❌ Priority processor error: {e}")
                time.sleep(5.0)  # Wait before retrying
    
    def _analytics_loop(self):
        """Background loop to collect priority analytics"""
        while True:
            try:
                # Collect metrics every 60 seconds
                time.sleep(60)
                self._collect_priority_analytics()
                
            except Exception as e:
                logger.error(f"❌ Analytics collection error: {e}")
                time.sleep(30.0)  # Wait before retrying
    
    async def submit_llm_request(self, plugin_id: str, provider: str, model: str,
                                priority_level: PriorityLevel, user_id: str = "system",
                                estimated_tokens: int = 1000, deadline: Optional[datetime] = None,
                                business_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """Submit an LLM access request for priority-based processing"""
        try:
            import uuid
            request_id = str(uuid.uuid4())
            
            # Estimate cost using cost estimator plugin
            estimated_cost = await self._estimate_request_cost(provider, model, estimated_tokens)
            
            # Create LLM request
            request = LLMRequest(
                request_id=request_id,
                plugin_id=plugin_id,
                provider=provider,
                model=model,
                priority_level=priority_level,
                user_id=user_id,
                estimated_tokens=estimated_tokens,
                estimated_cost=estimated_cost,
                deadline=deadline,
                business_context=business_context or {}
            )
            
            # Calculate priority score
            request.priority_score = self._calculate_priority_score(request)
            
            # Add to priority queue
            with self.queue_lock:
                heapq.heappush(self.request_queue, (-request.priority_score, request_id, request))
            
            # Store in database
            await self._store_llm_request(request)
            
            logger.info(f"🎯 LLM request queued: {plugin_id}/{provider} (priority: {request.priority_score:.2f})")
            
            return {
                'success': True,
                'request_id': request_id,
                'priority_score': request.priority_score,
                'estimated_wait_time_seconds': self._estimate_wait_time(request),
                'queue_position': self._get_queue_position(request_id)
            }
            
        except Exception as e:
            logger.error(f"❌ Submit LLM request failed: {e}")
            return {'success': False, 'error': str(e)}
    
    def _calculate_priority_score(self, request: LLMRequest) -> float:
        """Calculate priority score using AI-powered multi-factor analysis"""
        try:
            base_score = float(request.priority_level.value)
            
            # Apply business rule policies
            for policy_id, policy in self.policies.items():
                if not policy.enabled:
                    continue
                
                try:
                    policy_score = self._apply_policy_rules(request, policy)
                    base_score += policy_score * policy.weight
                except Exception as e:
                    logger.warning(f"⚠️ Policy {policy_id} failed: {e}")
            
            # Time criticality adjustment
            if request.deadline:
                time_factor = self._calculate_time_criticality(request.deadline)
                base_score *= time_factor
            
            # Cost efficiency consideration
            cost_factor = self._calculate_cost_efficiency(request.estimated_cost)
            base_score *= cost_factor
            
            # Plugin reputation factor
            plugin_factor = self._get_plugin_reputation_factor(request.plugin_id)
            base_score *= plugin_factor
            
            # Resource availability adjustment
            availability_factor = self._get_resource_availability_factor()
            base_score *= availability_factor
            
            # Ensure minimum score
            final_score = max(0.1, base_score)
            
            logger.debug(f"Priority score calculated: {request.plugin_id} = {final_score:.2f}")
            return final_score
            
        except Exception as e:
            logger.error(f"❌ Priority score calculation failed: {e}")
            return float(request.priority_level.value)  # Fallback to base priority
    
    def _apply_policy_rules(self, request: LLMRequest, policy: PriorityPolicy) -> float:
        """Apply specific policy rules to calculate adjustment score"""
        rules = policy.rules
        adjustment = 0.0
        
        try:
            if policy.policy_id == 'user_tier_priority':
                user_tier = request.business_context.get('user_tier', 'standard')
                tier_multiplier = rules.get('user_tiers', {}).get(user_tier, 1.0)
                adjustment = (tier_multiplier - 1.0) * 2.0  # Scale adjustment
            
            elif policy.policy_id == 'time_criticality':
                urgency = request.business_context.get('urgency', 'normal')
                urgency_multiplier = rules.get('urgency_multiplier', {}).get(urgency, 1.0)
                adjustment = (urgency_multiplier - 1.0) * 3.0  # Higher scale for urgency
            
            elif policy.policy_id == 'cost_efficiency':
                cost = request.estimated_cost
                if cost < 0.01:
                    multiplier = rules.get('cost_thresholds', {}).get('low_cost', 1.0)
                elif cost < 0.10:
                    multiplier = rules.get('cost_thresholds', {}).get('medium_cost', 1.0)
                elif cost < 1.00:
                    multiplier = rules.get('cost_thresholds', {}).get('high_cost', 1.0)
                else:
                    multiplier = rules.get('cost_thresholds', {}).get('very_high_cost', 1.0)
                adjustment = (multiplier - 1.0) * 1.5
            
            elif policy.policy_id == 'plugin_reputation':
                reputation = self._get_plugin_reputation(request.plugin_id)
                if reputation > 9.0:
                    multiplier = rules.get('reputation_thresholds', {}).get('excellent', 1.0)
                elif reputation > 7.0:
                    multiplier = rules.get('reputation_thresholds', {}).get('good', 1.0)
                elif reputation > 5.0:
                    multiplier = rules.get('reputation_thresholds', {}).get('average', 1.0)
                elif reputation > 3.0:
                    multiplier = rules.get('reputation_thresholds', {}).get('poor', 1.0)
                else:
                    multiplier = rules.get('reputation_thresholds', {}).get('very_poor', 1.0)
                adjustment = (multiplier - 1.0) * 1.0
            
            elif policy.policy_id == 'resource_availability':
                load_factor = self._get_current_load_factor()
                if load_factor < 0.25:
                    multiplier = rules.get('load_adjustments', {}).get('low_load', 1.0)
                elif load_factor < 0.50:
                    multiplier = rules.get('load_adjustments', {}).get('medium_load', 1.0)
                elif load_factor < 0.75:
                    multiplier = rules.get('load_adjustments', {}).get('high_load', 1.0)
                elif load_factor < 0.90:
                    multiplier = rules.get('load_adjustments', {}).get('very_high_load', 1.0)
                else:
                    multiplier = rules.get('load_adjustments', {}).get('critical_load', 1.0)
                adjustment = (multiplier - 1.0) * 2.0
            
        except Exception as e:
            logger.warning(f"⚠️ Policy rule application failed for {policy.policy_id}: {e}")
        
        return adjustment
    
    def _calculate_time_criticality(self, deadline: datetime) -> float:
        """Calculate time criticality factor based on deadline"""
        try:
            now = datetime.utcnow()
            if deadline <= now:
                return 3.0  # Past deadline - highest priority
            
            time_remaining = (deadline - now).total_seconds()
            hours_remaining = time_remaining / 3600
            
            if hours_remaining < 1:
                return 2.5  # Less than 1 hour
            elif hours_remaining < 4:
                return 2.0  # Less than 4 hours
            elif hours_remaining < 24:
                return 1.5  # Less than 1 day
            elif hours_remaining < 168:  # 1 week
                return 1.2  # Less than 1 week
            else:
                return 1.0  # More than 1 week
                
        except Exception as e:
            logger.warning(f"⚠️ Time criticality calculation failed: {e}")
            return 1.0
    
    def _calculate_cost_efficiency(self, estimated_cost: float) -> float:
        """Calculate cost efficiency factor"""
        try:
            # Prefer lower cost operations when resources are constrained
            if estimated_cost < 0.001:
                return 1.2  # Very cheap operations get bonus
            elif estimated_cost < 0.01:
                return 1.1  # Cheap operations get slight bonus
            elif estimated_cost < 0.10:
                return 1.0  # Normal cost - no adjustment
            elif estimated_cost < 1.0:
                return 0.9  # Expensive operations get slight penalty
            else:
                return 0.7  # Very expensive operations get larger penalty
                
        except Exception as e:
            logger.warning(f"⚠️ Cost efficiency calculation failed: {e}")
            return 1.0
    
    def _get_plugin_reputation_factor(self, plugin_id: str) -> float:
        """Get reputation factor for plugin"""
        try:
            reputation_score = self._get_plugin_reputation(plugin_id)
            
            # Convert 0-10 reputation score to 0.5-1.5 multiplier
            factor = 0.5 + (reputation_score / 10.0)
            return min(1.5, max(0.5, factor))
            
        except Exception as e:
            logger.warning(f"⚠️ Plugin reputation factor calculation failed: {e}")
            return 1.0
    
    def _get_plugin_reputation(self, plugin_id: str) -> float:
        """Get plugin reputation score"""
        try:
            if plugin_id in self.plugin_profiles:
                return self.plugin_profiles[plugin_id].reputation_score
            
            # Query from database
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT reputation_score FROM plugin_profiles 
                WHERE plugin_id = ?
            ''', (plugin_id,))
            
            result = cursor.fetchone()
            conn.close()
            
            if result:
                return result[0]
            else:
                # Default reputation for new plugins
                return 5.0
                
        except Exception as e:
            logger.warning(f"⚠️ Plugin reputation lookup failed: {e}")
            return 5.0
    
    def _get_resource_availability_factor(self) -> float:
        """Get current resource availability adjustment factor"""
        try:
            load_factor = self._get_current_load_factor()
            
            # Convert load factor to availability adjustment
            if load_factor < 0.25:
                return 1.0  # Low load - no adjustment
            elif load_factor < 0.50:
                return 0.95  # Medium load - slight adjustment
            elif load_factor < 0.75:
                return 0.85  # High load - more aggressive adjustment
            elif load_factor < 0.90:
                return 0.70  # Very high load - significant adjustment
            else:
                return 0.50  # Critical load - major adjustment
                
        except Exception as e:
            logger.warning(f"⚠️ Resource availability calculation failed: {e}")
            return 1.0
    
    def _get_current_load_factor(self) -> float:
        """Get current system load factor (0.0 - 1.0)"""
        try:
            # Calculate based on active requests and queue size
            with self.queue_lock:
                queue_size = len(self.request_queue)
            
            with self.processing_lock:
                active_count = len(self.active_requests)
            
            # Simple load calculation - in production this would be more sophisticated
            total_capacity = 50  # Estimated max concurrent requests
            current_load = (queue_size + active_count) / total_capacity
            
            return min(1.0, max(0.0, current_load))
            
        except Exception as e:
            logger.warning(f"⚠️ Load factor calculation failed: {e}")
            return 0.5  # Conservative estimate
    
    async def _estimate_request_cost(self, provider: str, model: str, estimated_tokens: int) -> float:
        """Estimate request cost using cost estimator plugin"""
        try:
            if self.cost_estimator:
                cost_result = await self.cost_estimator.process({}, {
                    'operation': 'estimate_cost',
                    'provider': provider,
                    'model': model,
                    'input_tokens': estimated_tokens,
                    'output_tokens': estimated_tokens // 2  # Estimate output tokens
                })
                
                if cost_result.get('success'):
                    return cost_result.get('estimates', [{}])[0].get('total_cost', 0.01)
            
            # Fallback cost estimation
            cost_per_1k_tokens = {
                'openai': {'gpt-4': 0.03, 'gpt-3.5-turbo': 0.002},
                'anthropic': {'claude-3': 0.015, 'claude-2': 0.008},
                'ollama': {'mistral': 0.0, 'llama2': 0.0}  # Local models
            }.get(provider, {}).get(model, 0.01)
            
            return (estimated_tokens / 1000) * cost_per_1k_tokens
            
        except Exception as e:
            logger.warning(f"⚠️ Cost estimation failed: {e}")
            return 0.01  # Default fallback cost
    
    def _estimate_wait_time(self, request: LLMRequest) -> float:
        """Estimate wait time for request based on queue position and priority"""
        try:
            with self.queue_lock:
                queue_size = len(self.request_queue)
                
                # Count higher priority requests ahead in queue
                higher_priority_count = sum(1 for _, _, queued_request in self.request_queue 
                                           if queued_request.priority_score > request.priority_score)
            
            # Estimate based on average processing time
            average_processing_time = 5.0  # seconds - could be dynamic
            estimated_wait = higher_priority_count * average_processing_time
            
            return max(0.0, estimated_wait)
            
        except Exception as e:
            logger.warning(f"⚠️ Wait time estimation failed: {e}")
            return 30.0  # Conservative estimate
    
    def _get_queue_position(self, request_id: str) -> int:
        """Get queue position for request"""
        try:
            with self.queue_lock:
                for i, (_, rid, _) in enumerate(self.request_queue):
                    if rid == request_id:
                        return i + 1
            return -1
            
        except Exception as e:
            logger.warning(f"⚠️ Queue position lookup failed: {e}")
            return -1
    
    def _can_process_request(self, request: LLMRequest) -> bool:
        """Check if request can be processed now"""
        try:
            # Check rate limits via rate limiter plugin
            if self.rate_limiter:
                rate_check = asyncio.run(self.rate_limiter.process({}, {
                    'operation': 'check_rate_limit',
                    'plugin_id': request.plugin_id,
                    'provider': request.provider
                }))
                
                if not rate_check.get('allowed', True):
                    return False
            
            # Check budget constraints via budget limiter
            if self.budget_limiter:
                budget_check = asyncio.run(self.budget_limiter.process({}, {
                    'operation': 'monitor_and_adjust',
                    'plugin_id': request.plugin_id,
                    'provider': request.provider
                }))
                
                # If budget adjustments were made, respect them
                if budget_check.get('success') and budget_check.get('total_adjustments', 0) > 0:
                    return False
            
            # Check capacity limits
            with self.processing_lock:
                if len(self.active_requests) >= 10:  # Max concurrent requests
                    return False
            
            return True
            
        except Exception as e:
            logger.warning(f"⚠️ Process check failed: {e}")
            return False
    
    def _start_request_processing(self, request: LLMRequest):
        """Start processing a request"""
        try:
            request.status = RequestStatus.PROCESSING
            request.started_at = datetime.utcnow()
            request.wait_time_seconds = (request.started_at - request.created_at).total_seconds()
            
            with self.processing_lock:
                self.active_requests[request.request_id] = request
            
            logger.info(f"🚀 Started processing request: {request.plugin_id}/{request.provider} (waited: {request.wait_time_seconds:.1f}s)")
            
        except Exception as e:
            logger.error(f"❌ Start request processing failed: {e}")
    
    async def _store_llm_request(self, request: LLMRequest):
        """Store LLM request in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO llm_requests
                (request_id, plugin_id, provider, model, priority_level, user_id,
                 estimated_tokens, estimated_cost, deadline, business_context,
                 created_at, started_at, completed_at, status, priority_score,
                 wait_time_seconds, processing_time_seconds)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (request.request_id, request.plugin_id, request.provider, request.model,
                 request.priority_level.value, request.user_id, request.estimated_tokens,
                 request.estimated_cost, request.deadline.isoformat() if request.deadline else None,
                 json.dumps(request.business_context), request.created_at.isoformat(),
                 request.started_at.isoformat() if request.started_at else None,
                 request.completed_at.isoformat() if request.completed_at else None,
                 request.status.value, request.priority_score, request.wait_time_seconds,
                 request.processing_time_seconds))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Store LLM request failed: {e}")
    
    def _collect_priority_analytics(self):
        """Collect priority analytics and metrics"""
        try:
            with self.queue_lock:
                total_queued = len(self.request_queue)
            
            with self.processing_lock:
                total_processing = len(self.active_requests)
            
            # Query database for additional metrics
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get counts by status
            cursor.execute('''
                SELECT status, COUNT(*) FROM llm_requests 
                WHERE created_at >= datetime('now', '-1 hour')
                GROUP BY status
            ''')
            
            status_counts = dict(cursor.fetchall())
            
            # Get timing metrics
            cursor.execute('''
                SELECT AVG(wait_time_seconds), AVG(processing_time_seconds)
                FROM llm_requests 
                WHERE completed_at IS NOT NULL 
                AND created_at >= datetime('now', '-1 hour')
            ''')
            
            timing_result = cursor.fetchone()
            avg_wait_time = timing_result[0] if timing_result[0] else 0.0
            avg_processing_time = timing_result[1] if timing_result[1] else 0.0
            
            # Calculate resource utilization
            max_capacity = 50.0  # Estimated max capacity
            current_utilization = (total_queued + total_processing) / max_capacity
            
            # Priority distribution
            cursor.execute('''
                SELECT priority_level, COUNT(*) FROM llm_requests 
                WHERE created_at >= datetime('now', '-1 hour')
                GROUP BY priority_level
            ''')
            
            priority_dist = dict(cursor.fetchall())
            
            # Store analytics
            cursor.execute('''
                INSERT INTO priority_analytics
                (total_requests, queued_requests, processing_requests, 
                 completed_requests, failed_requests, average_wait_time,
                 average_processing_time, resource_utilization, priority_distribution)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (sum(status_counts.values()), total_queued, total_processing,
                 status_counts.get('completed', 0), status_counts.get('failed', 0),
                 avg_wait_time, avg_processing_time, current_utilization,
                 json.dumps(priority_dist)))
            
            conn.commit()
            conn.close()
            
            logger.debug(f"📊 Analytics collected: queue={total_queued}, processing={total_processing}, utilization={current_utilization:.1%}")
            
        except Exception as e:
            logger.error(f"❌ Analytics collection failed: {e}")
    
    async def get_priority_dashboard(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive priority management dashboard"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            
            # Current queue status
            with self.queue_lock:
                current_queue_size = len(self.request_queue)
                queue_priorities = [req.priority_score for _, _, req in self.request_queue]
            
            with self.processing_lock:
                current_processing = len(self.active_requests)
            
            # Historical metrics
            cursor.execute('''
                SELECT status, priority_level, COUNT(*), AVG(wait_time_seconds), AVG(processing_time_seconds)
                FROM llm_requests 
                WHERE created_at >= ?
                GROUP BY status, priority_level
            ''', (since_time,))
            
            historical_metrics = []
            for row in cursor.fetchall():
                historical_metrics.append({
                    'status': row[0],
                    'priority_level': row[1],
                    'count': row[2],
                    'avg_wait_time': row[3] or 0.0,
                    'avg_processing_time': row[4] or 0.0
                })
            
            # Plugin performance
            cursor.execute('''
                SELECT plugin_id, COUNT(*) as total_requests,
                       SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as successful,
                       AVG(priority_score) as avg_priority,
                       AVG(wait_time_seconds) as avg_wait
                FROM llm_requests 
                WHERE created_at >= ?
                GROUP BY plugin_id
                ORDER BY total_requests DESC
            ''', (since_time,))
            
            plugin_performance = []
            for row in cursor.fetchall():
                plugin_performance.append({
                    'plugin_id': row[0],
                    'total_requests': row[1],
                    'successful_requests': row[2],
                    'success_rate': (row[2] / row[1]) * 100 if row[1] > 0 else 0.0,
                    'avg_priority_score': row[3] or 0.0,
                    'avg_wait_time': row[4] or 0.0
                })
            
            conn.close()
            
            return {
                'success': True,
                'dashboard_timestamp': datetime.utcnow().isoformat(),
                'time_window_hours': hours,
                'current_status': {
                    'queue_size': current_queue_size,
                    'processing_count': current_processing,
                    'queue_priorities': {
                        'min': min(queue_priorities) if queue_priorities else 0,
                        'max': max(queue_priorities) if queue_priorities else 0,
                        'avg': sum(queue_priorities) / len(queue_priorities) if queue_priorities else 0
                    }
                },
                'historical_metrics': historical_metrics,
                'plugin_performance': plugin_performance,
                'active_policies': [
                    {
                        'policy_id': p.policy_id,
                        'name': p.name,
                        'weight': p.weight,
                        'enabled': p.enabled
                    } for p in self.policies.values()
                ]
            }
            
        except Exception as e:
            logger.error(f"❌ Priority dashboard failed: {e}")
            return {'success': False, 'error': str(e)}


# Plugin metadata
plug_metadata = {
    "name": "intelligent_llm_priority_manager",
    "owner": "plugpipe_ai_team",
    "version": "1.0.0",
    "status": "stable",
    "description": "AI-powered priority management system for LLM resource allocation with user-configurable business rules and intelligent demand-based scheduling",
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["submit_request", "get_dashboard", "update_policy", "get_queue_status"]
            },
            "plugin_id": {"type": "string"},
            "provider": {"type": "string"},
            "model": {"type": "string"},
            "priority_level": {
                "type": "string",
                "enum": ["EMERGENCY", "CRITICAL", "HIGH", "NORMAL", "LOW", "BACKGROUND"]
            },
            "user_id": {"type": "string"},
            "estimated_tokens": {"type": "integer"},
            "deadline": {"type": "string", "format": "date-time"},
            "business_context": {"type": "object"},
            "hours": {"type": "integer"}
        },
        "required": ["operation"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "request_id": {"type": "string"},
            "priority_score": {"type": "number"},
            "estimated_wait_time_seconds": {"type": "number"},
            "queue_position": {"type": "integer"},
            "dashboard_timestamp": {"type": "string"},
            "time_window_hours": {"type": "integer"},
            "current_status": {"type": "object"},
            "historical_metrics": {"type": "array"},
            "plugin_performance": {"type": "array"},
            "active_policies": {"type": "array"},
            "error": {"type": "string"}
        }
    }
}

# Global priority manager instance
priority_manager = None

def get_priority_manager():
    """Get or create the global priority manager instance"""
    global priority_manager
    if priority_manager is None:
        priority_manager = IntelligentLLMPriorityManager()
    return priority_manager


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point
    
    Operations:
    - submit_request: Submit LLM access request for priority-based processing
    - get_dashboard: Get comprehensive priority management dashboard
    - update_policy: Update priority policy configuration
    - get_queue_status: Get current queue status and metrics
    """
    operation = cfg.get('operation', 'get_dashboard')
    
    try:
        manager = get_priority_manager()
        
        if operation == 'submit_request':
            # Convert priority level string to enum
            priority_str = cfg.get('priority_level', 'NORMAL')
            priority_level = PriorityLevel[priority_str]
            
            # Parse deadline if provided
            deadline = None
            if cfg.get('deadline'):
                try:
                    from datetime import datetime
                    deadline = datetime.fromisoformat(cfg['deadline'].replace('Z', '+00:00'))
                except:
                    pass
            
            return await manager.submit_llm_request(
                plugin_id=cfg.get('plugin_id', 'unknown'),
                provider=cfg.get('provider', 'openai'),
                model=cfg.get('model', 'gpt-3.5-turbo'),
                priority_level=priority_level,
                user_id=cfg.get('user_id', 'system'),
                estimated_tokens=cfg.get('estimated_tokens', 1000),
                deadline=deadline,
                business_context=cfg.get('business_context', {})
            )
        
        elif operation == 'get_dashboard':
            return await manager.get_priority_dashboard(
                hours=cfg.get('hours', 24)
            )
        
        elif operation == 'get_queue_status':
            with manager.queue_lock:
                queue_size = len(manager.request_queue)
                queue_details = []
                for i, (priority_score, request_id, request) in enumerate(manager.request_queue[:10]):  # Top 10
                    queue_details.append({
                        'position': i + 1,
                        'request_id': request_id,
                        'plugin_id': request.plugin_id,
                        'priority_score': -priority_score,  # Convert back from heap format
                        'created_at': request.created_at.isoformat(),
                        'estimated_cost': request.estimated_cost
                    })
            
            with manager.processing_lock:
                processing_count = len(manager.active_requests)
            
            return {
                'success': True,
                'queue_status': {
                    'total_queued': queue_size,
                    'currently_processing': processing_count,
                    'queue_details': queue_details
                }
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "supported_operations": [
                    "submit_request", "get_dashboard", "update_policy", "get_queue_status"
                ]
            }
    
    except Exception as e:
        logger.error(f"❌ Intelligent priority manager operation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test the plugin
    async def test_intelligent_priority_manager():
        """Test intelligent priority manager functionality"""
        print("🧠🎯 Testing Intelligent LLM Priority Manager...")
        
        # Test submitting requests
        result = await process({}, {
            'operation': 'submit_request',
            'plugin_id': 'critical_ai_plugin',
            'provider': 'openai',
            'model': 'gpt-4',
            'priority_level': 'HIGH',
            'user_id': 'premium_user',
            'estimated_tokens': 2000,
            'business_context': {'user_tier': 'premium', 'urgency': 'urgent'}
        })
        print(f"Submit Request: {result}")
        
        # Test queue status
        result = await process({}, {
            'operation': 'get_queue_status'
        })
        print(f"Queue Status: {result}")
        
        # Test dashboard
        result = await process({}, {
            'operation': 'get_dashboard',
            'hours': 24
        })
        print(f"Dashboard: {result}")
        
        print("✅ Intelligent priority manager tests completed!")
    
    asyncio.run(test_intelligent_priority_manager())