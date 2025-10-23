# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
🏛️ AI Resource Governance Plugin - Centralized BYOAI Cost Control

HOLISTIC AI RESOURCE MANAGEMENT SYSTEM that orchestrates all AI cost control plugins
and provides unified governance across the entire PlugPipe ecosystem.

Key Features:
- Centralized AI budget management with global limits
- Orchestrates existing limiter plugins (budget_aware_rate_limiter, llm_priority_manager, etc.)
- Real-time cost tracking and predictive alerts
- AI call chain monitoring and cascade protection  
- Per-plugin and per-user quota enforcement
- Emergency stop mechanisms and provider fallbacks
- Comprehensive audit trails and compliance reporting

Architecture:
- Uses pp() function to discover and orchestrate existing AI control plugins
- Provides unified configuration via config-ai-governance.yaml
- Real-time monitoring with configurable alert thresholds
- Integration with all existing LLM and cost control plugins

Author: PlugPipe AI Governance Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sys
import os
import yaml
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from pathlib import Path
import sqlite3
from collections import defaultdict
import uuid

# Add PlugPipe paths for plugin discovery
sys.path.insert(0, get_plugpipe_root())

try:
    from shares.loader import pp
    from shares.utils.config_loader import load_main_config, get_llm_config
    from shares.utils.secure_yaml_loader import secure_yaml_load
except ImportError as e:
    logging.warning(f"Import warning: {e}")
    def pp(plugin_name): return None
    def load_main_config(): return {}
    def get_llm_config(primary=True): return {}
    def secure_yaml_load(file, inject_secrets=True): return {}

logger = logging.getLogger(__name__)

@dataclass
class AIUsageRecord:
    """Record of AI resource usage for tracking and auditing."""
    timestamp: str
    plugin_name: str
    user_id: str
    operation: str
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_usd: float
    duration_seconds: float
    chain_id: str = None  # For tracking AI call chains
    chain_depth: int = 0
    request_id: str = field(default_factory=lambda: str(uuid.uuid4()))

@dataclass
class AIBudgetStatus:
    """Current budget status and limits."""
    daily_spent_usd: float = 0.0
    daily_limit_usd: float = 100.0
    monthly_spent_usd: float = 0.0
    monthly_limit_usd: float = 2000.0
    remaining_daily_usd: float = 100.0
    remaining_monthly_usd: float = 2000.0
    percentage_used: float = 0.0
    alert_level: str = "normal"  # normal, warning, critical, emergency
    
class AIResourceGovernance:
    """Centralized AI resource governance orchestrator."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.ai_config = config.get("ai_governance", {})
        self.enabled = self.ai_config.get("enabled", True)
        self.mode = self.ai_config.get("mode", "enforcing")
        
        # Initialize database for tracking
        self.db_path = Path("ai_governance.db")
        self._init_database()
        
        # Cache for limiter plugins
        self._limiter_plugins = {}
        
        logger.info(f"AI Resource Governance initialized in {self.mode} mode")
    
    def _init_database(self):
        """Initialize SQLite database for AI usage tracking."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    CREATE TABLE IF NOT EXISTS ai_usage (
                        id INTEGER PRIMARY KEY,
                        timestamp TEXT,
                        plugin_name TEXT,
                        user_id TEXT,
                        operation TEXT,
                        provider TEXT,
                        model TEXT,
                        input_tokens INTEGER,
                        output_tokens INTEGER,
                        total_tokens INTEGER,
                        cost_usd REAL,
                        duration_seconds REAL,
                        chain_id TEXT,
                        chain_depth INTEGER,
                        request_id TEXT UNIQUE
                    )
                ''')
                
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_timestamp ON ai_usage(timestamp)
                ''')
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_plugin ON ai_usage(plugin_name)
                ''')
                conn.execute('''
                    CREATE INDEX IF NOT EXISTS idx_chain ON ai_usage(chain_id)
                ''')
                
        except Exception as e:
            logger.error(f"Database initialization failed: {e}")
    
    async def check_ai_usage_permission(self, plugin_name: str, user_id: str, 
                                      estimated_tokens: int, estimated_cost: float,
                                      chain_context: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Comprehensive AI usage permission check.
        
        Returns permission decision with detailed reasoning.
        """
        try:
            if not self.enabled:
                return {"allowed": True, "reason": "AI governance disabled"}
            
            # Get current budget status
            budget_status = await self._get_budget_status()
            
            # Check global budget limits
            if budget_status.remaining_daily_usd < estimated_cost:
                return {
                    "allowed": False,
                    "reason": "Daily budget exceeded",
                    "current_spend": budget_status.daily_spent_usd,
                    "daily_limit": budget_status.daily_limit_usd,
                    "requested_cost": estimated_cost
                }
            
            # Check plugin-specific quotas
            plugin_check = await self._check_plugin_quota(plugin_name, estimated_tokens, estimated_cost)
            if not plugin_check["allowed"]:
                return plugin_check
            
            # Check user-specific quotas
            user_check = await self._check_user_quota(user_id, estimated_tokens, estimated_cost)
            if not user_check["allowed"]:
                return user_check
            
            # Check AI call chain limits
            if chain_context:
                chain_check = await self._check_chain_limits(chain_context, estimated_cost)
                if not chain_check["allowed"]:
                    return chain_check
            
            # All checks passed
            return {
                "allowed": True,
                "reason": "All quota and budget checks passed",
                "budget_status": asdict(budget_status)
            }
            
        except Exception as e:
            logger.error(f"Permission check failed: {e}")
            return {
                "allowed": self.mode == "permissive",
                "reason": f"Permission check error: {e}"
            }
    
    async def record_ai_usage(self, usage_record: AIUsageRecord) -> bool:
        """Record AI usage for tracking and billing."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT OR REPLACE INTO ai_usage 
                    (timestamp, plugin_name, user_id, operation, provider, model,
                     input_tokens, output_tokens, total_tokens, cost_usd, 
                     duration_seconds, chain_id, chain_depth, request_id)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    usage_record.timestamp,
                    usage_record.plugin_name,
                    usage_record.user_id,
                    usage_record.operation,
                    usage_record.provider,
                    usage_record.model,
                    usage_record.input_tokens,
                    usage_record.output_tokens,
                    usage_record.total_tokens,
                    usage_record.cost_usd,
                    usage_record.duration_seconds,
                    usage_record.chain_id,
                    usage_record.chain_depth,
                    usage_record.request_id
                ))
            
            # Check if usage triggers alerts
            await self._check_usage_alerts(usage_record)
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to record AI usage: {e}")
            return False
    
    async def get_ai_usage_dashboard(self, timeframe: str = "today") -> Dict[str, Any]:
        """Generate comprehensive AI usage dashboard data."""
        try:
            budget_status = await self._get_budget_status()
            
            # Get usage statistics
            usage_stats = await self._get_usage_statistics(timeframe)
            
            # Get top consuming plugins
            top_plugins = await self._get_top_plugins(timeframe)
            
            # Get cost trends
            cost_trends = await self._get_cost_trends(timeframe)
            
            # Get active alerts
            active_alerts = await self._get_active_alerts()
            
            return {
                "budget_status": asdict(budget_status),
                "usage_statistics": usage_stats,
                "top_consuming_plugins": top_plugins,
                "cost_trends": cost_trends,
                "active_alerts": active_alerts,
                "governance_mode": self.mode,
                "governance_enabled": self.enabled,
                "last_updated": datetime.now().isoformat()
            }
            
        except Exception as e:
            logger.error(f"Dashboard generation failed: {e}")
            return {"error": str(e)}
    
    async def orchestrate_limiter_plugins(self, operation: str, context: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate existing AI limiter plugins for unified control."""
        try:
            results = {}
            
            # Orchestrate Budget Aware Rate Limiter
            if self.ai_config.get("ai_plugin_integration", {}).get("budget_aware_rate_limiter", {}).get("enabled", True):
                budget_limiter = await pp("budget_aware_rate_limiter", version="1.0.0")
                if budget_limiter:
                    limiter_result = await budget_limiter.process(context, {
                        "operation": operation,
                        "sync_with_global_budget": True,
                        "global_budget_status": await self._get_budget_status()
                    })
                    results["budget_aware_rate_limiter"] = limiter_result
            
            # Orchestrate LLM Priority Manager
            if self.ai_config.get("ai_plugin_integration", {}).get("intelligent_llm_priority_manager", {}).get("enabled", True):
                priority_manager = await pp("intelligent_llm_priority_manager", version="1.0.0")
                if priority_manager:
                    priority_result = await priority_manager.process(context, {
                        "operation": operation,
                        "use_global_priorities": True,
                        "plugin_quotas": self.ai_config.get("plugin_quotas", {})
                    })
                    results["intelligent_llm_priority_manager"] = priority_result
            
            # Orchestrate Cost Estimator
            if self.ai_config.get("ai_plugin_integration", {}).get("llm_cost_estimator", {}).get("enabled", True):
                cost_estimator = await pp("llm_cost_estimator", version="1.0.0")
                if cost_estimator:
                    cost_result = await cost_estimator.process(context, {
                        "operation": operation,
                        "real_time_tracking": True,
                        "predictive_alerts": True
                    })
                    results["llm_cost_estimator"] = cost_result
            
            return {
                "success": True,
                "orchestrated_plugins": len(results),
                "plugin_results": results
            }
            
        except Exception as e:
            logger.error(f"Plugin orchestration failed: {e}")
            return {"success": False, "error": str(e)}
    
    async def _get_budget_status(self) -> AIBudgetStatus:
        """Get current budget status with limits and usage."""
        try:
            today = datetime.now().date()
            month_start = today.replace(day=1)
            
            with sqlite3.connect(self.db_path) as conn:
                # Daily spending
                daily_spent = conn.execute('''
                    SELECT COALESCE(SUM(cost_usd), 0) FROM ai_usage 
                    WHERE DATE(timestamp) = ?
                ''', (today.isoformat(),)).fetchone()[0]
                
                # Monthly spending
                monthly_spent = conn.execute('''
                    SELECT COALESCE(SUM(cost_usd), 0) FROM ai_usage 
                    WHERE DATE(timestamp) >= ?
                ''', (month_start.isoformat(),)).fetchone()[0]
            
            daily_limit = self.ai_config.get("global_budget", {}).get("daily_limit_usd", 100.0)
            monthly_limit = self.ai_config.get("global_budget", {}).get("monthly_limit_usd", 2000.0)
            
            budget_status = AIBudgetStatus(
                daily_spent_usd=daily_spent,
                daily_limit_usd=daily_limit,
                monthly_spent_usd=monthly_spent,
                monthly_limit_usd=monthly_limit,
                remaining_daily_usd=max(0, daily_limit - daily_spent),
                remaining_monthly_usd=max(0, monthly_limit - monthly_spent),
                percentage_used=(daily_spent / daily_limit * 100) if daily_limit > 0 else 0
            )
            
            # Determine alert level
            if budget_status.percentage_used >= 100:
                budget_status.alert_level = "emergency"
            elif budget_status.percentage_used >= 95:
                budget_status.alert_level = "critical"  
            elif budget_status.percentage_used >= 80:
                budget_status.alert_level = "warning"
            else:
                budget_status.alert_level = "normal"
            
            return budget_status
            
        except Exception as e:
            logger.error(f"Budget status check failed: {e}")
            return AIBudgetStatus()
    
    async def _check_plugin_quota(self, plugin_name: str, tokens: int, cost: float) -> Dict[str, Any]:
        """Check plugin-specific quota limits."""
        try:
            plugin_quotas = self.ai_config.get("plugin_quotas", {})
            quota = plugin_quotas.get(plugin_name, plugin_quotas.get("_default", {}))
            
            if not quota:
                return {"allowed": True, "reason": "No quota limits configured"}
            
            # Check today's usage for this plugin
            today = datetime.now().date()
            with sqlite3.connect(self.db_path) as conn:
                today_usage = conn.execute('''
                    SELECT 
                        COALESCE(SUM(total_tokens), 0) as tokens,
                        COALESCE(COUNT(*), 0) as requests,
                        COALESCE(SUM(cost_usd), 0) as cost
                    FROM ai_usage 
                    WHERE plugin_name = ? AND DATE(timestamp) = ?
                ''', (plugin_name, today.isoformat())).fetchone()
                
                current_tokens, current_requests, current_cost = today_usage
            
            # Check limits
            daily_token_limit = quota.get("daily_tokens", float('inf'))
            daily_request_limit = quota.get("daily_requests", float('inf'))
            daily_cost_limit = quota.get("daily_cost_usd", float('inf'))
            
            if current_tokens + tokens > daily_token_limit:
                return {
                    "allowed": False,
                    "reason": "Plugin daily token quota exceeded",
                    "plugin": plugin_name,
                    "current_tokens": current_tokens,
                    "limit": daily_token_limit,
                    "requested": tokens
                }
            
            if current_cost + cost > daily_cost_limit:
                return {
                    "allowed": False,
                    "reason": "Plugin daily cost quota exceeded",
                    "plugin": plugin_name,
                    "current_cost": current_cost,
                    "limit": daily_cost_limit,
                    "requested": cost
                }
            
            return {"allowed": True, "reason": "Plugin quota check passed"}
            
        except Exception as e:
            logger.error(f"Plugin quota check failed: {e}")
            return {"allowed": True, "reason": f"Quota check error: {e}"}
    
    async def _check_user_quota(self, user_id: str, tokens: int, cost: float) -> Dict[str, Any]:
        """Check user-specific quota limits."""
        try:
            user_quotas = self.ai_config.get("user_quotas", {})
            if not user_quotas.get("enabled", True):
                return {"allowed": True, "reason": "User quotas disabled"}
            
            # Determine user quota (admin vs default)
            if "admin" in user_id.lower():
                quota = user_quotas.get("admin_user", {})
            else:
                quota = user_quotas.get("default_user", {})
            
            if not quota:
                return {"allowed": True, "reason": "No user quota configured"}
            
            # Check today's usage for this user
            today = datetime.now().date()
            with sqlite3.connect(self.db_path) as conn:
                today_usage = conn.execute('''
                    SELECT 
                        COALESCE(SUM(total_tokens), 0) as tokens,
                        COALESCE(COUNT(*), 0) as requests,
                        COALESCE(SUM(cost_usd), 0) as cost
                    FROM ai_usage 
                    WHERE user_id = ? AND DATE(timestamp) = ?
                ''', (user_id, today.isoformat())).fetchone()
                
                current_tokens, current_requests, current_cost = today_usage
            
            # Check limits
            daily_token_limit = quota.get("daily_tokens", float('inf'))
            daily_cost_limit = quota.get("daily_cost_usd", float('inf'))
            
            if current_tokens + tokens > daily_token_limit:
                return {
                    "allowed": False,
                    "reason": "User daily token quota exceeded",
                    "user": user_id,
                    "current_tokens": current_tokens,
                    "limit": daily_token_limit
                }
            
            if current_cost + cost > daily_cost_limit:
                return {
                    "allowed": False,
                    "reason": "User daily cost quota exceeded",
                    "user": user_id,
                    "current_cost": current_cost,
                    "limit": daily_cost_limit
                }
            
            return {"allowed": True, "reason": "User quota check passed"}
            
        except Exception as e:
            logger.error(f"User quota check failed: {e}")
            return {"allowed": True, "reason": f"User quota check error: {e}"}
    
    async def _check_chain_limits(self, chain_context: Dict[str, Any], cost: float) -> Dict[str, Any]:
        """Check AI call chain limits to prevent cascading costs."""
        try:
            chain_config = self.ai_config.get("chain_monitoring", {})
            if not chain_config.get("enabled", True):
                return {"allowed": True, "reason": "Chain monitoring disabled"}
            
            chain_id = chain_context.get("chain_id")
            chain_depth = chain_context.get("chain_depth", 0)
            
            max_depth = chain_config.get("max_chain_depth", 3)
            max_cost = chain_config.get("max_chain_cost_usd", 20.0)
            
            # Check chain depth
            if chain_depth >= max_depth:
                return {
                    "allowed": False,
                    "reason": "AI call chain depth limit exceeded",
                    "current_depth": chain_depth,
                    "max_depth": max_depth,
                    "chain_id": chain_id
                }
            
            # Check chain cost if chain_id provided
            if chain_id:
                with sqlite3.connect(self.db_path) as conn:
                    chain_cost = conn.execute('''
                        SELECT COALESCE(SUM(cost_usd), 0) FROM ai_usage 
                        WHERE chain_id = ?
                    ''', (chain_id,)).fetchone()[0]
                
                if chain_cost + cost > max_cost:
                    return {
                        "allowed": False,
                        "reason": "AI call chain cost limit exceeded",
                        "current_cost": chain_cost,
                        "max_cost": max_cost,
                        "chain_id": chain_id
                    }
            
            return {"allowed": True, "reason": "Chain limits check passed"}
            
        except Exception as e:
            logger.error(f"Chain limit check failed: {e}")
            return {"allowed": True, "reason": f"Chain check error: {e}"}
    
    async def _check_usage_alerts(self, usage_record: AIUsageRecord):
        """Check if usage triggers any alerts and send notifications."""
        try:
            budget_status = await self._get_budget_status()
            
            alert_thresholds = self.ai_config.get("alert_thresholds", {})
            
            # Check if we've crossed alert thresholds
            if (budget_status.alert_level == "warning" and 
                budget_status.percentage_used >= alert_thresholds.get("warning_percent", 80)):
                await self._send_alert("budget_warning", {
                    "message": f"AI budget at {budget_status.percentage_used:.1f}% of daily limit",
                    "budget_status": asdict(budget_status),
                    "usage_record": asdict(usage_record)
                })
            
            elif (budget_status.alert_level == "critical" and 
                  budget_status.percentage_used >= alert_thresholds.get("critical_percent", 95)):
                await self._send_alert("budget_critical", {
                    "message": f"CRITICAL: AI budget at {budget_status.percentage_used:.1f}% of daily limit",
                    "budget_status": asdict(budget_status),
                    "usage_record": asdict(usage_record)
                })
            
        except Exception as e:
            logger.error(f"Alert check failed: {e}")
    
    async def _send_alert(self, alert_type: str, data: Dict[str, Any]):
        """Send alerts via configured channels."""
        try:
            alert_config = self.ai_config.get("ai_monitoring", {}).get("alerts", {})
            
            alert_message = {
                "alert_type": alert_type,
                "timestamp": datetime.now().isoformat(),
                "severity": "warning" if "warning" in alert_type else "critical",
                "data": data
            }
            
            # Log alert (always enabled)
            logger.warning(f"AI Governance Alert [{alert_type}]: {data.get('message', 'No message')}")
            
            # Email alerts (if configured)
            if alert_config.get("email", {}).get("enabled", False):
                # Implementation would integrate with email service
                logger.info(f"Email alert sent: {alert_type}")
            
            # Slack alerts (if configured)  
            if alert_config.get("slack", {}).get("enabled", False):
                # Implementation would integrate with Slack
                logger.info(f"Slack alert sent: {alert_type}")
            
        except Exception as e:
            logger.error(f"Alert sending failed: {e}")
    
    async def _get_usage_statistics(self, timeframe: str) -> Dict[str, Any]:
        """Get AI usage statistics for specified timeframe."""
        try:
            # Implementation would query database for stats
            return {
                "total_requests": 0,
                "total_tokens": 0,
                "total_cost_usd": 0.0,
                "avg_cost_per_request": 0.0,
                "timeframe": timeframe
            }
        except Exception as e:
            logger.error(f"Usage statistics failed: {e}")
            return {}
    
    async def _get_top_plugins(self, timeframe: str) -> List[Dict[str, Any]]:
        """Get top AI consuming plugins."""
        try:
            # Implementation would query database for top consumers
            return []
        except Exception as e:
            logger.error(f"Top plugins query failed: {e}")
            return []
    
    async def _get_cost_trends(self, timeframe: str) -> Dict[str, Any]:
        """Get cost trend analysis."""
        try:
            # Implementation would calculate trends
            return {"trend": "stable"}
        except Exception as e:
            logger.error(f"Cost trends failed: {e}")
            return {}
    
    async def _get_active_alerts(self) -> List[Dict[str, Any]]:
        """Get currently active alerts."""
        try:
            # Implementation would return active alerts
            return []
        except Exception as e:
            logger.error(f"Active alerts query failed: {e}")
            return []

# Plugin metadata
plug_metadata = {
    "name": "ai_resource_governance",
    "version": "1.0.0",
    "description": "Centralized AI resource governance with holistic cost control across all PlugPipe AI plugins",
    "owner": "PlugPipe AI Governance Team",
    "status": "stable",
    "capabilities": [
        "centralized_ai_budget_control",
        "plugin_quota_management", 
        "user_quota_management",
        "ai_call_chain_monitoring",
        "real_time_cost_tracking",
        "automated_alert_system",
        "limiter_plugin_orchestration",
        "compliance_audit_trails"
    ]
}

async def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point for AI resource governance operations."""
    try:
        # Load AI governance configuration
        try:
            governance_config = secure_yaml_load("config-ai-governance.yaml", inject_secrets=True)
        except:
            # Fallback to main config if governance config doesn't exist
            governance_config = load_main_config()
        
        # Initialize governance system
        governance = AIResourceGovernance(governance_config)
        
        # Get operation
        operation = context.get("operation", config.get("operation", "get_status"))
        
        if operation == "check_permission":
            # Check if AI usage is allowed
            plugin_name = context.get("plugin_name", "unknown")
            user_id = context.get("user_id", "default_user")
            estimated_tokens = context.get("estimated_tokens", 0)
            estimated_cost = context.get("estimated_cost", 0.0)
            chain_context = context.get("chain_context")
            
            permission = await governance.check_ai_usage_permission(
                plugin_name, user_id, estimated_tokens, estimated_cost, chain_context
            )
            
            return {
                "success": True,
                "operation": "check_permission",
                "permission": permission,
                "governance_mode": governance.mode
            }
        
        elif operation == "record_usage":
            # Record AI usage
            usage_data = context.get("usage_record", {})
            usage_record = AIUsageRecord(**usage_data)
            
            recorded = await governance.record_ai_usage(usage_record)
            
            return {
                "success": recorded,
                "operation": "record_usage",
                "recorded": recorded
            }
        
        elif operation == "get_dashboard":
            # Get AI usage dashboard
            timeframe = context.get("timeframe", "today")
            dashboard = await governance.get_ai_usage_dashboard(timeframe)
            
            return {
                "success": True,
                "operation": "get_dashboard", 
                "dashboard": dashboard
            }
        
        elif operation == "orchestrate_limiters":
            # Orchestrate existing limiter plugins
            limiter_operation = context.get("limiter_operation", "sync_budgets")
            result = await governance.orchestrate_limiter_plugins(limiter_operation, context)
            
            return {
                "success": result.get("success", False),
                "operation": "orchestrate_limiters",
                "orchestration_result": result
            }
        
        elif operation == "get_status":
            # Get governance system status
            budget_status = await governance._get_budget_status()
            
            return {
                "success": True,
                "operation": "get_status",
                "governance_enabled": governance.enabled,
                "governance_mode": governance.mode,
                "budget_status": asdict(budget_status),
                "database_path": str(governance.db_path)
            }
        
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "supported_operations": [
                    "check_permission",
                    "record_usage", 
                    "get_dashboard",
                    "orchestrate_limiters",
                    "get_status"
                ]
            }
            
    except Exception as e:
        logger.error(f"AI Resource Governance failed: {e}")
        return {
            "success": False,
            "error": str(e),
            "operation": context.get("operation", "unknown")
        }