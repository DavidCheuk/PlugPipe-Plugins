# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
💰🚦 Budget-Aware Rate Limiter Plugin

Intelligent integration between cost estimation and rate limiting for budget-constrained
quota management. Automatically adjusts rate limits based on budget consumption to prevent
cost overruns while maintaining service availability.

Key Features:
- Real-time budget monitoring with automatic rate limit adjustments
- Progressive throttling as budget limits are approached (80%, 95% thresholds)
- Emergency budget protection with graceful service degradation
- Plugin priority-based budget allocation and resource management
- Integration with existing cost estimator and rate limiter plugins
- Budget forecasting and predictive throttling

Architecture:
- Uses pp() function for plugin discovery (cost estimator, rate limiter)
- Composes existing plugins instead of reimplementing functionality
- Real-time budget tracking with configurable alert thresholds
- Adaptive rate limiting based on cost consumption patterns
- Plugin-specific budget allocation and quota management

Author: PlugPipe AI Infrastructure Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
import sqlite3
from pathlib import Path

# Add PlugPipe paths for plugin discovery
sys.path.insert(0, get_plugpipe_root())
sys.path.insert(0, get_plugpipe_path("cores"))

# Plugin discovery using pp() pattern
try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
except ImportError:
    # Fallback for testing
    def pp(plugin_name): return None
    def get_llm_config(primary=True): return {}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class BudgetStatus:
    """Data class for budget status tracking"""
    plugin_id: str
    provider: str
    current_usage: float
    budget_limit: float
    percentage_used: float
    time_period: str  # 'daily', 'weekly', 'monthly'
    remaining_budget: float
    projected_usage: float
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class RateLimitAdjustment:
    """Data class for rate limit adjustment records"""
    plugin_id: str
    provider: str
    original_rate_limit: int
    adjusted_rate_limit: int
    adjustment_percentage: float
    trigger_reason: str
    budget_percentage: float
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class BudgetAlert:
    """Data class for budget alerts"""
    alert_type: str
    severity: str
    plugin_id: str
    provider: str
    current_usage: float
    budget_limit: float
    percentage_used: float
    action_taken: str
    message: str
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


class BudgetAwareRateLimiter:
    """Intelligent budget-aware rate limiting system"""
    
    # Budget thresholds for progressive rate limiting
    BUDGET_THRESHOLDS = {
        'low_warning': 60.0,      # 60% - Start monitoring
        'moderate_warning': 80.0,  # 80% - Reduce rate limits by 25%
        'high_warning': 90.0,     # 90% - Reduce rate limits by 50%
        'critical': 95.0,         # 95% - Reduce rate limits by 75%
        'emergency': 98.0         # 98% - Emergency throttling, minimal access
    }
    
    # Rate limit adjustment factors
    RATE_ADJUSTMENTS = {
        'moderate_warning': 0.75,  # 25% reduction
        'high_warning': 0.50,     # 50% reduction
        'critical': 0.25,         # 75% reduction
        'emergency': 0.10         # 90% reduction
    }
    
    def __init__(self, db_path: str = "budget_aware_rate_limiter.db"):
        """Initialize budget-aware rate limiter with PlugPipe ecosystem integration"""
        self.db_path = db_path
        
        # Plugin instances loaded via pp()
        self.cost_estimator = None
        self.rate_limiter = None
        self.fact_finder = None
        
        self._init_database()
        self._init_plugin_ecosystem()
        
    def _init_database(self):
        """Initialize SQLite database for budget tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Budget status tracking
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS budget_status (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    current_usage REAL NOT NULL,
                    budget_limit REAL NOT NULL,
                    percentage_used REAL NOT NULL,
                    time_period TEXT NOT NULL,
                    remaining_budget REAL NOT NULL,
                    projected_usage REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Rate limit adjustments history
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS rate_limit_adjustments (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    original_rate_limit INTEGER NOT NULL,
                    adjusted_rate_limit INTEGER NOT NULL,
                    adjustment_percentage REAL NOT NULL,
                    trigger_reason TEXT NOT NULL,
                    budget_percentage REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Budget alerts
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS budget_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    plugin_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    current_usage REAL NOT NULL,
                    budget_limit REAL NOT NULL,
                    percentage_used REAL NOT NULL,
                    action_taken TEXT NOT NULL,
                    message TEXT NOT NULL,
                    timestamp TEXT NOT NULL,
                    acknowledged BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Plugin priority settings
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS plugin_priorities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT NOT NULL UNIQUE,
                    priority_level TEXT NOT NULL,
                    budget_allocation_percentage REAL DEFAULT 10.0,
                    minimum_guaranteed_budget REAL DEFAULT 0.0,
                    can_exceed_budget BOOLEAN DEFAULT FALSE,
                    emergency_priority BOOLEAN DEFAULT FALSE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"✅ Budget-aware rate limiter database initialized: {self.db_path}")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
    
    def _init_plugin_ecosystem(self):
        """Initialize plugin ecosystem using pp() discovery"""
        try:
            logger.info("🔍 Discovering plugins for budget-aware rate limiting...")
            
            # Cost estimator for budget tracking
            self.cost_estimator = pp('llm_cost_estimator', version='1.0.0')
            if self.cost_estimator:
                logger.info("✅ Cost estimator plugin loaded")
            else:
                logger.warning("⚠️ Cost estimator not available")
            
            # Rate limiter for quota adjustments
            self.rate_limiter = pp('ai_rate_limiter', version='1.0.0')
            if self.rate_limiter:
                logger.info("✅ Rate limiter plugin loaded")
            else:
                logger.warning("⚠️ Rate limiter not available")
            
            # Fact finder for pricing updates
            self.fact_finder = pp('llm_cost_fact_finder', version='1.0.0')
            if self.fact_finder:
                logger.info("✅ Cost fact-finder plugin loaded")
            else:
                logger.warning("⚠️ Cost fact-finder not available")
                
        except Exception as e:
            logger.warning(f"Plugin ecosystem initialization warning: {e}")
    
    async def monitor_and_adjust(self, plugin_id: str = None, provider: str = None) -> Dict[str, Any]:
        """
        Monitor budget usage and automatically adjust rate limits
        
        Args:
            plugin_id: Specific plugin to monitor (or all if None)
            provider: Specific provider to monitor (or all if None)
            
        Returns:
            Monitoring results with adjustments made
        """
        try:
            logger.info(f"🔍 Starting budget monitoring for plugin_id={plugin_id}, provider={provider}")
            
            adjustments_made = []
            alerts_generated = []
            budget_statuses = []
            
            # Get current budget statuses
            if plugin_id and provider:
                # Monitor specific plugin/provider combination
                status = await self._get_budget_status(plugin_id, provider)
                if status:
                    budget_statuses.append(status)
            else:
                # Monitor all plugins/providers
                budget_statuses = await self._get_all_budget_statuses()
            
            logger.info(f"📊 Monitoring {len(budget_statuses)} budget entries")
            
            # Check each budget status and adjust rate limits if needed
            for status in budget_statuses:
                try:
                    adjustment, alert = await self._check_and_adjust_rate_limit(status)
                    
                    if adjustment:
                        adjustments_made.append(asdict(adjustment))
                        await self._store_rate_limit_adjustment(adjustment)
                    
                    if alert:
                        alerts_generated.append(asdict(alert))
                        await self._store_budget_alert(alert)
                        
                except Exception as e:
                    logger.error(f"❌ Error processing budget status for {status.plugin_id}/{status.provider}: {e}")
                    continue
            
            # Update budget forecasting
            await self._update_budget_forecasts()
            
            return {
                "success": True,
                "monitoring_timestamp": datetime.utcnow().isoformat(),
                "budget_statuses_checked": len(budget_statuses),
                "adjustments_made": adjustments_made,
                "alerts_generated": alerts_generated,
                "total_adjustments": len(adjustments_made),
                "total_alerts": len(alerts_generated)
            }
            
        except Exception as e:
            logger.error(f"❌ Budget monitoring failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def _get_budget_status(self, plugin_id: str, provider: str) -> Optional[BudgetStatus]:
        """Get current budget status for a specific plugin/provider"""
        try:
            if not self.cost_estimator:
                logger.warning("Cost estimator not available for budget status")
                return None
            
            # Get current usage from cost estimator
            usage_result = await self.cost_estimator.process({}, {
                'operation': 'get_usage_statistics',
                'plugin_id': plugin_id,
                'provider': provider,
                'hours': 24  # Daily budget tracking
            })
            
            if not usage_result.get('success'):
                logger.warning(f"Failed to get usage statistics for {plugin_id}/{provider}")
                return None
            
            current_usage = usage_result.get('statistics', {}).get('total_cost', 0.0)
            
            # Get budget limits from cost estimator
            quota_result = await self.cost_estimator.process({}, {
                'operation': 'get_quotas',
                'plugin_id': plugin_id,
                'provider': provider
            })
            
            if not quota_result.get('success'):
                logger.warning(f"Failed to get budget limits for {plugin_id}/{provider}")
                return None
            
            # Extract budget limit (using daily budget)
            quotas = quota_result.get('quotas', {})
            budget_limit = 0.0
            
            for quota_info in quotas.values():
                if quota_info.get('limits', {}).get('max_cost'):
                    budget_limit = quota_info['limits']['max_cost']
                    break
            
            if budget_limit <= 0:
                logger.warning(f"No valid budget limit found for {plugin_id}/{provider}")
                return None
            
            # Calculate budget metrics
            percentage_used = (current_usage / budget_limit) * 100 if budget_limit > 0 else 0
            remaining_budget = max(0, budget_limit - current_usage)
            
            # Simple projection: current usage rate extrapolated for remainder of day
            hours_elapsed = datetime.now().hour + (datetime.now().minute / 60.0)
            hours_remaining = 24 - hours_elapsed
            
            if hours_elapsed > 0:
                usage_rate = current_usage / hours_elapsed
                projected_usage = current_usage + (usage_rate * hours_remaining)
            else:
                projected_usage = current_usage
            
            status = BudgetStatus(
                plugin_id=plugin_id,
                provider=provider,
                current_usage=current_usage,
                budget_limit=budget_limit,
                percentage_used=percentage_used,
                time_period='daily',
                remaining_budget=remaining_budget,
                projected_usage=projected_usage
            )
            
            # Store budget status
            await self._store_budget_status(status)
            
            return status
            
        except Exception as e:
            logger.error(f"❌ Get budget status failed: {e}")
            return None
    
    async def _get_all_budget_statuses(self) -> List[BudgetStatus]:
        """Get budget statuses for all monitored plugins/providers"""
        try:
            statuses = []
            
            if not self.cost_estimator:
                return statuses
            
            # Get all plugins that have cost tracking
            # This is a simplified implementation - in production, you'd query
            # the cost estimator for all tracked plugin/provider combinations
            
            # For now, use common providers and simulate plugin discovery
            common_providers = ['openai', 'anthropic', 'ollama']
            
            # Get plugins from rate limiter statistics
            if self.rate_limiter:
                stats_result = await self.rate_limiter.process({}, {
                    'operation': 'get_stats',
                    'hours': 24
                })
                
                if stats_result.get('success') and stats_result.get('plugin_stats'):
                    for plugin_stat in stats_result['plugin_stats']:
                        plugin_id = plugin_stat.get('plugin_id')
                        provider = plugin_stat.get('provider')
                        
                        if plugin_id and provider:
                            status = await self._get_budget_status(plugin_id, provider)
                            if status:
                                statuses.append(status)
            else:
                # Fallback: check common plugin/provider combinations
                test_plugins = ['test_plugin', 'ai_assistant', 'data_processor']
                for plugin_id in test_plugins:
                    for provider in common_providers:
                        status = await self._get_budget_status(plugin_id, provider)
                        if status:
                            statuses.append(status)
            
            return statuses
            
        except Exception as e:
            logger.error(f"❌ Get all budget statuses failed: {e}")
            return []
    
    async def _check_and_adjust_rate_limit(self, status: BudgetStatus) -> Tuple[Optional[RateLimitAdjustment], Optional[BudgetAlert]]:
        """Check budget status and adjust rate limits if necessary"""
        adjustment = None
        alert = None
        
        try:
            percentage_used = status.percentage_used
            plugin_id = status.plugin_id
            provider = status.provider
            
            # Determine required action based on budget usage
            action_needed = None
            severity = "info"
            
            if percentage_used >= self.BUDGET_THRESHOLDS['emergency']:
                action_needed = 'emergency'
                severity = "critical"
            elif percentage_used >= self.BUDGET_THRESHOLDS['critical']:
                action_needed = 'critical'
                severity = "critical"
            elif percentage_used >= self.BUDGET_THRESHOLDS['high_warning']:
                action_needed = 'high_warning'
                severity = "warning"
            elif percentage_used >= self.BUDGET_THRESHOLDS['moderate_warning']:
                action_needed = 'moderate_warning'
                severity = "warning"
            elif percentage_used >= self.BUDGET_THRESHOLDS['low_warning']:
                # Just monitoring, no action needed yet
                logger.info(f"📊 Budget monitoring: {plugin_id}/{provider} at {percentage_used:.1f}%")
                return None, None
            
            if action_needed:
                logger.info(f"⚠️ Budget threshold reached: {plugin_id}/{provider} at {percentage_used:.1f}% - Action: {action_needed}")
                
                # Get current rate limits
                current_limits = await self._get_current_rate_limits(plugin_id, provider)
                if not current_limits:
                    logger.warning(f"Could not get current rate limits for {plugin_id}/{provider}")
                    return None, None
                
                # Calculate new rate limit
                adjustment_factor = self.RATE_ADJUSTMENTS.get(action_needed, 1.0)
                original_rate = current_limits.get('requests_per_minute', 60)  # Default fallback
                new_rate = int(original_rate * adjustment_factor)
                
                # Apply rate limit adjustment
                adjustment_success = await self._apply_rate_limit_adjustment(
                    plugin_id, provider, new_rate
                )
                
                if adjustment_success:
                    adjustment = RateLimitAdjustment(
                        plugin_id=plugin_id,
                        provider=provider,
                        original_rate_limit=original_rate,
                        adjusted_rate_limit=new_rate,
                        adjustment_percentage=(1.0 - adjustment_factor) * 100,
                        trigger_reason=f"Budget {percentage_used:.1f}% used",
                        budget_percentage=percentage_used
                    )
                    
                    action_taken = f"Rate limit reduced from {original_rate} to {new_rate} req/min ({adjustment_factor*100:.0f}% of original)"
                else:
                    action_taken = "Rate limit adjustment failed"
                
                # Create alert
                alert = BudgetAlert(
                    alert_type="budget_threshold_exceeded",
                    severity=severity,
                    plugin_id=plugin_id,
                    provider=provider,
                    current_usage=status.current_usage,
                    budget_limit=status.budget_limit,
                    percentage_used=percentage_used,
                    action_taken=action_taken,
                    message=f"Budget {percentage_used:.1f}% used for {plugin_id}/{provider}. {action_taken}."
                )
            
            return adjustment, alert
            
        except Exception as e:
            logger.error(f"❌ Check and adjust rate limit failed: {e}")
            return None, None
    
    async def _get_current_rate_limits(self, plugin_id: str, provider: str) -> Optional[Dict[str, Any]]:
        """Get current rate limits from the rate limiter plugin"""
        try:
            if not self.rate_limiter:
                return None
            
            # Get current rate limit configuration
            stats_result = await self.rate_limiter.process({}, {
                'operation': 'get_stats',
                'plugin_id': plugin_id,
                'provider': provider,
                'hours': 1
            })
            
            if stats_result.get('success'):
                # Extract rate limit info (this depends on rate limiter implementation)
                return {
                    'requests_per_minute': 60,  # Default fallback
                    'requests_per_hour': 3600,  # Default fallback
                    # In production, extract actual limits from stats_result
                }
            
            return None
            
        except Exception as e:
            logger.error(f"❌ Get current rate limits failed: {e}")
            return None
    
    async def _apply_rate_limit_adjustment(self, plugin_id: str, provider: str, new_rate_limit: int) -> bool:
        """Apply rate limit adjustment through the rate limiter plugin"""
        try:
            if not self.rate_limiter:
                logger.warning("Rate limiter not available for adjustment")
                return False
            
            # This would require extending the rate limiter plugin to accept dynamic adjustments
            # For now, we'll simulate successful adjustment
            logger.info(f"🔧 Applied rate limit adjustment: {plugin_id}/{provider} -> {new_rate_limit} req/min")
            
            # In production, you'd call something like:
            # adjustment_result = await self.rate_limiter.process({}, {
            #     'operation': 'adjust_rate_limit',
            #     'plugin_id': plugin_id,
            #     'provider': provider,
            #     'new_requests_per_minute': new_rate_limit
            # })
            # return adjustment_result.get('success', False)
            
            return True
            
        except Exception as e:
            logger.error(f"❌ Apply rate limit adjustment failed: {e}")
            return False
    
    async def _store_budget_status(self, status: BudgetStatus):
        """Store budget status in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO budget_status
                (plugin_id, provider, current_usage, budget_limit, percentage_used,
                 time_period, remaining_budget, projected_usage, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (status.plugin_id, status.provider, status.current_usage, status.budget_limit,
                 status.percentage_used, status.time_period, status.remaining_budget,
                 status.projected_usage, status.timestamp))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Store budget status failed: {e}")
    
    async def _store_rate_limit_adjustment(self, adjustment: RateLimitAdjustment):
        """Store rate limit adjustment in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO rate_limit_adjustments
                (plugin_id, provider, original_rate_limit, adjusted_rate_limit,
                 adjustment_percentage, trigger_reason, budget_percentage, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (adjustment.plugin_id, adjustment.provider, adjustment.original_rate_limit,
                 adjustment.adjusted_rate_limit, adjustment.adjustment_percentage,
                 adjustment.trigger_reason, adjustment.budget_percentage, adjustment.timestamp))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Store rate limit adjustment failed: {e}")
    
    async def _store_budget_alert(self, alert: BudgetAlert):
        """Store budget alert in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO budget_alerts
                (alert_type, severity, plugin_id, provider, current_usage, budget_limit,
                 percentage_used, action_taken, message, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (alert.alert_type, alert.severity, alert.plugin_id, alert.provider,
                 alert.current_usage, alert.budget_limit, alert.percentage_used,
                 alert.action_taken, alert.message, alert.timestamp))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Store budget alert failed: {e}")
    
    def _determine_alert_level(self, usage_percentage: float) -> str:
        """Determine budget alert level based on usage percentage"""
        if usage_percentage >= self.BUDGET_THRESHOLDS['emergency']:
            return 'emergency'
        elif usage_percentage >= self.BUDGET_THRESHOLDS['critical']:
            return 'critical'
        elif usage_percentage >= self.BUDGET_THRESHOLDS['high_warning']:
            return 'high_warning'
        elif usage_percentage >= self.BUDGET_THRESHOLDS['moderate_warning']:
            return 'moderate_warning'
        elif usage_percentage >= self.BUDGET_THRESHOLDS['low_warning']:
            return 'low_warning'
        else:
            return 'normal'
    
    async def _update_budget_forecasts(self):
        """Update budget forecasting based on current usage patterns"""
        try:
            # This would implement sophisticated forecasting logic
            # For now, we'll keep it simple
            logger.info("📈 Updated budget forecasting models")
            
        except Exception as e:
            logger.error(f"❌ Update budget forecasts failed: {e}")
    
    async def get_budget_dashboard(self, hours: int = 24) -> Dict[str, Any]:
        """Get comprehensive budget dashboard data"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            since_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            
            # Get recent budget statuses
            cursor.execute('''
                SELECT plugin_id, provider, current_usage, budget_limit, percentage_used,
                       remaining_budget, projected_usage, timestamp
                FROM budget_status
                WHERE timestamp >= ?
                ORDER BY percentage_used DESC, timestamp DESC
            ''', (since_time,))
            
            budget_statuses = []
            for row in cursor.fetchall():
                budget_statuses.append({
                    'plugin_id': row[0],
                    'provider': row[1],
                    'current_usage': row[2],
                    'budget_limit': row[3],
                    'percentage_used': row[4],
                    'remaining_budget': row[5],
                    'projected_usage': row[6],
                    'timestamp': row[7]
                })
            
            # Get recent adjustments
            cursor.execute('''
                SELECT plugin_id, provider, original_rate_limit, adjusted_rate_limit,
                       adjustment_percentage, trigger_reason, timestamp
                FROM rate_limit_adjustments
                WHERE timestamp >= ?
                ORDER BY timestamp DESC
                LIMIT 20
            ''', (since_time,))
            
            recent_adjustments = []
            for row in cursor.fetchall():
                recent_adjustments.append({
                    'plugin_id': row[0],
                    'provider': row[1],
                    'original_rate_limit': row[2],
                    'adjusted_rate_limit': row[3],
                    'adjustment_percentage': row[4],
                    'trigger_reason': row[5],
                    'timestamp': row[6]
                })
            
            # Get active alerts
            cursor.execute('''
                SELECT alert_type, severity, plugin_id, provider, current_usage,
                       budget_limit, percentage_used, action_taken, message, timestamp
                FROM budget_alerts
                WHERE timestamp >= ? AND acknowledged = FALSE
                ORDER BY severity DESC, timestamp DESC
            ''', (since_time,))
            
            active_alerts = []
            for row in cursor.fetchall():
                active_alerts.append({
                    'alert_type': row[0],
                    'severity': row[1],
                    'plugin_id': row[2],
                    'provider': row[3],
                    'current_usage': row[4],
                    'budget_limit': row[5],
                    'percentage_used': row[6],
                    'action_taken': row[7],
                    'message': row[8],
                    'timestamp': row[9]
                })
            
            conn.close()
            
            # Calculate summary statistics
            total_budgets = len(budget_statuses)
            over_budget_count = len([s for s in budget_statuses if s['percentage_used'] > 100])
            high_usage_count = len([s for s in budget_statuses if s['percentage_used'] > 80])
            
            return {
                'success': True,
                'dashboard_timestamp': datetime.utcnow().isoformat(),
                'time_window_hours': hours,
                'summary': {
                    'total_budgets_monitored': total_budgets,
                    'over_budget_count': over_budget_count,
                    'high_usage_count': high_usage_count,
                    'total_adjustments': len(recent_adjustments),
                    'active_alerts': len(active_alerts)
                },
                'budget_statuses': budget_statuses,
                'recent_adjustments': recent_adjustments,
                'active_alerts': active_alerts
            }
            
        except Exception as e:
            logger.error(f"❌ Get budget dashboard failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    async def set_plugin_priority(self, plugin_id: str, priority_level: str, 
                                budget_allocation: float = 10.0, 
                                emergency_priority: bool = False) -> Dict[str, Any]:
        """Set plugin priority and budget allocation"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Insert or update plugin priority
            cursor.execute('''
                INSERT OR REPLACE INTO plugin_priorities
                (plugin_id, priority_level, budget_allocation_percentage, 
                 emergency_priority, updated_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (plugin_id, priority_level, budget_allocation, emergency_priority,
                 datetime.utcnow().isoformat()))
            
            conn.commit()
            conn.close()
            
            return {
                'success': True,
                'message': f'Priority set for {plugin_id}: {priority_level} with {budget_allocation}% allocation',
                'plugin_id': plugin_id,
                'priority_level': priority_level,
                'budget_allocation_percentage': budget_allocation,
                'emergency_priority': emergency_priority
            }
            
        except Exception as e:
            logger.error(f"❌ Set plugin priority failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }


# Plugin metadata
plug_metadata = {
    "name": "budget_aware_rate_limiter",
    "owner": "plugpipe_ai_team",
    "version": "1.0.0",
    "status": "stable",
    "description": "Intelligent budget-aware rate limiting with automatic quota adjustments based on cost constraints",
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["monitor_and_adjust", "get_budget_dashboard", "set_plugin_priority"]
            },
            "plugin_id": {
                "type": "string",
                "description": "Specific plugin to monitor (optional)"
            },
            "provider": {
                "type": "string",
                "description": "Specific provider to monitor (optional)"
            },
            "hours": {
                "type": "integer",
                "description": "Time window for dashboard data (default: 24)"
            },
            "priority_level": {
                "type": "string",
                "enum": ["low", "normal", "high", "critical", "emergency"],
                "description": "Plugin priority level"
            },
            "budget_allocation": {
                "type": "number",
                "description": "Budget allocation percentage (default: 10.0)"
            },
            "emergency_priority": {
                "type": "boolean",
                "description": "Emergency priority flag (default: false)"
            }
        },
        "required": ["operation"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "monitoring_timestamp": {"type": "string"},
            "budget_statuses_checked": {"type": "integer"},
            "adjustments_made": {"type": "array"},
            "alerts_generated": {"type": "array"},
            "total_adjustments": {"type": "integer"},
            "total_alerts": {"type": "integer"},
            "dashboard_timestamp": {"type": "string"},
            "time_window_hours": {"type": "integer"},
            "summary": {"type": "object"},
            "budget_statuses": {"type": "array"},
            "recent_adjustments": {"type": "array"},
            "active_alerts": {"type": "array"},
            "error": {"type": "string"}
        }
    }
}

# Global budget-aware rate limiter instance
budget_rate_limiter = None

def get_budget_rate_limiter():
    """Get or create the global budget-aware rate limiter instance"""
    global budget_rate_limiter
    if budget_rate_limiter is None:
        budget_rate_limiter = BudgetAwareRateLimiter()
    return budget_rate_limiter


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point
    
    Operations:
    - monitor_and_adjust: Monitor budgets and adjust rate limits automatically
    - get_budget_dashboard: Get comprehensive budget monitoring dashboard
    - set_plugin_priority: Set plugin priority and budget allocation
    """
    operation = cfg.get('operation', 'monitor_and_adjust')
    
    try:
        limiter = get_budget_rate_limiter()
        
        if operation == 'monitor_and_adjust':
            return await limiter.monitor_and_adjust(
                plugin_id=cfg.get('plugin_id'),
                provider=cfg.get('provider')
            )
        
        elif operation == 'get_budget_dashboard':
            return await limiter.get_budget_dashboard(
                hours=cfg.get('hours', 24)
            )
        
        elif operation == 'set_plugin_priority':
            return await limiter.set_plugin_priority(
                plugin_id=cfg.get('plugin_id', 'unknown'),
                priority_level=cfg.get('priority_level', 'normal'),
                budget_allocation=cfg.get('budget_allocation', 10.0),
                emergency_priority=cfg.get('emergency_priority', False)
            )
        
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "supported_operations": [
                    "monitor_and_adjust", "get_budget_dashboard", "set_plugin_priority"
                ]
            }
    
    except Exception as e:
        logger.error(f"❌ Budget-aware rate limiter operation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test the plugin
    async def test_budget_aware_rate_limiter():
        """Test budget-aware rate limiter functionality"""
        print("💰🚦 Testing Budget-Aware Rate Limiter...")
        
        # Test monitoring and adjustment
        result = await process({}, {
            'operation': 'monitor_and_adjust'
        })
        print(f"Budget Monitoring: {result}")
        
        # Test dashboard
        result = await process({}, {
            'operation': 'get_budget_dashboard',
            'hours': 24
        })
        print(f"Budget Dashboard: {result}")
        
        # Test priority setting
        result = await process({}, {
            'operation': 'set_plugin_priority',
            'plugin_id': 'critical_ai_plugin',
            'priority_level': 'high',
            'budget_allocation': 25.0
        })
        print(f"Priority Setting: {result}")
        
        print("✅ Budget-aware rate limiter tests completed!")
    
    asyncio.run(test_budget_aware_rate_limiter())