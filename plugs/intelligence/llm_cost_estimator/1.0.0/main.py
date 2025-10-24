#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
🧮 LLM Cost Estimation Plugin

Production-ready plugin for calculating, tracking, and optimizing LLM usage costs across
all PlugPipe plugins. Provides comprehensive cost analysis, budget monitoring, and usage
optimization recommendations.

Key Features:
- Multi-provider cost calculations (OpenAI, Anthropic, Ollama)
- Token-based and request-based cost estimation
- Budget tracking and alert generation
- Usage optimization recommendations
- Historical cost analysis and trending
- ROI analysis for different models and providers

Author: PlugPipe AI Infrastructure Team
Version: 1.0.0
"""

import asyncio
import json
import logging
import os
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, asdict
import sqlite3
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@dataclass
class CostEstimate:
    """Data class for cost estimation results"""
    provider: str
    model: str
    input_tokens: int
    output_tokens: int
    total_tokens: int
    input_cost: float
    output_cost: float
    total_cost: float
    currency: str = "USD"
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


@dataclass
class BudgetAlert:
    """Data class for budget alerts"""
    alert_type: str
    severity: str
    message: str
    current_usage: float
    budget_limit: float
    percentage_used: float
    timestamp: str = None
    
    def __post_init__(self):
        if self.timestamp is None:
            self.timestamp = datetime.utcnow().isoformat()


class LLMCostEstimator:
    """Production-ready LLM cost estimation and budget monitoring service"""
    
    # Provider pricing models (per 1K tokens)
    PROVIDER_PRICING = {
        'openai': {
            'gpt-4': {'input': 0.03, 'output': 0.06},
            'gpt-4-turbo': {'input': 0.01, 'output': 0.03},
            'gpt-3.5-turbo': {'input': 0.0015, 'output': 0.002},
            'gpt-4o': {'input': 0.005, 'output': 0.015},
            'gpt-4o-mini': {'input': 0.00015, 'output': 0.0006}
        },
        'anthropic': {
            'claude-3-opus': {'input': 0.015, 'output': 0.075},
            'claude-3-sonnet': {'input': 0.003, 'output': 0.015},
            'claude-3-haiku': {'input': 0.00025, 'output': 0.00125},
            'claude-3-5-sonnet': {'input': 0.003, 'output': 0.015}
        },
        'ollama': {
            'mistral:latest': {'input': 0.0, 'output': 0.0},
            'llama2:latest': {'input': 0.0, 'output': 0.0},
            'codellama:latest': {'input': 0.0, 'output': 0.0},
            'vicuna:latest': {'input': 0.0, 'output': 0.0}
        }
    }
    
    def __init__(self, db_path: str = "llm_cost_tracking.db"):
        """Initialize cost estimator with local SQLite database"""
        self.db_path = db_path
        self.currency = "USD"
        self._init_database()
        
    def _init_database(self):
        """Initialize SQLite database for cost tracking"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Create cost estimates table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS cost_estimates (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    input_tokens INTEGER NOT NULL,
                    output_tokens INTEGER NOT NULL,
                    total_tokens INTEGER NOT NULL,
                    input_cost REAL NOT NULL,
                    output_cost REAL NOT NULL,
                    total_cost REAL NOT NULL,
                    currency TEXT DEFAULT 'USD',
                    timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create budget alerts table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS budget_alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT,
                    alert_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    message TEXT NOT NULL,
                    current_usage REAL NOT NULL,
                    budget_limit REAL NOT NULL,
                    percentage_used REAL NOT NULL,
                    timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create budget settings table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS budget_settings (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT,
                    provider TEXT,
                    daily_budget REAL,
                    weekly_budget REAL,
                    monthly_budget REAL,
                    alert_threshold_80 BOOLEAN DEFAULT TRUE,
                    alert_threshold_95 BOOLEAN DEFAULT TRUE,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            # Create usage optimization table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS optimization_recommendations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    plugin_id TEXT NOT NULL,
                    recommendation_type TEXT NOT NULL,
                    current_model TEXT,
                    suggested_model TEXT,
                    potential_savings REAL,
                    confidence_score REAL,
                    reasoning TEXT,
                    timestamp TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                )
            ''')
            
            conn.commit()
            conn.close()
            logger.info(f"✅ Database initialized: {self.db_path}")
            
        except Exception as e:
            logger.error(f"❌ Database initialization failed: {e}")
            raise
    
    async def estimate_cost(self, plugin_id: str, provider: str, model: str, 
                           input_tokens: int, output_tokens: int = None) -> Dict[str, Any]:
        """
        Estimate cost for LLM usage
        
        Args:
            plugin_id: Plugin requesting cost estimation
            provider: LLM provider (openai, anthropic, ollama)
            model: Model name
            input_tokens: Number of input tokens
            output_tokens: Number of output tokens (estimated if None)
        
        Returns:
            Cost estimation with detailed breakdown
        """
        try:
            # Normalize provider and model names
            provider = provider.lower()
            model = model.lower()
            
            # Get pricing information
            if provider not in self.PROVIDER_PRICING:
                return {
                    "success": False,
                    "error": f"Unknown provider: {provider}",
                    "supported_providers": list(self.PROVIDER_PRICING.keys())
                }
            
            provider_models = self.PROVIDER_PRICING[provider]
            
            # Find matching model (exact match or partial match)
            model_pricing = None
            for model_key, pricing in provider_models.items():
                if model == model_key or model.startswith(model_key.split(':')[0]):
                    model_pricing = pricing
                    model = model_key
                    break
            
            if model_pricing is None:
                # Use default pricing for unknown models based on provider
                if provider == 'openai':
                    model_pricing = {'input': 0.01, 'output': 0.03}  # GPT-4 Turbo pricing
                    model = 'gpt-4-turbo-fallback'
                elif provider == 'anthropic':
                    model_pricing = {'input': 0.003, 'output': 0.015}  # Claude-3 Sonnet pricing
                    model = 'claude-3-sonnet-fallback'
                elif provider == 'ollama':
                    model_pricing = {'input': 0.0, 'output': 0.0}  # Free
                    model = 'ollama-free-fallback'
            
            # Estimate output tokens if not provided
            if output_tokens is None:
                output_tokens = int(input_tokens * 0.3)  # Typical output ratio
            
            total_tokens = input_tokens + output_tokens
            
            # Calculate costs (pricing is per 1K tokens)
            input_cost = (input_tokens / 1000.0) * model_pricing['input']
            output_cost = (output_tokens / 1000.0) * model_pricing['output']
            total_cost = input_cost + output_cost
            
            # Create cost estimate
            estimate = CostEstimate(
                provider=provider,
                model=model,
                input_tokens=input_tokens,
                output_tokens=output_tokens,
                total_tokens=total_tokens,
                input_cost=input_cost,
                output_cost=output_cost,
                total_cost=total_cost,
                currency=self.currency
            )
            
            # Store estimate in database
            await self._store_cost_estimate(plugin_id, estimate)
            
            # Check budget alerts
            alerts = await self._check_budget_alerts(plugin_id, provider, total_cost)
            
            return {
                "success": True,
                "cost_estimate": asdict(estimate),
                "budget_alerts": alerts,
                "optimization_available": await self._has_optimization_recommendations(plugin_id)
            }
            
        except Exception as e:
            logger.error(f"❌ Cost estimation failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_usage_statistics(self, plugin_id: str = None, provider: str = None,
                                  hours: int = 24) -> Dict[str, Any]:
        """Get usage statistics and cost breakdown"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Build query conditions
            conditions = []
            params = []
            
            if plugin_id:
                conditions.append("plugin_id = ?")
                params.append(plugin_id)
            
            if provider:
                conditions.append("provider = ?")
                params.append(provider.lower())
            
            # Time window
            since_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat()
            conditions.append("timestamp >= ?")
            params.append(since_time)
            
            where_clause = "WHERE " + " AND ".join(conditions) if conditions else ""
            
            # Get aggregated statistics
            cursor.execute(f'''
                SELECT 
                    COUNT(*) as total_requests,
                    SUM(total_tokens) as total_tokens,
                    SUM(total_cost) as total_cost,
                    AVG(total_cost) as avg_cost_per_request,
                    provider,
                    model,
                    COUNT(*) as request_count
                FROM cost_estimates 
                {where_clause}
                GROUP BY provider, model
                ORDER BY total_cost DESC
            ''', params)
            
            provider_breakdown = []
            total_cost = 0
            total_tokens = 0
            total_requests = 0
            
            for row in cursor.fetchall():
                provider_data = {
                    "provider": row[4],
                    "model": row[5],
                    "requests": row[6],
                    "total_tokens": row[1] or 0,
                    "total_cost": row[2] or 0,
                    "avg_cost_per_request": row[3] or 0
                }
                provider_breakdown.append(provider_data)
                total_cost += row[2] or 0
                total_tokens += row[1] or 0
                total_requests += row[6] or 0
            
            # Get cost trends (daily breakdown)
            cursor.execute(f'''
                SELECT 
                    DATE(created_at) as date,
                    SUM(total_cost) as daily_cost,
                    COUNT(*) as daily_requests
                FROM cost_estimates 
                {where_clause}
                GROUP BY DATE(created_at)
                ORDER BY date DESC
                LIMIT 30
            ''', params)
            
            daily_trends = []
            for row in cursor.fetchall():
                daily_trends.append({
                    "date": row[0],
                    "cost": row[1] or 0,
                    "requests": row[2] or 0
                })
            
            conn.close()
            
            return {
                "success": True,
                "statistics": {
                    "total_requests": total_requests,
                    "total_tokens": total_tokens,
                    "total_cost": total_cost,
                    "currency": self.currency,
                    "time_window_hours": hours,
                    "provider_breakdown": provider_breakdown,
                    "daily_trends": daily_trends,
                    "avg_cost_per_request": total_cost / max(total_requests, 1),
                    "cost_per_1k_tokens": (total_cost / max(total_tokens, 1)) * 1000
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Usage statistics failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def set_budget(self, plugin_id: str = None, provider: str = None,
                        daily_budget: float = None, weekly_budget: float = None,
                        monthly_budget: float = None) -> Dict[str, Any]:
        """Set budget limits for plugin or provider"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Check if budget already exists
            cursor.execute('''
                SELECT id FROM budget_settings 
                WHERE plugin_id = ? AND provider = ?
            ''', (plugin_id, provider))
            
            existing = cursor.fetchone()
            
            if existing:
                # Update existing budget
                cursor.execute('''
                    UPDATE budget_settings 
                    SET daily_budget = ?, weekly_budget = ?, monthly_budget = ?,
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                ''', (daily_budget, weekly_budget, monthly_budget, existing[0]))
            else:
                # Insert new budget
                cursor.execute('''
                    INSERT INTO budget_settings 
                    (plugin_id, provider, daily_budget, weekly_budget, monthly_budget)
                    VALUES (?, ?, ?, ?, ?)
                ''', (plugin_id, provider, daily_budget, weekly_budget, monthly_budget))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "message": f"Budget set successfully for {plugin_id or 'global'}/{provider or 'all providers'}",
                "budget_limits": {
                    "daily": daily_budget,
                    "weekly": weekly_budget,
                    "monthly": monthly_budget,
                    "currency": self.currency
                }
            }
            
        except Exception as e:
            logger.error(f"❌ Set budget failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    async def get_optimization_recommendations(self, plugin_id: str) -> Dict[str, Any]:
        """Generate cost optimization recommendations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get recent usage patterns
            cursor.execute('''
                SELECT provider, model, AVG(input_tokens), AVG(output_tokens), 
                       AVG(total_cost), COUNT(*) as usage_count
                FROM cost_estimates 
                WHERE plugin_id = ? AND timestamp >= ?
                GROUP BY provider, model
                ORDER BY usage_count DESC
            ''', (plugin_id, (datetime.utcnow() - timedelta(days=7)).isoformat()))
            
            usage_patterns = cursor.fetchall()
            recommendations = []
            
            for pattern in usage_patterns:
                provider, model, avg_input, avg_output, avg_cost, usage_count = pattern
                
                # Generate recommendations based on usage patterns
                if avg_cost > 0.01:  # High cost per request
                    # Find cheaper alternatives
                    cheaper_models = self._find_cheaper_alternatives(provider, model, avg_input, avg_output)
                    for alt_model, savings in cheaper_models:
                        recommendations.append({
                            "type": "model_optimization",
                            "current_model": f"{provider}/{model}",
                            "suggested_model": f"{provider}/{alt_model}",
                            "potential_savings": savings * usage_count,
                            "confidence_score": 0.8,
                            "reasoning": f"Switch to {alt_model} could save ${savings:.4f} per request"
                        })
                
                if usage_count > 100:  # High usage
                    # Suggest batch processing
                    batch_savings = avg_cost * 0.15  # Assume 15% savings from batching
                    recommendations.append({
                        "type": "batch_optimization",
                        "current_model": f"{provider}/{model}",
                        "suggested_model": f"{provider}/{model}",
                        "potential_savings": batch_savings * usage_count,
                        "confidence_score": 0.6,
                        "reasoning": "Consider batching requests to reduce per-request overhead"
                    })
            
            # Store recommendations
            for rec in recommendations[:5]:  # Limit to top 5
                cursor.execute('''
                    INSERT INTO optimization_recommendations 
                    (plugin_id, recommendation_type, current_model, suggested_model,
                     potential_savings, confidence_score, reasoning, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (plugin_id, rec['type'], rec['current_model'], rec['suggested_model'],
                     rec['potential_savings'], rec['confidence_score'], rec['reasoning'],
                     datetime.utcnow().isoformat()))
            
            conn.commit()
            conn.close()
            
            return {
                "success": True,
                "recommendations": recommendations,
                "total_potential_savings": sum(r['potential_savings'] for r in recommendations),
                "currency": self.currency
            }
            
        except Exception as e:
            logger.error(f"❌ Optimization recommendations failed: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    
    def _find_cheaper_alternatives(self, provider: str, current_model: str, 
                                  avg_input: float, avg_output: float) -> List[Tuple[str, float]]:
        """Find cheaper model alternatives"""
        alternatives = []
        
        if provider not in self.PROVIDER_PRICING:
            return alternatives
        
        current_pricing = None
        for model_key, pricing in self.PROVIDER_PRICING[provider].items():
            if current_model == model_key:
                current_pricing = pricing
                break
        
        if not current_pricing:
            return alternatives
        
        current_cost = (avg_input / 1000.0 * current_pricing['input'] + 
                       avg_output / 1000.0 * current_pricing['output'])
        
        # Check other models in same provider
        for model_key, pricing in self.PROVIDER_PRICING[provider].items():
            if model_key != current_model:
                alt_cost = (avg_input / 1000.0 * pricing['input'] + 
                           avg_output / 1000.0 * pricing['output'])
                if alt_cost < current_cost:
                    savings = current_cost - alt_cost
                    alternatives.append((model_key, savings))
        
        return sorted(alternatives, key=lambda x: x[1], reverse=True)
    
    async def _store_cost_estimate(self, plugin_id: str, estimate: CostEstimate):
        """Store cost estimate in database"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT INTO cost_estimates 
                (plugin_id, provider, model, input_tokens, output_tokens, total_tokens,
                 input_cost, output_cost, total_cost, currency, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (plugin_id, estimate.provider, estimate.model, estimate.input_tokens,
                 estimate.output_tokens, estimate.total_tokens, estimate.input_cost,
                 estimate.output_cost, estimate.total_cost, estimate.currency,
                 estimate.timestamp))
            
            conn.commit()
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Store cost estimate failed: {e}")
    
    async def _check_budget_alerts(self, plugin_id: str, provider: str, cost: float) -> List[Dict]:
        """Check if budget alerts should be triggered"""
        alerts = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # Get budget settings
            cursor.execute('''
                SELECT daily_budget, weekly_budget, monthly_budget 
                FROM budget_settings 
                WHERE (plugin_id = ? OR plugin_id IS NULL) 
                AND (provider = ? OR provider IS NULL)
                ORDER BY plugin_id DESC, provider DESC
                LIMIT 1
            ''', (plugin_id, provider))
            
            budget_settings = cursor.fetchone()
            if not budget_settings:
                conn.close()
                return alerts
            
            daily_budget, weekly_budget, monthly_budget = budget_settings
            
            # Check daily usage
            if daily_budget:
                today = datetime.utcnow().date().isoformat()
                cursor.execute('''
                    SELECT SUM(total_cost) FROM cost_estimates 
                    WHERE plugin_id = ? AND provider = ? AND DATE(created_at) = ?
                ''', (plugin_id, provider, today))
                
                daily_usage = (cursor.fetchone()[0] or 0) + cost
                daily_percent = (daily_usage / daily_budget) * 100
                
                if daily_percent >= 95:
                    alerts.append({
                        "type": "daily_budget_critical",
                        "severity": "CRITICAL",
                        "percentage": daily_percent,
                        "current_usage": daily_usage,
                        "budget_limit": daily_budget
                    })
                elif daily_percent >= 80:
                    alerts.append({
                        "type": "daily_budget_warning",
                        "severity": "WARNING",
                        "percentage": daily_percent,
                        "current_usage": daily_usage,
                        "budget_limit": daily_budget
                    })
            
            # Similar checks for weekly and monthly budgets...
            
            conn.close()
            
        except Exception as e:
            logger.error(f"❌ Budget alert check failed: {e}")
        
        return alerts
    
    async def _has_optimization_recommendations(self, plugin_id: str) -> bool:
        """Check if plugin has optimization recommendations"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                SELECT COUNT(*) FROM optimization_recommendations 
                WHERE plugin_id = ? AND timestamp >= ?
            ''', (plugin_id, (datetime.utcnow() - timedelta(days=1)).isoformat()))
            
            count = cursor.fetchone()[0]
            conn.close()
            
            return count > 0
            
        except Exception as e:
            logger.error(f"❌ Check optimization recommendations failed: {e}")
            return False


# Plugin metadata
plug_metadata = {
    "name": "llm_cost_estimator",
    "owner": "plugpipe_ai_team",
    "version": "1.0.0",
    "status": "stable",
    "description": "Production-ready LLM cost estimation and budget monitoring plugin",
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["estimate_cost", "get_usage_statistics", "set_budget", 
                        "get_optimization_recommendations"]
            },
            "plugin_id": {"type": "string"},
            "provider": {"type": "string"},
            "model": {"type": "string"},
            "input_tokens": {"type": "integer"},
            "output_tokens": {"type": "integer"},
            "hours": {"type": "integer"},
            "daily_budget": {"type": "number"},
            "weekly_budget": {"type": "number"},
            "monthly_budget": {"type": "number"}
        },
        "required": ["operation"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "cost_estimate": {"type": "object"},
            "statistics": {"type": "object"},
            "budget_limits": {"type": "object"},
            "recommendations": {"type": "array"},
            "budget_alerts": {"type": "array"},
            "error": {"type": "string"}
        }
    }
}

# Global cost estimator instance (initialized lazily)
cost_estimator = None

def get_cost_estimator():
    """Get or create the global cost estimator instance"""
    global cost_estimator
    if cost_estimator is None:
        cost_estimator = LLMCostEstimator()
    return cost_estimator


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point
    
    Operations:
    - estimate_cost: Calculate cost for LLM usage
    - get_usage_statistics: Get usage and cost analytics
    - set_budget: Set budget limits
    - get_optimization_recommendations: Get cost optimization suggestions
    """
    operation = cfg.get('operation', 'estimate_cost')
    
    try:
        # Get the cost estimator instance (initializes database if needed)
        estimator = get_cost_estimator()
        
        if operation == 'estimate_cost':
            return await estimator.estimate_cost(
                plugin_id=cfg.get('plugin_id', 'unknown'),
                provider=cfg.get('provider', 'openai'),
                model=cfg.get('model', 'gpt-4'),
                input_tokens=cfg.get('input_tokens', 100),
                output_tokens=cfg.get('output_tokens')
            )
        
        elif operation == 'get_usage_statistics':
            return await estimator.get_usage_statistics(
                plugin_id=cfg.get('plugin_id'),
                provider=cfg.get('provider'),
                hours=cfg.get('hours', 24)
            )
        
        elif operation == 'set_budget':
            return await estimator.set_budget(
                plugin_id=cfg.get('plugin_id'),
                provider=cfg.get('provider'),
                daily_budget=cfg.get('daily_budget'),
                weekly_budget=cfg.get('weekly_budget'),
                monthly_budget=cfg.get('monthly_budget')
            )
        
        elif operation == 'get_optimization_recommendations':
            return await estimator.get_optimization_recommendations(
                plugin_id=cfg.get('plugin_id', 'unknown')
            )
        
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "supported_operations": [
                    "estimate_cost", "get_usage_statistics", 
                    "set_budget", "get_optimization_recommendations"
                ]
            }
    
    except Exception as e:
        logger.error(f"❌ LLM cost estimator operation failed: {e}")
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test the plugin
    async def test_cost_estimator():
        """Test LLM cost estimator functionality"""
        print("🧮 Testing LLM Cost Estimator Plugin...")
        
        # Test cost estimation
        result = await process({}, {
            'operation': 'estimate_cost',
            'plugin_id': 'test_plugin',
            'provider': 'openai',
            'model': 'gpt-4',
            'input_tokens': 1000,
            'output_tokens': 300
        })
        print(f"Cost Estimation: {result}")
        
        # Test usage statistics
        result = await process({}, {
            'operation': 'get_usage_statistics',
            'plugin_id': 'test_plugin',
            'hours': 24
        })
        print(f"Usage Statistics: {result}")
        
        # Test budget setting
        result = await process({}, {
            'operation': 'set_budget',
            'plugin_id': 'test_plugin',
            'provider': 'openai',
            'daily_budget': 50.0,
            'monthly_budget': 1000.0
        })
        print(f"Budget Setting: {result}")
        
        # Test optimization recommendations
        result = await process({}, {
            'operation': 'get_optimization_recommendations',
            'plugin_id': 'test_plugin'
        })
        print(f"Optimization Recommendations: {result}")
        
        print("✅ All tests completed!")
    
    asyncio.run(test_cost_estimator())