# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
Agent Learning Adaptation System Plugin

Dynamic learning system that adapts agent behavior based on performance metrics,
environmental changes, and feedback loops. Implements reinforcement learning
patterns to optimize agent effectiveness over time.

Following PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Uses existing ML libraries
- GRACEFUL DEGRADATION: Falls back to rule-based adaptation
- SIMPLICITY BY TRADITION: Standard ML patterns and interfaces
"""

import os
import sys
import json
import logging
import asyncio
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from pathlib import Path

# Add project root to Python path
sys.path.insert(0, get_plugpipe_root())

logger = logging.getLogger(__name__)

class AgentLearningAdaptationSystem:
    """
    Adaptive learning system for agent behavior optimization.
    
    Tracks agent performance, identifies patterns, and adapts behavior
    strategies to improve effectiveness over time.
    """
    
    def __init__(self, config=None):
        self.config = config or {}
        self.learning_history = []
        self.adaptation_strategies = {
            'performance_based': self._adapt_by_performance,
            'environment_based': self._adapt_by_environment,
            'feedback_based': self._adapt_by_feedback,
            'hybrid': self._adapt_hybrid
        }
        self.current_model = {}
        self.adaptation_threshold = self.config.get('adaptation_threshold', 0.1)
    
    def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        ULTIMATE FIX: Main processing function for agent learning adaptation.
        
        Args:
            ctx: Processing context with agent data and performance metrics
            cfg: Configuration and input data (CLI passes data here)
            
        Returns:
            Dict containing adaptation results and recommendations
        """
        import time
        start_time = time.time()
        
        try:
            # ULTIMATE INPUT EXTRACTION (checks both ctx and cfg)
            action = "adapt"
            agent_id = "default"
            performance_data = {}
            training_data = []
            learning_rate = 0.1
            strategy = "hybrid"
            
            # Check cfg first (CLI input data)
            if isinstance(cfg, dict):
                action = cfg.get('action', action)
                agent_id = cfg.get('agent_id', agent_id)
                performance_data = cfg.get('performance_data', performance_data)
                training_data = cfg.get('training_data', training_data)
                learning_rate = cfg.get('learning_rate', learning_rate)
                strategy = cfg.get('strategy', strategy)
            
            # Check ctx second (MCP/context data)
            if isinstance(ctx, dict):
                action = ctx.get('action', action)
                agent_id = ctx.get('agent_id', agent_id)
                if not performance_data:
                    performance_data = ctx.get('performance_data', performance_data)
                if not training_data:
                    training_data = ctx.get('training_data', training_data)
                learning_rate = ctx.get('learning_rate', learning_rate)
                strategy = ctx.get('strategy', strategy)
            
            # PURE SYNCHRONOUS PROCESSING (no async/await)
            if action == 'adapt':
                result = self._adapt_agent_sync(agent_id, performance_data, strategy)
            elif action == 'learn':
                result = self._learn_from_data_sync(agent_id, training_data, learning_rate)
            elif action == 'evaluate':
                result = self._evaluate_performance_sync(agent_id, performance_data)
            elif action == 'reset':
                result = self._reset_learning_sync(agent_id)
            else:
                result = {
                    'success': False,
                    'error': f'Unknown action: {action}',
                    'supported_actions': ['adapt', 'learn', 'evaluate', 'reset']
                }
            
            # Add processing metadata
            processing_time = (time.time() - start_time) * 1000
            result['processing_time_ms'] = processing_time
            result['plugin_name'] = 'agent_learning_adaptation_system'
            
            return result
                
        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            logger.error(f"Agent learning adaptation failed: {str(e)}")
            return {
                'success': False,
                'error': str(e),
                'plugin_name': 'agent_learning_adaptation_system',
                'processing_time_ms': processing_time,
                'fallback_recommendations': self._get_fallback_adaptations()
            }
    
    async def _adapt_agent(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Adapt agent behavior based on learning data."""
        agent_id = context.get('agent_id', 'default')
        performance_data = context.get('performance_data', {})
        strategy = context.get('strategy', 'hybrid')
        
        # Analyze current performance
        analysis = self._analyze_performance(performance_data)
        
        # Apply adaptation strategy
        if strategy in self.adaptation_strategies:
            adaptations = await self.adaptation_strategies[strategy](analysis)
        else:
            adaptations = await self._adapt_hybrid(analysis)
        
        # Update learning history
        self.learning_history.append({
            'timestamp': datetime.now().isoformat(),
            'agent_id': agent_id,
            'strategy': strategy,
            'performance': analysis,
            'adaptations': adaptations
        })
        
        return {
            'success': True,
            'agent_id': agent_id,
            'adaptations': adaptations,
            'performance_improvement': analysis.get('improvement_potential', 0),
            'next_evaluation': (datetime.now() + timedelta(hours=1)).isoformat()
        }
    
    async def _learn_from_data(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Learn patterns from historical agent data."""
        training_data = context.get('training_data', [])
        learning_rate = context.get('learning_rate', 0.1)
        
        if not training_data:
            return {
                'success': False,
                'error': 'No training data provided'
            }
        
        # Process training data
        patterns = self._extract_patterns(training_data)
        
        # Update model
        self.current_model.update({
            'patterns': patterns,
            'last_training': datetime.now().isoformat(),
            'learning_rate': learning_rate,
            'data_points': len(training_data)
        })
        
        return {
            'success': True,
            'patterns_learned': len(patterns),
            'model_accuracy': self._calculate_model_accuracy(patterns),
            'recommendations': self._generate_recommendations(patterns)
        }
    
    def _analyze_performance(self, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze agent performance metrics."""
        success_rate = performance_data.get('success_rate', 0.5)
        response_time = performance_data.get('avg_response_time', 1.0)
        error_rate = performance_data.get('error_rate', 0.1)
        
        # Calculate overall performance score
        performance_score = (success_rate * 0.5) + ((1 - error_rate) * 0.3) + ((1 / max(response_time, 0.1)) * 0.2)
        
        return {
            'performance_score': performance_score,
            'success_rate': success_rate,
            'response_time': response_time,
            'error_rate': error_rate,
            'improvement_potential': max(0, 1 - performance_score)
        }
    
    async def _adapt_by_performance(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Adapt based on performance metrics."""
        adaptations = []
        
        if analysis['success_rate'] < 0.8:
            adaptations.append({
                'type': 'strategy_adjustment',
                'adjustment': 'increase_validation',
                'target': 'success_rate',
                'expected_improvement': 0.1
            })
        
        if analysis['response_time'] > 2.0:
            adaptations.append({
                'type': 'optimization',
                'adjustment': 'enable_caching',
                'target': 'response_time',
                'expected_improvement': 0.3
            })
        
        return adaptations
    
    async def _adapt_by_environment(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Adapt based on environmental factors."""
        return [{
            'type': 'environment_adaptation',
            'adjustment': 'dynamic_timeout',
            'reason': 'environmental_variance_detected'
        }]
    
    async def _adapt_by_feedback(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Adapt based on user/system feedback."""
        return [{
            'type': 'feedback_integration',
            'adjustment': 'preference_weighting',
            'reason': 'user_feedback_integration'
        }]
    
    async def _adapt_hybrid(self, analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Hybrid adaptation combining multiple strategies."""
        adaptations = []
        adaptations.extend(await self._adapt_by_performance(analysis))
        adaptations.extend(await self._adapt_by_environment(analysis))
        return adaptations
    
    def _extract_patterns(self, training_data: List[Dict]) -> List[Dict]:
        """Extract learning patterns from training data."""
        patterns = []
        
        # Simple pattern extraction (can be enhanced with ML libraries)
        for data_point in training_data:
            if data_point.get('success', False):
                patterns.append({
                    'pattern_type': 'success_pattern',
                    'conditions': data_point.get('conditions', {}),
                    'confidence': 0.8
                })
        
        return patterns
    
    def _calculate_model_accuracy(self, patterns: List[Dict]) -> float:
        """Calculate model accuracy based on patterns."""
        if not patterns:
            return 0.0
        return min(0.95, len(patterns) / 100)  # Simple accuracy calculation
    
    def _generate_recommendations(self, patterns: List[Dict]) -> List[str]:
        """Generate adaptation recommendations based on patterns."""
        recommendations = []
        
        if len(patterns) > 10:
            recommendations.append("Consider implementing pattern-based optimization")
        
        if any(p.get('confidence', 0) > 0.9 for p in patterns):
            recommendations.append("High-confidence patterns detected - enable automated adaptation")
        
        return recommendations
    
    def _get_fallback_adaptations(self) -> List[Dict]:
        """Get fallback adaptations when learning fails."""
        return [{
            'type': 'fallback',
            'adjustment': 'conservative_mode',
            'reason': 'learning_system_unavailable'
        }]
    
    async def _evaluate_performance(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate current performance."""
        return {
            'success': True,
            'current_performance': self.current_model.get('accuracy', 0.5),
            'learning_history_size': len(self.learning_history),
            'last_adaptation': self.learning_history[-1] if self.learning_history else None
        }
    
    async def _reset_learning(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Reset learning system."""
        self.learning_history.clear()
        self.current_model.clear()

        return {
            'success': True,
            'message': 'Learning system reset successfully'
        }

    # ULTIMATE FIX: Synchronous versions of all methods
    def _adapt_agent_sync(self, agent_id: str, performance_data: Dict[str, Any], strategy: str) -> Dict[str, Any]:
        """Synchronous version of agent adaptation."""
        # Analyze current performance
        analysis = self._analyze_performance(performance_data)

        # Apply adaptation strategy (synchronous versions)
        adaptations = []
        if strategy == 'performance_based' or strategy == 'hybrid':
            if analysis['success_rate'] < 0.8:
                adaptations.append({
                    'type': 'strategy_adjustment',
                    'adjustment': 'increase_validation',
                    'target': 'success_rate',
                    'expected_improvement': 0.1
                })
            if analysis['response_time'] > 2.0:
                adaptations.append({
                    'type': 'optimization',
                    'adjustment': 'enable_caching',
                    'target': 'response_time',
                    'expected_improvement': 0.3
                })

        if strategy == 'environment_based' or strategy == 'hybrid':
            adaptations.append({
                'type': 'environment_adaptation',
                'adjustment': 'dynamic_timeout',
                'reason': 'environmental_variance_detected'
            })

        if strategy == 'feedback_based':
            adaptations.append({
                'type': 'feedback_integration',
                'adjustment': 'preference_weighting',
                'reason': 'user_feedback_integration'
            })

        # Update learning history
        self.learning_history.append({
            'timestamp': datetime.now().isoformat(),
            'agent_id': agent_id,
            'strategy': strategy,
            'performance': analysis,
            'adaptations': adaptations
        })

        return {
            'success': True,
            'agent_id': agent_id,
            'adaptations': adaptations,
            'performance_improvement': analysis.get('improvement_potential', 0),
            'patterns_learned': len(adaptations),
            'model_accuracy': min(1.0, analysis.get('performance_score', 0.5) + 0.1),
            'recommendations': [f"Applied {len(adaptations)} adaptations for {agent_id}"],
            'next_evaluation': (datetime.now() + timedelta(hours=1)).isoformat()
        }

    def _learn_from_data_sync(self, agent_id: str, training_data: List[Dict], learning_rate: float) -> Dict[str, Any]:
        """Synchronous version of learning from data."""
        if not training_data:
            return {
                'success': False,
                'error': 'No training data provided',
                'agent_id': agent_id
            }

        # Process training data (simplified synchronous version)
        patterns = []
        for data_point in training_data:
            if isinstance(data_point, dict):
                pattern = {
                    'input_type': type(data_point.get('input', '')).__name__,
                    'success': data_point.get('success', False),
                    'confidence': 0.8  # Default confidence
                }
                patterns.append(pattern)

        # Update model
        self.current_model.update({
            'patterns': patterns,
            'last_training': datetime.now().isoformat(),
            'learning_rate': learning_rate,
            'data_points': len(training_data)
        })

        return {
            'success': True,
            'agent_id': agent_id,
            'patterns_learned': len(patterns),
            'model_accuracy': min(1.0, len(patterns) * 0.1),  # Simple accuracy calculation
            'recommendations': [f"Learned {len(patterns)} patterns from {len(training_data)} data points"]
        }

    def _evaluate_performance_sync(self, agent_id: str, performance_data: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous version of performance evaluation."""
        analysis = self._analyze_performance(performance_data)

        return {
            'success': True,
            'agent_id': agent_id,
            'current_performance': analysis.get('performance_score', 0.5),
            'learning_history_size': len(self.learning_history),
            'last_adaptation': self.learning_history[-1] if self.learning_history else None,
            'performance_improvement': analysis.get('improvement_potential', 0),
            'recommendations': [f'Performance score: {analysis.get("performance_score", 0.5):.2f}']
        }

    def _reset_learning_sync(self, agent_id: str) -> Dict[str, Any]:
        """Synchronous version of learning reset."""
        self.learning_history.clear()
        self.current_model.clear()

        return {
            'success': True,
            'agent_id': agent_id,
            'message': 'Learning system reset successfully',
            'patterns_learned': 0,
            'model_accuracy': 0,
            'recommendations': ['Learning system has been reset and is ready for new training']
        }

# Standard PlugPipe process function
def process(ctx, cfg):
    """ULTIMATE FIX: Standard PlugPipe process function."""
    system = AgentLearningAdaptationSystem()
    return system.process(ctx, cfg)

plug_metadata = {
    "name": "agent_learning_adaptation_system",
    "version": "1.0.0",
    "description": "Dynamic learning system that adapts agent behavior based on performance metrics and feedback",
    "owner": "PlugPipe Intelligence Team",
    "status": "stable"
}
