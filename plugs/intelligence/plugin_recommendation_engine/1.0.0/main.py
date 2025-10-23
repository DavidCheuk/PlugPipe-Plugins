#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Plugin Recommendation Engine - Focused Intelligence Plugin for PlugPipe

Provides intelligent plugin recommendations based on requirements and capabilities.
Extracted from orchestrator to maintain single responsibility principle and
achieve 100% PlugPipe compliance.

Key Capabilities:
- Domain-based plugin matching
- Capability-based recommendations
- Compatibility evaluation
- Intelligent ranking and scoring

Follows PlugPipe Principles:
- SINGLE RESPONSIBILITY: Only handles plugin recommendations
- REUSE EVERYTHING: Uses existing data structures
- NO CUSTOM IMPLEMENTATIONS: Pure recommendation logic
"""

import os
import time
import sys
import json
import logging
import asyncio
from typing import Dict, List, Any
from dataclasses import dataclass, asdict

logger = logging.getLogger(__name__)


@dataclass
class PluginRecommendation:
    """Structured recommendation for plugin combinations."""
    type: str
    plugins: List[str]
    reasoning: str
    confidence_score: float
    architectural_benefit: str


class PluginRecommendationEngine:
    """
    Intelligent plugin recommendation engine.

    PLUGPIPE COMPLIANCE:
    - SINGLE RESPONSIBILITY: Only handles recommendations
    - NO BUSINESS LOGIC DUPLICATION: Pure matching algorithms
    - FOCUSED SCOPE: Domain-specific recommendation logic
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.recommendation_settings = config.get('recommendation_settings', {})
        self.max_suggestions = self.recommendation_settings.get('max_suggestions_per_type', 3)
        self.include_reasoning = self.recommendation_settings.get('include_reasoning', True)
        self.prefer_domain_matches = self.recommendation_settings.get('prefer_domain_matches', True)

        logger.info("Initialized PluginRecommendationEngine with focused responsibility")

    async def suggest_combinations(self, requirements: Dict[str, Any],
                                 capabilities: Dict[str, Any]) -> List[PluginRecommendation]:
        """
        Generate intelligent plugin combination suggestions.

        ARCHITECTURAL COMPLIANCE: Pure recommendation logic, no business rules
        """
        try:
            recommendations = []

            requirement_data = requirements.get('requirement_analysis', {})
            capability_index = capabilities.get('capability_index', {})

            if not requirement_data or not capability_index:
                logger.warning("Insufficient data for recommendations")
                return recommendations

            # Extract requirement parameters
            required_capabilities = requirement_data.get('required_capabilities', [])
            domain = requirement_data.get('domain', 'general')
            intent = requirement_data.get('primary_intent', 'integration')

            # Get available data
            available_plugins = capability_index.get('plugins', {})
            category_plugins = capability_index.get('categories', {})
            capability_plugins = capability_index.get('capabilities', {})

            # Generate domain-based recommendations
            domain_recs = self._generate_domain_recommendations(
                domain, category_plugins, available_plugins
            )
            recommendations.extend(domain_recs)

            # Generate capability-based recommendations
            capability_recs = self._generate_capability_recommendations(
                required_capabilities, capability_plugins, available_plugins
            )
            recommendations.extend(capability_recs)

            # Generate architectural recommendations
            arch_recs = self._generate_architectural_recommendations()
            recommendations.extend(arch_recs)

            logger.info(f"Generated {len(recommendations)} plugin recommendations")
            return recommendations

        except Exception as e:
            logger.error(f"Error generating recommendations: {e}")
            return []

    async def _generate_domain_recommendations(self, domain: str,
                                             category_plugins: Dict[str, List[str]],
                                             available_plugins: Dict[str, Any]) -> List[PluginRecommendation]:
        """Generate recommendations based on domain expertise."""
        recommendations = []

        domain_matches = category_plugins.get(domain, [])
        if domain_matches:
            # Calculate confidence based on number of available plugins
            confidence = min(0.9, len(domain_matches) / 10.0 + 0.5)

            recommendations.append(PluginRecommendation(
                type='domain_based',
                plugins=domain_matches[:self.max_suggestions],
                reasoning=f'Plugins specialized for {domain} domain provide domain-specific expertise',
                confidence_score=confidence,
                architectural_benefit='domain_expertise_reuse'
            ))

        return recommendations

    async def _generate_capability_recommendations(self, required_capabilities: List[str],
                                                 capability_plugins: Dict[str, List[str]],
                                                 available_plugins: Dict[str, Any]) -> List[PluginRecommendation]:
        """Generate recommendations based on required capabilities."""
        recommendations = []

        if not required_capabilities:
            return recommendations

        # Find plugins that match required capabilities
        capability_matches = []
        for capability in required_capabilities:
            matching_plugins = capability_plugins.get(capability, [])
            capability_matches.extend(matching_plugins)

        # Remove duplicates while preserving order
        unique_matches = list(dict.fromkeys(capability_matches))

        if unique_matches:
            # Calculate confidence based on capability coverage
            coverage_ratio = len(unique_matches) / max(len(required_capabilities), 1)
            confidence = min(0.95, coverage_ratio * 0.8 + 0.3)

            recommendations.append(PluginRecommendation(
                type='capability_based',
                plugins=unique_matches[:self.max_suggestions],
                reasoning=f'Plugins providing required capabilities: {", ".join(required_capabilities[:3])}',
                confidence_score=confidence,
                architectural_benefit='capability_focused_composition'
            ))

        return recommendations

    async def _generate_architectural_recommendations(self) -> List[PluginRecommendation]:
        """Generate recommendations for architectural compliance."""
        recommendations = []

        # Always recommend using the decomposed intelligence plugins
        recommendations.append(PluginRecommendation(
            type='architectural_compliance',
            plugins=[
                'intelligence.plugin_capability_analyzer',
                'intelligence.requirement_analyzer',
                'intelligence.plugin_recommendation_engine'
            ],
            reasoning='Use focused intelligence plugins for maintainable, PlugPipe-compliant architecture',
            confidence_score=1.0,
            architectural_benefit='plugpipe_principle_compliance'
        ))

        return recommendations

    async def match_by_domain(self, domain: str, capabilities: Dict[str, Any]) -> List[str]:
        """Match plugins by specific domain."""
        capability_index = capabilities.get('capability_index', {})
        category_plugins = capability_index.get('categories', {})
        return category_plugins.get(domain, [])

    async def match_by_capability(self, capability: str, capabilities: Dict[str, Any]) -> List[str]:
        """Match plugins by specific capability."""
        capability_index = capabilities.get('capability_index', {})
        capability_plugins = capability_index.get('capabilities', {})
        return capability_plugins.get(capability, [])

    async def evaluate_compatibility(self, plugin_list: List[str],
                                   capabilities: Dict[str, Any]) -> Dict[str, float]:
        """Evaluate compatibility scores for plugin combinations."""
        scores = {}

        for plugin in plugin_list:
            # Simple heuristic: plugins in intelligence domain get higher scores
            if 'intelligence' in plugin:
                scores[plugin] = 0.9
            elif any(domain in plugin for domain in ['security', 'automation', 'core']):
                scores[plugin] = 0.8
            else:
                scores[plugin] = 0.7

        return scores


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for plugin recommendations.

    PLUGPIPE COMPLIANCE: Focused responsibility, clear interface
    """
    try:
        operation = cfg.get('operation')
        if not operation:
            return {
                'success': False,
                'error': 'Missing required operation parameter',
                'status': 'failed',
                'timestamp': asyncio.get_event_loop().time()
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        requirements = cfg.get('requirements', {})
        capabilities = cfg.get('capabilities', {})

        engine = PluginRecommendationEngine(cfg)

        if operation == 'suggest_combinations':
            recommendations = engine.suggest_combinations(requirements, capabilities)
            return {
                'success': True,
                'operation_completed': operation,
                'recommendations': [asdict(rec) for rec in recommendations],
                'timestamp': asyncio.get_event_loop().time(),
                'status': 'completed'
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        elif operation == 'match_by_domain':
            domain = cfg.get('context', {}).get('domain', 'general')
            matches = engine.match_by_domain(domain, capabilities)
            return {
                'success': True,
                'operation_completed': operation,
                'matches': matches,
                'timestamp': asyncio.get_event_loop().time(),
                'status': 'completed'
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        elif operation == 'match_by_capability':
            capability = cfg.get('context', {}).get('capability', '')
            matches = engine.match_by_capability(capability, capabilities)
            return {
                'success': True,
                'operation_completed': operation,
                'matches': matches,
                'timestamp': asyncio.get_event_loop().time(),
                'status': 'completed'
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        elif operation == 'evaluate_compatibility':
            plugin_list = cfg.get('context', {}).get('plugins', [])
            scores = engine.evaluate_compatibility(plugin_list, capabilities)
            return {
                'success': True,
                'operation_completed': operation,
                'compatibility_scores': scores,
                'timestamp': asyncio.get_event_loop().time(),
                'status': 'completed'
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'processing_time_ms': (time.time() - start_time) * 1000,
                'status': 'failed',
                'timestamp': asyncio.get_event_loop().time()
            }

    except Exception as e:
        logger.error(f"Error in plugin recommendation engine: {e}")
        return {
            'success': False,
            'error': str(e),
            'status': 'failed',
            'timestamp': asyncio.get_event_loop().time()
        , 'processing_time_ms': (time.time() - start_time) * 1000}