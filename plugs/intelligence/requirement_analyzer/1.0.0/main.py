#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Requirement Analyzer - Focused Intelligence Plugin for PlugPipe

Analyzes natural language requirements and extracts structured information for intelligent
plugin composition. Extracted from monolithic mix_and_match to follow single responsibility principle.

Key Capabilities:
- Natural language requirement parsing
- Intent extraction and classification
- Domain detection and pattern recognition
- Complexity assessment
- Security requirement identification

Follows PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Uses existing LLM configuration
- Single Responsibility: Only handles requirement analysis
- Plugin-First Development: Focused, reusable component
"""

import os
import sys
import json
import logging
import asyncio
import re
import time
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict

# Add PlugPipe paths for reusing existing infrastructure
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

try:
    from shares.utils.config_loader import get_llm_config
    import openai
except ImportError as e:
    print(f"Warning: Optional dependency missing: {e}")

logger = logging.getLogger(__name__)


@dataclass
class RequirementAnalysis:
    """Analysis of natural language requirements."""
    primary_intent: str
    domain: str
    complexity_level: str
    required_capabilities: List[str]
    integration_patterns: List[str]
    security_requirements: List[str]
    data_flow_requirements: List[str]
    performance_requirements: List[str]
    scalability_requirements: List[str]


class RequirementAnalyzer:
    """
    Analyzes natural language requirements to extract structured information.

    Follows PlugPipe principles:
    - REUSE: Uses existing get_llm_config() infrastructure
    - SIMPLE: Focused on requirement analysis only
    - CONVENTION: Standard analysis patterns
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.llm_config = config.get('llm_config', {})
        self.analysis_settings = config.get('analysis_settings', {})

        # Initialize LLM configuration using PlugPipe infrastructure
        try:
            self.llm_config_full = get_llm_config(primary=True)
        except Exception as e:
            logger.warning(f"Could not load LLM config: {e}")
            self.llm_config_full = {}

        # Domain patterns for classification
        self.domain_patterns = {
            'ecommerce': ['payment', 'stripe', 'shopify', 'order', 'product', 'cart', 'checkout'],
            'healthcare': ['patient', 'medical', 'hipaa', 'health', 'clinical', 'fhir'],
            'finance': ['banking', 'investment', 'trading', 'financial', 'fintech', 'ledger'],
            'security': ['authentication', 'authorization', 'encrypt', 'secure', 'audit', 'compliance'],
            'communication': ['email', 'slack', 'teams', 'notification', 'messaging', 'chat'],
            'data': ['database', 'analytics', 'etl', 'data', 'warehouse', 'pipeline'],
            'devops': ['docker', 'kubernetes', 'ci/cd', 'deployment', 'infrastructure', 'monitoring'],
            'social': ['twitter', 'facebook', 'linkedin', 'social', 'api', 'feed'],
            'productivity': ['calendar', 'task', 'project', 'workflow', 'automation', 'schedule']
        }

        logger.info("Initialized RequirementAnalyzer with domain patterns")

    def analyze_requirements(self, request: str, context: Dict[str, Any] = None) -> RequirementAnalysis:
        """Analyze natural language requirements using pattern matching and LLM."""
        try:
            logger.info(f"Analyzing requirements: {request[:100]}...")

            if context is None:
                context = {}

            # Extract basic patterns
            primary_intent = self._extract_primary_intent(request)
            domain = self._detect_domain(request, context)
            complexity = self._assess_complexity(request, context)

            # Extract specific requirements
            capabilities = self._extract_required_capabilities(request)
            integration_patterns = self._extract_integration_patterns(request)
            security_requirements = self._extract_security_requirements(request)
            data_flow = self._extract_data_flow_requirements(request)
            performance = self._extract_performance_requirements(request)
            scalability = self._extract_scalability_requirements(request)

            analysis = RequirementAnalysis(
                primary_intent=primary_intent,
                domain=domain,
                complexity_level=complexity,
                required_capabilities=capabilities,
                integration_patterns=integration_patterns,
                security_requirements=security_requirements,
                data_flow_requirements=data_flow,
                performance_requirements=performance,
                scalability_requirements=scalability
            )

            logger.info(f"Requirements analysis completed: {analysis.primary_intent} in {analysis.domain}")
            return analysis

        except Exception as e:
            logger.error(f"Failed to analyze requirements: {e}")
            # Return basic analysis as fallback
            return RequirementAnalysis(
                primary_intent="integration",
                domain="general",
                complexity_level='moderate',
                required_capabilities=[],
                integration_patterns=[],
                security_requirements=[],
                data_flow_requirements=[],
                performance_requirements=[],
                scalability_requirements=[]
            )

    def _extract_primary_intent(self, request: str) -> str:
        """Extract the primary intent from the request."""
        request_lower = request.lower()

        intent_patterns = {
            'integrate': ['integrate', 'connect', 'combine', 'link'],
            'automate': ['automate', 'workflow', 'process', 'schedule'],
            'monitor': ['monitor', 'track', 'observe', 'watch'],
            'secure': ['secure', 'protect', 'authenticate', 'authorize'],
            'analyze': ['analyze', 'report', 'dashboard', 'metrics'],
            'transform': ['transform', 'convert', 'process', 'format'],
            'notify': ['notify', 'alert', 'message', 'email'],
            'store': ['store', 'save', 'persist', 'database']
        }

        for intent, keywords in intent_patterns.items():
            if any(keyword in request_lower for keyword in keywords):
                return intent

        return 'integration'  # Default intent

    def _detect_domain(self, request: str, context: Dict[str, Any] = None) -> str:
        """Detect the domain from the request and context."""
        if context and 'domain' in context:
            return context['domain']

        request_lower = request.lower()

        for domain, keywords in self.domain_patterns.items():
            if any(keyword in request_lower for keyword in keywords):
                return domain

        return 'general'

    def _assess_complexity(self, request: str, context: Dict[str, Any] = None) -> str:
        """Assess the complexity level of the request."""
        if context and 'complexity_level' in context:
            return context['complexity_level']

        request_lower = request.lower()

        enterprise_indicators = [
            'enterprise', 'compliance', 'governance', 'audit', 'soc2', 'gdpr',
            'scalable', 'high availability', 'load balancing', 'distributed'
        ]

        complex_indicators = [
            'multi-step', 'workflow', 'pipeline', 'orchestration', 'multiple',
            'advanced', 'custom', 'integration', 'api'
        ]

        simple_indicators = [
            'simple', 'basic', 'quick', 'easy', 'straightforward', 'minimal'
        ]

        if any(indicator in request_lower for indicator in enterprise_indicators):
            return 'enterprise'
        elif any(indicator in request_lower for indicator in complex_indicators):
            return 'complex'
        elif any(indicator in request_lower for indicator in simple_indicators):
            return 'simple'
        else:
            return 'moderate'

    def _extract_required_capabilities(self, request: str) -> List[str]:
        """Extract required capabilities from the request."""
        request_lower = request.lower()
        capabilities = []

        capability_patterns = {
            'api_integration': ['api', 'rest', 'graphql', 'webhook'],
            'data_processing': ['data', 'etl', 'transform', 'parse'],
            'authentication': ['auth', 'login', 'oauth', 'jwt'],
            'notification': ['notify', 'alert', 'email', 'sms'],
            'file_handling': ['file', 'upload', 'download', 'storage'],
            'database': ['database', 'sql', 'nosql', 'store'],
            'monitoring': ['monitor', 'log', 'metric', 'health'],
            'security': ['encrypt', 'secure', 'validate', 'sanitize'],
            'scheduling': ['schedule', 'cron', 'timer', 'interval'],
            'reporting': ['report', 'analytics', 'dashboard', 'chart']
        }

        for capability, keywords in capability_patterns.items():
            if any(keyword in request_lower for keyword in keywords):
                capabilities.append(capability)

        return capabilities

    def _extract_integration_patterns(self, request: str) -> List[str]:
        """Extract integration patterns from the request."""
        request_lower = request.lower()
        patterns = []

        pattern_keywords = {
            'event_driven': ['event', 'trigger', 'webhook', 'callback'],
            'batch_processing': ['batch', 'bulk', 'scheduled', 'periodic'],
            'real_time': ['real-time', 'live', 'streaming', 'immediate'],
            'request_response': ['request', 'response', 'synchronous', 'api'],
            'pub_sub': ['publish', 'subscribe', 'message', 'queue'],
            'pipeline': ['pipeline', 'workflow', 'chain', 'sequence']
        }

        for pattern, keywords in pattern_keywords.items():
            if any(keyword in request_lower for keyword in keywords):
                patterns.append(pattern)

        return patterns

    def _extract_security_requirements(self, request: str) -> List[str]:
        """Extract security requirements from the request."""
        request_lower = request.lower()
        requirements = []

        security_keywords = {
            'encryption': ['encrypt', 'ssl', 'tls', 'crypto'],
            'authentication': ['auth', 'login', 'credential'],
            'authorization': ['permission', 'role', 'access'],
            'compliance': ['compliance', 'gdpr', 'hipaa', 'soc2'],
            'audit': ['audit', 'log', 'trail', 'tracking'],
            'validation': ['validate', 'sanitize', 'input', 'xss']
        }

        for requirement, keywords in security_keywords.items():
            if any(keyword in request_lower for keyword in keywords):
                requirements.append(requirement)

        return requirements

    def _extract_data_flow_requirements(self, request: str) -> List[str]:
        """Extract data flow requirements from the request."""
        request_lower = request.lower()
        requirements = []

        if 'transform' in request_lower or 'convert' in request_lower:
            requirements.append('data_transformation')
        if 'validate' in request_lower or 'check' in request_lower:
            requirements.append('data_validation')
        if 'store' in request_lower or 'persist' in request_lower:
            requirements.append('data_persistence')
        if 'sync' in request_lower or 'synchronize' in request_lower:
            requirements.append('data_synchronization')

        return requirements

    def _extract_performance_requirements(self, request: str) -> List[str]:
        """Extract performance requirements from the request."""
        request_lower = request.lower()
        requirements = []

        if any(word in request_lower for word in ['fast', 'quick', 'speed', 'performance']):
            requirements.append('high_performance')
        if any(word in request_lower for word in ['cache', 'caching', 'memory']):
            requirements.append('caching')
        if any(word in request_lower for word in ['async', 'asynchronous', 'non-blocking']):
            requirements.append('asynchronous_processing')

        return requirements

    def _extract_scalability_requirements(self, request: str) -> List[str]:
        """Extract scalability requirements from the request."""
        request_lower = request.lower()
        requirements = []

        if any(word in request_lower for word in ['scale', 'scalable', 'scaling']):
            requirements.append('horizontal_scaling')
        if any(word in request_lower for word in ['load', 'traffic', 'volume']):
            requirements.append('load_handling')
        if any(word in request_lower for word in ['distributed', 'cluster', 'multi-node']):
            requirements.append('distributed_processing')

        return requirements


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for requirement analysis.
    Follows PlugPipe's standard plugin interface.
    """
    try:
        operation = cfg.get('operation')
        if not operation:
            return {
                'success': False,
                'error': 'Missing required operation parameter',
                'timestamp': time.time()
            }

        analyzer = RequirementAnalyzer(cfg)

        if operation == 'analyze_requirements':
            natural_language_request = cfg.get('natural_language_request')
            if not natural_language_request:
                return {'success': False, 'error': 'Missing natural_language_request parameter'}

            context = cfg.get('context', {})
            analysis = analyzer.analyze_requirements(natural_language_request, context)

            return {
                'success': True,
                'operation_completed': operation,
                'requirement_analysis': asdict(analysis),
                'timestamp': time.time(),
                'status': 'completed'
            }

        elif operation == 'extract_intent':
            natural_language_request = cfg.get('natural_language_request')
            if not natural_language_request:
                return {'success': False, 'error': 'Missing natural_language_request parameter'}

            intent = analyzer._extract_primary_intent(natural_language_request)
            return {
                'success': True,
                'operation_completed': operation,
                'extracted_intent': intent,
                'timestamp': time.time()
            }

        elif operation == 'identify_patterns':
            natural_language_request = cfg.get('natural_language_request')
            if not natural_language_request:
                return {'success': False, 'error': 'Missing natural_language_request parameter'}

            patterns = analyzer._extract_integration_patterns(natural_language_request)
            return {
                'success': True,
                'operation_completed': operation,
                'identified_patterns': patterns,
                'timestamp': time.time()
            }

        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'timestamp': time.time()
            }

    except Exception as e:
        logger.error(f"Error in requirement analyzer: {e}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': asyncio.get_event_loop().time()
        }