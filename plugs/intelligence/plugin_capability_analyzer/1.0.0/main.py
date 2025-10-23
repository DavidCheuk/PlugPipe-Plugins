#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Plugin Capability Analyzer - Focused Intelligence Plugin for PlugPipe

Analyzes and indexes plugin capabilities for intelligent composition.
Extracted from monolithic mix_and_match to follow PlugPipe's single responsibility principle.

Key Capabilities:
- Plugin capability discovery and analysis
- Capability indexing and search
- Metadata extraction and caching
- Integration point identification

Follows PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Uses existing loader and discovery systems
- Single Responsibility: Only handles capability analysis
- Plugin-First Development: Focused, reusable component
"""

import os
import time
import sys
import json
import yaml
import logging
import asyncio
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field, asdict
from pathlib import Path

# Add PlugPipe paths for reusing existing infrastructure
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

try:
    from shares.loader import discover_local_plugins, pp
except ImportError as e:
    print(f"Warning: PlugPipe infrastructure not available: {e}")

logger = logging.getLogger(__name__)


@dataclass
class PluginCapability:
    """Represents a plugin capability for intelligent combination."""
    plugin_name: str
    version: str
    category: str
    capabilities: List[str]
    input_schema: Dict[str, Any]
    output_schema: Dict[str, Any]
    revolutionary_features: List[str] = field(default_factory=list)
    integration_points: List[str] = field(default_factory=list)
    security_features: List[str] = field(default_factory=list)


class PluginCapabilityAnalyzer:
    """
    Analyzes and indexes plugin capabilities using existing PlugPipe infrastructure.

    Follows PlugPipe principles:
    - REUSE: Uses discover_local_plugins() and pp() functions
    - SIMPLE: Focused on single responsibility
    - CONVENTION: Standard plugin patterns
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.analysis_settings = config.get('analysis_settings', {})
        self.cache_metadata = self.analysis_settings.get('cache_metadata', True)
        self.scan_depth = self.analysis_settings.get('scan_depth', 'comprehensive')
        self.include_experimental = self.analysis_settings.get('include_experimental', False)

        self.capability_index = {}
        self.domain_patterns = {}
        self.security_patterns = {}

        logger.info(f"Initialized PluginCapabilityAnalyzer with scan_depth: {self.scan_depth}")

    async def analyze_plugin(self, plugin_fqn: str) -> Optional[PluginCapability]:
        """
        Analyze a single plugin's capabilities.
        REUSES: PlugPipe's pp() function for plugin discovery
        """
        try:
            # Use existing PlugPipe infrastructure
            plugin_info = pp(plugin_fqn)
            if not plugin_info:
                logger.warning(f"Plugin not found: {plugin_fqn}")
                return None

            # Extract capability information from plugin metadata
            plugin_path = plugin_info.get('path', '')
            version = plugin_info.get('version', '1.0.0')

            capability = self._analyze_plugin_capabilities(plugin_fqn, version, plugin_path)
            return capability

        except Exception as e:
            logger.error(f"Error analyzing plugin {plugin_fqn}: {e}")
            return None

    async def _analyze_plugin_capabilities(self, fqn: str, version: str, path: str) -> PluginCapability:
        """
        Extract detailed capability information from plugin.
        REUSES: PlugPipe's standard plugin.yaml structure
        """
        try:
            # Load plugin.yaml using PlugPipe conventions
            plugin_yaml_path = Path(path) / "plug.yaml"
            if not plugin_yaml_path.exists():
                # Fallback to legacy naming
                plugin_yaml_path = Path(path) / "plugin.yaml"

            if plugin_yaml_path.exists():
                with open(plugin_yaml_path, 'r') as f:
                    metadata = yaml.safe_load(f)
            else:
                metadata = {}

            # Extract capabilities following PlugPipe conventions
            capabilities = []
            if 'revolutionary_capabilities' in metadata:
                capabilities.extend(metadata['revolutionary_capabilities'])
            if 'capabilities' in metadata:
                capabilities.extend(metadata['capabilities'])
            if 'tags' in metadata:
                capabilities.extend([f"tag:{tag}" for tag in metadata['tags']])

            # Extract schemas
            input_schema = metadata.get('input_schema', {})
            output_schema = metadata.get('output_schema', {})

            # Determine category from path structure (PlugPipe convention)
            path_parts = Path(path).parts
            category = "general"
            if len(path_parts) >= 2:
                category = path_parts[-3]  # e.g., "security", "intelligence", etc.

            # Extract integration points
            integration_points = []
            if 'integrates_with' in metadata:
                integration_points = metadata['integrates_with']

            # Extract security features
            security_features = []
            if category == 'security' or 'security' in metadata.get('tags', []):
                security_features = metadata.get('security_features', [])
                if 'universal_security_interface' in metadata:
                    security_features.append('universal_security_interface')

            return PluginCapability(
                plugin_name=fqn,
                version=version,
                category=category,
                capabilities=capabilities,
                input_schema=input_schema,
                output_schema=output_schema,
                revolutionary_features=metadata.get('revolutionary_capabilities', []),
                integration_points=integration_points,
                security_features=security_features
            )

        except Exception as e:
            logger.error(f"Error analyzing capabilities for {fqn}: {e}")
            return PluginCapability(
                plugin_name=fqn,
                version=version,
                category="unknown",
                capabilities=[],
                input_schema={},
                output_schema={}
            )

    async def build_capability_index(self) -> Dict[str, Any]:
        """
        Build comprehensive capability index.
        REUSES: PlugPipe's discover_local_plugins() function
        """
        try:
            logger.info("Building capability index using PlugPipe discovery...")

            # Use existing PlugPipe plugin discovery
            discovered_plugins = discover_local_plugins()

            # Handle the case where discover_local_plugins returns a tuple
            if isinstance(discovered_plugins, tuple):
                discovered_plugins = discovered_plugins[0] if discovered_plugins else []

            index = {
                'plugins': {},
                'capabilities': {},
                'categories': {},
                'integration_points': {},
                'security_features': {}
            }

            for plugin_info in discovered_plugins:
                # Handle tuple format (fqn, version, path)
                if isinstance(plugin_info, tuple) and len(plugin_info) >= 3:
                    fqn, version, path = plugin_info[0], plugin_info[1], plugin_info[2]
                elif isinstance(plugin_info, dict):
                    fqn = plugin_info.get('fqn', '')
                    version = plugin_info.get('version', '1.0.0')
                    path = plugin_info.get('path', '')
                else:
                    continue

                if not fqn:
                    continue

                # Skip experimental plugins if not requested
                # Note: We can't check tags here since we only have tuple data
                # This would require loading the plugin.yaml file

                capability = self._analyze_plugin_capabilities(fqn, version, path)
                if capability:
                    # Index by plugin name - ensure capability is properly serializable
                    try:
                        index['plugins'][fqn] = asdict(capability)
                    except Exception as e:
                        logger.warning(f"Could not serialize capability for {fqn}: {e}")
                        continue

                    # Index by capabilities - ensure strings only
                    for cap in capability.capabilities:
                        cap_str = str(cap)  # Ensure it's a string
                        if cap_str not in index['capabilities']:
                            index['capabilities'][cap_str] = []
                        index['capabilities'][cap_str].append(fqn)

                    # Index by category - ensure string
                    category_str = str(capability.category)
                    if category_str not in index['categories']:
                        index['categories'][category_str] = []
                    index['categories'][category_str].append(fqn)

                    # Index by integration points - ensure strings
                    for integration in capability.integration_points:
                        integration_str = str(integration)
                        if integration_str not in index['integration_points']:
                            index['integration_points'][integration_str] = []
                        index['integration_points'][integration_str].append(fqn)

                    # Index security features - ensure strings
                    for security_feature in capability.security_features:
                        feature_str = str(security_feature)
                        if feature_str not in index['security_features']:
                            index['security_features'][feature_str] = []
                        index['security_features'][feature_str].append(fqn)

            self.capability_index = index
            logger.info(f"Built capability index with {len(index['plugins'])} plugins")
            return index

        except Exception as e:
            logger.error(f"Error building capability index: {e}")
            return {'success': False, 'error': str(e), 'processing_time_ms': (time.time() - start_time) * 1000}

    async def search_capabilities(self, search_query: str) -> List[str]:
        """Search for plugins with specific capabilities."""
        try:
            if not self.capability_index:
                self.build_capability_index()

            matching_plugins = []
            query_lower = search_query.lower()

            # Search in capabilities
            for capability, plugins in self.capability_index.get('capabilities', {}).items():
                if query_lower in capability.lower():
                    matching_plugins.extend(plugins)

            # Search in categories
            for category, plugins in self.capability_index.get('categories', {}).items():
                if query_lower in category.lower():
                    matching_plugins.extend(plugins)

            # Remove duplicates and return
            return list(set(matching_plugins))

        except Exception as e:
            logger.error(f"Error searching capabilities: {e}")
            return []

    async def get_plugin_metadata(self, plugin_fqn: str) -> Dict[str, Any]:
        """Get detailed metadata for a specific plugin."""
        try:
            if not self.capability_index:
                self.build_capability_index()

            return self.capability_index.get('plugins', {}).get(plugin_fqn, {})

        except Exception as e:
            logger.error(f"Error getting plugin metadata: {e}")
            return {'error': 'Unknown', 'processing_time_ms': (time.time() - start_time) * 1000}


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for plugin capability analysis.
    Follows PlugPipe's standard plugin interface.
    """
    try:
        operation = cfg.get('operation')
        if not operation:
            return {
                'success': False,
                'error': 'Missing required operation parameter',
                'timestamp': asyncio.get_event_loop().time()
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        analyzer = PluginCapabilityAnalyzer(cfg)

        if operation == 'analyze_plugin':
            plugin_fqn = cfg.get('plugin_fqn')
            if not plugin_fqn:
                return {'success': False, 'error': 'Missing plugin_fqn parameter', 'processing_time_ms': (time.time() - start_time) * 1000}

            capability = analyzer.analyze_plugin(plugin_fqn)
            return {
                'success': True,
                'operation_completed': operation,
                'plugin_capabilities': [asdict(capability)] if capability else [],
                'timestamp': asyncio.get_event_loop().time(),
                'status': 'completed'
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        elif operation == 'build_capability_index':
            index = analyzer.build_capability_index()
            return {
                'success': True,
                'operation_completed': operation,
                'capability_index': index,
                'timestamp': asyncio.get_event_loop().time(),
                'status': 'completed'
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        elif operation == 'search_capabilities':
            search_query = cfg.get('search_query', '')
            matching_plugins = analyzer.search_capabilities(search_query)
            return {
                'success': True,
                'operation_completed': operation,
                'matching_plugins': matching_plugins,
                'timestamp': asyncio.get_event_loop().time()
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        elif operation == 'get_plugin_metadata':
            plugin_fqn = cfg.get('plugin_fqn')
            if not plugin_fqn:
                return {'success': False, 'error': 'Missing plugin_fqn parameter', 'processing_time_ms': (time.time() - start_time) * 1000}

            metadata = analyzer.get_plugin_metadata(plugin_fqn)
            return {
                'success': True,
                'operation_completed': operation,
                'metadata': metadata,
                'timestamp': asyncio.get_event_loop().time()
            , 'processing_time_ms': (time.time() - start_time) * 1000}

        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'processing_time_ms': (time.time() - start_time) * 1000,
                'timestamp': asyncio.get_event_loop().time()
            }

    except Exception as e:
        logger.error(f"Error in plugin capability analyzer: {e}")
        return {
            'success': False,
            'error': str(e),
            'timestamp': asyncio.get_event_loop().time()
        , 'processing_time_ms': (time.time() - start_time) * 1000}