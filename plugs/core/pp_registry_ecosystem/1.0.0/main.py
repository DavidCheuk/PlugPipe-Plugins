# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
PlugPipe Registry Ecosystem Orchestrator

Central orchestrator for the complete PlugPipe registry ecosystem, coordinating
multiple registry-related plugins to provide comprehensive registry management.

Following PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Orchestrates existing registry plugins
- GRACEFUL DEGRADATION: Falls back when specific registry plugins unavailable
- SIMPLICITY BY TRADITION: Standard registry coordination patterns
- DEFAULT TO CREATING PLUGINS: Coordinates plugins, doesn't reimplement

Orchestrates:
- plugin_registry_scanner: Core plugin discovery and scanning
- universal_registry_scanner: Universal registry scanning capabilities  
- pp_registry_comprehensive_reporter: Comprehensive reporting system
- database_plugin_registry: Database registry population
- pipe_sharing_system: Registry-based pipe sharing
"""

import os
import sys
import json
import logging
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add PlugPipe to path
sys.path.insert(0, get_plugpipe_root())

logger = logging.getLogger(__name__)

try:
    from shares.loader import pp
except ImportError:
    # Fallback for testing
    def pp(plugin_name: str):
        logger.warning(f"pp() function unavailable, using mock for {plugin_name}")
        class MockPlugin:
            def process(self, context, config):
                return {"success": True, "mock": True, "plugin": plugin_name}
        return MockPlugin()

class RegistryEcosystemOrchestrator:
    """Orchestrates the complete PlugPipe registry ecosystem"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        
        # Registry plugins to orchestrate
        self.registry_plugins = {
            'scanner': 'plugin_registry_scanner',
            'universal_scanner': 'universal_registry_scanner', 
            'reporter': 'pp_registry_comprehensive_reporter',
            'database_registry': 'database_plugin_registry',
            'pipe_sharing': 'pipe_sharing_system'
        }
        
    def orchestrate_full_ecosystem(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate the complete registry ecosystem"""
        
        ecosystem_results = {
            'timestamp': datetime.utcnow().isoformat(),
            'ecosystem_status': 'running',
            'orchestrated_components': {},
            'summary': {},
            'errors': []
        }
        
        # Step 1: Core Registry Scanning
        scanner_result = self._orchestrate_registry_scanning(context)
        ecosystem_results['orchestrated_components']['scanning'] = scanner_result
        
        # Step 2: Universal Registry Operations
        universal_result = self._orchestrate_universal_registry(context)
        ecosystem_results['orchestrated_components']['universal'] = universal_result
        
        # Step 3: Comprehensive Reporting
        reporting_result = self._orchestrate_reporting(context)
        ecosystem_results['orchestrated_components']['reporting'] = reporting_result
        
        # Step 4: Database Registry Management
        database_result = self._orchestrate_database_registry(context)
        ecosystem_results['orchestrated_components']['database'] = database_result
        
        # Step 5: Pipe Sharing System
        sharing_result = self._orchestrate_pipe_sharing(context)
        ecosystem_results['orchestrated_components']['sharing'] = sharing_result
        
        # Generate ecosystem summary
        ecosystem_results['summary'] = self._generate_ecosystem_summary(ecosystem_results)
        
        return ecosystem_results
    
    def _orchestrate_registry_scanning(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate core registry scanning functionality"""
        
        try:
            scanner_plugin = pp('plugin_registry_scanner')
            scanner_context = {
                **context,
                'include_metadata': True,
                'format': 'json'
            }
            
            result = scanner_plugin.process(scanner_context, self.config)
            return {
                'status': 'success',
                'plugin': 'plugin_registry_scanner',
                'result': result
            }
            
        except Exception as e:
            self.logger.error(f"Registry scanning orchestration failed: {e}")
            return {
                'status': 'error',
                'plugin': 'plugin_registry_scanner',
                'error': str(e),
                'fallback': 'Basic registry scanning unavailable'
            }
    
    def _orchestrate_universal_registry(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate universal registry scanning"""
        
        try:
            universal_plugin = pp('universal_registry_scanner')
            result = universal_plugin.process(context, self.config)
            return {
                'status': 'success', 
                'plugin': 'universal_registry_scanner',
                'result': result
            }
            
        except Exception as e:
            self.logger.warning(f"Universal registry scanning failed: {e}")
            return {
                'status': 'fallback',
                'plugin': 'universal_registry_scanner',
                'error': str(e),
                'fallback': 'Using core scanning only'
            }
    
    def _orchestrate_reporting(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate comprehensive registry reporting"""
        
        try:
            reporter_plugin = pp('pp_registry_comprehensive_reporter')
            reporting_context = {
                **context,
                'output_format': context.get('output_format', 'json'),
                'include_summary': True
            }
            
            result = reporter_plugin.process(reporting_context, self.config)
            return {
                'status': 'success',
                'plugin': 'pp_registry_comprehensive_reporter', 
                'result': result
            }
            
        except Exception as e:
            self.logger.warning(f"Registry reporting failed: {e}")
            return {
                'status': 'fallback',
                'plugin': 'pp_registry_comprehensive_reporter',
                'error': str(e),
                'fallback': 'Basic reporting only'
            }
    
    def _orchestrate_database_registry(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate database registry population"""
        
        try:
            db_registry_plugin = pp('database_plugin_registry')
            result = db_registry_plugin.process(context, self.config)
            return {
                'status': 'success',
                'plugin': 'database_plugin_registry',
                'result': result
            }
            
        except Exception as e:
            self.logger.warning(f"Database registry failed: {e}")
            return {
                'status': 'fallback',
                'plugin': 'database_plugin_registry', 
                'error': str(e),
                'fallback': 'Registry database not updated'
            }
    
    def _orchestrate_pipe_sharing(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Orchestrate pipe sharing system"""
        
        try:
            sharing_plugin = pp('pipe_sharing_system')
            result = sharing_plugin.process(context, self.config)
            return {
                'status': 'success',
                'plugin': 'pipe_sharing_system',
                'result': result
            }
            
        except Exception as e:
            self.logger.warning(f"Pipe sharing orchestration failed: {e}")
            return {
                'status': 'fallback',
                'plugin': 'pipe_sharing_system',
                'error': str(e),
                'fallback': 'Pipe sharing disabled'
            }
    
    def _generate_ecosystem_summary(self, ecosystem_results: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of ecosystem orchestration"""
        
        components = ecosystem_results['orchestrated_components']
        
        successful_components = [
            name for name, result in components.items() 
            if result.get('status') == 'success'
        ]
        
        fallback_components = [
            name for name, result in components.items() 
            if result.get('status') == 'fallback'
        ]
        
        error_components = [
            name for name, result in components.items()
            if result.get('status') == 'error'  
        ]
        
        return {
            'total_components': len(components),
            'successful_components': len(successful_components),
            'fallback_components': len(fallback_components),
            'error_components': len(error_components),
            'success_rate': len(successful_components) / len(components) if components else 0,
            'ecosystem_health': 'healthy' if len(error_components) == 0 else 'degraded',
            'component_status': {
                'successful': successful_components,
                'fallback': fallback_components,
                'errors': error_components
            }
        }

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    PlugPipe entry point for Registry Ecosystem Orchestrator
    
    Orchestrates the complete PlugPipe registry ecosystem including:
    - Core registry scanning
    - Universal registry operations  
    - Comprehensive reporting
    - Database registry management
    - Pipe sharing systems
    """
    
    try:
        orchestrator = RegistryEcosystemOrchestrator(cfg)
        
        operation = ctx.get('operation', 'full_ecosystem')
        
        if operation == 'full_ecosystem':
            return orchestrator.orchestrate_full_ecosystem(ctx)
        else:
            return {
                'status': 'error',
                'error': f'Unsupported operation: {operation}',
                'supported_operations': ['full_ecosystem']
            }
            
    except Exception as e:
        logger.error(f"Registry ecosystem orchestration failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__
        }

# Plugin metadata
plug_metadata = {
    "name": "pp_registry_ecosystem",
    "version": "1.0.0", 
    "description": "Central orchestrator for complete PlugPipe registry ecosystem",
    "author": "PlugPipe Core Team",
    "license": "MIT",
    "category": "core",
    "tags": ["registry", "ecosystem", "orchestrator", "core"],
    "dependencies": [
        "plugin_registry_scanner",
        "universal_registry_scanner", 
        "pp_registry_comprehensive_reporter",
        "database_plugin_registry",
        "pipe_sharing_system"
    ],
    "type": "orchestration"
}