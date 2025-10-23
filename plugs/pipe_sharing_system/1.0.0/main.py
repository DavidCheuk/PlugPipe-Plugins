#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Pipe Sharing System Plugin

Enterprise pipe sharing orchestrator that coordinates registry plugins 
for comprehensive pipe distribution and collaboration workflows.

Following PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Orchestrates existing registry plugins
- GRACEFUL DEGRADATION: Works with available registry components
- SIMPLICITY BY TRADITION: Standard sharing/distribution patterns
- DEFAULT TO CREATING PLUGINS: Coordinates plugins, doesn't reimplement

This plugin coordinates existing registry infrastructure:
📦 Registry Management - Uses plugin_registry_scanner for pipe discovery
🌐 Web Interface - Coordinates Registry Web Server Plugin for sharing UI  
📊 Reporting - Uses pp_registry_comprehensive_reporter for analytics
💾 Database - Coordinates database_plugin_registry for persistence
🔍 Universal Scanning - Uses universal_registry_scanner for broad discovery
"""

import asyncio
import logging
import importlib.util
from typing import Dict, Any
from datetime import datetime, timezone

logger = logging.getLogger(__name__)

class PipeSharingOrchestrator:
    """Orchestrates existing registry plugins for pipe sharing."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.registry_plugins = {}
        self._load_registry_plugins()
        logger.info("Pipe Sharing System initialized")
    
    def _load_registry_plugins(self):
        """Load available registry plugins."""
        plugins_to_load = [
            ('plugin_registry_scanner', 'plugs/core/plugin_registry_scanner/1.0.0/main.py'),
            ('universal_registry_scanner', 'plugs/core/universal_registry_scanner/1.0.0/main.py'),
            ('pp_registry_comprehensive_reporter', 'plugs/governance/pp_registry_comprehensive_reporter/1.0.0/main.py')
        ]
        
        for name, path in plugins_to_load:
            try:
                spec = importlib.util.spec_from_file_location(name, path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.registry_plugins[name] = module
                    logger.info(f"Loaded registry plugin: {name}")
            except Exception as e:
                logger.warning(f"Could not load {name}: {e}")
    
    async def share_pipes(self, sharing_request: Dict[str, Any]) -> Dict[str, Any]:
        """Share pipes using orchestrated registry plugins."""
        action = sharing_request.get('action', 'list_shareable')
        
        if action == 'list_shareable':
            # Use registry scanner to find shareable pipes
            if 'plugin_registry_scanner' in self.registry_plugins:
                scanner = self.registry_plugins['plugin_registry_scanner']
                result = await scanner.process({'scan_type': 'pipes'}, self.config)
                return {
                    'success': True,
                    'shareable_pipes': result.get('pipes', []),
                    'message': 'Found shareable pipes using registry scanner'
                }
            
            return {
                'success': True,
                'shareable_pipes': [],
                'message': 'Fallback mode - no registry scanner available'
            }
        
        elif action == 'generate_share_report':
            # Use comprehensive reporter for sharing analytics
            if 'pp_registry_comprehensive_reporter' in self.registry_plugins:
                reporter = self.registry_plugins['pp_registry_comprehensive_reporter']
                result = await reporter.process({'report_type': 'sharing_analytics'}, self.config)
                return {
                    'success': True,
                    'sharing_report': result,
                    'message': 'Generated sharing report using comprehensive reporter'
                }
        
        return {
            'success': False,
            'error': f'Unknown sharing action: {action}'
        }

sharing_orchestrator = None

def process(context=None, config=None):
    """
    ULTIMATE FIX: Sync wrapper for pipe sharing system plugin.

    This function provides synchronous access to the async pipe sharing
    functionality while maintaining compatibility with PlugPipe framework expectations.

    Args:
        context: Request context (dict) - Can be first parameter for single-param calls
        config: Configuration parameters (dict) - Optional second parameter

    Returns:
        dict: Plugin response with success status and results
    """
    # Handle dual parameter calling patterns
    if context is None and config is None:
        # No parameters provided
        ctx = {}
        cfg = {}
    elif config is None:
        # Single parameter - determine if it's context or config
        if isinstance(context, dict):
            if 'action' in context or 'pipe_filters' in context:
                # Looks like context
                ctx = context
                cfg = {}
            else:
                # Assume it's config
                ctx = {}
                cfg = context
        else:
            ctx = {}
            cfg = {}
    else:
        # Both parameters provided
        ctx = context if context else {}
        cfg = config if config else {}

    # Run the async implementation synchronously
    try:
        loop = asyncio.get_event_loop()
        if loop.is_running():
            # If loop is already running, use thread executor
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor() as executor:
                future = executor.submit(_run_async_process_sync, ctx, cfg)
                return future.result(timeout=30)  # 30 second timeout
        else:
            # No loop running, create one
            return loop.run_until_complete(_run_async_process(ctx, cfg))
    except RuntimeError:
        # Fallback to thread executor
        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(_run_async_process_sync, ctx, cfg)
            return future.result(timeout=30)
    except Exception as e:
        return {
            'success': False,
            'error': f'Pipe sharing system execution error: {str(e)}',
            'message': 'Plugin execution failed'
        }

async def _run_async_process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Internal async implementation for pipe sharing system."""
    global sharing_orchestrator

    if sharing_orchestrator is None:
        sharing_orchestrator = PipeSharingOrchestrator(config)

    try:
        result = await sharing_orchestrator.share_pipes(context)
        return {
            'success': result['success'],
            'message': 'Pipe sharing orchestration completed',
            'result': result
        }
    except Exception as e:
        return {
            'success': False,
            'error': str(e),
            'message': 'Pipe sharing orchestration failed'
        }

def _run_async_process_sync(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous runner for async pipe sharing process."""
    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        try:
            return loop.run_until_complete(_run_async_process(context, config))
        finally:
            loop.close()
    except Exception as e:
        return {
            'success': False,
            'error': f'Async execution error: {str(e)}',
            'message': 'Failed to execute async pipe sharing system'
        }

plug_metadata = {
    "name": "pipe_sharing_system",
    "version": "1.0.0", 
    "description": "Enterprise pipe sharing orchestrator coordinating registry plugins for comprehensive distribution and collaboration",
    "author": "PlugPipe Registry Team",
    "tags": ["sharing", "registry", "distribution", "collaboration"],
    "category": "registry",
    "status": "stable",
    "capabilities": ["pipe_sharing", "registry_orchestration", "distribution_management"]
}
