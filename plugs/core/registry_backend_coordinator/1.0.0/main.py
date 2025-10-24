#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Registry Backend Coordinator Plugin

Extracted from MultiBackendRegistryService to follow Plugin-First Development principle.
Handles complex coordination logic between multiple registry backends.
"""

import time
from typing import Dict, List, Any, Optional, Tuple

def process(plugin_ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Plugin entry point for registry backend coordination.

    Args:
        plugin_ctx: Plugin execution context
        config: Configuration including operation, backends, and parameters

    Returns:
        Coordination results with status and processed data
    """
    start_time = time.time()

    try:
        operation = config.get('operation', 'coordinate_backends')
        backends = config.get('backends', [])

        if operation == 'coordinate_backends':
            return coordinate_multiple_backends(backends, config, start_time)
        elif operation == 'prioritize_results':
            return prioritize_backend_results(config.get('results', []), config.get('priorities', {}), start_time)
        elif operation == 'handle_fallback':
            return handle_backend_fallback(backends, config, start_time)
        elif operation == 'aggregate_search':
            return aggregate_search_results(backends, config.get('query', ''), config, start_time)
        elif operation == 'deduplicate':
            return deduplicate_plugin_data(config.get('plugin_data', []), start_time)
        else:
            return {
                'status': 'error',
                'error': f'Unknown operation: {operation}',
                'processing_time_ms': (time.time() - start_time) * 1000
            }

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'processing_time_ms': (time.time() - start_time) * 1000
        }

def coordinate_multiple_backends(backends: List[Any], config: Dict[str, Any], start_time: float) -> Dict[str, Any]:
    """Coordinate operations across multiple registry backends."""
    try:
        results = []
        backend_status = {}

        for backend in backends:
            backend_name = type(backend).__name__
            try:
                # Attempt to get plugins from backend
                if hasattr(backend, 'list_plugs'):
                    backend_result = backend.list_plugs(
                        cursor=config.get('cursor'),
                        limit=config.get('limit', 1000)
                    )
                    results.append({
                        'backend': backend_name,
                        'result': backend_result,
                        'status': 'success'
                    })
                    backend_status[backend_name] = 'success'
                else:
                    backend_status[backend_name] = 'unsupported'

            except Exception as e:
                backend_status[backend_name] = f'error: {str(e)}'

        return {
            'status': 'success' if results else 'partial',
            'coordinated_results': results,
            'backend_status': backend_status,
            'processing_time_ms': (time.time() - start_time) * 1000
        }

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'processing_time_ms': (time.time() - start_time) * 1000
        }

def prioritize_backend_results(results: List[Dict], priorities: Dict[str, int], start_time: float) -> Dict[str, Any]:
    """Prioritize results based on backend priorities."""
    try:
        # Sort results by backend priority
        prioritized = sorted(
            results,
            key=lambda x: priorities.get(x.get('backend', ''), 0),
            reverse=True
        )

        return {
            'status': 'success',
            'prioritized_results': prioritized,
            'processing_time_ms': (time.time() - start_time) * 1000
        }

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'processing_time_ms': (time.time() - start_time) * 1000
        }

def handle_backend_fallback(backends: List[Any], config: Dict[str, Any], start_time: float) -> Dict[str, Any]:
    """Handle fallback logic when primary backends fail."""
    try:
        primary_backend = backends[0] if backends else None
        fallback_backends = backends[1:] if len(backends) > 1 else []

        # Try primary backend first
        if primary_backend:
            try:
                result = primary_backend.list_plugs(
                    cursor=config.get('cursor'),
                    limit=config.get('limit', 1000)
                )
                return {
                    'status': 'success',
                    'result': result,
                    'backend_used': 'primary',
                    'processing_time_ms': (time.time() - start_time) * 1000
                }
            except Exception as primary_error:
                # Try fallback backends
                for i, fallback in enumerate(fallback_backends):
                    try:
                        result = fallback.list_plugs(
                            cursor=config.get('cursor'),
                            limit=config.get('limit', 1000)
                        )
                        return {
                            'status': 'success',
                            'result': result,
                            'backend_used': f'fallback_{i}',
                            'primary_error': str(primary_error),
                            'processing_time_ms': (time.time() - start_time) * 1000
                        }
                    except Exception:
                        continue

        return {
            'status': 'error',
            'error': 'All backends failed',
            'processing_time_ms': (time.time() - start_time) * 1000
        }

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'processing_time_ms': (time.time() - start_time) * 1000
        }

def aggregate_search_results(backends: List[Any], query: str, config: Dict[str, Any], start_time: float) -> Dict[str, Any]:
    """Aggregate search results from multiple backends."""
    try:
        aggregated_results = []

        for backend in backends:
            if hasattr(backend, 'search_plugs'):
                try:
                    search_result = backend.search_plugs(
                        query=query,
                        cursor=config.get('cursor'),
                        limit=config.get('limit', 50)
                    )
                    if isinstance(search_result, tuple):
                        plugins, cursor = search_result
                        aggregated_results.extend(plugins)
                    else:
                        aggregated_results.extend(search_result)
                except Exception:
                    continue

        return {
            'status': 'success',
            'aggregated_results': aggregated_results,
            'total_results': len(aggregated_results),
            'processing_time_ms': (time.time() - start_time) * 1000
        }

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'processing_time_ms': (time.time() - start_time) * 1000
        }

def deduplicate_plugin_data(plugin_data: List[Dict], start_time: float) -> Dict[str, Any]:
    """Deduplicate plugin data across multiple backends."""
    try:
        seen = set()
        deduplicated = []

        for plugin in plugin_data:
            plugin_id = (plugin.get('name'), plugin.get('version'))
            if plugin_id not in seen and plugin_id[0]:  # Valid name required
                seen.add(plugin_id)
                deduplicated.append(plugin)

        return {
            'status': 'success',
            'deduplicated_data': deduplicated,
            'original_count': len(plugin_data),
            'deduplicated_count': len(deduplicated),
            'processing_time_ms': (time.time() - start_time) * 1000
        }

    except Exception as e:
        return {
            'status': 'error',
            'error': str(e),
            'processing_time_ms': (time.time() - start_time) * 1000
        }