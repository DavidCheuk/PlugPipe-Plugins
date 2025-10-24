#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Multi-Backend Search Processing Plugin

Extracted from MultiBackendRegistryService to follow Plugin-First Development principle.
Handles complex search processing, ranking, and coordination across multiple registry backends.

Key Features:
- Trinity Architecture search support (plug/pipe/glue)
- Advanced ranking algorithms (relevance, popularity, date, alphabetical)
- Fuzzy search capabilities
- Result deduplication and aggregation
- Backend-agnostic search coordination
"""

import time
import re
from typing import Dict, List, Any, Optional, Tuple
from collections import defaultdict

def process(plugin_ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Plugin entry point for multi-backend search processing.

    Args:
        plugin_ctx: Plugin execution context
        config: Search configuration including query, backends, and parameters

    Returns:
        Processed search results with ranking and metadata
    """
    start_time = time.time()

    try:
        operation = config.get('operation', 'process_search')

        if operation == 'process_search':
            return process_multi_backend_search(config, start_time)
        elif operation == 'aggregate_results':
            return aggregate_search_results(config.get('raw_results', []), config, start_time)
        elif operation == 'rank_results':
            return rank_search_results(config.get('results', []), config.get('ranking_algorithm', 'relevance'), start_time)
        elif operation == 'filter_results':
            return filter_search_results(config.get('results', []), config, start_time)
        elif operation == 'deduplicate_results':
            return deduplicate_search_results(config.get('results', []), start_time)
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
            'processing_time_ms': (time.time() - start_time) * 1000,
            'search_results': []
        }

def process_multi_backend_search(config: Dict[str, Any], start_time: float) -> Dict[str, Any]:
    """Process search query across multiple backends with coordination."""

    search_query = config.get('search_query', '')
    backends = config.get('backends', [])
    search_config = config.get('search_config', {})

    limit = search_config.get('limit', 50)
    cursor = search_config.get('cursor')
    component_type = search_config.get('component_type', 'all')
    fuzzy_search = search_config.get('fuzzy_search', False)
    ranking_algorithm = search_config.get('ranking_algorithm', 'relevance')

    # Sanitize search query using universal sanitizer
    sanitized_query = sanitize_search_query(search_query)
    if not sanitized_query:
        return {
            'status': 'error',
            'error': 'Invalid search query after sanitization',
            'processing_time_ms': (time.time() - start_time) * 1000,
            'search_results': []
        }

    # Collect results from all backends
    all_results = []
    backends_searched = 0
    search_errors = []

    for backend in backends:
        try:
            # Attempt backend search
            backend_results = search_single_backend(
                backend, sanitized_query, cursor, limit, component_type
            )

            if backend_results:
                all_results.extend(backend_results)
                backends_searched += 1

        except Exception as backend_error:
            search_errors.append(f"Backend {type(backend).__name__}: {str(backend_error)}")
            continue

    # Process and rank results
    if fuzzy_search:
        all_results = apply_fuzzy_search_filtering(all_results, sanitized_query)

    # Deduplicate results
    deduplicated_results = deduplicate_by_name_and_version(all_results)

    # Apply ranking algorithm
    ranked_results = apply_ranking_algorithm(deduplicated_results, ranking_algorithm, sanitized_query)

    # Apply limit
    final_results = ranked_results[:limit]

    # Generate result metadata
    result_metadata = {
        'total_found': len(deduplicated_results),
        'processing_time_ms': (time.time() - start_time) * 1000,
        'backends_searched': backends_searched,
        'ranking_algorithm_used': ranking_algorithm,
        'fuzzy_search_applied': fuzzy_search,
        'query_sanitized': sanitized_query != search_query
    }

    return {
        'status': 'success' if backends_searched > 0 else 'error',
        'search_results': final_results,
        'result_metadata': result_metadata,
        'next_cursor': generate_next_cursor(final_results, limit) if len(final_results) == limit else None,
        'errors': search_errors if search_errors else []
    }

def search_single_backend(backend: Any, query: str, cursor: Optional[str], limit: int, component_type: str) -> List[Dict[str, Any]]:
    """Search a single backend with proper error handling."""

    if hasattr(backend, 'search_plugs'):
        # Use backend's native search method
        try:
            result = backend.search_plugs(query=query, cursor=cursor, limit=limit)
            if isinstance(result, tuple):
                return result[0] if result[0] else []
            return result if result else []
        except Exception:
            pass

    # Fallback to list_plugs with manual filtering
    if hasattr(backend, 'list_plugs'):
        try:
            result = backend.list_plugs(cursor=cursor, limit=limit * 2)  # Get more for filtering
            plugins = result[0] if isinstance(result, tuple) else result

            if plugins:
                return manual_search_filter(plugins, query, component_type)
        except Exception:
            pass

    return []

def manual_search_filter(plugins: List[Dict[str, Any]], query: str, component_type: str) -> List[Dict[str, Any]]:
    """Manual search filtering when backend doesn't support native search."""

    query_lower = query.lower()
    matching_plugins = []

    for plugin in plugins:
        # Component type filtering
        if component_type != 'all':
            plugin_type = plugin.get('type', 'plug')
            if plugin_type != component_type:
                continue

        # Search in multiple fields
        searchable_text = ' '.join([
            plugin.get('name', '').lower(),
            plugin.get('description', '').lower(),
            plugin.get('category', '').lower(),
            ' '.join(plugin.get('tags', [])).lower()
        ])

        if query_lower in searchable_text:
            # Calculate relevance score
            plugin['_search_score'] = calculate_relevance_score(plugin, query_lower)
            matching_plugins.append(plugin)

    return matching_plugins

def sanitize_search_query(query: str) -> str:
    """Sanitize search query using PlugPipe security principles."""

    if not query or not isinstance(query, str):
        return ""

    # Remove potentially dangerous patterns
    query = re.sub(r'[<>&"\'`]', '', query)  # Remove HTML/script chars
    query = re.sub(r'[|;$]', '', query)      # Remove command injection chars
    query = re.sub(r'\s+', ' ', query)       # Normalize whitespace
    query = query.strip()

    # Length limit for performance
    if len(query) > 200:
        query = query[:200]

    return query

def apply_fuzzy_search_filtering(results: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    """Apply fuzzy search filtering for approximate matches."""

    query_words = query.lower().split()
    fuzzy_results = []

    for result in results:
        name_words = result.get('name', '').lower().split('_')
        desc_words = result.get('description', '').lower().split()

        # Calculate fuzzy match score
        fuzzy_score = 0
        for q_word in query_words:
            for field_words in [name_words, desc_words]:
                for field_word in field_words:
                    if q_word in field_word or field_word in q_word:
                        fuzzy_score += 1
                    elif len(q_word) > 3 and len(field_word) > 3:
                        # Simple character overlap scoring
                        overlap = len(set(q_word) & set(field_word))
                        if overlap >= len(q_word) * 0.6:
                            fuzzy_score += 0.5

        if fuzzy_score > 0:
            result['_fuzzy_score'] = fuzzy_score
            fuzzy_results.append(result)

    return fuzzy_results

def deduplicate_by_name_and_version(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Remove duplicate results based on name and version."""

    seen = set()
    deduplicated = []

    for result in results:
        name = result.get('name', '')
        version = result.get('version', '1.0.0')
        key = f"{name}:{version}"

        if key not in seen:
            seen.add(key)
            deduplicated.append(result)

    return deduplicated

def apply_ranking_algorithm(results: List[Dict[str, Any]], algorithm: str, query: str) -> List[Dict[str, Any]]:
    """Apply the specified ranking algorithm to search results."""

    if algorithm == 'relevance':
        return sorted(results, key=lambda x: (
            x.get('_search_score', 0) + x.get('_fuzzy_score', 0)
        ), reverse=True)

    elif algorithm == 'alphabetical':
        return sorted(results, key=lambda x: x.get('name', '').lower())

    elif algorithm == 'date':
        return sorted(results, key=lambda x: x.get('created_at', ''), reverse=True)

    elif algorithm == 'popularity':
        return sorted(results, key=lambda x: x.get('usage_count', 0), reverse=True)

    else:
        # Default to relevance
        return apply_ranking_algorithm(results, 'relevance', query)

def calculate_relevance_score(plugin: Dict[str, Any], query: str) -> float:
    """Calculate relevance score for search ranking."""

    score = 0.0
    name = plugin.get('name', '').lower()
    description = plugin.get('description', '').lower()

    # Exact name match gets highest score
    if query == name:
        score += 10.0
    elif query in name:
        score += 5.0

    # Description matches
    query_words = query.split()
    for word in query_words:
        if word in name:
            score += 3.0
        if word in description:
            score += 1.0

    # Category/tag matches
    category = plugin.get('category', '').lower()
    tags = [tag.lower() for tag in plugin.get('tags', [])]

    for word in query_words:
        if word == category:
            score += 2.0
        if word in tags:
            score += 1.5

    return score

def generate_next_cursor(results: List[Dict[str, Any]], limit: int) -> Optional[str]:
    """Generate pagination cursor for next page of results."""

    if not results or len(results) < limit:
        return None

    # Simple cursor based on last result name
    last_result = results[-1]
    return f"cursor_{last_result.get('name', '')}"

def aggregate_search_results(raw_results: List[List[Dict[str, Any]]], config: Dict[str, Any], start_time: float) -> Dict[str, Any]:
    """Aggregate search results from multiple sources."""

    aggregated = []
    for result_set in raw_results:
        aggregated.extend(result_set)

    return {
        'status': 'success',
        'search_results': aggregated,
        'result_metadata': {
            'total_aggregated': len(aggregated),
            'processing_time_ms': (time.time() - start_time) * 1000
        }
    }

def rank_search_results(results: List[Dict[str, Any]], algorithm: str, start_time: float) -> Dict[str, Any]:
    """Standalone ranking operation."""

    ranked_results = apply_ranking_algorithm(results, algorithm, '')

    return {
        'status': 'success',
        'search_results': ranked_results,
        'result_metadata': {
            'ranking_algorithm': algorithm,
            'processing_time_ms': (time.time() - start_time) * 1000
        }
    }

def filter_search_results(results: List[Dict[str, Any]], config: Dict[str, Any], start_time: float) -> Dict[str, Any]:
    """Standalone filtering operation."""

    search_config = config.get('search_config', {})
    component_type = search_config.get('component_type', 'all')

    filtered_results = []
    for result in results:
        if component_type == 'all' or result.get('type') == component_type:
            filtered_results.append(result)

    return {
        'status': 'success',
        'search_results': filtered_results,
        'result_metadata': {
            'filter_applied': component_type,
            'processing_time_ms': (time.time() - start_time) * 1000
        }
    }

def deduplicate_search_results(results: List[Dict[str, Any]], start_time: float) -> Dict[str, Any]:
    """Standalone deduplication operation."""

    deduplicated = deduplicate_by_name_and_version(results)

    return {
        'status': 'success',
        'search_results': deduplicated,
        'result_metadata': {
            'original_count': len(results),
            'deduplicated_count': len(deduplicated),
            'processing_time_ms': (time.time() - start_time) * 1000
        }
    }