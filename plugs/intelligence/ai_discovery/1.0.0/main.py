#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
AI Discovery Plugin - Completing Existing Implementation

This plugin implements AI-powered plugin discovery using semantic search and embeddings.
It leverages existing PlugPipe infrastructure:
- cores/discovery/ai_search.py for AI search capabilities
- cores/discovery_coordinator.py for registry coordination
- cores/registry_backend for plugin metadata

Implementation follows Anti-Duplication Intelligence by improving existing functionality
rather than creating duplicates.
"""

import sys
import os
import time
from datetime import datetime
from typing import Dict, List, Any, Optional

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))

def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    AI-powered plugin discovery using semantic search and embeddings.
    
    Args:
        context: Execution context with environment and metadata
        config: Discovery configuration with query and search parameters
        
    Returns:
        Dict containing discovery results with similarity scores and metadata
    """
    start_time = time.time()
    
    try:
        # Extract search parameters
        query = config.get('query', '')
        limit = config.get('limit', 10)
        embedding_provider = config.get('embedding_provider', 'ollama')
        embedding_model = config.get('embedding_model', 'nomic-embed-text')
        threshold = config.get('threshold', 0.1)
        
        if not query.strip():
            return {
                "success": False,
                "error": "Query parameter is required",
                "processing_time_ms": (time.time() - start_time) * 1000,
                "timestamp": datetime.now().isoformat()
            }
        
        # Initialize discovery system using existing infrastructure
        discovery_results = _perform_ai_discovery(
            query=query,
            limit=limit,
            embedding_provider=embedding_provider,
            embedding_model=embedding_model,
            threshold=threshold,
            context=context
        )
        
        processing_time = (time.time() - start_time) * 1000
        
        return {
            "success": True,
            "query": query,
            "results_count": len(discovery_results),
            "embedding_provider_used": embedding_provider,
            "processing_time_ms": round(processing_time, 2),
            "results": discovery_results,
            "threshold_applied": threshold,
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        
        return {
            "success": False,
            "query": config.get('query', ''),
            "error": str(e),
            "processing_time_ms": round(processing_time, 2),
            "timestamp": datetime.now().isoformat()
        }

def _perform_ai_discovery(
    query: str,
    limit: int,
    embedding_provider: str,
    embedding_model: str,
    threshold: float,
    context: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """
    Perform AI-powered discovery using existing PlugPipe AI search infrastructure.
    
    This leverages:
    - cores/discovery/ai_search.py for semantic search
    - cores/discovery_coordinator.py for registry coordination
    - cores/registry_backend for plugin metadata access
    """
    try:
        # Try to use existing AI search infrastructure
        from cores.discovery.ai_search import AISearchDiscovery, OllamaEmbeddingProvider
        from cores.discovery_coordinator import DiscoveryCoordinator
        from cores.registry_backend import get_registry_backends
        from shares.utils.config_loader import load_main_config
        
        # Load configuration
        try:
            config = load_main_config()
        except:
            config = {}
        
        # Initialize registry backends
        backends = get_registry_backends(config)
        coordinator = DiscoveryCoordinator(backends)
        
        # Initialize embedding provider
        provider = _initialize_embedding_provider(embedding_provider, embedding_model)
        
        # Create AI search discovery
        discovery = AISearchDiscovery(coordinator, embedding_provider=provider)
        
        # Perform search
        raw_results = discovery.search_plugs(query)
        
        # Format and filter results
        formatted_results = []
        for result in raw_results[:limit]:
            similarity_score = result.get('similarity_score', 0.0)
            
            if similarity_score >= threshold:
                formatted_results.append({
                    "name": result.get('name', 'unknown'),
                    "version": result.get('version', '1.0.0'),
                    "description": result.get('description', 'No description available'),
                    "category": result.get('category', 'uncategorized'),
                    "similarity_score": round(similarity_score, 3),
                    "source_registry": result.get('source_registry', 'local'),
                    "sbom_valid": result.get('sbom_valid', True),
                    "sbom_hash": result.get('sbom_hash', '')[:8] if result.get('sbom_hash') else '',
                    "plugin_type": _determine_plugin_type(result.get('name', ''))
                })
        
        return formatted_results
        
    except ImportError as e:
        # Fallback to keyword-based search if AI infrastructure unavailable
        return _fallback_keyword_search(query, limit, threshold, context)
    except Exception as e:
        # Additional fallback for any other issues
        return _fallback_keyword_search(query, limit, threshold, context)

def _initialize_embedding_provider(provider_type: str, model: str):
    """Initialize embedding provider based on configuration."""
    try:
        if provider_type == "ollama":
            from cores.discovery.ai_search import OllamaEmbeddingProvider
            provider = OllamaEmbeddingProvider(model=model)
            # Test provider with a simple embedding
            provider.embed(["test"])
            return provider
        elif provider_type == "http":
            # HTTP provider would need endpoint configuration
            return None
        else:
            return None
    except Exception:
        # Return None to trigger keyword fallback
        return None

def _fallback_keyword_search(query: str, limit: int, threshold: float, context: Dict[str, Any]) -> List[Dict[str, Any]]:
    """
    Fallback keyword-based search when AI infrastructure is unavailable.
    Uses simple keyword matching against plugin names and descriptions.
    """
    try:
        # Simple keyword search implementation
        from pathlib import Path
        import yaml
        
        query_keywords = query.lower().split()
        results = []
        
        # Search in plugs directory
        plugs_dir = Path("plugs")
        if plugs_dir.exists():
            for plugin_path in plugs_dir.glob("*/*/1.0.0"):
                manifest_file = None
                if (plugin_path / "plug.yaml").exists():
                    manifest_file = plugin_path / "plug.yaml"
                
                if manifest_file:
                    try:
                        with open(manifest_file, 'r') as f:
                            manifest = yaml.safe_load(f)
                        
                        # Simple keyword matching
                        searchable_text = f"{manifest.get('name', '')} {manifest.get('description', '')} {' '.join(manifest.get('tags', []))}"
                        searchable_text = searchable_text.lower()
                        
                        # Calculate simple keyword match score
                        matches = sum(1 for keyword in query_keywords if keyword in searchable_text)
                        similarity_score = matches / len(query_keywords) if query_keywords else 0.0
                        
                        if similarity_score >= threshold:
                            results.append({
                                "name": manifest.get('name', plugin_path.parent.parent.name),
                                "version": manifest.get('version', '1.0.0'),
                                "description": manifest.get('description', 'No description available'),
                                "category": manifest.get('category', plugin_path.parent.parent.parent.name),
                                "similarity_score": round(similarity_score, 3),
                                "source_registry": "local_keyword_search",
                                "sbom_valid": True,
                                "sbom_hash": "",
                                "plugin_type": "plugin"
                            })
                    except Exception:
                        continue
        
        # Search in pipes directory
        pipes_dir = Path("pipes")
        if pipes_dir.exists():
            for pipe_path in pipes_dir.glob("*/1.0.0"):
                manifest_file = None
                if (pipe_path / "pipe.yaml").exists():
                    manifest_file = pipe_path / "pipe.yaml"
                
                if manifest_file:
                    try:
                        with open(manifest_file, 'r') as f:
                            manifest = yaml.safe_load(f)
                        
                        # Handle PipeSpec format
                        if manifest.get('kind') == 'PipeSpec' and 'metadata' in manifest:
                            metadata = manifest['metadata']
                            searchable_text = f"{metadata.get('name', '')} {metadata.get('doc', metadata.get('description', ''))} {' '.join(metadata.get('tags', []))}"
                        else:
                            searchable_text = f"{manifest.get('name', '')} {manifest.get('description', '')}"
                        
                        searchable_text = searchable_text.lower()
                        
                        # Calculate simple keyword match score
                        matches = sum(1 for keyword in query_keywords if keyword in searchable_text)
                        similarity_score = matches / len(query_keywords) if query_keywords else 0.0
                        
                        if similarity_score >= threshold:
                            if manifest.get('kind') == 'PipeSpec' and 'metadata' in manifest:
                                metadata = manifest['metadata']
                                results.append({
                                    "name": metadata.get('name', pipe_path.parent.name),
                                    "version": str(metadata.get('version', '1.0.0')),
                                    "description": metadata.get('doc', metadata.get('description', 'No description available')),
                                    "category": "pipes",
                                    "similarity_score": round(similarity_score, 3),
                                    "source_registry": "local_keyword_search",
                                    "sbom_valid": True,
                                    "sbom_hash": "",
                                    "plugin_type": "pipe"
                                })
                    except Exception:
                        continue
        
        # Sort by similarity score and limit results
        results.sort(key=lambda x: x['similarity_score'], reverse=True)
        return results[:limit]
        
    except Exception:
        return [{
            "name": "search_error",
            "version": "1.0.0", 
            "description": "An error occurred during plugin discovery",
            "category": "error",
            "similarity_score": 0.0,
            "source_registry": "error",
            "sbom_valid": False,
            "sbom_hash": "",
            "plugin_type": "error"
        }]

def _determine_plugin_type(plugin_name: str) -> str:
    """Determine plugin type based on name and location."""
    if any(keyword in plugin_name.lower() for keyword in ['pipe', 'pipeline', 'workflow', 'orchestrat']):
        return "pipe"
    return "plugin"

# Plugin metadata
plug_metadata = {
    "name": "ai_discovery",
    "version": "1.0.0",
    "type": "plugin",
    "description": "AI-powered plugin discovery using embeddings and semantic search",
    "category": "intelligence",
    "tags": ["ai", "discovery", "search", "embeddings", "semantic", "mcp"]
}