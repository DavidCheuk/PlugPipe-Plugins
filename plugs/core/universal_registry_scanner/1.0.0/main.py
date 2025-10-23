# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
Universal PlugPipe Registry Scanner
Works with all supported registry types - filesystem, remote, GitHub, database, API-based registries
Provides accurate plugin/pipe counts and metadata across the entire PlugPipe ecosystem
"""

import os
import sys
import json
import glob
import yaml
import sqlite3
import asyncio
import aiohttp
import requests
import subprocess
import logging
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
from abc import ABC, abstractmethod

class RegistryInterface(ABC):
    """Abstract interface for all registry types"""
    
    @abstractmethod
    async def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover all plugins in this registry"""
        raise NotImplementedError("Subclasses must implement discover_plugins")

    @abstractmethod
    async def get_plugin_metadata(self, plugin_name: str) -> Dict[str, Any]:
        """Get detailed metadata for a specific plugin"""
        raise NotImplementedError("Subclasses must implement get_plugin_metadata")

    @abstractmethod
    async def validate_registry_health(self) -> Dict[str, Any]:
        """Validate the health and availability of this registry"""
        raise NotImplementedError("Subclasses must implement validate_registry_health")

class FilesystemRegistry(RegistryInterface):
    """Filesystem-based registry scanner - delegates to plugin_registry_scanner for actual scanning"""
    
    def __init__(self, base_path: str = get_plugpipe_root()):
        self.base_path = Path(base_path)
        self.logger = logging.getLogger(f"{__name__}.FilesystemRegistry")
        
        # Import and initialize the existing plugin_registry_scanner
        try:
            # Add project root to path for plugin discovery
            sys.path.insert(0, get_plugpipe_root())
            spec_path = get_plugpipe_path("plugs/core/plugin_registry_scanner/1.0.0/main.py")
            import importlib.util
            spec = importlib.util.spec_from_file_location("plugin_registry_scanner", spec_path)
            scanner_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(scanner_module)
            self.scanner = scanner_module.PlugPipeRegistryScanner()
            self.logger.info("Successfully initialized plugin_registry_scanner for delegation")
        except Exception as e:
            self.logger.error(f"Failed to initialize plugin_registry_scanner: {e}")
            self.scanner = None
    
    async def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover all plugins in filesystem registry using plugin_registry_scanner"""
        if not self.scanner:
            self.logger.error("plugin_registry_scanner not available, falling back to basic scanning")
            return await self._fallback_discover_plugins()
        
        try:
            # Delegate to the existing plugin_registry_scanner
            scanner_result = self.scanner.scan_all_plugins(include_metadata=True, format="json")
            
            if scanner_result.get("success"):
                plugins = []
                
                # Process plugs data
                for plug in scanner_result.get("plugs_data", []):
                    plugins.append({
                        "name": plug.get("name"),
                        "version": plug.get("version", "1.0.0"),
                        "category": plug.get("category", "unknown"),
                        "type": "plug",
                        "registry_type": "filesystem",
                        "description": plug.get("description", ""),
                        "status": plug.get("status", "active"),
                        "author": plug.get("author", plug.get("owner", "Unknown")),
                        "license": plug.get("license", "Unknown"),
                        "tags": plug.get("tags", []),
                        "path": plug.get("path", "")
                    })
                
                # Process pipes data
                for pipe in scanner_result.get("pipes_data", []):
                    plugins.append({
                        "name": pipe.get("name"),
                        "version": pipe.get("version", "1.0.0"), 
                        "category": pipe.get("category", "pipes"),
                        "type": "pipe",
                        "registry_type": "filesystem",
                        "description": pipe.get("description", ""),
                        "status": pipe.get("status", "active"),
                        "author": pipe.get("author", pipe.get("owner", "Unknown")),
                        "license": pipe.get("license", "Unknown"),
                        "tags": pipe.get("tags", []),
                        "path": pipe.get("path", "")
                    })
                
                self.logger.info(f"plugin_registry_scanner discovered {len(plugins)} plugins/pipes")
                return plugins
            else:
                self.logger.error(f"plugin_registry_scanner returned error: {scanner_result.get('error')}")
                return await self._fallback_discover_plugins()
                
        except Exception as e:
            self.logger.error(f"Error delegating to plugin_registry_scanner: {e}")
            return await self._fallback_discover_plugins()
    
    async def _fallback_discover_plugins(self) -> List[Dict[str, Any]]:
        """Fallback basic plugin discovery if delegation fails"""
        plugins = []
        
        # Scan plugs directory recursively
        plug_files = glob.glob(str(self.base_path / 'plugs' / '**' / 'plug.yaml'), recursive=True)
        
        # Scan pipes directory recursively  
        pipe_files = glob.glob(str(self.base_path / 'pipes' / '**' / 'pipe.yaml'), recursive=True)
        
        # Process all manifest files
        for manifest_path in plug_files + pipe_files:
            plugin_data = await self._process_manifest(manifest_path)
            if plugin_data:
                plugins.append(plugin_data)
        
        self.logger.warning(f"Used fallback discovery, found {len(plugins)} plugins/pipes")
        return plugins
    
    async def get_plugin_metadata(self, plugin_name: str) -> Dict[str, Any]:
        """Get detailed metadata for a specific plugin"""
        # Search for the plugin manifest
        for manifest_path in glob.glob(str(self.base_path / '**' / '*.yaml'), recursive=True):
            try:
                with open(manifest_path, 'r') as f:
                    manifest = yaml.safe_load(f)
                if manifest.get('name') == plugin_name:
                    return await self._process_manifest(manifest_path)
            except Exception:
                continue
        
        return {"error": f"Plugin {plugin_name} not found in filesystem registry"}
    
    async def validate_registry_health(self) -> Dict[str, Any]:
        """Validate filesystem registry health"""
        plugs_dir = self.base_path / 'plugs'
        pipes_dir = self.base_path / 'pipes'
        
        health = {
            "registry_type": "filesystem",
            "base_path": str(self.base_path),
            "accessible": True,
            "plugs_directory_exists": plugs_dir.exists(),
            "pipes_directory_exists": pipes_dir.exists(),
            "permissions_ok": os.access(self.base_path, os.R_OK),
            "total_manifests": len(glob.glob(str(self.base_path / '**' / '*.yaml'), recursive=True))
        }
        
        return health
    
    async def _process_manifest(self, manifest_path: str) -> Optional[Dict[str, Any]]:
        """Process a single manifest file"""
        try:
            with open(manifest_path, 'r') as f:
                manifest = yaml.safe_load(f)
            
            plugin_type = 'pipe' if '/pipes/' in manifest_path else 'plug'
            
            plugin_data = {
                "name": manifest.get('name', 'unknown'),
                "version": manifest.get('version', '1.0.0'),
                "category": manifest.get('category', 'unknown'),
                "description": manifest.get('description', 'No description available'),
                "author": manifest.get('author', 'Unknown'),
                "license": manifest.get('license', 'Unknown'),
                "type": plugin_type,
                "registry_type": "filesystem",
                "manifest_path": manifest_path,
                "last_modified": datetime.fromtimestamp(os.path.getmtime(manifest_path)).isoformat()
            }
            
            return plugin_data
            
        except Exception as e:
            self.logger.warning(f"Failed to process manifest {manifest_path}: {str(e)}")
            return None

class DatabaseRegistry(RegistryInterface):
    """Database-backed registry scanner"""
    
    def __init__(self, db_path: str = get_plugpipe_path("plugpipe_storage.db")):
        self.db_path = db_path
        self.logger = logging.getLogger(f"{__name__}.DatabaseRegistry")
    
    async def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover all plugins in database registry"""
        plugins = []
        
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Try different possible table structures
            tables_to_check = [
                "plugins", "plugin_registry", "validation_results", 
                "plugpipe_plugins", "registry_entries"
            ]
            
            for table_name in tables_to_check:
                try:
                    cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
                    if cursor.fetchone():
                        cursor.execute(f"SELECT * FROM {table_name} LIMIT 10")
                        rows = cursor.fetchall()
                        
                        for row in rows:
                            plugin_data = {
                                "registry_type": "database",
                                "table_source": table_name,
                                "raw_data": dict(row)
                            }
                            
                            # Try to extract standard fields
                            if 'plugin_name' in row.keys():
                                plugin_data['name'] = row['plugin_name']
                            elif 'name' in row.keys():
                                plugin_data['name'] = row['name']
                            
                            plugins.append(plugin_data)
                        
                        break
                        
                except sqlite3.Error:
                    continue
            
            conn.close()
            
        except Exception as e:
            self.logger.error(f"Database registry scan failed: {str(e)}")
        
        return plugins
    
    async def get_plugin_metadata(self, plugin_name: str) -> Dict[str, Any]:
        """Get detailed metadata for a specific plugin from database"""
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # Search across different tables
            cursor.execute("""
                SELECT name FROM sqlite_master WHERE type='table'
            """)
            tables = [row[0] for row in cursor.fetchall()]
            
            for table in tables:
                try:
                    cursor.execute(f"""
                        SELECT * FROM {table} 
                        WHERE plugin_name = ? OR name = ?
                    """, (plugin_name, plugin_name))
                    
                    row = cursor.fetchone()
                    if row:
                        conn.close()
                        return {
                            "registry_type": "database",
                            "table_source": table,
                            "data": dict(row)
                        }
                except sqlite3.Error:
                    continue
            
            conn.close()
            return {"error": f"Plugin {plugin_name} not found in database registry"}
            
        except Exception as e:
            return {"error": f"Database query failed: {str(e)}"}
    
    async def validate_registry_health(self) -> Dict[str, Any]:
        """Validate database registry health"""
        health = {
            "registry_type": "database",
            "db_path": self.db_path,
            "accessible": False,
            "tables": [],
            "total_records": 0
        }
        
        try:
            if os.path.exists(self.db_path):
                conn = sqlite3.connect(self.db_path)
                cursor = conn.cursor()
                
                # Get all tables
                cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
                tables = [row[0] for row in cursor.fetchall()]
                health["tables"] = tables
                
                # Count total records across relevant tables
                total_records = 0
                for table in tables:
                    if any(keyword in table.lower() for keyword in ['plugin', 'registry', 'validation']):
                        cursor.execute(f"SELECT COUNT(*) FROM {table}")
                        count = cursor.fetchone()[0]
                        total_records += count
                
                health["total_records"] = total_records
                health["accessible"] = True
                
                conn.close()
                
        except Exception as e:
            health["error"] = str(e)
        
        return health

class RemoteAPIRegistry(RegistryInterface):
    """Remote API-based registry scanner"""
    
    def __init__(self, api_endpoint: str, auth_config: Dict[str, Any] = None):
        self.api_endpoint = api_endpoint.rstrip('/')
        self.auth_config = auth_config or {}
        self.logger = logging.getLogger(f"{__name__}.RemoteAPIRegistry")
    
    async def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover all plugins from remote API registry"""
        plugins = []
        
        try:
            async with aiohttp.ClientSession() as session:
                # Common API endpoints to try
                endpoints_to_try = [
                    f"{self.api_endpoint}/plugins",
                    f"{self.api_endpoint}/api/plugins",
                    f"{self.api_endpoint}/registry/list",
                    f"{self.api_endpoint}/v1/plugins"
                ]
                
                for endpoint in endpoints_to_try:
                    try:
                        headers = self._get_auth_headers()
                        async with session.get(endpoint, headers=headers, timeout=30) as response:
                            if response.status == 200:
                                data = await response.json()
                                
                                # Handle different API response formats
                                if isinstance(data, list):
                                    plugin_list = data
                                elif isinstance(data, dict):
                                    plugin_list = data.get('plugins', data.get('data', data.get('results', [])))
                                else:
                                    continue
                                
                                for plugin in plugin_list:
                                    if isinstance(plugin, dict):
                                        plugin['registry_type'] = 'remote_api'
                                        plugin['api_endpoint'] = endpoint
                                        plugins.append(plugin)
                                
                                break
                                
                    except Exception as e:
                        self.logger.debug(f"Failed to fetch from {endpoint}: {str(e)}")
                        continue
        
        except Exception as e:
            self.logger.error(f"Remote API registry scan failed: {str(e)}")
        
        return plugins
    
    async def get_plugin_metadata(self, plugin_name: str) -> Dict[str, Any]:
        """Get detailed metadata for a specific plugin from remote API"""
        try:
            async with aiohttp.ClientSession() as session:
                endpoints_to_try = [
                    f"{self.api_endpoint}/plugins/{plugin_name}",
                    f"{self.api_endpoint}/api/plugins/{plugin_name}",
                    f"{self.api_endpoint}/registry/plugin/{plugin_name}"
                ]
                
                headers = self._get_auth_headers()
                
                for endpoint in endpoints_to_try:
                    try:
                        async with session.get(endpoint, headers=headers, timeout=30) as response:
                            if response.status == 200:
                                data = await response.json()
                                data['registry_type'] = 'remote_api'
                                return data
                    except Exception:
                        continue
                
                return {"error": f"Plugin {plugin_name} not found in remote API registry"}
                
        except Exception as e:
            return {"error": f"Remote API query failed: {str(e)}"}
    
    async def validate_registry_health(self) -> Dict[str, Any]:
        """Validate remote API registry health"""
        health = {
            "registry_type": "remote_api",
            "api_endpoint": self.api_endpoint,
            "accessible": False,
            "response_time_ms": None,
            "endpoints_available": []
        }
        
        try:
            start_time = datetime.now()
            
            async with aiohttp.ClientSession() as session:
                # Test common endpoints
                test_endpoints = [
                    f"{self.api_endpoint}/health",
                    f"{self.api_endpoint}/api/health", 
                    f"{self.api_endpoint}/status",
                    f"{self.api_endpoint}/plugins"
                ]
                
                headers = self._get_auth_headers()
                
                for endpoint in test_endpoints:
                    try:
                        async with session.get(endpoint, headers=headers, timeout=10) as response:
                            if response.status < 400:
                                health["endpoints_available"].append({
                                    "endpoint": endpoint,
                                    "status": response.status,
                                    "accessible": True
                                })
                                health["accessible"] = True
                    except Exception:
                        health["endpoints_available"].append({
                            "endpoint": endpoint,
                            "accessible": False
                        })
                
                response_time = (datetime.now() - start_time).total_seconds() * 1000
                health["response_time_ms"] = response_time
                
        except Exception as e:
            health["error"] = str(e)
        
        return health
    
    def _get_auth_headers(self) -> Dict[str, str]:
        """Get authentication headers based on auth_config"""
        headers = {}
        
        if self.auth_config.get('api_key'):
            headers['Authorization'] = f"Bearer {self.auth_config['api_key']}"
        elif self.auth_config.get('token'):
            headers['Authorization'] = f"Token {self.auth_config['token']}"
        elif self.auth_config.get('basic_auth'):
            import base64
            auth_string = f"{self.auth_config['basic_auth']['username']}:{self.auth_config['basic_auth']['password']}"
            encoded = base64.b64encode(auth_string.encode()).decode()
            headers['Authorization'] = f"Basic {encoded}"
        
        return headers

class GitHubRegistry(RegistryInterface):
    """GitHub repository-based registry scanner"""
    
    def __init__(self, repo_url: str, branch: str = "main", token: str = None):
        self.repo_url = repo_url.rstrip('/')
        self.branch = branch
        self.token = token
        self.logger = logging.getLogger(f"{__name__}.GitHubRegistry")
        
        # Parse GitHub repo info
        if 'github.com' in repo_url:
            parts = repo_url.replace('https://github.com/', '').split('/')
            if len(parts) >= 2:
                self.owner = parts[0]
                self.repo = parts[1]
                self.api_base = f"https://api.github.com/repos/{self.owner}/{self.repo}"
    
    async def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover all plugins from GitHub repository"""
        plugins = []
        
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.token:
                headers["Authorization"] = f"token {self.token}"
            
            async with aiohttp.ClientSession() as session:
                # Search for plugin manifests in the repository
                search_url = f"{self.api_base}/git/trees/{self.branch}?recursive=1"
                
                async with session.get(search_url, headers=headers) as response:
                    if response.status == 200:
                        data = await response.json()
                        
                        # Find all .yaml files that could be manifests
                        manifest_files = []
                        for item in data.get('tree', []):
                            if item['type'] == 'blob' and (
                                item['path'].endswith('plug.yaml') or 
                                item['path'].endswith('pipe.yaml') or
                                item['path'].endswith('plugin.yaml')
                            ):
                                manifest_files.append(item['path'])
                        
                        # Fetch content of each manifest file
                        for manifest_path in manifest_files[:50]:  # Limit to avoid rate limits
                            plugin_data = await self._fetch_github_manifest(session, manifest_path, headers)
                            if plugin_data:
                                plugins.append(plugin_data)
        
        except Exception as e:
            self.logger.error(f"GitHub registry scan failed: {str(e)}")
        
        return plugins
    
    async def get_plugin_metadata(self, plugin_name: str) -> Dict[str, Any]:
        """Get detailed metadata for a specific plugin from GitHub"""
        # This would require searching through the repository
        # Implementation would be similar to discover_plugins but filtered
        return {"error": "GitHub plugin metadata lookup not yet implemented"}
    
    async def validate_registry_health(self) -> Dict[str, Any]:
        """Validate GitHub registry health"""
        health = {
            "registry_type": "github",
            "repo_url": self.repo_url,
            "branch": self.branch,
            "accessible": False,
            "rate_limit_remaining": None
        }
        
        try:
            headers = {"Accept": "application/vnd.github.v3+json"}
            if self.token:
                headers["Authorization"] = f"token {self.token}"
            
            async with aiohttp.ClientSession() as session:
                # Test repository accessibility
                async with session.get(self.api_base, headers=headers) as response:
                    if response.status == 200:
                        health["accessible"] = True
                        
                        # Check rate limit
                        if 'X-RateLimit-Remaining' in response.headers:
                            health["rate_limit_remaining"] = int(response.headers['X-RateLimit-Remaining'])
                    else:
                        health["error"] = f"HTTP {response.status}"
        
        except Exception as e:
            health["error"] = str(e)
        
        return health
    
    async def _fetch_github_manifest(self, session: aiohttp.ClientSession, manifest_path: str, headers: Dict[str, str]) -> Optional[Dict[str, Any]]:
        """Fetch and parse a manifest file from GitHub"""
        try:
            file_url = f"{self.api_base}/contents/{manifest_path}?ref={self.branch}"
            
            async with session.get(file_url, headers=headers) as response:
                if response.status == 200:
                    file_data = await response.json()
                    
                    # Decode base64 content
                    import base64
                    content = base64.b64decode(file_data['content']).decode('utf-8')
                    manifest = yaml.safe_load(content)
                    
                    plugin_data = {
                        "name": manifest.get('name', 'unknown'),
                        "version": manifest.get('version', '1.0.0'),
                        "category": manifest.get('category', 'unknown'),
                        "description": manifest.get('description', 'No description available'),
                        "author": manifest.get('author', 'Unknown'),
                        "license": manifest.get('license', 'Unknown'),
                        "type": 'pipe' if 'pipe.yaml' in manifest_path else 'plug',
                        "registry_type": "github",
                        "repo_url": self.repo_url,
                        "manifest_path": manifest_path,
                        "github_sha": file_data.get('sha')
                    }
                    
                    return plugin_data
        
        except Exception as e:
            self.logger.debug(f"Failed to fetch GitHub manifest {manifest_path}: {str(e)}")
        
        return None

class UniversalRegistryScanner:
    """Main scanner that orchestrates all registry types"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.logger = logging.getLogger(__name__)
        self.registries = {}
        self._initialize_registries()
    
    def _initialize_registries(self):
        """Initialize all configured registry scanners"""
        
        # Always initialize filesystem registry
        filesystem_config = self.config.get('filesystem', {})
        base_path = filesystem_config.get('base_path', get_plugpipe_root())
        self.registries['filesystem'] = FilesystemRegistry(base_path)
        
        # Initialize database registry if configured
        if 'database' in self.config:
            db_config = self.config['database']
            db_path = db_config.get('db_path', get_plugpipe_path("plugpipe_storage.db"))
            self.registries['database'] = DatabaseRegistry(db_path)
        
        # Initialize remote API registry if configured
        if 'remote_api' in self.config:
            api_config = self.config['remote_api']
            self.registries['remote_api'] = RemoteAPIRegistry(
                api_config['endpoint'],
                api_config.get('auth', {})
            )
        
        # Initialize GitHub registry if configured
        if 'github' in self.config:
            github_config = self.config['github']
            self.registries['github'] = GitHubRegistry(
                github_config['repo_url'],
                github_config.get('branch', 'main'),
                github_config.get('token')
            )
    
    async def scan_all_registries(self, registry_types: List[str] = None, include_metadata: bool = True, output_format: str = "json") -> Dict[str, Any]:
        """Scan all configured registries"""
        
        if registry_types is None:
            registry_types = list(self.registries.keys())
        
        results = {
            "scan_timestamp": datetime.now().isoformat(),
            "registry_results": {},
            "summary": {
                "total_plugins": 0,
                "total_pipes": 0,
                "registries_scanned": len(registry_types),
                "registry_breakdown": {}
            }
        }
        
        # Scan each registry type
        for registry_type in registry_types:
            if registry_type in self.registries:
                try:
                    registry = self.registries[registry_type]
                    plugins = await registry.discover_plugins()
                    
                    # Count plugs vs pipes
                    plugs = [p for p in plugins if p.get('type') == 'plug']
                    pipes = [p for p in plugins if p.get('type') == 'pipe']
                    
                    registry_result = {
                        "registry_type": registry_type,
                        "total_plugins": len(plugins),
                        "plugs": len(plugs),
                        "pipes": len(pipes),
                        "plugins": plugins if include_metadata else []
                    }
                    
                    results["registry_results"][registry_type] = registry_result
                    results["summary"]["total_plugins"] += len(plugs)
                    results["summary"]["total_pipes"] += len(pipes)
                    results["summary"]["registry_breakdown"][registry_type] = {
                        "plugs": len(plugs),
                        "pipes": len(pipes),
                        "total": len(plugins)
                    }
                    
                except Exception as e:
                    self.logger.error(f"Failed to scan {registry_type} registry: {str(e)}")
                    results["registry_results"][registry_type] = {
                        "error": str(e),
                        "registry_type": registry_type
                    }
        
        # Calculate final totals
        results["summary"]["grand_total"] = results["summary"]["total_plugins"] + results["summary"]["total_pipes"]
        
        if output_format == "summary":
            return results["summary"]
        elif output_format == "csv":
            return self._format_as_csv(results)
        elif output_format == "detailed":
            return results
        else:  # json
            return results
    
    async def count_by_registry(self, breakdown_by_category: bool = True, include_health_status: bool = True) -> Dict[str, Any]:
        """Get counts by registry type"""
        counts = {
            "scan_timestamp": datetime.now().isoformat(),
            "registry_counts": {},
            "total_across_all_registries": {
                "plugs": 0,
                "pipes": 0,
                "total": 0
            }
        }
        
        for registry_type, registry in self.registries.items():
            try:
                plugins = await registry.discover_plugins()
                
                plugs = [p for p in plugins if p.get('type') == 'plug']
                pipes = [p for p in plugins if p.get('type') == 'pipe']
                
                registry_count = {
                    "plugs": len(plugs),
                    "pipes": len(pipes), 
                    "total": len(plugins)
                }
                
                if breakdown_by_category:
                    categories = {}
                    for plugin in plugins:
                        cat = plugin.get('category', 'unknown')
                        categories[cat] = categories.get(cat, 0) + 1
                    registry_count["categories"] = categories
                
                if include_health_status:
                    health = await registry.validate_registry_health()
                    registry_count["health_status"] = health
                
                counts["registry_counts"][registry_type] = registry_count
                counts["total_across_all_registries"]["plugs"] += len(plugs)
                counts["total_across_all_registries"]["pipes"] += len(pipes)
                counts["total_across_all_registries"]["total"] += len(plugins)
                
            except Exception as e:
                counts["registry_counts"][registry_type] = {"error": str(e)}
        
        return counts
    
    async def verify_registry_consistency(self, show_discrepancies: bool = True) -> Dict[str, Any]:
        """Verify consistency across all registry types"""
        consistency_report = {
            "scan_timestamp": datetime.now().isoformat(),
            "registries_compared": list(self.registries.keys()),
            "consistency_summary": {
                "total_unique_plugins": 0,
                "plugins_in_all_registries": 0,
                "plugins_missing_from_some": 0
            }
        }
        
        # Collect all plugins from all registries
        all_plugins_by_registry = {}
        for registry_type, registry in self.registries.items():
            try:
                plugins = await registry.discover_plugins()
                plugin_names = {p.get('name') for p in plugins if p.get('name')}
                all_plugins_by_registry[registry_type] = plugin_names
            except Exception as e:
                all_plugins_by_registry[registry_type] = set()
                self.logger.error(f"Failed to scan {registry_type}: {str(e)}")
        
        # Find unique plugins and intersections
        all_plugin_names = set()
        for names in all_plugins_by_registry.values():
            all_plugin_names.update(names)
        
        consistency_report["consistency_summary"]["total_unique_plugins"] = len(all_plugin_names)
        
        # Find plugins in all registries
        if len(all_plugins_by_registry) > 1:
            common_plugins = set.intersection(*all_plugins_by_registry.values())
            consistency_report["consistency_summary"]["plugins_in_all_registries"] = len(common_plugins)
            consistency_report["consistency_summary"]["plugins_missing_from_some"] = len(all_plugin_names) - len(common_plugins)
            
            if show_discrepancies:
                discrepancies = {}
                for plugin_name in all_plugin_names:
                    registries_with_plugin = [
                        reg_type for reg_type, names in all_plugins_by_registry.items() 
                        if plugin_name in names
                    ]
                    registries_missing_plugin = [
                        reg_type for reg_type in all_plugins_by_registry.keys()
                        if plugin_name not in all_plugins_by_registry[reg_type]
                    ]
                    
                    if registries_missing_plugin:
                        discrepancies[plugin_name] = {
                            "available_in": registries_with_plugin,
                            "missing_from": registries_missing_plugin
                        }
                
                consistency_report["discrepancies"] = discrepancies
        
        return consistency_report
    
    async def registry_health_check(self, timeout_seconds: int = 30) -> Dict[str, Any]:
        """Comprehensive health check of all registry endpoints"""
        health_report = {
            "scan_timestamp": datetime.now().isoformat(),
            "overall_health": "healthy",
            "registry_health": {}
        }
        
        unhealthy_count = 0
        
        for registry_type, registry in self.registries.items():
            try:
                health = await asyncio.wait_for(
                    registry.validate_registry_health(),
                    timeout=timeout_seconds
                )
                health_report["registry_health"][registry_type] = health
                
                if not health.get("accessible", False) or "error" in health:
                    unhealthy_count += 1
                    
            except asyncio.TimeoutError:
                health_report["registry_health"][registry_type] = {
                    "error": f"Health check timed out after {timeout_seconds} seconds",
                    "registry_type": registry_type,
                    "accessible": False
                }
                unhealthy_count += 1
            except Exception as e:
                health_report["registry_health"][registry_type] = {
                    "error": str(e),
                    "registry_type": registry_type,
                    "accessible": False
                }
                unhealthy_count += 1
        
        # Determine overall health
        total_registries = len(self.registries)
        if unhealthy_count == 0:
            health_report["overall_health"] = "healthy"
        elif unhealthy_count < total_registries:
            health_report["overall_health"] = "degraded"
        else:
            health_report["overall_health"] = "unhealthy"
        
        health_report["summary"] = {
            "total_registries": total_registries,
            "healthy_registries": total_registries - unhealthy_count,
            "unhealthy_registries": unhealthy_count,
            "health_percentage": ((total_registries - unhealthy_count) / total_registries * 100) if total_registries > 0 else 0
        }
        
        return health_report
    
    def _format_as_csv(self, results: Dict[str, Any]) -> str:
        """Format results as CSV"""
        import io
        import csv
        
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Header
        writer.writerow(['registry_type', 'plugin_name', 'version', 'category', 'type', 'description'])
        
        # Data rows
        for registry_type, registry_result in results["registry_results"].items():
            if "plugins" in registry_result:
                for plugin in registry_result["plugins"]:
                    writer.writerow([
                        registry_type,
                        plugin.get('name', ''),
                        plugin.get('version', ''),
                        plugin.get('category', ''),
                        plugin.get('type', ''),
                        plugin.get('description', '')[:100] + '...' if len(plugin.get('description', '')) > 100 else plugin.get('description', '')
                    ])
        
        return output.getvalue()

def process(ctx, cfg):
    """Standard PlugPipe process function"""
    scanner = UniversalRegistryScanner()
    
    # Get input data from context
    input_data = ctx.get("input") or ctx.get("with") or ctx
    if not isinstance(input_data, dict):
        input_data = {"operation": "count_by_registry"}
    
    operation = input_data.get('operation', 'count_by_registry')
    
    try:
        # Run the async operation
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        
        if operation == "scan_all_registries":
            registry_types = input_data.get('registry_types', ["filesystem"])
            include_metadata = input_data.get('include_metadata', True)
            output_format = input_data.get('output_format', 'json')
            result = loop.run_until_complete(
                scanner.scan_all_registries(registry_types, include_metadata, output_format)
            )
            
        elif operation == "count_by_registry":
            breakdown_by_category = input_data.get('breakdown_by_category', True)
            include_health_status = input_data.get('include_health_status', False)  # Default false for performance
            result = loop.run_until_complete(
                scanner.count_by_registry(breakdown_by_category, include_health_status)
            )
            
        elif operation == "verify_registry_consistency":
            show_discrepancies = input_data.get('show_discrepancies', True)
            result = loop.run_until_complete(
                scanner.verify_registry_consistency(show_discrepancies)
            )
            
        elif operation == "registry_health_check":
            timeout_seconds = input_data.get('timeout_seconds', 30)
            result = loop.run_until_complete(
                scanner.registry_health_check(timeout_seconds)
            )
            
        else:
            return {
                "success": False,
                "error": f"Unknown operation: {operation}",
                "available_operations": ["scan_all_registries", "count_by_registry", "verify_registry_consistency", "registry_health_check"]
            }
        
        loop.close()
        
        return {
            "success": True,
            "operation": operation,
            "data": result
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "operation": operation
        }

def main():
    """Main entry point for direct usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Universal PlugPipe Registry Scanner')
    parser.add_argument('operation', choices=['scan_all_registries', 'count_by_registry', 'verify_registry_consistency', 'registry_health_check'])
    parser.add_argument('--config', '-c', help='Configuration file path (JSON/YAML)')
    parser.add_argument('--registry-types', nargs='+', default=['filesystem'], help='Registry types to scan')
    parser.add_argument('--output-format', choices=['json', 'summary', 'detailed', 'csv'], default='json')
    
    args = parser.parse_args()
    
    # Load configuration
    config = {}
    if args.config:
        with open(args.config, 'r') as f:
            if args.config.endswith('.yaml') or args.config.endswith('.yml'):
                config = yaml.safe_load(f)
            else:
                config = json.load(f)
    
    scanner = UniversalRegistryScanner(config)
    
    # Create input data
    input_data = {
        'operation': args.operation,
        'registry_types': args.registry_types,
        'output_format': args.output_format
    }
    
    # Run via process function
    result = process({'input': input_data}, {})
    
    if result['success']:
        if args.output_format == 'csv':
            print(result['data'])
        else:
            print(json.dumps(result['data'], indent=2))
    else:
        print(f"Error: {result['error']}", file=sys.stderr)
        sys.exit(1)

if __name__ == "__main__":
    main()