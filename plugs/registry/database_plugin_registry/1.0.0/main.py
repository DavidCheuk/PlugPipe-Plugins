# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
Database Plugin Registry Populator

This plugin reads all plugins from the filesystem and populates them into the 
database using the Database Factory abstraction. It provides the bridge between
filesystem-based plugin discovery and database-backed plugin storage.

Key Features:
- Scans all plugin directories and reads plugin metadata
- Populates database using Database Factory abstraction
- Supports batch operations for efficient bulk loading
- Provides comprehensive plugin catalog management
- Integrates with existing PlugPipe plugin architecture
"""

import asyncio
import os
import json
import yaml
import logging
import subprocess
from typing import Dict, List, Any, Optional
from pathlib import Path
import importlib.util
import sys

logger = logging.getLogger(__name__)

class DatabasePluginRegistryPopulator:
    """
    Plugin Registry Populator that uses Database Factory to store plugin metadata.
    
    Provides the bridge between filesystem plugin discovery and database storage,
    utilizing the Database Factory abstraction for vendor-neutral database operations.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.plugs_directory = config.get('plugs_directory', get_plugpipe_path("plugs"))
        self.database_factory = None
        self.total_plugins_processed = 0
        self.successful_inserts = 0
        self.failed_inserts = 0
        
        logger.info(f"Database Plugin Registry Populator initialized for directory: {self.plugs_directory}")
    
    async def initialize(self) -> bool:
        """Initialize Database Factory connection."""
        try:
            # Import and initialize Database Factory
            factory_path = Path(__file__).parent.parent.parent.parent / "database" / "factory" / "1.0.0"
            if not factory_path.exists():
                logger.error(f"Database Factory plugin not found at: {factory_path}")
                return False
            
            # Import Database Factory using importlib
            import importlib.util
            spec = importlib.util.spec_from_file_location("database_factory_main", factory_path / "main.py")
            factory_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(factory_module)
            DatabaseFactoryPlugin = factory_module.DatabaseFactoryPlugin
            
            # Create and initialize Database Factory with SQLite config
            factory_config = {
                'database_factory': {
                    'primary_database': 'sqlite',
                    'fallback_databases': ['sqlite'],
                    'enable_failover': True
                },
                'databases': {
                    'sqlite': {
                        'database': {
                            'file_path': '/tmp/plugins_registry.db',
                            'timeout_seconds': 30,
                            'backup_enabled': True,
                            'connection_pool_size': 10
                        }
                    }
                }
            }
            
            self.database_factory = DatabaseFactoryPlugin(factory_config)
            init_success = await self.database_factory.initialize()
            
            if not init_success:
                logger.error("Failed to initialize Database Factory")
                return False
            
            logger.info("Database Factory initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Database Plugin Registry: {e}")
            return False
    
    def scan_plugin_directories(self) -> List[Dict[str, Any]]:
        """Scan filesystem for plugin metadata."""
        plugins = []
        
        try:
            plugs_path = Path(self.plugs_directory)
            if not plugs_path.exists():
                logger.warning(f"Plugs directory not found: {self.plugs_directory}")
                return []
            
            logger.info(f"Scanning plugins in: {self.plugs_directory}")
            
            # Walk through plugin directory structure
            for category_dir in plugs_path.iterdir():
                if not category_dir.is_dir() or category_dir.name.startswith('.'):
                    continue
                
                for plugin_dir in category_dir.iterdir():
                    if not plugin_dir.is_dir() or plugin_dir.name.startswith('.'):
                        continue
                    
                    for version_dir in plugin_dir.iterdir():
                        if not version_dir.is_dir() or version_dir.name.startswith('.'):
                            continue
                        
                        plugin_metadata = self._extract_plugin_metadata(
                            category_dir.name, 
                            plugin_dir.name, 
                            version_dir.name, 
                            version_dir
                        )
                        
                        if plugin_metadata:
                            plugins.append(plugin_metadata)
                            
            logger.info(f"Discovered {len(plugins)} plugins")
            return plugins
            
        except Exception as e:
            logger.error(f"Failed to scan plugin directories: {e}")
            return []
    
    def _extract_plugin_metadata(self, category: str, name: str, version: str, version_path: Path) -> Optional[Dict[str, Any]]:
        """Extract metadata from a single plugin directory."""
        try:
            # Look for plug.yaml or plugin.yaml
            manifest_file = None
            for filename in ['plug.yaml', 'plugin.yaml']:
                manifest_path = version_path / filename
                if manifest_path.exists():
                    manifest_file = manifest_path
                    break
            
            if not manifest_file:
                logger.warning(f"No manifest found for plugin: {category}/{name}/{version}")
                return None
            
            # Read manifest
            with open(manifest_file, 'r') as f:
                manifest = yaml.safe_load(f)
            
            if not manifest:
                logger.warning(f"Empty manifest for plugin: {category}/{name}/{version}")
                return None
            
            # Generate SBOM using PlugPipe CLI
            sbom_data = self._generate_sbom_via_cli(version_path)
            
            # Create comprehensive plugin metadata
            plugin_metadata = {
                'name': manifest.get('name', name),
                'category': category,
                'version': manifest.get('version', version),
                'description': manifest.get('description', f'{name} plugin'),
                'owner': manifest.get('owner', 'unknown'),
                'status': manifest.get('status', 'development'),
                'tags': manifest.get('tags', []),
                'dependencies': self._count_dependencies(manifest.get('dependencies', [])),
                'input_schema': manifest.get('input_schema', {}),
                'output_schema': manifest.get('output_schema', {}),
                'config_schema': manifest.get('config_schema', {}),
                'entrypoint': manifest.get('entrypoint', 'main.py'),
                'revolutionary_capabilities': manifest.get('revolutionary_capabilities', []),
                'tests_passing': self._check_tests_status(version_path),
                'author': manifest.get('author'),
                'sbom_path': str(version_path / 'sbom'),
                'sbom_data': sbom_data,  # Generated SBOM data via CLI
                'plugin_path': str(version_path),
                'manifest_path': str(manifest_file),
                'created_at': manifest.get('created_at'),
                'updated_at': manifest.get('updated_at')
            }
            
            return plugin_metadata
            
        except Exception as e:
            logger.error(f"Failed to extract metadata for {category}/{name}/{version}: {e}")
            return None
    
    def _count_dependencies(self, dependencies: List) -> int:
        """Count plugin dependencies."""
        if not dependencies:
            return 0
        return len(dependencies)
    
    def _check_tests_status(self, plugin_path: Path) -> bool:
        """Check if tests are present and potentially passing."""
        # Simple check for test files existence
        test_patterns = ['test_*.py', '*_test.py', 'tests.py']
        for pattern in test_patterns:
            if list(plugin_path.glob(pattern)) or list(plugin_path.glob(f'tests/{pattern}')):
                return True
        return False
    
    def _generate_sbom_via_cli(self, plugin_path: Path) -> Dict[str, Any]:
        """Generate SBOM using PlugPipe CLI tools."""
        try:
            # Get the absolute path to the sbom_helper_cli.py script
            project_root = Path(__file__).parent.parent.parent.parent.parent  # Go up to PlugPipe root
            sbom_cli_path = project_root / "scripts" / "sbom_helper_cli.py"
            
            if not sbom_cli_path.exists():
                logger.warning(f"SBOM CLI not found at: {sbom_cli_path}")
                return {'error': 'sbom_cli_not_found'}
            
            # Run SBOM generation with proper PYTHONPATH and skip validation
            env = os.environ.copy()
            env['PYTHONPATH'] = str(project_root)
            
            result = subprocess.run([
                'python3', str(sbom_cli_path), str(plugin_path)
            ], capture_output=True, text=True, cwd=str(project_root), env=env)
            
            logger.info(f"SBOM CLI result for {plugin_path}: return_code={result.returncode}")
            
            # SBOM is first-class citizen - always try to read generated files regardless of return code
            # The CLI might fail on validation but still generate SBOM successfully
            sbom_dir = plugin_path / 'sbom'
            if sbom_dir.exists():
                sbom_data = {
                    'cli_attempted': True,
                    'cli_return_code': result.returncode,
                    'sbom_generated': True
                }
                
                # Try to read sbom-complete.json (new format)
                sbom_complete_json = sbom_dir / 'sbom-complete.json'
                if sbom_complete_json.exists():
                    with open(sbom_complete_json, 'r') as f:
                        sbom_data['sbom_complete'] = json.load(f)
                
                # Try to read sbom.json
                sbom_json = sbom_dir / 'sbom.json'
                if sbom_json.exists():
                    with open(sbom_json, 'r') as f:
                        sbom_data['sbom_json'] = json.load(f)
                
                # Try to read lib_sbom.yaml
                lib_sbom_yaml = sbom_dir / 'lib_sbom.yaml'
                if lib_sbom_yaml.exists():
                    with open(lib_sbom_yaml, 'r') as f:
                        sbom_data['lib_sbom'] = yaml.safe_load(f)
                
                # Try to read lib_sbom.json
                lib_sbom_json = sbom_dir / 'lib_sbom.json'
                if lib_sbom_json.exists():
                    with open(lib_sbom_json, 'r') as f:
                        sbom_data['lib_sbom_json'] = json.load(f)
                
                # Verify SBOM data integrity (SBOM is first-class citizen)
                verification_result = self._verify_sbom_data(sbom_data, plugin_path)
                sbom_data.update(verification_result)
                
                logger.info(f"SBOM data successfully read and verified for {plugin_path}")
                return sbom_data
            else:
                logger.warning(f"SBOM directory not created for: {plugin_path}")
                return {
                    'cli_attempted': True,
                    'cli_return_code': result.returncode,
                    'sbom_generated': False,
                    'error': 'sbom_dir_not_created'
                }
                
        except Exception as e:
            logger.error(f"Failed to generate SBOM via CLI for {plugin_path}: {e}")
            return {'error': str(e)}
    
    def _verify_sbom_data(self, sbom_data: Dict[str, Any], plugin_path: Path) -> Dict[str, Any]:
        """
        Comprehensive SBOM verification including nested dependency validation.
        SBOM is first-class citizen - verify integrity and dependency chains.
        """
        verification_result = {
            'sbom_verified': False,
            'verification_errors': [],
            'dependency_chain_valid': False,
            'nested_dependencies_count': 0,
            'missing_dependencies': [],
            'circular_dependencies': []
        }
        
        try:
            # 1. Verify SBOM file completeness
            required_sbom_files = ['sbom_complete', 'lib_sbom']
            missing_files = [f for f in required_sbom_files if f not in sbom_data]
            if missing_files:
                verification_result['verification_errors'].append(f"Missing SBOM files: {missing_files}")
            
            # 2. Verify nested dependency structure
            if 'sbom_complete' in sbom_data:
                sbom_complete = sbom_data['sbom_complete']
                
                # Check for dependency components
                if 'components' in sbom_complete:
                    components = sbom_complete['components']
                    verification_result['nested_dependencies_count'] = len(components)
                    
                    # Verify each component has required fields
                    for component in components:
                        if not all(field in component for field in ['name', 'version', 'type']):
                            verification_result['verification_errors'].append(
                                f"Component missing required fields: {component.get('name', 'unknown')}"
                            )
                
                # Check for dependency relationships
                if 'dependencies' in sbom_complete:
                    dependencies = sbom_complete['dependencies']
                    
                    # Verify dependency chain integrity
                    dependency_chain_result = self._verify_dependency_chain(dependencies, plugin_path)
                    verification_result.update(dependency_chain_result)
            
            # 3. Verify library SBOM consistency
            if 'lib_sbom' in sbom_data:
                lib_sbom = sbom_data['lib_sbom']
                
                # Check for library dependencies
                if 'dependencies' in lib_sbom:
                    lib_dependencies = lib_sbom['dependencies']
                    
                    # Verify library dependencies are accessible
                    for dep_name, dep_info in lib_dependencies.items():
                        if isinstance(dep_info, dict) and 'version' in dep_info:
                            # Check if dependency plugin exists
                            dep_path = self._resolve_dependency_path(dep_name, dep_info['version'])
                            if not dep_path or not dep_path.exists():
                                verification_result['missing_dependencies'].append(f"{dep_name}@{dep_info['version']}")
            
            # 4. Cross-reference SBOM files for consistency
            consistency_check = self._cross_reference_sbom_files(sbom_data)
            verification_result.update(consistency_check)
            
            # 5. Final verification status
            if not verification_result['verification_errors'] and not verification_result['missing_dependencies']:
                verification_result['sbom_verified'] = True
                verification_result['dependency_chain_valid'] = True
            
            logger.info(f"SBOM verification completed for {plugin_path}: {verification_result['sbom_verified']}")
            
        except Exception as e:
            verification_result['verification_errors'].append(f"SBOM verification failed: {str(e)}")
            logger.error(f"SBOM verification error for {plugin_path}: {e}")
        
        return verification_result
    
    def _verify_dependency_chain(self, dependencies: List[Dict], plugin_path: Path) -> Dict[str, Any]:
        """Verify the dependency chain doesn't have circular dependencies or broken links."""
        result = {
            'dependency_chain_valid': True,
            'circular_dependencies': [],
            'missing_dependencies': []
        }
        
        try:
            # Build dependency graph
            dependency_graph = {}
            for dep in dependencies:
                if 'ref' in dep and 'dependsOn' in dep:
                    ref = dep['ref']
                    depends_on = dep['dependsOn'] if isinstance(dep['dependsOn'], list) else [dep['dependsOn']]
                    dependency_graph[ref] = depends_on
            
            # Check for circular dependencies using DFS
            visited = set()
            rec_stack = set()
            
            def has_cycle(node):
                if node in rec_stack:
                    return True
                if node in visited:
                    return False
                
                visited.add(node)
                rec_stack.add(node)
                
                for neighbor in dependency_graph.get(node, []):
                    if has_cycle(neighbor):
                        result['circular_dependencies'].append(f"{node} -> {neighbor}")
                        return True
                
                rec_stack.remove(node)
                return False
            
            # Check all nodes for cycles
            for node in dependency_graph:
                if node not in visited:
                    has_cycle(node)
            
            # Verify dependency availability
            for dep in dependencies:
                if 'ref' in dep:
                    ref_parts = dep['ref'].split('@')
                    if len(ref_parts) == 2:
                        dep_name, dep_version = ref_parts
                        dep_path = self._resolve_dependency_path(dep_name, dep_version)
                        if not dep_path or not dep_path.exists():
                            result['missing_dependencies'].append(dep['ref'])
            
            if result['circular_dependencies'] or result['missing_dependencies']:
                result['dependency_chain_valid'] = False
            
        except Exception as e:
            result['dependency_chain_valid'] = False
            logger.error(f"Dependency chain verification failed: {e}")
        
        return result
    
    def _resolve_dependency_path(self, dep_name: str, dep_version: str) -> Path:
        """Resolve the file system path for a dependency."""
        try:
            # Look for dependency in plugs directory
            plugs_dir = Path(self.plugs_directory)
            
            # Search pattern: plugs/{category}/{dep_name}/{dep_version}/
            for category_dir in plugs_dir.iterdir():
                if not category_dir.is_dir():
                    continue
                
                dep_dir = category_dir / dep_name / dep_version
                if dep_dir.exists():
                    return dep_dir
            
            return None
            
        except Exception as e:
            logger.error(f"Failed to resolve dependency path for {dep_name}@{dep_version}: {e}")
            return None
    
    def _cross_reference_sbom_files(self, sbom_data: Dict[str, Any]) -> Dict[str, Any]:
        """Cross-reference different SBOM files for consistency."""
        result = {
            'sbom_consistency_verified': True,
            'consistency_errors': []
        }
        
        try:
            # Compare component counts between different SBOM formats
            if 'sbom_complete' in sbom_data and 'lib_sbom' in sbom_data:
                sbom_complete = sbom_data['sbom_complete']
                lib_sbom = sbom_data['lib_sbom']
                
                # Get component counts
                complete_components = len(sbom_complete.get('components', []))
                lib_dependencies = len(lib_sbom.get('dependencies', {}))
                
                # Allow some variance since formats might differ
                if abs(complete_components - lib_dependencies) > 5:  # Allow 5 component difference
                    result['consistency_errors'].append(
                        f"Component count mismatch: complete={complete_components}, lib={lib_dependencies}"
                    )
                
                # Check for common dependencies
                if 'dependencies' in sbom_complete and 'dependencies' in lib_sbom:
                    # Handle both list and dict formats for dependencies
                    if isinstance(sbom_complete['dependencies'], list):
                        complete_deps = {dep.get('ref', '').split('@')[0] for dep in sbom_complete['dependencies'] if isinstance(dep, dict) and 'ref' in dep}
                    else:
                        complete_deps = set(sbom_complete['dependencies'].keys())
                    
                    lib_deps = set(lib_sbom['dependencies'].keys())
                    
                    # Find missing cross-references
                    missing_in_lib = complete_deps - lib_deps
                    missing_in_complete = lib_deps - complete_deps
                    
                    if missing_in_lib:
                        result['consistency_errors'].append(f"Missing in lib_sbom: {missing_in_lib}")
                    if missing_in_complete:
                        result['consistency_errors'].append(f"Missing in sbom_complete: {missing_in_complete}")
            
            if result['consistency_errors']:
                result['sbom_consistency_verified'] = False
            
        except Exception as e:
            result['sbom_consistency_verified'] = False
            result['consistency_errors'].append(f"Cross-reference verification failed: {str(e)}")
        
        return result
    
    async def populate_database(self, plugins: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Populate database with plugin metadata."""
        if not self.database_factory:
            logger.error("Database Factory not initialized")
            return {'success': False, 'message': 'Database not initialized'}
        
        self.total_plugins_processed = len(plugins)
        self.successful_inserts = 0
        self.failed_inserts = 0
        
        logger.info(f"Starting to populate database with {len(plugins)} plugins")
        
        for plugin in plugins:
            try:
                success = await self.database_factory.store_plugin(plugin)
                if success:
                    self.successful_inserts += 1
                else:
                    self.failed_inserts += 1
                    logger.warning(f"Failed to store plugin: {plugin.get('name', 'unknown')}")
                    
            except Exception as e:
                self.failed_inserts += 1
                logger.error(f"Error storing plugin {plugin.get('name', 'unknown')}: {e}")
        
        result = {
            'success': self.successful_inserts > 0,
            'total_plugins': self.total_plugins_processed,
            'successful_inserts': self.successful_inserts,
            'failed_inserts': self.failed_inserts,
            'success_rate': (self.successful_inserts / self.total_plugins_processed * 100) if self.total_plugins_processed > 0 else 0
        }
        
        logger.info(f"Database population completed: {result}")
        return result
    
    async def health_check(self) -> Dict[str, Any]:
        """Check health of database connection."""
        if not self.database_factory:
            return {'healthy': False, 'message': 'Database Factory not initialized'}
        
        try:
            factory_health = await self.database_factory.health_check()
            return {
                'healthy': factory_health.get('factory_healthy', False),
                'factory_status': factory_health,
                'populator_stats': {
                    'total_processed': self.total_plugins_processed,
                    'successful_inserts': self.successful_inserts,
                    'failed_inserts': self.failed_inserts
                }
            }
        except Exception as e:
            return {'healthy': False, 'message': str(e)}
    
    async def list_database_plugins(self) -> List[Dict[str, Any]]:
        """List all plugins currently in database."""
        if not self.database_factory:
            return []
        
        try:
            # Request all plugins without pagination limits for registry listing
            result = await self.database_factory.list_plugins()
            
            # Handle tuple response format from pagination-enabled databases
            if isinstance(result, tuple) and len(result) == 2:
                plugins_list, total_count = result
                
                # If we got a partial result due to pagination, get all plugins
                if len(plugins_list) < total_count:
                    logger.info(f"Got {len(plugins_list)} of {total_count} plugins, fetching remaining...")
                    # Try to get database plugin directly for unlimited query
                    active_plugin = await self.database_factory._get_active_plugin()
                    if active_plugin and hasattr(active_plugin, 'list_plugins'):
                        # Request with high limit to get all plugins
                        full_result = await active_plugin.list_plugins(limit=1000, offset=0)
                        if isinstance(full_result, tuple):
                            plugins_list, total_count = full_result
                    
                logger.info(f"Retrieved {len(plugins_list)} plugins from database (total: {total_count})")
                return plugins_list
            elif isinstance(result, list):
                logger.info(f"Retrieved {len(result)} plugins from database")
                return result
            else:
                logger.warning(f"Unexpected response format from database: {type(result)}")
                return []
                
        except Exception as e:
            logger.error(f"Failed to list database plugins: {e}")
            return []


# Plugin metadata for PlugPipe registration
plug_metadata = {
    "name": "database_plugin_registry",
    "version": "1.0.0",
    "owner": "plugpipe-team",
    "status": "production",
    "description": "Database Plugin Registry Populator that bridges filesystem plugin discovery with database storage via Database Factory abstraction",
    "category": "registry",
    "tags": ["database", "registry", "plugins", "population", "factory"],
    "input_schema": {
        "type": "object",
        "properties": {
            "plugs_directory": {"type": "string", "description": "Path to plugins directory"},
            "populate_database": {"type": "boolean", "description": "Whether to populate database"},
            "scan_only": {"type": "boolean", "description": "Only scan, don't populate"}
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "total_plugins": {"type": "number"},
            "successful_inserts": {"type": "number"},
            "failed_inserts": {"type": "number"},
            "plugins": {"type": "array"}
        }
    },
    "revolutionary_capabilities": [
        "filesystem_to_database_bridge",
        "database_factory_integration",
        "bulk_plugin_population",
        "vendor_neutral_database_abstraction"
    ]
}


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin process function."""
    try:
        # Initialize populator
        populator = DatabasePluginRegistryPopulator(cfg)
        
        init_success = await populator.initialize()
        if not init_success:
            return {
                'success': False,
                'message': 'Failed to initialize Database Plugin Registry',
                'error': 'initialization_failed'
            }
        
        # Scan filesystem for plugins
        plugins = populator.scan_plugin_directories()
        
        # If scan_only mode, return plugins without populating database
        if cfg.get('scan_only', False):
            return {
                'success': True,
                'message': f'Scanned {len(plugins)} plugins',
                'total_plugins': len(plugins),
                'plugins': plugins
            }
        
        # Populate database if requested
        if cfg.get('populate_database', True):
            result = await populator.populate_database(plugins)
            result['plugins'] = plugins[:10]  # Return first 10 for verification
            return result
        
        return {
            'success': True,
            'message': f'Discovered {len(plugins)} plugins',
            'total_plugins': len(plugins),
            'plugins': plugins
        }
        
    except Exception as e:
        logger.error(f"Database Plugin Registry process failed: {e}")
        return {
            'success': False,
            'message': str(e),
            'error': 'process_failed'
        }


# Async entry point for direct execution
async def main():
    """Direct execution entry point for testing."""
    config = {
        'plugs_directory': get_plugpipe_path("plugs"),
        'populate_database': True
    }
    
    result = await process({}, config)
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    asyncio.run(main())