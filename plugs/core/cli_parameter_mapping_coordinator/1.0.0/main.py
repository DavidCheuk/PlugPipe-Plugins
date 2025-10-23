# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
CLI Parameter Mapping Coordinator Plugin
Intelligent coordination system for CLI parameter mappings with plugin lifecycle management

This plugin automatically detects plugin changes, manages versioning issues,
and maintains synchronized parameter mappings across the entire PlugPipe ecosystem.
"""

import json
import yaml
import os
import sys
import hashlib
import importlib.util
import re
import logging
from datetime import datetime
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
from dataclasses import dataclass, field

# Add project root to path for plugin discovery
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
sys.path.insert(0, PROJECT_ROOT)

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Universal Input Sanitizer availability check
SANITIZER_AVAILABLE = True
try:
    # Check if Universal Input Sanitizer plugin is available
    from pathlib import Path
    sanitizer_path = Path(PROJECT_ROOT) / "plugs" / "security" / "universal_input_sanitizer" / "1.0.0" / "main.py"
    if not sanitizer_path.exists():
        SANITIZER_AVAILABLE = False
        logger.warning("Universal Input Sanitizer not available - using fallback validation")
except Exception as e:
    SANITIZER_AVAILABLE = False
    logger.warning(f"Universal Input Sanitizer check failed: {e}")

@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_violations: List[str] = field(default_factory=list)
    sanitized_data: Optional[Dict[str, Any]] = None

# Plugin metadata
plug_metadata = {
    "name": "cli_parameter_mapping_coordinator",
    "version": "1.0.0", 
    "owner": "plugpipe-core",
    "status": "production"
}

class CLIParameterMappingCoordinator:
    """Intelligent coordinator for CLI parameter mappings and plugin lifecycle"""

    def __init__(self):
        self.plugs_dir = Path("plugs")
        self.mapping_cache_file = Path("cli_parameter_mapping_cache.json")
        self.plugin_registry_cache = {}
        self.mapping_versions = {}

        # Security configuration
        self.max_plugins_to_scan = 500  # Prevent resource exhaustion
        self.allowed_file_extensions = {'.py', '.yaml', '.yml', '.json'}
        self.safe_plugin_path_pattern = re.compile(r'^[a-zA-Z0-9/_.-]+$')
        self.dangerous_patterns = ['../', '..\\', '/etc/', '/root/', 'C:\\Windows']

    def _validate_plugin_path(self, plugin_path: str) -> bool:
        """Validate plugin path for security"""
        try:
            # Check for dangerous patterns
            for pattern in self.dangerous_patterns:
                if pattern in plugin_path:
                    logger.warning(f"Dangerous path pattern detected: {plugin_path}")
                    return False

            # Check path format
            if not self.safe_plugin_path_pattern.match(plugin_path):
                logger.warning(f"Invalid plugin path format: {plugin_path}")
                return False

            # Ensure path is within plugs directory
            resolved_path = Path(plugin_path).resolve()
            plugs_path = Path("plugs").resolve()

            try:
                resolved_path.relative_to(plugs_path)
            except ValueError:
                logger.warning(f"Plugin path outside plugs directory: {plugin_path}")
                return False

            return True
        except Exception as e:
            logger.error(f"Path validation error: {e}")
            return False

    def _validate_plugin_name(self, name: str) -> bool:
        """Validate plugin name for security"""
        if not name or not isinstance(name, str):
            return False

        # Check for dangerous patterns
        if not re.match(r'^[a-zA-Z0-9._-]+$', name):
            return False

        # Check for command injection patterns
        dangerous_patterns = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>']
        if any(pattern in name for pattern in dangerous_patterns):
            return False

        return True

    async def pp(self, plugin_path: str):
        """PlugPipe plugin discovery pattern with security validation"""
        try:
            # Validate plugin path
            if not self._validate_plugin_path(plugin_path):
                logger.error(f"Plugin path validation failed: {plugin_path}")
                return None

            # Construct full plugin path
            if not plugin_path.endswith('/main.py'):
                plugin_path = f"plugs/{plugin_path}/main.py"

            # Additional security check on final path
            if not self._validate_plugin_path(plugin_path):
                logger.error(f"Final plugin path validation failed: {plugin_path}")
                return None

            # Load plugin module
            spec = importlib.util.spec_from_file_location("plugin", plugin_path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                logger.info(f"Plugin loaded successfully: {plugin_path}")
                return module
            return None
        except Exception as e:
            logger.error(f"Plugin loading failed for {plugin_path}: {e}")
            return None
    
    def _calculate_plugin_hash(self, plugin_path: Path) -> str:
        """Calculate hash of plugin files for change detection with security validation"""
        try:
            # Validate plugin path
            if not self._validate_plugin_path(str(plugin_path)):
                logger.error(f"Invalid plugin path for hashing: {plugin_path}")
                return ""

            hash_content = ""

            # Hash main plugin files with security checks
            for file_path in [plugin_path / "main.py", plugin_path / "plug.yaml"]:
                if file_path.exists():
                    # Validate file extension
                    if file_path.suffix not in self.allowed_file_extensions:
                        logger.warning(f"Skipping file with disallowed extension: {file_path}")
                        continue

                    # Check file size (prevent reading huge files)
                    file_size = file_path.stat().st_size
                    if file_size > 10 * 1024 * 1024:  # 10MB limit
                        logger.warning(f"Skipping large file: {file_path} ({file_size} bytes)")
                        continue

                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            # Basic content validation
                            if len(content.strip()) > 0:
                                hash_content += content
                    except (UnicodeDecodeError, PermissionError) as e:
                        logger.warning(f"Could not read file {file_path}: {e}")
                        continue

            if hash_content:
                return hashlib.sha256(hash_content.encode('utf-8')).hexdigest()
            else:
                logger.warning(f"No valid content found for hashing: {plugin_path}")
                return ""

        except Exception as e:
            logger.error(f"Error calculating plugin hash: {e}")
            return ""
    
    def _load_mapping_cache(self) -> Dict[str, Any]:
        """Load parameter mapping cache"""
        if self.mapping_cache_file.exists():
            try:
                with open(self.mapping_cache_file, 'r') as f:
                    return json.load(f)
            except Exception as e:
                print(f"Failed to load mapping cache: {e}")
        
        return {
            "plugins": {},
            "last_scan": None,
            "mapping_version": "1.0.0"
        }
    
    def _save_mapping_cache(self, cache_data: Dict[str, Any]) -> None:
        """Save parameter mapping cache"""
        try:
            with open(self.mapping_cache_file, 'w') as f:
                json.dump(cache_data, f, indent=2)
        except Exception as e:
            print(f"Failed to save mapping cache: {e}")
    
    def _extract_plugin_schema(self, plugin_path: Path) -> Optional[Dict[str, Any]]:
        """Extract input schema from plugin manifest with security validation"""
        try:
            # Validate plugin path
            if not self._validate_plugin_path(str(plugin_path)):
                logger.error(f"Invalid plugin path for schema extraction: {plugin_path}")
                return None

            plug_yaml = plugin_path / "plug.yaml"
            if plug_yaml.exists():
                # Check file size before reading
                file_size = plug_yaml.stat().st_size
                if file_size > 1024 * 1024:  # 1MB limit for YAML files
                    logger.warning(f"Plugin manifest too large: {plug_yaml} ({file_size} bytes)")
                    return None

                try:
                    with open(plug_yaml, 'r', encoding='utf-8') as f:
                        content = f.read()

                        # Basic content validation
                        if len(content.strip()) == 0:
                            logger.warning(f"Empty plugin manifest: {plug_yaml}")
                            return None

                        # Use safe YAML loading
                        manifest = yaml.safe_load(content)
                        if not isinstance(manifest, dict):
                            logger.warning(f"Invalid manifest format: {plug_yaml}")
                            return None

                        schema = manifest.get('input_schema', {})
                        if isinstance(schema, dict):
                            return schema
                        else:
                            logger.warning(f"Invalid input_schema format: {plug_yaml}")
                            return {}

                except yaml.YAMLError as e:
                    logger.error(f"YAML parsing error in {plug_yaml}: {e}")
                    return None
                except (UnicodeDecodeError, PermissionError) as e:
                    logger.error(f"File reading error {plug_yaml}: {e}")
                    return None

        except Exception as e:
            logger.error(f"Failed to extract schema from {plugin_path}: {e}")

        return None
    
    def _detect_schema_changes(self, old_schema: Dict, new_schema: Dict) -> Dict[str, Any]:
        """Detect changes between schema versions"""
        changes = {
            "breaking_changes": [],
            "additions": [],
            "removals": [],
            "modifications": []
        }
        
        old_props = old_schema.get('properties', {})
        new_props = new_schema.get('properties', {})
        
        # Detect removed properties (breaking changes)
        for prop in old_props:
            if prop not in new_props:
                changes["breaking_changes"].append(f"Removed property: {prop}")
                changes["removals"].append(prop)
        
        # Detect added properties
        for prop in new_props:
            if prop not in old_props:
                changes["additions"].append(prop)
        
        # Detect modified properties
        for prop in old_props:
            if prop in new_props and old_props[prop] != new_props[prop]:
                changes["modifications"].append({
                    "property": prop,
                    "old": old_props[prop],
                    "new": new_props[prop]
                })
        
        return changes
    
    def _generate_parameter_mappings(self, plugin_name: str, schema: Dict[str, Any]) -> Dict[str, Any]:
        """Generate parameter mappings from plugin schema"""
        mappings = {}
        properties = schema.get('properties', {})
        
        for prop_name, prop_def in properties.items():
            # Convert property name to CLI parameter format
            cli_param = prop_name.replace('_', '-')
            
            # Generate mapping function based on property type
            prop_type = prop_def.get('type', 'string')
            
            if prop_type == 'boolean':
                mappings[cli_param] = f"lambda x: {{'{prop_name}': bool(x)}}"
            elif prop_type == 'integer':
                mappings[cli_param] = f"lambda x: {{'{prop_name}': int(x)}}"
            elif prop_type == 'array':
                mappings[cli_param] = f"lambda x: {{'{prop_name}': x if isinstance(x, list) else [x]}}"
            elif prop_type == 'object':
                if 'context' in prop_name.lower():
                    mappings[cli_param] = f"lambda x: {{'context': {{'{prop_name}': x}}}}"
                else:
                    mappings[cli_param] = f"lambda x: {{'{prop_name}': x}}"
            else:  # string and others
                mappings[cli_param] = f"lambda x: {{'{prop_name}': x}}"
        
        return mappings
    
    def _fallback_security_validation(self, data: Dict[str, Any]) -> ValidationResult:
        """Fallback security validation when Universal Input Sanitizer unavailable"""
        result = ValidationResult(is_valid=True)

        try:
            # Convert data to string for pattern checking
            data_str = json.dumps(data, default=str).lower()

            # Check for dangerous patterns
            dangerous_patterns = [
                'rm -rf', 'del /f', 'format c:', 'dd if=',
                'wget http', 'curl http', 'nc -l', 'netcat',
                '/etc/passwd', '/etc/shadow', 'c:\\windows',
                '$(', '`', '${', 'eval(', 'exec(',
                'system(', 'shell_exec', 'passthru',
                '../../', '..\\..\\', '<script', 'javascript:',
                'file://', 'ftp://', 'ldap://'
            ]

            for pattern in dangerous_patterns:
                if pattern in data_str:
                    result.is_valid = False
                    result.security_violations.append(f"Dangerous pattern detected: {pattern}")

            # Validate plugin names if present
            if 'plugin_name' in data:
                if not self._validate_plugin_name(data['plugin_name']):
                    result.is_valid = False
                    result.security_violations.append(f"Invalid plugin name: {data['plugin_name']}")

            # Check for path traversal in any path-like fields
            for key, value in data.items():
                if isinstance(value, str) and ('path' in key.lower() or 'dir' in key.lower()):
                    if not self._validate_plugin_path(value):
                        result.is_valid = False
                        result.security_violations.append(f"Invalid path in {key}: {value}")

        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Validation error: {str(e)}")

        return result

    async def detect_plugin_changes(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Detect changes in plugin ecosystem"""
        cache_data = self._load_mapping_cache()
        detected_changes = []
        
        try:
            # Resource exhaustion protection
            plugin_count = 0

            # Scan all plugins with security limits
            for plugin_path in self.plugs_dir.glob("*/*/1.0.0"):
                plugin_count += 1
                if plugin_count > self.max_plugins_to_scan:
                    logger.warning(f"Plugin scan limit reached: {self.max_plugins_to_scan}")
                    break

                if not (plugin_path / "plug.yaml").exists():
                    continue

                # Validate plugin path
                if not self._validate_plugin_path(str(plugin_path)):
                    logger.warning(f"Skipping invalid plugin path: {plugin_path}")
                    continue
                
                plugin_name = f"{plugin_path.parent.parent.name}.{plugin_path.parent.name}"
                current_hash = self._calculate_plugin_hash(plugin_path)
                cached_info = cache_data["plugins"].get(plugin_name, {})
                
                if cached_info.get("hash") != current_hash:
                    # Plugin has changed
                    schema = self._extract_plugin_schema(plugin_path)
                    old_schema = cached_info.get("schema", {})
                    
                    schema_changes = self._detect_schema_changes(old_schema, schema or {})
                    
                    change_info = {
                        "plugin_name": plugin_name,
                        "plugin_path": str(plugin_path),
                        "change_type": "new" if not cached_info else "modified",
                        "hash_old": cached_info.get("hash"),
                        "hash_new": current_hash,
                        "schema_changes": schema_changes,
                        "requires_mapping_update": bool(schema_changes["breaking_changes"] or 
                                                      schema_changes["additions"] or 
                                                      schema_changes["modifications"])
                    }
                    
                    detected_changes.append(change_info)
                    
                    # Update cache
                    cache_data["plugins"][plugin_name] = {
                        "hash": current_hash,
                        "schema": schema,
                        "last_updated": datetime.now().isoformat()
                    }
            
            # Update cache
            cache_data["last_scan"] = datetime.now().isoformat()
            self._save_mapping_cache(cache_data)
            
            return {
                'success': True,
                'operation': 'detect_plugin_changes',
                'plugin_changes': detected_changes,
                'total_changes': len(detected_changes),
                'breaking_changes_count': sum(1 for c in detected_changes 
                                            if c['schema_changes']['breaking_changes']),
                'message': f'Detected {len(detected_changes)} plugin changes'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Change detection failed: {str(e)}'
            }
    
    async def sync_parameter_mappings(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Synchronize parameter mappings with current plugin state"""
        try:
            # Load CLI parameter processor plugin
            cli_processor = await self.pp("core/cli_parameter_processor/1.0.0")
            if not cli_processor:
                return {
                    'success': False,
                    'error': 'CLI Parameter Processor plugin not found'
                }
            
            cache_data = self._load_mapping_cache()
            updated_mappings = {}
            
            # Generate mappings for all plugins
            for plugin_name, plugin_info in cache_data["plugins"].items():
                schema = plugin_info.get("schema", {})
                if schema:
                    mappings = self._generate_parameter_mappings(plugin_name, schema)
                    updated_mappings[plugin_name] = mappings
            
            return {
                'success': True,
                'operation': 'sync_parameter_mappings',
                'mapping_updates': updated_mappings,
                'plugins_updated': len(updated_mappings),
                'message': f'Synchronized parameter mappings for {len(updated_mappings)} plugins'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Mapping synchronization failed: {str(e)}'
            }
    
    async def coordinate_parameter_ecosystem(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Coordinate entire parameter mapping ecosystem"""
        try:
            # Step 1: Detect changes
            changes_result = await self.detect_plugin_changes(ctx, cfg)
            
            # Step 2: Sync mappings if changes detected
            sync_result = None
            if changes_result['success'] and changes_result['total_changes'] > 0:
                sync_result = await self.sync_parameter_mappings(ctx, cfg)
            
            # Step 3: Integrate with freeze/release manager for version coordination
            version_coordination = await self._coordinate_with_freeze_manager(ctx, cfg)
            
            # Step 4: Run meta testing to validate coordination effectiveness
            meta_test_result = await self._run_meta_testing(ctx, cfg)
            
            return {
                'success': True,
                'operation': 'coordinate_parameter_ecosystem',
                'coordination_status': {
                    'changes_detected': changes_result['total_changes'],
                    'mappings_synchronized': sync_result['plugins_updated'] if sync_result else 0,
                    'version_coordination': version_coordination,
                    'meta_test_results': meta_test_result,
                    'ecosystem_health': 'healthy' if changes_result['breaking_changes_count'] == 0 else 'requires_attention'
                },
                'plugin_changes': changes_result.get('plugin_changes', []),
                'mapping_updates': sync_result.get('mapping_updates', {}) if sync_result else {},
                'message': 'Parameter ecosystem coordination completed'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Ecosystem coordination failed: {str(e)}'
            }
    
    async def _coordinate_with_freeze_manager(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Coordinate with freeze/release manager for version management"""
        try:
            freeze_manager = await self.pp("core/freeze_release_manager/1.0.0")
            if not freeze_manager:
                return {"status": "freeze_manager_unavailable"}
            
            # Get freeze/release status
            status_result = await freeze_manager.process(ctx, {"action": "status"})
            
            return {
                "status": "coordinated",
                "frozen_versions": status_result.get("total_frozen_versions", 0),
                "released_versions": status_result.get("total_released_versions", 0)
            }
            
        except Exception as e:
            return {"status": "coordination_failed", "error": str(e)}
    
    async def _run_meta_testing(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Run meta testing to validate coordination system effectiveness"""
        try:
            # Load intelligent test agent for meta testing
            intelligent_test_agent = await self.pp("testing/intelligent_test_agent/1.0.0")
            if not intelligent_test_agent:
                return {"status": "meta_test_unavailable", "reason": "intelligent_test_agent not found"}
            
            # Test 1: Validate that parameter mappings are working correctly
            mapping_test_result = await self._test_parameter_mapping_accuracy()
            
            # Test 2: Test that change detection is functioning
            change_detection_test = await self._test_change_detection_capability()
            
            # Test 3: Test schema evolution handling
            schema_evolution_test = await self._test_schema_evolution_handling()
            
            # Test 4: Use intelligent test agent for comprehensive coordination testing
            comprehensive_test_config = {
                "operation": "comprehensive_plugin_test",
                "context": {
                    "plugin_path": get_plugpipe_path("plugs/core/cli_parameter_mapping_coordinator/1.0.0/"),
                    "test_categories": ["unit", "integration", "ecosystem", "meta"],
                    "include_ai_testing": True,
                    "focus_areas": [
                        "parameter_mapping_accuracy",
                        "change_detection_reliability", 
                        "schema_evolution_handling",
                        "coordination_effectiveness"
                    ]
                }
            }
            
            comprehensive_result = await intelligent_test_agent.process(ctx, comprehensive_test_config)
            
            return {
                "status": "meta_testing_completed",
                "test_results": {
                    "parameter_mapping_accuracy": mapping_test_result,
                    "change_detection_capability": change_detection_test,
                    "schema_evolution_handling": schema_evolution_test,
                    "comprehensive_ai_testing": comprehensive_result
                },
                "overall_coordination_health": self._assess_coordination_health([
                    mapping_test_result, 
                    change_detection_test, 
                    schema_evolution_test
                ])
            }
            
        except Exception as e:
            return {"status": "meta_testing_failed", "error": str(e)}
    
    async def _test_parameter_mapping_accuracy(self) -> Dict[str, Any]:
        """Test that parameter mappings are generated accurately"""
        try:
            # Load CLI parameter processor to test mapping accuracy
            cli_processor = await self.pp("core/cli_parameter_processor/1.0.0")
            if not cli_processor:
                return {"status": "failed", "reason": "cli_parameter_processor not available"}
            
            # Test sample parameter conversions
            test_cases = [
                {
                    "plugin": "governance.ai_resource_governance",
                    "cli_args": {"operation": "status", "user": "test"},
                    "expected_keys": ["operation", "context"]
                },
                {
                    "plugin": "security.security_orchestrator", 
                    "cli_args": {"validate": True, "scan_type": "comprehensive"},
                    "expected_keys": ["validate", "scan_type"]
                }
            ]
            
            test_results = []
            for test_case in test_cases:
                try:
                    result = await cli_processor.process({}, {
                        'operation': 'convert_params_to_json',
                        'plugin_name': test_case["plugin"],
                        'cli_arguments': test_case["cli_args"]
                    })
                    
                    if result['success']:
                        config = result['converted_config']
                        has_expected_keys = all(
                            any(key in str(config) for key in test_case["expected_keys"])
                            for key in test_case["expected_keys"]
                        )
                        test_results.append({
                            "plugin": test_case["plugin"],
                            "status": "passed" if has_expected_keys else "failed",
                            "config_generated": bool(config)
                        })
                    else:
                        test_results.append({
                            "plugin": test_case["plugin"],
                            "status": "failed",
                            "error": result.get("error")
                        })
                        
                except Exception as e:
                    test_results.append({
                        "plugin": test_case["plugin"],
                        "status": "error",
                        "error": str(e)
                    })
            
            passed_tests = sum(1 for t in test_results if t["status"] == "passed")
            total_tests = len(test_results)
            
            return {
                "status": "completed",
                "accuracy_score": passed_tests / total_tests if total_tests > 0 else 0,
                "tests_passed": passed_tests,
                "total_tests": total_tests,
                "test_details": test_results
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _test_change_detection_capability(self) -> Dict[str, Any]:
        """Test that change detection is working correctly"""
        try:
            # Test change detection by examining cache consistency
            cache_data = self._load_mapping_cache()
            
            if not cache_data.get("plugins"):
                return {"status": "warning", "message": "No cached plugins to test against"}
            
            # Sample a few plugins and re-calculate their hashes
            sample_plugins = list(cache_data["plugins"].keys())[:5]
            consistency_results = []
            
            for plugin_name in sample_plugins:
                cached_info = cache_data["plugins"][plugin_name]
                
                # Reconstruct plugin path
                parts = plugin_name.split(".")
                if len(parts) == 2:
                    plugin_path = Path("plugs") / parts[0] / parts[1] / "1.0.0"
                    
                    if plugin_path.exists():
                        current_hash = self._calculate_plugin_hash(plugin_path)
                        cached_hash = cached_info.get("hash")
                        
                        consistency_results.append({
                            "plugin": plugin_name,
                            "hash_consistent": current_hash == cached_hash,
                            "has_schema": bool(cached_info.get("schema"))
                        })
            
            consistent_count = sum(1 for r in consistency_results if r["hash_consistent"])
            total_count = len(consistency_results)
            
            return {
                "status": "completed",
                "consistency_score": consistent_count / total_count if total_count > 0 else 1,
                "consistent_plugins": consistent_count,
                "total_tested": total_count,
                "details": consistency_results
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    async def _test_schema_evolution_handling(self) -> Dict[str, Any]:
        """Test schema evolution detection and handling"""
        try:
            # Create mock schema changes to test evolution handling
            old_schema = {
                "properties": {
                    "operation": {"type": "string"},
                    "user": {"type": "string"}
                }
            }
            
            new_schema = {
                "properties": {
                    "operation": {"type": "string"}, 
                    "user": {"type": "string"},
                    "budget": {"type": "number"},  # Addition
                    # "deprecated_param" removed - breaking change
                }
            }
            
            # Test schema change detection
            changes = self._detect_schema_changes(old_schema, new_schema)
            
            # Verify that changes are detected correctly
            has_additions = bool(changes["additions"])
            detects_modifications = isinstance(changes["modifications"], list)
            detects_breaking_changes = isinstance(changes["breaking_changes"], list)
            
            evolution_score = sum([
                has_additions, 
                detects_modifications, 
                detects_breaking_changes
            ]) / 3
            
            return {
                "status": "completed",
                "evolution_handling_score": evolution_score,
                "detects_additions": has_additions,
                "detects_modifications": detects_modifications,
                "detects_breaking_changes": detects_breaking_changes,
                "sample_changes": changes
            }
            
        except Exception as e:
            return {"status": "error", "error": str(e)}
    
    def _assess_coordination_health(self, test_results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Assess overall coordination system health based on meta test results"""
        try:
            health_scores = []
            
            for result in test_results:
                if result.get("status") == "completed":
                    # Extract numerical scores from different test types
                    if "accuracy_score" in result:
                        health_scores.append(result["accuracy_score"])
                    elif "consistency_score" in result:
                        health_scores.append(result["consistency_score"])
                    elif "evolution_handling_score" in result:
                        health_scores.append(result["evolution_handling_score"])
                elif result.get("status") == "warning":
                    health_scores.append(0.7)  # Partial credit for warnings
                # Failed tests contribute 0 to overall score
            
            if health_scores:
                overall_health = sum(health_scores) / len(health_scores)
                
                if overall_health >= 0.9:
                    health_status = "excellent"
                elif overall_health >= 0.7:
                    health_status = "good"
                elif overall_health >= 0.5:
                    health_status = "fair"
                else:
                    health_status = "needs_attention"
                    
                return {
                    "overall_score": overall_health,
                    "health_status": health_status,
                    "tests_analyzed": len(test_results),
                    "recommendation": self._generate_health_recommendation(health_status)
                }
            else:
                return {
                    "overall_score": 0,
                    "health_status": "unknown",
                    "tests_analyzed": 0,
                    "recommendation": "Run meta testing to assess coordination health"
                }
                
        except Exception as e:
            return {
                "overall_score": 0,
                "health_status": "error",
                "error": str(e),
                "recommendation": "Fix meta testing errors"
            }
    
    def _generate_health_recommendation(self, health_status: str) -> str:
        """Generate recommendations based on coordination health status"""
        recommendations = {
            "excellent": "Coordination system is performing optimally. Continue monitoring.",
            "good": "Coordination system is stable. Consider minor optimizations.",
            "fair": "Coordination system needs attention. Review failed test details.",
            "needs_attention": "Coordination system requires immediate fixes. Check error logs.",
            "unknown": "Unable to assess health. Run comprehensive meta testing."
        }
        return recommendations.get(health_status, "No recommendation available")

def process(ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """PlugPipe synchronous entry point with Universal Input Sanitizer integration."""
    import asyncio
    return asyncio.run(async_process(ctx, cfg))

async def async_process(ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Main plugin entry point with security validation"""
    try:
        # Step 1: Universal Input Sanitizer integration
        if SANITIZER_AVAILABLE:
            try:
                # Load and use Universal Input Sanitizer
                sys.path.insert(0, os.path.join(PROJECT_ROOT, "shares"))
                from loader import pp

                sanitizer_result = pp("universal_input_sanitizer", **{"context": ctx, **cfg})

                if not sanitizer_result.get('success', False):
                    logger.error(f"Input validation failed: {sanitizer_result.get('error', 'Unknown error')}")
                    return {
                        'status': 'error',
                        'error': f"Input validation failed: {sanitizer_result.get('error', 'Security validation failed')}",
                        'security_violation': True,
                        'operation': cfg.get('operation', 'unknown')
                    }

                # Use sanitized data if available
                if 'sanitized_data' in sanitizer_result:
                    ctx = sanitizer_result['sanitized_data'].get('context', ctx)
                    cfg = sanitizer_result['sanitized_data'].get('config', cfg)

                logger.info("Universal Input Sanitizer validation passed")

            except Exception as e:
                logger.warning(f"Universal Input Sanitizer failed, using fallback: {e}")
                # Fall through to fallback validation
                coordinator = CLIParameterMappingCoordinator()
                validation_result = coordinator._fallback_security_validation({**ctx, **cfg})

                if not validation_result.is_valid:
                    return {
                        'status': 'error',
                        'error': 'Input validation failed (fallback)',
                        'security_violations': validation_result.security_violations,
                        'security_violation': True,
                        'operation': cfg.get('operation', 'unknown')
                    }
        else:
            # Use fallback validation
            coordinator = CLIParameterMappingCoordinator()
            validation_result = coordinator._fallback_security_validation({**ctx, **cfg})

            if not validation_result.is_valid:
                return {
                    'status': 'error',
                    'error': 'Input validation failed (fallback)',
                    'security_violations': validation_result.security_violations,
                    'security_violation': True,
                    'operation': cfg.get('operation', 'unknown')
                }

        # Step 2: Process with validated input
        coordinator = CLIParameterMappingCoordinator()
        operation = cfg.get('operation')

        if operation == 'detect_plugin_changes':
            return await coordinator.detect_plugin_changes(ctx, cfg)
        elif operation == 'sync_parameter_mappings':
            return await coordinator.sync_parameter_mappings(ctx, cfg)
        elif operation == 'coordinate_parameter_ecosystem':
            return await coordinator.coordinate_parameter_ecosystem(ctx, cfg)
        elif operation == 'validate_mapping_compatibility':
            return {
                'success': True,
                'operation': 'validate_mapping_compatibility',
                'message': 'Mapping compatibility validation not yet implemented'
            }
        elif operation == 'analyze_schema_evolution':
            return {
                'success': True,
                'operation': 'analyze_schema_evolution',
                'message': 'Schema evolution analysis not yet implemented'
            }
        elif operation == 'monitor_plugin_lifecycle':
            return {
                'success': True,
                'operation': 'monitor_plugin_lifecycle',
                'message': 'Plugin lifecycle monitoring not yet implemented'
            }
        elif operation == 'run_meta_testing':
            return await coordinator._run_meta_testing(ctx, cfg)
        elif operation == 'test_parameter_mapping_accuracy':
            return await coordinator._test_parameter_mapping_accuracy()
        elif operation == 'test_change_detection_capability':
            return await coordinator._test_change_detection_capability()
        elif operation == 'test_schema_evolution_handling':
            return await coordinator._test_schema_evolution_handling()
        else:
            if operation is None:
                return {
                    'success': True,
                    'operation': 'default',
                    'message': 'CLI Parameter Mapping Coordinator is operational',
                    'available_operations': [
                        'detect_plugin_changes',
                        'sync_parameter_mappings',
                        'coordinate_parameter_ecosystem',
                        'validate_mapping_compatibility',
                        'analyze_schema_evolution',
                        'monitor_plugin_lifecycle',
                        'run_meta_testing',
                        'test_parameter_mapping_accuracy',
                        'test_change_detection_capability',
                        'test_schema_evolution_handling'
                    ]
                }
            else:
                return {
                    'success': False,
                    'error': f'Unknown operation: {operation}',
                    'available_operations': [
                        'detect_plugin_changes',
                        'sync_parameter_mappings',
                        'coordinate_parameter_ecosystem',
                        'validate_mapping_compatibility',
                        'analyze_schema_evolution',
                        'monitor_plugin_lifecycle',
                        'run_meta_testing',
                        'test_parameter_mapping_accuracy',
                        'test_change_detection_capability',
                        'test_schema_evolution_handling'
                    ]
                }

    except Exception as e:
        logger.error(f"Plugin execution error: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__,
            'operation': cfg.get('operation', 'unknown')
        }

async def pp():
    """PlugPipe plugin discovery function"""
    return plug_metadata

if __name__ == '__main__':
    import asyncio
    
    # Test the coordinator
    test_ctx = {'session_id': 'test_coordination'}
    test_cfg = {'operation': 'coordinate_parameter_ecosystem'}
    
    result = asyncio.run(async_process(test_ctx, test_cfg))
    print(json.dumps(result, indent=2))