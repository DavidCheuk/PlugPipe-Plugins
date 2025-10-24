#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Freeze/Release Manager Plugin

Provides comprehensive freeze and release management for PlugPipe plugins and pipelines
to maintain backward compatibility and prevent changes after release.

Features:
- Plugin/Pipeline Version Freezing - Lock specific versions to prevent modifications
- Release Status Management - Control release lifecycle and compatibility guarantees
- Backward Compatibility Validation - Ensure changes don't break existing dependencies
- Version Immutability Enforcement - Prevent changes to released versions
- Rollback Protection - Protect critical versions from accidental rollbacks
- Dependency Impact Analysis - Analyze impact of version changes on ecosystem
"""

import json
import os
import shutil
import hashlib
import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
from dataclasses import dataclass, asdict
import yaml

logger = logging.getLogger(__name__)

@dataclass
class ReleaseInfo:
    """Information about a released plugin/pipeline version."""
    name: str
    version: str
    type: str  # 'plugin' or 'pipeline'
    release_date: str
    frozen: bool
    immutable: bool
    checksum: str
    dependencies: List[Dict[str, str]]
    backward_compatible_versions: List[str]
    breaking_changes: List[str]
    deprecation_date: Optional[str] = None
    end_of_life_date: Optional[str] = None

@dataclass
class FreezeRequest:
    """Request to freeze a plugin/pipeline version."""
    name: str
    version: str
    type: str
    reason: str
    frozen_by: str
    freeze_level: str  # 'soft' or 'hard'

class FreezeReleaseManager:
    """Comprehensive freeze and release management for PlugPipe."""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Configuration paths
        self.plugs_dir = config.get('plugs_dir', 'plugs')
        self.pipes_dir = config.get('pipes_dir', 'pipes') 
        self.freeze_registry = config.get('freeze_registry', 'freeze_registry.json')
        self.release_registry = config.get('release_registry', 'release_registry.json')
        
        # Initialize registries
        self._load_registries()
    
    def _load_registries(self):
        """Load freeze and release registries."""
        try:
            # Load freeze registry
            if os.path.exists(self.freeze_registry):
                with open(self.freeze_registry, 'r') as f:
                    self.frozen_versions = json.load(f)
            else:
                self.frozen_versions = {}
            
            # Load release registry  
            if os.path.exists(self.release_registry):
                with open(self.release_registry, 'r') as f:
                    self.released_versions = json.load(f)
            else:
                self.released_versions = {}
                
        except Exception as e:
            self.logger.warning(f"Failed to load registries: {e}")
            self.frozen_versions = {}
            self.released_versions = {}
    
    def _save_registries(self):
        """Save freeze and release registries."""
        try:
            with open(self.freeze_registry, 'w') as f:
                json.dump(self.frozen_versions, f, indent=2)
            
            with open(self.release_registry, 'w') as f:
                json.dump(self.released_versions, f, indent=2)
                
        except Exception as e:
            self.logger.error(f"Failed to save registries: {e}")
    
    def _calculate_checksum(self, path: str) -> str:
        """Calculate checksum for a directory or file."""
        if os.path.isfile(path):
            with open(path, 'rb') as f:
                return hashlib.sha256(f.read()).hexdigest()
        
        # Directory checksum - hash all files
        checksums = []
        for root, dirs, files in os.walk(path):
            # Sort for consistent ordering
            dirs.sort()
            files.sort()
            
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'rb') as f:
                        file_checksum = hashlib.sha256(f.read()).hexdigest()
                        checksums.append(f"{file_path}:{file_checksum}")
                except Exception:
                    continue
        
        combined = '|'.join(checksums)
        return hashlib.sha256(combined.encode()).hexdigest()
    
    def _get_dependencies(self, manifest_path: str) -> List[Dict[str, str]]:
        """Extract dependencies from plugin/pipeline manifest."""
        try:
            with open(manifest_path, 'r') as f:
                manifest = yaml.safe_load(f)
            
            dependencies = []
            
            # Plugin dependencies
            if 'dependencies' in manifest:
                for dep in manifest['dependencies']:
                    if isinstance(dep, dict):
                        dependencies.append(dep)
                    elif isinstance(dep, str):
                        dependencies.append({'name': dep, 'version': '*'})
            
            # Pipeline step dependencies
            if 'pipeline' in manifest:
                for step in manifest['pipeline']:
                    if 'uses' in step:
                        dependencies.append({
                            'name': step['uses'], 
                            'version': step.get('version', '*')
                        })
            
            return dependencies
            
        except Exception as e:
            self.logger.warning(f"Failed to extract dependencies from {manifest_path}: {e}")
            return []
    
    def _find_dependents(self, name: str, version: str) -> List[Dict[str, Any]]:
        """Find plugins/pipelines that depend on the given version."""
        dependents = []
        
        # Check plugins
        plugs_path = Path(self.plugs_dir)
        if plugs_path.exists():
            for plugin_dir in plugs_path.rglob("*/*/plug.yaml"):
                try:
                    dependencies = self._get_dependencies(str(plugin_dir))
                    for dep in dependencies:
                        if dep.get('name') == name:
                            dependents.append({
                                'name': plugin_dir.parent.parent.name,
                                'version': plugin_dir.parent.name,
                                'type': 'plugin',
                                'path': str(plugin_dir.parent)
                            })
                except Exception:
                    continue
        
        # Check pipelines
        pipes_path = Path(self.pipes_dir)
        if pipes_path.exists():
            for pipe_dir in pipes_path.rglob("*/pipe.yaml"):
                try:
                    dependencies = self._get_dependencies(str(pipe_dir))
                    for dep in dependencies:
                        if dep.get('name') == name:
                            dependents.append({
                                'name': pipe_dir.parent.name,
                                'version': '1.0.0',  # Default for pipes
                                'type': 'pipeline',
                                'path': str(pipe_dir.parent)
                            })
                except Exception:
                    continue
        
        return dependents
    
    def freeze_version(self, name: str, version: str, type_: str, 
                      reason: str = "", frozen_by: str = "system",
                      freeze_level: str = "soft") -> Dict[str, Any]:
        """Freeze a specific version to prevent modifications."""
        try:
            freeze_key = f"{name}:{version}:{type_}"
            
            # Check if already frozen
            if freeze_key in self.frozen_versions:
                return {
                    'success': True,
                    'message': f'{type_.title()} {name} v{version} is already frozen',
                    'freeze_info': self.frozen_versions[freeze_key]
                }
            
            # Find the version path
            if type_ == 'plugin':
                version_path = os.path.join(self.plugs_dir, name, version)
                manifest_file = 'plug.yaml'
            else:  # pipeline
                version_path = os.path.join(self.pipes_dir, name, version) 
                manifest_file = 'pipe.yaml'
            
            if not os.path.exists(version_path):
                return {
                    'success': False,
                    'error': f'{type_.title()} {name} v{version} not found at {version_path}'
                }
            
            # Calculate checksum for immutability verification
            checksum = self._calculate_checksum(version_path)
            
            # Get dependencies
            manifest_path = os.path.join(version_path, manifest_file)
            dependencies = self._get_dependencies(manifest_path) if os.path.exists(manifest_path) else []
            
            # Create freeze record
            freeze_info = {
                'name': name,
                'version': version,
                'type': type_,
                'frozen_date': datetime.now(timezone.utc).isoformat(),
                'reason': reason,
                'frozen_by': frozen_by,
                'freeze_level': freeze_level,
                'checksum': checksum,
                'dependencies': dependencies,
                'path': version_path
            }
            
            # Hard freeze: make directory read-only
            if freeze_level == 'hard':
                self._apply_hard_freeze(version_path)
                freeze_info['read_only'] = True
            
            # Save freeze info
            self.frozen_versions[freeze_key] = freeze_info
            self._save_registries()
            
            return {
                'success': True,
                'message': f'{type_.title()} {name} v{version} frozen successfully',
                'freeze_level': freeze_level,
                'freeze_info': freeze_info
            }
            
        except Exception as e:
            self.logger.error(f"Failed to freeze {name} v{version}: {e}")
            return {
                'success': False,
                'error': f'Failed to freeze version: {str(e)}'
            }
    
    def _apply_hard_freeze(self, path: str):
        """Apply hard freeze by making directory read-only."""
        try:
            for root, dirs, files in os.walk(path):
                # Make directories read-only
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    os.chmod(dir_path, 0o555)  # r-xr-xr-x
                
                # Make files read-only
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    os.chmod(file_path, 0o444)  # r--r--r--
            
            # Make root directory read-only
            os.chmod(path, 0o555)
            
        except Exception as e:
            self.logger.warning(f"Failed to apply hard freeze to {path}: {e}")
    
    def unfreeze_version(self, name: str, version: str, type_: str,
                        reason: str = "", unfrozen_by: str = "system") -> Dict[str, Any]:
        """Unfreeze a version to allow modifications."""
        try:
            freeze_key = f"{name}:{version}:{type_}"
            
            if freeze_key not in self.frozen_versions:
                return {
                    'success': False,
                    'error': f'{type_.title()} {name} v{version} is not frozen'
                }
            
            freeze_info = self.frozen_versions[freeze_key]
            
            # Remove hard freeze if applied
            if freeze_info.get('read_only'):
                self._remove_hard_freeze(freeze_info['path'])
            
            # Remove from frozen versions
            del self.frozen_versions[freeze_key]
            self._save_registries()
            
            return {
                'success': True,
                'message': f'{type_.title()} {name} v{version} unfrozen successfully',
                'reason': reason,
                'unfrozen_by': unfrozen_by
            }
            
        except Exception as e:
            self.logger.error(f"Failed to unfreeze {name} v{version}: {e}")
            return {
                'success': False,
                'error': f'Failed to unfreeze version: {str(e)}'
            }
    
    def _remove_hard_freeze(self, path: str):
        """Remove hard freeze by restoring write permissions."""
        try:
            for root, dirs, files in os.walk(path):
                # Restore directory permissions
                for dir_name in dirs:
                    dir_path = os.path.join(root, dir_name)
                    os.chmod(dir_path, 0o755)  # rwxr-xr-x
                
                # Restore file permissions
                for file_name in files:
                    file_path = os.path.join(root, file_name)
                    os.chmod(file_path, 0o644)  # rw-r--r--
            
            # Restore root directory permissions
            os.chmod(path, 0o755)
            
        except Exception as e:
            self.logger.warning(f"Failed to remove hard freeze from {path}: {e}")
    
    def mark_as_released(self, name: str, version: str, type_: str,
                        release_notes: str = "",
                        breaking_changes: List[str] = None) -> Dict[str, Any]:
        """Mark a version as officially released with compatibility guarantees."""
        try:
            release_key = f"{name}:{version}:{type_}"
            
            # Check if already released
            if release_key in self.released_versions:
                return {
                    'success': True,
                    'message': f'{type_.title()} {name} v{version} is already released',
                    'release_info': self.released_versions[release_key]
                }
            
            # Find the version path
            if type_ == 'plugin':
                version_path = os.path.join(self.plugs_dir, name, version)
                manifest_file = 'plug.yaml'
            else:  # pipeline
                version_path = os.path.join(self.pipes_dir, name, version)
                manifest_file = 'pipe.yaml'
            
            if not os.path.exists(version_path):
                return {
                    'success': False,
                    'error': f'{type_.title()} {name} v{version} not found'
                }
            
            # Calculate checksum for immutability
            checksum = self._calculate_checksum(version_path)
            
            # Get dependencies
            manifest_path = os.path.join(version_path, manifest_file)
            dependencies = self._get_dependencies(manifest_path) if os.path.exists(manifest_path) else []
            
            # Find dependents for impact analysis
            dependents = self._find_dependents(name, version)
            
            # Create release info
            release_info = ReleaseInfo(
                name=name,
                version=version,
                type=type_,
                release_date=datetime.now(timezone.utc).isoformat(),
                frozen=True,
                immutable=True,
                checksum=checksum,
                dependencies=dependencies,
                backward_compatible_versions=[],
                breaking_changes=breaking_changes or []
            )
            
            # Auto-freeze released version with hard freeze
            freeze_result = self.freeze_version(
                name, version, type_, 
                reason=f"Auto-frozen due to release",
                frozen_by="release_manager",
                freeze_level="hard"
            )
            
            # Save release info
            self.released_versions[release_key] = {
                **asdict(release_info),
                'release_notes': release_notes,
                'dependents_count': len(dependents),
                'auto_frozen': freeze_result.get('success', False)
            }
            
            self._save_registries()
            
            return {
                'success': True,
                'message': f'{type_.title()} {name} v{version} marked as released',
                'release_info': self.released_versions[release_key],
                'auto_frozen': freeze_result.get('success', False),
                'dependents_count': len(dependents)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to mark {name} v{version} as released: {e}")
            return {
                'success': False,
                'error': f'Failed to mark as released: {str(e)}'
            }
    
    def validate_compatibility(self, name: str, old_version: str, 
                             new_version: str, type_: str) -> Dict[str, Any]:
        """Validate backward compatibility between versions."""
        try:
            # Get manifests for both versions
            if type_ == 'plugin':
                old_manifest_path = os.path.join(self.plugs_dir, name, old_version, 'plug.yaml')
                new_manifest_path = os.path.join(self.plugs_dir, name, new_version, 'plug.yaml')
            else:
                old_manifest_path = os.path.join(self.pipes_dir, name, old_version, 'pipe.yaml')
                new_manifest_path = os.path.join(self.pipes_dir, name, new_version, 'pipe.yaml')
            
            compatibility_issues = []
            
            try:
                with open(old_manifest_path, 'r') as f:
                    old_manifest = yaml.safe_load(f)
                with open(new_manifest_path, 'r') as f:
                    new_manifest = yaml.safe_load(f)
                
                # Check input/output schema compatibility
                old_input = old_manifest.get('input_schema', {})
                new_input = new_manifest.get('input_schema', {})
                old_output = old_manifest.get('output_schema', {})
                new_output = new_manifest.get('output_schema', {})
                
                # Check for removed required input fields (breaking change)
                old_required = set(old_input.get('required', []))
                new_required = set(new_input.get('required', []))
                removed_required = old_required - new_required
                
                if removed_required:
                    compatibility_issues.append({
                        'type': 'breaking_change',
                        'category': 'input_schema',
                        'description': f'Removed required input fields: {list(removed_required)}'
                    })
                
                # Check for removed output fields (potential breaking change)
                old_output_props = set(old_output.get('properties', {}).keys())
                new_output_props = set(new_output.get('properties', {}).keys())
                removed_output = old_output_props - new_output_props
                
                if removed_output:
                    compatibility_issues.append({
                        'type': 'potential_breaking_change',
                        'category': 'output_schema', 
                        'description': f'Removed output fields: {list(removed_output)}'
                    })
                
                # Check dependency changes
                old_deps = set(f"{dep.get('name', '')}:{dep.get('version', '*')}" 
                              for dep in self._get_dependencies(old_manifest_path))
                new_deps = set(f"{dep.get('name', '')}:{dep.get('version', '*')}" 
                              for dep in self._get_dependencies(new_manifest_path))
                
                if old_deps != new_deps:
                    compatibility_issues.append({
                        'type': 'dependency_change',
                        'category': 'dependencies',
                        'description': f'Dependency changes detected',
                        'added': list(new_deps - old_deps),
                        'removed': list(old_deps - new_deps)
                    })
                
            except FileNotFoundError:
                compatibility_issues.append({
                    'type': 'error',
                    'category': 'manifest_missing',
                    'description': f'Manifest file not found for version comparison'
                })
            
            # Determine overall compatibility
            has_breaking_changes = any(issue['type'] == 'breaking_change' for issue in compatibility_issues)
            is_compatible = not has_breaking_changes
            
            return {
                'success': True,
                'compatible': is_compatible,
                'has_breaking_changes': has_breaking_changes,
                'compatibility_issues': compatibility_issues,
                'analysis_date': datetime.now(timezone.utc).isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Failed to validate compatibility: {e}")
            return {
                'success': False,
                'error': f'Failed to validate compatibility: {str(e)}'
            }
    
    def check_freeze_status(self, name: str = None, version: str = None, 
                           type_: str = None) -> Dict[str, Any]:
        """Check freeze status of versions."""
        try:
            if name and version and type_:
                # Check specific version
                freeze_key = f"{name}:{version}:{type_}"
                if freeze_key in self.frozen_versions:
                    return {
                        'success': True,
                        'frozen': True,
                        'freeze_info': self.frozen_versions[freeze_key]
                    }
                else:
                    return {
                        'success': True,
                        'frozen': False,
                        'message': f'{type_.title()} {name} v{version} is not frozen'
                    }
            else:
                # List all frozen versions
                return {
                    'success': True,
                    'frozen_versions': self.frozen_versions,
                    'total_frozen': len(self.frozen_versions)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to check freeze status: {e}")
            return {
                'success': False,
                'error': f'Failed to check freeze status: {str(e)}'
            }
    
    def check_release_status(self, name: str = None, version: str = None,
                           type_: str = None) -> Dict[str, Any]:
        """Check release status of versions."""
        try:
            if name and version and type_:
                # Check specific version
                release_key = f"{name}:{version}:{type_}"
                if release_key in self.released_versions:
                    return {
                        'success': True,
                        'released': True,
                        'release_info': self.released_versions[release_key]
                    }
                else:
                    return {
                        'success': True,
                        'released': False,
                        'message': f'{type_.title()} {name} v{version} is not released'
                    }
            else:
                # List all released versions
                return {
                    'success': True,
                    'released_versions': self.released_versions,
                    'total_released': len(self.released_versions)
                }
                
        except Exception as e:
            self.logger.error(f"Failed to check release status: {e}")
            return {
                'success': False,
                'error': f'Failed to check release status: {str(e)}'
            }
    
    def get_dependents(self, name: str, version: str) -> Dict[str, Any]:
        """Get list of plugins/pipelines that depend on the specified version."""
        try:
            dependents = self._find_dependents(name, version)
            
            return {
                'success': True,
                'dependents': dependents,
                'dependents_count': len(dependents)
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get dependents: {e}")
            return {
                'success': False,
                'error': f'Failed to get dependents: {str(e)}'
            }
    
    def verify_integrity(self, name: str, version: str, type_: str) -> Dict[str, Any]:
        """Verify integrity of a frozen/released version using checksums."""
        try:
            freeze_key = f"{name}:{version}:{type_}"
            release_key = f"{name}:{version}:{type_}"
            
            # Get expected checksum
            expected_checksum = None
            if freeze_key in self.frozen_versions:
                expected_checksum = self.frozen_versions[freeze_key].get('checksum')
            elif release_key in self.released_versions:
                expected_checksum = self.released_versions[release_key].get('checksum')
            
            if not expected_checksum:
                return {
                    'success': False,
                    'error': f'{type_.title()} {name} v{version} is not frozen or released'
                }
            
            # Calculate current checksum
            if type_ == 'plugin':
                version_path = os.path.join(self.plugs_dir, name, version)
            else:
                version_path = os.path.join(self.pipes_dir, name, version)
            
            if not os.path.exists(version_path):
                return {
                    'success': False,
                    'error': f'Version path not found: {version_path}'
                }
            
            current_checksum = self._calculate_checksum(version_path)
            
            # Compare checksums
            integrity_ok = current_checksum == expected_checksum
            
            return {
                'success': True,
                'integrity_ok': integrity_ok,
                'expected_checksum': expected_checksum,
                'current_checksum': current_checksum,
                'message': 'Integrity verified' if integrity_ok else 'Integrity violation detected'
            }
            
        except Exception as e:
            self.logger.error(f"Failed to verify integrity: {e}")
            return {
                'success': False,
                'error': f'Failed to verify integrity: {str(e)}'
            }

    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Main process function following PlugPipe contract."""
        try:
            action = ctx.get('action', 'status')
            
            if action == 'freeze_version':
                return self.freeze_version(
                    ctx.get('name'),
                    ctx.get('version'),
                    ctx.get('type'),
                    ctx.get('reason', ''),
                    ctx.get('frozen_by', 'system'),
                    ctx.get('freeze_level', 'soft')
                )
            
            elif action == 'unfreeze_version':
                return self.unfreeze_version(
                    ctx.get('name'),
                    ctx.get('version'),
                    ctx.get('type'),
                    ctx.get('reason', ''),
                    ctx.get('unfrozen_by', 'system')
                )
            
            elif action == 'mark_as_released':
                return self.mark_as_released(
                    ctx.get('name'),
                    ctx.get('version'),
                    ctx.get('type'),
                    ctx.get('release_notes', ''),
                    ctx.get('breaking_changes', [])
                )
            
            elif action == 'validate_compatibility':
                return self.validate_compatibility(
                    ctx.get('name'),
                    ctx.get('old_version'),
                    ctx.get('new_version'),
                    ctx.get('type')
                )
            
            elif action == 'check_freeze_status':
                return self.check_freeze_status(
                    ctx.get('name'),
                    ctx.get('version'),
                    ctx.get('type')
                )
            
            elif action == 'check_release_status':
                return self.check_release_status(
                    ctx.get('name'),
                    ctx.get('version'),
                    ctx.get('type')
                )
            
            elif action == 'get_dependents':
                return self.get_dependents(
                    ctx.get('name'),
                    ctx.get('version')
                )
            
            elif action == 'verify_integrity':
                return self.verify_integrity(
                    ctx.get('name'),
                    ctx.get('version'),
                    ctx.get('type')
                )
            
            elif action == 'status':
                return {
                    'success': True,
                    'message': 'Freeze/Release Manager is operational',
                    'total_frozen_versions': len(self.frozen_versions),
                    'total_released_versions': len(self.released_versions),
                    'available_actions': [
                        'freeze_version', 'unfreeze_version', 'mark_as_released',
                        'validate_compatibility', 'check_freeze_status', 
                        'check_release_status', 'get_dependents', 'verify_integrity'
                    ]
                }
            
            else:
                return {
                    'success': False,
                    'error': f'Unknown action: {action}',
                    'available_actions': [
                        'freeze_version', 'unfreeze_version', 'mark_as_released',
                        'validate_compatibility', 'check_freeze_status',
                        'check_release_status', 'get_dependents', 'verify_integrity', 'status'
                    ]
                }
                
        except Exception as e:
            logger.error(f"Freeze/Release Manager failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'timestamp': datetime.now(timezone.utc).isoformat()
            }


# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "freeze_release_manager",
    "version": "1.0.0",
    "description": "Comprehensive freeze and release management for PlugPipe plugins and pipelines",
    "owner": "PlugPipe Core Team", 
    "status": "production",
    "category": "core",
    "tags": ["version-control", "release-management", "compatibility", "core", "freeze"],
    "capabilities": [
        "version_freezing",
        "release_management", 
        "compatibility_validation",
        "integrity_verification",
        "dependency_analysis",
        "immutability_enforcement"
    ]
}

# Async process function for PlugPipe contract
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Async entry point for Freeze/Release Manager."""
    manager = FreezeReleaseManager(cfg)
    return await manager.process(ctx, cfg)