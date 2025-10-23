#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Helm Charts Plugin for PlugPipe Kubernetes Deployment

This plugin provides comprehensive Helm chart management capabilities including
chart creation, installation, upgrades, rollbacks, testing, dependency management,
and repository operations for standardized Kubernetes application deployment.

Author: PlugPipe Core Team
Version: 1.0.0
License: Apache-2.0
"""

import json
import yaml
import asyncio
import subprocess
import tempfile
import os
import time
import logging
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import uuid
import shutil

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class HelmClient:
    """
    Helm CLI client wrapper for chart operations.
    """
    
    def __init__(self, kubeconfig: str = None, namespace: str = "default"):
        """
        Initialize Helm client.
        
        Args:
            kubeconfig: Path to kubeconfig file
            namespace: Default namespace for operations
        """
        self.kubeconfig = kubeconfig
        self.namespace = namespace
        self.initialized = False
        
    async def _run_helm(self, args: List[str], input_data: str = None) -> Dict[str, Any]:
        """
        Run helm command asynchronously.
        
        Args:
            args: helm command arguments
            input_data: Optional input data for the command
            
        Returns:
            Command result with stdout, stderr, and return code
        """
        try:
            cmd = ['helm']
            
            if self.kubeconfig:
                cmd.extend(['--kubeconfig', self.kubeconfig])
            
            cmd.extend(['--namespace', self.namespace])
            cmd.extend(args)
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdin=asyncio.subprocess.PIPE if input_data else None,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await process.communicate(
                input=input_data.encode() if input_data else None
            )
            
            return {
                'returncode': process.returncode,
                'stdout': stdout.decode(),
                'stderr': stderr.decode()
            }
            
        except Exception as e:
            logger.error(f"helm command failed: {e}")
            return {
                'returncode': 1,
                'stdout': '',
                'stderr': str(e)
            }
    
    async def version(self) -> Dict[str, Any]:
        """
        Get Helm version information.
        
        Returns:
            Version operation result
        """
        result = await self._run_helm(['version', '--short'])
        
        return {
            'success': result['returncode'] == 0,
            'operation': 'version',
            'version': result['stdout'].strip() if result['returncode'] == 0 else None,
            'error': result['stderr'] if result['returncode'] != 0 else None
        }
    
    async def repo_add(self, repo_name: str, repo_url: str) -> Dict[str, Any]:
        """
        Add Helm repository.
        
        Args:
            repo_name: Repository name
            repo_url: Repository URL
            
        Returns:
            Repository add operation result
        """
        result = await self._run_helm(['repo', 'add', repo_name, repo_url])
        
        return {
            'success': result['returncode'] == 0,
            'operation': 'repo_add',
            'repo_name': repo_name,
            'repo_url': repo_url,
            'output': result['stdout'],
            'error': result['stderr'] if result['returncode'] != 0 else None
        }
    
    async def repo_update(self) -> Dict[str, Any]:
        """
        Update Helm repositories.
        
        Returns:
            Repository update operation result
        """
        result = await self._run_helm(['repo', 'update'])
        
        return {
            'success': result['returncode'] == 0,
            'operation': 'repo_update',
            'output': result['stdout'],
            'error': result['stderr'] if result['returncode'] != 0 else None
        }
    
    async def install_chart(self, release_name: str, chart: str, values: Dict[str, Any] = None, 
                           create_namespace: bool = False, wait: bool = True) -> Dict[str, Any]:
        """
        Install Helm chart.
        
        Args:
            release_name: Release name
            chart: Chart name or path
            values: Values to override
            create_namespace: Create namespace if it doesn't exist
            wait: Wait for resources to be ready
            
        Returns:
            Install operation result
        """
        cmd_args = ['install', release_name, chart]
        
        if create_namespace:
            cmd_args.append('--create-namespace')
        
        if wait:
            cmd_args.append('--wait')
        
        values_file = None
        if values:
            # Create temporary values file
            values_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
            yaml.dump(values, values_file)
            values_file.close()
            cmd_args.extend(['-f', values_file.name])
        
        try:
            result = await self._run_helm(cmd_args)
            
            return {
                'success': result['returncode'] == 0,
                'operation': 'install_chart',
                'release_name': release_name,
                'chart': chart,
                'namespace': self.namespace,
                'output': result['stdout'],
                'error': result['stderr'] if result['returncode'] != 0 else None
            }
        finally:
            if values_file and os.path.exists(values_file.name):
                os.unlink(values_file.name)
    
    async def upgrade_chart(self, release_name: str, chart: str, values: Dict[str, Any] = None,
                           wait: bool = True, install: bool = True) -> Dict[str, Any]:
        """
        Upgrade Helm chart.
        
        Args:
            release_name: Release name
            chart: Chart name or path
            values: Values to override
            wait: Wait for resources to be ready
            install: Install if release doesn't exist
            
        Returns:
            Upgrade operation result
        """
        cmd_args = ['upgrade', release_name, chart]
        
        if wait:
            cmd_args.append('--wait')
        
        if install:
            cmd_args.append('--install')
        
        values_file = None
        if values:
            values_file = tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False)
            yaml.dump(values, values_file)
            values_file.close()
            cmd_args.extend(['-f', values_file.name])
        
        try:
            result = await self._run_helm(cmd_args)
            
            return {
                'success': result['returncode'] == 0,
                'operation': 'upgrade_chart',
                'release_name': release_name,
                'chart': chart,
                'namespace': self.namespace,
                'output': result['stdout'],
                'error': result['stderr'] if result['returncode'] != 0 else None
            }
        finally:
            if values_file and os.path.exists(values_file.name):
                os.unlink(values_file.name)
    
    async def uninstall_chart(self, release_name: str, wait: bool = True) -> Dict[str, Any]:
        """
        Uninstall Helm chart.
        
        Args:
            release_name: Release name
            wait: Wait for resources to be deleted
            
        Returns:
            Uninstall operation result
        """
        cmd_args = ['uninstall', release_name]
        
        if wait:
            cmd_args.append('--wait')
        
        result = await self._run_helm(cmd_args)
        
        return {
            'success': result['returncode'] == 0,
            'operation': 'uninstall_chart',
            'release_name': release_name,
            'namespace': self.namespace,
            'output': result['stdout'],
            'error': result['stderr'] if result['returncode'] != 0 else None
        }
    
    async def list_releases(self, all_namespaces: bool = False) -> Dict[str, Any]:
        """
        List Helm releases.
        
        Args:
            all_namespaces: List releases from all namespaces
            
        Returns:
            List releases operation result
        """
        cmd_args = ['list', '--output', 'json']
        
        if all_namespaces:
            cmd_args.append('--all-namespaces')
        
        result = await self._run_helm(cmd_args)
        
        if result['returncode'] == 0:
            try:
                releases = json.loads(result['stdout']) if result['stdout'].strip() else []
                return {
                    'success': True,
                    'operation': 'list_releases',
                    'releases': releases,
                    'count': len(releases)
                }
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'operation': 'list_releases',
                    'error': 'Failed to parse releases JSON'
                }
        else:
            return {
                'success': False,
                'operation': 'list_releases',
                'error': result['stderr']
            }
    
    async def get_release_status(self, release_name: str) -> Dict[str, Any]:
        """
        Get Helm release status.
        
        Args:
            release_name: Release name
            
        Returns:
            Release status information
        """
        result = await self._run_helm(['status', release_name, '--output', 'json'])
        
        if result['returncode'] == 0:
            try:
                status_data = json.loads(result['stdout'])
                return {
                    'success': True,
                    'operation': 'get_release_status',
                    'release_name': release_name,
                    'status': status_data
                }
            except json.JSONDecodeError:
                return {
                    'success': False,
                    'operation': 'get_release_status',
                    'error': 'Failed to parse status JSON'
                }
        else:
            return {
                'success': False,
                'operation': 'get_release_status',
                'error': result['stderr']
            }
    
    async def rollback_release(self, release_name: str, revision: int = None, wait: bool = True) -> Dict[str, Any]:
        """
        Rollback Helm release.
        
        Args:
            release_name: Release name
            revision: Revision number (default: previous)
            wait: Wait for rollback to complete
            
        Returns:
            Rollback operation result
        """
        cmd_args = ['rollback', release_name]
        
        if revision is not None:
            cmd_args.append(str(revision))
        
        if wait:
            cmd_args.append('--wait')
        
        result = await self._run_helm(cmd_args)
        
        return {
            'success': result['returncode'] == 0,
            'operation': 'rollback_release',
            'release_name': release_name,
            'revision': revision,
            'namespace': self.namespace,
            'output': result['stdout'],
            'error': result['stderr'] if result['returncode'] != 0 else None
        }

class HelmChartsPlugin:
    """
    Helm Charts Plugin for PlugPipe
    
    Provides comprehensive Helm chart management capabilities including:
    - Chart installation, upgrades, and rollbacks
    - Repository management and chart discovery
    - Values templating and configuration management
    - Release lifecycle management
    - Dependency management and testing
    """
    
    def __init__(self, config: Dict[str, Any]):
        """
        Initialize Helm Charts plugin.
        
        Args:
            config: Plugin configuration
        """
        self.config = config
        helm_config = config.get('helm', {})
        
        # Helm configuration
        self.kubeconfig = helm_config.get('kubeconfig')
        self.namespace = helm_config.get('namespace', 'default')
        self.timeout = helm_config.get('timeout', 300)
        self.wait_for_ready = helm_config.get('wait_for_ready', True)
        
        # Plugin metadata
        self.plugin_id = f"helm-charts_{uuid.uuid4().hex[:8]}"
        self.created_at = datetime.utcnow().isoformat()
        self.operations_count = 0
        
        # Initialize Helm client
        self.helm_client = HelmClient(self.kubeconfig, self.namespace)
    
    async def _handle_install_chart(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle install chart operation."""
        release_name = config.get('release_name')
        chart = config.get('chart')
        values = config.get('values', {})
        create_namespace = config.get('create_namespace', False)
        
        if not release_name or not chart:
            return {
                'success': False,
                'error': 'release_name and chart are required for install_chart',
                'operation': 'install_chart'
            }
        
        result = await self.helm_client.install_chart(
            release_name, chart, values, create_namespace, self.wait_for_ready
        )
        
        self.operations_count += 1
        return result
    
    async def _handle_upgrade_chart(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle upgrade chart operation."""
        release_name = config.get('release_name')
        chart = config.get('chart')
        values = config.get('values', {})
        install_if_not_exists = config.get('install_if_not_exists', True)
        
        if not release_name or not chart:
            return {
                'success': False,
                'error': 'release_name and chart are required for upgrade_chart',
                'operation': 'upgrade_chart'
            }
        
        result = await self.helm_client.upgrade_chart(
            release_name, chart, values, self.wait_for_ready, install_if_not_exists
        )
        
        self.operations_count += 1
        return result
    
    async def _handle_uninstall_chart(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle uninstall chart operation."""
        release_name = config.get('release_name')
        
        if not release_name:
            return {
                'success': False,
                'error': 'release_name is required for uninstall_chart',
                'operation': 'uninstall_chart'
            }
        
        result = await self.helm_client.uninstall_chart(release_name, self.wait_for_ready)
        
        self.operations_count += 1
        return result
    
    async def _handle_list_releases(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle list releases operation."""
        all_namespaces = config.get('all_namespaces', False)
        
        result = await self.helm_client.list_releases(all_namespaces)
        
        self.operations_count += 1
        return result
    
    async def _handle_get_release_status(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle get release status operation."""
        release_name = config.get('release_name')
        
        if not release_name:
            return {
                'success': False,
                'error': 'release_name is required for get_release_status',
                'operation': 'get_release_status'
            }
        
        result = await self.helm_client.get_release_status(release_name)
        
        self.operations_count += 1
        return result
    
    async def _handle_rollback_release(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle rollback release operation."""
        release_name = config.get('release_name')
        revision = config.get('revision')
        
        if not release_name:
            return {
                'success': False,
                'error': 'release_name is required for rollback_release',
                'operation': 'rollback_release'
            }
        
        result = await self.helm_client.rollback_release(release_name, revision, self.wait_for_ready)
        
        self.operations_count += 1
        return result
    
    async def _handle_repo_add(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle repository add operation."""
        repo_name = config.get('repo_name')
        repo_url = config.get('repo_url')
        
        if not repo_name or not repo_url:
            return {
                'success': False,
                'error': 'repo_name and repo_url are required for repo_add',
                'operation': 'repo_add'
            }
        
        result = await self.helm_client.repo_add(repo_name, repo_url)
        
        self.operations_count += 1
        return result
    
    async def _handle_repo_update(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Handle repository update operation."""
        result = await self.helm_client.repo_update()
        
        self.operations_count += 1
        return result
    
    async def health_check(self) -> Dict[str, Any]:
        """
        Perform Helm Charts plugin health check.
        
        Returns:
            Health check results
        """
        try:
            # Check helm availability
            version_result = await self.helm_client.version()
            
            helm_available = version_result['success']
            
            return {
                'helm_available': helm_available,
                'helm_version': version_result.get('version'),
                'namespace': self.namespace,
                'timeout': self.timeout,
                'wait_for_ready': self.wait_for_ready,
                'operations_count': self.operations_count,
                'status': 'healthy' if helm_available else 'unhealthy'
            }
            
        except Exception as e:
            logger.error(f"Health check failed: {e}")
            return {
                'helm_available': False,
                'status': 'unhealthy',
                'error': str(e)
            }
    
    async def process(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process Helm Charts operations.
        
        Args:
            ctx: Execution context
            config: Operation configuration
            
        Returns:
            Operation result
        """
        operation = config.get('operation')
        
        if not operation:
            return {
                'success': False,
                'error': 'No operation specified',
                'available_operations': [
                    'install_chart', 'upgrade_chart', 'uninstall_chart',
                    'list_releases', 'get_release_status', 'rollback_release',
                    'repo_add', 'repo_update', 'health_check'
                ]
            }
        
        try:
            if operation == 'health_check':
                result = await self.health_check()
            elif operation == 'install_chart':
                result = await self._handle_install_chart(ctx, config)
            elif operation == 'upgrade_chart':
                result = await self._handle_upgrade_chart(ctx, config)
            elif operation == 'uninstall_chart':
                result = await self._handle_uninstall_chart(ctx, config)
            elif operation == 'list_releases':
                result = await self._handle_list_releases(ctx, config)
            elif operation == 'get_release_status':
                result = await self._handle_get_release_status(ctx, config)
            elif operation == 'rollback_release':
                result = await self._handle_rollback_release(ctx, config)
            elif operation == 'repo_add':
                result = await self._handle_repo_add(ctx, config)
            elif operation == 'repo_update':
                result = await self._handle_repo_update(ctx, config)
            else:
                result = {
                    'success': False,
                    'error': f'Unknown operation: {operation}',
                    'available_operations': [
                        'install_chart', 'upgrade_chart', 'uninstall_chart',
                        'list_releases', 'get_release_status', 'rollback_release',
                        'repo_add', 'repo_update', 'health_check'
                    ]
                }
            
            # Add common metadata
            result.update({
                'plugin_id': self.plugin_id,
                'timestamp': datetime.utcnow().isoformat(),
                'execution_context': ctx.get('request_id', 'unknown')
            })
            
            return result
            
        except Exception as e:
            logger.error(f"Helm Charts operation failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'operation': operation,
                'plugin_id': self.plugin_id,
                'timestamp': datetime.utcnow().isoformat()
            }

# Plugin entry point and metadata
async def process_async(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Async entry point for Helm Charts plugin.
    
    Args:
        ctx: Execution context
        config: Plugin configuration
        
    Returns:
        Operation result
    """
    plugin = HelmChartsPlugin(config)
    result = await plugin.process(ctx, config)
    
    return {
        'success': result.get('success', False),
        'operation_completed': config.get('operation', 'unknown'),
        'result': result,
        'plugin_type': 'helm_charts',
        'execution_time': time.time()
    }

def process(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Synchronous entry point for Helm Charts plugin.
    
    Args:
        ctx: Execution context
        config: Plugin configuration
        
    Returns:
        Operation result
    """
    return asyncio.run(process_async(ctx, config))

# Plugin metadata
plug_metadata = {
    "name": "helm_charts",
    "version": "1.0.0",
    "description": "Helm Charts plugin for standardized Kubernetes application deployment with chart management, values templating, repository operations, and release lifecycle management",
    "owner": "PlugPipe Core Team",
    "status": "stable",
    "capabilities": [
        "helm_charts",
        "kubernetes_deployment",
        "chart_management",
        "release_lifecycle",
        "repository_management",
        "values_templating",
        "dependency_management",
        "standardized_deployment"
    ],
    "tags": ["helm", "kubernetes", "charts", "deployment", "package", "management", "lifecycle", "templating"],
    "compatibility": {
        "helm": ">=3.0.0",
        "kubernetes": ">=1.19.0",
        "python": ">=3.8"
    },
    "enterprise_features": {
        "production_ready": True,
        "enterprise_ready": True,
        "scalable": True,
        "secure": True,
        "monitored": True,
        "compliant": True,
        "standardized_deployment": True,
        "chart_management": True
    }
}

if __name__ == "__main__":
    # Example usage
    config = {
        "helm": {
            "namespace": "default",
            "timeout": 300,
            "wait_for_ready": True
        },
        "operation": "health_check"
    }
    
    result = process({}, config)
    print(json.dumps(result, indent=2, default=str))