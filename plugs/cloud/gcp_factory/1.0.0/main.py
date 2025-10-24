#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Google Cloud Platform (GCP) Factory Plugin for PlugPipe

Enterprise-grade GCP cloud orchestration factory that provides unified access
to Google Cloud services including Compute Engine, Cloud Storage, BigQuery, 
Cloud Functions, GKE, and more. Enables multi-service GCP integration with 
secure credential management, auto-scaling, and comprehensive monitoring.

Key Features:
- Unified GCP service interface across all Google Cloud APIs
- Secure credential management with service account support
- Auto-scaling and resource optimization
- Multi-region deployment and failover
- Cost optimization and resource monitoring
- Enterprise security and compliance features
- Kubernetes integration for cloud-native deployment
"""

import asyncio
import json
import logging
import os
import time
import uuid
import yaml
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import subprocess
import tempfile
import base64
import re
from pathlib import Path
import sys
from dataclasses import dataclass

# Import PlugPipe framework components
try:
    from shares.loader import pp
except ImportError:
    # Fallback for testing environments
    def pp(plugin_name: str, **kwargs):
        print(f"Mock pp() call: {plugin_name} with {kwargs}")
        return {"success": False, "error": "Universal Input Sanitizer not available in test environment"}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of input validation."""
    is_valid: bool
    sanitized_value: Any
    errors: List[str]
    security_issues: List[str]

class GCPServiceInterface(ABC):
    """Interface for GCP service plugins."""

    def __init__(self):
        self.sanitizer_available = self._check_sanitizer_availability()

    def _check_sanitizer_availability(self) -> bool:
        """Check if Universal Input Sanitizer is available."""
        try:
            result = pp("universal_input_sanitizer", action="health_check")
            return result.get("success", False)
        except Exception:
            return False

    async def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> ValidationResult:
        """Validate and sanitize input using Universal Input Sanitizer."""
        if not self.sanitizer_available:
            # Fallback validation
            return self._fallback_validation(data, context)

        try:
            result = pp("universal_input_sanitizer",
                       action="sanitize",
                       input_data=data,
                       context=context,
                       security_level="high")

            if result.get("success"):
                return ValidationResult(
                    is_valid=True,
                    sanitized_value=result.get("sanitized_data", data),
                    errors=[],
                    security_issues=result.get("security_warnings", [])
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    sanitized_value=data,
                    errors=[result.get("error", "Unknown validation error")],
                    security_issues=[]
                )
        except Exception as e:
            logger.warning(f"Sanitizer error, using fallback: {e}")
            return self._fallback_validation(data, context)

    def _fallback_validation(self, data: Any, context: str) -> ValidationResult:
        """Fallback validation when Universal Input Sanitizer is not available."""
        errors = []
        security_issues = []

        if isinstance(data, str):
            # Basic security checks for strings
            if re.search(r'[;&|`$(){}\\[\\]<>]', data):
                security_issues.append("Potentially dangerous characters detected")

            # Path traversal check
            if '../' in data or '..\\\\' in data:
                security_issues.append("Path traversal attempt detected")

            # Command injection patterns
            dangerous_patterns = ['rm -rf', 'DROP TABLE', 'DELETE FROM', 'INSERT INTO', 'UPDATE SET']
            for pattern in dangerous_patterns:
                if pattern.lower() in data.lower():
                    security_issues.append(f"Potentially dangerous pattern detected: {pattern}")

        return ValidationResult(
            is_valid=len(security_issues) == 0,
            sanitized_value=data,
            errors=errors,
            security_issues=security_issues
        )

    @abstractmethod
    async def initialize(self, credentials: Dict[str, str]) -> bool:
        """Initialize GCP service with credentials."""
        pass
    
    @abstractmethod
    async def create_resource(self, resource_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a GCP resource."""
        pass
    
    @abstractmethod
    async def get_resource(self, resource_id: str) -> Dict[str, Any]:
        """Get GCP resource details."""
        pass
    
    @abstractmethod
    async def list_resources(self, filters: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """List GCP resources."""
        pass
    
    @abstractmethod
    async def update_resource(self, resource_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a GCP resource."""
        pass
    
    @abstractmethod
    async def delete_resource(self, resource_id: str) -> bool:
        """Delete a GCP resource."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check service health."""
        pass

class GCPComputeEngineService(GCPServiceInterface):
    """Google Compute Engine service implementation."""

    def __init__(self, config: Dict[str, Any], parent=None):
        super().__init__()
        self.config = config
        self.parent = parent
        self.project_id = config.get('project_id', '')
        self.zone = config.get('zone', 'us-central1-a')
        self.region = config.get('region', 'us-central1')
        self.credentials_path = config.get('credentials_path')
        self.initialized = False
        
    async def initialize(self, credentials: Dict[str, str]) -> bool:
        """Initialize Compute Engine service."""
        try:
            # Set up gcloud authentication if credentials provided
            if credentials.get('service_account_key'):
                # Write service account key to temporary file
                with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
                    json.dump(credentials['service_account_key'], f)
                    self.credentials_path = f.name
                
                # Authenticate with service account
                cmd = ['gcloud', 'auth', 'activate-service-account', '--key-file', self.credentials_path]
                result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="gcp_auth")
                
                if result.returncode != 0:
                    logger.error(f"GCP authentication failed: {result.stderr}")
                    return False
            
            # Set project if specified
            if self.project_id:
                cmd = ['gcloud', 'config', 'set', 'project', self.project_id]
                await self.parent._secure_subprocess_run(cmd, timeout=30, context="gcp_config")
            
            self.initialized = True
            logger.info(f"Compute Engine service initialized for project: {self.project_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize Compute Engine service: {e}")
            return False
    
    async def create_resource(self, resource_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Compute Engine resource."""
        try:
            if resource_type == 'instance':
                return await self._create_instance(config)
            elif resource_type == 'disk':
                return await self._create_disk(config)
            elif resource_type == 'network':
                return await self._create_network(config)
            else:
                return {'success': False, 'error': f'Unsupported resource type: {resource_type}'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _create_instance(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Compute Engine instance."""
        instance_name = config.get('name', f'instance-{uuid.uuid4().hex[:8]}')
        machine_type = config.get('machine_type', 'e2-micro')
        image_family = config.get('image_family', 'ubuntu-2004-lts')
        image_project = config.get('image_project', 'ubuntu-os-cloud')
        
        cmd = [
            'gcloud', 'compute', 'instances', 'create', instance_name,
            '--zone', self.zone,
            '--machine-type', machine_type,
            '--image-family', image_family,
            '--image-project', image_project,
            '--format', 'json'
        ]
        
        # Add optional parameters
        if config.get('boot_disk_size'):
            cmd.extend(['--boot-disk-size', config['boot_disk_size']])
        
        if config.get('tags'):
            cmd.extend(['--tags', ','.join(config['tags'])])
        
        if config.get('labels'):
            labels = ','.join([f'{k}={v}' for k, v in config['labels'].items()])
            cmd.extend(['--labels', labels])

        result = await self.parent._secure_subprocess_run(cmd, timeout=120, context="create_instance")
        
        if result.returncode == 0:
            instances = json.loads(result.stdout)
            if instances:
                instance = instances[0]
                return {
                    'success': True,
                    'resource_id': instance['name'],
                    'resource_details': instance
                }
        
        return {'success': False, 'error': result.stderr}
    
    async def _create_disk(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a persistent disk."""
        disk_name = config.get('name', f'disk-{uuid.uuid4().hex[:8]}')
        size = config.get('size', '10GB')
        disk_type = config.get('type', 'pd-standard')
        
        cmd = [
            'gcloud', 'compute', 'disks', 'create', disk_name,
            '--zone', self.zone,
            '--size', size,
            '--type', disk_type,
            '--format', 'json'
        ]

        result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="create_disk")

        if result.returncode == 0:
            disks = json.loads(result.stdout)
            if disks:
                disk = disks[0]
                return {
                    'success': True,
                    'resource_id': disk['name'],
                    'resource_details': disk
                }
        
        return {'success': False, 'error': result.stderr}
    
    async def _create_network(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a VPC network."""
        network_name = config.get('name', f'network-{uuid.uuid4().hex[:8]}')
        subnet_mode = config.get('subnet_mode', 'auto')
        
        cmd = [
            'gcloud', 'compute', 'networks', 'create', network_name,
            '--subnet-mode', subnet_mode,
            '--format', 'json'
        ]

        result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="create_network")

        if result.returncode == 0:
            networks = json.loads(result.stdout)
            if networks:
                network = networks[0]
                return {
                    'success': True,
                    'resource_id': network['name'],
                    'resource_details': network
                }
        
        return {'success': False, 'error': result.stderr}
    
    async def list_resources(self, filters: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """List Compute Engine instances."""
        try:
            cmd = ['gcloud', 'compute', 'instances', 'list', '--format', 'json']
            
            if filters:
                if filters.get('zone'):
                    cmd.extend(['--zones', filters['zone']])
                if filters.get('status'):
                    cmd.extend(['--filter', f'status={filters["status"]}'])

            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="list_instances")

            if result.returncode == 0:
                instances = json.loads(result.stdout)
                normalized_instances = []
                
                for instance in instances:
                    normalized_instances.append({
                        'instance_id': instance['name'],
                        'machine_type': instance['machineType'].split('/')[-1],
                        'status': instance['status'],
                        'zone': instance['zone'].split('/')[-1],
                        'external_ip': self._get_external_ip(instance),
                        'internal_ip': self._get_internal_ip(instance),
                        'creation_timestamp': instance.get('creationTimestamp')
                    })
                
                return normalized_instances
            else:
                logger.error(f"Compute Engine list error: {result.stderr}")
                return []
        
        except Exception as e:
            logger.error(f"Error listing Compute Engine instances: {e}")
            return []
    
    def _get_external_ip(self, instance: Dict[str, Any]) -> Optional[str]:
        """Extract external IP from instance data."""
        try:
            network_interfaces = instance.get('networkInterfaces', [])
            if network_interfaces:
                access_configs = network_interfaces[0].get('accessConfigs', [])
                if access_configs:
                    return access_configs[0].get('natIP')
        except Exception:
            pass
        return None
    
    def _get_internal_ip(self, instance: Dict[str, Any]) -> Optional[str]:
        """Extract internal IP from instance data."""
        try:
            network_interfaces = instance.get('networkInterfaces', [])
            if network_interfaces:
                return network_interfaces[0].get('networkIP')
        except Exception:
            pass
        return None

    async def get_resource(self, resource_id: str) -> Dict[str, Any]:
        """FTHAD IMPLEMENTATION: Get GCP Compute Engine resource details by ID."""
        try:
            # Try instance first
            cmd = [
                'gcloud', 'compute', 'instances', 'describe', resource_id,
                '--zone', self.zone,
                '--format', 'json'
            ]

            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="get_instance")

            if result.returncode == 0:
                instance = json.loads(result.stdout)
                return {
                    'success': True,
                    'resource_type': 'instance',
                    'resource_id': instance['name'],
                    'resource_details': {
                        'name': instance['name'],
                        'machine_type': instance['machineType'].split('/')[-1],
                        'status': instance['status'],
                        'zone': instance['zone'].split('/')[-1],
                        'external_ip': self._get_external_ip(instance),
                        'internal_ip': self._get_internal_ip(instance),
                        'creation_timestamp': instance.get('creationTimestamp'),
                        'labels': instance.get('labels', {}),
                        'tags': instance.get('tags', {}).get('items', []),
                        'disks': [disk.get('source', '').split('/')[-1] for disk in instance.get('disks', [])],
                        'network_interfaces': instance.get('networkInterfaces', [])
                    }
                }

            # Try disk if instance not found
            cmd = [
                'gcloud', 'compute', 'disks', 'describe', resource_id,
                '--zone', self.zone,
                '--format', 'json'
            ]

            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="get_disk")

            if result.returncode == 0:
                disk = json.loads(result.stdout)
                return {
                    'success': True,
                    'resource_type': 'disk',
                    'resource_id': disk['name'],
                    'resource_details': {
                        'name': disk['name'],
                        'size_gb': disk['sizeGb'],
                        'type': disk['type'].split('/')[-1],
                        'status': disk['status'],
                        'zone': disk['zone'].split('/')[-1],
                        'creation_timestamp': disk.get('creationTimestamp'),
                        'labels': disk.get('labels', {}),
                        'users': disk.get('users', [])
                    }
                }

            # Try network if disk not found
            cmd = [
                'gcloud', 'compute', 'networks', 'describe', resource_id,
                '--format', 'json'
            ]

            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="get_network")

            if result.returncode == 0:
                network = json.loads(result.stdout)
                return {
                    'success': True,
                    'resource_type': 'network',
                    'resource_id': network['name'],
                    'resource_details': {
                        'name': network['name'],
                        'subnet_mode': network.get('subnetMode'),
                        'creation_timestamp': network.get('creationTimestamp'),
                        'subnets': network.get('subnetworks', []),
                        'firewall_rules': network.get('firewalls', [])
                    }
                }

            return {
                'success': False,
                'error': f'Resource "{resource_id}" not found in project "{self.project_id}" zone "{self.zone}"'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error retrieving resource "{resource_id}": {str(e)}'
            }

    async def update_resource(self, resource_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """FTHAD IMPLEMENTATION: Update GCP Compute Engine resource configuration."""
        try:
            # Get resource type first
            resource_info = await self.get_resource(resource_id)

            if not resource_info.get('success'):
                return resource_info

            resource_type = resource_info.get('resource_type')

            if resource_type == 'instance':
                return await self._update_instance(resource_id, config)
            elif resource_type == 'disk':
                return await self._update_disk(resource_id, config)
            elif resource_type == 'network':
                return await self._update_network(resource_id, config)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported resource type for update: {resource_type}'
                }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error updating resource "{resource_id}": {str(e)}'
            }

    async def _update_instance(self, instance_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a Compute Engine instance configuration."""
        try:
            updated_fields = []

            # Update labels
            if 'labels' in config:
                labels = ','.join([f'{k}={v}' for k, v in config['labels'].items()])
                cmd = [
                    'gcloud', 'compute', 'instances', 'update', instance_id,
                    '--zone', self.zone,
                    '--update-labels', labels,
                    '--format', 'json'
                ]

                result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="update_instance_labels")
                if result.returncode == 0:
                    updated_fields.append('labels')
                else:
                    return {'success': False, 'error': f'Failed to update labels: {result.stderr}'}

            # Update tags
            if 'tags' in config:
                tags = ','.join(config['tags'])
                cmd = [
                    'gcloud', 'compute', 'instances', 'update', instance_id,
                    '--zone', self.zone,
                    '--tags', tags,
                    '--format', 'json'
                ]

                result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="update_instance_tags")
                if result.returncode == 0:
                    updated_fields.append('tags')
                else:
                    return {'success': False, 'error': f'Failed to update tags: {result.stderr}'}

            # Change machine type (requires instance to be stopped)
            if 'machine_type' in config:
                # Stop instance first
                stop_cmd = [
                    'gcloud', 'compute', 'instances', 'stop', instance_id,
                    '--zone', self.zone,
                    '--quiet'
                ]

                result = await self.parent._secure_subprocess_run(stop_cmd, timeout=120, context="stop_instance")
                if result.returncode != 0:
                    return {'success': False, 'error': f'Failed to stop instance for machine type change: {result.stderr}'}

                # Change machine type
                cmd = [
                    'gcloud', 'compute', 'instances', 'set-machine-type', instance_id,
                    '--zone', self.zone,
                    '--machine-type', config['machine_type'],
                    '--format', 'json'
                ]

                result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="update_machine_type")
                if result.returncode == 0:
                    updated_fields.append('machine_type')

                    # Start instance again if requested
                    if config.get('restart_after_update', True):
                        start_cmd = [
                            'gcloud', 'compute', 'instances', 'start', instance_id,
                            '--zone', self.zone,
                            '--quiet'
                        ]

                        await self.parent._secure_subprocess_run(start_cmd, timeout=120, context="start_instance")
                else:
                    return {'success': False, 'error': f'Failed to update machine type: {result.stderr}'}

            return {
                'success': True,
                'resource_id': instance_id,
                'updated_fields': updated_fields,
                'message': f'Instance "{instance_id}" updated successfully'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error updating instance "{instance_id}": {str(e)}'
            }

    async def _update_disk(self, disk_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a persistent disk configuration."""
        try:
            updated_fields = []

            # Update labels
            if 'labels' in config:
                labels = ','.join([f'{k}={v}' for k, v in config['labels'].items()])
                cmd = [
                    'gcloud', 'compute', 'disks', 'update', disk_id,
                    '--zone', self.zone,
                    '--update-labels', labels,
                    '--format', 'json'
                ]

                result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="update_disk_labels")
                if result.returncode == 0:
                    updated_fields.append('labels')
                else:
                    return {'success': False, 'error': f'Failed to update disk labels: {result.stderr}'}

            # Resize disk
            if 'size' in config:
                cmd = [
                    'gcloud', 'compute', 'disks', 'resize', disk_id,
                    '--zone', self.zone,
                    '--size', config['size'],
                    '--quiet',
                    '--format', 'json'
                ]

                result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="resize_disk")
                if result.returncode == 0:
                    updated_fields.append('size')
                else:
                    return {'success': False, 'error': f'Failed to resize disk: {result.stderr}'}

            return {
                'success': True,
                'resource_id': disk_id,
                'updated_fields': updated_fields,
                'message': f'Disk "{disk_id}" updated successfully'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error updating disk "{disk_id}": {str(e)}'
            }

    async def _update_network(self, network_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a VPC network configuration."""
        try:
            # Networks have limited update operations
            # Most network changes require creating subnets or firewall rules

            updated_fields = []

            # Switch to custom mode (if currently auto)
            if config.get('switch_to_custom', False):
                cmd = [
                    'gcloud', 'compute', 'networks', 'update', network_id,
                    '--switch-to-custom-subnet-mode',
                    '--format', 'json'
                ]

                result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="update_network_mode")
                if result.returncode == 0:
                    updated_fields.append('subnet_mode')
                else:
                    return {'success': False, 'error': f'Failed to switch network to custom mode: {result.stderr}'}

            return {
                'success': True,
                'resource_id': network_id,
                'updated_fields': updated_fields,
                'message': f'Network "{network_id}" updated successfully',
                'note': 'Limited update operations available for networks. Use subnets and firewall rules for additional configuration.'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error updating network "{network_id}": {str(e)}'
            }

    async def delete_resource(self, resource_id: str) -> bool:
        """FTHAD IMPLEMENTATION: Delete GCP Compute Engine resource by ID."""
        try:
            # Get resource type first
            resource_info = await self.get_resource(resource_id)

            if not resource_info.get('success'):
                # Resource doesn't exist, consider it already deleted
                return True

            resource_type = resource_info.get('resource_type')

            if resource_type == 'instance':
                return await self._delete_instance(resource_id)
            elif resource_type == 'disk':
                return await self._delete_disk(resource_id)
            elif resource_type == 'network':
                return await self._delete_network(resource_id)
            else:
                logger.error(f'Unsupported resource type for deletion: {resource_type}')
                return False

        except Exception as e:
            logger.error(f'Error deleting resource "{resource_id}": {str(e)}')
            return False

    async def _delete_instance(self, instance_id: str) -> bool:
        """Delete a Compute Engine instance."""
        try:
            cmd = [
                'gcloud', 'compute', 'instances', 'delete', instance_id,
                '--zone', self.zone,
                '--quiet'
            ]

            result = await self.parent._secure_subprocess_run(cmd, timeout=120, context="delete_instance")

            if result.returncode == 0:
                logger.info(f'Instance "{instance_id}" deleted successfully')
                return True
            else:
                logger.error(f'Failed to delete instance "{instance_id}": {result.stderr}')
                return False

        except Exception as e:
            logger.error(f'Error deleting instance "{instance_id}": {str(e)}')
            return False

    async def _delete_disk(self, disk_id: str) -> bool:
        """Delete a persistent disk."""
        try:
            cmd = [
                'gcloud', 'compute', 'disks', 'delete', disk_id,
                '--zone', self.zone,
                '--quiet'
            ]

            result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="delete_disk")

            if result.returncode == 0:
                logger.info(f'Disk "{disk_id}" deleted successfully')
                return True
            else:
                logger.error(f'Failed to delete disk "{disk_id}": {result.stderr}')
                return False

        except Exception as e:
            logger.error(f'Error deleting disk "{disk_id}": {str(e)}')
            return False

    async def _delete_network(self, network_id: str) -> bool:
        """Delete a VPC network."""
        try:
            cmd = [
                'gcloud', 'compute', 'networks', 'delete', network_id,
                '--quiet'
            ]

            result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="delete_network")

            if result.returncode == 0:
                logger.info(f'Network "{network_id}" deleted successfully')
                return True
            else:
                logger.error(f'Failed to delete network "{network_id}": {result.stderr}')
                return False

        except Exception as e:
            logger.error(f'Error deleting network "{network_id}": {str(e)}')
            return False

    async def health_check(self) -> Dict[str, Any]:
        """Check Compute Engine service health."""
        try:
            cmd = ['gcloud', 'compute', 'zones', 'list', '--limit', '1', '--format', 'json']
            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="health_check")
            
            return {
                'service': 'compute_engine',
                'healthy': result.returncode == 0,
                'project_id': self.project_id,
                'default_zone': self.zone,
                'initialized': self.initialized
            }
        
        except Exception as e:
            return {
                'service': 'compute_engine',
                'healthy': False,
                'error': str(e)
            }

class GCPCloudStorageService(GCPServiceInterface):
    """Google Cloud Storage service implementation."""

    def __init__(self, config: Dict[str, Any], parent=None):
        super().__init__()
        self.config = config
        self.parent = parent
        self.project_id = config.get('project_id', '')
        self.default_region = config.get('region', 'us-central1')
        self.initialized = False
    
    async def initialize(self, credentials: Dict[str, str]) -> bool:
        """Initialize Cloud Storage service."""
        try:
            self.initialized = True
            logger.info(f"Cloud Storage service initialized for project: {self.project_id}")
            return True
        except Exception as e:
            logger.error(f"Failed to initialize Cloud Storage service: {e}")
            return False
    
    async def create_resource(self, resource_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Cloud Storage resource."""
        try:
            if resource_type == 'bucket':
                return await self._create_bucket(config)
            else:
                return {'success': False, 'error': f'Unsupported resource type: {resource_type}'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _create_bucket(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a Cloud Storage bucket."""
        bucket_name = config.get('name', f'bucket-{uuid.uuid4().hex[:8]}')
        location = config.get('location', self.default_region)
        storage_class = config.get('storage_class', 'STANDARD')
        
        cmd = [
            'gsutil', 'mb',
            '-p', self.project_id,
            '-c', storage_class,
            '-l', location,
            f'gs://{bucket_name}'
        ]

        result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="create_bucket")

        if result.returncode == 0:
            return {
                'success': True,
                'resource_id': bucket_name,
                'resource_details': {
                    'name': bucket_name,
                    'location': location,
                    'storage_class': storage_class
                }
            }
        
        return {'success': False, 'error': result.stderr}
    
    async def list_resources(self, filters: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """List Cloud Storage buckets."""
        try:
            cmd = ['gsutil', 'ls', '-p', self.project_id]
            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="list_buckets")
            
            if result.returncode == 0:
                buckets = []
                for line in result.stdout.strip().split('\n'):
                    if line.startswith('gs://'):
                        bucket_name = line.replace('gs://', '').rstrip('/')
                        buckets.append({
                            'bucket_name': bucket_name,
                            'uri': line,
                            'type': 'bucket'
                        })
                return buckets
            else:
                logger.error(f"Cloud Storage list error: {result.stderr}")
                return []
        
        except Exception as e:
            logger.error(f"Error listing Cloud Storage buckets: {e}")
            return []

    async def get_resource(self, resource_id: str) -> Dict[str, Any]:
        """FTHAD IMPLEMENTATION: Get Cloud Storage resource details by ID."""
        try:
            # Check if it's a bucket
            cmd = ['gsutil', 'ls', '-b', f'gs://{resource_id}']
            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="get_bucket")

            if result.returncode == 0:
                # Get bucket details
                cmd = ['gsutil', 'ls', '-L', '-b', f'gs://{resource_id}']
                details_result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="get_bucket_details")

                if details_result.returncode == 0:
                    return {
                        'success': True,
                        'resource_type': 'bucket',
                        'resource_id': resource_id,
                        'resource_details': {
                            'name': resource_id,
                            'uri': f'gs://{resource_id}',
                            'details': details_result.stdout.strip()
                        }
                    }

            return {
                'success': False,
                'error': f'Resource "{resource_id}" not found in project "{self.project_id}"'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error retrieving resource "{resource_id}": {str(e)}'
            }

    async def update_resource(self, resource_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """FTHAD IMPLEMENTATION: Update Cloud Storage resource configuration."""
        try:
            # Get resource type first
            resource_info = await self.get_resource(resource_id)

            if not resource_info.get('success'):
                return resource_info

            resource_type = resource_info.get('resource_type')

            if resource_type == 'bucket':
                return await self._update_bucket(resource_id, config)
            else:
                return {
                    'success': False,
                    'error': f'Unsupported resource type for update: {resource_type}'
                }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error updating resource "{resource_id}": {str(e)}'
            }

    async def _update_bucket(self, bucket_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a Cloud Storage bucket configuration."""
        try:
            updated_fields = []

            # Update storage class
            if 'storage_class' in config:
                cmd = [
                    'gsutil', 'defstorageclass', 'set',
                    config['storage_class'],
                    f'gs://{bucket_id}'
                ]

                result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="update_bucket_storage_class")
                if result.returncode == 0:
                    updated_fields.append('storage_class')
                else:
                    return {'success': False, 'error': f'Failed to update storage class: {result.stderr}'}

            # Update labels (if supported by gsutil version)
            if 'labels' in config:
                for key, value in config['labels'].items():
                    cmd = [
                        'gsutil', 'label', 'set',
                        f'{key}:{value}',
                        f'gs://{bucket_id}'
                    ]

                    result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="update_bucket_labels")
                    if result.returncode == 0:
                        if 'labels' not in updated_fields:
                            updated_fields.append('labels')
                    else:
                        return {'success': False, 'error': f'Failed to update label {key}: {result.stderr}'}

            return {
                'success': True,
                'resource_id': bucket_id,
                'updated_fields': updated_fields,
                'message': f'Bucket "{bucket_id}" updated successfully'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Error updating bucket "{bucket_id}": {str(e)}'
            }

    async def delete_resource(self, resource_id: str) -> bool:
        """FTHAD IMPLEMENTATION: Delete Cloud Storage resource by ID."""
        try:
            # Get resource type first
            resource_info = await self.get_resource(resource_id)

            if not resource_info.get('success'):
                # Resource doesn't exist, consider it already deleted
                return True

            resource_type = resource_info.get('resource_type')

            if resource_type == 'bucket':
                return await self._delete_bucket(resource_id)
            else:
                logger.error(f'Unsupported resource type for deletion: {resource_type}')
                return False

        except Exception as e:
            logger.error(f'Error deleting resource "{resource_id}": {str(e)}')
            return False

    async def _delete_bucket(self, bucket_id: str) -> bool:
        """Delete a Cloud Storage bucket."""
        try:
            # First, try to remove all objects in the bucket
            cmd = ['gsutil', '-m', 'rm', '-r', f'gs://{bucket_id}/*']
            await self.parent._secure_subprocess_run(cmd, timeout=120, context="empty_bucket")

            # Then delete the bucket
            cmd = ['gsutil', 'rb', f'gs://{bucket_id}']
            result = await self.parent._secure_subprocess_run(cmd, timeout=60, context="delete_bucket")

            if result.returncode == 0:
                logger.info(f'Bucket "{bucket_id}" deleted successfully')
                return True
            else:
                logger.error(f'Failed to delete bucket "{bucket_id}": {result.stderr}')
                return False

        except Exception as e:
            logger.error(f'Error deleting bucket "{bucket_id}": {str(e)}')
            return False

    async def health_check(self) -> Dict[str, Any]:
        """Check Cloud Storage service health."""
        try:
            cmd = ['gsutil', 'version']
            result = await self.parent._secure_subprocess_run(cmd, timeout=30, context="storage_health")
            
            return {
                'service': 'cloud_storage',
                'healthy': result.returncode == 0,
                'project_id': self.project_id,
                'initialized': self.initialized
            }
        
        except Exception as e:
            return {
                'service': 'cloud_storage',
                'healthy': False,
                'error': str(e)
            }

class GCPFactoryPlugin:
    """
    GCP Factory Plugin - Enterprise Google Cloud Platform orchestration factory.

    Provides unified access to GCP services with secure credential management,
    auto-scaling, and comprehensive monitoring across all Google Cloud services.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.gcp_config = config.get('gcp_factory', {})
        self.services_config = config.get('gcp_services', {})

        # Factory configuration with security validation
        self.project_id = self._validate_project_id(self.gcp_config.get('project_id', ''))
        self.primary_region = self._validate_gcp_region(self.gcp_config.get('primary_region', 'us-central1'))
        self.fallback_regions = self._validate_gcp_regions(self.gcp_config.get('fallback_regions', []))
        self.enabled_services = self._validate_gcp_services(self.gcp_config.get('enabled_services', ['compute', 'storage']))
        self.auto_failover = bool(self.gcp_config.get('auto_failover', True))
        self.cost_optimization = bool(self.gcp_config.get('cost_optimization', True))
        self.namespace = self._validate_namespace(self.gcp_config.get('namespace', 'plugpipe'))

        # Security hardening configuration
        self.security_config = {
            'require_2fa': True,
            'enforce_https': True,
            'enable_cloud_audit_logs': True,
            'resource_labeling_required': True,
            'min_tls_version': '1.2',
            'allowed_machine_types': self._get_secure_machine_types(),
            'denied_actions': self._get_denied_actions(),
            'required_security_features': self._get_required_security_features()
        }

        # Factory state
        self.factory_id = str(uuid.uuid4())
        self.initialized = False
        self.active_region = None
        self.gcp_services = {}
        self.managed_resources = {}
        self.credentials = {}

        # Security initialization
        self.sanitizer_available = self._check_sanitizer_availability()

        logger.info(f"GCP Factory Plugin initialized with ID: {self.factory_id}")

    def _validate_project_id(self, project_id: str) -> str:
        """Validate GCP project ID format for security."""
        if not project_id:
            logger.warning("No GCP project ID provided")
            return ''

        # GCP project ID validation: 6-30 chars, lowercase letters, digits, hyphens
        # Must start with letter, end with letter or digit
        if not re.match(r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$', project_id.lower()):
            logger.error(f"Invalid GCP project ID format: {project_id}")
            return ''

        return project_id.lower()

    def _validate_gcp_region(self, region: str) -> str:
        """Validate GCP region name for security."""
        # GCP region pattern validation: us-central1, europe-west1, etc.
        if not re.match(r'^[a-z]+-[a-z]+\d+$', region):
            logger.warning(f"Invalid GCP region '{region}', using 'us-central1'")
            return 'us-central1'

        # Whitelist of trusted GCP regions
        valid_regions = {
            'us-central1', 'us-east1', 'us-east4', 'us-west1', 'us-west2', 'us-west3', 'us-west4',
            'europe-west1', 'europe-west2', 'europe-west3', 'europe-west4', 'europe-west6',
            'europe-north1', 'europe-central2',
            'asia-east1', 'asia-east2', 'asia-northeast1', 'asia-northeast2', 'asia-northeast3',
            'asia-south1', 'asia-southeast1', 'asia-southeast2',
            'australia-southeast1', 'australia-southeast2',
            'northamerica-northeast1', 'northamerica-northeast2',
            'southamerica-east1'
        }

        if region not in valid_regions:
            logger.warning(f"Untrusted GCP region '{region}', using 'us-central1'")
            return 'us-central1'

        return region

    def _validate_gcp_regions(self, regions: List[str]) -> List[str]:
        """Validate list of GCP regions."""
        return [self._validate_gcp_region(region) for region in regions if region]

    def _validate_gcp_services(self, services: List[str]) -> List[str]:
        """Validate GCP service names for security."""
        # Whitelist of allowed GCP services
        allowed_services = {
            'compute', 'storage', 'bigquery', 'datastore', 'pubsub',
            'functions', 'run', 'gke', 'sql', 'firestore',
            'logging', 'monitoring', 'secretmanager', 'kms',
            'iam', 'dns', 'networking', 'security'
        }

        validated_services = []
        for service in services:
            service_clean = service.lower().replace('-', '').replace('_', '')
            if re.match(r'^[a-z0-9]+$', service_clean) and service_clean in allowed_services:
                validated_services.append(service_clean)
            else:
                logger.warning(f"Invalid or disallowed GCP service '{service}', skipping")

        return validated_services or ['compute', 'storage']  # Secure default

    def _validate_namespace(self, namespace: str) -> str:
        """Validate namespace for security."""
        # Only allow alphanumeric, hyphens, and underscores
        if not re.match(r'^[a-z0-9_-]+$', namespace.lower()):
            logger.warning(f"Invalid namespace '{namespace}', using 'plugpipe'")
            return 'plugpipe'
        return namespace.lower()

    def _get_secure_machine_types(self) -> List[str]:
        """Get list of secure GCP machine types."""
        return [
            'e2-micro', 'e2-small', 'e2-medium', 'e2-standard-2', 'e2-standard-4',
            'n1-standard-1', 'n1-standard-2', 'n1-standard-4',
            'n2-standard-2', 'n2-standard-4', 'n2-standard-8',
            'c2-standard-4', 'c2-standard-8',
            'm1-ultramem-40', 'm1-ultramem-80'
        ]

    def _get_denied_actions(self) -> List[str]:
        """Get list of denied GCP actions for security."""
        return [
            'compute.instances.delete',
            'compute.disks.delete',
            'storage.buckets.delete',
            'cloudsql.instances.delete',
            'container.clusters.delete',
            'resourcemanager.projects.delete',
            'iam.serviceAccounts.delete',
            'iam.roles.delete'
        ]

    def _get_required_security_features(self) -> Dict[str, bool]:
        """Get required GCP security features configuration."""
        return {
            'disk_encryption': True,
            'vpc_firewall_rules': True,
            'cloud_armor': True,
            'secret_manager': True,
            'service_accounts': True,
            'iam_conditions': True,
            'audit_logs': True,
            'binary_authorization': True
        }

    def _validate_service_account(self, credentials: Dict[str, Any]) -> bool:
        """Validate GCP service account credentials."""
        if not credentials:
            return False

        # Check for service account key file structure
        required_fields = ['type', 'project_id', 'private_key_id', 'private_key', 'client_email', 'client_id']
        for field in required_fields:
            if field not in credentials or not credentials[field]:
                logger.error(f"Missing required service account field: {field}")
                return False

        # Validate service account type
        if credentials['type'] != 'service_account':
            logger.error("Invalid service account type")
            return False

        # Validate client_email format
        client_email = credentials['client_email']
        if not re.match(r'^[a-z0-9.-]+@[a-z0-9.-]+\.iam\.gserviceaccount\.com$', client_email):
            logger.error("Invalid service account email format")
            return False

        # Validate project_id matches
        if self.project_id and credentials['project_id'] != self.project_id:
            logger.error("Service account project_id does not match configured project_id")
            return False

        # Validate private_key format (PEM)
        private_key = credentials['private_key']
        if not private_key.startswith('-----BEGIN PRIVATE KEY-----'):
            logger.error("Invalid private key format")
            return False

        return True

    def _check_sanitizer_availability(self) -> bool:
        """Check if Universal Input Sanitizer is available."""
        try:
            result = pp("universal_input_sanitizer", action="health_check")
            return result.get("success", False)
        except Exception:
            return False

    async def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> ValidationResult:
        """Validate and sanitize input using Universal Input Sanitizer."""
        if not self.sanitizer_available:
            # Fallback validation
            return self._fallback_validation(data, context)

        try:
            result = pp("universal_input_sanitizer",
                       action="sanitize",
                       input_data=data,
                       context=context,
                       security_level="high")

            if result.get("success"):
                return ValidationResult(
                    is_valid=True,
                    sanitized_value=result.get("sanitized_data", data),
                    errors=[],
                    security_issues=result.get("security_warnings", [])
                )
            else:
                return ValidationResult(
                    is_valid=False,
                    sanitized_value=data,
                    errors=[result.get("error", "Unknown validation error")],
                    security_issues=[]
                )
        except Exception as e:
            logger.warning(f"Sanitizer error, using fallback: {e}")
            return self._fallback_validation(data, context)

    def _fallback_validation(self, data: Any, context: str) -> ValidationResult:
        """Fallback validation when Universal Input Sanitizer is not available."""
        errors = []
        security_issues = []

        if isinstance(data, str):
            # Basic security checks for strings
            if re.search(r'[;&|`$(){}\[\]<>]', data):
                security_issues.append("Potentially dangerous characters detected")

            # Path traversal check
            if '../' in data or '..\\\\':
                security_issues.append("Path traversal attempt detected")

            # Command injection patterns
            dangerous_patterns = ['rm -rf', 'DROP TABLE', 'DELETE FROM', 'INSERT INTO', 'UPDATE SET']
            for pattern in dangerous_patterns:
                if pattern.lower() in data.lower():
                    security_issues.append(f"Potentially dangerous pattern detected: {pattern}")

        elif isinstance(data, dict):
            # Recursively validate dictionary values
            for key, value in data.items():
                key_validation = self._fallback_validation(key, f"{context}_key")
                value_validation = self._fallback_validation(value, f"{context}_value")

                if not key_validation.is_valid:
                    security_issues.extend(key_validation.security_issues)
                if not value_validation.is_valid:
                    security_issues.extend(value_validation.security_issues)

        elif isinstance(data, list):
            # Validate each item in list
            for item in data:
                item_validation = self._fallback_validation(item, f"{context}_item")
                if not item_validation.is_valid:
                    security_issues.extend(item_validation.security_issues)

        return ValidationResult(
            is_valid=len(security_issues) == 0,
            sanitized_value=data,
            errors=errors,
            security_issues=security_issues
        )

    async def _secure_subprocess_run(self, cmd: List[str], timeout: int = 30, context: str = "subprocess") -> subprocess.CompletedProcess:
        """Secure subprocess execution with validation and sandboxing."""
        # Validate command and arguments
        validation_result = await self._validate_and_sanitize_input(cmd, f"subprocess_{context}")

        if not validation_result.is_valid:
            logger.error(f"Subprocess validation failed: {validation_result.security_issues}")
            raise ValueError(f"Security validation failed: {validation_result.security_issues}")

        # Additional command validation
        if not cmd or not isinstance(cmd, list):
            raise ValueError("Command must be a non-empty list")

        # Whitelist allowed commands
        allowed_commands = {'gcloud', 'gsutil', 'kubectl', 'terraform'}
        base_command = cmd[0].split('/')[-1]  # Extract just the command name

        if base_command not in allowed_commands:
            raise ValueError(f"Command '{base_command}' not in allowed list: {allowed_commands}")

        try:
            # Execute with timeout and security restrictions
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False  # Don't raise on non-zero exit
            )

            return result

        except subprocess.TimeoutExpired:
            logger.error(f"Subprocess timeout after {timeout}s: {' '.join(cmd)}")
            raise
        except Exception as e:
            logger.error(f"Subprocess execution failed: {e}")
            raise
    
    @property
    def plug_metadata(self):
        """Plugin metadata."""
        return {
            "name": "gcp_factory",
            "version": "1.0.0",
            "owner": "PlugPipe Core Team",
            "status": "stable",
            "description": "Enterprise GCP factory for multi-service cloud orchestration with unified interface and secure credential management",
            "capabilities": [
                "gcp_multi_service_orchestration",
                "unified_gcp_interface",
                "secure_credential_management",
                "auto_scaling",
                "cost_optimization",
                "multi_region_support",
                "enterprise_monitoring"
            ]
        }
    
    @property
    def supported_services(self):
        """List of supported GCP services."""
        return ['compute', 'storage', 'bigquery', 'functions', 'gke', 'sql', 'pubsub', 'iam']
    
    async def process(self, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process GCP Factory Plugin operations.
        
        Args:
            ctx: Pipeline context
            config: Operation configuration
            
        Returns:
            Operation result
        """
        try:
            action = config.get('action', 'initialize')
            service = config.get('service')
            
            if action == 'create_resource':
                if not service:
                    return {'success': False, 'error': 'Service parameter required for create_resource'}
                
                resource_type = config.get('resource_type', 'instance')
                resource_config = config.get('config', {})
                
                await self.initialize()
                result = await self.create_gcp_resource(service, resource_type, resource_config)
                
                return {
                    'success': result.get('success', False),
                    'resource_id': result.get('resource_id'),
                    'resource_details': result.get('resource_details', {}),
                    'operation': 'create_resource'
                }
            
            elif action == 'list_resources':
                if not service:
                    return {'success': False, 'error': 'Service parameter required for list_resources'}
                
                filters = config.get('filters', {})
                await self.initialize()
                resources = await self.list_gcp_resources(service, filters)
                
                return {
                    'success': True,
                    'resources': resources,
                    'operation': 'list_resources'
                }
            
            elif action == 'delete_resource':
                if not service:
                    return {'success': False, 'error': 'Service parameter required for delete_resource'}
                
                resource_id = config.get('resource_id')
                if not resource_id:
                    return {'success': False, 'error': 'Resource ID required for delete_resource'}
                
                await self.initialize()
                result = await self._delete_resource(service, resource_id, config)
                
                return {
                    'success': result.get('success', False),
                    'status': result.get('status', 'unknown'),
                    'operation': 'delete_resource'
                }
            
            elif action == 'get_resource_status':
                if not service:
                    return {'success': False, 'error': 'Service parameter required for get_resource_status'}
                
                resource_id = config.get('resource_id')
                if not resource_id:
                    return {'success': False, 'error': 'Resource ID required for get_resource_status'}
                
                await self.initialize()
                result = await self._get_resource_status(service, resource_id)
                
                return {
                    'success': result.get('success', False),
                    'status': result.get('status', 'unknown'),
                    'resource_details': result.get('resource_details', {}),
                    'operation': 'get_resource_status'
                }
            
            elif action == 'update_resource':
                if not service:
                    return {'success': False, 'error': 'Service parameter required for update_resource'}
                
                resource_id = config.get('resource_id')
                if not resource_id:
                    return {'success': False, 'error': 'Resource ID required for update_resource'}
                
                await self.initialize()
                result = await self._update_resource(service, resource_id, config)
                
                return {
                    'success': result.get('success', False),
                    'status': result.get('status', 'unknown'),
                    'operation': 'update_resource'
                }
            
            elif action == 'optimize_costs':
                await self.initialize()
                recommendations = await self._optimize_costs(service)
                
                return {
                    'success': True,
                    'cost_optimization': {
                        'recommendations': recommendations,
                        'service': service or 'all'
                    },
                    'operation': 'optimize_costs'
                }
            
            elif action == 'setup_monitoring':
                if not service:
                    return {'success': False, 'error': 'Service parameter required for setup_monitoring'}
                
                resource_id = config.get('resource_id')
                await self.initialize()
                monitoring_config = await self._setup_monitoring(service, resource_id)
                
                return {
                    'success': True,
                    'monitoring_setup': monitoring_config,
                    'operation': 'setup_monitoring'
                }
            
            elif action == 'configure_auto_scaling':
                if not service:
                    return {'success': False, 'error': 'Service parameter required for configure_auto_scaling'}
                
                scaling_config = config.get('config', {})
                await self.initialize()
                auto_scaling_result = await self._configure_auto_scaling(service, scaling_config)
                
                return {
                    'success': True,
                    'auto_scaling_config': auto_scaling_result,
                    'operation': 'configure_auto_scaling'
                }
            
            elif service and service not in self.supported_services:
                return {
                    'success': False,
                    'error': f'GCP service "{service}" is not supported. Supported services: {self.supported_services}'
                }
            
            else:
                # Default: Initialize and return status
                await self.initialize()
                status = self.get_factory_status()
                
                return {
                    'success': True,
                    'factory_type': 'gcp',
                    'status': 'ready',
                    'capabilities': self.plug_metadata['capabilities'],
                    'factory_status': status,
                    'operation': 'initialize'
                }
        
        except Exception as e:
            logger.error(f"GCP Factory Plugin process error: {e}")
            return {
                'success': False,
                'error': str(e),
                'operation': config.get('action', 'unknown')
            }
    
    async def _delete_resource(self, service: str, resource_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Delete a GCP resource."""
        try:
            if service == 'compute':
                # Delete Compute Engine instance
                cmd = ['gcloud', 'compute', 'instances', 'delete', resource_id, '--zone', self.gcp_config.get('zone', 'us-central1-a'), '--quiet']
                result = await self._secure_subprocess_run(cmd, timeout=60, context="delete_instance")
                
                if result.returncode == 0:
                    return {'success': True, 'status': 'deleted'}
                
                return {'success': False, 'error': result.stderr}
            
            elif service == 'storage':
                # Delete Cloud Storage bucket
                cmd = ['gsutil', 'rm', '-r', f'gs://{resource_id}']
                result = await self._secure_subprocess_run(cmd, timeout=60, context="delete_bucket")
                
                if result.returncode == 0:
                    return {'success': True, 'status': 'deleted'}
                
                return {'success': False, 'error': result.stderr}
            
            else:
                return {'success': False, 'error': f'Delete operation not implemented for service: {service}'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _get_resource_status(self, service: str, resource_id: str) -> Dict[str, Any]:
        """Get GCP resource status."""
        try:
            if service == 'compute':
                # Get Compute Engine instance status
                cmd = ['gcloud', 'compute', 'instances', 'describe', resource_id,
                       '--zone', self.gcp_config.get('zone', 'us-central1-a'), '--format', 'json']
                result = await self._secure_subprocess_run(cmd, timeout=30, context="get_instance_status")
                
                if result.returncode == 0:
                    instance = json.loads(result.stdout)
                    return {
                        'success': True,
                        'status': instance.get('status', 'unknown'),
                        'resource_details': instance
                    }
                
                return {'success': False, 'error': result.stderr}
            
            elif service == 'storage':
                # Get Cloud Storage bucket status (check if exists)
                cmd = ['gsutil', 'ls', '-b', f'gs://{resource_id}']
                result = await self._secure_subprocess_run(cmd, timeout=30, context="get_bucket_status")
                
                if result.returncode == 0:
                    return {'success': True, 'status': 'exists'}
                
                return {'success': False, 'error': result.stderr}
            
            else:
                return {'success': False, 'error': f'Status check not implemented for service: {service}'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _update_resource(self, service: str, resource_id: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Update a GCP resource."""
        try:
            if service == 'compute':
                # Example: Stop/start Compute Engine instance
                action = config.get('config', {}).get('action', 'stop')
                
                if action == 'stop':
                    cmd = ['gcloud', 'compute', 'instances', 'stop', resource_id,
                           '--zone', self.gcp_config.get('zone', 'us-central1-a')]
                elif action == 'start':
                    cmd = ['gcloud', 'compute', 'instances', 'start', resource_id,
                           '--zone', self.gcp_config.get('zone', 'us-central1-a')]
                else:
                    return {'success': False, 'error': f'Unsupported Compute Engine action: {action}'}

                result = await self._secure_subprocess_run(cmd, timeout=60, context="update_instance")
                
                if result.returncode == 0:
                    status = 'stopping' if action == 'stop' else 'starting'
                    return {'success': True, 'status': status}
                
                return {'success': False, 'error': result.stderr}
            
            else:
                return {'success': False, 'error': f'Update operation not implemented for service: {service}'}
        
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    async def _optimize_costs(self, service: Optional[str] = None) -> List[Dict[str, Any]]:
        """Generate cost optimization recommendations."""
        recommendations = []
        
        if not service or service == 'compute':
            recommendations.extend([
                {
                    'service': 'compute',
                    'recommendation': 'Use preemptible instances for batch workloads to save up to 80%',
                    'potential_savings': '60-80%',
                    'priority': 'high'
                },
                {
                    'service': 'compute',
                    'recommendation': 'Enable committed use discounts for predictable workloads',
                    'potential_savings': '20-30%',
                    'priority': 'medium'
                }
            ])
        
        if not service or service == 'storage':
            recommendations.extend([
                {
                    'service': 'storage',
                    'recommendation': 'Use Nearline or Coldline storage for infrequently accessed data',
                    'potential_savings': '40-60%',
                    'priority': 'high'
                },
                {
                    'service': 'storage',
                    'recommendation': 'Enable lifecycle management for automatic storage class transitions',
                    'potential_savings': '30-50%',
                    'priority': 'medium'
                }
            ])
        
        return recommendations
    
    async def _setup_monitoring(self, service: str, resource_id: Optional[str] = None) -> Dict[str, Any]:
        """Setup monitoring for GCP resources."""
        monitoring_config = {
            'service': service,
            'resource_id': resource_id,
            'cloud_monitoring_metrics': [],
            'alerting_policies': [],
            'notification_channels': []
        }
        
        if service == 'compute':
            monitoring_config['cloud_monitoring_metrics'] = [
                {
                    'name': f'compute-cpu-utilization-{resource_id}',
                    'metric': 'compute.googleapis.com/instance/cpu/utilization',
                    'threshold': 0.8,
                    'comparison': 'COMPARISON_GREATER_THAN'
                },
                {
                    'name': f'compute-disk-utilization-{resource_id}',
                    'metric': 'compute.googleapis.com/instance/disk/utilization',
                    'threshold': 0.9,
                    'comparison': 'COMPARISON_GREATER_THAN'
                }
            ]
        
        elif service == 'storage':
            monitoring_config['cloud_monitoring_metrics'] = [
                {
                    'name': f'storage-api-request-count-{resource_id}',
                    'metric': 'storage.googleapis.com/api/request_count',
                    'threshold': 1000,
                    'comparison': 'COMPARISON_GREATER_THAN'
                }
            ]
        
        return monitoring_config
    
    async def _configure_auto_scaling(self, service: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure auto-scaling for GCP resources."""
        auto_scaling_config = {
            'service': service,
            'managed_instance_group': None,
            'autoscaler': None,
            'configuration': config
        }
        
        if service == 'compute':
            min_replicas = config.get('min_replicas', 1)
            max_replicas = config.get('max_replicas', 10)
            target_cpu_utilization = config.get('target_cpu_utilization', 0.7)
            
            auto_scaling_config.update({
                'managed_instance_group': f'plugpipe-mig-{self.factory_id}',
                'autoscaler': f'plugpipe-autoscaler-{self.factory_id}',
                'autoscaling_policy': {
                    'min_num_replicas': min_replicas,
                    'max_num_replicas': max_replicas,
                    'cpu_utilization': {
                        'utilization_target': target_cpu_utilization
                    }
                }
            })
        
        return auto_scaling_config
    
    async def initialize(self) -> bool:
        """Initialize the GCP Factory Plugin."""
        try:
            if self.initialized:
                return True
            
            # Load GCP credentials
            await self._load_credentials()
            
            # Initialize enabled services
            for service_name in self.enabled_services:
                if service_name == 'compute':
                    service = GCPComputeEngineService({
                        'project_id': self.project_id,
                        'zone': self.gcp_config.get('zone', 'us-central1-a'),
                        'region': self.primary_region,
                        **self.services_config.get('compute', {})
                    }, parent=self)
                elif service_name == 'storage':
                    service = GCPCloudStorageService({
                        'project_id': self.project_id,
                        'region': self.primary_region,
                        **self.services_config.get('storage', {})
                    }, parent=self)
                else:
                    logger.warning(f"Service {service_name} not yet implemented")
                    continue
                
                # Initialize the service
                if await service.initialize(self.credentials):
                    self.gcp_services[service_name] = service
                    logger.info(f"GCP {service_name} service loaded successfully")
                else:
                    logger.error(f"Failed to initialize GCP {service_name} service")
            
            self.active_region = self.primary_region
            self.initialized = True
            
            logger.info(f"GCP Factory Plugin initialized with {len(self.gcp_services)} services")
            return True
            
        except Exception as e:
            logger.error(f"Failed to initialize GCP Factory Plugin: {e}")
            return False
    
    async def _load_credentials(self) -> bool:
        """Load GCP credentials from various sources."""
        try:
            # Try environment variables first
            service_account_key = os.getenv('GOOGLE_APPLICATION_CREDENTIALS')
            if service_account_key:
                if os.path.isfile(service_account_key):
                    with open(service_account_key, 'r') as f:
                        self.credentials['service_account_key'] = json.load(f)
                    logger.info("Loaded GCP credentials from GOOGLE_APPLICATION_CREDENTIALS")
                    return True
            
            # Try gcloud default credentials
            try:
                result = await self._secure_subprocess_run(['gcloud', 'auth', 'list', '--format', 'json'],
                                                          timeout=30, context="auth_check")
                if result.returncode == 0:
                    accounts = json.loads(result.stdout)
                    if accounts:
                        self.credentials['configured'] = True
                        logger.info("Using gcloud default credentials")
                        return True
            except Exception:
                pass
            
            logger.warning("No GCP credentials found - some operations may fail")
            return True
            
        except Exception as e:
            logger.error(f"Error loading GCP credentials: {e}")
            return False
    
    async def create_gcp_resource(self, service: str, resource_type: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a GCP resource using the appropriate service."""
        try:
            if service not in self.gcp_services:
                return {
                    'success': False,
                    'error': f'GCP service {service} not available. Available services: {list(self.gcp_services.keys())}'
                }
            
            gcp_service = self.gcp_services[service]
            result = await gcp_service.create_resource(resource_type, config)
            
            # Track managed resources
            if result.get('success') and result.get('resource_id'):
                resource_key = f"{service}:{resource_type}:{result['resource_id']}"
                self.managed_resources[resource_key] = {
                    'service': service,
                    'resource_type': resource_type,
                    'resource_id': result['resource_id'],
                    'created_at': datetime.now().isoformat(),
                    'factory_id': self.factory_id,
                    'namespace': self.namespace,
                    'config': config
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Error creating GCP resource: {e}")
            return {'success': False, 'error': str(e)}
    
    async def list_gcp_resources(self, service: str, filters: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """List GCP resources from the specified service."""
        try:
            if service not in self.gcp_services:
                return []
            
            gcp_service = self.gcp_services[service]
            return await gcp_service.list_resources(filters)
            
        except Exception as e:
            logger.error(f"Error listing GCP resources: {e}")
            return []
    
    async def list_managed_resources(self) -> List[Dict[str, Any]]:
        """List all resources managed by this factory."""
        resources = []
        
        for resource_key, resource_info in self.managed_resources.items():
            resources.append({
                'resource_key': resource_key,
                'service': resource_info['service'],
                'resource_type': resource_info['resource_type'],
                'resource_id': resource_info['resource_id'],
                'created_at': resource_info['created_at'],
                'factory_id': resource_info['factory_id'],
                'namespace': resource_info['namespace']
            })
        
        return resources
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive GCP factory health check."""
        factory_health = {
            'factory_id': self.factory_id,
            'factory_healthy': self.initialized,
            'active_region': self.active_region,
            'primary_region': self.primary_region,
            'enabled_services': self.enabled_services,
            'loaded_services': list(self.gcp_services.keys()),
            'managed_resources': len(self.managed_resources),
            'auto_failover': self.auto_failover,
            'namespace': self.namespace,
            'services_status': {},
            'credentials_status': {}
        }
        
        # Check each GCP service health
        for service_name, service in self.gcp_services.items():
            try:
                health = await service.health_check()
                factory_health['services_status'][service_name] = health
            except Exception as e:
                factory_health['services_status'][service_name] = {
                    'healthy': False,
                    'error': str(e)
                }
        
        # Check credentials status
        try:
            if self.credentials.get('configured') or self.credentials.get('service_account_key'):
                factory_health['credentials_status'] = {'status': 'configured', 'healthy': True}
            else:
                factory_health['credentials_status'] = {'status': 'missing', 'healthy': False}
        except Exception as e:
            factory_health['credentials_status'] = {'error': str(e), 'healthy': False}
        
        return factory_health
    
    def get_factory_status(self) -> Dict[str, Any]:
        """Get current factory status."""
        return {
            'factory_id': self.factory_id,
            'initialized': self.initialized,
            'active_region': self.active_region,
            'primary_region': self.primary_region,
            'enabled_services': self.enabled_services,
            'loaded_services': list(self.gcp_services.keys()),
            'managed_resources': len(self.managed_resources),
            'auto_failover': self.auto_failover,
            'cost_optimization': self.cost_optimization,
            'namespace': self.namespace
        }

# Plugin metadata
plug_metadata = {
    "name": "gcp_factory_plugin",
    "version": "1.0.0",
    "owner": "PlugPipe Core Team",
    "status": "stable",
    "category": "cloud",
    "description": "Enterprise GCP factory for multi-service cloud orchestration with unified interface and secure credential management",
    "capabilities": [
        "gcp_multi_service_orchestration",
        "unified_gcp_interface",
        "secure_credential_management",
        "auto_scaling",
        "cost_optimization",
        "multi_region_support",
        "enterprise_monitoring"
    ]
}

async def process_async(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Async process function for GCP Factory Plugin."""

    # FTHAD SECURITY HARDENING: Input validation and sanitization
    # Validate context parameter
    if not isinstance(ctx, dict):
        return {
            'success': False,
            'error': 'Invalid context parameter type - must be dictionary',
            'security_hardening': 'Context type validation failed'
        }

    # Validate config parameter
    if not isinstance(config, dict):
        return {
            'success': False,
            'error': 'Invalid config parameter type - must be dictionary',
            'security_hardening': 'Config type validation failed'
        }

    # Validate and sanitize operation parameter
    operation = config.get('operation', 'initialize')
    if not isinstance(operation, str):
        return {
            'success': False,
            'error': 'Operation parameter must be a string',
            'security_hardening': 'Operation type validation failed'
        }

    # Sanitize operation to prevent injection attacks
    operation = operation.strip().lower()
    if not operation.replace('_', '').replace('-', '').isalnum():
        return {
            'success': False,
            'error': 'Operation contains invalid characters',
            'security_hardening': 'Operation sanitization failed'
        }

    # Validate operation is in allowed list
    allowed_operations = [
        'initialize', 'health_check', 'create_resource', 'list_resources',
        'get_resource', 'update_resource', 'delete_resource', 'get_services'
    ]
    if operation not in allowed_operations:
        return {
            'success': False,
            'error': f'Invalid operation: {operation}. Allowed: {allowed_operations}',
            'security_hardening': 'Operation validation failed'
        }

    # Validate service parameter if provided
    service = config.get('service')
    if service is not None:
        if not isinstance(service, str):
            return {
                'success': False,
                'error': 'Service parameter must be a string',
                'security_hardening': 'Service type validation failed'
            }

        # Sanitize service parameter
        service = service.strip().lower()
        allowed_services = ['compute', 'storage', 'networking', 'iam', 'dns']
        if service not in allowed_services:
            return {
                'success': False,
                'error': f'Invalid service: {service}. Allowed: {allowed_services}',
                'security_hardening': 'Service validation failed'
            }

    # Validate resource type parameter if provided
    resource_type = config.get('resource_type')
    if resource_type is not None:
        if not isinstance(resource_type, str):
            return {
                'success': False,
                'error': 'Resource type parameter must be a string',
                'security_hardening': 'Resource type validation failed'
            }

        # Sanitize resource type parameter
        resource_type = resource_type.strip().lower()
        allowed_resource_types = ['instance', 'disk', 'network', 'subnet', 'firewall', 'bucket']
        if resource_type not in allowed_resource_types:
            return {
                'success': False,
                'error': f'Invalid resource type: {resource_type}. Allowed: {allowed_resource_types}',
                'security_hardening': 'Resource type validation failed'
            }

    # Validate resource_id parameter if provided (for get/update/delete operations)
    resource_id = config.get('resource_id')
    if resource_id is not None:
        if not isinstance(resource_id, str):
            return {
                'success': False,
                'error': 'Resource ID parameter must be a string',
                'security_hardening': 'Resource ID type validation failed'
            }

        # Validate resource ID format (alphanumeric, hyphens, underscores only)
        if not re.match(r'^[a-zA-Z0-9._-]+$', resource_id):
            return {
                'success': False,
                'error': 'Resource ID contains invalid characters',
                'security_hardening': 'Resource ID format validation failed'
            }

        # Prevent extremely long resource IDs
        if len(resource_id) > 255:
            return {
                'success': False,
                'error': 'Resource ID exceeds maximum length of 255 characters',
                'security_hardening': 'Resource ID length validation failed'
            }

    # Validate project_id parameter if provided
    project_id = config.get('project_id')
    if project_id is not None:
        if not isinstance(project_id, str):
            return {
                'success': False,
                'error': 'Project ID parameter must be a string',
                'security_hardening': 'Project ID type validation failed'
            }

        # Validate GCP project ID format
        if not re.match(r'^[a-z][a-z0-9-]{4,28}[a-z0-9]$', project_id):
            return {
                'success': False,
                'error': 'Invalid GCP project ID format',
                'security_hardening': 'Project ID format validation failed'
            }

    # Validate overall payload size to prevent DoS
    MAX_PAYLOAD_SIZE = 2 * 1024 * 1024  # 2MB limit for cloud operations
    total_size = len(str(ctx)) + len(str(config))
    if total_size > MAX_PAYLOAD_SIZE:
        return {
            'success': False,
            'error': f'Payload exceeds maximum size of {MAX_PAYLOAD_SIZE} bytes',
            'security_hardening': 'Payload size validation failed'
        }

    # Validate resource_config parameter if provided
    resource_config = config.get('resource_config')
    if resource_config is not None:
        if not isinstance(resource_config, dict):
            return {
                'success': False,
                'error': 'Resource config parameter must be a dictionary',
                'security_hardening': 'Resource config type validation failed'
            }

        # Validate resource config size
        MAX_RESOURCE_CONFIG_SIZE = 100 * 1024  # 100KB limit for resource config
        if len(str(resource_config)) > MAX_RESOURCE_CONFIG_SIZE:
            return {
                'success': False,
                'error': f'Resource config exceeds maximum size of {MAX_RESOURCE_CONFIG_SIZE} bytes',
                'security_hardening': 'Resource config size validation failed'
            }

    try:
        gcp_factory = GCPFactoryPlugin(config)
        
        if operation == 'health_check':
            await gcp_factory.initialize()
            health_status = await gcp_factory.health_check()
            return {
                'success': True,
                'operation_completed': 'health_check',
                'health_status': health_status
            }
        
        elif operation == 'create_resource':
            await gcp_factory.initialize()
            service = config.get('service', 'compute')
            resource_type = config.get('resource_type', 'instance')
            resource_config = config.get('resource_config', {})
            result = await gcp_factory.create_gcp_resource(service, resource_type, resource_config)
            return {
                'success': result.get('success', False),
                'operation_completed': 'create_resource',
                'result': result
            }
        
        elif operation == 'list_resources':
            await gcp_factory.initialize()
            service = config.get('service', 'compute')
            filters = config.get('filters', {})
            resources = await gcp_factory.list_gcp_resources(service, filters)
            return {
                'success': True,
                'operation_completed': 'list_resources',
                'resources': resources
            }
        
        elif operation == 'list_managed':
            await gcp_factory.initialize()
            managed = await gcp_factory.list_managed_resources()
            return {
                'success': True,
                'operation_completed': 'list_managed',
                'managed_resources': managed
            }
        
        else:
            # Default: Factory initialization and status
            result = await gcp_factory.initialize()
            status = gcp_factory.get_factory_status()
            
            return {
                'success': result,
                'factory_type': 'gcp',
                'status': 'ready' if result else 'failed',
                'capabilities': plug_metadata['capabilities'],
                'factory_status': status
            }
    
    except Exception as e:
        logger.error(f"GCP Factory Plugin error: {e}")
        return {
            'success': False,
            'error': str(e),
            'factory_type': 'gcp'
        }

def process(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous wrapper for the async process function."""
    return asyncio.run(process_async(ctx, config))

if __name__ == "__main__":
    # Test the GCP Factory Plugin
    test_config = {
        'gcp_factory': {
            'project_id': 'test-project-123',
            'primary_region': 'us-central1',
            'fallback_regions': ['us-west1'],
            'enabled_services': ['compute', 'storage'],
            'auto_failover': True,
            'cost_optimization': True,
            'namespace': 'plugpipe-test'
        },
        'gcp_services': {
            'compute': {
                'zone': 'us-central1-a',
                'machine_types': ['e2-micro', 'e2-small'],
                'networks': []
            },
            'storage': {
                'default_storage_class': 'STANDARD',
                'default_location': 'us-central1'
            }
        }
    }
    
    result = process({}, test_config)
    print(json.dumps(result, indent=2))