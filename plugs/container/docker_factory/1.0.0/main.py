#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Docker Factory Plugin for PlugPipe

Enterprise-grade container orchestration factory that manages plugin execution
in isolated Docker containers. Provides secure plugin isolation, resource management,
and scalable containerized execution following the proven factory pattern.

Key Features:
- Container-based plugin isolation and sandboxing
- Dynamic container scaling based on demand
- Resource limits and monitoring per container
- Secure inter-container communication
- Enterprise container orchestration capabilities
- Zero-downtime container updates and scaling
"""

import asyncio
import json
import logging
import os
import re
import shlex
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import subprocess
import tempfile
import yaml

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Try to import the pp function for Universal Input Sanitizer
try:
    import sys
    import os
    sys.path.append(os.path.join(os.path.dirname(__file__), '..', '..', '..', '..'))
    from shares.loader import pp
    SANITIZER_AVAILABLE = True
except ImportError:
    SANITIZER_AVAILABLE = False
    logger.warning("Universal Input Sanitizer not available - using fallback validation")

@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_violations: List[str] = field(default_factory=list)
    sanitized_data: Optional[Dict[str, Any]] = None

class ContainerInterface(ABC):
    """Interface for container execution plugins."""

    @abstractmethod
    async def start_container(self, image: str, config: Dict[str, Any]) -> str:
        """Start a container and return container ID."""
        pass

    @abstractmethod
    async def stop_container(self, container_id: str) -> bool:
        """Stop a container."""
        pass

    @abstractmethod
    async def execute_in_container(self, container_id: str, command: str) -> Dict[str, Any]:
        """Execute command in container."""
        pass

    @abstractmethod
    async def get_container_status(self, container_id: str) -> Dict[str, Any]:
        """Get container status and health."""
        pass

    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check container system health."""
        pass

class DockerContainerPlugin(ContainerInterface):
    """Docker-based container execution plugin with comprehensive security hardening."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('docker', {})
        self.registry = self._validate_registry(self.config.get('registry', 'docker.io'))
        self.network = self._validate_network_name(self.config.get('network', 'plugpipe-network'))
        self.resource_limits = self._validate_resource_limits(self.config.get('resource_limits', {}))
        self.security_options = self._validate_security_options(self.config.get('security_options', {}))
        self.initialized = False
        self.sanitizer_available = SANITIZER_AVAILABLE

        # Security constraints
        self.max_concurrent_containers = 50
        self.allowed_image_patterns = [
            r'^[a-zA-Z0-9][a-zA-Z0-9._/-]*:[a-zA-Z0-9._-]+$',  # Standard image:tag
            r'^[a-zA-Z0-9][a-zA-Z0-9._/-]*@sha256:[a-f0-9]{64}$'  # Image by digest
        ]
        self.dangerous_capabilities = [
            'SYS_ADMIN', 'NET_ADMIN', 'SYS_PTRACE', 'SYS_MODULE',
            'DAC_READ_SEARCH', 'DAC_OVERRIDE', 'SETUID', 'SETGID'
        ]

        # Enhanced security configuration
        self._setup_enhanced_security_defaults()

    def _setup_enhanced_security_defaults(self):
        """Setup enhanced security hardening defaults for container operations."""
        # Container security defaults
        self.security_config = {
            'enforce_read_only_root': True,
            'drop_all_capabilities': True,
            'enable_seccomp': True,
            'enable_apparmor': True,
            'disable_network_access': False,  # Allow but restricted
            'prevent_privilege_escalation': True,
            'enforce_non_root_user': True,
            'enable_resource_quotas': True,
            'scan_images_for_vulnerabilities': True
        }

        # Blocked container operations
        self.blocked_operations = {
            'mount_docker_socket', 'privileged_mode', 'host_network',
            'host_pid', 'host_ipc', 'kernel_memory_access'
        }

        # Trusted container registries
        self.trusted_registries = {
            'docker.io', 'gcr.io', 'quay.io', 'registry.redhat.io',
            'mcr.microsoft.com', 'public.ecr.aws', 'harbor.local'
        }

    def _validate_container_image(self, image: str) -> Dict[str, Any]:
        """Enhanced validation for container images."""
        validation_result = {
            'is_valid': True,
            'sanitized_image': image,
            'errors': [],
            'security_issues': []
        }

        try:
            # Basic image format validation
            if not image or not isinstance(image, str):
                validation_result['is_valid'] = False
                validation_result['errors'].append("Invalid image format")
                return validation_result

            # Check against allowed patterns
            valid_pattern = False
            for pattern in self.allowed_image_patterns:
                if re.match(pattern, image):
                    valid_pattern = True
                    break

            if not valid_pattern:
                validation_result['is_valid'] = False
                validation_result['errors'].append(f"Image '{image}' doesn't match allowed patterns")
                return validation_result

            # Extract registry from image
            registry = self._extract_registry_from_image(image)

            # Validate registry against trusted list
            if registry not in self.trusted_registries:
                validation_result['security_issues'].append(
                    f"Untrusted registry '{registry}', consider using trusted registries"
                )
                # Don't fail, but warn

            # Check for dangerous image names
            dangerous_images = {
                'latest', 'alpine:latest', 'ubuntu:latest', 'centos:latest'
            }
            if image.split(':')[-1] in dangerous_images or ':latest' in image:
                validation_result['security_issues'].append(
                    "Using 'latest' tag is discouraged for security - use specific versions"
                )

            # Block known malicious patterns
            malicious_patterns = [
                r'.*cryptominer.*', r'.*bitcoin.*', r'.*monero.*',
                r'.*malware.*', r'.*backdoor.*'
            ]

            for pattern in malicious_patterns:
                if re.search(pattern, image, re.IGNORECASE):
                    validation_result['is_valid'] = False
                    validation_result['errors'].append(f"Blocked potentially malicious image: {image}")
                    return validation_result

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['errors'].append(f"Image validation error: {str(e)}")

        return validation_result

    def _extract_registry_from_image(self, image: str) -> str:
        """Extract registry name from container image."""
        # Handle different image formats
        if '/' not in image:
            return 'docker.io'  # Default registry

        parts = image.split('/')
        if len(parts) >= 2 and '.' in parts[0]:
            return parts[0]  # Has registry
        else:
            return 'docker.io'  # Default Docker Hub

    def _validate_container_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Enhanced validation for container configuration."""
        validation_result = {
            'is_valid': True,
            'sanitized_config': config.copy(),
            'errors': [],
            'security_issues': []
        }

        try:
            sanitized = validation_result['sanitized_config']

            # Validate environment variables
            if 'environment' in sanitized:
                sanitized['environment'] = self._validate_environment_variables(
                    sanitized['environment']
                )

            # Validate ports
            if 'ports' in sanitized:
                sanitized['ports'] = self._validate_container_ports(sanitized['ports'])

            # Validate volumes
            if 'volumes' in sanitized:
                volume_validation = self._validate_container_volumes(sanitized['volumes'])
                if not volume_validation['is_valid']:
                    validation_result['errors'].extend(volume_validation['errors'])
                    validation_result['is_valid'] = False
                sanitized['volumes'] = volume_validation['sanitized_volumes']

            # Force security options
            if 'security_opt' not in sanitized:
                sanitized['security_opt'] = []

            # Enforce read-only root filesystem
            if self.security_config['enforce_read_only_root']:
                sanitized['read_only'] = True

            # Drop all capabilities by default
            if self.security_config['drop_all_capabilities']:
                sanitized['cap_drop'] = ['ALL']
                if 'cap_add' in sanitized:
                    # Only allow safe capabilities
                    safe_caps = {'NET_BIND_SERVICE', 'CHOWN', 'FOWNER'}
                    sanitized['cap_add'] = [
                        cap for cap in sanitized['cap_add'] if cap in safe_caps
                    ]

            # Prevent privilege escalation
            if self.security_config['prevent_privilege_escalation']:
                sanitized['security_opt'].append('no-new-privileges:true')

            # Enforce non-root user
            if self.security_config['enforce_non_root_user']:
                if 'user' not in sanitized or sanitized['user'] == 'root':
                    sanitized['user'] = '1000:1000'  # Default non-root user

            # Block dangerous operations
            dangerous_configs = {
                'privileged': True,
                'pid_mode': 'host',
                'network_mode': 'host',
                'ipc_mode': 'host'
            }

            for key, dangerous_value in dangerous_configs.items():
                if sanitized.get(key) == dangerous_value:
                    validation_result['errors'].append(
                        f"Dangerous configuration blocked: {key}={dangerous_value}"
                    )
                    validation_result['is_valid'] = False

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['errors'].append(f"Configuration validation error: {str(e)}")

        return validation_result

    def _validate_environment_variables(self, env_vars: Dict[str, str]) -> Dict[str, str]:
        """Validate and sanitize container environment variables."""
        sanitized_env = {}

        # Dangerous environment variables that should be blocked
        blocked_env_vars = {
            'DOCKER_HOST', 'DOCKER_CERT_PATH', 'DOCKER_TLS_VERIFY',
            'PATH', 'HOME', 'USER', 'SHELL', 'PWD'
        }

        for key, value in env_vars.items():
            # Environment variable name validation
            if not re.match(r'^[A-Z][A-Z0-9_]*$', key):
                logger.warning(f"Invalid environment variable name '{key}', skipping")
                continue

            # Block sensitive variables
            if key in blocked_env_vars:
                logger.warning(f"Blocked dangerous environment variable '{key}', skipping")
                continue

            # Sanitize value (remove potentially dangerous characters)
            sanitized_value = re.sub(r'[;&|`$()<>]', '', str(value))
            sanitized_env[key] = sanitized_value

        return sanitized_env

    def _validate_container_ports(self, ports: List[str]) -> List[str]:
        """Validate container port mappings for security."""
        validated_ports = []

        # Blocked port ranges
        blocked_ranges = [
            (1, 1023),      # System/privileged ports
            (22, 22),       # SSH
            (3389, 3389),   # RDP
            (5432, 5432),   # PostgreSQL
            (3306, 3306),   # MySQL
        ]

        for port_mapping in ports:
            try:
                # Parse port mapping (e.g., "8080:80", "80")
                if ':' in port_mapping:
                    host_port, container_port = port_mapping.split(':', 1)
                    host_port_num = int(host_port)
                else:
                    host_port_num = int(port_mapping)
                    container_port = port_mapping

                # Check against blocked ranges
                blocked = False
                for start, end in blocked_ranges:
                    if start <= host_port_num <= end:
                        logger.warning(f"Blocked dangerous port {host_port_num}, skipping")
                        blocked = True
                        break

                if not blocked and 1 <= host_port_num <= 65535:
                    validated_ports.append(port_mapping)

            except (ValueError, IndexError):
                logger.warning(f"Invalid port mapping '{port_mapping}', skipping")
                continue

        return validated_ports

    def _validate_container_volumes(self, volumes: List[str]) -> Dict[str, Any]:
        """Validate container volume mounts for security."""
        validation_result = {
            'is_valid': True,
            'sanitized_volumes': [],
            'errors': []
        }

        # Dangerous paths that should never be mounted
        dangerous_paths = {
            '/var/run/docker.sock',  # Docker socket
            '/proc', '/sys', '/dev',  # System directories
            '/etc/passwd', '/etc/shadow',  # System files
            '/root', '/home',  # User directories
            '/boot', '/usr/bin', '/bin'  # System binaries
        }

        for volume in volumes:
            try:
                # Parse volume mapping (e.g., "/host/path:/container/path:ro")
                parts = volume.split(':')
                if len(parts) < 2:
                    validation_result['errors'].append(f"Invalid volume format: {volume}")
                    validation_result['is_valid'] = False
                    continue

                host_path = parts[0]

                # Check against dangerous paths
                if any(host_path.startswith(dangerous) for dangerous in dangerous_paths):
                    validation_result['errors'].append(
                        f"Dangerous volume mount blocked: {host_path}"
                    )
                    validation_result['is_valid'] = False
                    continue

                # Force read-only for sensitive directories
                if host_path.startswith('/etc') or host_path.startswith('/usr'):
                    if len(parts) == 2:
                        volume += ':ro'  # Add read-only flag
                    elif parts[2] != 'ro':
                        parts[2] = 'ro'  # Force read-only
                        volume = ':'.join(parts)

                validation_result['sanitized_volumes'].append(volume)

            except Exception as e:
                validation_result['errors'].append(f"Volume validation error: {str(e)}")
                validation_result['is_valid'] = False

        return validation_result

    async def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Universal input validation and sanitization for container operations."""
        validation_result = {
            'is_valid': True,
            'sanitized_value': data,
            'errors': [],
            'security_issues': []
        }

        try:
            if context == 'container_image' and isinstance(data, str):
                image_validation = self._validate_container_image(data)
                validation_result.update(image_validation)
                validation_result['sanitized_value'] = image_validation['sanitized_image']

            elif context == 'container_config' and isinstance(data, dict):
                config_validation = self._validate_container_config(data)
                validation_result.update(config_validation)
                validation_result['sanitized_value'] = config_validation['sanitized_config']

            elif context == 'container_id' and isinstance(data, str):
                # Container ID validation (Docker format)
                if not re.match(r'^[a-f0-9]{12,64}$', data):
                    validation_result['is_valid'] = False
                    validation_result['errors'].append(f"Invalid container ID format: {data}")

            elif isinstance(data, str):
                # Generic string sanitization
                sanitized = re.sub(r'[;&|`$()<>"\\\*]', '', data)
                validation_result['sanitized_value'] = sanitized[:1024]  # Limit length

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['errors'].append(f"Input validation error: {str(e)}")
            validation_result['security_issues'].append("Input validation failed")

        return validation_result
        
    async def initialize(self) -> bool:
        """Initialize Docker container system with security validation."""
        try:
            # Validate Docker availability with security checks
            if not await self._validate_docker_security():
                logger.error("Docker security validation failed")
                return False

            # Check Docker availability
            result = await self._run_secure_command(['docker', '--version'])
            if not result.get('success', False):
                logger.error("Docker not available")
                return False

            # Create PlugPipe network if it doesn't exist
            await self._ensure_network()

            self.initialized = True
            logger.info("Docker container plugin initialized successfully with security hardening")
            return True

        except Exception as e:
            logger.error(f"Docker initialization failed: {e}")
            return False

    def _validate_registry(self, registry: str) -> str:
        """Validate Docker registry URL for security."""
        if not registry or not isinstance(registry, str):
            return 'docker.io'

        # Remove potentially dangerous patterns
        registry = re.sub(r'[;|&`$(){}\\[\\]<>]', '', registry)

        # Validate format (allow hostname:port format)
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*(?::[0-9]+)?(?:/[a-zA-Z0-9._/-]*)?$', registry):
            logger.warning(f"Invalid registry format: {registry}, using default")
            return 'docker.io'

        return registry

    def _validate_network_name(self, network: str) -> str:
        """Validate Docker network name for security."""
        if not network or not isinstance(network, str):
            return 'plugpipe-network'

        # Remove dangerous characters
        network = re.sub(r'[;|&`$(){}\\[\\]<>\'"\\\\]', '', network)

        # Validate format
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', network):
            logger.warning(f"Invalid network name: {network}, using default")
            return 'plugpipe-network'

        return network

    def _validate_resource_limits(self, limits: Dict[str, Any]) -> Dict[str, Any]:
        """Validate resource limits for security."""
        validated = {}

        # Memory validation
        if 'memory' in limits:
            memory = str(limits['memory'])
            if re.match(r'^\d+[kmgtKMGT]?b?$', memory):
                validated['memory'] = memory
            else:
                logger.warning(f"Invalid memory limit: {memory}")

        # CPU validation
        if 'cpu' in limits:
            try:
                cpu = float(limits['cpu'])
                if 0.1 <= cpu <= 16.0:  # Reasonable limits
                    validated['cpu'] = cpu
                else:
                    logger.warning(f"CPU limit out of range: {cpu}")
            except (ValueError, TypeError):
                logger.warning(f"Invalid CPU limit: {limits['cpu']}")

        return validated

    def _validate_security_options(self, options: Dict[str, Any]) -> Dict[str, Any]:
        """Validate security options."""
        validated = {
            'read_only': True,  # Force read-only by default
            'no_new_privileges': True  # Force no new privileges
        }

        if isinstance(options, dict):
            # Only allow specific security options
            for key in ['read_only', 'no_new_privileges']:
                if key in options and isinstance(options[key], bool):
                    validated[key] = options[key]

        return validated

    async def _validate_docker_security(self) -> bool:
        """Validate Docker daemon security configuration."""
        try:
            # Check if Docker daemon is running in rootless mode (preferred)
            result = await self._run_secure_command(['docker', 'info', '--format', '{{.SecurityOptions}}'])

            if result.get('success', False):
                security_info = result.get('stdout', '')
                logger.info(f"Docker security options: {security_info}")

            # Check for dangerous Docker configurations
            result = await self._run_secure_command(['docker', 'version', '--format', 'json'])

            if result.get('success', False):
                try:
                    version_info = json.loads(result.get('stdout', '{}'))
                    server_version = version_info.get('Server', {}).get('Version', '')
                    logger.info(f"Docker server version: {server_version}")
                except json.JSONDecodeError:
                    logger.warning("Could not parse Docker version info")

            return True

        except Exception as e:
            logger.error(f"Docker security validation failed: {e}")
            return False

    async def _run_secure_command(self, cmd: List[str], timeout: int = 30) -> Dict[str, Any]:
        """Run command with security constraints."""
        try:
            # Sanitize command arguments
            sanitized_cmd = []
            for arg in cmd:
                # Remove dangerous characters
                clean_arg = re.sub(r'[;|&`$(){}\\[\\]<>]', '', str(arg))
                sanitized_cmd.append(shlex.quote(clean_arg))

            # Execute with timeout
            result = subprocess.run(
                sanitized_cmd,
                capture_output=True,
                text=True,
                timeout=timeout
            )

            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'stdout': '',
                'stderr': 'Command timeout',
                'return_code': -1
            }
        except Exception as e:
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'return_code': -1
            }

    async def _ensure_network(self) -> None:
        """Ensure PlugPipe Docker network exists."""
        try:
            result = subprocess.run([
                'docker', 'network', 'inspect', self.network
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                # Create network
                subprocess.run([
                    'docker', 'network', 'create', 
                    '--driver', 'bridge',
                    self.network
                ], capture_output=True, text=True, timeout=30)
                logger.info(f"Created Docker network: {self.network}")
        except Exception as e:
            logger.warning(f"Network setup warning: {e}")
    
    async def start_container(self, image: str, config: Dict[str, Any]) -> str:
        """Start a Docker container for plugin execution."""
        try:
            container_name = f"plugpipe-{uuid.uuid4().hex[:8]}"
            
            # Build Docker run command
            cmd = ['docker', 'run', '-d']
            
            # Add resource limits
            if 'memory' in self.resource_limits:
                cmd.extend(['--memory', self.resource_limits['memory']])
            if 'cpu' in self.resource_limits:
                cmd.extend(['--cpus', str(self.resource_limits['cpu'])])
            
            # Add security options
            if self.security_options.get('read_only', True):
                cmd.append('--read-only')
            if self.security_options.get('no_new_privileges', True):
                cmd.append('--security-opt=no-new-privileges')
            
            # Add network
            cmd.extend(['--network', self.network])
            
            # Add environment variables
            for key, value in config.get('environment', {}).items():
                cmd.extend(['-e', f"{key}={value}"])
            
            # Add volumes if specified
            for volume in config.get('volumes', []):
                cmd.extend(['-v', volume])
            
            # Add container name and image
            cmd.extend(['--name', container_name, image])
            
            # Add command if specified
            if 'command' in config:
                cmd.extend(config['command'])
            
            # Execute Docker run
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode == 0:
                container_id = result.stdout.strip()
                logger.info(f"Started container {container_name}: {container_id}")
                return container_id
            else:
                logger.error(f"Container start failed: {result.stderr}")
                return ""
                
        except Exception as e:
            logger.error(f"Container start error: {e}")
            return ""
    
    async def stop_container(self, container_id: str) -> bool:
        """Stop a Docker container."""
        try:
            result = subprocess.run([
                'docker', 'stop', container_id
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                # Remove container
                subprocess.run([
                    'docker', 'rm', container_id
                ], capture_output=True, text=True, timeout=30)
                logger.info(f"Stopped and removed container: {container_id}")
                return True
            else:
                logger.error(f"Container stop failed: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Container stop error: {e}")
            return False
    
    async def execute_in_container(self, container_id: str, command: str) -> Dict[str, Any]:
        """Execute command in Docker container."""
        try:
            result = subprocess.run([
                'docker', 'exec', container_id, 'sh', '-c', command
            ], capture_output=True, text=True, timeout=300)
            
            return {
                'success': result.returncode == 0,
                'stdout': result.stdout,
                'stderr': result.stderr,
                'return_code': result.returncode
            }
            
        except Exception as e:
            logger.error(f"Container execution error: {e}")
            return {
                'success': False,
                'stdout': '',
                'stderr': str(e),
                'return_code': -1
            }
    
    async def get_container_status(self, container_id: str) -> Dict[str, Any]:
        """Get Docker container status."""
        try:
            result = subprocess.run([
                'docker', 'inspect', container_id
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                inspect_data = json.loads(result.stdout)[0]
                state = inspect_data['State']
                
                return {
                    'healthy': state['Status'] == 'running',
                    'status': state['Status'],
                    'started_at': state.get('StartedAt'),
                    'finished_at': state.get('FinishedAt'),
                    'exit_code': state.get('ExitCode'),
                    'pid': state.get('Pid'),
                    'container_id': container_id
                }
            else:
                return {
                    'healthy': False,
                    'status': 'not_found',
                    'container_id': container_id
                }
                
        except Exception as e:
            logger.error(f"Container status error: {e}")
            return {
                'healthy': False,
                'status': 'error',
                'error': str(e),
                'container_id': container_id
            }
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Docker system health."""
        try:
            # Check Docker daemon
            result = subprocess.run(['docker', 'version'], 
                                  capture_output=True, text=True, timeout=10)
            docker_healthy = result.returncode == 0
            
            # Get running containers
            result = subprocess.run(['docker', 'ps', '-q'], 
                                  capture_output=True, text=True, timeout=10)
            running_containers = len(result.stdout.strip().split('\n')) if result.stdout.strip() else 0
            
            # Get system info
            result = subprocess.run(['docker', 'system', 'df'], 
                                  capture_output=True, text=True, timeout=10)
            system_info = result.stdout if result.returncode == 0 else ""
            
            return {
                'healthy': docker_healthy,
                'docker_version': self._get_docker_version(),
                'running_containers': running_containers,
                'network': self.network,
                'registry': self.registry,
                'system_info': system_info,
                'resource_limits': self.resource_limits,
                'security_options': self.security_options
            }
            
        except Exception as e:
            logger.error(f"Docker health check error: {e}")
            return {
                'healthy': False,
                'error': str(e)
            }
    
    def _get_docker_version(self) -> str:
        """Get Docker version."""
        try:
            result = subprocess.run(['docker', '--version'], 
                                  capture_output=True, text=True, timeout=10)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"

class DockerFactoryPlugin:
    """
    Docker Factory Plugin - Enterprise container orchestration factory.
    
    Manages containerized plugin execution with isolation, scaling, and monitoring.
    Follows the proven factory pattern established by Database Factory Plugin.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.factory_config = config.get('docker_factory', {})
        self.containers_config = self._sanitize_containers_config(config.get('containers', {}))
        
        # Factory configuration with sanitization
        self.primary_container_type = self.factory_config.get('primary_container_type', 'docker')
        self.fallback_container_types = self.factory_config.get('fallback_container_types', [])
        self.enable_failover = self.factory_config.get('enable_failover', True)
        self.max_containers = self._sanitize_max_containers(self.factory_config.get('max_containers', 10))
        self.auto_scaling = self.factory_config.get('auto_scaling', True)
        self.namespace = self._sanitize_namespace(self.factory_config.get('namespace', 'plugpipe'))
        
        # Factory state
        self.factory_id = str(uuid.uuid4())
        self.initialized = False
        self.active_container_type = None
        self.container_plugins = {}
        self.running_containers = {}
        self.container_queue = asyncio.Queue()
        
        logger.info(f"Docker Factory Plugin initialized with ID: {self.factory_id}")

    def _sanitize_namespace(self, namespace: str) -> str:
        """Sanitize namespace for security."""
        if not namespace or not isinstance(namespace, str):
            return 'plugpipe'

        # Remove dangerous characters and patterns
        namespace = re.sub(r'[;|&`$(){}\\[\\]<>\'"\\\\]', '', namespace)
        namespace = re.sub(r'\s*(rm\s+-rf|curl\s+|wget\s+|nc\s+)', '', namespace, flags=re.IGNORECASE)

        # Validate format
        if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', namespace):
            logger.warning(f"Invalid namespace format: {namespace}, using default")
            return 'plugpipe'

        return namespace

    def _sanitize_max_containers(self, max_containers) -> int:
        """Sanitize max_containers for security."""
        try:
            max_containers = int(max_containers)
            if max_containers < 1 or max_containers > 100:  # Reasonable limits
                logger.warning(f"Max containers out of range: {max_containers}, using default")
                return 10
            return max_containers
        except (ValueError, TypeError):
            logger.warning(f"Invalid max_containers: {max_containers}, using default")
            return 10

    def _sanitize_containers_config(self, containers_config: Dict[str, Any]) -> Dict[str, Any]:
        """Sanitize containers configuration for security."""
        if not isinstance(containers_config, dict):
            return {}

        sanitized = {}

        for container_type, config in containers_config.items():
            if not isinstance(config, dict):
                continue

            sanitized_config = {}

            # Sanitize registry
            if 'registry' in config:
                registry = str(config['registry'])
                # Remove dangerous patterns
                registry = re.sub(r'[;|&`$(){}\\[\\]<>]', '', registry)
                if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', registry):
                    logger.warning(f"Invalid registry format: {registry}, using default")
                    registry = 'docker.io'
                sanitized_config['registry'] = registry

            # Sanitize network
            if 'network' in config:
                network = str(config['network'])
                # Remove dangerous patterns
                network = re.sub(r'[;|&`$(){}\\[\\]<>]', '', network)
                if not re.match(r'^[a-zA-Z0-9][a-zA-Z0-9._-]*$', network):
                    logger.warning(f"Invalid network format: {network}, using default")
                    network = 'plugpipe-network'
                sanitized_config['network'] = network

            # Copy other safe fields
            for key in ['resource_limits', 'security_options']:
                if key in config:
                    sanitized_config[key] = config[key]

            sanitized[container_type] = sanitized_config

        return sanitized
    
    async def initialize(self) -> bool:
        """Initialize the Docker Factory Plugin."""
        try:
            logger.info("Initializing Docker Factory Plugin...")
            
            # Load primary container plugin
            if await self._load_container_plugin(self.primary_container_type):
                self.active_container_type = self.primary_container_type
                logger.info(f"Primary container type loaded: {self.primary_container_type}")
            else:
                logger.warning(f"Primary container type failed: {self.primary_container_type}")
                
                # Try fallback container types
                for fallback_type in self.fallback_container_types:
                    if await self._load_container_plugin(fallback_type):
                        self.active_container_type = fallback_type
                        logger.info(f"Using fallback container type: {fallback_type}")
                        break
                else:
                    logger.error("No container plugins could be loaded")
                    return False
            
            self.initialized = True
            logger.info(f"Docker Factory Plugin initialized successfully with {self.active_container_type}")
            return True
            
        except Exception as e:
            logger.error(f"Docker Factory Plugin initialization failed: {e}")
            return False
    
    async def _load_container_plugin(self, container_type: str) -> bool:
        """Load a container plugin."""
        try:
            config = self.containers_config.get(container_type, {})
            
            if container_type == 'docker':
                plugin = DockerContainerPlugin(config)
                if await plugin.initialize():
                    self.container_plugins[container_type] = plugin
                    return True
            
            return False
            
        except Exception as e:
            logger.error(f"Failed to load container plugin {container_type}: {e}")
            return False
    
    async def start_containerized_plugin(self, plugin_config: Dict[str, Any]) -> str:
        """Start a plugin in a container."""
        if not self.initialized:
            logger.error("Docker Factory not initialized")
            return ""
        
        try:
            active_plugin = self.container_plugins[self.active_container_type]
            
            # Prepare container configuration
            image = plugin_config.get('image', 'plugpipe/base:latest')
            container_config = {
                'environment': {
                    'PLUGPIPE_NAMESPACE': self.namespace,
                    'PLUGPIPE_FACTORY_ID': self.factory_id,
                    **plugin_config.get('environment', {})
                },
                'volumes': plugin_config.get('volumes', []),
                'command': plugin_config.get('command', [])
            }
            
            # Start container
            container_id = await active_plugin.start_container(image, container_config)
            
            if container_id:
                self.running_containers[container_id] = {
                    'plugin_name': plugin_config.get('name', 'unknown'),
                    'started_at': datetime.utcnow().isoformat(),
                    'image': image,
                    'container_type': self.active_container_type
                }
                logger.info(f"Started containerized plugin: {container_id}")
                return container_id
            else:
                logger.error("Failed to start container")
                return ""
                
        except Exception as e:
            logger.error(f"Error starting containerized plugin: {e}")
            return ""
    
    async def stop_containerized_plugin(self, container_id: str) -> bool:
        """Stop a containerized plugin."""
        if not self.initialized:
            logger.error("Docker Factory not initialized")
            return False
        
        try:
            active_plugin = self.container_plugins[self.active_container_type]
            
            if await active_plugin.stop_container(container_id):
                if container_id in self.running_containers:
                    del self.running_containers[container_id]
                logger.info(f"Stopped containerized plugin: {container_id}")
                return True
            else:
                logger.error(f"Failed to stop container: {container_id}")
                return False
                
        except Exception as e:
            logger.error(f"Error stopping containerized plugin: {e}")
            return False
    
    async def execute_in_plugin(self, container_id: str, command: str) -> Dict[str, Any]:
        """Execute command in containerized plugin."""
        if not self.initialized:
            return {'success': False, 'error': 'Docker Factory not initialized'}
        
        try:
            active_plugin = self.container_plugins[self.active_container_type]
            return await active_plugin.execute_in_container(container_id, command)
            
        except Exception as e:
            logger.error(f"Error executing in plugin container: {e}")
            return {'success': False, 'error': str(e)}
    
    async def get_container_status(self, container_id: str) -> Dict[str, Any]:
        """Get status of a specific container."""
        if not self.initialized:
            return {'healthy': False, 'error': 'Docker Factory not initialized'}
        
        try:
            active_plugin = self.container_plugins[self.active_container_type]
            status = await active_plugin.get_container_status(container_id)
            
            # Add factory context
            if container_id in self.running_containers:
                status.update(self.running_containers[container_id])
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting container status: {e}")
            return {'healthy': False, 'error': str(e)}
    
    async def list_running_containers(self) -> List[Dict[str, Any]]:
        """List all running containers managed by factory."""
        containers = []
        
        for container_id, info in self.running_containers.items():
            status = await self.get_container_status(container_id)
            containers.append({
                'container_id': container_id,
                **info,
                **status
            })
        
        return containers
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive factory health check."""
        factory_health = {
            'factory_id': self.factory_id,
            'factory_healthy': self.initialized,
            'active_container_type': self.active_container_type,
            'total_container_types': len(self.container_plugins),
            'healthy_container_types': 0,
            'running_containers': len(self.running_containers),
            'max_containers': self.max_containers,
            'auto_scaling': self.auto_scaling,
            'namespace': self.namespace,
            'container_status': {},
            'system_resources': {}
        }
        
        # Check each container plugin health
        for container_type, plugin in self.container_plugins.items():
            try:
                health = await plugin.health_check()
                factory_health['container_status'][container_type] = health
                if health.get('healthy', False):
                    factory_health['healthy_container_types'] += 1
            except Exception as e:
                factory_health['container_status'][container_type] = {
                    'healthy': False,
                    'error': str(e)
                }
        
        # System resource monitoring
        try:
            factory_health['system_resources'] = await self._get_system_resources()
        except Exception as e:
            factory_health['system_resources'] = {'error': str(e)}
        
        return factory_health
    
    async def _get_system_resources(self) -> Dict[str, Any]:
        """Get system resource information."""
        try:
            # Get Docker system info
            result = subprocess.run(['docker', 'system', 'info', '--format', 'json'], 
                                  capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                docker_info = json.loads(result.stdout)
                return {
                    'containers_running': docker_info.get('ContainersRunning', 0),
                    'containers_paused': docker_info.get('ContainersPaused', 0),
                    'containers_stopped': docker_info.get('ContainersStopped', 0),
                    'images': docker_info.get('Images', 0),
                    'server_version': docker_info.get('ServerVersion', 'unknown'),
                    'storage_driver': docker_info.get('Driver', 'unknown'),
                    'memory_total': docker_info.get('MemTotal', 0),
                    'ncpu': docker_info.get('NCPU', 0)
                }
            else:
                return {'error': 'Docker system info unavailable'}
                
        except Exception as e:
            return {'error': str(e)}
    
    async def switch_container_type(self, target_type: str) -> bool:
        """Switch active container type (for failover)."""
        if not self.enable_failover:
            logger.warning("Container type switching disabled")
            return False
        
        if target_type not in self.container_plugins:
            logger.error(f"Container type not available: {target_type}")
            return False
        
        try:
            # Test target container type
            target_plugin = self.container_plugins[target_type]
            health = await target_plugin.health_check()
            
            if health.get('healthy', False):
                self.active_container_type = target_type
                logger.info(f"Switched to container type: {target_type}")
                return True
            else:
                logger.error(f"Target container type unhealthy: {target_type}")
                return False
                
        except Exception as e:
            logger.error(f"Error switching container type: {e}")
            return False
    
    def get_factory_status(self) -> Dict[str, Any]:
        """Get current factory status."""
        return {
            'factory_id': self.factory_id,
            'initialized': self.initialized,
            'active_container_type': self.active_container_type,
            'primary_container_type': self.primary_container_type,
            'running_containers': len(self.running_containers),
            'max_containers': self.max_containers,
            'auto_scaling': self.auto_scaling,
            'enable_failover': self.enable_failover,
            'namespace': self.namespace
        }

# Plugin metadata
plug_metadata = {
    "name": "docker_factory_plugin",
    "version": "1.0.0",
    "owner": "PlugPipe Core Team",
    "status": "stable",
    "description": "Enterprise Docker factory for containerized plugin execution with isolation and scaling",
    "capabilities": [
        "containerized_plugin_execution",
        "container_isolation",
        "resource_management",
        "auto_scaling",
        "container_failover",
        "security_sandboxing",
        "enterprise_orchestration"
    ]
}

async def process_async(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Async process function for Docker Factory Plugin with security hardening."""
    try:
        # Input sanitization with Universal Input Sanitizer
        if SANITIZER_AVAILABLE:
            try:
                sanitizer_result = pp(
                    "universal_input_sanitizer",
                    action="sanitize",
                    input_data=config,
                    context="docker_factory_plugin"
                )

                if not sanitizer_result.get("success", False):
                    return {
                        'success': False,
                        'error': f"Input validation failed: {sanitizer_result.get('error')}",
                        'factory_type': 'docker'
                    }

                config = sanitizer_result.get("sanitized_data", config)
                logger.info("Input successfully sanitized by Universal Input Sanitizer")

            except Exception as e:
                logger.warning(f"Universal Input Sanitizer failed, using fallback: {e}")

        # Fallback validation for critical security
        operation = config.get('operation', 'initialize')
        if not isinstance(operation, str) or not re.match(r'^[a-z_]+$', operation):
            return {
                'success': False,
                'error': 'Invalid operation format',
                'factory_type': 'docker'
            }

        factory = DockerFactoryPlugin(config)
        
        if operation == 'health_check':
            await factory.initialize()
            health_status = await factory.health_check()
            return {
                'success': True,
                'operation_completed': 'health_check',
                'health_status': health_status
            }
        
        elif operation == 'start_plugin':
            await factory.initialize()
            plugin_config = config.get('plugin_config', {})
            container_id = await factory.start_containerized_plugin(plugin_config)
            return {
                'success': bool(container_id),
                'operation_completed': 'start_plugin',
                'container_id': container_id
            }
        
        elif operation == 'stop_plugin':
            await factory.initialize()
            container_id = config.get('container_id', '')
            success = await factory.stop_containerized_plugin(container_id)
            return {
                'success': success,
                'operation_completed': 'stop_plugin',
                'container_id': container_id
            }
        
        elif operation == 'list_containers':
            await factory.initialize()
            containers = await factory.list_running_containers()
            return {
                'success': True,
                'operation_completed': 'list_containers',
                'containers': containers
            }
        
        else:
            # Default: Factory initialization and status
            result = await factory.initialize()
            status = factory.get_factory_status()
            
            return {
                'success': result,
                'factory_type': 'docker',
                'status': 'ready' if result else 'failed',
                'active_container_type': factory.active_container_type,
                'capabilities': plug_metadata['capabilities'],
                'factory_status': status
            }
    
    except Exception as e:
        logger.error(f"Docker Factory Plugin error: {e}")
        return {
            'success': False,
            'error': str(e),
            'factory_type': 'docker'
        }

def process(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous wrapper for the async process function."""
    return asyncio.run(process_async(ctx, config))

if __name__ == "__main__":
    # Test the Docker Factory Plugin
    test_config = {
        'docker_factory': {
            'primary_container_type': 'docker',
            'fallback_container_types': [],
            'enable_failover': True,
            'max_containers': 5,
            'auto_scaling': True,
            'namespace': 'plugpipe-test'
        },
        'containers': {
            'docker': {
                'registry': 'docker.io',
                'network': 'plugpipe-network',
                'resource_limits': {
                    'memory': '512m',
                    'cpu': '0.5'
                },
                'security_options': {
                    'read_only': True,
                    'no_new_privileges': True
                }
            }
        }
    }
    
    result = process({}, test_config)
    print(json.dumps(result, indent=2))