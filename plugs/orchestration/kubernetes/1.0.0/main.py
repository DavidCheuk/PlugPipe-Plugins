#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Kubernetes Plugin for PlugPipe

Enterprise-grade Kubernetes orchestration plugin that provides service discovery,
auto-scaling, load balancing, and comprehensive plugin lifecycle management
in Kubernetes environments.

Key Features:
- Service discovery and registration for plugins
- Horizontal Pod Autoscaling (HPA) for plugin instances
- Load balancing across plugin replicas
- Health monitoring with auto-restart capabilities
- ConfigMaps and Secrets management for plugin configuration
- Network policies and resource quotas enforcement
- Enterprise Kubernetes-native plugin orchestration
"""

import asyncio
import json
import logging
import os
import time
import uuid
import yaml
import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Dict, List, Any, Optional, Union
import subprocess
import tempfile
import base64
from pathlib import Path

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class KubernetesInterface(ABC):
    """Interface for Kubernetes orchestration plugins."""
    
    @abstractmethod
    async def create_deployment(self, name: str, config: Dict[str, Any]) -> bool:
        """Create a Kubernetes deployment."""
        pass
    
    @abstractmethod
    async def create_service(self, name: str, config: Dict[str, Any]) -> bool:
        """Create a Kubernetes service."""
        pass
    
    @abstractmethod
    async def create_configmap(self, name: str, data: Dict[str, str]) -> bool:
        """Create a ConfigMap."""
        pass
    
    @abstractmethod
    async def create_secret(self, name: str, data: Dict[str, str]) -> bool:
        """Create a Secret."""
        pass
    
    @abstractmethod
    async def scale_deployment(self, name: str, replicas: int) -> bool:
        """Scale a deployment."""
        pass
    
    @abstractmethod
    async def get_service_status(self, name: str) -> Dict[str, Any]:
        """Get service status and endpoints."""
        pass
    
    @abstractmethod
    async def health_check(self) -> Dict[str, Any]:
        """Check Kubernetes cluster health."""
        pass

class KubernetesOrchestrator(KubernetesInterface):
    """Kubernetes-based orchestration plugin."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('kubernetes', {})
        self.namespace = self._validate_namespace(self.config.get('namespace', 'plugpipe-system'))
        self.image_registry = self._validate_registry(self.config.get('image_registry', 'plugpipe'))
        self.resource_defaults = self.config.get('resource_defaults', {})
        self.security_context = self._validate_security_context(self.config.get('security_context', {}))
        self.network_policies = self.config.get('network_policies', {})
        self.monitoring = self.config.get('monitoring', {})
        self.initialized = False

        # Security hardening defaults
        self._setup_security_defaults()

    def _validate_namespace(self, namespace: str) -> str:
        """Validate and sanitize Kubernetes namespace name."""
        # Kubernetes namespace name validation
        if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', namespace):
            logger.warning(f"Invalid namespace '{namespace}', using default 'plugpipe-system'")
            return 'plugpipe-system'

        # Prevent system namespace usage
        system_namespaces = {'kube-system', 'kube-public', 'kube-node-lease', 'default'}
        if namespace in system_namespaces:
            logger.warning(f"Cannot use system namespace '{namespace}', using 'plugpipe-system'")
            return 'plugpipe-system'

        return namespace

    def _validate_registry(self, registry: str) -> str:
        """Validate and sanitize container registry name."""
        # Basic registry validation
        if not re.match(r'^[a-z0-9]([a-z0-9.-]*[a-z0-9])?(/[a-z0-9._-]+)*$', registry):
            logger.warning(f"Invalid registry '{registry}', using default 'plugpipe'")
            return 'plugpipe'
        return registry

    def _validate_security_context(self, security_context: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and harden security context."""
        hardened_context = {
            'runAsNonRoot': True,
            'runAsUser': 1000,
            'runAsGroup': 1000,
            'fsGroup': 1000,
            'allowPrivilegeEscalation': False,
            'readOnlyRootFilesystem': True,
            'capabilities': {
                'drop': ['ALL']
            }
        }

        # Merge user config with hardened defaults (hardened takes precedence for security)
        result = {**security_context, **hardened_context}

        # Prevent dangerous privilege escalation
        if result.get('runAsUser') == 0:
            logger.warning("Cannot run as root user, forcing runAsUser: 1000")
            result['runAsUser'] = 1000

        return result

    def _setup_security_defaults(self):
        """Setup security hardening defaults."""
        # Resource limits for security
        if not self.resource_defaults:
            self.resource_defaults = {
                'requests': {
                    'memory': '64Mi',
                    'cpu': '50m'
                },
                'limits': {
                    'memory': '512Mi',
                    'cpu': '500m'
                }
            }

        # Network policies for security
        if not self.network_policies:
            self.network_policies = {
                'enabled': True,
                'defaultDeny': True,
                'allowedIngress': [],
                'allowedEgress': []
            }

    def _validate_image_name(self, image: str) -> str:
        """Validate and sanitize container image name."""
        # Container image validation - registry/namespace/name:tag format
        if not re.match(r'^[a-z0-9.-]+(/[a-z0-9._-]+)*:[a-zA-Z0-9._-]+$', image):
            logger.error(f"Invalid container image format: {image}")
            return f"{self.image_registry}/default:latest"

        # Whitelist trusted registries
        trusted_registries = {
            'plugpipe', 'docker.io', 'gcr.io', 'k8s.gcr.io',
            'registry.k8s.io', 'quay.io'
        }

        registry = image.split('/')[0]
        if registry not in trusted_registries:
            logger.warning(f"Untrusted registry '{registry}', using default")
            return f"{self.image_registry}/default:latest"

        return image

    def _validate_k8s_resource_name(self, name: str) -> str:
        """Validate Kubernetes resource name format."""
        # Kubernetes resource name validation (RFC 1123)
        if not re.match(r'^[a-z0-9]([-a-z0-9]*[a-z0-9])?$', name) or len(name) > 63:
            logger.error(f"Invalid Kubernetes resource name: {name}")
            return f"plugin-{uuid.uuid4().hex[:8]}"

        # Prevent reserved names
        reserved_names = {
            'kubernetes', 'kube-system', 'default', 'kube-public',
            'system', 'admin', 'root', 'api'
        }
        if name in reserved_names:
            logger.warning(f"Reserved resource name '{name}', using generated name")
            return f"plugin-{uuid.uuid4().hex[:8]}"

        return name

    def _validate_k8s_labels(self, labels: Dict[str, str]) -> Dict[str, str]:
        """Validate and sanitize Kubernetes labels."""
        validated_labels = {}

        for key, value in labels.items():
            # Validate label key (kubernetes.io format or custom)
            if not re.match(r'^([a-z0-9.-]+/)?[a-z0-9]([-._a-z0-9]*[a-z0-9])?$', key):
                logger.warning(f"Invalid label key '{key}', skipping")
                continue

            # Validate label value
            if not re.match(r'^[a-z0-9A-Z]([-._a-z0-9A-Z]*[a-z0-9A-Z])?$', value) or len(value) > 63:
                logger.warning(f"Invalid label value '{value}' for key '{key}', skipping")
                continue

            validated_labels[key] = value

        return validated_labels

    def _validate_environment_variables(self, env_vars: Dict[str, str]) -> Dict[str, str]:
        """Validate and sanitize environment variables."""
        validated_env = {}

        # Blocked environment variables (security sensitive)
        blocked_env_vars = {
            'KUBERNETES_SERVICE_HOST', 'KUBERNETES_SERVICE_PORT',
            'KUBECONFIG', 'HOME', 'PATH', 'USER', 'PWD'
        }

        for key, value in env_vars.items():
            # Environment variable name validation
            if not re.match(r'^[A-Z][A-Z0-9_]*$', key):
                logger.warning(f"Invalid environment variable name '{key}', skipping")
                continue

            # Block sensitive variables
            if key in blocked_env_vars:
                logger.warning(f"Blocked environment variable '{key}', skipping")
                continue

            # Sanitize value (remove potentially dangerous characters)
            sanitized_value = re.sub(r'[^\w\s./-]', '', str(value))
            validated_env[key] = sanitized_value

        return validated_env

    def _validate_ports(self, ports: List[int]) -> List[int]:
        """Validate port numbers for security."""
        validated_ports = []

        # Blocked port ranges
        blocked_ranges = [
            (1, 1023),      # System/privileged ports
            (6443, 6443),   # Kubernetes API server
            (10250, 10255), # Kubelet ports
            (30000, 32767)  # NodePort range (should be explicit)
        ]

        for port in ports:
            if not isinstance(port, int) or port <= 0 or port > 65535:
                logger.warning(f"Invalid port number: {port}, skipping")
                continue

            # Check against blocked ranges
            blocked = False
            for start, end in blocked_ranges:
                if start <= port <= end:
                    logger.warning(f"Blocked port {port} (range {start}-{end}), skipping")
                    blocked = True
                    break

            if not blocked:
                validated_ports.append(port)

        # Default port if none valid
        if not validated_ports:
            validated_ports = [8080]

        return validated_ports

    def _validate_resource_limits(self, resources: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and enforce resource limits."""
        # Maximum allowed resource limits (security constraints)
        max_limits = {
            'memory': '2Gi',
            'cpu': '2',
            'ephemeral-storage': '10Gi'
        }

        # Minimum required requests
        min_requests = {
            'memory': '32Mi',
            'cpu': '10m'
        }

        validated_resources = {
            'requests': {},
            'limits': {}
        }

        # Validate requests
        requests = resources.get('requests', {})
        for resource, value in requests.items():
            if resource in min_requests:
                # Parse and validate resource values
                if self._parse_resource_value(value) >= self._parse_resource_value(min_requests[resource]):
                    validated_resources['requests'][resource] = value
                else:
                    logger.warning(f"Resource request {resource}={value} below minimum, using {min_requests[resource]}")
                    validated_resources['requests'][resource] = min_requests[resource]

        # Ensure minimum requests
        for resource, min_value in min_requests.items():
            if resource not in validated_resources['requests']:
                validated_resources['requests'][resource] = min_value

        # Validate limits
        limits = resources.get('limits', {})
        for resource, value in limits.items():
            if resource in max_limits:
                if self._parse_resource_value(value) <= self._parse_resource_value(max_limits[resource]):
                    validated_resources['limits'][resource] = value
                else:
                    logger.warning(f"Resource limit {resource}={value} exceeds maximum, using {max_limits[resource]}")
                    validated_resources['limits'][resource] = max_limits[resource]

        # Ensure limits are set
        for resource, max_value in max_limits.items():
            if resource not in validated_resources['limits']:
                validated_resources['limits'][resource] = max_value

        return validated_resources

    def _parse_resource_value(self, value: str) -> float:
        """Parse Kubernetes resource value to comparable number."""
        try:
            # Simple parsing for common units
            if value.endswith('Gi'):
                return float(value[:-2]) * 1024 * 1024 * 1024
            elif value.endswith('Mi'):
                return float(value[:-2]) * 1024 * 1024
            elif value.endswith('Ki'):
                return float(value[:-2]) * 1024
            elif value.endswith('m'):
                return float(value[:-1]) / 1000
            else:
                return float(value)
        except (ValueError, IndexError):
            return 0.0

    async def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Validate and sanitize input using Kubernetes-specific validation."""
        validation_result = {
            'is_valid': True,
            'sanitized_value': data,
            'errors': [],
            'security_issues': []
        }

        try:
            if isinstance(data, dict):
                sanitized_data = {}

                for key, value in data.items():
                    # Validate based on context
                    if context == 'deployment' and key == 'image':
                        sanitized_data[key] = self._validate_image_name(value)
                    elif context == 'deployment' and key == 'name':
                        sanitized_data[key] = self._validate_k8s_resource_name(value)
                    elif key == 'labels':
                        sanitized_data[key] = self._validate_k8s_labels(value)
                    elif key == 'environment':
                        sanitized_data[key] = self._validate_environment_variables(value)
                    elif key == 'ports':
                        sanitized_data[key] = self._validate_ports(value if isinstance(value, list) else [value])
                    elif key == 'resources':
                        sanitized_data[key] = self._validate_resource_limits(value)
                    else:
                        # Generic validation
                        if isinstance(value, str):
                            # Remove potentially dangerous characters
                            sanitized_value = re.sub(r'[<>"\';\\]', '', value)
                            sanitized_data[key] = sanitized_value
                        else:
                            sanitized_data[key] = value

                validation_result['sanitized_value'] = sanitized_data

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['errors'].append(f"Validation error: {str(e)}")
            validation_result['security_issues'].append("Input validation failed")

        return validation_result
        
    async def initialize(self) -> bool:
        """Initialize Kubernetes orchestrator."""
        try:
            # Check kubectl availability
            result = subprocess.run(['kubectl', 'version', '--client'], 
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                logger.error("kubectl not available")
                return False
            
            # Check cluster connectivity
            result = subprocess.run(['kubectl', 'cluster-info'], 
                                  capture_output=True, text=True, timeout=15)
            if result.returncode != 0:
                logger.error("Kubernetes cluster not accessible")
                return False
            
            # Ensure namespace exists
            await self._ensure_namespace()
            
            # Setup RBAC if needed
            await self._setup_rbac()
            
            self.initialized = True
            logger.info("Kubernetes orchestrator initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Kubernetes initialization failed: {e}")
            return False
    
    async def _ensure_namespace(self) -> None:
        """Ensure PlugPipe namespace exists."""
        try:
            result = subprocess.run([
                'kubectl', 'get', 'namespace', self.namespace
            ], capture_output=True, text=True, timeout=10)
            
            if result.returncode != 0:
                # Create namespace
                namespace_yaml = f"""
apiVersion: v1
kind: Namespace
metadata:
  name: {self.namespace}
  labels:
    name: {self.namespace}
    app.kubernetes.io/name: plugpipe
    app.kubernetes.io/component: orchestration
"""
                await self._apply_yaml(namespace_yaml)
                logger.info(f"Created Kubernetes namespace: {self.namespace}")
        except Exception as e:
            logger.warning(f"Namespace setup warning: {e}")
    
    async def _setup_rbac(self) -> None:
        """Setup RBAC for PlugPipe operations."""
        try:
            rbac_yaml = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: plugpipe-orchestrator
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["autoscaling"]
  resources: ["horizontalpodautoscalers"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: ["networking.k8s.io"]
  resources: ["networkpolicies"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: plugpipe-orchestrator
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: plugpipe-orchestrator
subjects:
- kind: ServiceAccount
  name: plugpipe-orchestrator
  namespace: {self.namespace}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: plugpipe-orchestrator
  namespace: {self.namespace}
"""
            await self._apply_yaml(rbac_yaml)
            logger.info("RBAC setup completed")
        except Exception as e:
            logger.warning(f"RBAC setup warning: {e}")
    
    async def _apply_yaml(self, yaml_content: str) -> bool:
        """Apply YAML configuration to Kubernetes."""
        try:
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                f.write(yaml_content)
                f.flush()
                
                result = subprocess.run([
                    'kubectl', 'apply', '-f', f.name
                ], capture_output=True, text=True, timeout=30)
                
                os.unlink(f.name)
                return result.returncode == 0
        except Exception as e:
            logger.error(f"YAML apply error: {e}")
            return False
    
    async def create_deployment(self, name: str, config: Dict[str, Any]) -> bool:
        """Create a Kubernetes deployment for plugin."""
        try:
            # Validate input configuration
            validation_result = await self._validate_and_sanitize_input(config, "deployment")
            if not validation_result['is_valid']:
                logger.error(f"Invalid deployment config: {validation_result['errors']}")
                return False

            validated_config = validation_result['sanitized_value']

            # Use validated values
            image = self._validate_image_name(validated_config.get('image', f"{self.image_registry}/{name}:latest"))
            replicas = max(1, min(validated_config.get('replicas', 1), 10))  # Limit replicas 1-10
            port = validated_config.get('port', 8080)

            # Validate port
            valid_ports = self._validate_ports([port])
            port = valid_ports[0] if valid_ports else 8080

            # Validate and merge resource configuration
            resources = self._validate_resource_limits({**self.resource_defaults, **validated_config.get('resources', {})})
            
            # Environment variables (validated)
            validated_env = self._validate_environment_variables(validated_config.get('environment', {}))
            env_vars = []
            for key, value in validated_env.items():
                env_vars.append(f"        - name: {key}\n          value: \"{value}\"")
            env_section = "\n".join(env_vars) if env_vars else ""
            
            # Resource limits and requests
            resource_section = ""
            if resources:
                resource_section = f"""
        resources:
          requests:
            memory: "{resources.get('requests', {}).get('memory', '128Mi')}"
            cpu: "{resources.get('requests', {}).get('cpu', '100m')}"
          limits:
            memory: "{resources.get('limits', {}).get('memory', '512Mi')}"
            cpu: "{resources.get('limits', {}).get('cpu', '500m')}"
"""
            
            # Validate resource name and generate labels
            validated_name = self._validate_k8s_resource_name(name)
            labels = self._validate_k8s_labels({
                'app': validated_name,
                'app.kubernetes.io/name': validated_name,
                'app.kubernetes.io/component': 'plugin',
                'app.kubernetes.io/part-of': 'plugpipe',
                'plugpipe.security/validated': 'true'
            })

            # Format labels for YAML
            label_lines = []
            for key, value in labels.items():
                label_lines.append(f"    {key}: {value}")
            labels_section = "\n".join(label_lines)

            deployment_yaml = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: {validated_name}
  namespace: {self.namespace}
  labels:
{labels_section}
spec:
  replicas: {replicas}
  selector:
    matchLabels:
      app: {validated_name}
  template:
    metadata:
      labels:
{labels_section}
    spec:
      serviceAccountName: plugpipe-orchestrator
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        fsGroup: 2000
      containers:
      - name: {validated_name}
        image: {image}
        ports:
        - containerPort: {port}
          name: http
        env:
        - name: PLUGPIPE_NAMESPACE
          value: "{self.namespace}"
        - name: PLUGPIPE_PLUGIN_NAME
          value: "{name}"
{env_section}
{resource_section}
        livenessProbe:
          httpGet:
            path: /health
            port: {port}
          initialDelaySeconds: 30
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /ready
            port: {port}
          initialDelaySeconds: 5
          periodSeconds: 5
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
"""
            
            return await self._apply_yaml(deployment_yaml)
            
        except Exception as e:
            logger.error(f"Error creating deployment {name}: {e}")
            return False
    
    async def create_service(self, name: str, config: Dict[str, Any]) -> bool:
        """Create a Kubernetes service for plugin."""
        try:
            # Validate input
            validation_result = await self._validate_and_sanitize_input(config, "service")
            if not validation_result['is_valid']:
                logger.error(f"Invalid service config: {validation_result['errors']}")
                return False

            validated_config = validation_result['sanitized_value']
            validated_name = self._validate_k8s_resource_name(name)

            # Validate port
            port = validated_config.get('port', 8080)
            valid_ports = self._validate_ports([port])
            port = valid_ports[0] if valid_ports else 8080

            # Validate service type
            service_type = validated_config.get('type', 'ClusterIP')
            allowed_service_types = {'ClusterIP', 'NodePort', 'LoadBalancer'}
            if service_type not in allowed_service_types:
                logger.warning(f"Invalid service type '{service_type}', using ClusterIP")
                service_type = 'ClusterIP'

            # Generate validated labels
            labels = self._validate_k8s_labels({
                'app': validated_name,
                'app.kubernetes.io/name': validated_name,
                'app.kubernetes.io/component': 'plugin',
                'app.kubernetes.io/part-of': 'plugpipe',
                'plugpipe.security/validated': 'true'
            })

            # Format labels for YAML
            label_lines = []
            for key, value in labels.items():
                label_lines.append(f"    {key}: {value}")
            labels_section = "\n".join(label_lines)

            service_yaml = f"""
apiVersion: v1
kind: Service
metadata:
  name: {validated_name}
  namespace: {self.namespace}
  labels:
{labels_section}
spec:
  type: {service_type}
  ports:
  - port: {port}
    targetPort: http
    protocol: TCP
    name: http
  selector:
    app: {validated_name}
"""
            
            return await self._apply_yaml(service_yaml)
            
        except Exception as e:
            logger.error(f"Error creating service {name}: {e}")
            return False
    
    async def create_configmap(self, name: str, data: Dict[str, str]) -> bool:
        """Create a ConfigMap for plugin configuration."""
        try:
            data_section = []
            for key, value in data.items():
                # Properly escape and format the value
                escaped_value = value.replace('\n', '\\n').replace('"', '\\"')
                data_section.append(f'  {key}: "{escaped_value}"')
            
            configmap_yaml = f"""
apiVersion: v1
kind: ConfigMap
metadata:
  name: {name}
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/name: {name}
    app.kubernetes.io/component: config
    app.kubernetes.io/part-of: plugpipe
data:
{chr(10).join(data_section)}
"""
            
            return await self._apply_yaml(configmap_yaml)
            
        except Exception as e:
            logger.error(f"Error creating ConfigMap {name}: {e}")
            return False
    
    async def create_secret(self, name: str, data: Dict[str, str]) -> bool:
        """Create a Secret for sensitive plugin data."""
        try:
            data_section = []
            for key, value in data.items():
                # Base64 encode the value
                encoded_value = base64.b64encode(value.encode()).decode()
                data_section.append(f'  {key}: {encoded_value}')
            
            secret_yaml = f"""
apiVersion: v1
kind: Secret
metadata:
  name: {name}
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/name: {name}
    app.kubernetes.io/component: secret
    app.kubernetes.io/part-of: plugpipe
type: Opaque
data:
{chr(10).join(data_section)}
"""
            
            return await self._apply_yaml(secret_yaml)
            
        except Exception as e:
            logger.error(f"Error creating Secret {name}: {e}")
            return False
    
    async def scale_deployment(self, name: str, replicas: int) -> bool:
        """Scale a deployment to specified number of replicas."""
        try:
            result = subprocess.run([
                'kubectl', 'scale', 'deployment', name, 
                f'--replicas={replicas}', '-n', self.namespace
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                logger.info(f"Scaled deployment {name} to {replicas} replicas")
                return True
            else:
                logger.error(f"Failed to scale deployment {name}: {result.stderr}")
                return False
                
        except Exception as e:
            logger.error(f"Error scaling deployment {name}: {e}")
            return False
    
    async def create_hpa(self, name: str, config: Dict[str, Any]) -> bool:
        """Create Horizontal Pod Autoscaler for plugin."""
        try:
            min_replicas = config.get('min_replicas', 1)
            max_replicas = config.get('max_replicas', 10)
            target_cpu = config.get('target_cpu_percent', 70)
            
            hpa_yaml = f"""
apiVersion: autoscaling/v2
kind: HorizontalPodAutoscaler
metadata:
  name: {name}
  namespace: {self.namespace}
  labels:
    app.kubernetes.io/name: {name}
    app.kubernetes.io/component: autoscaler
    app.kubernetes.io/part-of: plugpipe
spec:
  scaleTargetRef:
    apiVersion: apps/v1
    kind: Deployment
    name: {name}
  minReplicas: {min_replicas}
  maxReplicas: {max_replicas}
  metrics:
  - type: Resource
    resource:
      name: cpu
      target:
        type: Utilization
        averageUtilization: {target_cpu}
  - type: Resource
    resource:
      name: memory
      target:
        type: Utilization
        averageUtilization: 80
"""
            
            return await self._apply_yaml(hpa_yaml)
            
        except Exception as e:
            logger.error(f"Error creating HPA {name}: {e}")
            return False
    
    async def get_service_status(self, name: str) -> Dict[str, Any]:
        """Get service status and endpoints."""
        try:
            # Get service info
            result = subprocess.run([
                'kubectl', 'get', 'service', name, '-n', self.namespace, 
                '-o', 'json'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                service_data = json.loads(result.stdout)
                
                # Get endpoint info
                endpoints_result = subprocess.run([
                    'kubectl', 'get', 'endpoints', name, '-n', self.namespace, 
                    '-o', 'json'
                ], capture_output=True, text=True, timeout=30)
                
                endpoints_data = {}
                if endpoints_result.returncode == 0:
                    endpoints_data = json.loads(endpoints_result.stdout)
                
                return {
                    'healthy': True,
                    'service': service_data,
                    'endpoints': endpoints_data,
                    'cluster_ip': service_data.get('spec', {}).get('clusterIP'),
                    'ports': service_data.get('spec', {}).get('ports', []),
                    'namespace': self.namespace
                }
            else:
                return {
                    'healthy': False,
                    'error': 'Service not found',
                    'namespace': self.namespace
                }
                
        except Exception as e:
            logger.error(f"Error getting service status {name}: {e}")
            return {
                'healthy': False,
                'error': str(e),
                'namespace': self.namespace
            }
    
    async def get_deployment_status(self, name: str) -> Dict[str, Any]:
        """Get deployment status and replica information."""
        try:
            result = subprocess.run([
                'kubectl', 'get', 'deployment', name, '-n', self.namespace, 
                '-o', 'json'
            ], capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                deployment_data = json.loads(result.stdout)
                status = deployment_data.get('status', {})
                
                return {
                    'healthy': status.get('readyReplicas', 0) > 0,
                    'replicas': status.get('replicas', 0),
                    'ready_replicas': status.get('readyReplicas', 0),
                    'available_replicas': status.get('availableReplicas', 0),
                    'conditions': status.get('conditions', []),
                    'namespace': self.namespace
                }
            else:
                return {
                    'healthy': False,
                    'error': 'Deployment not found',
                    'namespace': self.namespace
                }
                
        except Exception as e:
            logger.error(f"Error getting deployment status {name}: {e}")
            return {
                'healthy': False,
                'error': str(e),
                'namespace': self.namespace
            }
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Kubernetes cluster health."""
        try:
            # Check cluster info
            result = subprocess.run(['kubectl', 'cluster-info'], 
                                  capture_output=True, text=True, timeout=15)
            cluster_healthy = result.returncode == 0
            
            # Get node status
            result = subprocess.run([
                'kubectl', 'get', 'nodes', '-o', 'json'
            ], capture_output=True, text=True, timeout=15)
            
            nodes_info = {}
            if result.returncode == 0:
                nodes_data = json.loads(result.stdout)
                nodes_info = {
                    'total_nodes': len(nodes_data.get('items', [])),
                    'ready_nodes': len([
                        node for node in nodes_data.get('items', [])
                        if any(condition.get('type') == 'Ready' and condition.get('status') == 'True' 
                              for condition in node.get('status', {}).get('conditions', []))
                    ])
                }
            
            # Get namespace status
            result = subprocess.run([
                'kubectl', 'get', 'all', '-n', self.namespace
            ], capture_output=True, text=True, timeout=15)
            namespace_healthy = result.returncode == 0
            
            return {
                'healthy': cluster_healthy and namespace_healthy,
                'cluster_info': result.stdout if cluster_healthy else "Cluster unavailable",
                'namespace': self.namespace,
                'nodes': nodes_info,
                'kubectl_version': self._get_kubectl_version(),
                'image_registry': self.image_registry,
                'monitoring_enabled': bool(self.monitoring),
                'security_context': self.security_context
            }
            
        except Exception as e:
            logger.error(f"Kubernetes health check error: {e}")
            return {
                'healthy': False,
                'error': str(e)
            }
    
    def _get_kubectl_version(self) -> str:
        """Get kubectl version."""
        try:
            result = subprocess.run(['kubectl', 'version', '--client', '--short'], 
                                  capture_output=True, text=True, timeout=10)
            return result.stdout.strip() if result.returncode == 0 else "unknown"
        except:
            return "unknown"

class KubernetesPlugin:
    """
    Kubernetes Plugin - Enterprise Kubernetes orchestration for PlugPipe.
    
    Provides service discovery, auto-scaling, load balancing, and comprehensive
    plugin lifecycle management in Kubernetes environments.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.k8s_config = config.get('kubernetes_plugin', {})
        self.orchestrator_config = config.get('kubernetes', {})
        
        # Plugin configuration
        self.namespace = self.k8s_config.get('namespace', 'plugpipe-system')
        self.enable_auto_scaling = self.k8s_config.get('enable_auto_scaling', True)
        self.enable_service_discovery = self.k8s_config.get('enable_service_discovery', True)
        self.enable_load_balancing = self.k8s_config.get('enable_load_balancing', True)
        self.enable_health_monitoring = self.k8s_config.get('enable_health_monitoring', True)
        self.default_replicas = self.k8s_config.get('default_replicas', 2)
        
        # Plugin state
        self.plugin_id = str(uuid.uuid4())
        self.initialized = False
        self.orchestrator = None
        self.managed_plugins = {}
        
        logger.info(f"Kubernetes Plugin initialized with ID: {self.plugin_id}")
    
    async def initialize(self) -> bool:
        """Initialize the Kubernetes Plugin."""
        try:
            logger.info("Initializing Kubernetes Plugin...")
            
            # Initialize Kubernetes orchestrator
            self.orchestrator = KubernetesOrchestrator({
                'kubernetes': self.orchestrator_config
            })
            
            if not await self.orchestrator.initialize():
                logger.error("Failed to initialize Kubernetes orchestrator")
                return False
            
            self.initialized = True
            logger.info("Kubernetes Plugin initialized successfully")
            return True
            
        except Exception as e:
            logger.error(f"Kubernetes Plugin initialization failed: {e}")
            return False
    
    async def deploy_plugin(self, plugin_config: Dict[str, Any]) -> str:
        """Deploy a plugin to Kubernetes."""
        if not self.initialized:
            logger.error("Kubernetes Plugin not initialized")
            return ""

        try:
            # Validate plugin configuration
            validation_result = await self.orchestrator._validate_and_sanitize_input(plugin_config, "deployment")
            if not validation_result['is_valid']:
                logger.error(f"Invalid plugin config: {validation_result['errors']}")
                return ""

            validated_config = validation_result['sanitized_value']
            plugin_name = self.orchestrator._validate_k8s_resource_name(
                validated_config.get('name', f'plugin-{uuid.uuid4().hex[:8]}')
            )
            
            # Create ConfigMap for plugin configuration (with validation)
            if validated_config.get('config_data'):
                config_name = f"{plugin_name}-config"
                # Validate config data
                validated_config_data = {}
                for key, value in validated_config['config_data'].items():
                    # Basic validation for config keys and values
                    if re.match(r'^[A-Z][A-Z0-9_]*$', key) and isinstance(value, str):
                        validated_config_data[key] = re.sub(r'[<>"\';\\]', '', value)
                await self.orchestrator.create_configmap(config_name, validated_config_data)

            # Create Secret for sensitive data (with validation)
            if validated_config.get('secret_data'):
                secret_name = f"{plugin_name}-secret"
                # Validate secret data
                validated_secret_data = {}
                for key, value in validated_config['secret_data'].items():
                    if re.match(r'^[a-z][a-z0-9-]*$', key) and isinstance(value, str):
                        # Don't log secret values, just validate format
                        validated_secret_data[key] = value
                await self.orchestrator.create_secret(secret_name, validated_secret_data)

            # Create deployment with validated configuration
            deployment_config = {
                'image': validated_config.get('image'),
                'replicas': max(1, min(validated_config.get('replicas', self.default_replicas), 10)),
                'port': validated_config.get('port', 8080),
                'environment': validated_config.get('environment', {}),
                'resources': validated_config.get('resources', {})
            }
            
            if await self.orchestrator.create_deployment(plugin_name, deployment_config):
                # Create service with validated configuration
                service_config = {
                    'port': validated_config.get('port', 8080),
                    'type': validated_config.get('service_type', 'ClusterIP')
                }
                
                if await self.orchestrator.create_service(plugin_name, service_config):
                    # Create HPA if auto-scaling enabled (with validation)
                    if self.enable_auto_scaling and validated_config.get('auto_scaling', True):
                        hpa_config = {
                            'min_replicas': max(1, validated_config.get('min_replicas', 1)),
                            'max_replicas': min(20, validated_config.get('max_replicas', 10)),
                            'target_cpu_percent': max(30, min(90, validated_config.get('target_cpu_percent', 70)))
                        }
                        await self.orchestrator.create_hpa(plugin_name, hpa_config)
                    
                    # Track deployed plugin
                    self.managed_plugins[plugin_name] = {
                        'deployed_at': datetime.utcnow().isoformat(),
                        'config': validated_config,  # Store validated config
                        'auto_scaling': self.enable_auto_scaling and validated_config.get('auto_scaling', True),
                        'replicas': deployment_config['replicas'],
                        'security_validated': True
                    }
                    
                    logger.info(f"Successfully deployed plugin: {plugin_name}")
                    return plugin_name
                else:
                    logger.error(f"Failed to create service for plugin: {plugin_name}")
                    return ""
            else:
                logger.error(f"Failed to create deployment for plugin: {plugin_name}")
                return ""
                
        except Exception as e:
            logger.error(f"Error deploying plugin: {e}")
            return ""
    
    async def scale_plugin(self, plugin_name: str, replicas: int) -> bool:
        """Scale a deployed plugin."""
        if not self.initialized:
            logger.error("Kubernetes Plugin not initialized")
            return False
        
        try:
            if await self.orchestrator.scale_deployment(plugin_name, replicas):
                if plugin_name in self.managed_plugins:
                    self.managed_plugins[plugin_name]['replicas'] = replicas
                logger.info(f"Scaled plugin {plugin_name} to {replicas} replicas")
                return True
            else:
                logger.error(f"Failed to scale plugin: {plugin_name}")
                return False
                
        except Exception as e:
            logger.error(f"Error scaling plugin: {e}")
            return False
    
    async def get_plugin_status(self, plugin_name: str) -> Dict[str, Any]:
        """Get status of a deployed plugin."""
        if not self.initialized:
            return {'healthy': False, 'error': 'Kubernetes Plugin not initialized'}
        
        try:
            # Get deployment status
            deployment_status = await self.orchestrator.get_deployment_status(plugin_name)
            
            # Get service status
            service_status = await self.orchestrator.get_service_status(plugin_name)
            
            # Combine status information
            status = {
                'plugin_name': plugin_name,
                'deployment': deployment_status,
                'service': service_status,
                'healthy': deployment_status.get('healthy', False) and service_status.get('healthy', False),
                'namespace': self.namespace
            }
            
            # Add managed plugin info if available
            if plugin_name in self.managed_plugins:
                status['managed_info'] = self.managed_plugins[plugin_name]
            
            return status
            
        except Exception as e:
            logger.error(f"Error getting plugin status: {e}")
            return {'healthy': False, 'error': str(e)}
    
    async def list_deployed_plugins(self) -> List[Dict[str, Any]]:
        """List all deployed plugins managed by this plugin."""
        plugins = []
        
        for plugin_name, info in self.managed_plugins.items():
            status = await self.get_plugin_status(plugin_name)
            plugins.append({
                'name': plugin_name,
                'info': info,
                'status': status
            })
        
        return plugins
    
    async def discover_services(self, labels: Dict[str, str] = None) -> List[Dict[str, Any]]:
        """Discover services in the cluster."""
        if not self.enable_service_discovery:
            return []
        
        try:
            cmd = ['kubectl', 'get', 'services', '-n', self.namespace, '-o', 'json']
            if labels:
                label_selector = ','.join([f"{k}={v}" for k, v in labels.items()])
                cmd.extend(['-l', label_selector])
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            
            if result.returncode == 0:
                services_data = json.loads(result.stdout)
                return services_data.get('items', [])
            else:
                logger.error(f"Failed to discover services: {result.stderr}")
                return []
                
        except Exception as e:
            logger.error(f"Error discovering services: {e}")
            return []
    
    async def health_check(self) -> Dict[str, Any]:
        """Comprehensive Kubernetes plugin health check."""
        plugin_health = {
            'plugin_id': self.plugin_id,
            'plugin_healthy': self.initialized,
            'namespace': self.namespace,
            'features': {
                'auto_scaling': self.enable_auto_scaling,
                'service_discovery': self.enable_service_discovery,
                'load_balancing': self.enable_load_balancing,
                'health_monitoring': self.enable_health_monitoring
            },
            'managed_plugins': len(self.managed_plugins),
            'cluster_status': {},
            'capabilities': []
        }
        
        # Get cluster health from orchestrator
        if self.orchestrator:
            try:
                cluster_health = await self.orchestrator.health_check()
                plugin_health['cluster_status'] = cluster_health
                plugin_health['plugin_healthy'] = plugin_health['plugin_healthy'] and cluster_health.get('healthy', False)
            except Exception as e:
                plugin_health['cluster_status'] = {'error': str(e)}
        
        # Add capabilities
        plugin_health['capabilities'] = [
            'service_discovery',
            'auto_scaling', 
            'load_balancing',
            'health_monitoring',
            'plugin_deployment',
            'resource_management',
            'kubernetes_native'
        ]
        
        return plugin_health
    
    def get_plugin_status_summary(self) -> Dict[str, Any]:
        """Get current plugin status summary."""
        return {
            'plugin_id': self.plugin_id,
            'initialized': self.initialized,
            'namespace': self.namespace,
            'managed_plugins': len(self.managed_plugins),
            'features': {
                'auto_scaling': self.enable_auto_scaling,
                'service_discovery': self.enable_service_discovery,
                'load_balancing': self.enable_load_balancing,
                'health_monitoring': self.enable_health_monitoring
            },
            'default_replicas': self.default_replicas
        }

# Plugin metadata
plug_metadata = {
    "name": "kubernetes_plugin",
    "version": "1.0.0",
    "owner": "PlugPipe Core Team",
    "status": "stable",
    "description": "Enterprise Kubernetes orchestration plugin for service discovery, auto-scaling, and plugin lifecycle management",
    "capabilities": [
        "service_discovery",
        "auto_scaling",
        "load_balancing", 
        "health_monitoring",
        "plugin_deployment",
        "resource_management",
        "kubernetes_native"
    ]
}

async def process_async(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Async process function for Kubernetes Plugin."""
    try:
        k8s_plugin = KubernetesPlugin(config)
        
        operation = config.get('operation', 'initialize')
        
        if operation == 'health_check':
            await k8s_plugin.initialize()
            health_status = await k8s_plugin.health_check()
            return {
                'success': True,
                'operation_completed': 'health_check',
                'health_status': health_status
            }
        
        elif operation == 'deploy_plugin':
            await k8s_plugin.initialize()
            plugin_config = config.get('plugin_config', {})
            plugin_name = await k8s_plugin.deploy_plugin(plugin_config)
            return {
                'success': bool(plugin_name),
                'operation_completed': 'deploy_plugin',
                'plugin_name': plugin_name
            }
        
        elif operation == 'scale_plugin':
            await k8s_plugin.initialize()
            plugin_name = config.get('plugin_name', '')
            replicas = config.get('replicas', 1)
            success = await k8s_plugin.scale_plugin(plugin_name, replicas)
            return {
                'success': success,
                'operation_completed': 'scale_plugin',
                'plugin_name': plugin_name,
                'replicas': replicas
            }
        
        elif operation == 'list_plugins':
            await k8s_plugin.initialize()
            plugins = await k8s_plugin.list_deployed_plugins()
            return {
                'success': True,
                'operation_completed': 'list_plugins',
                'plugins': plugins
            }
        
        elif operation == 'discover_services':
            await k8s_plugin.initialize()
            labels = config.get('labels', {})
            services = await k8s_plugin.discover_services(labels)
            return {
                'success': True,
                'operation_completed': 'discover_services',
                'services': services
            }
        
        else:
            # Default: Plugin initialization and status
            result = await k8s_plugin.initialize()
            status = k8s_plugin.get_plugin_status_summary()
            
            return {
                'success': result,
                'plugin_type': 'kubernetes',
                'status': 'ready' if result else 'failed',
                'capabilities': plug_metadata['capabilities'],
                'plugin_status': status
            }
    
    except Exception as e:
        logger.error(f"Kubernetes Plugin error: {e}")
        return {
            'success': False,
            'error': str(e),
            'plugin_type': 'kubernetes'
        }

def process(ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Synchronous wrapper for the async process function."""
    return asyncio.run(process_async(ctx, config))

if __name__ == "__main__":
    # Test the Kubernetes Plugin
    test_config = {
        'kubernetes_plugin': {
            'namespace': 'plugpipe-test',
            'enable_auto_scaling': True,
            'enable_service_discovery': True,
            'enable_load_balancing': True,
            'enable_health_monitoring': True,
            'default_replicas': 2
        },
        'kubernetes': {
            'namespace': 'plugpipe-test',
            'image_registry': 'plugpipe',
            'resource_defaults': {
                'requests': {
                    'memory': '128Mi',
                    'cpu': '100m'
                },
                'limits': {
                    'memory': '512Mi',
                    'cpu': '500m'
                }
            },
            'security_context': {
                'runAsNonRoot': True,
                'runAsUser': 1000
            }
        }
    }
    
    result = process({}, test_config)
    print(json.dumps(result, indent=2))