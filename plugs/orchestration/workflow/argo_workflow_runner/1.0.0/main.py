# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Argo Workflow Runner Plugin - Enhanced with FTHAD Methodology
Professional Argo Workflows orchestration with comprehensive security controls
"""

import requests
import time
import logging
import re
import json
from datetime import datetime, timedelta
from urllib.parse import urlparse
from typing import Dict, Any, Optional, List

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

def process(ctx: Dict[str, Any], cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    FTHAD IMPLEMENTATION: Comprehensive Argo Workflow Runner with enterprise security controls

    Executes Argo Workflows with:
    - Input validation and sanitization
    - Authentication security controls
    - Comprehensive error handling
    - Timeout and resource management
    - Detailed logging and monitoring
    - Security-aware workflow submission
    """

    if cfg is None:
        cfg = {}

    # Initialize results
    execution_results = {
        'timestamp': datetime.now().isoformat(),
        'plugin': 'argo_workflow_runner',
        'success': True,
        'workflow_name': None,
        'phase': None,
        'execution_time': 0,
        'logs': [],
        'security_validations': []
    }

    try:
        logger.info("Starting Argo Workflow execution with FTHAD security controls")
        start_time = time.time()

        # FTHAD HARDENING: Input validation and security controls
        validation_result = _validate_and_sanitize_inputs(ctx, cfg)
        if not validation_result['valid']:
            execution_results.update({
                'success': False,
                'error': validation_result['error'],
                'security_validation_failed': True
            })
            return {'argo_workflow_runner': execution_results}

        # Extract validated parameters
        argo_url = validation_result['argo_url']
        auth_token = validation_result['auth_token']
        namespace = validation_result['namespace']
        workflow_manifest = validation_result['workflow_manifest']
        timeout = validation_result['timeout']
        poll_interval = validation_result['poll_interval']

        execution_results['security_validations'] = validation_result['validations']

        # FTHAD IMPLEMENTATION: Enhanced workflow submission with error handling
        logger.info(f"Submitting workflow to Argo: {argo_url}")
        submission_result = _submit_workflow(
            argo_url, auth_token, namespace, workflow_manifest
        )

        if not submission_result['success']:
            execution_results.update({
                'success': False,
                'error': submission_result['error'],
                'submission_failed': True
            })
            return {'argo_workflow_runner': execution_results}

        workflow_name = submission_result['workflow_name']
        execution_results['workflow_name'] = workflow_name
        logger.info(f"Workflow submitted successfully: {workflow_name}")

        # FTHAD IMPLEMENTATION: Enhanced status polling with comprehensive monitoring
        logger.info(f"Polling workflow status with {timeout}s timeout")
        polling_result = _poll_workflow_status(
            argo_url, auth_token, namespace, workflow_name, timeout, poll_interval
        )

        if not polling_result['success']:
            execution_results.update({
                'success': False,
                'error': polling_result['error'],
                'polling_failed': True
            })
            return {'argo_workflow_runner': execution_results}

        # Update final results
        execution_results.update({
            'phase': polling_result['phase'],
            'result': polling_result['result'],
            'execution_time': time.time() - start_time,
            'logs': polling_result.get('logs', [])
        })

        # FTHAD IMPLEMENTATION: Result analysis and recommendations
        if polling_result['phase'] == 'Failed':
            execution_results['recommendations'] = _analyze_workflow_failure(polling_result['result'])
        elif polling_result['phase'] == 'Succeeded':
            execution_results['performance_metrics'] = _extract_performance_metrics(polling_result['result'])

        logger.info(f"Argo workflow execution completed: {polling_result['phase']}")

    except Exception as e:
        logger.error(f"Argo workflow execution failed: {str(e)}")
        execution_results.update({
            'success': False,
            'error': f'Unexpected error: {str(e)}',
            'execution_time': time.time() - start_time if 'start_time' in locals() else 0
        })

    return {'argo_workflow_runner': execution_results}

def _validate_and_sanitize_inputs(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """FTHAD HARDENING: Comprehensive input validation and sanitization"""
    validations = []

    # Validate context and config types
    if not isinstance(ctx, dict):
        return {'valid': False, 'error': 'Context must be a dictionary'}
    if not isinstance(cfg, dict):
        return {'valid': False, 'error': 'Configuration must be a dictionary'}

    validations.append("Input type validation passed")

    # Validate required configuration
    if 'argo_url' not in cfg:
        return {'valid': False, 'error': 'argo_url is required in configuration'}
    if 'auth_token' not in cfg:
        return {'valid': False, 'error': 'auth_token is required in configuration'}

    # Validate and sanitize Argo URL
    argo_url = str(cfg['argo_url']).strip()
    if not _is_valid_argo_url(argo_url):
        return {'valid': False, 'error': 'Invalid Argo URL format'}

    validations.append("Argo URL validation passed")

    # Validate auth token format
    auth_token = str(cfg['auth_token']).strip()
    if not _is_valid_auth_token(auth_token):
        return {'valid': False, 'error': 'Invalid auth token format'}

    validations.append("Auth token validation passed")

    # Validate namespace
    namespace = cfg.get('namespace', 'default')
    if not _is_valid_kubernetes_namespace(namespace):
        return {'valid': False, 'error': 'Invalid Kubernetes namespace format'}

    validations.append("Namespace validation passed")

    # Validate workflow manifest
    if 'workflow_manifest' not in ctx:
        return {'valid': False, 'error': 'workflow_manifest is required in context'}

    workflow_manifest = ctx['workflow_manifest']
    manifest_validation = _validate_workflow_manifest(workflow_manifest)
    if not manifest_validation['valid']:
        return {'valid': False, 'error': manifest_validation['error']}

    validations.append("Workflow manifest validation passed")

    # Validate timeout and poll interval
    timeout = cfg.get('timeout', 600)
    if not isinstance(timeout, (int, float)) or timeout < 10 or timeout > 7200:  # 10s to 2h
        return {'valid': False, 'error': 'timeout must be between 10 and 7200 seconds'}

    poll_interval = cfg.get('poll_interval', 5)
    if not isinstance(poll_interval, (int, float)) or poll_interval < 1 or poll_interval > 60:
        return {'valid': False, 'error': 'poll_interval must be between 1 and 60 seconds'}

    validations.append("Timeout and polling validation passed")

    return {
        'valid': True,
        'argo_url': argo_url,
        'auth_token': auth_token,
        'namespace': namespace,
        'workflow_manifest': workflow_manifest,
        'timeout': timeout,
        'poll_interval': poll_interval,
        'validations': validations
    }

def _submit_workflow(argo_url: str, auth_token: str, namespace: str, workflow_manifest: Dict[str, Any]) -> Dict[str, Any]:
    """FTHAD IMPLEMENTATION: Enhanced workflow submission with error handling"""
    try:
        url = f"{argo_url.rstrip('/')}/api/v1/workflows/{namespace}"
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "User-Agent": "PlugPipe-ArgoRunner/1.0"
        }

        # Submit workflow with timeout
        response = requests.post(
            url,
            headers=headers,
            json=workflow_manifest,
            timeout=30  # 30s submission timeout
        )

        response.raise_for_status()
        workflow_data = response.json()

        # Extract workflow name
        workflow_name = workflow_data.get("metadata", {}).get("name")
        if not workflow_name:
            return {'success': False, 'error': 'No workflow name in response'}

        return {
            'success': True,
            'workflow_name': workflow_name,
            'workflow_data': workflow_data
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'Workflow submission timed out'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Connection to Argo server failed'}
    except requests.exceptions.HTTPError as e:
        return {'success': False, 'error': f'HTTP error during submission: {e.response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': f'Workflow submission failed: {str(e)}'}

def _poll_workflow_status(argo_url: str, auth_token: str, namespace: str, workflow_name: str,
                         timeout: float, poll_interval: float) -> Dict[str, Any]:
    """FTHAD IMPLEMENTATION: Enhanced status polling with comprehensive monitoring"""
    try:
        poll_url = f"{argo_url.rstrip('/')}/api/v1/workflows/{namespace}/{workflow_name}"
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "User-Agent": "PlugPipe-ArgoRunner/1.0"
        }

        start_time = time.time()
        logs = []

        while True:
            if time.time() - start_time > timeout:
                return {
                    'success': False,
                    'error': f'Workflow polling timed out after {timeout} seconds',
                    'logs': logs
                }

            time.sleep(poll_interval)

            try:
                response = requests.get(poll_url, headers=headers, timeout=10)
                response.raise_for_status()
                workflow_status = response.json()

                status = workflow_status.get("status", {})
                phase = status.get("phase", "")

                # Log phase transitions
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'phase': phase,
                    'elapsed': time.time() - start_time
                }
                logs.append(log_entry)

                # Check for completion
                if phase in ("Succeeded", "Failed", "Error"):
                    return {
                        'success': True,
                        'phase': phase,
                        'result': workflow_status,
                        'logs': logs
                    }

            except requests.exceptions.RequestException as e:
                logs.append({
                    'timestamp': datetime.now().isoformat(),
                    'error': f'Polling request failed: {str(e)}'
                })
                # Continue polling despite request failures
                continue

    except Exception as e:
        return {'success': False, 'error': f'Status polling failed: {str(e)}'}

def _is_valid_argo_url(url: str) -> bool:
    """Validate Argo server URL format and security"""
    try:
        parsed = urlparse(url)
        if parsed.scheme not in ('http', 'https'):
            return False
        if not parsed.netloc:
            return False
        # Security: reject URLs with suspicious patterns
        if any(suspicious in url.lower() for suspicious in ['..', '\\', '<', '>', '"', "'"]):
            return False
        return True
    except:
        return False

def _is_valid_auth_token(token: str) -> bool:
    """Validate auth token format"""
    if not token or len(token) < 10:
        return False
    # Security: basic token format validation
    if any(char in token for char in ['\n', '\r', '\t', ' ']):
        return False
    return True

def _is_valid_kubernetes_namespace(namespace: str) -> bool:
    """Validate Kubernetes namespace format"""
    if not namespace or len(namespace) > 63:
        return False
    # RFC 1123 label format
    pattern = r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?$'
    return re.match(pattern, namespace) is not None

def _validate_workflow_manifest(manifest: Any) -> Dict[str, Any]:
    """Validate workflow manifest structure"""
    if not isinstance(manifest, dict):
        return {'valid': False, 'error': 'Workflow manifest must be a dictionary'}

    # Check required fields
    if 'apiVersion' not in manifest:
        return {'valid': False, 'error': 'Workflow manifest missing apiVersion'}
    if 'kind' not in manifest:
        return {'valid': False, 'error': 'Workflow manifest missing kind'}
    if manifest.get('kind') != 'Workflow':
        return {'valid': False, 'error': 'Manifest kind must be Workflow'}
    if 'metadata' not in manifest:
        return {'valid': False, 'error': 'Workflow manifest missing metadata'}
    if 'spec' not in manifest:
        return {'valid': False, 'error': 'Workflow manifest missing spec'}

    return {'valid': True}

def _analyze_workflow_failure(result: Dict[str, Any]) -> List[str]:
    """Analyze failed workflow and provide recommendations"""
    recommendations = []

    status = result.get('status', {})
    message = status.get('message', '')

    if 'timeout' in message.lower():
        recommendations.append('Consider increasing workflow timeout')
    if 'resource' in message.lower():
        recommendations.append('Check resource limits and availability')
    if 'permission' in message.lower():
        recommendations.append('Verify RBAC permissions for workflow execution')
    if 'image' in message.lower():
        recommendations.append('Verify container image accessibility')

    if not recommendations:
        recommendations.append('Review workflow logs for detailed error information')

    return recommendations

def _extract_performance_metrics(result: Dict[str, Any]) -> Dict[str, Any]:
    """Extract performance metrics from successful workflow"""
    status = result.get('status', {})

    return {
        'started_at': status.get('startedAt'),
        'finished_at': status.get('finishedAt'),
        'duration': status.get('duration'),
        'phase': status.get('phase'),
        'nodes_count': len(status.get('nodes', {}))
    }
