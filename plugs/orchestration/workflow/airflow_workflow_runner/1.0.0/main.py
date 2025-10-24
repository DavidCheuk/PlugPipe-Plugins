# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Airflow Workflow Runner Plugin - Enhanced with FTHAD Methodology
Professional Apache Airflow DAG orchestration with comprehensive security controls
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
    FTHAD IMPLEMENTATION: Comprehensive Airflow DAG Runner with enterprise security controls

    Executes Apache Airflow DAGs with:
    - Input validation and sanitization
    - Authentication security controls
    - Comprehensive error handling
    - Timeout and resource management
    - Detailed logging and monitoring
    - Security-aware DAG execution
    """

    if cfg is None:
        cfg = {}

    # Initialize results
    execution_results = {
        'timestamp': datetime.now().isoformat(),
        'plugin': 'airflow_workflow_runner',
        'success': True,
        'dag_run_id': None,
        'state': None,
        'execution_time': 0,
        'logs': [],
        'security_validations': []
    }

    try:
        logger.info("Starting Airflow DAG execution with FTHAD security controls")
        start_time = time.time()

        # FTHAD HARDENING: Input validation and security controls
        validation_result = _validate_and_sanitize_inputs(ctx, cfg)
        if not validation_result['valid']:
            execution_results.update({
                'success': False,
                'error': validation_result['error'],
                'security_validation_failed': True
            })
            return {'airflow_workflow_runner': execution_results}

        # Extract validated parameters
        airflow_url = validation_result['airflow_url']
        auth_token = validation_result['auth_token']
        dag_id = validation_result['dag_id']
        parameters = validation_result['parameters']
        run_id = validation_result['run_id']
        timeout = validation_result['timeout']
        poll_interval = validation_result['poll_interval']

        execution_results['security_validations'] = validation_result['validations']

        # FTHAD IMPLEMENTATION: Enhanced DAG execution with error handling
        logger.info(f"Triggering DAG: {dag_id} on Airflow: {airflow_url}")
        trigger_result = _trigger_dag_run(
            airflow_url, auth_token, dag_id, parameters, run_id
        )

        if not trigger_result['success']:
            execution_results.update({
                'success': False,
                'error': trigger_result['error'],
                'trigger_failed': True
            })
            return {'airflow_workflow_runner': execution_results}

        dag_run_id = trigger_result['dag_run_id']
        execution_results['dag_run_id'] = dag_run_id
        logger.info(f"DAG run triggered successfully: {dag_run_id}")

        # FTHAD IMPLEMENTATION: Enhanced status polling with comprehensive monitoring
        logger.info(f"Polling DAG run status with {timeout}s timeout")
        polling_result = _poll_dag_run_status(
            airflow_url, auth_token, dag_id, dag_run_id, timeout, poll_interval
        )

        if not polling_result['success']:
            execution_results.update({
                'success': False,
                'error': polling_result['error'],
                'polling_failed': True
            })
            return {'airflow_workflow_runner': execution_results}

        # Update final results
        execution_results.update({
            'state': polling_result['state'],
            'result': polling_result['result'],
            'execution_time': time.time() - start_time,
            'logs': polling_result.get('logs', [])
        })

        # FTHAD IMPLEMENTATION: Result analysis and recommendations
        if polling_result['state'] == 'failed':
            execution_results['recommendations'] = _analyze_dag_failure(polling_result['result'])
        elif polling_result['state'] == 'success':
            execution_results['performance_metrics'] = _extract_dag_performance_metrics(polling_result['result'])

        logger.info(f"Airflow DAG execution completed: {polling_result['state']}")

    except Exception as e:
        logger.error(f"Airflow DAG execution failed: {str(e)}")
        execution_results.update({
            'success': False,
            'error': f'Unexpected error: {str(e)}',
            'execution_time': time.time() - start_time if 'start_time' in locals() else 0
        })

    return {'airflow_workflow_runner': execution_results}

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
    if 'airflow_url' not in cfg:
        return {'valid': False, 'error': 'airflow_url is required in configuration'}
    if 'auth_token' not in cfg:
        return {'valid': False, 'error': 'auth_token is required in configuration'}
    if 'dag_id' not in cfg:
        return {'valid': False, 'error': 'dag_id is required in configuration'}

    # Validate and sanitize Airflow URL
    airflow_url = str(cfg['airflow_url']).strip()
    if not _is_valid_airflow_url(airflow_url):
        return {'valid': False, 'error': 'Invalid Airflow URL format'}

    validations.append("Airflow URL validation passed")

    # Validate auth token format
    auth_token = str(cfg['auth_token']).strip()
    if not _is_valid_auth_token(auth_token):
        return {'valid': False, 'error': 'Invalid auth token format'}

    validations.append("Auth token validation passed")

    # Validate DAG ID format
    dag_id = str(cfg['dag_id']).strip()
    if not _is_valid_dag_id(dag_id):
        return {'valid': False, 'error': 'Invalid DAG ID format'}

    validations.append("DAG ID validation passed")

    # Validate parameters
    parameters = ctx.get('parameters', {})
    if not isinstance(parameters, dict):
        return {'valid': False, 'error': 'Parameters must be a dictionary'}

    # Sanitize parameters to prevent injection
    sanitized_parameters = _sanitize_parameters(parameters)
    validations.append("Parameters validation and sanitization passed")

    # Validate run ID
    run_id = ctx.get('run_id')
    if run_id is not None:
        run_id = str(run_id).strip()
        if not _is_valid_run_id(run_id):
            return {'valid': False, 'error': 'Invalid run ID format'}
    else:
        # Generate secure run ID if not provided
        run_id = f"plugpipe-{datetime.now().strftime('%Y%m%d-%H%M%S')}-{int(time.time() * 1000) % 10000}"

    validations.append("Run ID validation passed")

    # Validate timeout and poll interval
    timeout = cfg.get('timeout', 600)
    if not isinstance(timeout, (int, float)) or timeout < 30 or timeout > 14400:  # 30s to 4h
        return {'valid': False, 'error': 'timeout must be between 30 and 14400 seconds'}

    poll_interval = cfg.get('poll_interval', 5)
    if not isinstance(poll_interval, (int, float)) or poll_interval < 1 or poll_interval > 300:
        return {'valid': False, 'error': 'poll_interval must be between 1 and 300 seconds'}

    validations.append("Timeout and polling validation passed")

    return {
        'valid': True,
        'airflow_url': airflow_url,
        'auth_token': auth_token,
        'dag_id': dag_id,
        'parameters': sanitized_parameters,
        'run_id': run_id,
        'timeout': timeout,
        'poll_interval': poll_interval,
        'validations': validations
    }

def _trigger_dag_run(airflow_url: str, auth_token: str, dag_id: str,
                    parameters: Dict[str, Any], run_id: str) -> Dict[str, Any]:
    """FTHAD IMPLEMENTATION: Enhanced DAG triggering with error handling"""
    try:
        url = f"{airflow_url.rstrip('/')}/api/v1/dags/{dag_id}/dagRuns"
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "Content-Type": "application/json",
            "User-Agent": "PlugPipe-AirflowRunner/1.0"
        }

        payload = {
            "conf": parameters,
            "dag_run_id": run_id
        }

        # Trigger DAG with timeout
        response = requests.post(
            url,
            headers=headers,
            json=payload,
            timeout=30  # 30s trigger timeout
        )

        response.raise_for_status()
        dag_run_data = response.json()

        # Extract DAG run ID
        dag_run_id = dag_run_data.get("dag_run_id")
        if not dag_run_id:
            return {'success': False, 'error': 'No DAG run ID in response'}

        return {
            'success': True,
            'dag_run_id': dag_run_id,
            'dag_run_data': dag_run_data
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'error': 'DAG trigger request timed out'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'error': 'Connection to Airflow server failed'}
    except requests.exceptions.HTTPError as e:
        return {'success': False, 'error': f'HTTP error during DAG trigger: {e.response.status_code}'}
    except Exception as e:
        return {'success': False, 'error': f'DAG trigger failed: {str(e)}'}

def _poll_dag_run_status(airflow_url: str, auth_token: str, dag_id: str, dag_run_id: str,
                        timeout: float, poll_interval: float) -> Dict[str, Any]:
    """FTHAD IMPLEMENTATION: Enhanced status polling with comprehensive monitoring"""
    try:
        poll_url = f"{airflow_url.rstrip('/')}/api/v1/dags/{dag_id}/dagRuns/{dag_run_id}"
        headers = {
            "Authorization": f"Bearer {auth_token}",
            "User-Agent": "PlugPipe-AirflowRunner/1.0"
        }

        start_time = time.time()
        logs = []

        while True:
            if time.time() - start_time > timeout:
                return {
                    'success': False,
                    'error': f'DAG run polling timed out after {timeout} seconds',
                    'logs': logs
                }

            time.sleep(poll_interval)

            try:
                response = requests.get(poll_url, headers=headers, timeout=10)
                response.raise_for_status()
                dag_run_data = response.json()

                state = dag_run_data.get("state", "")

                # Log state transitions
                log_entry = {
                    'timestamp': datetime.now().isoformat(),
                    'state': state,
                    'elapsed': time.time() - start_time
                }
                logs.append(log_entry)

                # Check for completion
                if state in ("success", "failed"):
                    return {
                        'success': True,
                        'state': state,
                        'result': dag_run_data,
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

def _is_valid_airflow_url(url: str) -> bool:
    """Validate Airflow server URL format and security"""
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

def _is_valid_dag_id(dag_id: str) -> bool:
    """Validate Airflow DAG ID format"""
    if not dag_id or len(dag_id) > 250:
        return False
    # Airflow DAG ID restrictions: alphanumeric, underscores, hyphens, dots
    pattern = r'^[a-zA-Z0-9_\-\.]+$'
    return re.match(pattern, dag_id) is not None

def _is_valid_run_id(run_id: str) -> bool:
    """Validate DAG run ID format"""
    if not run_id or len(run_id) > 250:
        return False
    # Similar to DAG ID but more restrictive
    pattern = r'^[a-zA-Z0-9_\-\.]+$'
    return re.match(pattern, run_id) is not None

def _sanitize_parameters(parameters: Dict[str, Any]) -> Dict[str, Any]:
    """Sanitize parameters to prevent injection attacks"""
    sanitized = {}

    for key, value in parameters.items():
        # Sanitize keys
        if isinstance(key, str):
            key_clean = re.sub(r'[<>"\';\\]+', '', str(key))
            if len(key_clean) > 100:  # Limit key length
                key_clean = key_clean[:100]
        else:
            key_clean = str(key)[:100]

        # Sanitize values
        if isinstance(value, str):
            value_clean = re.sub(r'[<>"\x00-\x1f]+', '', str(value))
            if len(value_clean) > 10000:  # Limit value length
                value_clean = value_clean[:10000]
            sanitized[key_clean] = value_clean
        elif isinstance(value, (int, float, bool)):
            sanitized[key_clean] = value
        elif isinstance(value, (list, dict)):
            # For complex types, convert to JSON string (sanitized)
            try:
                json_str = json.dumps(value)[:10000]  # Limit JSON size
                sanitized[key_clean] = json.loads(json_str)
            except:
                sanitized[key_clean] = str(value)[:1000]
        else:
            sanitized[key_clean] = str(value)[:1000]

    return sanitized

def _analyze_dag_failure(result: Dict[str, Any]) -> List[str]:
    """Analyze failed DAG run and provide recommendations"""
    recommendations = []

    # Analyze common failure patterns
    state = result.get('state', '')

    if 'timeout' in str(result).lower():
        recommendations.append('Consider increasing DAG timeout or optimizing task performance')

    if 'permission' in str(result).lower():
        recommendations.append('Verify DAG permissions and service account access')

    if 'connection' in str(result).lower():
        recommendations.append('Check external service connections and network accessibility')

    if 'resource' in str(result).lower():
        recommendations.append('Review resource requirements and cluster capacity')

    if not recommendations:
        recommendations.append('Review DAG run logs for detailed error information')

    return recommendations

def _extract_dag_performance_metrics(result: Dict[str, Any]) -> Dict[str, Any]:
    """Extract performance metrics from successful DAG run"""
    return {
        'start_date': result.get('start_date'),
        'end_date': result.get('end_date'),
        'execution_date': result.get('execution_date'),
        'state': result.get('state'),
        'dag_id': result.get('dag_id'),
        'run_id': result.get('dag_run_id'),
        'external_trigger': result.get('external_trigger', False)
    }
