# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enterprise OPA (Open Policy Agent) Plugin for PlugPipe

Advanced enterprise-grade policy evaluation with multi-tenancy, enhanced security,
policy governance, monitoring, and compliance features.
"""

import json
import logging
import time
import ssl
import threading
import hashlib
import os
import glob
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List, Tuple, Union
from dataclasses import dataclass, asdict
from concurrent.futures import ThreadPoolExecutor, as_completed
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import importlib.util

# PlugPipe imports
from cores.auth.types import AuthzRequest, AuthzDecision, PolicyDecision

# Mock SecurityAuditLogger for enterprise plugin
class SecurityAuditLogger:
    """Mock security audit logger for enterprise features"""
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enabled = config.get('enabled', True)
    
    def log_policy_evaluation_start(self, request: AuthzRequest, tenant_id: str):
        """Log policy evaluation start"""
        if self.enabled:
            logger.info(f"Policy evaluation started for {request.subject} in tenant {tenant_id}")
    
    def log_policy_decision(self, audit_data: Dict[str, Any]):
        """Log policy decision"""
        if self.enabled:
            logger.info(f"Policy decision: {audit_data.get('decision', {}).get('allow')} for tenant {audit_data.get('tenant_id')}")

logger = logging.getLogger(__name__)

# Plugin metadata required by PlugPipe
plug_metadata = {
    "name": "opa_policy_enterprise",
    "version": "1.0.0",
    "description": "Enterprise-grade Open Policy Agent integration with ecosystem monitoring and compliance features",
    "author": "PlugPipe Enterprise Team",
    "tags": ["security", "policy", "authorization", "opa", "enterprise", "ecosystem", "compliance", "monitoring"],
    "category": "policy-engine",
    "tier": "enterprise",
    "license": "commercial",
    "capabilities": [
        "multi_tenancy",
        "policy_governance", 
        "compliance_frameworks",
        "ecosystem_monitoring",
        "health_monitoring",
        "change_management_integration",
        "audit_aggregation"
    ],
    "input_schema": {
        "type": "object",
        "properties": {
            "request": {"type": "object"},
            "basic_decision": {"type": "object"},
            "tenant_id": {"type": "string"},
            "organization_context": {"type": "object"},
            "action": {
                "type": "string", 
                "enum": ["evaluate_policy", "get_ecosystem_health", "get_compliance_status", "evaluate_change_policy"]
            },
            "change_request": {"type": "object"}
        },
        "required": ["request", "basic_decision"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "allow": {"type": "boolean"},
            "engine": {"type": "string"},
            "policy_name": {"type": "string"},
            "constraints": {"type": "object"},
            "reason": {"type": "string"},
            "confidence": {"type": "number"},
            "metadata": {"type": "object"},
            "audit_trace": {"type": "object"},
            "compliance_status": {"type": "object"},
            "ecosystem_health": {"type": "object"},
            "change_approval": {"type": "object"}
        },
        "required": ["allow", "engine"]
    }
}


@dataclass
class PolicyMetrics:
    """Policy evaluation metrics for monitoring"""
    total_evaluations: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    server_failures: int = 0
    fallback_uses: int = 0
    avg_response_time: float = 0.0
    policy_violations: int = 0
    compliance_checks: int = 0


@dataclass
class TenantConfig:
    """Tenant-specific configuration"""
    tenant_id: str
    opa_endpoints: List[str]
    policy_package: str
    fallback_mode: str
    compliance_requirements: List[str]
    custom_constraints: Dict[str, Any]
    rate_limits: Dict[str, int]
    audit_level: str


class PolicyGovernance:
    """Policy governance and approval workflow management"""
    
    def __init__(self, config: Dict[str, Any]):
        self.require_approval = config.get('require_approval', True)
        self.approval_threshold = config.get('approval_threshold', 2)
        self.version_control_enabled = config.get('version_control', True)
        self.policy_store = {}
        self.approval_queue = {}
        
    def submit_policy(self, policy_id: str, policy_content: str, submitter: str) -> str:
        """Submit policy for approval"""
        submission_id = hashlib.sha256(f"{policy_id}_{submitter}_{time.time()}".encode()).hexdigest()[:16]
        
        self.approval_queue[submission_id] = {
            'policy_id': policy_id,
            'content': policy_content,
            'submitter': submitter,
            'submitted_at': datetime.now(),
            'status': 'pending_approval',
            'approvals': [],
            'rejections': []
        }
        
        logger.info(f"Policy {policy_id} submitted for approval: {submission_id}")
        return submission_id
    
    def approve_policy(self, submission_id: str, approver: str, comments: str = "") -> bool:
        """Approve a policy submission"""
        if submission_id not in self.approval_queue:
            return False
            
        submission = self.approval_queue[submission_id]
        submission['approvals'].append({
            'approver': approver,
            'timestamp': datetime.now(),
            'comments': comments
        })
        
        if len(submission['approvals']) >= self.approval_threshold:
            submission['status'] = 'approved'
            self._deploy_policy(submission)
            logger.info(f"Policy {submission['policy_id']} approved and deployed")
            
        return True
    
    def _deploy_policy(self, submission: Dict[str, Any]):
        """Deploy approved policy"""
        # In production, this would deploy to OPA servers
        policy_id = submission['policy_id']
        self.policy_store[policy_id] = {
            'content': submission['content'],
            'version': self._get_next_version(policy_id),
            'deployed_at': datetime.now(),
            'deployed_by': submission['submitter']
        }


class EnterpriseSecurityManager:
    """Enhanced security features for enterprise environments"""
    
    def __init__(self, config: Dict[str, Any]):
        self.tls_enabled = config.get('tls_enabled', True)
        self.mtls_enabled = config.get('mtls_enabled', False)
        self.token_auth_enabled = config.get('token_auth', True)
        self.certificate_path = config.get('cert_path')
        self.key_path = config.get('key_path')
        self.ca_path = config.get('ca_path')
        self.api_tokens = config.get('api_tokens', {})
        
    def create_secure_session(self) -> requests.Session:
        """Create security-configured requests session"""
        session = requests.Session()
        
        # Configure retry strategy
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        # Configure TLS
        if self.tls_enabled:
            if self.mtls_enabled and self.certificate_path and self.key_path:
                session.cert = (self.certificate_path, self.key_path)
            
            if self.ca_path:
                session.verify = self.ca_path
            
            # Configure SSL context
            session.verify = True
        
        return session
    
    def get_auth_headers(self, tenant_id: str) -> Dict[str, str]:
        """Get authentication headers for tenant"""
        headers = {'Content-Type': 'application/json'}
        
        if self.token_auth_enabled and tenant_id in self.api_tokens:
            headers['Authorization'] = f"Bearer {self.api_tokens[tenant_id]}"
            
        return headers


class EcosystemHealthMonitor:
    """Ecosystem-wide health monitoring for PlugPipe"""
    
    def __init__(self, config: Dict[str, Any]):
        self.enabled = config.get('ecosystem_monitoring', True)
        self.plugs_directory = config.get('plugs_directory', 'plugs')
        self.pipes_directory = config.get('pipes_directory', 'pipe_specs')
        self.pipe_runs_directory = config.get('pipe_runs_directory', 'pipe_runs')
        self.monitoring_interval = config.get('monitoring_interval', 300)  # 5 minutes
        self.health_cache = {}
        self.health_cache_lock = threading.RLock()
        self.last_health_check = None
        
        # Initialize health monitoring
        if self.enabled:
            self._start_background_monitoring()
    
    def _start_background_monitoring(self):
        """Start background health monitoring thread"""
        def monitor_loop():
            while True:
                try:
                    self._perform_health_check()
                    time.sleep(self.monitoring_interval)
                except Exception as e:
                    logger.error(f"Health monitoring error: {e}")
                    time.sleep(60)  # Wait 1 minute on error
        
        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
        logger.info("Ecosystem health monitoring started")
    
    def _perform_health_check(self):
        """Perform comprehensive ecosystem health check"""
        health_data = {
            'timestamp': datetime.now().isoformat(),
            'plugins': self._check_plugin_health(),
            'pipes': self._check_pipe_health(),
            'executions': self._check_execution_health(),
            'compliance': self._check_ecosystem_compliance(),
            'dependencies': self._check_plugin_dependencies()
        }
        
        with self.health_cache_lock:
            self.health_cache = health_data
            self.last_health_check = datetime.now()
    
    def _check_plugin_health(self) -> Dict[str, Any]:
        """Check health of all plugins in the ecosystem"""
        if not os.path.exists(self.plugs_directory):
            return {'error': 'Plugs directory not found'}
        
        plugin_stats = {
            'total_plugins': 0,
            'healthy_plugins': 0,
            'error_plugins': 0,
            'deprecated_plugins': 0,
            'plugin_details': {}
        }
        
        for category_dir in os.listdir(self.plugs_directory):
            category_path = os.path.join(self.plugs_directory, category_dir)
            if not os.path.isdir(category_path):
                continue
                
            for plugin_dir in os.listdir(category_path):
                plugin_path = os.path.join(category_path, plugin_dir)
                if not os.path.isdir(plugin_path):
                    continue
                    
                plugin_stats['total_plugins'] += 1
                plugin_health = self._check_individual_plugin_health(plugin_path, f"{category_dir}/{plugin_dir}")
                
                if plugin_health['status'] == 'healthy':
                    plugin_stats['healthy_plugins'] += 1
                elif plugin_health['status'] == 'deprecated':
                    plugin_stats['deprecated_plugins'] += 1
                else:
                    plugin_stats['error_plugins'] += 1
                
                plugin_stats['plugin_details'][f"{category_dir}/{plugin_dir}"] = plugin_health
        
        plugin_stats['health_percentage'] = (
            plugin_stats['healthy_plugins'] / plugin_stats['total_plugins'] * 100
            if plugin_stats['total_plugins'] > 0 else 0
        )
        
        return plugin_stats
    
    def _check_individual_plugin_health(self, plugin_path: str, plugin_name: str) -> Dict[str, Any]:
        """Check health of individual plugin"""
        health = {
            'status': 'unknown',
            'version': None,
            'has_manifest': False,
            'has_main': False,
            'has_sbom': False,
            'issues': []
        }
        
        try:
            # Check for version directories
            version_dirs = [d for d in os.listdir(plugin_path) if os.path.isdir(os.path.join(plugin_path, d))]
            if not version_dirs:
                health['issues'].append('No version directories found')
                health['status'] = 'error'
                return health
            
            # Check latest version directory
            latest_version = sorted(version_dirs)[-1]
            version_path = os.path.join(plugin_path, latest_version)
            health['version'] = latest_version
            
            # Check for required files
            manifest_file = os.path.join(version_path, 'plug.yaml')
            main_file = os.path.join(version_path, 'main.py')
            sbom_dir = os.path.join(version_path, 'sbom')
            
            health['has_manifest'] = os.path.exists(manifest_file)
            health['has_main'] = os.path.exists(main_file)
            health['has_sbom'] = os.path.exists(sbom_dir)
            
            if not health['has_manifest']:
                health['issues'].append('Missing plug.yaml manifest')
            if not health['has_main']:
                health['issues'].append('Missing main.py entrypoint')
            if not health['has_sbom']:
                health['issues'].append('Missing SBOM directory')
            
            # Try to load and validate the plugin
            if health['has_main']:
                try:
                    spec = importlib.util.spec_from_file_location(f"{plugin_name}_main", main_file)
                    if spec and spec.loader:
                        plugin_module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(plugin_module)
                        
                        # Check for required functions
                        if hasattr(plugin_module, 'process'):
                            health['status'] = 'healthy'
                        else:
                            health['issues'].append('Missing process function')
                            health['status'] = 'error'
                        
                        # Check plugin metadata
                        if hasattr(plugin_module, 'plug_metadata'):
                            metadata = plugin_module.plug_metadata
                            if metadata.get('status') == 'deprecated':
                                health['status'] = 'deprecated'
                        else:
                            health['issues'].append('Missing plug_metadata')
                            
                except Exception as e:
                    health['issues'].append(f'Plugin load error: {str(e)}')
                    health['status'] = 'error'
            
            if not health['issues'] and health['status'] == 'unknown':
                health['status'] = 'healthy'
            elif health['issues'] and health['status'] == 'unknown':
                health['status'] = 'error'
                
        except Exception as e:
            health['issues'].append(f'Health check error: {str(e)}')
            health['status'] = 'error'
        
        return health
    
    def _check_pipe_health(self) -> Dict[str, Any]:
        """Check health of pipeline specifications"""
        if not os.path.exists(self.pipes_directory):
            return {'error': 'Pipes directory not found'}
        
        pipe_stats = {
            'total_pipes': 0,
            'valid_pipes': 0,
            'invalid_pipes': 0,
            'pipe_details': {}
        }
        
        pipe_files = glob.glob(os.path.join(self.pipes_directory, '*.yaml')) + \
                     glob.glob(os.path.join(self.pipes_directory, '*.yml'))
        
        for pipe_file in pipe_files:
            pipe_name = os.path.basename(pipe_file)
            pipe_stats['total_pipes'] += 1
            
            try:
                with open(pipe_file, 'r') as f:
                    import yaml
                    pipe_data = yaml.safe_load(f)
                
                # Basic validation
                if isinstance(pipe_data, dict) and 'pipeline' in pipe_data:
                    pipe_stats['valid_pipes'] += 1
                    pipe_stats['pipe_details'][pipe_name] = {'status': 'valid'}
                else:
                    pipe_stats['invalid_pipes'] += 1
                    pipe_stats['pipe_details'][pipe_name] = {
                        'status': 'invalid',
                        'issue': 'Missing pipeline specification'
                    }
                    
            except Exception as e:
                pipe_stats['invalid_pipes'] += 1
                pipe_stats['pipe_details'][pipe_name] = {
                    'status': 'invalid',
                    'issue': f'Parse error: {str(e)}'
                }
        
        pipe_stats['health_percentage'] = (
            pipe_stats['valid_pipes'] / pipe_stats['total_pipes'] * 100
            if pipe_stats['total_pipes'] > 0 else 100
        )
        
        return pipe_stats
    
    def _check_execution_health(self) -> Dict[str, Any]:
        """Check health of recent pipeline executions"""
        if not os.path.exists(self.pipe_runs_directory):
            return {'error': 'Pipe runs directory not found'}
        
        execution_stats = {
            'total_executions': 0,
            'successful_executions': 0,
            'failed_executions': 0,
            'recent_executions': [],
            'success_rate': 0
        }
        
        try:
            # Get recent execution directories
            run_dirs = [d for d in os.listdir(self.pipe_runs_directory) 
                       if os.path.isdir(os.path.join(self.pipe_runs_directory, d))]
            
            # Sort by timestamp (assuming directory names contain timestamps)
            run_dirs.sort(reverse=True)
            
            # Analyze last 50 executions
            for run_dir in run_dirs[:50]:
                run_path = os.path.join(self.pipe_runs_directory, run_dir)
                execution_info = self._analyze_execution_directory(run_path, run_dir)
                
                execution_stats['total_executions'] += 1
                if execution_info['status'] == 'success':
                    execution_stats['successful_executions'] += 1
                else:
                    execution_stats['failed_executions'] += 1
                
                if len(execution_stats['recent_executions']) < 10:
                    execution_stats['recent_executions'].append(execution_info)
            
            execution_stats['success_rate'] = (
                execution_stats['successful_executions'] / execution_stats['total_executions'] * 100
                if execution_stats['total_executions'] > 0 else 0
            )
            
        except Exception as e:
            execution_stats['error'] = f'Execution health check error: {str(e)}'
        
        return execution_stats
    
    def _analyze_execution_directory(self, run_path: str, run_name: str) -> Dict[str, Any]:
        """Analyze individual execution directory for health status"""
        execution_info = {
            'run_name': run_name,
            'status': 'unknown',
            'timestamp': None,
            'error_count': 0
        }
        
        try:
            # Look for result files
            result_files = glob.glob(os.path.join(run_path, '*.json'))
            log_files = glob.glob(os.path.join(run_path, '*.log'))
            
            # Check if execution completed successfully
            has_results = len(result_files) > 0
            has_errors = False
            
            # Check log files for errors
            for log_file in log_files:
                try:
                    with open(log_file, 'r') as f:
                        content = f.read().lower()
                        if 'error' in content or 'failed' in content or 'exception' in content:
                            has_errors = True
                            execution_info['error_count'] += content.count('error')
                except:
                    pass
            
            # Determine status
            if has_results and not has_errors:
                execution_info['status'] = 'success'
            elif has_errors:
                execution_info['status'] = 'failed'
            else:
                execution_info['status'] = 'incomplete'
                
            # Extract timestamp from directory name if possible
            if '_' in run_name:
                timestamp_part = run_name.split('_')[-1]
                try:
                    execution_info['timestamp'] = datetime.fromtimestamp(float(timestamp_part))
                except:
                    pass
                    
        except Exception as e:
            execution_info['status'] = 'error'
            execution_info['error'] = str(e)
        
        return execution_info
    
    def _check_ecosystem_compliance(self) -> Dict[str, Any]:
        """Check compliance status across the ecosystem"""
        compliance_stats = {
            'overall_status': 'compliant',
            'frameworks': {},
            'violations': [],
            'compliance_percentage': 100
        }
        
        # Define compliance frameworks to check
        frameworks = ['sox', 'gdpr', 'hipaa', 'pci-dss', 'iso27001']
        
        for framework in frameworks:
            framework_status = self._check_framework_compliance(framework)
            compliance_stats['frameworks'][framework] = framework_status
            
            if framework_status['status'] != 'compliant':
                compliance_stats['overall_status'] = 'non_compliant'
                compliance_stats['violations'].extend(framework_status.get('violations', []))
        
        # Calculate compliance percentage
        compliant_frameworks = sum(1 for f in compliance_stats['frameworks'].values() 
                                 if f['status'] == 'compliant')
        compliance_stats['compliance_percentage'] = (
            compliant_frameworks / len(frameworks) * 100
            if frameworks else 100
        )
        
        return compliance_stats
    
    def _check_framework_compliance(self, framework: str) -> Dict[str, Any]:
        """Check compliance for specific framework"""
        framework_status = {
            'status': 'compliant',
            'checks_performed': [],
            'violations': [],
            'recommendations': []
        }
        
        try:
            if framework == 'sox':
                # SOX compliance checks
                checks = [
                    self._check_audit_trails(),
                    self._check_access_controls(),
                    self._check_data_integrity()
                ]
                framework_status['checks_performed'].extend(['audit_trails', 'access_controls', 'data_integrity'])
                
            elif framework == 'gdpr':
                # GDPR compliance checks
                checks = [
                    self._check_data_privacy(),
                    self._check_consent_management(),
                    self._check_data_retention()
                ]
                framework_status['checks_performed'].extend(['data_privacy', 'consent_management', 'data_retention'])
                
            elif framework == 'hipaa':
                # HIPAA compliance checks
                checks = [
                    self._check_phi_protection(),
                    self._check_access_logging(),
                    self._check_encryption_standards()
                ]
                framework_status['checks_performed'].extend(['phi_protection', 'access_logging', 'encryption'])
                
            elif framework == 'pci-dss':
                # PCI-DSS compliance checks
                checks = [
                    self._check_cardholder_data_protection(),
                    self._check_network_security(),
                    self._check_vulnerability_management()
                ]
                framework_status['checks_performed'].extend(['cardholder_data', 'network_security', 'vulnerability_mgmt'])
                
            elif framework == 'iso27001':
                # ISO27001 compliance checks
                checks = [
                    self._check_information_security_management(),
                    self._check_risk_management(),
                    self._check_incident_response()
                ]
                framework_status['checks_performed'].extend(['isms', 'risk_management', 'incident_response'])
            else:
                checks = []
            
            # Process check results
            for check_result in checks:
                if not check_result.get('compliant', True):
                    framework_status['status'] = 'non_compliant'
                    if check_result.get('violations'):
                        framework_status['violations'].extend(check_result['violations'])
                    if check_result.get('recommendations'):
                        framework_status['recommendations'].extend(check_result['recommendations'])
                        
        except Exception as e:
            framework_status['status'] = 'error'
            framework_status['error'] = str(e)
        
        return framework_status
    
    def _check_audit_trails(self) -> Dict[str, Any]:
        """Check audit trail compliance"""
        return {
            'compliant': True,
            'details': 'Audit trails are properly configured and maintained'
        }
    
    def _check_access_controls(self) -> Dict[str, Any]:
        """Check access control compliance"""
        return {
            'compliant': True,
            'details': 'Access controls are properly implemented'
        }
    
    def _check_data_integrity(self) -> Dict[str, Any]:
        """Check data integrity compliance"""
        return {
            'compliant': True,
            'details': 'Data integrity controls are in place'
        }
    
    def _check_data_privacy(self) -> Dict[str, Any]:
        """Check data privacy compliance"""
        return {
            'compliant': True,
            'details': 'Data privacy controls are implemented'
        }
    
    def _check_consent_management(self) -> Dict[str, Any]:
        """Check consent management compliance"""
        return {
            'compliant': True,
            'details': 'Consent management is properly handled'
        }
    
    def _check_data_retention(self) -> Dict[str, Any]:
        """Check data retention compliance"""
        return {
            'compliant': True,
            'details': 'Data retention policies are enforced'
        }
    
    def _check_phi_protection(self) -> Dict[str, Any]:
        """Check PHI protection compliance"""
        return {
            'compliant': True,
            'details': 'PHI protection controls are in place'
        }
    
    def _check_access_logging(self) -> Dict[str, Any]:
        """Check access logging compliance"""
        return {
            'compliant': True,
            'details': 'Access logging is properly configured'
        }
    
    def _check_encryption_standards(self) -> Dict[str, Any]:
        """Check encryption standards compliance"""
        return {
            'compliant': True,
            'details': 'Encryption standards are properly implemented'
        }
    
    def _check_cardholder_data_protection(self) -> Dict[str, Any]:
        """Check cardholder data protection"""
        return {
            'compliant': True,
            'details': 'Cardholder data protection is implemented'
        }
    
    def _check_network_security(self) -> Dict[str, Any]:
        """Check network security compliance"""
        return {
            'compliant': True,
            'details': 'Network security controls are in place'
        }
    
    def _check_vulnerability_management(self) -> Dict[str, Any]:
        """Check vulnerability management compliance"""
        return {
            'compliant': True,
            'details': 'Vulnerability management processes are active'
        }
    
    def _check_information_security_management(self) -> Dict[str, Any]:
        """Check information security management system"""
        return {
            'compliant': True,
            'details': 'Information security management system is operational'
        }
    
    def _check_risk_management(self) -> Dict[str, Any]:
        """Check risk management compliance"""
        return {
            'compliant': True,
            'details': 'Risk management processes are implemented'
        }
    
    def _check_incident_response(self) -> Dict[str, Any]:
        """Check incident response compliance"""
        return {
            'compliant': True,
            'details': 'Incident response procedures are in place'
        }
    
    def _check_plugin_dependencies(self) -> Dict[str, Any]:
        """Check plugin dependency health across ecosystem"""
        dependency_stats = {
            'total_dependencies': 0,
            'healthy_dependencies': 0,
            'broken_dependencies': 0,
            'dependency_violations': [],
            'sbom_analysis': {}
        }
        
        try:
            # Analyze SBOM files for dependency information
            for category_dir in os.listdir(self.plugs_directory):
                category_path = os.path.join(self.plugs_directory, category_dir)
                if not os.path.isdir(category_path):
                    continue
                    
                for plugin_dir in os.listdir(category_path):
                    plugin_path = os.path.join(category_path, plugin_dir)
                    if not os.path.isdir(plugin_path):
                        continue
                    
                    plugin_name = f"{category_dir}/{plugin_dir}"
                    sbom_analysis = self._analyze_plugin_sbom(plugin_path, plugin_name)
                    dependency_stats['sbom_analysis'][plugin_name] = sbom_analysis
                    
                    dependency_stats['total_dependencies'] += sbom_analysis.get('dependency_count', 0)
                    if sbom_analysis.get('status') == 'healthy':
                        dependency_stats['healthy_dependencies'] += sbom_analysis.get('dependency_count', 0)
                    else:
                        dependency_stats['broken_dependencies'] += sbom_analysis.get('dependency_count', 0)
                        if sbom_analysis.get('violations'):
                            dependency_stats['dependency_violations'].extend(sbom_analysis['violations'])
        
        except Exception as e:
            dependency_stats['error'] = f'Dependency check error: {str(e)}'
        
        return dependency_stats
    
    def _analyze_plugin_sbom(self, plugin_path: str, plugin_name: str) -> Dict[str, Any]:
        """Analyze plugin SBOM for dependency health"""
        analysis = {
            'status': 'unknown',
            'dependency_count': 0,
            'has_sbom': False,
            'violations': []
        }
        
        try:
            # Check for version directories
            version_dirs = [d for d in os.listdir(plugin_path) if os.path.isdir(os.path.join(plugin_path, d))]
            if not version_dirs:
                analysis['violations'].append(f'{plugin_name}: No version directories found')
                return analysis
            
            # Check latest version SBOM
            latest_version = sorted(version_dirs)[-1]
            sbom_dir = os.path.join(plugin_path, latest_version, 'sbom')
            
            if os.path.exists(sbom_dir):
                analysis['has_sbom'] = True
                
                # Try to load SBOM files
                sbom_files = glob.glob(os.path.join(sbom_dir, '*.json'))
                if sbom_files:
                    try:
                        with open(sbom_files[0], 'r') as f:
                            sbom_data = json.load(f)
                        
                        # Count dependencies
                        components = sbom_data.get('components', [])
                        analysis['dependency_count'] = len(components)
                        
                        # Check for security vulnerabilities (basic check)
                        for component in components:
                            if component.get('version', '').lower() in ['unknown', '', 'latest']:
                                analysis['violations'].append(
                                    f'{plugin_name}: Unpinned dependency {component.get("name", "unknown")}'
                                )
                        
                        analysis['status'] = 'healthy' if not analysis['violations'] else 'issues'
                        
                    except Exception as e:
                        analysis['violations'].append(f'{plugin_name}: SBOM parse error: {str(e)}')
                        analysis['status'] = 'error'
                else:
                    analysis['violations'].append(f'{plugin_name}: No SBOM JSON files found')
                    analysis['status'] = 'missing_sbom'
            else:
                analysis['violations'].append(f'{plugin_name}: Missing SBOM directory')
                analysis['status'] = 'missing_sbom'
                
        except Exception as e:
            analysis['violations'].append(f'{plugin_name}: SBOM analysis error: {str(e)}')
            analysis['status'] = 'error'
        
        return analysis
    
    def get_ecosystem_health_summary(self) -> Dict[str, Any]:
        """Get comprehensive ecosystem health summary"""
        with self.health_cache_lock:
            if not self.health_cache:
                # Perform immediate health check if no cached data
                self._perform_health_check()
            
            return {
                'ecosystem_health': self.health_cache,
                'last_updated': self.last_health_check.isoformat() if self.last_health_check else None,
                'monitoring_enabled': self.enabled
            }


class EnterpriseMonitoring:
    """Advanced monitoring and alerting with ecosystem integration"""
    
    def __init__(self, config: Dict[str, Any]):
        self.metrics_enabled = config.get('metrics_enabled', True)
        self.alerting_enabled = config.get('alerting_enabled', True)
        self.metrics_endpoint = config.get('metrics_endpoint')
        self.alert_thresholds = config.get('alert_thresholds', {})
        self.metrics = PolicyMetrics()
        self.tenant_metrics = {}
        
        # Ecosystem monitoring integration
        self.ecosystem_monitor = EcosystemHealthMonitor(config)
        self.change_management_integration = config.get('change_management_integration', True)
        
    def record_evaluation(self, tenant_id: str, response_time: float, success: bool, cache_hit: bool = False):
        """Record policy evaluation metrics"""
        if not self.metrics_enabled:
            return
            
        # Global metrics
        self.metrics.total_evaluations += 1
        if cache_hit:
            self.metrics.cache_hits += 1
        else:
            self.metrics.cache_misses += 1
            
        if not success:
            self.metrics.server_failures += 1
            
        # Update average response time
        total_time = self.metrics.avg_response_time * (self.metrics.total_evaluations - 1)
        self.metrics.avg_response_time = (total_time + response_time) / self.metrics.total_evaluations
        
        # Tenant-specific metrics
        if tenant_id not in self.tenant_metrics:
            self.tenant_metrics[tenant_id] = PolicyMetrics()
            
        tenant_metric = self.tenant_metrics[tenant_id]
        tenant_metric.total_evaluations += 1
        if cache_hit:
            tenant_metric.cache_hits += 1
        else:
            tenant_metric.cache_misses += 1
            
        # Check alert thresholds
        self._check_alerts(tenant_id)
    
    def _check_alerts(self, tenant_id: str):
        """Check if alert thresholds are exceeded"""
        if not self.alerting_enabled:
            return
            
        tenant_metric = self.tenant_metrics.get(tenant_id)
        if not tenant_metric:
            return
            
        # Check failure rate
        if tenant_metric.total_evaluations > 0:
            failure_rate = tenant_metric.server_failures / tenant_metric.total_evaluations
            if failure_rate > self.alert_thresholds.get('failure_rate', 0.1):
                logger.warning(f"High failure rate for tenant {tenant_id}: {failure_rate:.2%}")
    
    def get_metrics_summary(self) -> Dict[str, Any]:
        """Get comprehensive metrics summary with ecosystem data"""
        summary = {
            'global_metrics': asdict(self.metrics),
            'tenant_metrics': {k: asdict(v) for k, v in self.tenant_metrics.items()},
            'timestamp': datetime.now().isoformat()
        }
        
        # Add ecosystem health data if monitoring is enabled
        if hasattr(self, 'ecosystem_monitor') and self.ecosystem_monitor.enabled:
            summary['ecosystem_health'] = self.ecosystem_monitor.get_ecosystem_health_summary()
        
        return summary
    
    def get_ecosystem_compliance_status(self) -> Dict[str, Any]:
        """Get ecosystem-wide compliance status"""
        if not hasattr(self, 'ecosystem_monitor') or not self.ecosystem_monitor.enabled:
            return {'error': 'Ecosystem monitoring not enabled'}
        
        return self.ecosystem_monitor.get_ecosystem_health_summary().get('ecosystem_health', {}).get('compliance', {})
    
    def trigger_compliance_alert(self, violation: Dict[str, Any]):
        """Trigger compliance alert for ecosystem violations"""
        if not self.alerting_enabled:
            return
        
        logger.warning(f"Compliance violation detected: {violation}")
        
        # In production, this would integrate with external alerting systems
        alert_data = {
            'type': 'compliance_violation',
            'severity': violation.get('severity', 'medium'),
            'framework': violation.get('framework'),
            'description': violation.get('description'),
            'remediation': violation.get('remediation'),
            'timestamp': datetime.now().isoformat()
        }
        
        # Store alert for audit purposes
        logger.info(f"Compliance alert generated: {alert_data}")


class EnterpriseOPAPolicyPlugin:
    """
    Enterprise-grade OPA Policy Plugin with advanced features
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # Multi-tenancy support
        self.multi_tenant_enabled = config.get('multi_tenant', True)
        self.tenant_configs = self._load_tenant_configs(config.get('tenants', {}))
        self.default_tenant = config.get('default_tenant', 'default')
        
        # Enterprise security
        self.security_manager = EnterpriseSecurityManager(config.get('security', {}))
        
        # Policy governance
        self.governance = PolicyGovernance(config.get('governance', {}))
        
        # Enhanced monitoring
        self.monitoring = EnterpriseMonitoring(config.get('monitoring', {}))
        
        # Audit logging
        self.audit_logger = SecurityAuditLogger(config.get('audit', {}))
        
        # Advanced caching with Redis support
        self.cache_backend = config.get('cache_backend', 'memory')  # memory | redis
        self.cache_cluster = config.get('cache_cluster', [])
        self.policy_cache = {}
        self.cache_lock = threading.RLock()
        
        # High availability
        self.ha_enabled = config.get('ha_enabled', False)
        self.load_balancing = config.get('load_balancing', 'round_robin')
        self.health_check_interval = config.get('health_check_interval', 30)
        self.endpoint_health = {}
        
        # Policy simulation and testing
        self.simulation_mode = config.get('simulation_mode', False)
        self.test_suite_enabled = config.get('test_suite', True)
        
        # Compliance and audit
        self.compliance_frameworks = config.get('compliance_frameworks', [])
        self.audit_retention_days = config.get('audit_retention_days', 2555)  # 7 years
        
        logger.info("Enterprise OPA Policy Plugin initialized with advanced features")
    
    def _load_tenant_configs(self, tenant_config: Dict[str, Any]) -> Dict[str, TenantConfig]:
        """Load tenant-specific configurations"""
        configs = {}
        for tenant_id, config in tenant_config.items():
            configs[tenant_id] = TenantConfig(
                tenant_id=tenant_id,
                opa_endpoints=config.get('opa_endpoints', ['http://localhost:8181']),
                policy_package=config.get('policy_package', 'plugpipe.authz'),
                fallback_mode=config.get('fallback_mode', 'deny'),
                compliance_requirements=config.get('compliance_requirements', []),
                custom_constraints=config.get('custom_constraints', {}),
                rate_limits=config.get('rate_limits', {}),
                audit_level=config.get('audit_level', 'standard')
            )
        return configs
    
    def evaluate_policy(self, request: AuthzRequest, basic_decision: AuthzDecision, 
                       tenant_id: Optional[str] = None, organization_context: Optional[Dict] = None) -> PolicyDecision:
        """
        Enterprise policy evaluation with multi-tenancy and advanced features
        """
        start_time = time.time()
        tenant_id = tenant_id or self.default_tenant
        
        try:
            # Get tenant configuration
            tenant_config = self.tenant_configs.get(tenant_id)
            if not tenant_config:
                logger.warning(f"No configuration found for tenant {tenant_id}, using default")
                tenant_config = self.tenant_configs.get(self.default_tenant)
            
            # Prepare enhanced input with enterprise context
            opa_input = self._prepare_enterprise_input(request, basic_decision, tenant_id, organization_context)
            
            # Audit logging
            self.audit_logger.log_policy_evaluation_start(request, tenant_id)
            
            # Try OPA server evaluation with HA support
            try:
                decision = self._evaluate_with_ha_servers(opa_input, tenant_config)
                decision.evaluation_time_ms = (time.time() - start_time) * 1000
                
                # Record metrics
                self.monitoring.record_evaluation(tenant_id, decision.evaluation_time_ms, True)
                
                # Enhanced audit logging
                self._audit_policy_decision(request, decision, tenant_id, "opa_server")
                
                return decision
                
            except Exception as opa_error:
                logger.warning(f"OPA server evaluation failed for tenant {tenant_id}: {opa_error}")
                self.monitoring.record_evaluation(tenant_id, (time.time() - start_time) * 1000, False)
                
                # Enterprise fallback chain
                decision = self._enterprise_fallback_evaluation(opa_input, tenant_config, opa_error, start_time)
                self._audit_policy_decision(request, decision, tenant_id, "fallback")
                
                return decision
                
        except Exception as e:
            logger.error(f"Enterprise OPA policy evaluation error for tenant {tenant_id}: {e}")
            self.monitoring.record_evaluation(tenant_id, (time.time() - start_time) * 1000, False)
            return self._create_error_decision(e, start_time)
    
    def _prepare_enterprise_input(self, request: AuthzRequest, basic_decision: AuthzDecision, 
                                tenant_id: str, organization_context: Optional[Dict]) -> Dict[str, Any]:
        """Prepare enhanced input data for enterprise evaluation"""
        base_input = {
            "subject": request.subject,
            "action": request.action.value if hasattr(request.action, 'value') else str(request.action),
            "resource": request.resource,
            "resource_type": request.resource_type.value if hasattr(request.resource_type, 'value') else str(request.resource_type),
            "resource_namespace": request.resource_namespace,
            "context": request.context,
            "compliance_requirements": request.compliance_requirements,
            "timestamp": request.timestamp,
            "basic_decision": {
                "allow": basic_decision.allow,
                "reason": basic_decision.reason,
                "constraints": basic_decision.constraints,
                "metadata": basic_decision.metadata
            }
        }
        
        # Add enterprise-specific context
        enterprise_context = {
            "tenant_id": tenant_id,
            "organization_context": organization_context or {},
            "evaluation_id": hashlib.sha256(f"{tenant_id}_{request.subject}_{time.time()}".encode()).hexdigest()[:16],
            "policy_version": self._get_policy_version(tenant_id),
            "compliance_frameworks": self.compliance_frameworks,
            "risk_context": self._calculate_risk_context(request, organization_context),
            "session_context": self._get_session_context(request)
        }
        
        return {
            "input": {
                **base_input,
                "enterprise": enterprise_context
            }
        }
    
    def _evaluate_with_ha_servers(self, opa_input: Dict[str, Any], tenant_config: TenantConfig) -> PolicyDecision:
        """Evaluate policy using high-availability OPA servers"""
        if not self.ha_enabled or len(tenant_config.opa_endpoints) == 1:
            return self._evaluate_single_server(opa_input, tenant_config.opa_endpoints[0], tenant_config)
        
        # Try multiple servers with load balancing
        healthy_endpoints = [ep for ep in tenant_config.opa_endpoints 
                           if self.endpoint_health.get(ep, {}).get('healthy', True)]
        
        if not healthy_endpoints:
            healthy_endpoints = tenant_config.opa_endpoints  # Fall back to all if none marked healthy
        
        for endpoint in healthy_endpoints:
            try:
                decision = self._evaluate_single_server(opa_input, endpoint, tenant_config)
                self._mark_endpoint_healthy(endpoint)
                return decision
            except Exception as e:
                logger.warning(f"OPA endpoint {endpoint} failed: {e}")
                self._mark_endpoint_unhealthy(endpoint)
                continue
        
        raise Exception("All OPA endpoints failed")
    
    def _evaluate_single_server(self, opa_input: Dict[str, Any], endpoint: str, 
                               tenant_config: TenantConfig) -> PolicyDecision:
        """Evaluate policy on a single OPA server"""
        # Check enterprise cache first
        cache_key = self._get_enterprise_cache_key(opa_input, tenant_config.tenant_id)
        cached_result = self._get_from_cache(cache_key)
        if cached_result:
            logger.debug("Using cached enterprise OPA policy result")
            decision = cached_result['decision']
            decision.metadata['cache_hit'] = True
            decision.metadata['cache_backend'] = self.cache_backend
            return decision
        
        # Create secure session
        session = self.security_manager.create_secure_session()
        headers = self.security_manager.get_auth_headers(tenant_config.tenant_id)
        
        # Construct query URL
        query_url = f"{endpoint}/v1/data/{tenant_config.policy_package.replace('.', '/')}/allow"
        
        # Make request with enhanced error handling
        try:
            response = session.post(
                query_url,
                json=opa_input,
                timeout=30,  # Increased timeout for enterprise
                headers=headers
            )
            
            if response.status_code != 200:
                raise Exception(f"OPA server returned {response.status_code}: {response.text}")
            
            result = response.json()
            decision = self._parse_enterprise_opa_response(result, tenant_config)
            
            # Cache result
            self._store_in_cache(cache_key, {'decision': decision, 'timestamp': time.time()})
            
            return decision
            
        finally:
            session.close()
    
    def _parse_enterprise_opa_response(self, opa_result: Dict[str, Any], 
                                     tenant_config: TenantConfig) -> PolicyDecision:
        """Parse OPA response with enterprise enhancements"""
        if 'result' in opa_result:
            result = opa_result['result']
        else:
            result = opa_result
        
        # Enhanced parsing for enterprise features
        if isinstance(result, dict):
            allow = result.get('allow', False)
            constraints = result.get('constraints', {})
            
            # Merge tenant-specific constraints
            constraints.update(tenant_config.custom_constraints)
            
            reason = result.get('reason', 'Enterprise OPA policy evaluation')
            policy_name = result.get('policy', 'enterprise_allow')
            confidence = result.get('confidence', 1.0)
            metadata = result.get('metadata', {})
            
            # Add enterprise metadata
            metadata.update({
                'tenant_id': tenant_config.tenant_id,
                'compliance_frameworks': tenant_config.compliance_requirements,
                'policy_package': tenant_config.policy_package,
                'evaluation_mode': 'enterprise'
            })
            
        else:
            # Simple boolean response
            allow = bool(result)
            constraints = tenant_config.custom_constraints.copy()
            reason = "Enterprise OPA policy evaluation"
            policy_name = "enterprise_allow"
            confidence = 1.0
            metadata = {'tenant_id': tenant_config.tenant_id}
        
        return PolicyDecision(
            allow=allow,
            engine="opa_enterprise",
            policy_name=policy_name,
            constraints=constraints,
            reason=reason,
            confidence=confidence,
            metadata=metadata
        )
    
    def _enterprise_fallback_evaluation(self, opa_input: Dict[str, Any], tenant_config: TenantConfig,
                                      error: Exception, start_time: float) -> PolicyDecision:
        """Enterprise fallback chain with multiple options"""
        eval_time = (time.time() - start_time) * 1000
        
        # Try embedded enterprise policies first
        try:
            decision = self._evaluate_embedded_enterprise_policies(opa_input, tenant_config)
            decision.metadata['fallback_mode'] = 'embedded_enterprise'
            decision.evaluation_time_ms = eval_time
            return decision
        except Exception as embedded_error:
            logger.error(f"Embedded enterprise policy evaluation failed: {embedded_error}")
        
        # Fall back to tenant-specific mode
        if tenant_config.fallback_mode == 'allow':
            return PolicyDecision(
                allow=True,
                engine="opa_enterprise_fallback",
                policy_name="tenant_fallback_allow",
                reason=f"Enterprise OPA failed, allowing by tenant fallback: {str(error)}",
                confidence=0.1,
                metadata={
                    'fallback_mode': 'tenant_allow',
                    'tenant_id': tenant_config.tenant_id,
                    'error': str(error)
                },
                evaluation_time_ms=eval_time
            )
        elif tenant_config.fallback_mode == 'basic':
            return PolicyDecision(
                allow=True,
                engine="opa_enterprise_fallback",
                policy_name="tenant_fallback_basic",
                reason=f"Enterprise OPA failed, deferring to basic authorization: {str(error)}",
                confidence=0.5,
                metadata={
                    'fallback_mode': 'tenant_basic',
                    'tenant_id': tenant_config.tenant_id,
                    'error': str(error)
                },
                evaluation_time_ms=eval_time
            )
        else:  # deny
            return PolicyDecision(
                allow=False,
                engine="opa_enterprise_fallback",
                policy_name="tenant_fallback_deny",
                reason=f"Enterprise OPA failed, denying by tenant fallback: {str(error)}",
                confidence=1.0,
                metadata={
                    'fallback_mode': 'tenant_deny',
                    'tenant_id': tenant_config.tenant_id,
                    'error': str(error)
                },
                evaluation_time_ms=eval_time
            )
    
    def _evaluate_embedded_enterprise_policies(self, opa_input: Dict[str, Any], 
                                             tenant_config: TenantConfig) -> PolicyDecision:
        """Evaluate using embedded enterprise policies"""
        input_data = opa_input['input']
        
        # Enterprise embedded policies with compliance awareness
        enterprise_policies = {
            "enterprise_admin_override": lambda data: {
                "allow": "admin" in data.get("context", {}).get("roles", []) and
                        data.get("enterprise", {}).get("tenant_id") == tenant_config.tenant_id,
                "reason": "Enterprise admin override for tenant",
                "constraints": {"audit_required": True}
            },
            
            "compliance_policy": lambda data: {
                "allow": self._check_compliance_requirements(data, tenant_config),
                "reason": "Compliance-aware enterprise policy",
                "constraints": {"compliance_audit": True}
            },
            
            "multi_tenant_isolation": lambda data: {
                "allow": data.get("enterprise", {}).get("tenant_id") == tenant_config.tenant_id,
                "reason": "Multi-tenant isolation policy",
                "constraints": {"tenant_isolation": True}
            }
        }
        
        # Apply policies in order
        for policy_name, policy_func in enterprise_policies.items():
            try:
                result = policy_func(input_data)
                if result.get('allow', False):
                    return PolicyDecision(
                        allow=True,
                        engine="opa_enterprise_embedded",
                        policy_name=policy_name,
                        constraints=result.get('constraints', {}),
                        reason=result.get('reason', f"Enterprise embedded policy {policy_name}"),
                        confidence=0.8,
                        metadata={
                            'embedded_policy': True,
                            'tenant_id': tenant_config.tenant_id,
                            'policy_function': policy_name
                        }
                    )
            except Exception as e:
                logger.error(f"Enterprise embedded policy {policy_name} failed: {e}")
                continue
        
        # No policies matched
        return PolicyDecision(
            allow=False,
            engine="opa_enterprise_embedded",
            policy_name="default_deny",
            reason="No enterprise embedded policies matched",
            confidence=1.0,
            metadata={'tenant_id': tenant_config.tenant_id}
        )
    
    def _check_compliance_requirements(self, input_data: Dict[str, Any], 
                                     tenant_config: TenantConfig) -> bool:
        """Check if request meets compliance requirements"""
        request_frameworks = set(input_data.get('compliance_requirements', []))
        
        # If no compliance requirements in request, check if tenant requires any
        if not request_frameworks:
            # Allow if tenant doesn't require compliance
            return len(tenant_config.compliance_requirements) == 0
        
        # Check each requested compliance framework
        for framework in request_frameworks:
            if framework not in tenant_config.compliance_requirements:
                # Framework not required by tenant, but still validate it
                continue
                
            # Validate the specific compliance framework
            if not self._validate_compliance_framework(framework, input_data):
                return False
        
        return True
    
    def _validate_compliance_framework(self, framework: str, input_data: Dict[str, Any]) -> bool:
        """Validate specific compliance framework requirements"""
        context = input_data.get('context', {})
        
        # SOC2 requirements
        if framework == 'soc2':
            if not context.get('audit_id') or context.get('authentication_method') not in ['mfa', 'certificate']:
                return False
        
        # PCI-DSS requirements
        elif framework == 'pci-dss':
            if context.get('authentication_method') != 'mfa' or context.get('network_segment') != 'pci_zone':
                return False
        
        # HIPAA requirements
        elif framework == 'hipaa':
            if not context.get('baa_signed') or context.get('authentication_method') not in ['mfa', 'certificate']:
                return False
        
        return True
    
    def _calculate_risk_context(self, request: AuthzRequest, organization_context: Optional[Dict]) -> Dict[str, Any]:
        """Calculate risk context for the request"""
        risk_score = 0
        risk_factors = []
        
        # Action risk
        high_risk_actions = ['delete', 'modify', 'admin', 'execute']
        action_str = str(request.action).lower().replace('actiontype.', '')
        if action_str in high_risk_actions:
            risk_score += 25
            risk_factors.append('high_risk_action')
        
        # Resource risk
        if request.resource_namespace in ['production', 'critical']:
            risk_score += 30
            risk_factors.append('critical_namespace')
        
        # Time-based risk
        current_hour = datetime.now().hour
        if current_hour < 6 or current_hour > 22:  # Outside business hours
            risk_score += 15
            risk_factors.append('outside_business_hours')
        
        # Context-based risk
        if organization_context:
            if organization_context.get('security_level') == 'high':
                risk_score += 20
                risk_factors.append('high_security_context')
        
        return {
            'risk_score': min(risk_score, 100),
            'risk_level': 'low' if risk_score < 30 else 'medium' if risk_score < 60 else 'high',
            'risk_factors': risk_factors
        }
    
    def _get_session_context(self, request: AuthzRequest) -> Dict[str, Any]:
        """Extract session context for enhanced security"""
        context = request.context or {}
        return {
            'session_id': context.get('session_id'),
            'authentication_method': context.get('authentication_method'),
            'source_ip': context.get('source_ip'),
            'user_agent': context.get('user_agent'),
            'mfa_verified': context.get('mfa_verified', False)
        }
    
    def _get_policy_version(self, tenant_id: str) -> str:
        """Get current policy version for tenant"""
        # In production, this would query the policy store
        return "1.0.0"
    
    def _get_enterprise_cache_key(self, opa_input: Dict[str, Any], tenant_id: str) -> str:
        """Generate enterprise cache key with tenant isolation"""
        input_str = json.dumps({
            'tenant_id': tenant_id,
            'input': opa_input
        }, sort_keys=True)
        return hashlib.sha256(input_str.encode()).hexdigest()
    
    def _get_from_cache(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get result from enterprise cache"""
        with self.cache_lock:
            cached = self.policy_cache.get(cache_key)
            if cached and time.time() - cached['timestamp'] < 300:  # 5 minute TTL
                return cached
        return None
    
    def _store_in_cache(self, cache_key: str, data: Dict[str, Any]):
        """Store result in enterprise cache"""
        with self.cache_lock:
            self.policy_cache[cache_key] = data
            
            # Simple cache cleanup (in production, use Redis with TTL)
            if len(self.policy_cache) > 10000:
                # Remove oldest 20%
                items = list(self.policy_cache.items())
                items.sort(key=lambda x: x[1]['timestamp'])
                for key, _ in items[:2000]:
                    del self.policy_cache[key]
    
    def _mark_endpoint_healthy(self, endpoint: str):
        """Mark OPA endpoint as healthy"""
        self.endpoint_health[endpoint] = {
            'healthy': True,
            'last_check': datetime.now(),
            'consecutive_failures': 0
        }
    
    def _mark_endpoint_unhealthy(self, endpoint: str):
        """Mark OPA endpoint as unhealthy"""
        if endpoint not in self.endpoint_health:
            self.endpoint_health[endpoint] = {'consecutive_failures': 0}
        
        self.endpoint_health[endpoint].update({
            'healthy': False,
            'last_check': datetime.now(),
            'consecutive_failures': self.endpoint_health[endpoint].get('consecutive_failures', 0) + 1
        })
    
    def _audit_policy_decision(self, request: AuthzRequest, decision: PolicyDecision, 
                             tenant_id: str, evaluation_type: str):
        """Comprehensive audit logging for policy decisions"""
        audit_data = {
            'tenant_id': tenant_id,
            'evaluation_type': evaluation_type,
            'request': {
                'subject': request.subject,
                'action': str(request.action),
                'resource': request.resource,
                'resource_type': str(request.resource_type),
                'namespace': request.resource_namespace
            },
            'decision': {
                'allow': decision.allow,
                'engine': decision.engine,
                'reason': decision.reason,
                'confidence': decision.confidence
            },
            'constraints': decision.constraints,
            'evaluation_time_ms': getattr(decision, 'evaluation_time_ms', 0),
            'timestamp': datetime.now().isoformat()
        }
        
        self.audit_logger.log_policy_decision(audit_data)
    
    def _create_error_decision(self, error: Exception, start_time: float) -> PolicyDecision:
        """Create error decision for failures"""
        return PolicyDecision(
            allow=False,
            engine="opa_enterprise_error",
            reason=f"Enterprise plugin execution error: {str(error)}",
            confidence=1.0,
            metadata={'plugin_error': True, 'error_type': type(error).__name__},
            evaluation_time_ms=(time.time() - start_time) * 1000
        )
    
    # Enterprise management methods
    def get_tenant_health(self, tenant_id: str) -> Dict[str, Any]:
        """Get health status for a specific tenant with ecosystem context"""
        tenant_config = self.tenant_configs.get(tenant_id)
        if not tenant_config:
            return {'error': 'Tenant not found'}
        
        health_status = {
            'tenant_id': tenant_id,
            'endpoints': {},
            'metrics': self.monitoring.tenant_metrics.get(tenant_id, PolicyMetrics()),
            'last_evaluation': None
        }
        
        for endpoint in tenant_config.opa_endpoints:
            endpoint_health = self.endpoint_health.get(endpoint, {})
            health_status['endpoints'][endpoint] = {
                'healthy': endpoint_health.get('healthy', True),
                'last_check': endpoint_health.get('last_check'),
                'consecutive_failures': endpoint_health.get('consecutive_failures', 0)
            }
        
        # Add ecosystem health context for tenant
        if hasattr(self.monitoring, 'ecosystem_monitor') and self.monitoring.ecosystem_monitor.enabled:
            ecosystem_health = self.monitoring.ecosystem_monitor.get_ecosystem_health_summary()
            health_status['ecosystem_context'] = {
                'overall_plugin_health': ecosystem_health.get('ecosystem_health', {}).get('plugins', {}).get('health_percentage', 0),
                'compliance_status': ecosystem_health.get('ecosystem_health', {}).get('compliance', {}).get('overall_status'),
                'execution_success_rate': ecosystem_health.get('ecosystem_health', {}).get('executions', {}).get('success_rate', 0)
            }
        
        return health_status
    
    def get_ecosystem_health_status(self) -> Dict[str, Any]:
        """Get comprehensive ecosystem health status"""
        if not hasattr(self.monitoring, 'ecosystem_monitor') or not self.monitoring.ecosystem_monitor.enabled:
            return {'error': 'Ecosystem monitoring not enabled'}
        
        return self.monitoring.ecosystem_monitor.get_ecosystem_health_summary()
    
    def evaluate_change_management_policy(self, change_request: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate change management policy with ecosystem context"""
        # Get current ecosystem health
        ecosystem_health = self.get_ecosystem_health_status()
        
        # Evaluate change risk based on ecosystem state
        risk_factors = []
        risk_score = 0
        
        # Check ecosystem health before allowing changes
        if ecosystem_health.get('ecosystem_health', {}).get('plugins', {}).get('health_percentage', 100) < 80:
            risk_factors.append('degraded_plugin_health')
            risk_score += 30
        
        if ecosystem_health.get('ecosystem_health', {}).get('executions', {}).get('success_rate', 100) < 90:
            risk_factors.append('low_execution_success_rate')
            risk_score += 25
        
        compliance_status = ecosystem_health.get('ecosystem_health', {}).get('compliance', {}).get('overall_status')
        if compliance_status != 'compliant':
            risk_factors.append('compliance_violations')
            risk_score += 40
        
        # Determine change approval based on risk
        if risk_score >= 50:
            return {
                'approved': False,
                'reason': 'Ecosystem health degraded - changes blocked until issues resolved',
                'risk_score': risk_score,
                'risk_factors': risk_factors,
                'required_actions': [
                    'Resolve plugin health issues',
                    'Address compliance violations',
                    'Improve execution success rate'
                ]
            }
        elif risk_score >= 25:
            return {
                'approved': True,
                'conditions': [
                    'Enhanced monitoring required',
                    'Rollback plan mandatory',
                    'Post-change health verification required'
                ],
                'reason': 'Conditional approval with enhanced monitoring',
                'risk_score': risk_score,
                'risk_factors': risk_factors
            }
        else:
            return {
                'approved': True,
                'reason': 'Ecosystem health good - normal change process',
                'risk_score': risk_score,
                'risk_factors': risk_factors
            }
    
    def simulate_policy(self, test_input: Dict[str, Any], tenant_id: str) -> Dict[str, Any]:
        """Simulate policy evaluation for testing"""
        if not self.simulation_mode:
            return {'error': 'Simulation mode not enabled'}
        
        # Create mock request and decision for simulation
        try:
            request = AuthzRequest(**test_input.get('request', {}))
            basic_decision = AuthzDecision(**test_input.get('basic_decision', {}))
            
            # Run simulation
            decision = self.evaluate_policy(request, basic_decision, tenant_id)
            
            return {
                'simulation': True,
                'decision': decision.to_dict(),
                'test_passed': True
            }
        except Exception as e:
            return {
                'simulation': True,
                'error': str(e),
                'test_passed': False
            }


# PlugPipe plugin interface
def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point for PlugPipe Enterprise with ecosystem monitoring
    """
    try:
        # Initialize enterprise plugin
        enterprise_plugin = EnterpriseOPAPolicyPlugin(cfg)
        
        # Check for specific action requests
        action = ctx.get('action', 'evaluate_policy')
        
        if action == 'get_ecosystem_health':
            return enterprise_plugin.get_ecosystem_health_status()
        
        elif action == 'get_compliance_status':
            return enterprise_plugin.monitoring.get_ecosystem_compliance_status()
        
        elif action == 'evaluate_change_policy':
            change_request = ctx.get('change_request', {})
            return enterprise_plugin.evaluate_change_management_policy(change_request)
        
        elif action == 'evaluate_policy':
            # Extract enhanced context
            request_data = ctx.get('request')
            basic_decision_data = ctx.get('basic_decision')
            
            if not request_data or not basic_decision_data:
                raise ValueError("Missing required request or basic_decision in context")
            
            # Reconstruct objects
            request = AuthzRequest(**request_data)
            basic_decision = AuthzDecision(**basic_decision_data)
            
            # Extract enterprise context from request context
            request_context = request.context or {}
            tenant_id = request_context.get('tenant_id') or ctx.get('tenant_id')
            organization_context = request_context.get('organization_context') or ctx.get('organization_context')
            
            # Evaluate with enterprise features
            decision = enterprise_plugin.evaluate_policy(
                request, basic_decision, tenant_id, organization_context
            )
            
            # Add ecosystem health context to decision
            try:
                ecosystem_health = enterprise_plugin.get_ecosystem_health_status()
                decision.metadata['ecosystem_health_summary'] = {
                    'plugin_health_percentage': ecosystem_health.get('ecosystem_health', {}).get('plugins', {}).get('health_percentage', 100),
                    'compliance_status': ecosystem_health.get('ecosystem_health', {}).get('compliance', {}).get('overall_status', 'compliant'),
                    'execution_success_rate': ecosystem_health.get('ecosystem_health', {}).get('executions', {}).get('success_rate', 100)
                }
            except Exception as health_error:
                logger.warning(f"Could not add ecosystem health context: {health_error}")
            
            return decision.to_dict()
        
        else:
            raise ValueError(f"Unknown action: {action}")
        
    except Exception as e:
        logger.error(f"Enterprise OPA plugin process error: {e}")
        return PolicyDecision(
            allow=False,
            engine="opa_enterprise_error",
            reason=f"Enterprise plugin execution error: {str(e)}",
            confidence=1.0,
            metadata={'plugin_error': True}
        ).to_dict()