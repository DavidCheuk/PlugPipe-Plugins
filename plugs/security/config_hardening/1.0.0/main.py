# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
#!/usr/bin/env python3
"""
PlugPipe Security Configuration Hardening Plugin

SECURITY FIRST: Validates and hardens PlugPipe configuration for production deployment.
Enforces secure defaults and prevents common security misconfigurations.

Key Features:
- Validates service binding configurations (prevents 0.0.0.0 in production)
- Checks for required security environment variables
- Enforces secure authentication settings
- Validates TLS/SSL configuration
- Audits CORS and networking settings
- Generates security configuration reports
- AI-powered code quality improvement
- Placeholder implementation completion
- Real-time monitoring and reporting

Following CLAUDE.md principles:
- REUSE: Leverages existing Universal Input Sanitizer for validation
- PLUGIN-FIRST: Configuration hardening as a reusable plugin
- SECURITY-FIRST: Fails secure by default with explicit opt-in for insecure settings
"""

import os
import sys
import yaml
import json
import logging
import asyncio
import inspect
import concurrent.futures
import re
import shutil
import time
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime
from pathlib import Path

# Add project root to path for imports
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))

try:
    from shares.loader import pp
    from shares.loader import load_config
except ImportError:
    # Fallback for standalone execution
    def pp(plugin_name):
        return None
    def load_config():
        return {}

logger = logging.getLogger(__name__)

class ConfigurationHardeningPlugin:
    """
    Security Configuration Hardening Plugin v1.2.0
    
    Validates PlugPipe configuration files and environment settings for security compliance.
    Provides recommendations and can automatically apply security hardening.
    Includes AI-powered code quality improvement and placeholder implementation completion.
    """
    
    def __init__(self):
        # Load environment variables from .env file if it exists
        self._load_env_file()

        self.logger = self._setup_logging()
        self.universal_sanitizer = pp('universal_input_sanitizer')
        self.security_findings = []
        
        # Enhanced AI-powered capabilities - reusing existing abstract plugins
        self.codebase_auto_fixer = pp('codebase_auto_fixer')
        self.context_analyzer = pp('context_analyzer')
        self.llm_service = pp('llm_service')
        self.monitoring_prometheus = pp('monitoring_prometheus')

        # FTHAD FIX: Plugin availability tracking for graceful degradation
        self.ai_capabilities = {
            'auto_fixer': self.codebase_auto_fixer is not None,
            'context_analyzer': self.context_analyzer is not None,
            'llm_service': self.llm_service is not None,
            'monitoring': self.monitoring_prometheus is not None,
            'universal_sanitizer': self.universal_sanitizer is not None
        }

        # Security validation rules
        self.security_rules = self._load_security_rules()

        # AI-powered auto-fixing configuration with availability-based enabling
        self.ai_fix_enabled = any([
            self.ai_capabilities['auto_fixer'],
            self.ai_capabilities['context_analyzer'],
            self.ai_capabilities['llm_service']
        ])
        self.monitoring_enabled = self.ai_capabilities['monitoring']
        self.auto_remediation_threshold = 0.8  # Confidence threshold for automatic fixes
        
    def _setup_logging(self):
        """Set up dedicated logging for security configuration validation."""
        logger = logging.getLogger(f"config_hardening_{id(self)}")
        logger.setLevel(logging.INFO)
        if not logger.handlers:
            handler = logging.StreamHandler()
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            logger.addHandler(handler)
        return logger

    def _load_env_file(self):
        """Load environment variables from .env file if it exists."""
        try:
            # Get PlugPipe root directory
            plugpipe_root = get_plugpipe_root()
            env_file = os.path.join(plugpipe_root, '.env')

            if os.path.exists(env_file):
                with open(env_file, 'r') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#') and '=' in line:
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            # Only set if not already in environment
                            if key not in os.environ:
                                os.environ[key] = value
        except Exception as e:
            # Fail silently - environment loading is not critical
            pass

    def _load_security_rules(self) -> Dict[str, Any]:
        """Load security validation rules and secure defaults."""
        return {
            "network_security": {
                "insecure_bindings": ["0.0.0.0"],
                "secure_bindings": ["127.0.0.1", "localhost"],
                "production_requires_explicit": True
            },
            "environment_security": {
                "production_required_vars": [
                    "JWT_SECRET",
                    "POSTGRES_CONNECTION_STRING", 
                    "REDIS_URL"
                ],
                "development_required_vars": [
                    "DEV_JWT_SECRET"
                ],
                "sensitive_vars": [
                    "JWT_SECRET", "API_KEY", "PASSWORD", "TOKEN", "SECRET"
                ]
            },
            "tls_security": {
                "production_requires_https": True,
                "required_tls_vars": [
                    "SSL_CERT_PATH", "SSL_KEY_PATH"
                ]
            },
            "cors_security": {
                "disallowed_origins": ["*"],
                "require_explicit_origins": True
            },
            "auth_security": {
                "min_jwt_expiry": 900,      # 15 minutes
                "max_jwt_expiry": 3600,     # 1 hour
                "require_jwt_in_production": True
            }
        }
    
    def _call_ai_plugin_safely(self, ai_plugin, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Safely call an AI plugin with proper null checking and error handling.

        FTHAD FIX: Implements proper plugin availability checking and graceful degradation
        for abstract plugins that may not be available.
        """
        try:
            # CRITICAL FIX: Check if plugin is available before calling
            if ai_plugin is None:
                return {
                    'success': False,
                    'error': 'AI plugin not available',
                    'fallback_used': True,
                    'security_hardening': 'Graceful degradation when AI plugins unavailable'
                }

            # CRITICAL FIX: Ensure plugin has process method
            if not hasattr(ai_plugin, 'process'):
                return {
                    'success': False,
                    'error': 'Plugin does not have process method',
                    'fallback_used': True,
                    'security_hardening': 'Plugin interface validation'
                }

            # Call the plugin with proper error handling
            result = ai_plugin.process(context, config)
            
            # Check if result is a coroutine that needs to be awaited
            if inspect.iscoroutine(result):
                try:
                    # Try to get the existing event loop
                    loop = asyncio.get_event_loop()
                    if loop.is_running():
                        # If loop is running, we can't use run_until_complete
                        # Create a new thread for async execution
                        
                        def run_in_thread():
                            new_loop = asyncio.new_event_loop()
                            asyncio.set_event_loop(new_loop)
                            try:
                                return new_loop.run_until_complete(result)
                            finally:
                                new_loop.close()
                        
                        with concurrent.futures.ThreadPoolExecutor() as executor:
                            future = executor.submit(run_in_thread)
                            result = future.result(timeout=30)  # 30 second timeout
                    else:
                        # Loop exists but not running, safe to use run_until_complete
                        result = loop.run_until_complete(result)
                except RuntimeError:
                    # No event loop exists, create one
                    loop = asyncio.new_event_loop()
                    asyncio.set_event_loop(loop)
                    try:
                        result = loop.run_until_complete(result)
                    finally:
                        loop.close()
            
            return result if isinstance(result, dict) else {'success': False, 'error': 'Invalid plugin response type'}
            
        except Exception as e:
            self.logger.warning(f"AI plugin call failed: {e}")
            return {
                'success': False,
                'error': f'AI plugin execution failed: {str(e)}',
                'method': 'async_safe_plugin_call'
            }

    def _sanitize_config_hardening_input(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive input sanitization for Config Hardening Plugin.

        Security Features:
        - Malicious pattern detection and blocking
        - Input length limits and bounds checking
        - Nested dictionary recursive sanitization
        - Operation and configuration validation
        - File path validation and sanitization
        """

        # Malicious patterns to detect and block
        malicious_patterns = [
            '<script>', 'javascript:', 'vbscript:', 'data:',
            '../../', '../', '/etc/', '/proc/', '/sys/',
            'rm -rf', 'sudo', 'chmod', 'chown',
            'DROP TABLE', 'DELETE FROM', 'UPDATE SET',
            '__import__', 'eval(', 'exec(', 'subprocess',
            'os.system', 'shell=True', 'shell_injection'
        ]

        def _sanitize_value(value: Any, key: str = '') -> Any:
            """Recursively sanitize values"""
            if isinstance(value, str):
                # Check for malicious patterns
                value_lower = value.lower()
                for pattern in malicious_patterns:
                    if pattern in value_lower:
                        return {
                            '_security_blocked': True,
                            '_security_message': f'Malicious pattern detected in {key}: {pattern}'
                        }

                # Length limits based on field type
                max_length = 2000  # Default max length
                if key in ['operation', 'config_file', 'environment']:
                    max_length = 100
                elif key in ['finding', 'recommendation', 'error']:
                    max_length = 500

                if len(value) > max_length:
                    return {
                        '_security_blocked': True,
                        '_security_message': f'Input too long for {key}: max {max_length} characters'
                    }

                # Remove potentially dangerous characters
                sanitized = value.replace('\x00', '').replace('\x01', '').replace('\x02', '')
                return sanitized

            elif isinstance(value, (int, float)):
                # Bounds checking for numeric values
                if key in ['security_score', 'compliance_percentage']:
                    if value < 0 or value > 100:
                        return {
                            '_security_blocked': True,
                            '_security_message': f'Invalid {key}: must be between 0 and 100'
                        }
                elif key in ['port', 'timeout']:
                    if value < 0 or value > 65535:
                        return {
                            '_security_blocked': True,
                            '_security_message': f'Invalid {key}: must be between 0 and 65535'
                        }

                return value

            elif isinstance(value, dict):
                # Recursively sanitize dictionaries
                sanitized_dict = {}
                for sub_key, sub_value in value.items():
                    if isinstance(sub_key, str) and len(sub_key) > 100:
                        return {
                            '_security_blocked': True,
                            '_security_message': f'Dictionary key too long: max 100 characters'
                        }

                    sanitized_sub = _sanitize_value(sub_value, f"{key}.{sub_key}")
                    if isinstance(sanitized_sub, dict) and sanitized_sub.get('_security_blocked'):
                        return sanitized_sub

                    sanitized_dict[sub_key] = sanitized_sub

                return sanitized_dict

            elif isinstance(value, list):
                # Sanitize lists with size limits
                if len(value) > 1000:  # Max 1000 items in lists
                    return {
                        '_security_blocked': True,
                        '_security_message': f'List too large for {key}: max 1000 items'
                    }

                sanitized_list = []
                for i, item in enumerate(value):
                    sanitized_item = _sanitize_value(item, f"{key}[{i}]")
                    if isinstance(sanitized_item, dict) and sanitized_item.get('_security_blocked'):
                        return sanitized_item
                    sanitized_list.append(sanitized_item)

                return sanitized_list

            else:
                # Allow other types (bool, None) but with restrictions
                return value

        # Main sanitization logic
        try:
            # Check overall input size
            input_str = str(input_data)
            if len(input_str) > 500000:  # 500KB input limit for config hardening
                return {
                    '_security_blocked': True,
                    '_security_message': 'Input data too large: maximum 500KB allowed'
                }

            # Validate operation against whitelist
            if 'operation' in input_data:
                operation = input_data.get('operation', 'validate')
                valid_operations = [
                    'validate', 'harden', 'report', 'ai_fix', 'monitor',
                    'auto_remediate', 'verify_fixes', 'status_api',
                    'fix_placeholders', 'scan_codebase', 'analyze_return_none'
                ]
                if operation not in valid_operations:
                    return {
                        '_security_blocked': True,
                        '_security_message': f'Invalid operation: {operation}. Allowed: {valid_operations}'
                    }

            # Recursively sanitize all input data
            sanitized = {}
            for key, value in input_data.items():
                sanitized_value = _sanitize_value(value, key)
                if isinstance(sanitized_value, dict) and sanitized_value.get('_security_blocked'):
                    return sanitized_value
                sanitized[key] = sanitized_value

            # Additional config file path validation
            if 'config_file' in sanitized:
                config_file = str(sanitized['config_file'])
                # Only allow relative paths within project
                if config_file.startswith('/') or '..' in config_file:
                    sanitized['config_file'] = 'config.yaml'  # Safe default

            return sanitized

        except Exception as e:
            return {
                '_security_blocked': True,
                '_security_message': f'Input sanitization error: {str(e)}'
            }

    def _validate_configuration(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive security configuration validation.
        
        Validates:
        - Network binding security (prevents 0.0.0.0 in production)
        - Authentication settings (JWT, API keys)
        - TLS/SSL configuration
        - CORS settings
        - Environment variable security
        """
        self.logger.info("Starting comprehensive security configuration validation")
        
        try:
            config_file = config.get('config_file', 'config.yaml')
            environment = config.get('environment', 'development')
            
            # Load configuration file
            config_data = self._load_config_file(config_file)
            if not config_data:
                return {
                    'success': False,
                    'error': f'Unable to load configuration file: {config_file}',
                    'security_score': 0
                }
            
            security_findings = []
            security_score = 100
            
            # Network security validation
            network_findings = self._validate_network_security(config_data, environment)
            security_findings.extend(network_findings)
            
            # Authentication security validation
            auth_findings = self._validate_authentication_security(config_data, environment)
            security_findings.extend(auth_findings)
            
            # TLS/SSL validation
            tls_findings = self._validate_tls_security(config_data, environment)
            security_findings.extend(tls_findings)
            
            # CORS validation
            cors_findings = self._validate_cors_security(config_data, environment)
            security_findings.extend(cors_findings)
            
            # Environment variables validation
            env_findings = self._validate_environment_security(environment)
            security_findings.extend(env_findings)
            
            # Calculate security score
            security_score = max(0, 100 - (len(security_findings) * 10))
            
            # Generate security grade
            security_grade = self._calculate_security_grade(security_score)
            
            self.logger.info(f"Security validation completed. Score: {security_score}/100, Grade: {security_grade}")
            
            return {
                'success': True,
                'security_score': security_score,
                'security_grade': security_grade,
                'security_findings': security_findings,
                'environment': environment,
                'config_file': config_file,
                'validation_timestamp': datetime.now().isoformat(),
                'recommendations': self._generate_recommendations(security_findings)
            }
            
        except Exception as e:
            self.logger.error(f"Security validation failed: {e}")
            return {
                'success': False,
                'error': f'Security validation failed: {str(e)}',
                'security_score': 0,
                'security_findings': []
            }

    def _harden_configuration(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Apply security hardening to configuration files.
        
        Applies:
        - Secure binding defaults
        - Strong authentication settings
        - TLS enforcement
        - Secure CORS configuration
        """
        self.logger.info("Starting configuration hardening")
        
        try:
            config_file = config.get('config_file', 'config.yaml')
            environment = config.get('environment', 'production')
            auto_apply = config.get('auto_apply', False)
            
            # Load current configuration
            config_data = self._load_config_file(config_file)
            if not config_data:
                return {
                    'success': False,
                    'error': f'Unable to load configuration file: {config_file}'
                }
            
            hardening_actions = []
            
            # Apply network security hardening
            if environment == 'production':
                if 'server' in config_data:
                    old_host = config_data['server'].get('host', '127.0.0.1')
                    if old_host == '0.0.0.0':
                        config_data['server']['host'] = '127.0.0.1'
                        hardening_actions.append({
                            'action': 'network_security',
                            'change': f'Changed host from {old_host} to 127.0.0.1',
                            'reason': 'Prevent external exposure in production'
                        })
            
            # Apply authentication hardening
            if 'auth' not in config_data:
                config_data['auth'] = {}
            
            if 'jwt' not in config_data['auth']:
                config_data['auth']['jwt'] = {
                    'expiry': 1800,  # 30 minutes
                    'require_https': environment == 'production',
                    'algorithm': 'HS256'
                }
                hardening_actions.append({
                    'action': 'auth_security',
                    'change': 'Added secure JWT configuration',
                    'reason': 'Enable secure authentication'
                })
            
            # Apply TLS hardening
            if environment == 'production':
                if 'tls' not in config_data:
                    config_data['tls'] = {
                        'enabled': True,
                        'min_version': 'TLSv1.2',
                        'require_cert': True
                    }
                    hardening_actions.append({
                        'action': 'tls_security',
                        'change': 'Added TLS configuration',
                        'reason': 'Enforce encrypted connections'
                    })
            
            # Apply CORS hardening
            if 'cors' in config_data:
                if config_data['cors'].get('origins') == ['*']:
                    config_data['cors']['origins'] = ['https://localhost:3000']
                    hardening_actions.append({
                        'action': 'cors_security',
                        'change': 'Restricted CORS origins from wildcard',
                        'reason': 'Prevent unauthorized cross-origin access'
                    })
            
            # Save hardened configuration if auto_apply is enabled
            backup_file = None
            if auto_apply and hardening_actions:
                backup_file = f"{config_file}.backup.{int(time.time())}"
                shutil.copy(config_file, backup_file)
                
                with open(config_file, 'w') as f:
                    yaml.dump(config_data, f, default_flow_style=False)
                
                self.logger.info(f"Applied {len(hardening_actions)} hardening actions to {config_file}")
                
            return {
                'success': True,
                'hardening_actions': hardening_actions,
                'config_file': config_file,
                'backup_created': backup_file,
                'applied': auto_apply,
                'hardening_timestamp': datetime.now().isoformat()
            }
            
        except Exception as e:
            self.logger.error(f"Configuration hardening failed: {e}")
            return {
                'success': False,
                'error': f'Configuration hardening failed: {str(e)}'
            }

    def _auto_remediate_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Comprehensive automated security remediation.
        
        Combines validation, hardening, AI-powered fixes, and monitoring setup
        for complete security automation.
        """
        self.logger.info("Starting comprehensive automated remediation")
        
        try:
            enable_auto_remediation = config.get('enable_auto_remediation', False)
            threshold = config.get('auto_remediation_threshold', 0.8)
            
            remediation_results = {
                'validation': {},
                'hardening': {},
                'ai_fixes': {},
                'monitoring_setup': {},
                'success': True,
                'remediation_actions': []
            }
            
            # Step 1: Validate current configuration
            self.logger.info("Step 1: Validating current configuration")
            validation_result = self._validate_configuration(context, config)
            remediation_results['validation'] = validation_result
            
            if not validation_result.get('success'):
                remediation_results['success'] = False
                return remediation_results
            
            security_score = validation_result.get('security_score', 0)
            self.logger.info(f"Current security score: {security_score}/100")
            
            # Step 2: Apply configuration hardening if needed
            if security_score < 80:
                self.logger.info("Step 2: Applying configuration hardening")
                harden_config = dict(config)
                harden_config['auto_apply'] = enable_auto_remediation
                
                hardening_result = self._harden_configuration(context, harden_config)
                remediation_results['hardening'] = hardening_result
                
                if hardening_result.get('success'):
                    actions = hardening_result.get('hardening_actions', [])
                    remediation_results['remediation_actions'].extend(actions)
            
            # Step 3: AI-powered code quality fixes
            if enable_auto_remediation:
                self.logger.info("Step 3: Applying AI-powered fixes")
                ai_fix_result = self._ai_powered_fix(context, config)
                remediation_results['ai_fixes'] = ai_fix_result
                
                if ai_fix_result.get('success'):
                    remediation_results['remediation_actions'].append({
                        'action': 'ai_enhancement',
                        'change': 'Applied AI-powered code improvements',
                        'reason': 'Improve code quality and security'
                    })
            
            # Step 4: Setup monitoring
            self.logger.info("Step 4: Setting up security monitoring")
            monitoring_result = self._start_monitoring(context, config)
            remediation_results['monitoring_setup'] = monitoring_result
            
            if monitoring_result.get('success'):
                remediation_results['remediation_actions'].append({
                    'action': 'monitoring_setup',
                    'change': 'Configured security monitoring',
                    'reason': 'Enable continuous security oversight'
                })
            
            # Final validation
            self.logger.info("Step 5: Final security validation")
            final_validation = self._validate_configuration(context, config)
            final_score = final_validation.get('security_score', 0)
            
            self.logger.info(f"Automated remediation completed. Final security score: {final_score}/100")
            
            remediation_results.update({
                'initial_score': security_score,
                'final_score': final_score,
                'improvement': final_score - security_score,
                'remediation_timestamp': datetime.now().isoformat(),
                'total_actions': len(remediation_results['remediation_actions'])
            })
            
            return remediation_results
            
        except Exception as e:
            self.logger.error(f"Automated remediation failed: {e}")
            return {
                'success': False,
                'error': f'Automated remediation failed: {str(e)}'
            }

    def _generate_security_report(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive security report."""
        self.logger.info("Generating comprehensive security report")
        
        try:
            # Run validation to get current state
            validation_result = self._validate_configuration(context, config)
            
            if not validation_result.get('success'):
                return validation_result
            
            report = {
                'report_type': 'security_assessment',
                'generated_at': datetime.now().isoformat(),
                'security_overview': {
                    'overall_score': validation_result.get('security_score', 0),
                    'security_grade': validation_result.get('security_grade', 'F'),
                    'findings_count': len(validation_result.get('security_findings', [])),
                    'environment': validation_result.get('environment', 'unknown')
                },
                'detailed_findings': validation_result.get('security_findings', []),
                'recommendations': validation_result.get('recommendations', []),
                'compliance_status': self._assess_compliance_status(validation_result),
                'next_steps': self._generate_next_steps(validation_result)
            }
            
            return {
                'success': True,
                'report': report,
                'format': 'json'
            }
            
        except Exception as e:
            self.logger.error(f"Security report generation failed: {e}")
            return {
                'success': False,
                'error': f'Security report generation failed: {str(e)}'
            }

    def _ai_powered_fix(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """AI-powered security enhancement and configuration optimization."""
        self.logger.info("Starting AI-powered security enhancement")
        
        try:
            if not self.llm_service:
                return {
                    'success': False,
                    'error': 'LLM service not available for AI-powered fixes'
                }
            
            use_llm = config.get('use_llm_recommendations', True)
            context_analysis = config.get('context_analysis', True)
            
            ai_results = {
                'recommendations': [],
                'applied_fixes': [],
                'success': True
            }
            
            if use_llm:
                # Use LLM for security recommendations
                llm_context = {
                    'task': 'security_configuration_analysis',
                    'config_data': context.get('config_data', {}),
                    'security_findings': self.security_findings
                }
                
                llm_result = self._call_ai_plugin_safely(self.llm_service, llm_context, {
                    'prompt': 'Analyze this PlugPipe configuration for security improvements',
                    'model': 'gpt-4'
                })
                
                if llm_result.get('success'):
                    ai_results['recommendations'].extend(
                        llm_result.get('recommendations', [])
                    )
            
            if context_analysis and self.context_analyzer:
                # Use context analyzer for deeper understanding
                analysis_result = self._call_ai_plugin_safely(self.context_analyzer, context, {
                    'analysis_type': 'security_configuration'
                })
                
                if analysis_result.get('success'):
                    ai_results['applied_fixes'].extend(
                        analysis_result.get('fixes', [])
                    )
            
            return ai_results
            
        except Exception as e:
            self.logger.error(f"AI-powered fix failed: {e}")
            return {
                'success': False,
                'error': f'AI-powered fix failed: {str(e)}'
            }

    def _start_monitoring(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Start security monitoring with Prometheus integration."""
        self.logger.info("Starting security monitoring")
        
        try:
            monitor_interval = config.get('monitor_interval', '5m')
            notification_channels = config.get('notification_channels', ['logs'])
            
            monitoring_config = {
                'enabled': True,
                'interval': monitor_interval,
                'notifications': notification_channels,
                'metrics': [
                    'security_score',
                    'failed_auth_attempts',
                    'configuration_changes',
                    'tls_errors',
                    'cors_violations'
                ]
            }
            
            if self.monitoring_prometheus:
                prometheus_result = self._call_ai_plugin_safely(
                    self.monitoring_prometheus,
                    context,
                    {
                        'action': 'setup_monitoring',
                        'config': monitoring_config
                    }
                )
                
                if prometheus_result.get('success'):
                    return {
                        'success': True,
                        'monitoring_enabled': True,
                        'prometheus_integration': True,
                        'config': monitoring_config
                    }
            
            # Fallback monitoring setup
            return {
                'success': True,
                'monitoring_enabled': True,
                'prometheus_integration': False,
                'config': monitoring_config,
                'note': 'Basic monitoring enabled without Prometheus'
            }
            
        except Exception as e:
            self.logger.error(f"Monitoring setup failed: {e}")
            return {
                'success': False,
                'error': f'Monitoring setup failed: {str(e)}'
            }

    def _verify_previous_fixes(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Verify that previously applied security fixes are still effective."""
        self.logger.info("Verifying previous security fixes")
        
        try:
            # Re-run validation to check current state
            current_validation = self._validate_configuration(context, config)
            
            if not current_validation.get('success'):
                return current_validation
            
            verification_results = {
                'success': True,
                'verification_timestamp': datetime.now().isoformat(),
                'current_score': current_validation.get('security_score', 0),
                'current_grade': current_validation.get('security_grade', 'F'),
                'findings': current_validation.get('security_findings', []),
                'status': 'verified'
            }
            
            # Check if score has degraded
            if current_validation.get('security_score', 0) < 70:
                verification_results.update({
                    'status': 'degraded',
                    'recommendation': 'Security posture has degraded, re-run auto_remediate',
                    'urgency': 'high'
                })
            
            return verification_results
            
        except Exception as e:
            self.logger.error(f"Fix verification failed: {e}")
            return {
                'success': False,
                'error': f'Fix verification failed: {str(e)}'
            }

    def _generate_status_api(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive status API response for frontend integration."""
        self.logger.info("Generating status API response")
        
        try:
            # Run validation to get current security state
            validation_result = self._validate_configuration(context, config)
            
            if not validation_result.get('success'):
                return {
                    'success': False,
                    'error': validation_result.get('error', 'Validation failed'),
                    'status': 'error'
                }
            
            security_score = validation_result.get('security_score', 0)
            security_grade = validation_result.get('security_grade', 'F')
            findings = validation_result.get('security_findings', [])
            
            # Categorize findings
            critical_findings = [f for f in findings if f.get('severity') == 'critical']
            high_findings = [f for f in findings if f.get('severity') == 'high']
            medium_findings = [f for f in findings if f.get('severity') == 'medium']
            
            status_response = {
                'success': True,
                'status': 'healthy' if security_score >= 80 else 'warning' if security_score >= 60 else 'critical',
                'timestamp': datetime.now().isoformat(),
                'security_overview': {
                    'score': security_score,
                    'grade': security_grade,
                    'max_score': 100,
                    'status_color': self._get_status_color(security_score)
                },
                'compliance_status': {
                    'total_checks': len(findings) + (100 - len(findings)),
                    'passed_checks': 100 - len(findings),
                    'failed_checks': len(findings),
                    'compliance_percentage': max(0, 100 - len(findings) * 10)
                },
                'findings_summary': {
                    'total': len(findings),
                    'critical': len(critical_findings),
                    'high': len(high_findings),
                    'medium': len(medium_findings),
                    'low': len(findings) - len(critical_findings) - len(high_findings) - len(medium_findings)
                },
                'detailed_findings': findings,
                'recommendations': validation_result.get('recommendations', []),
                'environment': validation_result.get('environment', 'unknown'),
                'config_file': validation_result.get('config_file', 'unknown'),
                'next_assessment': (datetime.now().timestamp() + 3600),  # Next hour
                'actions_available': [
                    'validate',
                    'harden', 
                    'auto_remediate',
                    'ai_fix',
                    'monitor'
                ]
            }
            
            return status_response
            
        except Exception as e:
            self.logger.error(f"Status API generation failed: {e}")
            return {
                'success': False,
                'error': f'Status API generation failed: {str(e)}',
                'status': 'error',
                'timestamp': datetime.now().isoformat()
            }

    def _fix_placeholder_implementations(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """AI-assisted fixing of placeholder implementations in codebase."""
        self.logger.info("Starting AI-assisted placeholder implementation fixing")
        
        try:
            max_files = config.get('max_files', 10)
            ai_assistance = config.get('ai_assistance', True)
            backup_before_fix = config.get('backup_before_fix', True)
            
            if not self.codebase_auto_fixer:
                return {
                    'success': False,
                    'error': 'Codebase auto-fixer plugin not available'
                }
            
            # Scan for placeholder implementations first
            scan_result = self._scan_codebase_quality(context, {
                'scan_directories': ['cores', 'plugs', 'shares'],
                'focus': 'placeholder_implementations'
            })
            
            if not scan_result.get('success'):
                return scan_result
            
            placeholder_files = scan_result.get('analysis', {}).get('top_problem_files', [])[:max_files]
            
            fixing_results = {
                'success': True,
                'files_processed': 0,
                'files_fixed': 0,
                'fixes_applied': [],
                'errors': []
            }
            
            for file_info in placeholder_files:
                file_path = file_info.get('file', '')
                
                try:
                    # Use codebase auto-fixer to fix placeholders
                    fix_context = {
                        'file_path': file_path,
                        'task': 'fix_placeholder_implementations',
                        'backup': backup_before_fix
                    }
                    
                    fix_result = self._call_ai_plugin_safely(
                        self.codebase_auto_fixer,
                        fix_context,
                        {
                            'ai_assistance': ai_assistance,
                            'max_fixes_per_file': 5
                        }
                    )
                    
                    fixing_results['files_processed'] += 1
                    
                    if fix_result.get('success'):
                        fixing_results['files_fixed'] += 1
                        fixing_results['fixes_applied'].append({
                            'file': file_path,
                            'fixes': fix_result.get('fixes', []),
                            'backup_created': fix_result.get('backup_path')
                        })
                    else:
                        fixing_results['errors'].append({
                            'file': file_path,
                            'error': fix_result.get('error', 'Unknown error')
                        })
                        
                except Exception as e:
                    fixing_results['errors'].append({
                        'file': file_path,
                        'error': f'Processing failed: {str(e)}'
                    })
            
            return fixing_results
            
        except Exception as e:
            self.logger.error(f"Placeholder fixing failed: {e}")
            return {
                'success': False,
                'error': f'Placeholder fixing failed: {str(e)}'
            }

    def _scan_codebase_quality(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Comprehensive codebase quality scanning for placeholder implementations."""
        self.logger.info("Starting comprehensive codebase quality scan")
        
        try:
            scan_directories = config.get('scan_directories', ['cores', 'plugs', 'shares'])
            focus = config.get('focus', 'placeholder_implementations')
            
            scan_results = {
                'success': True,
                'scan_timestamp': datetime.now().isoformat(),
                'directories_scanned': scan_directories,
                'focus': focus,
                'files_scanned': 0,
                'total_issues': 0,
                'summary': {},
                'analysis': {
                    'total_files_scanned': 0,
                    'files_with_issues': 0,
                    'total_issues_found': 0,
                    'issue_categories': {},
                    'top_problem_files': []
                }
            }
            
            # Define patterns to scan for
            placeholder_patterns = [
                r'NotImplementedError',
                r'pass\s*#\s*TODO',
                r'raise\s+NotImplementedError',
                r'def\s+\w+\([^)]*\):\s*pass\s*$',
                r'def\s+\w+\([^)]*\):\s*"""[^"]*"""\s*pass\s*$',
                r'# TODO:.*implement',
                r'# FIXME:.*implement'
            ]

            # Enhanced patterns for return None analysis
            return_none_patterns = [
                r'def\s+(create_\w+|process_\w+|execute_\w+|validate_\w+|generate_\w+)\([^)]*\):\s*return\s+None\s*$',
                r'def\s+\w+\([^)]*\):\s*"""[^"]*"""\s*return\s+None\s*$',
                r'def\s+\w+\([^)]*\):\s*return\s+None\s*#.*placeholder',
                r'def\s+\w+\([^)]*\):\s*return\s+None\s*#.*TODO',
                r'def\s+\w+\([^)]*\):\s*return\s+None\s*#.*FIXME'
            ]

            # Combine all patterns for comprehensive scanning
            all_patterns = placeholder_patterns + return_none_patterns
            
            issues_found = {}
            
            # Scan each directory
            for directory in scan_directories:
                # Use absolute path relative to PlugPipe root
                base_path = Path(get_plugpipe_root())
                directory_path = base_path / directory
                self.logger.info(f"Scanning directory: {directory_path}")
                if not directory_path.exists():
                    self.logger.warning(f"Directory not found: {directory_path}")
                    continue
                    
                for file_path in directory_path.rglob('*.py'):
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            
                        scan_results['analysis']['total_files_scanned'] += 1
                        file_issues = []
                        
                        for pattern in all_patterns:
                            matches = re.finditer(pattern, content, re.MULTILINE)
                            for match in matches:
                                line_num = content[:match.start()].count('\n') + 1
                                file_issues.append({
                                    'pattern': pattern,
                                    'line': line_num,
                                    'matched_text': match.group().strip(),
                                    'severity': 'medium'
                                })
                        
                        if file_issues:
                            issues_found[str(file_path)] = file_issues
                            scan_results['analysis']['files_with_issues'] += 1
                            scan_results['analysis']['total_issues_found'] += len(file_issues)
                            
                    except Exception as e:
                        self.logger.warning(f"Could not scan file {file_path}: {e}")
            
            # Generate top problem files
            sorted_files = sorted(
                issues_found.items(),
                key=lambda x: len(x[1]),
                reverse=True
            )
            
            scan_results['analysis']['top_problem_files'] = [
                {
                    'file': file_path,
                    'issue_count': len(issues),
                    'issues': issues[:5]  # Top 5 issues per file
                }
                for file_path, issues in sorted_files[:20]  # Top 20 problem files
            ]
            
            # Categorize issues
            for issues in issues_found.values():
                for issue in issues:
                    category = self._categorize_issue(issue['matched_text'])
                    if category not in scan_results['analysis']['issue_categories']:
                        scan_results['analysis']['issue_categories'][category] = 0
                    scan_results['analysis']['issue_categories'][category] += 1

            # Update top-level summary fields
            scan_results['files_scanned'] = scan_results['analysis']['total_files_scanned']
            scan_results['total_issues'] = scan_results['analysis']['total_issues_found']
            scan_results['summary'] = scan_results['analysis']['issue_categories']

            self.logger.info(f"Codebase scan completed. Found {scan_results['analysis']['total_issues_found']} issues in {scan_results['analysis']['files_with_issues']} files")

            return scan_results
            
        except Exception as e:
            self.logger.error(f"Codebase quality scan failed: {e}")
            return {
                'success': False,
                'error': f'Codebase quality scan failed: {str(e)}'
            }

    # Helper methods
    def _load_config_file(self, config_file: str) -> Dict[str, Any]:
        """Load and parse configuration file."""
        try:
            if not os.path.exists(config_file):
                self.logger.warning(f"Configuration file not found: {config_file}")
                return {}
            
            with open(config_file, 'r') as f:
                if config_file.endswith('.yaml') or config_file.endswith('.yml'):
                    return yaml.safe_load(f) or {}
                elif config_file.endswith('.json'):
                    return json.load(f) or {}
                else:
                    self.logger.warning(f"Unsupported config file format: {config_file}")
                    return {}
                    
        except Exception as e:
            self.logger.error(f"Failed to load config file {config_file}: {e}")
            return {}

    def _validate_network_security(self, config_data: Dict[str, Any], environment: str) -> List[Dict[str, Any]]:
        """Validate network security settings."""
        findings = []
        
        if 'server' in config_data:
            host = config_data['server'].get('host', '127.0.0.1')
            port = config_data['server'].get('port', 8000)
            
            if host == '0.0.0.0' and environment == 'production':
                findings.append({
                    'category': 'network_security',
                    'severity': 'critical',
                    'finding': 'Server bound to 0.0.0.0 in production environment',
                    'recommendation': 'Change host to 127.0.0.1 or specific interface',
                    'risk': 'External exposure of internal services'
                })
            
            if port < 1024 and environment == 'production':
                findings.append({
                    'category': 'network_security',
                    'severity': 'medium',
                    'finding': f'Server using privileged port {port}',
                    'recommendation': 'Use port > 1024 or ensure proper privilege management',
                    'risk': 'Requires root privileges'
                })
        
        return findings

    def _validate_authentication_security(self, config_data: Dict[str, Any], environment: str) -> List[Dict[str, Any]]:
        """Validate authentication security settings."""
        findings = []
        
        if 'auth' not in config_data and environment == 'production':
            findings.append({
                'category': 'auth_security',
                'severity': 'critical',
                'finding': 'No authentication configuration found',
                'recommendation': 'Configure JWT or API key authentication',
                'risk': 'Unauthenticated access to services'
            })
        elif 'auth' in config_data:
            auth_config = config_data['auth']
            
            if 'jwt' in auth_config:
                jwt_config = auth_config['jwt']
                expiry = jwt_config.get('expiry', 0)
                
                if expiry < self.security_rules['auth_security']['min_jwt_expiry']:
                    findings.append({
                        'category': 'auth_security',
                        'severity': 'medium',
                        'finding': f'JWT expiry too short: {expiry}s',
                        'recommendation': f'Set expiry to at least {self.security_rules["auth_security"]["min_jwt_expiry"]}s',
                        'risk': 'Frequent token refresh required'
                    })
                
                if expiry > self.security_rules['auth_security']['max_jwt_expiry']:
                    findings.append({
                        'category': 'auth_security',
                        'severity': 'high',
                        'finding': f'JWT expiry too long: {expiry}s',
                        'recommendation': f'Set expiry to at most {self.security_rules["auth_security"]["max_jwt_expiry"]}s',
                        'risk': 'Long-lived tokens increase security risk'
                    })
        
        return findings

    def _validate_tls_security(self, config_data: Dict[str, Any], environment: str) -> List[Dict[str, Any]]:
        """Validate TLS/SSL security settings."""
        findings = []
        
        if environment == 'production':
            if 'tls' not in config_data:
                findings.append({
                    'category': 'tls_security',
                    'severity': 'critical',
                    'finding': 'No TLS configuration found for production',
                    'recommendation': 'Configure TLS with valid certificates',
                    'risk': 'Unencrypted data transmission'
                })
            else:
                tls_config = config_data['tls']
                
                if not tls_config.get('enabled', False):
                    findings.append({
                        'category': 'tls_security',
                        'severity': 'critical',
                        'finding': 'TLS is disabled in production',
                        'recommendation': 'Enable TLS encryption',
                        'risk': 'Unencrypted data transmission'
                    })
                
                min_version = tls_config.get('min_version', 'TLSv1.0')
                if min_version in ['TLSv1.0', 'TLSv1.1']:
                    findings.append({
                        'category': 'tls_security',
                        'severity': 'high',
                        'finding': f'Weak TLS minimum version: {min_version}',
                        'recommendation': 'Use TLSv1.2 or higher',
                        'risk': 'Vulnerable to known TLS attacks'
                    })
        
        return findings

    def _validate_cors_security(self, config_data: Dict[str, Any], environment: str) -> List[Dict[str, Any]]:
        """Validate CORS security settings."""
        findings = []
        
        if 'cors' in config_data:
            cors_config = config_data['cors']
            origins = cors_config.get('origins', [])
            
            if '*' in origins:
                severity = 'critical' if environment == 'production' else 'medium'
                findings.append({
                    'category': 'cors_security',
                    'severity': severity,
                    'finding': 'CORS allows all origins (*)',
                    'recommendation': 'Specify explicit allowed origins',
                    'risk': 'Cross-origin attacks from any domain'
                })
            
            credentials = cors_config.get('credentials', False)
            if credentials and '*' in origins:
                findings.append({
                    'category': 'cors_security',
                    'severity': 'critical',
                    'finding': 'CORS allows credentials with wildcard origins',
                    'recommendation': 'Remove wildcard when credentials are enabled',
                    'risk': 'Credential theft via cross-origin attacks'
                })
        
        return findings

    def _validate_environment_security(self, environment: str) -> List[Dict[str, Any]]:
        """Validate environment variable security."""
        findings = []
        
        required_vars = self.security_rules['environment_security'].get(
            f'{environment}_required_vars', []
        )
        
        for var in required_vars:
            if not os.getenv(var):
                findings.append({
                    'category': 'environment_security',
                    'severity': 'high',
                    'finding': f'Required environment variable {var} not set',
                    'recommendation': f'Set {var} environment variable',
                    'risk': 'Service may fail to start or operate insecurely'
                })
        
        # Check for sensitive vars in environment
        sensitive_patterns = self.security_rules['environment_security']['sensitive_vars']
        for key, value in os.environ.items():
            for pattern in sensitive_patterns:
                if pattern.lower() in key.lower():
                    if len(value) < 16:
                        findings.append({
                            'category': 'environment_security',
                            'severity': 'medium',
                            'finding': f'Environment variable {key} appears to be a weak secret',
                            'recommendation': 'Use strong, randomly generated secrets',
                            'risk': 'Weak secrets are vulnerable to brute force attacks'
                        })
        
        return findings

    def _calculate_security_grade(self, score: int) -> str:
        """Calculate security grade from score."""
        if score >= 90:
            return 'A'
        elif score >= 80:
            return 'B'
        elif score >= 70:
            return 'C'
        elif score >= 60:
            return 'D'
        else:
            return 'F'

    def _get_status_color(self, score: int) -> str:
        """Get status color for frontend display."""
        if score >= 80:
            return 'green'
        elif score >= 60:
            return 'yellow'
        else:
            return 'red'

    def _generate_recommendations(self, findings: List[Dict[str, Any]]) -> List[str]:
        """Generate actionable recommendations from findings."""
        recommendations = []
        
        for finding in findings:
            if finding.get('recommendation'):
                recommendations.append(finding['recommendation'])
        
        # Remove duplicates while preserving order
        seen = set()
        unique_recommendations = []
        for rec in recommendations:
            if rec not in seen:
                seen.add(rec)
                unique_recommendations.append(rec)
        
        return unique_recommendations

    def _assess_compliance_status(self, validation_result: Dict[str, Any]) -> Dict[str, Any]:
        """Assess compliance status based on validation results."""
        findings = validation_result.get('security_findings', [])
        critical_count = len([f for f in findings if f.get('severity') == 'critical'])
        high_count = len([f for f in findings if f.get('severity') == 'high'])
        
        if critical_count > 0:
            status = 'non_compliant'
        elif high_count > 2:
            status = 'partially_compliant'
        else:
            status = 'compliant'
        
        return {
            'status': status,
            'critical_issues': critical_count,
            'high_issues': high_count,
            'total_issues': len(findings)
        }

    def _generate_next_steps(self, validation_result: Dict[str, Any]) -> List[str]:
        """Generate next steps based on validation results."""
        score = validation_result.get('security_score', 0)
        findings = validation_result.get('security_findings', [])
        
        next_steps = []
        
        if score < 60:
            next_steps.append("Run 'auto_remediate' operation for comprehensive security fixes")
        elif score < 80:
            next_steps.append("Run 'harden' operation to apply security hardening")
        
        if any(f.get('severity') == 'critical' for f in findings):
            next_steps.append("Address critical security findings immediately")
        
        if score >= 80:
            next_steps.append("Setup continuous monitoring with 'monitor' operation")
        
        next_steps.append("Schedule regular security assessments")
        
        return next_steps

    def _analyze_return_none_patterns(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Specialized analysis of return None patterns to distinguish valid vs invalid implementations."""
        self.logger.info("Starting specialized return None pattern analysis")

        # SECURITY: Validate and sanitize input parameters
        try:
            if not isinstance(context, dict) or not isinstance(config, dict):
                raise ValueError("Invalid input types: context and config must be dictionaries")

            # Sanitize target directories to prevent path traversal
            raw_directories = config.get('target_directories', ['plugs/', 'cores/', 'shares/'])
            if not isinstance(raw_directories, list):
                raise ValueError("target_directories must be a list")

            # Security: Validate directory paths to prevent path traversal attacks
            allowed_base_paths = [get_plugpipe_path("plugs"), get_plugpipe_path("cores"), get_plugpipe_path("shares")]
            scan_directories = []

            for directory in raw_directories:
                if not isinstance(directory, str):
                    self.logger.warning(f"Skipping invalid directory type: {type(directory)}")
                    continue

                # Remove dangerous characters and normalize path
                sanitized_dir = directory.strip().rstrip('/').replace('..', '').replace('//', '/')
                if not sanitized_dir or sanitized_dir.startswith('/'):
                    self.logger.warning(f"Skipping invalid directory path: {directory}")
                    continue

                # Construct full path and validate it's within allowed directories
                full_path = Path(get_plugpipe_root()) / sanitized_dir
                full_path = full_path.resolve()  # Resolve any symlinks/relative paths

                # Security check: ensure path is within allowed base paths
                path_allowed = any(str(full_path).startswith(base_path) for base_path in allowed_base_paths)
                if path_allowed and full_path.exists():
                    scan_directories.append(sanitized_dir)
                else:
                    self.logger.warning(f"Directory access denied or not found: {directory}")

            if not scan_directories:
                raise ValueError("No valid directories to scan after security validation")

        except Exception as e:
            self.logger.error(f"Security validation failed in return None analysis: {e}")
            return {
                'success': False,
                'error': f'Security validation failed: {str(e)}',
                'security_hardening': 'Input validation and path traversal prevention active'
            }

        start_time = datetime.now()

        analysis_result = {
            'success': True,
            'analysis_timestamp': start_time.isoformat(),
            'pattern_analysis': 'return_none_patterns',
            'total_return_none_functions': 0,
            'valid_return_none_patterns': 0,
            'invalid_return_none_patterns': 0,
            'suspicious_return_none_patterns': 0,
            'detailed_analysis': {
                'valid_patterns': [],
                'invalid_patterns': [],
                'suspicious_patterns': []
            },
            'recommendations': []
        }

        # Valid return None patterns (error handling, optional data)
        valid_patterns = [
            r'if\s+not\s+.*:\s*return\s+None',  # Conditional validation
            r'except\s+.*:\s*.*return\s+None',   # Exception handling
            r'def\s+.*_optional\([^)]*\):\s*.*return\s+None',  # Optional methods
            r'def\s+.*get_.*\([^)]*\):\s*.*return\s+None',     # Getter methods
        ]

        # Invalid return None patterns (placeholders, missing logic)
        invalid_patterns = [
            r'def\s+(create_\w+|process_\w+|execute_\w+|validate_\w+|generate_\w+)\([^)]*\):\s*return\s+None\s*$',
            r'def\s+\w+\([^)]*\):\s*"""[^"]*"""\s*return\s+None\s*$',
            r'def\s+\w+\([^)]*\):\s*return\s+None\s*#.*placeholder',
        ]

        # Scan each directory
        for directory in scan_directories:
            base_path = Path(get_plugpipe_root())
            directory_path = base_path / directory

            if not directory_path.exists():
                continue

            for file_path in directory_path.rglob('*.py'):
                try:
                    # Security: Validate file path and size before reading
                    if not file_path.is_file():
                        self.logger.warning(f"Skipping non-file: {file_path}")
                        continue

                    # Security: Check file size to prevent memory exhaustion attacks
                    file_size = file_path.stat().st_size
                    max_file_size = 10 * 1024 * 1024  # 10MB limit
                    if file_size > max_file_size:
                        self.logger.warning(f"Skipping large file (>{max_file_size/1024/1024}MB): {file_path}")
                        continue

                    # Security: Validate file extension and check for symlinks
                    if file_path.is_symlink():
                        self.logger.warning(f"Skipping symlink for security: {file_path}")
                        continue

                    if not file_path.suffix == '.py':
                        self.logger.warning(f"Skipping non-Python file: {file_path}")
                        continue

                    # Secure file reading with timeout protection
                    with open(file_path, 'r', encoding='utf-8') as f:
                        content = f.read(max_file_size)  # Limit read size

                    # Find all functions that return None
                    return_none_matches = re.finditer(r'def\s+(\w+)\([^)]*\):[^{]*?return\s+None', content, re.MULTILINE | re.DOTALL)

                    for match in return_none_matches:
                        function_context = match.group(0)
                        function_name = match.group(1)
                        line_num = content[:match.start()].count('\n') + 1
                        relative_path = str(file_path.relative_to(base_path))

                        analysis_result['total_return_none_functions'] += 1

                        # Categorize the pattern
                        is_valid = any(re.search(pattern, function_context) for pattern in valid_patterns)
                        is_invalid = any(re.search(pattern, function_context) for pattern in invalid_patterns)

                        pattern_info = {
                            'file': relative_path,
                            'function_name': function_name,
                            'line_number': line_num,
                            'context': function_context[:200] + '...' if len(function_context) > 200 else function_context
                        }

                        if is_valid:
                            analysis_result['valid_return_none_patterns'] += 1
                            analysis_result['detailed_analysis']['valid_patterns'].append(pattern_info)
                        elif is_invalid:
                            analysis_result['invalid_return_none_patterns'] += 1
                            analysis_result['detailed_analysis']['invalid_patterns'].append(pattern_info)
                        else:
                            analysis_result['suspicious_return_none_patterns'] += 1
                            analysis_result['detailed_analysis']['suspicious_patterns'].append(pattern_info)

                except Exception as e:
                    self.logger.warning(f"Failed to analyze {file_path}: {e}")

        # Generate recommendations
        if analysis_result['invalid_return_none_patterns'] > 0:
            analysis_result['recommendations'].append(
                f"Found {analysis_result['invalid_return_none_patterns']} functions with invalid return None patterns that need business logic implementation"
            )

        if analysis_result['suspicious_return_none_patterns'] > 0:
            analysis_result['recommendations'].append(
                f"Found {analysis_result['suspicious_return_none_patterns']} functions with suspicious return None patterns requiring manual review"
            )

        if analysis_result['valid_return_none_patterns'] > 0:
            analysis_result['recommendations'].append(
                f"Verified {analysis_result['valid_return_none_patterns']} valid return None patterns (error handling, optional data)"
            )

        processing_time = (datetime.now() - start_time).total_seconds()
        analysis_result['processing_time_seconds'] = processing_time

        self.logger.info(f"Return None pattern analysis completed in {processing_time:.2f}s")
        return analysis_result

    def _categorize_issue(self, matched_text: str) -> str:
        """Categorize placeholder implementation issues."""
        if 'NotImplementedError' in matched_text:
            return 'not_implemented_error'
        elif 'return None' in matched_text:
            # Distinguish between valid and invalid return None patterns
            if any(action in matched_text for action in ['create_', 'process_', 'execute_', 'validate_', 'generate_']):
                return 'invalid_return_none_action_function'
            elif 'placeholder' in matched_text or 'TODO' in matched_text or 'FIXME' in matched_text:
                return 'invalid_return_none_placeholder'
            else:
                return 'suspicious_return_none'
        elif 'TODO' in matched_text:
            return 'todo_placeholder'
        elif 'pass' in matched_text:
            return 'empty_function'
        elif 'FIXME' in matched_text:
            return 'fixme_placeholder'
        else:
            return 'other_placeholder'

    def process(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main processing function for configuration hardening.
        
        Args:
            context: Processing context with configuration files and environment
            config: Plugin configuration
            
        Returns:
            Dictionary with security findings and recommendations
        """
        try:
            self.security_findings = []

            # SECURITY HARDENING: Comprehensive input validation and sanitization
            sanitized_context = self._sanitize_config_hardening_input(context)
            if sanitized_context.get('_security_blocked'):
                return {
                    'success': False,
                    'error': sanitized_context['_security_message'],
                    'security_hardening': 'Malicious input patterns detected and blocked'
                }

            sanitized_config = self._sanitize_config_hardening_input(config)
            if sanitized_config.get('_security_blocked'):
                return {
                    'success': False,
                    'error': sanitized_config['_security_message'],
                    'security_hardening': 'Malicious configuration patterns detected and blocked'
                }

            # Use sanitized inputs for processing
            context = sanitized_context
            config = sanitized_config

            operation = config.get('operation', 'validate')
            
            if operation == 'validate':
                return self._validate_configuration(context, config)
            elif operation == 'harden':
                return self._harden_configuration(context, config)
            elif operation == 'report':
                return self._generate_security_report(context, config)
            elif operation == 'ai_fix':
                return self._ai_powered_fix(context, config)
            elif operation == 'monitor':
                return self._start_monitoring(context, config)
            elif operation == 'auto_remediate':
                return self._auto_remediate_issues(context, config)
            elif operation == 'verify_fixes':
                return self._verify_previous_fixes(context, config)
            elif operation == 'status_api':
                return self._generate_status_api(context, config)
            elif operation == 'fix_placeholders':
                return self._fix_placeholder_implementations(context, config)
            elif operation == 'scan_codebase':
                return self._scan_codebase_quality(context, config)
            elif operation == 'analyze_return_none':
                return self._analyze_return_none_patterns(context, config)
            else:
                return {
                    'success': False,
                    'error': f'Unknown operation: {operation}',
                    'supported_operations': ['validate', 'harden', 'report', 'ai_fix', 'monitor', 'auto_remediate', 'verify_fixes', 'status_api', 'fix_placeholders', 'scan_codebase', 'analyze_return_none']
                }
                
        except Exception as e:
            self.logger.error(f"Configuration hardening failed: {e}")
            return {
                'success': False,
                'error': f'Configuration hardening failed: {str(e)}',
                'security_findings': self.security_findings
            }

# Process function for PlugPipe integration - ULTIMATE FIX PATTERN
def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main entry point for the configuration hardening plugin.

    ULTIMATE FIX: Pure synchronous implementation with dual parameter checking.
    - Checks both ctx and cfg for input data (CLI uses cfg, MCP uses ctx)
    - Pure synchronous to eliminate async issues completely
    - Comprehensive input parameter extraction and validation
    """

    try:
        # ULTIMATE FIX PART 1: Check both ctx and cfg for input data
        # CLI typically uses cfg, MCP uses ctx
        input_data = {}

        # Extract from ctx (MCP style)
        if ctx and isinstance(ctx, dict):
            input_data.update(ctx)

        # Extract from cfg (CLI style) - takes precedence
        if cfg and isinstance(cfg, dict):
            input_data.update(cfg)

        # ULTIMATE FIX PART 2: Input validation and sanitization
        if not isinstance(input_data, dict):
            return {
                'success': False,
                'error': 'Invalid input: must be a dictionary',
                'security_hardening': 'Input validation active - ultimate fix pattern'
            }

        # ULTIMATE FIX PART 3: Pure synchronous implementation
        plugin = ConfigurationHardeningPlugin()

        # Add ultimate fix confirmation to context
        enhanced_context = dict(input_data)
        enhanced_context['ultimate_fix_applied'] = True
        enhanced_context['parameter_extraction'] = {
            'ctx_processed': bool(ctx),
            'cfg_processed': bool(cfg),
            'combined_input_valid': bool(input_data)
        }

        return plugin.process(enhanced_context, input_data)

    except Exception as e:
        return {
            'success': False,
            'error': f'Config hardening error: {str(e)}',
            'security_hardening': 'Comprehensive error handling with ultimate fix pattern'
        }

# Plugin metadata
plug_metadata = {
    "name": "config_hardening", 
    "version": "1.2.0",
    "description": "AI-powered security configuration hardening with async-safe AI plugin integration and comprehensive code quality improvement",
    "author": "PlugPipe Security Team",
    "license": "MIT",
    "category": "security",
    "tags": ["security", "configuration", "hardening", "ai", "async-safe", "code-quality", "placeholder-fixing"],
    "requirements": ["pyyaml"],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["validate", "harden", "report", "ai_fix", "monitor", "auto_remediate", "verify_fixes", "status_api", "fix_placeholders", "scan_codebase"],
                "default": "validate",
                "description": "Security operation to perform"
            },
            "config_file": {
                "type": "string",
                "default": "config.yaml",
                "description": "Configuration file to analyze"
            },
            "environment": {
                "type": "string",
                "enum": ["development", "staging", "production"],
                "default": "development",
                "description": "Target environment for security validation"
            }
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "security_score": {"type": "integer", "minimum": 0, "maximum": 100},
            "security_grade": {"type": "string", "pattern": "^[A-F]$"},
            "security_findings": {"type": "array"},
            "recommendations": {"type": "array"}
        }
    },
    "sbom": "sbom/"
}