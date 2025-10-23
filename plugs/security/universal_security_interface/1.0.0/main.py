#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Universal Security Plugin Interface Standard for PlugPipe
Provides standardized format and interface for all security plugins
"""

import asyncio
import os
import json
import time
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Union
from enum import Enum
import importlib.util

class SecurityAction(Enum):
    """Standardized security actions"""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    MODIFY = "MODIFY"
    REVIEW = "REVIEW"

class ThreatLevel(Enum):
    """Standardized threat levels"""
    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

@dataclass
class ThreatDetection:
    """Standardized threat detection result"""
    threat_id: str
    threat_type: str
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any]
    recommendation: str
    start_position: Optional[int] = None
    end_position: Optional[int] = None
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        result = asdict(self)
        result['threat_level'] = self.threat_level.value
        return result

@dataclass
class SecurityPluginResult:
    """Standardized security plugin result format"""
    # Core decision fields
    action: SecurityAction
    vote: SecurityAction  # For consensus systems
    threat_score: float  # 0.0 to 1.0
    
    # Detection details
    threats_detected: List[ThreatDetection]
    
    # Plugin metadata
    plugin_name: str
    plugin_version: str
    processing_time_ms: float
    timestamp: str
    
    # Optional fields
    confidence: float = 1.0
    modified_content: Optional[str] = None
    metadata: Dict[str, Any] = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        result = asdict(self)
        # Convert enums to strings
        result['action'] = self.action.value
        result['vote'] = self.vote.value
        result['threats_detected'] = [threat.to_dict() for threat in self.threats_detected]
        return result

class SecurityPluginContext:
    """Standardized context for security plugin processing"""
    
    def __init__(self, 
                 content: str,
                 operation: str = "analyze",
                 content_type: str = "text",
                 source_ip: Optional[str] = None,
                 user_id: Optional[str] = None,
                 request_id: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        self.content = content
        self.operation = operation
        self.content_type = content_type
        self.source_ip = source_ip
        self.user_id = user_id
        self.request_id = request_id or str(uuid.uuid4())
        self.metadata = metadata or {}
        self.timestamp = time.time()
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary"""
        return {
            'content': self.content,
            'operation': self.operation,
            'content_type': self.content_type,
            'source_ip': self.source_ip,
            'user_id': self.user_id,
            'request_id': self.request_id,
            'metadata': self.metadata,
            'timestamp': self.timestamp
        }

class UniversalSecurityPlugin(ABC):
    """Universal base class for all security plugins"""
    
    def __init__(self):
        self.plugin_name = self.__class__.__name__
        self.plugin_version = "1.0.0"
    
    @abstractmethod
    async def analyze_content(self, context: SecurityPluginContext, config: Dict[str, Any]) -> SecurityPluginResult:
        """
        Main analysis method that all security plugins must implement
        
        Args:
            context: Standardized context with content to analyze
            config: Plugin-specific configuration
            
        Returns:
            SecurityPluginResult: Standardized result format
        """
        pass
    
    def create_threat_detection(self,
                              threat_type: str,
                              threat_level: ThreatLevel,
                              confidence: float,
                              description: str,
                              evidence: Dict[str, Any],
                              recommendation: str,
                              start_pos: Optional[int] = None,
                              end_pos: Optional[int] = None) -> ThreatDetection:
        """Helper to create standardized threat detection"""
        return ThreatDetection(
            threat_id=f"{self.plugin_name}_{threat_type}_{int(time.time())}_{uuid.uuid4().hex[:8]}",
            threat_type=threat_type,
            threat_level=threat_level,
            confidence=confidence,
            description=description,
            evidence=evidence,
            recommendation=recommendation,
            start_position=start_pos,
            end_position=end_pos
        )
    
    def create_result(self,
                     action: SecurityAction,
                     threat_score: float,
                     threats: List[ThreatDetection],
                     confidence: float = 1.0,
                     modified_content: Optional[str] = None,
                     metadata: Optional[Dict[str, Any]] = None) -> SecurityPluginResult:
        """Helper to create standardized result"""
        return SecurityPluginResult(
            action=action,
            vote=action,  # Vote same as action by default
            threat_score=threat_score,
            threats_detected=threats,
            plugin_name=self.plugin_name,
            plugin_version=self.plugin_version,
            processing_time_ms=0.0,  # Will be set by wrapper
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
            confidence=confidence,
            modified_content=modified_content,
            metadata=metadata
        )

class LegacyPluginWrapper:
    """Wrapper to make legacy plugins compatible with universal interface"""
    
    def __init__(self, legacy_plugin, plugin_name: str):
        self.legacy_plugin = legacy_plugin
        self.plugin_name = plugin_name
    
    async def analyze_content(self, context: SecurityPluginContext, config: Dict[str, Any]) -> SecurityPluginResult:
        """Convert legacy plugin calls to universal format"""
        start_time = time.time()
        
        try:
            # Convert universal context to legacy context
            legacy_context = {
                'text': context.content,
                'payload': context.content,
                'content': context.content,
                'data': context.content,
                'operation': context.operation,
                'request_id': context.request_id,
                'source_ip': context.source_ip,
                'user_id': context.user_id,
                **context.metadata
            }
            
            # Call legacy plugin
            if asyncio.iscoroutinefunction(self.legacy_plugin.process):
                legacy_result = await self.legacy_plugin.process(legacy_context, config)
            else:
                legacy_result = self.legacy_plugin.process(legacy_context, config)
            
            processing_time = (time.time() - start_time) * 1000
            
            # Convert legacy result to universal format
            return self._convert_legacy_result(legacy_result, processing_time)
            
        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            return SecurityPluginResult(
                action=SecurityAction.ALLOW,  # Fail open
                vote=SecurityAction.ALLOW,
                threat_score=0.0,
                threats_detected=[],
                plugin_name=self.plugin_name,
                plugin_version="legacy",
                processing_time_ms=processing_time,
                timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
                metadata={'error': str(e), 'legacy_plugin': True}
            )
    
    def _convert_legacy_result(self, legacy_result: Any, processing_time: float) -> SecurityPluginResult:
        """Convert legacy plugin result to universal format"""
        
        threats = []
        action = SecurityAction.ALLOW
        threat_score = 0.0
        metadata = {'legacy_plugin': True}
        
        if isinstance(legacy_result, dict):
            # Extract action from various possible fields
            if 'action' in legacy_result:
                action_str = legacy_result['action']
            elif 'status' in legacy_result:
                status = legacy_result['status']
                if status == 'success' or status == 'completed':
                    # Check for threats/entities to determine action
                    if (legacy_result.get('security_threats') or 
                        legacy_result.get('secrets_found') or
                        legacy_result.get('detected_entities') or
                        legacy_result.get('threat_score', 0) > 0.5):
                        action_str = 'BLOCK'
                    else:
                        action_str = 'ALLOW'
                else:
                    action_str = 'BLOCK' if status == 'blocked' else 'ALLOW'
            else:
                # Infer from threat indicators
                if (legacy_result.get('threats_detected') or
                    legacy_result.get('security_threats') or
                    legacy_result.get('secrets_found') or
                    legacy_result.get('detected_entities') or
                    legacy_result.get('threat_score', 0) > 0.5):
                    action_str = 'BLOCK'
                else:
                    action_str = 'ALLOW'
            
            # Convert to SecurityAction enum
            try:
                action = SecurityAction(action_str.upper())
            except ValueError:
                action = SecurityAction.ALLOW
            
            # Extract threat score
            threat_score = float(legacy_result.get('threat_score', 
                                               legacy_result.get('score', 
                                               legacy_result.get('confidence', 0.0))))
            
            # Convert legacy threats to universal format
            if 'secrets_found' in legacy_result:
                for secret in legacy_result['secrets_found']:
                    threats.append(ThreatDetection(
                        threat_id=f"legacy_secret_{uuid.uuid4().hex[:8]}",
                        threat_type=secret.get('type', 'secret'),
                        threat_level=ThreatLevel.HIGH,
                        confidence=secret.get('confidence', 0.9),
                        description=f"Secret detected: {secret.get('type', 'unknown')}",
                        evidence={'secret_type': secret.get('type'), 'preview': secret.get('value_preview')},
                        recommendation="Remove or encrypt secret",
                        start_position=secret.get('start'),
                        end_position=secret.get('end')
                    ))
            
            if 'security_threats' in legacy_result:
                for threat in legacy_result['security_threats']:
                    threats.append(ThreatDetection(
                        threat_id=threat.get('threat_id', f"legacy_threat_{uuid.uuid4().hex[:8]}"),
                        threat_type=threat.get('threat_type', 'unknown'),
                        threat_level=ThreatLevel(threat.get('level', 'medium')),
                        confidence=threat.get('confidence', 0.5),
                        description=threat.get('description', ''),
                        evidence={'details': threat.get('details', {})},
                        recommendation=threat.get('recommendation', 'Review content')
                    ))
            
            if 'detected_entities' in legacy_result:
                for entity in legacy_result['detected_entities']:
                    threats.append(ThreatDetection(
                        threat_id=f"legacy_entity_{uuid.uuid4().hex[:8]}",
                        threat_type=entity.get('entity_type', 'pii'),
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=entity.get('confidence', 0.7),
                        description=f"PII detected: {entity.get('entity_type')}",
                        evidence={'entity_type': entity.get('entity_type'), 'text': entity.get('text_preview')},
                        recommendation="Sanitize or encrypt PII",
                        start_position=entity.get('start'),
                        end_position=entity.get('end')
                    ))
            
            # Preserve original metadata
            metadata.update({k: v for k, v in legacy_result.items() 
                           if k not in ['action', 'status', 'threat_score', 'threats_detected', 
                                      'security_threats', 'secrets_found', 'detected_entities']})
        
        return SecurityPluginResult(
            action=action,
            vote=action,
            threat_score=threat_score,
            threats_detected=threats,
            plugin_name=self.plugin_name,
            plugin_version="legacy",
            processing_time_ms=processing_time,
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
            metadata=metadata
        )

class UniversalSecurityInterface:
    """Main interface plugin for PlugPipe"""
    
    def __init__(self):
        self.plugin_name = "universal_security_interface"
        self.plugin_version = "1.0.0"
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """PlugPipe plugin entry point"""
        operation = ctx.get('operation', 'get_interface_standard')
        
        try:
            if operation == 'create_plugin_template':
                return await self._create_plugin_template(ctx, cfg)
            elif operation == 'validate_plugin_interface':
                return await self._validate_plugin_interface(ctx, cfg)
            elif operation == 'wrap_legacy_plugin':
                return await self._wrap_legacy_plugin(ctx, cfg)
            elif operation == 'get_interface_standard':
                return await self._get_interface_standard(ctx, cfg)
            else:
                return {
                    'status': 'error',
                    'error': f'Unknown operation: {operation}',
                    'supported_operations': ['create_plugin_template', 'validate_plugin_interface', 'wrap_legacy_plugin', 'get_interface_standard']
                }
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e),
                'operation': operation
            }
    
    async def _create_plugin_template(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Generate template for new universal security plugin"""
        plugin_name = ctx.get('plugin_name')
        plugin_version = ctx.get('plugin_version', '1.0.0')
        
        if not plugin_name:
            return {'status': 'error', 'error': 'plugin_name required'}
        
        template = self._generate_plugin_template(plugin_name, plugin_version)
        
        return {
            'status': 'completed',
            'plugin_name': plugin_name,
            'plugin_version': plugin_version,
            'template': template,
            'interface_version': '1.0.0'
        }
    
    async def _validate_plugin_interface(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Validate plugin follows universal interface"""
        plugin_path = ctx.get('plugin_path')
        plugin_name = ctx.get('plugin_name')

        # SECURITY: Input validation and sanitization
        if not ctx or not isinstance(ctx, dict):
            return {'status': 'error', 'error': 'Invalid or empty context: ctx must be a non-empty dictionary'}

        if not isinstance(cfg, dict):
            return {'status': 'error', 'error': 'Invalid config: cfg must be a dictionary'}

        if not plugin_path or not plugin_name:
            return {'status': 'error', 'error': 'plugin_path and plugin_name required'}

        # SECURITY: Sanitize and validate plugin_path to prevent path traversal
        if not isinstance(plugin_path, str) or not isinstance(plugin_name, str):
            return {'status': 'error', 'error': 'plugin_path and plugin_name must be strings'}

        # Remove dangerous characters and validate path
        sanitized_path = plugin_path.strip().replace('..', '').replace('//', '/').rstrip('/')
        if not sanitized_path or sanitized_path.startswith('/') or '\\' in sanitized_path:
            return {'status': 'error', 'error': 'Invalid plugin_path: path traversal detected or invalid format'}

        # SECURITY: Ensure plugin_path is within PlugPipe directory structure
        import os.path
        abs_plugin_path = os.path.abspath(sanitized_path)
        plugpipe_root = os.path.abspath('.')
        if not abs_plugin_path.startswith(plugpipe_root):
            return {'status': 'error', 'error': 'Security violation: plugin_path must be within PlugPipe directory'}

        # SECURITY: Validate plugin_name format (alphanumeric, underscore, hyphen only)
        import re
        if not re.match(r'^[a-zA-Z0-9_-]+$', plugin_name):
            return {'status': 'error', 'error': 'Invalid plugin_name: only alphanumeric, underscore, and hyphen allowed'}

        # Use sanitized path for validation
        plugin_path = sanitized_path

        # Implement comprehensive validation logic
        validation_issues = []
        compliant = True

        try:
            # 1. Validate plugin file structure
            plugin_main_path = os.path.join(plugin_path, 'main.py')
            plugin_yaml_path = os.path.join(plugin_path, 'plug.yaml')

            if not os.path.exists(plugin_main_path):
                validation_issues.append({
                    'type': 'missing_file',
                    'severity': 'critical',
                    'message': 'main.py file not found',
                    'recommendation': 'Create main.py with plugin implementation'
                })
                compliant = False

            if not os.path.exists(plugin_yaml_path):
                validation_issues.append({
                    'type': 'missing_file',
                    'severity': 'critical',
                    'message': 'plug.yaml file not found',
                    'recommendation': 'Create plug.yaml with plugin metadata'
                })
                compliant = False

            # 2. Validate plug.yaml structure if it exists
            if os.path.exists(plugin_yaml_path):
                try:
                    import yaml
                    with open(plugin_yaml_path, 'r') as f:
                        plugin_metadata = yaml.safe_load(f)

                    # Check required fields
                    required_fields = ['name', 'version', 'description', 'category']
                    for field in required_fields:
                        if field not in plugin_metadata:
                            validation_issues.append({
                                'type': 'missing_metadata',
                                'severity': 'high',
                                'message': f'Missing required field: {field}',
                                'recommendation': f'Add {field} field to plug.yaml'
                            })
                            compliant = False

                    # Validate security category for security plugins
                    if plugin_metadata.get('category') == 'security':
                        if 'security' not in plugin_metadata.get('tags', []):
                            validation_issues.append({
                                'type': 'missing_security_tag',
                                'severity': 'medium',
                                'message': 'Security plugin missing security tag',
                                'recommendation': 'Add "security" to tags array'
                            })

                except Exception as e:
                    validation_issues.append({
                        'type': 'yaml_parse_error',
                        'severity': 'critical',
                        'message': f'Failed to parse plug.yaml: {str(e)}',
                        'recommendation': 'Fix YAML syntax errors'
                    })
                    compliant = False

            # 3. Validate main.py implementation if it exists
            if os.path.exists(plugin_main_path):
                try:
                    # SECURITY: Check file size to prevent memory exhaustion
                    file_size = os.path.getsize(plugin_main_path)
                    max_file_size = 5 * 1024 * 1024  # 5MB limit
                    if file_size > max_file_size:
                        validation_issues.append({
                            'type': 'file_too_large',
                            'severity': 'critical',
                            'message': f'main.py file too large ({file_size/1024/1024:.1f}MB > {max_file_size/1024/1024}MB)',
                            'recommendation': 'Split large plugin into smaller modules'
                        })
                        compliant = False
                        plugin_code = ""  # Skip content analysis for large files
                    else:
                        # SECURITY: Safe file reading with encoding validation
                        with open(plugin_main_path, 'r', encoding='utf-8', errors='ignore') as f:
                            plugin_code = f.read(max_file_size)  # Limit read size

                    # Check for required process function
                    if 'def process(' not in plugin_code:
                        validation_issues.append({
                            'type': 'missing_process_function',
                            'severity': 'critical',
                            'message': 'Missing required process() function',
                            'recommendation': 'Implement process(context, config) function'
                        })
                        compliant = False

                    # Check for security-specific validations if it's a security plugin
                    if ctx.get('category') == 'security':
                        # Check for UniversalSecurityPlugin inheritance
                        if 'UniversalSecurityPlugin' not in plugin_code:
                            validation_issues.append({
                                'type': 'missing_security_interface',
                                'severity': 'high',
                                'message': 'Security plugin should inherit from UniversalSecurityPlugin',
                                'recommendation': 'Inherit from UniversalSecurityPlugin base class'
                            })

                        # Check for analyze_content method
                        if 'def analyze_content(' not in plugin_code:
                            validation_issues.append({
                                'type': 'missing_analyze_content',
                                'severity': 'high',
                                'message': 'Security plugin missing analyze_content method',
                                'recommendation': 'Implement analyze_content method for security analysis'
                            })

                    # Check for basic error handling
                    if 'try:' not in plugin_code and 'except' not in plugin_code:
                        validation_issues.append({
                            'type': 'missing_error_handling',
                            'severity': 'medium',
                            'message': 'No error handling detected',
                            'recommendation': 'Add try/except blocks for robust error handling'
                        })

                    # Check for logging
                    if 'logging' not in plugin_code and 'logger' not in plugin_code:
                        validation_issues.append({
                            'type': 'missing_logging',
                            'severity': 'low',
                            'message': 'No logging detected',
                            'recommendation': 'Add logging for better debugging and monitoring'
                        })

                    # Check for security imports if it's a security plugin
                    if ctx.get('category') == 'security':
                        security_imports = ['re', 'hashlib', 'hmac', 'secrets']
                        has_security_imports = any(imp in plugin_code for imp in security_imports)
                        if not has_security_imports:
                            validation_issues.append({
                                'type': 'missing_security_imports',
                                'severity': 'low',
                                'message': 'No security-related imports detected',
                                'recommendation': 'Consider adding security libraries (re, hashlib, etc.)'
                            })

                    # SECURITY: Check for dangerous patterns in code
                    dangerous_patterns = [
                        ('eval(', 'Use of eval() function detected - potential code injection risk'),
                        ('exec(', 'Use of exec() function detected - potential code injection risk'),
                        ('__import__', 'Dynamic import detected - potential security risk'),
                        ('os.system(', 'Use of os.system() detected - potential command injection risk'),
                        ('subprocess.call(', 'Use of subprocess.call() without shell=False - potential command injection'),
                        ('shell=True', 'subprocess with shell=True detected - potential command injection risk')
                    ]

                    for pattern, message in dangerous_patterns:
                        if pattern in plugin_code:
                            validation_issues.append({
                                'type': 'security_risk',
                                'severity': 'high',
                                'message': message,
                                'recommendation': 'Review and secure dangerous code patterns'
                            })

                    # SECURITY: Check for proper input validation in process function
                    if 'def process(' in plugin_code:
                        process_section = plugin_code[plugin_code.find('def process('):plugin_code.find('def process(') + 1000]
                        if 'isinstance(' not in process_section and 'type(' not in process_section:
                            validation_issues.append({
                                'type': 'missing_input_validation',
                                'severity': 'medium',
                                'message': 'process() function lacks input type validation',
                                'recommendation': 'Add isinstance() checks for context and config parameters'
                            })

                except Exception as e:
                    validation_issues.append({
                        'type': 'code_analysis_error',
                        'severity': 'medium',
                        'message': f'Failed to analyze main.py: {str(e)}',
                        'recommendation': 'Check file permissions and encoding'
                    })

            # 4. Validate plugin can be loaded (if requested)
            if cfg.get('test_import', False) and os.path.exists(plugin_main_path):
                try:
                    spec = importlib.util.spec_from_file_location("plugin_under_test", plugin_main_path)
                    if spec and spec.loader:
                        module = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(module)

                        # Check if process function is callable
                        if hasattr(module, 'process') and callable(getattr(module, 'process')):
                            validation_issues.append({
                                'type': 'import_success',
                                'severity': 'info',
                                'message': 'Plugin imports successfully',
                                'recommendation': 'Plugin structure is valid'
                            })
                        else:
                            validation_issues.append({
                                'type': 'process_not_callable',
                                'severity': 'critical',
                                'message': 'process function exists but is not callable',
                                'recommendation': 'Ensure process function is properly defined'
                            })
                            compliant = False
                    else:
                        validation_issues.append({
                            'type': 'import_spec_error',
                            'severity': 'critical',
                            'message': 'Failed to create import specification',
                            'recommendation': 'Check Python syntax and file structure'
                        })
                        compliant = False

                except Exception as e:
                    validation_issues.append({
                        'type': 'import_error',
                        'severity': 'critical',
                        'message': f'Failed to import plugin: {str(e)}',
                        'recommendation': 'Fix Python syntax errors and dependencies'
                    })
                    compliant = False

            return {
                'status': 'completed',
                'plugin_path': plugin_path,
                'plugin_name': plugin_name,
                'compliant': compliant,
                'issues': validation_issues,
                'validation_summary': {
                    'total_issues': len(validation_issues),
                    'critical_issues': len([i for i in validation_issues if i.get('severity') == 'critical']),
                    'high_issues': len([i for i in validation_issues if i.get('severity') == 'high']),
                    'medium_issues': len([i for i in validation_issues if i.get('severity') == 'medium']),
                    'low_issues': len([i for i in validation_issues if i.get('severity') == 'low'])
                },
                'interface_version': '1.0.0'
            }

        except Exception as e:
            return {
                'status': 'error',
                'error': f'Validation failed: {str(e)}',
                'plugin_path': plugin_path,
                'plugin_name': plugin_name,
                'compliant': False,
                'issues': [{
                    'type': 'validation_exception',
                    'severity': 'critical',
                    'message': f'Validation process failed: {str(e)}',
                    'recommendation': 'Check plugin path and permissions'
                }]
            }
    
    async def _wrap_legacy_plugin(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Create wrapper for legacy plugin"""
        plugin_path = ctx.get('plugin_path')
        plugin_name = ctx.get('plugin_name')
        
        if not plugin_path or not plugin_name:
            return {'status': 'error', 'error': 'plugin_path and plugin_name required'}
        
        try:
            # Load legacy plugin
            spec = importlib.util.spec_from_file_location("legacy_plugin", f"{plugin_path}/main.py")
            legacy_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(legacy_module)
            
            # Create wrapper
            wrapper = LegacyPluginWrapper(legacy_module, plugin_name)
            
            return {
                'status': 'completed',
                'plugin_path': plugin_path,
                'plugin_name': plugin_name,
                'wrapper_created': True,
                'interface_version': '1.0.0'
            }
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Failed to wrap legacy plugin: {str(e)}',
                'plugin_path': plugin_path,
                'plugin_name': plugin_name
            }
    
    async def _get_interface_standard(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get the universal interface standard"""
        format_type = ctx.get('format', 'classes')
        
        if format_type == 'classes':
            return {
                'status': 'completed',
                'interface_classes': {
                    'SecurityAction': [action.value for action in SecurityAction],
                    'ThreatLevel': [level.value for level in ThreatLevel],
                    'SecurityPluginResult': 'Standardized result format',
                    'SecurityPluginContext': 'Standardized context format',
                    'ThreatDetection': 'Standardized threat detection format',
                    'UniversalSecurityPlugin': 'Base class for security plugins'
                },
                'interface_version': '1.0.0'
            }
        elif format_type == 'schema':
            return {
                'status': 'completed',
                'schema': {
                    'SecurityPluginResult': {
                        'action': 'SecurityAction enum',
                        'vote': 'SecurityAction enum',
                        'threat_score': 'float 0.0-1.0',
                        'threats_detected': 'List[ThreatDetection]',
                        'plugin_name': 'string',
                        'plugin_version': 'string',
                        'processing_time_ms': 'float',
                        'timestamp': 'string ISO format'
                    }
                },
                'interface_version': '1.0.0'
            }
        else:
            return {
                'status': 'completed',
                'documentation': 'Universal Security Plugin Interface Standard for PlugPipe',
                'interface_version': '1.0.0'
            }
    
    def _generate_plugin_template(self, plugin_name: str, plugin_version: str) -> str:
        """Generate template code for new plugin"""
        return f'''#!/usr/bin/env python3
"""
{plugin_name} - Universal Security Plugin
Follows PlugPipe Universal Security Plugin Interface Standard
"""

import asyncio
from typing import Dict, Any, List
from shares.loader import pp

class {plugin_name}:
    """
    {plugin_name} security plugin following universal interface
    """
    
    def __init__(self):
        self.plugin_name = "{plugin_name}"
        self.plugin_version = "{plugin_version}"
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        PlugPipe plugin entry point
        """
        # Get universal interface
        interface = pp("universal_security_interface")
        
        # FTHAD SECURITY HARDENING: Input validation and sanitization
        # Validate context parameter
        if not isinstance(ctx, dict):
            return {
                'status': 'error',
                'action': 'BLOCK',
                'vote': 'BLOCK',
                'threat_score': 1.0,
                'threats_detected': [],
                'error': 'Invalid context parameter type',
                'security_hardening': 'Context type validation failed'
            }

        # Validate configuration parameter
        if not isinstance(cfg, dict):
            return {
                'status': 'error',
                'action': 'BLOCK',
                'vote': 'BLOCK',
                'threat_score': 1.0,
                'threats_detected': [],
                'error': 'Invalid configuration parameter type',
                'security_hardening': 'Configuration type validation failed'
            }

        # Extract and validate content
        content = ctx.get('text', ctx.get('payload', ctx.get('content', '')))

        # Validate content type and length
        if not isinstance(content, str):
            return {
                'status': 'error',
                'action': 'BLOCK',
                'vote': 'BLOCK',
                'threat_score': 1.0,
                'threats_detected': [],
                'error': 'Content must be a string',
                'security_hardening': 'Content type validation failed'
            }

        # Prevent extremely large inputs that could cause DoS
        MAX_CONTENT_LENGTH = 10 * 1024 * 1024  # 10MB limit
        if len(content) > MAX_CONTENT_LENGTH:
            return {
                'status': 'error',
                'action': 'BLOCK',
                'vote': 'BLOCK',
                'threat_score': 0.8,
                'threats_detected': [],
                'error': f'Content exceeds maximum length of {{MAX_CONTENT_LENGTH}} bytes',
                'security_hardening': 'Content length validation failed'
            }

        # Sanitize content for processing (remove null bytes and control characters)
        content = content.replace('\x00', '').replace('\x01', '').replace('\x02', '')

        # Additional parameter validation
        operation = ctx.get('operation', 'analyze')
        if operation and not isinstance(operation, str):
            return {
                'status': 'error',
                'action': 'BLOCK',
                'vote': 'BLOCK',
                'threat_score': 0.7,
                'threats_detected': [],
                'error': 'Operation parameter must be a string',
                'security_hardening': 'Operation type validation failed'
            }

        # Validate operation is in allowed list
        allowed_operations = ['analyze', 'scan', 'detect', 'check', 'validate']
        if operation and operation not in allowed_operations:
            return {
                'status': 'error',
                'action': 'BLOCK',
                'vote': 'BLOCK',
                'threat_score': 0.6,
                'threats_detected': [],
                'error': f'Invalid operation: {{operation}}. Allowed: {{allowed_operations}}',
                'security_hardening': 'Operation validation failed'
            }
        
        # FTHAD IMPLEMENTATION: Comprehensive security analysis logic
        threats_detected = []
        threat_score = 0.0
        content_lower = content.lower()

        # SQL Injection Detection
        sql_patterns = [
            r"union\s+select", r"or\s+1\s*=\s*1", r"drop\s+table", r"'; delete",
            r"select.*from.*where", r"insert\s+into", r"update.*set", r"'\s*or\s*'",
            r"--\s*", r"/\*.*\*/", r"0x[0-9a-f]+", r"char\(\d+\)"
        ]

        import re
        for pattern in sql_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                threats_detected.append({
                    'threat_id': str(uuid.uuid4()),
                    'threat_type': 'sql_injection',
                    'threat_level': 'high',
                    'confidence': 0.85,
                    'description': f'SQL injection pattern detected: {{pattern}}',
                    'evidence': {'pattern': pattern, 'content_match': True},
                    'recommendation': 'Block and sanitize input parameters'
                })
                threat_score = max(threat_score, 0.85)

        # XSS Detection
        xss_patterns = [
            r"<script", r"javascript:", r"onerror\s*=", r"onload\s*=",
            r"<img.*src.*javascript", r"<iframe", r"eval\(", r"document\.cookie"
        ]

        for pattern in xss_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                threats_detected.append({
                    'threat_id': str(uuid.uuid4()),
                    'threat_type': 'cross_site_scripting',
                    'threat_level': 'high',
                    'confidence': 0.80,
                    'description': f'XSS pattern detected: {{pattern}}',
                    'evidence': {'pattern': pattern, 'content_match': True},
                    'recommendation': 'Sanitize and encode user input'
                })
                threat_score = max(threat_score, 0.80)

        # Command Injection Detection
        cmd_patterns = [
            r";\s*rm\s", r";\s*cat\s", r";\s*ls\s", r"\|\s*nc\s",
            r"&&\s*", r"\$\(.*\)", r"`.*`", r"exec\(", r"system\("
        ]

        for pattern in cmd_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                threats_detected.append({
                    'threat_id': str(uuid.uuid4()),
                    'threat_type': 'command_injection',
                    'threat_level': 'critical',
                    'confidence': 0.90,
                    'description': f'Command injection pattern detected: {{pattern}}',
                    'evidence': {'pattern': pattern, 'content_match': True},
                    'recommendation': 'Block execution and validate input strictly'
                })
                threat_score = max(threat_score, 0.90)

        # Path Traversal Detection
        path_patterns = [
            r"\.\./", r"\.\.\\", r"/etc/passwd", r"/etc/shadow",
            r"\\windows\\system32", r"%2e%2e%2f", r"%2e%2e%5c"
        ]

        for pattern in path_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                threats_detected.append({
                    'threat_id': str(uuid.uuid4()),
                    'threat_type': 'path_traversal',
                    'threat_level': 'high',
                    'confidence': 0.75,
                    'description': f'Path traversal pattern detected: {{pattern}}',
                    'evidence': {'pattern': pattern, 'content_match': True},
                    'recommendation': 'Validate and restrict file access paths'
                })
                threat_score = max(threat_score, 0.75)

        # Credential Harvesting Detection
        cred_patterns = [
            r"password\s*[:=]\s*['\"][^'\"]+['\"]", r"api[_-]?key\s*[:=]",
            r"access[_-]?token\s*[:=]", r"secret[_-]?key\s*[:=]",
            r"-----BEGIN\s+PRIVATE\s+KEY-----", r"ssh-rsa\s+[A-Za-z0-9+/]+"
        ]

        for pattern in cred_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                threats_detected.append({
                    'threat_id': str(uuid.uuid4()),
                    'threat_type': 'credential_exposure',
                    'threat_level': 'critical',
                    'confidence': 0.95,
                    'description': f'Credential exposure pattern detected: {{pattern}}',
                    'evidence': {'pattern': pattern, 'content_match': True},
                    'recommendation': 'Immediately secure and rotate exposed credentials'
                })
                threat_score = max(threat_score, 0.95)
        
        # Return universal format
        return {{{{
            'status': 'completed',
            'action': 'BLOCK' if threat_score > 0.7 else 'ALLOW',
            'vote': 'BLOCK' if threat_score > 0.7 else 'ALLOW',
            'threat_score': threat_score,
            'threats_detected': threats_detected,
            'plugin_name': self.plugin_name,
            'plugin_version': self.plugin_version,
            'timestamp': time.strftime("%Y-%m-%dT%H:%M:%S"),
            'metadata': {{'analysis_type': 'content_scan'}}
        }}}}

# Plugin entry point
plugin_instance = {plugin_name}()

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    return await plugin_instance.process(ctx, cfg)
'''

# Plugin entry point
plugin_instance = UniversalSecurityInterface()

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe plugin entry point"""
    return await plugin_instance.process(ctx, cfg)

if __name__ == "__main__":
    # Test the interface plugin
    import asyncio
    
    async def test():
        interface = UniversalSecurityInterface()
        
        # Test template generation
        result = await interface.process({
            'operation': 'create_plugin_template',
            'plugin_name': 'TestSecurityPlugin'
        }, {})
        
        print("Template generation result:")
        print(result['status'])
        if result['status'] == 'completed':
            print("Template created successfully!")
    
    asyncio.run(test())