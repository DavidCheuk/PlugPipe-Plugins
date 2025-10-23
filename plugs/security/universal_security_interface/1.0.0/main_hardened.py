#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Universal Security Plugin Interface Standard for PlugPipe - HARDENED VERSION
Provides standardized format and interface for all security plugins with comprehensive validation and error handling
"""

import asyncio
import os
import json
import time
import uuid
import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, asdict
from typing import Dict, List, Any, Optional, Union
from enum import Enum
import importlib.util

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

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
    """Standardized threat detection result with validation"""
    threat_id: str
    threat_type: str
    threat_level: ThreatLevel
    confidence: float  # 0.0 to 1.0
    description: str
    evidence: Dict[str, Any]
    recommendation: str
    start_position: Optional[int] = None
    end_position: Optional[int] = None
    
    def __post_init__(self):
        """Validate threat detection data"""
        if not isinstance(self.threat_id, str) or not self.threat_id.strip():
            raise ValueError("threat_id must be a non-empty string")
        
        if not isinstance(self.threat_type, str) or not self.threat_type.strip():
            raise ValueError("threat_type must be a non-empty string")
        
        if not isinstance(self.threat_level, ThreatLevel):
            raise ValueError("threat_level must be a ThreatLevel enum")
        
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        
        if not isinstance(self.description, str) or not self.description.strip():
            raise ValueError("description must be a non-empty string")
        
        if not isinstance(self.evidence, dict):
            raise ValueError("evidence must be a dictionary")
        
        if not isinstance(self.recommendation, str) or not self.recommendation.strip():
            raise ValueError("recommendation must be a non-empty string")
        
        if self.start_position is not None and not isinstance(self.start_position, int):
            raise ValueError("start_position must be an integer or None")
        
        if self.end_position is not None and not isinstance(self.end_position, int):
            raise ValueError("end_position must be an integer or None")
        
        if (self.start_position is not None and self.end_position is not None and 
            self.start_position > self.end_position):
            raise ValueError("start_position must be less than or equal to end_position")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with validation"""
        result = asdict(self)
        result['threat_level'] = self.threat_level.value
        return result

@dataclass
class SecurityPluginResult:
    """Standardized security plugin result format with validation"""
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
        """Validate security plugin result data"""
        if self.metadata is None:
            self.metadata = {}
        
        # Validate required fields
        if not isinstance(self.action, SecurityAction):
            raise ValueError("action must be a SecurityAction enum")
        
        if not isinstance(self.vote, SecurityAction):
            raise ValueError("vote must be a SecurityAction enum")
        
        if not isinstance(self.threat_score, (int, float)) or not (0.0 <= self.threat_score <= 1.0):
            raise ValueError("threat_score must be a number between 0.0 and 1.0")
        
        if not isinstance(self.threats_detected, list):
            raise ValueError("threats_detected must be a list")
        
        for threat in self.threats_detected:
            if not isinstance(threat, ThreatDetection):
                raise ValueError("All items in threats_detected must be ThreatDetection objects")
        
        if not isinstance(self.plugin_name, str) or not self.plugin_name.strip():
            raise ValueError("plugin_name must be a non-empty string")
        
        if not isinstance(self.plugin_version, str) or not self.plugin_version.strip():
            raise ValueError("plugin_version must be a non-empty string")
        
        if not isinstance(self.processing_time_ms, (int, float)) or self.processing_time_ms < 0:
            raise ValueError("processing_time_ms must be a non-negative number")
        
        if not isinstance(self.timestamp, str) or not self.timestamp.strip():
            raise ValueError("timestamp must be a non-empty string")
        
        if not isinstance(self.confidence, (int, float)) or not (0.0 <= self.confidence <= 1.0):
            raise ValueError("confidence must be a number between 0.0 and 1.0")
        
        if self.modified_content is not None and not isinstance(self.modified_content, str):
            raise ValueError("modified_content must be a string or None")
        
        if not isinstance(self.metadata, dict):
            raise ValueError("metadata must be a dictionary")
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization with validation"""
        result = asdict(self)
        # Convert enums to strings
        result['action'] = self.action.value
        result['vote'] = self.vote.value
        result['threats_detected'] = [threat.to_dict() for threat in self.threats_detected]
        return result

class SecurityPluginContext:
    """Standardized context for security plugin processing with validation"""
    
    def __init__(self, 
                 content: str,
                 operation: str = "analyze",
                 content_type: str = "text",
                 source_ip: Optional[str] = None,
                 user_id: Optional[str] = None,
                 request_id: Optional[str] = None,
                 metadata: Optional[Dict[str, Any]] = None):
        
        # Validate and sanitize inputs
        if not isinstance(content, str):
            raise ValueError("content must be a string")
        
        if not isinstance(operation, str) or not operation.strip():
            raise ValueError("operation must be a non-empty string")
        
        if not isinstance(content_type, str) or not content_type.strip():
            raise ValueError("content_type must be a non-empty string")
        
        if source_ip is not None:
            if not isinstance(source_ip, str) or not source_ip.strip():
                raise ValueError("source_ip must be a non-empty string or None")
            # Basic IP validation
            if not self._is_valid_ip(source_ip):
                logger.warning(f"Invalid IP format: {source_ip}")
        
        if user_id is not None:
            if not isinstance(user_id, str) or not user_id.strip():
                raise ValueError("user_id must be a non-empty string or None")
        
        if request_id is not None:
            if not isinstance(request_id, str) or not request_id.strip():
                raise ValueError("request_id must be a non-empty string or None")
        
        if metadata is not None and not isinstance(metadata, dict):
            raise ValueError("metadata must be a dictionary or None")
        
        self.content = content
        self.operation = operation
        self.content_type = content_type
        self.source_ip = source_ip
        self.user_id = user_id
        self.request_id = request_id or str(uuid.uuid4())
        self.metadata = metadata or {}
        self.timestamp = time.time()
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Basic IP address validation"""
        try:
            import ipaddress
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary with validation"""
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
    """Universal base class for all security plugins with validation"""
    
    def __init__(self):
        self.plugin_name = self.__class__.__name__
        self.plugin_version = "1.0.0"
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
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
        """Helper to create standardized threat detection with validation"""
        
        # Generate unique threat ID
        threat_id = f"{self.plugin_name}_{threat_type}_{int(time.time())}_{uuid.uuid4().hex[:8]}"
        
        return ThreatDetection(
            threat_id=threat_id,
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
        """Helper to create standardized result with validation"""
        
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
    """Wrapper to make legacy plugins compatible with universal interface - HARDENED"""
    
    def __init__(self, legacy_plugin, plugin_name: str):
        if not legacy_plugin:
            raise ValueError("legacy_plugin cannot be None")
        
        if not isinstance(plugin_name, str) or not plugin_name.strip():
            raise ValueError("plugin_name must be a non-empty string")
        
        self.legacy_plugin = legacy_plugin
        self.plugin_name = plugin_name
        self.logger = logging.getLogger(f"{__name__}.LegacyWrapper.{plugin_name}")
    
    async def analyze_content(self, context: SecurityPluginContext, config: Dict[str, Any]) -> SecurityPluginResult:
        """Convert legacy plugin calls to universal format with comprehensive error handling"""
        start_time = time.time()
        
        try:
            # Validate inputs
            if not isinstance(context, SecurityPluginContext):
                raise ValueError("context must be a SecurityPluginContext")
            
            if not isinstance(config, dict):
                raise ValueError("config must be a dictionary")
            
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
            
            # Call legacy plugin with timeout
            plugin_timeout = config.get('plugin_timeout', 30.0)
            
            if asyncio.iscoroutinefunction(self.legacy_plugin.process):
                legacy_result = await asyncio.wait_for(
                    self.legacy_plugin.process(legacy_context, config),
                    timeout=plugin_timeout
                )
            else:
                legacy_result = self.legacy_plugin.process(legacy_context, config)
            
            processing_time = (time.time() - start_time) * 1000
            
            # Convert legacy result to universal format
            return self._convert_legacy_result(legacy_result, processing_time)
            
        except asyncio.TimeoutError:
            processing_time = (time.time() - start_time) * 1000
            self.logger.error(f"Legacy plugin {self.plugin_name} timed out")
            return self._create_timeout_result(processing_time)
        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            self.logger.exception(f"Legacy plugin {self.plugin_name} failed: {str(e)}")
            return self._create_error_result(str(e), processing_time)
    
    def _create_timeout_result(self, processing_time: float) -> SecurityPluginResult:
        """Create timeout error result"""
        return SecurityPluginResult(
            action=SecurityAction.ALLOW,  # Fail open for timeout
            vote=SecurityAction.ALLOW,
            threat_score=0.0,
            threats_detected=[],
            plugin_name=self.plugin_name,
            plugin_version="legacy",
            processing_time_ms=processing_time,
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
            metadata={'error': 'timeout', 'legacy_plugin': True}
        )
    
    def _create_error_result(self, error_message: str, processing_time: float) -> SecurityPluginResult:
        """Create error result"""
        return SecurityPluginResult(
            action=SecurityAction.ALLOW,  # Fail open for errors
            vote=SecurityAction.ALLOW,
            threat_score=0.0,
            threats_detected=[],
            plugin_name=self.plugin_name,
            plugin_version="legacy",
            processing_time_ms=processing_time,
            timestamp=time.strftime('%Y-%m-%dT%H:%M:%S'),
            metadata={'error': error_message, 'legacy_plugin': True}
        )
    
    def _convert_legacy_result(self, legacy_result: Any, processing_time: float) -> SecurityPluginResult:
        """Convert legacy plugin result to universal format with validation"""
        
        threats = []
        action = SecurityAction.ALLOW
        threat_score = 0.0
        metadata = {'legacy_plugin': True}
        
        try:
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
                
                # Convert to SecurityAction enum with validation
                try:
                    action = SecurityAction(action_str.upper())
                except (ValueError, AttributeError):
                    self.logger.warning(f"Invalid action '{action_str}' from legacy plugin, defaulting to ALLOW")
                    action = SecurityAction.ALLOW
                
                # Extract and validate threat score
                try:
                    threat_score = float(legacy_result.get('threat_score', 
                                                       legacy_result.get('score', 
                                                       legacy_result.get('confidence', 0.0))))
                    if not (0.0 <= threat_score <= 1.0):
                        self.logger.warning(f"Invalid threat score {threat_score}, clamping to 0.0-1.0 range")
                        threat_score = max(0.0, min(1.0, threat_score))
                except (ValueError, TypeError):
                    self.logger.warning("Invalid threat score format, defaulting to 0.0")
                    threat_score = 0.0
                
                # Convert legacy threats to universal format with validation
                threats = self._convert_legacy_threats(legacy_result)
                
                # Preserve original metadata (filtered for safety)
                safe_metadata_keys = [
                    'processing_time', 'scan_time', 'patterns_checked', 'text_length',
                    'total_secrets', 'entities_found', 'analysis_type'
                ]
                
                for key, value in legacy_result.items():
                    if (key not in ['action', 'status', 'threat_score', 'threats_detected', 
                                  'security_threats', 'secrets_found', 'detected_entities'] and
                        key in safe_metadata_keys):
                        metadata[key] = value
            
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
            
        except Exception as e:
            self.logger.exception(f"Error converting legacy result: {str(e)}")
            return self._create_error_result(f"Conversion error: {str(e)}", processing_time)
    
    def _convert_legacy_threats(self, legacy_result: Dict[str, Any]) -> List[ThreatDetection]:
        """Convert legacy threat formats to universal ThreatDetection objects"""
        threats = []
        
        try:
            # Convert secrets_found
            if 'secrets_found' in legacy_result:
                for secret in legacy_result['secrets_found']:
                    if isinstance(secret, dict):
                        threats.append(ThreatDetection(
                            threat_id=f"legacy_secret_{uuid.uuid4().hex[:8]}",
                            threat_type=secret.get('type', 'secret'),
                            threat_level=ThreatLevel.HIGH,
                            confidence=min(max(secret.get('confidence', 0.9), 0.0), 1.0),
                            description=f"Secret detected: {secret.get('type', 'unknown')}",
                            evidence={
                                'secret_type': secret.get('type'),
                                'preview': secret.get('value_preview', '')[:50]  # Limit preview length
                            },
                            recommendation="Remove or encrypt secret",
                            start_position=secret.get('start'),
                            end_position=secret.get('end')
                        ))
            
            # Convert security_threats
            if 'security_threats' in legacy_result:
                for threat in legacy_result['security_threats']:
                    if isinstance(threat, dict):
                        try:
                            threat_level = ThreatLevel(threat.get('level', 'medium'))
                        except ValueError:
                            threat_level = ThreatLevel.MEDIUM
                        
                        threats.append(ThreatDetection(
                            threat_id=threat.get('threat_id', f"legacy_threat_{uuid.uuid4().hex[:8]}"),
                            threat_type=threat.get('threat_type', 'unknown'),
                            threat_level=threat_level,
                            confidence=min(max(threat.get('confidence', 0.5), 0.0), 1.0),
                            description=threat.get('description', '')[:200],  # Limit description length
                            evidence={'details': threat.get('details', {})},
                            recommendation=threat.get('recommendation', 'Review content')[:100]  # Limit length
                        ))
            
            # Convert detected_entities
            if 'detected_entities' in legacy_result:
                for entity in legacy_result['detected_entities']:
                    if isinstance(entity, dict):
                        threats.append(ThreatDetection(
                            threat_id=f"legacy_entity_{uuid.uuid4().hex[:8]}",
                            threat_type=entity.get('entity_type', 'pii'),
                            threat_level=ThreatLevel.MEDIUM,
                            confidence=min(max(entity.get('confidence', 0.7), 0.0), 1.0),
                            description=f"PII detected: {entity.get('entity_type', 'unknown')}",
                            evidence={
                                'entity_type': entity.get('entity_type'),
                                'text': str(entity.get('text_preview', ''))[:50]  # Limit and ensure string
                            },
                            recommendation="Sanitize or encrypt PII",
                            start_position=entity.get('start'),
                            end_position=entity.get('end')
                        ))
                        
        except Exception as e:
            self.logger.error(f"Error converting legacy threats: {str(e)}")
        
        return threats

class UniversalSecurityInterfaceHardened:
    """Main interface plugin for PlugPipe - HARDENED with comprehensive validation and error handling"""
    
    def __init__(self):
        self.plugin_name = "universal_security_interface"
        self.plugin_version = "1.0.0_hardened"
        self.supported_operations = [
            'create_plugin_template', 
            'validate_plugin_interface', 
            'wrap_legacy_plugin', 
            'get_interface_standard'
        ]
        self.logger = logging.getLogger(f"{__name__}.{self.__class__.__name__}")
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """PlugPipe plugin entry point with comprehensive error handling"""
        operation = ctx.get('operation', 'get_interface_standard')
        request_id = ctx.get('request_id', f"req_{int(time.time())}")
        
        # Input validation
        validation_result = self._validate_input(ctx, cfg)
        if validation_result:
            return validation_result
        
        try:
            self.logger.info(f"Processing operation: {operation}", extra={'request_id': request_id})
            
            if operation == 'create_plugin_template':
                return await self._create_plugin_template(ctx, cfg)
            elif operation == 'validate_plugin_interface':
                return await self._validate_plugin_interface(ctx, cfg)
            elif operation == 'wrap_legacy_plugin':
                return await self._wrap_legacy_plugin(ctx, cfg)
            elif operation == 'get_interface_standard':
                return await self._get_interface_standard(ctx, cfg)
            else:
                return self._create_error_response(
                    f'Unknown operation: {operation}',
                    operation,
                    request_id,
                    error_type='UnsupportedOperation',
                    additional_data={'supported_operations': self.supported_operations}
                )
        except ValueError as e:
            self.logger.error(f"Validation error in {operation}: {str(e)}", extra={'request_id': request_id})
            return self._create_error_response(
                f'Validation error: {str(e)}',
                operation,
                request_id,
                error_type='ValidationError'
            )
        except PermissionError as e:
            self.logger.error(f"Permission error in {operation}: {str(e)}", extra={'request_id': request_id})
            return self._create_error_response(
                f'Permission denied: {str(e)}',
                operation,
                request_id,
                error_type='PermissionError'
            )
        except FileNotFoundError as e:
            self.logger.error(f"File not found in {operation}: {str(e)}", extra={'request_id': request_id})
            return self._create_error_response(
                f'File not found: {str(e)}',
                operation,
                request_id,
                error_type='FileNotFoundError'
            )
        except Exception as e:
            self.logger.exception(f"Unexpected error in {operation}: {str(e)}", extra={'request_id': request_id})
            return self._create_error_response(
                f'Unexpected error: {str(e)}',
                operation,
                request_id,
                error_type='UnexpectedError'
            )
    
    def _validate_input(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Comprehensive input validation"""
        
        # Basic input validation
        if not isinstance(ctx, dict):
            return self._create_error_response(
                'Context must be a dictionary',
                'unknown',
                'validation_error',
                error_type='InvalidInput'
            )
        
        if not isinstance(cfg, dict):
            return self._create_error_response(
                'Configuration must be a dictionary',
                ctx.get('operation', 'unknown'),
                ctx.get('request_id', 'validation_error'),
                error_type='InvalidInput'
            )
        
        operation = ctx.get('operation', 'get_interface_standard')
        
        # Operation-specific validation
        if operation == 'create_plugin_template':
            plugin_name = ctx.get('plugin_name')
            if not plugin_name or not isinstance(plugin_name, str):
                return self._create_error_response(
                    'plugin_name is required and must be a string',
                    operation,
                    ctx.get('request_id', 'validation_error'),
                    error_type='MissingRequiredParameter'
                )
            
            # Validate plugin name format (security: prevent path traversal)
            if not re.match(r'^[a-zA-Z0-9_-]+$', plugin_name):
                return self._create_error_response(
                    'plugin_name must contain only alphanumeric characters, underscores, and hyphens',
                    operation,
                    ctx.get('request_id', 'validation_error'),
                    error_type='InvalidParameterFormat'
                )
            
            # Length limits
            if len(plugin_name) > 100:
                return self._create_error_response(
                    'plugin_name must be 100 characters or less',
                    operation,
                    ctx.get('request_id', 'validation_error'),
                    error_type='InvalidParameterLength'
                )
        
        elif operation in ['validate_plugin_interface', 'wrap_legacy_plugin']:
            plugin_path = ctx.get('plugin_path')
            plugin_name = ctx.get('plugin_name')
            
            if not plugin_path or not isinstance(plugin_path, str):
                return self._create_error_response(
                    'plugin_path is required and must be a string',
                    operation,
                    ctx.get('request_id', 'validation_error'),
                    error_type='MissingRequiredParameter'
                )
            
            if not plugin_name or not isinstance(plugin_name, str):
                return self._create_error_response(
                    'plugin_name is required and must be a string',
                    operation,
                    ctx.get('request_id', 'validation_error'),
                    error_type='MissingRequiredParameter'
                )
            
            # Security: validate path (prevent path traversal)
            if '..' in plugin_path or plugin_path.startswith('/'):
                return self._create_error_response(
                    'Invalid plugin_path: path traversal not allowed',
                    operation,
                    ctx.get('request_id', 'validation_error'),
                    error_type='SecurityViolation'
                )
            
            # Validate plugin name
            if not re.match(r'^[a-zA-Z0-9_-]+$', plugin_name):
                return self._create_error_response(
                    'plugin_name must contain only alphanumeric characters, underscores, and hyphens',
                    operation,
                    ctx.get('request_id', 'validation_error'),
                    error_type='InvalidParameterFormat'
                )
        
        return None  # No validation errors
    
    def _create_error_response(self, 
                             error_message: str, 
                             operation: str, 
                             request_id: str,
                             error_type: str = 'Error',
                             additional_data: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Create standardized error response"""
        
        error_response = {
            'status': 'error',
            'error': str(error_message),
            'error_type': error_type,
            'operation': operation,
            'request_id': request_id,
            'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S'),
            'plugin_name': self.plugin_name,
            'plugin_version': self.plugin_version
        }
        
        if additional_data:
            error_response.update(additional_data)
        
        return error_response
    
    async def _create_plugin_template(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Generate template for new universal security plugin with validation"""
        plugin_name = ctx.get('plugin_name')
        plugin_version = ctx.get('plugin_version', '1.0.0')
        request_id = ctx.get('request_id', f"req_{int(time.time())}")
        
        try:
            template = self._generate_plugin_template(plugin_name, plugin_version)
            
            return {
                'status': 'completed',
                'plugin_name': plugin_name,
                'plugin_version': plugin_version,
                'template': template,
                'interface_version': self.plugin_version,
                'request_id': request_id,
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
            }
        except Exception as e:
            self.logger.exception(f"Error generating plugin template: {str(e)}")
            return self._create_error_response(
                f'Template generation failed: {str(e)}',
                'create_plugin_template',
                request_id,
                error_type='TemplateGenerationError'
            )
    
    async def _get_interface_standard(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get the universal interface standard with validation"""
        format_type = ctx.get('format', 'classes')
        request_id = ctx.get('request_id', f"req_{int(time.time())}")
        
        if format_type == 'classes':
            return {
                'status': 'completed',
                'interface_classes': {
                    'SecurityAction': [action.value for action in SecurityAction],
                    'ThreatLevel': [level.value for level in ThreatLevel],
                    'SecurityPluginResult': 'Standardized result format with validation',
                    'SecurityPluginContext': 'Standardized context format with validation',
                    'ThreatDetection': 'Standardized threat detection format with validation',
                    'UniversalSecurityPlugin': 'Base class for security plugins with validation'
                },
                'interface_version': self.plugin_version,
                'request_id': request_id,
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
            }
        elif format_type == 'schema':
            return {
                'status': 'completed',
                'schema': {
                    'SecurityPluginResult': {
                        'action': 'SecurityAction enum (ALLOW|BLOCK|MODIFY|REVIEW)',
                        'vote': 'SecurityAction enum (for consensus)',
                        'threat_score': 'float 0.0-1.0 (validated)',
                        'threats_detected': 'List[ThreatDetection] (validated)',
                        'plugin_name': 'string (non-empty, validated)',
                        'plugin_version': 'string (non-empty, validated)',
                        'processing_time_ms': 'float (non-negative, validated)',
                        'timestamp': 'string ISO format (validated)'
                    },
                    'ThreatDetection': {
                        'threat_id': 'string (unique, non-empty)',
                        'threat_type': 'string (non-empty)',
                        'threat_level': 'ThreatLevel enum (validated)',
                        'confidence': 'float 0.0-1.0 (validated)',
                        'description': 'string (non-empty)',
                        'evidence': 'dict (validated)',
                        'recommendation': 'string (non-empty)'
                    }
                },
                'interface_version': self.plugin_version,
                'request_id': request_id,
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
            }
        else:
            return {
                'status': 'completed',
                'documentation': 'Universal Security Plugin Interface Standard for PlugPipe - Hardened Version',
                'features': [
                    'Comprehensive input validation',
                    'Type checking and sanitization',
                    'Error handling and logging',
                    'Security measures (path traversal prevention)',
                    'Graceful degradation',
                    'Legacy plugin compatibility'
                ],
                'interface_version': self.plugin_version,
                'request_id': request_id,
                'timestamp': time.strftime('%Y-%m-%dT%H:%M:%S')
            }
    
    def _generate_plugin_template(self, plugin_name: str, plugin_version: str) -> str:
        """Generate hardened template code for new plugin"""
        return f'''#!/usr/bin/env python3
"""
{plugin_name} - Universal Security Plugin (HARDENED)
Follows PlugPipe Universal Security Plugin Interface Standard with comprehensive validation
"""

import asyncio
import time
import logging
from typing import Dict, Any, List
from shares.loader import pp

# Import universal interface components
try:
    from shares.security.universal_security_plugin_interface import (
        UniversalSecurityPlugin, SecurityPluginContext, SecurityPluginResult,
        SecurityAction, ThreatLevel, ThreatDetection
    )
except ImportError:
    # Fallback if universal interface not available
    print("Warning: Universal security interface not available")
    
    class SecurityAction:
        ALLOW = "ALLOW"
        BLOCK = "BLOCK"
        
    class ThreatLevel:
        LOW = "low"
        HIGH = "high"

class {plugin_name}(UniversalSecurityPlugin):
    """
    {plugin_name} security plugin following universal interface with validation
    """
    
    def __init__(self):
        super().__init__()
        self.plugin_name = "{plugin_name}"
        self.plugin_version = "{plugin_version}"
        self.logger = logging.getLogger(f"{{__name__}}.{plugin_name}")
    
    async def analyze_content(self, context: SecurityPluginContext, config: Dict[str, Any]) -> SecurityPluginResult:
        """
        Analyze content for security threats with comprehensive validation
        
        Args:
            context: SecurityPluginContext with content to analyze
            config: Plugin configuration
            
        Returns:
            SecurityPluginResult with standardized format
        """
        start_time = time.time()
        threats = []
        threat_score = 0.0
        
        try:
            # Validate inputs
            if not isinstance(context, SecurityPluginContext):
                raise ValueError("Invalid context type")
            
            if not isinstance(config, dict):
                raise ValueError("Invalid config type")
            
            content = context.content
            if not content:
                self.logger.info("Empty content provided")
                return self.create_result(
                    action=SecurityAction.ALLOW,
                    threat_score=0.0,
                    threats=[],
                    metadata={{"analysis_type": "empty_content", "processing_time_ms": (time.time() - start_time) * 1000}}
                )
            
            # FTHAD IMPLEMENTATION: Comprehensive security analysis logic
            # Multi-layered threat detection system

            # 1. SQL Injection Detection
            sql_injection_patterns = [
                r"(\b(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|EXEC|UNION)\b.*\b(FROM|INTO|WHERE|SET|VALUES)\b)",
                r"('.*OR.*'.*=.*')",  # OR-based injection
                r"(\b1\s*=\s*1\b)",   # Always true condition
                r"(;.*--)",           # SQL comment injection
                r"(\|\|.*CONCAT)",    # String concatenation
                r"(\bxp_cmdshell\b)",  # Command execution
                r"(\bsp_executesql\b)" # SQL Server execution
            ]

            for pattern in sql_injection_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="sql_injection",
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.85,
                        description="SQL injection pattern detected",
                        evidence={"pattern": pattern, "content_preview": content[:100]},
                        recommendation="Block SQL injection attempt immediately"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.9)

            # 2. Cross-Site Scripting (XSS) Detection
            xss_patterns = [
                r"<script[^>]*>.*?</script>",
                r"javascript:",
                r"on\w+\s*=",  # Event handlers
                r"eval\s*\(",
                r"document\.cookie",
                r"window\.location",
                r"<iframe[^>]*>",
                r"<object[^>]*>",
                r"<embed[^>]*>"
            ]

            for pattern in xss_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="xss_attempt",
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        description="Cross-site scripting pattern detected",
                        evidence={"pattern": pattern, "content_preview": content[:100]},
                        recommendation="Sanitize or block XSS attempt"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.8)

            # 3. Command Injection Detection
            command_injection_patterns = [
                r"(\||&|;|`|\$\(|\${).*\b(cat|ls|ps|kill|rm|mv|cp|chmod|sudo|su|passwd|whoami|id|uname)\b",
                r"(\.\./){2,}",  # Path traversal
                r"\b(system|exec|shell_exec|passthru|eval)\s*\(",
                r"(\||&|;)\s*(wget|curl|nc|netcat|telnet)",
                r"/bin/(bash|sh|csh|ksh|zsh)",
                r"cmd\.exe|powershell\.exe"
            ]

            for pattern in command_injection_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="command_injection",
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.9,
                        description="Command injection pattern detected",
                        evidence={"pattern": pattern, "content_preview": content[:100]},
                        recommendation="Block command injection attempt immediately"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.95)

            # 4. Path Traversal Detection
            path_traversal_patterns = [
                r"(\.\./){2,}",
                r"\.\.\\",
                r"/%2e%2e/",
                r"\\\.\.\\",
                r"/etc/passwd",
                r"/etc/shadow",
                r"C:\\Windows\\System32",
                r"%systemroot%",
                r"\$HOME"
            ]

            for pattern in path_traversal_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="path_traversal",
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.75,
                        description="Path traversal attempt detected",
                        evidence={"pattern": pattern, "content_preview": content[:100]},
                        recommendation="Block path traversal attempt"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.8)

            # 5. Credential Exposure Detection
            credential_patterns = [
                r"password\s*[:=]\s*['\"][^'\"]{3,}['\"]",
                r"api[_-]?key\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                r"secret[_-]?key\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                r"access[_-]?token\s*[:=]\s*['\"][^'\"]{10,}['\"]",
                r"bearer\s+[a-zA-Z0-9]{20,}",
                r"ssh-rsa\s+[A-Za-z0-9+/]{100,}",
                r"-----BEGIN\s+(RSA\s+)?PRIVATE\s+KEY-----",
                r"[A-Za-z0-9+/]{40,}={0,2}"  # Base64 encoded secrets
            ]

            for pattern in credential_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="credential_exposure",
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.7,
                        description="Potential credential exposure detected",
                        evidence={"pattern": pattern, "content_preview": "*** REDACTED ***"},
                        recommendation="Review and secure exposed credentials immediately"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.85)

            # 6. Malware Signature Detection
            malware_patterns = [
                r"powershell.*-EncodedCommand",
                r"cmd.*\/c.*echo.*>.*\.bat",
                r"certutil.*-decode",
                r"bitsadmin.*\/transfer",
                r"regsvr32.*\/s.*\/u.*scrobj\.dll",
                r"mshta.*javascript:",
                r"wscript.*\.shell",
                r"CreateObject.*WScript\.Shell"
            ]

            for pattern in malware_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="malware_signature",
                        threat_level=ThreatLevel.CRITICAL,
                        confidence=0.9,
                        description="Malware signature pattern detected",
                        evidence={"pattern": pattern, "content_preview": content[:100]},
                        recommendation="Block malware execution attempt immediately"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.95)

            # 7. Data Exfiltration Detection
            exfiltration_patterns = [
                r"curl.*-d.*@",  # Data upload via curl
                r"wget.*--post-data",
                r"base64.*-d.*\|.*sh",
                r"gzip.*-c.*\|.*nc",
                r"tar.*-c.*\|.*nc",
                r"dd.*if=.*\|.*nc"
            ]

            for pattern in exfiltration_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="data_exfiltration",
                        threat_level=ThreatLevel.HIGH,
                        confidence=0.8,
                        description="Data exfiltration pattern detected",
                        evidence={"pattern": pattern, "content_preview": content[:100]},
                        recommendation="Block data exfiltration attempt"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.85)

            # 8. Suspicious Network Activity Detection
            network_patterns = [
                r"\b(?:\d{1,3}\.){3}\d{1,3}:\d{1,5}\b",  # IP:Port combinations
                r"nc\s+-l\s+-p\s+\d+",  # Netcat listeners
                r"python.*-c.*socket",   # Python reverse shells
                r"bash.*-i.*>&.*\/dev\/tcp",  # Bash reverse shells
                r"telnet.*\d+.*\d+",     # Telnet connections
                r"ssh.*-R.*:.*:"         # SSH tunneling
            ]

            for pattern in network_patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    threat = self.create_threat_detection(
                        threat_type="suspicious_network",
                        threat_level=ThreatLevel.MEDIUM,
                        confidence=0.6,
                        description="Suspicious network activity pattern detected",
                        evidence={"pattern": pattern, "content_preview": content[:100]},
                        recommendation="Review network activity for legitimacy"
                    )
                    threats.append(threat)
                    threat_score = max(threat_score, 0.6)
            
            # Determine action based on analysis
            if threat_score > 0.7:
                action = SecurityAction.BLOCK
            elif threat_score > 0.5:
                action = SecurityAction.REVIEW
            else:
                action = SecurityAction.ALLOW
            
            processing_time = (time.time() - start_time) * 1000
            
            result = self.create_result(
                action=action,
                threat_score=threat_score,
                threats=threats,
                confidence=1.0,
                metadata={{
                    "analysis_type": "content_scan",
                    "patterns_checked": 1,  # Update based on your implementation
                    "processing_time_ms": processing_time
                }}
            )
            
            # Update processing time
            result.processing_time_ms = processing_time
            
            self.logger.info(f"Analysis completed: {{action.value}} (score: {{threat_score}})")
            return result
            
        except Exception as e:
            processing_time = (time.time() - start_time) * 1000
            self.logger.exception(f"Error during analysis: {str(e)}")
            
            # Return safe default on error
            return self.create_result(
                action=SecurityAction.ALLOW,  # Fail open
                threat_score=0.0,
                threats=[],
                confidence=0.0,
                metadata={{
                    "error": str(e),
                    "analysis_type": "error_fallback",
                    "processing_time_ms": processing_time
                }}
            )

# Plugin entry point for PlugPipe with error handling
class PluginWrapper:
    def __init__(self):
        self.plugin = {plugin_name}()
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        PlugPipe plugin entry point with comprehensive error handling
        """
        try:
            # Validate inputs
            if not isinstance(ctx, dict):
                return {{"status": "error", "error": "Context must be a dictionary"}}
            
            if not isinstance(cfg, dict):
                return {{"status": "error", "error": "Config must be a dictionary"}}
            
            # Convert legacy context to universal context
            content = ctx.get('text', ctx.get('payload', ctx.get('content', '')))
            
            context = SecurityPluginContext(
                content=str(content) if content else '',
                operation=ctx.get('operation', 'analyze'),
                content_type=ctx.get('content_type', 'text'),
                source_ip=ctx.get('source_ip'),
                user_id=ctx.get('user_id'),
                request_id=ctx.get('request_id'),
                metadata={{k: v for k, v in ctx.items() 
                          if k not in ['text', 'payload', 'content']}}
            )
            
            # Process through universal interface
            result = await self.plugin.analyze_content(context, cfg)
            
            # Return in universal format
            return result.to_dict()
            
        except Exception as e:
            return {{
                "status": "error",
                "error": str(e),
                "plugin_name": "{plugin_name}",
                "plugin_version": "{plugin_version}",
                "timestamp": time.strftime('%Y-%m-%dT%H:%M:%S')
            }}

# Plugin instance
plugin_wrapper = PluginWrapper()

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe async entry point"""
    return await plugin_wrapper.process(ctx, cfg)

if __name__ == "__main__":
    # Test the plugin
    import asyncio
    
    async def test():
        plugin = UniversalSecurityInterfaceHardened()
        
        test_cases = [
            "normal text content",
            "malicious_pattern in text",
            "",
            "test with various patterns"
        ]
        
        for test_content in test_cases:
            try:
                context = SecurityPluginContext(content=test_content)
                result = await plugin.analyze_content(context, {})
                
                print(f"Content: {test_content[:30]}...")
                print(f"Action: {result.action.value}")
                print(f"Threat Score: {result.threat_score}")
                print(f"Threats: {len(result.threats_detected) if hasattr(result, 'threats_detected') else 0}")
                print("-" * 40)
            except Exception as e:
                print(f"Test failed: {str(e)}")
    
    asyncio.run(test())
'''

# Plugin entry point - HARDENED VERSION
plugin_instance = UniversalSecurityInterfaceHardened()

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe plugin entry point - HARDENED with comprehensive security validation"""

    # FTHAD HARDENING: Input validation and sanitization
    if not isinstance(ctx, dict):
        raise ValueError("Context must be a dictionary")
    if not isinstance(cfg, dict):
        raise ValueError("Configuration must be a dictionary")

    # Security validation for configuration
    if 'max_payload_size' in cfg:
        max_size = cfg.get('max_payload_size', 10485760)  # 10MB default
        if not isinstance(max_size, int) or max_size < 0 or max_size > 104857600:  # 100MB max
            raise ValueError("Invalid max_payload_size: must be positive integer <= 100MB")

    # Validate threat level configuration
    if 'threat_levels' in cfg:
        valid_levels = {'low', 'medium', 'high', 'critical'}
        threat_levels = cfg.get('threat_levels', [])
        if not isinstance(threat_levels, list):
            raise ValueError("threat_levels must be a list")
        for level in threat_levels:
            if level not in valid_levels:
                raise ValueError(f"Invalid threat level: {level}. Must be one of {valid_levels}")

    # DoS protection - limit context size
    ctx_str = str(ctx)
    if len(ctx_str) > 1048576:  # 1MB limit
        raise ValueError("Context size exceeds maximum allowed (1MB)")

    # Sanitize string inputs in context
    sanitized_ctx = {}
    for key, value in ctx.items():
        if isinstance(key, str):
            # Remove potential injection patterns from keys
            key_clean = re.sub(r'[<>"\';\\]+', '', str(key))
            if len(key_clean) > 100:  # Limit key length
                key_clean = key_clean[:100]
        else:
            key_clean = key

        if isinstance(value, str):
            # Basic sanitization for string values
            value_clean = re.sub(r'[<>"\x00-\x1f]+', '', str(value))
            if len(value_clean) > 10000:  # Limit value length
                value_clean = value_clean[:10000]
        else:
            value_clean = value

        sanitized_ctx[key_clean] = value_clean

    try:
        # Execute with hardened context
        result = await plugin_instance.process(sanitized_ctx, cfg)

        # Validate output structure
        if not isinstance(result, dict):
            raise ValueError("Plugin must return a dictionary")

        return result

    except Exception as e:
        # Security-aware error handling
        error_msg = str(e)
        # Sanitize error message to prevent information leakage
        if len(error_msg) > 500:
            error_msg = error_msg[:500] + "..."

        return {
            "success": False,
            "error": "Security validation failed",
            "details": re.sub(r'[<>"\';\\]+', '', error_msg),
            "timestamp": datetime.now().isoformat()
        }

if __name__ == "__main__":
    # Test the hardened interface plugin
    import asyncio
    
    async def test():
        interface = UniversalSecurityInterfaceHardened()
        
        # Test template generation
        result = await interface.process({
            'operation': 'create_plugin_template',
            'plugin_name': 'TestSecurityPlugin'
        }, {})
        
        print("Hardened Interface Test Results:")
        print(f"Template generation: {result.get('status')}")
        if result.get('status') == 'completed':
            print("✅ Template created successfully!")
            print(f"Template length: {len(result.get('template', ''))} characters")
        else:
            print(f"❌ Template creation failed: {result.get('error')}")
    
    asyncio.run(test())