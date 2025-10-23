#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
FTHAD-Enhanced MCP Guardian - Enterprise Security Orchestrator & Proxy
Phase 1 (FIX): Comprehensive Security Hardening Applied

FTHAD Methodology: Fix-Test-Harden-Audit-Doc
- Enterprise plugin orchestration with health monitoring
- Advanced threat correlation and scoring algorithms
- Universal Input Sanitizer plugin integration (REUSE EVERYTHING principle)
- Circuit breaker patterns for plugin failure handling
- Real-time security analytics and reporting
- Enterprise audit logging with correlation tracking
- Rate limiting with adaptive thresholds
- Fail-secure orchestration with graceful degradation
- Plugin lifecycle management with performance monitoring
- Advanced AI model availability management

Integration Features:
- Leverages existing universal_input_sanitizer plugin for consistent validation
- Two-phase security scanning: input sanitization → threat analysis
- Standardized security component reuse across PlugPipe ecosystem
- Maintains separation of concerns while ensuring comprehensive protection
"""

import time
import sys
import os
import json
import re
import uuid
import threading
import hashlib
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime, timedelta
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum
import concurrent.futures

# Add project root to path for plugin loading
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))

class PluginStatus(Enum):
    """Plugin status enumeration"""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    FAILED = "failed"
    CIRCUIT_OPEN = "circuit_open"
    UNKNOWN = "unknown"

class ThreatLevel(Enum):
    """Threat level enumeration"""
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

@dataclass
class PluginHealth:
    """Plugin health tracking"""
    name: str
    status: PluginStatus = PluginStatus.UNKNOWN
    last_success: Optional[datetime] = None
    last_failure: Optional[datetime] = None
    failure_count: int = 0
    success_count: int = 0
    avg_response_time: float = 0.0
    circuit_breaker_open: bool = False
    circuit_breaker_open_until: Optional[datetime] = None

@dataclass
class ThreatEvent:
    """Structured threat event"""
    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    plugin_name: str = ""
    threat_type: str = ""
    threat_level: ThreatLevel = ThreatLevel.NONE
    confidence: float = 0.0
    description: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.utcnow)

class OrchestrationAuditLogger:
    """Enterprise audit logging for orchestration events with correlation tracking"""

    def __init__(self, max_events: int = 50000):
        self.audit_events = deque(maxlen=max_events)
        self.threat_events = deque(maxlen=10000)
        self.lock = threading.Lock()

    def log_orchestration_event(self, event_type: str, orchestration_id: str,
                               details: Dict[str, Any], severity: str = "INFO"):
        """Log structured orchestration events"""
        with self.lock:
            event = {
                "timestamp": datetime.utcnow().isoformat(),
                "event_id": str(uuid.uuid4()),
                "orchestration_id": orchestration_id,
                "event_type": event_type,
                "severity": severity,
                "details": details,
                "plugin": "mcp_guardian"
            }
            self.audit_events.append(event)

    def log_threat_event(self, threat: ThreatEvent, orchestration_id: str):
        """Log threat events with correlation"""
        with self.lock:
            event = {
                "timestamp": threat.timestamp.isoformat(),
                "event_id": threat.event_id,
                "orchestration_id": orchestration_id,
                "plugin_name": threat.plugin_name,
                "threat_type": threat.threat_type,
                "threat_level": threat.threat_level.value,
                "confidence": threat.confidence,
                "description": threat.description,
                "metadata": threat.metadata
            }
            self.threat_events.append(event)

    def get_recent_events(self, limit: int = 100, event_type: str = "all") -> List[Dict[str, Any]]:
        """Retrieve recent events with filtering"""
        with self.lock:
            if event_type == "threats":
                return list(self.threat_events)[-limit:]
            elif event_type == "orchestration":
                return list(self.audit_events)[-limit:]
            else:
                # Merge and sort by timestamp
                all_events = list(self.audit_events) + list(self.threat_events)
                all_events.sort(key=lambda x: x["timestamp"])
                return all_events[-limit:]

class OrchestrationRateLimiter:
    """Advanced rate limiting for orchestration requests with adaptive thresholds"""

    def __init__(self):
        self.request_history = defaultdict(deque)
        self.blocked_requestors = {}
        self.adaptive_thresholds = defaultdict(lambda: 100)  # Dynamic per-requestor limits
        self.lock = threading.Lock()

    def check_rate_limit(self, requestor_id: str, base_limit: int = 100,
                        window_seconds: int = 60) -> Tuple[bool, Dict[str, Any]]:
        """Check rate limits with adaptive thresholds based on threat history"""
        with self.lock:
            now = time.time()
            requestor_requests = self.request_history[requestor_id]

            # Clean old requests
            while requestor_requests and requestor_requests[0] < now - window_seconds:
                requestor_requests.popleft()

            # Check if requestor is blocked
            if requestor_id in self.blocked_requestors:
                if now < self.blocked_requestors[requestor_id]:
                    return False, {
                        "blocked": True,
                        "reason": "Rate limit exceeded - adaptive backoff in effect",
                        "unblock_time": self.blocked_requestors[requestor_id]
                    }
                else:
                    del self.blocked_requestors[requestor_id]

            # Get adaptive threshold for this requestor
            current_limit = min(self.adaptive_thresholds[requestor_id], base_limit * 2)
            current_requests = len(requestor_requests)

            if current_requests >= current_limit:
                # Calculate adaptive backoff based on threat history
                base_backoff = 60
                threat_multiplier = max(1.0, current_requests / current_limit)
                block_duration = min(600, base_backoff * threat_multiplier)

                self.blocked_requestors[requestor_id] = now + block_duration

                return False, {
                    "blocked": True,
                    "reason": "Rate limit exceeded",
                    "current_requests": current_requests,
                    "adaptive_limit": current_limit,
                    "block_duration": block_duration,
                    "threat_multiplier": threat_multiplier
                }

            requestor_requests.append(now)
            return True, {
                "allowed": True,
                "current_requests": current_requests + 1,
                "adaptive_limit": current_limit
            }

    def adjust_threshold(self, requestor_id: str, threat_level: ThreatLevel):
        """Adjust rate limit threshold based on threat behavior"""
        with self.lock:
            current = self.adaptive_thresholds[requestor_id]

            if threat_level in [ThreatLevel.HIGH, ThreatLevel.CRITICAL]:
                # Reduce threshold for high-threat requestors
                self.adaptive_thresholds[requestor_id] = max(10, current * 0.5)
            elif threat_level == ThreatLevel.MEDIUM:
                self.adaptive_thresholds[requestor_id] = max(25, current * 0.75)
            elif threat_level == ThreatLevel.NONE:
                # Gradually restore threshold for clean requestors
                self.adaptive_thresholds[requestor_id] = min(200, current * 1.1)

class OrchestrationInputValidator:
    """Lightweight input validation for orchestration requests (delegates to universal_input_sanitizer)"""

    @classmethod
    def validate_operation(cls, operation: str) -> Tuple[bool, List[str]]:
        """Validate operation type"""
        threats = []
        valid_operations = ['health_check', 'get_status', 'scan', 'security_scan', 'orchestrate']
        if operation not in valid_operations:
            threats.append(f"Invalid operation: {operation}")
        return len(threats) == 0, threats

    @classmethod
    def sanitize_basic_input(cls, value: str, max_length: int = 10000) -> str:
        """Basic input sanitization for non-content fields (operation, requestor_id, etc.)"""
        if not isinstance(value, str):
            value = str(value)

        # Truncate to max length
        value = value[:max_length]

        # Remove basic dangerous characters for orchestration metadata
        dangerous_chars = r'[<>"\'\\\x00-\x1f\x7f-\x9f]'
        sanitized = re.sub(dangerous_chars, '', value)

        # Normalize whitespace
        sanitized = re.sub(r'\s+', ' ', sanitized).strip()

        return sanitized

class PluginCircuitBreaker:
    """Circuit breaker pattern for plugin fault tolerance"""

    def __init__(self, failure_threshold: int = 5, recovery_timeout: int = 60):
        self.failure_threshold = failure_threshold
        self.recovery_timeout = recovery_timeout
        self.plugin_states = defaultdict(lambda: {
            'failures': 0,
            'last_failure': None,
            'state': 'closed',  # closed, open, half_open
            'last_success': None
        })
        self.lock = threading.Lock()

    def can_execute(self, plugin_name: str) -> bool:
        """Check if plugin can be executed based on circuit breaker state"""
        with self.lock:
            state = self.plugin_states[plugin_name]
            now = datetime.utcnow()

            if state['state'] == 'open':
                # Check if recovery timeout has passed
                if state['last_failure'] and (now - state['last_failure']).seconds > self.recovery_timeout:
                    state['state'] = 'half_open'
                    return True
                return False

            return True  # closed or half_open

    def record_success(self, plugin_name: str):
        """Record successful plugin execution"""
        with self.lock:
            state = self.plugin_states[plugin_name]
            state['failures'] = 0
            state['last_success'] = datetime.utcnow()
            state['state'] = 'closed'

    def record_failure(self, plugin_name: str):
        """Record failed plugin execution"""
        with self.lock:
            state = self.plugin_states[plugin_name]
            state['failures'] += 1
            state['last_failure'] = datetime.utcnow()

            if state['failures'] >= self.failure_threshold:
                state['state'] = 'open'

class ThreatCorrelationEngine:
    """Advanced threat correlation and scoring"""

    def __init__(self):
        self.threat_patterns = defaultdict(list)
        self.correlation_rules = self._initialize_correlation_rules()

    def _initialize_correlation_rules(self) -> Dict[str, Dict[str, Any]]:
        """Initialize threat correlation rules"""
        return {
            "multi_vector_attack": {
                "description": "Multiple threat types detected simultaneously",
                "threshold": 3,
                "scoring_multiplier": 2.0,
                "confidence_boost": 0.3
            },
            "repeated_threats": {
                "description": "Same threat type detected by multiple plugins",
                "threshold": 2,
                "scoring_multiplier": 1.5,
                "confidence_boost": 0.2
            },
            "high_confidence_consensus": {
                "description": "High confidence threats with consensus",
                "threshold": 0.8,
                "scoring_multiplier": 1.8,
                "confidence_boost": 0.25
            }
        }

    def correlate_threats(self, threat_events: List[ThreatEvent]) -> Dict[str, Any]:
        """Correlate threat events and calculate composite threat score"""
        if not threat_events:
            return {
                "composite_threat_level": ThreatLevel.NONE,
                "composite_score": 0.0,
                "correlation_analysis": {},
                "recommendations": []
            }

        # Group threats by type
        threat_by_type = defaultdict(list)
        for threat in threat_events:
            threat_by_type[threat.threat_type].append(threat)

        # Calculate base threat score
        base_score = sum(threat.threat_level.value * threat.confidence for threat in threat_events)
        base_score = base_score / len(threat_events) if threat_events else 0.0

        correlation_analysis = {}
        score_multiplier = 1.0
        confidence_adjustment = 0.0

        # Apply correlation rules
        unique_threat_types = len(threat_by_type.keys())

        # Multi-vector attack detection
        if unique_threat_types >= self.correlation_rules["multi_vector_attack"]["threshold"]:
            correlation_analysis["multi_vector_attack"] = True
            score_multiplier *= self.correlation_rules["multi_vector_attack"]["scoring_multiplier"]
            confidence_adjustment += self.correlation_rules["multi_vector_attack"]["confidence_boost"]

        # Repeated threat pattern detection
        for threat_type, threats in threat_by_type.items():
            if len(threats) >= self.correlation_rules["repeated_threats"]["threshold"]:
                correlation_analysis[f"repeated_{threat_type}"] = len(threats)
                score_multiplier *= self.correlation_rules["repeated_threats"]["scoring_multiplier"]

        # High confidence consensus
        high_confidence_threats = [t for t in threat_events if t.confidence >= 0.8]
        if len(high_confidence_threats) >= 2:
            correlation_analysis["high_confidence_consensus"] = len(high_confidence_threats)
            score_multiplier *= self.correlation_rules["high_confidence_consensus"]["scoring_multiplier"]
            confidence_adjustment += self.correlation_rules["high_confidence_consensus"]["confidence_boost"]

        # Calculate final composite score
        composite_score = min(4.0, base_score * score_multiplier)
        final_confidence = min(1.0, sum(t.confidence for t in threat_events) / len(threat_events) + confidence_adjustment)

        # Determine composite threat level
        if composite_score >= 3.5:
            composite_level = ThreatLevel.CRITICAL
        elif composite_score >= 2.5:
            composite_level = ThreatLevel.HIGH
        elif composite_score >= 1.5:
            composite_level = ThreatLevel.MEDIUM
        elif composite_score >= 0.5:
            composite_level = ThreatLevel.LOW
        else:
            composite_level = ThreatLevel.NONE

        # Generate recommendations
        recommendations = self._generate_recommendations(composite_level, correlation_analysis)

        return {
            "composite_threat_level": composite_level,
            "composite_score": composite_score,
            "composite_confidence": final_confidence,
            "correlation_analysis": correlation_analysis,
            "threat_breakdown": {t_type: len(threats) for t_type, threats in threat_by_type.items()},
            "recommendations": recommendations
        }

    def _generate_recommendations(self, threat_level: ThreatLevel,
                                correlation_analysis: Dict[str, Any]) -> List[str]:
        """Generate security recommendations based on threat analysis"""
        recommendations = []

        if threat_level == ThreatLevel.CRITICAL:
            recommendations.extend([
                "IMMEDIATE ACTION REQUIRED: Block request and investigate",
                "Escalate to security team for manual review",
                "Consider temporary IP/user blocking"
            ])
        elif threat_level == ThreatLevel.HIGH:
            recommendations.extend([
                "Block request and log for security review",
                "Increase monitoring for this source",
                "Consider rate limiting adjustments"
            ])
        elif threat_level == ThreatLevel.MEDIUM:
            recommendations.extend([
                "Enhanced logging and monitoring recommended",
                "Consider additional verification steps"
            ])

        if correlation_analysis.get("multi_vector_attack"):
            recommendations.append("Multi-vector attack detected - implement comprehensive blocking")

        if any(key.startswith("repeated_") for key in correlation_analysis.keys()):
            recommendations.append("Repeated threat patterns detected - consider pattern-based blocking")

        return recommendations

class MCPGuardianOrchestrator:
    """Enterprise-grade MCP Guardian orchestrator with comprehensive hardening"""

    def __init__(self):
        self.audit_logger = OrchestrationAuditLogger()
        self.rate_limiter = OrchestrationRateLimiter()
        self.circuit_breaker = PluginCircuitBreaker()
        self.correlation_engine = ThreatCorrelationEngine()
        self.plugin_health = {}
        self.security_plugins = self._initialize_security_plugins()

    def _initialize_security_plugins(self) -> List[Dict[str, Any]]:
        """Initialize security plugins with enhanced metadata and universal input sanitizer integration"""
        return [
            {
                'name': 'universal_input_sanitizer',
                'priority': 0,  # First priority for input validation
                'threat_categories': ['input_validation', 'sanitization'],
                'params_template': {
                    'input_data': None,
                    'sanitization_types': ['all']
                },
                'is_input_validator': True  # Special flag for pre-processing
            },
            {
                'name': 'mcp_security_policy_engine',
                'priority': 1,
                'threat_categories': ['policy_violation', 'access_control'],
                'params_template': {
                    'text': None,
                    'operation': 'analyze',
                    'action': 'query',
                    'resource': 'database'
                }
            },
            {
                'name': 'hhem_detector',
                'priority': 2,
                'threat_categories': ['harmful_content', 'manipulation'],
                'params_template': {
                    'text': None,
                    'operation': 'analyze'
                }
            },
            {
                'name': 'cyberpig_ai',
                'priority': 3,
                'threat_categories': ['cybersecurity', 'threat_intelligence'],
                'params_template': {
                    'text': None
                }
            },
            {
                'name': 'enhanced_mcp_schema_validation',
                'priority': 4,
                'threat_categories': ['protocol_violation', 'schema_validation'],
                'params_template': {
                    'text': None,
                    'operation': 'validate_mcp_request',
                    'request': {'method': 'query', 'params': {'query': None}}
                }
            },
            {
                'name': 'presidio_dlp',
                'priority': 5,
                'threat_categories': ['data_leak', 'pii_detection'],
                'params_template': {
                    'text': None
                }
            },
            {
                'name': 'llm_guard',
                'priority': 6,
                'threat_categories': ['prompt_injection', 'jailbreak'],
                'params_template': {
                    'text': None,
                    'operation': 'scan_input'
                }
            }
        ]

def process(ctx, cfg):
    """
    FTHAD-Enhanced MCP Guardian - Enterprise Security Orchestrator
    Phase 1 (FIX): Comprehensive security hardening applied
    """
    start_time = time.time()
    orchestration_id = str(uuid.uuid4())

    try:
        # Initialize orchestrator
        orchestrator = MCPGuardianOrchestrator()

        # Enhanced input extraction with validation
        operation = "health_check"
        text = ""
        ai_strict_mode = False
        requestor_id = "unknown"

        # Input type validation - fail-secure for invalid types
        if not isinstance(ctx, (dict, type(None))) or not isinstance(cfg, (dict, type(None))):
            return {
                'status': 'error',
                'error': 'Invalid input types - expected dict or None',
                'plugin': 'mcp_guardian',
                'orchestration_id': orchestration_id,
                'action': 'BLOCK',
                'threat_score': 1.0,
                'fthad_enhanced': True,
                'security_level': 'enterprise',
                'processing_time_ms': (time.time() - start_time) * 1000
            }

        # Extract and sanitize parameters
        if isinstance(cfg, dict):
            operation = OrchestrationInputValidator.sanitize_basic_input(cfg.get('operation', operation), 100)
            text = str(cfg.get('text', cfg.get('input', '')))  # Don't pre-sanitize content - let universal_input_sanitizer handle it
            ai_strict_mode = cfg.get('ai_strict_mode', False) or cfg.get('ai_required', False)
            requestor_id = OrchestrationInputValidator.sanitize_basic_input(cfg.get('requestor_id', 'cfg_source'), 100)

        if isinstance(ctx, dict):
            operation = OrchestrationInputValidator.sanitize_basic_input(ctx.get('operation', operation), 100)
            text = str(ctx.get('text', ctx.get('input', text)))  # Don't pre-sanitize content - let universal_input_sanitizer handle it
            ai_strict_mode = ai_strict_mode or ctx.get('ai_strict_mode', False) or ctx.get('ai_required', False)
            requestor_id = OrchestrationInputValidator.sanitize_basic_input(ctx.get('requestor_id', requestor_id), 100)

        # Generate requestor ID hash for privacy
        requestor_hash = hashlib.sha256(requestor_id.encode()).hexdigest()[:16]

        # Log orchestration start
        orchestrator.audit_logger.log_orchestration_event(
            "orchestration_start", orchestration_id,
            {
                "operation": operation,
                "requestor_hash": requestor_hash,
                "ai_strict_mode": ai_strict_mode,
                "text_length": len(text)
            }
        )

        # Rate limiting check
        rate_allowed, rate_info = orchestrator.rate_limiter.check_rate_limit(requestor_hash)
        if not rate_allowed:
            orchestrator.audit_logger.log_orchestration_event(
                "rate_limit_exceeded", orchestration_id,
                {"requestor_hash": requestor_hash, "rate_info": rate_info}, "WARNING"
            )
            return {
                "status": "error",
                "error": "Rate limit exceeded",
                "plugin": "mcp_guardian",
                "orchestration_id": orchestration_id,
                "rate_limit_info": rate_info,
                "action": "BLOCK",
                "fthad_enhanced": True,
                "processing_time_ms": (time.time() - start_time) * 1000
            }

        # Basic operation validation (content validation delegated to universal_input_sanitizer)
        is_valid_op, op_threats = OrchestrationInputValidator.validate_operation(operation)
        if not is_valid_op:
            orchestrator.audit_logger.log_orchestration_event(
                "invalid_operation", orchestration_id,
                {"threats": op_threats, "operation": operation, "requestor_hash": requestor_hash}, "ERROR"
            )
            return {
                "status": "error",
                "error": "Invalid operation",
                "validation_threats": op_threats,
                "plugin": "mcp_guardian",
                "orchestration_id": orchestration_id,
                "action": "BLOCK",
                "fthad_enhanced": True,
                "processing_time_ms": (time.time() - start_time) * 1000
            }

        # Handle health check and status operations
        if operation in ['health_check', 'get_status']:
            return {
                "status": "success",
                "plugin": "mcp_guardian",
                "role": "enterprise_security_orchestrator",
                "orchestration_id": orchestration_id,
                "healthy": True,
                "security_features": {
                    "input_validation": True,
                    "universal_input_sanitizer": True,
                    "rate_limiting": True,
                    "circuit_breaker": True,
                    "threat_correlation": True,
                    "audit_logging": True,
                    "adaptive_thresholds": True,
                    "reusable_components": True
                },
                "security_plugins_total": len(orchestrator.security_plugins),
                "security_plugins_available": "runtime_check_skipped",
                "available_plugins": [p['name'] for p in orchestrator.security_plugins],
                "security_level": "enterprise_grade",
                "fthad_enhanced": True,
                "fthad_version": "1.0.0",
                "processing_time_ms": (time.time() - start_time) * 1000
            }

        # Handle orchestration operations
        elif operation in ['scan', 'security_scan', 'orchestrate']:
            if not text:
                return {
                    "status": "error",
                    "error": "No text provided for security scan",
                    "plugin": "mcp_guardian",
                    "orchestration_id": orchestration_id,
                    "action": "BLOCK",
                    "fthad_enhanced": True,
                    "processing_time_ms": (time.time() - start_time) * 1000
                }

            # Execute orchestrated security scan
            return _execute_enterprise_orchestration(
                orchestrator, text, ai_strict_mode, requestor_hash,
                orchestration_id, start_time
            )

        else:
            # Handle unknown operations
            orchestrator.audit_logger.log_orchestration_event(
                "unknown_operation", orchestration_id,
                {"operation": operation, "requestor_hash": requestor_hash}, "WARNING"
            )

            return {
                "status": "success",
                "operation": operation,
                "message": f"Operation {operation} completed by enterprise orchestrator",
                "plugin": "mcp_guardian",
                "orchestration_id": orchestration_id,
                "action": "ALLOW",
                "fthad_enhanced": True,
                "processing_time_ms": (time.time() - start_time) * 1000
            }

    except Exception as e:
        # Fail-secure error handling
        return {
            "status": "error",
            "error": f"Enterprise orchestration failed: {str(e)}",
            "plugin": "mcp_guardian",
            "orchestration_id": orchestration_id,
            "action": "BLOCK",  # Fail-secure
            "fthad_enhanced": True,
            "security_level": "enterprise",
            "processing_time_ms": (time.time() - start_time) * 1000
        }

def _execute_enterprise_orchestration(orchestrator: MCPGuardianOrchestrator,
                                    text: str, ai_strict_mode: bool,
                                    requestor_hash: str, orchestration_id: str,
                                    start_time: float) -> Dict[str, Any]:
    """Execute enterprise-grade security orchestration with advanced features"""

    try:
        from shares.loader import pp

        threat_events = []
        plugin_results = []
        successful_scans = 0
        ai_unavailable_plugins = []
        plugin_performance = {}

        # Log orchestration execution start
        orchestrator.audit_logger.log_orchestration_event(
            "orchestration_execution_start", orchestration_id,
            {
                "plugins_total": len(orchestrator.security_plugins),
                "ai_strict_mode": ai_strict_mode,
                "requestor_hash": requestor_hash
            }
        )

        # First pass: Execute universal input sanitizer for input validation
        sanitized_text = text
        input_validation_result = None

        for plugin_config in orchestrator.security_plugins:
            if plugin_config.get('is_input_validator', False):
                plugin_name = plugin_config['name']
                plugin_start = time.time()

                try:
                    plugin = pp(plugin_name)
                    if plugin is None:
                        continue

                    # Prepare sanitizer parameters
                    sanitizer_params = {
                        'input_data': text,
                        'sanitization_types': ['all']
                    }

                    # Execute sanitizer
                    sanitizer_result = plugin.process(sanitizer_params, {})

                    if sanitizer_result.get('success', False):
                        # Use sanitized output for subsequent plugins
                        sanitized_text = sanitizer_result.get('sanitized_output', text)
                        input_validation_result = sanitizer_result

                        # Create threat event if unsafe input detected
                        if not sanitizer_result.get('is_safe', True):
                            threat_event = ThreatEvent(
                                plugin_name=plugin_name,
                                threat_type='input_validation',
                                threat_level=ThreatLevel.HIGH if len(sanitizer_result.get('threats_detected', [])) > 0 else ThreatLevel.MEDIUM,
                                confidence=sanitizer_result.get('confidence_score', 0.8),
                                description=f"Input validation detected {len(sanitizer_result.get('threats_detected', []))} threats",
                                metadata={
                                    'threats_detected': sanitizer_result.get('threats_detected', []),
                                    'threat_categories': sanitizer_result.get('threat_categories', []),
                                    'original_text_length': len(text),
                                    'sanitized_text_length': len(sanitized_text)
                                }
                            )
                            threat_events.append(threat_event)
                            orchestrator.audit_logger.log_threat_event(threat_event, orchestration_id)

                        plugin_execution_time = (time.time() - plugin_start) * 1000
                        plugin_performance[plugin_name] = plugin_execution_time
                        successful_scans += 1

                        plugin_results.append({
                            'plugin': plugin_name,
                            'threats_detected': len(sanitizer_result.get('threats_detected', [])),
                            'threat_confidence': sanitizer_result.get('confidence_score', 0.0),
                            'action': "BLOCK" if not sanitizer_result.get('is_safe', True) else "ALLOW",
                            'status': 'success',
                            'execution_time_ms': plugin_execution_time,
                            'threat_details': {
                                'type': 'input_validation',
                                'description': f"Sanitized input with {len(sanitizer_result.get('threats_detected', []))} threats removed",
                                'threats_categories': sanitizer_result.get('threat_categories', [])
                            }
                        })

                        # Log input sanitization
                        orchestrator.audit_logger.log_orchestration_event(
                            "input_sanitization_completed", orchestration_id,
                            {
                                "original_length": len(text),
                                "sanitized_length": len(sanitized_text),
                                "threats_detected": len(sanitizer_result.get('threats_detected', [])),
                                "is_safe": sanitizer_result.get('is_safe', True)
                            }
                        )

                except Exception as e:
                    # Input sanitization failure - use original text but log warning
                    orchestrator.audit_logger.log_orchestration_event(
                        "input_sanitization_failed", orchestration_id,
                        {"error": str(e), "plugin": plugin_name}, "WARNING"
                    )
                    sanitized_text = text  # Fallback to original text

                break  # Only process first input validator

        # Second pass: Execute security analysis plugins with sanitized input
        for plugin_config in orchestrator.security_plugins:
            if plugin_config.get('is_input_validator', False):
                continue  # Skip input validators in second pass
            plugin_name = plugin_config['name']
            plugin_start = time.time()

            # Check circuit breaker
            if not orchestrator.circuit_breaker.can_execute(plugin_name):
                plugin_results.append({
                    'plugin': plugin_name,
                    'status': 'circuit_breaker_open',
                    'message': 'Plugin temporarily disabled due to failures'
                })
                continue

            try:
                plugin = pp(plugin_name)
                if plugin is None:
                    orchestrator.circuit_breaker.record_failure(plugin_name)
                    continue

                # Prepare plugin parameters using sanitized text
                params = plugin_config['params_template'].copy()
                for key, value in params.items():
                    if value is None:
                        if key == 'text':
                            params[key] = sanitized_text  # Use sanitized input
                        elif key == 'request' and isinstance(value, dict) and 'params' in value:
                            params[key]['params']['query'] = sanitized_text  # Use sanitized input

                params['ai_strict_mode'] = ai_strict_mode
                params['orchestration_id'] = orchestration_id

                # Execute plugin with timeout
                with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                    future = executor.submit(plugin.process, params, {})
                    try:
                        result = future.result(timeout=30)  # 30-second timeout
                    except concurrent.futures.TimeoutError:
                        raise Exception("Plugin execution timeout")

                plugin_execution_time = (time.time() - plugin_start) * 1000
                plugin_performance[plugin_name] = plugin_execution_time

                # Handle AI unavailability in strict mode
                if result.get('status') == 'error' and result.get('error_type') == 'AI_MODELS_UNAVAILABLE':
                    ai_unavailable_plugins.append({
                        'plugin': plugin_name,
                        'error': result.get('error'),
                        'missing_dependencies': result.get('missing_dependencies', []),
                        'recommendation': result.get('recommendation')
                    })
                    continue

                orchestrator.circuit_breaker.record_success(plugin_name)
                successful_scans += 1

                # Enhanced threat extraction and event creation
                threat_event = _extract_threat_event(result, plugin_name, plugin_config['threat_categories'])
                if threat_event.threat_level != ThreatLevel.NONE:
                    threat_events.append(threat_event)
                    orchestrator.audit_logger.log_threat_event(threat_event, orchestration_id)

                plugin_results.append({
                    'plugin': plugin_name,
                    'threats_detected': threat_event.threat_level.value,
                    'threat_confidence': threat_event.confidence,
                    'action': "BLOCK" if threat_event.threat_level.value > 0 else "ALLOW",
                    'status': 'success',
                    'execution_time_ms': plugin_execution_time,
                    'threat_details': {
                        'type': threat_event.threat_type,
                        'description': threat_event.description
                    } if threat_event.threat_level != ThreatLevel.NONE else None
                })

            except Exception as e:
                orchestrator.circuit_breaker.record_failure(plugin_name)
                plugin_results.append({
                    'plugin': plugin_name,
                    'status': 'error',
                    'error': str(e),
                    'execution_time_ms': (time.time() - plugin_start) * 1000
                })

        # Handle AI unavailability in strict mode
        if ai_unavailable_plugins and ai_strict_mode:
            all_dependencies = []
            for plugin_info in ai_unavailable_plugins:
                all_dependencies.extend(plugin_info.get('missing_dependencies', []))

            orchestrator.audit_logger.log_orchestration_event(
                "ai_models_unavailable", orchestration_id,
                {
                    "failed_plugins": ai_unavailable_plugins,
                    "missing_dependencies": list(set(all_dependencies))
                }, "CRITICAL"
            )

            return {
                "status": "error",
                "error": f"AI models unavailable for {len(ai_unavailable_plugins)} plugins in strict mode",
                "error_type": "AI_MODELS_UNAVAILABLE",
                "plugin": "mcp_guardian",
                "orchestration_id": orchestration_id,
                "role": "enterprise_security_orchestrator",
                "ai_strict_mode": True,
                "failed_plugins": ai_unavailable_plugins,
                "missing_dependencies": list(set(all_dependencies)),
                "recommendation": "Install missing AI dependencies or disable ai_strict_mode",
                "security_impact": "CRITICAL - Multiple AI security models unavailable",
                "action": "BLOCK",
                "fthad_enhanced": True,
                "processing_time_ms": (time.time() - start_time) * 1000
            }

        # Advanced threat correlation and scoring
        correlation_result = orchestrator.correlation_engine.correlate_threats(threat_events)

        # Adjust rate limiting based on threat level
        orchestrator.rate_limiter.adjust_threshold(requestor_hash, correlation_result["composite_threat_level"])

        # Final orchestration decision
        final_action = "BLOCK" if correlation_result["composite_threat_level"].value > 0 else "ALLOW"

        # Log orchestration completion
        orchestrator.audit_logger.log_orchestration_event(
            "orchestration_completed", orchestration_id,
            {
                "final_action": final_action,
                "composite_threat_level": correlation_result["composite_threat_level"].value,
                "successful_scans": successful_scans,
                "total_threats": len(threat_events),
                "requestor_hash": requestor_hash
            }
        )

        return {
            "status": "success",
            "plugin": "mcp_guardian",
            "role": "enterprise_security_orchestrator",
            "operation": "orchestrate",
            "orchestration_id": orchestration_id,
            "ai_strict_mode": ai_strict_mode,

            # Input Sanitization Results
            "input_sanitization": {
                "performed": input_validation_result is not None,
                "original_length": len(text),
                "sanitized_length": len(sanitized_text),
                "threats_removed": len(input_validation_result.get('threats_detected', [])) if input_validation_result else 0,
                "is_safe": input_validation_result.get('is_safe', True) if input_validation_result else True,
                "sanitization_confidence": input_validation_result.get('confidence_score', 1.0) if input_validation_result else 1.0
            },

            # Threat Analysis Results
            "action": final_action,  # Standard field name for action
            "threat_score": correlation_result["composite_score"],  # Standard field name for threat score
            "composite_threat_level": correlation_result["composite_threat_level"].value,
            "composite_threat_score": correlation_result["composite_score"],
            "composite_confidence": correlation_result["composite_confidence"],
            "total_threats_detected": len(threat_events),
            "final_action": final_action,

            # Orchestration Metrics
            "plugins_executed": successful_scans,
            "plugins_total": len(orchestrator.security_plugins),
            "ai_unavailable_count": len(ai_unavailable_plugins),

            # Detailed Results
            "plugin_results": plugin_results,
            "threat_correlation": correlation_result["correlation_analysis"],
            "threat_breakdown": correlation_result["threat_breakdown"],
            "security_recommendations": correlation_result["recommendations"],

            # Performance Metrics
            "plugin_performance": plugin_performance,
            "avg_plugin_execution_time": sum(plugin_performance.values()) / len(plugin_performance) if plugin_performance else 0,

            # Enterprise Features
            "fthad_enhanced": True,
            "security_level": "enterprise",
            "fthad_version": "1.0.0",
            "processing_time_ms": (time.time() - start_time) * 1000,

            # Integration Features
            "universal_input_sanitizer_integrated": True,
            "reusable_security_components": True
        }

    except Exception as e:
        orchestrator.audit_logger.log_orchestration_event(
            "orchestration_error", orchestration_id,
            {"error": str(e), "requestor_hash": requestor_hash}, "ERROR"
        )

        return {
            "status": "error",
            "error": f"Enterprise orchestration execution failed: {str(e)}",
            "plugin": "mcp_guardian",
            "orchestration_id": orchestration_id,
            "action": "BLOCK",  # Fail-secure
            "fthad_enhanced": True,
            "security_level": "enterprise",
            "processing_time_ms": (time.time() - start_time) * 1000
        }

def _extract_threat_event(plugin_result: Dict[str, Any], plugin_name: str,
                         threat_categories: List[str]) -> ThreatEvent:
    """Extract and normalize threat event from plugin result"""

    threat_event = ThreatEvent(plugin_name=plugin_name)

    if not isinstance(plugin_result, dict):
        return threat_event

    # Extract threat information from various plugin response formats
    threats_count = 0
    threat_confidence = 0.0
    threat_type = "unknown"
    threat_description = ""

    # Handle different threat detection formats
    if 'threats_detected' in plugin_result:
        threats_data = plugin_result['threats_detected']
        if isinstance(threats_data, list):
            threats_count = len(threats_data)
            if threats_data:
                threat_type = threats_data[0].get('threat_type', 'unknown')
                threat_description = threats_data[0].get('description', 'Threat detected')
        elif isinstance(threats_data, int):
            threats_count = threats_data

    elif 'threat_detected' in plugin_result and plugin_result.get('threat_detected'):
        threats_count = 1
        threat_type = plugin_result.get('threat_type', 'unknown')

    elif 'blocked' in plugin_result and plugin_result.get('blocked'):
        threats_count = 1
        threat_type = "access_blocked"

    elif 'allowed' in plugin_result and not plugin_result.get('allowed'):
        threats_count = 1
        threat_type = "access_denied"

    elif 'action' in plugin_result and plugin_result.get('action') == 'BLOCK':
        threats_count = 1
        threat_type = "blocked_content"

    elif 'security_violations' in plugin_result:
        violations = plugin_result.get('security_violations', [])
        threats_count = len(violations) if isinstance(violations, list) else (1 if violations else 0)
        threat_type = "security_violation"

    elif 'secrets_found' in plugin_result:
        secrets = plugin_result.get('secrets_found', [])
        threats_count = len(secrets) if isinstance(secrets, list) else (1 if secrets else 0)
        threat_type = "data_leak"

    # Extract confidence
    threat_confidence = plugin_result.get('confidence', 0.0)
    if 'threat_score' in plugin_result:
        threat_confidence = max(threat_confidence, plugin_result.get('threat_score', 0.0))

    # Determine threat level based on count and plugin category
    if threats_count == 0:
        threat_level = ThreatLevel.NONE
    elif threats_count >= 3 or threat_confidence >= 0.9:
        threat_level = ThreatLevel.CRITICAL
    elif threats_count >= 2 or threat_confidence >= 0.7:
        threat_level = ThreatLevel.HIGH
    elif threats_count >= 1 or threat_confidence >= 0.4:
        threat_level = ThreatLevel.MEDIUM
    else:
        threat_level = ThreatLevel.LOW

    # Enhance threat type with category context
    if threat_type == "unknown" and threat_categories:
        threat_type = threat_categories[0]

    threat_event.threat_type = threat_type
    threat_event.threat_level = threat_level
    threat_event.confidence = threat_confidence
    threat_event.description = threat_description or f"{threats_count} threat(s) detected by {plugin_name}"
    threat_event.metadata = {
        "threats_count": threats_count,
        "plugin_categories": threat_categories,
        "raw_result": plugin_result
    }

    return threat_event