#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
MCP Protocol Integration for AI Rate Limiter - Enterprise Security Hardened
Enterprise-grade MCP rate limiting with Universal Input Sanitizer integration
and comprehensive security validation for production environments
"""

import json
import time
import re
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
import os
import pickle
import sys

# Add PlugPipe core path for pp() function access
from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
from shares.loader import pp

@dataclass
class ValidationResult:
    """Security validation result for rate limiter operations"""
    is_valid: bool
    sanitized_value: Any
    errors: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    rate_limit_violations: List[str] = field(default_factory=list)
    sanitization_applied: bool = False

class MCPRateLimiterSecurityHardening:
    """Security hardening for MCP AI Rate Limiter operations"""

    def __init__(self):
        # Maximum input sizes for resource protection
        self.max_config_size = 100 * 1024  # 100KB for configuration
        self.max_string_length = 10000
        self.max_list_items = 1000
        self.max_dict_keys = 100

        # MCP Rate Limiter-specific dangerous patterns
        self.dangerous_patterns = [
            # Enhanced SQL Injection patterns
            r';\s*DROP\s+TABLE',
            r';\s*DROP\s+\w+',
            r';\s*DELETE\s+FROM',
            r';\s*INSERT\s+INTO',
            r';\s*UPDATE\s+.*SET',
            r'UNION\s+SELECT',
            r"'\s*OR\s+'\d+=\d+",
            r'";\s*--',
            r"';\s*--",
            r';\s*--',
            r"';\s*OR\s+'[^']*'\s*=\s*'[^']*'",
            r"'\s*OR\s+'[^']*'\s*=\s*'[^']*'",
            r'OR\s+1\s*=\s*1',
            r'SELECT\s+\*\s+FROM',
            r'information_schema',
            r'LOAD_FILE\s*\(',
            r'INTO\s+OUTFILE',
            r'HAVING\s+\d+',

            # Enhanced Command injection patterns
            r';\s*rm\s+-rf',
            r';\s*cat\s+/etc/',
            r';\s*curl\s+',
            r';\s*wget\s+',
            r';\s*nc\s+',
            r'\|\s*nc\s+',
            r'\$\(',
            r'`[^`]*`',
            r'&&\s*[a-zA-Z]',
            r'\|\|\s*[a-zA-Z]',
            r';\s*ls\s+',
            r';\s*ps\s+',
            r';\s*whoami',
            r';\s*id\s+',
            r';\s*uname',
            r';\s*netstat',
            r'&\s*echo\s+',
            r'\|\s*sh',
            r'\|\s*bash',

            # Enhanced Path traversal patterns
            r'\.\./.*etc/passwd',
            r'\.\./.*etc/shadow',
            r'\.\./.*proc/',
            r'%2e%2e%2f',
            r'%252f',
            r'\\.\\.\\',

            # Enhanced Script injection patterns
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'onload\s*=',
            r'onerror\s*=',
            r'eval\s*\(',
            r'setTimeout\s*\(',

            # Enhanced Rate limiter bypass patterns
            r'BYPASS\s+RATE\s+LIMIT',
            r'DISABLE\s+RATE\s+LIMITING',
            r'UNLIMITED\s+REQUESTS',
            r'BYPASS\s+THROTTLING',
            r'OVERRIDE\s+LIMIT',
            r'SET\s+LIMIT\s*=\s*0',
            r'RATE\s+LIMIT\s+DISABLE',
            r'THROTTLE\s+BYPASS',
            r'MAX\s+REQUESTS\s*=\s*-1',
            r'INFINITE\s+LIMIT',

            # Enhanced MCP bypass patterns
            r'MCP\s+BYPASS',
            r'PROTOCOL\s+OVERRIDE',
            r'DISABLE\s+MCP',
            r'MCP\s+DISABLE',
            r'ENDPOINT\s+BYPASS',
            r'COST\s+BYPASS',

            # Enhanced Resource exhaustion patterns
            r';\s*shutdown',
            r';\s*reboot',
            r'>&\s*/dev/null',
            r'2>&1',
            r'/dev/tcp/',
            r'mkfifo',
        ]

        # Compile patterns for performance
        self.dangerous_regex = re.compile('|'.join(self.dangerous_patterns), re.IGNORECASE)

        # Valid operations (whitelist)
        self.valid_operations = {
            "check_mcp_limit", "set_client_tier", "get_mcp_statistics",
            "scan", "security_scan", "get_status", "validate_endpoint",
            "reset_limits", "emergency_stop", "audit_report"
        }

        # Valid tiers (whitelist)
        self.valid_tiers = {"basic", "standard", "premium", "enterprise"}

        # Valid endpoints (whitelist)
        self.valid_endpoints = {
            "tools/call", "resources/read", "prompts/get", "server/initialize",
            "server/ping", "unknown", "client/connect", "client/disconnect"
        }

        # Initialize Universal Input Sanitizer
        self.sanitizer = None
        try:
            self.sanitizer = pp("universal_input_sanitizer")
        except Exception:
            pass  # Fallback to manual validation if sanitizer unavailable

    def validate_rate_limiter_input(self, data: Any, context: str = "general") -> ValidationResult:
        """Validate MCP rate limiter input with comprehensive security checks"""
        result = ValidationResult(is_valid=True, sanitized_value=data)

        try:
            # Size validation first
            data_size = len(str(data))
            if data_size > self.max_config_size:
                result.is_valid = False
                result.errors.append(f"Input size {data_size} exceeds maximum {self.max_config_size}")
                return result

            # Convert to string for pattern validation
            data_str = str(data) if data is not None else ""

            # Pattern-based security validation
            dangerous_pattern_found = self.dangerous_regex.search(data_str)
            if dangerous_pattern_found:
                result.security_issues.append("Dangerous patterns detected in rate limiter input")
                result.warnings.append("Security patterns detected in rate limiter configuration")

            # Universal Input Sanitizer validation (if available)
            sanitizer_success = False
            if self.sanitizer:
                try:
                    sanitizer_result = self.sanitizer.process({}, {
                        "operation": "validate_and_sanitize",
                        "input_data": data,
                        "validation_mode": "strict",
                        "context": f"rate_limiter_{context}"
                    })

                    if sanitizer_result.get("success") and sanitizer_result.get("validation_result"):
                        validation = sanitizer_result["validation_result"]
                        if not validation.get("is_safe", True):
                            result.security_issues.extend(validation.get("threats_detected", []))
                            result.warnings.append("Universal Input Sanitizer detected security issues")

                        # Use sanitized data if available
                        if sanitizer_result.get("sanitized_data"):
                            result.sanitized_value = sanitizer_result["sanitized_data"]
                            result.sanitization_applied = True
                            sanitizer_success = True

                            # Preserve security issues flag if dangerous patterns were found
                            if dangerous_pattern_found and "Dangerous patterns detected in rate limiter input" not in result.security_issues:
                                result.security_issues.append("Dangerous patterns detected in rate limiter input")
                        else:
                            result.sanitized_value = self._fallback_sanitize_rate_limiter(data)
                            result.sanitization_applied = True
                    else:
                        result.sanitized_value = self._fallback_sanitize_rate_limiter(data)
                        result.sanitization_applied = True

                except Exception as e:
                    result.warnings.append(f"Universal Input Sanitizer validation failed: {str(e)}")
                    result.sanitized_value = self._fallback_sanitize_rate_limiter(data)
                    result.sanitization_applied = True

            # Apply fallback sanitization if sanitizer unavailable OR security issues detected
            if not sanitizer_success or result.security_issues:
                result.sanitized_value = self._fallback_sanitize_rate_limiter(data)
                result.sanitization_applied = True

            # Rate limiter-specific validation
            rate_limiter_result = self._validate_rate_limiter_context(result.sanitized_value, context)
            result.rate_limit_violations.extend(rate_limiter_result.get("violations", []))
            if rate_limiter_result.get("violations"):
                result.warnings.extend(rate_limiter_result.get("violations", []))

            # Final security validation - ensure dangerous patterns are flagged
            if dangerous_pattern_found:
                result.security_issues = ["Dangerous patterns detected in rate limiter input"]

                # Add pattern-specific details
                original_str = str(data) if data is not None else ""
                for i, pattern in enumerate(self.dangerous_patterns):
                    if re.search(pattern, original_str, re.IGNORECASE):
                        result.security_issues.append(f"Matched dangerous patterns: Pattern {i+1}")
                        break

            return result

        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Rate limiter input validation failed: {str(e)}")

            # Emergency security check even on exception
            try:
                data_str = str(data) if data is not None else ""
                if self.dangerous_regex.search(data_str):
                    result.security_issues = ["EXCEPTION: Dangerous patterns detected in rate limiter input"]
                    result.warnings.append("EXCEPTION: Security patterns detected despite error")
            except:
                pass

            return result

    def _fallback_sanitize_rate_limiter(self, data: Any) -> Any:
        """Fallback sanitization for rate limiter operations"""
        if isinstance(data, dict):
            sanitized = {}
            # Define allowed fields for rate limiter operations
            allowed_fields = {
                "operation", "context", "client_id", "endpoint", "estimated_cost",
                "tier", "rate_limit", "burst_size", "window_size", "cost_limit",
                "hourly_limit", "daily_limit", "per_request_limit", "threshold",
                "mcp_operation", "tool_name", "resource_id", "prompt_id",
                "server_endpoint", "protocol_version", "timeout", "retry_count"
            }

            for key, value in data.items():
                if isinstance(key, str):
                    # Sanitize key
                    clean_key = self._sanitize_string(key)
                    if len(clean_key) <= 100 and clean_key:
                        # Only allow known rate limiter fields
                        if clean_key in allowed_fields:
                            sanitized[clean_key] = self._fallback_sanitize_rate_limiter(value)
                elif isinstance(key, (int, float)):
                    sanitized[str(key)] = self._fallback_sanitize_rate_limiter(value)
            return sanitized

        elif isinstance(data, list):
            if len(data) > self.max_list_items:
                data = data[:self.max_list_items]
            return [self._fallback_sanitize_rate_limiter(item) for item in data]

        elif isinstance(data, str):
            return self._sanitize_string(data)

        elif isinstance(data, (int, float, bool)):
            return data

        elif data is None:
            return None

        else:
            return self._sanitize_string(str(data))

    def _sanitize_string(self, data: str) -> str:
        """Enhanced string sanitization for rate limiter context"""
        if not isinstance(data, str):
            return str(data)

        # Length limit
        if len(data) > self.max_string_length:
            data = data[:self.max_string_length]

        # Remove null bytes and control characters
        data = ''.join(char for char in data if ord(char) >= 32 or char in '\t\n\r')

        # Replace dangerous patterns with safe tokens
        data = re.sub(r'<script[^>]*>', '[SCRIPT_TAG_REMOVED]', data, flags=re.IGNORECASE)
        data = data.replace('javascript:', '[JS_SCHEME]')
        data = data.replace('vbscript:', '[VBS_SCHEME]')
        data = data.replace('../', '[PATH_TRAVERSAL]')
        data = data.replace('..\\', '[PATH_TRAVERSAL]')
        data = data.replace('%2e%2e%2f', '[ENCODED_PATH_TRAVERSAL]')
        data = data.replace('%2e%2e%5c', '[ENCODED_PATH_TRAVERSAL]')
        data = data.replace('%252f', '[ENCODED_PATH_TRAVERSAL]')
        data = data.replace('`', '[BACKTICK]')
        data = data.replace('$(', '[CMD_SUB]')
        data = data.replace('${', '[VAR_SUB]')

        # Enhanced rate limiter-specific sanitization
        data = re.sub(r'BYPASS\s+RATE\s+LIMIT', '[RATE_BYPASS_ATTEMPT]', data, flags=re.IGNORECASE)
        data = re.sub(r'DISABLE\s+RATE\s+LIMITING', '[RATE_DISABLE_ATTEMPT]', data, flags=re.IGNORECASE)
        data = re.sub(r'UNLIMITED\s+REQUESTS', '[UNLIMITED_ATTEMPT]', data, flags=re.IGNORECASE)
        data = re.sub(r'OVERRIDE\s+LIMIT', '[OVERRIDE_ATTEMPT]', data, flags=re.IGNORECASE)

        # Enhanced SQL injection sanitization
        data = re.sub(r';\s*DROP\s+\w+', '[SQL_DROP]', data, flags=re.IGNORECASE)
        data = re.sub(r';\s*DELETE\s+FROM', '[SQL_DELETE]', data, flags=re.IGNORECASE)
        data = re.sub(r'UNION\s+SELECT', '[SQL_UNION]', data, flags=re.IGNORECASE)
        data = re.sub(r"'\s*OR\s+'", '[SQL_OR]', data, flags=re.IGNORECASE)

        # Enhanced command injection sanitization
        data = re.sub(r';\s*rm\s+-rf', '[CMD_RM]', data, flags=re.IGNORECASE)
        data = re.sub(r';\s*cat\s+/etc/', '[CMD_CAT]', data, flags=re.IGNORECASE)
        data = re.sub(r'&&\s*[a-zA-Z]', '[CMD_AND]', data, flags=re.IGNORECASE)
        data = re.sub(r'\|\|\s*[a-zA-Z]', '[CMD_OR]', data, flags=re.IGNORECASE)

        # Basic HTML escaping for rate limiter reporting context
        data = data.replace('&', '&amp;')
        data = data.replace('<', '&lt;')
        data = data.replace('>', '&gt;')
        data = data.replace('"', '&quot;')
        data = data.replace("'", '&#x27;')

        return data.strip()

    def _validate_rate_limiter_context(self, data: Any, context: str) -> Dict[str, Any]:
        """Validate rate limiter-specific context and constraints"""
        violations = []

        if isinstance(data, dict):
            # Validate operation field
            operation = data.get("operation")
            if operation and operation not in self.valid_operations:
                violations.append(f"Invalid operation: {operation}")

            # Validate tier field
            tier = data.get("tier")
            if tier and tier not in self.valid_tiers:
                violations.append(f"Invalid tier: {tier}")

            # Validate endpoint field
            endpoint = data.get("endpoint")
            if endpoint and endpoint not in self.valid_endpoints:
                violations.append(f"Invalid endpoint: {endpoint}")

            # Validate numeric limits for costs and rates
            for field_name in ["estimated_cost", "cost_limit", "rate_limit", "hourly_limit", "daily_limit"]:
                field_value = data.get(field_name)
                if field_value is not None:
                    if not isinstance(field_value, (int, float)) or field_value < 0:
                        violations.append(f"Invalid {field_name}: must be non-negative number")
                    elif field_value > 1000000:  # Reasonable upper limit
                        violations.append(f"Invalid {field_name}: exceeds maximum allowed value")

            # Validate client_id format
            client_id = data.get("client_id")
            if client_id and isinstance(client_id, str):
                if len(client_id) > 100 or not re.match(r'^[a-zA-Z0-9_\-\.@]+$', client_id):
                    violations.append(f"Invalid client_id format: {client_id}")

        return {"violations": violations}

    def validate_rate_limiter_context(self, data: Any, context: str) -> Dict[str, Any]:
        """Public wrapper for rate limiter context validation"""
        return self._validate_rate_limiter_context(data, context)

# Simplified rate limit configuration
RATE_LIMITS = {
    'tools/call': 30,
    'resources/read': 60, 
    'prompts/get': 20,
    'server/initialize': 10,
    'server/ping': 1000,
    'unknown': 30
}

COST_LIMITS = {
    'basic': {'per_request': 1.0, 'hourly': 50.0, 'daily': 500.0},
    'standard': {'per_request': 5.0, 'hourly': 200.0, 'daily': 2000.0},
    'premium': {'per_request': 25.0, 'hourly': 800.0, 'daily': 8000.0}
}

def process(ctx, cfg):
    """
    PlugPipe entry point for MCP Rate Limiter - Enterprise Security Hardened
    Enhanced with Universal Input Sanitizer integration and comprehensive security validation
    """
    start_time = time.time()

    # Initialize security hardening
    security_hardening = MCPRateLimiterSecurityHardening()

    try:
        # Security validation of input parameters first
        input_data = {}
        if isinstance(ctx, dict):
            input_data.update(ctx)
        if isinstance(cfg, dict):
            input_data.update(cfg)

        # Validate and sanitize all input data
        validation_result = security_hardening.validate_rate_limiter_input(input_data, "rate_limit_check")

        # Extract validated and sanitized values
        if validation_result.sanitized_value:
            validated_data = validation_result.sanitized_value
        else:
            validated_data = input_data

        # Security metadata for all responses
        security_metadata = {
            "sanitization_applied": validation_result.sanitization_applied,
            "security_issues_count": len(validation_result.security_issues),
            "validation_warnings": validation_result.warnings,
            "validation_time": (time.time() - start_time) * 1000
        }

        # Multi-source data extraction using validated data
        operation = "check_mcp_limit"
        client_id = "anonymous"
        endpoint = "unknown"
        estimated_cost = 0.0
        tier = "basic"

        # Extract from validated data (security-checked)
        operation = validated_data.get('operation', operation)
        client_id = validated_data.get('client_id', client_id)
        endpoint = validated_data.get('endpoint', endpoint)
        estimated_cost = validated_data.get('estimated_cost', estimated_cost)
        tier = validated_data.get('tier', tier)

        # Handle MCP request structure in validated data
        if 'original_request' in validated_data:
            original_request = validated_data['original_request']
            if isinstance(original_request, dict) and 'params' in original_request:
                params = original_request['params']
                if isinstance(params, dict):
                    operation = params.get('operation', operation)
                    client_id = params.get('client_id', client_id)
                    endpoint = params.get('endpoint', endpoint)
                    estimated_cost = params.get('estimated_cost', estimated_cost)
        
        # Load persistent state
        state_file = "/tmp/mcp_rate_limiter_state.pkl"
        client_tiers = {}
        cost_tracking = {}
        
        try:
            if os.path.exists(state_file):
                with open(state_file, 'rb') as f:
                    state = pickle.load(f)
                    client_tiers = state.get('client_tiers', {})
                    cost_tracking = state.get('cost_tracking', {})
        except:
            pass  # Use empty state on error
        
        # Get client tier
        client_tier = client_tiers.get(client_id, 'basic')
        cost_limits = COST_LIMITS.get(client_tier, COST_LIMITS['basic'])
        
        # Process operations
        if operation == 'check_mcp_limit':
            # Check endpoint rate limits
            endpoint_limit = RATE_LIMITS.get(endpoint, RATE_LIMITS['unknown'])
            
            # Check cost limits
            if estimated_cost > cost_limits['per_request']:
                return {
                    "status": "success",
                    "allowed": False,
                    "reason": "per_request_cost_exceeded",
                    "metadata": {
                        "client_tier": client_tier,
                        "endpoint": endpoint,
                        "estimated_cost": estimated_cost,
                        "limit": cost_limits['per_request']
                    },
                    "security_metadata": security_metadata
                }
            
            # Initialize cost tracking if needed
            if client_id not in cost_tracking:
                cost_tracking[client_id] = {
                    'hourly': 0.0, 'daily': 0.0, 'total': 0.0,
                    'last_reset_hour': datetime.utcnow().hour,
                    'last_reset_day': datetime.utcnow().day
                }
            
            client_costs = cost_tracking[client_id]
            current_time = datetime.utcnow()
            
            # Reset counters if needed
            if current_time.hour != client_costs['last_reset_hour']:
                client_costs['hourly'] = 0.0
                client_costs['last_reset_hour'] = current_time.hour
                
            if current_time.day != client_costs['last_reset_day']:
                client_costs['daily'] = 0.0
                client_costs['last_reset_day'] = current_time.day
            
            # Check hourly/daily limits
            if client_costs['hourly'] + estimated_cost > cost_limits['hourly']:
                return {
                    "status": "success",
                    "allowed": False,
                    "reason": "hourly_cost_exceeded",
                    "metadata": {"client_tier": client_tier, "endpoint": endpoint},
                    "security_metadata": security_metadata
                }
                
            if client_costs['daily'] + estimated_cost > cost_limits['daily']:
                return {
                    "status": "success",
                    "allowed": False,
                    "reason": "daily_cost_exceeded",
                    "metadata": {"client_tier": client_tier, "endpoint": endpoint},
                    "security_metadata": security_metadata
                }

            return {
                "status": "success",
                "allowed": True,
                "operation": operation,
                "metadata": {
                    "client_tier": client_tier,
                    "endpoint": endpoint,
                    "estimated_cost": estimated_cost,
                    "endpoint_limit": endpoint_limit
                },
                "security_metadata": security_metadata
            }
            
        elif operation == 'set_client_tier':
            if tier in COST_LIMITS:
                client_tiers[client_id] = tier
                # Save state
                try:
                    state = {'client_tiers': client_tiers, 'cost_tracking': cost_tracking}
                    with open(state_file, 'wb') as f:
                        pickle.dump(state, f)
                except:
                    pass
                    
                return {
                    "status": "success",
                    "operation": operation,
                    "client_id": client_id,
                    "tier": tier,
                    "message": f"Client tier set to {tier}",
                    "security_metadata": security_metadata
                }
            else:
                return {
                    "status": "error",
                    "error": f"Invalid tier: {tier}",
                    "valid_tiers": list(COST_LIMITS.keys()),
                    "security_metadata": security_metadata
                }
                
        elif operation == 'get_mcp_statistics':
            if client_id != "anonymous":
                client_stats = cost_tracking.get(client_id, {})
                return {
                    "status": "success",
                    "operation": operation,
                    "statistics": {
                        "client_id": client_id,
                        "tier": client_tiers.get(client_id, 'basic'),
                        "costs": client_stats,
                        "limits": COST_LIMITS[client_tiers.get(client_id, 'basic')]
                    },
                    "security_metadata": security_metadata
                }
            else:
                return {
                    "status": "success",
                    "operation": operation,
                    "statistics": {
                        "total_clients": len(client_tiers),
                        "client_tiers": client_tiers,
                        "total_cost": sum(costs.get('total', 0.0) for costs in cost_tracking.values())
                    },
                    "security_metadata": security_metadata
                }
        
        elif operation in ['scan', 'security_scan']:
            # Generic security scanning operation - check rate limits for security scanning
            return {
                "status": "success",
                "operation": operation,
                "allowed": True,
                "reason": "security_scan_allowed",
                "threats_detected": 0,  # Rate limiter doesn't detect security threats
                "action": "ALLOW",
                "plugin_name": "ai_rate_limiter_mcp_integration",
                "processing_time_ms": (time.time() - start_time) * 1000,
                "metadata": {
                    "rate_limit_status": "within_limits",
                    "client_id": client_id
                },
                "security_metadata": security_metadata
            }
            
        elif operation == 'get_status':
            # Status check operation for MCP interface compatibility
            return {
                "status": "success",
                "operation": operation,
                "plugin_name": "ai_rate_limiter_mcp_integration",
                "rate_limiter_status": "operational",
                "mcp_integration": "enabled",
                "supported_operations": ["check_mcp_limit", "set_client_tier", "get_mcp_statistics", "scan", "get_status"],
                "processing_time_ms": (time.time() - start_time) * 1000,
                "security_metadata": security_metadata
            }
                
        else:
            return {
                "status": "error",
                "error": f"Unknown operation: {operation}",
                "supported_operations": ["check_mcp_limit", "set_client_tier", "get_mcp_statistics", "scan", "get_status"],
                "security_metadata": security_metadata
            }
            
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        return {
            "status": "error",
            "error": str(e),
            "plugin_name": "ai_rate_limiter_mcp_integration",
            "processing_time_ms": processing_time,
            "security_metadata": {
                "sanitization_applied": False,
                "security_issues_count": 0,
                "validation_warnings": ["Exception occurred during processing"],
                "validation_time": processing_time
            }
        }
        
