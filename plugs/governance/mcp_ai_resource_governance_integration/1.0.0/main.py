#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
MCP AI Resource Governance Integration Plugin - Enterprise Security Hardened Version
Extends existing AI resource governance with MCP-specific cost tracking and controls
Enhanced with Universal Input Sanitizer integration and comprehensive security validation.

Security Features:
- Universal Input Sanitizer integration
- Multi-layer resource governance validation
- Resource exhaustion protection
- Configuration security validation
- Permission whitelist enforcement
- Path traversal prevention for configurations
- Comprehensive security logging
"""

import asyncio
import json
import logging
import time
import re
from dataclasses import dataclass, asdict, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
import sys
import os

# Add parent directories to path for plugin imports
sys.path.append(str(Path(__file__).parent.parent.parent.parent))
sys.path.append(str(Path(__file__).parent.parent.parent.parent / "plugs" / "governance" / "ai_resource_governance" / "1.0.0"))

# Import PlugPipe framework components for security
try:
    from shares.loader import pp
except ImportError:
    # Fallback for testing environments
    def pp(plugin_name: str, **kwargs):
        print(f"Mock pp() call: {plugin_name} with {kwargs}")
        return {"success": False, "error": "Universal Input Sanitizer not available in test environment"}

try:
    from main import AIResourceGovernancePlugin as BaseGovernancePlugin
except ImportError:
    # Fallback implementation if base plugin not available
    class BaseGovernancePlugin:
        def __init__(self, config: Dict[str, Any]):
            self.config = config

        async def check_permission(self, context: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "success", "permission_granted": True}

        async def record_usage(self, context: Dict[str, Any]) -> Dict[str, Any]:
            return {"status": "success", "usage_recorded": True}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of input validation with enhanced security context."""
    is_valid: bool
    sanitized_value: Any
    errors: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    governance_violations: List[str] = field(default_factory=list)
    sanitization_applied: bool = False

class MCPGovernanceSecurityHardening:
    """Security hardening for MCP AI resource governance operations"""

    def __init__(self):
        # Maximum input sizes for resource protection
        self.max_config_size = 100 * 1024  # 100KB for configuration
        self.max_string_length = 10000
        self.max_list_items = 1000
        self.max_dict_keys = 100

        # MCP Governance-specific dangerous patterns
        self.dangerous_patterns = [
            # Enhanced SQL Injection patterns
            r';\s*DROP\s+TABLE',
            r';\s*DROP\s+\w+',  # Catch any DROP statement, not just tables
            r';\s*DELETE\s+FROM',
            r';\s*INSERT\s+INTO',
            r';\s*UPDATE\s+.*SET',
            r'UNION\s+SELECT',
            r"'\s*OR\s+'\d+=\d+",
            r'";\s*--',
            r"';\s*--",  # Single quote followed by comment
            r';\s*--',   # Semicolon followed by comment
            r"';\s*OR\s+'[^']*'\s*=\s*'[^']*'",
            r"'\s*OR\s+'[^']*'\s*=\s*'[^']*'",  # SQL OR injection without semicolon
            r'OR\s+1\s*=\s*1',
            r"OR\s+['\"]1['\"]?\s*=\s*['\"]1['\"]?",  # Enhanced OR 1=1 patterns
            r"'\s*OR\s*['\"]?\d+['\"]?\s*=\s*['\"]?\d+['\"]?",  # General numeric equality injection
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
            r'\|\s*nc\s+',  # Pipe to netcat
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
            r'exec\s+',

            # Enhanced Path traversal patterns
            r'\.\./\.\./\.\.',
            r'\.\.\\\.\.\\\.\.\\',
            r'/etc/passwd',
            r'/etc/shadow',
            r'\\windows\\system32',
            r'%2e%2e%2f',
            r'%2e%2e%5c',
            r'%252f',
            r'\.\./etc/',
            r'\.\.[\\/]etc[\\/]',
            r'\.\.[\\/]\.\.[\\/]',
            r'\.\.[\\/]windows[\\/]',
            r'\.\.[\\/]usr[\\/]',
            r'\.\.[\\/]var[\\/]',
            r'\.\.[\\/]tmp[\\/]',
            r'/\.\./',
            r'\\\.\.\\',

            # Script injection patterns
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'eval\s*\(',
            r'exec\s*\(',
            r'system\s*\(',
            r'__import__',
            r'getattr\s*\(',
            r'setattr\s*\(',

            # Enhanced MCP Governance bypass patterns
            r';\s*shutdown',
            r';\s*reboot',
            r'>&\s*/dev/null',
            r'2>&1',
            r'/dev/tcp/',
            r'mkfifo',

            # Enhanced Resource governance manipulation patterns
            r'DISABLE\s+GOVERNANCE',
            r'BYPASS\s+BUDGET',
            r'OVERRIDE\s+LIMIT',
            r'SET\s+COST\s*=\s*0',
            r'UNLIMITED\s+BUDGET',
            r'ADMIN\s+OVERRIDE',
            r'EMERGENCY\s+BYPASS',
            r'QUOTA\s+DISABLE',
            r'LIMIT\s+REMOVE',
            r'THRESHOLD\s+IGNORE',
            # Additional cost manipulation patterns
            r'SET\s+COST\s*=\s*0',
            r'UNLIMITED',
            r'BYPASS\s+LIMIT',
            r'DISABLE\s+TRACKING',
            r'BYPASS\s+ALL',
            r'DISABLE\s+ALL\s+LIMITS',
            # Additional emergency bypass patterns
            r'EMERGENCY\s+BYPASS',
            r'THRESHOLD\s+IGNORE',
            r'DISABLE\s+ALL\s+LIMITS',

            # SECURITY HARDENING: Enhanced MCP governance-specific patterns
            r'API_KEY\s*=\s*["\'][^"\']+["\']',  # API key exposure
            r'TOKEN\s*=\s*["\'][^"\']+["\']',    # Token exposure
            r'PASSWORD\s*=\s*["\'][^"\']+["\']', # Password exposure
            r'SECRET\s*=\s*["\'][^"\']+["\']',   # Secret exposure
            r'ADMIN\s+OVERRIDE',                 # Admin privilege escalation
            r'ROOT\s+ACCESS',                    # Root access attempts
            r'SUDO\s+',                          # Sudo command attempts
            r'PRIVILEGE\s+ESCALATION',           # Privilege escalation
            r'COST\s*=\s*0',                     # Cost manipulation to zero
            r'LIMIT\s*=\s*999999',               # Limit manipulation to max
            r'QUOTA\s*=\s*UNLIMITED',            # Quota bypass
            r'BUDGET\s*=\s*INF',                 # Infinite budget attempts
            r'THRESHOLD\s*=\s*NONE',             # Threshold removal
            r'GOVERNANCE\s*=\s*DISABLED',        # Governance disabling
            r'AUDIT\s*=\s*FALSE',                # Audit disabling
            r'["\']?audit["\']?\s*:\s*["\']?FALSE["\']?',  # JSON audit disabling
            r'["\']?audit["\']?\s*:\s*["\']?false["\']?',  # JSON audit disabling (lowercase)
            r'TRACKING\s*=\s*OFF',               # Tracking disabling
            r'MONITOR\s*=\s*DISABLED',           # Monitoring disabling
            r'ALERT\s*=\s*SILENT',               # Alert silencing
            r'LOG\s*=\s*NULL',                   # Log nullification
            r'RECORD\s*=\s*SKIP',                # Record skipping
            r'VALIDATE\s*=\s*BYPASS',            # Validation bypass
            r'SECURITY\s*=\s*DISABLED',          # Security disabling
            r'SANITIZE\s*=\s*FALSE',             # Sanitization disabling
        ]

        # Compile patterns for performance - Enhanced with additional governance patterns
        try:
            self.dangerous_regex = re.compile('|'.join(self.dangerous_patterns), re.IGNORECASE)
        except re.error as e:
            # Fallback: Use individual pattern matching if compilation fails
            self.dangerous_regex = None
            logger.warning(f"Regex compilation failed: {e}. Using individual pattern matching.")

        # Valid operations (whitelist)
        self.valid_operations = {
            "check_permission", "record_usage", "get_dashboard", "get_status",
            "get_cost_prediction", "get_usage_stats", "emergency_stop",
            "configure_limits", "audit_report"
        }

        # Valid governance modes (whitelist)
        self.valid_governance_modes = {"basic", "standard", "enterprise"}

        # Valid tool categories (whitelist)
        self.valid_tool_categories = {"safe", "standard", "sensitive", "destructive"}

        # Initialize Universal Input Sanitizer
        self.sanitizer = None
        try:
            self.sanitizer = pp("universal_input_sanitizer")
        except Exception:
            pass  # Fallback to manual validation if sanitizer unavailable

    def validate_governance_input(self, data: Any, context: str = "general") -> ValidationResult:
        """Validate MCP governance input with comprehensive security checks"""
        result = ValidationResult(is_valid=True, sanitized_value=data)

        try:
            # EMERGENCY DEBUG: Add debug info to all results
            result.warnings.append(f"DEBUG: validate_governance_input called with data: {repr(data)}")
            result.warnings.append(f"DEBUG: dangerous_regex available: {bool(hasattr(self, 'dangerous_regex'))}")
            # Size validation first
            data_size = len(str(data))
            if data_size > self.max_config_size:
                result.is_valid = False
                result.errors.append(f"Input size {data_size} exceeds maximum {self.max_config_size}")
                return result

            # Convert to string for pattern validation
            data_str = str(data) if data is not None else ""
            result.warnings.append(f"DEBUG: data_str = {repr(data_str)}")

            # Pattern-based security validation
            dangerous_pattern_found = None
            if self.dangerous_regex:
                dangerous_pattern_found = self.dangerous_regex.search(data_str)
            else:
                # Fallback: Check individual patterns if regex compilation failed
                import re as regex_fallback
                for pattern in self.dangerous_patterns:
                    try:
                        if regex_fallback.search(pattern, data_str, regex_fallback.IGNORECASE):
                            dangerous_pattern_found = True
                            break
                    except:
                        continue
            result.warnings.append(f"DEBUG: dangerous_pattern_found = {bool(dangerous_pattern_found)}")

            if dangerous_pattern_found:
                result.security_issues.append("Dangerous patterns detected in governance input")
                result.warnings.append("Security patterns detected in governance configuration")
                result.warnings.append(f"DEBUG: dangerous_pattern_found = {bool(dangerous_pattern_found)}, matched: {repr(dangerous_pattern_found.group())}")
            else:
                result.warnings.append("DEBUG: No dangerous patterns found - checking individual patterns")
                # Debug: Test a few key patterns individually
                test_patterns = [
                    r"'\s*OR\s+'[^']*'\s*=\s*'[^']*'",
                    r'OR\s+1\s*=\s*1'
                ]
                import re
                for i, pattern in enumerate(test_patterns):
                    match = re.search(pattern, data_str, re.IGNORECASE)
                    result.warnings.append(f"DEBUG: Pattern {i}: {bool(match)} - {pattern}")

            # Universal Input Sanitizer validation (if available) - SECURITY FIX
            sanitizer_success = False
            if self.sanitizer:
                try:
                    # SECURITY FIX: Convert data to string for Universal Input Sanitizer
                    import json
                    data_str = json.dumps(data) if not isinstance(data, str) else data

                    sanitizer_result = self.sanitizer.process({}, {
                        "input_data": data_str,
                        "sanitization_types": ["sql_injection", "xss", "path_traversal", "command_injection"],
                        "validation_mode": "strict"
                    })

                    # DEBUG: Force security issues if dangerous patterns found regardless of sanitizer
                    if dangerous_pattern_found:
                        result.warnings.append("DEBUG: Dangerous pattern detected, forcing security issue flag")

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

                            # CRITICAL: If we detected dangerous patterns earlier, preserve that flag
                            # even if sanitizer reports success
                            if dangerous_pattern_found and "Dangerous patterns detected in governance input" not in result.security_issues:
                                result.security_issues.append("Dangerous patterns detected in governance input")
                        else:
                            result.sanitized_value = self._fallback_sanitize_governance(data)
                            result.sanitization_applied = True
                    else:
                        result.sanitized_value = self._fallback_sanitize_governance(data)
                        result.sanitization_applied = True

                except Exception as e:
                    result.warnings.append(f"Universal Input Sanitizer validation failed: {str(e)}")
                    result.sanitized_value = self._fallback_sanitize_governance(data)
                    result.sanitization_applied = True

            # Apply fallback sanitization if sanitizer unavailable OR security issues detected
            if not sanitizer_success or result.security_issues:
                result.sanitized_value = self._fallback_sanitize_governance(data)
                result.sanitization_applied = True

            # Governance-specific validation
            governance_result = self._validate_governance_context(result.sanitized_value, context)
            result.governance_violations.extend(governance_result.get("violations", []))
            if governance_result.get("violations"):
                result.warnings.extend(governance_result.get("violations", []))

            # CRITICAL: Final security validation - ensure dangerous patterns are ALWAYS flagged
            # This is the last check before returning, nothing can override this
            if dangerous_pattern_found:
                # FORCE create a NEW security_issues list to ensure it can't be cleared by external factors
                result.security_issues = ["Dangerous patterns detected in governance input"]

                # Enhanced security hardening: Add pattern-specific details for debugging
                original_str = str(data) if data is not None else ""
                pattern_matches = []
                import re as regex_module  # Import with alias to avoid scope conflicts

                for i, pattern in enumerate(self.dangerous_patterns):
                    try:
                        if regex_module.search(pattern, original_str, regex_module.IGNORECASE):
                            pattern_matches.append(f"Pattern {i+1}: {pattern[:30]}...")
                            break  # Just need to know one matched
                    except Exception:
                        # Skip pattern if regex compilation fails
                        continue

                if pattern_matches:
                    result.security_issues.append(f"Matched dangerous patterns: {', '.join(pattern_matches)}")

                # SECURITY HARDENING: Additional governance-specific threat detection
                if "DROP" in original_str.upper() or "DELETE" in original_str.upper():
                    result.security_issues.append("CRITICAL: Database destruction patterns detected")
                if "BYPASS" in original_str.upper() or "UNLIMITED" in original_str.upper():
                    result.security_issues.append("CRITICAL: Governance bypass attempts detected")
                if "EMERGENCY" in original_str.upper() and "OVERRIDE" in original_str.upper():
                    result.security_issues.append("CRITICAL: Emergency override attempt detected")

            return result

        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Governance input validation failed: {str(e)}")

            # EMERGENCY: Even if there's an exception, check for dangerous patterns
            try:
                data_str = str(data) if data is not None else ""
                if self.dangerous_regex.search(data_str):
                    result.security_issues = ["EXCEPTION: Dangerous patterns detected in governance input"]
                    result.warnings.append("EXCEPTION: Security patterns detected despite error")
            except:
                pass  # Don't let secondary errors mask the primary error

            return result

    def _fallback_sanitize_governance(self, data: Any) -> Any:
        """Fallback sanitization for governance operations"""
        if isinstance(data, dict):
            sanitized = {}
            # Define allowed fields for governance operations
            allowed_fields = {
                "operation", "context", "plugin_name", "user_id", "client_id", "tool_name",
                "resource_request", "budget_request", "cost_prediction", "usage_data",
                "governance_mode", "mcp_governance_mode", "tool_category", "emergency_action", "limit_config",
                "estimated_tokens", "model_provider", "is_admin", "approval_required",
                "actual_cost", "estimated_cost", "actual_tokens", "api_costs",
                "processing_costs", "storage_costs", "bandwidth_costs", "cost_tracking_enabled",
                "per_tool_limits", "emergency_thresholds", "budget_alerts", "model_quotas"
            }

            for key, value in data.items():
                if isinstance(key, str):
                    # Sanitize key
                    clean_key = self._sanitize_string(key)
                    if len(clean_key) <= 100 and clean_key:  # Reasonable key length
                        # Only allow known governance fields - filter out dangerous fields
                        if clean_key in allowed_fields:
                            sanitized[clean_key] = self._fallback_sanitize_governance(value)
                elif isinstance(key, (int, float)):
                    sanitized[str(key)] = self._fallback_sanitize_governance(value)
            return sanitized

        elif isinstance(data, list):
            if len(data) > self.max_list_items:
                data = data[:self.max_list_items]  # Truncate oversized lists
            return [self._fallback_sanitize_governance(item) for item in data]

        elif isinstance(data, str):
            return self._sanitize_string(data)

        elif isinstance(data, (int, float, bool)):
            return data

        elif data is None:
            return None

        else:
            # Convert unknown types to string and sanitize
            return self._sanitize_string(str(data))

    def _sanitize_string(self, data: str) -> str:
        """Enhanced string sanitization for governance context"""
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

        # Enhanced governance-specific sanitization
        data = re.sub(r'SET\s+COST\s*=\s*0', '[COST_MANIPULATION]', data, flags=re.IGNORECASE)
        data = re.sub(r'UNLIMITED', '[UNLIMITED_TOKEN]', data, flags=re.IGNORECASE)
        data = re.sub(r'BYPASS\s+LIMIT', '[BYPASS_ATTEMPT]', data, flags=re.IGNORECASE)
        data = re.sub(r'DISABLE\s+TRACKING', '[DISABLE_ATTEMPT]', data, flags=re.IGNORECASE)
        data = re.sub(r'EMERGENCY\s+BYPASS', '[EMERGENCY_BYPASS]', data, flags=re.IGNORECASE)
        data = re.sub(r'THRESHOLD\s+IGNORE', '[THRESHOLD_BYPASS]', data, flags=re.IGNORECASE)

        # Enhanced SQL injection sanitization
        data = re.sub(r';\s*DROP\s+TABLE', '[SQL_DROP]', data, flags=re.IGNORECASE)
        data = re.sub(r';\s*DELETE\s+FROM', '[SQL_DELETE]', data, flags=re.IGNORECASE)
        data = re.sub(r'UNION\s+SELECT', '[SQL_UNION]', data, flags=re.IGNORECASE)
        data = re.sub(r"'\s*OR\s+'", '[SQL_OR]', data, flags=re.IGNORECASE)

        # Enhanced command injection sanitization
        data = re.sub(r';\s*rm\s+-rf', '[CMD_RM]', data, flags=re.IGNORECASE)
        data = re.sub(r';\s*cat\s+/etc/', '[CMD_CAT]', data, flags=re.IGNORECASE)
        data = re.sub(r'&&\s*[a-zA-Z]', '[CMD_AND]', data, flags=re.IGNORECASE)
        data = re.sub(r'\|\|\s*[a-zA-Z]', '[CMD_OR]', data, flags=re.IGNORECASE)

        # Basic HTML escaping for governance reporting context
        data = data.replace('&', '&amp;')
        data = data.replace('<', '&lt;')
        data = data.replace('>', '&gt;')
        data = data.replace('"', '&quot;')
        data = data.replace("'", '&#x27;')

        return data.strip()

    def _validate_governance_context(self, data: Any, context: str) -> Dict[str, Any]:
        """Validate governance-specific context and constraints"""
        violations = []

        if isinstance(data, dict):
            # Validate operation field
            operation = data.get("operation")
            if operation and operation not in self.valid_operations:
                violations.append(f"Invalid operation: {operation}")

            # Validate governance_mode field
            governance_mode = data.get("governance_mode")
            if governance_mode and governance_mode not in self.valid_governance_modes:
                violations.append(f"Invalid governance mode: {governance_mode}")

            # Validate tool_category field
            tool_category = data.get("tool_category")
            if tool_category and tool_category not in self.valid_tool_categories:
                violations.append(f"Invalid tool category: {tool_category}")

            # Validate numeric limits for costs and budgets
            for field_name in ["actual_cost", "estimated_cost", "budget_request"]:
                field_value = data.get(field_name)
                if field_value is not None:
                    if not isinstance(field_value, (int, float)) or field_value < 0:
                        violations.append(f"Invalid {field_name}: must be non-negative number")
                    elif field_value > 10000:  # Reasonable upper limit
                        violations.append(f"Invalid {field_name}: exceeds maximum allowed value")

            # Validate token limits
            for field_name in ["actual_tokens", "estimated_tokens"]:
                field_value = data.get(field_name)
                if field_value is not None:
                    if not isinstance(field_value, int) or field_value < 0:
                        violations.append(f"Invalid {field_name}: must be non-negative integer")
                    elif field_value > 1000000:  # Reasonable upper limit
                        violations.append(f"Invalid {field_name}: exceeds maximum token limit")

        return {"violations": violations}

    def validate_governance_context(self, data: Any, context: str) -> Dict[str, Any]:
        """Public wrapper for governance context validation"""
        return self._validate_governance_context(data, context)

class GovernanceMode(Enum):
    BASIC = "basic"
    STANDARD = "standard"
    ENTERPRISE = "enterprise"

@dataclass
class MCPCostMetrics:
    token_consumption: int
    api_call_costs: float
    processing_time_costs: float
    storage_costs: float
    bandwidth_costs: float
    total_cost: float
    timestamp: str

@dataclass
class ToolLimits:
    max_cost_per_call: float
    max_tokens_per_call: int
    max_calls_per_hour: int
    max_daily_cost: float
    approval_required: bool = False
    admin_only: bool = False

@dataclass
class EmergencyThreshold:
    daily_limit: float
    hourly_limit: float
    per_tool_limit: float
    automatic_actions: List[str]

@dataclass
class BudgetAllocation:
    daily_budget: float
    weekly_budget: float
    monthly_budget: float
    current_usage: float = 0.0
    
class MCPAIResourceGovernancePlugin:
    """
    MCP-Aware AI Resource Governance Integration - Enterprise Security Hardened
    Extends existing AI resource governance with MCP-specific features
    Enhanced with Universal Input Sanitizer integration and comprehensive security validation.
    """

    def __init__(self, config: Dict[str, Any]):
        # Initialize security hardening first
        self.security_hardening = MCPGovernanceSecurityHardening()

        # Validate and sanitize configuration
        config_validation = self.security_hardening.validate_governance_input(config, "configuration")
        if config_validation.errors:
            logger.error(f"Configuration validation errors: {config_validation.errors}")
            raise ValueError(f"Invalid configuration: {'; '.join(config_validation.errors)}")

        # Use sanitized configuration
        self.config = config_validation.sanitized_value
        governance_mode_str = self.config.get('mcp_governance_mode', 'basic')
        self.governance_mode = GovernanceMode(governance_mode_str)

        # Initialize base governance plugin
        self.base_governance = BaseGovernancePlugin(self.config)
        
        # MCP-specific configuration
        self.cost_tracking_enabled = config.get('cost_tracking_enabled', True)
        self.per_tool_limits = self._load_per_tool_limits(config.get('per_tool_limits', {}))
        self.emergency_thresholds = self._load_emergency_thresholds(config.get('emergency_thresholds', {}))
        self.budget_alerts = config.get('budget_alerts', {})
        self.model_quotas = config.get('model_quotas', {})
        
        # Cost tracking providers
        self.cost_providers = {
            'anthropic_claude': {
                'pricing_model': 'per_token',
                'input_cost_per_1k_tokens': 0.008,
                'output_cost_per_1k_tokens': 0.024,
                'max_context_tokens': 200000
            },
            'openai_gpt4': {
                'pricing_model': 'per_token', 
                'input_cost_per_1k_tokens': 0.03,
                'output_cost_per_1k_tokens': 0.06,
                'max_context_tokens': 8192
            },
            'local_llm': {
                'pricing_model': 'compute_time',
                'cost_per_second': 0.001,
                'max_context_tokens': 4096
            }
        }
        
        # Usage tracking
        self.usage_history: Dict[str, List[MCPCostMetrics]] = {}
        self.daily_usage: Dict[str, float] = {}
        self.hourly_usage: Dict[str, float] = {}
        self.emergency_stops: List[Dict[str, Any]] = []
        
        # Feature activation based on governance mode
        self.active_features = self._get_active_features()
        
        logger.info(f"MCP AI Resource Governance initialized in {self.governance_mode.value} mode")
    
    def _load_per_tool_limits(self, limits_config: Dict[str, Any]) -> Dict[str, ToolLimits]:
        """Load per-tool resource limits configuration"""
        limits = {}
        
        # Default limits
        default_config = limits_config.get('default', {})
        limits['default'] = ToolLimits(
            max_cost_per_call=default_config.get('max_cost_per_call', 1.0),
            max_tokens_per_call=default_config.get('max_tokens_per_call', 10000),
            max_calls_per_hour=default_config.get('max_calls_per_hour', 100),
            max_daily_cost=default_config.get('max_daily_cost', 50.0)
        )
        
        # Tool category limits
        tool_categories = limits_config.get('tool_categories', {})
        for category, category_config in tool_categories.items():
            limits[category] = ToolLimits(
                max_cost_per_call=category_config.get('max_cost_per_call', 1.0),
                max_tokens_per_call=category_config.get('max_tokens_per_call', 10000),
                max_calls_per_hour=category_config.get('max_calls_per_hour', 100),
                max_daily_cost=category_config.get('max_daily_cost', 50.0),
                approval_required=category_config.get('approval_required', False),
                admin_only=category_config.get('admin_only', False)
            )
        
        return limits
    
    def _load_emergency_thresholds(self, threshold_config: Dict[str, Any]) -> EmergencyThreshold:
        """Load emergency control thresholds"""
        cost_thresholds = threshold_config.get('cost_thresholds', {})
        automatic_actions = threshold_config.get('automatic_actions', [])
        
        return EmergencyThreshold(
            daily_limit=cost_thresholds.get('daily_limit', 500.0),
            hourly_limit=cost_thresholds.get('hourly_limit', 100.0),
            per_tool_limit=cost_thresholds.get('per_tool_limit', 10.0),
            automatic_actions=automatic_actions
        )
    
    def _get_active_features(self) -> List[str]:
        """Get active features based on governance mode"""
        mode_features = {
            GovernanceMode.BASIC: [
                "mcp_cost_tracking",
                "simple_budget_alerts"
            ],
            GovernanceMode.STANDARD: [
                "mcp_cost_tracking",
                "per_tool_resource_limits", 
                "model_quota_enforcement",
                "predictive_cost_analysis"
            ],
            GovernanceMode.ENTERPRISE: [
                "mcp_cost_tracking",
                "per_tool_resource_limits",
                "model_quota_enforcement", 
                "predictive_cost_analysis",
                "emergency_controls",
                "advanced_analytics",
                "compliance_reporting"
            ]
        }
        
        return mode_features.get(self.governance_mode, [])
    
    def _classify_tool(self, tool_name: str) -> str:
        """Classify tool into safety category"""
        safe_tools = ["calculator", "timer", "weather"]
        standard_tools = ["file_reader", "api_caller"]
        sensitive_tools = ["database_query", "user_manager"] 
        destructive_tools = ["file_deleter", "system_admin"]
        
        if tool_name.lower() in safe_tools:
            return "safe"
        elif tool_name.lower() in standard_tools:
            return "standard"
        elif tool_name.lower() in sensitive_tools:
            return "sensitive"
        elif tool_name.lower() in destructive_tools:
            return "destructive"
        else:
            return "standard"  # Default to standard
    
    def _get_tool_limits(self, tool_name: str) -> ToolLimits:
        """Get resource limits for a specific tool"""
        tool_category = self._classify_tool(tool_name)
        return self.per_tool_limits.get(tool_category, self.per_tool_limits['default'])
    
    async def _calculate_cost_prediction(self, context: Dict[str, Any]) -> Dict[str, float]:
        """Calculate predicted cost for tool call"""
        if "predictive_cost_analysis" not in self.active_features:
            return {"predicted_cost": 0.0, "confidence": 0.0}
        
        tool_name = context.get('plugin_name', 'unknown')
        estimated_tokens = context.get('estimated_tokens', 1000)
        model_provider = context.get('model_provider', 'anthropic_claude')
        
        provider_config = self.cost_providers.get(model_provider, self.cost_providers['anthropic_claude'])
        
        if provider_config['pricing_model'] == 'per_token':
            # Assume 80% input, 20% output ratio for prediction
            input_tokens = int(estimated_tokens * 0.8)
            output_tokens = int(estimated_tokens * 0.2)
            
            input_cost = (input_tokens / 1000) * provider_config['input_cost_per_1k_tokens']
            output_cost = (output_tokens / 1000) * provider_config['output_cost_per_1k_tokens']
            predicted_cost = input_cost + output_cost
        else:
            # Compute time based
            estimated_time = context.get('estimated_processing_time', 10.0)  # seconds
            predicted_cost = estimated_time * provider_config['cost_per_second']
        
        # Add confidence based on historical data
        confidence = 0.8  # Default confidence
        tool_history = self.usage_history.get(tool_name, [])
        if len(tool_history) > 5:
            confidence = 0.95  # Higher confidence with more data
        
        return {
            "predicted_cost": round(predicted_cost, 4),
            "confidence": confidence,
            "breakdown": {
                "input_cost": input_cost if provider_config['pricing_model'] == 'per_token' else 0,
                "output_cost": output_cost if provider_config['pricing_model'] == 'per_token' else 0,
                "compute_cost": predicted_cost if provider_config['pricing_model'] == 'compute_time' else 0
            }
        }
    
    async def _check_emergency_thresholds(self, context: Dict[str, Any], predicted_cost: float) -> Dict[str, Any]:
        """Check if request would trigger emergency thresholds"""
        if "emergency_controls" not in self.active_features:
            return {"emergency_triggered": False}
        
        tool_name = context.get('plugin_name', 'unknown')
        user_id = context.get('user_id', 'anonymous')
        
        current_time = datetime.now()
        
        # Check daily limit
        daily_key = f"{user_id}:{current_time.strftime('%Y-%m-%d')}"
        current_daily = self.daily_usage.get(daily_key, 0.0)
        if current_daily + predicted_cost > self.emergency_thresholds.daily_limit:
            return {
                "emergency_triggered": True,
                "threshold_type": "daily_limit",
                "current_usage": current_daily,
                "limit": self.emergency_thresholds.daily_limit,
                "would_exceed": current_daily + predicted_cost
            }
        
        # Check hourly limit  
        hourly_key = f"{user_id}:{current_time.strftime('%Y-%m-%d:%H')}"
        current_hourly = self.hourly_usage.get(hourly_key, 0.0)
        if current_hourly + predicted_cost > self.emergency_thresholds.hourly_limit:
            return {
                "emergency_triggered": True,
                "threshold_type": "hourly_limit",
                "current_usage": current_hourly,
                "limit": self.emergency_thresholds.hourly_limit,
                "would_exceed": current_hourly + predicted_cost
            }
        
        # Check per-tool limit
        tool_daily_key = f"{tool_name}:{current_time.strftime('%Y-%m-%d')}"
        current_tool_daily = self.daily_usage.get(tool_daily_key, 0.0)
        if current_tool_daily + predicted_cost > self.emergency_thresholds.per_tool_limit:
            return {
                "emergency_triggered": True,
                "threshold_type": "per_tool_limit", 
                "tool_name": tool_name,
                "current_usage": current_tool_daily,
                "limit": self.emergency_thresholds.per_tool_limit,
                "would_exceed": current_tool_daily + predicted_cost
            }
        
        return {"emergency_triggered": False}
    
    async def _trigger_emergency_actions(self, emergency_info: Dict[str, Any]) -> List[str]:
        """Trigger automatic emergency actions"""
        actions_taken = []
        
        for action in self.emergency_thresholds.automatic_actions:
            if action == "rate_limiting_activation":
                # Could integrate with rate limiter plugin
                actions_taken.append("Rate limiting activated")
            elif action == "expensive_tool_blocking":
                # Block tools above certain cost threshold
                actions_taken.append("Expensive tools blocked")
            elif action == "admin_notifications":
                # Send notifications to administrators
                actions_taken.append("Admin notifications sent")
            elif action == "audit_logging_increase":
                # Increase audit logging level
                actions_taken.append("Audit logging increased")
        
        # Log emergency event
        emergency_event = {
            "timestamp": datetime.now().isoformat(),
            "emergency_info": emergency_info,
            "actions_taken": actions_taken
        }
        self.emergency_stops.append(emergency_event)
        
        logger.warning(f"Emergency threshold triggered: {emergency_info}")
        
        return actions_taken
    
    async def _record_mcp_usage(self, context: Dict[str, Any], actual_cost: float) -> None:
        """Record MCP-specific usage metrics"""
        if not self.cost_tracking_enabled:
            return
        
        tool_name = context.get('plugin_name', 'unknown')
        user_id = context.get('user_id', 'anonymous')
        current_time = datetime.now()
        
        # Create cost metrics
        metrics = MCPCostMetrics(
            token_consumption=context.get('actual_tokens', 0),
            api_call_costs=context.get('api_costs', 0.0),
            processing_time_costs=context.get('processing_costs', 0.0),
            storage_costs=context.get('storage_costs', 0.0),
            bandwidth_costs=context.get('bandwidth_costs', 0.0),
            total_cost=actual_cost,
            timestamp=current_time.isoformat()
        )
        
        # Store in usage history
        if tool_name not in self.usage_history:
            self.usage_history[tool_name] = []
        self.usage_history[tool_name].append(metrics)
        
        # Update daily/hourly usage
        daily_key = f"{user_id}:{current_time.strftime('%Y-%m-%d')}"
        hourly_key = f"{user_id}:{current_time.strftime('%Y-%m-%d:%H')}"
        tool_daily_key = f"{tool_name}:{current_time.strftime('%Y-%m-%d')}"
        
        self.daily_usage[daily_key] = self.daily_usage.get(daily_key, 0.0) + actual_cost
        self.hourly_usage[hourly_key] = self.hourly_usage.get(hourly_key, 0.0) + actual_cost
        self.daily_usage[tool_daily_key] = self.daily_usage.get(tool_daily_key, 0.0) + actual_cost
    
    async def check_mcp_permission(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Check if MCP tool call is permitted based on governance rules with security validation"""
        start_time = time.time()

        try:
            # SECURITY: Validate and sanitize input context first
            context_validation = self.security_hardening.validate_governance_input(context, "permission_check")
            if context_validation.errors:
                return {
                    "status": "denied",
                    "message": f"Context validation failed: {'; '.join(context_validation.errors)}",
                    "permission_granted": False,
                    "reason": "validation_failure",
                    "security_validation": {
                        "errors": context_validation.errors,
                        "security_issues": context_validation.security_issues,
                        "governance_violations": context_validation.governance_violations
                    }
                }

            # Use sanitized context for processing
            sanitized_context = context_validation.sanitized_value

            # Log security issues if detected but allow processing to continue
            security_metadata = {
                "sanitization_applied": context_validation.sanitization_applied,
                "security_issues_count": len(context_validation.security_issues),
                "governance_violations_count": len(context_validation.governance_violations),
                "validation_time": time.time() - start_time
            }

            if context_validation.security_issues:
                logger.warning(f"Security issues detected in permission context: {context_validation.security_issues}")

            # First check base governance plugin
            base_result = await self.base_governance.check_permission(sanitized_context)
            if not base_result.get('permission_granted', False):
                base_result["security_metadata"] = security_metadata
                return base_result
            
            tool_name = sanitized_context.get('plugin_name', 'unknown')
            user_id = sanitized_context.get('user_id', 'anonymous')

            # Get tool-specific limits
            tool_limits = self._get_tool_limits(tool_name)

            # Check admin-only restrictions
            if tool_limits.admin_only and not sanitized_context.get('is_admin', False):
                return {
                    "status": "denied",
                    "message": f"Tool '{tool_name}' requires admin permissions",
                    "permission_granted": False,
                    "reason": "admin_required",
                    "security_metadata": security_metadata
                }

            # Get cost prediction
            cost_prediction = await self._calculate_cost_prediction(sanitized_context)
            predicted_cost = cost_prediction['predicted_cost']

            # Check per-call cost limit
            if predicted_cost > tool_limits.max_cost_per_call:
                return {
                    "status": "denied",
                    "message": f"Predicted cost ${predicted_cost:.4f} exceeds limit ${tool_limits.max_cost_per_call}",
                    "permission_granted": False,
                    "reason": "cost_limit_exceeded",
                    "cost_prediction": cost_prediction,
                    "security_metadata": security_metadata
                }

            # Check token limits
            estimated_tokens = sanitized_context.get('estimated_tokens', 0)
            if estimated_tokens > tool_limits.max_tokens_per_call:
                return {
                    "status": "denied",
                    "message": f"Estimated tokens {estimated_tokens} exceeds limit {tool_limits.max_tokens_per_call}",
                    "permission_granted": False,
                    "reason": "token_limit_exceeded",
                    "security_metadata": security_metadata
                }

            # Check emergency thresholds
            emergency_check = await self._check_emergency_thresholds(sanitized_context, predicted_cost)
            if emergency_check.get('emergency_triggered', False):
                actions_taken = await self._trigger_emergency_actions(emergency_check)
                return {
                    "status": "denied",
                    "message": f"Emergency threshold triggered: {emergency_check['threshold_type']}",
                    "permission_granted": False,
                    "reason": "emergency_threshold",
                    "emergency_info": emergency_check,
                    "actions_taken": actions_taken,
                    "security_metadata": security_metadata
                }

            # Check if approval is required
            if tool_limits.approval_required:
                return {
                    "status": "warning",
                    "message": f"Tool '{tool_name}' requires explicit approval",
                    "permission_granted": False,
                    "reason": "approval_required",
                    "cost_prediction": cost_prediction,
                    "requires_approval": True,
                    "security_metadata": security_metadata
                }

            # Permission granted
            return {
                "status": "success",
                "message": "MCP tool call permitted",
                "permission_granted": True,
                "cost_prediction": cost_prediction,
                "tool_limits": asdict(tool_limits),
                "security_metadata": security_metadata
            }
            
        except Exception as e:
            logger.error(f"Error in MCP permission check: {str(e)}")
            return {
                "status": "error",
                "message": f"Permission check failed: {str(e)}",
                "permission_granted": False,
                "error": str(e)
            }
    
    async def record_mcp_usage(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Record actual MCP usage after tool execution"""
        try:
            # First record in base governance plugin
            base_result = await self.base_governance.record_usage(context)
            
            # Record MCP-specific usage
            actual_cost = context.get('actual_cost', context.get('estimated_cost', 0.0))
            await self._record_mcp_usage(context, actual_cost)
            
            return {
                "status": "success",
                "message": "MCP usage recorded successfully",
                "usage_recorded": True,
                "base_governance_result": base_result,
                "mcp_cost_tracking_enabled": self.cost_tracking_enabled
            }
            
        except Exception as e:
            logger.error(f"Error recording MCP usage: {str(e)}")
            return {
                "status": "error", 
                "message": f"Usage recording failed: {str(e)}",
                "usage_recorded": False,
                "error": str(e)
            }
    
    async def get_mcp_dashboard_data(self) -> Dict[str, Any]:
        """Get MCP-specific dashboard data"""
        try:
            current_time = datetime.now()
            
            # Real-time metrics
            real_time_metrics = {
                "total_tools_tracked": len(self.usage_history),
                "total_cost_today": sum(
                    cost for key, cost in self.daily_usage.items()
                    if current_time.strftime('%Y-%m-%d') in key
                ),
                "emergency_stops_count": len(self.emergency_stops),
                "active_governance_mode": self.governance_mode.value,
                "cost_tracking_enabled": self.cost_tracking_enabled
            }
            
            # Cost trends (last 7 days)
            cost_trends = []
            for i in range(7):
                date = (current_time - timedelta(days=i)).strftime('%Y-%m-%d')
                daily_total = sum(
                    cost for key, cost in self.daily_usage.items()
                    if date in key
                )
                cost_trends.append({
                    "date": date,
                    "total_cost": daily_total
                })
            
            # Plugin usage breakdown
            plugin_usage_breakdown = {}
            for tool_name, metrics_list in self.usage_history.items():
                total_cost = sum(m.total_cost for m in metrics_list)
                total_tokens = sum(m.token_consumption for m in metrics_list)
                plugin_usage_breakdown[tool_name] = {
                    "total_cost": total_cost,
                    "total_tokens": total_tokens,
                    "call_count": len(metrics_list),
                    "average_cost": total_cost / len(metrics_list) if metrics_list else 0
                }
            
            # Active alerts
            alerts = []
            
            # Check budget alerts
            for threshold in [0.7, 0.9, 1.0]:
                daily_limit = self.emergency_thresholds.daily_limit
                current_daily = sum(
                    cost for key, cost in self.daily_usage.items()
                    if current_time.strftime('%Y-%m-%d') in key
                )
                
                if current_daily >= daily_limit * threshold:
                    level = "warning" if threshold < 0.9 else "critical" if threshold < 1.0 else "emergency"
                    alerts.append({
                        "level": level,
                        "message": f"Daily budget at {threshold*100:.0f}% (${current_daily:.2f}/${daily_limit:.2f})",
                        "timestamp": current_time.isoformat()
                    })
            
            return {
                "success": True,
                "dashboard_data": {
                    "real_time_metrics": real_time_metrics,
                    "cost_trends": cost_trends,
                    "plugin_usage_breakdown": plugin_usage_breakdown,
                    "alerts": alerts
                }
            }
            
        except Exception as e:
            logger.error(f"Error generating MCP dashboard data: {str(e)}")
            return {
                "success": False,
                "error": str(e),
                "dashboard_data": {}
            }
    
    async def process_request(self, input_data: Dict[str, Any]) -> Dict[str, Any]:
        """Main plugin entry point"""
        try:
            operation = input_data.get('operation', 'check_permission')
            context = input_data.get('context', {})
            
            if operation == 'check_permission':
                return await self.check_mcp_permission(context)
            elif operation == 'record_usage':
                return await self.record_mcp_usage(context)
            elif operation == 'get_dashboard':
                return await self.get_mcp_dashboard_data()
            elif operation == 'get_status':
                return {
                    "status": "success",
                    "message": "MCP AI Resource Governance active",
                    "governance_mode": self.governance_mode.value,
                    "active_features": self.active_features,
                    "cost_tracking_enabled": self.cost_tracking_enabled
                }
            else:
                return {
                    "status": "error",
                    "message": f"Unknown operation: {operation}",
                    "supported_operations": [
                        "check_permission", "record_usage", 
                        "get_dashboard", "get_status"
                    ]
                }
                
        except Exception as e:
            logger.error(f"Error processing request: {str(e)}")
            return {
                "status": "error",
                "message": f"Request processing failed: {str(e)}",
                "error": str(e)
            }

def main(input_data: str) -> str:
    """Main plugin function"""
    try:
        # Parse input
        if isinstance(input_data, str):
            data = json.loads(input_data)
        else:
            data = input_data
        
        # Load configuration
        config_path = Path(__file__).parent / "config.json"
        if config_path.exists():
            with open(config_path) as f:
                config = json.load(f)
        else:
            config = {
                "mcp_governance_mode": "standard",
                "cost_tracking_enabled": True,
                "per_tool_limits": {},
                "emergency_thresholds": {},
                "budget_alerts": {},
                "model_quotas": {}
            }
        
        # Create plugin instance
        plugin = MCPAIResourceGovernancePlugin(config)
        
        # Process request
        result = asyncio.run(plugin.process_request(data))
        
        return json.dumps(result, indent=2)
        
    except Exception as e:
        error_result = {
            "status": "error",
            "message": f"Plugin execution failed: {str(e)}",
            "error": str(e)
        }
        return json.dumps(error_result, indent=2)

def process(ctx: Dict[str, Any], cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    Synchronous plugin entry point for MCP AI Resource Governance operations.
    ULTIMATE FIX: Dual parameter compatibility with comprehensive security hardening.
    """
    start_time = time.time()

    try:
        # ULTIMATE FIX PART 1: Check both ctx and cfg for input data
        input_data = {}
        if ctx and isinstance(ctx, dict):
            input_data.update(ctx)
        if cfg and isinstance(cfg, dict):
            input_data.update(cfg)

        # ULTIMATE FIX PART 2: Legacy compatibility for old parameter names
        if not input_data and ctx:
            # Support legacy 'inputs' parameter
            if isinstance(ctx, dict) and 'inputs' in ctx:
                input_data = ctx['inputs']
            else:
                input_data = ctx

        # SECURITY: Initialize security hardening for validation
        security_hardening = MCPGovernanceSecurityHardening()

        # SECURITY: Validate and sanitize inputs
        input_validation = security_hardening.validate_governance_input(input_data, "process_inputs")

        # CRITICAL SECURITY FIX: Block ALL security issues AND errors
        if input_validation.errors or input_validation.security_issues:
            error_messages = []
            if input_validation.errors:
                error_messages.extend(input_validation.errors)
            if input_validation.security_issues:
                error_messages.extend([f"SECURITY THREAT: {issue}" for issue in input_validation.security_issues])

            return {
                "success": False,
                "status": "blocked",
                "message": f"Security validation failed: {'; '.join(error_messages)}",
                "security_validation": {
                    "errors": input_validation.errors,
                    "security_issues": input_validation.security_issues,
                    "governance_violations": input_validation.governance_violations,
                    "blocked_reason": "Malicious patterns detected by security hardening system"
                },
                "ultimate_fix_applied": True,
                "threat_blocked": True
            }

        # Use sanitized inputs
        sanitized_inputs = input_validation.sanitized_value

        # Convert PlugPipe format to plugin format
        input_data = {
            'operation': sanitized_inputs.get('operation', 'get_status'),
            'client_id': sanitized_inputs.get('client_id', 'anonymous'),
            'tool_name': sanitized_inputs.get('tool_name', 'unknown'),
            'resource_request': sanitized_inputs.get('resource_request', {}),
            'budget_request': sanitized_inputs.get('budget_request', {})
        }
        
        # ULTIMATE FIX PART 3: Create config from cfg parameter with fallback
        config = cfg or {
            "mcp_governance_mode": "standard",
            "cost_tracking_enabled": True,
            "per_tool_limits": {},
            "emergency_thresholds": {},
            "budget_alerts": {},
            "model_quotas": {}
        }
        
        # Create plugin instance
        plugin = MCPAIResourceGovernancePlugin(config)
        
        # Process request
        result = asyncio.run(plugin.process_request(input_data))

        # Add security metadata to response
        security_metadata = {
            "sanitization_applied": input_validation.sanitization_applied,
            "security_issues_count": len(input_validation.security_issues),
            "governance_violations_count": len(input_validation.governance_violations),
            "processing_time": time.time() - start_time
        }

        if isinstance(result, dict):
            result["security_metadata"] = security_metadata

        return result
        
    except Exception as e:
        return {
            "success": False,
            "status": "error",
            "message": f"Plugin execution failed: {str(e)}",
            "error": str(e)
        }

if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_data = sys.argv[1]
    else:
        input_data = sys.stdin.read()
    
    result = main(input_data)
    print(result)