# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Echo Plugin - Enterprise-Grade Security Hardened Version
Universal text echoing with comprehensive input validation and sanitization.

Security Features:
- Universal Input Sanitizer integration
- Input size limits and validation
- Content type validation
- Character encoding validation
- XSS prevention for web contexts
- Command injection prevention
- Path traversal prevention
"""

import re
import time
from datetime import datetime
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from shares.loader import pp

@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_violations: List[str] = field(default_factory=list)
    sanitized_data: Optional[str] = None

class EchoSecurityHardening:
    """Security hardening for echo plugin operations"""

    def __init__(self):
        # Maximum input size (1MB for text content)
        self.max_input_size = 1024 * 1024

        # Dangerous patterns for security validation
        self.dangerous_patterns = [
            r'<script[^>]*>',
            r'javascript:',
            r'vbscript:',
            r'data:',
            r'onload\s*=',
            r'onerror\s*=',
            r'onclick\s*=',
            r'eval\s*\(',
            r'exec\s*\(',
            r'\.\.[\\/]',
            r'[\\/]\.\.[\\/]',
            r'\$\{.*\}',
            r'`.*`',
            r'system\s*\(',
            r'os\.system',
            r'subprocess\.',
            r'import\s+os',
            r'__import__',
            r'getattr\s*\(',
            r'setattr\s*\(',
            r'hasattr\s*\(',
            r'globals\s*\(',
            r'locals\s*\(',
            r'vars\s*\(',
            r'dir\s*\(',
            r'help\s*\(',
            r'input\s*\(',
            r'raw_input\s*\(',
            r'file\s*\(',
            r'open\s*\(',
            # URL encoded patterns
            r'%2e%2e%2f',  # ../
            r'%2e%2e%5c',  # ..\
            r'%252f',      # double encoded /
            r'%252e',      # double encoded .
            # HTML entity encoded patterns
            r'&colon;',    # :
            r'&#97;',      # 'a' in javascript
            r'&#106;',     # 'j' in javascript
            r'&#115;',     # 's' in javascript
        ]

        # Compile patterns for performance
        self.dangerous_regex = re.compile('|'.join(self.dangerous_patterns), re.IGNORECASE)

        # Safe character pattern (printable ASCII + common Unicode)
        self.safe_char_pattern = re.compile(r'^[\x20-\x7E\u00A0-\uFFFF\s]*$')

        # Initialize Universal Input Sanitizer
        self.sanitizer = None
        try:
            self.sanitizer = pp("universal_input_sanitizer")
        except Exception:
            pass  # Fallback to manual validation if sanitizer unavailable

    def validate_input_data(self, data: Any) -> ValidationResult:
        """Validate input data with comprehensive security checks"""
        result = ValidationResult(is_valid=True)

        try:
            # Convert to string for validation
            if data is None:
                data_str = ""
            elif isinstance(data, str):
                data_str = data
            elif isinstance(data, (int, float, bool)):
                data_str = str(data)
            elif isinstance(data, (list, dict)):
                data_str = str(data)
            else:
                data_str = str(data)

            # Size validation
            if len(data_str) > self.max_input_size:
                result.is_valid = False
                result.errors.append(f"Input size {len(data_str)} exceeds maximum {self.max_input_size}")
                return result

            # Character encoding validation
            if not self.safe_char_pattern.match(data_str):
                result.warnings.append("Input contains potentially unsafe characters")

            # Pattern-based security validation
            if self.dangerous_regex.search(data_str):
                result.security_violations.append("Input contains potentially dangerous patterns")
                result.warnings.append("Security patterns detected in input")

            # Universal Input Sanitizer validation (if available)
            sanitizer_success = False
            if self.sanitizer:
                try:
                    sanitizer_result = self.sanitizer.process({}, {
                        "input_data": data_str,
                        "sanitization_types": ["sql_injection", "xss", "path_traversal", "command_injection"]
                    })

                    # Check if sanitizer found threats FIRST (new interface)
                    if not sanitizer_result.get("is_safe", False):
                        result.security_violations.extend(sanitizer_result.get("threats_detected", []))
                        result.warnings.append("Universal Input Sanitizer detected security issues")
                        result.sanitized_data = self._fallback_sanitize(data_str)
                    elif sanitizer_result.get("is_safe", False) and sanitizer_result.get("success", False):
                        # Use sanitized data if available and input is safe
                        result.sanitized_data = sanitizer_result.get("sanitized_output", data_str)
                        sanitizer_success = True
                    else:
                        # If result is unclear, use fallback
                        result.sanitized_data = self._fallback_sanitize(data_str)

                except Exception as e:
                    result.warnings.append(f"Universal Input Sanitizer validation failed: {str(e)}")
                    result.sanitized_data = self._fallback_sanitize(data_str)

            # Apply fallback sanitization if sanitizer unavailable OR dangerous patterns detected
            if not sanitizer_success or result.security_violations:
                result.sanitized_data = self._fallback_sanitize(data_str)

            return result

        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Input validation failed: {str(e)}")
            return result

    def _fallback_sanitize(self, data: str) -> str:
        """Fallback sanitization when Universal Input Sanitizer unavailable"""
        # Basic HTML escaping
        data = data.replace('&', '&amp;')
        data = data.replace('<', '&lt;')
        data = data.replace('>', '&gt;')
        data = data.replace('"', '&quot;')
        data = data.replace("'", '&#x27;')

        # Path traversal sanitization
        data = data.replace('../', '[PATH_TRAVERSAL]')
        data = data.replace('..\\', '[PATH_TRAVERSAL]')
        data = data.replace('..%2f', '[PATH_TRAVERSAL]')
        data = data.replace('..%5c', '[PATH_TRAVERSAL]')

        # URL encoded path traversal
        data = data.replace('%2e%2e%2f', '[ENCODED_PATH_TRAVERSAL]')
        data = data.replace('%2e%2e%5c', '[ENCODED_PATH_TRAVERSAL]')
        data = data.replace('%252f', '[DOUBLE_ENCODED_SLASH]')
        data = data.replace('%252e', '[DOUBLE_ENCODED_DOT]')

        # JavaScript scheme sanitization
        data = data.replace('javascript:', '[JS_SCHEME]')
        data = data.replace('vbscript:', '[VBS_SCHEME]')
        data = data.replace('data:', '[DATA_SCHEME]')

        # HTML entity encoded schemes
        data = data.replace('&colon;', '[ENCODED_COLON]')
        data = data.replace('javascript&colon;', '[ENCODED_JS_SCHEME]')
        data = data.replace('&#97;', '[ENCODED_A]')
        data = data.replace('&#106;', '[ENCODED_J]')
        data = data.replace('&#115;', '[ENCODED_S]')

        # SQL injection patterns
        data = data.replace('UNION SELECT', '[SQL_UNION]')
        data = data.replace('union select', '[SQL_UNION]')
        data = data.replace('DROP TABLE', '[SQL_DROP]')
        data = data.replace('drop table', '[SQL_DROP]')
        data = data.replace('DELETE FROM', '[SQL_DELETE]')
        data = data.replace('delete from', '[SQL_DELETE]')
        data = data.replace('INSERT INTO', '[SQL_INSERT]')
        data = data.replace('insert into', '[SQL_INSERT]')

        # Command injection patterns
        data = data.replace(';', '[SEMICOLON]')
        data = data.replace('|', '[PIPE]')
        data = data.replace('&', '[AMPERSAND]')
        data = data.replace('`', '[BACKTICK]')
        data = data.replace('$(', '[CMD_SUB]')
        data = data.replace('${', '[VAR_SUB]')

        # Remove null bytes and control characters
        data = ''.join(char for char in data if ord(char) >= 32 or char in '\t\n\r')

        return data

def process(ctx, cfg):
    """
    Process echo request with enterprise security hardening.

    Args:
        ctx: Plugin context containing input data
        cfg: Plugin configuration

    Returns:
        Dict containing echoed data with security metadata
    """
    start_time = time.time()
    security_hardening = EchoSecurityHardening()

    try:
        # Extract input data with fallback chain
        if isinstance(ctx, dict):
            val = ctx.get("with") or ctx.get("input") or ctx.get("inputs") or ctx

            if isinstance(val, dict):
                data = val.get("data")
                if data is None and val:
                    # Get first value from dict if no 'data' key
                    data = list(val.values())[0] if val.values() else ""
            else:
                data = val
        else:
            # Handle direct string/primitive input
            data = ctx

        # Validate and sanitize input
        validation_result = security_hardening.validate_input_data(data)

        if not validation_result.is_valid:
            error_message = validation_result.errors[0] if validation_result.errors else "Input validation failed"
            return {
                "success": False,
                "error": error_message,
                "validation_errors": validation_result.errors,
                "echoed": "",
                "metadata": {
                    "validation_failed": True,
                    "security_violations": validation_result.security_violations,
                    "timestamp": datetime.now().isoformat(),
                    "execution_time_ms": round((time.time() - start_time) * 1000, 2)
                }
            }

        # Use sanitized data
        sanitized_data = validation_result.sanitized_data or ""

        # Build response with security metadata
        response = {
            "success": True,
            "echoed": sanitized_data,
            "metadata": {
                "input_length": len(str(data)) if data is not None else 0,
                "output_length": len(sanitized_data),
                "timestamp": datetime.now().isoformat(),
                "execution_time_ms": round((time.time() - start_time) * 1000, 2),
                "validation_passed": True,
                "security_hardened": True
            }
        }

        # Add security warnings if any
        if validation_result.warnings:
            response["metadata"]["security_warnings"] = validation_result.warnings

        if validation_result.security_violations:
            response["metadata"]["security_violations"] = validation_result.security_violations

        # Add configuration metadata if enabled
        if cfg and isinstance(cfg, dict):
            if cfg.get("add_metadata", True):
                response["metadata"]["config_applied"] = True

            if cfg.get("add_timestamp", False):
                response["timestamp"] = datetime.now().isoformat()

            if cfg.get("prefix"):
                response["echoed"] = cfg["prefix"] + response["echoed"]

            if cfg.get("suffix"):
                response["echoed"] = response["echoed"] + cfg["suffix"]

        return response

    except Exception as e:
        return {
            "success": False,
            "error": f"Echo processing failed: {str(e)}",
            "echoed": "",
            "metadata": {
                "exception_occurred": True,
                "timestamp": datetime.now().isoformat(),
                "execution_time_ms": round((time.time() - start_time) * 1000, 2)
            }
        }
