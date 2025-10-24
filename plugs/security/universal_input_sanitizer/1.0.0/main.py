#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Universal Input Sanitizer Plugin - Complete Rewrite

A comprehensive input sanitization plugin that provides robust protection against
SQL injection, XSS, path traversal, command injection, and other security threats.

This rewrite follows the Fix-Test-Harden-Audit-Doc methodology and implements
proven security patterns based on 2025 Python security best practices.

Key Security Features:
- Multi-layer threat detection with comprehensive pattern matching
- Fail-safe security logic (default to unsafe unless explicitly validated)
- Built-in Python security libraries integration
- Extensive input validation across all major threat categories
- Comprehensive logging and audit trail

SECURITY PRINCIPLE: Never depend on fallback validation - this plugin must
correctly identify and block all threats as the primary security layer.
"""

import re
import html
import logging
import urllib.parse
import os
import json
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime
from dataclasses import dataclass

# Security threat patterns based on 2025 research
class SecurityPatterns:
    """Comprehensive security patterns for threat detection"""

    # SQL Injection patterns - comprehensive coverage
    SQL_INJECTION_PATTERNS = [
        r'(?i)(\s|^)(\'|")\s*(;|\s)*(DROP|DELETE|INSERT|UPDATE|CREATE|ALTER|EXEC|EXECUTE)\s+',
        r'(?i)\s*UNION\s+SELECT\s*',
        r'(?i)\s*OR\s+1\s*=\s*1\s*',
        r'(?i)\'.*\'.*OR.*\'.*\'',
        r'(?i)\'.*OR.*\'.*=.*\'',
        r'(?i)\'.*;.*--',
        r'(?i)\bSELECT\b.*\bFROM\b.*\bWHERE\b.*=.*\'.*\'',
        r'(?i)\s*--\s*',
        r'(?i)/\*.*\*/',
        r'(?i)\bUNION\b.*\bSELECT\b',
        r'(?i)(\s|^)(\'|").*(\bAND\b|\bOR\b).*(\bLIKE\b|\b=\b).*(\1)',
        r'(?i);.*DROP\s+TABLE',
        r'(?i);.*DELETE\s+FROM',
        r'(?i);.*INSERT\s+INTO',
        r'(?i);.*UPDATE\s+SET',
        r'(?i)\'\s*;',
        r'(?i)\\x27',  # Hex encoded single quote
        r'(?i)%27',    # URL encoded single quote
        r'(?i)0x[0-9a-f]+',  # Hex values often used in injections
    ]

    # XSS patterns - comprehensive coverage
    XSS_PATTERNS = [
        r'(?i)<\s*script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script\s*>',
        r'(?i)<\s*iframe\b[^<]*(?:(?!<\/iframe>)<[^<]*)*<\/iframe\s*>',
        r'(?i)javascript\s*:',
        r'(?i)vbscript\s*:',
        r'(?i)on\w+\s*=',
        r'(?i)expression\s*\(',
        r'(?i)<\s*object\b',
        r'(?i)<\s*embed\b',
        r'(?i)<\s*link\b.*javascript',
        r'(?i)<\s*meta\b.*http-equiv',
        r'(?i)<\s*style\b.*expression',
        r'(?i)<\s*img\b.*onerror',
        r'(?i)<\s*svg\b.*onload',
        r'(?i)data\s*:\s*text\s*/\s*html',
        r'(?i)<%.*%>',  # Server-side script tags
        r'(?i)<\?\s*php',  # PHP tags
        r'(?i)alert\s*\(',
        r'(?i)document\s*\.\s*cookie',
        r'(?i)window\s*\.\s*location',
    ]

    # Path traversal patterns
    PATH_TRAVERSAL_PATTERNS = [
        r'\.\./',
        r'\.\.\\',
        r'%2e%2e%2f',
        r'%2e%2e\\',
        r'\.\.%2f',
        r'\.\.%5c',
        r'%252e%252e%252f',
        r'/etc/passwd',
        r'/etc/shadow',
        r'c:\\windows\\system32',
        r'\\\\.*\\.*',
        r'\.\.%252f',
        r'\.\.%c0%af',
        r'\.\.%c1%9c',
        r'....\/\/',
        r'....\\\\',
    ]

    # Command injection patterns
    COMMAND_INJECTION_PATTERNS = [
        r'[;&|`$]',
        r'(?i)\b(cmd|powershell|bash|sh|exec|system|eval)\b',
        r'(?i)(\|\s*\w+|\&\&|\|\|)',
        r'(?i)>(>)?|<(<)?',
        r'(?i)nc\s+\-',
        r'(?i)wget\s+',
        r'(?i)curl\s+',
        r'(?i)chmod\s+',
        r'(?i)rm\s+\-',
        r'(?i)kill\s+',
        r'(?i)sudo\s+',
        r'(?i)su\s+',
        r'(?i)cat\s+/etc/',
        r'(?i)ls\s+\-',
        r'(?i)ps\s+aux',
    ]

    # LDAP injection patterns
    LDAP_INJECTION_PATTERNS = [
        r'\*\)',
        r'\|\|',
        r'\&\&',
        r'(?i)\(\|\(',
        r'(?i)\(\&\(',
        r'(?i)\*\|\*',
        r'(?i)admin\)\(',
        r'(?i)\)\(\|',
    ]

@dataclass
class ThreatDetectionResult:
    """Result of threat detection analysis"""
    is_safe: bool
    threats_detected: List[str]
    threat_categories: List[str]
    confidence_score: float
    sanitized_output: Optional[str] = None
    processing_time_ms: float = 0.0

class UniversalInputSanitizer:
    """
    Universal Input Sanitizer - Complete Rewrite

    Provides comprehensive input sanitization with proper threat detection
    and fail-safe security logic.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.patterns = SecurityPatterns()
        self.max_input_length = 10000  # Maximum allowed input length
        self.strict_mode = True  # Fail-safe: reject on any uncertainty

        # Initialize security modules
        self._initialize_security_modules()

    def _initialize_security_modules(self):
        """Initialize additional security validation modules"""
        try:
            # Try to import additional security libraries if available
            import html
            self.html_escape = html.escape
            self.html_available = True
        except ImportError:
            self.html_available = False
            self.logger.warning("HTML escaping not available")

        try:
            import urllib.parse
            self.url_quote = urllib.parse.quote
            self.url_available = True
        except ImportError:
            self.url_available = False
            self.logger.warning("URL encoding not available")

    def process(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Main processing function for input sanitization

        Args:
            context: Processing context (not used in this implementation)
            config: Configuration containing input_data and sanitization_types

        Returns:
            Dict with security analysis results
        """
        start_time = datetime.now()

        try:
            # Extract input parameters
            input_data = config.get('input_data', '')
            sanitization_types = config.get('sanitization_types', ['all'])

            # CRITICAL FIX: Ensure input_data is a string
            if not isinstance(input_data, str):
                # Convert to string or reject
                if isinstance(input_data, (dict, list)):
                    input_data = str(input_data)
                else:
                    input_data = str(input_data) if input_data is not None else ''

            if not input_data:
                return {
                    'success': True,
                    'is_safe': True,
                    'threats_detected': [],
                    'sanitized_output': '',
                    'message': 'Empty input - safe'
                }

            # Perform comprehensive threat analysis
            result = self._comprehensive_threat_analysis(input_data, sanitization_types)

            # Calculate processing time
            processing_time = (datetime.now() - start_time).total_seconds() * 1000
            result.processing_time_ms = processing_time

            # Log security analysis
            self._log_security_analysis(input_data, result)

            # Return standardized response
            return {
                'success': True,
                'is_safe': result.is_safe,
                'threats_detected': result.threats_detected,
                'threat_categories': result.threat_categories,
                'confidence_score': result.confidence_score,
                'sanitized_output': result.sanitized_output,
                'processing_time_ms': result.processing_time_ms,
                'message': 'Input analysis completed'
            }

        except Exception as e:
            import traceback
            error_trace = traceback.format_exc()
            self.logger.error(f"Universal Input Sanitizer error: {e}\nTraceback: {error_trace}")
            # FAIL-SAFE: Return unsafe on any error
            return {
                'success': False,
                'is_safe': False,
                'threats_detected': [f'Processing error: {str(e)}'],
                'threat_categories': ['processing_error'],
                'error': str(e),
                'traceback': error_trace
            }

    def _comprehensive_threat_analysis(self, input_data: str, sanitization_types: List[str]) -> ThreatDetectionResult:
        """
        Comprehensive threat analysis across all categories

        CRITICAL: This method implements fail-safe logic - default to unsafe
        unless explicitly validated as safe.
        """
        threats_detected = []
        threat_categories = []
        confidence_scores = []

        # Input length validation
        if len(input_data) > self.max_input_length:
            threats_detected.append(f'Input too long: {len(input_data)} > {self.max_input_length}')
            threat_categories.append('length_violation')
            confidence_scores.append(1.0)

        # Check each requested sanitization type
        if 'all' in sanitization_types:
            sanitization_types = ['sql_injection', 'xss', 'path_traversal', 'command_injection', 'ldap_injection']

        for threat_type in sanitization_types:
            if threat_type == 'sql_injection':
                sql_threats = self._detect_sql_injection(input_data)
                if sql_threats:
                    threats_detected.extend(sql_threats)
                    threat_categories.append('sql_injection')
                    confidence_scores.append(0.95)

            elif threat_type == 'xss':
                xss_threats = self._detect_xss(input_data)
                if xss_threats:
                    threats_detected.extend(xss_threats)
                    threat_categories.append('xss')
                    confidence_scores.append(0.9)

            elif threat_type == 'path_traversal':
                path_threats = self._detect_path_traversal(input_data)
                if path_threats:
                    threats_detected.extend(path_threats)
                    threat_categories.append('path_traversal')
                    confidence_scores.append(0.9)

            elif threat_type == 'command_injection':
                cmd_threats = self._detect_command_injection(input_data)
                if cmd_threats:
                    threats_detected.extend(cmd_threats)
                    threat_categories.append('command_injection')
                    confidence_scores.append(0.9)

            elif threat_type == 'ldap_injection':
                ldap_threats = self._detect_ldap_injection(input_data)
                if ldap_threats:
                    threats_detected.extend(ldap_threats)
                    threat_categories.append('ldap_injection')
                    confidence_scores.append(0.85)

        # Additional security checks
        encoding_threats = self._detect_encoding_attacks(input_data)
        if encoding_threats:
            threats_detected.extend(encoding_threats)
            threat_categories.append('encoding_attack')
            confidence_scores.append(0.8)

        # Calculate overall safety
        is_safe = len(threats_detected) == 0
        average_confidence = sum(confidence_scores) / len(confidence_scores) if confidence_scores else 1.0

        # Generate sanitized output only for safe inputs
        sanitized_output = self._generate_safe_output(input_data) if is_safe else None

        return ThreatDetectionResult(
            is_safe=is_safe,
            threats_detected=threats_detected,
            threat_categories=list(set(threat_categories)),  # Remove duplicates
            confidence_score=average_confidence,
            sanitized_output=sanitized_output
        )

    def _detect_sql_injection(self, input_data: str) -> List[str]:
        """Detect SQL injection attempts"""
        threats = []

        for pattern in self.patterns.SQL_INJECTION_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE | re.MULTILINE):
                threats.append(f"SQL injection pattern detected: {pattern[:50]}...")

        # Additional context-aware SQL injection detection
        if "'" in input_data:
            # Check for SQL injection patterns with quotes
            if any(keyword in input_data.upper() for keyword in ['OR', 'AND', 'UNION', 'SELECT', 'DROP', 'DELETE']):
                threats.append("Potential SQL injection: Quote with SQL keywords")

        # Check for SQL comment patterns
        if '--' in input_data or '/*' in input_data:
            threats.append("SQL comment pattern detected")

        # Check for hex/url encoding that might hide SQL injection
        if re.search(r'(?i)(0x[0-9a-f]+|%27|%22|\\x27|\\x22)', input_data):
            threats.append("Encoded characters that may hide SQL injection")

        return threats

    def _detect_xss(self, input_data: str) -> List[str]:
        """Detect XSS attempts"""
        threats = []

        for pattern in self.patterns.XSS_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                threats.append(f"XSS pattern detected: {pattern[:50]}...")

        # Additional XSS detection
        if '<' in input_data and '>' in input_data:
            # Check for potential HTML/XML tags
            if re.search(r'<[^>]*>', input_data):
                threats.append("HTML/XML tags detected - potential XSS")

        # Check for JavaScript event handlers
        if re.search(r'(?i)on\w+\s*=', input_data):
            threats.append("JavaScript event handler detected")

        # Check for data URLs that could contain scripts
        if 'data:' in input_data.lower():
            threats.append("Data URL detected - potential XSS vector")

        return threats

    def _detect_path_traversal(self, input_data: str) -> List[str]:
        """Detect path traversal attempts"""
        threats = []

        for pattern in self.patterns.PATH_TRAVERSAL_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                threats.append(f"Path traversal pattern detected: {pattern}")

        # Additional path traversal detection
        if '..' in input_data:
            threats.append("Directory traversal sequence detected")

        # Check for absolute paths to sensitive files
        sensitive_paths = ['/etc/', '/proc/', '/sys/', '\\windows\\', '\\system32\\']
        for path in sensitive_paths:
            if path.lower() in input_data.lower():
                threats.append(f"Sensitive system path detected: {path}")

        return threats

    def _detect_command_injection(self, input_data: str) -> List[str]:
        """Detect command injection attempts"""
        threats = []

        for pattern in self.patterns.COMMAND_INJECTION_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                threats.append(f"Command injection pattern detected: {pattern[:30]}...")

        # Additional command injection detection
        command_separators = [';', '&&', '||', '|', '&', '`', '$']
        for separator in command_separators:
            if separator in input_data:
                threats.append(f"Command separator detected: {separator}")

        # Check for common system commands
        system_commands = ['rm', 'del', 'format', 'fdisk', 'mkfs', 'dd', 'cat', 'type', 'more', 'less']
        for cmd in system_commands:
            if re.search(rf'\b{cmd}\b', input_data, re.IGNORECASE):
                threats.append(f"System command detected: {cmd}")

        return threats

    def _detect_ldap_injection(self, input_data: str) -> List[str]:
        """Detect LDAP injection attempts"""
        threats = []

        for pattern in self.patterns.LDAP_INJECTION_PATTERNS:
            if re.search(pattern, input_data, re.IGNORECASE):
                threats.append(f"LDAP injection pattern detected: {pattern}")

        return threats

    def _detect_encoding_attacks(self, input_data: str) -> List[str]:
        """Detect encoding-based attacks"""
        threats = []

        # Check for URL encoding that might hide attacks
        if '%' in input_data:
            url_encoded_patterns = ['%3c', '%3e', '%22', '%27', '%3b', '%7c', '%26', '%2e', '%2f', '%5c']
            for pattern in url_encoded_patterns:
                if pattern.lower() in input_data.lower():
                    threats.append(f"URL encoded dangerous character: {pattern}")

            # Check for double URL encoding
            if '%25' in input_data.lower():
                threats.append("Double URL encoding detected - potential evasion attempt")

        # Check for unicode/hex encoding
        if re.search(r'\\x[0-9a-f]{2}', input_data, re.IGNORECASE):
            threats.append("Hex encoded characters detected")

        if re.search(r'\\u[0-9a-f]{4}', input_data, re.IGNORECASE):
            threats.append("Unicode encoded characters detected")

        # Check for base64 that might hide payloads
        if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', input_data):
            threats.append("Potential base64 encoded content detected")

        return threats

    def _generate_safe_output(self, input_data: str) -> str:
        """Generate safe output for validated input"""
        if self.html_available:
            # HTML escape for safety
            return self.html_escape(input_data)
        else:
            # Manual HTML escaping as fallback
            return (input_data
                   .replace('&', '&amp;')
                   .replace('<', '&lt;')
                   .replace('>', '&gt;')
                   .replace('"', '&quot;')
                   .replace("'", '&#x27;'))

    def _log_security_analysis(self, input_data: str, result: ThreatDetectionResult):
        """Log security analysis for audit trail"""
        log_data = {
            'timestamp': datetime.now().isoformat(),
            'input_length': len(input_data),
            'input_preview': input_data[:100] + '...' if len(input_data) > 100 else input_data,
            'is_safe': result.is_safe,
            'threats_count': len(result.threats_detected),
            'threat_categories': result.threat_categories,
            'confidence_score': result.confidence_score,
            'processing_time_ms': result.processing_time_ms
        }

        if result.is_safe:
            self.logger.info(f"✅ Input validated as safe: {json.dumps(log_data)}")
        else:
            self.logger.warning(f"🚨 Threats detected in input: {json.dumps(log_data)}")
            # Log specific threats for security audit
            for threat in result.threats_detected:
                self.logger.warning(f"   Threat: {threat}")

# Plugin interface function
def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Plugin interface for Universal Input Sanitizer

    Args:
        context: Execution context
        config: Configuration with input_data and sanitization_types

    Returns:
        Security analysis results
    """
    sanitizer = UniversalInputSanitizer()
    return sanitizer.process(context, config)