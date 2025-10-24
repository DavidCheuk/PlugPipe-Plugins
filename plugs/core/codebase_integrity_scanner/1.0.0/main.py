#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enhanced Codebase Integrity Scanner Plugin - Enterprise Security Hardened

A comprehensive AI-powered agent that constantly scans the PlugPipe codebase to ensure:
1. No stubs, placeholders, or TODO items remain in production code
2. All claimed functionality is actually implemented and tested
3. All plugins have complete code, tests, SBOM, and documentation
4. AI-generated code is verified for correctness and functionality
5. Registry integrity and consistency
6. Security implementation completeness across all language wrappers
7. Functional verification through automated testing
8. Code quality analysis and architectural compliance

This plugin embodies "no fluffer lips" - everything must be concrete as claimed.
Enhanced with AI detection, functional verification, and Universal Input Sanitizer integration
for enterprise-grade security validation of all scan configurations and user inputs.
"""

import os
import re
import ast
import json
import yaml
import asyncio
import logging
import hashlib
import inspect
import importlib.util
import statistics
from typing import Dict, List, Any, Optional, Tuple, Set, Callable
from datetime import datetime, timezone
from pathlib import Path
from dataclasses import dataclass, asdict, field
from collections import defaultdict
import subprocess
import tempfile
import sys
import time
import threading

# Add PlugPipe core path for pp() function access
from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
from shares.loader import pp

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Security validation result for codebase scanner operations"""
    is_valid: bool
    sanitized_value: Any
    errors: List[str] = field(default_factory=list)
    security_issues: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    scan_violations: List[str] = field(default_factory=list)
    sanitization_applied: bool = False

class CodebaseScannerSecurityHardening:
    """Security hardening for Codebase Integrity Scanner operations"""

    def __init__(self):
        # Maximum input sizes for resource protection
        self.max_config_size = 50 * 1024  # 50KB for scan configuration
        self.max_string_length = 5000
        self.max_list_items = 500
        self.max_dict_keys = 50

        # Codebase Scanner-specific dangerous patterns
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
            r'document\.',
            r'window\.',
            r'location\.',

            # Enhanced Code execution patterns
            r'eval\s*\(',
            r'exec\s*\(',
            r'execfile\s*\(',
            r'compile\s*\(',
            r'__import__\s*\(',
            r'subprocess\.',
            r'os\.system',
            r'os\.popen',
            r'os\.spawn',
            r'commands\.',

            # Enhanced Serialization patterns
            r'pickle\.loads',
            r'marshal\.loads',
            r'yaml\.load\s*\(',
            r'yaml\.unsafe_load',

            # Enhanced Scanner bypass patterns
            r'BYPASS\s+SCAN',
            r'DISABLE\s+SCANNER',
            r'SKIP\s+VALIDATION',
            r'IGNORE\s+CHECKS',
            r'SCANNER\s+OFF',
            r'NO\s+SCAN',
            r'SCAN\s+BYPASS',
            r'UNLIMITED\s+SCAN',
            r'DISABLE\s+INTEGRITY',
            r'BYPASS\s+INTEGRITY',

            # Enhanced File system patterns
            r';\s*find\s+/',
            r';\s*locate\s+',
            r';\s*grep\s+-r',
            r'file://',
            r'ftp://',
            r'sftp://',

            # Enhanced Resource exhaustion patterns
            r';\s*shutdown',
            r';\s*reboot',
            r'>&\s*/dev/null',
            r'2>&1',
            r'/dev/tcp/',
            r'mkfifo',
        ]

        # Valid scan operations (whitelist)
        self.valid_scan_types = {
            "full", "quick", "security", "placeholders", "plugins",
            "integrity", "quality", "functional", "ai_detection"
        }

        # Valid severity levels (whitelist)
        self.valid_severity_levels = {"low", "medium", "high", "critical"}

        # Valid output formats (whitelist)
        self.valid_output_formats = {"detailed", "summary", "json", "csv", "xml"}

        # Valid scan paths (secure whitelist)
        self.valid_scan_base_paths = {
            get_plugpipe_root(),
            "/tmp/plugpipe_test",
            "/tmp/scanner_test"
        }

        # Compile patterns for performance
        self.dangerous_regex = re.compile('|'.join(self.dangerous_patterns), re.IGNORECASE)

        # Initialize Universal Input Sanitizer
        self.sanitizer = None
        try:
            self.sanitizer = pp("universal_input_sanitizer")
        except Exception:
            pass  # Fallback to manual validation if sanitizer unavailable

    def validate_scanner_input(self, data: Any, context: str = "general") -> ValidationResult:
        """Validate codebase scanner input with comprehensive security checks"""
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
                result.security_issues.append("Dangerous patterns detected in scanner input")
                result.warnings.append("Security patterns detected in scanner configuration")

            # Universal Input Sanitizer validation (if available)
            sanitizer_success = False
            if self.sanitizer:
                try:
                    sanitizer_result = self.sanitizer.process({}, {
                        "operation": "validate_and_sanitize",
                        "input_data": data,
                        "validation_mode": "strict",
                        "context": f"scanner_{context}"
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
                            if dangerous_pattern_found and "Dangerous patterns detected in scanner input" not in result.security_issues:
                                result.security_issues.append("Dangerous patterns detected in scanner input")
                        else:
                            result.sanitized_value = self._fallback_sanitize_scanner(data)
                            result.sanitization_applied = True
                    else:
                        result.sanitized_value = self._fallback_sanitize_scanner(data)
                        result.sanitization_applied = True

                except Exception as e:
                    result.warnings.append(f"Universal Input Sanitizer validation failed: {str(e)}")
                    result.sanitized_value = self._fallback_sanitize_scanner(data)
                    result.sanitization_applied = True

            # Apply fallback sanitization if sanitizer unavailable OR security issues detected
            if not sanitizer_success or result.security_issues:
                result.sanitized_value = self._fallback_sanitize_scanner(data)
                result.sanitization_applied = True

            # Scanner-specific validation
            scanner_result = self._validate_scanner_context(result.sanitized_value, context)
            result.scan_violations.extend(scanner_result.get("violations", []))
            if scanner_result.get("violations"):
                result.warnings.extend(scanner_result.get("violations", []))

            # Final security validation - ensure dangerous patterns are flagged
            if dangerous_pattern_found:
                result.security_issues = ["Dangerous patterns detected in scanner input"]

                # Add pattern-specific details
                original_str = str(data) if data is not None else ""
                for i, pattern in enumerate(self.dangerous_patterns):
                    if re.search(pattern, original_str, re.IGNORECASE):
                        result.security_issues.append(f"Matched dangerous patterns: Pattern {i+1}")
                        break

            return result

        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Scanner input validation failed: {str(e)}")

            # Emergency security check even on exception
            try:
                data_str = str(data) if data is not None else ""
                if self.dangerous_regex.search(data_str):
                    result.security_issues = ["EXCEPTION: Dangerous patterns detected in scanner input"]
            except:
                pass

            return result

    def _fallback_sanitize_scanner(self, data: Any) -> Any:
        """Fallback sanitization for scanner data when Universal Input Sanitizer unavailable"""
        if isinstance(data, str):
            # Remove dangerous patterns
            sanitized = data
            for pattern in self.dangerous_patterns:
                sanitized = re.sub(pattern, '[SANITIZED]', sanitized, flags=re.IGNORECASE)

            # Limit string length
            if len(sanitized) > self.max_string_length:
                sanitized = sanitized[:self.max_string_length] + "...[TRUNCATED]"

            return sanitized

        elif isinstance(data, dict):
            # Sanitize dictionary values and limit keys
            sanitized_dict = {}
            key_count = 0
            for key, value in data.items():
                if key_count >= self.max_dict_keys:
                    break
                if isinstance(key, str) and len(key) < 100:  # Reasonable key length
                    safe_key = re.sub(r'[^\w\-_.]', '', str(key))[:50]
                    sanitized_dict[safe_key] = self._fallback_sanitize_scanner(value)
                    key_count += 1
            return sanitized_dict

        elif isinstance(data, list):
            # Sanitize list items and limit length
            return [self._fallback_sanitize_scanner(item) for item in data[:self.max_list_items]]

        else:
            return data

    def _validate_scanner_context(self, data: Any, context: str) -> Dict[str, Any]:
        """Validate scanner-specific contexts and constraints"""
        violations = []

        if isinstance(data, dict):
            # Validate scan_type
            scan_type = data.get("scan_type")
            if scan_type and scan_type not in self.valid_scan_types:
                violations.append(f"Invalid scan_type: {scan_type}")

            # Validate severity_threshold
            severity = data.get("severity_threshold")
            if severity and severity not in self.valid_severity_levels:
                violations.append(f"Invalid severity_threshold: {severity}")

            # Validate output_format
            output_format = data.get("output_format")
            if output_format and output_format not in self.valid_output_formats:
                violations.append(f"Invalid output_format: {output_format}")

            # Validate base_path security
            base_path = data.get("base_path")
            if base_path:
                path_str = str(base_path)
                if not any(path_str.startswith(valid_path) for valid_path in self.valid_scan_base_paths):
                    violations.append(f"Invalid base_path: {base_path} - must be within allowed directories")

            # Validate target_paths
            target_paths = data.get("target_paths", [])
            if isinstance(target_paths, list):
                for path in target_paths:
                    if isinstance(path, str) and (len(path) > 500 or '..' in path):
                        violations.append(f"Invalid target_path: {path}")

            # Validate exclude_patterns
            exclude_patterns = data.get("exclude_patterns", [])
            if isinstance(exclude_patterns, list) and len(exclude_patterns) > 100:
                violations.append("Too many exclude_patterns specified")

        return {"violations": violations}

@dataclass
class IntegrityIssue:
    """Represents a codebase integrity issue."""
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    category: str  # PLACEHOLDER, MISSING_IMPL, INCOMPLETE, SECURITY, REGISTRY, AI_GENERATED, FUNCTIONAL, QUALITY
    file_path: str
    line_number: Optional[int]
    description: str
    suggestion: str
    context: Dict[str, Any]
    ai_confidence: Optional[float] = None  # For AI-generated code detection
    functional_test_result: Optional[bool] = None  # For functional verification
    quality_score: Optional[int] = None  # Code quality score 0-100


@dataclass
class ScanResult:
    """Complete scan results with enhanced AI and functional analysis."""
    scan_timestamp: str
    total_files_scanned: int
    issues_found: List[IntegrityIssue]
    integrity_score: int  # 0-100
    critical_issues: int
    high_issues: int
    medium_issues: int
    low_issues: int
    recommendations: List[str]
    ai_generated_files_detected: int = 0
    functional_tests_run: int = 0
    functional_tests_passed: int = 0
    plugins_verified: int = 0
    code_quality_average: float = 0.0
    performance_metrics: Dict[str, float] = field(default_factory=dict)


class CodebaseIntegrityScanner:
    """
    Comprehensive codebase integrity scanner that ensures production readiness.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.base_path = config.get('base_path', get_plugpipe_root())
        self.exclusions = config.get('exclusions', ['.venv', '__pycache__', '.git', 'node_modules'])
        
        # Enhanced AI detection enabled by default
        self.ai_detection_enabled = config.get('ai_detection_enabled', True)
        self.functional_testing_enabled = config.get('functional_testing_enabled', True)
        self.quality_analysis_enabled = config.get('quality_analysis_enabled', True)
        
        self.placeholder_patterns = [
            r'TODO',
            r'FIXME', 
            r'HACK',
            r'XXX',
            r'NotImplemented',
            r'raise NotImplementedError',
            r'pass\s*#.*TODO',
            r'pass\s*#.*FIXME',
            r'pass\s*$',  # Bare pass statements
            r'\.\.\.', # Ellipsis placeholders
            r'# stub',
            r'# placeholder',
            r'# not implemented',
            r'def.*:\s*pass\s*$',  # Empty function definitions
            r'class.*:\s*pass\s*$'  # Empty class definitions
        ]
        
        # AI-generated code patterns
        self.ai_generated_patterns = [
            r'# Generated by.*AI',
            r'# AI-generated',
            r'# Auto-generated',
            r'Generated with.*Claude',
            r'🤖.*Generated',
            r'This code was generated',
            r'# GPT.*generated',
            r'# ChatGPT.*generated',
            r'# Anthropic.*Claude',
            # Common AI coding patterns
            r'"""\s*[A-Z][^"]*\.\s*"""',  # AI-style docstrings
            r'try:\s*import.*except.*as.*:',  # AI-style graceful imports
            r'from typing import.*Union\[.*\]',  # AI-style complex typing
            # Revolutionary/marketing language patterns
            r'REVOLUTIONARY',
            r'FIRST.*TO.*MARKET',
            r'NO COMPETITOR',
            r'WORLD.*FIRST',
            r'BREAKTHROUGH',
            r'✅.*capabilities',
            r'🚀.*features'
        ]
        
        # Registry integrity patterns
        self.registry_issues = [
            r'yaml_dir.*\.yaml',  # YAML file usage in registry
            r'registry.*backend.*yaml'
        ]
        
        # Security gaps patterns
        self.security_gaps = [
            r'# TODO.*security',
            r'# FIXME.*security',
            r'without.*security',
            r'no.*security',
            r'bypass.*security'
        ]
        
        # Performance tracking
        self.scan_start_time = None
        self.files_processed = 0
        self.ai_files_detected = 0
        self.functional_tests_executed = 0
        self.functional_tests_passed = 0
        
        # Plugin testing framework integration
        sys.path.insert(0, self.base_path) if self.base_path not in sys.path else None

    async def scan_codebase(self) -> ScanResult:
        """Perform comprehensive codebase integrity scan with AI detection and functional verification."""
        logger.info("Starting comprehensive enhanced codebase integrity scan")
        print(f"🔍 DEBUG: Starting scan of {self.base_path}")
        
        self.scan_start_time = time.time()
        issues = []
        total_files = 0
        
        # Scan Python files
        print("🐍 DEBUG: Starting Python files scan...")
        python_issues, python_files = await self._scan_python_files()
        print(f"🐍 DEBUG: Python scan complete - {python_files} files, {len(python_issues)} issues")
        issues.extend(python_issues)
        total_files += python_files
        
        # Scan YAML/JSON configuration files
        config_issues, config_files = await self._scan_config_files()
        issues.extend(config_issues)
        total_files += config_files
        
        # Scan plugin completeness
        plugin_issues = await self._scan_plugin_completeness()
        issues.extend(plugin_issues)
        
        # Scan registry integrity
        registry_issues = await self._scan_registry_integrity()
        issues.extend(registry_issues)
        
        # Scan security implementation completeness
        security_issues = await self._scan_security_completeness()
        issues.extend(security_issues)
        
        # Scan documentation consistency
        doc_issues = await self._scan_documentation_consistency()
        issues.extend(doc_issues)
        
        # Enhanced AI-generated code detection
        if self.ai_detection_enabled:
            ai_issues = await self._scan_ai_generated_code()
            issues.extend(ai_issues)
        
        # Functional verification of plugins
        if self.functional_testing_enabled:
            functional_issues = await self._verify_plugin_functionality()
            issues.extend(functional_issues)
        
        # Code quality analysis
        if self.quality_analysis_enabled:
            quality_issues = await self._analyze_code_quality()
            issues.extend(quality_issues)
        
        # Calculate metrics
        critical_issues = len([i for i in issues if i.severity == 'CRITICAL'])
        high_issues = len([i for i in issues if i.severity == 'HIGH'])
        medium_issues = len([i for i in issues if i.severity == 'MEDIUM'])
        low_issues = len([i for i in issues if i.severity == 'LOW'])
        
        # Calculate integrity score (0-100)
        total_issues = len(issues)
        integrity_score = max(0, 100 - (critical_issues * 20 + high_issues * 10 + medium_issues * 5 + low_issues * 2))
        
        # Generate recommendations
        recommendations = self._generate_recommendations(issues)
        
        # Calculate enhanced metrics
        scan_duration = time.time() - self.scan_start_time if self.scan_start_time else 0
        
        return ScanResult(
            scan_timestamp=datetime.now(timezone.utc).isoformat(),
            total_files_scanned=total_files,
            issues_found=issues,
            integrity_score=integrity_score,
            critical_issues=critical_issues,
            high_issues=high_issues,
            medium_issues=medium_issues,
            low_issues=low_issues,
            recommendations=recommendations,
            ai_generated_files_detected=self.ai_files_detected,
            functional_tests_run=self.functional_tests_executed,
            functional_tests_passed=self.functional_tests_passed,
            plugins_verified=len([i for i in issues if i.category == 'FUNCTIONAL' and i.functional_test_result is True]),
            code_quality_average=statistics.mean([i.quality_score for i in issues if i.quality_score]) if any(i.quality_score for i in issues) else 0.0,
            performance_metrics={
                'scan_duration_seconds': scan_duration,
                'files_per_second': total_files / scan_duration if scan_duration > 0 else 0,
                'issues_per_file': len(issues) / total_files if total_files > 0 else 0
            }
        )

    async def _scan_python_files(self) -> Tuple[List[IntegrityIssue], int]:
        """Scan Python files for placeholders and incomplete implementations."""
        issues = []
        file_count = 0
        
        for root, dirs, files in os.walk(self.base_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclusions]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    file_count += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            lines = content.split('\n')
                        
                        # Check for placeholder patterns
                        for line_no, line in enumerate(lines, 1):
                            for pattern in self.placeholder_patterns:
                                if re.search(pattern, line, re.IGNORECASE):
                                    severity = self._determine_severity(pattern, file_path)
                                    issues.append(IntegrityIssue(
                                        severity=severity,
                                        category='PLACEHOLDER',
                                        file_path=file_path,
                                        line_number=line_no,
                                        description=f"Placeholder found: {pattern}",
                                        suggestion=f"Implement complete functionality replacing '{line.strip()}'",
                                        context={'line_content': line.strip(), 'pattern': pattern}
                                    ))
                        
                        # Check for empty function/class definitions
                        issues.extend(await self._check_empty_definitions(file_path, content))
                        
                        # Check for missing imports that indicate incomplete implementation
                        issues.extend(await self._check_missing_implementations(file_path, content))
                        
                    except Exception as e:
                        logger.warning(f"Could not scan {file_path}: {e}")
        
        return issues, file_count

    async def _scan_config_files(self) -> Tuple[List[IntegrityIssue], int]:
        """Scan YAML/JSON configuration files for integrity issues."""
        issues = []
        file_count = 0
        
        for root, dirs, files in os.walk(self.base_path):
            dirs[:] = [d for d in dirs if d not in self.exclusions]
            
            for file in files:
                if file.endswith(('.yaml', '.yml', '.json')):
                    file_path = os.path.join(root, file)
                    file_count += 1
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Check for YAML registry usage (should be database)
                        if 'yaml_backend' in content.lower() or 'yaml_dir' in content.lower():
                            issues.append(IntegrityIssue(
                                severity='CRITICAL',
                                category='REGISTRY',
                                file_path=file_path,
                                line_number=None,
                                description="YAML-based registry detected - conflicts with 'never use YAML' directive",
                                suggestion="Migrate to database-backed registry service",
                                context={'file_type': 'config'}
                            ))
                        
                        # Check for incomplete configurations
                        if 'TODO' in content or 'FIXME' in content:
                            issues.append(IntegrityIssue(
                                severity='HIGH',
                                category='INCOMPLETE',
                                file_path=file_path,
                                line_number=None,
                                description="Incomplete configuration detected",
                                suggestion="Complete all configuration parameters",
                                context={'file_type': 'config'}
                            ))
                            
                    except Exception as e:
                        logger.warning(f"Could not scan config file {file_path}: {e}")
        
        return issues, file_count

    async def _scan_plugin_completeness(self) -> List[IntegrityIssue]:
        """Scan all plugins for completeness (code, tests, SBOM, docs)."""
        issues = []
        
        plugins_path = os.path.join(self.base_path, 'plugs')
        if not os.path.exists(plugins_path):
            return issues
        
        for root, dirs, files in os.walk(plugins_path):
            # Look for plugin directories (should contain plug.yaml or plugin.yaml)
            if 'plug.yaml' in files or 'plugin.yaml' in files:
                plugin_dir = root
                plugin_name = os.path.basename(os.path.dirname(plugin_dir))
                
                # Check for required files
                required_files = ['main.py']
                missing_files = []
                
                for req_file in required_files:
                    if not os.path.exists(os.path.join(plugin_dir, req_file)):
                        missing_files.append(req_file)
                
                if missing_files:
                    issues.append(IntegrityIssue(
                        severity='CRITICAL',
                        category='MISSING_IMPL',
                        file_path=plugin_dir,
                        line_number=None,
                        description=f"Plugin {plugin_name} missing required files: {missing_files}",
                        suggestion=f"Implement missing files: {missing_files}",
                        context={'plugin_name': plugin_name, 'missing_files': missing_files}
                    ))
                
                # Check for SBOM directory
                sbom_dir = os.path.join(plugin_dir, 'sbom')
                if not os.path.exists(sbom_dir):
                    issues.append(IntegrityIssue(
                        severity='HIGH',
                        category='MISSING_IMPL',
                        file_path=plugin_dir,
                        line_number=None,
                        description=f"Plugin {plugin_name} missing SBOM directory",
                        suggestion="Generate SBOM using scripts/sbom_helper_cli.py",
                        context={'plugin_name': plugin_name}
                    ))
                
                # Check main.py for placeholder implementations
                main_py = os.path.join(plugin_dir, 'main.py')
                if os.path.exists(main_py):
                    try:
                        with open(main_py, 'r') as f:
                            content = f.read()
                            
                        # Check if it's just a placeholder
                        if len(content.strip()) < 100 or 'pass' in content:
                            issues.append(IntegrityIssue(
                                severity='CRITICAL',
                                category='PLACEHOLDER',
                                file_path=main_py,
                                line_number=None,
                                description=f"Plugin {plugin_name} main.py appears to be a placeholder",
                                suggestion="Implement complete plugin functionality",
                                context={'plugin_name': plugin_name}
                            ))
                    except Exception as e:
                        logger.warning(f"Could not check {main_py}: {e}")
        
        return issues

    async def _scan_registry_integrity(self) -> List[IntegrityIssue]:
        """Scan registry implementation for scalability issues."""
        issues = []
        
        # Check for YAML backend usage
        registry_backend_path = os.path.join(self.base_path, 'cores', 'registry_backend')
        
        if os.path.exists(registry_backend_path):
            yaml_backend_file = os.path.join(registry_backend_path, 'yaml_backend.py')
            if os.path.exists(yaml_backend_file):
                issues.append(IntegrityIssue(
                    severity='CRITICAL',
                    category='REGISTRY',
                    file_path=yaml_backend_file,
                    line_number=None,
                    description="YAML backend still present - unsuitable for large-scale use",
                    suggestion="Replace with database-backed registry service",
                    context={'issue': 'scalability'}
                ))
        
        # Check configuration files for YAML registry usage
        config_files = ['config.yaml', 'config.yml']
        for config_file in config_files:
            config_path = os.path.join(self.base_path, config_file)
            if os.path.exists(config_path):
                try:
                    with open(config_path, 'r') as f:
                        content = f.read()
                    
                    if 'yaml_backend' in content or 'yaml_dir' in content:
                        issues.append(IntegrityIssue(
                            severity='CRITICAL',
                            category='REGISTRY',
                            file_path=config_path,
                            line_number=None,
                            description="Configuration still uses YAML registry backend",
                            suggestion="Configure database registry backend",
                            context={'config_file': config_file}
                        ))
                except Exception as e:
                    logger.warning(f"Could not check config {config_path}: {e}")
        
        return issues

    async def _scan_security_completeness(self) -> List[IntegrityIssue]:
        """Scan security implementation completeness across language wrappers."""
        issues = []
        
        # Check language wrappers for security implementation
        wrappers_path = os.path.join(self.base_path, 'cores', 'wrappers')
        if os.path.exists(wrappers_path):
            languages = ['nodejs_wrapper.py', 'go_wrapper.py', 'rust_wrapper.py', 'java_wrapper.py']
            
            for lang_wrapper in languages:
                wrapper_path = os.path.join(wrappers_path, lang_wrapper)
                if os.path.exists(wrapper_path):
                    try:
                        with open(wrapper_path, 'r') as f:
                            content = f.read()
                        
                        # Check for security implementation
                        security_features = [
                            'signature_verification',
                            'sandbox',
                            'filesystem_access',
                            'network_access',
                            'resource_limits'
                        ]
                        
                        missing_security = []
                        for feature in security_features:
                            if feature not in content:
                                missing_security.append(feature)
                        
                        if missing_security:
                            issues.append(IntegrityIssue(
                                severity='CRITICAL',
                                category='SECURITY',
                                file_path=wrapper_path,
                                line_number=None,
                                description=f"Language wrapper missing security features: {missing_security}",
                                suggestion="Implement complete security enforcement for all language wrappers",
                                context={
                                    'language': lang_wrapper.replace('_wrapper.py', ''),
                                    'missing_features': missing_security
                                }
                            ))
                        
                    except Exception as e:
                        logger.warning(f"Could not check security in {wrapper_path}: {e}")
                else:
                    issues.append(IntegrityIssue(
                        severity='HIGH',
                        category='MISSING_IMPL',
                        file_path=wrapper_path,
                        line_number=None,
                        description=f"Language wrapper not implemented: {lang_wrapper}",
                        suggestion=f"Implement {lang_wrapper} with complete security features",
                        context={'language': lang_wrapper.replace('_wrapper.py', '')}
                    ))
        
        return issues

    async def _scan_documentation_consistency(self) -> List[IntegrityIssue]:
        """Scan for documentation inconsistencies and missing implementations."""
        issues = []
        
        # Check docs directory for documented features without implementation
        docs_path = os.path.join(self.base_path, 'docs')
        if os.path.exists(docs_path):
            for root, dirs, files in os.walk(docs_path):
                for file in files:
                    if file.endswith('.md'):
                        file_path = os.path.join(root, file)
                        try:
                            with open(file_path, 'r', encoding='utf-8') as f:
                                content = f.read()
                            
                            # Check for documented plugins without implementation
                            plugin_mentions = re.findall(r'`([a-zA-Z_][a-zA-Z0-9_]*)`', content)
                            for plugin_mention in plugin_mentions:
                                if '_plugin' in plugin_mention or plugin_mention.endswith('_agent'):
                                    # Check if this plugin actually exists
                                    plugin_path = os.path.join(self.base_path, 'plugs', plugin_mention)
                                    if not os.path.exists(plugin_path):
                                        issues.append(IntegrityIssue(
                                            severity='MEDIUM',
                                            category='MISSING_IMPL',
                                            file_path=file_path,
                                            line_number=None,
                                            description=f"Documentation references unimplemented plugin: {plugin_mention}",
                                            suggestion=f"Either implement {plugin_mention} or remove from documentation",
                                            context={
                                                'documented_plugin': plugin_mention,
                                                'doc_file': file
                                            }
                                        ))
                            
                        except Exception as e:
                            logger.warning(f"Could not scan documentation {file_path}: {e}")
        
        return issues

    async def _scan_ai_generated_code(self) -> List[IntegrityIssue]:
        """Scan for AI-generated code and verify its quality and functionality."""
        logger.info("Scanning for AI-generated code")
        issues = []
        
        for root, dirs, files in os.walk(self.base_path):
            dirs[:] = [d for d in dirs if d not in self.exclusions]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                            lines = content.split('\n')
                        
                        # Check for AI-generated patterns
                        ai_confidence = self._calculate_ai_confidence(content, lines)
                        
                        if ai_confidence > 0.7:  # High confidence AI-generated
                            self.ai_files_detected += 1
                            
                            # Verify AI-generated code quality
                            quality_issues = await self._verify_ai_code_quality(file_path, content)
                            
                            base_issue = IntegrityIssue(
                                severity='MEDIUM',
                                category='AI_GENERATED',
                                file_path=file_path,
                                line_number=None,
                                description=f"AI-generated code detected (confidence: {ai_confidence:.2f})",
                                suggestion="Verify AI-generated code functionality and add comprehensive tests",
                                context={
                                    'ai_confidence': ai_confidence,
                                    'file_size': len(content),
                                    'line_count': len(lines)
                                },
                                ai_confidence=ai_confidence
                            )
                            
                            issues.append(base_issue)
                            issues.extend(quality_issues)
                        
                    except Exception as e:
                        logger.warning(f"Could not scan for AI code in {file_path}: {e}")
        
        logger.info(f"AI-generated code scan complete: {self.ai_files_detected} files detected")
        return issues
    
    def _calculate_ai_confidence(self, content: str, lines: List[str]) -> float:
        """Calculate confidence that code is AI-generated based on patterns."""
        ai_indicators = 0
        total_indicators = len(self.ai_generated_patterns)
        
        # Check for explicit AI generation markers
        for pattern in self.ai_generated_patterns:
            if re.search(pattern, content, re.IGNORECASE | re.MULTILINE):
                ai_indicators += 1
        
        # Additional heuristics for AI-generated code
        
        # Long, complex type annotations (AI loves these)
        complex_typing = len(re.findall(r'Union\[.*\]|Optional\[.*\]|Dict\[.*,.*\]', content))
        if complex_typing > 5:
            ai_indicators += 0.5
        
        # Overly comprehensive error handling
        try_except_count = content.count('try:') + content.count('except')
        if try_except_count > len(lines) / 20:  # High ratio of exception handling
            ai_indicators += 0.5
        
        # Verbose docstrings with marketing language
        docstring_pattern = r'"""[^"]*(?:revolutionary|breakthrough|first|unique|comprehensive)[^"]*"""'
        if re.search(docstring_pattern, content, re.IGNORECASE):
            ai_indicators += 1
        
        # Multiple inheritance or complex class hierarchies (AI tendency)
        class_complexity = len(re.findall(r'class.*\([^\)]+,.*\):', content))
        if class_complexity > 2:
            ai_indicators += 0.3
        
        # Excessive use of dataclasses and enums
        dataclass_count = content.count('@dataclass') + content.count('class.*Enum')
        if dataclass_count > 5:
            ai_indicators += 0.3
        
        # Calculate confidence score
        confidence = min(1.0, ai_indicators / max(1, total_indicators * 0.3))
        return confidence
    
    async def _verify_ai_code_quality(self, file_path: str, content: str) -> List[IntegrityIssue]:
        """Verify the quality of AI-generated code."""
        issues = []
        
        # Check for over-engineering (common AI issue)
        if len(content) > 10000:  # Very large files
            complexity_score = self._calculate_complexity_score(content)
            if complexity_score > 80:
                issues.append(IntegrityIssue(
                    severity='HIGH',
                    category='QUALITY',
                    file_path=file_path,
                    line_number=None,
                    description=f"AI-generated code appears over-engineered (complexity: {complexity_score})",
                    suggestion="Simplify implementation to focus on core functionality",
                    context={'complexity_score': complexity_score},
                    quality_score=100 - complexity_score
                ))
        
        # Check for unused imports (AI tends to add many)
        unused_imports = self._find_unused_imports(content)
        if len(unused_imports) > 5:
            issues.append(IntegrityIssue(
                severity='MEDIUM',
                category='QUALITY',
                file_path=file_path,
                line_number=None,
                description=f"AI-generated code has many unused imports: {len(unused_imports)}",
                suggestion=f"Remove unused imports: {', '.join(unused_imports[:5])}",
                context={'unused_imports': unused_imports}
            ))
        
        # Check for excessive abstraction
        abstraction_score = self._calculate_abstraction_score(content)
        if abstraction_score > 70:
            issues.append(IntegrityIssue(
                severity='MEDIUM',
                category='QUALITY',
                file_path=file_path,
                line_number=None,
                description=f"AI-generated code may be overly abstract (score: {abstraction_score})",
                suggestion="Consider simplifying abstractions for better maintainability",
                context={'abstraction_score': abstraction_score}
            ))
        
        return issues
    
    def _calculate_complexity_score(self, content: str) -> int:
        """Calculate complexity score for code (0-100)."""
        lines = content.split('\n')
        
        # Count various complexity indicators
        class_count = content.count('class ')
        function_count = content.count('def ')
        if_count = content.count('if ')
        loop_count = content.count('for ') + content.count('while ')
        try_count = content.count('try:')
        import_count = content.count('import ') + content.count('from ')
        
        # Calculate complexity metrics
        lines_per_function = len(lines) / max(1, function_count)
        control_flow_density = (if_count + loop_count + try_count) / len(lines) * 100
        
        # Weighted complexity score
        complexity = min(100, int(
            (class_count * 5) +
            (function_count * 2) +
            (lines_per_function * 0.5) +
            (control_flow_density * 2) +
            (import_count * 0.5)
        ))
        
        return complexity
    
    def _find_unused_imports(self, content: str) -> List[str]:
        """Find potentially unused imports."""
        unused = []
        
        try:
            tree = ast.parse(content)
            
            # Extract imports
            imports = []
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.append(alias.name.split('.')[0])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        for alias in node.names:
                            imports.append(alias.name)
            
            # Check if imports are used
            for imp in imports:
                if imp not in ['os', 'sys', 're']:  # Skip common modules
                    if content.count(imp) <= 1:  # Only appears in import line
                        unused.append(imp)
        
        except SyntaxError:
            pass  # Skip files with syntax errors
        
        return unused
    
    def _calculate_abstraction_score(self, content: str) -> int:
        """Calculate abstraction level score (0-100)."""
        # Count abstraction indicators
        abstract_methods = content.count('@abstractmethod')
        interfaces = content.count('ABC')
        generics = content.count('TypeVar') + content.count('Generic')
        metaclasses = content.count('metaclass=')
        decorators = content.count('@')
        
        # Calculate score
        score = min(100, (abstract_methods * 15) + (interfaces * 10) + 
                   (generics * 5) + (metaclasses * 20) + (decorators * 2))
        
        return score

    async def _check_empty_definitions(self, file_path: str, content: str) -> List[IntegrityIssue]:
        """Check for empty function/class definitions that indicate placeholders."""
        issues = []
        
        try:
            tree = ast.parse(content)
            
            class EmptyDefinitionVisitor(ast.NodeVisitor):
                def visit_FunctionDef(self, node):
                    # Check if function body is just 'pass'
                    if (len(node.body) == 1 and 
                        isinstance(node.body[0], ast.Pass)):
                        issues.append(IntegrityIssue(
                            severity='HIGH',
                            category='PLACEHOLDER',
                            file_path=file_path,
                            line_number=node.lineno,
                            description=f"Empty function definition: {node.name}",
                            suggestion=f"Implement function body for {node.name}",
                            context={'function_name': node.name, 'type': 'function'}
                        ))
                    self.generic_visit(node)
                
                def visit_ClassDef(self, node):
                    # Check if class body is just 'pass'  
                    if (len(node.body) == 1 and 
                        isinstance(node.body[0], ast.Pass)):
                        issues.append(IntegrityIssue(
                            severity='HIGH',
                            category='PLACEHOLDER',
                            file_path=file_path,
                            line_number=node.lineno,
                            description=f"Empty class definition: {node.name}",
                            suggestion=f"Implement class body for {node.name}",
                            context={'class_name': node.name, 'type': 'class'}
                        ))
                    self.generic_visit(node)
            
            visitor = EmptyDefinitionVisitor()
            visitor.visit(tree)
            
        except SyntaxError:
            # File might not be valid Python
            pass
        except Exception as e:
            logger.warning(f"Could not parse AST for {file_path}: {e}")
        
        return issues

    async def _check_missing_implementations(self, file_path: str, content: str) -> List[IntegrityIssue]:
        """Check for missing implementations indicated by import patterns."""
        issues = []
        
        # Look for imports that suggest missing implementation
        missing_impl_patterns = [
            r'from.*import.*# TODO',
            r'import.*# not implemented',
            r'try:.*import.*except.*ImportError.*pass'
        ]
        
        lines = content.split('\n')
        for line_no, line in enumerate(lines, 1):
            for pattern in missing_impl_patterns:
                if re.search(pattern, line, re.IGNORECASE):
                    issues.append(IntegrityIssue(
                        severity='MEDIUM',
                        category='MISSING_IMPL',
                        file_path=file_path,
                        line_number=line_no,
                        description=f"Missing implementation indicated by import pattern",
                        suggestion="Implement missing functionality or remove dead imports",
                        context={'line_content': line.strip()}
                    ))
        
        return issues

    def _determine_severity(self, pattern: str, file_path: str) -> str:
        """Determine severity based on pattern and file location."""
        # Critical for core system files
        if '/cores/' in file_path:
            return 'CRITICAL'
        
        # High for plugins
        if '/plugs/' in file_path:
            return 'HIGH'
        
        # Critical for certain patterns
        critical_patterns = ['NotImplemented', 'raise NotImplementedError']
        if any(cp in pattern for cp in critical_patterns):
            return 'CRITICAL'
        
        # High for TODO/FIXME in main functionality
        if pattern in ['TODO', 'FIXME'] and 'test' not in file_path:
            return 'HIGH'
        
        return 'MEDIUM'

    def _generate_recommendations(self, issues: List[IntegrityIssue]) -> List[str]:
        """Generate prioritized recommendations based on issues found."""
        recommendations = []
        
        # Count issues by category
        category_counts = {}
        for issue in issues:
            category_counts[issue.category] = category_counts.get(issue.category, 0) + 1
        
        # Generate recommendations based on most common issues
        if category_counts.get('REGISTRY', 0) > 0:
            recommendations.append(
                "🏗️ CRITICAL: Replace YAML registry with database-backed service for scalability"
            )
        
        if category_counts.get('PLACEHOLDER', 0) > 0:
            recommendations.append(
                "📝 HIGH: Remove all placeholder code and implement complete functionality"
            )
        
        if category_counts.get('MISSING_IMPL', 0) > 0:
            recommendations.append(
                "🔧 HIGH: Complete all missing plugin implementations and required files"
            )
        
        if category_counts.get('SECURITY', 0) > 0:
            recommendations.append(
                "🛡️ CRITICAL: Extend security enforcement to all language wrappers"
            )
        
        # General recommendations
        recommendations.extend([
            "🎯 Create automated CI/CD checks to prevent placeholder code merging",
            "📊 Implement comprehensive testing for all implemented features",
            "🔍 Set up regular integrity scanning in development workflow",
            "📚 Ensure all documented features have corresponding implementations"
        ])
        
        return recommendations

    async def _verify_plugin_functionality(self) -> List[IntegrityIssue]:
        """Verify that plugins actually work as claimed through functional testing."""
        issues = []
        plugin_dirs = []
        
        # Find all plugin directories
        for root, dirs, files in os.walk(self.base_path):
            if 'main.py' in files and 'plug.yaml' in files:
                plugin_dirs.append(root)
        
        logger.info(f"Found {len(plugin_dirs)} plugins for functional verification")
        
        for plugin_dir in plugin_dirs:
            try:
                # Load plugin module
                main_path = os.path.join(plugin_dir, 'main.py')
                plug_yaml_path = os.path.join(plugin_dir, 'plug.yaml')
                
                # Check if plugin can be loaded
                spec = importlib.util.spec_from_file_location(f"plugin_{hash(plugin_dir)}", main_path)
                if spec and spec.loader:
                    plugin_module = importlib.util.module_from_spec(spec)
                    
                    # Try to load the module
                    spec.loader.exec_module(plugin_module)
                    self.functional_tests_executed += 1
                    
                    # Check required functions exist
                    if hasattr(plugin_module, 'process'):
                        # Try basic functionality test
                        if hasattr(plugin_module, 'plug_metadata'):
                            try:
                                # Test plugin metadata
                                metadata = plugin_module.plug_metadata
                                if not isinstance(metadata, dict):
                                    issues.append(IntegrityIssue(
                                        severity='HIGH',
                                        category='FUNCTIONAL',
                                        file_path=main_path,
                                        line_number=None,
                                        description="Plugin metadata is not a dictionary",
                                        suggestion="Ensure plug_metadata returns a proper dictionary",
                                        context={'plugin_dir': plugin_dir, 'test_type': 'metadata_validation'},
                                        functional_test_result=False
                                    ))
                                else:
                                    self.functional_tests_passed += 1
                            except Exception as e:
                                issues.append(IntegrityIssue(
                                    severity='HIGH',
                                    category='FUNCTIONAL',
                                    file_path=main_path,
                                    line_number=None,
                                    description=f"Plugin metadata access failed: {str(e)}",
                                    suggestion="Fix plugin metadata implementation",
                                    context={'plugin_dir': plugin_dir, 'test_type': 'metadata_access', 'error': str(e)},
                                    functional_test_result=False
                                ))
                    else:
                        issues.append(IntegrityIssue(
                            severity='CRITICAL',
                            category='FUNCTIONAL',
                            file_path=main_path,
                            line_number=None,
                            description="Plugin missing required 'process' function",
                            suggestion="Implement the required process() function",
                            context={'plugin_dir': plugin_dir, 'test_type': 'process_function_check'},
                            functional_test_result=False
                        ))
                        
            except Exception as e:
                issues.append(IntegrityIssue(
                    severity='HIGH',
                    category='FUNCTIONAL',
                    file_path=plugin_dir,
                    line_number=None,
                    description=f"Plugin loading failed: {str(e)}",
                    suggestion="Fix import errors and dependencies",
                    context={'plugin_dir': plugin_dir, 'test_type': 'plugin_loading', 'error': str(e)},
                    functional_test_result=False
                ))
        
        return issues

    async def _analyze_code_quality(self) -> List[IntegrityIssue]:
        """Analyze code quality using AST parsing and complexity metrics."""
        issues = []
        
        for root, dirs, files in os.walk(self.base_path):
            # Skip excluded directories
            dirs[:] = [d for d in dirs if d not in self.exclusions]
            
            for file in files:
                if file.endswith('.py'):
                    file_path = os.path.join(root, file)
                    
                    try:
                        with open(file_path, 'r', encoding='utf-8') as f:
                            content = f.read()
                        
                        # Parse AST for quality analysis
                        try:
                            tree = ast.parse(content)
                            
                            # Calculate cyclomatic complexity
                            complexity = self._calculate_complexity(tree)
                            if complexity > 10:  # High complexity threshold
                                issues.append(IntegrityIssue(
                                    severity='MEDIUM',
                                    category='QUALITY',
                                    file_path=file_path,
                                    line_number=None,
                                    description=f"High cyclomatic complexity: {complexity}",
                                    suggestion="Consider refactoring complex functions into smaller ones",
                                    context={'complexity_score': complexity, 'analysis_type': 'cyclomatic_complexity'},
                                    quality_score=max(0, 100 - complexity * 5)
                                ))
                            
                            # Check for code duplication patterns
                            if self._detect_code_duplication(content):
                                issues.append(IntegrityIssue(
                                    severity='LOW',
                                    category='QUALITY',
                                    file_path=file_path,
                                    line_number=None,
                                    description="Potential code duplication detected",
                                    suggestion="Extract common code into reusable functions",
                                    context={'analysis_type': 'code_duplication'},
                                    quality_score=70
                                ))
                                
                        except SyntaxError:
                            issues.append(IntegrityIssue(
                                severity='CRITICAL',
                                category='QUALITY',
                                file_path=file_path,
                                line_number=None,
                                description="Python syntax error",
                                suggestion="Fix syntax errors in the code",
                                context={'analysis_type': 'syntax_check'},
                                quality_score=0
                            ))
                            
                    except Exception as e:
                        logger.warning(f"Could not analyze quality of {file_path}: {e}")
        
        return issues
    
    def _calculate_complexity(self, tree: ast.AST) -> int:
        """Calculate cyclomatic complexity of AST."""
        complexity = 1  # Base complexity
        
        for node in ast.walk(tree):
            # Add complexity for control flow structures
            if isinstance(node, (ast.If, ast.While, ast.For, ast.AsyncFor, 
                               ast.ExceptHandler, ast.With, ast.AsyncWith)):
                complexity += 1
            elif isinstance(node, (ast.BoolOp, ast.Compare)):
                # Add complexity for boolean operations and comparisons
                complexity += 1
        
        return complexity
    
    def _detect_code_duplication(self, content: str) -> bool:
        """Simple code duplication detection."""
        lines = [line.strip() for line in content.split('\n') if line.strip() and not line.strip().startswith('#')]
        
        # Look for repeated code blocks (3+ identical lines)
        line_counts = {}
        for line in lines:
            if len(line) > 10:  # Only consider substantial lines
                line_counts[line] = line_counts.get(line, 0) + 1
        
        # If any line appears more than twice, consider it duplication
        return any(count > 2 for count in line_counts.values())


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main process function for Codebase Integrity Scanner - Enterprise Security Hardened
    Enhanced with Universal Input Sanitizer integration and comprehensive security validation

    Scans the entire PlugPipe codebase to ensure production readiness
    and identify all placeholder/incomplete implementations.
    """
    start_time = time.time()

    # Initialize security hardening
    security_hardening = CodebaseScannerSecurityHardening()

    try:
        logger.info("Starting codebase integrity scan with enterprise security hardening")

        # Security validation of input parameters first
        input_data = {}
        if isinstance(ctx, dict):
            input_data.update(ctx)
        if isinstance(cfg, dict):
            input_data.update(cfg)

        # Validate and sanitize all input data
        validation_result = security_hardening.validate_scanner_input(input_data, "scan_configuration")

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
            "scan_violations": validation_result.scan_violations,
            "validation_time": (time.time() - start_time) * 1000
        }

        # Use validated configuration for scanner initialization
        scanner_config = {
            'base_path': validated_data.get('base_path', get_plugpipe_root()),
            'exclusions': validated_data.get('exclusions', ['.venv', '__pycache__', '.git', 'node_modules']),
            'ai_detection_enabled': validated_data.get('ai_detection_enabled', True),
            'functional_testing_enabled': validated_data.get('functional_testing_enabled', True),
            'quality_analysis_enabled': validated_data.get('quality_analysis_enabled', True),
            'scan_type': validated_data.get('scan_type', 'full'),
            'severity_threshold': validated_data.get('severity_threshold', 'medium'),
            'output_format': validated_data.get('output_format', 'detailed'),
            'target_paths': validated_data.get('target_paths', []),
            'exclude_patterns': validated_data.get('exclude_patterns', [])
        }

        # Initialize scanner with validated configuration
        scanner = CodebaseIntegrityScanner(scanner_config)

        # Perform comprehensive scan
        scan_result = await scanner.scan_codebase()

        # Add security validation metadata to scan results
        scan_result.performance_metrics.update({
            "security_validation_time": security_metadata["validation_time"],
            "security_issues_detected": security_metadata["security_issues_count"],
            "sanitization_applied": security_metadata["sanitization_applied"]
        })

        # Prepare response with security metadata
        response = {
            'success': True,
            'operation_completed': 'codebase_integrity_scan',
            'scan_results': asdict(scan_result),
            'summary': {
                'total_files_scanned': scan_result.total_files_scanned,
                'integrity_score': scan_result.integrity_score,
                'total_issues': len(scan_result.issues_found),
                'critical_issues': scan_result.critical_issues,
                'high_issues': scan_result.high_issues,
                'status': 'CRITICAL' if scan_result.critical_issues > 0 else
                         'HIGH' if scan_result.high_issues > 0 else
                         'MEDIUM' if scan_result.medium_issues > 0 else
                         'HEALTHY'
            },
            'prioritized_fixes': scan_result.recommendations,
            'timestamp': scan_result.scan_timestamp,
            'security_metadata': security_metadata
        }

        logger.info(f"Integrity scan complete: {scan_result.integrity_score}/100 score, "
                   f"{len(scan_result.issues_found)} issues found")

        return response

    except Exception as e:
        logger.error(f"Codebase integrity scan failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation_completed': 'codebase_integrity_scan',
            'timestamp': datetime.now(timezone.utc).isoformat(),
            'security_metadata': {
                "sanitization_applied": False,
                "security_issues_count": 0,
                "validation_warnings": [f"Scan failed with error: {str(e)}"],
                "scan_violations": [],
                "validation_time": (time.time() - start_time) * 1000
            }
        }


# Plugin metadata
plug_metadata = {
    "name": "codebase_integrity_scanner",
    "version": "1.0.0",
    "description": "Comprehensive codebase integrity scanner that ensures production readiness",
    "author": "PlugPipe Core Team",
    "tags": ["integrity", "quality", "scanner", "production-ready"],
    "category": "quality-assurance"
}


async def pp():
    """PlugPipe plugin discovery function"""
    return plug_metadata

if __name__ == "__main__":
    # Test the scanner with limited scope for debugging
    async def test_scanner():
        test_config = {
            'base_path': get_plugpipe_root(),  # Scan full codebase
            'exclusions': ['.venv', '__pycache__', '.git', 'node_modules', 'deployment', 'frontend/node_modules'],
            'ai_detection_enabled': True,
            'functional_testing_enabled': True,   # Enable full functionality
            'quality_analysis_enabled': True     # Enable full functionality
        }
        
        print("🔍 Starting enhanced codebase integrity scanner test...")
        print(f"📂 Scanning path: {test_config['base_path']}")
        
        result = await process({}, test_config)
        
        # Print summary only for debugging
        if result.get('success'):
            summary = result.get('summary', {})
            print(f"✅ Scan completed successfully!")
            print(f"📊 Files scanned: {summary.get('total_files_scanned', 0)}")
            print(f"🎯 Integrity score: {summary.get('integrity_score', 0)}/100")
            print(f"⚠️  Total issues: {summary.get('total_issues', 0)}")
            print(f"🔥 Critical issues: {summary.get('critical_issues', 0)}")
            print(f"📈 Status: {summary.get('status', 'UNKNOWN')}")
            
            # Show first few issues for debugging
            issues = result.get('scan_results', {}).get('issues_found', [])
            if issues:
                print(f"\n🐛 Sample issues (first 3):")
                for i, issue in enumerate(issues[:3]):
                    print(f"  {i+1}. [{issue['severity']}] {issue['category']}: {issue['description']}")
        else:
            print(f"❌ Scan failed: {result.get('error', 'Unknown error')}")
    
    asyncio.run(test_scanner())