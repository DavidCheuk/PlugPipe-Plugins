# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Generic Compliance Report Generator Plugin

Universal compliance report generation supporting multiple frameworks, formats, and automated scheduling.
Integrates with existing PlugPipe ecosystem for comprehensive compliance reporting.
"""

import json
import logging
import asyncio
from datetime import datetime, timedelta
from typing import Dict, Any, List, Optional, Union
from pathlib import Path
import uuid
import time
from concurrent.futures import ThreadPoolExecutor
import os
from dataclasses import dataclass
import re

# PlugPipe pp function for dynamic plugin discovery
try:
    from shares.loader import pp
except ImportError:
    def pp(plugin_name: str, **kwargs) -> Dict[str, Any]:
        return {"success": False, "error": "Plugin loader not available"}

# Optional imports with fallbacks
try:
    import pandas as pd
except ImportError:
    pd = None

try:
    import schedule
except ImportError:
    schedule = None

# Optional template engine imports
try:
    import jinja2
    from jinja2 import Environment, FileSystemLoader, Template
except ImportError:
    jinja2 = None
    Environment = FileSystemLoader = Template = None

# Report format generators (optional)
try:
    from reportlab.pdfgen import canvas
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib import colors
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False
    canvas = letter = A4 = getSampleStyleSheet = SimpleDocTemplate = Paragraph = Spacer = Table = TableStyle = colors = inch = None

try:
    import openpyxl
    from openpyxl.styles import Font, Alignment, PatternFill
    from openpyxl.chart import BarChart, Reference
    EXCEL_AVAILABLE = True
except ImportError:
    EXCEL_AVAILABLE = False
    logging.warning("OpenPyXL not available - Excel generation disabled")

try:
    from docx import Document
    from docx.shared import Inches
    WORD_AVAILABLE = True
except ImportError:
    WORD_AVAILABLE = False
    logging.warning("python-docx not available - Word generation disabled")

# Visualization
try:
    import plotly.graph_objects as go
    import plotly.express as px
    from plotly.subplots import make_subplots
    PLOTLY_AVAILABLE = True
except ImportError:
    PLOTLY_AVAILABLE = False
    logging.warning("Plotly not available - advanced visualizations disabled")

# PlugPipe integration utilities
from shares.utils.config_loader import get_llm_config


@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    security_violations: List[str]
    sanitized_data: Optional[Dict[str, Any]] = None


# Plugin metadata
plug_metadata = {
    "name": "generic_report_generator",
    "version": "1.0.0",
    "description": "Universal compliance report generation plugin supporting multiple frameworks, formats, and automated scheduling",
    "author": "PlugPipe Compliance Team",
    "tags": ["compliance", "reporting", "audit", "governance", "frameworks", "automation"]
}


class ComplianceReportGenerator:
    """Universal compliance report generator with multi-framework support"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = self._validate_and_sanitize_config(config)
        self.logger = logging.getLogger(__name__)

        # Universal Input Sanitizer integration
        self.sanitizer_available = self._check_sanitizer_availability()

        # LLM integration for intelligent content generation
        self.llm_config = get_llm_config(primary=True)

        # Report templates and frameworks (secure path handling)
        self.templates_dir = self._get_secure_templates_dir()

        # Template engine setup with security configurations
        self.jinja_env = Environment(
            loader=FileSystemLoader(str(self.templates_dir)),
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )

        # Supported frameworks configuration
        self.frameworks = {
            "sox": {
                "name": "Sarbanes-Oxley Act",
                "description": "SOX compliance for financial reporting",
                "templates": ["sox_404_assessment", "sox_302_certification", "sox_controls_testing"],
                "scoring_weights": {"financial_controls": 40, "it_controls": 30, "process_controls": 30}
            },
            "gdpr": {
                "name": "General Data Protection Regulation", 
                "description": "EU GDPR data privacy compliance",
                "templates": ["gdpr_compliance_assessment", "privacy_impact_assessment", "data_breach_report"],
                "scoring_weights": {"data_processing": 35, "consent_management": 25, "security_measures": 40}
            },
            "hipaa": {
                "name": "Health Insurance Portability and Accountability Act",
                "description": "Healthcare data protection compliance",
                "templates": ["hipaa_risk_assessment", "security_incident_report", "phi_access_audit"],
                "scoring_weights": {"physical_safeguards": 30, "administrative_safeguards": 35, "technical_safeguards": 35}
            },
            "pci_dss": {
                "name": "Payment Card Industry Data Security Standard",
                "description": "Payment card data protection",
                "templates": ["pci_self_assessment", "vulnerability_scan_report", "penetration_test_report"],
                "scoring_weights": {"network_security": 25, "data_protection": 30, "access_control": 25, "monitoring": 20}
            },
            "iso27001": {
                "name": "ISO 27001 Information Security Management",
                "description": "Information security management system",
                "templates": ["isms_effectiveness", "risk_treatment_plan", "security_controls_assessment"],
                "scoring_weights": {"risk_management": 40, "security_controls": 35, "continual_improvement": 25}
            },
            "nist": {
                "name": "NIST Cybersecurity Framework",
                "description": "NIST cybersecurity standards",
                "templates": ["csf_assessment", "risk_management_report", "security_controls_matrix"],
                "scoring_weights": {"identify": 20, "protect": 25, "detect": 20, "respond": 20, "recover": 15}
            },
            "fedramp": {
                "name": "Federal Risk and Authorization Management Program",
                "description": "Federal cloud security requirements",
                "templates": ["ato_package", "continuous_monitoring", "security_assessment_report"],
                "scoring_weights": {"security_controls": 50, "continuous_monitoring": 30, "risk_assessment": 20}
            },
            "cis": {
                "name": "Center for Internet Security Controls",
                "description": "CIS security controls framework",
                "templates": ["cis_controls_assessment", "security_benchmarks", "implementation_guide"],
                "scoring_weights": {"basic_controls": 60, "foundational_controls": 25, "organizational_controls": 15}
            },
            "cobit": {
                "name": "Control Objectives for Information Technologies",
                "description": "IT governance framework",
                "templates": ["cobit_maturity_assessment", "governance_evaluation", "risk_management_review"],
                "scoring_weights": {"governance": 40, "management": 35, "evaluation": 25}
            },
            "itil": {
                "name": "Information Technology Infrastructure Library",
                "description": "IT service management framework",
                "templates": ["itil_service_assessment", "process_maturity", "service_improvement"],
                "scoring_weights": {"service_strategy": 20, "service_design": 20, "service_transition": 20, "service_operation": 25, "continual_improvement": 15}
            }
        }
        
        # Active reports tracking
        self.active_reports = {}
        self.scheduled_reports = {}
        
        # Thread pool for concurrent report generation
        self.executor = ThreadPoolExecutor(max_workers=5)
        
        self.logger.info(f"Generic Report Generator initialized with {len(self.frameworks)} frameworks")

    def _check_sanitizer_availability(self) -> bool:
        """Check if Universal Input Sanitizer is available"""
        try:
            result = pp("universal_input_sanitizer", action="health_check")
            return result.get("success", False)
        except Exception as e:
            self.logger.warning(f"Universal Input Sanitizer not available: {e}")
            return False

    async def _sanitize_input(self, data: Any) -> ValidationResult:
        """Sanitize input using Universal Input Sanitizer with comprehensive validation"""
        validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            security_violations=[]
        )

        try:
            if self.sanitizer_available:
                # Use Universal Input Sanitizer
                sanitizer_result = pp(
                    "universal_input_sanitizer",
                    action="sanitize",
                    input_data=data
                )

                if not sanitizer_result.get("success", False):
                    validation_result.is_valid = False
                    validation_result.security_violations.append(
                        sanitizer_result.get("error", "Input sanitization failed")
                    )
                    return validation_result

                # Check for security warnings
                security_warnings = sanitizer_result.get("security_warnings", [])
                if security_warnings:
                    validation_result.security_violations.extend(security_warnings)
                    validation_result.is_valid = False
                    return validation_result

                validation_result.sanitized_data = sanitizer_result.get("sanitized_data", data)
            else:
                # Fallback comprehensive validation
                validation_result = self._fallback_security_validation(data)

        except Exception as e:
            self.logger.error(f"Input sanitization error: {e}")
            validation_result.is_valid = False
            validation_result.errors.append(f"Sanitization failed: {str(e)}")
            return validation_result

        return validation_result

    def _fallback_security_validation(self, data: Any) -> ValidationResult:
        """Fallback security validation when sanitizer is unavailable"""
        validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            security_violations=[],
            sanitized_data=data
        )

        def validate_string(value: str) -> bool:
            """Validate string for malicious patterns"""
            dangerous_patterns = [
                r'\$\(.*\)',  # Command substitution
                r'`.*`',      # Backtick execution
                r';.*rm\s+-rf',  # Dangerous file operations
                r'\.\./',     # Path traversal
                r'</?\.*(script|iframe|object)',  # Script injection
                r'(drop|delete|insert|update|union)\s+',  # SQL injection patterns
                r'(exec|eval|system|shell_exec)\s*\(',  # Code execution
                r'/etc/(passwd|shadow|hosts)',  # Sensitive file access
                r'(curl|wget|nc)\s+.*\.(com|org|net)',  # External communication
                r'(shutdown|reboot|halt)\s',  # System control
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, value, re.IGNORECASE):
                    return False
            return True

        def validate_data_recursive(obj: Any, path: str = "") -> None:
            """Recursively validate data structure"""
            if isinstance(obj, str):
                if not validate_string(obj):
                    validation_result.is_valid = False
                    validation_result.security_violations.append(
                        f"Malicious pattern detected in {path or 'input'}: {obj[:50]}..."
                    )
            elif isinstance(obj, dict):
                for key, value in obj.items():
                    key_str = str(key)
                    if not validate_string(key_str):
                        validation_result.is_valid = False
                        validation_result.security_violations.append(
                            f"Malicious pattern in key {path}.{key_str}"
                        )
                    validate_data_recursive(value, f"{path}.{key_str}" if path else key_str)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    validate_data_recursive(item, f"{path}[{i}]" if path else f"[{i}]")

        try:
            validate_data_recursive(data)
        except Exception as e:
            validation_result.is_valid = False
            validation_result.errors.append(f"Validation error: {str(e)}")

        return validation_result

    def _validate_and_sanitize_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate and sanitize plugin configuration"""
        safe_config = {}

        # Validate and sanitize each config item
        for key, value in config.items():
            if isinstance(value, str):
                # Validate string configurations
                if any(pattern in value.lower() for pattern in ['../', '/etc/', '$(', '`', ';', '|', '&']):
                    self.logger.warning(f"Potentially unsafe config value for {key}, using default")
                    continue
            safe_config[key] = value

        return safe_config

    def _get_secure_templates_dir(self) -> Path:
        """Get secure templates directory with path validation"""
        base_dir = Path(__file__).parent
        templates_dir = base_dir / "templates"

        # Ensure we stay within plugin directory
        try:
            templates_dir = templates_dir.resolve()
            base_dir = base_dir.resolve()

            # Verify templates directory is within plugin directory
            if not str(templates_dir).startswith(str(base_dir)):
                self.logger.error("Templates directory outside plugin bounds, using default")
                templates_dir = base_dir / "templates"

            templates_dir.mkdir(exist_ok=True)
            return templates_dir

        except Exception as e:
            self.logger.error(f"Template directory setup failed: {e}")
            fallback_dir = base_dir / "templates"
            fallback_dir.mkdir(exist_ok=True)
            return fallback_dir

    async def _validate_report_config(self, report_config: Dict[str, Any]) -> ValidationResult:
        """Comprehensive validation of report configuration"""
        validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            security_violations=[]
        )

        # Sanitize the entire report configuration
        sanitize_result = await self._sanitize_input(report_config)
        if not sanitize_result.is_valid:
            return sanitize_result

        # Framework validation
        framework = report_config.get('compliance_framework')
        if not framework:
            validation_result.errors.append('compliance_framework is required')
            validation_result.is_valid = False
        elif framework not in self.frameworks and framework != 'custom':
            validation_result.errors.append(f'Unsupported framework: {framework}')
            validation_result.is_valid = False

        # Output format validation
        output_format = report_config.get('output_format', 'pdf')
        valid_formats = ['json', 'html', 'markdown', 'csv']
        if PDF_AVAILABLE:
            valid_formats.append('pdf')
        if EXCEL_AVAILABLE:
            valid_formats.append('excel')
        if WORD_AVAILABLE:
            valid_formats.append('word')

        if output_format not in valid_formats:
            validation_result.warnings.append(f'Output format {output_format} may not be supported')

        # Time range validation
        time_range = report_config.get('time_range', {})
        if time_range:
            start_date = time_range.get('start_date')
            end_date = time_range.get('end_date')
            if start_date and end_date:
                try:
                    start = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                    end = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                    if start >= end:
                        validation_result.errors.append('start_date must be before end_date')
                        validation_result.is_valid = False
                except ValueError as e:
                    validation_result.errors.append(f'Invalid date format: {e}')
                    validation_result.is_valid = False

        # Data sources validation
        data_sources = report_config.get('data_sources', [])
        valid_source_types = ['plugin_metrics', 'audit_logs', 'security_scans', 'policy_violations', 'system_health', 'custom_api']

        for source in data_sources:
            if not isinstance(source, dict):
                validation_result.errors.append('Each data source must be an object')
                validation_result.is_valid = False
                continue

            source_type = source.get('source_type')
            if source_type not in valid_source_types:
                validation_result.warnings.append(f'Unknown data source type: {source_type}')

        validation_result.sanitized_data = sanitize_result.sanitized_data
        return validation_result

    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Main plugin entry point with comprehensive input validation"""
        try:
            # Comprehensive input validation and sanitization
            input_validation = await self._sanitize_input({"ctx": ctx, "cfg": cfg})
            if not input_validation.is_valid:
                return {
                    'status': 'error',
                    'message': 'Input validation failed',
                    'errors': input_validation.errors,
                    'security_violations': input_validation.security_violations
                }

            action = ctx.get('action', 'generate_report')

            # Additional action validation
            valid_actions = ['generate_report', 'schedule_report', 'list_templates', 'validate_data', 'export_report', 'get_report_status']
            if action not in valid_actions:
                return {
                    'status': 'error',
                    'message': f'Unknown action: {action}',
                    'supported_actions': valid_actions
                }

            if action == 'generate_report':
                return await self._generate_report(ctx, cfg)
            elif action == 'schedule_report':
                return await self._schedule_report(ctx, cfg)
            elif action == 'list_templates':
                return await self._list_templates(ctx, cfg)
            elif action == 'validate_data':
                return await self._validate_data(ctx, cfg)
            elif action == 'export_report':
                return await self._export_report(ctx, cfg)
            elif action == 'get_report_status':
                return await self._get_report_status(ctx, cfg)

        except Exception as e:
            self.logger.error(f"Report generation error: {e}")
            # Ensure no sensitive information leaks in error messages
            safe_error_msg = str(e)[:100] if len(str(e)) < 100 else "Internal processing error"
            return {
                'status': 'error',
                'message': safe_error_msg
            }

    async def _generate_report(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Generate a compliance report with comprehensive validation"""
        report_config = ctx.get('report_config', {})

        # Comprehensive validation of report configuration
        validation_result = await self._validate_report_config(report_config)
        if not validation_result.is_valid:
            return {
                'status': 'error',
                'message': 'Report configuration validation failed',
                'errors': validation_result.errors,
                'warnings': validation_result.warnings,
                'security_violations': validation_result.security_violations
            }

        # Use sanitized data if available
        if validation_result.sanitized_data:
            report_config = validation_result.sanitized_data

        framework = report_config['compliance_framework']
        
        # Generate unique report ID
        report_id = str(uuid.uuid4())
        
        # Initialize report tracking
        self.active_reports[report_id] = {
            'status': 'in_progress',
            'started_at': datetime.utcnow(),
            'config': report_config
        }
        
        try:
            # Collect data from configured sources
            data = await self._collect_report_data(report_config)
            
            # Generate report content
            report_content = await self._generate_report_content(framework, report_config, data)
            
            # Calculate compliance score
            compliance_score = self._calculate_compliance_score(framework, data)
            
            # Generate findings summary
            findings_summary = self._generate_findings_summary(data)
            
            # Format report based on output format
            output_format = report_config.get('output_format', 'pdf')
            formatted_report = await self._format_report(report_content, output_format, report_config)
            
            # Update report tracking
            self.active_reports[report_id].update({
                'status': 'completed',
                'completed_at': datetime.utcnow(),
                'content': formatted_report,
                'metadata': {
                    'title': f"{self.frameworks.get(framework, {}).get('name', framework)} Compliance Report",
                    'framework': framework,
                    'generated_at': datetime.utcnow().isoformat(),
                    'generated_by': 'generic_report_generator',
                    'data_sources_used': list(data.keys()),
                    'record_count': sum(len(v) if isinstance(v, list) else 1 for v in data.values()),
                    'findings_summary': findings_summary,
                    'compliance_score': compliance_score
                }
            })
            
            return {
                'status': 'success',
                'message': f'Report generated successfully for framework: {framework}',
                'report_id': report_id,
                'report_metadata': self.active_reports[report_id]['metadata'],
                'report_content': formatted_report if len(str(formatted_report)) < 10000 else {'message': 'Report content too large, use export_report action'},
                'compliance_score': compliance_score,
                'findings_summary': findings_summary
            }
            
        except Exception as e:
            # Update report tracking with error
            self.active_reports[report_id].update({
                'status': 'error',
                'error': str(e),
                'failed_at': datetime.utcnow()
            })
            
            self.logger.error(f"Report generation failed for {report_id}: {e}")
            return {
                'status': 'error',
                'message': f'Report generation failed: {str(e)}',
                'report_id': report_id
            }

    async def _collect_report_data(self, report_config: Dict[str, Any]) -> Dict[str, Any]:
        """Collect data from various sources for report generation"""
        data = {}
        data_sources = report_config.get('data_sources', [])
        
        for source in data_sources:
            source_type = source.get('source_type')
            source_config = source.get('source_config', {})
            
            try:
                if source_type == 'plugin_metrics':
                    data['plugin_metrics'] = await self._collect_plugin_metrics(source_config)
                elif source_type == 'audit_logs':
                    data['audit_logs'] = await self._collect_audit_logs(source_config)
                elif source_type == 'security_scans':
                    data['security_scans'] = await self._collect_security_scans(source_config)
                elif source_type == 'policy_violations':
                    data['policy_violations'] = await self._collect_policy_violations(source_config)
                elif source_type == 'system_health':
                    data['system_health'] = await self._collect_system_health(source_config)
                elif source_type == 'custom_api':
                    data[f'custom_{source_config.get("name", "api")}'] = await self._collect_custom_api_data(source_config)
                else:
                    self.logger.warning(f"Unknown data source type: {source_type}")
                    
            except Exception as e:
                self.logger.error(f"Failed to collect data from {source_type}: {e}")
                data[f'{source_type}_error'] = str(e)
        
        # If no specific data sources configured, collect default data
        if not data_sources:
            data = await self._collect_default_data()
        
        return data

    async def _collect_default_data(self) -> Dict[str, Any]:
        """Collect default compliance data when no specific sources configured"""
        return {
            'system_info': {
                'timestamp': datetime.utcnow().isoformat(),
                'system': 'PlugPipe Universal Integration Hub',
                'version': '1.0.0'
            },
            'plugin_count': len(list(Path('plugs').rglob('plug.yaml'))) if Path('plugs').exists() else 0,
            'sample_metrics': {
                'uptime_hours': 24,
                'successful_integrations': 95,
                'failed_integrations': 5,
                'security_scans_passed': 18,
                'security_scans_failed': 2
            }
        }

    async def _collect_plugin_metrics(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Collect plugin performance and health metrics"""
        # This would integrate with monitoring/prometheus plugin in production
        return {
            'total_plugins': 120,
            'active_plugins': 118,
            'failed_plugins': 2,
            'average_response_time_ms': 150,
            'success_rate_percentage': 98.3
        }

    async def _collect_audit_logs(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Collect audit trail and access logs"""
        # This would integrate with audit_elk_stack plugin in production
        return {
            'total_events': 10000,
            'security_events': 150,
            'access_violations': 5,
            'privileged_access_events': 25,
            'data_access_events': 500
        }

    async def _collect_security_scans(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Collect security scan results"""
        # This would integrate with security plugins in production
        return {
            'vulnerability_scans': {
                'critical': 0,
                'high': 2,
                'medium': 8,
                'low': 15,
                'total': 25
            },
            'compliance_scans': {
                'passed': 18,
                'failed': 2,
                'warnings': 5
            }
        }

    async def _collect_policy_violations(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Collect policy violation data"""
        # This would integrate with opa_policy_enterprise plugin in production
        return {
            'total_violations': 12,
            'critical_violations': 1,
            'resolved_violations': 10,
            'pending_violations': 2,
            'violation_types': {
                'access_control': 5,
                'data_handling': 4,
                'configuration': 3
            }
        }

    async def _collect_system_health(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Collect system health and performance data"""
        # This would integrate with monitoring plugins in production  
        return {
            'overall_health': 'healthy',
            'uptime_percentage': 99.9,
            'cpu_usage_percentage': 45,
            'memory_usage_percentage': 60,
            'disk_usage_percentage': 35,
            'network_latency_ms': 12
        }

    async def _collect_custom_api_data(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Collect data from custom API endpoints"""
        # Placeholder for custom API integration
        return {
            'custom_data': 'placeholder',
            'note': f'Custom API integration for {config.get("name", "unknown")}'
        }

    async def _generate_report_content(self, framework: str, report_config: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate report content based on framework and data"""
        report_type = report_config.get('report_type', 'detailed_compliance')
        
        content = {
            'title': f"{self.frameworks.get(framework, {}).get('name', framework)} Compliance Report",
            'framework': framework,
            'report_type': report_type,
            'generated_at': datetime.utcnow().isoformat(),
            'executive_summary': await self._generate_executive_summary(framework, data),
            'detailed_findings': await self._generate_detailed_findings(framework, data),
            'recommendations': await self._generate_recommendations(framework, data),
            'appendices': {
                'data_sources': list(data.keys()),
                'methodology': 'Automated compliance assessment using PlugPipe Universal Integration Hub'
            }
        }
        
        return content

    async def _generate_executive_summary(self, framework: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate executive summary using LLM if available"""
        framework_info = self.frameworks.get(framework, {})
        
        # Try to use LLM for intelligent summary generation
        if self.llm_config:
            try:
                prompt = f"""
                Generate an executive summary for a {framework_info.get('name', framework)} compliance report.
                
                Framework: {framework}
                Data Summary: {json.dumps(data, indent=2)}
                
                Include:
                1. Overall compliance status
                2. Key findings and risks
                3. Critical recommendations
                4. Business impact assessment
                
                Keep it concise and executive-focused (2-3 paragraphs).
                """
                
                # This would use the LLM service in production
                summary = await self._generate_with_llm(prompt)
                if summary:
                    return {'content': summary, 'generated_by': 'llm'}
                    
            except Exception as e:
                self.logger.warning(f"LLM summary generation failed: {e}")
        
        # Fallback to template-based summary
        return {
            'content': f"This {framework_info.get('name', framework)} compliance assessment evaluated {len(data)} data sources and found the system to be in good compliance standing with minor areas for improvement.",
            'generated_by': 'template'
        }

    async def _generate_detailed_findings(self, framework: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate detailed findings based on framework requirements"""
        findings = []
        
        # Analyze each data source for compliance issues
        for source, source_data in data.items():
            if isinstance(source_data, dict):
                if 'violations' in source_data or 'failed' in source_data or 'errors' in source_data:
                    findings.append({
                        'category': source,
                        'severity': 'medium',
                        'finding': f'Issues detected in {source}',
                        'details': source_data,
                        'recommendation': f'Review and resolve issues in {source}'
                    })
                elif 'success_rate' in str(source_data).lower() or 'healthy' in str(source_data).lower():
                    findings.append({
                        'category': source,
                        'severity': 'low',
                        'finding': f'{source} operating within normal parameters',
                        'details': source_data,
                        'recommendation': 'Continue monitoring'
                    })
        
        return findings

    async def _generate_recommendations(self, framework: str, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations"""
        recommendations = [
            {
                'priority': 'high',
                'category': 'monitoring',
                'recommendation': 'Implement continuous compliance monitoring',
                'rationale': 'Proactive monitoring prevents compliance violations',
                'implementation': 'Set up automated compliance checks using PlugPipe ecosystem'
            },
            {
                'priority': 'medium',
                'category': 'documentation',
                'recommendation': 'Maintain comprehensive audit documentation',
                'rationale': 'Documentation is required for compliance validation',
                'implementation': 'Use automated report generation for regular documentation'
            }
        ]
        
        return recommendations

    async def _format_report(self, content: Dict[str, Any], output_format: str, config: Dict[str, Any]) -> Union[str, bytes, Dict[str, Any]]:
        """Format report content based on requested output format"""
        if output_format == 'json':
            return content
        elif output_format == 'html':
            return await self._generate_html_report(content, config)
        elif output_format == 'pdf' and PDF_AVAILABLE:
            return await self._generate_pdf_report(content, config)
        elif output_format == 'excel' and EXCEL_AVAILABLE:
            return await self._generate_excel_report(content, config)
        elif output_format == 'word' and WORD_AVAILABLE:
            return await self._generate_word_report(content, config)
        elif output_format == 'markdown':
            return await self._generate_markdown_report(content, config)
        elif output_format == 'csv':
            return await self._generate_csv_report(content, config)
        else:
            return {
                'format': output_format,
                'status': 'unsupported',
                'content': content,
                'note': f'Format {output_format} not supported or libraries not available'
            }

    async def _generate_html_report(self, content: Dict[str, Any], config: Dict[str, Any]) -> str:
        """Generate HTML report"""
        html_template = """
        <!DOCTYPE html>
        <html>
        <head>
            <title>{{ title }}</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 40px; }
                .header { border-bottom: 2px solid #333; margin-bottom: 20px; }
                .finding { margin: 10px 0; padding: 10px; border-left: 4px solid #007cba; }
                .critical { border-left-color: #d32f2f; }
                .high { border-left-color: #f57c00; }
                .medium { border-left-color: #fbc02d; }
                .low { border-left-color: #388e3c; }
                .recommendation { background: #f5f5f5; padding: 15px; margin: 10px 0; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>{{ title }}</h1>
                <p>Framework: {{ framework }} | Generated: {{ generated_at }}</p>
            </div>
            
            <h2>Executive Summary</h2>
            <p>{{ executive_summary.content }}</p>
            
            <h2>Detailed Findings</h2>
            {% for finding in detailed_findings %}
            <div class="finding {{ finding.severity }}">
                <strong>{{ finding.category }}</strong> - {{ finding.severity.upper() }}
                <p>{{ finding.finding }}</p>
                <p><em>Recommendation: {{ finding.recommendation }}</em></p>
            </div>
            {% endfor %}
            
            <h2>Recommendations</h2>
            {% for rec in recommendations %}
            <div class="recommendation">
                <strong>{{ rec.priority.upper() }} Priority:</strong> {{ rec.recommendation }}
                <p>{{ rec.rationale }}</p>
                <p><strong>Implementation:</strong> {{ rec.implementation }}</p>
            </div>
            {% endfor %}
        </body>
        </html>
        """
        
        template = Template(html_template)
        return template.render(**content)

    async def _generate_markdown_report(self, content: Dict[str, Any], config: Dict[str, Any]) -> str:
        """Generate Markdown report"""
        md_content = f"""# {content['title']}

**Framework:** {content['framework']}  
**Generated:** {content['generated_at']}  

## Executive Summary

{content['executive_summary']['content']}

## Detailed Findings

"""
        
        for finding in content.get('detailed_findings', []):
            md_content += f"""### {finding['category']} - {finding['severity'].upper()}

**Finding:** {finding['finding']}  
**Recommendation:** {finding['recommendation']}

"""
        
        md_content += "\n## Recommendations\n\n"
        
        for rec in content.get('recommendations', []):
            md_content += f"""### {rec['priority'].upper()} Priority: {rec['recommendation']}

{rec['rationale']}

**Implementation:** {rec['implementation']}

"""
        
        return md_content

    def _calculate_compliance_score(self, framework: str, data: Dict[str, Any]) -> float:
        """Calculate compliance score based on framework and data"""
        framework_info = self.frameworks.get(framework, {})
        scoring_weights = framework_info.get('scoring_weights', {})
        
        # Simple scoring algorithm - would be more sophisticated in production
        base_score = 85.0  # Baseline compliance score
        
        # Adjust based on violations and issues
        for source, source_data in data.items():
            if isinstance(source_data, dict):
                if 'violations' in source_data:
                    violations = source_data.get('violations', 0)
                    if isinstance(violations, (int, float)):
                        base_score -= violations * 2  # Deduct 2 points per violation
                
                if 'failed' in source_data:
                    failed = source_data.get('failed', 0)
                    if isinstance(failed, (int, float)):
                        base_score -= failed * 1.5  # Deduct 1.5 points per failure
        
        # Ensure score is within valid range
        return max(0.0, min(100.0, base_score))

    def _generate_findings_summary(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Generate summary of findings by severity"""
        summary = {
            'total_findings': 0,
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0
        }
        
        # Analyze data for findings - simplified for demo
        for source, source_data in data.items():
            if isinstance(source_data, dict):
                # Count findings based on data patterns
                if any(keyword in str(source_data).lower() for keyword in ['error', 'violation', 'failed']):
                    summary['medium_findings'] += 1
                    summary['total_findings'] += 1
                elif any(keyword in str(source_data).lower() for keyword in ['warning', 'issue']):
                    summary['low_findings'] += 1 
                    summary['total_findings'] += 1
        
        return summary

    async def _generate_with_llm(self, prompt: str) -> Optional[str]:
        """Generate content using LLM service (placeholder implementation)"""
        # This would integrate with intelligence/llm_service plugin in production
        try:
            # Simulate LLM response
            await asyncio.sleep(0.1)  # Simulate processing time
            return "AI-generated summary would appear here in production implementation."
        except Exception as e:
            self.logger.error(f"LLM generation failed: {e}")
            return None

    async def _schedule_report(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Schedule recurring report generation"""
        schedule_config = ctx.get('schedule_config', {})
        report_config = ctx.get('report_config', {})
        
        if not schedule_config.get('cron_expression'):
            return {
                'status': 'error',
                'message': 'cron_expression is required for scheduling'
            }
        
        schedule_id = str(uuid.uuid4())
        
        # Store scheduled report configuration
        self.scheduled_reports[schedule_id] = {
            'id': schedule_id,
            'name': f"{report_config.get('compliance_framework', 'unknown')} Scheduled Report",
            'schedule': schedule_config['cron_expression'],
            'next_run': datetime.utcnow() + timedelta(hours=24),  # Simplified next run calculation
            'status': 'active',
            'report_config': report_config,
            'schedule_config': schedule_config,
            'created_at': datetime.utcnow()
        }
        
        self.logger.info(f"Scheduled report {schedule_id} created")
        
        return {
            'status': 'success',
            'message': 'Report scheduled successfully',
            'schedule_id': schedule_id,
            'next_run': self.scheduled_reports[schedule_id]['next_run'].isoformat()
        }

    async def _list_templates(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """List available report templates"""
        templates = []
        
        for framework_id, framework_info in self.frameworks.items():
            for template_id in framework_info.get('templates', []):
                templates.append({
                    'id': template_id,
                    'name': template_id.replace('_', ' ').title(),
                    'framework': framework_id,
                    'description': f"{framework_info['name']} template: {template_id}"
                })
        
        return {
            'status': 'success',
            'message': f'Found {len(templates)} available templates',
            'available_templates': templates,
            'supported_frameworks': list(self.frameworks.keys())
        }

    async def _validate_data(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Validate report configuration and data sources"""
        report_config = ctx.get('report_config', {})
        
        errors = []
        warnings = []
        
        # Validate framework
        framework = report_config.get('compliance_framework')
        if not framework:
            errors.append('compliance_framework is required')
        elif framework not in self.frameworks and framework != 'custom':
            errors.append(f'Unsupported framework: {framework}')
        
        # Validate output format
        output_format = report_config.get('output_format', 'pdf')
        supported_formats = ['json', 'html', 'markdown', 'csv']
        if PDF_AVAILABLE:
            supported_formats.append('pdf')
        if EXCEL_AVAILABLE:
            supported_formats.append('excel')
        if WORD_AVAILABLE:
            supported_formats.append('word')
            
        if output_format not in supported_formats:
            warnings.append(f'Output format {output_format} may not be fully supported')
        
        # Validate data sources
        data_sources = report_config.get('data_sources', [])
        valid_source_types = ['plugin_metrics', 'audit_logs', 'security_scans', 'policy_violations', 'system_health', 'custom_api']
        
        for source in data_sources:
            source_type = source.get('source_type')
            if source_type not in valid_source_types:
                warnings.append(f'Unknown data source type: {source_type}')
        
        is_valid = len(errors) == 0
        
        return {
            'status': 'success',
            'validation_results': {
                'is_valid': is_valid,
                'errors': errors,
                'warnings': warnings
            },
            'supported_formats': supported_formats,
            'supported_frameworks': list(self.frameworks.keys()),
            'supported_source_types': valid_source_types
        }

    async def _export_report(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Export generated report to specified destination"""
        report_id = ctx.get('report_id')
        export_config = ctx.get('export_config', {})
        
        if not report_id or report_id not in self.active_reports:
            return {
                'status': 'error',
                'message': 'Invalid or missing report_id'
            }
        
        report = self.active_reports[report_id]
        if report['status'] != 'completed':
            return {
                'status': 'error',
                'message': f'Report is not completed. Status: {report["status"]}'
            }
        
        destination = export_config.get('destination', 'file_system')
        # Secure path generation for exports
        safe_filename = self._generate_safe_filename(report_id, report['config'].get('output_format', 'json'))
        export_path = f"/tmp/{safe_filename}"

        try:
            # Write report content to file with path validation
            export_path = self._validate_export_path(export_path)
            with open(export_path, 'w', encoding='utf-8') as f:
                if isinstance(report['content'], dict):
                    json.dump(report['content'], f, indent=2, default=str)
                else:
                    f.write(str(report['content']))
            
            self.logger.info(f"Report {report_id} exported to {export_path}")
            
            return {
                'status': 'success',
                'message': 'Report exported successfully',
                'export_location': export_path,
                'report_metadata': report.get('metadata', {})
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': f'Export failed: {str(e)}'
            }

    async def _get_report_status(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get status of a report or list all reports"""
        report_id = ctx.get('report_id')
        
        if report_id:
            # Get specific report status
            if report_id in self.active_reports:
                report = self.active_reports[report_id].copy()
                # Remove large content from status response
                if 'content' in report:
                    report['content'] = {'status': 'available', 'size': len(str(report['content']))}
                return {
                    'status': 'success',
                    'report_status': report
                }
            else:
                return {
                    'status': 'error',
                    'message': 'Report not found'
                }
        else:
            # List all reports
            reports_summary = []
            for rid, report in self.active_reports.items():
                summary = {
                    'report_id': rid,
                    'status': report['status'],
                    'framework': report['config'].get('compliance_framework'),
                    'started_at': report.get('started_at'),
                    'completed_at': report.get('completed_at')
                }
                reports_summary.append(summary)
            
            scheduled_summary = []
            for sid, scheduled in self.scheduled_reports.items():
                summary = {
                    'schedule_id': sid,
                    'name': scheduled['name'],
                    'schedule': scheduled['schedule'],
                    'next_run': scheduled['next_run'],
                    'status': scheduled['status']
                }
                scheduled_summary.append(summary)
            
            return {
                'status': 'success',
                'active_reports': reports_summary,
                'scheduled_reports': scheduled_summary,
                'total_active': len(reports_summary),
                'total_scheduled': len(scheduled_summary)
            }

    def _generate_safe_filename(self, report_id: str, format_extension: str) -> str:
        """Generate safe filename for report exports"""
        # Remove any potentially dangerous characters
        safe_id = re.sub(r'[^a-zA-Z0-9\-_]', '', str(report_id))[:50]
        safe_extension = re.sub(r'[^a-zA-Z0-9]', '', str(format_extension))[:10]
        return f"report_{safe_id}.{safe_extension}"

    def _validate_export_path(self, export_path: str) -> str:
        """Validate export path for security"""
        # Ensure path is within /tmp and doesn't contain traversal attempts
        resolved_path = Path(export_path).resolve()
        tmp_path = Path("/tmp").resolve()

        if not str(resolved_path).startswith(str(tmp_path)):
            raise ValueError("Export path must be within /tmp directory")

        # Additional check for dangerous patterns
        if any(pattern in str(resolved_path) for pattern in ['..', '/etc', '/proc', '/sys']):
            raise ValueError("Invalid export path detected")

        return str(resolved_path)


# Main plugin entry point
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Plugin entry point"""
    generator = ComplianceReportGenerator(cfg)
    return await generator.process(ctx, cfg)


if __name__ == "__main__":
    # Test the plugin
    import asyncio
    
    async def test_plugin():
        test_config = {}
        test_context = {
            'action': 'generate_report',
            'report_config': {
                'compliance_framework': 'gdpr',
                'report_type': 'detailed_compliance',
                'output_format': 'json',
                'time_range': {
                    'period': 'monthly'
                }
            }
        }
        
        result = await process(test_context, test_config)
        print(json.dumps(result, indent=2, default=str))
    
    asyncio.run(test_plugin())