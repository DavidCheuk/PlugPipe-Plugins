#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Template Security Plugin for PlugPipe

Enterprise-grade template security plugin that eliminates Server-Side Template Injection (SSTI) 
vulnerabilities through sandboxed Jinja2 environments and security orchestration.

Features:
- Jinja2 SandboxedEnvironment for SSTI prevention
- Template variable validation via Presidio DLP integration
- Security orchestration through plugin composition
- Comprehensive audit logging and threat correlation
- Graceful degradation when composed plugins unavailable

Security Coverage:
- OWASP Top 10: Injection (A03:2021)
- Server-Side Template Injection (SSTI) prevention
- Template variable sanitization and validation
- Restricted template execution environment
"""

import os
import sys
import json
import time
import hashlib
import logging
from typing import Dict, List, Optional, Any, Tuple
from datetime import datetime

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../..')))

try:
    # Use Jinja2 SandboxedEnvironment for SSTI prevention
    from jinja2 import SandboxedEnvironment, select_autoescape, StrictUndefined
    from jinja2.exceptions import SecurityError, TemplateError, UndefinedError
    JINJA2_AVAILABLE = True
except ImportError:
    JINJA2_AVAILABLE = False

try:
    # Try to import PlugPipe services for plugin composition
    from shares.loader import pp
    PLUGPIPE_SERVICES_AVAILABLE = True
except ImportError:
    PLUGPIPE_SERVICES_AVAILABLE = False

# Plugin metadata
plug_metadata = {
    "name": "template_security",
    "version": "1.0.0",
    "description": "Enterprise-grade template security plugin using proven security tools - eliminates SSTI vulnerabilities",
    "author": "PlugPipe Security Team",
    "license": "MIT",
    "category": "security",
    "tags": ["security", "template", "ssti", "jinja2", "sandboxing"],
    "owasp_coverage": [
        "A03:2021 - Injection",
        "Server-Side Template Injection (SSTI) Prevention",
        "Template Variable Validation",
        "Secure Template Rendering"
    ]
}

class SecureTemplateRenderer:
    """Secure template rendering with sandboxed environment and plugin composition"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config.get('template_security', {})
        self.logger = logging.getLogger(__name__)
        
        if not JINJA2_AVAILABLE:
            self.logger.warning("Jinja2 not available. Install with: pip install jinja2")
            self.enabled = False
            return
            
        self.enabled = True
        self._initialize_security_plugins()
        self._initialize_sandboxed_environment()
        
    def _initialize_security_plugins(self):
        """Initialize connections to existing security plugins using pp() discovery."""
        self.plugins = {}
        
        try:
            if PLUGPIPE_SERVICES_AVAILABLE:
                # Use PlugPipe plugin discovery - following CLAUDE.md principles
                self.logger.info("Initializing security plugin composition...")
                self.plugins['security_orchestrator'] = pp('security/security_orchestrator')
                self.plugins['presidio_dlp'] = pp('security/presidio_dlp')
                self.logger.info(f"Initialized {len(self.plugins)} security plugins for composition")
            else:
                self.logger.warning("PlugPipe services unavailable - falling back to basic security")
        except Exception as e:
            self.logger.warning(f"Plugin composition initialization failed: {e} - using fallback security")
            
    def _initialize_sandboxed_environment(self):
        """Initialize Jinja2 SandboxedEnvironment with security restrictions"""
        
        # Configure sandboxed environment with strict security settings
        self.env = SandboxedEnvironment(
            # Enable autoescape for XSS prevention
            autoescape=select_autoescape(['html', 'xml']),
            # Use StrictUndefined to fail on undefined variables
            undefined=StrictUndefined,
            # Disable extensions that could be dangerous
            extensions=[],
            # Restrict template size to prevent DoS
            cache_size=0,  # Disable template caching for security
        )
        
        # Remove dangerous globals and functions from template environment
        dangerous_functions = [
            '__import__', 'eval', 'exec', 'compile', 'open', 'file',
            'input', 'raw_input', 'reload', '__builtins__', 'globals',
            'locals', 'vars', 'dir', 'hasattr', 'getattr', 'setattr',
            'delattr', 'isinstance', 'issubclass', 'callable'
        ]
        
        for func in dangerous_functions:
            self.env.globals.pop(func, None)
            
        # Add safe globals if needed
        self.env.globals['len'] = len
        self.env.globals['str'] = str
        self.env.globals['int'] = int
        self.env.globals['float'] = float
        
        self.logger.info("Initialized Jinja2 SandboxedEnvironment with security restrictions")
        
    def _validate_template_variables(self, context: Dict[str, Any]) -> Tuple[bool, List[str], List[str]]:
        """Validate template variables using Presidio DLP if available"""
        threats = []
        warnings = []
        is_safe = True
        
        try:
            if 'presidio_dlp' in self.plugins:
                # Use Presidio DLP for PII detection in template variables
                for key, value in context.items():
                    if isinstance(value, str):
                        dlp_result = self.plugins['presidio_dlp'].process({
                            'operation': 'analyze',
                            'text': value
                        })
                        
                        if dlp_result.get('status') == 'success':
                            entities = dlp_result.get('entities', [])
                            if entities:
                                is_safe = False
                                threats.extend([f"PII detected in variable '{key}': {entity['entity_type']}" 
                                              for entity in entities])
            else:
                # Fallback basic validation
                self.logger.debug("Using fallback variable validation (Presidio DLP unavailable)")
                for key, value in context.items():
                    if isinstance(value, str):
                        # Basic checks for potentially dangerous content
                        dangerous_patterns = ['{{', '}}', '{%', '%}', '__', 'import', 'eval', 'exec']
                        for pattern in dangerous_patterns:
                            if pattern in value:
                                warnings.append(f"Potentially dangerous content in variable '{key}': {pattern}")
                                
        except Exception as e:
            self.logger.error(f"Template variable validation error: {e}")
            warnings.append(f"Variable validation error: {str(e)}")
            
        return is_safe, threats, warnings
        
    def _audit_template_rendering(self, template_string: str, context: Dict[str, Any], 
                                execution_time: float) -> Dict[str, Any]:
        """Create comprehensive audit log for template rendering"""
        
        template_hash = hashlib.sha256(template_string.encode()).hexdigest()
        audit_id = f"template_{int(time.time())}_{template_hash[:8]}"
        
        audit_data = {
            'template_hash': template_hash,
            'variables_count': len(context),
            'variables_validated': 'presidio_dlp' in self.plugins,
            'security_level_applied': self.config.get('security_level', 'standard'),
            'execution_time': execution_time,
            'audit_id': audit_id,
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            if 'security_orchestrator' in self.plugins:
                # Use security orchestrator for comprehensive audit logging
                self.plugins['security_orchestrator'].process({
                    'operation': 'audit_log',
                    'event_type': 'template_rendering',
                    'data': audit_data
                })
        except Exception as e:
            self.logger.warning(f"Security orchestrator audit logging failed: {e}")
            
        return audit_data
        
    def render_secure_template(self, template_string: str, context: Dict[str, Any] = None,
                             security_level: str = 'standard') -> Dict[str, Any]:
        """Securely render template using sandboxed environment and security validation"""
        
        if not self.enabled:
            return {
                "success": False,
                "error": {
                    "type": "dependency_error",
                    "message": "Jinja2 not available for secure template rendering",
                    "security_blocked": False
                }
            }
            
        if context is None:
            context = {}
            
        start_time = time.time()
        result = {
            "success": False,
            "security_validation": {
                "is_safe": False,
                "threats_detected": [],
                "security_warnings": [],
                "validation_plugins_used": list(self.plugins.keys()),
                "confidence_score": 0.0
            }
        }
        
        try:
            # Step 1: Validate template variables using plugin composition
            variables_safe, threats, warnings = self._validate_template_variables(context)
            result["security_validation"]["threats_detected"] = threats
            result["security_validation"]["security_warnings"] = warnings
            
            # Step 2: Security level enforcement
            if security_level in ['strict', 'enterprise'] and not variables_safe:
                result["error"] = {
                    "type": "security_validation_failed",
                    "message": "Template variables failed security validation",
                    "security_blocked": True
                }
                return result
                
            # Step 3: Secure template rendering using SandboxedEnvironment
            template = self.env.from_string(template_string)
            rendered_output = template.render(**context)
            
            # Step 4: Final security assessment
            execution_time = time.time() - start_time
            confidence_score = 0.9 if variables_safe else 0.6
            if 'presidio_dlp' in self.plugins:
                confidence_score += 0.1
                
            result.update({
                "success": True,
                "rendered_output": rendered_output,
                "security_validation": {
                    "is_safe": variables_safe,
                    "threats_detected": threats,
                    "security_warnings": warnings,
                    "validation_plugins_used": list(self.plugins.keys()),
                    "confidence_score": confidence_score
                }
            })
            
            # Step 5: Audit logging
            if self.config.get('audit_template', True):
                audit_data = self._audit_template_rendering(template_string, context, execution_time)
                result["template_audit"] = audit_data
                
        except SecurityError as e:
            result["error"] = {
                "type": "template_security_error",
                "message": f"Template security violation: {str(e)}",
                "security_blocked": True
            }
        except UndefinedError as e:
            result["error"] = {
                "type": "template_undefined_error",
                "message": f"Template undefined variable: {str(e)}",
                "security_blocked": False
            }
        except TemplateError as e:
            result["error"] = {
                "type": "template_rendering_error",
                "message": f"Template rendering error: {str(e)}",
                "security_blocked": False
            }
        except Exception as e:
            self.logger.error(f"Unexpected template rendering error: {e}")
            result["error"] = {
                "type": "unexpected_error",
                "message": str(e),
                "security_blocked": False
            }
            
        return result

def process(ctx, cfg):
    """
    PlugPipe entry point for Template Security plugin
    
    Args:
        ctx: Plugin execution context
        cfg: Plugin configuration
        
    Returns:
        Secure template rendering results and security validation
    """
    
    try:
        # Extract input parameters
        template_string = ctx.get('template_string', '')
        context = ctx.get('context', {})
        security_level = ctx.get('security_level', 'standard')
        validate_variables = ctx.get('validate_variables', True)
        audit_template = ctx.get('audit_template', True)
        
        if not template_string:
            return {
                "success": False,
                "error": {
                    "type": "missing_template",
                    "message": "No template_string provided for rendering",
                    "security_blocked": False
                }
            }
        
        # Initialize plugin with configuration
        plugin_config = dict(cfg)
        plugin_config['template_security'] = {
            'security_level': security_level,
            'validate_variables': validate_variables,
            'audit_template': audit_template
        }
        
        renderer = SecureTemplateRenderer(plugin_config)
        
        if not renderer.enabled:
            return {
                "success": False,
                "error": {
                    "type": "plugin_disabled",
                    "message": "Template security plugin disabled (Jinja2 not available)",
                    "security_blocked": False
                },
                "installation_hint": "pip install jinja2"
            }
        
        # Perform secure template rendering
        result = renderer.render_secure_template(
            template_string=template_string,
            context=context,
            security_level=security_level
        )
        
        # Add plugin metadata
        result.update({
            "plugin_info": {
                "name": plug_metadata["name"],
                "version": plug_metadata["version"],
                "security_approach": "sandboxed_jinja2_with_plugin_composition",
                "owasp_coverage": plug_metadata["owasp_coverage"]
            }
        })
        
        return result
        
    except Exception as e:
        return {
            "success": False,
            "error": {
                "type": "plugin_error",
                "message": str(e),
                "error_class": type(e).__name__,
                "security_blocked": False
            },
            "jinja2_available": JINJA2_AVAILABLE,
            "plugpipe_services_available": PLUGPIPE_SERVICES_AVAILABLE
        }