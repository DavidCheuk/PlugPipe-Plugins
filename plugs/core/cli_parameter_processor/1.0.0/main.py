#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
CLI Parameter Processor Plugin
Universal command-line parameter to JSON converter for enhanced PlugPipe UX

This plugin enables user-friendly CLI commands by converting command-line arguments
to the JSON format expected by PlugPipe plugins, eliminating the friction of
creating JSON input files for simple operations.
"""

import json
import yaml
import os
import sys
import re
import logging
import importlib.util
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable
from pathlib import Path
from dataclasses import dataclass, field

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Add project root to path for plugin discovery
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))
sys.path.insert(0, PROJECT_ROOT)

# Universal Input Sanitizer availability check
SANITIZER_AVAILABLE = True
try:
    # Check if Universal Input Sanitizer plugin is available
    sanitizer_path = Path(PROJECT_ROOT) / "plugs" / "security" / "universal_input_sanitizer" / "1.0.0" / "main.py"
    if not sanitizer_path.exists():
        SANITIZER_AVAILABLE = False
        logger.warning("Universal Input Sanitizer not available - using fallback validation")
except Exception as e:
    SANITIZER_AVAILABLE = False
    logger.warning(f"Universal Input Sanitizer check failed: {e}")

@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_violations: List[str] = field(default_factory=list)
    sanitized_data: Optional[Dict[str, Any]] = None

# Plugin metadata
plug_metadata = {
    "name": "cli_parameter_processor",
    "version": "1.0.0",
    "owner": "plugpipe-core",
    "status": "production"
}

class CLIParameterProcessor:
    """Universal CLI parameter processor for PlugPipe plugins with security hardening"""

    def __init__(self):
        # Security configuration
        self.max_file_size = 10 * 1024 * 1024  # 10MB limit
        self.allowed_file_extensions = {'.json', '.yaml', '.yml'}
        self.safe_plugin_name_pattern = re.compile(r'^[a-zA-Z0-9._-]+$')
        self.dangerous_patterns = [
            'rm -rf', 'del /f', 'format c:', 'dd if=',
            'wget', 'curl', 'nc -l', 'netcat',
            '/etc/passwd', '/etc/shadow', 'c:\\windows',
            '$(', '`', '${', 'eval(', 'exec(',
            'system(', 'shell_exec', 'passthru',
            '../../', '..\\..\\', '<script', 'javascript:',
            'file://', 'ftp://', 'ldap://'
        ]

        # Initialize universal parameter mappings after security methods
        self._initialize_mappings()

    def _validate_plugin_name(self, name: str) -> bool:
        """Validate plugin name for security"""
        if not name or not isinstance(name, str):
            return False

        # Check pattern match
        if not self.safe_plugin_name_pattern.match(name):
            return False

        # Check for dangerous patterns
        name_lower = name.lower()
        for pattern in self.dangerous_patterns:
            if pattern in name_lower:
                return False

        return True

    def _validate_file_path(self, file_path: str) -> bool:
        """Validate file path for security"""
        try:
            # Convert to Path object for validation
            path = Path(file_path)

            # Check for dangerous patterns
            path_str = str(path).lower()
            for pattern in self.dangerous_patterns:
                if pattern in path_str:
                    return False

            # Check file extension
            if path.suffix not in self.allowed_file_extensions:
                return False

            # Check for path traversal
            if '..' in path.parts:
                return False

            # Check if path exists and is a file
            if path.exists() and not path.is_file():
                return False

            return True
        except Exception:
            return False

    def _validate_parameter_value(self, value: Any) -> bool:
        """Validate parameter value for dangerous content"""
        if isinstance(value, str):
            value_lower = value.lower()
            for pattern in self.dangerous_patterns:
                if pattern in value_lower:
                    return False
        elif isinstance(value, (list, tuple)):
            for item in value:
                if not self._validate_parameter_value(item):
                    return False
        elif isinstance(value, dict):
            for k, v in value.items():
                if not self._validate_parameter_value(k) or not self._validate_parameter_value(v):
                    return False
        return True

    def _fallback_security_validation(self, data: Dict[str, Any]) -> ValidationResult:
        """Fallback security validation when Universal Input Sanitizer unavailable"""
        result = ValidationResult(is_valid=True)

        try:
            # Validate plugin name if present
            if 'plugin_name' in data:
                if not self._validate_plugin_name(data['plugin_name']):
                    result.is_valid = False
                    result.security_violations.append(f"Invalid plugin name: {data['plugin_name']}")

            # Validate CLI arguments
            if 'cli_arguments' in data and isinstance(data['cli_arguments'], dict):
                for key, value in data['cli_arguments'].items():
                    if not self._validate_parameter_value(key) or not self._validate_parameter_value(value):
                        result.is_valid = False
                        result.security_violations.append(f"Dangerous content in parameter: {key}")

            # Check for dangerous patterns in entire data structure
            data_str = json.dumps(data, default=str).lower()
            for pattern in self.dangerous_patterns:
                if pattern in data_str:
                    result.is_valid = False
                    result.security_violations.append(f"Dangerous pattern detected: {pattern}")

        except Exception as e:
            result.is_valid = False
            result.errors.append(f"Validation error: {str(e)}")

        return result

    def _initialize_mappings(self):
        """Initialize parameter mappings with security validation"""
        # Universal parameter mappings that work for all plugins
        self.universal_mappings = {
            'operation': lambda x: {'operation': x},
            'user': lambda x: {'user': x},
            'session_id': lambda x: {'context': {'session_id': x}},
            'verbose': lambda x: {'verbose': bool(x)},
            'validate': lambda x: {'validate': bool(x)},
            'context': self._parse_context_params,
            # Authentication parameters
            'api_key': lambda x: {'api_key': x},
            'api-key': lambda x: {'api_key': x},
            'token': lambda x: {'token': x},
            'resource_id': lambda x: {'resource_id': x},
            'resource-id': lambda x: {'resource_id': x}
        }
        
        # Plugin-specific parameter mappings
        self.plugin_mappings = self._load_plugin_mappings()
    
    def _load_plugin_mappings(self) -> Dict[str, Dict[str, Callable]]:
        """Load plugin-specific parameter mappings"""
        mappings = {}
        
        # AI Governance parameters
        mappings['governance.ai_resource_governance'] = {
            'budget': lambda x: {'budget': int(x)},
            'currency': lambda x: {'currency': x},
            'period': lambda x: {'context': {'period': x}}
        }
        
        # API Conversion parameters  
        mappings['integration.api2mcp_factory'] = {
            'source_format': lambda x: {'source_format': x},
            'target_format': lambda x: {'target_format': x},
            'api_spec': lambda x: {'api_spec': self._load_api_spec(x)}
        }
        
        # Security parameters
        mappings['security.security_orchestrator'] = {
            'scan_type': lambda x: {'context': {'scan_type': x}},
            'severity': lambda x: {'severity': x}
        }
        
        # Testing parameters
        mappings['testing.intelligent_test_agent'] = {
            'test_categories': lambda x: {'test_categories': x if isinstance(x, list) else [x]},
            'include_ai_testing': lambda x: {'include_ai_testing': bool(x)}
        }
        
        # Unified Attack Database parameters
        mappings['unified_attack_database'] = {
            'cases': lambda x: {'test_cases': int(x)},
            'test-cases': lambda x: {'test_cases': int(x)},
            'github': lambda x: {'include_github_payloads': bool(x)},
            'include-github-payloads': lambda x: {'include_github_payloads': bool(x)},
            'unique': lambda x: {'unique_only': bool(x)},
            'unique-only': lambda x: {'unique_only': bool(x)},
            'exclude-previous': lambda x: {'exclude_previous': bool(x)},
            'randomize': lambda x: {'randomize': bool(x)},
            'categories': lambda x: {'categories': x.split(',') if isinstance(x, str) else x},
            'format': lambda x: {'protocol_format': x},
            'protocol-format': lambda x: {'protocol_format': x},
            'delay': lambda x: {'github_rate_limit_delay': float(x)},
            'github-rate-limit-delay': lambda x: {'github_rate_limit_delay': float(x)},
            'max-delay': lambda x: {'github_max_delay': float(x)},
            'github-max-delay': lambda x: {'github_max_delay': float(x)},
            'category': lambda x: {'category': x},
            'severity': lambda x: {'severity': x},
            'protocol': lambda x: {'protocol_format': x},
            'source': lambda x: {'source': x},
            'limit': lambda x: {'limit': int(x)},
            'output': lambda x: {'output_file': x},
            'export-format': lambda x: {'export_format': x}
        }
        
        # Security unified attack database full name mapping
        mappings['security.unified_attack_database'] = mappings['unified_attack_database']
        
        return mappings
    
    def _parse_context_params(self, context_params: List[str]) -> Dict[str, Any]:
        """Parse context key=value pairs"""
        context = {}
        if isinstance(context_params, list):
            for param in context_params:
                if '=' in param:
                    key, value = param.split('=', 1)
                    context[key.strip()] = value.strip()
        return {'context': context}
    
    def _load_api_spec(self, file_path: str) -> Dict[str, Any]:
        """Load API specification from file with security validation"""
        try:
            # Validate file path for security
            if not self._validate_file_path(file_path):
                logger.error(f"Invalid file path: {file_path}")
                return {"error": "Invalid file path"}

            # Check file size
            path = Path(file_path)
            if path.exists() and path.stat().st_size > self.max_file_size:
                logger.error(f"File too large: {file_path}")
                return {"error": "File too large"}

            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

                # Basic content validation
                if len(content.strip()) == 0:
                    return {"error": "Empty file"}

                # Parse based on file extension
                if file_path.endswith('.json'):
                    try:
                        return json.loads(content)
                    except json.JSONDecodeError as e:
                        return {"error": f"Invalid JSON: {e}"}
                else:
                    try:
                        return yaml.safe_load(content)
                    except yaml.YAMLError as e:
                        return {"error": f"Invalid YAML: {e}"}

        except (PermissionError, FileNotFoundError) as e:
            logger.error(f"File access error: {e}")
            return {"error": f"File access error: {e}"}
        except Exception as e:
            logger.error(f"Failed to load API spec: {e}")
            return {"error": f"Failed to load API spec: {e}"}
    
    def _deep_merge(self, target: Dict, source: Dict) -> None:
        """Deep merge source dict into target dict"""
        for key, value in source.items():
            if key in target and isinstance(target[key], dict) and isinstance(value, dict):
                self._deep_merge(target[key], value)
            else:
                target[key] = value
    
    def _add_automatic_context(self, config: Dict[str, Any], plugin_name: str) -> None:
        """Add automatic context metadata"""
        if 'context' not in config:
            config['context'] = {}
        
        config['context'].update({
            'timestamp': datetime.now().isoformat(),
            'request_id': f'cli_{int(datetime.now().timestamp())}',
            'interface': 'cli',
            'plugin_target': plugin_name
        })
    
    async def convert_params_to_json(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Convert CLI parameters to plugin JSON configuration with security validation"""
        plugin_name = cfg.get('plugin_name')
        cli_args = cfg.get('cli_arguments', {})

        # Security validation
        if not plugin_name or not cli_args:
            return {
                'success': False,
                'error': 'plugin_name and cli_arguments are required'
            }

        # Validate plugin name
        if not self._validate_plugin_name(plugin_name):
            logger.error(f"Invalid plugin name: {plugin_name}")
            return {
                'success': False,
                'error': f'Invalid plugin name: {plugin_name}',
                'security_violation': True
            }

        # Validate CLI arguments
        for key, value in cli_args.items():
            if not self._validate_parameter_value(key) or not self._validate_parameter_value(value):
                logger.error(f"Dangerous content in CLI argument: {key}")
                return {
                    'success': False,
                    'error': f'Dangerous content in CLI argument: {key}',
                    'security_violation': True
                }
        
        config = {}
        processed_params = []
        
        try:
            # Apply universal parameter mappings
            for param_name, mapper in self.universal_mappings.items():
                cli_param = param_name.replace('-', '_')
                if cli_param in cli_args and cli_args[cli_param] is not None:
                    mapped_value = mapper(cli_args[cli_param])
                    self._deep_merge(config, mapped_value)
                    processed_params.append(param_name)
            
            # Apply plugin-specific mappings
            if plugin_name in self.plugin_mappings:
                for param_name, mapper in self.plugin_mappings[plugin_name].items():
                    cli_param = param_name.replace('-', '_')
                    if cli_param in cli_args and cli_args[cli_param] is not None:
                        mapped_value = mapper(cli_args[cli_param])
                        self._deep_merge(config, mapped_value)
                        processed_params.append(param_name)
            
            # Handle generic --param key=value parameters
            if 'param' in cli_args and cli_args['param']:
                for param in cli_args['param']:
                    if '=' in param:
                        key, value = param.split('=', 1)
                        config[key.strip()] = value.strip()
                        processed_params.append(f"param:{key}")
            
            # Add automatic context
            self._add_automatic_context(config, plugin_name)
            
            return {
                'success': True,
                'operation': 'convert_params_to_json',
                'converted_config': config,
                'processed_parameters': processed_params,
                'message': f'Successfully converted {len(processed_params)} parameters for {plugin_name}'
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Parameter conversion failed: {str(e)}'
            }
    
    async def discover_plugin_parameters(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Discover available parameters for a plugin"""
        plugin_name = cfg.get('plugin_name')
        
        if not plugin_name:
            return {
                'success': False,
                'error': 'plugin_name is required'
            }
        
        try:
            discovered_params = []
            
            # Add universal parameters
            for param in self.universal_mappings.keys():
                discovered_params.append({
                    'name': param.replace('_', '-'),
                    'type': 'universal',
                    'description': f'Universal parameter: {param}'
                })
            
            # Add plugin-specific parameters
            if plugin_name in self.plugin_mappings:
                for param in self.plugin_mappings[plugin_name].keys():
                    discovered_params.append({
                        'name': param.replace('_', '-'),
                        'type': 'plugin-specific',
                        'description': f'Plugin-specific parameter for {plugin_name}'
                    })
            
            return {
                'success': True,
                'operation': 'discover_plugin_parameters',
                'plugin_name': plugin_name,
                'discovered_parameters': discovered_params,
                'parameter_count': len(discovered_params)
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Parameter discovery failed: {str(e)}'
            }
    
    async def generate_parameter_help(self, ctx: Dict, cfg: Dict) -> Dict[str, Any]:
        """Generate parameter help for a plugin"""
        plugin_name = cfg.get('plugin_name')
        
        if not plugin_name:
            return {
                'success': False,
                'error': 'plugin_name is required'
            }
        
        try:
            help_sections = {
                'plugin': plugin_name,
                'universal_parameters': {},
                'plugin_specific_parameters': {},
                'examples': []
            }
            
            # Universal parameters help
            help_sections['universal_parameters'] = {
                '--operation': 'Operation to perform (e.g., status, convert_api)',
                '--user': 'User context for the operation',
                '--validate': 'Enable validation mode',
                '--verbose': 'Enable verbose output'
            }
            
            # Plugin-specific help
            if plugin_name == 'governance.ai_resource_governance':
                help_sections['plugin_specific_parameters'] = {
                    '--budget': 'Budget amount (integer)',
                    '--currency': 'Currency code (default: USD)', 
                    '--period': 'Budget period (monthly, yearly)'
                }
                help_sections['examples'] = [
                    f'pp run {plugin_name} --operation status --user demo-user',
                    f'pp run {plugin_name} --operation set_budget --budget 1000 --period monthly'
                ]
            
            elif plugin_name == 'integration.api2mcp_factory':
                help_sections['plugin_specific_parameters'] = {
                    '--source-format': 'Source API format (OpenAPI, Swagger, etc.)',
                    '--target-format': 'Target API format (MCP, FastAPI, etc.)',
                    '--api-spec': 'Path to API specification file'
                }
                help_sections['examples'] = [
                    f'pp run {plugin_name} --operation convert_api --source-format OpenAPI --target-format MCP'
                ]
            
            return {
                'success': True,
                'operation': 'generate_parameter_help',
                'parameter_help': help_sections
            }
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Help generation failed: {str(e)}'
            }

async def process(ctx: Dict, cfg: Dict) -> Dict[str, Any]:
    """Main plugin entry point with Universal Input Sanitizer integration"""
    try:
        # Step 1: Universal Input Sanitizer integration
        if SANITIZER_AVAILABLE:
            try:
                # Load and use Universal Input Sanitizer
                sys.path.insert(0, os.path.join(PROJECT_ROOT, "shares"))
                from loader import pp

                sanitizer_result = pp("universal_input_sanitizer", **{"context": ctx, **cfg})

                if not sanitizer_result.get('success', False):
                    logger.error(f"Input validation failed: {sanitizer_result.get('error', 'Unknown error')}")
                    return {
                        'success': False,
                        'error': f"Input validation failed: {sanitizer_result.get('error', 'Security validation failed')}",
                        'security_violation': True,
                        'operation': cfg.get('operation', 'unknown')
                    }

                # Use sanitized data if available
                if 'sanitized_data' in sanitizer_result:
                    ctx = sanitizer_result['sanitized_data'].get('context', ctx)
                    cfg = sanitizer_result['sanitized_data'].get('config', cfg)

                logger.info("Universal Input Sanitizer validation passed")

            except Exception as e:
                logger.warning(f"Universal Input Sanitizer failed, using fallback: {e}")
                # Fall through to fallback validation
                processor = CLIParameterProcessor()
                validation_result = processor._fallback_security_validation({**ctx, **cfg})

                if not validation_result.is_valid:
                    return {
                        'success': False,
                        'error': 'Input validation failed (fallback)',
                        'security_violations': validation_result.security_violations,
                        'security_violation': True,
                        'operation': cfg.get('operation', 'unknown')
                    }
        else:
            # Use fallback validation
            processor = CLIParameterProcessor()
            validation_result = processor._fallback_security_validation({**ctx, **cfg})

            if not validation_result.is_valid:
                return {
                    'success': False,
                    'error': 'Input validation failed (fallback)',
                    'security_violations': validation_result.security_violations,
                    'security_violation': True,
                    'operation': cfg.get('operation', 'unknown')
                }

        # Step 2: Process with validated input
        processor = CLIParameterProcessor()
        operation = cfg.get('operation')

        if operation == 'convert_params_to_json':
            return await processor.convert_params_to_json(ctx, cfg)
        elif operation == 'discover_plugin_parameters':
            return await processor.discover_plugin_parameters(ctx, cfg)
        elif operation == 'generate_parameter_help':
            return await processor.generate_parameter_help(ctx, cfg)
        elif operation == 'register_parameter_mapping':
            return {
                'success': True,
                'operation': 'register_parameter_mapping',
                'message': 'Parameter mapping registration not yet implemented'
            }
        elif operation == 'validate_parameter_format':
            return {
                'success': True,
                'operation': 'validate_parameter_format',
                'message': 'Parameter validation not yet implemented'
            }
        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}'
            }

    except Exception as e:
        logger.error(f"Plugin execution error: {e}")
        return {
            'success': False,
            'error': str(e),
            'error_type': type(e).__name__,
            'operation': cfg.get('operation', 'unknown')
        }

if __name__ == '__main__':
    import asyncio
    
    # Test the plugin
    test_ctx = {'session_id': 'test_session'}
    test_cfg = {
        'operation': 'convert_params_to_json',
        'plugin_name': 'governance.ai_resource_governance',
        'cli_arguments': {
            'operation': 'status',
            'user': 'demo-user',
            'budget': 1000,
            'period': 'monthly'
        }
    }
    
    result = asyncio.run(process(test_ctx, test_cfg))
    print(json.dumps(result, indent=2))