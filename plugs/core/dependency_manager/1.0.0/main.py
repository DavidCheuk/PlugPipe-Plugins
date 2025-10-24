#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Dependency Manager

Orchestrates external dependency installation and management for plugins requiring
external packages, binaries, or system dependencies.

Following PlugPipe Principles:
- REUSE EVERYTHING, REINVENT NOTHING: Uses existing package managers (apt, pip, npm, etc.)
- GRACEFUL DEGRADATION: Provides fallback mechanisms when dependencies unavailable
- SIMPLICITY BY TRADITION: Standard dependency management patterns
- DEFAULT TO CREATING PLUGINS: Manages dependencies through plugin orchestration

Handles:
- Binary dependencies (trivy, docker, kubectl, etc.)
- Python packages (via pip)
- System packages (via apt/yum/brew)
- Node.js packages (via npm)
- Container images (via docker)
"""

import os
import sys
import json
import subprocess
import logging
import platform
import shutil
import re
import urllib.parse
from typing import Dict, Any, List, Optional, Tuple
from pathlib import Path
import tempfile
from dataclasses import dataclass, field

# Universal Input Sanitizer Integration
try:
    from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
    from shares.loader import pp
    SANITIZER_AVAILABLE = True
except ImportError:
    def pp(*args, **kwargs):
        return {"success": False, "error": "pp function not available"}
    SANITIZER_AVAILABLE = False

logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    security_violations: List[str] = field(default_factory=list)
    sanitized_data: Optional[Dict[str, Any]] = None

class DependencyManager:
    """Manages external dependencies for PlugPipe plugins"""
    
    def __init__(self, config: Dict[str, Any] = None):
        self.config = config or {}
        self.system = platform.system().lower()
        self.arch = platform.machine().lower()
        self.sanitizer_available = SANITIZER_AVAILABLE

        # Security configuration
        self.max_dependencies = 100
        self.allowed_hosts = [
            'github.com', 'raw.githubusercontent.com', 'dl.k8s.io',
            'releases.hashicorp.com', 'get.helm.sh', 'pypi.org',
            'registry.npmjs.org', 'hub.docker.com'
        ]
        self.allowed_schemes = ['https']
        self.safe_install_dir = Path.home() / '.local' / 'bin'

        # Dependency installation strategies
        self.strategies = {
            'binary': self._install_binary_dependency,
            'python': self._install_python_dependency,
            'system': self._install_system_dependency,
            'npm': self._install_npm_dependency,
            'docker': self._install_docker_dependency,
            'go': self._install_go_dependency
        }

    async def _sanitize_input(self, data: Any) -> ValidationResult:
        """Sanitize input using Universal Input Sanitizer with comprehensive validation."""
        try:
            # Check sanitizer availability
            if self.sanitizer_available:
                # Use Universal Input Sanitizer
                try:
                    sanitizer_result = pp(
                        "universal_input_sanitizer",
                        **data
                    )
                except Exception as sanitizer_error:
                    logger.warning(f"Universal Input Sanitizer failed, using fallback: {sanitizer_error}")
                    return self._fallback_security_validation(data)

                if not sanitizer_result.get("success", False):
                    return ValidationResult(
                        is_valid=False,
                        security_violations=[sanitizer_result.get("error", "Sanitization failed")]
                    )

                return ValidationResult(
                    is_valid=True,
                    sanitized_data=sanitizer_result.get("sanitized_data")
                )
            else:
                # Fallback comprehensive validation
                return self._fallback_security_validation(data)

        except Exception as e:
            return ValidationResult(is_valid=False, errors=[str(e)])

    def _fallback_security_validation(self, data: Any) -> ValidationResult:
        """Fallback security validation when sanitizer unavailable."""
        violations = []

        def check_patterns(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    check_patterns(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    check_patterns(item, current_path)
            elif isinstance(obj, str):
                dangerous_patterns = [
                    '; rm -rf', '$(', '`', '|sh', '&& rm',
                    '/etc/passwd', '/etc/shadow', '../',
                    'curl -L', '&& curl', '| sh'
                ]
                for pattern in dangerous_patterns:
                    if pattern in obj:
                        violations.append(f"Dangerous pattern '{pattern}' in {path}")

        check_patterns(data)

        return ValidationResult(
            is_valid=len(violations) == 0,
            security_violations=violations,
            sanitized_data=data if len(violations) == 0 else None
        )

    def _validate_dependency_name(self, name: str) -> bool:
        """Validate dependency name for security."""
        if not name or not isinstance(name, str):
            return False

        # Allow only alphanumeric, dash, underscore, and dot
        if not re.match(r'^[a-zA-Z0-9._-]+$', name):
            logger.warning(f"Invalid dependency name format: {name}")
            return False

        # Block suspicious patterns
        dangerous_patterns = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>']
        if any(pattern in name for pattern in dangerous_patterns):
            logger.warning(f"Dangerous patterns in dependency name: {name}")
            return False

        return True

    def _validate_url(self, url: str) -> bool:
        """Validate URL for security."""
        if not url or not isinstance(url, str):
            return False

        try:
            parsed = urllib.parse.urlparse(url)

            # Check scheme
            if parsed.scheme not in self.allowed_schemes:
                logger.warning(f"Disallowed URL scheme: {parsed.scheme}")
                return False

            # Check hostname
            if parsed.hostname not in self.allowed_hosts:
                logger.warning(f"Disallowed hostname: {parsed.hostname}")
                return False

            # Check for path traversal
            if '../' in parsed.path or '..\\' in parsed.path:
                logger.warning(f"Path traversal detected in URL: {url}")
                return False

            return True

        except Exception as e:
            logger.warning(f"URL validation failed: {e}")
            return False

    def _validate_install_path(self, path: str) -> str:
        """Validate and sanitize install path."""
        if not path or not isinstance(path, str):
            return str(self.safe_install_dir)

        try:
            # Resolve the path and check if it's within safe directory
            resolved_path = Path(path).resolve()

            # Check for path traversal
            if '../' in path or '..\\' in path:
                logger.warning(f"Path traversal detected, using safe directory")
                return str(self.safe_install_dir)

            # Ensure it's within a safe directory
            safe_dirs = [Path.home() / '.local', Path('/usr/local'), Path('/opt')]
            if not any(str(resolved_path).startswith(str(safe_dir)) for safe_dir in safe_dirs):
                logger.warning(f"Unsafe install path, using safe directory")
                return str(self.safe_install_dir)

            return str(resolved_path)

        except Exception as e:
            logger.warning(f"Path validation failed: {e}, using safe directory")
            return str(self.safe_install_dir)

    def _sanitize_command_args(self, args: List[str]) -> List[str]:
        """Sanitize command arguments to prevent injection."""
        sanitized = []

        for arg in args:
            if not isinstance(arg, str):
                continue

            # Remove dangerous characters
            dangerous_chars = [';', '|', '&', '`', '$', '(', ')', '{', '}', '<', '>']
            sanitized_arg = arg
            for char in dangerous_chars:
                sanitized_arg = sanitized_arg.replace(char, '')

            # Remove shell injection patterns
            injection_patterns = ['&&', '||', '$(', '`']
            for pattern in injection_patterns:
                sanitized_arg = sanitized_arg.replace(pattern, '')

            sanitized.append(sanitized_arg)

        return sanitized

    def _run_secure_command(self, cmd: List[str], timeout: int = 300) -> Dict[str, Any]:
        """Run command with security restrictions."""
        try:
            # Sanitize command arguments
            sanitized_cmd = self._sanitize_command_args(cmd)

            # Log the command for security auditing
            logger.info(f"Executing secure command: {' '.join(sanitized_cmd)}")

            result = subprocess.run(
                sanitized_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                shell=False  # Never use shell=True for security
            )

            return {
                'success': result.returncode == 0,
                'return_code': result.returncode,
                'stdout': result.stdout,
                'stderr': result.stderr
            }

        except subprocess.TimeoutExpired:
            return {
                'success': False,
                'error': 'Command execution timed out',
                'timeout': True
            }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def check_and_install_dependencies(self, dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check and install all dependencies for a plugin with security validation"""

        # Security validation: Check dependency count
        if len(dependencies) > self.max_dependencies:
            return {
                'status': 'error',
                'error': f'Too many dependencies ({len(dependencies)}). Maximum allowed: {self.max_dependencies}',
                'security_violation': True
            }

        results = {
            'status': 'success',
            'dependencies_checked': len(dependencies),
            'installed': [],
            'already_available': [],
            'failed': [],
            'errors': [],
            'security_violations': []
        }

        for dep in dependencies:
            dep_name = dep.get('name', 'unknown')
            dep_type = dep.get('type', 'binary')

            try:
                # Security validation: Validate dependency name
                if not self._validate_dependency_name(dep_name):
                    violation = f"Invalid dependency name: {dep_name}"
                    results['security_violations'].append(violation)
                    results['failed'].append(dep_name)
                    results['errors'].append(f"{dep_name}: {violation}")
                    continue

                # Security validation: Validate URL if provided
                url = dep.get('url')
                if url and not self._validate_url(url):
                    violation = f"Invalid or unsafe URL: {url}"
                    results['security_violations'].append(violation)
                    results['failed'].append(dep_name)
                    results['errors'].append(f"{dep_name}: {violation}")
                    continue

                # Check if dependency is already available
                if self._check_dependency_available(dep):
                    results['already_available'].append(dep_name)
                    continue

                # Install dependency with security validation
                install_result = self._install_dependency(dep)

                if install_result['success']:
                    results['installed'].append(dep_name)
                else:
                    results['failed'].append(dep_name)
                    results['errors'].append(f"{dep_name}: {install_result['error']}")

            except Exception as e:
                results['failed'].append(dep_name)
                results['errors'].append(f"{dep_name}: {str(e)}")
                logger.error(f"Failed to process dependency {dep_name}: {e}")
        
        # Set overall status
        if results['security_violations']:
            results['status'] = 'security_failure'
        elif results['failed']:
            results['status'] = 'partial' if results['installed'] or results['already_available'] else 'failed'

        return results
    
    def _check_dependency_available(self, dep: Dict[str, Any]) -> bool:
        """Check if a dependency is already available"""
        
        dep_type = dep.get('type', 'binary')
        name = dep['name']
        
        if dep_type == 'binary':
            return shutil.which(name) is not None
        elif dep_type == 'python':
            try:
                __import__(name.replace('-', '_'))
                return True
            except ImportError:
                return False
        elif dep_type == 'system':
            # Check system packages (simplified)
            if self.system == 'linux':
                result = subprocess.run(['dpkg', '-l', name], 
                                      capture_output=True, text=True)
                return result.returncode == 0
            return False
        elif dep_type == 'npm':
            result = subprocess.run(['npm', 'list', '-g', name], 
                                  capture_output=True, text=True)
            return result.returncode == 0
        elif dep_type == 'docker':
            result = subprocess.run(['docker', 'images', '-q', name], 
                                  capture_output=True, text=True)
            return bool(result.stdout.strip())
            
        return False
    
    def _install_dependency(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Install a dependency based on its type"""
        
        dep_type = dep.get('type', 'binary')
        
        if dep_type in self.strategies:
            return self.strategies[dep_type](dep)
        else:
            return {'success': False, 'error': f'Unknown dependency type: {dep_type}'}
    
    def _install_binary_dependency(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Install binary dependencies"""
        
        name = dep['name']
        install_method = dep.get('install_method', 'auto')
        
        # Known binary installation methods
        if name == 'trivy':
            return self._install_trivy()
        elif name == 'kubectl':
            return self._install_kubectl()
        elif name == 'helm':
            return self._install_helm()
        elif name == 'docker':
            return self._install_docker_binary()
        else:
            # Generic binary installation
            return self._install_generic_binary(dep)
    
    def _install_trivy(self) -> Dict[str, Any]:
        """Install Trivy security scanner with secure download"""
        try:
            if self.system == 'linux':
                # Secure installation using validated URL and path
                install_script_url = 'https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh'

                if not self._validate_url(install_script_url):
                    return {'success': False, 'error': 'Trivy installation URL validation failed'}

                install_path = self._validate_install_path(str(self.safe_install_dir))

                # Download and execute securely
                result = self._run_secure_command([
                    'curl', '-sfL', install_script_url,
                    '|', 'sh', '-s', '--', '-b', install_path, 'v0.65.0'
                ])

                if result['success']:
                    return {'success': True, 'message': 'Trivy installed successfully'}
                else:
                    return {'success': False, 'error': f'Trivy installation failed: {result.get("stderr", result.get("error"))}'}
            else:
                return {'success': False, 'error': f'Trivy installation not supported for {self.system}'}

        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _install_kubectl(self) -> Dict[str, Any]:
        """Install kubectl with secure download"""
        try:
            if self.system == 'linux':
                # First get the stable version
                version_url = 'https://dl.k8s.io/release/stable.txt'
                if not self._validate_url(version_url):
                    return {'success': False, 'error': 'kubectl version URL validation failed'}

                version_result = self._run_secure_command(['curl', '-L', '-s', version_url])
                if not version_result['success']:
                    return {'success': False, 'error': 'Failed to get kubectl stable version'}

                version = version_result['stdout'].strip()
                download_url = f'https://dl.k8s.io/release/{version}/bin/linux/amd64/kubectl'

                if not self._validate_url(download_url):
                    return {'success': False, 'error': 'kubectl download URL validation failed'}

                install_path = self._validate_install_path(str(self.safe_install_dir / 'kubectl'))

                # Download kubectl
                download_result = self._run_secure_command(['curl', '-LO', download_url])
                if not download_result['success']:
                    return {'success': False, 'error': 'Failed to download kubectl'}

                # Make executable and move to install path
                chmod_result = self._run_secure_command(['chmod', '+x', 'kubectl'])
                move_result = self._run_secure_command(['mv', 'kubectl', install_path])

                if chmod_result['success'] and move_result['success']:
                    return {'success': True, 'message': 'kubectl installed successfully'}
                else:
                    return {'success': False, 'error': 'Failed to install kubectl'}
            else:
                return {'success': False, 'error': f'kubectl installation not supported for {self.system}'}

        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _install_python_dependency(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Install Python packages via pip"""
        try:
            name = dep['name']
            version = dep.get('version', '')
            
            package_spec = f"{name}=={version}" if version else name
            
            result = subprocess.run([sys.executable, '-m', 'pip', 'install', package_spec], 
                                  capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {'success': True, 'message': f'Python package {name} installed successfully'}
            else:
                return {'success': False, 'error': f'pip install failed: {result.stderr}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _install_system_dependency(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Install system packages"""
        try:
            name = dep['name']
            
            if self.system == 'linux':
                # Try apt first
                result = subprocess.run(['sudo', 'apt', 'update'], capture_output=True)
                if result.returncode == 0:
                    result = subprocess.run(['sudo', 'apt', 'install', '-y', name], 
                                          capture_output=True, text=True, timeout=300)
                    
                    if result.returncode == 0:
                        return {'success': True, 'message': f'System package {name} installed successfully'}
                    else:
                        return {'success': False, 'error': f'apt install failed: {result.stderr}'}
                else:
                    return {'success': False, 'error': 'Cannot update apt package list'}
            else:
                return {'success': False, 'error': f'System package installation not supported for {self.system}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _install_npm_dependency(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Install npm packages"""
        try:
            name = dep['name']
            global_install = dep.get('global', True)
            
            cmd = ['npm', 'install']
            if global_install:
                cmd.append('-g')
            cmd.append(name)
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {'success': True, 'message': f'npm package {name} installed successfully'}
            else:
                return {'success': False, 'error': f'npm install failed: {result.stderr}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _install_docker_dependency(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Pull Docker images"""
        try:
            name = dep['name']
            tag = dep.get('tag', 'latest')
            
            image_name = f"{name}:{tag}"
            
            result = subprocess.run(['docker', 'pull', image_name], 
                                  capture_output=True, text=True, timeout=600)
            
            if result.returncode == 0:
                return {'success': True, 'message': f'Docker image {image_name} pulled successfully'}
            else:
                return {'success': False, 'error': f'docker pull failed: {result.stderr}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _install_go_dependency(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Install Go binaries"""
        try:
            name = dep['name']
            package = dep.get('package', name)
            
            result = subprocess.run(['go', 'install', package], 
                                  capture_output=True, text=True, timeout=300)
            
            if result.returncode == 0:
                return {'success': True, 'message': f'Go package {name} installed successfully'}
            else:
                return {'success': False, 'error': f'go install failed: {result.stderr}'}
                
        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def _install_generic_binary(self, dep: Dict[str, Any]) -> Dict[str, Any]:
        """Install generic binary from URL with security validation"""
        try:
            name = dep['name']
            url = dep.get('url')

            if not url:
                return {'success': False, 'error': f'No URL provided for binary {name}'}

            # Security validation
            if not self._validate_dependency_name(name):
                return {'success': False, 'error': f'Invalid dependency name: {name}'}

            if not self._validate_url(url):
                return {'success': False, 'error': f'Invalid or unsafe URL: {url}'}

            # Secure install path
            install_path = self._validate_install_path(
                dep.get('install_path', str(self.safe_install_dir / name))
            )

            # Secure download
            download_result = self._run_secure_command(['curl', '-L', '-o', install_path, url])

            if download_result['success']:
                # Make executable
                chmod_result = self._run_secure_command(['chmod', '+x', install_path])
                if chmod_result['success']:
                    return {'success': True, 'message': f'Binary {name} installed successfully'}
                else:
                    return {'success': False, 'error': 'Failed to make binary executable'}
            else:
                return {'success': False, 'error': f'Download failed: {download_result.get("stderr", download_result.get("error"))}'}

        except Exception as e:
            return {'success': False, 'error': str(e)}
    
    def validate_mandatory_dependencies(self, dependencies: List[Dict[str, Any]], security_level: str = 'medium', mandatory_mode: bool = False) -> Dict[str, Any]:
        """Validate mandatory dependencies without installing - fail hard if any are missing"""
        # SECURITY: Prevent resource exhaustion attacks
        MAX_DEPENDENCIES = 100
        if len(dependencies) > MAX_DEPENDENCIES:
            return {
                'status': 'error',
                'error': f'Too many dependencies ({len(dependencies)}). Maximum allowed: {MAX_DEPENDENCIES}',
                'halt_execution': True,
                'security_violation': True
            }
        
        logger.info(f"🔒 Validating mandatory dependencies (security_level: {security_level}, mandatory_mode: {mandatory_mode})")
        
        validation_results = {
            'status': 'success',
            'mandatory_mode': mandatory_mode,
            'security_level': security_level,
            'dependencies_checked': len(dependencies),
            'critical_failures': [],
            'failures': [],
            'available': [],
            'errors': []
        }
        
        for dep in dependencies:
            # SECURITY: Validate and sanitize dependency input
            if not isinstance(dep, dict):
                validation_results['errors'].append({
                    'name': 'invalid_dependency',
                    'error': 'Dependency must be a dictionary object',
                    'type': 'validation'
                })
                continue
                
            dep_name = dep.get('name', 'unknown')
            dep_type = dep.get('type', 'binary')
            
            # SECURITY: Sanitize dependency names to prevent injection
            if not isinstance(dep_name, str) or not dep_name.strip():
                validation_results['errors'].append({
                    'name': 'invalid_name',
                    'error': 'Dependency name must be a non-empty string',
                    'type': 'validation'
                })
                continue
                
            # Remove potentially dangerous characters
            dep_name = ''.join(c for c in dep_name if c.isalnum() or c in '-_.')
            
            dep_security_level = dep.get('security_level', security_level)
            is_mandatory = dep.get('mandatory', False) or mandatory_mode
            failure_message = dep.get('failure_message', f"Mandatory {dep_type} dependency '{dep_name}' is not available")
            
            try:
                is_available = self._check_dependency_available(dep)
                
                if is_available:
                    validation_results['available'].append(dep_name)
                    logger.debug(f"✅ Dependency {dep_name} is available")
                else:
                    failure_info = {
                        'name': dep_name,
                        'type': dep_type,
                        'security_level': dep_security_level,
                        'failure_message': failure_message,
                        'mandatory': is_mandatory
                    }
                    
                    if is_mandatory:
                        if dep_security_level in ['critical', 'high']:
                            validation_results['critical_failures'].append(failure_info)
                            logger.error(f"❌ CRITICAL: {failure_message}")
                        else:
                            validation_results['failures'].append(failure_info)
                            logger.warning(f"⚠️  MANDATORY: {failure_message}")
                    else:
                        logger.info(f"ℹ️  Optional dependency {dep_name} not available (graceful degradation)")
                        
            except Exception as e:
                error_info = {
                    'name': dep_name,
                    'error': str(e),
                    'type': dep_type
                }
                validation_results['errors'].append(error_info)
                logger.error(f"Error validating {dep_name}: {e}")
        
        # Determine overall status
        if validation_results['critical_failures']:
            validation_results['status'] = 'critical_failure'
            if mandatory_mode:
                # In mandatory mode, critical failures should halt execution
                validation_results['halt_execution'] = True
                validation_results['exit_message'] = f"CRITICAL: {len(validation_results['critical_failures'])} mandatory dependencies failed validation. Execution halted for security."
        elif validation_results['failures']:
            validation_results['status'] = 'failure' if mandatory_mode else 'warning'
            if mandatory_mode:
                validation_results['halt_execution'] = True
                validation_results['exit_message'] = f"MANDATORY: {len(validation_results['failures'])} required dependencies failed validation. Execution halted."
        
        return validation_results
    
    def check_dependencies_only(self, dependencies: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check dependency availability without attempting installation"""
        logger.info("🔍 Checking dependency availability (no installation)")
        
        results = {
            'status': 'success',
            'dependencies_checked': len(dependencies),
            'available': [],
            'unavailable': [],
            'errors': []
        }
        
        for dep in dependencies:
            dep_name = dep.get('name', 'unknown')
            
            try:
                is_available = self._check_dependency_available(dep)
                
                if is_available:
                    results['available'].append(dep_name)
                else:
                    results['unavailable'].append(dep_name)
                    
            except Exception as e:
                results['errors'].append({
                    'name': dep_name,
                    'error': str(e)
                })
        
        if results['unavailable'] or results['errors']:
            results['status'] = 'partial'
        
        return results

def process(ctx: Dict[str, Any], cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """
    PlugPipe entry point for Dependency Manager with Universal Input Sanitizer integration

    Args:
        ctx: Context containing dependencies list and operation mode
        cfg: Configuration
    """

    try:
        # Universal Input Sanitizer integration
        if SANITIZER_AVAILABLE:
            try:
                sanitizer_result = pp("universal_input_sanitizer", **ctx)

                if not sanitizer_result.get("success", False):
                    return {
                        'status': 'error',
                        'error': f"Input validation failed: {sanitizer_result.get('error')}",
                        'security_violation': True
                    }

                ctx = sanitizer_result.get("sanitized_data", ctx)
            except Exception as sanitizer_error:
                logger.warning(f"Universal Input Sanitizer failed, using fallback: {sanitizer_error}")
                # Continue with fallback validation

        manager = DependencyManager(cfg)

        # Determine operation mode
        operation = ctx.get('operation', 'install')
        security_level = ctx.get('security_level', 'medium')
        mandatory_mode = ctx.get('mandatory_mode', False)

        dependencies = ctx.get('dependencies', [])
        if not dependencies:
            return {
                'status': 'success',
                'message': 'No dependencies to check',
                'dependencies_checked': 0
            }
        
        # Route based on operation mode
        if operation == 'validate_mandatory':
            return manager.validate_mandatory_dependencies(dependencies, security_level, mandatory_mode)
        elif operation == 'check_only':
            return manager.check_dependencies_only(dependencies)
        else:
            # Default: install mode
            return manager.check_and_install_dependencies(dependencies)
        
    except Exception as e:
        logger.error(f"Dependency manager failed: {e}")
        return {
            'status': 'error',
            'error': str(e),
            'error_type': type(e).__name__
        }

# Plugin metadata
plug_metadata = {
    "name": "dependency_manager",
    "version": "1.0.0",
    "description": "Manages external dependencies for PlugPipe plugins",
    "author": "PlugPipe Core Team",
    "license": "MIT",
    "category": "core",
    "tags": ["dependencies", "package-management", "installation", "core"],
    "type": "utility"
}