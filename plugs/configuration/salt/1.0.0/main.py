# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Salt Configuration Management Plugin for PlugPipe

This plugin provides comprehensive Salt Stack configuration management capabilities
including state management, pillar data, grains, execution modules, and orchestration.
Supports both Salt Master/Minion and Salt SSH architectures.
"""

import asyncio
import json
import logging
import os
import re
import shlex
import subprocess
import tempfile
import yaml
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass

# Import PlugPipe framework for Universal Input Sanitizer
try:
    from shares.loader import pp
except ImportError:
    pp = None

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str] = None
    warnings: List[str] = None
    security_violations: List[str] = None
    sanitized_data: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.errors is None:
            self.errors = []
        if self.warnings is None:
            self.warnings = []
        if self.security_violations is None:
            self.security_violations = []

@dataclass
class SaltConfig:
    """Salt configuration settings with security validation"""
    master_host: str = "localhost"
    master_port: int = 4506
    salt_dir: str = "/etc/salt"
    pillar_root: str = "/srv/pillar"
    state_root: str = "/srv/salt"
    timeout: int = 300
    ssh_mode: bool = False
    ssh_user: str = "root"
    ssh_key_path: str = ""
    roster_file: str = "/etc/salt/roster"

    def __post_init__(self):
        """Validate configuration for security issues"""
        self._validate_config()

    def _validate_config(self):
        """Validate configuration for security issues"""
        # Validate paths to prevent path traversal
        paths_to_check = [
            self.salt_dir, self.pillar_root, self.state_root,
            self.ssh_key_path, self.roster_file
        ]
        for path in paths_to_check:
            if path and ("../" in path or "..\\" in path):
                raise ValueError(f"Path traversal attempt detected in: {path}")

        # Validate timeout constraints (5 seconds to 1 hour)
        if self.timeout < 5 or self.timeout > 3600:
            raise ValueError(f"Invalid timeout: {self.timeout}. Must be 5-3600 seconds")

        # Validate port ranges
        if self.master_port < 1024 or self.master_port > 65535:
            raise ValueError(f"Invalid Salt master port: {self.master_port}. Must be 1024-65535")

        # Validate master hostname
        if not self._is_valid_hostname(self.master_host):
            raise ValueError(f"Invalid Salt master hostname: {self.master_host}")

        # Validate SSH user
        if self.ssh_mode and not self._is_valid_username(self.ssh_user):
            raise ValueError(f"Invalid SSH username: {self.ssh_user}")

    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname format"""
        if not hostname or len(hostname) > 255:
            return False
        # Check for dangerous characters
        dangerous_chars = [';', '|', '&', '$', '`', '>', '<', '\n', '\r']
        if any(char in hostname for char in dangerous_chars):
            return False
        # Basic hostname pattern
        hostname_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(hostname_pattern, hostname))

    def _is_valid_username(self, username: str) -> bool:
        """Validate username format"""
        if not username or len(username) > 32:
            return False
        # Check for dangerous characters
        dangerous_chars = [';', '|', '&', '$', '`', '>', '<', '\n', '\r', ' ']
        if any(char in username for char in dangerous_chars):
            return False
        # Basic username pattern
        username_pattern = r'^[a-zA-Z][a-zA-Z0-9_-]*$'
        return bool(re.match(username_pattern, username))

class SaltStateManager:
    """Manages Salt state operations"""
    
    def __init__(self, config: SaltConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SaltStateManager")
    
    async def apply_state(self, target: str, state: str, pillar_data: Dict = None) -> Dict:
        """Apply Salt state to target minions"""
        cmd = ["salt", target, "state.apply", state]
        
        if pillar_data:
            pillar_file = await self._create_temp_pillar(pillar_data)
            cmd.extend(["pillar", f"'{json.dumps(pillar_data)}'"])
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def test_state(self, target: str, state: str, pillar_data: Dict = None) -> Dict:
        """Test Salt state without applying changes"""
        cmd = ["salt", target, "state.apply", state, "test=True"]
        
        if pillar_data:
            cmd.extend(["pillar", f"'{json.dumps(pillar_data)}'"])
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def highstate(self, target: str) -> Dict:
        """Apply highstate to target minions"""
        cmd = ["salt", target, "state.highstate"]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def list_states(self) -> List[str]:
        """List available Salt states"""
        cmd = ["salt-run", "state.show_top"]
        result = await self._run_salt_command(cmd)
        
        states = []
        if result.get("success") and result.get("output"):
            try:
                top_data = yaml.safe_load(result["output"])
                for env, targets in top_data.items():
                    for target, state_list in targets.items():
                        states.extend(state_list)
            except Exception as e:
                self.logger.warning(f"Failed to parse state list: {e}")
        
        return list(set(states))
    
    async def _create_temp_pillar(self, pillar_data: Dict) -> str:
        """Create temporary pillar file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.sls', delete=False) as f:
            yaml.dump(pillar_data, f)
            return f.name
    
    async def _run_salt_command(self, cmd: List[str]) -> Dict:
        """Execute Salt command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config.salt_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.config.timeout
            )
            
            return {
                "success": process.returncode == 0,
                "return_code": process.returncode,
                "output": stdout.decode('utf-8') if stdout else "",
                "error": stderr.decode('utf-8') if stderr else "",
                "command": " ".join(cmd)
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": f"Command timed out after {self.config.timeout} seconds",
                "command": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": str(e),
                "command": " ".join(cmd)
            }

class SaltMinionManager:
    """Manages Salt minion operations"""
    
    def __init__(self, config: SaltConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SaltMinionManager")
    
    async def list_minions(self, status: str = "up") -> List[str]:
        """List Salt minions by status"""
        cmd = ["salt-run", "manage." + status]
        result = await self._run_salt_command(cmd)
        
        minions = []
        if result.get("success") and result.get("output"):
            try:
                # Parse YAML output for minion list
                output_lines = result["output"].strip().split('\n')
                for line in output_lines:
                    line = line.strip()
                    if line and not line.startswith('-'):
                        minions.append(line.replace('- ', ''))
            except Exception as e:
                self.logger.warning(f"Failed to parse minion list: {e}")
        
        return minions
    
    async def accept_key(self, minion_id: str) -> Dict:
        """Accept minion key"""
        cmd = ["salt-key", "-a", minion_id, "-y"]
        return await self._run_salt_command(cmd)
    
    async def delete_key(self, minion_id: str) -> Dict:
        """Delete minion key"""
        cmd = ["salt-key", "-d", minion_id, "-y"]
        return await self._run_salt_command(cmd)
    
    async def list_keys(self) -> Dict:
        """List all minion keys"""
        cmd = ["salt-key", "-L", "--out=json"]
        result = await self._run_salt_command(cmd)
        
        if result.get("success") and result.get("output"):
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse key list JSON")
        
        return {}
    
    async def get_grains(self, target: str, grain: str = None) -> Dict:
        """Get minion grains"""
        if grain:
            cmd = ["salt", target, "grains.get", grain, "--out=json"]
        else:
            cmd = ["salt", target, "grains.items", "--out=json"]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        result = await self._run_salt_command(cmd)
        
        if result.get("success") and result.get("output"):
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse grains JSON")
        
        return {}
    
    async def set_grains(self, target: str, grain: str, value: Any) -> Dict:
        """Set minion grains"""
        cmd = ["salt", target, "grains.setval", grain, str(value)]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def _run_salt_command(self, cmd: List[str]) -> Dict:
        """Execute Salt command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config.salt_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.config.timeout
            )
            
            return {
                "success": process.returncode == 0,
                "return_code": process.returncode,
                "output": stdout.decode('utf-8') if stdout else "",
                "error": stderr.decode('utf-8') if stderr else "",
                "command": " ".join(cmd)
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": f"Command timed out after {self.config.timeout} seconds",
                "command": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": str(e),
                "command": " ".join(cmd)
            }

class SaltPillarManager:
    """Manages Salt pillar data"""
    
    def __init__(self, config: SaltConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SaltPillarManager")
    
    async def get_pillar(self, target: str, key: str = None) -> Dict:
        """Get pillar data for target"""
        if key:
            cmd = ["salt", target, "pillar.get", key, "--out=json"]
        else:
            cmd = ["salt", target, "pillar.items", "--out=json"]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        result = await self._run_salt_command(cmd)
        
        if result.get("success") and result.get("output"):
            try:
                return json.loads(result["output"])
            except json.JSONDecodeError:
                self.logger.warning("Failed to parse pillar JSON")
        
        return {}
    
    async def refresh_pillar(self, target: str) -> Dict:
        """Refresh pillar data on target minions"""
        cmd = ["salt", target, "saltutil.refresh_pillar"]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def _run_salt_command(self, cmd: List[str]) -> Dict:
        """Execute Salt command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config.salt_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.config.timeout
            )
            
            return {
                "success": process.returncode == 0,
                "return_code": process.returncode,
                "output": stdout.decode('utf-8') if stdout else "",
                "error": stderr.decode('utf-8') if stderr else "",
                "command": " ".join(cmd)
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": f"Command timed out after {self.config.timeout} seconds",
                "command": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": str(e),
                "command": " ".join(cmd)
            }

class SaltExecutionManager:
    """Manages Salt execution modules"""
    
    def __init__(self, config: SaltConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.SaltExecutionManager")
    
    async def execute_module(self, target: str, module: str, function: str, args: List[str] = None) -> Dict:
        """Execute Salt module function on target"""
        cmd = ["salt", target, f"{module}.{function}"]
        
        if args:
            cmd.extend(args)
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def run_command(self, target: str, command: str) -> Dict:
        """Run shell command on target minions"""
        cmd = ["salt", target, "cmd.run", command]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def copy_file(self, target: str, source: str, destination: str) -> Dict:
        """Copy file to target minions"""
        cmd = ["salt", target, "cp.get_file", source, destination]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def install_package(self, target: str, package: str, version: str = None) -> Dict:
        """Install package on target minions"""
        if version:
            cmd = ["salt", target, "pkg.install", f"{package}={version}"]
        else:
            cmd = ["salt", target, "pkg.install", package]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def service_status(self, target: str, service: str) -> Dict:
        """Check service status on target minions"""
        cmd = ["salt", target, "service.status", service]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def manage_service(self, target: str, service: str, action: str) -> Dict:
        """Manage service on target minions (start, stop, restart, reload)"""
        valid_actions = ["start", "stop", "restart", "reload", "enable", "disable"]
        if action not in valid_actions:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": f"Invalid action '{action}'. Valid actions: {valid_actions}",
                "command": ""
            }
        
        cmd = ["salt", target, f"service.{action}", service]
        
        if self.config.ssh_mode:
            cmd = ["salt-ssh"] + cmd[1:]
        
        return await self._run_salt_command(cmd)
    
    async def _run_salt_command(self, cmd: List[str]) -> Dict:
        """Execute Salt command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config.salt_dir
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(), 
                timeout=self.config.timeout
            )
            
            return {
                "success": process.returncode == 0,
                "return_code": process.returncode,
                "output": stdout.decode('utf-8') if stdout else "",
                "error": stderr.decode('utf-8') if stderr else "",
                "command": " ".join(cmd)
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": f"Command timed out after {self.config.timeout} seconds",
                "command": " ".join(cmd)
            }
        except Exception as e:
            return {
                "success": False,
                "return_code": -1,
                "output": "",
                "error": str(e),
                "command": " ".join(cmd)
            }

class SaltPlugin:
    """Main Salt plugin class with enterprise security hardening"""

    def __init__(self, config: Dict):
        self.config = self._parse_config(config)
        self.state_manager = SaltStateManager(self.config)
        self.minion_manager = SaltMinionManager(self.config)
        self.pillar_manager = SaltPillarManager(self.config)
        self.execution_manager = SaltExecutionManager(self.config)
        self.logger = logging.getLogger(f"{__name__}.SaltPlugin")

        # Universal Input Sanitizer availability check
        self.sanitizer_available = pp is not None
        if self.sanitizer_available:
            try:
                # Test sanitizer availability
                test_result = pp("universal_input_sanitizer", action="health_check")
                self.sanitizer_available = test_result.get("success", False)
            except Exception:
                self.sanitizer_available = False

        self.logger.info(f"Universal Input Sanitizer available: {self.sanitizer_available}")
    
    def _parse_config(self, config: Dict) -> SaltConfig:
        """Parse configuration dictionary into SaltConfig with validation"""
        try:
            return SaltConfig(
                master_host=config.get("master_host", "localhost"),
                master_port=config.get("master_port", 4506),
                salt_dir=config.get("salt_dir", "/etc/salt"),
                pillar_root=config.get("pillar_root", "/srv/pillar"),
                state_root=config.get("state_root", "/srv/salt"),
                timeout=config.get("timeout", 300),
                ssh_mode=config.get("ssh_mode", False),
                ssh_user=config.get("ssh_user", "root"),
                ssh_key_path=config.get("ssh_key_path", ""),
                roster_file=config.get("roster_file", "/etc/salt/roster")
            )
        except ValueError as e:
            raise ValueError(f"Configuration validation failed: {e}")

    async def _sanitize_input(self, data: Any) -> ValidationResult:
        """Sanitize input using Universal Input Sanitizer with comprehensive validation"""
        try:
            # Check sanitizer availability
            if self.sanitizer_available:
                # Use Universal Input Sanitizer
                sanitizer_result = pp(
                    "universal_input_sanitizer",
                    action="sanitize",
                    input_data=data
                )

                if not sanitizer_result.get("success", False):
                    return ValidationResult(
                        is_valid=False,
                        security_violations=[sanitizer_result.get("error", "Sanitization failed")]
                    )

                return ValidationResult(
                    is_valid=True,
                    sanitized_data=sanitizer_result.get("sanitized_data", data)
                )
            else:
                # Fallback comprehensive validation
                return self._fallback_security_validation(data)

        except Exception as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"Input sanitization error: {str(e)}"]
            )

    def _fallback_security_validation(self, data: Any) -> ValidationResult:
        """Comprehensive fallback validation when Universal Input Sanitizer unavailable"""
        violations = []
        warnings = []

        def check_data_recursive(obj, path=""):
            if isinstance(obj, dict):
                for key, value in obj.items():
                    current_path = f"{path}.{key}" if path else key
                    check_data_recursive(value, current_path)
            elif isinstance(obj, list):
                for i, item in enumerate(obj):
                    current_path = f"{path}[{i}]"
                    check_data_recursive(item, current_path)
            elif isinstance(obj, str):
                # Check for dangerous patterns
                dangerous_patterns = [
                    r';\s*rm\s+-rf',
                    r'<script[^>]*>',
                    r'system\s*\(',
                    r'\$\([^)]*\)',
                    r'`[^`]*`',
                    r'\|\s*nc\s+-l',
                    r'&&\s*(rm|del|shutdown)',
                    r'\\\.\./',
                    r'\.\./.*\.\./'
                ]

                for pattern in dangerous_patterns:
                    if re.search(pattern, obj, re.IGNORECASE):
                        violations.append(f"Dangerous pattern detected at {path}: {pattern}")

                # Check for Salt-specific security patterns
                salt_security_patterns = [
                    r'salt.*master.*key',
                    r'salt.*secret',
                    r'pillar.*password',
                    r'ssh.*private.*key'
                ]

                for pattern in salt_security_patterns:
                    if re.search(pattern, obj, re.IGNORECASE):
                        violations.append(f"Salt security violation at {path}: potential credential exposure")

        check_data_recursive(data)

        return ValidationResult(
            is_valid=len(violations) == 0,
            warnings=warnings,
            security_violations=violations
        )

    def _sanitize_salt_arguments(self, args: List[str]) -> List[str]:
        """Sanitize Salt command arguments to prevent injection"""
        sanitized_args = []
        dangerous_patterns = [
            ';', '|', '&', '$(', '`', '>', '<',
            '&&', '||', '\n', '\r', 'rm -rf', 'sudo su',
            'nc -l', 'netcat', 'curl http', 'wget http',
            'shutdown', 'reboot', '/etc/passwd', '/etc/shadow'
        ]

        for arg in args:
            # Check for dangerous patterns
            if any(pattern in str(arg) for pattern in dangerous_patterns):
                self.logger.warning(f"Dangerous Salt argument blocked: {arg}")
                continue  # Skip dangerous arguments

            # Escape shell metacharacters
            sanitized_arg = shlex.quote(str(arg))
            sanitized_args.append(sanitized_arg)

        return sanitized_args

    def _create_error_response(self, errors: List[str], operation: str = "") -> Dict:
        """Create standardized error response"""
        return {
            "success": False,
            "status": "error",
            "error": "Input validation failed: " + "; ".join(errors),
            "operation": operation,
            "available_operations": [
                "apply_state", "test_state", "highstate", "list_states",
                "list_minions", "accept_key", "delete_key", "list_keys",
                "get_grains", "set_grains", "get_pillar", "refresh_pillar",
                "execute_module", "run_command", "copy_file", "install_package",
                "service_status", "manage_service"
            ],
            "timestamp": datetime.now().isoformat()
        }

    def _sanitize_error_message(self, error_msg: str) -> str:
        """Sanitize error messages to prevent credential leakage"""
        sensitive_patterns = [
            (r'password[^\s]*\s*[=:]\s*[^\s]+', 'password=[REDACTED]'),
            (r'secret[^\s]*\s*[=:]\s*[^\s]+', 'secret=[REDACTED]'),
            (r'key[^\s]*\s*[=:]\s*[^\s]+', 'key=[REDACTED]'),
            (r'token[^\s]*\s*[=:]\s*[^\s]+', 'token=[REDACTED]'),
            (r'auth[^\s]*\s*[=:]\s*[^\s]+', 'auth=[REDACTED]')
        ]

        sanitized = error_msg
        for pattern, replacement in sensitive_patterns:
            sanitized = re.sub(pattern, replacement, sanitized, flags=re.IGNORECASE)

        # Add generic message for potentially sensitive errors
        if any(keyword in error_msg.lower() for keyword in ['password', 'secret', 'key', 'token', 'ssl']):
            sanitized = "Salt operation failed - sensitive information redacted. Check Salt logs for details."

        return sanitized

    def _is_dangerous_command(self, command: str) -> bool:
        """Check if command contains dangerous patterns"""
        dangerous_patterns = [
            r'rm\s+-rf',
            r'shutdown',
            r'reboot',
            r'halt',
            r'init\s+0',
            r'>/etc/',
            r'cat\s+/etc/passwd',
            r'cat\s+/etc/shadow',
            r'curl\s+.*\|\s*sh',
            r'wget\s+.*\|\s*sh',
            r'nc\s+-l',
            r'netcat\s+-l',
            r'dd\s+if=',
            r'mkfs\.',
            r'fdisk',
            r'parted',
            r'crontab\s+-r'
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    async def process(self, ctx: Dict, cfg: Dict) -> Dict:
        """Main plugin processing function with comprehensive security validation"""
        operation = cfg.get("operation", "")
        target = cfg.get("target", "*")

        start_time = datetime.now()

        # Input validation and sanitization
        validation_result = await self._sanitize_input(cfg)
        if not validation_result.is_valid:
            return self._create_error_response(validation_result.security_violations, operation)

        # Use sanitized configuration
        sanitized_config = validation_result.sanitized_data or cfg

        # Validate operation
        valid_operations = [
            "apply_state", "test_state", "highstate", "list_states",
            "list_minions", "accept_key", "delete_key", "list_keys",
            "get_grains", "set_grains", "get_pillar", "refresh_pillar",
            "execute_module", "run_command", "copy_file", "install_package",
            "service_status", "manage_service"
        ]

        if operation not in valid_operations:
            return {
                "success": False,
                "status": "error",
                "message": f"Unknown operation: {operation}",
                "available_operations": valid_operations,
                "timestamp": datetime.now().isoformat()
            }

        try:
            if operation == "apply_state":
                state = sanitized_config.get("state", "")
                pillar_data = sanitized_config.get("pillar_data", {})
                result = await self.state_manager.apply_state(target, state, pillar_data)
                
            elif operation == "test_state":
                state = sanitized_config.get("state", "")
                pillar_data = sanitized_config.get("pillar_data", {})
                result = await self.state_manager.test_state(target, state, pillar_data)
                
            elif operation == "highstate":
                result = await self.state_manager.highstate(target)
                
            elif operation == "list_states":
                states = await self.state_manager.list_states()
                result = {"success": True, "states": states}
                
            elif operation == "list_minions":
                status = sanitized_config.get("status", "up")
                minions = await self.minion_manager.list_minions(status)
                result = {"success": True, "minions": minions}
                
            elif operation == "accept_key":
                minion_id = sanitized_config.get("minion_id", "")
                result = await self.minion_manager.accept_key(minion_id)
                
            elif operation == "delete_key":
                minion_id = sanitized_config.get("minion_id", "")
                result = await self.minion_manager.delete_key(minion_id)
                
            elif operation == "list_keys":
                keys = await self.minion_manager.list_keys()
                result = {"success": True, "keys": keys}
                
            elif operation == "get_grains":
                grain = sanitized_config.get("grain")
                grains = await self.minion_manager.get_grains(target, grain)
                result = {"success": True, "grains": grains}
                
            elif operation == "set_grains":
                grain = sanitized_config.get("grain", "")
                value = sanitized_config.get("value", "")
                result = await self.minion_manager.set_grains(target, grain, value)
                
            elif operation == "get_pillar":
                key = sanitized_config.get("key")
                pillar = await self.pillar_manager.get_pillar(target, key)
                result = {"success": True, "pillar": pillar}
                
            elif operation == "refresh_pillar":
                result = await self.pillar_manager.refresh_pillar(target)
                
            elif operation == "execute_module":
                module = sanitized_config.get("module", "")
                function = sanitized_config.get("function", "")
                args = sanitized_config.get("args", [])
                # Sanitize arguments for security
                sanitized_args = self._sanitize_salt_arguments(args)
                result = await self.execution_manager.execute_module(target, module, function, sanitized_args)
                
            elif operation == "run_command":
                command = sanitized_config.get("command", "")
                # Additional validation for dangerous commands
                if self._is_dangerous_command(command):
                    result = {
                        "success": False,
                        "error": "Dangerous command blocked by security policy",
                        "command": command
                    }
                else:
                    result = await self.execution_manager.run_command(target, command)
                
            elif operation == "copy_file":
                source = sanitized_config.get("source", "")
                destination = sanitized_config.get("destination", "")
                result = await self.execution_manager.copy_file(target, source, destination)
                
            elif operation == "install_package":
                package = sanitized_config.get("package", "")
                version = sanitized_config.get("version")
                result = await self.execution_manager.install_package(target, package, version)
                
            elif operation == "service_status":
                service = sanitized_config.get("service", "")
                result = await self.execution_manager.service_status(target, service)
                
            elif operation == "manage_service":
                service = sanitized_config.get("service", "")
                action = sanitized_config.get("action", "")
                result = await self.execution_manager.manage_service(target, service, action)
                
            else:
                result = {
                    "success": False,
                    "error": f"Unknown operation: {operation}",
                    "available_operations": [
                        "apply_state", "test_state", "highstate", "list_states",
                        "list_minions", "accept_key", "delete_key", "list_keys",
                        "get_grains", "set_grains", "get_pillar", "refresh_pillar",
                        "execute_module", "run_command", "copy_file", "install_package",
                        "service_status", "manage_service"
                    ]
                }
            
            # Add execution metadata
            execution_time = (datetime.now() - start_time).total_seconds()
            result.update({
                "operation": operation,
                "target": target,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
                "salt_config": {
                    "master_host": self.config.master_host,
                    "ssh_mode": self.config.ssh_mode,
                    "timeout": self.config.timeout
                }
            })
            
            return result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Salt operation failed: {e}")
            sanitized_error = self._sanitize_error_message(str(e))
            return {
                "success": False,
                "operation": operation,
                "target": target,
                "error": sanitized_error,
                "error_type": type(e).__name__,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
                "error_details": {
                    "error_type": "SaltOperationError",
                    "suggested_fix": "Check Salt configuration and target connectivity",
                    "documentation_link": "https://docs.saltproject.io/en/latest/"
                }
            }

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "salt",
    "version": "1.0.0",
    "description": "Salt Stack configuration management and orchestration plugin",
    "author": "PlugPipe Team",
    "category": "configuration",
    "tags": ["salt", "configuration", "orchestration", "infrastructure", "automation"],
    "requirements": ["salt-master", "salt-minion", "salt-ssh"],
    "supports_async": True
}

# Main process function for PlugPipe
async def process(ctx: Dict, cfg: Dict) -> Dict:
    """PlugPipe entry point for Salt plugin with security validation"""
    try:
        plugin = SaltPlugin(cfg)
        return await plugin.process(ctx, cfg)
    except ValueError as e:
        # Configuration validation failed
        return {
            "success": False,
            "status": "error",
            "error": f"Configuration validation failed: {str(e)}",
            "error_details": {
                "error_type": "ConfigurationError",
                "suggested_fix": "Check Salt configuration parameters for security compliance",
                "documentation_link": "https://docs.saltproject.io/en/latest/ref/configuration/"
            },
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        # Unexpected initialization error
        return {
            "success": False,
            "status": "error",
            "error": f"Salt plugin initialization failed: {str(e)}",
            "error_details": {
                "error_type": "InitializationError",
                "suggested_fix": "Check Salt installation and plugin dependencies",
                "documentation_link": "https://docs.saltproject.io/en/latest/topics/installation/"
            },
            "timestamp": datetime.now().isoformat()
        }