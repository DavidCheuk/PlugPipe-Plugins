# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Ansible Configuration Management Plugin for PlugPipe

This plugin provides comprehensive Ansible automation capabilities including
playbook execution, inventory management, role management, ad-hoc commands,
vault integration, and AWX/Tower integration support.
"""

import asyncio
import json
import logging
import os
import subprocess
import tempfile
import yaml
import re
import shlex
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional, Any, Union
from dataclasses import dataclass

# PlugPipe pp function for dynamic plugin discovery
try:
    from shares.loader import pp
except ImportError:
    def pp(plugin_name: str, **kwargs) -> Dict[str, Any]:
        return {"success": False, "error": "Plugin loader not available"}

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@dataclass
class ValidationResult:
    """Result of input validation with security context"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    security_violations: List[str]
    sanitized_data: Optional[Dict[str, Any]] = None

@dataclass
class AnsibleConfig:
    """Ansible configuration settings with security validation"""
    inventory_path: str = "/etc/ansible/hosts"
    playbook_path: str = "/etc/ansible/playbooks"
    roles_path: str = "/etc/ansible/roles"
    vault_password_file: str = ""
    private_key_file: str = ""
    remote_user: str = "root"
    become: bool = True
    become_method: str = "sudo"
    become_user: str = "root"
    host_key_checking: bool = False
    timeout: int = 1800
    forks: int = 5
    verbosity: int = 0
    check_mode: bool = False
    diff_mode: bool = False
    ask_vault_pass: bool = False
    vault_id: str = ""
    galaxy_server_url: str = "https://galaxy.ansible.com"
    collections_paths: List[str] = None

    def __post_init__(self):
        if self.collections_paths is None:
            self.collections_paths = ["/etc/ansible/collections"]
        # Validate configuration for security
        self._validate_config()

    def _validate_config(self):
        """Validate configuration for security issues"""
        # Validate paths to prevent path traversal
        paths_to_check = [self.inventory_path, self.playbook_path, self.roles_path]
        if self.vault_password_file:
            paths_to_check.append(self.vault_password_file)
        if self.private_key_file:
            paths_to_check.append(self.private_key_file)

        for path in paths_to_check:
            if path and ("../" in path or "..\\" in path):
                raise ValueError(f"Path traversal attempt detected in: {path}")

        # Validate become method
        allowed_become_methods = ["sudo", "su", "pbrun", "pfexec", "doas", "dzdo", "ksu"]
        if self.become_method not in allowed_become_methods:
            raise ValueError(f"Invalid become method: {self.become_method}")

        # Validate timeout
        if self.timeout < 1 or self.timeout > 7200:  # Max 2 hours
            raise ValueError(f"Invalid timeout: {self.timeout}")

        # Validate verbosity
        if self.verbosity < 0 or self.verbosity > 4:
            raise ValueError(f"Invalid verbosity level: {self.verbosity}")

class AnsiblePlaybookManager:
    """Manages Ansible playbook operations"""
    
    def __init__(self, config: AnsibleConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.AnsiblePlaybookManager")
    
    async def run_playbook(self, playbook_name: str, inventory: str = None, 
                          extra_vars: Dict = None, tags: List[str] = None,
                          skip_tags: List[str] = None, limit: str = None) -> Dict:
        """Run Ansible playbook"""
        playbook_path = os.path.join(self.config.playbook_path, playbook_name)
        if not os.path.exists(playbook_path):
            playbook_path = playbook_name  # Use as absolute path
        
        cmd = ["ansible-playbook", playbook_path]
        
        # Inventory
        if inventory:
            cmd.extend(["-i", inventory])
        elif self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        # Extra variables
        if extra_vars:
            cmd.extend(["--extra-vars", json.dumps(extra_vars)])
        
        # Tags
        if tags:
            cmd.extend(["--tags", ",".join(tags)])
        
        if skip_tags:
            cmd.extend(["--skip-tags", ",".join(skip_tags)])
        
        # Limit hosts
        if limit:
            cmd.extend(["--limit", limit])
        
        # Authentication and privilege escalation
        if self.config.remote_user:
            cmd.extend(["-u", self.config.remote_user])
        
        if self.config.private_key_file:
            cmd.extend(["--private-key", self.config.private_key_file])
        
        if self.config.become:
            cmd.append("--become")
            cmd.extend(["--become-method", self.config.become_method])
            cmd.extend(["--become-user", self.config.become_user])
        
        # Vault
        if self.config.vault_password_file:
            cmd.extend(["--vault-password-file", self.config.vault_password_file])
        elif self.config.ask_vault_pass:
            cmd.append("--ask-vault-pass")
        
        # Other options
        if self.config.check_mode:
            cmd.append("--check")
        
        if self.config.diff_mode:
            cmd.append("--diff")
        
        if self.config.forks != 5:
            cmd.extend(["-f", str(self.config.forks)])
        
        if self.config.verbosity > 0:
            cmd.append("-" + "v" * min(self.config.verbosity, 4))

        # Sanitize command arguments
        cmd = self._sanitize_command_arguments(cmd)

        return await self._run_ansible_command(cmd)
    
    async def check_playbook_syntax(self, playbook_name: str) -> Dict:
        """Check playbook syntax with security validation"""
        # Validate input
        validation_result = await self._sanitize_input({"playbook_name": playbook_name})
        if not validation_result.is_valid:
            return {
                "success": False,
                "error": "Input validation failed",
                "security_violations": validation_result.security_violations
            }

        # Validate playbook path
        if not playbook_name or '../' in playbook_name:
            return {
                "success": False,
                "error": "Invalid playbook name - path traversal detected"
            }

        playbook_path = os.path.join(self.config.playbook_path, playbook_name)
        if not os.path.exists(playbook_path):
            if os.path.isabs(playbook_name):
                allowed_dirs = [self.config.playbook_path, "/opt/ansible/playbooks"]
                if not any(playbook_name.startswith(allowed_dir) for allowed_dir in allowed_dirs):
                    return {"success": False, "error": "Playbook path not in allowed directories"}
                playbook_path = playbook_name
            else:
                return {"success": False, "error": f"Playbook not found: {playbook_name}"}

        cmd = ["ansible-playbook", "--syntax-check", playbook_path]

        if self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])

        cmd = self._sanitize_command_arguments(cmd)
        return await self._run_ansible_command(cmd)
    
    async def list_tasks(self, playbook_name: str) -> Dict:
        """List tasks in playbook"""
        playbook_path = os.path.join(self.config.playbook_path, playbook_name)
        if not os.path.exists(playbook_path):
            playbook_path = playbook_name
        
        cmd = ["ansible-playbook", "--list-tasks", playbook_path]
        
        if self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        return await self._run_ansible_command(cmd)
    
    async def list_hosts(self, playbook_name: str) -> Dict:
        """List hosts that would be affected by playbook"""
        playbook_path = os.path.join(self.config.playbook_path, playbook_name)
        if not os.path.exists(playbook_path):
            playbook_path = playbook_name
        
        cmd = ["ansible-playbook", "--list-hosts", playbook_path]
        
        if self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        return await self._run_ansible_command(cmd)
    
    async def _run_ansible_command(self, cmd: List[str]) -> Dict:
        """Execute Ansible command and return structured result"""
        try:
            env = os.environ.copy()
            env["ANSIBLE_HOST_KEY_CHECKING"] = "False" if not self.config.host_key_checking else "True"
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
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

class AnsibleInventoryManager:
    """Manages Ansible inventory operations"""
    
    def __init__(self, config: AnsibleConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.AnsibleInventoryManager")
    
    async def list_hosts(self, inventory: str = None, pattern: str = "all") -> Dict:
        """List hosts from inventory"""
        cmd = ["ansible", pattern, "--list-hosts"]
        
        if inventory:
            cmd.extend(["-i", inventory])
        elif self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        return await self._run_ansible_command(cmd)
    
    async def list_groups(self, inventory: str = None) -> Dict:
        """List groups from inventory"""
        cmd = ["ansible-inventory", "--list"]
        
        if inventory:
            cmd.extend(["-i", inventory])
        elif self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        return await self._run_ansible_command(cmd)
    
    async def get_host_vars(self, hostname: str, inventory: str = None) -> Dict:
        """Get variables for specific host"""
        cmd = ["ansible-inventory", "--host", hostname]
        
        if inventory:
            cmd.extend(["-i", inventory])
        elif self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        return await self._run_ansible_command(cmd)
    
    async def ping_hosts(self, pattern: str = "all", inventory: str = None) -> Dict:
        """Ping hosts to check connectivity"""
        cmd = ["ansible", pattern, "-m", "ping"]
        
        if inventory:
            cmd.extend(["-i", inventory])
        elif self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        if self.config.remote_user:
            cmd.extend(["-u", self.config.remote_user])
        
        if self.config.private_key_file:
            cmd.extend(["--private-key", self.config.private_key_file])
        
        return await self._run_ansible_command(cmd)
    
    async def gather_facts(self, pattern: str = "all", inventory: str = None) -> Dict:
        """Gather facts from hosts"""
        cmd = ["ansible", pattern, "-m", "setup"]
        
        if inventory:
            cmd.extend(["-i", inventory])
        elif self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        if self.config.remote_user:
            cmd.extend(["-u", self.config.remote_user])
        
        if self.config.private_key_file:
            cmd.extend(["--private-key", self.config.private_key_file])
        
        if self.config.become:
            cmd.append("--become")
        
        return await self._run_ansible_command(cmd)
    
    async def _run_ansible_command(self, cmd: List[str]) -> Dict:
        """Execute Ansible command and return structured result"""
        try:
            env = os.environ.copy()
            env["ANSIBLE_HOST_KEY_CHECKING"] = "False" if not self.config.host_key_checking else "True"
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
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

class AnsibleModuleManager:
    """Manages Ansible ad-hoc module execution"""
    
    def __init__(self, config: AnsibleConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.AnsibleModuleManager")
    
    async def run_module(self, pattern: str, module_name: str, module_args: str = "",
                        inventory: str = None, become: bool = None) -> Dict:
        """Run Ansible module on hosts"""
        cmd = ["ansible", pattern, "-m", module_name]
        
        if module_args:
            cmd.extend(["-a", module_args])
        
        if inventory:
            cmd.extend(["-i", inventory])
        elif self.config.inventory_path:
            cmd.extend(["-i", self.config.inventory_path])
        
        if self.config.remote_user:
            cmd.extend(["-u", self.config.remote_user])
        
        if self.config.private_key_file:
            cmd.extend(["--private-key", self.config.private_key_file])
        
        # Use parameter become if provided, otherwise use config
        use_become = become if become is not None else self.config.become
        if use_become:
            cmd.append("--become")
            cmd.extend(["--become-method", self.config.become_method])
            cmd.extend(["--become-user", self.config.become_user])
        
        if self.config.vault_password_file:
            cmd.extend(["--vault-password-file", self.config.vault_password_file])
        
        if self.config.forks != 5:
            cmd.extend(["-f", str(self.config.forks)])
        
        return await self._run_ansible_command(cmd)
    
    async def copy_file(self, pattern: str, src: str, dest: str, 
                       inventory: str = None, owner: str = None, mode: str = None) -> Dict:
        """Copy file to hosts using copy module"""
        args = f"src={src} dest={dest}"
        if owner:
            args += f" owner={owner}"
        if mode:
            args += f" mode={mode}"
        
        return await self.run_module(pattern, "copy", args, inventory, True)
    
    async def install_package(self, pattern: str, package: str, state: str = "present",
                             inventory: str = None) -> Dict:
        """Install package on hosts"""
        # Detect package manager based on target system
        # This is a simplified approach - in practice, you'd detect the OS
        args = f"name={package} state={state}"
        
        return await self.run_module(pattern, "package", args, inventory, True)
    
    async def manage_service(self, pattern: str, service: str, state: str = "started",
                            enabled: bool = None, inventory: str = None) -> Dict:
        """Manage service on hosts"""
        args = f"name={service} state={state}"
        if enabled is not None:
            args += f" enabled={'yes' if enabled else 'no'}"
        
        return await self.run_module(pattern, "service", args, inventory, True)
    
    async def run_command(self, pattern: str, command: str, inventory: str = None) -> Dict:
        """Run shell command on hosts with security validation"""
        # Validate command for dangerous operations
        validation_result = await self._sanitize_input({
            "pattern": pattern,
            "command": command,
            "inventory": inventory
        })

        if not validation_result.is_valid:
            return {
                "success": False,
                "error": "Command validation failed - potentially dangerous command blocked",
                "security_violations": validation_result.security_violations
            }

        # Additional command validation - block obviously dangerous commands
        dangerous_commands = [
            'rm -rf', 'dd if=', 'mkfs', 'fdisk', 'format',
            'shutdown', 'reboot', 'halt', 'init 0', 'init 6',
            'passwd', 'useradd', 'userdel', 'chmod 777',
            'curl http', 'wget http', 'nc -l', 'netcat -l'
        ]

        if any(dangerous_cmd in command.lower() for dangerous_cmd in dangerous_commands):
            return {
                "success": False,
                "error": "Command blocked - contains dangerous operations",
                "blocked_command": command[:100]
            }

        return await self.run_module(pattern, "shell", command, inventory, True)
    
    async def _run_ansible_command(self, cmd: List[str]) -> Dict:
        """Execute Ansible command and return structured result"""
        try:
            env = os.environ.copy()
            env["ANSIBLE_HOST_KEY_CHECKING"] = "False" if not self.config.host_key_checking else "True"
            
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
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

class AnsibleRoleManager:
    """Manages Ansible roles and Galaxy operations"""
    
    def __init__(self, config: AnsibleConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.AnsibleRoleManager")
    
    async def install_role(self, role_name: str, version: str = None, 
                          force: bool = False) -> Dict:
        """Install role from Ansible Galaxy"""
        cmd = ["ansible-galaxy", "role", "install", role_name]
        
        if version:
            cmd.extend(["--version", version])
        
        if force:
            cmd.append("--force")
        
        cmd.extend(["--roles-path", self.config.roles_path])
        
        return await self._run_ansible_command(cmd)
    
    async def install_collection(self, collection_name: str, version: str = None,
                                force: bool = False) -> Dict:
        """Install collection from Ansible Galaxy"""
        cmd = ["ansible-galaxy", "collection", "install", collection_name]
        
        if version:
            cmd.extend(["--version", version])
        
        if force:
            cmd.append("--force")
        
        if self.config.collections_paths:
            cmd.extend(["--collections-path", self.config.collections_paths[0]])
        
        return await self._run_ansible_command(cmd)
    
    async def list_roles(self) -> Dict:
        """List installed roles"""
        cmd = ["ansible-galaxy", "role", "list", "--roles-path", self.config.roles_path]
        
        return await self._run_ansible_command(cmd)
    
    async def list_collections(self) -> Dict:
        """List installed collections"""
        cmd = ["ansible-galaxy", "collection", "list"]
        
        if self.config.collections_paths:
            cmd.extend(["--collections-path", self.config.collections_paths[0]])
        
        return await self._run_ansible_command(cmd)
    
    async def remove_role(self, role_name: str) -> Dict:
        """Remove installed role"""
        cmd = ["ansible-galaxy", "role", "remove", role_name, "--roles-path", self.config.roles_path]
        
        return await self._run_ansible_command(cmd)
    
    async def search_roles(self, search_term: str) -> Dict:
        """Search for roles in Galaxy"""
        cmd = ["ansible-galaxy", "role", "search", search_term]
        
        return await self._run_ansible_command(cmd)
    
    async def search_collections(self, search_term: str) -> Dict:
        """Search for collections in Galaxy"""
        cmd = ["ansible-galaxy", "collection", "search", search_term]
        
        return await self._run_ansible_command(cmd)
    
    async def _run_ansible_command(self, cmd: List[str]) -> Dict:
        """Execute Ansible command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
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

class AnsiblePlugin:
    """Main Ansible plugin class"""
    
    def __init__(self, config: Dict):
        self.config = self._parse_config(config)
        self.playbook_manager = AnsiblePlaybookManager(self.config)
        self.inventory_manager = AnsibleInventoryManager(self.config)
        self.module_manager = AnsibleModuleManager(self.config)
        self.role_manager = AnsibleRoleManager(self.config)
        self.logger = logging.getLogger(f"{__name__}.AnsiblePlugin")
    
    def _parse_config(self, config: Dict) -> AnsibleConfig:
        """Parse configuration dictionary into AnsibleConfig"""
        return AnsibleConfig(
            inventory_path=config.get("inventory_path", "/etc/ansible/hosts"),
            playbook_path=config.get("playbook_path", "/etc/ansible/playbooks"),
            roles_path=config.get("roles_path", "/etc/ansible/roles"),
            vault_password_file=config.get("vault_password_file", ""),
            private_key_file=config.get("private_key_file", ""),
            remote_user=config.get("remote_user", "root"),
            become=config.get("become", True),
            become_method=config.get("become_method", "sudo"),
            become_user=config.get("become_user", "root"),
            host_key_checking=config.get("host_key_checking", False),
            timeout=config.get("timeout", 1800),
            forks=config.get("forks", 5),
            verbosity=config.get("verbosity", 0),
            check_mode=config.get("check_mode", False),
            diff_mode=config.get("diff_mode", False),
            ask_vault_pass=config.get("ask_vault_pass", False),
            vault_id=config.get("vault_id", ""),
            galaxy_server_url=config.get("galaxy_server_url", "https://galaxy.ansible.com"),
            collections_paths=config.get("collections_paths", ["/etc/ansible/collections"])
        )
    
    def _check_sanitizer_availability(self) -> bool:
        """Check if Universal Input Sanitizer is available"""
        try:
            result = pp("universal_input_sanitizer", action="health_check")
            return result.get("success", False)
        except Exception as e:
            logger.warning(f"Universal Input Sanitizer not available: {e}")
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
            if hasattr(self, 'sanitizer_available') and self.sanitizer_available:
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
            logger.error(f"Input sanitization error: {e}")
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
                r'</?.*(script|iframe|object)',  # Script injection
                r'(exec|eval|system|shell_exec)\s*\(',  # Code execution
                r'/etc/(passwd|shadow|hosts)',  # Sensitive file access
                r'(curl|wget|nc)\s+.*\.(com|org|net)',  # External communication
                r'(shutdown|reboot|halt)\s',  # System control
                r'ansible_become_pass',  # Ansible password exposure
                r'vault_pass',  # Vault password exposure
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

    async def process(self, ctx: Dict, cfg: Dict) -> Dict:
        """Main plugin processing function with comprehensive security validation"""
        # Comprehensive input validation and sanitization
        input_validation = await self._sanitize_input({"ctx": ctx, "cfg": cfg})
        if not input_validation.is_valid:
            return {
                'status': 'error',
                'message': 'Input validation failed',
                'errors': input_validation.errors,
                'security_violations': input_validation.security_violations
            }

        operation = cfg.get("operation", "")

        # Validate operation
        valid_operations = [
            "run_playbook", "check_syntax", "list_tasks", "list_hosts", "list_groups",
            "get_host_vars", "ping_hosts", "gather_facts", "run_module", "copy_file",
            "install_package", "manage_service", "run_command", "install_role",
            "install_collection", "list_roles", "list_collections", "remove_role",
            "search_roles", "search_collections"
        ]

        if operation not in valid_operations:
            return {
                'status': 'error',
                'message': f'Unknown operation: {operation}',
                'available_operations': valid_operations
            }

        start_time = datetime.now()

        # Check sanitizer availability once per process call
        self.sanitizer_available = self._check_sanitizer_availability()

        try:
            if operation == "run_playbook":
                playbook_name = cfg.get("playbook_name", "")
                inventory = cfg.get("inventory")
                extra_vars = cfg.get("extra_vars", {})
                tags = cfg.get("tags")
                skip_tags = cfg.get("skip_tags")
                limit = cfg.get("limit")
                result = await self.playbook_manager.run_playbook(
                    playbook_name, inventory, extra_vars, tags, skip_tags, limit
                )
                
            elif operation == "check_syntax":
                playbook_name = cfg.get("playbook_name", "")
                result = await self.playbook_manager.check_playbook_syntax(playbook_name)
                
            elif operation == "list_tasks":
                playbook_name = cfg.get("playbook_name", "")
                result = await self.playbook_manager.list_tasks(playbook_name)
                
            elif operation == "list_hosts":
                if cfg.get("playbook_name"):
                    result = await self.playbook_manager.list_hosts(cfg["playbook_name"])
                else:
                    inventory = cfg.get("inventory")
                    pattern = cfg.get("pattern", "all")
                    result = await self.inventory_manager.list_hosts(inventory, pattern)
                
            elif operation == "list_groups":
                inventory = cfg.get("inventory")
                result = await self.inventory_manager.list_groups(inventory)
                
            elif operation == "get_host_vars":
                hostname = cfg.get("hostname", "")
                inventory = cfg.get("inventory")
                result = await self.inventory_manager.get_host_vars(hostname, inventory)
                
            elif operation == "ping_hosts":
                pattern = cfg.get("pattern", "all")
                inventory = cfg.get("inventory")
                result = await self.inventory_manager.ping_hosts(pattern, inventory)
                
            elif operation == "gather_facts":
                pattern = cfg.get("pattern", "all")
                inventory = cfg.get("inventory")
                result = await self.inventory_manager.gather_facts(pattern, inventory)
                
            elif operation == "run_module":
                pattern = cfg.get("pattern", "all")
                module_name = cfg.get("module_name", "")
                module_args = cfg.get("module_args", "")
                inventory = cfg.get("inventory")
                become = cfg.get("become")
                result = await self.module_manager.run_module(
                    pattern, module_name, module_args, inventory, become
                )
                
            elif operation == "copy_file":
                pattern = cfg.get("pattern", "all")
                src = cfg.get("src", "")
                dest = cfg.get("dest", "")
                inventory = cfg.get("inventory")
                owner = cfg.get("owner")
                mode = cfg.get("mode")
                result = await self.module_manager.copy_file(
                    pattern, src, dest, inventory, owner, mode
                )
                
            elif operation == "install_package":
                pattern = cfg.get("pattern", "all")
                package = cfg.get("package", "")
                state = cfg.get("state", "present")
                inventory = cfg.get("inventory")
                result = await self.module_manager.install_package(
                    pattern, package, state, inventory
                )
                
            elif operation == "manage_service":
                pattern = cfg.get("pattern", "all")
                service = cfg.get("service", "")
                state = cfg.get("state", "started")
                enabled = cfg.get("enabled")
                inventory = cfg.get("inventory")
                result = await self.module_manager.manage_service(
                    pattern, service, state, enabled, inventory
                )
                
            elif operation == "run_command":
                pattern = cfg.get("pattern", "all")
                command = cfg.get("command", "")
                inventory = cfg.get("inventory")
                result = await self.module_manager.run_command(pattern, command, inventory)
                
            elif operation == "install_role":
                role_name = cfg.get("role_name", "")
                version = cfg.get("version")
                force = cfg.get("force", False)
                result = await self.role_manager.install_role(role_name, version, force)
                
            elif operation == "install_collection":
                collection_name = cfg.get("collection_name", "")
                version = cfg.get("version")
                force = cfg.get("force", False)
                result = await self.role_manager.install_collection(collection_name, version, force)
                
            elif operation == "list_roles":
                result = await self.role_manager.list_roles()
                
            elif operation == "list_collections":
                result = await self.role_manager.list_collections()
                
            elif operation == "remove_role":
                role_name = cfg.get("role_name", "")
                result = await self.role_manager.remove_role(role_name)
                
            elif operation == "search_roles":
                search_term = cfg.get("search_term", "")
                result = await self.role_manager.search_roles(search_term)
                
            elif operation == "search_collections":
                search_term = cfg.get("search_term", "")
                result = await self.role_manager.search_collections(search_term)
                
            else:
                result = {
                    "success": False,
                    "error": f"Unknown operation: {operation}",
                    "available_operations": [
                        "run_playbook", "check_syntax", "list_tasks", "list_hosts", "list_groups",
                        "get_host_vars", "ping_hosts", "gather_facts", "run_module", "copy_file",
                        "install_package", "manage_service", "run_command", "install_role",
                        "install_collection", "list_roles", "list_collections", "remove_role",
                        "search_roles", "search_collections"
                    ]
                }
            
            # Add execution metadata
            execution_time = (datetime.now() - start_time).total_seconds()
            result.update({
                "operation": operation,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
                "ansible_config": {
                    "inventory_path": self.config.inventory_path,
                    "remote_user": self.config.remote_user,
                    "become": self.config.become,
                    "timeout": self.config.timeout,
                    "forks": self.config.forks
                }
            })
            
            return result

        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Ansible operation failed: {e}")
            # Sanitize error message to prevent information leakage
            error_message = str(e)
            # Remove sensitive information from error messages
            sensitive_patterns = ['password', 'secret', 'key', 'token', 'vault']
            for pattern in sensitive_patterns:
                if pattern in error_message.lower():
                    error_message = "Operation failed - sensitive information redacted"
                    break

            return {
                "success": False,
                "operation": operation,
                "error": error_message,
                "error_type": type(e).__name__,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
                "status": "error"
            }

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "ansible",
    "version": "1.0.0",
    "description": "Ansible automation and configuration management plugin",
    "author": "PlugPipe Team",
    "category": "configuration",
    "tags": ["ansible", "automation", "configuration", "orchestration", "playbooks"],
    "requirements": ["ansible-core", "ansible", "ansible-galaxy"],
    "supports_async": True
}

# Main process function for PlugPipe with enhanced security
async def process(ctx: Dict, cfg: Dict) -> Dict:
    """PlugPipe entry point for Ansible plugin with comprehensive security validation"""
    try:
        # Initialize plugin with security-validated configuration
        plugin = AnsiblePlugin(cfg)
        return await plugin.process(ctx, cfg)
    except ValueError as e:
        # Handle configuration validation errors
        return {
            "success": False,
            "status": "error",
            "error": f"Configuration validation failed: {str(e)}",
            "timestamp": datetime.now().isoformat()
        }
    except Exception as e:
        # Handle other initialization errors
        logger.error(f"Ansible plugin initialization failed: {e}")
        return {
            "success": False,
            "status": "error",
            "error": "Plugin initialization failed",
            "timestamp": datetime.now().isoformat()
        }