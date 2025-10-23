# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Chef Configuration Management Plugin for PlugPipe

This plugin provides comprehensive Chef configuration management capabilities
including cookbook management, node bootstrapping, recipe execution, data bags,
environments, and both Chef Server/Client and Chef Solo architectures.
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

# Import PlugPipe's pp function for Universal Input Sanitizer integration
try:
    import sys
    from shares.plugpipe_path_helper import setup_plugpipe_environment; setup_plugpipe_environment()
    from shares.loader import pp
except ImportError:
    # Fallback if pp not available
    def pp(*args, **kwargs):
        return {"success": False, "error": "PlugPipe loader not available"}

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
class ChefConfig:
    """Chef configuration settings with security validation"""
    chef_server_url: str = ""
    client_name: str = ""
    client_key_path: str = ""
    cookbook_path: str = "/var/chef/cookbooks"
    cache_path: str = "/var/chef/cache"
    node_name: str = ""
    environment: str = "_default"
    run_list: List[str] = None
    validation_key_path: str = ""
    chef_zero_port: int = 8889
    solo_mode: bool = False
    timeout: int = 1800
    log_level: str = "info"
    ssl_verify_mode: str = "verify_peer"

    def __post_init__(self):
        if self.run_list is None:
            self.run_list = []
        # Validate configuration for security issues
        self._validate_config()

    def _validate_config(self):
        """Validate configuration for security issues"""
        # Validate paths to prevent path traversal
        paths_to_check = [self.cookbook_path, self.cache_path, self.client_key_path, self.validation_key_path]
        for path in paths_to_check:
            if path and ("../" in path or "..\\" in path):
                raise ValueError(f"Path traversal attempt detected in: {path}")

        # Validate timeout constraints (1 second to 2 hours)
        if self.timeout < 1 or self.timeout > 7200:
            raise ValueError(f"Invalid timeout: {self.timeout}. Must be 1-7200 seconds")

        # Validate log level
        valid_log_levels = ["debug", "info", "warn", "error", "fatal"]
        if self.log_level not in valid_log_levels:
            raise ValueError(f"Invalid log level: {self.log_level}. Must be one of {valid_log_levels}")

        # Validate SSL verification mode
        valid_ssl_modes = ["verify_peer", "verify_none"]
        if self.ssl_verify_mode not in valid_ssl_modes:
            raise ValueError(f"Invalid SSL verify mode: {self.ssl_verify_mode}. Must be one of {valid_ssl_modes}")

        # Validate Chef Zero port range
        if self.chef_zero_port < 1024 or self.chef_zero_port > 65535:
            raise ValueError(f"Invalid Chef Zero port: {self.chef_zero_port}. Must be 1024-65535")

class ChefCookbookManager:
    """Manages Chef cookbook operations with security hardening"""

    def __init__(self, config: ChefConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.ChefCookbookManager")
        self.sanitizer_available = self._check_sanitizer_availability()

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
                r'\.\.//',     # Path traversal
                r'</?.*(script|iframe|object)',  # Script injection
                r'(exec|eval|system|shell_exec)\s*\(',  # Code execution
                r'/etc/(passwd|shadow|hosts)',  # Sensitive file access
                r'(curl|wget|nc)\s+.*\.(com|org|net)',  # External communication
                r'(shutdown|reboot|halt)\s',  # System control
                r'knife\s+(ssh|bootstrap).*[;&|]',  # Chef command injection
                r'chef-(client|solo).*[;&|]',  # Chef execution injection
                r'cookbook.*\.\./',  # Cookbook path traversal
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

    def _sanitize_chef_arguments(self, args: List[str]) -> List[str]:
        """Sanitize Chef command arguments to prevent injection"""
        sanitized_args = []
        dangerous_patterns = [
            ';', '|', '&', '$(', '`', '>', '<',
            '&&', '||', '\n', '\r', 'rm -rf', 'sudo su'
        ]

        for arg in args:
            # Check for dangerous patterns
            if any(pattern in str(arg) for pattern in dangerous_patterns):
                continue  # Skip dangerous arguments

            # Escape shell metacharacters
            sanitized_arg = shlex.quote(str(arg))
            sanitized_args.append(sanitized_arg)

        return sanitized_args
    
    async def upload_cookbook(self, cookbook_name: str, cookbook_path: str = None) -> Dict:
        """Upload cookbook to Chef Server with security validation"""
        # Input sanitization
        validation_result = await self._sanitize_input({
            "cookbook_name": cookbook_name,
            "cookbook_path": cookbook_path
        })

        if not validation_result.is_valid:
            return {
                "success": False,
                "error": "Input validation failed",
                "security_violations": validation_result.security_violations
            }

        if not cookbook_path:
            cookbook_path = os.path.join(self.config.cookbook_path, cookbook_name)

        cmd = ["knife", "cookbook", "upload", cookbook_name, "--cookbook-path", self.config.cookbook_path]

        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])

        # Sanitize command arguments
        cmd = self._sanitize_chef_arguments(cmd)

        return await self._run_chef_command(cmd)
    
    async def download_cookbook(self, cookbook_name: str, version: str = None) -> Dict:
        """Download cookbook from Chef Server"""
        cmd = ["knife", "cookbook", "download", cookbook_name]
        
        if version:
            cmd.append(version)
        
        cmd.extend(["--dir", self.config.cookbook_path])
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def list_cookbooks(self) -> Dict:
        """List available cookbooks"""
        if self.config.solo_mode:
            # For Chef Solo, list local cookbooks
            cmd = ["find", self.config.cookbook_path, "-name", "metadata.rb", "-o", "-name", "metadata.json"]
        else:
            # For Chef Server, use knife
            cmd = ["knife", "cookbook", "list", "--format", "json"]
            
            if self.config.chef_server_url:
                cmd.extend(["--server-url", self.config.chef_server_url])
        
        result = await self._run_chef_command(cmd)
        
        if self.config.solo_mode and result.get("success"):
            # Parse local cookbook list
            cookbook_files = result.get("output", "").strip().split('\n')
            cookbooks = []
            for file_path in cookbook_files:
                if file_path:
                    cookbook_dir = os.path.dirname(file_path)
                    cookbook_name = os.path.basename(cookbook_dir)
                    if cookbook_name not in cookbooks:
                        cookbooks.append(cookbook_name)
            result["cookbooks"] = cookbooks
        
        return result
    
    async def delete_cookbook(self, cookbook_name: str, version: str = None) -> Dict:
        """Delete cookbook from Chef Server"""
        cmd = ["knife", "cookbook", "delete", cookbook_name, "--yes"]
        
        if version:
            cmd.extend(["--version", version])
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def test_cookbook(self, cookbook_name: str) -> Dict:
        """Test cookbook using foodcritic and cookstyle"""
        cookbook_path = os.path.join(self.config.cookbook_path, cookbook_name)
        
        results = {}
        
        # Run foodcritic
        foodcritic_cmd = ["foodcritic", cookbook_path]
        foodcritic_result = await self._run_chef_command(foodcritic_cmd)
        results["foodcritic"] = foodcritic_result
        
        # Run cookstyle (RuboCop for Chef)
        cookstyle_cmd = ["cookstyle", cookbook_path]
        cookstyle_result = await self._run_chef_command(cookstyle_cmd)
        results["cookstyle"] = cookstyle_result
        
        # Determine overall success
        results["success"] = foodcritic_result.get("success", False) and cookstyle_result.get("success", False)
        
        return results
    
    async def _run_chef_command(self, cmd: List[str]) -> Dict:
        """Execute Chef command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config.cookbook_path
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

class ChefNodeManager:
    """Manages Chef node operations with security hardening"""

    def __init__(self, config: ChefConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.ChefNodeManager")
        self.sanitizer_available = self._check_sanitizer_availability()

    def _check_sanitizer_availability(self) -> bool:
        """Check if Universal Input Sanitizer is available"""
        try:
            result = pp("universal_input_sanitizer", action="health_check")
            return result.get("success", False)
        except Exception as e:
            self.logger.warning(f"Universal Input Sanitizer not available: {e}")
            return False

    async def _sanitize_input(self, data: Any) -> ValidationResult:
        """Sanitize input using Universal Input Sanitizer"""
        validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            security_violations=[]
        )

        try:
            if self.sanitizer_available:
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

                validation_result.sanitized_data = sanitizer_result.get("sanitized_data", data)
            else:
                # Fallback validation
                validation_result.sanitized_data = data
                validation_result.warnings.append("Universal Input Sanitizer not available")

        except Exception as e:
            self.logger.error(f"Input sanitization error: {e}")
            validation_result.is_valid = False
            validation_result.errors.append(f"Sanitization failed: {str(e)}")

        return validation_result

    def _sanitize_chef_arguments(self, args: List[str]) -> List[str]:
        """Sanitize Chef command arguments to prevent injection"""
        sanitized_args = []
        dangerous_patterns = [
            ';', '|', '&', '$(', '`', '>', '<',
            '&&', '||', '\n', '\r', 'rm -rf', 'sudo su'
        ]

        for arg in args:
            # Check for dangerous patterns
            if any(pattern in str(arg) for pattern in dangerous_patterns):
                continue  # Skip dangerous arguments

            # Escape shell metacharacters
            sanitized_arg = shlex.quote(str(arg))
            sanitized_args.append(sanitized_arg)

        return sanitized_args
    
    async def bootstrap_node(self, node_address: str, ssh_user: str = "root", ssh_key: str = None) -> Dict:
        """Bootstrap a new Chef node"""
        cmd = ["knife", "bootstrap", node_address, "--ssh-user", ssh_user]
        
        if ssh_key:
            cmd.extend(["--ssh-identity-file", ssh_key])
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        if self.config.environment != "_default":
            cmd.extend(["--environment", self.config.environment])
        
        if self.config.run_list:
            cmd.extend(["--run-list", ",".join(self.config.run_list)])
        
        return await self._run_chef_command(cmd)
    
    async def list_nodes(self) -> Dict:
        """List all Chef nodes"""
        cmd = ["knife", "node", "list", "--format", "json"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def show_node(self, node_name: str) -> Dict:
        """Show detailed node information"""
        cmd = ["knife", "node", "show", node_name, "--format", "json"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def delete_node(self, node_name: str) -> Dict:
        """Delete a Chef node"""
        cmd = ["knife", "node", "delete", node_name, "--yes"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def run_chef_client(self, node_name: str = None, run_list: List[str] = None) -> Dict:
        """Run chef-client on node"""
        if self.config.solo_mode:
            return await self._run_chef_solo(run_list)
        else:
            return await self._run_chef_client_remote(node_name, run_list)
    
    async def _run_chef_solo(self, run_list: List[str] = None) -> Dict:
        """Run chef-solo locally"""
        # Create solo.rb configuration
        solo_config = await self._create_solo_config()
        
        cmd = ["chef-solo", "--config", solo_config]
        
        if run_list:
            # Create JSON attributes file with run_list
            json_attribs = await self._create_json_attributes({"run_list": run_list})
            cmd.extend(["--json-attributes", json_attribs])
        elif self.config.run_list:
            json_attribs = await self._create_json_attributes({"run_list": self.config.run_list})
            cmd.extend(["--json-attributes", json_attribs])
        
        cmd.extend(["--log_level", self.config.log_level])
        
        return await self._run_chef_command(cmd)
    
    async def _run_chef_client_remote(self, node_name: str, run_list: List[str] = None) -> Dict:
        """Run chef-client on remote node"""
        if not node_name:
            node_name = self.config.node_name
        
        cmd = ["knife", "ssh", f"name:{node_name}", "chef-client"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def _create_solo_config(self) -> str:
        """Create chef-solo configuration file"""
        solo_config = {
            "cookbook_path": [self.config.cookbook_path],
            "cache_type": "BasicFile",
            "cache_options": {"path": os.path.join(self.config.cache_path, "checksums")},
            "log_level": self.config.log_level.lower()
        }
        
        config_file = tempfile.NamedTemporaryFile(mode='w', suffix='.rb', delete=False)
        
        for key, value in solo_config.items():
            if isinstance(value, list):
                config_file.write(f'{key} {value}\n')
            elif isinstance(value, str):
                config_file.write(f'{key} "{value}"\n')
            else:
                config_file.write(f'{key} {value}\n')
        
        config_file.close()
        return config_file.name
    
    async def _create_json_attributes(self, attributes: Dict) -> str:
        """Create JSON attributes file"""
        json_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        json.dump(attributes, json_file, indent=2)
        json_file.close()
        return json_file.name
    
    async def _run_chef_command(self, cmd: List[str]) -> Dict:
        """Execute Chef command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy()
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

class ChefDataManager:
    """Manages Chef data bags and environments with security hardening"""

    def __init__(self, config: ChefConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.ChefDataManager")
        self.sanitizer_available = self._check_sanitizer_availability()

    def _check_sanitizer_availability(self) -> bool:
        """Check if Universal Input Sanitizer is available"""
        try:
            result = pp("universal_input_sanitizer", action="health_check")
            return result.get("success", False)
        except Exception as e:
            self.logger.warning(f"Universal Input Sanitizer not available: {e}")
            return False

    async def _sanitize_input(self, data: Any) -> ValidationResult:
        """Sanitize input using Universal Input Sanitizer"""
        validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            security_violations=[]
        )

        try:
            if self.sanitizer_available:
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

                validation_result.sanitized_data = sanitizer_result.get("sanitized_data", data)
            else:
                validation_result.sanitized_data = data
                validation_result.warnings.append("Universal Input Sanitizer not available")

        except Exception as e:
            self.logger.error(f"Input sanitization error: {e}")
            validation_result.is_valid = False
            validation_result.errors.append(f"Sanitization failed: {str(e)}")

        return validation_result

    def _sanitize_chef_arguments(self, args: List[str]) -> List[str]:
        """Sanitize Chef command arguments to prevent injection"""
        sanitized_args = []
        dangerous_patterns = [
            ';', '|', '&', '$(', '`', '>', '<',
            '&&', '||', '\n', '\r', 'rm -rf', 'sudo su'
        ]

        for arg in args:
            # Check for dangerous patterns
            if any(pattern in str(arg) for pattern in dangerous_patterns):
                continue  # Skip dangerous arguments

            # Escape shell metacharacters
            sanitized_arg = shlex.quote(str(arg))
            sanitized_args.append(sanitized_arg)

        return sanitized_args
    
    async def create_data_bag(self, data_bag_name: str) -> Dict:
        """Create a new data bag"""
        cmd = ["knife", "data", "bag", "create", data_bag_name]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def create_data_bag_item(self, data_bag_name: str, item_name: str, item_data: Dict) -> Dict:
        """Create data bag item"""
        # Create temporary JSON file for the item
        item_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        item_data_with_id = {"id": item_name, **item_data}
        json.dump(item_data_with_id, item_file, indent=2)
        item_file.close()
        
        cmd = ["knife", "data", "bag", "from", "file", data_bag_name, item_file.name]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        result = await self._run_chef_command(cmd)
        
        # Clean up temporary file
        os.unlink(item_file.name)
        
        return result
    
    async def list_data_bags(self) -> Dict:
        """List all data bags"""
        cmd = ["knife", "data", "bag", "list", "--format", "json"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def show_data_bag_item(self, data_bag_name: str, item_name: str) -> Dict:
        """Show data bag item"""
        cmd = ["knife", "data", "bag", "show", data_bag_name, item_name, "--format", "json"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def delete_data_bag_item(self, data_bag_name: str, item_name: str) -> Dict:
        """Delete data bag item"""
        cmd = ["knife", "data", "bag", "delete", data_bag_name, item_name, "--yes"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def create_environment(self, environment_name: str, environment_data: Dict) -> Dict:
        """Create Chef environment"""
        # Create temporary JSON file for the environment
        env_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False)
        env_data_with_name = {"name": environment_name, **environment_data}
        json.dump(env_data_with_name, env_file, indent=2)
        env_file.close()
        
        cmd = ["knife", "environment", "from", "file", env_file.name]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        result = await self._run_chef_command(cmd)
        
        # Clean up temporary file
        os.unlink(env_file.name)
        
        return result
    
    async def list_environments(self) -> Dict:
        """List all environments"""
        cmd = ["knife", "environment", "list", "--format", "json"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def show_environment(self, environment_name: str) -> Dict:
        """Show environment details"""
        cmd = ["knife", "environment", "show", environment_name, "--format", "json"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def delete_environment(self, environment_name: str) -> Dict:
        """Delete environment"""
        cmd = ["knife", "environment", "delete", environment_name, "--yes"]
        
        if self.config.chef_server_url:
            cmd.extend(["--server-url", self.config.chef_server_url])
        
        return await self._run_chef_command(cmd)
    
    async def _run_chef_command(self, cmd: List[str]) -> Dict:
        """Execute Chef command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=os.environ.copy()
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

class ChefPlugin:
    """Main Chef plugin class with comprehensive security hardening"""

    def __init__(self, config: Dict):
        self.config = self._parse_config(config)
        self.cookbook_manager = ChefCookbookManager(self.config)
        self.node_manager = ChefNodeManager(self.config)
        self.data_manager = ChefDataManager(self.config)
        self.logger = logging.getLogger(f"{__name__}.ChefPlugin")
        self.sanitizer_available = self._check_sanitizer_availability()

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
                r'\.\.//',     # Path traversal
                r'</?.*(script|iframe|object)',  # Script injection
                r'(exec|eval|system|shell_exec)\s*\(',  # Code execution
                r'/etc/(passwd|shadow|hosts)',  # Sensitive file access
                r'(curl|wget|nc)\s+.*\.(com|org|net)',  # External communication
                r'(shutdown|reboot|halt)\s',  # System control
                r'knife\s+(ssh|bootstrap).*[;&|]',  # Chef command injection
                r'chef-(client|solo).*[;&|]',  # Chef execution injection
                r'cookbook.*\.\./',  # Cookbook path traversal
                r'data.bag.*[;&|]',  # Data bag injection
                r'environment.*[;&|]',  # Environment injection
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
    
    def _parse_config(self, config: Dict) -> ChefConfig:
        """Parse configuration dictionary into ChefConfig"""
        return ChefConfig(
            chef_server_url=config.get("chef_server_url", ""),
            client_name=config.get("client_name", ""),
            client_key_path=config.get("client_key_path", ""),
            cookbook_path=config.get("cookbook_path", "/var/chef/cookbooks"),
            cache_path=config.get("cache_path", "/var/chef/cache"),
            node_name=config.get("node_name", ""),
            environment=config.get("environment", "_default"),
            run_list=config.get("run_list", []),
            validation_key_path=config.get("validation_key_path", ""),
            chef_zero_port=config.get("chef_zero_port", 8889),
            solo_mode=config.get("solo_mode", False),
            timeout=config.get("timeout", 1800),
            log_level=config.get("log_level", "info"),
            ssl_verify_mode=config.get("ssl_verify_mode", "verify_peer")
        )
    
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
            "upload_cookbook", "download_cookbook", "list_cookbooks", "delete_cookbook", "test_cookbook",
            "bootstrap_node", "list_nodes", "show_node", "delete_node", "run_chef_client",
            "create_data_bag", "create_data_bag_item", "list_data_bags", "show_data_bag_item", "delete_data_bag_item",
            "create_environment", "list_environments", "show_environment", "delete_environment"
        ]

        if operation not in valid_operations:
            return {
                'status': 'error',
                'message': f'Unknown operation: {operation}',
                'available_operations': valid_operations
            }

        start_time = datetime.now()

        try:
            if operation == "upload_cookbook":
                cookbook_name = cfg.get("cookbook_name", "")
                cookbook_path = cfg.get("cookbook_path")
                result = await self.cookbook_manager.upload_cookbook(cookbook_name, cookbook_path)
                
            elif operation == "download_cookbook":
                cookbook_name = cfg.get("cookbook_name", "")
                version = cfg.get("version")
                result = await self.cookbook_manager.download_cookbook(cookbook_name, version)
                
            elif operation == "list_cookbooks":
                result = await self.cookbook_manager.list_cookbooks()
                
            elif operation == "delete_cookbook":
                cookbook_name = cfg.get("cookbook_name", "")
                version = cfg.get("version")
                result = await self.cookbook_manager.delete_cookbook(cookbook_name, version)
                
            elif operation == "test_cookbook":
                cookbook_name = cfg.get("cookbook_name", "")
                result = await self.cookbook_manager.test_cookbook(cookbook_name)
                
            elif operation == "bootstrap_node":
                node_address = cfg.get("node_address", "")
                ssh_user = cfg.get("ssh_user", "root")
                ssh_key = cfg.get("ssh_key")
                result = await self.node_manager.bootstrap_node(node_address, ssh_user, ssh_key)
                
            elif operation == "list_nodes":
                result = await self.node_manager.list_nodes()
                
            elif operation == "show_node":
                node_name = cfg.get("node_name", "")
                result = await self.node_manager.show_node(node_name)
                
            elif operation == "delete_node":
                node_name = cfg.get("node_name", "")
                result = await self.node_manager.delete_node(node_name)
                
            elif operation == "run_chef_client":
                node_name = cfg.get("node_name")
                run_list = cfg.get("run_list")
                result = await self.node_manager.run_chef_client(node_name, run_list)
                
            elif operation == "create_data_bag":
                data_bag_name = cfg.get("data_bag_name", "")
                result = await self.data_manager.create_data_bag(data_bag_name)
                
            elif operation == "create_data_bag_item":
                data_bag_name = cfg.get("data_bag_name", "")
                item_name = cfg.get("item_name", "")
                item_data = cfg.get("item_data", {})
                result = await self.data_manager.create_data_bag_item(data_bag_name, item_name, item_data)
                
            elif operation == "list_data_bags":
                result = await self.data_manager.list_data_bags()
                
            elif operation == "show_data_bag_item":
                data_bag_name = cfg.get("data_bag_name", "")
                item_name = cfg.get("item_name", "")
                result = await self.data_manager.show_data_bag_item(data_bag_name, item_name)
                
            elif operation == "delete_data_bag_item":
                data_bag_name = cfg.get("data_bag_name", "")
                item_name = cfg.get("item_name", "")
                result = await self.data_manager.delete_data_bag_item(data_bag_name, item_name)
                
            elif operation == "create_environment":
                environment_name = cfg.get("environment_name", "")
                environment_data = cfg.get("environment_data", {})
                result = await self.data_manager.create_environment(environment_name, environment_data)
                
            elif operation == "list_environments":
                result = await self.data_manager.list_environments()
                
            elif operation == "show_environment":
                environment_name = cfg.get("environment_name", "")
                result = await self.data_manager.show_environment(environment_name)
                
            elif operation == "delete_environment":
                environment_name = cfg.get("environment_name", "")
                result = await self.data_manager.delete_environment(environment_name)
                
            else:
                result = {
                    "success": False,
                    "error": f"Unknown operation: {operation}",
                    "available_operations": [
                        "upload_cookbook", "download_cookbook", "list_cookbooks", "delete_cookbook", "test_cookbook",
                        "bootstrap_node", "list_nodes", "show_node", "delete_node", "run_chef_client",
                        "create_data_bag", "create_data_bag_item", "list_data_bags", "show_data_bag_item", "delete_data_bag_item",
                        "create_environment", "list_environments", "show_environment", "delete_environment"
                    ]
                }
            
            # Add execution metadata
            execution_time = (datetime.now() - start_time).total_seconds()
            result.update({
                "operation": operation,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
                "chef_config": {
                    "chef_server_url": self.config.chef_server_url,
                    "solo_mode": self.config.solo_mode,
                    "environment": self.config.environment,
                    "timeout": self.config.timeout
                }
            })
            
            return result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Chef operation failed: {e}")

            # Sanitize error message to prevent information leakage
            error_message = str(e)
            sensitive_patterns = [
                r'password[=:]\S+',
                r'key[=:]\S+',
                r'token[=:]\S+',
                r'secret[=:]\S+',
                r'/[\w/.]+\.pem'
            ]

            for pattern in sensitive_patterns:
                error_message = re.sub(pattern, '[REDACTED]', error_message, flags=re.IGNORECASE)

            return {
                "success": False,
                "operation": operation,
                "error": error_message,
                "error_type": type(e).__name__,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat()
            }

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "chef",
    "version": "1.0.0",
    "description": "Chef configuration management and automation plugin",
    "author": "PlugPipe Team",
    "category": "configuration",
    "tags": ["chef", "configuration", "automation", "infrastructure", "cookbooks"],
    "requirements": ["chef-client", "chef-server", "knife"],
    "supports_async": True
}

# Main process function for PlugPipe
async def process(ctx: Dict, cfg: Dict) -> Dict:
    """PlugPipe entry point for Chef plugin with security hardening"""
    try:
        plugin = ChefPlugin(cfg)
        return await plugin.process(ctx, cfg)
    except Exception as e:
        logger.error(f"Chef plugin initialization failed: {e}")
        return {
            "success": False,
            "error": "Plugin initialization failed",
            "error_type": type(e).__name__,
            "timestamp": datetime.now().isoformat()
        }