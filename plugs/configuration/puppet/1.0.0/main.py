# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Puppet Configuration Management Plugin for PlugPipe

This plugin provides comprehensive Puppet configuration management capabilities
including manifest compilation and application, node classification, module management,
PuppetDB integration, Hiera data management, and Puppet Enterprise features.
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
class PuppetConfig:
    """Puppet configuration settings with security validation"""
    puppet_dir: str = "/etc/puppet"
    manifest_path: str = "/etc/puppet/manifests"
    modules_path: str = "/etc/puppet/modules"
    hiera_config: str = "/etc/puppet/hiera.yaml"
    puppet_server: str = ""
    puppet_port: int = 8140
    environment: str = "production"
    node_name: str = ""
    ssl_dir: str = "/etc/puppet/ssl"
    vardir: str = "/var/puppet"
    rundir: str = "/var/run/puppet"
    logdir: str = "/var/log/puppet"
    timeout: int = 1800
    apply_mode: bool = True
    debug: bool = False
    verbose: bool = False
    noop: bool = False
    use_puppetdb: bool = False
    puppetdb_server: str = ""
    puppetdb_port: int = 8081

    def __post_init__(self):
        # Validate configuration for security
        self._validate_config()

    def _validate_config(self):
        """Validate configuration for security issues"""
        # Validate paths to prevent path traversal
        paths_to_check = [
            self.puppet_dir, self.manifest_path, self.modules_path,
            self.hiera_config, self.ssl_dir, self.vardir, self.rundir, self.logdir
        ]

        for path in paths_to_check:
            if path and ("../" in path or "..\\" in path):
                raise ValueError(f"Path traversal attempt detected in: {path}")

        # Validate timeout constraints (1 second to 2 hours)
        if self.timeout < 1 or self.timeout > 7200:
            raise ValueError(f"Invalid timeout: {self.timeout}")

        # Validate port ranges
        if self.puppet_port < 1024 or self.puppet_port > 65535:
            raise ValueError(f"Invalid Puppet port: {self.puppet_port}")

        if self.puppetdb_port < 1024 or self.puppetdb_port > 65535:
            raise ValueError(f"Invalid PuppetDB port: {self.puppetdb_port}")

        # Validate server URLs
        if self.puppet_server and not re.match(r'^[a-zA-Z0-9.-]+$', self.puppet_server):
            raise ValueError(f"Invalid Puppet server hostname: {self.puppet_server}")

        if self.puppetdb_server and not re.match(r'^[a-zA-Z0-9.-]+$', self.puppetdb_server):
            raise ValueError(f"Invalid PuppetDB server hostname: {self.puppetdb_server}")

class PuppetManifestManager:
    """Manages Puppet manifest operations"""
    
    def __init__(self, config: PuppetConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PuppetManifestManager")
    
    async def apply_manifest(self, manifest_file: str, node_name: str = None) -> Dict:
        """Apply Puppet manifest to target node with security validation"""
        # Validate manifest file path for security
        if not manifest_file or '../' in manifest_file:
            return {
                "success": False,
                "error": "Invalid manifest file - path traversal detected"
            }

        if self.config.apply_mode:
            cmd = ["puppet", "apply"]
        else:
            cmd = ["puppet", "agent", "--test"]

        # Manifest file
        if os.path.isabs(manifest_file):
            # Validate absolute path is in allowed directories
            allowed_dirs = [self.config.manifest_path, "/opt/puppet/manifests"]
            if not any(manifest_file.startswith(allowed_dir) for allowed_dir in allowed_dirs):
                return {"success": False, "error": "Manifest path not in allowed directories"}
            cmd.append(manifest_file)
        else:
            manifest_path = os.path.join(self.config.manifest_path, manifest_file)
            cmd.append(manifest_path)
        
        # Environment
        if self.config.environment != "production":
            cmd.extend(["--environment", self.config.environment])
        
        # Node name
        if node_name:
            cmd.extend(["--certname", node_name])
        
        # Options
        if self.config.noop:
            cmd.append("--noop")
        
        if self.config.debug:
            cmd.append("--debug")
        
        if self.config.verbose:
            cmd.append("--verbose")
        
        # Module path
        cmd.extend(["--modulepath", self.config.modules_path])
        
        return await self._run_puppet_command(cmd)
    
    async def compile_manifest(self, manifest_file: str, node_name: str = None) -> Dict:
        """Compile Puppet manifest without applying"""
        cmd = ["puppet", "apply", "--noop", "--detailed-exitcodes"]
        
        # Manifest file
        if os.path.isabs(manifest_file):
            cmd.append(manifest_file)
        else:
            manifest_path = os.path.join(self.config.manifest_path, manifest_file)
            cmd.append(manifest_path)
        
        # Environment
        if self.config.environment != "production":
            cmd.extend(["--environment", self.config.environment])
        
        # Node name
        if node_name:
            cmd.extend(["--certname", node_name])
        
        # Module path
        cmd.extend(["--modulepath", self.config.modules_path])
        
        return await self._run_puppet_command(cmd)
    
    async def validate_manifest(self, manifest_file: str) -> Dict:
        """Validate Puppet manifest syntax"""
        if os.path.isabs(manifest_file):
            manifest_path = manifest_file
        else:
            manifest_path = os.path.join(self.config.manifest_path, manifest_file)
        
        cmd = ["puppet", "parser", "validate", manifest_path]
        
        return await self._run_puppet_command(cmd)
    
    async def list_manifests(self) -> Dict:
        """List available Puppet manifests"""
        try:
            manifests = []
            manifest_dir = Path(self.config.manifest_path)
            
            if manifest_dir.exists():
                for manifest_file in manifest_dir.rglob("*.pp"):
                    relative_path = manifest_file.relative_to(manifest_dir)
                    manifests.append(str(relative_path))
            
            return {
                "success": True,
                "manifests": manifests,
                "manifest_path": self.config.manifest_path
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": f"list manifests in {self.config.manifest_path}"
            }
    
    async def _run_puppet_command(self, cmd: List[str]) -> Dict:
        """Execute Puppet command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=self.config.puppet_dir
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

class PuppetNodeManager:
    """Manages Puppet node operations"""
    
    def __init__(self, config: PuppetConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PuppetNodeManager")
    
    async def run_agent(self, node_name: str = None, once: bool = True) -> Dict:
        """Run Puppet agent"""
        cmd = ["puppet", "agent"]
        
        if once:
            cmd.append("--test")
        else:
            cmd.append("--no-daemonize")
        
        # Node name
        if node_name:
            cmd.extend(["--certname", node_name])
        elif self.config.node_name:
            cmd.extend(["--certname", self.config.node_name])
        
        # Server
        if self.config.puppet_server:
            cmd.extend(["--server", self.config.puppet_server])
        
        # Environment
        if self.config.environment != "production":
            cmd.extend(["--environment", self.config.environment])
        
        # Options
        if self.config.noop:
            cmd.append("--noop")
        
        if self.config.debug:
            cmd.append("--debug")
        
        if self.config.verbose:
            cmd.append("--verbose")
        
        return await self._run_puppet_command(cmd)
    
    async def list_nodes(self) -> Dict:
        """List Puppet nodes"""
        if self.config.use_puppetdb:
            return await self._list_nodes_puppetdb()
        else:
            return await self._list_nodes_filesystem()
    
    async def _list_nodes_puppetdb(self) -> Dict:
        """List nodes from PuppetDB"""
        cmd = ["puppet", "query", "nodes"]
        
        if self.config.puppetdb_server:
            cmd.extend(["--puppetdb_server", self.config.puppetdb_server])
        
        return await self._run_puppet_command(cmd)
    
    async def _list_nodes_filesystem(self) -> Dict:
        """List nodes from filesystem (certificates)"""
        try:
            nodes = []
            ssl_dir = Path(self.config.ssl_dir)
            certs_dir = ssl_dir / "certs"
            
            if certs_dir.exists():
                for cert_file in certs_dir.glob("*.pem"):
                    node_name = cert_file.stem
                    if node_name != "ca":  # Skip CA certificate
                        nodes.append(node_name)
            
            return {
                "success": True,
                "nodes": nodes,
                "ssl_dir": str(ssl_dir)
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": f"list nodes from {self.config.ssl_dir}"
            }
    
    async def show_node(self, node_name: str) -> Dict:
        """Show node information"""
        if self.config.use_puppetdb:
            cmd = ["puppet", "query", "facts", f"certname={node_name}"]
            
            if self.config.puppetdb_server:
                cmd.extend(["--puppetdb_server", self.config.puppetdb_server])
            
            return await self._run_puppet_command(cmd)
        else:
            # Show node facts from last run
            return await self._show_node_facts(node_name)
    
    async def _show_node_facts(self, node_name: str) -> Dict:
        """Show node facts from filesystem"""
        try:
            facts_file = os.path.join(self.config.vardir, "facts", f"{node_name}.yaml")
            
            if os.path.exists(facts_file):
                with open(facts_file, 'r') as f:
                    facts = yaml.safe_load(f)
                
                return {
                    "success": True,
                    "node": node_name,
                    "facts": facts
                }
            else:
                return {
                    "success": False,
                    "error": f"Facts file not found for node {node_name}",
                    "facts_file": facts_file
                }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": f"show facts for {node_name}"
            }
    
    async def clean_node(self, node_name: str) -> Dict:
        """Clean node certificates"""
        cmd = ["puppet", "cert", "clean", node_name]
        
        return await self._run_puppet_command(cmd)
    
    async def sign_node(self, node_name: str) -> Dict:
        """Sign node certificate"""
        cmd = ["puppet", "cert", "sign", node_name]
        
        return await self._run_puppet_command(cmd)
    
    async def _run_puppet_command(self, cmd: List[str]) -> Dict:
        """Execute Puppet command and return structured result"""
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

class PuppetModuleManager:
    """Manages Puppet modules and Forge operations"""
    
    def __init__(self, config: PuppetConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PuppetModuleManager")
    
    async def install_module(self, module_name: str, version: str = None, force: bool = False) -> Dict:
        """Install module from Puppet Forge"""
        cmd = ["puppet", "module", "install", module_name]
        
        if version:
            cmd.extend(["--version", version])
        
        if force:
            cmd.append("--force")
        
        cmd.extend(["--modulepath", self.config.modules_path])
        
        return await self._run_puppet_command(cmd)
    
    async def list_modules(self) -> Dict:
        """List installed modules"""
        cmd = ["puppet", "module", "list", "--modulepath", self.config.modules_path]
        
        return await self._run_puppet_command(cmd)
    
    async def upgrade_module(self, module_name: str) -> Dict:
        """Upgrade module to latest version"""
        cmd = ["puppet", "module", "upgrade", module_name, "--modulepath", self.config.modules_path]
        
        return await self._run_puppet_command(cmd)
    
    async def uninstall_module(self, module_name: str, force: bool = False) -> Dict:
        """Uninstall module"""
        cmd = ["puppet", "module", "uninstall", module_name]
        
        if force:
            cmd.append("--force")
        
        cmd.extend(["--modulepath", self.config.modules_path])
        
        return await self._run_puppet_command(cmd)
    
    async def search_modules(self, search_term: str) -> Dict:
        """Search for modules in Puppet Forge"""
        cmd = ["puppet", "module", "search", search_term]
        
        return await self._run_puppet_command(cmd)
    
    async def generate_module(self, module_name: str) -> Dict:
        """Generate new module skeleton"""
        cmd = ["puppet", "module", "generate", module_name]
        
        return await self._run_puppet_command(cmd, cwd=self.config.modules_path)
    
    async def _run_puppet_command(self, cmd: List[str], cwd: str = None) -> Dict:
        """Execute Puppet command and return structured result"""
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                cwd=cwd or self.config.puppet_dir
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

class PuppetHieraManager:
    """Manages Puppet Hiera data operations"""
    
    def __init__(self, config: PuppetConfig):
        self.config = config
        self.logger = logging.getLogger(f"{__name__}.PuppetHieraManager")
    
    async def lookup_data(self, key: str, node_name: str = None) -> Dict:
        """Look up data from Hiera"""
        cmd = ["puppet", "lookup", key]
        
        if node_name:
            cmd.extend(["--node", node_name])
        
        if self.config.environment != "production":
            cmd.extend(["--environment", self.config.environment])
        
        if os.path.exists(self.config.hiera_config):
            cmd.extend(["--hiera_config", self.config.hiera_config])
        
        return await self._run_puppet_command(cmd)
    
    async def explain_lookup(self, key: str, node_name: str = None) -> Dict:
        """Explain Hiera lookup process"""
        cmd = ["puppet", "lookup", "--explain", key]
        
        if node_name:
            cmd.extend(["--node", node_name])
        
        if self.config.environment != "production":
            cmd.extend(["--environment", self.config.environment])
        
        if os.path.exists(self.config.hiera_config):
            cmd.extend(["--hiera_config", self.config.hiera_config])
        
        return await self._run_puppet_command(cmd)
    
    async def validate_hiera_config(self) -> Dict:
        """Validate Hiera configuration"""
        if not os.path.exists(self.config.hiera_config):
            return {
                "success": False,
                "error": f"Hiera config file not found: {self.config.hiera_config}",
                "command": "validate hiera config"
            }
        
        try:
            with open(self.config.hiera_config, 'r') as f:
                hiera_config = yaml.safe_load(f)
            
            # Basic validation
            required_keys = ['version', 'hierarchy']
            missing_keys = [key for key in required_keys if key not in hiera_config]
            
            if missing_keys:
                return {
                    "success": False,
                    "error": f"Missing required keys in Hiera config: {missing_keys}",
                    "config_file": self.config.hiera_config
                }
            
            return {
                "success": True,
                "config_file": self.config.hiera_config,
                "config": hiera_config,
                "valid": True
            }
        except Exception as e:
            return {
                "success": False,
                "error": str(e),
                "command": f"validate {self.config.hiera_config}"
            }
    
    async def _run_puppet_command(self, cmd: List[str]) -> Dict:
        """Execute Puppet command and return structured result"""
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

class PuppetPlugin:
    """Main Puppet plugin class"""
    
    def __init__(self, config: Dict):
        self.config = self._parse_config(config)
        self.manifest_manager = PuppetManifestManager(self.config)
        self.node_manager = PuppetNodeManager(self.config)
        self.module_manager = PuppetModuleManager(self.config)
        self.hiera_manager = PuppetHieraManager(self.config)
        self.logger = logging.getLogger(f"{__name__}.PuppetPlugin")
    
    def _parse_config(self, config: Dict) -> PuppetConfig:
        """Parse configuration dictionary into PuppetConfig"""
        return PuppetConfig(
            puppet_dir=config.get("puppet_dir", "/etc/puppet"),
            manifest_path=config.get("manifest_path", "/etc/puppet/manifests"),
            modules_path=config.get("modules_path", "/etc/puppet/modules"),
            hiera_config=config.get("hiera_config", "/etc/puppet/hiera.yaml"),
            puppet_server=config.get("puppet_server", ""),
            puppet_port=config.get("puppet_port", 8140),
            environment=config.get("environment", "production"),
            node_name=config.get("node_name", ""),
            ssl_dir=config.get("ssl_dir", "/etc/puppet/ssl"),
            vardir=config.get("vardir", "/var/puppet"),
            rundir=config.get("rundir", "/var/run/puppet"),
            logdir=config.get("logdir", "/var/log/puppet"),
            timeout=config.get("timeout", 1800),
            apply_mode=config.get("apply_mode", True),
            debug=config.get("debug", False),
            verbose=config.get("verbose", False),
            noop=config.get("noop", False),
            use_puppetdb=config.get("use_puppetdb", False),
            puppetdb_server=config.get("puppetdb_server", ""),
            puppetdb_port=config.get("puppetdb_port", 8081)
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
                r'\.\./|\.\.\\\\',     # Path traversal
                r'</?.*(script|iframe|object)',  # Script injection
                r'(exec|eval|system|shell_exec)\s*\(',  # Code execution
                r'/etc/(passwd|shadow|hosts)',  # Sensitive file access
                r'(curl|wget|nc)\s+.*\.(com|org|net)',  # External communication
                r'(shutdown|reboot|halt)\s',  # System control
                r'puppet_.*_pass',  # Puppet password exposure
                r'(ssl_key|private_key)',  # SSL key exposure
                r'hiera_.*secret',  # Hiera secret exposure
                r'puppet.*master.*key',  # Puppet master key
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

    def _sanitize_puppet_arguments(self, args: List[str]) -> List[str]:
        """Sanitize Puppet command arguments to prevent injection"""
        sanitized_args = []
        dangerous_patterns = [
            ';', '|', '&', '$(', '`', '>', '<',
            '&&', '||', '\n', '\r', 'rm -rf', 'sudo su',
            'nc -l', 'netcat', 'curl http', 'wget http'
        ]

        for arg in args:
            arg_str = str(arg)
            # Check for dangerous patterns
            if any(pattern in arg_str for pattern in dangerous_patterns):
                continue  # Skip dangerous arguments

            # Escape shell metacharacters
            sanitized_arg = shlex.quote(arg_str)
            sanitized_args.append(sanitized_arg)

        return sanitized_args
    
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
            "apply_manifest", "compile_manifest", "validate_manifest", "list_manifests",
            "run_agent", "list_nodes", "show_node", "clean_node", "sign_node",
            "install_module", "list_modules", "upgrade_module", "uninstall_module",
            "search_modules", "generate_module", "lookup_data", "explain_lookup", "validate_hiera"
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
            if operation == "apply_manifest":
                manifest_file = cfg.get("manifest_file", "")
                node_name = cfg.get("node_name")
                result = await self.manifest_manager.apply_manifest(manifest_file, node_name)
                
            elif operation == "compile_manifest":
                manifest_file = cfg.get("manifest_file", "")
                node_name = cfg.get("node_name")
                result = await self.manifest_manager.compile_manifest(manifest_file, node_name)
                
            elif operation == "validate_manifest":
                manifest_file = cfg.get("manifest_file", "")
                result = await self.manifest_manager.validate_manifest(manifest_file)
                
            elif operation == "list_manifests":
                result = await self.manifest_manager.list_manifests()
                
            elif operation == "run_agent":
                node_name = cfg.get("node_name")
                once = cfg.get("once", True)
                result = await self.node_manager.run_agent(node_name, once)
                
            elif operation == "list_nodes":
                result = await self.node_manager.list_nodes()
                
            elif operation == "show_node":
                node_name = cfg.get("node_name", "")
                result = await self.node_manager.show_node(node_name)
                
            elif operation == "clean_node":
                node_name = cfg.get("node_name", "")
                result = await self.node_manager.clean_node(node_name)
                
            elif operation == "sign_node":
                node_name = cfg.get("node_name", "")
                result = await self.node_manager.sign_node(node_name)
                
            elif operation == "install_module":
                module_name = cfg.get("module_name", "")
                version = cfg.get("version")
                force = cfg.get("force", False)
                result = await self.module_manager.install_module(module_name, version, force)
                
            elif operation == "list_modules":
                result = await self.module_manager.list_modules()
                
            elif operation == "upgrade_module":
                module_name = cfg.get("module_name", "")
                result = await self.module_manager.upgrade_module(module_name)
                
            elif operation == "uninstall_module":
                module_name = cfg.get("module_name", "")
                force = cfg.get("force", False)
                result = await self.module_manager.uninstall_module(module_name, force)
                
            elif operation == "search_modules":
                search_term = cfg.get("search_term", "")
                result = await self.module_manager.search_modules(search_term)
                
            elif operation == "generate_module":
                module_name = cfg.get("module_name", "")
                result = await self.module_manager.generate_module(module_name)
                
            elif operation == "lookup_data":
                key = cfg.get("key", "")
                node_name = cfg.get("node_name")
                result = await self.hiera_manager.lookup_data(key, node_name)
                
            elif operation == "explain_lookup":
                key = cfg.get("key", "")
                node_name = cfg.get("node_name")
                result = await self.hiera_manager.explain_lookup(key, node_name)
                
            elif operation == "validate_hiera":
                result = await self.hiera_manager.validate_hiera_config()
                
            else:
                result = {
                    "success": False,
                    "error": f"Unknown operation: {operation}",
                    "available_operations": [
                        "apply_manifest", "compile_manifest", "validate_manifest", "list_manifests",
                        "run_agent", "list_nodes", "show_node", "clean_node", "sign_node",
                        "install_module", "list_modules", "upgrade_module", "uninstall_module",
                        "search_modules", "generate_module", "lookup_data", "explain_lookup", "validate_hiera"
                    ]
                }
            
            # Add execution metadata
            execution_time = (datetime.now() - start_time).total_seconds()
            result.update({
                "operation": operation,
                "execution_time": execution_time,
                "timestamp": datetime.now().isoformat(),
                "puppet_config": {
                    "puppet_dir": self.config.puppet_dir,
                    "environment": self.config.environment,
                    "apply_mode": self.config.apply_mode,
                    "use_puppetdb": self.config.use_puppetdb,
                    "timeout": self.config.timeout
                }
            })
            
            return result
            
        except Exception as e:
            execution_time = (datetime.now() - start_time).total_seconds()
            self.logger.error(f"Puppet operation failed: {e}")
            # Sanitize error message to prevent information leakage
            error_message = str(e)
            # Remove sensitive information from error messages
            sensitive_patterns = ['password', 'secret', 'key', 'token', 'ssl', 'cert']
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
    "name": "puppet",
    "version": "1.0.0",
    "description": "Puppet configuration management and automation plugin",
    "author": "PlugPipe Team",
    "category": "configuration",
    "tags": ["puppet", "configuration", "automation", "infrastructure", "manifests"],
    "requirements": ["puppet", "puppet-agent", "puppet-server"],
    "supports_async": True
}

# Main process function for PlugPipe with enhanced security
async def process(ctx: Dict, cfg: Dict) -> Dict:
    """PlugPipe entry point for Puppet plugin with comprehensive security validation"""
    try:
        # Initialize plugin with security-validated configuration
        plugin = PuppetPlugin(cfg)
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
        logger.error(f"Puppet plugin initialization failed: {e}")
        return {
            "success": False,
            "status": "error",
            "error": "Plugin initialization failed",
            "timestamp": datetime.now().isoformat()
        }