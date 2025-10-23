# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

from shares.plugpipe_path_helper import get_plugpipe_root, get_plugpipe_path, setup_plugpipe_environment
"""
Trivy Container Security Scanner Plug for PlugPipe Security.

This plugin demonstrates the PlugPipe principle "reuse, never reinvent" by leveraging 
Aqua Security's Trivy vulnerability scanner instead of implementing custom security scanning.

Philosophy:
- Reuse Trivy's battle-tested vulnerability detection engine
- Never reinvent security scanning that's already been proven in production
- Integrate with existing CI/CD and security workflows
- Provide comprehensive vulnerability analysis for containers and filesystems

Security Features via Trivy:
- Comprehensive vulnerability database with frequent updates
- Container image scanning with OS and library vulnerability detection
- Filesystem scanning for embedded vulnerabilities
- Configuration scanning for misconfigurations and security issues
- Kubernetes manifest scanning for security best practices
- SBOM generation and analysis
"""

import os
import json
import asyncio
import tempfile
import shutil
import logging
import subprocess
from pathlib import Path
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone
import time
import hashlib

try:
    import aiofiles
    AIOFILES_AVAILABLE = True
except ImportError:
    AIOFILES_AVAILABLE = False

try:
    import yaml
    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

logger = logging.getLogger(__name__)


class TrivySecurityPlug:
    """
    Trivy-based vulnerability scanning plugin for comprehensive security analysis.
    
    This plugin wraps Aqua Security's Trivy scanner instead of implementing custom
    vulnerability detection, following PlugPipe's "reuse, never reinvent" principle.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Trivy security plugin."""
        self.config = config or {}
        self.trivy_config = self.config.get("trivy_config", {})
        
        # Trivy configuration - use full path to ensure it's found
        self.trivy_binary = self.trivy_config.get("trivy_binary", "/home/david/.local/bin/trivy")
        self.trivy_cache_dir = self.trivy_config.get("cache_dir", "/tmp/trivy-cache")
        self.db_repository = self.trivy_config.get("db_repository", "ghcr.io/aquasecurity/trivy-db")
        self.severity_levels = self.trivy_config.get("severity_levels", ["CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self.scan_timeout = self.trivy_config.get("scan_timeout", 300)  # 5 minutes
        self.update_db_on_startup = self.trivy_config.get("update_db", True)
        self.offline_mode = self.trivy_config.get("offline_mode", False)
        
        # Output configuration
        self.default_output_format = self.trivy_config.get("output_format", "json")
        self.include_dev_deps = self.trivy_config.get("include_dev_dependencies", False)
        self.skip_dirs = self.trivy_config.get("skip_dirs", [".git", "node_modules", "__pycache__"])
        
        # Compliance and policy configuration
        self.compliance_frameworks = self.trivy_config.get("compliance", ["cis", "nist"])
        self.custom_policies_dir = self.trivy_config.get("custom_policies_dir")
        
        # Integration configuration
        self.integrate_with_registry = self.trivy_config.get("integrate_registry", True)
        self.registry_credentials = self.trivy_config.get("registry_credentials", {})
        
        # Performance optimization
        self.parallel_scans = self.trivy_config.get("parallel_scans", 4)
        self.cache_ttl = self.trivy_config.get("cache_ttl", 86400)  # 24 hours
        
        # Initialize Trivy environment
        self._initialize_trivy_environment()
        
        logger.info("Trivy security plugin initialized successfully")
    
    def _initialize_trivy_environment(self):
        """Initialize Trivy scanning environment with automatic dependency management."""
        try:
            # Create cache directory
            os.makedirs(self.trivy_cache_dir, exist_ok=True)
            
            # Check Trivy installation - if not available, try to install
            result = subprocess.run(
                [self.trivy_binary, "--version"],
                capture_output=True,
                text=True,
                timeout=10
            )
            
            if result.returncode != 0:
                logger.warning(f"Trivy not available at {self.trivy_binary}, attempting automatic installation...")
                
                # Try to install Trivy using dependency manager
                install_result = self._install_trivy_dependency()
                if not install_result.get('success', False):
                    raise RuntimeError(f"Failed to install Trivy: {install_result.get('error', 'Unknown error')}")
                
                # Retry version check
                result = subprocess.run(
                    [self.trivy_binary, "--version"],
                    capture_output=True,
                    text=True,
                    timeout=10
                )
                
                if result.returncode != 0:
                    raise RuntimeError(f"Trivy installation succeeded but binary still not working: {result.stderr}")
            
            trivy_version = result.stdout.strip()
            logger.info(f"Using {trivy_version} from {self.trivy_binary}")
            
            # Update vulnerability database if requested
            if self.update_db_on_startup and not self.offline_mode:
                self._update_vulnerability_database()
            
        except subprocess.TimeoutExpired:
            raise RuntimeError("Trivy installation check timed out")
        except Exception as e:
            raise RuntimeError(f"Failed to initialize Trivy environment: {str(e)}")
    
    def _install_trivy_dependency(self):
        """Install Trivy using PlugPipe dependency manager"""
        try:
            # Import dependency manager
            sys.path.insert(0, get_plugpipe_root())
            from shares.loader import pp
            
            dependency_manager = pp('dependency_manager')
            
            # Define Trivy dependency
            trivy_dependency = {
                'dependencies': [{
                    'name': 'trivy',
                    'type': 'binary',
                    'version': '0.65.0',
                    'required': True
                }]
            }
            
            result = dependency_manager.process(trivy_dependency, {})
            return result
            
        except Exception as e:
            logger.error(f"Failed to use dependency manager for Trivy installation: {e}")
            return {'success': False, 'error': str(e)}
    
    def _update_vulnerability_database(self):
        """Update Trivy vulnerability database."""
        try:
            logger.info("Updating Trivy vulnerability database...")
            
            cmd = [
                self.trivy_binary,
                "image",
                "--download-db-only",
                "--cache-dir", self.trivy_cache_dir
            ]
            
            if self.db_repository:
                cmd.extend(["--db-repository", self.db_repository])
            
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=120  # 2 minutes for DB update
            )
            
            if result.returncode == 0:
                logger.info("Vulnerability database updated successfully")
            else:
                logger.warning(f"Database update warning: {result.stderr}")
            
        except subprocess.TimeoutExpired:
            logger.error("Database update timed out")
        except Exception as e:
            logger.error(f"Failed to update vulnerability database: {str(e)}")
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process security scanning operation using Trivy.
        
        Args:
            ctx: Operation context with scanning parameters
            cfg: Plug configuration
            
        Returns:
            Security scanning result with vulnerability analysis
        """
        try:
            # Extract operation parameters
            operation = ctx.get("operation")
            if not operation:
                return {
                    "success": False,
                    "error": "Operation parameter is required"
                }
            
            # Route to appropriate scanner
            if operation == "scan_image":
                result = await self._scan_container_image(ctx, cfg)
            elif operation == "scan_filesystem":
                result = await self._scan_filesystem(ctx, cfg)
            elif operation == "scan_repository":
                result = await self._scan_repository(ctx, cfg)
            elif operation == "scan_kubernetes":
                result = await self._scan_kubernetes_manifests(ctx, cfg)
            elif operation == "generate_sbom":
                result = await self._generate_sbom(ctx, cfg)
            elif operation == "scan_config":
                result = await self._scan_configuration(ctx, cfg)
            elif operation == "compliance_check":
                result = await self._compliance_check(ctx, cfg)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operation: {operation}"
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Trivy security scanning error: {str(e)}")
            return {
                "success": False,
                "error": f"Security scanning failed: {str(e)}"
            }
    
    async def _scan_container_image(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Scan container image for vulnerabilities using Trivy."""
        try:
            image_name = ctx.get("image_name")
            if not image_name:
                return {"success": False, "error": "image_name is required for container scanning"}
            
            scan_config = ctx.get("scan_config", {})
            
            # Build Trivy command
            cmd = [
                self.trivy_binary,
                "image",
                "--format", scan_config.get("format", self.default_output_format),
                "--cache-dir", self.trivy_cache_dir,
                "--timeout", f"{self.scan_timeout}s"
            ]
            
            # Add severity filter
            severity_filter = scan_config.get("severity", self.severity_levels)
            if severity_filter:
                cmd.extend(["--severity", ",".join(severity_filter)])
            
            # Add vulnerability types
            vuln_types = scan_config.get("vuln_types", ["os", "library"])
            if vuln_types:
                cmd.extend(["--vuln-type", ",".join(vuln_types)])
            
            # Add registry authentication if needed
            if self.registry_credentials and image_name.count('/') > 0:
                registry_host = image_name.split('/')[0]
                if registry_host in self.registry_credentials:
                    creds = self.registry_credentials[registry_host]
                    cmd.extend([
                        "--username", creds.get("username", ""),
                        "--password", creds.get("password", "")
                    ])
            
            # Add offline mode if configured
            if self.offline_mode:
                cmd.append("--offline-scan")
            
            # Add custom policies if configured
            if self.custom_policies_dir and os.path.exists(self.custom_policies_dir):
                cmd.extend(["--config-policy", self.custom_policies_dir])
            
            # Add image name
            cmd.append(image_name)
            
            # Execute scan
            start_time = time.time()
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=self.scan_timeout
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown scan error"
                return {
                    "success": False,
                    "error": f"Image scan failed: {error_msg}",
                    "execution_time": execution_time
                }
            
            # Parse scan results
            scan_output = stdout.decode('utf-8')
            vulnerabilities = self._parse_trivy_output(scan_output, scan_config.get("format", "json"))
            
            # Generate security metrics
            security_metrics = self._generate_security_metrics(vulnerabilities)
            
            return {
                "success": True,
                "result": {
                    "image_name": image_name,
                    "vulnerabilities": vulnerabilities,
                    "security_metrics": security_metrics,
                    "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                    "execution_time_seconds": execution_time
                },
                "trivy_metadata": {
                    "trivy_version": await self._get_trivy_version(),
                    "scan_type": "container_image",
                    "severity_filter": severity_filter,
                    "vuln_types": vuln_types
                }
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"Image scan timed out after {self.scan_timeout} seconds"
            }
        except Exception as e:
            logger.error(f"Container image scan error: {str(e)}")
            return {
                "success": False,
                "error": f"Container image scan failed: {str(e)}"
            }
    
    async def _scan_filesystem(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Scan filesystem for vulnerabilities using Trivy."""
        try:
            target_path = ctx.get("target_path")
            if not target_path or not os.path.exists(target_path):
                return {"success": False, "error": "valid target_path is required for filesystem scanning"}
            
            scan_config = ctx.get("scan_config", {})
            
            # Build Trivy command
            cmd = [
                self.trivy_binary,
                "filesystem",
                "--format", scan_config.get("format", self.default_output_format),
                "--cache-dir", self.trivy_cache_dir,
                "--timeout", f"{self.scan_timeout}s"
            ]
            
            # Add severity filter
            severity_filter = scan_config.get("severity", self.severity_levels)
            if severity_filter:
                cmd.extend(["--severity", ",".join(severity_filter)])
            
            # Add skip directories
            skip_dirs = scan_config.get("skip_dirs", self.skip_dirs)
            for skip_dir in skip_dirs:
                cmd.extend(["--skip-dirs", skip_dir])
            
            # Add security checks
            security_checks = scan_config.get("security_checks", ["vuln", "secret", "config"])
            if security_checks:
                cmd.extend(["--scanners", ",".join(security_checks)])
            
            # Add custom policies if configured
            if self.custom_policies_dir and os.path.exists(self.custom_policies_dir):
                cmd.extend(["--config-policy", self.custom_policies_dir])
            
            # Add target path
            cmd.append(target_path)
            
            # Execute scan
            start_time = time.time()
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=self.scan_timeout
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown scan error"
                return {
                    "success": False,
                    "error": f"Filesystem scan failed: {error_msg}",
                    "execution_time": execution_time
                }
            
            # Parse scan results
            scan_output = stdout.decode('utf-8')
            vulnerabilities = self._parse_trivy_output(scan_output, scan_config.get("format", "json"))
            
            # Generate security metrics
            security_metrics = self._generate_security_metrics(vulnerabilities)
            
            # Generate file hashes for integrity checking
            file_hashes = await self._generate_file_hashes(target_path, scan_config.get("hash_files", True))
            
            return {
                "success": True,
                "result": {
                    "target_path": target_path,
                    "vulnerabilities": vulnerabilities,
                    "security_metrics": security_metrics,
                    "file_hashes": file_hashes,
                    "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                    "execution_time_seconds": execution_time
                },
                "trivy_metadata": {
                    "trivy_version": await self._get_trivy_version(),
                    "scan_type": "filesystem",
                    "severity_filter": severity_filter,
                    "security_checks": security_checks
                }
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"Filesystem scan timed out after {self.scan_timeout} seconds"
            }
        except Exception as e:
            logger.error(f"Filesystem scan error: {str(e)}")
            return {
                "success": False,
                "error": f"Filesystem scan failed: {str(e)}"
            }
    
    async def _scan_kubernetes_manifests(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Scan Kubernetes manifests for security misconfigurations."""
        try:
            manifest_path = ctx.get("manifest_path")
            if not manifest_path or not os.path.exists(manifest_path):
                return {"success": False, "error": "valid manifest_path is required for Kubernetes scanning"}
            
            scan_config = ctx.get("scan_config", {})
            
            # Build Trivy command for Kubernetes config scanning
            cmd = [
                self.trivy_binary,
                "config",
                "--format", scan_config.get("format", self.default_output_format),
                "--cache-dir", self.trivy_cache_dir,
                "--timeout", f"{self.scan_timeout}s"
            ]
            
            # Add severity filter
            severity_filter = scan_config.get("severity", ["HIGH", "CRITICAL"])
            if severity_filter:
                cmd.extend(["--severity", ",".join(severity_filter)])
            
            # Add policy configuration
            policy_types = scan_config.get("policy_types", ["kubernetes"])
            if policy_types:
                cmd.extend(["--policy", ",".join(policy_types)])
            
            # Add compliance frameworks
            compliance = scan_config.get("compliance", self.compliance_frameworks)
            if compliance:
                cmd.extend(["--compliance", ",".join(compliance)])
            
            # Add custom policies if configured
            if self.custom_policies_dir and os.path.exists(self.custom_policies_dir):
                cmd.extend(["--config-policy", self.custom_policies_dir])
            
            # Add manifest path
            cmd.append(manifest_path)
            
            # Execute scan
            start_time = time.time()
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=self.scan_timeout
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown scan error"
                return {
                    "success": False,
                    "error": f"Kubernetes manifest scan failed: {error_msg}",
                    "execution_time": execution_time
                }
            
            # Parse scan results
            scan_output = stdout.decode('utf-8')
            misconfigurations = self._parse_trivy_output(scan_output, scan_config.get("format", "json"))
            
            # Generate security metrics for misconfigurations
            security_metrics = self._generate_security_metrics(misconfigurations)
            
            return {
                "success": True,
                "result": {
                    "manifest_path": manifest_path,
                    "misconfigurations": misconfigurations,
                    "security_metrics": security_metrics,
                    "scan_timestamp": datetime.now(timezone.utc).isoformat(),
                    "execution_time_seconds": execution_time
                },
                "trivy_metadata": {
                    "trivy_version": await self._get_trivy_version(),
                    "scan_type": "kubernetes_config",
                    "severity_filter": severity_filter,
                    "policy_types": policy_types,
                    "compliance_frameworks": compliance
                }
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"Kubernetes scan timed out after {self.scan_timeout} seconds"
            }
        except Exception as e:
            logger.error(f"Kubernetes manifest scan error: {str(e)}")
            return {
                "success": False,
                "error": f"Kubernetes manifest scan failed: {str(e)}"
            }
    
    async def _generate_sbom(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Generate Software Bill of Materials using Trivy."""
        try:
            target = ctx.get("target")
            target_type = ctx.get("target_type", "image")  # image, filesystem, repository
            
            if not target:
                return {"success": False, "error": "target is required for SBOM generation"}
            
            sbom_config = ctx.get("sbom_config", {})
            
            # Build Trivy command for SBOM generation
            cmd = [
                self.trivy_binary,
                target_type,
                "--format", sbom_config.get("format", "spdx-json"),
                "--cache-dir", self.trivy_cache_dir,
                "--timeout", f"{self.scan_timeout}s"
            ]
            
            # Add SBOM-specific options
            if sbom_config.get("include_dev_deps", self.include_dev_deps):
                cmd.append("--include-dev-deps")
            
            # Add target
            cmd.append(target)
            
            # Execute SBOM generation
            start_time = time.time()
            
            result = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, stderr = await asyncio.wait_for(
                result.communicate(),
                timeout=self.scan_timeout
            )
            
            execution_time = time.time() - start_time
            
            if result.returncode != 0:
                error_msg = stderr.decode('utf-8') if stderr else "Unknown SBOM generation error"
                return {
                    "success": False,
                    "error": f"SBOM generation failed: {error_msg}",
                    "execution_time": execution_time
                }
            
            # Parse SBOM output
            sbom_output = stdout.decode('utf-8')
            
            # Save SBOM to file if requested
            sbom_file_path = None
            if sbom_config.get("save_to_file"):
                sbom_file_path = sbom_config.get("file_path", f"/tmp/sbom-{int(time.time())}.json")
                with open(sbom_file_path, 'w') as f:
                    f.write(sbom_output)
            
            return {
                "success": True,
                "result": {
                    "target": target,
                    "target_type": target_type,
                    "sbom": sbom_output if sbom_config.get("include_sbom", True) else "SBOM generated successfully",
                    "sbom_file_path": sbom_file_path,
                    "sbom_format": sbom_config.get("format", "spdx-json"),
                    "generation_timestamp": datetime.now(timezone.utc).isoformat(),
                    "execution_time_seconds": execution_time
                },
                "trivy_metadata": {
                    "trivy_version": await self._get_trivy_version(),
                    "operation": "sbom_generation"
                }
            }
            
        except asyncio.TimeoutError:
            return {
                "success": False,
                "error": f"SBOM generation timed out after {self.scan_timeout} seconds"
            }
        except Exception as e:
            logger.error(f"SBOM generation error: {str(e)}")
            return {
                "success": False,
                "error": f"SBOM generation failed: {str(e)}"
            }
    
    def _parse_trivy_output(self, output: str, format_type: str) -> Dict[str, Any]:
        """Parse Trivy scan output based on format type."""
        try:
            if format_type == "json":
                return json.loads(output) if output.strip() else {}
            elif format_type in ["yaml", "yml"]:
                return yaml.safe_load(output) if YAML_AVAILABLE and output.strip() else {}
            else:
                # For other formats, return raw output
                return {"raw_output": output}
        except Exception as e:
            logger.error(f"Failed to parse Trivy output: {str(e)}")
            return {"parse_error": str(e), "raw_output": output}
    
    def _generate_security_metrics(self, vulnerabilities: Dict[str, Any]) -> Dict[str, Any]:
        """Generate security metrics from vulnerability data."""
        try:
            metrics = {
                "total_vulnerabilities": 0,
                "severity_breakdown": {
                    "CRITICAL": 0,
                    "HIGH": 0,
                    "MEDIUM": 0,
                    "LOW": 0,
                    "UNKNOWN": 0
                },
                "vulnerability_types": {},
                "affected_packages": [],
                "security_score": 100,  # Start with perfect score
                "risk_level": "LOW"
            }
            
            # Handle different output formats
            if isinstance(vulnerabilities, dict):
                if "Results" in vulnerabilities:
                    # Standard Trivy JSON output
                    for result in vulnerabilities.get("Results", []):
                        for vuln in result.get("Vulnerabilities", []):
                            severity = vuln.get("Severity", "UNKNOWN")
                            metrics["severity_breakdown"][severity] += 1
                            metrics["total_vulnerabilities"] += 1
                            
                            # Track vulnerability types
                            vuln_type = vuln.get("Type", "unknown")
                            metrics["vulnerability_types"][vuln_type] = metrics["vulnerability_types"].get(vuln_type, 0) + 1
                            
                            # Track affected packages
                            pkg_name = vuln.get("PkgName", "unknown")
                            if pkg_name not in metrics["affected_packages"]:
                                metrics["affected_packages"].append(pkg_name)
            
            # Calculate security score (100 - weighted severity penalties)
            score_penalties = {
                "CRITICAL": 25,
                "HIGH": 10,
                "MEDIUM": 3,
                "LOW": 1
            }
            
            total_penalty = 0
            for severity, count in metrics["severity_breakdown"].items():
                if severity in score_penalties:
                    total_penalty += count * score_penalties[severity]
            
            metrics["security_score"] = max(0, 100 - total_penalty)
            
            # Determine risk level
            if metrics["severity_breakdown"]["CRITICAL"] > 0:
                metrics["risk_level"] = "CRITICAL"
            elif metrics["severity_breakdown"]["HIGH"] > 5:
                metrics["risk_level"] = "HIGH"
            elif metrics["severity_breakdown"]["HIGH"] > 0 or metrics["severity_breakdown"]["MEDIUM"] > 10:
                metrics["risk_level"] = "MEDIUM"
            else:
                metrics["risk_level"] = "LOW"
            
            return metrics
            
        except Exception as e:
            logger.error(f"Failed to generate security metrics: {str(e)}")
            return {"error": str(e)}
    
    async def _generate_file_hashes(self, target_path: str, enabled: bool = True) -> Dict[str, str]:
        """Generate file hashes for integrity checking."""
        if not enabled:
            return {}
        
        try:
            file_hashes = {}
            
            if os.path.isfile(target_path):
                # Single file
                file_hashes[target_path] = await self._hash_file(target_path)
            elif os.path.isdir(target_path):
                # Directory - hash important files
                for root, dirs, files in os.walk(target_path):
                    # Skip hidden directories and common build artifacts
                    dirs[:] = [d for d in dirs if not d.startswith('.') and d not in self.skip_dirs]
                    
                    for file in files:
                        if not file.startswith('.') and file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.xml')):
                            file_path = os.path.join(root, file)
                            try:
                                file_hashes[file_path] = await self._hash_file(file_path)
                            except Exception as e:
                                logger.warning(f"Failed to hash {file_path}: {str(e)}")
                            
                            # Limit to prevent memory issues
                            if len(file_hashes) > 1000:
                                break
            
            return file_hashes
            
        except Exception as e:
            logger.error(f"Failed to generate file hashes: {str(e)}")
            return {}
    
    async def _hash_file(self, file_path: str) -> str:
        """Generate SHA256 hash of a file."""
        try:
            hash_sha256 = hashlib.sha256()
            
            if AIOFILES_AVAILABLE:
                async with aiofiles.open(file_path, 'rb') as f:
                    while chunk := await f.read(8192):
                        hash_sha256.update(chunk)
            else:
                with open(file_path, 'rb') as f:
                    while chunk := f.read(8192):
                        hash_sha256.update(chunk)
            
            return hash_sha256.hexdigest()
            
        except Exception as e:
            logger.error(f"Failed to hash file {file_path}: {str(e)}")
            return ""
    
    async def _get_trivy_version(self) -> str:
        """Get Trivy version string."""
        try:
            result = await asyncio.create_subprocess_exec(
                self.trivy_binary, "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            stdout, _ = await asyncio.wait_for(result.communicate(), timeout=10)
            return stdout.decode('utf-8').strip()
            
        except Exception:
            return "unknown"
    
    async def health_check(self) -> Dict[str, Any]:
        """Check Trivy availability and database status."""
        try:
            # Check Trivy binary
            version = await self._get_trivy_version()
            
            # Check cache directory
            cache_exists = os.path.exists(self.trivy_cache_dir)
            cache_writable = os.access(self.trivy_cache_dir, os.W_OK) if cache_exists else False
            
            # Check database freshness
            db_files = []
            if cache_exists:
                db_pattern = os.path.join(self.trivy_cache_dir, "db", "*")
                import glob
                db_files = glob.glob(db_pattern)
            
            db_age_hours = 0
            if db_files:
                latest_db = max(db_files, key=os.path.getmtime)
                db_age_hours = (time.time() - os.path.getmtime(latest_db)) / 3600
            
            healthy = all([
                "Version" in version,
                cache_exists,
                cache_writable,
                db_age_hours < 168  # Less than 1 week old
            ])
            
            return {
                "healthy": healthy,
                "trivy_version": version,
                "cache_directory": {
                    "path": self.trivy_cache_dir,
                    "exists": cache_exists,
                    "writable": cache_writable
                },
                "vulnerability_database": {
                    "files_found": len(db_files),
                    "age_hours": db_age_hours,
                    "update_needed": db_age_hours > 24
                },
                "configuration": {
                    "offline_mode": self.offline_mode,
                    "severity_levels": self.severity_levels,
                    "scan_timeout": self.scan_timeout
                }
            }
            
        except Exception as e:
            return {
                "healthy": False,
                "error": str(e)
            }


# Plug entry point for PlugPipe compatibility
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Plug entry point for PlugPipe compatibility.
    
    This function demonstrates the plugin-first approach by leveraging Trivy's
    proven vulnerability scanning engine instead of implementing custom security scanning.
    
    Args:
        ctx: Plug execution context with scanning parameters
        cfg: Plug configuration including Trivy settings
        
    Returns:
        Security scanning result with vulnerability analysis
    """
    try:
        # Create plugin instance
        plugin = TrivySecurityPlug(cfg)
        
        # Execute security scan
        result = await plugin.process(ctx, cfg)
        
        return result
        
    except Exception as e:
        logger.error(f"Trivy security plugin error: {str(e)}")
        return {
            "success": False,
            "error": f"Trivy security error: {str(e)}"
        }


# Health check for monitoring systems
async def health_check(cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """Health check for Trivy security plugin."""
    try:
        plugin = TrivySecurityPlug(cfg)
        return await plugin.health_check()
    except Exception as e:
        return {
            "healthy": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test execution
    import asyncio
    
    async def test():
        # Test with minimal configuration
        config = {
            "trivy_config": {
                "offline_mode": True,  # For testing without network
                "update_db": False
            }
        }
        
        # Test health check
        health = await health_check(config)
        print("Health check:", json.dumps(health, indent=2))
        
        # Test image scan (would require Trivy installation)
        # scan_ctx = {
        #     "operation": "scan_image",
        #     "image_name": "alpine:latest",
        #     "scan_config": {
        #         "severity": ["HIGH", "CRITICAL"]
        #     }
        # }
        # 
        # result = await process(scan_ctx, config)
        # print("Image scan test:", json.dumps(result, indent=2))
    
    asyncio.run(test())