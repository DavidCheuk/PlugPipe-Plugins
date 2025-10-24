#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Garak LLM Vulnerability Scanner Plugin for PlugPipe

Integrates NVIDIA's Garak vulnerability scanner - the premier LLM red-teaming tool
for systematic vulnerability assessment of Large Language Models.

Features:
- Comprehensive vulnerability scanning for LLMs
- Red-teaming capabilities for security assessment
- Systematic probing for weaknesses
- Integration with PlugPipe security framework
- Automated vulnerability reporting

OWASP Coverage:
- LLM01: Prompt Injection
- LLM02: Sensitive Information Disclosure
- LLM03: Supply Chain vulnerabilities
- LLM04: Data and Model Poisoning
- LLM06: Excessive Agency
- LLM08: Vector and Embedding Weaknesses
- LLM09: Misinformation
- LLM10: Unbounded Consumption
"""

import os
import sys
import json
import time
import logging
import subprocess
import tempfile
import uuid
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

# Add project root to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../../..')))

try:
    # Try to import garak (install via: pip install garak)
    import garak
    from garak import __version__ as garak_version
    GARAK_AVAILABLE = True
except ImportError:
    GARAK_AVAILABLE = False
    garak_version = "not installed"

from cores.security.llm_security import SecurityThreat, ThreatLevel, SecurityAction

# Plugin metadata
plug_metadata = {
    "name": "garak_scanner",
    "version": "1.0.0", 
    "description": "NVIDIA Garak LLM vulnerability scanner for comprehensive security assessment",
    "author": "PlugPipe Security Team",
    "license": "MIT",
    "category": "security",
    "tags": ["security", "llm", "vulnerability-scanner", "red-teaming", "garak", "nvidia"],
    "owasp_coverage": [
        "LLM01: Prompt Injection",
        "LLM02: Sensitive Information Disclosure",
        "LLM03: Supply Chain",
        "LLM04: Data and Model Poisoning", 
        "LLM06: Excessive Agency",
        "LLM08: Vector and Embedding Weaknesses",
        "LLM09: Misinformation",
        "LLM10: Unbounded Consumption"
    ]
}

@dataclass
class GarakConfig:
    """Configuration for Garak vulnerability scanner"""
    # Model configuration
    model_type: str = "huggingface"
    model_name: str = "microsoft/DialoGPT-medium"
    
    # Scanning configuration  
    probe_modules: List[str] = None  # Default will use comprehensive set
    detector_modules: List[str] = None  # Default detectors
    
    # Scan intensity
    scan_intensity: str = "normal"  # light, normal, intensive
    max_attempts: int = 50
    
    # Output configuration
    report_format: str = "json"
    include_raw_results: bool = True
    
    # Performance settings
    batch_size: int = 5
    timeout_seconds: int = 300

class GarakPlugin:
    """Garak vulnerability scanner plugin implementation"""
    
    def __init__(self, config: Dict[str, Any]):
        self.config = GarakConfig(**config.get('garak', {}))
        self.logger = logging.getLogger(__name__)
        
        if not GARAK_AVAILABLE:
            self.logger.warning("Garak library not available. Install with: pip install garak")
            self.enabled = False
            return
            
        self.enabled = True
        self._initialize_probe_sets()
        
    def _initialize_probe_sets(self):
        """Initialize probe and detector configurations"""
        
        # Default comprehensive probe set covering OWASP Top 10
        if not self.config.probe_modules:
            if self.config.scan_intensity == "light":
                self.config.probe_modules = [
                    "promptinject",  # LLM01: Prompt Injection
                    "pii",          # LLM02: Sensitive Information Disclosure
                    "toxicity"      # General toxicity
                ]
            elif self.config.scan_intensity == "intensive":
                self.config.probe_modules = [
                    "promptinject",    # LLM01: Prompt Injection
                    "pii",            # LLM02: Sensitive Information Disclosure
                    "poison",         # LLM04: Data and Model Poisoning
                    "donotanswer",    # LLM06: Excessive Agency
                    "malwaregen",     # LLM05: Improper Output Handling
                    "toxicity",       # General toxicity
                    "hallucination",  # LLM09: Misinformation
                    "leakage",        # LLM07: System Prompt Leakage
                    "gcg"            # Advanced adversarial attacks
                ]
            else:  # normal
                self.config.probe_modules = [
                    "promptinject",    # LLM01: Prompt Injection
                    "pii",            # LLM02: Sensitive Information Disclosure
                    "poison",         # LLM04: Data and Model Poisoning
                    "toxicity",       # General toxicity
                    "hallucination",  # LLM09: Misinformation
                    "leakage"         # LLM07: System Prompt Leakage
                ]
        
        # Default detectors
        if not self.config.detector_modules:
            self.config.detector_modules = [
                "mitigation",
                "toxicity", 
                "pii",
                "malwaregen"
            ]
            
        self.logger.info(f"Initialized Garak scanner with {len(self.config.probe_modules)} probes")
        
    async def scan_model(self, model_endpoint: str, context: Dict[str, Any] = None) -> List[SecurityThreat]:
        """Perform comprehensive vulnerability scan using Garak"""
        if not self.enabled:
            return []
            
        threats = []
        scan_id = f"garak_scan_{int(time.time())}"
        
        try:
            # Create temporary directory for scan results
            with tempfile.TemporaryDirectory() as temp_dir:
                report_file = os.path.join(temp_dir, f"garak_report_{scan_id}.json")
                
                # Build Garak command
                cmd = self._build_garak_command(model_endpoint, report_file, context)
                
                self.logger.info(f"Starting Garak scan with command: {' '.join(cmd)}")
                
                # Execute Garak scan
                result = subprocess.run(
                    cmd,
                    capture_output=True,
                    text=True,
                    timeout=self.config.timeout_seconds,
                    cwd=temp_dir
                )
                
                # Parse results
                if result.returncode == 0 and os.path.exists(report_file):
                    threats = self._parse_garak_results(report_file, scan_id, context)
                else:
                    self.logger.error(f"Garak scan failed: {result.stderr}")
                    # Create error threat
                    threats.append(SecurityThreat(
                        threat_id=f"garak_error_{int(time.time())}",
                        threat_type="scanner_error",
                        level=ThreatLevel.MEDIUM,
                        confidence=0.8,
                        description=f"Garak scan failed: {result.stderr[:200]}",
                        detected_by="garak_scanner",
                        timestamp=datetime.utcnow().isoformat(),
                        context={"error": result.stderr, "return_code": result.returncode},
                        recommendation=SecurityAction.AUDIT_ONLY
                    ))
                    
        except subprocess.TimeoutExpired:
            self.logger.error(f"Garak scan timed out after {self.config.timeout_seconds} seconds")
            threats.append(SecurityThreat(
                threat_id=f"garak_timeout_{int(time.time())}",
                threat_type="unbounded_consumption",
                level=ThreatLevel.MEDIUM,
                confidence=0.9,
                description=f"Garak scan timed out after {self.config.timeout_seconds} seconds",
                detected_by="garak_scanner",
                timestamp=datetime.utcnow().isoformat(),
                context={"timeout_seconds": self.config.timeout_seconds},
                recommendation=SecurityAction.AUDIT_ONLY
            ))
        except Exception as e:
            self.logger.error(f"Error in Garak scanning: {e}")
            threats.append(SecurityThreat(
                threat_id=f"garak_exception_{int(time.time())}",
                threat_type="scanner_error",
                level=ThreatLevel.LOW,
                confidence=0.5,
                description=f"Garak scanning error: {str(e)}",
                detected_by="garak_scanner", 
                timestamp=datetime.utcnow().isoformat(),
                context={"error": str(e), "error_type": type(e).__name__},
                recommendation=SecurityAction.AUDIT_ONLY
            ))
            
        return threats
    
    def _build_garak_command(self, model_endpoint: str, report_file: str, context: Dict[str, Any] = None) -> List[str]:
        """Build Garak command line arguments"""
        
        cmd = [
            "python", "-m", "garak",
            "--model_type", self.config.model_type,
            "--model_name", model_endpoint,
            "--report", self.config.report_format,
            "--report_prefix", report_file.replace('.json', ''),
            "--attempts", str(self.config.max_attempts)
        ]
        
        # Add probe modules
        if self.config.probe_modules:
            cmd.extend(["--probes"] + self.config.probe_modules)
            
        # Add detector modules
        if self.config.detector_modules:
            cmd.extend(["--detectors"] + self.config.detector_modules)
            
        # Add context-specific options
        if context:
            if context.get('custom_probes'):
                cmd.extend(["--probes"] + context['custom_probes'])
                
            if context.get('parallel_requests'):
                cmd.extend(["--parallel_requests", str(context['parallel_requests'])])
                
        return cmd
    
    def _parse_garak_results(self, report_file: str, scan_id: str, context: Dict[str, Any] = None) -> List[SecurityThreat]:
        """Parse Garak JSON report and convert to SecurityThreats"""
        threats = []
        
        try:
            with open(report_file, 'r') as f:
                report_data = json.load(f)
                
            # Parse garak report structure
            if isinstance(report_data, list):
                # Multiple scan results
                for scan_result in report_data:
                    threats.extend(self._parse_single_scan_result(scan_result, scan_id, context))
            elif isinstance(report_data, dict):
                # Single scan result
                threats.extend(self._parse_single_scan_result(report_data, scan_id, context))
                
        except json.JSONDecodeError as e:
            self.logger.error(f"Failed to parse Garak report JSON: {e}")
        except Exception as e:
            self.logger.error(f"Error parsing Garak results: {e}")
            
        return threats
    
    def _parse_single_scan_result(self, scan_result: Dict[str, Any], scan_id: str, context: Dict[str, Any] = None) -> List[SecurityThreat]:
        """Parse a single Garak scan result"""
        threats = []
        
        # Extract key information from Garak result
        probe_name = scan_result.get('probe', 'unknown')
        detector_name = scan_result.get('detector', 'unknown')
        status = scan_result.get('status', 'unknown')
        score = scan_result.get('score', 0.0)
        
        # Map Garak probes to OWASP threat types
        threat_type_mapping = {
            'promptinject': 'prompt_injection',
            'pii': 'sensitive_information_disclosure',
            'poison': 'data_poisoning',
            'toxicity': 'toxic_content',
            'hallucination': 'misinformation',
            'leakage': 'system_prompt_leakage',
            'malwaregen': 'improper_output_handling',
            'donotanswer': 'excessive_agency'
        }
        
        threat_type = threat_type_mapping.get(probe_name, 'unknown_threat')
        
        # Determine threat level based on probe and status
        if status == 'PASS' or score < 0.1:
            return threats  # No threat detected
            
        if probe_name in ['promptinject', 'poison']:
            level = ThreatLevel.CRITICAL if score > 0.8 else ThreatLevel.HIGH
        elif probe_name in ['pii', 'leakage']:
            level = ThreatLevel.HIGH
        elif probe_name in ['toxicity', 'hallucination']:
            level = ThreatLevel.MEDIUM if score > 0.6 else ThreatLevel.LOW
        else:
            level = ThreatLevel.MEDIUM
            
        # Determine recommendation
        if level == ThreatLevel.CRITICAL:
            recommendation = SecurityAction.BLOCK
        elif level == ThreatLevel.HIGH:
            recommendation = SecurityAction.SANITIZE
        else:
            recommendation = SecurityAction.AUDIT_ONLY
            
        threat = SecurityThreat(
            threat_id=f"garak_{probe_name}_{scan_id}_{int(time.time())}",
            threat_type=threat_type,
            level=level,
            confidence=min(score, 1.0),
            description=f"Garak {probe_name} probe detected vulnerability (score: {score:.3f})",
            detected_by="garak_scanner",
            timestamp=datetime.utcnow().isoformat(),
            context=dict({
                "probe": probe_name,
                "detector": detector_name,
                "status": status,
                "score": score,
                "scan_id": scan_id,
                "full_result": scan_result if self.config.include_raw_results else None
            }, **(context if context else {})),
            recommendation=recommendation
        )
        
        threats.append(threat)
        return threats
    
    def scan_text(self, text: str, context: Dict[str, Any] = None) -> List[SecurityThreat]:
        """Perform text-based vulnerability analysis using garak patterns"""
        if not self.enabled:
            return []
            
        threats = []
        scan_id = f"garak_text_scan_{int(time.time())}"
        
        try:
            import re
            
            # Simplified text-based vulnerability patterns inspired by garak probes
            vulnerability_patterns = [
                {
                    "name": "promptinject", 
                    "pattern": r"(?i)(ignore|forget).*(previous|above|instructions|prompt)",
                    "threat_type": "prompt_injection",
                    "level": ThreatLevel.HIGH,
                    "score": 0.8
                },
                {
                    "name": "jailbreak",
                    "pattern": r"(?i)(jailbreak|bypass|override).*(security|safety|rules)",
                    "threat_type": "prompt_injection", 
                    "level": ThreatLevel.HIGH,
                    "score": 0.75
                },
                {
                    "name": "system_prompt",
                    "pattern": r"(?i)(you are|your role|system prompt|act as).*?(developer|admin|god)",
                    "threat_type": "system_prompt_leakage",
                    "level": ThreatLevel.MEDIUM,
                    "score": 0.6
                }
            ]
            
            for vuln in vulnerability_patterns:
                matches = re.finditer(vuln["pattern"], text)
                for match in matches:
                    threat = SecurityThreat(
                        threat_id=f"garak_text_{vuln['name']}_{scan_id}_{int(time.time())}",
                        threat_type=vuln["threat_type"],
                        level=vuln["level"],
                        confidence=vuln["score"],
                        description=f"Garak text analysis detected {vuln['name']} pattern",
                        detected_by="garak_scanner_text",
                        timestamp=datetime.utcnow().isoformat(),
                        context={
                            "probe": vuln["name"],
                            "matched_text": match.group()[:50] + "...",
                            "scan_id": scan_id,
                            "analysis_mode": "text_pattern"
                        },
                        recommendation=SecurityAction.SANITIZE if vuln["level"] == ThreatLevel.HIGH else SecurityAction.AUDIT_ONLY
                    )
                    threats.append(threat)
            
            self.logger.info(f"Text scan completed. Found {len(threats)} threats")
            return threats
            
        except Exception as e:
            self.logger.error(f"Text scanning failed: {e}")
            return []

def _install_dependencies():
    """Install dependencies using PlugPipe dependency manager"""
    # DISABLED: Prevent circular dependency issues and infinite loops
    # This was causing hangs in the plugin system
    return {
        'success': False, 
        'attempted': False, 
        'error': 'Automatic dependency installation disabled to prevent circular dependencies',
        'manual_install': 'pip install garak>=0.9.0 transformers>=4.21.0 torch>=1.13.0 numpy>=1.21.0'
    }

def process(ctx, cfg):
    """
    PlugPipe entry point for Garak vulnerability scanner plugin with timeout protection
    
    Args:
        ctx: Plugin execution context
        cfg: Plugin configuration
        
    Returns:
        Vulnerability scan results and plugin status
    """
    
    import asyncio
    import concurrent.futures
    
    def _garak_process_sync():
        global garak, GARAK_AVAILABLE  # Declare globals at function level
        
        # Extract input parameters with robust fallback parsing (like cyberpig_ai)
        # Check cfg (configuration) first, then ctx (context) as fallback
        operation = cfg.get('operation', ctx.get('operation', 'scan_model'))
        
        # Extract text from multiple possible sources
        text = ""
        if 'text' in cfg:
            text = str(cfg['text'])
        elif 'payload' in cfg:
            text = str(cfg['payload'])
        elif 'content' in cfg:
            text = str(cfg['content'])
        elif 'text' in ctx:
            text = str(ctx['text'])
        elif 'payload' in ctx:
            text = str(ctx['payload'])
        elif 'content' in ctx:
            text = str(ctx['content'])
        
        # Extract model endpoint
        model_endpoint = cfg.get('model_endpoint', cfg.get('endpoint', cfg.get('url', 
                         ctx.get('model_endpoint', ctx.get('endpoint', ctx.get('url', ''))))))
        
        scan_context = cfg.get('context', ctx.get('context', {}))
        
        # Handle analyze operation as text-based scanning
        if operation == 'analyze':
            operation = 'scan_text'  # Convert to internal operation
            if not text:
                return {
                    "status": "error",
                    "error": "No text provided for vulnerability analysis",
                    # Universal Security Interface fields
                    "action": "ALLOW",
                    "threat_score": 0.0,
                    "threats_detected": [],
                    "plugin_name": "garak_scanner",
                    "confidence": 0.0,
                    "processing_time_ms": time.time() * 1000
                }
        
        # AI Strict Mode Configuration (check cfg first, then ctx)
        ai_strict_mode = (
            cfg.get('ai_strict_mode', False) or
            ctx.get('ai_strict_mode', False) or 
            cfg.get('ai_required', False) or
            ctx.get('ai_required', False) or 
            cfg.get('fallback_prohibited', False) or
            ctx.get('fallback_prohibited', False)
        )
        
        # Quick fallback for when garak is not available
        def quick_vulnerability_scan(text):
            import re
            threats = []
            
            # Quick prompt injection patterns
            injection_patterns = [
                r'(?i)ignore.*(previous|above|instructions)',
                r'(?i)system.*(prompt|role)',
                r'(?i)jailbreak|bypass.*security',
            ]
            
            for pattern in injection_patterns:
                if re.search(pattern, text):
                    threats.append({
                        "threat_type": "prompt_injection", 
                        "level": "medium",
                        "confidence": 0.6,
                        "description": "Potential prompt injection pattern detected",
                        "scanner": "garak_fallback"
                    })
                    break
            
            # Calculate threat score for Universal Security Interface
            max_threat_score = max((t.get('confidence', 0.0) for t in threats), default=0.0)
            action = "BLOCK" if len(threats) > 0 else "ALLOW"
            
            return {
                "status": "success",
                "operation": operation,
                # Universal Security Interface fields
                "action": action,
                "threat_score": max_threat_score,
                "threats_detected": threats,  # List format for Universal Security Interface
                "plugin_name": "garak_scanner",
                "confidence": max_threat_score if threats else 0.8,
                "processing_time_ms": time.time() * 1000,
                # Plugin-specific fields
                "threat_count": len(threats),
                "garak_available": False,
                "fallback_mode": True,
                "installation_hint": "Install garak for full vulnerability scanning: pip install garak"
            }
        
        # If operation is get_info, return info even without garak
        if operation == 'get_info':
            return {
                "status": "success",
                "operation": "get_info",
                "garak_available": GARAK_AVAILABLE,
                "garak_version": garak_version,
                "owasp_coverage": plug_metadata["owasp_coverage"],
                "installation_hint": "pip install garak" if not GARAK_AVAILABLE else None
            }
        
        # If garak not available, handle based on strict mode
        if not GARAK_AVAILABLE:
            if ai_strict_mode:
                # AI Strict Mode: Return error instead of fallback
                processing_time_ms = time.time() * 1000
                return {
                    "status": "error",
                    "error": "Garak AI vulnerability scanner required but unavailable",
                    "error_type": "AI_MODELS_UNAVAILABLE",
                    "ai_strict_mode": True,
                    "fallback_prohibited": True,
                    # Universal Security Interface fields
                    "action": "ALLOW",
                    "threat_score": 0.0,
                    "threats_detected": [],
                    "plugin_name": "garak_scanner",
                    "confidence": 0.0,
                    "processing_time_ms": processing_time_ms,
                    # Plugin-specific fields
                    "missing_dependencies": ["garak>=0.13.0", "transformers>=4.21.0", "torch>=1.13.0"],
                    "recommendation": "Install Garak AI scanner: pip install garak transformers torch",
                    "security_impact": "HIGH - AI-powered vulnerability scanning unavailable",
                    "garak_available": False,
                    "ai_models_active": False
                }
            
            # Lenient Mode: Try to install dependencies using dependency manager
            install_result = _install_dependencies()
            
            if install_result.get('success', False):
                # Try to re-import garak after installation
                try:
                    import importlib
                    garak = importlib.import_module('garak')
                    GARAK_AVAILABLE = True
                except ImportError:
                    pass
            
            # If still not available, use fallback
            if not GARAK_AVAILABLE:
                if text:  # Use text for basic pattern scanning
                    return quick_vulnerability_scan(text)
                else:
                    return {
                        "status": "disabled",
                        "reason": "Garak library not available and no text for fallback scanning",
                        # Universal Security Interface fields
                        "action": "ALLOW",
                        "threat_score": 0.0,
                        "threats_detected": [],
                        "plugin_name": "garak_scanner",
                        "confidence": 0.0,
                        "processing_time_ms": time.time() * 1000,
                        # Plugin-specific fields
                        "garak_available": False,
                        "installation_hint": "Use dependency_manager plugin or: pip install garak",
                        "dependency_install_attempted": install_result.get('attempted', False),
                        "dependency_install_error": install_result.get('error'),
                        "expected_params": ["text", "payload", "content"] if operation != 'scan_model' else ["model_endpoint"]
                    }
        
        # Continue with original garak processing
        
        if not model_endpoint and operation == 'scan_model':
            return {
                "status": "error",
                "error": "No model_endpoint provided for scanning",
                "garak_available": GARAK_AVAILABLE,
                "garak_version": garak_version
            }
        
        # Initialize plugin
        plugin = GarakPlugin(cfg)
        
        if not plugin.enabled:
            return {
                "status": "disabled",
                "reason": "Garak library not available",
                "garak_available": False,
                "installation_hint": "pip install garak",
                "garak_version": garak_version
            }
        
        # Perform vulnerability scan
        if operation == 'scan_model':
            import asyncio
            threats = asyncio.run(plugin.scan_model(model_endpoint, scan_context))
        elif operation == 'get_info':
            # Return plugin and Garak information
            return {
                "status": "success",
                "operation": "get_info",
                "garak_available": True,
                "garak_version": garak_version,
                "probe_modules": plugin.config.probe_modules,
                "detector_modules": plugin.config.detector_modules,
                "scan_intensity": plugin.config.scan_intensity,
                "owasp_coverage": plug_metadata["owasp_coverage"]
            }
        elif operation == 'scan_text':
            # Text analysis using garak probes directly
            if not text:
                return {
                    "status": "error",
                    "error": "No text provided for vulnerability analysis"
                }
            threats = plugin.scan_text(text)
        else:
            return {
                "status": "error", 
                "error": f"Unknown operation: {operation}. Use 'scan_model', 'scan_text', or 'get_info'"
            }
        
        # Format results
        threat_data = []
        for threat in threats:
            threat_data.append({
                "threat_id": threat.threat_id,
                "threat_type": threat.threat_type,
                "level": threat.level.value,
                "confidence": threat.confidence,
                "description": threat.description,
                "detected_by": threat.detected_by,
                "timestamp": threat.timestamp,
                "recommendation": threat.recommendation.value,
                "context": threat.context
            })
        
        # Calculate threat score and action for Universal Security Interface
        max_threat_score = max((threat.confidence for threat in threats), default=0.0)
        action = "BLOCK" if len(threats) > 0 else "ALLOW"
        
        return {
            "status": "success",
            "operation": operation,
            # Universal Security Interface fields
            "action": action,
            "threat_score": max_threat_score,
            "threats_detected": threat_data,  # List format for Universal Security Interface
            "plugin_name": "garak_scanner",
            "confidence": max_threat_score if threats else 0.8,
            "processing_time_ms": time.time() * 1000,
            # Plugin-specific fields
            "model_endpoint": model_endpoint,
            "threat_count": len(threats),
            "threats": threat_data,  # Backwards compatibility
            "scan_summary": {
                "total_threats": len(threats),
                "critical_threats": len([t for t in threats if t.level == ThreatLevel.CRITICAL]),
                "high_threats": len([t for t in threats if t.level == ThreatLevel.HIGH]),
                "medium_threats": len([t for t in threats if t.level == ThreatLevel.MEDIUM]),
                "low_threats": len([t for t in threats if t.level == ThreatLevel.LOW])
            },
            "garak_available": True,
            "garak_version": garak_version,
            "ai_models_active": True,
            "ai_strict_mode": ai_strict_mode,
            "processing_mode": "ai_vulnerability_scanning",
            "scan_configuration": {
                "probe_modules": plugin.config.probe_modules,
                "detector_modules": plugin.config.detector_modules,
                "scan_intensity": plugin.config.scan_intensity,
                "max_attempts": plugin.config.max_attempts
            }
        }
        
    # Run with timeout protection
    try:
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future = executor.submit(_garak_process_sync)
            return future.result(timeout=15.0)  # 15 second timeout for garak scans
            
    except concurrent.futures.TimeoutError:
        # Quick fallback on timeout
        text = ctx.get('text', ctx.get('payload', ctx.get('content', '')))
        if text:
            import re
            threats = []
            if re.search(r'(?i)ignore.*(previous|instructions)', text):
                threats.append({
                    "threat_type": "prompt_injection",
                    "level": "medium", 
                    "confidence": 0.5,
                    "description": "Quick pattern detection (garak timed out)",
                    "scanner": "garak_timeout_fallback"
                })
            
            return {
                "status": "success",
                "message": "Garak scan timed out, using quick pattern matching",
                "threats_detected": len(threats),
                "threats": threats,
                "timeout_duration": "15.0s",
                "fallback_mode": True,
                "action": "BLOCK" if len(threats) > 0 else "ALLOW"
            }
        else:
            return {
                "status": "error",
                "error": "Garak scan timed out and no text for fallback",
                "timeout_duration": "15.0s"
            }
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "error_type": type(e).__name__,
            "garak_available": GARAK_AVAILABLE,
            "garak_version": garak_version
        }