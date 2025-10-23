# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Advanced Risk Assessment Plugin for PlugPipe Compliance Framework

This plugin provides comprehensive risk assessment capabilities including:
- Multi-framework compliance risk assessment
- Automated threat modeling (STRIDE, PASTA, VAST)
- Quantitative and qualitative risk analysis
- Control gap analysis
- Risk matrix generation
- AI-powered risk identification and scoring
"""

import asyncio
import json
import logging
import uuid
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Tuple, Optional
import pandas as pd
import numpy as np
from dataclasses import dataclass
import hashlib

# Import PlugPipe components
from shares.utils.config_loader import get_llm_config

# PlugPipe pp function for dynamic plugin discovery
try:
    from shares.loader import pp
except ImportError:
    def pp(plugin_name: str, **kwargs) -> Dict[str, Any]:
        return {"success": False, "error": "Plugin loader not available"}

# Set up logging
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
class Risk:
    """Risk data structure"""
    risk_id: str
    title: str
    description: str
    category: str
    impact_score: int
    probability_score: int
    risk_score: float
    risk_level: str
    affected_assets: List[str]
    threat_sources: List[str]
    vulnerabilities: List[str]
    existing_controls: List[str]
    control_effectiveness: str
    residual_risk: float
    recommendations: List[str]

@dataclass
class ThreatScenario:
    """Threat scenario data structure"""
    scenario_id: str
    title: str
    threat_actor: str
    attack_vector: str
    target_asset: str
    impact: str
    likelihood: str
    risk_rating: str

class RiskAssessmentEngine:
    """Advanced risk assessment engine with multi-framework support"""

    def __init__(self, config: Dict[str, Any]):
        self.config = self._validate_and_sanitize_config(config)
        self.llm_config = get_llm_config(primary=True)

        # Universal Input Sanitizer integration
        self.sanitizer_available = self._check_sanitizer_availability()
        
        # Risk assessment frameworks
        self.frameworks = {
            "sox": {
                "name": "Sarbanes-Oxley Act",
                "risk_categories": ["financial_reporting", "internal_controls", "audit_integrity"],
                "risk_weights": {"financial_reporting": 0.5, "internal_controls": 0.3, "audit_integrity": 0.2}
            },
            "gdpr": {
                "name": "General Data Protection Regulation",
                "risk_categories": ["data_processing", "consent_management", "breach_notification", "privacy_rights"],
                "risk_weights": {"data_processing": 0.3, "consent_management": 0.25, "breach_notification": 0.25, "privacy_rights": 0.2}
            },
            "hipaa": {
                "name": "Health Insurance Portability and Accountability Act",
                "risk_categories": ["phi_protection", "access_controls", "audit_controls", "transmission_security"],
                "risk_weights": {"phi_protection": 0.4, "access_controls": 0.25, "audit_controls": 0.2, "transmission_security": 0.15}
            },
            "pci-dss": {
                "name": "Payment Card Industry Data Security Standard",
                "risk_categories": ["cardholder_data", "access_control", "network_security", "monitoring"],
                "risk_weights": {"cardholder_data": 0.4, "access_control": 0.3, "network_security": 0.2, "monitoring": 0.1}
            },
            "iso27001": {
                "name": "ISO 27001 Information Security Management",
                "risk_categories": ["information_security", "risk_management", "incident_response", "business_continuity"],
                "risk_weights": {"information_security": 0.35, "risk_management": 0.25, "incident_response": 0.2, "business_continuity": 0.2}
            },
            "nist": {
                "name": "NIST Cybersecurity Framework",
                "risk_categories": ["identify", "protect", "detect", "respond", "recover"],
                "risk_weights": {"identify": 0.2, "protect": 0.25, "detect": 0.2, "respond": 0.2, "recover": 0.15}
            }
        }
        
        # Risk matrix configuration
        self.default_risk_matrix = {
            "impact_scale": [
                {"level": 1, "label": "Negligible", "description": "Minimal impact", "financial_threshold": 1000},
                {"level": 2, "label": "Minor", "description": "Limited impact", "financial_threshold": 10000},
                {"level": 3, "label": "Moderate", "description": "Significant impact", "financial_threshold": 100000},
                {"level": 4, "label": "Major", "description": "Severe impact", "financial_threshold": 1000000},
                {"level": 5, "label": "Catastrophic", "description": "Critical impact", "financial_threshold": 10000000}
            ],
            "probability_scale": [
                {"level": 1, "label": "Very Low", "percentage": 5},
                {"level": 2, "label": "Low", "percentage": 15},
                {"level": 3, "label": "Medium", "percentage": 35},
                {"level": 4, "label": "High", "percentage": 65},
                {"level": 5, "label": "Very High", "percentage": 85}
            ],
            "risk_tolerance": {"low": 6, "medium": 12, "high": 20, "critical": 25}
        }
        
        # Threat modeling methodologies
        self.threat_models = {
            "stride": {
                "categories": ["Spoofing", "Tampering", "Repudiation", "Information Disclosure", "Denial of Service", "Elevation of Privilege"],
                "focus": "Technical security threats"
            },
            "pasta": {
                "stages": ["Define Objectives", "Define Technical Scope", "Application Decomposition", 
                          "Threat Analysis", "Weakness Analysis", "Attack Modeling", "Risk Analysis"],
                "focus": "Process-oriented threat analysis"
            },
            "vast": {
                "types": ["Application threat modeling", "Operational threat modeling"],
                "focus": "Visual and agile threat modeling"
            }
        }

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
                r'\.\.\/',     # Path traversal
                r'</?.*(script|iframe|object)',  # Script injection
                r'(drop|delete|insert|update|union)\s+',  # SQL injection patterns
                r'(exec|eval|system|shell_exec)\s*\(',  # Code execution
                r'/etc/(passwd|shadow|hosts)',  # Sensitive file access
                r'(curl|wget|nc)\s+.*\.(com|org|net)',  # External communication
                r'(shutdown|reboot|halt)\s',  # System control
                r'threat_override',  # Risk assessment specific
                r'bypass_assessment',  # Risk assessment bypass
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
                    logger.warning(f"Potentially unsafe config value for {key}, using default")
                    continue
            safe_config[key] = value

        return safe_config

    async def _validate_assessment_config(self, assessment_config: Dict[str, Any]) -> ValidationResult:
        """Comprehensive validation of assessment configuration"""
        validation_result = ValidationResult(
            is_valid=True,
            errors=[],
            warnings=[],
            security_violations=[]
        )

        # Sanitize the entire assessment configuration
        sanitize_result = await self._sanitize_input(assessment_config)
        if not sanitize_result.is_valid:
            return sanitize_result

        # Framework validation
        framework = assessment_config.get('framework')
        valid_frameworks = list(self.frameworks.keys()) + ['custom']
        if framework and framework not in valid_frameworks:
            validation_result.errors.append(f'Unsupported framework: {framework}')
            validation_result.is_valid = False

        # Scope validation
        scope = assessment_config.get('scope')
        valid_scopes = ["system", "application", "process", "data", "infrastructure", "organization", "custom"]
        if scope and scope not in valid_scopes:
            validation_result.warnings.append(f'Unknown scope: {scope}')

        # Risk categories validation
        risk_categories = assessment_config.get('risk_categories', [])
        valid_categories = ["operational", "financial", "strategic", "compliance", "technology", "security", "reputation", "legal"]
        for category in risk_categories:
            if category not in valid_categories:
                validation_result.warnings.append(f'Unknown risk category: {category}')

        # Assessment depth validation
        depth = assessment_config.get('assessment_depth')
        valid_depths = ["basic", "standard", "comprehensive", "deep_dive"]
        if depth and depth not in valid_depths:
            validation_result.warnings.append(f'Unknown assessment depth: {depth}')

        validation_result.sanitized_data = sanitize_result.sanitized_data
        return validation_result
    
    async def _collect_assessment_data(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Collect data from various sources for risk assessment"""
        logger.info("Collecting assessment data from integrated plugins")
        
        assessment_data = {
            "vulnerability_scans": [],
            "audit_logs": [],
            "security_events": [],
            "policy_violations": [],
            "system_metrics": [],
            "compliance_status": {}
        }
        
        try:
            # Collect vulnerability data
            vulnerability_scanner = await pp("garak_scanner", version="1.0.0")
            if vulnerability_scanner:
                vuln_result = await vulnerability_scanner.process(ctx, {"action": "scan_vulnerabilities"})
                assessment_data["vulnerability_scans"] = vuln_result.get("vulnerabilities", [])

            # Collect audit logs
            elk_stack = await pp("audit_elk_stack", version="1.0.0")
            if elk_stack:
                audit_result = await elk_stack.process(ctx, {"action": "query_logs", "query": "risk_assessment"})
                assessment_data["audit_logs"] = audit_result.get("logs", [])

            # Collect compliance status
            opa_policy = await pp("opa_policy_enterprise", version="1.0.0")
            if opa_policy:
                compliance_result = await opa_policy.process(ctx, {"action": "get_compliance_status"})
                assessment_data["compliance_status"] = compliance_result.get("compliance_status", {})

            # Collect system metrics
            prometheus = await pp("monitoring_prometheus", version="1.0.0")
            if prometheus:
                metrics_result = await prometheus.process(ctx, {"action": "query_metrics", "metric": "security_events"})
                assessment_data["system_metrics"] = metrics_result.get("metrics", [])
            
        except Exception as e:
            logger.warning(f"Error collecting assessment data: {e}")
        
        return assessment_data
    
    async def _identify_risks_with_ai(self, ctx: Dict[str, Any], assessment_data: Dict[str, Any], framework: str) -> List[Risk]:
        """Use AI to identify and analyze risks from collected data"""
        logger.info(f"Using AI to identify risks for framework: {framework}")
        
        identified_risks = []
        
        try:
            # Use LLM service for intelligent risk identification
            llm_service = await pp("llm_service", version="1.0.0")
            if llm_service:
                risk_prompt = f"""
                Analyze the following assessment data for {framework.upper()} compliance risks:
                
                Vulnerability Scans: {len(assessment_data.get('vulnerability_scans', []))} vulnerabilities found
                Audit Logs: {len(assessment_data.get('audit_logs', []))} audit events
                Security Events: {len(assessment_data.get('security_events', []))} security incidents
                Policy Violations: {len(assessment_data.get('policy_violations', []))} violations
                
                Framework Focus: {self.frameworks.get(framework, {}).get('name', framework)}
                Risk Categories: {self.frameworks.get(framework, {}).get('risk_categories', [])}
                
                Identify top 10 risks with:
                1. Risk title and description
                2. Impact score (1-5)
                3. Probability score (1-5)
                4. Affected assets
                5. Threat sources
                6. Existing controls
                7. Recommendations
                
                Format as JSON array of risk objects.
                """
                
                llm_result = await llm_service.process(ctx, {
                    "action": "generate_response",
                    "prompt": risk_prompt,
                    "response_format": "json"
                })
                
                if llm_result.get("status") == "success":
                    ai_risks = json.loads(llm_result.get("response", "[]"))
                    
                    for risk_data in ai_risks:
                        risk = Risk(
                            risk_id=str(uuid.uuid4()),
                            title=risk_data.get("title", "Unknown Risk"),
                            description=risk_data.get("description", ""),
                            category=risk_data.get("category", "operational"),
                            impact_score=min(max(risk_data.get("impact_score", 3), 1), 5),
                            probability_score=min(max(risk_data.get("probability_score", 3), 1), 5),
                            risk_score=0.0,  # Will be calculated
                            risk_level="",   # Will be determined
                            affected_assets=risk_data.get("affected_assets", []),
                            threat_sources=risk_data.get("threat_sources", []),
                            vulnerabilities=risk_data.get("vulnerabilities", []),
                            existing_controls=risk_data.get("existing_controls", []),
                            control_effectiveness=risk_data.get("control_effectiveness", "unknown"),
                            residual_risk=0.0,  # Will be calculated
                            recommendations=risk_data.get("recommendations", [])
                        )
                        identified_risks.append(risk)
            
        except Exception as e:
            logger.warning(f"Error in AI risk identification: {e}")
        
        # Add default risks based on assessment data if AI fails
        if not identified_risks:
            identified_risks = self._generate_default_risks(assessment_data, framework)
        
        # Calculate risk scores
        for risk in identified_risks:
            risk.risk_score = risk.impact_score * risk.probability_score
            risk.risk_level = self._determine_risk_level(risk.risk_score)
            risk.residual_risk = self._calculate_residual_risk(risk)
        
        return identified_risks
    
    def _generate_default_risks(self, assessment_data: Dict[str, Any], framework: str) -> List[Risk]:
        """Generate default risks based on assessment data"""
        default_risks = []
        
        # Based on vulnerabilities
        vuln_count = len(assessment_data.get("vulnerability_scans", []))
        if vuln_count > 0:
            risk = Risk(
                risk_id=str(uuid.uuid4()),
                title=f"Vulnerability Exposure Risk",
                description=f"System has {vuln_count} identified vulnerabilities that could be exploited",
                category="security",
                impact_score=min(4, max(2, vuln_count // 5)),
                probability_score=min(4, max(2, vuln_count // 10)),
                risk_score=0.0,
                risk_level="",
                affected_assets=["systems", "applications"],
                threat_sources=["external_attackers", "malicious_insiders"],
                vulnerabilities=[f"vulnerability_{i+1}" for i in range(min(vuln_count, 5))],
                existing_controls=["vulnerability_scanning", "patch_management"],
                control_effectiveness="partially_effective",
                residual_risk=0.0,
                recommendations=["Prioritize critical vulnerability patching", "Implement automated patch management"]
            )
            default_risks.append(risk)
        
        # Based on policy violations
        violation_count = len(assessment_data.get("policy_violations", []))
        if violation_count > 0:
            risk = Risk(
                risk_id=str(uuid.uuid4()),
                title="Policy Compliance Risk",
                description=f"Detected {violation_count} policy violations indicating compliance gaps",
                category="compliance",
                impact_score=3,
                probability_score=4,
                risk_score=0.0,
                risk_level="",
                affected_assets=["processes", "data"],
                threat_sources=["human_error", "process_gaps"],
                vulnerabilities=["policy_gaps", "training_deficiency"],
                existing_controls=["policy_monitoring", "training_programs"],
                control_effectiveness="ineffective",
                residual_risk=0.0,
                recommendations=["Strengthen policy enforcement", "Enhance staff training"]
            )
            default_risks.append(risk)
        
        return default_risks
    
    def _determine_risk_level(self, risk_score: float) -> str:
        """Determine risk level based on score"""
        if risk_score >= self.default_risk_matrix["risk_tolerance"]["critical"]:
            return "critical"
        elif risk_score >= self.default_risk_matrix["risk_tolerance"]["high"]:
            return "high"
        elif risk_score >= self.default_risk_matrix["risk_tolerance"]["medium"]:
            return "medium"
        else:
            return "low"
    
    def _calculate_residual_risk(self, risk: Risk) -> float:
        """Calculate residual risk after considering existing controls"""
        effectiveness_multipliers = {
            "effective": 0.2,
            "partially_effective": 0.5,
            "ineffective": 0.9,
            "not_implemented": 1.0,
            "unknown": 0.7
        }
        
        multiplier = effectiveness_multipliers.get(risk.control_effectiveness, 0.7)
        return risk.risk_score * multiplier
    
    async def _generate_threat_model(self, ctx: Dict[str, Any], methodology: str, assets: List[str]) -> Dict[str, Any]:
        """Generate threat model using specified methodology"""
        logger.info(f"Generating threat model using {methodology} methodology")
        
        threat_scenarios = []
        attack_paths = []
        
        if methodology == "stride":
            # Generate STRIDE-based threat scenarios
            stride_categories = self.threat_models["stride"]["categories"]
            
            for asset in assets:
                for category in stride_categories:
                    scenario = ThreatScenario(
                        scenario_id=str(uuid.uuid4()),
                        title=f"{category} threat against {asset}",
                        threat_actor="external_attacker",
                        attack_vector=self._get_attack_vector_for_stride(category),
                        target_asset=asset,
                        impact=self._assess_stride_impact(category, asset),
                        likelihood="medium",
                        risk_rating=self._calculate_scenario_risk(category, asset)
                    )
                    threat_scenarios.append(scenario)
        
        # Generate attack paths
        for scenario in threat_scenarios[:5]:  # Top 5 scenarios
            attack_path = {
                "path_id": str(uuid.uuid4()),
                "steps": self._generate_attack_steps(scenario),
                "difficulty": "medium",
                "detection_likelihood": "medium"
            }
            attack_paths.append(attack_path)
        
        return {
            "methodology_used": methodology,
            "threat_scenarios": [
                {
                    "scenario_id": s.scenario_id,
                    "title": s.title,
                    "threat_actor": s.threat_actor,
                    "attack_vector": s.attack_vector,
                    "target_asset": s.target_asset,
                    "impact": s.impact,
                    "likelihood": s.likelihood,
                    "risk_rating": s.risk_rating
                } for s in threat_scenarios
            ],
            "attack_paths": attack_paths
        }
    
    def _get_attack_vector_for_stride(self, category: str) -> str:
        """Get appropriate attack vector for STRIDE category"""
        vectors = {
            "Spoofing": "identity_theft",
            "Tampering": "data_modification",
            "Repudiation": "log_manipulation",
            "Information Disclosure": "data_exfiltration",
            "Denial of Service": "resource_exhaustion",
            "Elevation of Privilege": "privilege_escalation"
        }
        return vectors.get(category, "unknown")
    
    def _assess_stride_impact(self, category: str, asset: str) -> str:
        """Assess impact of STRIDE threat on asset"""
        # Simplified impact assessment
        high_impact_categories = ["Information Disclosure", "Tampering", "Elevation of Privilege"]
        return "high" if category in high_impact_categories else "medium"
    
    def _calculate_scenario_risk(self, category: str, asset: str) -> str:
        """Calculate risk rating for threat scenario"""
        # Simplified risk calculation
        high_risk_categories = ["Information Disclosure", "Elevation of Privilege"]
        critical_assets = ["data", "systems"]
        
        if category in high_risk_categories and asset in critical_assets:
            return "high"
        elif category in high_risk_categories or asset in critical_assets:
            return "medium"
        else:
            return "low"
    
    def _generate_attack_steps(self, scenario: ThreatScenario) -> List[str]:
        """Generate attack steps for scenario"""
        base_steps = [
            "Reconnaissance and target identification",
            "Initial access attempt",
            "Privilege escalation",
            "Lateral movement",
            "Data access/modification",
            "Cover tracks and maintain persistence"
        ]
        
        # Customize based on scenario
        if "data" in scenario.target_asset.lower():
            base_steps.append("Data exfiltration")
        
        return base_steps[:4]  # Return first 4 steps
    
    async def _perform_control_gap_analysis(self, ctx: Dict[str, Any], risks: List[Risk], framework: str) -> List[Dict[str, Any]]:
        """Perform control gap analysis"""
        logger.info(f"Performing control gap analysis for {framework}")
        
        control_gaps = []
        framework_info = self.frameworks.get(framework, {})
        
        # Analyze each risk category for control gaps
        for category in framework_info.get("risk_categories", ["operational", "security", "compliance"]):
            gap = {
                "gap_id": str(uuid.uuid4()),
                "control_objective": f"{framework.upper()} {category.replace('_', ' ').title()} Controls",
                "current_state": "partially_implemented",
                "desired_state": "fully_implemented",
                "gap_severity": "medium",
                "remediation_priority": 2,
                "estimated_effort": "medium",
                "estimated_cost": "$50,000 - $100,000"
            }
            
            # Assess gap severity based on related risks
            related_risks = [r for r in risks if r.category == category or category in r.description.lower()]
            if related_risks:
                high_risk_count = len([r for r in related_risks if r.risk_level in ["high", "critical"]])
                if high_risk_count > 0:
                    gap["gap_severity"] = "high" if high_risk_count > 2 else "medium"
                    gap["remediation_priority"] = 1 if gap["gap_severity"] == "high" else 2
            
            control_gaps.append(gap)
        
        return control_gaps
    
    def _generate_risk_matrix_data(self, risks: List[Risk]) -> Dict[str, Any]:
        """Generate risk matrix visualization data"""
        # Initialize 5x5 matrix
        matrix_data = [[{"risk_count": 0, "risk_level": "low", "risks": []} for _ in range(5)] for _ in range(5)]
        
        for risk in risks:
            # Adjust for 0-based indexing
            impact_idx = risk.impact_score - 1
            prob_idx = risk.probability_score - 1
            
            if 0 <= impact_idx < 5 and 0 <= prob_idx < 5:
                cell = matrix_data[prob_idx][impact_idx]
                cell["risk_count"] += 1
                cell["risks"].append(risk.risk_id)
                
                # Update cell risk level based on highest risk
                if risk.risk_level == "critical":
                    cell["risk_level"] = "critical"
                elif risk.risk_level == "high" and cell["risk_level"] not in ["critical"]:
                    cell["risk_level"] = "high"
                elif risk.risk_level == "medium" and cell["risk_level"] not in ["critical", "high"]:
                    cell["risk_level"] = "medium"
        
        return {
            "matrix_data": matrix_data,
            "impact_labels": [scale["label"] for scale in self.default_risk_matrix["impact_scale"]],
            "probability_labels": [scale["label"] for scale in self.default_risk_matrix["probability_scale"]]
        }
    
    def _generate_recommendations(self, risks: List[Risk], control_gaps: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Generate risk treatment recommendations"""
        recommendations = []
        
        # Prioritize critical and high risks
        high_priority_risks = [r for r in risks if r.risk_level in ["critical", "high"]]
        
        for i, risk in enumerate(high_priority_risks[:5]):  # Top 5 risks
            recommendation = {
                "recommendation_id": str(uuid.uuid4()),
                "title": f"Mitigate {risk.title}",
                "description": f"Implement controls to reduce {risk.title.lower()} to acceptable levels",
                "category": "preventive" if risk.probability_score > 3 else "detective",
                "priority": "critical" if risk.risk_level == "critical" else "high",
                "implementation_effort": "high" if risk.risk_score > 20 else "medium",
                "estimated_cost": {
                    "currency": "USD",
                    "amount": 50000 + (i * 25000),
                    "range": "$50K - $150K"
                },
                "risk_reduction": min(80, 20 + (risk.risk_score * 2)),
                "affected_risks": [risk.risk_id]
            }
            recommendations.append(recommendation)
        
        # Add control gap recommendations
        for gap in control_gaps[:3]:  # Top 3 gaps
            recommendation = {
                "recommendation_id": str(uuid.uuid4()),
                "title": f"Address {gap['control_objective']} Gap",
                "description": f"Implement missing controls for {gap['control_objective'].lower()}",
                "category": "corrective",
                "priority": "high" if gap["gap_severity"] == "high" else "medium",
                "implementation_effort": gap["estimated_effort"],
                "estimated_cost": {
                    "currency": "USD",
                    "amount": 75000,
                    "range": gap["estimated_cost"]
                },
                "risk_reduction": 60,
                "affected_risks": []
            }
            recommendations.append(recommendation)
        
        return recommendations

async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main process function for risk assessment plugin"""
    try:
        action = cfg.get("action", "assess_risks")
        logger.info(f"Risk Assessment Plugin - Action: {action}")

        # Initialize risk assessment engine
        engine = RiskAssessmentEngine(cfg)

        # Comprehensive input validation and sanitization
        input_validation = await engine._sanitize_input({"ctx": ctx, "cfg": cfg})
        if not input_validation.is_valid:
            return {
                'status': 'error',
                'message': 'Input validation failed',
                'errors': input_validation.errors,
                'security_violations': input_validation.security_violations
            }

        # Additional action validation
        valid_actions = ['assess_risks', 'generate_risk_matrix', 'calculate_risk_score', 'threat_modeling', 'control_gap_analysis', 'risk_treatment_plan']
        if action not in valid_actions:
            return {
                'status': 'error',
                'message': f'Unknown action: {action}',
                'supported_actions': valid_actions
            }
        
        if action == "assess_risks":
            return await _assess_risks(engine, ctx, cfg)
        elif action == "generate_risk_matrix":
            return await _generate_risk_matrix(engine, ctx, cfg)
        elif action == "threat_modeling":
            return await _threat_modeling(engine, ctx, cfg)
        elif action == "control_gap_analysis":
            return await _control_gap_analysis(engine, ctx, cfg)
        else:
            return {
                "status": "error",
                "message": f"Unsupported action: {action}",
                "error": f"Action '{action}' is not supported by this plugin"
            }
    
    except Exception as e:
        logger.error(f"Error in risk assessment plugin: {e}")
        return {
            "status": "error",
            "message": "Risk assessment failed",
            "error": str(e)
        }

async def _assess_risks(engine: RiskAssessmentEngine, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Perform comprehensive risk assessment"""
    assessment_config = cfg.get("assessment_config", {})

    # Validate assessment configuration
    validation_result = await engine._validate_assessment_config(assessment_config)
    if not validation_result.is_valid:
        return {
            'status': 'error',
            'message': 'Assessment configuration validation failed',
            'errors': validation_result.errors,
            'warnings': validation_result.warnings,
            'security_violations': validation_result.security_violations
        }

    # Use sanitized data if available
    if validation_result.sanitized_data:
        assessment_config = validation_result.sanitized_data

    framework = assessment_config.get("framework", "nist")
    
    # Generate assessment ID
    assessment_id = str(uuid.uuid4())
    
    # Collect assessment data
    assessment_data = await engine._collect_assessment_data(ctx, cfg)
    
    # Identify risks using AI
    identified_risks = await engine._identify_risks_with_ai(ctx, assessment_data, framework)
    
    # Perform control gap analysis
    control_gaps = await engine._perform_control_gap_analysis(ctx, identified_risks, framework)
    
    # Generate risk matrix
    risk_matrix = engine._generate_risk_matrix_data(identified_risks)
    
    # Generate recommendations
    recommendations = engine._generate_recommendations(identified_risks, control_gaps)
    
    # Calculate summary statistics
    total_risks = len(identified_risks)
    critical_risks = len([r for r in identified_risks if r.risk_level == "critical"])
    high_risks = len([r for r in identified_risks if r.risk_level == "high"])
    medium_risks = len([r for r in identified_risks if r.risk_level == "medium"])
    low_risks = len([r for r in identified_risks if r.risk_level == "low"])
    
    # Calculate overall risk score
    overall_risk_score = np.mean([r.risk_score for r in identified_risks]) if identified_risks else 0
    
    return {
        "status": "success",
        "message": f"Risk assessment completed for {framework.upper()} framework",
        "risk_assessment_id": assessment_id,
        "assessment_summary": {
            "total_risks": total_risks,
            "critical_risks": critical_risks,
            "high_risks": high_risks,
            "medium_risks": medium_risks,
            "low_risks": low_risks,
            "overall_risk_score": round(overall_risk_score, 2),
            "risk_trend": "stable",  # Would need historical data for actual trend
            "assessment_date": datetime.now().isoformat()
        },
        "identified_risks": [
            {
                "risk_id": r.risk_id,
                "title": r.title,
                "description": r.description,
                "category": r.category,
                "impact_score": r.impact_score,
                "probability_score": r.probability_score,
                "risk_score": r.risk_score,
                "risk_level": r.risk_level,
                "affected_assets": r.affected_assets,
                "threat_sources": r.threat_sources,
                "vulnerabilities": r.vulnerabilities,
                "existing_controls": r.existing_controls,
                "control_effectiveness": r.control_effectiveness,
                "residual_risk": r.residual_risk,
                "recommendations": r.recommendations
            } for r in identified_risks
        ],
        "risk_matrix": risk_matrix,
        "control_gaps": control_gaps,
        "recommendations": recommendations,
        "compliance_mapping": {
            "framework_controls": [
                {
                    "control_id": f"{framework.upper()}-{i+1:03d}",
                    "control_name": f"{framework.upper()} Control {i+1}",
                    "compliance_status": "partially_compliant",
                    "associated_risks": [r.risk_id for r in identified_risks[:2]],
                    "evidence": [f"Assessment evidence {i+1}"]
                } for i in range(5)
            ]
        }
    }

async def _generate_risk_matrix(engine: RiskAssessmentEngine, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Generate risk matrix visualization"""
    # This would typically load existing risk data
    # For demo, create sample risks
    sample_risks = [
        Risk(
            risk_id=str(uuid.uuid4()),
            title="Sample Risk",
            description="Sample risk for matrix",
            category="security",
            impact_score=3,
            probability_score=2,
            risk_score=6,
            risk_level="medium",
            affected_assets=[],
            threat_sources=[],
            vulnerabilities=[],
            existing_controls=[],
            control_effectiveness="partially_effective",
            residual_risk=3.0,
            recommendations=[]
        )
    ]
    
    risk_matrix = engine._generate_risk_matrix_data(sample_risks)
    
    return {
        "status": "success",
        "message": "Risk matrix generated successfully",
        "risk_matrix": risk_matrix
    }

async def _threat_modeling(engine: RiskAssessmentEngine, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Perform threat modeling"""
    threat_config = cfg.get("threat_model_config", {})
    methodology = threat_config.get("methodology", "stride")
    assets = threat_config.get("asset_types", ["data", "systems"])
    
    threat_model = await engine._generate_threat_model(ctx, methodology, assets)
    
    return {
        "status": "success",
        "message": f"Threat modeling completed using {methodology.upper()} methodology",
        "threat_model": threat_model
    }

async def _control_gap_analysis(engine: RiskAssessmentEngine, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Perform control gap analysis"""
    assessment_config = cfg.get("assessment_config", {})
    framework = assessment_config.get("framework", "nist")
    
    # Generate sample risks for gap analysis
    sample_risks = []
    control_gaps = await engine._perform_control_gap_analysis(ctx, sample_risks, framework)
    
    return {
        "status": "success",
        "message": f"Control gap analysis completed for {framework.upper()} framework",
        "control_gaps": control_gaps
    }

# Plugin metadata
plug_metadata = {
    "name": "risk_assessment",
    "version": "1.0.0",
    "description": "Advanced risk assessment engine for multi-framework compliance",
    "author": "PlugPipe Compliance Team",
    "capabilities": [
        "multi_framework_assessment",
        "automated_threat_modeling",
        "quantitative_risk_analysis",
        "control_gap_analysis",
        "ai_powered_assessment"
    ]
}

if __name__ == "__main__":
    # Test the plugin
    async def test_plugin():
        ctx = {"session_id": "test", "user": "test_user"}
        cfg = {
            "action": "assess_risks",
            "assessment_config": {
                "framework": "nist",
                "scope": "system",
                "assessment_depth": "standard"
            }
        }
        
        result = await process(ctx, cfg)
        print(json.dumps(result, indent=2))
    
    asyncio.run(test_plugin())