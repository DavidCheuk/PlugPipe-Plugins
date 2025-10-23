#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Ethics Guardrails Validator Plugin

Validates plugin generation requests against ethical and safety standards.
Prevents generation of harmful, unethical, or dangerous plugins.

Leverages existing PlugPipe validation infrastructure:
- Legal validation agents
- Security orchestrator
- Content validation systems
"""

import os
import sys
import json
import asyncio
import logging
from typing import Dict, List, Any, Optional, Tuple
from datetime import datetime, timezone
from dataclasses import dataclass

# Add PlugPipe paths
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

try:
    from shares.loader import pp
except ImportError:
    def pp(plugin_name):
        return None

logger = logging.getLogger(__name__)

@dataclass
class EthicsViolation:
    """Represents an ethics violation found in plugin request."""
    violation_type: str
    severity: str  # 'critical', 'high', 'medium', 'low'
    description: str
    recommendation: str
    blocked: bool

@dataclass
class EthicsValidationResult:
    """Result of ethics validation."""
    approved: bool
    violations: List[EthicsViolation]
    confidence_score: float
    validation_summary: str
    legal_check_passed: bool
    security_check_passed: bool

class EthicsGuardrailsValidator:
    """
    Comprehensive ethics validation system for plugin generation.
    
    Prevents generation of:
    - Harmful or dangerous plugins
    - Privacy-violating plugins
    - Unethical data collection plugins
    - Malicious automation plugins
    - Legally problematic plugins
    - Security-compromising plugins
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.blocked_keywords = self._load_blocked_keywords()
        self.harmful_patterns = self._load_harmful_patterns()
        
        # Ethics validation thresholds
        self.critical_threshold = config.get('critical_threshold', 0.9)
        self.high_threshold = config.get('high_threshold', 0.7)
        self.approval_threshold = config.get('approval_threshold', 0.8)
        
        # Integration with existing validation systems (graceful degradation)
        self.enable_legal_validation = config.get('enable_legal_validation', False)  # Default to False for reliability
        self.enable_security_validation = config.get('enable_security_validation', False)  # Default to False for reliability
        self.enable_prompt_injection_detection = config.get('enable_prompt_injection_detection', True)  # Enable advanced prompt injection detection
        self.enable_llm_guard = config.get('enable_llm_guard', True)  # Enable LLM Guard integration
        self.enable_garak_scanner = config.get('enable_garak_scanner', False)  # Garak is resource-intensive, default off
        
    def _load_blocked_keywords(self) -> List[str]:
        """Load blocked keywords that indicate harmful intent."""
        return [
            # Privacy violations
            'steal', 'extract', 'harvest', 'scrape_personal', 'collect_private',
            'bypass_privacy', 'track_users', 'surveillance', 'spy', 'monitor_secretly',
            
            # Security violations
            'hack', 'crack', 'exploit', 'backdoor', 'malware', 'virus', 'trojan',
            'keylogger', 'password_stealer', 'credential_harvester', 'ddos',
            'sql_injection', 'xss_attack', 'csrf_attack', 'privilege_escalation',
            
            # Data misuse
            'sell_data', 'leak_data', 'expose_data', 'unauthorized_access',
            'data_theft', 'identity_theft', 'financial_fraud',
            
            # Harmful automation
            'spam', 'phishing', 'scam', 'fake_news', 'disinformation',
            'harassment', 'cyberbullying', 'doxxing', 'swatting',
            
            # Legal violations
            'copyright_infringement', 'piracy', 'illegal_download',
            'money_laundering', 'tax_evasion', 'insider_trading',
            
            # Physical harm
            'weapon', 'explosive', 'poison', 'drug_manufacturing',
            'self_harm', 'suicide', 'violence', 'terrorism',
            
            # Discrimination
            'discriminate', 'bias_against', 'exclude_based_on',
            'racial_profiling', 'gender_discrimination',
        ]
    
    def _load_harmful_patterns(self) -> List[Dict[str, Any]]:
        """Load patterns that indicate harmful intent."""
        return [
            {
                'pattern': r'(?i)bypass.*security|circumvent.*protection',
                'severity': 'critical',
                'description': 'Attempts to bypass security measures',
                'category': 'security_violation'
            },
            {
                'pattern': r'(?i)collect.*without.*consent|harvest.*personal.*data',
                'severity': 'critical', 
                'description': 'Unauthorized data collection',
                'category': 'privacy_violation'
            },
            {
                'pattern': r'(?i)automate.*fake|generate.*spam|mass.*harassment',
                'severity': 'high',
                'description': 'Harmful automation patterns',
                'category': 'abuse_automation'
            },
            {
                'pattern': r'(?i)scrape.*profiles|extract.*contacts|steal.*emails',
                'severity': 'high',
                'description': 'Unauthorized data extraction',
                'category': 'data_theft'
            },
            {
                'pattern': r'(?i)hide.*from.*admin|conceal.*activity|stealth.*mode',
                'severity': 'medium',
                'description': 'Attempts to hide malicious activity',
                'category': 'concealment'
            },
        ]
    
    async def validate_plugin_request(self, request: str, context: Dict[str, Any]) -> EthicsValidationResult:
        """
        Main validation method that checks plugin request against ethics guidelines.
        
        Args:
            request: Natural language plugin request
            context: Additional context about the plugin request
            
        Returns:
            EthicsValidationResult with approval status and violations
        """
        violations = []
        
        # 1. Keyword-based validation
        keyword_violations = await self._check_blocked_keywords(request)
        violations.extend(keyword_violations)
        
        # 2. Pattern-based validation
        pattern_violations = await self._check_harmful_patterns(request)
        violations.extend(pattern_violations)
        
        # 3. Context-based validation
        context_violations = await self._check_context_indicators(request, context)
        violations.extend(context_violations)
        
        # 4. Legal validation (if enabled)
        legal_check_passed = True
        if self.enable_legal_validation:
            legal_violations = await self._run_legal_validation(request, context)
            violations.extend(legal_violations)
            legal_check_passed = not any(v.severity in ['critical', 'high'] for v in legal_violations)
        
        # 5. Advanced Prompt Injection Detection (if enabled)
        prompt_injection_check_passed = True
        if self.enable_prompt_injection_detection:
            injection_violations = await self._run_prompt_injection_detection(request, context)
            violations.extend(injection_violations)
            prompt_injection_check_passed = not any(v.severity in ['critical', 'high'] for v in injection_violations)
        
        # 6. Security validation (if enabled)
        security_check_passed = True
        if self.enable_security_validation:
            security_violations = await self._run_security_validation(request, context)
            violations.extend(security_violations)
            security_check_passed = not any(v.severity in ['critical', 'high'] for v in security_violations)
        
        # 6. Calculate overall approval
        approval_result = self._calculate_approval(violations)
        
        return EthicsValidationResult(
            approved=approval_result['approved'],
            violations=violations,
            confidence_score=approval_result['confidence'],
            validation_summary=approval_result['summary'],
            legal_check_passed=legal_check_passed,
            security_check_passed=security_check_passed
        )
    
    async def _check_blocked_keywords(self, request: str) -> List[EthicsViolation]:
        """Check for blocked keywords in the request."""
        violations = []
        request_lower = request.lower()
        
        for keyword in self.blocked_keywords:
            if keyword in request_lower:
                violations.append(EthicsViolation(
                    violation_type='blocked_keyword',
                    severity='critical',
                    description=f'Contains blocked keyword: {keyword}',
                    recommendation=f'Remove or rephrase content containing "{keyword}"',
                    blocked=True
                ))
        
        return violations
    
    async def _check_harmful_patterns(self, request: str) -> List[EthicsViolation]:
        """Check for harmful patterns using regex."""
        import re
        violations = []
        
        for pattern_def in self.harmful_patterns:
            if re.search(pattern_def['pattern'], request):
                violations.append(EthicsViolation(
                    violation_type=pattern_def['category'],
                    severity=pattern_def['severity'],
                    description=pattern_def['description'],
                    recommendation=f'Modify request to remove {pattern_def["category"]} patterns',
                    blocked=pattern_def['severity'] in ['critical', 'high']
                ))
        
        return violations
    
    async def _check_context_indicators(self, request: str, context: Dict[str, Any]) -> List[EthicsViolation]:
        """Check context for ethical red flags."""
        violations = []
        
        # Check domain context for high-risk areas
        domain = context.get('domain', '').lower()
        high_risk_domains = ['surveillance', 'tracking', 'scraping', 'exploitation']
        
        if any(risk_domain in domain for risk_domain in high_risk_domains):
            violations.append(EthicsViolation(
                violation_type='high_risk_domain',
                severity='high',
                description=f'Plugin request in high-risk domain: {domain}',
                recommendation='Consider alternative approaches that respect privacy and security',
                blocked=False
            ))
        
        # Check for complexity attempts to hide harmful intent
        complexity_level = context.get('complexity_level', '').lower()
        if complexity_level == 'enterprise' and any(keyword in request.lower() for keyword in ['stealth', 'hidden', 'bypass']):
            violations.append(EthicsViolation(
                violation_type='concealed_intent',
                severity='high',
                description='Enterprise-level plugin with concealment indicators',
                recommendation='Clarify legitimate business purpose and remove concealment language',
                blocked=True
            ))
        
        return violations
    
    async def _run_legal_validation(self, request: str, context: Dict[str, Any]) -> List[EthicsViolation]:
        """Run legal validation using existing legal validation agent."""
        violations = []
        
        try:
            # Use existing legal validation agent factory
            legal_validator = pp('agents.legal_validation_agent_factory')
            if not legal_validator:
                logger.warning("Legal validation agent not available")
                return violations
            
            # Prepare legal validation request
            legal_config = {
                'operation': 'run_legal_validation',
                'agent_config': {
                    'legal_domain': 'regulatory_compliance',
                    'jurisdiction': 'federal',
                    'compliance_level': 'practice_ready',
                    'validation_strictness': 0.85
                },
                'legal_validation_task': {
                    'content_to_validate': request,
                    'legal_context': 'AI plugin generation for business automation',
                    'validation_focus': ['regulatory_compliance', 'liability_assessment']
                }
            }
            
            # Run legal validation (handle both async and sync)
            if asyncio.iscoroutinefunction(legal_validator.process):
                legal_result = await legal_validator.process({}, legal_config)
            else:
                legal_result = legal_validator.process({}, legal_config)
            
            if legal_result.get('success') and 'legal_validation_results' in legal_result:
                legal_alerts = legal_result['legal_validation_results'].get('legal_alerts', [])
                
                for alert in legal_alerts:
                    if alert['severity'] in ['critical', 'high']:
                        violations.append(EthicsViolation(
                            violation_type='legal_violation',
                            severity=alert['severity'],
                            description=f"Legal issue: {alert['message']}",
                            recommendation=alert.get('required_action', 'Consult legal counsel'),
                            blocked=alert['severity'] == 'critical'
                        ))
        
        except Exception as e:
            logger.error(f"Legal validation failed: {e}")
            # Add a warning violation but don't block
            violations.append(EthicsViolation(
                violation_type='validation_error',
                severity='medium',
                description='Legal validation could not be completed',
                recommendation='Manual legal review recommended',
                blocked=False
            ))
        
        return violations
    
    async def _run_security_validation(self, request: str, context: Dict[str, Any]) -> List[EthicsViolation]:
        """Run security validation using existing security orchestrator."""
        violations = []
        
        try:
            # Use existing security orchestrator
            security_validator = pp('security.security_orchestrator')
            if not security_validator:
                logger.warning("Security orchestrator not available")
                return violations
            
            # Prepare security validation request
            security_config = {
                'operation': 'validate_request',
                'content': request,
                'context': context,
                'validation_types': ['threat_assessment', 'vulnerability_scan', 'malicious_intent_detection']
            }
            
            # Run security validation (handle both async and sync)
            if asyncio.iscoroutinefunction(security_validator.process):
                security_result = await security_validator.process({}, security_config)
            else:
                security_result = security_validator.process({}, security_config)
            
            if security_result.get('success'):
                # Process security alerts
                security_alerts = security_result.get('security_alerts', [])
                
                for alert in security_alerts:
                    if alert.get('severity') in ['critical', 'high']:
                        violations.append(EthicsViolation(
                            violation_type='security_violation',
                            severity=alert['severity'],
                            description=f"Security issue: {alert.get('description', 'Unknown')}",
                            recommendation=alert.get('mitigation', 'Review security implications'),
                            blocked=alert['severity'] == 'critical'
                        ))
        
        except Exception as e:
            logger.error(f"Security validation failed: {e}")
            # Add a warning violation but don't block
            violations.append(EthicsViolation(
                violation_type='validation_error',
                severity='medium',
                description='Security validation could not be completed',
                recommendation='Manual security review recommended',
                blocked=False
            ))
        
        return violations
    
    async def _run_prompt_injection_detection(self, request: str, context: Dict[str, Any]) -> List[EthicsViolation]:
        """Run advanced prompt injection detection using LLM Guard and optionally Garak."""
        violations = []
        
        # 1. LLM Guard Integration
        if self.enable_llm_guard:
            try:
                llm_guard = pp('security.llm_guard')
                if llm_guard:
                    # Configure LLM Guard for prompt injection detection
                    llm_guard_config = {
                        'operation': 'scan_input',
                        'text': request,
                        'context': context
                    }
                    
                    # Run LLM Guard scan (handle both async and sync)
                    if asyncio.iscoroutinefunction(llm_guard.process):
                        guard_result = await llm_guard.process({}, llm_guard_config)
                    else:
                        guard_result = llm_guard.process({}, llm_guard_config)
                    
                    if guard_result.get('status') == 'success':
                        threats = guard_result.get('threats', [])
                        
                        for threat in threats:
                            threat_type = threat.get('threat_type', 'unknown')
                            threat_level = threat.get('level', 'medium')
                            
                            # Focus on prompt injection and related threats
                            if any(keyword in threat_type.lower() for keyword in 
                                  ['prompt_injection', 'injection', 'code', 'toxic', 'pii', 'secrets']):
                                
                                violations.append(EthicsViolation(
                                    violation_type=f'llm_guard_{threat_type}',
                                    severity=threat_level,
                                    description=f"LLM Guard detected {threat_type}: {threat.get('description', 'No details')}",
                                    recommendation=f"Action: {threat.get('recommendation', 'Review content')}",
                                    blocked=threat_level in ['critical', 'high']
                                ))
                else:
                    logger.warning("LLM Guard plugin not available for prompt injection detection")
            
            except Exception as e:
                logger.error(f"LLM Guard prompt injection detection failed: {e}")
                violations.append(EthicsViolation(
                    violation_type='llm_guard_error',
                    severity='medium',
                    description=f'LLM Guard detection failed: {str(e)}',
                    recommendation='Manual review recommended due to detection system failure',
                    blocked=False
                ))
        
        # 2. Garak Scanner Integration (if enabled and for high-risk contexts)
        if self.enable_garak_scanner and context.get('complexity_level') == 'enterprise':
            try:
                garak_scanner = pp('security.garak_scanner')
                if garak_scanner:
                    # Use Garak for advanced prompt injection testing
                    garak_config = {
                        'operation': 'scan_model',  # This would need to be adapted for text scanning
                        'model_endpoint': 'text_analysis',  # Placeholder
                        'context': {
                            'custom_probes': ['promptinject', 'leakage'],
                            'user_id': context.get('user_id', 'ethics_validator'),
                            'scan_id': f'ethics_scan_{datetime.now().strftime("%Y%m%d_%H%M%S")}'
                        }
                    }
                    
                    # Note: Garak is primarily for model scanning, so this is conceptual
                    # In practice, you'd need to adapt Garak for direct text analysis
                    logger.info("Garak scanner integration would require adaptation for direct text analysis")
                    
                else:
                    logger.warning("Garak scanner plugin not available")
            
            except Exception as e:
                logger.error(f"Garak scanner integration failed: {e}")
        
        # 3. Advanced Pattern Detection for Prompt Injection
        injection_patterns = [
            {
                'pattern': r'(?i)ignore.*previous.*instruction|forget.*above|new.*instruction.*begin',
                'severity': 'critical',
                'description': 'Direct instruction override attempt',
                'category': 'prompt_injection_override'
            },
            {
                'pattern': r'(?i)system.*prompt|reveal.*prompt|show.*prompt|what.*your.*instruction',
                'severity': 'high',
                'description': 'System prompt extraction attempt',
                'category': 'prompt_leakage'
            },
            {
                'pattern': r'(?i)jailbreak|break.*out|escape.*mode|developer.*mode',
                'severity': 'high',
                'description': 'Jailbreak attempt detected',
                'category': 'jailbreak_attempt'
            },
            {
                'pattern': r'(?i)pretend.*you.*are|roleplay.*as|act.*like.*you.*are',
                'severity': 'medium',
                'description': 'Role manipulation attempt',
                'category': 'role_manipulation'
            },
            {
                'pattern': r'(?i)\\n\\n.*user:|\\n\\n.*human:|\\n\\n.*assistant:',
                'severity': 'high',
                'description': 'Conversation flow injection attempt',
                'category': 'conversation_injection'
            }
        ]
        
        import re
        for pattern_def in injection_patterns:
            if re.search(pattern_def['pattern'], request):
                violations.append(EthicsViolation(
                    violation_type=pattern_def['category'],
                    severity=pattern_def['severity'],
                    description=pattern_def['description'],
                    recommendation=f'Block or sanitize content with {pattern_def["category"]} patterns',
                    blocked=pattern_def['severity'] in ['critical', 'high']
                ))
        
        return violations
    
    def _calculate_approval(self, violations: List[EthicsViolation]) -> Dict[str, Any]:
        """Calculate overall approval based on violations."""
        
        # Check for blocking violations
        blocking_violations = [v for v in violations if v.blocked]
        if blocking_violations:
            return {
                'approved': False,
                'confidence': 1.0,
                'summary': f'Request blocked due to {len(blocking_violations)} critical violations'
            }
        
        # Calculate severity score
        severity_weights = {'critical': 1.0, 'high': 0.7, 'medium': 0.4, 'low': 0.1}
        total_severity = sum(severity_weights.get(v.severity, 0) for v in violations)
        
        # Calculate confidence (inverse of severity)
        confidence = max(0.0, 1.0 - (total_severity / 3.0))  # Normalize to 0-1
        
        # Determine approval
        approved = (
            confidence >= self.approval_threshold and
            total_severity < 2.0 and  # Less than 2 critical violations worth
            len([v for v in violations if v.severity == 'critical']) == 0
        )
        
        summary = self._generate_summary(violations, approved, confidence)
        
        return {
            'approved': approved,
            'confidence': confidence,
            'summary': summary
        }
    
    def _generate_summary(self, violations: List[EthicsViolation], approved: bool, confidence: float) -> str:
        """Generate human-readable summary of validation results."""
        if not violations:
            return "✅ Plugin request passed all ethics validations"
        
        critical_count = len([v for v in violations if v.severity == 'critical'])
        high_count = len([v for v in violations if v.severity == 'high'])
        
        if not approved:
            if critical_count > 0:
                return f"❌ BLOCKED: {critical_count} critical ethics violations detected"
            else:
                return f"⚠️ REJECTED: {high_count} high-severity violations, confidence too low ({confidence:.2f})"
        else:
            if violations:
                return f"⚠️ APPROVED with warnings: {len(violations)} issues found but non-blocking"
            else:
                return "✅ APPROVED: No ethics violations detected"


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main process function for Ethics Guardrails Validator.
    
    Validates plugin generation requests against ethical and safety standards.
    """
    try:
        operation = cfg.get('operation', 'validate_request')
        
        if operation == 'validate_request':
            # Extract validation parameters
            request = cfg.get('request', '')
            context = cfg.get('context', {})
            
            if not request:
                raise ValueError("request parameter is required for validation")
            
            # Initialize validator
            validator = EthicsGuardrailsValidator(cfg)
            
            # Run validation
            result = await validator.validate_plugin_request(request, context)
            
            return {
                'success': True,
                'operation_completed': 'validate_request',
                'ethics_validation': {
                    'approved': result.approved,
                    'confidence_score': result.confidence_score,
                    'summary': result.validation_summary,
                    'legal_check_passed': result.legal_check_passed,
                    'security_check_passed': result.security_check_passed,
                    'violations_found': len(result.violations),
                    'violations': [
                        {
                            'type': v.violation_type,
                            'severity': v.severity,
                            'description': v.description,
                            'recommendation': v.recommendation,
                            'blocked': v.blocked
                        }
                        for v in result.violations
                    ]
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif operation == 'get_blocked_keywords':
            validator = EthicsGuardrailsValidator(cfg)
            return {
                'success': True,
                'operation_completed': 'get_blocked_keywords',
                'blocked_keywords': validator.blocked_keywords,
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        elif operation == 'get_validation_config':
            return {
                'success': True,
                'operation_completed': 'get_validation_config',
                'config': {
                    'critical_threshold': cfg.get('critical_threshold', 0.9),
                    'high_threshold': cfg.get('high_threshold', 0.7),
                    'approval_threshold': cfg.get('approval_threshold', 0.8),
                    'enable_legal_validation': cfg.get('enable_legal_validation', True),
                    'enable_security_validation': cfg.get('enable_security_validation', True)
                },
                'timestamp': datetime.now(timezone.utc).isoformat()
            }
        
        else:
            raise ValueError(f"Unknown operation: {operation}")
    
    except Exception as e:
        logger.error(f"Ethics guardrails validation failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation_completed': cfg.get('operation', 'unknown'),
            'timestamp': datetime.now(timezone.utc).isoformat()
        }


# Plugin metadata
plug_metadata = {
    'name': 'security.ethics_guardrails_validator',
    'owner': 'PlugPipe Security Team',
    'version': '1.0.0',
    'status': 'production',
    'description': 'Comprehensive ethics and safety validation for plugin generation requests',
    'capabilities': [
        'ethics_validation',
        'safety_assessment',
        'legal_compliance_check',
        'security_validation',
        'harmful_content_detection',
        'privacy_protection',
        'abuse_prevention'
    ]
}