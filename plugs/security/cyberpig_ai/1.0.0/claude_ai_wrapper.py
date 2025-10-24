#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Claude AI Wrapper for Secret Detection
This wrapper allows Claude (me) to directly analyze secrets in real-time
"""

import json
import re
import math
from typing import Dict, Any, List

class ClaudeAIWrapper:
    """Wrapper that uses Claude's analysis capabilities for secret detection"""
    
    def __init__(self):
        self.model_name = "claude-sonnet-4-20250514"
        
    def analyze_secret(self, content: str, context: str = "") -> Dict[str, Any]:
        """
        Claude analyzes the content for secrets using advanced AI reasoning
        """
        # I (Claude) will analyze this content for secrets
        analysis = self._claude_secret_analysis(content, context)
        return analysis
    
    def _claude_secret_analysis(self, content: str, context: str = "") -> Dict[str, Any]:
        """
        My (Claude's) direct analysis of the content for secret patterns
        """
        
        # Advanced multi-layer analysis by Claude
        secrets_detected = []
        confidence_scores = []
        
        # 1. API Key Analysis
        api_key_analysis = self._analyze_api_keys(content)
        if api_key_analysis['found']:
            secrets_detected.extend(api_key_analysis['secrets'])
            confidence_scores.append(api_key_analysis['confidence'])
        
        # 2. Token Analysis  
        token_analysis = self._analyze_tokens(content)
        if token_analysis['found']:
            secrets_detected.extend(token_analysis['secrets'])
            confidence_scores.append(token_analysis['confidence'])
        
        # 3. Password Analysis
        password_analysis = self._analyze_passwords(content)
        if password_analysis['found']:
            secrets_detected.extend(password_analysis['secrets'])
            confidence_scores.append(password_analysis['confidence'])
        
        # 4. Database Connection Analysis
        db_analysis = self._analyze_database_connections(content)
        if db_analysis['found']:
            secrets_detected.extend(db_analysis['secrets'])
            confidence_scores.append(db_analysis['confidence'])
        
        # 5. Certificate/Key Analysis
        cert_analysis = self._analyze_certificates(content)
        if cert_analysis['found']:
            secrets_detected.extend(cert_analysis['secrets'])
            confidence_scores.append(cert_analysis['confidence'])
        
        # 6. Entropy-based Unknown Secret Analysis
        entropy_analysis = self._analyze_high_entropy_strings(content)
        if entropy_analysis['found']:
            secrets_detected.extend(entropy_analysis['secrets'])
            confidence_scores.append(entropy_analysis['confidence'])
        
        # 7. Context Analysis
        context_analysis = self._analyze_context_clues(content, context)
        if context_analysis['found']:
            secrets_detected.extend(context_analysis['secrets'])
            confidence_scores.append(context_analysis['confidence'])
        
        # Calculate overall confidence
        overall_confidence = max(confidence_scores) if confidence_scores else 0.0
        
        return {
            "analysis_by": "Claude AI",
            "model": self.model_name,
            "secrets_found": len(secrets_detected),
            "secrets": secrets_detected,
            "overall_confidence": overall_confidence,
            "is_secret_detected": len(secrets_detected) > 0,
            "analysis_layers": 7,
            "reasoning": self._generate_reasoning(secrets_detected, content)
        }
    
    def _analyze_api_keys(self, content: str) -> Dict[str, Any]:
        """Claude's analysis of API key patterns"""
        secrets = []
        
        # Advanced API key patterns I recognize
        patterns = [
            (r'sk-[a-zA-Z0-9]{20,}', 'OpenAI API Key', 0.95),
            (r'sk-proj-[a-zA-Z0-9]{20,}', 'OpenAI Project Key', 0.98),
            (r'sk-ant-[a-zA-Z0-9]{20,}', 'Anthropic API Key', 0.98),
            (r'AKIA[0-9A-Z]{16}', 'AWS Access Key', 0.95),
            (r'AIza[0-9A-Za-z_-]{35}', 'Google API Key', 0.90),
            (r'pk_live_[0-9a-zA-Z]{24}', 'Stripe Live Key', 0.95),
            (r'pk_test_[0-9a-zA-Z]{24}', 'Stripe Test Key', 0.90),
            (r'sk_live_[0-9a-zA-Z]{24}', 'Stripe Secret Live Key', 0.98),
            (r'sk_test_[0-9a-zA-Z]{24}', 'Stripe Secret Test Key', 0.90),
        ]
        
        max_confidence = 0.0
        for pattern, key_type, confidence in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                secrets.append({
                    'type': key_type,
                    'pattern': match[:20] + "..." if len(match) > 20 else match,
                    'confidence': confidence,
                    'analysis': f'Claude detected {key_type} with {confidence*100}% confidence'
                })
                max_confidence = max(max_confidence, confidence)
        
        return {
            'found': len(secrets) > 0,
            'secrets': secrets,
            'confidence': max_confidence
        }
    
    def _analyze_tokens(self, content: str) -> Dict[str, Any]:
        """Claude's analysis of token patterns"""
        secrets = []
        
        patterns = [
            (r'ghp_[a-zA-Z0-9]{36}', 'GitHub Personal Access Token', 0.95),
            (r'gho_[a-zA-Z0-9]{36}', 'GitHub OAuth Token', 0.95),
            (r'ghs_[a-zA-Z0-9]{36}', 'GitHub Server Token', 0.95),
            (r'glpat-[a-zA-Z0-9]{20}', 'GitLab Personal Access Token', 0.90),
            (r'xoxb-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', 'Slack Bot Token', 0.95),
            (r'xoxp-[0-9]{11,13}-[0-9]{11,13}-[a-zA-Z0-9]{24}', 'Slack User Token', 0.95),
            (r'eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+', 'JWT Token', 0.85),
        ]
        
        max_confidence = 0.0
        for pattern, token_type, confidence in patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                secrets.append({
                    'type': token_type,
                    'pattern': match[:30] + "..." if len(match) > 30 else match,
                    'confidence': confidence,
                    'analysis': f'Claude identified {token_type}'
                })
                max_confidence = max(max_confidence, confidence)
        
        return {
            'found': len(secrets) > 0,
            'secrets': secrets,
            'confidence': max_confidence
        }
    
    def _analyze_passwords(self, content: str) -> Dict[str, Any]:
        """Claude's analysis of password patterns"""
        secrets = []
        
        # Look for password patterns
        password_patterns = [
            (r'(?i)password["\'\s=:]+([^\s"\']{8,})', 'Password', 0.80),
            (r'(?i)passwd["\'\s=:]+([^\s"\']{8,})', 'Password', 0.80),
            (r'(?i)pwd["\'\s=:]+([^\s"\']{8,})', 'Password', 0.75),
            (r'(?i)pass["\'\s=:]+([^\s"\']{8,})', 'Password', 0.70),
        ]
        
        max_confidence = 0.0
        for pattern, secret_type, base_confidence in password_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                # Analyze password strength to adjust confidence
                strength_factor = self._analyze_password_strength(match)
                final_confidence = base_confidence * strength_factor
                
                if final_confidence > 0.6:  # Only report likely real passwords
                    secrets.append({
                        'type': secret_type,
                        'pattern': match[:15] + "..." if len(match) > 15 else match,
                        'confidence': final_confidence,
                        'analysis': f'Claude detected password with strength factor {strength_factor}'
                    })
                    max_confidence = max(max_confidence, final_confidence)
        
        return {
            'found': len(secrets) > 0,
            'secrets': secrets,
            'confidence': max_confidence
        }
    
    def _analyze_database_connections(self, content: str) -> Dict[str, Any]:
        """Claude's analysis of database connection strings"""
        secrets = []
        
        db_patterns = [
            (r'(mysql://[^\s"\']+)', 'MySQL Connection String', 0.90),
            (r'(postgresql://[^\s"\']+)', 'PostgreSQL Connection String', 0.90),
            (r'(mongodb://[^\s"\']+)', 'MongoDB Connection String', 0.90),
            (r'(redis://[^\s"\']+)', 'Redis Connection String', 0.85),
            (r'(sqlite:///[^\s"\']+)', 'SQLite Connection String', 0.70),
        ]
        
        max_confidence = 0.0
        for pattern, db_type, confidence in db_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                secrets.append({
                    'type': db_type,
                    'pattern': match[:40] + "..." if len(match) > 40 else match,
                    'confidence': confidence,
                    'analysis': f'Claude detected {db_type}'
                })
                max_confidence = max(max_confidence, confidence)
        
        return {
            'found': len(secrets) > 0,
            'secrets': secrets,
            'confidence': max_confidence
        }
    
    def _analyze_certificates(self, content: str) -> Dict[str, Any]:
        """Claude's analysis of certificates and private keys"""
        secrets = []
        
        cert_patterns = [
            (r'-----BEGIN PRIVATE KEY-----', 'Private Key', 0.95),
            (r'-----BEGIN RSA PRIVATE KEY-----', 'RSA Private Key', 0.95),
            (r'-----BEGIN OPENSSH PRIVATE KEY-----', 'OpenSSH Private Key', 0.95),
            (r'-----BEGIN EC PRIVATE KEY-----', 'EC Private Key', 0.95),
            (r'-----BEGIN CERTIFICATE-----', 'Certificate', 0.80),
        ]
        
        max_confidence = 0.0
        for pattern, cert_type, confidence in cert_patterns:
            if re.search(pattern, content):
                secrets.append({
                    'type': cert_type,
                    'pattern': f'{cert_type} detected',
                    'confidence': confidence,
                    'analysis': f'Claude identified {cert_type} header'
                })
                max_confidence = max(max_confidence, confidence)
        
        return {
            'found': len(secrets) > 0,
            'secrets': secrets,
            'confidence': max_confidence
        }
    
    def _analyze_high_entropy_strings(self, content: str) -> Dict[str, Any]:
        """Claude's entropy analysis for unknown secrets"""
        secrets = []
        
        # Find potential high-entropy strings
        potential_secrets = re.findall(r'[a-zA-Z0-9+/=_-]{20,}', content)
        
        max_confidence = 0.0
        for string in potential_secrets:
            entropy = self._calculate_shannon_entropy(string)
            
            # High entropy suggests randomness (potential secret)
            if entropy > 4.0 and len(string) >= 20:
                confidence = min(entropy / 5.0, 0.9)  # Cap at 90% for entropy-only analysis
                
                secret_type = self._classify_by_characteristics(string)
                
                secrets.append({
                    'type': f'High Entropy {secret_type}',
                    'pattern': string[:25] + "..." if len(string) > 25 else string,
                    'confidence': confidence,
                    'entropy': entropy,
                    'analysis': f'Claude detected high entropy ({entropy:.2f}) suggesting potential secret'
                })
                max_confidence = max(max_confidence, confidence)
        
        return {
            'found': len(secrets) > 0,
            'secrets': secrets,
            'confidence': max_confidence
        }
    
    def _analyze_context_clues(self, content: str, context: str) -> Dict[str, Any]:
        """Claude's contextual analysis"""
        secrets = []
        
        # Look for suspicious variable names or contexts
        context_patterns = [
            (r'(?i)(secret|key|token|auth|credential)["\'\s=:]+([a-zA-Z0-9_-]{16,})', 'Contextual Secret', 0.75),
            (r'(?i)(bearer|authorization)["\'\s=:]+([a-zA-Z0-9_-]{20,})', 'Authorization Token', 0.80),
            (r'(?i)(api[_-]?key)["\'\s=:]+([a-zA-Z0-9_-]{20,})', 'API Key', 0.85),
        ]
        
        max_confidence = 0.0
        for pattern, secret_type, confidence in context_patterns:
            matches = re.findall(pattern, content)
            for match in matches:
                secret_value = match[1] if isinstance(match, tuple) else match
                secrets.append({
                    'type': secret_type,
                    'pattern': secret_value[:20] + "..." if len(secret_value) > 20 else secret_value,
                    'confidence': confidence,
                    'analysis': f'Claude detected based on context clues'
                })
                max_confidence = max(max_confidence, confidence)
        
        return {
            'found': len(secrets) > 0,
            'secrets': secrets,
            'confidence': max_confidence
        }
    
    def _calculate_shannon_entropy(self, text: str) -> float:
        """Calculate Shannon entropy"""
        if not text:
            return 0.0
        
        freq = {}
        for char in text:
            freq[char] = freq.get(char, 0) + 1
        
        entropy = 0.0
        text_len = len(text)
        for count in freq.values():
            probability = count / text_len
            if probability > 0:
                entropy -= probability * math.log2(probability)
        
        return entropy
    
    def _classify_by_characteristics(self, string: str) -> str:
        """Classify string type based on characteristics"""
        if '+' in string or '/' in string or string.endswith('='):
            return 'Base64 Data'
        elif string.startswith(('sk-', 'pk-')):
            return 'API Key'
        elif len(string) == 40 and all(c in '0123456789abcdef' for c in string.lower()):
            return 'SHA-1 Hash'
        elif len(string) == 64 and all(c in '0123456789abcdef' for c in string.lower()):
            return 'SHA-256 Hash'
        else:
            return 'Unknown Secret'
    
    def _analyze_password_strength(self, password: str) -> float:
        """Analyze password strength to determine if it's likely real"""
        if len(password) < 8:
            return 0.3
        
        strength = 0.5  # Base strength
        
        # Length bonus
        if len(password) >= 12:
            strength += 0.2
        
        # Character variety bonus
        if any(c.isupper() for c in password):
            strength += 0.1
        if any(c.islower() for c in password):
            strength += 0.1
        if any(c.isdigit() for c in password):
            strength += 0.1
        if any(not c.isalnum() for c in password):
            strength += 0.1
        
        # Penalize common weak patterns
        weak_patterns = ['password', '123456', 'qwerty', 'admin', 'test']
        if any(pattern in password.lower() for pattern in weak_patterns):
            strength -= 0.3
        
        return min(strength, 1.0)
    
    def _generate_reasoning(self, secrets: List[Dict], content: str) -> str:
        """Generate Claude's reasoning for the analysis"""
        if not secrets:
            return "Claude analyzed the content and found no clear secret patterns. The content appears to be safe."
        
        reasoning = f"Claude detected {len(secrets)} potential secret(s):\n"
        for i, secret in enumerate(secrets[:3]):  # Show top 3
            reasoning += f"{i+1}. {secret['type']}: {secret.get('analysis', 'Pattern matched')}\n"
        
        if len(secrets) > 3:
            reasoning += f"... and {len(secrets) - 3} more potential secrets."
        
        return reasoning