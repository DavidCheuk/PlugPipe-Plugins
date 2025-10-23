#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Secret Scanner Plugin - Universal Interface Version
Follows PlugPipe Universal Security Plugin Interface Standard
"""

import asyncio
import re
import time
import sys
import os
from typing import Dict, Any, List

# Add shares to path for universal interface
sys.path.append(os.path.join(os.path.dirname(__file__), '../../../../'))
from shares.security.universal_security_plugin_interface import (
    UniversalSecurityPlugin, SecurityPluginContext, SecurityPluginResult,
    SecurityAction, ThreatLevel, ThreatDetection
)

# Comprehensive secret patterns
SECRET_PATTERNS = {
    # High severity patterns
    'openai_api_key': {
        'pattern': r'sk-[A-Za-z0-9]{32,}',
        'severity': ThreatLevel.CRITICAL,
        'description': 'OpenAI API key detected'
    },
    'github_token': {
        'pattern': r'ghp_[A-Za-z0-9]{36}',
        'severity': ThreatLevel.HIGH,
        'description': 'GitHub personal access token detected'
    },
    'github_pat': {
        'pattern': r'github_pat_[A-Za-z0-9_]{82}',
        'severity': ThreatLevel.HIGH,
        'description': 'GitHub PAT detected'
    },
    'aws_access_key': {
        'pattern': r'AKIA[A-Z0-9]{16}',
        'severity': ThreatLevel.CRITICAL,
        'description': 'AWS access key detected'
    },
    'aws_secret_key': {
        'pattern': r'[A-Za-z0-9/+=]{40}',
        'severity': ThreatLevel.CRITICAL,
        'description': 'AWS secret key detected'
    },
    'private_key': {
        'pattern': r'-----BEGIN (RSA |EC |)PRIVATE KEY-----',
        'severity': ThreatLevel.CRITICAL,
        'description': 'Private key detected'
    },
    'jwt_token': {
        'pattern': r'eyJ[A-Za-z0-9_/+=\-]+\.[A-Za-z0-9_/+=\-]+\.[A-Za-z0-9_/+=\-]+',
        'severity': ThreatLevel.HIGH,
        'description': 'JWT token detected'
    },
    
    # Medium severity patterns  
    'password_assignment': {
        'pattern': r'[Pp]assword\s*[=:]\s*["\'][^"\']{6,}["\']',
        'severity': ThreatLevel.MEDIUM,
        'description': 'Password assignment detected'
    },
    'database_connection': {
        'pattern': r'(mysql|postgresql|mongodb|redis)://[A-Za-z0-9._-]+:[A-Za-z0-9._-]+@[A-Za-z0-9.\-_]+',
        'severity': ThreatLevel.HIGH,
        'description': 'Database connection string with credentials detected'
    },
    'api_key_assignment': {
        'pattern': r'[Aa]pi[_-]?[Kk]ey\s*[=:]\s*["\'][A-Za-z0-9]{15,}["\']',
        'severity': ThreatLevel.HIGH,
        'description': 'API key assignment detected'
    },
    'slack_token': {
        'pattern': r'xox[baprs]-[A-Za-z0-9\-]+',
        'severity': ThreatLevel.HIGH,
        'description': 'Slack token detected'
    },
    'credentials_json': {
        'pattern': r'["\'](?:password|pwd|pass|secret|key)["\']:\s*["\'][^"\']{6,}["\']',
        'severity': ThreatLevel.MEDIUM,
        'description': 'Credentials in JSON detected'
    }
}

class SecretScannerUniversal(UniversalSecurityPlugin):
    """
    Secret Scanner following universal interface standard
    """
    
    def __init__(self):
        super().__init__()
        self.plugin_name = "cyberpig_ai"
        self.plugin_version = "1.0.0_universal"
        
        # Compile patterns for performance
        self.compiled_patterns = {}
        for secret_type, pattern_info in SECRET_PATTERNS.items():
            try:
                self.compiled_patterns[secret_type] = {
                    'regex': re.compile(pattern_info['pattern'], re.IGNORECASE),
                    'severity': pattern_info['severity'],
                    'description': pattern_info['description']
                }
            except re.error:
                continue  # Skip invalid patterns
    
    async def analyze_content(self, context: SecurityPluginContext, config: Dict[str, Any]) -> SecurityPluginResult:
        """
        Analyze content for secret patterns
        
        Args:
            context: SecurityPluginContext with content to analyze
            config: Plugin configuration
            
        Returns:
            SecurityPluginResult with standardized format
        """
        start_time = time.time()
        threats = []
        content = context.content
        
        if not content or not isinstance(content, str):
            return self.create_result(
                action=SecurityAction.ALLOW,
                threat_score=0.0,
                threats=[],
                metadata={'error': 'No valid content to scan', 'content_length': 0}
            )
        
        # Scan for secrets
        secrets_found = []
        for secret_type, pattern_info in self.compiled_patterns.items():
            matches = pattern_info['regex'].finditer(content)
            
            for match in matches:
                start_pos = match.start()
                end_pos = match.end()
                secret_value = match.group()
                
                # Create threat detection
                threat = self.create_threat_detection(
                    threat_type=f"secret_{secret_type}",
                    threat_level=pattern_info['severity'],
                    confidence=0.95,  # High confidence for pattern-based detection
                    description=f"{pattern_info['description']}: {secret_value[:10]}...",
                    evidence={
                        'secret_type': secret_type,
                        'value_preview': f"{secret_value[:10]}..." if len(secret_value) > 10 else secret_value,
                        'full_match': secret_value,
                        'pattern_matched': pattern_info['regex'].pattern
                    },
                    recommendation="Remove or encrypt this secret immediately",
                    start_pos=start_pos,
                    end_pos=end_pos
                )
                threats.append(threat)
                
                secrets_found.append({
                    'type': secret_type,
                    'confidence': 0.95,
                    'start': start_pos,
                    'end': end_pos,
                    'length': end_pos - start_pos,
                    'value_preview': f"{secret_value[:10]}..." if len(secret_value) > 10 else secret_value,
                    'severity': pattern_info['severity'].value
                })
        
        # Calculate threat score based on findings
        if not threats:
            threat_score = 0.0
            action = SecurityAction.ALLOW
        else:
            # Higher threat score for more/higher severity secrets
            severity_weights = {
                ThreatLevel.CRITICAL: 1.0,
                ThreatLevel.HIGH: 0.8,
                ThreatLevel.MEDIUM: 0.5,
                ThreatLevel.LOW: 0.3
            }
            
            total_weight = sum(severity_weights.get(threat.threat_level, 0.5) for threat in threats)
            threat_score = min(total_weight / len(threats) if threats else 0.0, 1.0)
            
            # Block if any critical or high severity secrets found
            critical_or_high = any(threat.threat_level in [ThreatLevel.CRITICAL, ThreatLevel.HIGH] 
                                 for threat in threats)
            action = SecurityAction.BLOCK if critical_or_high else SecurityAction.REVIEW
        
        processing_time = (time.time() - start_time) * 1000
        
        result = self.create_result(
            action=action,
            threat_score=threat_score,
            threats=threats,
            confidence=1.0,
            metadata={
                'secrets_found': secrets_found,
                'total_secrets': len(secrets_found),
                'patterns_checked': len(self.compiled_patterns),
                'text_length': len(content),
                'processing_time_ms': processing_time
            }
        )
        
        # Update processing time
        result.processing_time_ms = processing_time
        
        return result

# Legacy compatibility wrapper
class LegacyWrapper:
    """Wrapper for legacy PlugPipe interface compatibility"""
    
    def __init__(self):
        self.universal_plugin = SecretScannerUniversal()
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Legacy process method for backward compatibility"""
        
        # Convert legacy context to universal context
        content = ctx.get('text', ctx.get('payload', ctx.get('content', ctx.get('data', ''))))
        
        context = SecurityPluginContext(
            content=str(content) if content else '',
            operation=ctx.get('operation', 'analyze'),
            content_type=ctx.get('content_type', 'text'),
            source_ip=ctx.get('source_ip'),
            user_id=ctx.get('user_id'),
            request_id=ctx.get('request_id'),
            metadata={k: v for k, v in ctx.items() 
                     if k not in ['text', 'payload', 'content', 'data']}
        )
        
        # Process through universal interface
        result = await self.universal_plugin.analyze_content(context, cfg)
        
        # Convert back to legacy format for compatibility
        legacy_result = {
            'status': 'completed',
            'action': result.action.value,
            'threat_score': result.threat_score,
            'vote': result.vote.value,
            'threats_detected': [threat.description for threat in result.threats_detected],
            'plugin_name': result.plugin_name,
            'plugin_version': result.plugin_version,
            'processing_time': result.processing_time_ms,
            'timestamp': result.timestamp
        }
        
        # Add legacy-specific fields
        legacy_result.update(result.metadata)
        
        return legacy_result
    
    def process_sync(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Synchronous wrapper for legacy compatibility"""
        import asyncio
        try:
            loop = asyncio.get_event_loop()
            return loop.run_until_complete(self.process(ctx, cfg))
        except RuntimeError:
            # Create new event loop if none exists
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            try:
                return loop.run_until_complete(self.process(ctx, cfg))
            finally:
                loop.close()

# Plugin entry points
_legacy_wrapper = LegacyWrapper()

# For PlugPipe async interface
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe async entry point"""
    return await _legacy_wrapper.process(ctx, cfg)

# For PlugPipe sync interface (if needed)
def process_sync(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """PlugPipe sync entry point"""
    return _legacy_wrapper.process_sync(ctx, cfg)

# Direct universal interface access
def get_universal_plugin() -> SecretScannerUniversal:
    """Get the universal plugin instance directly"""
    return SecretScannerUniversal()

if __name__ == "__main__":
    # Test the plugin
    import asyncio
    
    async def test():
        plugin = SecretScannerUniversal()
        
        test_cases = [
            "sk-1234567890abcdef1234567890abcdef",
            "AKIAIOSFODNN7EXAMPLE",
            "This is just normal text",
            "password = 'secret123'"
        ]
        
        for test_content in test_cases:
            context = SecurityPluginContext(content=test_content)
            result = await plugin.analyze_content(context, {})
            
            print(f"Content: {test_content[:30]}...")
            print(f"Action: {result.action.value}")
            print(f"Threat Score: {result.threat_score}")
            print(f"Threats: {len(result.threats_detected)}")
            print("-" * 40)
    
    asyncio.run(test())