# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
OPA (Open Policy Agent) Plugin for PlugPipe

Integrates Open Policy Agent for advanced policy evaluation in the PlugPipe authorization framework.
Supports both local OPA server and embedded policy evaluation.
"""

import json
import logging
import time
import requests
from typing import Dict, Any, Optional, List
from cores.auth.types import AuthzRequest, AuthzDecision, PolicyDecision

logger = logging.getLogger(__name__)

# Plugin metadata required by PlugPipe
plug_metadata = {
    "name": "opa_policy",
    "version": "1.0.0",
    "description": "Open Policy Agent integration for advanced policy evaluation",
    "author": "PlugPipe Security Team",
    "tags": ["security", "policy", "authorization", "opa"],
    "category": "policy-engine",
    "input_schema": {
        "type": "object",
        "properties": {
            "request": {"type": "object"},
            "basic_decision": {"type": "object"}
        },
        "required": ["request", "basic_decision"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "allow": {"type": "boolean"},
            "engine": {"type": "string"},
            "policy_name": {"type": "string"},
            "constraints": {"type": "object"},
            "reason": {"type": "string"},
            "confidence": {"type": "number"},
            "metadata": {"type": "object"}
        },
        "required": ["allow", "engine"]
    }
}


class OPAPolicyPlugin:
    """
    OPA Policy Plugin for PlugPipe Authorization Framework
    
    Integrates with Open Policy Agent to evaluate complex authorization policies
    beyond basic RBAC capabilities.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        
        # OPA server configuration
        self.opa_url = config.get('opa_url', 'http://localhost:8181')
        self.policy_package = config.get('policy_package', 'plugpipe.authz')
        self.policy_rule = config.get('policy_rule', 'allow')
        self.timeout = config.get('timeout', 5.0)
        
        # Policy configuration
        self.fallback_mode = config.get('fallback_mode', 'deny')  # deny | allow | basic
        self.enable_caching = config.get('enable_caching', True)
        self.cache_ttl = config.get('cache_ttl', 300)  # 5 minutes
        
        # Built-in policies
        self.embedded_policies = config.get('embedded_policies', {})
        self.use_embedded_fallback = config.get('use_embedded_fallback', True)
        
        # Policy cache
        self.policy_cache: Dict[str, Any] = {}
        
        logger.info(f"OPA Policy Plugin initialized - URL: {self.opa_url}, Package: {self.policy_package}")
    
    def evaluate_policy(self, request: AuthzRequest, basic_decision: AuthzDecision) -> PolicyDecision:
        """
        Evaluate OPA policy for authorization request
        
        Args:
            request: Authorization request to evaluate
            basic_decision: Basic RBAC decision from previous layer
            
        Returns:
            PolicyDecision with OPA evaluation result
        """
        start_time = time.time()
        
        try:
            # Prepare input data for OPA
            opa_input = self._prepare_opa_input(request, basic_decision)
            
            # Try OPA server evaluation first
            try:
                decision = self._evaluate_with_opa_server(opa_input)
                decision.evaluation_time_ms = (time.time() - start_time) * 1000
                return decision
                
            except Exception as opa_error:
                logger.warning(f"OPA server evaluation failed: {opa_error}")
                
                # Fall back to embedded policies if enabled
                if self.use_embedded_fallback:
                    try:
                        decision = self._evaluate_with_embedded_policies(opa_input)
                        decision.metadata['fallback_mode'] = 'embedded'
                        decision.evaluation_time_ms = (time.time() - start_time) * 1000
                        return decision
                    except Exception as embedded_error:
                        logger.error(f"Embedded policy evaluation failed: {embedded_error}")
                
                # Apply fallback mode
                return self._apply_fallback_mode(opa_error, start_time)
                
        except Exception as e:
            logger.error(f"OPA policy evaluation error: {e}")
            return self._apply_fallback_mode(e, start_time)
    
    def _prepare_opa_input(self, request: AuthzRequest, basic_decision: AuthzDecision) -> Dict[str, Any]:
        """Prepare input data structure for OPA evaluation"""
        return {
            "input": {
                "subject": request.subject,
                "action": request.action.value if hasattr(request.action, 'value') else str(request.action),
                "resource": request.resource,
                "resource_type": request.resource_type.value if hasattr(request.resource_type, 'value') else str(request.resource_type),
                "resource_namespace": request.resource_namespace,
                "context": request.context,
                "compliance_requirements": request.compliance_requirements,
                "timestamp": request.timestamp,
                "basic_decision": {
                    "allow": basic_decision.allow,
                    "reason": basic_decision.reason,
                    "constraints": basic_decision.constraints,
                    "metadata": basic_decision.metadata
                }
            }
        }
    
    def _evaluate_with_opa_server(self, opa_input: Dict[str, Any]) -> PolicyDecision:
        """Evaluate policy using OPA server"""
        
        # Check cache first if enabled
        if self.enable_caching:
            cache_key = self._get_cache_key(opa_input)
            cached_result = self.policy_cache.get(cache_key)
            if cached_result and time.time() - cached_result['timestamp'] < self.cache_ttl:
                logger.debug("Using cached OPA policy result")
                decision = cached_result['decision']
                decision.metadata['cache_hit'] = True
                return decision
        
        # Construct OPA query URL
        query_url = f"{self.opa_url}/v1/data/{self.policy_package.replace('.', '/')}/{self.policy_rule}"
        
        # Make request to OPA server
        response = requests.post(
            query_url,
            json=opa_input,
            timeout=self.timeout,
            headers={'Content-Type': 'application/json'}
        )
        
        if response.status_code != 200:
            raise Exception(f"OPA server returned {response.status_code}: {response.text}")
        
        result = response.json()
        
        # Parse OPA response
        decision = self._parse_opa_response(result)
        
        # Cache result if enabled
        if self.enable_caching:
            cache_key = self._get_cache_key(opa_input)
            self.policy_cache[cache_key] = {
                'decision': decision,
                'timestamp': time.time()
            }
        
        return decision
    
    def _parse_opa_response(self, opa_result: Dict[str, Any]) -> PolicyDecision:
        """Parse OPA server response into PolicyDecision"""
        
        # Handle different OPA response formats
        if 'result' in opa_result:
            result = opa_result['result']
        else:
            result = opa_result
        
        # Extract decision
        if isinstance(result, bool):
            # Simple boolean result
            allow = result
            constraints = {}
            reason = "OPA policy evaluation"
            policy_name = self.policy_rule
            confidence = 1.0
            metadata = {}
        elif isinstance(result, dict):
            # Structured result
            allow = result.get('allow', False)
            constraints = result.get('constraints', {})
            reason = result.get('reason', 'OPA policy evaluation')
            policy_name = result.get('policy', self.policy_rule)
            confidence = result.get('confidence', 1.0)
            metadata = result.get('metadata', {})
        else:
            # Unexpected format - default to deny
            allow = False
            constraints = {}
            reason = f"Unexpected OPA response format: {type(result)}"
            policy_name = self.policy_rule
            confidence = 0.0
            metadata = {'parse_error': True}
        
        return PolicyDecision(
            allow=allow,
            engine="opa",
            policy_name=policy_name,
            constraints=constraints,
            reason=reason,
            confidence=confidence,
            metadata={
                'opa_package': self.policy_package,
                'opa_rule': self.policy_rule,
                'opa_url': self.opa_url,
                **metadata
            }
        )
    
    def _evaluate_with_embedded_policies(self, opa_input: Dict[str, Any]) -> PolicyDecision:
        """Evaluate using embedded Python policies as fallback"""
        
        input_data = opa_input['input']
        
        # Apply embedded policies - find first allowing policy
        for policy_name, policy_func in self.embedded_policies.items():
            try:
                if callable(policy_func):
                    result = policy_func(input_data)
                    
                    if isinstance(result, bool):
                        allow = result
                        reason = f"Embedded policy {policy_name}"
                        constraints = {}
                    elif isinstance(result, dict):
                        allow = result.get('allow', False)
                        reason = result.get('reason', f"Embedded policy {policy_name}")
                        constraints = result.get('constraints', {})
                    else:
                        continue  # Skip invalid policy results
                    
                    # Return first policy that allows (OR logic for embedded policies)
                    if allow:
                        return PolicyDecision(
                            allow=allow,
                            engine="opa_embedded",
                            policy_name=policy_name,
                            constraints=constraints,
                            reason=reason,
                            confidence=0.8,  # Lower confidence for embedded policies
                            metadata={
                                'embedded_policy': True,
                                'policy_function': policy_name
                            }
                        )
                    
            except Exception as e:
                logger.error(f"Embedded policy {policy_name} evaluation failed: {e}")
                continue
        
        # No embedded policies matched - apply default
        return PolicyDecision(
            allow=False,
            engine="opa_embedded",
            policy_name="default_deny",
            reason="No embedded policies matched",
            confidence=1.0,
            metadata={'embedded_fallback': True}
        )
    
    def _apply_fallback_mode(self, error: Exception, start_time: float) -> PolicyDecision:
        """Apply fallback mode when policy evaluation fails"""
        
        eval_time = (time.time() - start_time) * 1000
        
        if self.fallback_mode == 'allow':
            return PolicyDecision(
                allow=True,
                engine="opa_fallback",
                policy_name="fallback_allow",
                reason=f"OPA evaluation failed, allowing by fallback mode: {str(error)}",
                confidence=0.1,  # Very low confidence
                metadata={'fallback_mode': 'allow', 'error': str(error)},
                evaluation_time_ms=eval_time
            )
        elif self.fallback_mode == 'basic':
            return PolicyDecision(
                allow=True,  # Let basic decision stand
                engine="opa_fallback",
                policy_name="fallback_basic",
                reason=f"OPA evaluation failed, deferring to basic authorization: {str(error)}",
                confidence=0.5,
                metadata={'fallback_mode': 'basic', 'error': str(error)},
                evaluation_time_ms=eval_time
            )
        else:  # fallback_mode == 'deny'
            return PolicyDecision(
                allow=False,
                engine="opa_fallback",
                policy_name="fallback_deny",
                reason=f"OPA evaluation failed, denying by fallback mode: {str(error)}",
                confidence=1.0,  # High confidence in deny for security
                metadata={'fallback_mode': 'deny', 'error': str(error)},
                evaluation_time_ms=eval_time
            )
    
    def _get_cache_key(self, opa_input: Dict[str, Any]) -> str:
        """Generate cache key for OPA input"""
        # Create deterministic hash of input
        import hashlib
        input_str = json.dumps(opa_input, sort_keys=True)
        return hashlib.md5(input_str.encode()).hexdigest()
    
    def validate_policy(self, policy_content: str) -> Dict[str, Any]:
        """
        Validate OPA policy syntax and structure
        
        Args:
            policy_content: Rego policy content
            
        Returns:
            Validation result with errors and warnings
        """
        try:
            # Send policy to OPA for validation
            validate_url = f"{self.opa_url}/v1/policies/validate"
            
            response = requests.post(
                validate_url,
                json={"policy": policy_content},
                timeout=self.timeout
            )
            
            if response.status_code == 200:
                return {"valid": True, "errors": [], "warnings": []}
            else:
                result = response.json()
                return {
                    "valid": False,
                    "errors": result.get("errors", []),
                    "warnings": result.get("warnings", [])
                }
                
        except Exception as e:
            return {
                "valid": False,
                "errors": [f"Policy validation failed: {str(e)}"],
                "warnings": []
            }
    
    def reload_policies(self) -> bool:
        """Reload policies from OPA server"""
        try:
            # Clear cache
            self.policy_cache.clear()
            
            # Trigger policy reload if OPA supports it
            reload_url = f"{self.opa_url}/v1/policies"
            response = requests.get(reload_url, timeout=self.timeout)
            
            if response.status_code == 200:
                logger.info("OPA policies reloaded successfully")
                return True
            else:
                logger.warning(f"Policy reload returned {response.status_code}")
                return False
                
        except Exception as e:
            logger.error(f"Policy reload failed: {e}")
            return False


# PlugPipe plugin interface
def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> PolicyDecision:
    """
    Main plugin entry point for PlugPipe
    
    Args:
        ctx: Context containing authorization request and basic decision
        cfg: Plugin configuration
        
    Returns:
        PolicyDecision result
    """
    try:
        # Extract request and basic decision from context
        request_data = ctx.get('request')
        basic_decision_data = ctx.get('basic_decision')
        
        if not request_data or not basic_decision_data:
            raise ValueError("Missing required request or basic_decision in context")
        
        # Reconstruct objects from dictionaries
        request = AuthzRequest(**request_data)
        basic_decision = AuthzDecision(**basic_decision_data)
        
        # Initialize OPA plugin
        opa_plugin = OPAPolicyPlugin(cfg)
        
        # Evaluate policy
        decision = opa_plugin.evaluate_policy(request, basic_decision)
        
        # Return decision as dictionary for PlugPipe
        return decision.to_dict()
        
    except Exception as e:
        logger.error(f"OPA plugin process error: {e}")
        # Return denial on error
        return PolicyDecision(
            allow=False,
            engine="opa_error",
            reason=f"Plugin execution error: {str(e)}",
            confidence=1.0,
            metadata={'plugin_error': True}
        ).to_dict()


# Example embedded policies for fallback
EXAMPLE_EMBEDDED_POLICIES = {
    "admin_full_access": lambda input_data: {
        "allow": "admin" in input_data.get("context", {}).get("roles", []),
        "reason": "Admin role has full access",
        "constraints": {}
    },
    
    "developer_plugin_access": lambda input_data: {
        "allow": (
            "developer" in input_data.get("context", {}).get("roles", []) and
            input_data.get("resource_type") == "plugin" and
            input_data.get("action") in ["read", "execute"]
        ),
        "reason": "Developer can read and execute plugins",
        "constraints": {
            "memory_limit_mb": 512,
            "timeout_seconds": 30
        }
    },
    
    "namespace_isolation": lambda input_data: {
        "allow": (
            input_data.get("resource_namespace") == "public" or
            input_data.get("resource_namespace") in input_data.get("context", {}).get("allowed_namespaces", [])
        ),
        "reason": "Namespace access control",
        "constraints": {}
    }
}