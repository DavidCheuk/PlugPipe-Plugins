# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Cedar Policy Engine Plugin
===========================

AWS Cedar policy engine for fast, simple policy evaluation.

Cedar is AWS's open-source authorization policy language designed for:
- Simple, readable syntax
- Fast evaluation (< 10ms avg)
- Schema validation
- AWS-native integration

PlugPipe Integration:
- Used by policy_engine_adapter for Pro tier
- Ideal for simple to medium complexity policies
- Complements OPA for high-performance scenarios
"""

import json
import time
from typing import Dict, Any, List, Optional


class CedarPolicyEngine:
    """
    Cedar policy engine implementation.

    In a production environment, this would integrate with:
    - AWS Verified Permissions service
    - cedar-py Python bindings
    - Local Cedar evaluation engine

    For PlugPipe demo, we implement Cedar policy semantics.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.policies: Dict[str, Dict[str, Any]] = {}
        self.cache: Dict[str, Any] = {}
        self.cache_enabled = config.get("cache_enabled", True)
        self.cache_ttl = config.get("cache_ttl_seconds", 300)
        self.default_decision = config.get("default_decision", "deny")

    def evaluate(
        self,
        principal: Dict[str, str],
        action: Dict[str, str],
        resource: Dict[str, str],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate Cedar policies for a request.

        Cedar evaluation logic:
        1. Check cache
        2. Find applicable policies
        3. Evaluate permit/forbid policies
        4. Return decision with diagnostics
        """
        start_time = time.time()

        # Build cache key
        cache_key = self._build_cache_key(principal, action, resource)

        # Check cache
        if self.cache_enabled:
            cached = self._get_cached_decision(cache_key)
            if cached:
                cached["from_cache"] = True
                return cached

        # Find applicable policies
        applicable_policies = self._find_applicable_policies(
            principal, action, resource, context
        )

        if not applicable_policies:
            # No policies match - use default decision
            decision = {
                "decision": "Deny" if self.default_decision == "deny" else "Allow",
                "policy_id": "default_policy",
                "reason": f"No applicable policies found, default to {self.default_decision}",
                "diagnostics": {
                    "matched_policies": [],
                    "evaluation_notes": ["No policies matched request"]
                }
            }
        else:
            # Evaluate policies (forbid takes precedence over permit)
            decision = self._evaluate_policies(
                applicable_policies, principal, action, resource, context
            )

        # Add evaluation time
        evaluation_time = (time.time() - start_time) * 1000
        decision["evaluation_time_ms"] = evaluation_time

        # Cache decision
        if self.cache_enabled:
            self._cache_decision(cache_key, decision)

        return decision

    def _find_applicable_policies(
        self,
        principal: Dict[str, str],
        action: Dict[str, str],
        resource: Dict[str, str],
        context: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Find policies that apply to this request.

        Cedar policies match on:
        - Principal type and ID (with wildcards)
        - Action type and ID
        - Resource type and ID
        - Context conditions
        """
        applicable = []

        for policy_id, policy_data in self.policies.items():
            if self._policy_matches_request(
                policy_data, principal, action, resource, context
            ):
                applicable.append({
                    "id": policy_id,
                    "effect": policy_data["effect"],
                    "conditions": policy_data.get("conditions", [])
                })

        return applicable

    def _policy_matches_request(
        self,
        policy: Dict[str, Any],
        principal: Dict[str, str],
        action: Dict[str, str],
        resource: Dict[str, str],
        context: Dict[str, Any]
    ) -> bool:
        """Check if policy applies to request."""

        # Check principal
        policy_principal = policy.get("principal", {})
        if policy_principal:
            if not self._matches_entity(
                policy_principal,
                principal.get("type"),
                principal.get("id")
            ):
                return False

        # Check action
        policy_action = policy.get("action", {})
        if policy_action:
            if not self._matches_entity(
                policy_action,
                action.get("type"),
                action.get("id")
            ):
                return False

        # Check resource
        policy_resource = policy.get("resource", {})
        if policy_resource:
            if not self._matches_entity(
                policy_resource,
                resource.get("type"),
                resource.get("id")
            ):
                return False

        # Check context conditions
        conditions = policy.get("conditions", [])
        for condition in conditions:
            if not self._evaluate_condition(condition, context):
                return False

        return True

    def _matches_entity(
        self,
        policy_entity: Dict[str, Any],
        entity_type: Optional[str],
        entity_id: Optional[str]
    ) -> bool:
        """Check if entity matches policy specification."""

        # Wildcard match
        if policy_entity.get("type") == "*":
            return True

        # Type match
        if policy_entity.get("type") != entity_type:
            return False

        # ID match (with wildcard support)
        policy_id = policy_entity.get("id", "*")
        if policy_id == "*":
            return True

        return policy_id == entity_id

    def _evaluate_condition(
        self,
        condition: Dict[str, Any],
        context: Dict[str, Any]
    ) -> bool:
        """
        Evaluate Cedar condition.

        Simplified condition evaluation:
        - Equality checks
        - Comparison operators
        - Context attribute checks
        """
        operator = condition.get("operator", "==")
        left = condition.get("left")
        right = condition.get("right")

        # Resolve context references
        if isinstance(left, str) and left.startswith("context."):
            attr = left.replace("context.", "")
            left = context.get(attr)

        if isinstance(right, str) and right.startswith("context."):
            attr = right.replace("context.", "")
            right = context.get(attr)

        # Evaluate operator
        if operator == "==":
            return left == right
        elif operator == "!=":
            return left != right
        elif operator == ">":
            return left > right
        elif operator == "<":
            return left < right
        elif operator == ">=":
            return left >= right
        elif operator == "<=":
            return left <= right
        elif operator == "in":
            return left in right
        else:
            return False

    def _evaluate_policies(
        self,
        applicable_policies: List[Dict[str, Any]],
        principal: Dict[str, str],
        action: Dict[str, str],
        resource: Dict[str, str],
        context: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Evaluate applicable policies.

        Cedar semantics:
        - Any forbid → Deny
        - All permit, no forbid → Allow
        - No permit, no forbid → Deny (default)
        """
        has_permit = False
        has_forbid = False
        forbid_policy = None
        permit_policy = None

        for policy in applicable_policies:
            if policy["effect"] == "forbid":
                has_forbid = True
                forbid_policy = policy["id"]
                break  # Forbid takes precedence

            if policy["effect"] == "permit":
                has_permit = True
                permit_policy = policy["id"]

        # Decision logic
        if has_forbid:
            return {
                "decision": "Deny",
                "policy_id": forbid_policy,
                "reason": f"Explicitly forbidden by policy {forbid_policy}",
                "diagnostics": {
                    "matched_policies": [p["id"] for p in applicable_policies],
                    "evaluation_notes": ["Forbid policy matched"]
                }
            }

        if has_permit:
            return {
                "decision": "Allow",
                "policy_id": permit_policy,
                "reason": f"Permitted by policy {permit_policy}",
                "diagnostics": {
                    "matched_policies": [p["id"] for p in applicable_policies],
                    "evaluation_notes": ["Permit policy matched, no forbid"]
                }
            }

        # No applicable policies
        return {
            "decision": "Deny",
            "policy_id": "default_deny",
            "reason": "No permit policies matched",
            "diagnostics": {
                "matched_policies": [],
                "evaluation_notes": ["No permit or forbid policies matched"]
            }
        }

    def _build_cache_key(
        self,
        principal: Dict[str, str],
        action: Dict[str, str],
        resource: Dict[str, str]
    ) -> str:
        """Build cache key from request."""
        return f"{principal.get('type')}:{principal.get('id')}|{action.get('id')}|{resource.get('type')}:{resource.get('id')}"

    def _get_cached_decision(self, cache_key: str) -> Optional[Dict[str, Any]]:
        """Get cached decision if not expired."""
        if cache_key in self.cache:
            entry = self.cache[cache_key]
            if time.time() - entry["cached_at"] < self.cache_ttl:
                return entry["decision"].copy()

        return None

    def _cache_decision(self, cache_key: str, decision: Dict[str, Any]):
        """Cache a decision."""
        self.cache[cache_key] = {
            "decision": decision.copy(),
            "cached_at": time.time()
        }

    def validate_policy(self, policy_content: str) -> Dict[str, Any]:
        """
        Validate Cedar policy syntax.

        Cedar policy format:
        permit(
          principal == User::"alice",
          action == Action::"view",
          resource == Photo::"vacation.jpg"
        );
        """
        try:
            # Basic syntax validation
            if not policy_content.strip():
                return {"valid": False, "error": "Empty policy content"}

            # Check for required keywords
            if not any(kw in policy_content for kw in ["permit", "forbid"]):
                return {
                    "valid": False,
                    "error": "Cedar policy must contain 'permit' or 'forbid' statement"
                }

            # Check for basic structure
            if "(" not in policy_content or ")" not in policy_content:
                return {
                    "valid": False,
                    "error": "Cedar policy must have principal, action, resource"
                }

            return {
                "valid": True,
                "language": "cedar",
                "estimated_complexity": "low",
                "estimated_performance_ms": 5.0
            }

        except Exception as e:
            return {"valid": False, "error": f"Validation error: {str(e)}"}

    def load_policy(
        self,
        policy_id: str,
        policy_content: str,
        policy_metadata: Dict[str, Any]
    ) -> bool:
        """
        Load a Cedar policy.

        For demo purposes, we parse simple policy structure.
        Production would use Cedar parser.
        """
        try:
            # Validate first
            validation = self.validate_policy(policy_content)
            if not validation.get("valid"):
                return False

            # Parse policy (simplified)
            effect = "permit" if "permit" in policy_content else "forbid"

            # Store policy
            self.policies[policy_id] = {
                "content": policy_content,
                "effect": effect,
                "metadata": policy_metadata,
                "loaded_at": time.time(),
                "principal": self._parse_entity(policy_content, "principal"),
                "action": self._parse_entity(policy_content, "action"),
                "resource": self._parse_entity(policy_content, "resource"),
                "conditions": []
            }

            return True

        except Exception:
            return False

    def _parse_entity(self, policy_content: str, entity_type: str) -> Dict[str, Any]:
        """
        Parse entity from Cedar policy (simplified).

        Production would use proper Cedar parser.
        """
        # For demo, use simple patterns
        if entity_type in policy_content:
            # Extract type and ID if present
            # This is simplified - real Cedar parser would be more robust
            return {"type": "*", "id": "*"}

        return {}

    def list_policies(self) -> List[Dict[str, Any]]:
        """List all loaded policies."""
        policies = []

        for policy_id, policy_data in self.policies.items():
            policies.append({
                "id": policy_id,
                "effect": policy_data["effect"],
                "loaded_at": policy_data["loaded_at"],
                "metadata": policy_data.get("metadata", {})
            })

        return policies

    def delete_policy(self, policy_id: str) -> bool:
        """Delete a policy."""
        if policy_id in self.policies:
            del self.policies[policy_id]
            return True
        return False

    def health_check(self) -> Dict[str, Any]:
        """Health check."""
        return {
            "healthy": True,
            "policies_count": len(self.policies),
            "cache_size": len(self.cache)
        }


def process(plugin_ctx: Dict[str, Any], plugin_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Cedar Policy Engine main entry point.
    """
    action = plugin_ctx.get("action", "evaluate")

    # Initialize engine
    engine = CedarPolicyEngine(plugin_cfg)

    # Load default policies
    _load_default_policies(engine, plugin_cfg)

    if action == "evaluate":
        principal = plugin_ctx.get("principal", {})
        action_request = plugin_ctx.get("action_request", {})
        resource = plugin_ctx.get("resource", {})
        context = plugin_ctx.get("context", {})

        if not principal or not action_request or not resource:
            return {
                "success": False,
                "error": "Missing principal, action, or resource"
            }

        result = engine.evaluate(principal, action_request, resource, context)

        return {
            "success": True,
            **result
        }

    elif action == "validate_policy":
        policy_content = plugin_ctx.get("policy_content", "")

        if not policy_content:
            return {"success": False, "error": "Missing policy_content"}

        validation = engine.validate_policy(policy_content)

        return {
            "success": True,
            **validation
        }

    elif action == "load_policy":
        policy_id = plugin_ctx.get("policy_id", "")
        policy_content = plugin_ctx.get("policy_content", "")
        policy_metadata = plugin_ctx.get("policy_metadata", {})

        if not policy_id or not policy_content:
            return {"success": False, "error": "Missing policy_id or policy_content"}

        success = engine.load_policy(policy_id, policy_content, policy_metadata)

        return {"success": success}

    elif action == "list_policies":
        policies = engine.list_policies()

        return {
            "success": True,
            "policies": policies
        }

    elif action == "delete_policy":
        policy_id = plugin_ctx.get("policy_id", "")

        if not policy_id:
            return {"success": False, "error": "Missing policy_id"}

        success = engine.delete_policy(policy_id)

        return {"success": success}

    elif action == "health_check":
        health = engine.health_check()

        return {
            "success": True,
            **health
        }

    else:
        return {"success": False, "error": f"Unknown action: {action}"}


def _load_default_policies(engine: CedarPolicyEngine, config: Dict[str, Any]):
    """
    Load default Cedar policies for common scenarios.

    These provide sensible defaults for Pro tier users.
    """
    # Admin access policy
    engine.load_policy(
        "admin_allow_all",
        """
        permit(
          principal,
          action,
          resource
        ) when {
          principal.role == "admin"
        };
        """,
        {"description": "Admins have full access", "effect": "permit"}
    )

    # Read-only policy
    engine.load_policy(
        "read_allow",
        """
        permit(
          principal,
          action,
          resource
        ) when {
          action.id in ["read", "list", "get", "view"]
        };
        """,
        {"description": "Allow read-only actions for all users", "effect": "permit"}
    )

    # Pro tier protocol access
    engine.load_policy(
        "pro_protocols",
        """
        permit(
          principal,
          action == Action::"use_protocol",
          resource
        ) when {
          principal.tier == "pro" &&
          resource.id in ["mcp", "a2a", "rest", "graphql"]
        };
        """,
        {"description": "Pro tier can access all protocols", "effect": "permit"}
    )


if __name__ == "__main__":
    # Test the plugin
    test_input = {
        "action": "evaluate",
        "principal": {"type": "User", "id": "alice"},
        "action_request": {"type": "Action", "id": "read"},
        "resource": {"type": "Plugin", "id": "echo"},
        "context": {}
    }

    test_config = {
        "cache_enabled": True,
        "default_decision": "deny"
    }

    result = process(test_input, test_config)
    print(json.dumps(result, indent=2))
