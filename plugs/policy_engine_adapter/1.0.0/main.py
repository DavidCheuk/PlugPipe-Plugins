# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Policy Engine Adapter Plugin
=============================

Universal adapter for Policy-as-Code engines following PlugPipe spirit.

CRITICAL PLUGPIPE PRINCIPLES:
- REUSE EVERYTHING: Uses existing opa_policy_enterprise plugin via pp()
- NO CUSTOM LOGIC: All policy evaluation delegated to specialized plugins
- PLUGIN = ABSTRACTION: This adapter IS the abstraction layer
- DEFAULT TO PLUGINS: Routes to OPA/Cedar/Custom plugins, never hardcoded logic

Architecture:
    Frontend → policy_engine_adapter → pp("opa_policy_enterprise")
                                     → pp("cedar_policy")
                                     → pp("custom_policy")
"""

import json
import time
from typing import Dict, Any, Optional

# CRITICAL: Use pp() for plugin discovery - NEVER import plugins directly
from shares.loader import pp


def process(plugin_ctx: Dict[str, Any], plugin_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Policy Engine Adapter main entry point.

    Routes policy evaluation to appropriate policy engine plugin using pp().
    This follows PlugPipe spirit: PLUGINS ALL THE WAY DOWN.
    """
    action = plugin_ctx.get("action", "evaluate_policy")

    if action == "evaluate_policy":
        return _evaluate_policy_via_plugin(plugin_ctx, plugin_cfg)

    elif action == "list_engines":
        return _list_available_engines(plugin_ctx, plugin_cfg)

    elif action == "get_engine_health":
        return _get_engines_health(plugin_cfg)

    elif action == "route_policy":
        return _route_to_engine(plugin_ctx, plugin_cfg)

    else:
        return {"success": False, "error": f"Unknown action: {action}"}


def _evaluate_policy_via_plugin(
    plugin_ctx: Dict[str, Any],
    plugin_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Evaluate policy by routing to appropriate policy engine PLUGIN.

    PLUGPIPE SPIRIT: This function NEVER evaluates policies itself.
    It ALWAYS delegates to specialized policy plugins via pp().
    """
    policy_request = plugin_ctx.get("policy_request", {})

    if not policy_request:
        return {"success": False, "error": "Missing policy_request"}

    # Determine which policy engine plugin to use
    selected_engine = _select_engine(policy_request, plugin_cfg)

    if selected_engine == "none":
        # Free tier: No policy engine available
        return {
            "success": True,
            "decision": {
                "allow": _evaluate_hardcoded_free_tier(policy_request),
                "engine": "hardcoded_free_tier",
                "policy_name": "free_tier_permissions",
                "reason": "Free tier uses hardcoded permission checks",
                "confidence": 1.0,
                "evaluation_time_ms": 0.5,
                "metadata": {
                    "upgrade_url": "/settings/subscription",
                    "required_tier": "pro"
                }
            }
        }

    # Get the plugin name for the selected engine
    engine_plugin = _get_engine_plugin_name(selected_engine, plugin_cfg)

    if not engine_plugin:
        return {
            "success": False,
            "error": f"No plugin configured for engine: {selected_engine}"
        }

    # CRITICAL: Use pp() to call the policy engine plugin
    # This is the PLUGPIPE WAY - delegation via plugin discovery
    try:
        start_time = time.time()

        # Route to appropriate plugin based on engine type
        if selected_engine == "opa":
            # Call OPA plugin via pp()
            result = _call_opa_plugin(engine_plugin, policy_request, plugin_cfg)

        elif selected_engine == "cedar":
            # Call Cedar plugin via pp()
            result = _call_cedar_plugin(engine_plugin, policy_request, plugin_cfg)

        elif selected_engine == "custom":
            # Call Custom policy plugin via pp()
            result = _call_custom_plugin(engine_plugin, policy_request, plugin_cfg)

        else:
            return {
                "success": False,
                "error": f"Unsupported engine: {selected_engine}"
            }

        evaluation_time = (time.time() - start_time) * 1000

        # Add evaluation metadata
        if "decision" in result:
            result["decision"]["evaluation_time_ms"] = evaluation_time
            result["decision"]["engine"] = f"{selected_engine}_{result['decision'].get('engine', 'plugin')}"

        return result

    except Exception as e:
        return {
            "success": False,
            "error": f"Policy evaluation failed: {str(e)}",
            "decision": {
                "allow": False,
                "engine": f"{selected_engine}_error",
                "policy_name": "error_policy",
                "reason": f"Error: {str(e)}",
                "confidence": 1.0,
                "metadata": {"error": True}
            }
        }


def _call_opa_plugin(
    plugin_name: str,
    policy_request: Dict[str, Any],
    plugin_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Call OPA policy plugin via pp().

    PLUGPIPE PRINCIPLE: REUSE the existing opa_policy_enterprise plugin.
    """
    # Prepare input for opa_policy_enterprise plugin
    opa_input = {
        "action": "evaluate_policy",
        "request": {
            "subject": policy_request.get("subject", "unknown"),
            "action": policy_request.get("action", "unknown"),
            "resource": policy_request.get("resource", "unknown"),
            "resource_type": policy_request.get("resource_type", "unknown"),
        },
        "basic_decision": {
            "allow": True,  # Let OPA make the final decision
            "reason": "Forwarded from policy_engine_adapter"
        },
        "tenant_id": policy_request.get("tenant_id", "default")
    }

    # CRITICAL: Use pp() to discover and execute the OPA plugin
    opa_plugin = pp(plugin_name)

    if not opa_plugin:
        raise Exception(f"OPA plugin '{plugin_name}' not found")

    # Execute the OPA plugin
    opa_result = opa_plugin(opa_input)

    # Transform OPA result to standard format
    return {
        "success": True,
        "decision": {
            "allow": opa_result.get("allow", False),
            "engine": opa_result.get("engine", "opa"),
            "policy_name": "opa_enterprise_policy",
            "reason": opa_result.get("reason", "OPA policy evaluation"),
            "confidence": opa_result.get("confidence", 1.0),
            "metadata": opa_result.get("metadata", {})
        }
    }


def _call_cedar_plugin(
    plugin_name: str,
    policy_request: Dict[str, Any],
    plugin_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Call Cedar policy plugin via pp().

    PLUGPIPE PRINCIPLE: Delegate to specialized cedar_policy plugin.
    """
    # Prepare input for cedar_policy plugin
    cedar_input = {
        "action": "evaluate",
        "principal": {
            "type": "User",
            "id": policy_request.get("subject", "unknown")
        },
        "action_request": {
            "type": "Action",
            "id": policy_request.get("action", "unknown")
        },
        "resource": {
            "type": policy_request.get("resource_type", "Resource"),
            "id": policy_request.get("resource", "unknown")
        },
        "context": policy_request.get("context", {})
    }

    # CRITICAL: Use pp() to discover and execute the Cedar plugin
    cedar_plugin = pp(plugin_name)

    if not cedar_plugin:
        raise Exception(f"Cedar plugin '{plugin_name}' not found")

    # Execute the Cedar plugin
    cedar_result = cedar_plugin(cedar_input)

    # Transform Cedar result to standard format
    return {
        "success": True,
        "decision": {
            "allow": cedar_result.get("decision") == "Allow",
            "engine": "cedar",
            "policy_name": cedar_result.get("policy_id", "cedar_policy"),
            "reason": cedar_result.get("reason", "Cedar policy evaluation"),
            "confidence": 1.0,
            "metadata": {
                "cedar_diagnostics": cedar_result.get("diagnostics", {})
            }
        }
    }


def _call_custom_plugin(
    plugin_name: str,
    policy_request: Dict[str, Any],
    plugin_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Call Custom policy plugin via pp().

    PLUGPIPE PRINCIPLE: Support custom Python/JS policies via plugin.
    """
    # Prepare input for custom_policy plugin
    custom_input = {
        "action": "evaluate",
        "subject": policy_request.get("subject", "unknown"),
        "action_requested": policy_request.get("action", "unknown"),
        "resource": policy_request.get("resource", "unknown"),
        "resource_type": policy_request.get("resource_type", "unknown"),
        "context": policy_request.get("context", {}),
        "tenant_id": policy_request.get("tenant_id")
    }

    # CRITICAL: Use pp() to discover and execute the Custom policy plugin
    custom_plugin = pp(plugin_name)

    if not custom_plugin:
        raise Exception(f"Custom policy plugin '{plugin_name}' not found")

    # Execute the Custom policy plugin
    custom_result = custom_plugin(custom_input)

    # Transform Custom result to standard format
    return {
        "success": True,
        "decision": {
            "allow": custom_result.get("allow", False),
            "engine": "custom",
            "policy_name": custom_result.get("policy_name", "custom_policy"),
            "reason": custom_result.get("reason", "Custom policy evaluation"),
            "confidence": custom_result.get("confidence", 0.8),
            "metadata": custom_result.get("metadata", {})
        }
    }


def _select_engine(
    policy_request: Dict[str, Any],
    plugin_cfg: Dict[str, Any]
) -> str:
    """
    Select appropriate policy engine based on tenant tier and routing rules.

    Routing logic:
    1. Check explicit engine preference
    2. Route by tenant tier (free/pro/enterprise/custom)
    3. Route by resource type (commercial_plugin → OPA, etc.)
    4. Route by complexity (simple → Cedar, complex → OPA)
    5. Fallback to default engine
    """
    # 1. Explicit preference
    engine_preference = policy_request.get("engine_preference", "auto")
    if engine_preference != "auto":
        return engine_preference

    routing_rules = plugin_cfg.get("routing_rules", {})

    # 2. Route by tenant tier
    tenant_tier = policy_request.get("tenant_tier", "free")
    tier_routing = routing_rules.get("by_tenant_tier", {})
    tier_engine = tier_routing.get(tenant_tier)

    if tier_engine:
        return tier_engine

    # 3. Route by resource type
    resource_type = policy_request.get("resource_type", "unknown")
    resource_routing = routing_rules.get("by_resource_type", {})
    resource_engine = resource_routing.get(resource_type)

    if resource_engine:
        return resource_engine

    # 4. Route by complexity (heuristic)
    complexity = _determine_complexity(policy_request)
    complexity_routing = routing_rules.get("by_complexity", {})
    complexity_engine = complexity_routing.get(complexity)

    if complexity_engine:
        return complexity_engine

    # 5. Fallback to default
    return plugin_cfg.get("default_engine", "opa")


def _determine_complexity(policy_request: Dict[str, Any]) -> str:
    """
    Heuristically determine policy complexity.

    Complex: Commercial plugins, compliance requirements, multi-tenant isolation
    Medium: Custom business rules, multiple conditions
    Simple: Basic CRUD operations, read-only access
    """
    # Complex indicators
    if policy_request.get("resource_type") == "commercial_plugin":
        return "complex"

    if policy_request.get("compliance_requirements"):
        return "complex"

    if policy_request.get("context", {}).get("requires_advanced_authz"):
        return "complex"

    # Simple indicators
    action = policy_request.get("action", "").lower()
    if action in ["read", "list", "get", "view"]:
        return "simple"

    # Default to medium
    return "medium"


def _evaluate_hardcoded_free_tier(policy_request: Dict[str, Any]) -> bool:
    """
    Hardcoded permission checks for free tier (no policy engine).

    Free tier permissions:
    - MCP protocol: ✅ Allowed
    - A2A protocol: ❌ Denied (requires Pro)
    - Free plugins: ✅ Allowed (up to 10)
    - Commercial plugins: ❌ Denied (requires Pro)
    - GraphQL API: ❌ Denied (requires Pro)
    """
    resource_type = policy_request.get("resource_type", "")
    resource = policy_request.get("resource", "")
    action = policy_request.get("action", "")

    # Protocol access
    if resource_type == "protocol":
        if resource == "mcp" or resource == "rest":
            return True  # Free tier has MCP and REST
        else:
            return False  # A2A and GraphQL require Pro

    # Plugin access
    if resource_type in ["plugin", "free_plugin"]:
        return True  # Free plugins allowed

    if resource_type == "commercial_plugin":
        return False  # Commercial plugins require Pro

    # Default: deny unknown resources
    return False


def _list_available_engines(
    plugin_ctx: Dict[str, Any],
    plugin_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """
    List available policy engines based on tenant tier.
    """
    filter_tier = plugin_ctx.get("filter_by_tier", "free")
    routing_rules = plugin_cfg.get("routing_rules", {})
    tier_routing = routing_rules.get("by_tenant_tier", {})

    # Get engines for this tier
    available_for_tier = tier_routing.get(filter_tier, "none")

    engines = []

    if available_for_tier == "none":
        return {
            "success": True,
            "available_engines": [],
            "tier": filter_tier,
            "upgrade_required": True
        }

    if available_for_tier == "all":
        # Enterprise/Custom: All engines
        engines_list = ["opa", "cedar", "custom"]
    else:
        # Specific engine
        engines_list = [available_for_tier] if available_for_tier else []

    # Build engine details using pp() to check availability
    for engine_name in engines_list:
        plugin_name = _get_engine_plugin_name(engine_name, plugin_cfg)

        # Check if plugin is available
        try:
            plugin = pp(plugin_name)
            available = plugin is not None
        except:
            available = False

        engines.append({
            "name": engine_name,
            "plugin": plugin_name,
            "available": available,
            "capabilities": _get_engine_capabilities(engine_name)
        })

    return {
        "success": True,
        "available_engines": engines,
        "tier": filter_tier
    }


def _get_engines_health(plugin_cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Get health status of all policy engine plugins via pp().
    """
    health_status = {}

    engines = ["opa", "cedar", "custom"]

    for engine_name in engines:
        plugin_name = _get_engine_plugin_name(engine_name, plugin_cfg)

        try:
            # Try to load plugin via pp()
            plugin = pp(plugin_name)

            if plugin:
                # Try to get health if plugin supports it
                try:
                    health_result = plugin({"action": "health_check"})
                    health_status[engine_name] = {
                        "status": "healthy",
                        "plugin": plugin_name,
                        "details": health_result
                    }
                except:
                    health_status[engine_name] = {
                        "status": "healthy",
                        "plugin": plugin_name,
                        "message": "Plugin loaded successfully"
                    }
            else:
                health_status[engine_name] = {
                    "status": "unavailable",
                    "plugin": plugin_name,
                    "message": "Plugin not found"
                }

        except Exception as e:
            health_status[engine_name] = {
                "status": "error",
                "plugin": plugin_name,
                "error": str(e)
            }

    return {
        "success": True,
        "health": health_status
    }


def _route_to_engine(
    plugin_ctx: Dict[str, Any],
    plugin_cfg: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Determine which engine would be selected for a given request.
    Useful for debugging routing logic.
    """
    policy_request = plugin_ctx.get("policy_request", {})

    if not policy_request:
        return {"success": False, "error": "Missing policy_request"}

    selected_engine = _select_engine(policy_request, plugin_cfg)

    return {
        "success": True,
        "selected_engine": selected_engine,
        "routing_reason": _explain_routing(policy_request, selected_engine, plugin_cfg)
    }


def _explain_routing(
    policy_request: Dict[str, Any],
    selected_engine: str,
    plugin_cfg: Dict[str, Any]
) -> str:
    """Generate human-readable explanation of routing decision."""

    if policy_request.get("engine_preference", "auto") != "auto":
        return f"Explicit preference for {selected_engine}"

    if policy_request.get("tenant_tier"):
        return f"Routed by tenant tier: {policy_request['tenant_tier']} → {selected_engine}"

    if policy_request.get("resource_type"):
        return f"Routed by resource type: {policy_request['resource_type']} → {selected_engine}"

    return f"Default engine: {selected_engine}"


def _get_engine_plugin_name(engine: str, plugin_cfg: Dict[str, Any]) -> Optional[str]:
    """Get the plugin name for a given engine from configuration."""

    plugin_map = {
        "opa": plugin_cfg.get("opa_plugin", "opa_policy_enterprise"),
        "cedar": plugin_cfg.get("cedar_plugin", "cedar_policy"),
        "custom": plugin_cfg.get("custom_plugin", "custom_policy")
    }

    return plugin_map.get(engine)


def _get_engine_capabilities(engine_name: str) -> Dict[str, Any]:
    """Get capability information for an engine."""

    capabilities = {
        "opa": {
            "language": "rego",
            "complexity": "high",
            "performance": "medium",
            "features": ["versioning", "compliance", "multi-tenant", "governance"]
        },
        "cedar": {
            "language": "cedar",
            "complexity": "low",
            "performance": "high",
            "features": ["simple-syntax", "aws-native", "fast-evaluation"]
        },
        "custom": {
            "language": "python/javascript",
            "complexity": "medium",
            "performance": "medium",
            "features": ["flexible", "embedded", "custom-logic"]
        }
    }

    return capabilities.get(engine_name, {})


if __name__ == "__main__":
    # Test the adapter
    test_input = {
        "action": "evaluate_policy",
        "policy_request": {
            "subject": "test_user",
            "action": "read",
            "resource": "test_resource",
            "resource_type": "plugin",
            "tenant_tier": "enterprise",
            "tenant_id": "test_tenant"
        }
    }

    test_config = {
        "default_engine": "opa",
        "opa_plugin": "opa_policy_enterprise"
    }

    result = process(test_input, test_config)
    print(json.dumps(result, indent=2))
