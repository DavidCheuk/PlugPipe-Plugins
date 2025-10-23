# Policy Engine Adapter Plugin

**Version**: 1.0.0
**Category**: Adapter
**Tier**: Enterprise

---

## Overview

The **policy_engine_adapter** plugin is a universal adapter for Policy-as-Code (PaC) engines that follows **PlugPipe spirit** perfectly:

✅ **REUSE EVERYTHING**: Uses existing `opa_policy_enterprise` plugin via `pp()`
✅ **PLUGINS ALL THE WAY DOWN**: Never evaluates policies directly, always delegates
✅ **NO CUSTOM LOGIC**: Routes to specialized policy plugins (OPA, Cedar, Custom)
✅ **CONVENTION OVER CONFIGURATION**: Smart routing based on tenant tier and complexity

---

## Architecture

```
Frontend/API
    ↓
policy_engine_adapter (this plugin)
    ↓ pp("opa_policy_enterprise")      ← REUSE existing plugin
    ↓ pp("cedar_policy")                ← Delegate to Cedar plugin
    ↓ pp("custom_policy")               ← Delegate to Custom plugin
```

**This adapter IS the abstraction layer - implemented as a plugin!**

---

## Routing Logic

### By Tenant Tier (Default)

| Tier | Engine | Reason |
|------|--------|--------|
| **Free** | `none` | Hardcoded permissions only |
| **Pro** | `cedar` | Fast, simple policies |
| **Enterprise** | `opa` | Full-featured, compliance-ready |
| **Custom** | `all` | All engines available |

### By Resource Type

| Resource Type | Engine | Reason |
|--------------|--------|--------|
| `commercial_plugin` | `opa` | Complex licensing logic |
| `sensitive_data` | `opa` | Advanced security rules |
| `compliance_resource` | `opa` | HIPAA, SOC2, etc. |
| `simple_resource` | `cedar` | Fast evaluation |

### By Complexity (Heuristic)

| Complexity | Engine | Indicators |
|-----------|--------|-----------|
| **Simple** | `cedar` | read, list, get actions |
| **Medium** | `cedar` | Standard CRUD operations |
| **Complex** | `opa` | Compliance, licensing, multi-tenant |

---

## Usage

### 1. Evaluate Policy

```python
from shares.loader import pp

# Get the adapter plugin
policy_adapter = pp("policy_engine_adapter")

# Evaluate policy for Enterprise tenant
result = policy_adapter({
    "action": "evaluate_policy",
    "policy_request": {
        "subject": "john@acme.com",
        "action": "install",
        "resource": "threat_analyzer_pro",
        "resource_type": "commercial_plugin",
        "tenant_tier": "enterprise",
        "tenant_id": "acme-corp",
        "context": {
            "environment": "production"
        }
    }
})

print(result)
# {
#   "success": True,
#   "decision": {
#     "allow": True,
#     "engine": "opa_opa_policy_enterprise",
#     "policy_name": "opa_enterprise_policy",
#     "reason": "Enterprise tier with valid license",
#     "confidence": 1.0,
#     "evaluation_time_ms": 23.5
#   }
# }
```

### 2. List Available Engines

```python
# Get engines for Pro tier
result = policy_adapter({
    "action": "list_engines",
    "filter_by_tier": "pro"
})

print(result)
# {
#   "success": True,
#   "available_engines": [
#     {
#       "name": "cedar",
#       "plugin": "cedar_policy",
#       "available": True,
#       "capabilities": {
#         "language": "cedar",
#         "complexity": "low",
#         "performance": "high"
#       }
#     }
#   ],
#   "tier": "pro"
# }
```

### 3. Check Engine Health

```python
# Get health of all policy engines
result = policy_adapter({
    "action": "get_engine_health"
})

print(result)
# {
#   "success": True,
#   "health": {
#     "opa": {
#       "status": "healthy",
#       "plugin": "opa_policy_enterprise",
#       "message": "Plugin loaded successfully"
#     },
#     "cedar": {
#       "status": "unavailable",
#       "plugin": "cedar_policy",
#       "message": "Plugin not found"
#     }
#   }
# }
```

### 4. Debug Routing

```python
# See which engine would be selected
result = policy_adapter({
    "action": "route_policy",
    "policy_request": {
        "subject": "user@example.com",
        "action": "delete",
        "resource": "production-db",
        "resource_type": "sensitive_data",
        "tenant_tier": "pro"
    }
})

print(result)
# {
#   "success": True,
#   "selected_engine": "cedar",
#   "routing_reason": "Routed by tenant tier: pro → cedar"
# }
```

---

## Free Tier Permissions

For **free tier** tenants (no policy engine), the adapter uses hardcoded checks:

| Resource Type | Access | Reason |
|--------------|--------|--------|
| MCP protocol | ✅ Allowed | Core feature |
| REST API | ✅ Allowed | Core feature |
| A2A protocol | ❌ Denied | Requires Pro |
| GraphQL API | ❌ Denied | Requires Pro |
| Free plugins | ✅ Allowed | Up to 10 plugins |
| Commercial plugins | ❌ Denied | Requires Pro |

---

## Configuration

Default configuration (from `plug.yaml`):

```yaml
config_defaults:
  default_engine: opa
  opa_plugin: opa_policy_enterprise
  cedar_plugin: cedar_policy
  custom_plugin: custom_policy
  routing_rules:
    by_tenant_tier:
      free: none
      pro: cedar
      enterprise: opa
      custom: all
    by_resource_type:
      commercial_plugin: opa
      sensitive_data: opa
      compliance_resource: opa
      simple_resource: cedar
    by_complexity:
      simple: cedar
      medium: cedar
      complex: opa
```

### Custom Routing Rules

Override routing in your config file:

```yaml
# config/policy_engine_adapter.yaml
routing_rules:
  by_tenant_tier:
    pro: opa  # Use OPA for Pro tier instead of Cedar

  by_resource_type:
    api_endpoint: custom  # Route API endpoints to custom policies

  by_complexity:
    medium: opa  # Use OPA for medium complexity instead of Cedar
```

---

## PlugPipe Principles Compliance

✅ **REUSE EVERYTHING**: Uses existing `opa_policy_enterprise` plugin via `pp()`
✅ **NEVER REINVENT**: Delegates all policy evaluation to specialized plugins
✅ **DEFAULT TO PLUGINS**: The adapter itself IS a plugin
✅ **CONVENTION OVER CONFIGURATION**: Smart defaults with override capability
✅ **GRACEFUL DEGRADATION**: Free tier works without policy engines
✅ **SIMPLICITY**: Single adapter routes to all engines

---

## Dependencies

- **opa_policy_enterprise**: Required for OPA routing
- **cedar_policy**: Required for Cedar routing (optional)
- **custom_policy**: Required for custom policies (optional)

Install via:
```bash
./pp run dependency_manager --input '{"operation": "install", "plugin": "policy_engine_adapter"}'
```

---

## Testing

```bash
# Test the adapter
python plugs/policy_engine_adapter/1.0.0/main.py

# Test with PlugPipe CLI
./pp run policy_engine_adapter --input '{
  "action": "evaluate_policy",
  "policy_request": {
    "subject": "test_user",
    "action": "read",
    "resource": "test_resource",
    "resource_type": "plugin",
    "tenant_tier": "enterprise"
  }
}'
```

---

## Integration with Frontend

Update `PolicyContext.tsx` to use this plugin:

```typescript
const evaluatePolicy = async (request: PolicyRequest): Promise<PolicyDecision> => {
  // PLUGPIPE WAY: Use pp() to call policy_engine_adapter
  const response = await fetch(`${backendUrl}/api/pp/run/policy_engine_adapter`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      action: 'evaluate_policy',
      policy_request: {
        ...request,
        tenant_tier: tenant?.subscriptionTier,
        tenant_id: tenant?.id,
      },
    }),
  })

  const result = await response.json()
  return result.decision
}
```

---

## License

MIT License - PlugPipe Enterprise Team

---

**Status**: Production Ready
**Last Updated**: 2025-10-09
