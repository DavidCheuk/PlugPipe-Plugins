# OPA Policy Plugin for PlugPipe

This plugin integrates [Open Policy Agent (OPA)](https://www.openpolicyagent.org/) with PlugPipe's authorization framework, enabling sophisticated policy evaluation beyond basic RBAC.

## Features

- **🔗 OPA Server Integration**: Connects to local or remote OPA servers
- **🛡️ Fallback Policies**: Embedded Python policies for resilience when OPA is unavailable
- **⚡ Performance Caching**: Configurable policy result caching for improved performance
- **🎯 Constraint Generation**: Policies can impose resource constraints (memory, CPU, timeout)
- **🚨 Error Handling**: Robust fallback modes for server failures
- **📊 Risk-Based Access**: Dynamic risk scoring and time-based access control
- **✅ Compliance Ready**: Built-in support for SOC2, PCI-DSS, HIPAA compliance
- **🕒 Time-Aware Policies**: Working hours and weekend access controls

## Quick Start

### 1. Install and Start OPA Server

```bash
# Download OPA
curl -L -o opa https://openpolicyagent.org/downloads/v0.59.0/opa_linux_amd64_static
chmod +x opa

# Start OPA server
./opa run --server --log-level debug
```

### 2. Configure PlugPipe

Add to your PlugPipe authorization configuration:

```yaml
authorization:
  enable_policy_plugins: true
  policy_plugins:
    - name: opa_policy
      config:
        opa_url: "http://localhost:8181"
        policy_package: "plugpipe.authz"
        fallback_mode: "deny"
        enable_caching: true
```

### 3. Load Policies

Upload the example policy to OPA:

```bash
curl -X PUT http://localhost:8181/v1/policies/plugpipe \
  --data-binary @policies/plugpipe_authz.rego
```

## Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `opa_url` | string | `http://localhost:8181` | OPA server URL |
| `policy_package` | string | `plugpipe.authz` | OPA policy package name |
| `policy_rule` | string | `allow` | OPA policy rule to evaluate |
| `timeout` | number | `5.0` | Request timeout in seconds |
| `fallback_mode` | string | `deny` | Behavior when OPA fails (`deny`/`allow`/`basic`) |
| `enable_caching` | boolean | `true` | Enable policy result caching |
| `cache_ttl` | number | `300` | Cache time-to-live in seconds |
| `use_embedded_fallback` | boolean | `true` | Use embedded Python policies as fallback |

## Policy Examples

### Basic Allow/Deny Policy

```rego
package plugpipe.authz

import future.keywords.if

default allow := false

# Allow if basic RBAC allows
allow if {
    input.basic_decision.allow
}

# Admin override
allow if {
    "admin" in input.context.roles
}
```

### Resource Constraints Policy

```rego
package plugpipe.authz

# Generate constraints for plugin execution
constraints := {
    "memory_limit_mb": 512,
    "cpu_limit_percent": 50,
    "timeout_seconds": 30
} if {
    allow
    input.action == "execute"
    input.resource_type == "plugin"
}
```

### Time-Based Access Control

```rego
package plugpipe.authz

# Allow operations during working hours only
allow if {
    input.basic_decision.allow
    working_hours
    not weekend
}

working_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 17
}

weekend if {
    weekday := time.weekday(time.now_ns())
    weekday in [0, 6]
}
```

### Compliance Policies

```rego
package plugpipe.authz

# SOC2 compliance
allow if {
    input.basic_decision.allow
    "soc2" in input.compliance_requirements
    input.context.audit_id
    input.context.authentication_method in ["mfa", "certificate"]
}

# PCI-DSS compliance
allow if {
    input.basic_decision.allow
    "pci-dss" in input.compliance_requirements
    input.context.authentication_method == "mfa"
    input.context.network_segment == "pci_zone"
}
```

## Input Data Structure

The plugin provides the following data structure to OPA policies:

```json
{
  "input": {
    "subject": "user123",
    "action": "execute",
    "resource": "my-plugin",
    "resource_type": "plugin",
    "resource_namespace": "production",
    "context": {
      "roles": ["developer"],
      "authentication_method": "mfa",
      "audit_id": "req-123",
      "network_segment": "trusted"
    },
    "compliance_requirements": ["soc2"],
    "timestamp": 1640995200,
    "basic_decision": {
      "allow": true,
      "reason": "Basic RBAC authorization granted",
      "constraints": {},
      "metadata": {"layer": "basic_rbac"}
    }
  }
}
```

## Policy Response Format

Policies should return:

```json
{
  "allow": true,
  "constraints": {
    "memory_limit_mb": 512,
    "timeout_seconds": 30
  },
  "reason": "Policy evaluation successful",
  "metadata": {
    "policy_version": "1.0.0",
    "risk_score": 25
  }
}
```

## Fallback Modes

When OPA server is unavailable, the plugin supports multiple fallback modes:

### 1. Deny Mode (Default)
```yaml
fallback_mode: "deny"
```
Denies all requests when OPA is unavailable (most secure).

### 2. Allow Mode
```yaml
fallback_mode: "allow"
```
Allows all requests when OPA is unavailable (least secure).

### 3. Basic Mode
```yaml
fallback_mode: "basic"
```
Falls back to basic RBAC decision when OPA is unavailable (balanced).

## Embedded Fallback Policies

When `use_embedded_fallback: true`, the plugin can use Python-based policies:

```python
embedded_policies = {
    "admin_access": lambda input_data: {
        "allow": "admin" in input_data.get("context", {}).get("roles", []),
        "reason": "Admin role has full access"
    },
    
    "developer_plugins": lambda input_data: {
        "allow": (
            "developer" in input_data.get("context", {}).get("roles", []) and
            input_data.get("resource_type") == "plugin"
        ),
        "constraints": {"memory_limit_mb": 256}
    }
}
```

## Monitoring and Debugging

### Policy Validation

```bash
# Validate policy syntax
curl -X POST http://localhost:8181/v1/policies/validate \
  -d '{"policy": "package test\nallow = true"}'
```

### Query Policy Directly

```bash
# Test policy with sample input
curl -X POST http://localhost:8181/v1/data/plugpipe/authz/allow \
  -d '{
    "input": {
      "subject": "user123",
      "action": "execute",
      "resource": "test-plugin",
      "resource_type": "plugin",
      "context": {"roles": ["developer"]}
    }
  }'
```

### Enable Debug Logging

```python
import logging
logging.getLogger('plugs.opa_policy').setLevel(logging.DEBUG)
```

## Performance Considerations

- **Caching**: Enable caching for frequently evaluated policies
- **Policy Complexity**: Keep policies simple for better performance
- **Network Latency**: Consider OPA server proximity for production
- **Fallback Strategy**: Use embedded policies for critical paths

## Security Best Practices

1. **Secure OPA Server**: Use TLS and authentication for production OPA servers
2. **Policy Review**: Regularly review and audit policy changes
3. **Least Privilege**: Start with deny-by-default policies
4. **Monitoring**: Monitor policy evaluation performance and failures
5. **Fallback Security**: Choose appropriate fallback modes for your security requirements

## Troubleshooting

### Common Issues

1. **OPA Server Connection Failed**
   ```
   ERROR: OPA server evaluation failed: Connection refused
   ```
   - Check if OPA server is running
   - Verify `opa_url` configuration
   - Check network connectivity

2. **Policy Evaluation Error**
   ```
   ERROR: OPA server returned 500: policy evaluation error
   ```
   - Validate policy syntax with OPA
   - Check policy package and rule names
   - Review OPA server logs

3. **Cache Issues**
   ```
   WARNING: Using cached OPA policy result
   ```
   - Disable caching for debugging: `enable_caching: false`
   - Clear cache by restarting the plugin
   - Reduce `cache_ttl` for more frequent updates

### Debug Mode

Enable debug logging for detailed policy evaluation traces:

```yaml
logging:
  level: DEBUG
  loggers:
    - name: "plugs.opa_policy"
      level: DEBUG
```

## Integration Examples

### With PlugPipe Authorization Engine

```python
from cores.auth.authorization import PlugPipeAuthorizationEngine
from cores.auth.policy_coordinator import PolicyCoordinator

# Initialize authorization engine
auth_engine = PlugPipeAuthorizationEngine({
    'enable_policy_plugins': True
})

# Register OPA plugin
coordinator = PolicyCoordinator()
opa_plugin = OPAPolicyPlugin({
    'opa_url': 'http://localhost:8181',
    'policy_package': 'plugpipe.authz'
})
coordinator.register_policy_plugin('opa', opa_plugin)

# Set coordinator
auth_engine.set_policy_coordinator(coordinator)
```

### Custom Policy Development

Create organization-specific policies:

```rego
package myorg.policies

import future.keywords.if

# Organization-specific rules
allow if {
    input.basic_decision.allow
    valid_department
    within_budget_limits
}

valid_department if {
    input.context.department in ["engineering", "security"]
}

within_budget_limits if {
    monthly_usage := input.context.monthly_resource_usage
    budget_limit := input.context.budget_limit
    monthly_usage < budget_limit
}
```

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Support

- Documentation: [PlugPipe OPA Plugin Docs](https://plugpipe.dev/plugins/opa)
- Issues: [GitHub Issues](https://github.com/plugpipe/opa-policy-plugin/issues)
- Discussions: [PlugPipe Community](https://community.plugpipe.dev)