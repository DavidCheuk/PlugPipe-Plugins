# Enterprise Change Manager Plugin

The Enterprise Change Manager is a comprehensive policy-driven change orchestration plugin that enables enterprise-grade change management through composition of existing PlugPipe plugins.

## Overview

This plugin orchestrates complex enterprise changes by integrating with multiple existing plugins including Salt (configuration management), ELK Stack (audit logging), Prometheus (monitoring), OPA Policy (governance), and the dedicated Rollback Manager plugin.

## Key Features

- **Policy-Driven Approvals**: All changes are approved through OPA policy plugin evaluation
- **Risk Assessment**: Automatic risk level calculation based on scope and impact
- **Comprehensive Audit**: Complete audit trails through ELK Stack integration
- **Real-time Monitoring**: Change impact monitoring via Prometheus
- **Automatic Rollback**: Policy-based rollback using dedicated Rollback Manager plugin
- **Compliance Integration**: Enterprise compliance framework support (SOX, GDPR, ISO27001)
- **Agent Factory Integration**: Dynamic agent creation for specialized change tasks

## Architecture

The plugin follows CLAUDE.md principles of "plugs compose other plugs" and "reuse everything, reinvent nothing":

```
Enterprise Change Manager
├── PolicyManager (OPA Policy Integration)
├── ExistingPluginComposer
│   ├── Salt Plugin (Configuration Management)
│   ├── ELK Stack Plugin (Audit Logging)
│   ├── Prometheus Plugin (Monitoring)
│   └── Rollback Manager Plugin (Rollback Operations)
└── Agent Factory (Dynamic Agent Creation)
```

## Usage

### Planning a Change

```python
config = {
    "action": "plan_change",
    "change_request": {
        "type": "configuration",
        "description": "Update database connection settings",
        "targets": ["prod-db-01", "prod-db-02"],
        "requester": "devops_team",
        "environment": "production",
        "compliance": ["SOX", "GDPR"]
    }
}

result = plugin.process({}, config)
```

### Executing a Change

```python
config = {
    "action": "execute_change",
    "change_id": "change_1729123456"
}

result = plugin.process({}, config)
```

## Supported Actions

| Action | Description | Required Parameters |
|--------|-------------|-------------------|
| `plan_change` | Plan and approve a change | `change_request` |
| `execute_change` | Execute a planned change | `change_id` |
| `list_changes` | List all active changes | None |
| `get_change_status` | Get status of specific change | `change_id` |
| `status` | Get plugin status and capabilities | None |

## Change Request Schema

```yaml
change_request:
  type: "configuration" | "application_deployment" | "security_patch" | "infrastructure" | "emergency_fix" | "compliance_update"
  description: "Human-readable description"
  targets: ["server-01", "server-02"]  # Target systems
  requester: "user_or_team_name"
  environment: "production" | "staging" | "development"
  compliance: ["SOX", "GDPR", "HIPAA"]  # Compliance frameworks
  configuration: {}  # Configuration data
  rollback_plan: {}  # Rollback configuration
```

## Output Schema

```yaml
# Planning Response
status: "success" | "error"
change_id: "unique_change_identifier"
risk_level: "low" | "medium" | "high"
approval_status: "approved" | "rejected" | "pending"
policy_conditions: ["automated_rollback_required", "post_change_validation"]
audit_requirements: ["pre_change_approval", "detailed_logging"]

# Execution Response
status: "success" | "error"
change_id: "unique_change_identifier"
steps_completed: [{target: "server", result: {}, timestamp: 1234567890}]
technical_details: [{action: "action_name", details: {}, method: "plugin_name", timestamp: 1234567890}]
monitoring_data: {metrics: {}}
rollback_info: {executed: false, successful: null}
```

## Policy Integration

The plugin integrates with OPA policy plugins for governance:

### Change Approval Policies

Policies evaluate:
- **Requester authorization**: Can this user/team make this change?
- **Environment protection**: Production changes require higher approval
- **Risk assessment**: High-risk changes need additional approval
- **Compliance requirements**: SOX/GDPR changes need compliance approval

### Rollback Policies

Policies determine:
- **Automatic rollback triggers**: When to automatically rollback
- **Rollback methods**: Git, configuration, infrastructure rollback
- **Validation requirements**: Post-rollback verification needed

## Risk Assessment

Risk levels are calculated based on:

| Factor | Impact |
|--------|--------|
| Number of targets > 10 | +1 risk |
| Emergency fix type | +2 risk |
| No rollback plan | +1 risk |
| Production environment | +1 risk |

Risk calculation:
- **0 factors**: Low risk
- **1-2 factors**: Medium risk
- **3+ factors**: High risk

## Compliance Support

Supported compliance frameworks:
- **SOX**: Sarbanes-Oxley financial compliance
- **GDPR**: General Data Protection Regulation
- **HIPAA**: Health Insurance Portability and Accountability Act
- **ISO27001**: Information security management
- **PCI-DSS**: Payment Card Industry Data Security Standard

## Integration with Existing Plugins

### Salt Plugin Integration
```python
# Configuration change execution
salt_config = {
    "target": "server-01",
    "state": "highstate",
    "pillar_data": configuration,
    "test": dry_run_mode
}
result = salt_plugin.process({}, salt_config)
```

### ELK Stack Integration
```python
# Audit event logging
audit_event = {
    "action": "log_event",
    "index": "change_management",
    "document": {
        "event_type": "change_executed",
        "change_id": change_id,
        "details": execution_details
    }
}
result = elk_plugin.process({}, audit_event)
```

### Prometheus Integration
```python
# System monitoring
monitoring_config = {
    "action": "query_metrics",
    "metrics": ["cpu_usage", "memory_usage", "error_rate"],
    "time_range": "5m"
}
result = prometheus_plugin.process({}, monitoring_config)
```

### Rollback Manager Integration
```python
# Rollback execution
rollback_config = {
    "action": "execute_rollback",
    "snapshot_id": f"change_{change_id}_snapshot",
    "validation": validation_tests
}
result = rollback_plugin.process({}, rollback_config)
```

## Technical Details for Audit

All operations include comprehensive technical details for audit compliance:

```json
{
  "technical_details": [
    {
      "action": "target_configuration",
      "target": "server-01",
      "details": {"salt_state": "applied", "changes": 5},
      "method": "salt_plugin",
      "timestamp": 1729123456
    },
    {
      "action": "impact_monitoring",
      "details": {"cpu_usage": "normal", "error_rate": "low"},
      "method": "prometheus_plugin", 
      "timestamp": 1729123457
    }
  ]
}
```

## Error Handling and Fallbacks

The plugin provides graceful fallbacks when dependent plugins are unavailable:

- **Salt Plugin Missing**: Uses mock configuration management
- **ELK Stack Missing**: Falls back to Python logging
- **Prometheus Missing**: Uses mock monitoring
- **Policy Plugins Missing**: Uses mock approval with safe defaults

## Performance Considerations

- **Parallel Execution**: Changes to multiple targets executed in parallel
- **Async Operations**: Non-blocking policy evaluation and monitoring
- **Caching**: Policy decisions cached for similar requests
- **Timeout Handling**: All external plugin calls have timeouts

## Security Features

- **Policy-based Access Control**: All actions subject to policy evaluation
- **Audit Trails**: Complete audit logs of all operations
- **Rollback Capability**: Automatic rollback on security failures
- **Input Validation**: All inputs validated against schemas
- **Privilege Separation**: No direct system access, only through plugins

## Troubleshooting

### Common Issues

1. **Policy Evaluation Fails**
   - Verify OPA policy plugins are available
   - Check policy definitions are correct
   - Review requester permissions

2. **Change Execution Fails**
   - Check target system availability
   - Verify Salt plugin configuration
   - Review configuration syntax

3. **Rollback Not Working**
   - Ensure Rollback Manager plugin is available
   - Check snapshot was created successfully
   - Verify rollback permissions

### Debug Mode

Enable debug logging for detailed troubleshooting:

```python
import logging
logging.getLogger().setLevel(logging.DEBUG)
```

## Examples

See the test suite in `tests/test_enterprise_change_manager.py` for comprehensive examples of all plugin functionality.

## Dependencies

- **Core**: Python 3.8+, PlugPipe framework
- **Plugins**: Salt, ELK Stack, Prometheus, OPA Policy, Rollback Manager
- **Optional**: Agent Factory for specialized agents

## License

Part of PlugPipe framework. See main project license.