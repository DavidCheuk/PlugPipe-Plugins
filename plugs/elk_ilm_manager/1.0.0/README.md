# elk_ilm_manager Plugin

**Status**: ⏳ PLANNED - Specification Complete, Implementation Pending

## Purpose

Programmatic Index Lifecycle Management (ILM) for Elasticsearch indices in PlugPipe. Enables automated retention policies, rollover management, and lifecycle optimization for audit and security indices.

## Why This Plugin Exists

Following PlugPipe's "one plugin, one job" philosophy, this plugin handles **ILM operations only**. It was separated from `audit_elk_stack` to maintain focused responsibilities:

- `audit_elk_stack` → Event logging and searching
- `elk_ilm_manager` → Index lifecycle management (THIS PLUGIN)
- `elk_logstash_manager` → Pipeline configuration
- `elk_kibana_manager` → Dashboard and visualization

## Operations

### create_policy
Create new ILM policy with hot/warm/delete phases.

**Example**:
```bash
./pp run elk_ilm_manager --operation create_policy \
  --input '{
    "policy_config": {
      "policy_name": "plugpipe-security-180d",
      "hot_phase": {"rollover_max_age": "1d", "rollover_max_size": "50gb"},
      "warm_phase": {"min_age": "7d"},
      "delete_phase": {"min_age": "180d"}
    }
  }'
```

### apply_policy
Apply ILM policy to index pattern.

**Example**:
```bash
./pp run elk_ilm_manager --operation apply_policy \
  --input '{
    "apply_config": {
      "index_pattern": "plugpipe-security-*",
      "policy_name": "plugpipe-security-180d",
      "rollover_alias": "plugpipe-security"
    }
  }'
```

### get_policy_status
Check ILM policy execution status for indices.

**Example**:
```bash
./pp run elk_ilm_manager --operation get_policy_status \
  --input '{"apply_config": {"index_pattern": "plugpipe-audit-*"}}'
```

### force_rollover
Manually trigger index rollover.

**Example**:
```bash
./pp run elk_ilm_manager --operation force_rollover \
  --input '{"rollover_config": {"alias_name": "plugpipe-audit"}}'
```

### update_retention
Update retention period for existing policy.

**Example**:
```bash
./pp run elk_ilm_manager --operation update_retention \
  --input '{
    "retention_update": {
      "policy_name": "plugpipe-audit-policy",
      "delete_after": "180d"
    }
  }'
```

## Use Cases

### 1. Different Retention for Different Event Types

```bash
# Security events: 180 days
./pp run elk_ilm_manager --operation create_policy \
  --input '{"policy_config": {"policy_name": "security-180d", "delete_phase": {"min_age": "180d"}}}'

# Audit events: 90 days
./pp run elk_ilm_manager --operation create_policy \
  --input '{"policy_config": {"policy_name": "audit-90d", "delete_phase": {"min_age": "90d"}}}'

# Metrics: 30 days
./pp run elk_ilm_manager --operation create_policy \
  --input '{"policy_config": {"policy_name": "metrics-30d", "delete_phase": {"min_age": "30d"}}}'
```

### 2. Storage Optimization

```bash
# Move old data to warm tier for cost savings
./pp run elk_ilm_manager --operation create_policy \
  --input '{
    "policy_config": {
      "policy_name": "cost-optimized",
      "hot_phase": {"rollover_max_age": "1d"},
      "warm_phase": {
        "min_age": "7d",
        "shrink_shards": 1,
        "force_merge_segments": 1
      },
      "delete_phase": {"min_age": "90d"}
    }
  }'
```

### 3. Emergency Rollover

```bash
# Force rollover when index is too large
./pp run elk_ilm_manager --operation force_rollover \
  --input '{"rollover_config": {"alias_name": "plugpipe-audit"}}'
```

## Configuration

**Environment Variables**:
```bash
ELASTICSEARCH_URL=http://localhost:9200
ELK_USERNAME=elastic
ELK_PASSWORD=your_password
```

**Config File** (`config.json`):
```json
{
  "elasticsearch_url": "http://localhost:9200",
  "username": "elastic",
  "password": "your_password",
  "verify_ssl": true,
  "timeout": 30
}
```

## Implementation Status

**Phase**: 📋 Specification Complete

**Roadmap**:
- ✅ Plugin specification (plug.yaml)
- ✅ Documentation (README.md)
- ⏳ Implementation (main.py) - PENDING
- ⏳ Tests - PENDING
- ⏳ Integration with ./pp CLI - PENDING

See: [ELK Plugin Development Roadmap](../../../docs/claude_guidance/development/elk_plugin_development_roadmap.md)

## Dependencies

- `elasticsearch>=8.0.0` - Elasticsearch Python client
- `requests>=2.25.0` - HTTP client for API calls

## Related Plugins

- `audit_elk_stack` - Event logging and searching
- `elk_logstash_manager` - Logstash pipeline management
- `elk_kibana_manager` - Kibana dashboard management

## Notes

This plugin follows PlugPipe's infrastructure management principles:
- **Manual First**: Use scripts for initial setup
- **Plugin for Automation**: Use plugin for repetitive operations
- **Composable**: Works with other ELK plugins
- **Focused**: ILM operations only, nothing more

**When to use this plugin vs. manual management**:
- ✅ Plugin: Programmatic policy creation based on plugin metadata
- ✅ Plugin: Runtime policy updates
- ✅ Plugin: Automated policy application across many indices
- ❌ Manual: Initial ELK Stack setup
- ❌ Manual: One-time configuration changes
