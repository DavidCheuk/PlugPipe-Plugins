# Rollback Manager Plugin

The Rollback Manager is a dedicated plugin for comprehensive rollback operations across enterprise systems. It provides multi-layer rollback capabilities including Git, configuration, filesystem, and database rollback with verification and audit trails.

## Overview

This plugin implements the "single responsibility" principle by focusing solely on rollback operations. It's designed to be composed by other plugins (like Enterprise Change Manager) following CLAUDE.md principles of plugin composition.

## Key Features

- **Multi-Type Rollback**: Git, configuration, filesystem, database rollback support
- **Snapshot Management**: Create and manage rollback snapshots
- **Rollback Verification**: Post-rollback validation and testing
- **Audit Trails**: Comprehensive logging of all rollback operations  
- **Policy Integration**: Can be driven by policy plugins for rollback decisions
- **Metadata Persistence**: Snapshot metadata stored for compliance
- **Parallel Operations**: Concurrent rollback operations when safe

## Architecture

```
Rollback Manager
├── SnapshotManager
│   ├── Git Snapshot Creation
│   ├── Configuration Backup
│   ├── Filesystem Snapshot
│   └── Database Backup
└── RollbackExecutor
    ├── Rollback Execution
    ├── Verification Testing
    └── History Tracking
```

## Supported Rollback Types

| Type | Description | Use Case |
|------|-------------|----------|
| `git_commit` | Git-based rollback to specific commit | Source code, configuration files |
| `configuration` | Configuration file restoration | Application settings, system configs |
| `file_system` | File system backup and restore | File-based applications |
| `database` | Database backup and restore | Data rollbacks |
| `container` | Container image rollback | Container deployments |
| `infrastructure` | Infrastructure state rollback | IaC deployments |

## Usage

### Creating a Snapshot

```python
config = {
    "action": "create_snapshot",
    "snapshot_id": "deployment_v1.2.3",
    "type": "git_commit",
    "config": {
        "repo_path": "/app/source",
        "config_files": ["/etc/app/config.yml"]
    }
}

result = plugin.process({}, config)
```

### Executing Rollback

```python
config = {
    "action": "execute_rollback", 
    "snapshot_id": "deployment_v1.2.3",
    "validation": {
        "tests": [
            {"type": "git_commit", "expected_commit": "abc123"},
            {"type": "file_exists", "path": "/app/config.yml"},
            {"type": "service_status", "services": ["app", "database"]}
        ]
    }
}

result = plugin.process({}, config)
```

## Supported Actions

| Action | Description | Required Parameters |
|--------|-------------|-------------------|
| `create_snapshot` | Create rollback snapshot | `snapshot_id`, `type`, `config` |
| `execute_rollback` | Execute rollback operation | `snapshot_id` |
| `list_snapshots` | List all available snapshots | None |
| `get_rollback_history` | Get rollback operation history | None |
| `status` | Get plugin status and capabilities | None |

## Snapshot Configuration

### Git Commit Snapshot

```yaml
config:
  repo_path: "/path/to/repository"  # Git repository path
  branch: "main"                    # Optional: specific branch
```

### Configuration File Snapshot

```yaml
config:
  config_files:                     # List of configuration files
    - "/etc/app/config.yml"
    - "/opt/service/settings.conf"
  backup_location: "/backups/configs"  # Optional backup location
```

### Filesystem Snapshot

```yaml
config:
  paths:                            # Paths to backup
    - "/var/lib/app/data"
    - "/opt/app/uploads"
  backup_location: "/backups/fs"    # Backup storage location
```

### Database Snapshot

```yaml
config:
  database_name: "production_db"    # Database to backup
  connection_string: "postgresql://user:pass@host/db"
  backup_file: "/backups/db_snapshot.sql"
```

## Rollback Verification

Post-rollback verification ensures rollback success:

```yaml
validation:
  tests:
    - type: "file_exists"           # Check file exists
      path: "/app/config.yml"
    
    - type: "git_commit"            # Verify git commit
      expected_commit: "abc123def"
    
    - type: "service_status"        # Check service status
      services: ["nginx", "postgres"]
    
    - type: "health_check"          # HTTP health check
      url: "http://localhost:8080/health"
      expected_status: 200
```

## Output Schema

### Snapshot Creation Response

```yaml
status: "success" | "failed"
snapshot_id: "unique_snapshot_identifier"
type: "git_commit" | "configuration" | "file_system" | "database"
metadata:
  method: "git_commit" | "configuration_files" | "filesystem_backup"
  commit_hash: "abc123def"          # For git snapshots
  files: {"/path/file": "content"}  # For config snapshots
  backup_location: "/backup/path"   # For filesystem snapshots
  created_at: 1729123456
```

### Rollback Execution Response

```yaml
status: "completed" | "failed" | "partial"
rollback_id: "unique_rollback_identifier"
snapshot_id: "source_snapshot_id"
started_at: 1729123456
completed_at: 1729123460
duration: 4                         # seconds
technical_details:
  - action: "rollback_execution"
    method: "git_reset"
    result: {status: "success"}
    timestamp: 1729123457
  - action: "rollback_verification" 
    result: {passed: 2, total: 2}
    timestamp: 1729123459
execution_result:
  status: "success"
  method: "git_reset"
  commit_hash: "abc123def"
verification_results:
  status: "success"
  passed: 2
  total: 2
  results:
    - test: "git_commit"
      expected: "abc123def"
      actual: "abc123def"
      passed: true
    - test: "file_exists"
      path: "/app/config.yml"
      passed: true
```

## Snapshot Metadata Persistence

All snapshots are persisted with comprehensive metadata:

```json
{
  "id": "deployment_v1.2.3",
  "type": "git_commit",
  "created_at": 1729123456,
  "config": {
    "repo_path": "/app/source"
  },
  "status": "created",
  "metadata": {
    "method": "git_commit",
    "commit_hash": "abc123def456",
    "repo_path": "/app/source",
    "branch": "main"
  }
}
```

Metadata files are stored in `pipe_runs/rollback_snapshots/{snapshot_id}_metadata.json`.

## Rollback History Tracking

All rollback operations are tracked with complete audit trails:

```json
{
  "rollback_id": "rollback_1729123456",
  "snapshot_id": "deployment_v1.2.3", 
  "status": "completed",
  "started_at": 1729123456,
  "completed_at": 1729123460,
  "duration": 4,
  "technical_details": [
    {
      "action": "rollback_execution",
      "method": "git_reset",
      "result": {"status": "success", "commit_hash": "abc123"},
      "timestamp": 1729123457
    }
  ],
  "verification_results": {
    "status": "success",
    "passed": 2,
    "total": 2
  }
}
```

## Integration with Other Plugins

### Usage by Enterprise Change Manager

```python
# Create snapshot before change
snapshot_result = rollback_manager.process({}, {
    "action": "create_snapshot",
    "snapshot_id": f"change_{change_id}_snapshot",
    "type": "git_commit",
    "config": {"repo_path": "."}
})

# Execute rollback on failure
if change_failed:
    rollback_result = rollback_manager.process({}, {
        "action": "execute_rollback",
        "snapshot_id": f"change_{change_id}_snapshot",
        "validation": validation_config
    })
```

### Policy-Driven Rollback

```python
# Policy plugin determines rollback necessity
policy_decision = policy_plugin.evaluate_rollback_policy(failure_context)

if policy_decision["status"] == "automatic_rollback_required":
    rollback_config = {
        "action": "execute_rollback",
        "snapshot_id": snapshot_id,
        "validation": {"tests": policy_decision.get("validation_tests", [])}
    }
    rollback_result = rollback_manager.process({}, rollback_config)
```

## Git Rollback Implementation

The plugin uses Git commands for version control rollback:

```python
# Create git snapshot
result = subprocess.run(['git', 'rev-parse', 'HEAD'], capture_output=True)
commit_hash = result.stdout.strip()

# Execute git rollback  
result = subprocess.run(['git', 'reset', '--hard', commit_hash], capture_output=True)
```

## Configuration Rollback Implementation

Configuration files are backed up and restored:

```python
# Backup configuration
with open(config_file, 'r') as f:
    backup_content = f.read()

# Restore configuration
with open(config_file, 'w') as f:
    f.write(backup_content)
```

## Security Considerations

- **Path Validation**: All file paths validated to prevent traversal attacks
- **Permission Checks**: Rollback operations respect file permissions
- **Audit Logging**: All operations logged for security audit
- **Input Sanitization**: All inputs validated and sanitized
- **Least Privilege**: Operations use minimal required permissions

## Performance Features

- **Concurrent Operations**: Multiple snapshots can be created in parallel
- **Incremental Backups**: Only changed files backed up when possible
- **Compression**: Large backups compressed to save space
- **Streaming**: Large file operations streamed to manage memory
- **Timeout Handling**: All operations have configurable timeouts

## Error Handling

The plugin handles various error scenarios gracefully:

```python
# Git repository not found
if not os.path.exists(os.path.join(repo_path, '.git')):
    return {"status": "failed", "error": "Not a git repository"}

# File permission errors
try:
    with open(config_file, 'r') as f:
        content = f.read()
except PermissionError:
    return {"status": "failed", "error": "Permission denied"}

# Disk space issues
if not enough_disk_space(backup_size):
    return {"status": "failed", "error": "Insufficient disk space"}
```

## Monitoring and Alerting

The plugin provides metrics for monitoring:

- **Snapshot Creation Rate**: Number of snapshots created per hour
- **Rollback Success Rate**: Percentage of successful rollbacks
- **Rollback Duration**: Time taken for rollback operations
- **Verification Pass Rate**: Percentage of verifications that pass
- **Storage Usage**: Disk space used for snapshots

## CLI Usage

The plugin includes a CLI interface for direct usage:

```bash
# Create snapshot
python main.py --action create --snapshot-id "release_v2.1" --type git_commit

# Execute rollback
python main.py --action rollback --snapshot-id "release_v2.1"

# List snapshots
python main.py --action list

# Get rollback history
python main.py --action history

# Check status
python main.py --action status
```

## Testing

Comprehensive test suite covers all functionality:

```bash
# Run all tests
pytest tests/test_rollback_manager.py -v

# Run specific test categories
pytest tests/test_rollback_manager.py::TestSnapshotManager -v
pytest tests/test_rollback_manager.py::TestRollbackExecutor -v
pytest tests/test_rollback_manager.py::TestPluginIntegration -v

# Run integration tests
pytest tests/test_rollback_manager.py -m integration

# Run security tests  
pytest tests/test_rollback_manager.py -m security

# Run performance tests
pytest tests/test_rollback_manager.py -m performance
```

## Best Practices

1. **Always Create Snapshots**: Create snapshots before any significant change
2. **Verify After Rollback**: Always include verification tests
3. **Monitor Disk Usage**: Regular cleanup of old snapshots
4. **Test Rollback Procedures**: Regularly test rollback operations
5. **Document Rollback Plans**: Include rollback info in change requests
6. **Automate Where Possible**: Use policy plugins for rollback decisions

## Troubleshooting

### Common Issues

1. **Git Rollback Fails**
   ```bash
   # Check git repository status
   git status
   # Check for uncommitted changes
   git diff --name-only
   ```

2. **Configuration Rollback Permission Denied**
   ```bash
   # Check file permissions
   ls -la /etc/app/config.yml
   # Ensure proper user ownership
   ```

3. **Snapshot Storage Full**
   ```bash
   # Check disk usage
   df -h pipe_runs/rollback_snapshots/
   # Clean up old snapshots
   ```

### Debug Mode

Enable debug logging for detailed troubleshooting:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Examples

See the test suite in `tests/test_rollback_manager.py` for comprehensive examples of all plugin functionality.

## Dependencies

- **Core**: Python 3.8+, PlugPipe framework
- **System**: Git (for git rollback), sufficient disk space
- **Optional**: Database clients for database rollback

## License

Part of PlugPipe framework. See main project license.