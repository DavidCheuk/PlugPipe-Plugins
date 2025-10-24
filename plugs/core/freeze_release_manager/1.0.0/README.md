# Freeze/Release Manager Plugin

Comprehensive freeze and release management for PlugPipe plugins and pipelines to maintain backward compatibility and prevent changes after release.

## Overview

The Freeze/Release Manager provides enterprise-grade version control for PlugPipe plugins and pipelines, ensuring backward compatibility and preventing unauthorized modifications to released versions.

## Features

### 🔒 Version Freezing
- **Soft Freeze**: Prevents accidental modifications while allowing authorized changes
- **Hard Freeze**: Makes versions completely read-only at the filesystem level
- **Selective Freezing**: Freeze specific versions while allowing others to remain editable
- **Freeze Tracking**: Comprehensive audit trail of who froze what and when

### 🚀 Release Management
- **Official Release Marking**: Mark versions as officially released with compatibility guarantees
- **Automatic Freeze on Release**: Auto-freeze versions when marked as released
- **Release Notes**: Attach release notes and breaking change documentation
- **Immutability Enforcement**: Ensure released versions cannot be modified

### 🔍 Compatibility Validation
- **Schema Compatibility**: Validate input/output schema compatibility between versions
- **Breaking Change Detection**: Automatically detect potential breaking changes
- **Dependency Analysis**: Analyze dependency changes and their impact
- **Compatibility Reports**: Generate detailed compatibility analysis reports

### 🛡️ Integrity Verification
- **Cryptographic Checksums**: Use SHA-256 checksums to verify version integrity
- **Tamper Detection**: Detect unauthorized modifications to frozen/released versions
- **Integrity Monitoring**: Ongoing monitoring of version integrity
- **Audit Trails**: Comprehensive logging of all freeze/release operations

### 📊 Dependency Management
- **Dependent Discovery**: Find all plugins/pipelines that depend on a specific version
- **Impact Analysis**: Understand the impact of version changes on the ecosystem
- **Dependency Tracking**: Track complex dependency chains and relationships
- **Version Mapping**: Map compatibility between different versions

## Usage

### CLI Interface

The plugin includes a comprehensive CLI tool for easy management:

```bash
# Freeze a plugin version (soft freeze)
python scripts/freeze_release_cli.py freeze --name my_plugin --version 1.0.0 --type plugin --reason "Production release"

# Hard freeze for maximum protection
python scripts/freeze_release_cli.py freeze --name my_plugin --version 1.0.0 --type plugin --level hard

# Mark version as officially released
python scripts/freeze_release_cli.py release --name my_plugin --version 1.0.0 --type plugin --notes "Initial production release"

# Check compatibility between versions
python scripts/freeze_release_cli.py check-compatibility --name my_plugin --old-version 1.0.0 --new-version 1.1.0 --type plugin

# Check freeze/release status
python scripts/freeze_release_cli.py status --name my_plugin --version 1.0.0 --type plugin

# Get list of dependents
python scripts/freeze_release_cli.py dependents --name my_plugin --version 1.0.0

# Verify version integrity
python scripts/freeze_release_cli.py verify --name my_plugin --version 1.0.0 --type plugin

# List all frozen/released versions
python scripts/freeze_release_cli.py list --filter all
```

### Programmatic Usage

```python
import importlib.util

# Load the freeze/release manager
spec = importlib.util.spec_from_file_location(
    "freeze_release_manager",
    "plugs/core/freeze_release_manager/1.0.0/main.py"
)
manager_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(manager_module)

# Use the plugin
config = {'plugs_dir': 'plugs', 'pipes_dir': 'pipes'}
manager = manager_module.FreezeReleaseManager(config)

# Freeze a version
result = manager.freeze_version(
    'my_plugin', '1.0.0', 'plugin',
    reason='Production freeze', freeze_level='hard'
)

# Mark as released
result = manager.mark_as_released(
    'my_plugin', '1.0.0', 'plugin',
    release_notes='Production release v1.0.0'
)

# Validate compatibility
result = manager.validate_compatibility(
    'my_plugin', '1.0.0', '1.1.0', 'plugin'
)
```

### Integration with PlugPipe Ecosystem

```python
# Use as a plugin within pipelines
ctx = {
    'action': 'freeze_version',
    'name': 'target_plugin',
    'version': '1.0.0',
    'type': 'plugin',
    'freeze_level': 'hard'
}

result = await process(ctx, config)
```

## Configuration

The plugin supports flexible configuration:

```yaml
# config.yaml
freeze_release_manager:
  plugs_dir: "plugs"                    # Directory containing plugins
  pipes_dir: "pipes"                    # Directory containing pipelines
  freeze_registry: "freeze_registry.json"  # Freeze registry file
  release_registry: "release_registry.json"  # Release registry file
```

## Actions

### `freeze_version`
Freeze a specific version to prevent modifications.

**Input:**
- `name`: Plugin/pipeline name
- `version`: Version to freeze
- `type`: "plugin" or "pipeline"
- `reason`: Reason for freezing (optional)
- `freeze_level`: "soft" or "hard" (default: "soft")
- `frozen_by`: Who initiated the freeze (default: "system")

**Output:**
- `success`: Operation success status
- `freeze_info`: Detailed freeze information
- `message`: Human-readable status message

### `unfreeze_version`
Remove freeze protection from a version.

**Input:**
- `name`: Plugin/pipeline name
- `version`: Version to unfreeze
- `type`: "plugin" or "pipeline"
- `reason`: Reason for unfreezing (optional)
- `unfrozen_by`: Who initiated the unfreeze (default: "system")

**Output:**
- `success`: Operation success status
- `message`: Status message

### `mark_as_released`
Mark a version as officially released with compatibility guarantees.

**Input:**
- `name`: Plugin/pipeline name
- `version`: Version to release
- `type`: "plugin" or "pipeline"
- `release_notes`: Release notes (optional)
- `breaking_changes`: List of breaking changes (optional)

**Output:**
- `success`: Operation success status
- `release_info`: Detailed release information
- `auto_frozen`: Whether version was auto-frozen
- `dependents_count`: Number of dependent components

### `validate_compatibility`
Validate backward compatibility between versions.

**Input:**
- `name`: Plugin/pipeline name
- `old_version`: Old version for comparison
- `new_version`: New version for comparison
- `type`: "plugin" or "pipeline"

**Output:**
- `success`: Operation success status
- `compatible`: Whether versions are compatible
- `has_breaking_changes`: Whether breaking changes detected
- `compatibility_issues`: List of issues found

### `check_freeze_status`
Check freeze status of versions.

**Input:**
- `name`: Plugin/pipeline name (optional)
- `version`: Version (optional)
- `type`: Component type (optional)

**Output:**
- `success`: Operation success status
- `frozen`: Whether version is frozen (for specific version)
- `frozen_versions`: All frozen versions (for general status)
- `freeze_info`: Detailed freeze information

### `check_release_status`
Check release status of versions.

**Input:**
- `name`: Plugin/pipeline name (optional)
- `version`: Version (optional)
- `type`: Component type (optional)

**Output:**
- `success`: Operation success status
- `released`: Whether version is released (for specific version)
- `released_versions`: All released versions (for general status)
- `release_info`: Detailed release information

### `get_dependents`
Get list of components that depend on a specific version.

**Input:**
- `name`: Plugin/pipeline name
- `version`: Version

**Output:**
- `success`: Operation success status
- `dependents`: List of dependent components
- `dependents_count`: Number of dependents

### `verify_integrity`
Verify integrity of a frozen/released version using checksums.

**Input:**
- `name`: Plugin/pipeline name
- `version`: Version to verify
- `type`: Component type

**Output:**
- `success`: Operation success status
- `integrity_ok`: Whether integrity check passed
- `expected_checksum`: Expected checksum
- `current_checksum`: Current calculated checksum

### `status`
Get overall system status.

**Output:**
- `success`: Operation success status
- `total_frozen_versions`: Number of frozen versions
- `total_released_versions`: Number of released versions
- `available_actions`: List of available actions

## Freeze Levels

### Soft Freeze
- Prevents accidental modifications
- Allows authorized changes with proper unfreezing
- Registry-based protection
- Suitable for development/testing environments

### Hard Freeze
- Makes files/directories read-only at filesystem level
- Maximum protection against modifications
- Requires unfreezing before any changes
- Recommended for production releases

## Best Practices

### 1. Version Release Workflow
```bash
# 1. Validate compatibility with previous versions
python scripts/freeze_release_cli.py check-compatibility --name my_plugin --old-version 1.0.0 --new-version 1.1.0 --type plugin

# 2. Check for dependents
python scripts/freeze_release_cli.py dependents --name my_plugin --version 1.0.0

# 3. Mark as released (auto-freezes with hard freeze)
python scripts/freeze_release_cli.py release --name my_plugin --version 1.1.0 --type plugin --notes "Feature release with new capabilities"

# 4. Verify integrity
python scripts/freeze_release_cli.py verify --name my_plugin --version 1.1.0 --type plugin
```

### 2. Development Protection
```bash
# Soft freeze development versions for stability
python scripts/freeze_release_cli.py freeze --name dev_plugin --version 0.9.0 --type plugin --level soft --reason "Beta testing"

# Unfreeze when updates needed
python scripts/freeze_release_cli.py unfreeze --name dev_plugin --version 0.9.0 --type plugin --reason "Bug fixes required"
```

### 3. Production Safety
```bash
# Always use hard freeze for production releases
python scripts/freeze_release_cli.py release --name prod_plugin --version 2.0.0 --type plugin --notes "Production release"

# Regular integrity verification
python scripts/freeze_release_cli.py verify --name prod_plugin --version 2.0.0 --type plugin
```

## Error Handling

The plugin provides comprehensive error handling:

- **Version Not Found**: Clear error when attempting to freeze non-existent versions
- **Already Frozen/Released**: Informative messages for duplicate operations
- **Integrity Violations**: Detailed checksums for integrity failures
- **Permission Errors**: Helpful messages for filesystem permission issues
- **Dependency Conflicts**: Clear reporting of compatibility issues

## Security Features

- **Cryptographic Checksums**: SHA-256 checksums for tamper detection
- **Access Control Tracking**: Records who performs freeze/release operations
- **Audit Trails**: Comprehensive logging of all operations
- **Filesystem Protection**: Read-only enforcement for hard freezes
- **Registry Protection**: Secure storage of freeze/release metadata

## Performance

- **Fast Operations**: Most operations complete in seconds
- **Efficient Checksums**: Optimized directory hashing
- **Minimal Storage**: Compact registry storage
- **Scalable**: Handles large numbers of plugins/pipelines

## Enterprise Features

- **Approval Workflows**: Can be extended with approval processes
- **Compliance Reporting**: Generate compliance reports for audits
- **CI/CD Integration**: Integrate with automated build/release pipelines
- **Multi-Environment**: Support for different freeze policies per environment

## Integration Examples

### Change Management Integration
```python
# Integrate with change management for automated freeze
change_result = await change_manager.process({
    'action': 'execute_change',
    'change_id': 'CHANGE-123'
})

if change_result['success']:
    # Auto-freeze after successful change
    await freeze_manager.process({
        'action': 'freeze_version',
        'name': 'updated_plugin',
        'version': '1.2.0',
        'type': 'plugin',
        'reason': f"Auto-freeze after change {change_result['change_id']}"
    })
```

### CI/CD Pipeline Integration
```bash
# In CI/CD pipeline
if [ "$ENVIRONMENT" == "production" ]; then
    python scripts/freeze_release_cli.py release \
        --name $PLUGIN_NAME \
        --version $VERSION \
        --type plugin \
        --notes "Production release from CI/CD pipeline"
fi
```

### Dependency Validation
```python
# Before updating a dependency
dependents_result = await freeze_manager.process({
    'action': 'get_dependents',
    'name': 'base_plugin',
    'version': '1.0.0'
})

if dependents_result['dependents_count'] > 0:
    print(f"Warning: {dependents_result['dependents_count']} components depend on this version")
    # Validate compatibility with dependents
```

## Architecture

The Freeze/Release Manager follows PlugPipe's core principles:

- **Plugin-First Design**: Implemented as a reusable PlugPipe plugin
- **Composable**: Can be composed with other plugins for complex workflows
- **Standardized Interface**: Follows PlugPipe's process function contract
- **Secure by Default**: Built-in security features and audit trails
- **Enterprise-Ready**: Designed for production enterprise environments

## Troubleshooting

### Common Issues

1. **Permission Denied on Hard Freeze**
   ```bash
   # Solution: Run with appropriate permissions or unfreeze first
   python scripts/freeze_release_cli.py unfreeze --name my_plugin --version 1.0.0 --type plugin
   ```

2. **Integrity Check Failures**
   ```bash
   # Investigate what changed
   python scripts/freeze_release_cli.py verify --name my_plugin --version 1.0.0 --type plugin --json
   ```

3. **Registry Corruption**
   ```bash
   # Backup and recreate registries if needed
   cp freeze_registry.json freeze_registry.json.backup
   # Remove corrupted registry and re-freeze versions
   ```

## Contributing

When extending the Freeze/Release Manager:

1. Add new actions to the `process` method
2. Update input/output schemas in `plug.yaml`
3. Add comprehensive tests for new functionality
4. Update CLI tool for new actions
5. Document new features in this README

## License

This plugin is part of the PlugPipe core system and follows the PlugPipe licensing terms.