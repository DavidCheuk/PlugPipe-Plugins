# Plugin Change Hooks System

Auto-triggering hook system for plugin change validation that monitors plugin directory changes and automatically triggers the validation pipeline with issue tracking integration.

## Overview

The Plugin Change Hooks system provides automated validation triggering for PlugPipe plugins through:
- **Filesystem Monitoring**: Real-time watching of plugin directories for changes
- **Git Hooks Integration**: Pre-commit, post-commit, and pre-push validation
- **Automatic Pipeline Triggering**: Seamless integration with validation pipeline and issue tracker
- **Configurable Debouncing**: Smart change aggregation to avoid excessive validation runs
- **Background Execution**: Asynchronous validation that doesn't block development workflow

## Key Features

### 🔍 **Filesystem Monitoring**
- Real-time monitoring of plugin directories using the Watchdog library
- Configurable file patterns and ignore lists
- Debounced change detection to group related modifications
- Automatic plugin name extraction from file paths

### 🎣 **Git Hooks Integration** 
- Automatic installation of pre-commit, post-commit, and pre-push hooks
- Customizable hook scripts with template support
- Configurable failure handling (block commits or warn only)
- Repository-aware hook installation and management

### 🚀 **Validation Orchestration**
- Seamless integration with Plugin Change Validation Pipeline
- Automatic issue storage through Issue Tracker plugin
- Configurable validation scope (single plugin, affected plugins, full validation)
- Background async execution with timeout management

### ⚙️ **Smart Configuration**
- Multiple monitoring strategies (filesystem, git, manual)
- Development vs production configurations
- Enterprise-grade settings with comprehensive coverage
- Container and CI/CD friendly options

## Installation & Setup

### 1. Basic Monitoring
Start filesystem and git hook monitoring:

```bash
./pp run plugin_change_hooks --input '{
  "operation": "start_monitoring",
  "monitoring_config": {
    "watch_paths": ["plugs"],
    "enable_git_hooks": true,
    "enable_filesystem_watch": true
  }
}'
```

### 2. Development Setup
Lightweight configuration for development:

```bash
./pp run plugin_change_hooks --input '{
  "operation": "start_monitoring", 
  "monitoring_config": {
    "debounce_seconds": 2,
    "validation_on_startup": false
  },
  "validation_config": {
    "validation_scope": "changed_plugin_only",
    "async_validation": true
  }
}'
```

### 3. Git Hooks Only
Install only git hooks without filesystem monitoring:

```bash
./pp run plugin_change_hooks --input '{
  "operation": "setup_git_hooks",
  "git_hooks_config": {
    "install_pre_commit": true,
    "install_pre_push": true,
    "fail_on_validation_error": false
  }
}'
```

## Configuration Options

### Monitoring Configuration
```yaml
monitoring_config:
  watch_paths: ["plugs", "cores"]           # Paths to monitor
  watch_patterns: ["*.py", "*.yaml"]       # File patterns to watch
  ignore_patterns: ["__pycache__", "*.pyc"] # Patterns to ignore
  debounce_seconds: 5                       # Debounce delay
  enable_git_hooks: true                    # Enable git integration
  enable_filesystem_watch: true            # Enable filesystem monitoring
  validation_on_startup: false             # Run validation on startup
```

### Validation Configuration
```yaml
validation_config:
  trigger_validation_pipeline: true        # Trigger validation pipeline
  trigger_issue_tracker: true             # Store results in issue tracker
  validation_scope: "changed_plugin_only"  # Validation scope
  async_validation: true                   # Run validation asynchronously
  validation_timeout: 300                  # Maximum validation time
```

### Git Hooks Configuration
```yaml
git_hooks_config:
  install_pre_commit: true                 # Install pre-commit hook
  install_post_commit: false              # Install post-commit hook
  install_pre_push: true                  # Install pre-push hook
  fail_on_validation_error: false         # Fail git operations on errors
  hook_script_template: "custom script"   # Custom hook script template
```

## Operations

### Start Monitoring
```bash
./pp run plugin_change_hooks --input '{"operation": "start_monitoring"}'
```

### Stop Monitoring  
```bash
./pp run plugin_change_hooks --input '{"operation": "stop_monitoring"}'
```

### Get Status
```bash
./pp run plugin_change_hooks --input '{"operation": "get_status"}'
```

### Manual Validation Trigger
```bash
./pp run plugin_change_hooks --input '{
  "operation": "trigger_validation",
  "trigger_options": {
    "target_plugin": "my_plugin",
    "change_type": "modified",
    "force_validation": true
  }
}'
```

### Setup Git Hooks Only
```bash
./pp run plugin_change_hooks --input '{"operation": "setup_git_hooks"}'
```

### Setup Filesystem Watch Only
```bash
./pp run plugin_change_hooks --input '{"operation": "setup_filesystem_watch"}'
```

## Usage Scenarios

### Development Workflow
1. **Start monitoring** when beginning development session
2. **Edit plugin files** - changes are automatically detected
3. **Validation triggers** automatically after debounce period
4. **Results stored** in issue tracker for review
5. **Git commits** trigger additional validation through hooks

### CI/CD Pipeline
1. **Install git hooks** during repository setup
2. **Enable validation on commits/pushes** for quality gates
3. **Configure failure handling** based on pipeline requirements
4. **Integrate with build process** for comprehensive validation

### Enterprise Development
1. **Comprehensive monitoring** of all plugin and core directories  
2. **Strict validation** with failure blocking for production branches
3. **Issue tracking integration** for audit trails and reporting
4. **Background validation** to maintain developer productivity

## Integration with Other Plugins

### Plugin Change Validation Pipeline
The hook system automatically triggers the validation pipeline:
- Passes plugin name, change type, and file paths
- Executes comprehensive validation (integrity, security, compliance)
- Returns validation results for processing

### Issue Tracker
Validation results are automatically stored:
- Creates validation run records with unique IDs
- Stores issue details with metadata
- Enables historical tracking and analysis
- Supports multiple storage backends

### Architecture Guardian Watcher
Can work alongside the architecture guardian for:
- Real-time principle enforcement
- Comprehensive code quality monitoring
- Integrated compliance reporting

## File Structure

```
plugs/orchestration/plugin_change_hooks/1.0.0/
├── main.py                     # Main hook system implementation
├── plug.yaml                   # Plugin manifest and schemas  
├── README.md                   # This documentation
├── sbom/                       # Software Bill of Materials
└── examples/
    └── hook_configs.yaml       # Configuration examples
```

## Dependencies

### Required
- **Python 3.8+**: Core runtime
- **PlugPipe Core**: Plugin discovery and execution
- **Git**: For git hooks functionality (when using git integration)

### Optional
- **watchdog>=2.1.0**: For filesystem monitoring (install with `pip install watchdog`)

## Troubleshooting

### Filesystem Monitoring Not Working
```bash
# Install watchdog library
pip install watchdog

# Check if paths exist
ls -la plugs/

# Verify file patterns in configuration
```

### Git Hooks Not Triggering
```bash
# Check if git hooks are installed and executable
ls -la .git/hooks/
chmod +x .git/hooks/pre-commit

# Test git hook manually
./.git/hooks/pre-commit
```

### Validation Not Triggering
```bash
# Check plugin availability
./pp list | grep -E "(plugin_change_validation_pipeline|issue_tracker)"

# Check hook system status
./pp run plugin_change_hooks --input '{"operation": "get_status"}'

# Test manual validation
./pp run plugin_change_hooks --input '{"operation": "trigger_validation"}'
```

### Performance Issues
```bash
# Increase debounce time
"debounce_seconds": 10

# Reduce monitoring scope
"watch_paths": ["plugs/my_specific_plugin"]

# Use async validation
"async_validation": true
```

## Security Considerations

- **File System Access**: Monitoring requires read access to watched directories
- **Git Repository Modification**: Installing hooks modifies `.git/hooks/` directory
- **Process Execution**: Git hooks execute shell scripts during git operations
- **Network Access**: Validation may trigger network requests (cloud storage, external APIs)

## Performance Impact

- **Filesystem Monitoring**: Minimal overhead with efficient event-based watching
- **Debouncing**: Reduces validation frequency for rapid file changes
- **Async Execution**: Background validation doesn't block development workflow
- **Configurable Scope**: Limit validation to specific plugins or directories

## Best Practices

1. **Use Appropriate Debouncing**: Balance responsiveness vs validation frequency
2. **Configure Validation Scope**: Use `changed_plugin_only` for development
3. **Enable Async Validation**: Prevent blocking development workflow
4. **Set Reasonable Timeouts**: Avoid hanging validation processes
5. **Monitor Resource Usage**: Check system impact in resource-constrained environments
6. **Test Hook Installation**: Verify git hooks work correctly after installation

## Contributing

When extending the Plugin Change Hooks system:

1. Follow PlugPipe principles: reuse existing plugins and patterns
2. Maintain backward compatibility with existing configurations
3. Add comprehensive error handling and logging
4. Test with various development workflows and environments
5. Update documentation and examples for new features

## License

MIT License - See PlugPipe project license for details.