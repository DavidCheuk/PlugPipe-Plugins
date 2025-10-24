# PlugPipe Automated Test Generator CLI

## Overview

The PlugPipe Automated Test Generator provides comprehensive CLI integration for flexible test generation, execution, and management. It supports selective test patterns, interactive modes, and integration with the PlugPipe ecosystem.

## Installation & Setup

The CLI is automatically available when the `automated_test_generator` plugin is installed. Integrate with the main `pp` command by adding the following to your PlugPipe CLI configuration:

```bash
# Add to your pp command structure
alias pp-test-gen="/path/to/plugs/testing/automated_test_generator/1.0.0/cli/pp_test_gen.py"
```

## Commands

### Generate Tests

Generate comprehensive test suites for plugins with flexible options:

```bash
# Generate all tests for a plugin
pp test-gen generate --plugin my_plugin --category core

# Generate specific test types
pp test-gen generate --plugin my_plugin --types unit,integration,security

# Generate with performance testing for mission-critical plugins
pp test-gen generate --plugin orchestrator --types unit,integration,performance --category core

# Dry run to see configuration
pp test-gen generate --plugin my_plugin --dry-run --verbose
```

**Options:**
- `--plugin` (required): Plugin name to generate tests for
- `--category`: Plugin category (core, security, testing, etc.)
- `--types`: Test types (unit, integration, performance, security, compliance, api, e2e)
- `--patterns`: Specific test patterns to generate
- `--exclude-patterns`: Patterns to exclude
- `--framework`: Test framework (default: pytest)
- `--coverage-target`: Coverage target (0.0-1.0)
- `--max-time`: Max execution time in seconds
- `--parallel`: Enable parallel execution
- `--verbose`: Verbose output
- `--dry-run`: Show configuration without generating
- `--output-format`: Output format (table, json, yaml)

### Run Tests

Execute existing tests with pattern filtering and advanced options:

```bash
# Run all tests for a plugin
pp test-gen run --plugin my_plugin

# Run specific test patterns
pp test-gen run --plugin my_plugin --pattern "*performance*"

# Run with coverage and parallel execution
pp test-gen run --plugin my_plugin --coverage --parallel 4

# Run with pytest markers
pp test-gen run --plugin my_plugin --markers "slow,critical"

# Run with timeout
pp test-gen run --plugin my_plugin --max-time 600
```

**Options:**
- `--plugin` (required): Plugin name
- `--pattern`: Test pattern to run (pytest -k)
- `--markers`: Pytest markers (pytest -m)
- `--parallel`: Number of parallel workers
- `--coverage`: Show coverage report
- `--max-time`: Max execution time in seconds
- `--verbose`: Verbose output
- `--dry-run`: Show command without executing

### List Test Patterns

Discover available test patterns and categories:

```bash
# List all test patterns for a plugin
pp test-gen list --plugin my_plugin

# Show detailed patterns
pp test-gen list --plugin my_plugin --show-patterns
```

**Output includes:**
- Test files available
- Test categories (unit, integration, performance, security)
- Test functions and classes
- Common pattern suggestions

### Interactive Mode

Interactive test generation and execution:

```bash
# Start interactive mode
pp test-gen interactive --plugin my_plugin

# Interactive mode will prompt for:
# - Plugin information
# - Test types to generate
# - Performance testing options
# - Test execution preferences
```

## Test Selection Patterns

### Common Test Patterns

```bash
# Performance tests only
pp test-gen run --plugin my_plugin --pattern "*performance*"

# Security tests only
pp test-gen run --plugin my_plugin --pattern "*security*"

# Integration tests only
pp test-gen run --plugin my_plugin --pattern "*integration*"

# Baseline tests
pp test-gen run --plugin my_plugin --pattern "test_baseline_*"

# Stress tests
pp test-gen run --plugin my_plugin --pattern "*stress*"

# Redundancy tests
pp test-gen run --plugin my_plugin --pattern "*redundancy*"
```

### Test Categories

Generate or run specific test categories:

```bash
# Generate unit tests only
pp test-gen generate --plugin my_plugin --types unit

# Generate performance tests for mission-critical plugins
pp test-gen generate --plugin hub_registry --types performance --category core

# Generate security tests
pp test-gen generate --plugin my_plugin --types security

# Generate comprehensive test suite
pp test-gen generate --plugin my_plugin --types unit,integration,performance,security
```

### Test Tags/Markers

Use pytest markers for fine-grained test selection:

```bash
# Run only critical tests
pp test-gen run --plugin my_plugin --markers critical

# Run slow tests
pp test-gen run --plugin my_plugin --markers slow

# Run mission-critical tests
pp test-gen run --plugin my_plugin --markers mission_critical

# Exclude slow tests
pp test-gen run --plugin my_plugin --markers "not slow"
```

## Mission-Critical Plugin Detection

The automated test generator automatically detects mission-critical plugins and generates enhanced performance tests:

**Detection Criteria:**
- **Categories**: core, infrastructure, security, authentication, database, orchestration, monitoring
- **Keywords**: hub, registry, orchestrator, auth, security, database, cache, queue, monitor
- **Context Analysis**: Availability concerns detected by LLM analysis

**Enhanced Tests Generated:**
- Concurrent execution stress testing (20 threads × 10 executions)
- Memory leak detection (100 iterations with monitoring)
- Redundancy/failover validation (≥95% success rate requirement)
- Performance regression detection
- Resource constraint testing

## Output Formats

### Table Format (Default)

```
📊 Test Generation Results
=======================================
✅ Success: True
📋 Operation: generate_full_test_suite
🧪 Tests Generated: 15

📑 Test Categories:
   • Unit: 8 tests
   • Integration: 3 tests
   • Security: 2 tests
   • Performance: 2 tests

📈 Coverage Analysis:
   • Estimated Coverage: 85.2%
   • Functions Covered: 12/15
   • Lines Covered: 234/275
```

### JSON Format

```bash
pp test-gen generate --plugin my_plugin --output-format json
```

### YAML Format

```bash
pp test-gen generate --plugin my_plugin --output-format yaml
```

## Integration with PlugPipe Ecosystem

The CLI integrates seamlessly with the PlugPipe plugin ecosystem:

**Ecosystem Plugins Used:**
- `llm_service`: Intelligent test strategy generation
- `context_analyzer`: Deep code analysis and understanding
- `agent_factory`: Specialized test agent creation
- `performance_benchmark`: Enterprise-grade performance testing
- `cyberpig_ai`: Security test generation
- `codebase_integrity_scanner`: Test validation

**Recommendations Provided:**
```bash
💡 Recommendations:
   • Run generated tests with: pytest tests/
   • Check test coverage with: pytest --cov=main tests/
   • Validate SBOM with: python scripts/sbom_helper_cli.py
   • Review security tests for plugin-specific considerations
   • Use CLI: pp test-gen run --plugin my_plugin --pattern '*performance*'
```

## Examples

### Complete Development Workflow

```bash
# 1. Generate comprehensive test suite
pp test-gen generate --plugin my_new_plugin --category integration --types unit,integration,security

# 2. Run all tests
pp test-gen run --plugin my_new_plugin --coverage --verbose

# 3. Run only performance tests if mission-critical
pp test-gen run --plugin my_new_plugin --pattern "*performance*" --verbose

# 4. List available patterns for future reference
pp test-gen list --plugin my_new_plugin

# 5. Interactive mode for custom selection
pp test-gen interactive --plugin my_new_plugin
```

### CI/CD Integration

```bash
# Generate tests in CI pipeline
pp test-gen generate --plugin $PLUGIN_NAME --category $PLUGIN_CATEGORY --output-format json > test-results.json

# Run tests with timeout and parallel execution
pp test-gen run --plugin $PLUGIN_NAME --coverage --parallel 4 --max-time 600 --output-format junit

# Validate existing tests
pp test-gen run --plugin $PLUGIN_NAME --pattern "test_*_validation" --markers "not slow"
```

## Advanced Features

### Parallel Execution

```bash
# Run tests with 4 parallel workers
pp test-gen run --plugin my_plugin --parallel 4

# Generate with parallel execution enabled
pp test-gen generate --plugin my_plugin --parallel --max-time 300
```

### Custom Test Patterns

```bash
# Generate specific patterns
pp test-gen generate --plugin my_plugin --patterns "test_*_api,test_*_security"

# Exclude specific patterns
pp test-gen generate --plugin my_plugin --exclude-patterns "test_*_slow,test_*_experimental"
```

### Environment-Specific Testing

```bash
# Development environment (all tests)
pp test-gen run --plugin my_plugin --markers "not slow"

# Production validation (critical tests only)
pp test-gen run --plugin my_plugin --markers "critical" --max-time 300

# Performance testing (mission-critical plugins)
pp test-gen run --plugin my_plugin --pattern "*performance*" --parallel 2
```

## Integration with Main PP Command

To integrate with the main PlugPipe `pp` command, add the following to your PlugPipe CLI configuration:

```bash
# In your pp command structure, add:
case "$1" in
    test-gen)
        shift
        exec /path/to/plugs/testing/automated_test_generator/1.0.0/cli/pp_test_gen.py "$@"
        ;;
esac
```

This enables usage like:
```bash
pp test-gen generate --plugin my_plugin
pp test-gen run --plugin my_plugin --pattern "*performance*"
pp test-gen interactive
```

## Support & Troubleshooting

### Common Issues

1. **Plugin not found**: Ensure the plugin path is correct and the plugin exists
2. **Import errors**: Check that the plugin has proper dependencies and structure
3. **Test generation failures**: Use `--verbose` and `--dry-run` to debug configuration
4. **Performance test issues**: Ensure `performance_benchmark` plugin is available for mission-critical plugins

### Debug Mode

```bash
# Enable verbose output for debugging
pp test-gen generate --plugin my_plugin --verbose --dry-run

# Check what tests would be generated
pp test-gen list --plugin my_plugin --show-patterns
```

### Getting Help

```bash
# Show help for specific commands
pp test-gen generate --help
pp test-gen run --help
pp test-gen interactive --help
```