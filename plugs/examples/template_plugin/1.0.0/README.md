# Template Plugin

**Version**: 1.0.0
**Category**: examples
**Author**: PlugPipe Team
**License**: MIT

## Overview

This is a reference implementation demonstrating PlugPipe plugin best practices. Use this as a starting point for creating your own plugins.

## Features

- ✅ Standard `execute()` function (A2A compliant)
- ✅ Comprehensive error handling
- ✅ Input validation
- ✅ Batch processing support
- ✅ Proper logging
- ✅ Complete documentation
- ✅ SPDX copyright headers
- ✅ Type hints and docstrings

## Installation

No external dependencies required. This plugin is included in the PlugPipe-Plugins repository.

## Usage

### Basic Usage

```python
from shares.loader import pp

# Simple example
result = pp('template_plugin', {
    'action': 'example',
    'data': 'Hello World'
})

print(result)
# Output: {'success': True, 'result': 'Processed: Hello World', 'message': '...'}
```

### Available Actions

#### 1. Example Action

Demonstrates basic plugin execution:

```python
result = pp('template_plugin', {
    'action': 'example',
    'data': 'test data'
})
```

#### 2. Validate Action

Validates input data:

```python
result = pp('template_plugin', {
    'action': 'validate',
    'data': {'name': 'John', 'age': 30},
    'options': {
        'required_fields': ['name', 'age']
    }
})
```

#### 3. Process Action

Processes data with transformations:

```python
result = pp('template_plugin', {
    'action': 'process',
    'data': 'hello world',
    'options': {
        'transform': 'uppercase'  # or 'lowercase', 'reverse'
    }
})
```

#### 4. Batch Action

Processes multiple items:

```python
result = pp('template_plugin', {
    'action': 'batch',
    'data': ['item1', 'item2', 'item3'],
    'options': {
        'transform': 'uppercase'
    }
})
```

## Configuration

### Plugin Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `action` | string | Yes | 'example' | Action to perform |
| `data` | any | No | None | Input data |
| `options` | dict | No | {} | Configuration options |

### Options (per action)

**Validate action**:
- `required_fields`: List of required field names

**Process action**:
- `transform`: Transformation type ('uppercase', 'lowercase', 'reverse')

## Return Format

All actions return a dictionary with the following structure:

```python
{
    'success': bool,      # Whether operation succeeded
    'result': any,        # Operation result (if successful)
    'message': str,       # Human-readable message
    'error': str,         # Error message (if failed)
    'metadata': dict      # Additional metadata (optional)
}
```

## Error Handling

The plugin handles errors gracefully and returns appropriate error messages:

```python
# Unknown action
result = pp('template_plugin', {'action': 'unknown'})
# Returns: {'success': False, 'error': 'Unknown action: unknown', ...}

# Missing data
result = pp('template_plugin', {'action': 'validate'})
# Returns: {'success': False, 'error': 'No data provided for validation', ...}
```

## Best Practices Demonstrated

### 1. SPDX Copyright Headers

All Python files include proper SPDX headers:

```python
# SPDX-License-Identifier: MIT
# Copyright 2025 PlugPipe Team
# https://github.com/DavidCheuk/PlugPipe-Plugins
```

### 2. Standard Execute Function

```python
def execute(params: Dict[str, Any]) -> Dict[str, Any]:
    """Standard PlugPipe execution function."""
    # Implementation
```

### 3. Comprehensive Error Handling

```python
try:
    # Plugin logic
except TemplatePluginError as e:
    # Custom errors
except Exception as e:
    # Unexpected errors
```

### 4. Input Validation

```python
if data is None:
    return {'success': False, 'error': 'No data provided'}
```

### 5. Type Hints

```python
def execute(params: Dict[str, Any]) -> Dict[str, Any]:
    pass
```

### 6. Docstrings

```python
def execute(params: Dict[str, Any]) -> Dict[str, Any]:
    """
    Comprehensive docstring with:
    - Purpose
    - Args
    - Returns
    - Examples
    """
```

### 7. Logging

```python
import logging
logger = logging.getLogger(__name__)
logger.info("Executing action")
```

## A2A Protocol Compliance

This plugin is A2A (Agent-to-Agent) protocol compliant:

- ✅ Stateless execution (no persistent instance state)
- ✅ Standard `execute()` function
- ✅ Can generate `agent-card.json`
- ✅ Supports agent discovery
- ✅ Proper error handling

## Testing

### Unit Tests

```python
# tests/test_template_plugin.py
import pytest
from plugs.examples.template_plugin.main import execute

def test_example_action():
    result = execute({'action': 'example', 'data': 'test'})
    assert result['success'] == True
    assert 'Processed: test' in result['result']

def test_validate_action():
    result = execute({
        'action': 'validate',
        'data': {'name': 'John'},
        'options': {'required_fields': ['name']}
    })
    assert result['success'] == True
    assert result['valid'] == True
```

### Integration Tests

```bash
# Test via CLI
./pp run template_plugin --action example --data "test"
```

## Development Notes

### Adding New Actions

1. Create handler function: `_handle_new_action()`
2. Add to action router in `execute()`
3. Update documentation
4. Add tests

### Extending Functionality

This template can be extended to:
- Add database operations
- Integrate external APIs
- Implement caching
- Add authentication
- Create pipelines

## Contributing

This is a reference plugin maintained by the PlugPipe team. For contributions to your own plugins, see [CONTRIBUTING.md](../../../../CONTRIBUTING.md).

## License

MIT License - Copyright 2025 PlugPipe Team

## Support

- Documentation: https://github.com/DavidCheuk/PlugPipe/blob/main/docs
- Issues: https://github.com/DavidCheuk/PlugPipe-Plugins/issues
- Email: plugins@plugpipe.com
