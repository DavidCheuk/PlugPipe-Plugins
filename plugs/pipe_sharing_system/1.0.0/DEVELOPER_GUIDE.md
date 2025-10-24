# Pipe Sharing System Plugin - Developer Guide

## Overview

The Pipe Sharing System plugin is an enterprise pipe sharing orchestrator that coordinates registry plugins for comprehensive pipe distribution and collaboration workflows. This plugin serves as the central hub for sharing pipes across the PlugPipe ecosystem, enabling developers to discover, distribute, and collaborate on pipe implementations.

**Plugin Path**: `plugs/pipe_sharing_system/1.0.0/`
**Category**: Registry
**Version**: 1.0.0
**Status**: Stable
**Dependencies**: Python Standard Library, optional registry plugins

## Core Capabilities

- **Pipe Sharing**: Share pipes with public or private access controls
- **Registry Orchestration**: Coordinate multiple registry plugins for comprehensive coverage
- **Distribution Management**: Manage pipe distribution across different environments
- **Collaboration Workflows**: Enable team collaboration on pipe development
- **Analytics Reporting**: Generate reports on sharing and usage patterns

## Plugin Architecture

### Registry Integration

The plugin coordinates with existing registry infrastructure:

#### Registry Plugins Integration
- **plugin_registry_scanner**: For pipe discovery and scanning
- **universal_registry_scanner**: For broad registry scanning across platforms
- **pp_registry_comprehensive_reporter**: For analytics and reporting

#### Core Components
- **PipeSharingOrchestrator**: Main orchestration class
- **Registry Plugin Loader**: Dynamic loading of registry plugins
- **Sharing Workflow Manager**: Manages sharing operations and permissions

### Sharing Actions

#### 1. List Shareable Pipes
Lists all pipes available for sharing based on filters and permissions.

#### 2. Generate Share Report
Creates comprehensive reports on sharing activities and statistics.

#### 3. Share Pipe
Shares a specific pipe with configured permissions and settings.

#### 4. Manage Permissions
Manages sharing permissions and access controls for pipes.

## Configuration

### Default Configuration

```yaml
enable_public_sharing: true
require_approval: false
max_pipes_per_user: 50
```

### Configuration Options

#### Sharing Settings
- `enable_public_sharing`: Allow public pipe sharing
- Default: `true`

#### Approval Workflow
- `require_approval`: Require approval for shared pipes
- Default: `false`

#### User Limits
- `max_pipes_per_user`: Maximum pipes per user
- Default: `50`
- Range: `1` to `1000`

## API Reference

### Core Operations

#### 1. List Shareable Pipes
List all pipes available for sharing with optional filtering.

```python
context = {
    'action': 'list_shareable',
    'pipe_filters': {
        'category': 'security',
        'status': 'stable',
        'author': 'PlugPipe Team'
    }
}

result = process(context, config)
```

**Response Structure**:
```json
{
  "success": true,
  "message": "Pipe sharing orchestration completed",
  "result": {
    "pipes": [
      {
        "name": "security_scanner",
        "version": "1.0.0",
        "category": "security",
        "author": "PlugPipe Team",
        "status": "stable",
        "sharing_enabled": true
      }
    ],
    "total_count": 1,
    "filters_applied": {
      "category": "security",
      "status": "stable",
      "author": "PlugPipe Team"
    }
  }
}
```

#### 2. Generate Share Report
Generate comprehensive sharing reports and analytics.

```python
context = {
    'action': 'generate_share_report',
    'report_options': {
        'include_usage_stats': True,
        'time_range': '30_days',
        'report_format': 'detailed'
    }
}

result = process(context, config)
```

**Response Structure**:
```json
{
  "success": true,
  "message": "Pipe sharing orchestration completed",
  "result": {
    "report_id": "share_report_20231201_120000",
    "generated_at": "2023-12-01T12:00:00Z",
    "summary": {
      "total_shared_pipes": 156,
      "public_pipes": 89,
      "private_pipes": 67,
      "active_collaborations": 23
    },
    "usage_stats": {
      "downloads": 1247,
      "unique_users": 89,
      "popular_categories": ["security", "data", "api"]
    },
    "time_range": "30_days"
  }
}
```

#### 3. Share Pipe
Share a specific pipe with configured permissions.

```python
context = {
    'action': 'share_pipe',
    'pipe_name': 'data_processor',
    'sharing_options': {
        'public': True,
        'approval_required': False,
        'permissions': {
            'read': True,
            'fork': True,
            'contribute': False
        }
    }
}

result = process(context, config)
```

**Response Structure**:
```json
{
  "success": true,
  "message": "Pipe sharing orchestration completed",
  "result": {
    "pipe_name": "data_processor",
    "sharing_status": "active",
    "share_id": "share_data_processor_20231201",
    "sharing_options": {
      "public": true,
      "approval_required": false,
      "permissions": {
        "read": true,
        "fork": true,
        "contribute": false
      }
    },
    "share_url": "https://registry.plugpipe.com/pipes/data_processor"
  }
}
```

#### 4. Manage Permissions
Manage sharing permissions and access controls.

```python
context = {
    'action': 'manage_permissions',
    'pipe_name': 'api_connector',
    'permissions': {
        'users': ['user1', 'user2'],
        'groups': ['developers', 'admins'],
        'access_level': 'read_write',
        'expiration': '2024-12-31'
    }
}

result = process(context, config)
```

**Response Structure**:
```json
{
  "success": true,
  "message": "Pipe sharing orchestration completed",
  "result": {
    "pipe_name": "api_connector",
    "permissions_updated": true,
    "active_permissions": {
      "users": ["user1", "user2"],
      "groups": ["developers", "admins"],
      "access_level": "read_write",
      "expiration": "2024-12-31"
    },
    "permission_id": "perm_api_connector_20231201"
  }
}
```

### Filtering Options

#### By Category
Filter pipes by category:

```python
context = {
    'action': 'list_shareable',
    'pipe_filters': {
        'category': 'security'
    }
}

# Supported categories: security, data, api, integration, monitoring, etc.
```

#### By Status
Filter pipes by development status:

```python
context = {
    'action': 'list_shareable',
    'pipe_filters': {
        'status': 'stable'
    }
}

# Supported statuses: stable, development, experimental
```

#### By Author
Filter pipes by author:

```python
context = {
    'action': 'list_shareable',
    'pipe_filters': {
        'author': 'PlugPipe Team'
    }
}
```

#### Combined Filtering
Combine multiple filter criteria:

```python
context = {
    'action': 'list_shareable',
    'pipe_filters': {
        'category': 'security',
        'status': 'stable',
        'author': 'PlugPipe Team'
    }
}
```

## Integration Patterns

### Basic Pipe Sharing

```python
def share_pipe_basic(pipe_name, public=True):
    """Basic pipe sharing workflow"""

    config = {
        'enable_public_sharing': True,
        'require_approval': False
    }

    context = {
        'action': 'share_pipe',
        'pipe_name': pipe_name,
        'sharing_options': {
            'public': public,
            'approval_required': False
        }
    }

    result = process(context, config)

    if result['success']:
        return {
            'status': 'shared',
            'pipe_name': pipe_name,
            'share_id': result['result']['share_id'],
            'share_url': result['result'].get('share_url')
        }
    else:
        return {
            'status': 'failed',
            'error': result.get('error')
        }
```

### Registry Discovery and Sharing

```python
def discover_and_share_pipes(category_filter=None):
    """Discover pipes and enable sharing for selected ones"""

    config = {
        'enable_public_sharing': True,
        'max_pipes_per_user': 100
    }

    # Step 1: List shareable pipes
    list_context = {
        'action': 'list_shareable',
        'pipe_filters': {'category': category_filter} if category_filter else {}
    }

    list_result = process(list_context, config)

    if not list_result['success']:
        return {'error': 'Failed to list pipes'}

    pipes = list_result['result']['pipes']
    shared_pipes = []

    # Step 2: Share selected pipes
    for pipe in pipes:
        if pipe.get('status') == 'stable':  # Only share stable pipes
            share_context = {
                'action': 'share_pipe',
                'pipe_name': pipe['name'],
                'sharing_options': {
                    'public': True,
                    'approval_required': False
                }
            }

            share_result = process(share_context, config)

            if share_result['success']:
                shared_pipes.append({
                    'name': pipe['name'],
                    'share_id': share_result['result']['share_id']
                })

    return {
        'total_discovered': len(pipes),
        'total_shared': len(shared_pipes),
        'shared_pipes': shared_pipes
    }
```

### Collaboration Workflow

```python
def setup_collaboration(pipe_name, team_members, permissions_level='read_write'):
    """Set up collaboration for a pipe with team members"""

    config = {
        'enable_public_sharing': False,  # Private collaboration
        'require_approval': True
    }

    # Step 1: Share pipe privately
    share_context = {
        'action': 'share_pipe',
        'pipe_name': pipe_name,
        'sharing_options': {
            'public': False,
            'approval_required': True,
            'private_collaboration': True
        }
    }

    share_result = process(share_context, config)

    if not share_result['success']:
        return {'error': 'Failed to share pipe for collaboration'}

    # Step 2: Set up permissions for team members
    permissions_context = {
        'action': 'manage_permissions',
        'pipe_name': pipe_name,
        'permissions': {
            'users': team_members,
            'access_level': permissions_level,
            'collaboration_enabled': True
        }
    }

    permissions_result = process(permissions_context, config)

    return {
        'collaboration_setup': permissions_result['success'],
        'pipe_name': pipe_name,
        'team_members': team_members,
        'permissions_level': permissions_level,
        'share_id': share_result['result']['share_id'] if share_result['success'] else None
    }
```

### Analytics and Reporting

```python
def generate_sharing_analytics(time_range='30_days', detailed=True):
    """Generate comprehensive sharing analytics"""

    config = {
        'enable_public_sharing': True,
        'analytics_enabled': True
    }

    context = {
        'action': 'generate_share_report',
        'report_options': {
            'include_usage_stats': detailed,
            'include_user_metrics': detailed,
            'include_trend_analysis': detailed,
            'time_range': time_range,
            'report_format': 'comprehensive' if detailed else 'summary'
        }
    }

    result = process(context, config)

    if result['success']:
        report_data = result['result']

        return {
            'report_id': report_data['report_id'],
            'summary': report_data['summary'],
            'usage_stats': report_data.get('usage_stats', {}),
            'trends': report_data.get('trend_analysis', {}),
            'recommendations': report_data.get('recommendations', [])
        }
    else:
        return {
            'error': 'Failed to generate analytics report',
            'details': result.get('error')
        }
```

## Error Handling

### Common Error Scenarios

#### Invalid Action
```python
context = {'action': 'invalid_action'}
result = process(context)

# Result:
{
    "success": false,
    "error": "Unknown sharing action: invalid_action",
    "message": "Pipe sharing orchestration failed"
}
```

#### Missing Pipe Name
```python
context = {
    'action': 'share_pipe'
    # Missing pipe_name
}
result = process(context)

# Result:
{
    "success": false,
    "error": "Pipe name is required for sharing operation",
    "message": "Pipe sharing orchestration failed"
}
```

#### Permission Denied
```python
context = {
    'action': 'share_pipe',
    'pipe_name': 'restricted_pipe'
}
result = process(context)

# May result in:
{
    "success": false,
    "error": "Permission denied: User lacks sharing permissions for pipe 'restricted_pipe'",
    "message": "Pipe sharing orchestration failed"
}
```

### Error Recovery Patterns

```python
def robust_pipe_sharing(pipe_name, sharing_options, max_retries=3):
    """Robust pipe sharing with error recovery"""

    config = {
        'enable_public_sharing': True,
        'require_approval': False
    }

    for attempt in range(max_retries):
        try:
            context = {
                'action': 'share_pipe',
                'pipe_name': pipe_name,
                'sharing_options': sharing_options
            }

            result = process(context, config)

            if result['success']:
                return {
                    'status': 'success',
                    'attempt': attempt + 1,
                    'result': result['result']
                }

            # If not successful, log and retry
            print(f"Sharing attempt {attempt + 1} failed: {result.get('error')}")

        except Exception as e:
            print(f"Exception on attempt {attempt + 1}: {e}")

    # All retries exhausted
    return {
        'status': 'failed',
        'attempts': max_retries,
        'error': 'Max retries exhausted'
    }
```

## Performance Optimization

### Batch Operations

```python
def batch_share_pipes(pipe_list, sharing_options):
    """Share multiple pipes efficiently"""

    config = {
        'enable_public_sharing': True,
        'max_pipes_per_user': len(pipe_list) + 10  # Increase limit
    }

    results = []

    for pipe_name in pipe_list:
        context = {
            'action': 'share_pipe',
            'pipe_name': pipe_name,
            'sharing_options': sharing_options
        }

        result = process(context, config)
        results.append({
            'pipe_name': pipe_name,
            'success': result['success'],
            'share_id': result['result']['share_id'] if result['success'] else None
        })

    return {
        'total_pipes': len(pipe_list),
        'successful_shares': len([r for r in results if r['success']]),
        'results': results
    }
```

### Caching Strategy

```python
def cached_pipe_listing(cache_duration=300):
    """List pipes with caching for performance"""

    # This would integrate with a caching layer
    cache_key = "shareable_pipes_list"

    # Check cache first (pseudo-code)
    # cached_result = get_from_cache(cache_key)
    # if cached_result and not expired:
    #     return cached_result

    context = {'action': 'list_shareable'}
    result = process(context)

    if result['success']:
        # Cache the result (pseudo-code)
        # set_in_cache(cache_key, result, cache_duration)
        pass

    return result
```

## Testing

### Test Verification

The plugin has been tested with the ULTIMATE FIX pattern to ensure async/sync compatibility:

```bash
python -c "
import sys
sys.path.append('/mnt/c/Project/PlugPipe/plugs/pipe_sharing_system/1.0.0')
from main import process
result = process({'action': 'list_shareable'}, {})
print(f'Plugin working: {isinstance(result, dict)}')"
```

### Integration Testing

```python
def test_full_sharing_workflow():
    """Test complete sharing workflow"""

    config = {
        'enable_public_sharing': True,
        'require_approval': False
    }

    # Test 1: List shareable pipes
    list_result = process({'action': 'list_shareable'}, config)
    assert list_result['success']

    # Test 2: Share a pipe
    share_result = process({
        'action': 'share_pipe',
        'pipe_name': 'test_pipe',
        'sharing_options': {'public': True}
    }, config)
    assert share_result['success']

    # Test 3: Generate report
    report_result = process({'action': 'generate_share_report'}, config)
    assert report_result['success']

    # Test 4: Manage permissions
    permissions_result = process({
        'action': 'manage_permissions',
        'pipe_name': 'test_pipe',
        'permissions': {'users': ['testuser'], 'access_level': 'read'}
    }, config)
    assert permissions_result['success']

    return "All tests passed"
```

## Development Guidelines

### Adding New Sharing Actions

To add new sharing actions, extend the `PipeSharingOrchestrator.share_pipes()` method:

```python
async def share_pipes(self, context: Dict[str, Any]) -> Dict[str, Any]:
    action = context.get('action', 'list_shareable')

    # Add new action here
    if action == 'new_sharing_action':
        return await self._handle_new_sharing_action(context)

    # Existing actions...
```

### Registry Plugin Integration

To integrate with new registry plugins:

```python
def _load_registry_plugins(self):
    plugins_to_load = [
        # Existing plugins...
        ('new_registry_plugin', 'path/to/new_registry_plugin/main.py')
    ]
```

### Custom Sharing Options

```python
def custom_sharing_workflow(pipe_name, custom_options):
    """Example custom sharing workflow"""

    context = {
        'action': 'share_pipe',
        'pipe_name': pipe_name,
        'sharing_options': {
            'public': custom_options.get('public', True),
            'approval_required': custom_options.get('approval', False),
            'custom_metadata': custom_options.get('metadata', {})
        }
    }

    return process(context)
```

## Troubleshooting

### Common Issues

#### Registry Plugin Loading Failures
- **Symptom**: Registry plugins fail to load
- **Cause**: Missing plugin files or import errors
- **Solution**: Verify plugin paths and dependencies

#### Sharing Permission Errors
- **Symptom**: Permission denied when sharing pipes
- **Cause**: User lacks sufficient permissions
- **Solution**: Check user roles and pipe ownership

#### Performance Issues with Large Pipe Collections
- **Symptom**: Slow response times when listing many pipes
- **Solution**: Implement pagination and filtering

### Debug Mode

```python
def debug_sharing_system():
    """Debug pipe sharing system operations"""

    # Enable detailed logging
    import logging
    logging.basicConfig(level=logging.DEBUG)

    config = {
        'enable_public_sharing': True,
        'debug_mode': True
    }

    # Test basic operation
    result = process({'action': 'list_shareable'}, config)

    print(f"List operation successful: {result['success']}")
    print(f"Registry plugins loaded: {len(result.get('result', {}).get('registry_status', {}))}")

    return result
```

## Version History

### Version 1.0.0
- Initial release with comprehensive pipe sharing orchestration
- Integration with registry plugins (plugin_registry_scanner, universal_registry_scanner, pp_registry_comprehensive_reporter)
- Four core sharing actions: list_shareable, generate_share_report, share_pipe, manage_permissions
- ULTIMATE FIX pattern applied for async/sync compatibility
- Dual parameter handling for flexible API usage
- Comprehensive filtering and configuration options

## Support and Documentation

- **Plugin Source**: `plugs/pipe_sharing_system/1.0.0/main.py`
- **Configuration**: `plugs/pipe_sharing_system/1.0.0/plug.yaml`
- **Registry Integration**: Coordinates with existing registry plugins
- **API Documentation**: Complete in this developer guide

For additional support, refer to the PlugPipe documentation and registry plugin guidelines.