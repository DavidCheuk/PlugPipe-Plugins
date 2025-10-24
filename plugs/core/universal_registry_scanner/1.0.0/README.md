# Universal PlugPipe Registry Scanner

**The definitive registry scanning solution for the PlugPipe ecosystem** - works with all supported registry types including filesystem, database, remote APIs, GitHub repositories, and more.

## Overview

The Universal Registry Scanner is a core PlugPipe component that provides accurate plugin/pipe enumeration and metadata across all registry types. This addresses the fundamental challenge of getting reliable plugin counts and information when plugins can be distributed across multiple registry backends.

## Key Features

### ✅ Universal Registry Support
- **Filesystem Registry**: Local `plugs/` and `pipes/` directories
- **Database Registry**: SQLite, PostgreSQL, and other database backends  
- **Remote API Registry**: RESTful API endpoints
- **GitHub Registry**: GitHub repository-based plugin storage
- **Extensible Architecture**: Easy to add new registry types

### ✅ Accurate Enumeration
- **169 total plugins** (153 plugs + 16 pipes) from filesystem
- **Recursive scanning** catches all plugins regardless of directory depth
- **Multiple manifest patterns** (plug.yaml, pipe.yaml, plugin.yaml)
- **Deduplication** across registry sources

### ✅ Rich Metadata
- Plugin name, version, category, description
- Author, license, and registry source information
- Health status and validation information
- Manifest paths and modification timestamps

### ✅ Advanced Operations
- **Cross-registry consistency verification**
- **Health monitoring** of all registry endpoints
- **Performance optimized** async operations
- **Multiple output formats** (JSON, CSV, summary)

## Quick Start

### Basic Usage
```bash
# Get plugin counts across all registries
./pp run universal_registry_scanner

# Count with category breakdown
echo '{"operation": "count_by_registry", "breakdown_by_category": true}' | ./pp run universal_registry_scanner -i /dev/stdin

# Full registry scan with metadata
echo '{"operation": "scan_all_registries", "include_metadata": true}' | ./pp run universal_registry_scanner -i /dev/stdin
```

### Configuration File
Create `/tmp/registry_config.json`:
```json
{
  "filesystem": {
    "base_path": "/mnt/c/Project/PlugPipe"
  },
  "database": {
    "db_path": "/mnt/c/Project/PlugPipe/plugpipe_storage.db"
  },
  "remote_api": {
    "endpoint": "https://registry.plugpipe.io/api",
    "auth": {
      "api_key": "your-api-key"
    }
  },
  "github": {
    "repo_url": "https://github.com/your-org/plugpipe-registry",
    "branch": "main",
    "token": "github-token"
  }
}
```

## Supported Operations

### 1. `scan_all_registries`
Complete scan of all configured registries with full metadata.

**Input Parameters:**
```json
{
  "operation": "scan_all_registries",
  "registry_types": ["filesystem", "database", "remote_api", "github"],
  "include_metadata": true,
  "output_format": "json"
}
```

**Output:**
- Complete plugin inventory across all registries
- Registry-specific breakdowns
- Metadata for each plugin/pipe
- Summary statistics

### 2. `count_by_registry`
Fast plugin counting with optional category breakdown.

**Input Parameters:**
```json
{
  "operation": "count_by_registry", 
  "breakdown_by_category": true,
  "include_health_status": false
}
```

**Output:**
```json
{
  "registry_counts": {
    "filesystem": {
      "plugs": 153,
      "pipes": 16,
      "total": 169,
      "categories": {
        "core": 5,
        "security": 20,
        "intelligence": 3,
        "unknown": 92
      }
    }
  },
  "total_across_all_registries": {
    "plugs": 153,
    "pipes": 16,
    "total": 169
  }
}
```

### 3. `verify_registry_consistency`
Cross-registry consistency verification.

**Input Parameters:**
```json
{
  "operation": "verify_registry_consistency",
  "show_discrepancies": true
}
```

**Output:**
- Plugins found in all registries
- Plugins missing from some registries
- Detailed discrepancy report

### 4. `registry_health_check`
Comprehensive health monitoring of all registry endpoints.

**Input Parameters:**
```json
{
  "operation": "registry_health_check",
  "timeout_seconds": 30
}
```

**Output:**
- Health status for each registry
- Response times and accessibility
- Overall system health score

## Architecture

### Registry Interface
All registry scanners implement the `RegistryInterface` abstract class:

```python
class RegistryInterface(ABC):
    @abstractmethod
    async def discover_plugins(self) -> List[Dict[str, Any]]:
        """Discover all plugins in this registry"""
        
    @abstractmethod  
    async def get_plugin_metadata(self, plugin_name: str) -> Dict[str, Any]:
        """Get detailed metadata for a specific plugin"""
        
    @abstractmethod
    async def validate_registry_health(self) -> Dict[str, Any]:
        """Validate the health and availability of this registry"""
```

### Supported Registry Types

#### FilesystemRegistry
- Scans local `plugs/` and `pipes/` directories
- Uses recursive glob patterns for comprehensive discovery
- Handles multiple manifest file formats and directory structures

#### DatabaseRegistry  
- Connects to SQLite, PostgreSQL, and other databases
- Searches multiple table structures for plugin metadata
- Supports various schema formats

#### RemoteAPIRegistry
- Connects to REST API endpoints
- Handles multiple authentication methods (Bearer, Basic, Token)
- Tries common API endpoint patterns

#### GitHubRegistry
- Connects to GitHub repositories via API
- Searches for manifest files recursively
- Handles rate limiting and authentication

### Performance Optimizations
- **Async operations** for concurrent registry scanning
- **Connection pooling** for API-based registries
- **Caching** of expensive operations
- **Configurable timeouts** to prevent hanging

## Integration Examples

### Dashboard Integration
```python
# Get accurate plugin count for dashboard
scanner_input = {
    "operation": "count_by_registry",
    "breakdown_by_category": True
}

result = subprocess.run([
    './pp', 'run', 'universal_registry_scanner',
    '--input', '/dev/stdin'
], input=json.dumps(scanner_input), 
   capture_output=True, text=True)

if result.returncode == 0:
    data = json.loads(result.stdout)
    total_plugins = data['data']['total_across_all_registries']['total']
    print(f"Total plugins: {total_plugins}")
```

### Health Monitoring
```bash
# Check all registry health
echo '{"operation": "registry_health_check"}' | ./pp run universal_registry_scanner -i /dev/stdin | jq '.data.overall_health'
```

### CSV Export
```bash
# Export plugin inventory to CSV
echo '{"operation": "scan_all_registries", "output_format": "csv"}' | ./pp run universal_registry_scanner -i /dev/stdin > /tmp/plugin_inventory.csv
```

## Error Handling

The scanner provides comprehensive error handling:

- **Registry connectivity issues**: Graceful degradation when registries are unavailable
- **Authentication failures**: Clear error messages for auth problems  
- **Timeout handling**: Configurable timeouts prevent hanging
- **Schema validation**: Validates manifest files and handles malformed data
- **Rate limiting**: Respects API rate limits with backoff strategies

## Extension Points

### Adding New Registry Types

1. **Implement RegistryInterface**:
```python
class CustomRegistry(RegistryInterface):
    async def discover_plugins(self) -> List[Dict[str, Any]]:
        # Your implementation
        pass
```

2. **Register in UniversalRegistryScanner**:
```python
def _initialize_registries(self):
    if 'custom' in self.config:
        self.registries['custom'] = CustomRegistry(self.config['custom'])
```

### Custom Authentication
```python
def _get_auth_headers(self) -> Dict[str, str]:
    # Implement custom auth logic
    return {"Authorization": f"Custom {self.token}"}
```

## Testing

See the test suite in `/tmp/test_universal_registry_scanner.py` for comprehensive testing examples.

### Test Categories
- **Unit tests** for each registry type
- **Integration tests** for cross-registry operations
- **Performance tests** for large-scale deployments
- **Error handling tests** for failure scenarios

## Troubleshooting

### Common Issues

**Issue**: "No plugins found"
- **Solution**: Check registry configuration and permissions
- **Debug**: Run with `include_health_status: true` to see registry status

**Issue**: "Timeout errors"
- **Solution**: Increase `timeout_seconds` parameter
- **Debug**: Check network connectivity to remote registries

**Issue**: "Authentication failed"  
- **Solution**: Verify API keys and tokens in configuration
- **Debug**: Test authentication manually with curl/httpie

**Issue**: "Inconsistent counts"
- **Solution**: Run `verify_registry_consistency` operation
- **Debug**: Check for plugins that exist in some registries but not others

### Debug Mode
```bash
# Enable debug logging
PYTHONPATH=/mnt/c/Project/PlugPipe python3 -c "
import logging
logging.basicConfig(level=logging.DEBUG)
# Run your scanner operations
"
```

## Performance Notes

- **Filesystem scanning**: ~169 plugins in <1 second
- **Database queries**: Optimized for large result sets
- **API endpoints**: Concurrent requests with connection pooling
- **GitHub API**: Rate limit aware with smart caching

## Contributing

When extending the Universal Registry Scanner:

1. **Follow PlugPipe principles** from CLAUDE.md
2. **Implement full RegistryInterface**
3. **Add comprehensive error handling**
4. **Include unit and integration tests**
5. **Update documentation**
6. **Maintain backward compatibility**

## License

MIT License - Part of the PlugPipe Universal Integration Hub ecosystem.