# Issue Tracker Plugin

Comprehensive issue tracking system for plugin validation results with configurable storage backends.

## Overview

The Issue Tracker plugin provides a unified interface for storing, retrieving, and managing validation issues from PlugPipe plugin validation pipelines. It follows PlugPipe's core principles of modularity and reusability by supporting multiple storage backends through a pluggable architecture.

## Key Features

- **Multiple Storage Backends**: Database, cloud storage, file systems, and custom implementations
- **Auto-Selection**: Intelligent backend selection based on availability and configuration
- **Configurable Priority**: Define preferred storage backends with automatic failover
- **Health Monitoring**: Built-in health checks for all storage backends
- **Rich Operations**: Store, retrieve, search, summarize, and export validation issues
- **Metadata Tracking**: Comprehensive tracking of validation runs, scores, and timestamps

## Supported Storage Backends

### Database Backends
- **Database Factory Plugin**: Unified interface for SQLite, PostgreSQL, MongoDB with failover
- **SQLite**: Direct SQLite plugin integration
- **PostgreSQL**: Enterprise-grade relational database
- **MongoDB**: NoSQL document database
- **MySQL**: Popular relational database

### Cloud Storage Backends  
- **AWS S3**: Amazon Simple Storage Service
- **Azure Blob Storage**: Microsoft Azure cloud storage
- **Google Cloud Storage**: Google Cloud Platform storage

### File System Backends
- **Local File System**: Local JSON file storage (always available as fallback)
- **Network File System (NFS)**: Shared network storage
- **Hadoop Distributed File System (HDFS)**: Big data distributed storage

### Custom Backends
- **Extensible Architecture**: Add any storage backend through plugin configuration
- **Custom Health Checks**: Define backend-specific health validation
- **Configurable Priority**: Set priority levels for backend selection

## Configuration

### Basic Usage

```yaml
operation: store_issues
storage_backend: auto  # or specific backend name
storage_config:
  local_file:
    storage_path: "validation_issues.json"
    backup_enabled: true
    max_history: 100
```

### Enterprise Database Configuration

```yaml
operation: store_issues  
storage_backend: postgresql
storage_config:
  postgresql:
    host: "db.company.internal"
    port: 5432
    database: "plugpipe_production"
    username: "plugpipe_user"
    password: "${POSTGRES_PASSWORD}"
    table_name: "validation_issues"
```

### Multi-Backend with Auto-Selection

```yaml
operation: store_issues
storage_backend: auto
storage_config:
  # Primary: Database
  postgresql:
    host: "primary-db.internal"
    database: "plugpipe"
    username: "plugpipe"
    password: "${POSTGRES_PASSWORD}"
  
  # Backup: Cloud storage
  aws_s3:
    bucket: "plugpipe-backup"
    prefix: "validation-issues/"
    region: "us-west-2"
  
  # Fallback: Local storage
  local_file:
    storage_path: "fallback_issues.json"
```

## Operations

### Store Issues
Store validation issues from pipeline runs:

```yaml
operation: store_issues
issues:
  validation_run_id: "run_12345"
  timestamp: "2025-08-29T14:00:00Z"
  target_plugin: "security_scanner"
  pipeline_score: 85
  issues_list:
    - category: "security"
      severity: "high"
      description: "Vulnerability detected"
      file_path: "plugin/security.py"
      recommendation: "Update dependency"
```

### Retrieve Latest Issues
Get the most recent validation results:

```yaml
operation: get_latest_issues
```

### Get Issue Summary
Generate analytics and statistics:

```yaml
operation: get_issue_summary
```

### Health Status Check
Monitor system health:

```yaml
operation: get_health_status
```

## Examples

See the `examples/` directory for comprehensive configuration examples:

- `storage_configs.yaml`: Various storage backend configurations
- `test_issue_tracker.json`: Basic functionality testing
- `test_issue_tracker_local.json`: Local storage testing
- `test_issue_tracker_configurable.json`: Multi-backend testing

## File Structure

```
plugs/governance/issue_tracker/1.0.0/
├── main.py                    # Main plugin implementation
├── plug.yaml                  # Plugin manifest and schema
├── README.md                  # This documentation
├── sbom/                      # Software Bill of Materials
│   ├── lib_sbom.json
│   └── sbom-complete.json
└── examples/                  # Configuration examples
    ├── storage_configs.yaml   # Storage backend examples
    ├── test_issue_tracker.json
    ├── test_issue_tracker_local.json
    └── test_issue_tracker_configurable.json
```

## Integration with Validation Pipeline

The Issue Tracker integrates seamlessly with the Plugin Change Validation Pipeline:

```python
# Validation pipeline automatically uses issue tracker
validation_config = {
    'operation': 'full_validation',
    'target_plugin': 'my_plugin',
    'storage_backend': 'auto',
    'storage_config': {
        'postgresql': {...},
        'local_file': {...}
    }
}
```

## Development and Testing

### Local Development
For development and testing, use local file storage:

```yaml
storage_backend: local_file
storage_config:
  local_file:
    storage_path: "dev_issues.json"
    backup_enabled: false
    max_history: 25
```

### Testing
Run the provided test examples:

```bash
# Test basic functionality
./pp run issue_tracker --input examples/test_issue_tracker.json

# Test local storage
./pp run issue_tracker --input examples/test_issue_tracker_local.json

# Test health status
./pp run issue_tracker --input '{"operation": "get_health_status"}'
```

## Architecture

The Issue Tracker follows a modular architecture:

1. **Storage Backend Discovery**: Discovers available storage plugins
2. **Health Validation**: Tests backend health before use
3. **Priority-Based Selection**: Selects best available backend
4. **Graceful Failover**: Falls back to working backends on failure
5. **Unified Interface**: Consistent API regardless of backend

## Backend Priority

Default backend selection priority (lower number = higher priority):

1. Database Factory Plugin (priority 1)
2. Direct database plugins (priority 2)  
3. Cloud storage (priority 3)
4. File systems (priority 4)
5. Custom backends (configurable priority)
99. Local file system (ultimate fallback)

## Error Handling

The plugin includes comprehensive error handling:

- **Graceful Degradation**: Falls back to working storage backends
- **Health Monitoring**: Continuous monitoring of backend health
- **Error Reporting**: Detailed error messages and status reporting
- **Ultimate Fallback**: Local file storage always available

## Security Considerations

- **Credential Management**: Supports environment variable injection for secrets
- **SSL/TLS Support**: Secure connections for database and cloud backends
- **Access Control**: Respects backend-specific access controls
- **Data Encryption**: Supports encrypted storage where available

## Performance

- **Async Operations**: Full async/await support for performance
- **Connection Pooling**: Leverages backend connection pooling
- **Batch Operations**: Efficient batch processing for large datasets
- **Caching**: Intelligent caching where appropriate

## Extensibility

Add new storage backends by:

1. Creating a storage plugin that implements the standard interface
2. Adding configuration in `storage_config.custom_backends`
3. The issue tracker will automatically discover and use the new backend

```yaml
storage_config:
  custom_backends:
    my_custom_storage:
      plugin_name: "my_storage_plugin"
      priority: 2
      health_check:
        operation: "ping"
      config:
        endpoint: "https://my-storage.com"
        api_key: "${MY_STORAGE_API_KEY}"
```

## Contributing

When extending the Issue Tracker:

1. Follow PlugPipe principles: "reuse everything, reinvent nothing"
2. Use existing storage plugins rather than custom implementations
3. Maintain backward compatibility
4. Add comprehensive tests for new backends
5. Update documentation and examples

## License

MIT License - See PlugPipe project license for details.