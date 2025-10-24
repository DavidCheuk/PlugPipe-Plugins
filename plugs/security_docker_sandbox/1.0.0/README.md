# Docker Sandbox Plug

## Overview

The Docker Sandbox Plug demonstrates PlugPipe's core principle **"reuse, never reinvent"** by leveraging Docker's proven container isolation technology for secure plugin execution, instead of building custom sandboxing mechanisms.

## Philosophy: Plug-First Security

This plugin exemplifies the PlugPipe approach to security:

✅ **Reuse Proven Technology**: Docker containers provide enterprise-grade isolation with years of security hardening  
✅ **Never Reinvent Security**: Instead of custom sandboxing, we integrate with Docker's battle-tested container platform  
✅ **Enterprise Integration**: Works with existing Docker infrastructure, registries, and security policies  
✅ **Community Validated**: Leverages Docker's massive community and security validation  

## Features

### 🛡️ **Container-Based Isolation**
- **Process Isolation**: Each plugin runs in a separate container namespace
- **Resource Limits**: CPU, memory, and I/O limits via Docker's cgroup integration
- **Network Isolation**: Configurable network access with host restrictions
- **Filesystem Isolation**: Read-only and writable path controls

### 🔐 **Security Hardening** 
- **No New Privileges**: Prevents privilege escalation within containers
- **Read-Only Root**: Container filesystem is read-only except for designated paths
- **Non-Root Execution**: Plugs run as unprivileged user (UID 1000)
- **Temporary Filesystem**: Secure tmpfs with size limits and noexec

### ⚙️ **Enterprise Features**
- **Docker Registry Integration**: Support for private registries and image management
- **Resource Monitoring**: CPU and memory usage tracking
- **Execution Statistics**: Detailed performance metrics
- **Cleanup Automation**: Automatic container cleanup after execution

## Configuration

### Basic Usage

```yaml
# Pipe step using Docker sandbox
steps:
  - plugin: security_docker_sandbox
    config:
      plugin_path: "/path/to/target/plugin"
      function_name: "process"
      sandbox_config:
        isolation_level: "standard"
        resource_limits:
          memory_mb: 512
          cpu_limit: 1.0
          timeout_seconds: 300
```

### Advanced Configuration

```yaml
# Production-grade isolation
sandbox_config:
  isolation_level: "strict"
  resource_limits:
    memory_mb: 1024
    cpu_limit: 2.0
    timeout_seconds: 600
  network_access:
    enabled: false
  filesystem_access:
    read_only_paths:
      - "/usr"
      - "/lib" 
      - "/bin"
      - "/etc"
    writable_paths:
      - "/tmp"
    mount_host_paths:
      "/host/data": "/container/data:ro"
```

### Environment-Specific Templates

#### Development
```yaml
isolation_level: "permissive"
resource_limits:
  memory_mb: 256
  cpu_limit: 0.5
network_access:
  enabled: true
  allowed_hosts: ["127.0.0.1", "localhost"]
```

#### Production
```yaml
isolation_level: "strict"
resource_limits:
  memory_mb: 512
  cpu_limit: 1.0
network_access:
  enabled: false
filesystem_access:
  read_only_paths: ["/usr", "/lib", "/bin", "/etc"]
  writable_paths: ["/tmp"]
```

## Docker Integration

### Supported Base Images

| Runtime | Image | Description |
|---------|-------|-------------|
| Python | `python:3.11-slim` | Lightweight Python runtime |
| Node.js | `node:18-alpine` | Lightweight Node.js runtime |
| Generic | `ubuntu:22.04` | Multi-language Linux environment |

### Security Options

The plugin applies these Docker security hardening options:

```bash
--no-new-privileges    # Prevent privilege escalation
--read-only           # Read-only root filesystem
--tmpfs /tmp:noexec,nosuid,size=100m  # Secure temporary filesystem
--user 1000:1000      # Run as non-root user
```

## Installation

### Prerequisites

```bash
# Install Docker
curl -fsSL https://get.docker.com | sh

# Install Python dependencies
pip install docker>=6.0.0 asyncio-timeout>=4.0.0
```

### Plug Installation

```bash
# Install via PlugPipe CLI
plugpipe install security_docker_sandbox

# Or clone manually
git clone https://github.com/plugpipe/plugs/security_docker_sandbox
```

## Usage Examples

### Basic Plug Sandboxing

```python
import asyncio
from plugpipe import load_plugin

async def main():
    # Load Docker sandbox plugin
    sandbox = await load_plugin("security_docker_sandbox")
    
    # Execute plugin in isolated container
    result = await sandbox.process({
        "plugin_path": "/path/to/my_plugin",
        "function_name": "process",
        "args": ["arg1", "arg2"],
        "kwargs": {"param": "value"},
        "sandbox_config": {
            "isolation_level": "standard",
            "resource_limits": {
                "memory_mb": 256,
                "timeout_seconds": 60
            }
        }
    }, {})
    
    print(f"Success: {result['success']}")
    if result['success']:
        print(f"Result: {result['result']}")
        print(f"Execution time: {result['execution_stats']['execution_time_seconds']:.2f}s")
    else:
        print(f"Error: {result['error']}")

asyncio.run(main())
```

### Pipe Integration

```yaml
# pipeline.yaml
name: secure_data_processing
steps:
  - name: validate_input
    plugin: data_validator
    config:
      schema: input_schema.json
  
  - name: process_securely
    plugin: security_docker_sandbox
    config:
      plugin_path: plugs/data_processor
      function_name: process
      sandbox_config:
        isolation_level: strict
        resource_limits:
          memory_mb: 512
          cpu_limit: 1.0
          timeout_seconds: 300
        network_access:
          enabled: false
  
  - name: store_results
    plugin: database_writer
    config:
      connection: postgres_prod
```

## Monitoring and Observability

### Health Checks

```python
# Check Docker sandbox health
health = await sandbox.health_check()
print(f"Docker version: {health['docker_version']}")
print(f"Available images: {health['available_images']}")
```

### Execution Metrics

```python
# Execution statistics included in results
result = await sandbox.process(context, config)
stats = result.get('execution_stats', {})

print(f"Execution time: {stats['execution_time_seconds']:.2f}s")
print(f"Memory used: {stats['memory_used_mb']:.1f}MB")
print(f"CPU time: {stats['cpu_time_seconds']:.2f}s")
print(f"Exit code: {stats['exit_code']}")
```

### Integration with Monitoring Plugs

```yaml
# Monitor sandbox execution with Prometheus plugin
steps:
  - plugin: security_docker_sandbox
    config: {...}
    
  - plugin: prometheus_monitor
    config:
      metrics:
        - name: plugin_execution_time
          value: "{{ previous_step.execution_stats.execution_time_seconds }}"
        - name: plugin_memory_usage  
          value: "{{ previous_step.execution_stats.memory_used_mb }}"
```

## Security Considerations

### Container Escape Prevention
- Uses Docker's security options to prevent container escape
- Runs plugs as non-root user with minimal privileges
- Read-only filesystem prevents malicious file modifications

### Resource Protection
- Memory and CPU limits prevent resource exhaustion
- Execution timeouts prevent hanging processes
- Network isolation controls external communication

### Audit Trail Integration
```yaml
# Integrate with audit logging plugin
steps:
  - plugin: security_docker_sandbox
    config: {...}
    
  - plugin: security_audit_logger
    config:
      event_type: plugin_execution
      details:
        plugin: "{{ sandbox.plugin_path }}"
        execution_time: "{{ sandbox.execution_stats.execution_time_seconds }}"
        success: "{{ sandbox.success }}"
```

## Troubleshooting

### Common Issues

**Docker Not Available**
```
Error: Docker not available or not running
Solution: Ensure Docker is installed and running
```

**Image Not Found**
```
Error: Docker image not found: python:3.11-slim
Solution: Pull required image: docker pull python:3.11-slim
```

**Permission Denied**
```
Error: Permission denied accessing Docker socket
Solution: Add user to docker group or run with appropriate permissions
```

### Debug Mode

```yaml
# Enable verbose logging for troubleshooting
sandbox_config:
  debug: true
  preserve_containers: true  # Don't cleanup containers for inspection
```

## Architecture

This plugin follows PlugPipe's plugin-first security architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PlugPipe      │    │ Docker Sandbox   │    │ Docker Engine   │
│   Pipe      │───▶│ Plug           │───▶│ Container        │
│                 │    │                  │    │ Execution       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │
                                ▼
                       ┌──────────────────┐
                       │ Target Plug    │
                       │ Execution        │
                       │ (Isolated)       │
                       └──────────────────┘
```

## Contributing

This plugin demonstrates the PlugPipe principle of leveraging proven technology. When contributing:

1. **Maintain Docker Integration**: All enhancements should leverage Docker capabilities
2. **Security First**: Any changes must maintain or improve security posture
3. **Enterprise Compatibility**: Consider Docker Enterprise and Kubernetes integration
4. **Performance Optimization**: Monitor and optimize container startup time

## License

MIT License - see LICENSE file for details.

---

**PlugPipe Philosophy**: This plugin exemplifies "reuse, never reinvent" by leveraging Docker's proven container technology instead of building custom sandboxing mechanisms. By integrating with existing Docker infrastructure, we provide enterprise-grade security with battle-tested reliability.