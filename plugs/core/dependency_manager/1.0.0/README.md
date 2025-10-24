# PlugPipe Dependency Management

Comprehensive guide for managing external dependencies in PlugPipe plugins.

## Overview

PlugPipe provides automatic dependency management to ensure all external packages, binaries, and system dependencies are properly installed when developers download and use plugins.

## For Plugin Developers

### 1. Declaring Dependencies in Plugin Manifests

Add external dependencies to your `plug.yaml` manifest:

```yaml
# External dependencies (managed automatically)
external_dependencies:
  - name: trivy
    type: binary
    version: "0.65.0"
    required: true
    description: "Aqua Security Trivy vulnerability scanner"
    install_method: curl
    url: "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"

  - name: requests
    type: python
    version: "2.28.0"
    required: true
    description: "HTTP library for Python"

  - name: docker
    type: system
    required: true
    description: "Docker container platform"

# Plugin dependencies (other PlugPipe plugins)
dependencies:
  - name: dependency_manager
    version: "1.0.0"
    required: false  # graceful degradation
```

### 2. Dependency Types Supported

| Type | Description | Examples |
|------|-------------|----------|
| `binary` | Standalone executables | trivy, kubectl, helm |
| `python` | Python packages (pip) | requests, pandas, numpy |
| `system` | System packages (apt) | docker, git, curl |
| `npm` | Node.js packages | typescript, eslint |
| `docker` | Docker images | nginx, postgres |
| `go` | Go binaries | go install packages |

### 3. Using Dependency Manager in Plugin Code

```python
def _initialize_environment(self):
    """Initialize plugin with automatic dependency management."""
    try:
        # Check if dependency is available
        result = subprocess.run([self.binary_path, "--version"], 
                              capture_output=True, text=True, timeout=10)
        
        if result.returncode != 0:
            # Try to install using dependency manager
            install_result = self._install_dependencies()
            if not install_result.get('success', False):
                raise RuntimeError(f"Failed to install dependencies")
                
            # Retry check
            result = subprocess.run([self.binary_path, "--version"],
                                  capture_output=True, text=True, timeout=10)
            if result.returncode != 0:
                raise RuntimeError("Installation succeeded but binary not working")
        
        logger.info(f"Using {result.stdout.strip()}")
        
    except Exception as e:
        raise RuntimeError(f"Failed to initialize environment: {str(e)}")

def _install_dependencies(self):
    """Install dependencies using PlugPipe dependency manager"""
    try:
        from shares.loader import pp
        dependency_manager = pp('dependency_manager')
        
        # Define dependencies
        deps = {
            'dependencies': [{
                'name': 'trivy',
                'type': 'binary', 
                'version': '0.65.0',
                'required': True
            }]
        }
        
        return dependency_manager.process(deps, {})
        
    except Exception as e:
        logger.error(f"Failed to use dependency manager: {e}")
        return {'success': False, 'error': str(e)}
```

## For Plugin Users/Developers

### 1. Automatic Installation Script

Install all plugin dependencies at once:

```bash
# Install dependencies for all plugins
./scripts/install_plugin_dependencies.sh --all

# Install dependencies for specific plugin
./scripts/install_plugin_dependencies.sh security_docker_trivy

# Check system requirements
./scripts/install_plugin_dependencies.sh --check
```

### 2. Manual Dependency Management

Use the dependency manager plugin directly:

```bash
# Install dependencies using PlugPipe CLI
./pp run dependency_manager --context '{
  "dependencies": [
    {
      "name": "trivy",
      "type": "binary", 
      "version": "0.65.0",
      "required": true
    }
  ]
}'
```

### 3. Checking Plugin Dependencies

Before using a plugin, check what dependencies it needs:

```bash
# Check plugin manifest for dependencies
cat plugs/security_docker_trivy/1.0.0/plug.yaml | grep -A 10 "external_dependencies"
```

## Dependency Installation Methods

### Binary Dependencies

Supported installation methods:
- **curl**: Download from URL with install script
- **github**: Download from GitHub releases
- **direct**: Direct download and install
- **package**: Use system package manager

Example configurations:

```yaml
# Trivy (using install script)
- name: trivy
  type: binary
  install_method: curl
  url: "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh"

# kubectl (direct download)
- name: kubectl
  type: binary
  install_method: direct
  url: "https://dl.k8s.io/release/v1.28.0/bin/linux/amd64/kubectl"
  install_path: "/home/david/.local/bin/kubectl"
```

### Python Dependencies

Installed using pip with version pinning:

```yaml
- name: requests
  type: python
  version: "2.28.0"
  required: true
```

### System Dependencies

Installed using system package manager (apt on Ubuntu):

```yaml
- name: docker
  type: system
  required: true
  description: "Docker container platform"
```

### Docker Dependencies

Pull Docker images:

```yaml
- name: nginx
  type: docker
  tag: "alpine"
  required: true
```

## Best Practices

### 1. Plugin Development
- Always declare external dependencies in `plug.yaml`
- Include the `dependency_manager` plugin as a non-required dependency
- Implement graceful degradation when dependencies fail
- Use full paths for binaries to avoid PATH issues
- Test plugins with and without dependencies installed

### 2. Version Management
- Pin specific versions for production plugins
- Use version ranges for development (`>=1.0.0`)
- Test compatibility with multiple versions
- Document version requirements clearly

### 3. Error Handling
- Provide clear error messages when dependencies missing
- Implement fallback mechanisms where possible
- Log dependency installation attempts
- Fail gracefully with helpful suggestions

### 4. Security Considerations
- Verify checksums for downloaded binaries
- Use HTTPS URLs for all downloads
- Validate installation success before proceeding
- Avoid running unverified scripts

## Troubleshooting

### Common Issues

1. **Binary not found after installation**
   - Check PATH configuration
   - Use full paths in plugin code
   - Verify installation location

2. **Permission errors**
   - Ensure install directory is writable
   - Use user-local paths (~/.local/bin)
   - Check sudo requirements

3. **Network connectivity issues**
   - Implement timeout handling
   - Provide offline alternatives
   - Cache downloaded files

4. **Version conflicts**
   - Use virtual environments for Python
   - Pin exact versions
   - Test with multiple versions

### Debug Commands

```bash
# Check what dependencies are needed
./pp list | grep -i trivy

# Test dependency installation
./pp run dependency_manager --verbose

# Check installed binaries
which trivy
trivy --version

# Verify plugin works
./pp run security_docker_trivy
```

## Integration with CI/CD

### GitHub Actions

```yaml
name: Install Plugin Dependencies
steps:
  - name: Install PlugPipe Dependencies
    run: |
      cd PlugPipe
      ./scripts/install_plugin_dependencies.sh --all
      
  - name: Verify Dependencies
    run: |
      trivy --version
      kubectl version --client
```

### Docker Integration

```dockerfile
FROM ubuntu:22.04

# Install PlugPipe
COPY . /plugpipe
WORKDIR /plugpipe

# Install all plugin dependencies
RUN ./scripts/install_plugin_dependencies.sh --all

# Verify installation
RUN ./pp list && trivy --version
```

## Future Enhancements

- Support for Homebrew on macOS
- Windows package manager support
- Dependency caching and offline mode
- Version conflict resolution
- Dependency graph visualization
- Automatic security updates

This dependency management system ensures that PlugPipe plugins are truly portable and self-contained, eliminating the "works on my machine" problem for external dependencies.