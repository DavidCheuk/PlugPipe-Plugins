# MCPGovernance Plugin

**Enterprise Multi-Tenant Governance Platform for MCP Registries**

## Overview

MCPGovernance is a PlugPipe plugin that provides enterprise-grade multi-tenant governance for any MCP registry system. Following PlugPipe principles of **REUSE, NEVER REINVENT**, it integrates seamlessly into microservice architectures while maintaining universal compatibility.

## 🏗️ Microservice Architecture Integration

### Plugin-as-Microservice Design

MCPGovernance exemplifies PlugPipe's vision of plugins as microservices:

```
┌─────────────────────┐    ┌─────────────────────┐    ┌─────────────────────┐
│   PlugPipe Registry │    │   MCPGovernance     │    │   External MCP      │
│   Microservice      │◄──►│   Plugin/Service    │◄──►│   Registry          │
│   (Port 8080)       │    │   (Port 8090)       │    │   (Any Port)        │
└─────────────────────┘    └─────────────────────┘    └─────────────────────┘
          │                          │                          │
          └──────────────────────────┼──────────────────────────┘
                                     │
                            ┌─────────────────────┐
                            │   Policy Engine     │
                            │   (OPA - Port 8181) │
                            └─────────────────────┘
```

### Deployment Options

#### 1. **Docker Compose** (Development & Testing)
```bash
cd plugs/governance/mcpgovernance/1.0.0
docker-compose up -d
```

#### 2. **Kubernetes** (Production)
```bash
kubectl apply -f k8s-deployment.yaml
```

#### 3. **PlugPipe Plugin** (Integrated)
```bash
./pp run mcpgovernance
```

## 🔌 Universal Registry Integration

### Registry Abstraction Layer

MCPGovernance uses a universal adapter pattern to work with any registry:

```python
# PlugPipe Registry
adapter = RegistryAdapter('plugpipe', config)
plugins = await adapter.list_plugins()

# MCP Registry
adapter = RegistryAdapter('mcp', config)
tools = await adapter.list_plugins()

# Generic Registry
adapter = RegistryAdapter('generic', config)
resources = await adapter.list_plugins()
```

### Integration Points

1. **Authorization Middleware**: Intercepts all registry requests
2. **Plugin Filtering**: Applies tenant-specific access controls
3. **Audit Logging**: Comprehensive compliance tracking
4. **Performance Caching**: <1ms permission lookups

## 🚀 Quick Start

### 1. As a Microservice

```bash
# Start the complete governance stack
docker-compose up -d

# Access governance API
curl http://localhost:8090/governance/v1/authorize \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "tenant-alpha",
    "resource_id": "security_scanner",
    "operation": "read"
  }'
```

### 2. As a PlugPipe Plugin

```bash
# Run through PlugPipe
./pp run mcpgovernance

# Configure for your registry
export GOVERNANCE_PROVIDER=mcpgovernance
export GOVERNANCE_ENDPOINT=http://localhost:8090/governance/v1
```

## 📊 Performance Features

- **<1ms Permission Lookups**: Optimized caching system
- **Horizontal Scaling**: Kubernetes HPA with 3-10 replicas
- **Enterprise Monitoring**: Prometheus + Grafana integration
- **Zero-Downtime Deployment**: Rolling updates with health checks

## 🔒 Security Features

- **Multi-Tenant Isolation**: Complete tenant data separation
- **Policy-as-Code**: OPA integration for complex rules
- **Audit Compliance**: Comprehensive access logging
- **Zero-Trust Architecture**: All access explicitly authorized

## 🏢 Enterprise Integration

### Registry Service Integration

```python
# PlugPipe Registry Service Integration
class TenantAwareRegistryService:
    def __init__(self):
        self.governance = MCPGovernanceClient("http://mcpgovernance:8090")

    async def list_plugs(self, tenant_context):
        # Get all plugins
        plugins = await self.base_registry.list_plugs()

        # Apply governance filtering
        authorized_plugins = []
        for plugin in plugins:
            if await self.governance.authorize(tenant_context, plugin.id, "read"):
                authorized_plugins.append(plugin)

        return authorized_plugins
```

### Multi-Registry Support

```yaml
# Kubernetes ConfigMap
apiVersion: v1
kind: ConfigMap
metadata:
  name: registry-integration
data:
  registries.yaml: |
    registries:
      - name: "plugpipe-main"
        type: "plugpipe"
        endpoint: "http://plugpipe-registry:8080"
        governance_enabled: true

      - name: "external-mcp"
        type: "mcp"
        endpoint: "http://external-mcp:9000"
        governance_enabled: true

      - name: "legacy-system"
        type: "generic"
        endpoint: "http://legacy:8000"
        governance_enabled: false
```

## 🔧 Configuration

### Plugin Configuration (plug.yaml)

The plugin is fully configured through its manifest:

```yaml
name: mcpgovernance
version: 1.0.0
description: "Enterprise MCP Multi-Tenant Governance Platform"

# Microservice deployment ready
deployment:
  microservice: true
  scaling:
    horizontal: true
    max_instances: 10
  health_check:
    path: "/health"
    interval: 30

# Universal compatibility
compatibility:
  plugpipe_registry: ">=1.0.0"
  mcp_registry: ">=1.0.0"
  generic_registry: ">=1.0.0"
```

### Runtime Configuration

```yaml
server:
  host: "0.0.0.0"
  port: 8090
  workers: 4

database:
  type: "postgresql"
  connection_string: "postgresql://user:pass@postgres:5432/governance"

cache:
  redis_url: "redis://redis:6379/0"
  ttl_seconds: 300

opa_integration:
  enabled: true
  opa_server_url: "http://opa:8181"
  policy_bundle_path: "/policies"
```

## 📈 Monitoring & Observability

### Metrics Endpoints

- **Health**: `GET /health`
- **Readiness**: `GET /ready`
- **Metrics**: `GET /governance/v1/metrics`
- **Prometheus**: `GET /metrics` (standard format)

### Dashboard Integration

```bash
# Access Grafana dashboards
open http://localhost:3000
# Login: admin / governance123

# View Prometheus metrics
open http://localhost:9090
```

## 🔄 Smooth Migration Path

### Phase 0: P0 Tenant Isolation
- Basic tenant filtering
- Built-in governance rules
- SQLite for simplicity

### Phase 1: Plugin Integration
- Deploy MCPGovernance plugin
- Maintain P0 compatibility
- Add performance caching

### Phase 2: Enterprise Features
- OPA policy integration
- Advanced monitoring
- Multi-registry support

### Phase 3: Production Scale
- Kubernetes deployment
- Horizontal scaling
- Enterprise support

## 🧪 Testing

### Unit Tests
```bash
pytest tests/
```

### Integration Tests
```bash
# Start test environment
docker-compose -f docker-compose.test.yaml up -d

# Run integration tests
pytest tests/integration/
```

### Load Testing
```bash
# Test authorization performance
wrk -t12 -c400 -d30s --script=tests/load/auth_test.lua \
  http://localhost:8090/governance/v1/authorize
```

## 🎯 PlugPipe Spirit Compliance

✅ **REUSE**: Built on existing tenant isolation components
✅ **PLUGIN**: Standard PlugPipe plugin with plug.yaml manifest
✅ **MICROSERVICE**: Deployable as independent service
✅ **UNIVERSAL**: Works with any registry type
✅ **SIMPLE**: Single command deployment
✅ **INTEROPERABLE**: Standard REST API interfaces

## 📚 API Documentation

### Authorization Endpoint
```http
POST /governance/v1/authorize
Content-Type: application/json

{
  "tenant_id": "tenant-alpha",
  "resource_id": "security_scanner",
  "operation": "read",
  "registry_type": "plugpipe"
}
```

### Tenant Resources
```http
GET /governance/v1/tenants/{tenant_id}/resources?registry_type=plugpipe
```

### Configuration Validation
```http
POST /governance/v1/validate
Content-Type: application/json

{
  "configuration": {
    "tenants": {
      "tenant-alpha": {
        "plugins": ["security_scanner", "config_hardening"],
        "access_level": "read"
      }
    }
  }
}
```

## 🏭 Production Deployment

### Prerequisites
- Kubernetes cluster (1.19+)
- PostgreSQL database
- Redis instance
- OPA server (optional)

### Deployment
```bash
# Create namespace
kubectl create namespace plugpipe-governance

# Deploy secrets
kubectl apply -f k8s-secrets.yaml

# Deploy MCPGovernance
kubectl apply -f k8s-deployment.yaml

# Verify deployment
kubectl get pods -n plugpipe-governance
```

### Scaling
```bash
# Manual scaling
kubectl scale deployment mcpgovernance --replicas=5 -n plugpipe-governance

# Auto-scaling (HPA configured automatically)
kubectl get hpa -n plugpipe-governance
```

## 🤝 Contributing

MCPGovernance follows PlugPipe development principles:

1. **Convention Over Configuration**
2. **Plugin-First Architecture**
3. **Universal Compatibility**
4. **Performance by Default**
5. **Enterprise Ready**

## 📄 License

MIT License - Universal compatibility with enterprise systems

---

**MCPGovernance: Where PlugPipe Plugins Meet Enterprise Governance** 🚀