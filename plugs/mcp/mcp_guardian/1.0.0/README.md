# MCP Guardian - Enterprise Security Proxy

MCP Guardian is a comprehensive security proxy for the Model Context Protocol (MCP), designed to provide enterprise-grade security between load balancers and MCP servers/clients. It implements a hybrid architecture combining PlugPipe plugin orchestration with FastAPI microservice capabilities.

## Overview

MCP Guardian serves as a critical security layer in enterprise MCP deployments, orchestrating multiple security plugins to provide comprehensive threat detection, data loss prevention, and compliance validation for MCP traffic.

### Key Features

- **Enterprise Security Proxy**: Sits between load balancer and MCP infrastructure
- **Comprehensive Plugin Orchestration**: Integrates 12+ security plugins
- **Multi-Mode Deployment**: Plugin mode and microservice mode
- **Enterprise Authentication**: OAuth 2.1, mTLS, API key support
- **Multi-Tenant Architecture**: Strict tenant isolation and resource management
- **Real-Time Threat Detection**: Advanced AI/ML-based security analysis
- **Performance Optimized**: <5ms latency, 1000+ RPS throughput
- **Cloud-Native**: Full Kubernetes and container support

## Architecture

### Hybrid Plugin-Microservice Design

```
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   Load Balancer │───►│  MCP Guardian   │───►│   MCP Server    │
└─────────────────┘    │                 │    └─────────────────┘
                       │ ┌─────────────┐ │
                       │ │ FastAPI     │ │
                       │ │ Wrapper     │ │
                       │ └─────────────┘ │
                       │ ┌─────────────┐ │
                       │ │ PlugPipe    │ │
                       │ │ Engine      │ │
                       │ └─────────────┘ │
                       │ ┌─────────────┐ │
                       │ │ Security    │ │
                       │ │ Plugins     │ │
                       │ └─────────────┘ │
                       └─────────────────┘
```

### Security Plugin Integration

MCP Guardian orchestrates the following security plugins:

#### Core Plugins (Required)
- **open_appsec**: Advanced prompt injection protection
- **presidio_dlp**: Data loss prevention and PII detection
- **cyberpig_ai**: Secret and credential scanning
- **enhanced_mcp_schema_validation**: MCP protocol schema validation
- **mcp_security_policy_engine**: Policy-based access control

#### Advanced Plugins (Optional)
- **garak_scanner**: LLM vulnerability scanning
- **llm_guard**: AI model security assessment
- **mcp_security_middleware**: Advanced middleware security
- **enhanced_mcp_audit_integration**: Comprehensive audit logging
- **mcp_comprehensive_security_tester**: Security testing and validation
- **mcp_security_attack_simulator**: Attack simulation and testing
- **mcp_security_compliance_validator**: Compliance validation

## Installation & Deployment

### Prerequisites

- Python 3.11+
- Docker and Kubernetes (for container deployment)
- Redis (optional, for caching)
- OAuth 2.1 provider (for enterprise authentication)

### PlugPipe Plugin Installation

```bash
# Install via PlugPipe
./pp install mcp_guardian

# Run in plugin mode
./pp run mcp_guardian --config config.json
```

### Microservice Deployment

#### Docker Deployment

```bash
# Build container
docker build -t mcp-guardian:1.0.0 .

# Run container
docker run -d \
  --name mcp-guardian \
  -p 8080:8080 \
  -p 9090:9090 \
  -v /path/to/config.json:/app/config/config.json \
  mcp-guardian:1.0.0
```

#### Kubernetes Deployment

```bash
# Deploy to Kubernetes
kubectl apply -f k8s-deployment.yaml

# Check deployment status
kubectl get pods -n mcp-system -l app=mcp-guardian

# Check service endpoints
kubectl get svc -n mcp-system mcp-guardian
```

## Configuration

### Basic Configuration

```json
{
  "proxy_mode": "load_balancer",
  "upstream_mcp_server": "http://mcp-server:8000",
  "security_profile": "standard",
  
  "server": {
    "bind_host": "0.0.0.0",
    "bind_port": 8080,
    "max_concurrent_requests": 1000,
    "request_timeout": 30.0
  },
  
  "authentication": {
    "oauth2_enabled": true,
    "oauth2_issuer_url": "https://auth.example.com",
    "oauth2_client_id": "mcp-guardian"
  },
  
  "security": {
    "security_plugin_timeout": 5.0,
    "threat_score_threshold": 0.7,
    "rate_limiting_enabled": true
  }
}
```

### Security Profiles

#### Basic Profile
- Request validation
- Response filtering
- Basic threat detection
- Audit logging

#### Standard Profile (Recommended)
- Advanced threat detection
- Content filtering
- Prompt injection protection
- Data loss prevention
- Secret scanning
- Schema validation

#### Enterprise Profile
- Full security suite
- Behavioral analysis
- ML threat detection
- Compliance validation
- Attack simulation testing
- Advanced audit integration

### Environment Variables

```bash
# Core configuration
MCP_GUARDIAN_CONFIG=/app/config/config.json
MCP_GUARDIAN_LOG_LEVEL=INFO

# Authentication
OAUTH2_CLIENT_SECRET=your-client-secret-here
OAUTH2_ISSUER_URL=https://auth.example.com

# Caching (optional)
REDIS_URL=redis://redis:6379/0

# Monitoring
PROMETHEUS_METRICS_PORT=9090
```

## Usage

### Plugin Mode

```python
from main import process

# Configure MCP Guardian
input_data = {
    "mode": "plugin",
    "config": {
        "upstream_mcp_server": "http://localhost:8000",
        "security_profile": "standard"
    }
}

# Run security processing
result = await process(input_data)
print(f"Status: {result['status']}")
```

### Microservice Mode

```python
from main import create_fastapi_app
import uvicorn

# Create FastAPI app
config = {
    "upstream_mcp_server": "http://mcp-server:8000",
    "security_profile": "enterprise"
}

app = create_fastapi_app(config)

# Run server
uvicorn.run(app, host="0.0.0.0", port=8080)
```

### API Endpoints

#### Health Check
```bash
GET /health
```

Response:
```json
{
  "status": "healthy",
  "timestamp": 1699123456.789,
  "version": "1.0.0"
}
```

#### Metrics
```bash
GET /metrics
```

Returns Prometheus metrics in text format.

#### Proxy Endpoints
All other requests are proxied through the security pipeline:
```bash
POST /api/v1/mcp-request
GET /api/v1/mcp-status
# ... any MCP endpoint
```

## Security Features

### Threat Detection

MCP Guardian provides comprehensive threat detection including:

- **Prompt Injection**: Advanced detection of prompt manipulation attempts
- **Command Injection**: SQL injection, OS command injection prevention
- **Data Exfiltration**: PII detection and data loss prevention
- **Secret Exposure**: Credential and API key scanning
- **Protocol Attacks**: MCP-specific attack pattern detection
- **Behavioral Analysis**: Anomaly detection and user behavior analysis

### Access Control

- **OAuth 2.1 Compliance**: Full OAuth 2.1 resource server implementation
- **Multi-Tenant Support**: Strict tenant isolation and resource management
- **RBAC/ABAC**: Role-based and attribute-based access control
- **API Key Management**: Legacy API key support and management
- **mTLS Support**: Mutual TLS for service-to-service authentication

### Compliance

MCP Guardian supports multiple compliance frameworks:

- **OWASP LLM Top 10 2025**: Comprehensive coverage of LLM security risks
- **ISO 27001**: Information security management standards
- **SOC 2 Type II**: Service organization control standards
- **GDPR**: European data protection regulation compliance
- **HIPAA**: Healthcare information privacy and security

## Monitoring & Observability

### Prometheus Metrics

```
# Request metrics
mcp_guardian_requests_total{method, status}
mcp_guardian_request_duration_seconds

# Security metrics
mcp_guardian_security_events_total{action}
mcp_guardian_security_pipeline_duration_seconds

# System metrics
mcp_guardian_active_connections
```

### Structured Logging

```json
{
  "timestamp": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "logger": "mcp_guardian.engine",
  "request_id": "req_1699123456789",
  "tenant_id": "tenant_1",
  "action": "BLOCK",
  "security_score": 0.85,
  "threats_detected": 1,
  "plugin_results": {...}
}
```

### Health Checks

Kubernetes-ready health checks:
- **Liveness**: Basic service health
- **Readiness**: Security plugin availability
- **Startup**: Initial configuration validation

## Performance

### Performance Targets

- **Latency**: <5ms added latency (95th percentile)
- **Throughput**: 1000+ requests/second per instance
- **Concurrency**: 1000+ concurrent connections
- **Memory**: <2GB per instance
- **CPU**: <2 cores under normal load

### Optimization Features

- **Async Processing**: Full asyncio-based processing pipeline
- **Plugin Parallelization**: Concurrent security plugin execution
- **Connection Pooling**: Optimized upstream connections
- **Result Caching**: Redis-based security result caching
- **Request Batching**: Efficient request aggregation

## Testing

### Running Tests

```bash
# Install test dependencies
pip install -r requirements.txt
pip install pytest pytest-asyncio

# Run test suite
python -m pytest test_mcp_guardian.py -v --asyncio-mode=auto

# Run specific test categories
pytest test_mcp_guardian.py::TestSecurityPluginOrchestrator -v
pytest test_mcp_guardian.py::TestPerformance -v
```

### Test Categories

- **Unit Tests**: Individual component testing
- **Integration Tests**: End-to-end security pipeline testing
- **Performance Tests**: Load testing and benchmark validation
- **Security Tests**: Threat detection accuracy validation

## Development

### Development Setup

```bash
# Clone PlugPipe repository
git clone https://github.com/your-org/plugpipe.git
cd plugpipe

# Install development dependencies
pip install -r plugs/mcp/mcp_guardian/1.0.0/requirements.txt

# Run in development mode
python plugs/mcp/mcp_guardian/1.0.0/main.py --config config.json
```

### Plugin Development

To extend MCP Guardian with custom security plugins:

1. Create plugin in `plugs/security/your_plugin/1.0.0/`
2. Implement standard PlugPipe plugin interface
3. Add plugin dependency to `plug.yaml`
4. Configure plugin in security profile

### Contributing

1. Fork the repository
2. Create feature branch
3. Implement changes with tests
4. Submit pull request with documentation

## Troubleshooting

### Common Issues

#### Plugin Loading Errors
```bash
# Check plugin availability
./pp list | grep security

# Verify plugin configuration
./pp run your_security_plugin --test
```

#### Authentication Issues
```bash
# Verify OAuth 2.1 configuration
curl -H "Authorization: Bearer $TOKEN" http://localhost:8080/health

# Check token validation
./pp run auth_jwt_manager --verify-token $TOKEN
```

#### Performance Issues
```bash
# Monitor metrics
curl http://localhost:9090/metrics | grep mcp_guardian

# Check resource usage
kubectl top pods -n mcp-system -l app=mcp-guardian
```

### Debugging

Enable debug logging:
```json
{
  "monitoring": {
    "log_level": "DEBUG",
    "structured_logging": true
  },
  "deployment": {
    "debug": true
  }
}
```

## Security Considerations

### Deployment Security

- Run as non-root user in containers
- Use read-only root filesystem
- Implement network policies
- Regular security scanning
- Secret management via Kubernetes secrets

### Plugin Security

- Plugin sandboxing and isolation
- Timeout protection
- Resource limits
- Error handling and recovery

## Roadmap

### Phase 1 (Current) - Core Implementation
- ✅ Hybrid plugin-microservice architecture
- ✅ Core security plugin integration
- ✅ Basic enterprise features
- ✅ Container deployment

### Phase 2 (Q2 2025) - Advanced Features
- 🔄 Advanced multi-tenant architecture
- 🔄 Enhanced monitoring and observability
- 🔄 Service mesh integration
- 🔄 Advanced policy management

### Phase 3 (Q3-Q4 2025) - Enterprise Enhancement
- ⏳ Machine learning threat detection
- ⏳ Advanced compliance reporting
- ⏳ Enterprise integration APIs
- ⏳ Performance optimization

## Support

- **Documentation**: [PlugPipe MCP Guardian Docs](docs/)
- **Issues**: [GitHub Issues](https://github.com/your-org/plugpipe/issues)
- **Security**: [Security Policy](SECURITY.md)
- **License**: [MIT License](LICENSE)

---

**MCP Guardian v1.0.0** - Enterprise Security Proxy for Model Context Protocol  
© 2024 PlugPipe Security Team