# Prometheus Monitoring Plug

## Overview

The Prometheus Monitoring Plug demonstrates PlugPipe's core principle **"reuse, never reinvent"** by leveraging the Prometheus ecosystem's proven monitoring and observability stack instead of implementing custom metrics collection and visualization systems.

## Philosophy: Industry-Standard Observability

This plugin exemplifies the PlugPipe approach to monitoring and observability:

✅ **Reuse Proven Monitoring**: Prometheus provides industry-standard metrics collection and storage  
✅ **Never Reinvent Observability**: Instead of custom dashboards, we integrate with Grafana's proven visualization  
✅ **Ecosystem Integration**: Works with existing Prometheus, Grafana, and Alertmanager infrastructure  
✅ **Community Validated**: Leverages the massive Prometheus community and ecosystem  

## Features

### 📊 **Industry-Standard Metrics Collection**
- **Prometheus Client**: Official Prometheus Python client for metrics collection
- **Multiple Metric Types**: Counters, Gauges, Histograms, and Summaries
- **Label Support**: Rich dimensional metrics with custom labels
- **Pushgateway Integration**: Push-based metrics for batch jobs and short-lived processes

### 📈 **Powerful Querying and Alerting**
- **PromQL Queries**: Execute powerful Prometheus Query Language queries
- **Time Series Data**: Range queries with configurable time windows
- **Alert Rules**: Create and manage Prometheus alert rules
- **Webhook Integration**: Alert notifications via webhooks and external systems

### 🎨 **Grafana Integration**
- **Dashboard Management**: Integration with Grafana for visualization
- **Template Dashboards**: Pre-built dashboards for PlugPipe monitoring
- **API Integration**: Grafana API for programmatic dashboard management
- **Multi-Tenant Support**: Organization-based isolation in Grafana

### ⚙️ **Enterprise Features**
- **High Availability**: Prometheus federation and clustering support
- **Remote Storage**: Integration with long-term storage solutions
- **Service Discovery**: Automatic target discovery for scraping
- **Security Integration**: Authentication and authorization support

## Configuration

### Basic Usage

```yaml
# Pipe step using Prometheus monitoring
steps:
  - plugin: monitoring_prometheus
    config:
      operation: "record_metric"
      metric_name: "plugpipe_pipeline_duration"
      metric_value: 45.2
      metric_type: "histogram"
      labels:
        pipeline_name: "data_processing"
        status: "success"
```

### Advanced Configuration

```yaml
# Production Prometheus configuration
prometheus_config:
  prometheus_url: "https://prometheus.company.com:9090"
  gateway_url: "https://pushgateway.company.com:9091"  
  grafana_url: "https://grafana.company.com:3000"
  job_name: "plugpipe-production"
  instance: "${HOSTNAME}"

# Alert configuration
alert_config:
  alert_name: "PlugPipe High Error Rate"
  expression: "rate(plugpipe_plugin_errors_total[5m]) > 0.1"
  duration: "2m"
  severity: "warning"
  webhook_url: "https://alerts.company.com/webhook"
```

### Environment-Specific Templates

#### Development
```yaml
prometheus_config:
  gateway_url: "http://127.0.0.1:9091"
  prometheus_url: "http://127.0.0.1:9090"
  grafana_url: "http://127.0.0.1:3000"
  job_name: "plugpipe-dev"
scrape_interval: "5s"
```

#### Production
```yaml
prometheus_config:
  gateway_url: "${PUSHGATEWAY_URL}"
  prometheus_url: "${PROMETHEUS_URL}"
  grafana_url: "${GRAFANA_URL}"
  job_name: "plugpipe-prod"
  instance: "${INSTANCE_ID}"
enable_alerting: true
scrape_interval: "15s"
```

## Supported Operations

### Metric Recording

```python
# Record counter metric
counter_result = await prometheus.process({
    "operation": "record_counter",
    "metric_name": "plugpipe_requests_total",
    "metric_value": 1,
    "labels": {"endpoint": "/api/plugs", "method": "GET"}
}, config)

# Record gauge metric  
gauge_result = await prometheus.process({
    "operation": "record_gauge",
    "metric_name": "plugpipe_active_connections",
    "metric_value": 127
}, config)

# Record histogram metric
histogram_result = await prometheus.process({
    "operation": "record_histogram", 
    "metric_name": "plugpipe_request_duration_seconds",
    "metric_value": 0.045,
    "labels": {"handler": "plugin_executor"}
}, config)
```

### Metric Querying

```python
# Instant query
query_result = await prometheus.process({
    "operation": "query_metrics",
    "query": "rate(plugpipe_plugin_executions_total[5m])"
}, config)

# Range query
range_result = await prometheus.process({
    "operation": "query_metrics", 
    "query": "plugpipe_memory_usage_bytes",
    "time_range": {
        "start": "2024-01-01T00:00:00Z",
        "end": "2024-01-01T23:59:59Z", 
        "step": "1m"
    }
}, config)
```

### Alert Management

```python
# Create alert rule
alert_result = await prometheus.process({
    "operation": "create_alert",
    "alert_config": {
        "alert_name": "PlugPipe Memory High",
        "expression": "plugpipe_memory_usage_bytes > 1e9",
        "duration": "5m",
        "severity": "warning",
        "annotations": {
            "summary": "PlugPipe memory usage is high",
            "description": "Memory usage has been above 1GB for 5 minutes"
        },
        "webhook_url": "https://alerts.example.com/webhook"
    }
}, config)
```

## Prometheus Integration

### Server Configuration

```yaml
# prometheus.yml - Prometheus server configuration
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "plugpipe_alerts.yml"

scrape_configs:
  - job_name: 'plugpipe'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'
    scrape_interval: 15s

  - job_name: 'pushgateway'
    static_configs:
      - targets: ['localhost:9091']
```

### Alert Rules

```yaml
# plugpipe_alerts.yml - PlugPipe alert rules
groups:
  - name: plugpipe
    rules:
      - alert: PlugPipeHighErrorRate
        expr: rate(plugpipe_plugin_errors_total[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High plugin error rate"
          description: "Error rate is {{ $value }} errors/sec"

      - alert: PlugPipeMemoryHigh  
        expr: plugpipe_memory_usage_bytes / (1024*1024*1024) > 0.8
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High memory usage"
          description: "Memory usage is {{ $value }}GB"
```

## Installation

### Prerequisites

```bash
# Install Prometheus
wget https://github.com/prometheus/prometheus/releases/download/v2.40.0/prometheus-2.40.0.linux-amd64.tar.gz
tar xvfz prometheus-*.tar.gz
cd prometheus-*
./prometheus --config.file=prometheus.yml

# Install Grafana
wget -q -O - https://packages.grafana.com/gpg.key | sudo apt-key add -
echo "deb https://packages.grafana.com/oss/deb stable main" | sudo tee -a /etc/apt/sources.list.d/grafana.list
sudo apt-get update && sudo apt-get install grafana

# Install Pushgateway (optional)
wget https://github.com/prometheus/pushgateway/releases/download/v1.5.0/pushgateway-1.5.0.linux-amd64.tar.gz
tar xvfz pushgateway-*.tar.gz
cd pushgateway-*
./pushgateway
```

### Plug Installation

```bash
# Install Python dependencies
pip install prometheus-client>=0.15.0 requests>=2.25.0 grafana-api>=1.0.3

# Install via PlugPipe CLI
plugpipe install monitoring_prometheus

# Or clone manually
git clone https://github.com/plugpipe/plugs/monitoring_prometheus
```

## Usage Examples

### Basic Pipe Monitoring

```yaml
# pipeline.yaml - Pipe with monitoring
name: monitored_data_pipeline
steps:
  - name: record_start_metric
    plugin: monitoring_prometheus
    config:
      operation: record_counter
      metric_name: plugpipe_pipeline_starts_total
      metric_value: 1
      labels:
        pipeline_name: "data_pipeline"
  
  - name: process_data
    plugin: data_processor
    config:
      data_source: input.json
  
  - name: record_completion_metric
    plugin: monitoring_prometheus
    config:
      operation: record_histogram
      metric_name: plugpipe_pipeline_duration_seconds
      metric_value: "{{ pipeline.duration_seconds }}"
      labels:
        pipeline_name: "data_pipeline"
        status: "{{ previous_step.success | ternary('success', 'failed') }}"
```

### Security Monitoring Integration

```python
# Monitor security events with Prometheus
import asyncio
from plugpipe import load_plugin

async def monitor_security_event(event_type: str, user_id: str, success: bool):
    prometheus = await load_plugin("monitoring_prometheus")
    
    # Record authentication attempt
    await prometheus.process({
        "operation": "record_counter",
        "metric_name": "plugpipe_auth_attempts_total",
        "metric_value": 1,
        "labels": {
            "method": event_type,
            "status": "success" if success else "failure",
            "user_id": user_id
        }
    }, config)
    
    # Alert on high failure rate
    if not success:
        await prometheus.process({
            "operation": "create_alert",
            "alert_config": {
                "alert_name": "High Auth Failure Rate",
                "expression": f"rate(plugpipe_auth_attempts_total{{status='failure'}}[5m]) > 0.1",
                "duration": "2m",
                "severity": "warning"
            }
        }, config)
```

### Custom Metrics Dashboard

```python
# Create custom Grafana dashboard
dashboard_config = {
    "dashboard": {
        "title": "PlugPipe Plug Performance",
        "panels": [
            {
                "title": "Plug Execution Rate",
                "type": "graph",
                "targets": [
                    {
                        "expr": "rate(plugpipe_plugin_executions_total[5m])",
                        "legendFormat": "{{plugin_name}}"
                    }
                ]
            },
            {
                "title": "Plug Duration",
                "type": "graph", 
                "targets": [
                    {
                        "expr": "histogram_quantile(0.95, rate(plugpipe_plugin_duration_seconds_bucket[5m]))",
                        "legendFormat": "95th percentile"
                    }
                ]
            }
        ]
    }
}
```

## Grafana Dashboard Templates

### System Overview Dashboard

```json
{
  "dashboard": {
    "title": "PlugPipe System Overview",
    "panels": [
      {
        "title": "System Uptime",
        "type": "stat",
        "targets": [{"expr": "plugpipe_system_uptime_seconds"}]
      },
      {
        "title": "Memory Usage",
        "type": "graph",
        "targets": [{"expr": "plugpipe_memory_usage_bytes / (1024*1024*1024)"}]
      },
      {
        "title": "Plug Execution Rate", 
        "type": "graph",
        "targets": [{"expr": "rate(plugpipe_plugin_executions_total[5m])"}]
      },
      {
        "title": "Error Rate by Plug",
        "type": "table",
        "targets": [{"expr": "rate(plugpipe_plugin_errors_total[5m]) by (plugin_name)"}]
      }
    ]
  }
}
```

### Security Monitoring Dashboard

```json
{
  "dashboard": {
    "title": "PlugPipe Security Monitoring",
    "panels": [
      {
        "title": "Authentication Attempts",
        "type": "graph", 
        "targets": [{"expr": "rate(plugpipe_auth_attempts_total[5m]) by (status)"}]
      },
      {
        "title": "Capability Violations",
        "type": "graph",
        "targets": [{"expr": "rate(plugpipe_capability_violations_total[5m])"}]
      },
      {
        "title": "Failed Logins by Method",
        "type": "pie",
        "targets": [{"expr": "sum(rate(plugpipe_auth_attempts_total{status='failure'}[1h])) by (method)"}]
      }
    ]
  }
}
```

## Monitoring and Alerting

### Health Checks

```python
# Check monitoring infrastructure health
health = await prometheus.health_check()
print(f"Prometheus: {health['result']['prometheus_status']}")
print(f"Grafana: {health['result']['grafana_status']}")
print(f"Pushgateway: {health['result']['pushgateway_status']}")
```

### Performance Monitoring

```python
# Monitor plugin performance
async def monitor_plugin_execution(plugin_name: str, duration: float, success: bool):
    prometheus = await load_plugin("monitoring_prometheus")
    
    # Record execution
    await prometheus.process({
        "operation": "record_counter",
        "metric_name": "plugpipe_plugin_executions_total", 
        "metric_value": 1,
        "labels": {"plugin_name": plugin_name, "status": "success" if success else "error"}
    }, config)
    
    # Record duration
    await prometheus.process({
        "operation": "record_histogram",
        "metric_name": "plugpipe_plugin_duration_seconds",
        "metric_value": duration,
        "labels": {"plugin_name": plugin_name}
    }, config)
```

## Troubleshooting

### Common Issues

**Prometheus Not Reachable**
```
Error: Monitoring operation failed: HTTPConnectionPool(host='127.0.0.1', port=9090)
Solution: Ensure Prometheus server is running on configured URL
```

**Pushgateway Connection Failed**
```
Error: Failed to push metrics to gateway
Solution: Check pushgateway_url configuration and network connectivity
```

**Grafana API Authentication**
```
Error: 401 Unauthorized
Solution: Configure grafana_auth with valid API key or credentials
```

### Debug Mode

```yaml
# Enable debug logging
prometheus_config:
  debug: true
mock_mode: true  # Use mock for development
```

### Prometheus Logs

```bash
# Check Prometheus server logs
journalctl -u prometheus -f

# Check Pushgateway logs  
journalctl -u pushgateway -f

# Check metric ingestion
curl http://localhost:9090/api/v1/query?query=up
```

## Architecture

This plugin follows PlugPipe's plugin-first monitoring architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PlugPipe      │    │ Prometheus       │    │ Prometheus      │
│   Pipe      │───▶│ Plug           │───▶│ Server          │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Metrics          │    │ Grafana         │
                       │ Collection       │    │ Dashboards      │
                       │                  │    │                 │
                       └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Pushgateway      │    │ Alertmanager    │
                       │ (Optional)       │    │ (Optional)      │
                       └──────────────────┘    └─────────────────┘
```

## Contributing

This plugin demonstrates the PlugPipe principle of leveraging proven technology. When contributing:

1. **Maintain Prometheus Integration**: All enhancements should leverage Prometheus capabilities
2. **Follow Prometheus Best Practices**: Use appropriate metric types and naming conventions
3. **Grafana Compatibility**: Ensure dashboard templates work with current Grafana versions  
4. **Performance Optimization**: Monitor and optimize metric collection overhead

## License

MIT License - see LICENSE file for details.

---

**PlugPipe Philosophy**: This plugin exemplifies "reuse, never reinvent" by leveraging the Prometheus ecosystem's proven monitoring and observability stack instead of implementing custom metrics collection and visualization systems. By integrating with existing Prometheus and Grafana infrastructure, we provide industry-standard observability with battle-tested reliability and rich ecosystem support.