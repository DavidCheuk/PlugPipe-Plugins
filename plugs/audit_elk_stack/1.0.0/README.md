# ELK Stack Audit Logging Plug

## Overview

The ELK Stack Audit Logging Plug demonstrates PlugPipe's core principle **"reuse, never reinvent"** by leveraging the ELK Stack's proven enterprise logging and analytics platform instead of implementing custom audit logging and log management systems.

## Philosophy: Enterprise Log Management

This plugin exemplifies the PlugPipe approach to audit logging and log management:

✅ **Reuse Proven Logging**: ELK Stack provides enterprise-scale log ingestion, processing, and analytics  
✅ **Never Reinvent Log Management**: Instead of custom logging, we integrate with Elasticsearch, Logstash, and Kibana  
✅ **Ecosystem Integration**: Works with existing enterprise logging infrastructure and SIEM systems  
✅ **Battle-Tested Analytics**: Leverages ELK Stack's proven search, analytics, and visualization capabilities  

## Features

### 📊 **Enterprise-Scale Log Management**
- **Elasticsearch**: Distributed, real-time search and analytics engine
- **Logstash**: Centralized logging with data processing and transformation
- **Kibana**: Rich visualization and dashboard platform
- **Beats**: Lightweight data shippers for log collection

### 🔍 **Advanced Search and Analytics**
- **Real-Time Search**: Lightning-fast queries across massive log datasets
- **Full-Text Search**: Powerful text search with relevance scoring
- **Aggregations**: Statistical analysis and data summarization
- **Machine Learning**: Anomaly detection and pattern recognition

### 📈 **Rich Visualization and Dashboards**
- **Interactive Dashboards**: Real-time monitoring and analysis dashboards
- **Custom Visualizations**: Charts, graphs, maps, and custom visuals
- **Alerting**: Proactive notification on critical events and thresholds
- **Reporting**: Automated report generation and distribution

### 🛡️ **Security and Compliance**
- **Audit Trails**: Comprehensive logging for compliance and security
- **Access Controls**: Role-based access control and security features
- **Data Encryption**: Encryption at rest and in transit
- **Retention Policies**: Automated data lifecycle management

### ⚙️ **Enterprise Integration**
- **SIEM Integration**: Works with security information and event management systems
- **API Access**: REST APIs for programmatic log management
- **Multi-Tenant**: Index-level isolation for organizational separation
- **High Availability**: Clustering and failover support

## Configuration

### Basic Usage

```yaml
# Pipe step using ELK Stack audit logging
steps:
  - plugin: audit_elk_stack
    config:
      operation: "log_event"
      event_config:
        event_type: "security"
        event_level: "warning"
        source: "authentication_service"
        user_id: "john.doe"
        action: "login_attempt"
        resource: "user_management"
        outcome: "success"
        message: "User login successful"
```

### Advanced Configuration

```yaml
# Production ELK Stack configuration
elk_config:
  elasticsearch_url: "https://elasticsearch.company.com:9200"
  kibana_url: "https://kibana.company.com:5601"
  logstash_url: "https://logstash.company.com:5044"
  username: "${ELK_USERNAME}"
  password: "${ELK_PASSWORD}"
  verify_ssl: true

# Event configuration
event_config:
  event_type: "audit"
  event_level: "info"
  source: "plugpipe_orchestrator"
  user_id: "system"
  session_id: "session_12345"
  action: "pipeline_execution"
  resource: "data_processing_pipeline"
  outcome: "success"
  metadata:
    pipeline_id: "pipeline_001"
    execution_time: "45.2s"
    processed_records: 10000
```

### Environment-Specific Templates

#### Development
```yaml
elk_config:
  elasticsearch_url: "http://localhost:9200"
  kibana_url: "http://localhost:5601"
  logstash_url: "http://localhost:5044"
  verify_ssl: false
retention_days: 30
```

#### Production
```yaml
elk_config:
  elasticsearch_url: "${ELASTICSEARCH_URL}"
  kibana_url: "${KIBANA_URL}"
  logstash_url: "${LOGSTASH_URL}"
  username: "${ELK_USERNAME}"
  password: "${ELK_PASSWORD}"
  verify_ssl: true
retention_days: 365
```

## Supported Operations

### Event Logging

```python
# Log security event
security_result = await elk_audit.process({
    "operation": "log_event",
    "event_config": {
        "event_type": "security",
        "event_level": "critical",
        "source": "access_control",
        "user_id": "attacker_ip",
        "action": "unauthorized_access",
        "resource": "sensitive_data",
        "outcome": "blocked",
        "message": "Unauthorized access attempt blocked",
        "metadata": {
            "ip_address": "192.168.1.100",
            "user_agent": "curl/7.68.0",
            "attack_type": "brute_force"
        }
    }
}, config)

# Result: Event indexed in Elasticsearch with full audit trail
```

### Log Search and Analysis

```python
# Search audit logs
search_result = await elk_audit.process({
    "operation": "search_logs",
    "search_config": {
        "query": "event_type:security AND event_level:critical",
        "index_pattern": "plugpipe-security-*",
        "time_range": {
            "start": "2024-01-01T00:00:00Z",
            "end": "2024-01-01T23:59:59Z"
        },
        "size": 100
    }
}, config)

# Result: {
#   "total_hits": 15,
#   "hits": [
#     {
#       "@timestamp": "2024-01-01T10:30:00Z",
#       "event_type": "security",
#       "event_level": "critical",
#       "message": "Security violation detected"
#     }
#   ]
# }
```

### Dashboard Creation

```python
# Create security monitoring dashboard
dashboard_result = await elk_audit.process({
    "operation": "create_dashboard",
    "dashboard_config": {
        "dashboard_name": "Security Monitoring",
        "dashboard_type": "security",
        "visualizations": [
            {
                "name": "Security Events Timeline",
                "type": "histogram",
                "query": "event_type:security"
            },
            {
                "name": "Top Security Threats",
                "type": "pie",
                "query": "event_level:critical"
            }
        ]
    }
}, config)

# Result: Dashboard created in Kibana with real-time security visualization
```

### Alert Configuration

```python
# Configure security alerts
alert_result = await elk_audit.process({
    "operation": "configure_alerts",
    "alert_config": {
        "alert_name": "Brute Force Attack Detection",
        "query": "action:login AND outcome:failure",
        "threshold": {
            "value": 10,
            "comparison": "gte",
            "time_window": "5m"
        },
        "severity": "high",
        "notification_config": {
            "webhook_url": "https://security.company.com/alerts",
            "email_recipients": ["security@company.com"],
            "slack_channel": "#security-alerts"
        }
    }
}, config)
```

## ELK Stack Integration

### Elasticsearch Configuration

```yaml
# elasticsearch.yml - Elasticsearch cluster configuration
cluster.name: plugpipe-audit-cluster
node.name: plugpipe-audit-node-1
path.data: /var/lib/elasticsearch
path.logs: /var/log/elasticsearch

network.host: 0.0.0.0
http.port: 9200
discovery.type: single-node

# Security settings
xpack.security.enabled: true
xpack.security.transport.ssl.enabled: true
xpack.security.http.ssl.enabled: true

# Index lifecycle management
xpack.ilm.enabled: true
```

### Logstash Pipe Configuration

```ruby
# logstash.conf - PlugPipe audit log processing
input {
  http {
    port => 8080
    codec => json
    add_field => { "log_source" => "plugpipe_http" }
  }
  
  beats {
    port => 5044
    add_field => { "log_source" => "plugpipe_beats" }
  }
}

filter {
  # Parse PlugPipe audit events
  if [event_type] {
    mutate {
      add_field => { "[@metadata][index]" => "plugpipe-audit-%{+YYYY.MM.dd}" }
    }
    
    # Enrich security events
    if [event_type] == "security" {
      mutate {
        add_field => { "[@metadata][index]" => "plugpipe-security-%{+YYYY.MM.dd}" }
        add_tag => [ "security_event" ]
      }
      
      # GeoIP enrichment for IP addresses
      if [metadata][ip_address] {
        geoip {
          source => "[metadata][ip_address]"
          target => "geoip"
        }
      }
    }
    
    # Parse timestamps
    date {
      match => [ "@timestamp", "ISO8601" ]
    }
  }
}

output {
  elasticsearch {
    hosts => ["${ELASTICSEARCH_URL:localhost:9200}"]
    index => "%{[@metadata][index]}"
    template_name => "plugpipe_audit"
    template => "/etc/logstash/templates/plugpipe_audit.json"
    template_overwrite => true
  }
  
  # Output to stdout for debugging
  stdout {
    codec => rubydebug
  }
}
```

### Kibana Dashboard Configuration

```json
{
  "objects": [
    {
      "attributes": {
        "title": "PlugPipe Security Overview",
        "type": "dashboard",
        "description": "Real-time security monitoring dashboard",
        "panelsJSON": "[{\"version\":\"8.0.0\",\"panelIndex\":\"1\",\"gridData\":{\"x\":0,\"y\":0,\"w\":24,\"h\":15},\"panelRefName\":\"panel_1\"}]",
        "optionsJSON": "{\"useMargins\":true,\"syncColors\":false,\"hidePanelTitles\":false}",
        "version": 1,
        "timeRestore": false,
        "kibanaSavedObjectMeta": {
          "searchSourceJSON": "{\"query\":{\"query\":\"\",\"language\":\"kuery\"},\"filter\":[]}"
        }
      },
      "references": [
        {
          "name": "panel_1",
          "type": "visualization",
          "id": "security-events-timeline"
        }
      ]
    }
  ]
}
```

## Installation

### Prerequisites

```bash
# Docker Compose setup for ELK Stack
version: '3.8'
services:
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.5.0
    environment:
      - discovery.type=single-node
      - "ES_JAVA_OPTS=-Xms512m -Xmx512m"
    ports:
      - "9200:9200"
    volumes:
      - elasticsearch_data:/usr/share/elasticsearch/data

  kibana:
    image: docker.elastic.co/kibana/kibana:8.5.0
    ports:
      - "5601:5601"
    environment:
      - ELASTICSEARCH_HOSTS=http://elasticsearch:9200
    depends_on:
      - elasticsearch

  logstash:
    image: docker.elastic.co/logstash/logstash:8.5.0
    ports:
      - "5044:5044"
      - "8080:8080"
    volumes:
      - ./logstash.conf:/usr/share/logstash/pipeline/logstash.conf
    depends_on:
      - elasticsearch

volumes:
  elasticsearch_data:
```

### Plug Installation

```bash
# Install Python dependencies
pip install elasticsearch>=8.0.0 requests>=2.25.0 python-logstash>=0.4.8

# Install via PlugPipe CLI
plugpipe install audit_elk_stack

# Or clone manually
git clone https://github.com/plugpipe/plugs/audit_elk_stack
```

## Usage Examples

### Comprehensive Audit Pipe

```yaml
# pipeline.yaml - Pipe with comprehensive audit logging
name: audited_data_pipeline
steps:
  - name: log_pipeline_start
    plugin: audit_elk_stack
    config:
      operation: log_event
      event_config:
        event_type: "audit"
        event_level: "info"
        source: "pipeline_orchestrator"
        action: "pipeline_start"
        resource: "data_processing_pipeline"
        outcome: "success"
        metadata:
          pipeline_name: "audited_data_pipeline"
          user_id: "{{ pipeline.user }}"
  
  - name: process_sensitive_data
    plugin: data_processor
    config:
      data_source: "sensitive_customer_data.json"
  
  - name: log_data_access
    plugin: audit_elk_stack
    config:
      operation: log_event
      event_config:
        event_type: "security"
        event_level: "info"
        source: "data_processor"
        action: "data_access"
        resource: "sensitive_customer_data"
        outcome: "{{ previous_step.success | ternary('success', 'failure') }}"
        metadata:
          records_processed: "{{ previous_step.result.record_count }}"
  
  - name: create_compliance_report
    plugin: audit_elk_stack
    config:
      operation: search_logs
      search_config:
        query: "pipeline_name:audited_data_pipeline AND @timestamp:[now-1h TO now]"
        index_pattern: "plugpipe-audit-*"
```

### Security Event Monitoring

```python
# Real-time security monitoring with ELK Stack
import asyncio
from plugpipe import load_plugin

async def monitor_security_events():
    elk_audit = await load_plugin("audit_elk_stack")
    
    # Log suspicious activity
    await elk_audit.process({
        "operation": "log_event",
        "event_config": {
            "event_type": "security",
            "event_level": "warning",
            "source": "intrusion_detection",
            "action": "suspicious_activity",
            "resource": "network_traffic",
            "outcome": "detected",
            "message": "Unusual network pattern detected",
            "metadata": {
                "source_ip": "192.168.1.100",
                "destination_port": "22",
                "connection_attempts": 50,
                "pattern_type": "port_scan"
            }
        }
    }, config)
    
    # Search for recent security events
    search_result = await elk_audit.process({
        "operation": "search_logs",
        "search_config": {
            "query": "event_type:security AND event_level:(warning OR critical)",
            "time_range": {
                "start": "now-1h",
                "end": "now"
            },
            "size": 50
        }
    }, config)
    
    # Analyze patterns
    if search_result["success"] and search_result["result"]["total_hits"] > 10:
        print("High security activity detected - investigating...")
        
        # Create incident response dashboard
        await elk_audit.process({
            "operation": "create_dashboard",
            "dashboard_config": {
                "dashboard_name": "Security Incident Response",
                "dashboard_type": "security",
                "visualizations": [
                    {
                        "name": "Incident Timeline",
                        "type": "timeline",
                        "query": "event_type:security AND @timestamp:[now-1h TO now]"
                    }
                ]
            }
        }, config)
```

### Compliance Reporting

```python
# Generate compliance reports with ELK Stack
async def generate_compliance_report(report_type: str, time_period: str):
    elk_audit = await load_plugin("audit_elk_stack")
    
    # Define compliance queries
    compliance_queries = {
        "gdpr": {
            "data_processing": "metadata.personal_data:true",
            "consent_management": "action:consent_*",
            "data_breach": "event_level:critical AND metadata.data_breach:true"
        },
        "sox": {
            "financial_access": "resource:financial_data",
            "system_changes": "event_type:audit AND action:(create OR update OR delete)",
            "audit_trail": "*"
        },
        "hipaa": {
            "phi_access": "metadata.phi_access:true",
            "minimum_necessary": "metadata.minimum_necessary:*",
            "audit_logs": "resource:patient_data"
        }
    }
    
    if report_type not in compliance_queries:
        return {"error": f"Unsupported compliance type: {report_type}"}
    
    report_data = {}
    
    for category, query in compliance_queries[report_type].items():
        result = await elk_audit.process({
            "operation": "search_logs",
            "search_config": {
                "query": f"{query} AND @timestamp:[{time_period}]",
                "size": 1000
            }
        }, config)
        
        if result["success"]:
            report_data[category] = {
                "total_events": result["result"]["total_hits"],
                "events": result["result"]["hits"]
            }
    
    # Create compliance dashboard
    await elk_audit.process({
        "operation": "create_dashboard",
        "dashboard_config": {
            "dashboard_name": f"{report_type.upper()} Compliance Report",
            "dashboard_type": "compliance"
        }
    }, config)
    
    return {"report_data": report_data, "compliance_type": report_type}
```

## Index Templates and Mappings

### Audit Event Template

```json
{
  "index_patterns": ["plugpipe-audit-*"],
  "template": {
    "settings": {
      "number_of_shards": 1,
      "number_of_replicas": 0,
      "index.lifecycle.name": "plugpipe-audit-policy"
    },
    "mappings": {
      "properties": {
        "@timestamp": {
          "type": "date"
        },
        "event_id": {
          "type": "keyword"
        },
        "event_type": {
          "type": "keyword"
        },
        "event_level": {
          "type": "keyword"
        },
        "source": {
          "type": "keyword"
        },
        "user_id": {
          "type": "keyword"
        },
        "session_id": {
          "type": "keyword"
        },
        "action": {
          "type": "keyword"
        },
        "resource": {
          "type": "keyword"
        },
        "outcome": {
          "type": "keyword"
        },
        "message": {
          "type": "text",
          "analyzer": "standard"
        },
        "metadata": {
          "type": "object",
          "dynamic": true
        }
      }
    }
  }
}
```

### Security Event Template

```json
{
  "index_patterns": ["plugpipe-security-*"],
  "template": {
    "settings": {
      "number_of_shards": 2,
      "number_of_replicas": 1,
      "index.lifecycle.name": "plugpipe-security-policy"
    },
    "mappings": {
      "properties": {
        "threat_level": {
          "type": "keyword"
        },
        "attack_vector": {
          "type": "keyword"
        },
        "remediation": {
          "type": "text"
        },
        "geoip": {
          "properties": {
            "location": {
              "type": "geo_point"
            },
            "country_name": {
              "type": "keyword"
            },
            "city_name": {
              "type": "keyword"
            }
          }
        }
      }
    }
  }
}
```

## Monitoring and Alerting

### Health Checks

```python
# Check ELK Stack infrastructure health
health = await elk_audit.health_check()
print(f"Elasticsearch: {health['result']['elasticsearch_status']}")
print(f"Kibana: {health['result']['kibana_status']}")
print(f"Logstash: {health['result']['logstash_status']}")
```

### Performance Monitoring

```python
# Monitor log ingestion performance
async def monitor_log_performance():
    elk_audit = await load_plugin("audit_elk_stack")
    
    # Check index statistics
    stats_result = await elk_audit.process({
        "operation": "search_logs",
        "search_config": {
            "query": "*",
            "size": 0,
            "aggregations": {
                "events_per_hour": {
                    "date_histogram": {
                        "field": "@timestamp",
                        "calendar_interval": "hour"
                    }
                },
                "events_by_type": {
                    "terms": {
                        "field": "event_type"
                    }
                }
            }
        }
    }, config)
    
    return stats_result["result"]["aggregations"]
```

## Troubleshooting

### Common Issues

**Elasticsearch Not Reachable**
```
Error: Audit operation failed: ConnectionError((<urllib3.connection.HTTPConnection object at 0x...>))
Solution: Ensure Elasticsearch cluster is running and accessible
```

**Index Template Conflicts**
```
Error: index_template [plugpipe-audit] already exists
Solution: Update template with proper version or delete existing template
```

**Insufficient Storage Space**
```
Error: disk watermark [low] exceeded
Solution: Increase disk space or configure index lifecycle management
```

### Debug Mode

```yaml
# Enable debug logging
elk_config:
  debug: true
mock_mode: true  # Use mock for development
```

### ELK Stack Logs

```bash
# Check Elasticsearch logs
docker logs elasticsearch

# Check Kibana logs  
docker logs kibana

# Check Logstash logs
docker logs logstash

# Test index operations
curl -X GET "localhost:9200/plugpipe-audit-*/_search?pretty"
```

## Architecture

This plugin follows PlugPipe's plugin-first audit architecture:

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   PlugPipe      │    │ ELK Stack        │    │ Elasticsearch   │
│   Pipe      │───▶│ Plug           │───▶│ Cluster         │
│                 │    │                  │    │                 │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Log Processing   │    │ Kibana          │
                       │ (Logstash)       │    │ Dashboards      │
                       │                  │    │                 │
                       └──────────────────┘    └─────────────────┘
                                │                       │
                                ▼                       ▼
                       ┌──────────────────┐    ┌─────────────────┐
                       │ Data Collection  │    │ Alerting &      │
                       │ (Beats)          │    │ Notification    │
                       └──────────────────┘    └─────────────────┘
```

## Performance Optimization

### Index Lifecycle Management

```json
{
  "policy": {
    "phases": {
      "hot": {
        "actions": {
          "rollover": {
            "max_size": "10GB",
            "max_age": "7d"
          }
        }
      },
      "warm": {
        "min_age": "7d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "cold": {
        "min_age": "30d",
        "actions": {
          "allocate": {
            "number_of_replicas": 0
          }
        }
      },
      "delete": {
        "min_age": "365d"
      }
    }
  }
}
```

### Search Performance Tips

- **Use index patterns**: Target specific indices instead of searching all
- **Limit field retrieval**: Use `_source` filtering to reduce payload
- **Use aggregations**: Summarize data instead of retrieving raw documents
- **Time range filters**: Always specify time ranges for better performance

## Security Considerations

### Production Deployment

- **Enable Authentication**: Configure X-Pack security for authentication
- **Use HTTPS**: Enable SSL/TLS for all communication
- **Network Security**: Deploy in secure network with firewall rules
- **Regular Updates**: Keep ELK Stack updated with security patches

### Data Protection

- **Encryption**: Enable encryption at rest and in transit
- **Access Controls**: Implement role-based access control
- **Data Masking**: Mask sensitive information in logs
- **Retention Policies**: Implement appropriate data retention

## Contributing

This plugin demonstrates the PlugPipe principle of leveraging proven enterprise technology. When contributing:

1. **Maintain ELK Stack Integration**: All enhancements should leverage ELK Stack capabilities
2. **Follow Elasticsearch Best Practices**: Use appropriate mappings and index strategies
3. **Kibana Compatibility**: Ensure dashboards work with current Kibana versions
4. **Performance Optimization**: Monitor and optimize log ingestion and search performance

## License

MIT License - see LICENSE file for details.

---

**PlugPipe Philosophy**: This plugin exemplifies "reuse, never reinvent" by leveraging the ELK Stack's proven enterprise logging and analytics platform instead of implementing custom audit logging and log management systems. By integrating with existing enterprise logging infrastructure, we provide scalable, real-time log management with battle-tested reliability and rich ecosystem support.