# Demo Customer Support Pipe Examples

This directory contains example configurations and usage patterns for the demo_customer_support pipe.

## Basic Configuration

```yaml
# config.yaml - Basic configuration
demo_customer_support:
  timeout: 1800
  parallel_execution: false
  
# Plugin configurations
notification_service:
  # Configure notification_service plugin
  api_key: your_api_key_here
  timeout: 60
```

## Advanced Configuration

```yaml
# config-advanced.yaml - Advanced configuration
demo_customer_support:
  timeout: 3600
  retry_policy:
    max_retries: 5
    backoff: exponential
    retry_delay: 30
  parallel_execution: true
  error_handling:
    continue_on_error: false
    notify_on_failure: true
  monitoring:
    enable_metrics: true
    log_level: INFO

# Plugin configurations with advanced options
notification_service:
  # Advanced notification_service configuration
  api_key: your_api_key_here
  timeout: 120
  retry_attempts: 3
  rate_limit: 10
```

## Industry-Specific Examples

### General Industry Configuration

```yaml
# config-general.yaml
demo_customer_support:
  # General-specific settings
  timeout: 600
  compliance_mode: true
  audit_logging: true
  
notification_service:
  api_key: your_notification_service_api_key
  timeout: 60
  retry_attempts: 3
  environment: production
```

## Usage Examples

### Command Line Usage

```bash
# Basic execution
python scripts/orchestrator_cli.py run \
  --pipeline pipes/workflow/demo_customer_support/pipe.yaml \
  --config config.yaml

# With custom input
python scripts/orchestrator_cli.py run \
  --pipeline pipes/workflow/demo_customer_support/pipe.yaml \
  --config config.yaml \
  --input '{"workflow_data": {"param1": "value1"}}'

# Dry run mode
python scripts/orchestrator_cli.py run \
  --pipeline pipes/workflow/demo_customer_support/pipe.yaml \
  --config config.yaml \
  --dry-run
```

### Python API Usage

```python
# Using PlugPipe Python API
import sys
sys.path.append('/path/to/PlugPipe')

from shares.loader import pp

# Basic execution
result = pp("orchestrator", {
    "action": "run_pipeline",
    "pipeline_path": "pipes/workflow/demo_customer_support/pipe.yaml",
    "config_path": "config.yaml"
})

if result['success']:
    print("Pipeline executed successfully")
    print(f"Results: {result['data']}")
else:
    print(f"Pipeline failed: {result['error']}")

# Advanced execution with custom configuration
custom_config = {
    "timeout": 3600,
    "retry_policy": {
        "max_retries": 3,
        "backoff": "exponential"
    }
}

result = pp("orchestrator", {
    "action": "run_pipeline",
    "pipeline_path": "pipes/workflow/demo_customer_support/pipe.yaml",
    "config": custom_config,
    "input_data": {
        "workflow_params": {
            "priority": "high",
            "notify_on_completion": True
        }
    }
})
```

### Integration Examples

```python
# Integration with external systems
import asyncio
from datetime import datetime

async def run_workflow_with_monitoring():
    # Pre-execution setup
    workflow_id = f"demo_customer_support_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Configure monitoring
    monitoring_config = {
        "workflow_id": workflow_id,
        "enable_metrics": True,
        "alert_on_failure": True
    }
    
    # Execute pipeline
    result = pp("orchestrator", {
        "action": "run_pipeline",
        "pipeline_path": "pipes/workflow/demo_customer_support/pipe.yaml",
        "monitoring": monitoring_config
    })
    
    # Post-execution processing
    if result['success']:
        # Log success metrics
        print(f"Workflow {workflow_id} completed successfully")
        
        # Trigger downstream processes
        await trigger_downstream_workflows(result['data'])
    else:
        # Handle failure
        print(f"Workflow {workflow_id} failed: {result['error']}")
        await handle_workflow_failure(workflow_id, result['error'])

# Run the async function
asyncio.run(run_workflow_with_monitoring())
```

## Testing Examples

```python
# Testing pipe execution
import pytest
from unittest.mock import Mock, patch

def test_pipe_execution():
    # Mock plugin responses
    with patch('shares.loader.pp') as mock_pp:
        mock_pp.return_value = {'success': True, 'data': {'result': 'test'}}
        
        # Test execution
        result = pp("orchestrator", {
            "action": "run_pipeline",
            "pipeline_path": "pipes/workflow/demo_customer_support/pipe.yaml"
        })
        
        assert result['success'] is True

def test_error_handling():
    # Test error scenarios
    with patch('shares.loader.pp') as mock_pp:
        mock_pp.return_value = {'success': False, 'error': 'Plugin failed'}
        
        result = pp("orchestrator", {
            "action": "run_pipeline",
            "pipeline_path": "pipes/workflow/demo_customer_support/pipe.yaml"
        })
        
        assert result['success'] is False
        assert 'error' in result
```

## Monitoring and Debugging

```bash
# Monitor pipe execution
tail -f pipe_runs/*/logs/demo_customer_support.log

# Check individual step outputs
ls pipe_runs/latest/step_*_output.yaml

# View execution metrics
cat pipe_runs/latest/metrics.json

# Debug failed executions
python scripts/pipe_debugger.py --run-id <run_id> --step <step_id>
```

## Performance Tuning

```yaml
# config-performance.yaml - Performance optimized
demo_customer_support:
  # Parallel execution for independent steps
  parallel_execution: true
  
  # Optimized timeouts
  timeout: 1800
  step_timeout: 300
  
  # Resource management
  max_concurrent_steps: 4
  memory_limit: "2Gi"
  
  # Caching
  enable_caching: true
  cache_ttl: 3600
```

## Troubleshooting Examples

```bash
# Common troubleshooting commands

# Check plugin availability
python -c "from shares.loader import pp; print(pp('plugin_registry', {'action': 'list'}))"

# Validate pipe specification
python scripts/pipe_validator.py pipes/workflow/demo_customer_support/pipe.yaml

# Test plugin connectivity
python -c "from shares.loader import pp; print(pp(\"notification_service\", {\"action\": \"health_check\"}))"
```
