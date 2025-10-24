# Claims Processing Pipe Examples

This directory contains example configurations and usage patterns for the claims_processing pipe.

## Basic Configuration

```yaml
# config.yaml - Basic configuration
claims_processing:
  timeout: 1800
  parallel_execution: false
  
# Plugin configurations
claims_management:
  # Configure claims_management plugin
  api_key: your_api_key_here
  timeout: 60
medical_coding:
  # Configure medical_coding plugin
  api_key: your_api_key_here
  timeout: 60
payment_processing:
  # Configure payment_processing plugin
  api_key: your_api_key_here
  timeout: 60
```

## Advanced Configuration

```yaml
# config-advanced.yaml - Advanced configuration
claims_processing:
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
claims_management:
  # Advanced claims_management configuration
  api_key: your_api_key_here
  timeout: 120
  retry_attempts: 3
  rate_limit: 10
medical_coding:
  # Advanced medical_coding configuration
  api_key: your_api_key_here
  timeout: 120
  retry_attempts: 3
  rate_limit: 10
```

## Industry-Specific Examples

### Healthcare Industry Configuration

```yaml
# config-healthcare.yaml
claims_processing:
  # Healthcare-specific settings
  timeout: 1200
  compliance_mode: true
  audit_logging: true
  
claims_management:
  api_key: your_claims_management_api_key
  timeout: 60
  retry_attempts: 3
  environment: production
medical_coding:
  api_key: your_healthcare_api_key
  environment: production
  compliance:
    hipaa: true
    audit_logging: true
    encryption: required
  timeout: 120
payment_processing:
  api_key: your_payment_processing_api_key
  timeout: 60
  retry_attempts: 3
  environment: production
```

## Usage Examples

### Command Line Usage

```bash
# Basic execution
python scripts/orchestrator_cli.py run \
  --pipeline pipes/workflow/claims_processing/pipe.yaml \
  --config config.yaml

# With custom input
python scripts/orchestrator_cli.py run \
  --pipeline pipes/workflow/claims_processing/pipe.yaml \
  --config config.yaml \
  --input '{"workflow_data": {"param1": "value1"}}'

# Dry run mode
python scripts/orchestrator_cli.py run \
  --pipeline pipes/workflow/claims_processing/pipe.yaml \
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
    "pipeline_path": "pipes/workflow/claims_processing/pipe.yaml",
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
    "pipeline_path": "pipes/workflow/claims_processing/pipe.yaml",
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
    workflow_id = f"claims_processing_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Configure monitoring
    monitoring_config = {
        "workflow_id": workflow_id,
        "enable_metrics": True,
        "alert_on_failure": True
    }
    
    # Execute pipeline
    result = pp("orchestrator", {
        "action": "run_pipeline",
        "pipeline_path": "pipes/workflow/claims_processing/pipe.yaml",
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
            "pipeline_path": "pipes/workflow/claims_processing/pipe.yaml"
        })
        
        assert result['success'] is True

def test_error_handling():
    # Test error scenarios
    with patch('shares.loader.pp') as mock_pp:
        mock_pp.return_value = {'success': False, 'error': 'Plugin failed'}
        
        result = pp("orchestrator", {
            "action": "run_pipeline",
            "pipeline_path": "pipes/workflow/claims_processing/pipe.yaml"
        })
        
        assert result['success'] is False
        assert 'error' in result
```

## Monitoring and Debugging

```bash
# Monitor pipe execution
tail -f pipe_runs/*/logs/claims_processing.log

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
claims_processing:
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
python scripts/pipe_validator.py pipes/workflow/claims_processing/pipe.yaml

# Test plugin connectivity
python -c "from shares.loader import pp; print(pp(\"claims_management\", {\"action\": \"health_check\"}))"
python -c "from shares.loader import pp; print(pp(\"medical_coding\", {\"action\": \"health_check\"}))"
python -c "from shares.loader import pp; print(pp(\"payment_processing\", {\"action\": \"health_check\"}))"
```
