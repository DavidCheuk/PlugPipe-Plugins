# Kafka Producer Plugin - Developer Documentation

## Architecture Overview

The Kafka Producer Plugin implements a security-hardened, enterprise-grade message production system using the FTHAD (Fix-Test-Harden-Audit-Doc) methodology.

### Core Components

#### 1. MessageSerializerInterface (ABC Pattern)
```python
class MessageSerializerInterface(ABC):
    """Abstract interface for message serializers in Kafka Producer."""

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Return list of supported serialization formats."""
        pass

    @abstractmethod
    async def serialize(self, message: Any, format_type: str) -> Union[str, bytes]:
        """Serialize message to specified format."""
        pass
```

#### 2. UniversalKafkaProducerOrchestrator
Main orchestration class with comprehensive security validation:

```python
class UniversalKafkaProducerOrchestrator:
    """Universal Kafka producer for any streaming use case."""

    def __init__(self):
        self.producer = None
        self.redis_client = None
        self.logger = logging.getLogger(__name__)
        self.serializer = DefaultMessageSerializer()
```

### Security Architecture

#### Input Validation Pipeline
1. **Bootstrap Server Validation** → Network security
2. **Topic Name Validation** → Injection prevention
3. **Credential Validation** → Authentication security
4. **Producer Config Validation** → Resource protection
5. **Message Content Validation** → Content security

#### Security Methods Implementation
```python
# Network security validation
def _validate_kafka_bootstrap_servers(self, servers: List[str]) -> Dict[str, Any]

# Topic injection prevention
def _validate_kafka_topic_names(self, topics: List[str]) -> Dict[str, Any]

# Credential security validation
def _validate_kafka_credentials(self, creds: Dict[str, Any]) -> Dict[str, Any]

# Producer configuration security
def _validate_kafka_producer_config(self, config: Dict[str, Any]) -> Dict[str, Any]

# Message content validation
def _validate_message_content(self, message: Any) -> Dict[str, Any]

# Universal input sanitization
async def _validate_and_sanitize_input(self, data: Any, context: str) -> Dict[str, Any]
```

## Development Patterns

### 1. Adding New Serialization Formats

#### Step 1: Create Serializer Plugin
```python
# plugs/serialization/custom_serializer/1.0.0/main.py
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    message = ctx['message']
    format_type = ctx['format']

    # Implement custom serialization
    serialized = custom_serialize(message)

    return {
        'serialized_message': serialized,
        'format': format_type
    }
```

#### Step 2: Register Plugin
The Kafka Producer will automatically discover plugins named `{format}_serializer`:
```python
plugin_name = f"{serialization_format}_serializer"
plugin_wrapper = pp(plugin_name)
```

### 2. Adding Security Validation

#### Pattern for New Validation Methods
```python
def _validate_new_feature(self, data: Any) -> Dict[str, Any]:
    """Validate new feature for security vulnerabilities."""
    validation_result = {
        'is_valid': True,
        'security_issues': [],
        'sanitized_data': data
    }

    # Implement validation logic
    if dangerous_condition:
        validation_result['security_issues'].append("Description of issue")
        validation_result['is_valid'] = False

    # Sanitize data
    validation_result['sanitized_data'] = sanitize_data(data)

    return validation_result
```

#### Integration with Universal Sanitizer
```python
async def _validate_and_sanitize_input(self, data: Any, context: str) -> Dict[str, Any]:
    # Add new context handling
    elif context == 'new_feature' and isinstance(data, ExpectedType):
        feature_validation = self._validate_new_feature(data)
        validation_result.update(feature_validation)
```

### 3. Message Processing Flow

#### Single Message Processing
```python
async def publish_single_message(self, message: Any, topic: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    # 1. Message enrichment for PlugPipe signals
    if isinstance(message, dict):
        message = await self.enrich_message_metadata(message, ctx)

    # 2. Partition key for message routing
    partition_key = ctx.get('partition_key')
    key = partition_key.encode('utf-8') if partition_key else None

    # 3. Headers for additional metadata
    headers = ctx.get('headers', {})
    header_list = [(k, str(v).encode('utf-8')) for k, v in headers.items()]

    # 4. Publish message
    future = self.producer.send(topic=topic, value=message, key=key, headers=header_list)
    record_metadata = future.get(timeout=30)

    return {
        'status': 'success',
        'partition': record_metadata.partition,
        'offset': record_metadata.offset,
        'topic': record_metadata.topic,
        'timestamp': record_metadata.timestamp
    }
```

#### Batch Message Processing
```python
async def publish_batch_messages(self, messages: List[Any], topic: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
    results = []
    successful = 0
    failed = 0

    for message in messages:
        result = await self.publish_single_message(message, topic, ctx)
        results.append(result)

        if result['status'] == 'success':
            successful += 1
        else:
            failed += 1

    # Flush producer to ensure all messages sent
    self.producer.flush()

    overall_status = 'success' if failed == 0 else ('partial' if successful > 0 else 'error')

    return {
        'status': overall_status,
        'published_count': successful,
        'failed_count': failed,
        'details': results
    }
```

## Testing Patterns

### 1. FTHAD Test Structure
```python
class TestKafkaProducerFTHAD:
    def setup_method(self):
        self.orchestrator = kafka_producer_main.UniversalKafkaProducerOrchestrator()

    # FIX phase tests
    def test_fix_phase_abc_pattern_implementation(self):
        # Test ABC pattern implementation

    # TEST phase tests
    def test_test_phase_no_notimplementederror_instances(self):
        # Verify NotImplementedError elimination

    # HARDEN phase tests
    def test_harden_phase_kafka_security_validation(self):
        # Test security validation methods

    # AUDIT phase tests
    def test_audit_phase_code_quality_metrics(self):
        # Test code quality and compliance

    # DOC phase tests
    def test_doc_phase_comprehensive_functionality(self):
        # Test documentation coverage
```

### 2. Security Testing Patterns
```python
def test_security_validation_method(self):
    """Test pattern for security validation methods."""

    # Test valid inputs
    valid_input = create_valid_input()
    result = self.orchestrator._validate_method(valid_input)
    assert result['is_valid'] is True

    # Test dangerous inputs
    dangerous_inputs = [
        create_dangerous_input_1(),
        create_dangerous_input_2(),
        create_dangerous_input_3()
    ]

    for dangerous_input in dangerous_inputs:
        result = self.orchestrator._validate_method(dangerous_input)
        assert (result['is_valid'] is False or len(result['security_issues']) > 0)
```

### 3. Plugin Loading Testing
```python
def test_plugin_loading_scenarios(self):
    """Test plugin loading success and failure scenarios."""

    # Test successful plugin loading
    plugin = load_serializer_plugin('existing_format')
    assert plugin is not None

    # Test graceful failure for missing plugins
    plugin = load_serializer_plugin('non_existent_format')
    assert plugin is None  # Should not raise exception
```

## Configuration Patterns

### 1. Environment-Specific Configuration
```python
# Development
development_config = {
    "bootstrap_servers": ["localhost:9092"],
    "security_protocol": "PLAINTEXT",
    "acks": "1",
    "retries": 3
}

# Staging
staging_config = {
    "bootstrap_servers": ["staging-kafka.company.com:9092"],
    "security_protocol": "SASL_SSL",
    "sasl_mechanism": "SCRAM-SHA-256",
    "acks": "all",
    "retries": 10
}

# Production
production_config = {
    "bootstrap_servers": [
        "kafka1.prod.company.com:9092",
        "kafka2.prod.company.com:9092",
        "kafka3.prod.company.com:9092"
    ],
    "security_protocol": "SASL_SSL",
    "sasl_mechanism": "SCRAM-SHA-256",
    "acks": "all",
    "retries": 50,
    "enable_idempotence": True,
    "compression": "snappy"
}
```

### 2. Security Configuration Templates
```python
# High Security Template
high_security_config = {
    "security_protocol": "SASL_SSL",
    "sasl_mechanism": "SCRAM-SHA-256",
    "kafka_username": "secure_user",
    "kafka_password": "strong_password_minimum_8_chars",
    "request_timeout_ms": 30000,  # 30 seconds
    "retries": 10,
    "acks": "all",
    "enable_idempotence": True
}

# Performance Optimized Template
performance_config = {
    "compression": "snappy",
    "batch_size": 16384,  # 16KB
    "linger_ms": 100,
    "buffer_memory": 33554432,  # 32MB
    "max_in_flight_requests_per_connection": 5
}
```

## Error Handling Patterns

### 1. Comprehensive Error Classification
```python
class KafkaProducerError(Exception):
    """Base exception for Kafka Producer errors."""
    pass

class SecurityValidationError(KafkaProducerError):
    """Raised when security validation fails."""
    pass

class SerializationError(KafkaProducerError):
    """Raised when message serialization fails."""
    pass

class ProducerConfigurationError(KafkaProducerError):
    """Raised when producer configuration is invalid."""
    pass
```

### 2. Error Response Patterns
```python
def create_error_response(error_type: str, error_message: str, details: Dict = None) -> Dict[str, Any]:
    """Create standardized error response."""
    return {
        'kafka_status': 'error',
        'kafka_error': error_message,
        'kafka_result': {
            'status': 'error',
            'error': error_message,
            'error_type': error_type,
            'details': details or {}
        }
    }
```

### 3. Graceful Degradation Pattern
```python
async def with_graceful_degradation(self, operation: Callable, fallback: Callable = None):
    """Execute operation with graceful degradation."""
    try:
        return await operation()
    except Exception as e:
        self.logger.warning(f"Operation failed: {e}")
        if fallback:
            return await fallback()
        return create_error_response('operation_failed', str(e))
```

## Performance Optimization

### 1. Connection Management
```python
class ConnectionManager:
    """Manage Kafka producer connections efficiently."""

    def __init__(self):
        self.producers = {}
        self.connection_lock = asyncio.Lock()

    async def get_producer(self, config_hash: str, config: Dict[str, Any]) -> KafkaProducer:
        """Get or create producer with connection pooling."""
        async with self.connection_lock:
            if config_hash not in self.producers:
                self.producers[config_hash] = KafkaProducer(**config)
            return self.producers[config_hash]
```

### 2. Batch Optimization
```python
async def optimize_batch_processing(self, messages: List[Any], max_batch_size: int = 100) -> List[List[Any]]:
    """Optimize message batching for performance."""
    batches = []
    current_batch = []
    current_size = 0

    for message in messages:
        message_size = len(json.dumps(message))

        if current_size + message_size > max_batch_size and current_batch:
            batches.append(current_batch)
            current_batch = []
            current_size = 0

        current_batch.append(message)
        current_size += message_size

    if current_batch:
        batches.append(current_batch)

    return batches
```

### 3. Monitoring Integration
```python
class PerformanceMonitor:
    """Monitor Kafka Producer performance metrics."""

    def __init__(self):
        self.metrics = {
            'messages_produced': 0,
            'bytes_produced': 0,
            'errors_total': 0,
            'latency_samples': []
        }

    async def record_message(self, message_size: int, latency_ms: float):
        """Record message production metrics."""
        self.metrics['messages_produced'] += 1
        self.metrics['bytes_produced'] += message_size
        self.metrics['latency_samples'].append(latency_ms)

        # Keep only recent samples
        if len(self.metrics['latency_samples']) > 1000:
            self.metrics['latency_samples'] = self.metrics['latency_samples'][-1000:]
```

## Integration Guidelines

### 1. PlugPipe Signal Integration
```python
async def enrich_with_plugpipe_signals(self, message: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Enrich message with PlugPipe signal metadata."""
    if ctx.get('signal_metadata', False):
        enriched = dict(message)
        enriched.update({
            '_plugpipe_metadata': {
                'source_plugin': ctx.get('source_plugin'),
                'signal_type': ctx.get('signal_type'),
                'timestamp': ctx.get('timestamp'),
                'trace_id': ctx.get('trace_id'),
                'plugin_version': ctx.get('plugin_version')
            }
        })
        return enriched
    return message
```

### 2. Redis Coordination Integration
```python
async def coordinate_with_redis(self, config: Dict[str, Any], ctx: Dict[str, Any], result: Dict[str, Any]):
    """Coordinate with Redis for complex messaging workflows."""
    if not self.redis_client:
        return

    try:
        redis_config = config.get('redis_backend', {})
        queue_prefix = redis_config.get('queue_prefix', 'kafka_queue:')

        # Store result for downstream processing
        result_key = f"{queue_prefix}result:{ctx.get('trace_id', 'unknown')}"
        await self.redis_client.set(result_key, json.dumps(result), ex=3600)

        # Signal completion for orchestrated workflows
        completion_key = f"{queue_prefix}completion:{ctx.get('trace_id', 'unknown')}"
        await self.redis_client.lpush(completion_key, json.dumps({
            'plugin': 'kafka_producer',
            'status': result['status'],
            'timestamp': ctx.get('timestamp')
        }))
    except Exception as e:
        self.logger.warning(f"Redis coordination failed: {e}")
```

### 3. Monitoring Plugin Integration
```python
async def integrate_monitoring(self, config: Dict[str, Any]):
    """Integrate with monitoring plugins."""
    try:
        from shares.loader import pp
        monitoring_plugin = pp('monitoring_prometheus')

        if monitoring_plugin:
            await monitoring_plugin.process({
                'metric_name': 'kafka_producer_health',
                'metric_value': 1,
                'labels': {
                    'plugin': 'kafka_producer',
                    'version': '1.0.0'
                }
            }, {})
    except Exception as e:
        self.logger.warning(f"Monitoring integration failed: {e}")
```

This developer documentation provides comprehensive guidance for extending, modifying, and integrating the Kafka Producer Plugin within the PlugPipe ecosystem while maintaining security and performance standards.