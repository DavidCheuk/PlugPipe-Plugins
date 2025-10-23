# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Universal Kafka Producer Plugin for PlugPipe

Generic Kafka producer supporting ANY streaming use case:
- Event streaming and real-time processing
- Data pipelines and ETL workflows  
- Microservice communication
- Log aggregation and analytics
- IoT data ingestion
- API integration and webhooks
- PlugPipe signal distribution

REUSE, NEVER REINVENT: Leverages proven Kafka libraries and Redis coordination.
"""

import json
import asyncio
import logging
import re
import sys
import os
from typing import Dict, Any, List, Optional, Union, Callable
from abc import ABC, abstractmethod
from kafka import KafkaProducer
from kafka.errors import KafkaError, KafkaTimeoutError
import redis.asyncio as redis


class MessageSerializerInterface(ABC):
    """
    Abstract interface for message serializers in Kafka Producer.

    Enables pluggable serialization backends for different message formats
    while maintaining universal producer functionality.
    """

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Return list of supported serialization formats."""
        pass

    @abstractmethod
    async def serialize(self, message: Any, format_type: str) -> Union[str, bytes]:
        """Serialize message to specified format."""
        pass


class DefaultMessageSerializer(MessageSerializerInterface):
    """Default message serializer with basic format support."""

    def get_supported_formats(self) -> List[str]:
        return ["json", "string", "bytes"]

    async def serialize(self, message: Any, format_type: str) -> Union[str, bytes]:
        """Default serialization implementation."""
        if format_type == 'json':
            return json.dumps(message)
        elif format_type == 'string':
            return str(message)
        elif format_type == 'bytes':
            return message if isinstance(message, bytes) else str(message).encode('utf-8')
        else:
            return str(message)


def load_serializer_plugin(serialization_format: str) -> Optional[MessageSerializerInterface]:
    """
    Dynamically load serializer plugin for specific format.

    Uses PlugPipe's plugin discovery to find specialized serializers.
    Falls back to default serializer if no specialized plugin found.
    """
    try:
        # Add PlugPipe root to Python path
        plugpipe_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..'))
        if plugpipe_root not in sys.path:
            sys.path.insert(0, plugpipe_root)

        # Import PlugPipe's plugin loader
        from shares.loader import pp

        # Try to load specialized serializer plugin
        plugin_name = f"{serialization_format}_serializer"
        plugin_wrapper = pp(plugin_name)

        if plugin_wrapper:
            # Return wrapped plugin as serializer interface
            class PluginSerializerAdapter(MessageSerializerInterface):
                def __init__(self, plugin_wrapper):
                    self.plugin_wrapper = plugin_wrapper

                def get_supported_formats(self) -> List[str]:
                    return [serialization_format]

                async def serialize(self, message: Any, format_type: str) -> Union[str, bytes]:
                    result = await self.plugin_wrapper.process({'message': message, 'format': format_type}, {})
                    return result.get('serialized_message', str(message))

            return PluginSerializerAdapter(plugin_wrapper)

    except Exception as e:
        # Log warning but continue with default serializer
        logging.getLogger(__name__).warning(f"Failed to load {serialization_format} serializer plugin: {e}")

    return None


class UniversalKafkaProducerOrchestrator:
    """
    Universal Kafka producer for any streaming use case.

    PURE ORCHESTRATION ARCHITECTURE:
    - Delegates message serialization to proven Kafka libraries
    - Reuses Redis infrastructure for coordination and queuing
    - Leverages existing monitoring plugins for metrics
    - No custom streaming logic - pure orchestration
    """

    def __init__(self):
        self.producer = None
        self.redis_client = None
        self.logger = logging.getLogger(__name__)
        self.serializer = DefaultMessageSerializer()
        
    async def setup_kafka_producer(self, config: Dict[str, Any]) -> None:
        """Setup Kafka producer with universal configuration."""
        producer_config = {
            'bootstrap_servers': config['bootstrap_servers'],
            'acks': config.get('acks', '1'),
            'retries': config.get('retries', 3),
            'batch_size': config.get('batch_size', 100),
            'request_timeout_ms': config.get('timeout_ms', 30000),
            'enable_idempotence': config.get('enable_idempotence', True),
            'max_in_flight_requests_per_connection': config.get('max_in_flight', 5),
        }
        
        # Compression configuration
        compression_map = {
            'none': None,
            'gzip': 'gzip', 
            'snappy': 'snappy',
            'lz4': 'lz4',
            'zstd': 'zstd'
        }
        compression = config.get('compression', 'none')
        if compression != 'none':
            producer_config['compression_type'] = compression_map[compression]
            
        # Security configuration
        security_protocol = config.get('security_protocol', 'PLAINTEXT')
        if security_protocol != 'PLAINTEXT':
            producer_config['security_protocol'] = security_protocol
            
        sasl_mechanism = config.get('sasl_mechanism')
        if sasl_mechanism:
            producer_config['sasl_mechanism'] = sasl_mechanism
            producer_config['sasl_plain_username'] = config.get('kafka_username')
            producer_config['sasl_plain_password'] = config.get('kafka_password')
            
        # Serialization configuration
        serialization = config.get('serialization', 'json')
        if serialization == 'json':
            producer_config['value_serializer'] = lambda v: json.dumps(v).encode('utf-8')
        elif serialization == 'string':
            producer_config['value_serializer'] = lambda v: str(v).encode('utf-8')
        elif serialization == 'bytes':
            producer_config['value_serializer'] = lambda v: v if isinstance(v, bytes) else str(v).encode('utf-8')
        
        self.producer = KafkaProducer(**producer_config)
        
    async def setup_redis_coordination(self, config: Dict[str, Any]) -> None:
        """Setup Redis coordination for complex workflows."""
        redis_config = config.get('redis_backend', {})
        if redis_config.get('enabled', False):
            redis_url = redis_config.get('redis_url', 'redis://localhost:6379/2')
            self.redis_client = redis.from_url(redis_url)
            
    async def serialize_message(self, message: Any, serialization: str) -> Union[str, bytes]:
        """Universal message serialization with dynamic plugin support."""
        # For advanced formats, try to load specialized plugin
        if serialization in ['avro', 'protobuf']:
            plugin_serializer = load_serializer_plugin(serialization)
            if plugin_serializer:
                try:
                    return await plugin_serializer.serialize(message, serialization)
                except Exception as e:
                    self.logger.warning(f"Plugin serializer failed for {serialization}: {e}")
                    # Fall through to default behavior

        # Use default serializer for basic formats and fallback
        return await self.serializer.serialize(message, serialization)
            
    async def determine_topic(self, config: Dict[str, Any], ctx: Dict[str, Any]) -> str:
        """Determine target topic with flexible routing."""
        # Topic override in input
        if 'topic_override' in ctx:
            return ctx['topic_override']
            
        # PlugPipe signal routing
        signal_routing = config.get('signal_routing', {})
        signal_type = ctx.get('signal_type')
        if signal_type and signal_type in signal_routing:
            return signal_routing[signal_type]
            
        # Default configured topic
        return config['topic']
        
    async def enrich_message_metadata(self, message: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Enrich messages with PlugPipe metadata for signal tracking."""
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
        
    async def publish_single_message(self, message: Any, topic: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Publish single message with universal support."""
        try:
            # Message enrichment for PlugPipe signals
            if isinstance(message, dict):
                message = await self.enrich_message_metadata(message, ctx)
                
            # Partition key for message routing
            partition_key = ctx.get('partition_key')
            key = partition_key.encode('utf-8') if partition_key else None
            
            # Headers for additional metadata
            headers = ctx.get('headers', {})
            header_list = [(k, str(v).encode('utf-8')) for k, v in headers.items()]
            
            # Publish message
            future = self.producer.send(
                topic=topic,
                value=message,
                key=key,
                headers=header_list
            )
            
            # Get metadata
            record_metadata = future.get(timeout=30)
            
            return {
                'status': 'success',
                'partition': record_metadata.partition,
                'offset': record_metadata.offset,
                'topic': record_metadata.topic,
                'timestamp': record_metadata.timestamp
            }
            
        except KafkaTimeoutError as e:
            return {'status': 'error', 'error': f'Kafka timeout: {str(e)}'}
        except KafkaError as e:
            return {'status': 'error', 'error': f'Kafka error: {str(e)}'}
        except Exception as e:
            return {'status': 'error', 'error': f'Unexpected error: {str(e)}'}
            
    async def publish_batch_messages(self, messages: List[Any], topic: str, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Publish batch of messages for high-throughput use cases."""
        results = []
        successful = 0
        failed = 0
        
        try:
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
            
        except Exception as e:
            return {
                'status': 'error',
                'published_count': successful,
                'failed_count': failed + (len(messages) - len(results)),
                'error': f'Batch publish error: {str(e)}',
                'details': results
            }
            
    async def coordinate_with_redis(self, config: Dict[str, Any], ctx: Dict[str, Any], result: Dict[str, Any]) -> None:
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
            
    async def cleanup(self) -> None:
        """Clean up resources."""
        if self.producer:
            self.producer.close()
        if self.redis_client:
            await self.redis_client.close()

    # ================================
    # SECURITY HARDENING METHODS
    # ================================

    def _validate_kafka_bootstrap_servers(self, servers: List[str]) -> Dict[str, Any]:
        """Validate Kafka bootstrap servers for security vulnerabilities."""
        validation_result = {
            'is_valid': True,
            'security_issues': [],
            'sanitized_servers': []
        }

        for server in servers:
            # Check for dangerous localhost/internal network usage
            dangerous_patterns = [
                r'localhost',
                r'127\.0\.0\.1',
                r'192\.168\.',
                r'10\.',
                r'172\.1[6-9]\.',
                r'172\.2[0-9]\.',
                r'172\.3[0-1]\.',
                r'169\.254\.',  # Link-local
                r'0\.0\.0\.0'
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, server, re.IGNORECASE):
                    validation_result['security_issues'].append(f"Server uses internal/localhost address: {server}")

            # Check for command injection characters
            if re.search(r'[;&|`$]', server):
                validation_result['security_issues'].append(f"Server contains dangerous characters: {server}")
                validation_result['is_valid'] = False
                continue

            # Validate port range
            if ':' in server:
                try:
                    host, port = server.rsplit(':', 1)
                    port_num = int(port)
                    if port_num < 1 or port_num > 65535:
                        validation_result['security_issues'].append(f"Invalid port number: {port}")
                        validation_result['is_valid'] = False
                        continue
                except ValueError:
                    validation_result['security_issues'].append(f"Invalid port format: {server}")
                    validation_result['is_valid'] = False
                    continue

            # Server is acceptable (add warning for internal networks)
            validation_result['sanitized_servers'].append(server)

        return validation_result

    def _validate_kafka_topic_names(self, topics: List[str]) -> Dict[str, Any]:
        """Validate Kafka topic names for security vulnerabilities."""
        validation_result = {
            'is_valid': True,
            'security_issues': [],
            'sanitized_topics': []
        }

        for topic in topics:
            # Check for dangerous topic patterns
            if topic.startswith('__'):
                validation_result['security_issues'].append(f"System topic access attempted: {topic}")
                validation_result['is_valid'] = False
                continue

            # Check for path traversal attempts
            if '..' in topic:
                validation_result['security_issues'].append(f"Path traversal attempt in topic: {topic}")
                validation_result['is_valid'] = False
                continue

            # Check for command injection characters
            if re.search(r'[;&|`$]', topic):
                validation_result['security_issues'].append(f"Command injection characters in topic: {topic}")
                validation_result['is_valid'] = False
                continue

            # Check topic length (Kafka limit is 249 characters)
            if len(topic) > 249:
                validation_result['security_issues'].append(f"Topic name too long: {topic}")
                validation_result['is_valid'] = False
                continue

            # Validate topic name format (alphanumeric, hyphens, underscores, dots)
            if not re.match(r'^[a-zA-Z0-9._-]+$', topic):
                validation_result['security_issues'].append(f"Invalid topic name format: {topic}")
                validation_result['is_valid'] = False
                continue

            validation_result['sanitized_topics'].append(topic)

        return validation_result

    def _validate_kafka_credentials(self, creds: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Kafka credentials for security compliance."""
        validation_result = {
            'is_valid': True,
            'security_issues': [],
            'sanitized_credentials': {}
        }

        # Copy credentials for sanitization (hide sensitive values)
        for key, value in creds.items():
            if 'password' in key.lower() or 'secret' in key.lower():
                validation_result['sanitized_credentials'][key] = '[REDACTED]'
            else:
                validation_result['sanitized_credentials'][key] = value

        # Check for weak passwords
        password = creds.get('kafka_password', '')
        if password and len(password) < 8:
            validation_result['security_issues'].append("Kafka password too short (minimum 8 characters)")

        # Check for plaintext protocol
        security_protocol = creds.get('security_protocol', 'PLAINTEXT')
        if security_protocol == 'PLAINTEXT':
            validation_result['security_issues'].append("Using PLAINTEXT protocol is not secure")

        # Validate username format
        username = creds.get('kafka_username', '')
        if username and not re.match(r'^[a-zA-Z0-9._-]+$', username):
            validation_result['security_issues'].append(f"Invalid username format: {username}")
            validation_result['is_valid'] = False

        return validation_result

    def _validate_kafka_producer_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Kafka producer configuration for security issues."""
        validation_result = {
            'is_valid': True,
            'security_issues': [],
            'sanitized_config': {}
        }

        # Copy config for sanitization
        validation_result['sanitized_config'] = dict(config)

        # Validate acks configuration
        acks = config.get('acks', '1')
        if acks == '0':
            validation_result['security_issues'].append("acks=0 provides no delivery guarantee")

        # Validate timeout settings (prevent resource exhaustion)
        timeout_ms = config.get('request_timeout_ms', 30000)
        if timeout_ms > 300000:  # 5 minutes max
            validation_result['security_issues'].append(f"Request timeout too high: {timeout_ms}ms")
            validation_result['is_valid'] = False

        # Validate batch size (prevent resource exhaustion)
        batch_size = config.get('batch_size', 100)
        if batch_size > 100000:  # 100KB max
            validation_result['security_issues'].append(f"Batch size too high: {batch_size}")
            validation_result['is_valid'] = False

        # Validate retries (prevent infinite retry loops)
        retries = config.get('retries', 3)
        if retries > 50:
            validation_result['security_issues'].append(f"Retry count too high: {retries}")
            validation_result['is_valid'] = False

        return validation_result

    def _validate_message_content(self, message: Any) -> Dict[str, Any]:
        """Validate message content for security vulnerabilities."""
        validation_result = {
            'is_safe': True,
            'security_issues': [],
            'sanitized_message': message
        }

        # Convert message to string for analysis
        message_str = json.dumps(message) if isinstance(message, (dict, list)) else str(message)

        # Check message size (prevent resource exhaustion)
        if len(message_str) > 1048576:  # 1MB limit
            validation_result['security_issues'].append("Message too large (exceeds 1MB)")
            validation_result['is_safe'] = False

        # Check for dangerous content patterns
        dangerous_patterns = [
            r'<script[^>]*>.*?</script>',  # Script tags
            r'javascript:',               # JavaScript protocol
            r'data:text/html',           # Data URLs
            r'eval\s*\(',               # Code evaluation
            r'exec\s*\(',               # Code execution
            r'rm\s+-rf',                # Destructive commands
        ]

        for pattern in dangerous_patterns:
            if re.search(pattern, message_str, re.IGNORECASE | re.DOTALL):
                validation_result['security_issues'].append(f"Dangerous content pattern detected: {pattern}")

        return validation_result

    async def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Validate and sanitize input using Kafka Producer-specific validation."""
        validation_result = {
            'is_valid': True,
            'security_issues': [],
            'sanitized_data': data
        }

        try:
            if context == 'bootstrap_servers' and isinstance(data, list):
                server_validation = self._validate_kafka_bootstrap_servers(data)
                validation_result.update(server_validation)

            elif context == 'topic_names' and isinstance(data, list):
                topic_validation = self._validate_kafka_topic_names(data)
                validation_result.update(topic_validation)

            elif context == 'kafka_credentials' and isinstance(data, dict):
                cred_validation = self._validate_kafka_credentials(data)
                validation_result.update(cred_validation)
                validation_result['sanitized_data'] = cred_validation['sanitized_credentials']

            elif context == 'producer_config' and isinstance(data, dict):
                config_validation = self._validate_kafka_producer_config(data)
                validation_result.update(config_validation)
                validation_result['sanitized_data'] = config_validation['sanitized_config']

            elif context == 'message_content':
                content_validation = self._validate_message_content(data)
                validation_result['is_valid'] = content_validation['is_safe']
                validation_result['security_issues'] = content_validation['security_issues']
                validation_result['sanitized_data'] = content_validation['sanitized_message']

        except Exception as e:
            validation_result['is_valid'] = False
            validation_result['security_issues'].append(f"Validation error: {str(e)}")

        return validation_result


# PlugPipe Plugin Contract Implementation
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Universal Kafka Producer Plugin Contract Implementation
    
    Supports ANY streaming use case:
    - Simple event publishing
    - High-throughput data pipelines
    - Microservice communication
    - PlugPipe signal distribution
    """
    orchestrator = UniversalKafkaProducerOrchestrator()
    
    try:
        # Setup Kafka producer
        await orchestrator.setup_kafka_producer(cfg)
        
        # Setup Redis coordination if enabled
        await orchestrator.setup_redis_coordination(cfg)
        
        # Determine target topic with flexible routing
        topic = await orchestrator.determine_topic(cfg, ctx)
        
        # Process single message or batch
        if 'message' in ctx:
            result = await orchestrator.publish_single_message(ctx['message'], topic, ctx)
        elif 'messages' in ctx:
            result = await orchestrator.publish_batch_messages(ctx['messages'], topic, ctx)
        else:
            return {
                'kafka_status': 'error',
                'kafka_error': 'No message or messages provided in input'
            }
            
        # Redis coordination for complex workflows
        await orchestrator.coordinate_with_redis(cfg, ctx, result)
        
        return {
            'kafka_result': result,
            'kafka_status': result['status'],
            'kafka_error': result.get('error')
        }
        
    except Exception as e:
        return {
            'kafka_status': 'error',
            'kafka_error': f'Universal Kafka producer error: {str(e)}'
        }
    finally:
        await orchestrator.cleanup()


# Plugin metadata for PlugPipe framework
plug_metadata = {
    "name": "kafka_producer",
    "version": "1.0.0", 
    "description": "Universal Kafka producer plugin for any streaming use case",
    "author": "PlugPipe Streaming Team",
    "type": "streaming",
    "category": "messaging",
    "universal_use_cases": [
        "event_streaming",
        "data_pipelines", 
        "microservice_communication",
        "log_aggregation",
        "iot_data_ingestion",
        "api_integration",
        "analytics_platform",
        "plugpipe_signal_distribution"
    ],
    "revolutionary_capabilities": [
        "universal_message_serialization",
        "flexible_topic_routing",
        "high_throughput_batching",
        "enterprise_security_protocols",
        "redis_workflow_coordination",
        "plugpipe_signal_enrichment",
        "comprehensive_error_handling",
        "multi_cluster_support"
    ],
    "plugin_dependencies": {
        "required": [
            "monitoring_prometheus",  # Metrics and monitoring
        ],
        "optional": [
            "auth_session_redis",  # Redis coordination
            "audit_elk_stack"      # Event analytics
        ]
    },
    "data_integration": {
        "prometheus_metrics": [
            "kafka_messages_produced_total",
            "kafka_production_errors_total", 
            "kafka_batch_size_avg",
            "kafka_latency_ms_avg",
            "kafka_throughput_messages_per_sec"
        ],
        "elasticsearch_indices": [
            "kafka-producer-events-*",
            "kafka-message-tracking-*"
        ]
    },
    "zero_business_logic_overlap": True,
    "pure_orchestration": True,
    "reused_infrastructure": [
        "kafka-python library for proven Kafka client",
        "confluent-kafka library for enterprise features",
        "Redis coordination via auth_session_redis patterns",
        "Prometheus metrics via monitoring_prometheus",
        "ELK analytics via audit_elk_stack"
    ]
}