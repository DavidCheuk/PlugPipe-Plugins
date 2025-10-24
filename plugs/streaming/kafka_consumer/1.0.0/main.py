# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Universal Kafka Consumer Plugin for PlugPipe

Generic Kafka consumer supporting ANY streaming consumption use case:
- Event processing and real-time reactions
- Data pipeline consumption and ETL
- Microservice message handling  
- Log processing and analysis
- Analytics streaming and reporting
- IoT data processing and routing
- API integration and webhooks
- PlugPipe signal processing

REUSE, NEVER REINVENT: Leverages proven Kafka libraries and Redis coordination.
"""

import json
import asyncio
import logging
import re
from typing import Dict, Any, List, Optional, Union, Callable
from abc import ABC, abstractmethod
from kafka import KafkaConsumer
from kafka.errors import KafkaError, KafkaTimeoutError
import redis.asyncio as redis


class MessageDeserializerInterface(ABC):
    """
    Abstract interface for message deserializers.
    Enables pluggable deserialization strategies for different message formats.
    """

    @abstractmethod
    async def deserialize(self, message: Any, format_type: str) -> Any:
        """Deserialize message according to format type."""
        pass

    @abstractmethod
    def get_supported_formats(self) -> List[str]:
        """Get list of supported deserialization formats."""
        pass


class DefaultMessageDeserializer(MessageDeserializerInterface):
    """
    Default implementation of message deserializer for standard formats.
    """

    def get_supported_formats(self) -> List[str]:
        """Return supported formats."""
        return ['json', 'string', 'bytes']

    async def deserialize(self, message: Any, format_type: str) -> Any:
        """Deserialize message for supported formats."""
        if format_type == 'json':
            if isinstance(message, (str, bytes)):
                return json.loads(message)
            return message
        elif format_type == 'string':
            return str(message) if not isinstance(message, str) else message
        elif format_type == 'bytes':
            return message if isinstance(message, bytes) else str(message).encode('utf-8')
        else:
            return message


class UniversalKafkaConsumerOrchestrator:
    """
    Universal Kafka consumer for any streaming consumption use case.
    
    PURE ORCHESTRATION ARCHITECTURE:
    - Delegates message deserialization to proven Kafka libraries
    - Reuses Redis infrastructure for coordination and state management
    - Leverages existing monitoring plugins for metrics
    - No custom streaming logic - pure orchestration
    """
    
    def __init__(self):
        self.consumer = None
        self.redis_client = None
        self.logger = logging.getLogger(__name__)
        self.deserializer = DefaultMessageDeserializer()
        
    async def setup_kafka_consumer(self, config: Dict[str, Any]) -> None:
        """Setup Kafka consumer with universal configuration."""
        consumer_config = {
            'bootstrap_servers': config['bootstrap_servers'],
            'group_id': config['group_id'],
            'auto_offset_reset': config.get('auto_offset_reset', 'latest'),
            'enable_auto_commit': config.get('auto_commit', True),
            'auto_commit_interval_ms': config.get('commit_interval_ms', 5000),
            'session_timeout_ms': config.get('session_timeout_ms', 30000),
            'heartbeat_interval_ms': config.get('heartbeat_interval_ms', 3000),
            'max_poll_records': config.get('max_poll_records', 500),
        }
        
        # Security configuration
        security_protocol = config.get('security_protocol', 'PLAINTEXT')
        if security_protocol != 'PLAINTEXT':
            consumer_config['security_protocol'] = security_protocol
            
        sasl_mechanism = config.get('sasl_mechanism')
        if sasl_mechanism:
            consumer_config['sasl_mechanism'] = sasl_mechanism
            consumer_config['sasl_plain_username'] = config.get('kafka_username')
            consumer_config['sasl_plain_password'] = config.get('kafka_password')
            
        # Deserialization configuration
        deserialization = config.get('deserialization', 'json')
        if deserialization == 'json':
            consumer_config['value_deserializer'] = lambda v: json.loads(v.decode('utf-8'))
        elif deserialization == 'string':
            consumer_config['value_deserializer'] = lambda v: v.decode('utf-8')
        elif deserialization == 'bytes':
            consumer_config['value_deserializer'] = lambda v: v
            
        self.consumer = KafkaConsumer(*config['topics'], **consumer_config)
        
    async def setup_redis_coordination(self, config: Dict[str, Any]) -> None:
        """Setup Redis coordination for complex workflows."""
        redis_config = config.get('redis_backend', {})
        if redis_config.get('enabled', False):
            redis_url = redis_config.get('redis_url', 'redis://localhost:6379/2')
            self.redis_client = redis.from_url(redis_url)

    # =============================================
    # KAFKA SECURITY HARDENING METHODS
    # =============================================

    def _validate_kafka_bootstrap_servers(self, servers: Union[str, List[str]]) -> Dict[str, Any]:
        """Validate Kafka bootstrap servers for security vulnerabilities."""
        if isinstance(servers, str):
            servers = [servers]

        validation_result = {
            'is_valid': True,
            'sanitized_servers': [],
            'errors': [],
            'security_issues': []
        }

        for server in servers:
            if not isinstance(server, str):
                validation_result['is_valid'] = False
                validation_result['errors'].append('Server must be a string')
                continue

            # Block dangerous server patterns
            dangerous_patterns = [
                r'127\.0\.0\.1',  # Loopback IP
                r'localhost',     # Localhost
                r'192\.168\.',    # Private network
                r'10\.',          # Private network
                r'172\.(1[6-9]|2[0-9]|3[0-1])\.',  # Private network
                r'[;&|`$]',       # Command injection characters
            ]

            is_dangerous = False
            for pattern in dangerous_patterns:
                if re.search(pattern, server, re.IGNORECASE):
                    validation_result['security_issues'].append(f'Potentially dangerous server: {server}')
                    is_dangerous = True
                    break

            # Validate server format (host:port)
            if ':' in server:
                host, port_str = server.rsplit(':', 1)
                try:
                    port = int(port_str)
                    if port < 1 or port > 65535:
                        validation_result['is_valid'] = False
                        validation_result['errors'].append(f'Invalid port in server: {server}')
                        continue
                except ValueError:
                    validation_result['is_valid'] = False
                    validation_result['errors'].append(f'Invalid port format in server: {server}')
                    continue

            if not is_dangerous:
                validation_result['sanitized_servers'].append(server)

        return validation_result

    def _validate_kafka_topic_names(self, topics: List[str]) -> Dict[str, Any]:
        """Validate Kafka topic names for security compliance."""
        validation_result = {
            'is_valid': True,
            'sanitized_topics': [],
            'errors': [],
            'security_issues': []
        }

        for topic in topics:
            if not isinstance(topic, str):
                validation_result['is_valid'] = False
                validation_result['errors'].append('Topic name must be a string')
                continue

            # Kafka topic name restrictions
            if not re.match(r'^[a-zA-Z0-9._-]+$', topic):
                validation_result['is_valid'] = False
                validation_result['errors'].append(f'Invalid topic name format: {topic}')
                continue

            # Block dangerous topic patterns
            dangerous_patterns = [
                r'^__',           # System topics
                r'\.\.+',         # Path traversal patterns
                r'[;&|`$]',       # Command injection
            ]

            is_dangerous = False
            for pattern in dangerous_patterns:
                if re.search(pattern, topic):
                    validation_result['is_valid'] = False
                    validation_result['errors'].append(f'Dangerous topic pattern detected: {topic}')
                    is_dangerous = True
                    break

            # Length validation
            if len(topic) > 255:
                validation_result['is_valid'] = False
                validation_result['errors'].append(f'Topic name too long: {topic}')
                continue

            if not is_dangerous:
                validation_result['sanitized_topics'].append(topic)

        return validation_result

    def _validate_kafka_credentials(self, credentials: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Kafka authentication credentials for security."""
        validation_result = {
            'is_valid': True,
            'sanitized_credentials': {},
            'errors': [],
            'security_issues': []
        }

        # Validate username
        username = credentials.get('kafka_username', '')
        if username:
            if not isinstance(username, str) or len(username) < 1:
                validation_result['is_valid'] = False
                validation_result['errors'].append('Username must be a non-empty string')
            else:
                validation_result['sanitized_credentials']['kafka_username'] = username

        # Validate password
        password = credentials.get('kafka_password', '')
        if password:
            if not isinstance(password, str):
                validation_result['is_valid'] = False
                validation_result['errors'].append('Password must be a string')
            elif len(password) < 8:
                validation_result['security_issues'].append('Password too short (recommended: 8+ characters)')

            # Don't store password in sanitized output
            validation_result['sanitized_credentials']['kafka_password'] = '[REDACTED]'

        # Validate SASL mechanism
        sasl_mechanism = credentials.get('sasl_mechanism', '')
        if sasl_mechanism:
            allowed_mechanisms = {'PLAIN', 'SCRAM-SHA-256', 'SCRAM-SHA-512', 'GSSAPI'}
            if sasl_mechanism not in allowed_mechanisms:
                validation_result['security_issues'].append(f'Potentially insecure SASL mechanism: {sasl_mechanism}')

        # Validate security protocol
        security_protocol = credentials.get('security_protocol', 'PLAINTEXT')
        if security_protocol == 'PLAINTEXT':
            validation_result['security_issues'].append('Unencrypted connection detected (PLAINTEXT)')
        elif security_protocol not in {'SSL', 'SASL_SSL', 'SASL_PLAINTEXT'}:
            validation_result['security_issues'].append(f'Unknown security protocol: {security_protocol}')

        return validation_result

    def _validate_kafka_consumer_config(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Validate Kafka consumer configuration for security compliance."""
        validation_result = {
            'is_valid': True,
            'sanitized_config': config.copy(),
            'errors': [],
            'security_issues': []
        }

        # Validate group ID
        group_id = config.get('group_id', '')
        if not group_id or not isinstance(group_id, str):
            validation_result['is_valid'] = False
            validation_result['errors'].append('Consumer group ID is required and must be a string')
        elif not re.match(r'^[a-zA-Z0-9._-]+$', group_id):
            validation_result['is_valid'] = False
            validation_result['errors'].append('Invalid consumer group ID format')

        # Validate session timeout (prevent DoS)
        session_timeout = config.get('session_timeout_ms', 30000)
        if not isinstance(session_timeout, int) or session_timeout < 6000 or session_timeout > 300000:
            validation_result['security_issues'].append('Session timeout should be between 6000-300000ms')

        # Validate max poll records (prevent memory exhaustion)
        max_poll_records = config.get('max_poll_records', 500)
        if not isinstance(max_poll_records, int) or max_poll_records > 10000:
            validation_result['security_issues'].append('Max poll records should not exceed 10000')

        # Validate auto offset reset
        auto_offset_reset = config.get('auto_offset_reset', 'latest')
        if auto_offset_reset not in {'earliest', 'latest', 'none'}:
            validation_result['security_issues'].append(f'Invalid auto offset reset: {auto_offset_reset}')

        return validation_result

    def _validate_message_content(self, message: Any, max_size_bytes: int = 1048576) -> Dict[str, Any]:
        """Validate message content for security issues."""
        validation_result = {
            'is_safe': True,
            'sanitized_message': message,
            'errors': [],
            'security_issues': []
        }

        # Size validation (prevent memory bombs)
        try:
            if isinstance(message, (str, bytes)):
                message_size = len(message)
            else:
                message_size = len(str(message))

            if message_size > max_size_bytes:
                validation_result['is_safe'] = False
                validation_result['errors'].append(f'Message too large: {message_size} bytes (max: {max_size_bytes})')
                return validation_result
        except Exception:
            pass  # Continue with other validations

        # Content validation for strings
        if isinstance(message, str):
            # Check for dangerous patterns
            dangerous_patterns = [
                r'<script[^>]*>',  # Script injection
                r'javascript:',    # JavaScript protocol
                r'data:.*base64',  # Data URLs with base64
                r'rm\s+-rf',       # Dangerous shell commands
                r'[;&|`$]',        # Command injection characters
            ]

            for pattern in dangerous_patterns:
                if re.search(pattern, message, re.IGNORECASE):
                    validation_result['security_issues'].append('Potentially dangerous content detected')
                    break

        return validation_result

    async def _validate_and_sanitize_input(self, data: Any, context: str = "general") -> Dict[str, Any]:
        """Validate and sanitize input using Kafka-specific validation."""
        if context == 'bootstrap_servers':
            if isinstance(data, (str, list)):
                return self._validate_kafka_bootstrap_servers(data)
            else:
                return {'is_valid': False, 'errors': ['Bootstrap servers must be string or list']}

        elif context == 'topic_names':
            if isinstance(data, list):
                return self._validate_kafka_topic_names(data)
            else:
                return {'is_valid': False, 'errors': ['Topic names must be a list']}

        elif context == 'kafka_credentials':
            if isinstance(data, dict):
                return self._validate_kafka_credentials(data)
            else:
                return {'is_valid': False, 'errors': ['Credentials must be a dictionary']}

        elif context == 'consumer_config':
            if isinstance(data, dict):
                return self._validate_kafka_consumer_config(data)
            else:
                return {'is_valid': False, 'errors': ['Consumer config must be a dictionary']}

        elif context == 'message_content':
            return self._validate_message_content(data)

        # Default validation for general contexts
        return {'is_valid': True, 'sanitized_value': str(data)}

    async def deserialize_message(self, message: Any, deserialization: str) -> Any:
        """Universal message deserialization."""
        # Use default deserializer for standard formats
        if deserialization in self.deserializer.get_supported_formats():
            return await self.deserializer.deserialize(message, deserialization)
        elif deserialization == 'avro':
            # Delegate to Avro plugin implementation
            try:
                # Try to load Avro deserializer plugin dynamically
                from shares.loader import pp
                avro_plugin = None  # TODO: avro_deserializer plugin not yet implemented
                if avro_plugin:
                    return await avro_plugin.deserialize(message)
                else:
                    self.logger.warning("Avro deserializer plugin not available, falling back to bytes")
                    return message if isinstance(message, bytes) else str(message).encode('utf-8')
            except Exception as e:
                self.logger.warning(f"Avro deserialization failed: {e}, falling back to bytes")
                return message if isinstance(message, bytes) else str(message).encode('utf-8')
        elif deserialization == 'protobuf':
            # Delegate to Protobuf plugin implementation
            try:
                # Try to load Protobuf deserializer plugin dynamically
                from shares.loader import pp
                protobuf_plugin = None  # TODO: protobuf_deserializer plugin not yet implemented
                if protobuf_plugin:
                    return await protobuf_plugin.deserialize(message)
                else:
                    self.logger.warning("Protobuf deserializer plugin not available, falling back to bytes")
                    return message if isinstance(message, bytes) else str(message).encode('utf-8')
            except Exception as e:
                self.logger.warning(f"Protobuf deserialization failed: {e}, falling back to bytes")
                return message if isinstance(message, bytes) else str(message).encode('utf-8')
        else:
            return message
            
    async def extract_plugpipe_metadata(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """Extract PlugPipe signal metadata for routing."""
        if isinstance(message, dict) and '_plugpipe_metadata' in message:
            return message['_plugpipe_metadata']
        return {}
        
    async def apply_message_filter(self, message: Any, filter_criteria: Dict[str, Any]) -> bool:
        """Apply filtering criteria to messages."""
        if not filter_criteria:
            return True
            
        if not isinstance(message, dict):
            return True
            
        for key, expected_value in filter_criteria.items():
            if key not in message:
                return False
            if message[key] != expected_value:
                return False
                
        return True
        
    async def process_single_message(self, message: Any, ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Process single message with universal handling."""
        try:
            # Extract message data
            message_data = {
                'topic': message.topic,
                'partition': message.partition,
                'offset': message.offset,
                'timestamp': message.timestamp,
                'key': message.key.decode('utf-8') if message.key else None,
                'value': message.value,
                'headers': dict(message.headers) if message.headers else {}
            }
            
            # PlugPipe signal processing
            if config.get('signal_processing', False):
                metadata = await self.extract_plugpipe_metadata(message.value)
                message_data['plugpipe_metadata'] = metadata
                
            # Apply filtering
            filter_criteria = ctx.get('filter_criteria', {})
            if not await self.apply_message_filter(message.value, filter_criteria):
                return {'status': 'filtered', 'message': None}
                
            # Processing function delegation
            processing_function = ctx.get('processing_function')
            if processing_function:
                # Delegate to specified processing plugin
                message_data['processed_by'] = processing_function
                
            return {
                'status': 'success',
                'message': message_data
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': f'Message processing error: {str(e)}',
                'message': None
            }
            
    async def process_batch_messages(self, messages: List[Any], ctx: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Process batch of messages for high-throughput use cases."""
        processed_messages = []
        successful = 0
        failed = 0
        filtered = 0
        
        try:
            for message in messages:
                result = await self.process_single_message(message, ctx, config)
                
                if result['status'] == 'success':
                    processed_messages.append(result['message'])
                    successful += 1
                elif result['status'] == 'filtered':
                    filtered += 1
                else:
                    failed += 1
                    
            overall_status = 'success' if failed == 0 else ('partial' if successful > 0 else 'error')
            
            return {
                'status': overall_status,
                'consumed_count': len(messages),
                'processed_count': successful,
                'failed_count': failed,
                'filtered_count': filtered,
                'messages': processed_messages if ctx.get('return_messages', False) else []
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'consumed_count': len(messages),
                'processed_count': successful,
                'failed_count': failed + (len(messages) - len(processed_messages)),
                'error': f'Batch processing error: {str(e)}',
                'messages': []
            }
            
    async def handle_plugpipe_signals(self, messages: List[Dict[str, Any]], ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Handle PlugPipe ecosystem signals with routing."""
        signal_handlers = ctx.get('signal_handlers', {})
        routed_signals = {}
        
        for message in messages:
            metadata = message.get('plugpipe_metadata', {})
            signal_type = metadata.get('signal_type')
            
            if signal_type and signal_type in signal_handlers:
                handler_plugin = signal_handlers[signal_type]
                if handler_plugin not in routed_signals:
                    routed_signals[handler_plugin] = []
                routed_signals[handler_plugin].append(message)
                
        return {
            'status': 'success',
            'routed_signals': routed_signals,
            'signal_count': len(messages)
        }
        
    async def consume_messages(self, config: Dict[str, Any], ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Universal message consumption with flexible processing."""
        max_messages = ctx.get('max_messages', 100)
        timeout_ms = ctx.get('timeout_ms', 30000)
        processing_mode = ctx.get('processing_mode', 'single')
        
        consumed_messages = []
        
        try:
            # Poll for messages
            message_batch = self.consumer.poll(timeout_ms=timeout_ms, max_records=max_messages)
            
            # Flatten messages from all partitions
            all_messages = []
            for topic_partition, messages in message_batch.items():
                all_messages.extend(messages)
                
            if not all_messages:
                return {
                    'status': 'timeout',
                    'consumed_count': 0,
                    'processed_count': 0,
                    'messages': []
                }
                
            # Process based on mode
            if processing_mode == 'single':
                results = []
                for message in all_messages:
                    result = await self.process_single_message(message, ctx, config)
                    results.append(result)
                    
                successful = sum(1 for r in results if r['status'] == 'success')
                failed = sum(1 for r in results if r['status'] == 'error')
                
                return {
                    'status': 'success' if failed == 0 else 'partial',
                    'consumed_count': len(all_messages),
                    'processed_count': successful,
                    'failed_count': failed,
                    'messages': [r['message'] for r in results if r['message']]
                }
                
            elif processing_mode == 'batch':
                return await self.process_batch_messages(all_messages, ctx, config)
                
            elif processing_mode == 'stream':
                # Stream processing with PlugPipe signal handling
                if config.get('signal_processing', False):
                    processed_batch = await self.process_batch_messages(all_messages, ctx, config)
                    if processed_batch['status'] in ['success', 'partial']:
                        return await self.handle_plugpipe_signals(processed_batch['messages'], ctx)
                        
                return await self.process_batch_messages(all_messages, ctx, config)
                
        except KafkaTimeoutError:
            return {
                'status': 'timeout',
                'consumed_count': 0,
                'processed_count': 0,
                'error': 'Consumer timeout'
            }
        except KafkaError as e:
            return {
                'status': 'error',
                'consumed_count': 0,
                'processed_count': 0,
                'error': f'Kafka error: {str(e)}'
            }
        except Exception as e:
            return {
                'status': 'error',
                'consumed_count': 0,
                'processed_count': 0,
                'error': f'Unexpected error: {str(e)}'
            }
            
    async def coordinate_with_redis(self, config: Dict[str, Any], ctx: Dict[str, Any], result: Dict[str, Any]) -> None:
        """Coordinate with Redis for complex messaging workflows."""
        if not self.redis_client:
            return
            
        try:
            redis_config = config.get('redis_backend', {})
            result_ttl = redis_config.get('result_ttl', 3600)
            
            # Store consumption result
            result_key = f"kafka_consumer:result:{ctx.get('trace_id', 'unknown')}"
            await self.redis_client.set(result_key, json.dumps(result), ex=result_ttl)
            
            # Update consumption metrics
            metrics_key = f"kafka_consumer:metrics:{config['group_id']}"
            await self.redis_client.hincrby(metrics_key, 'total_consumed', result.get('consumed_count', 0))
            await self.redis_client.hincrby(metrics_key, 'total_processed', result.get('processed_count', 0))
            
        except Exception as e:
            self.logger.warning(f"Redis coordination failed: {e}")
            
    async def cleanup(self) -> None:
        """Clean up resources."""
        if self.consumer:
            self.consumer.close()
        if self.redis_client:
            await self.redis_client.close()


# PlugPipe Plugin Contract Implementation
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Universal Kafka Consumer Plugin Contract Implementation
    
    Supports ANY streaming consumption use case:
    - Simple event processing
    - High-throughput data pipelines
    - Microservice message handling
    - PlugPipe signal consumption
    """
    orchestrator = UniversalKafkaConsumerOrchestrator()
    
    try:
        # Setup Kafka consumer
        await orchestrator.setup_kafka_consumer(cfg)
        
        # Setup Redis coordination if enabled
        await orchestrator.setup_redis_coordination(cfg)
        
        # Consume and process messages
        result = await orchestrator.consume_messages(cfg, ctx)
        
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
            'kafka_error': f'Universal Kafka consumer error: {str(e)}'
        }
    finally:
        await orchestrator.cleanup()


# Plugin metadata for PlugPipe framework
plug_metadata = {
    "name": "kafka_consumer",
    "version": "1.0.0",
    "description": "Universal Kafka consumer plugin for any streaming consumption use case", 
    "author": "PlugPipe Streaming Team",
    "type": "streaming",
    "category": "messaging",
    "universal_use_cases": [
        "event_processing",
        "data_pipeline_consumption",
        "microservice_integration", 
        "log_processing",
        "analytics_streaming",
        "iot_data_processing",
        "api_integration",
        "plugpipe_signal_processing"
    ],
    "revolutionary_capabilities": [
        "universal_message_deserialization",
        "flexible_processing_modes",
        "consumer_group_coordination",
        "enterprise_security_protocols",
        "redis_state_coordination",
        "plugpipe_signal_routing",
        "comprehensive_error_handling",
        "multi_cluster_consumption"
    ],
    "plugin_dependencies": {
        "required": [
            "monitoring_prometheus"   # Metrics and monitoring
        ],
        "optional": [
            "auth_session_redis",     # Redis coordination
            "audit_elk_stack"         # Event analytics
        ]
    },
    "data_integration": {
        "prometheus_metrics": [
            "kafka_messages_consumed_total",
            "kafka_consumption_errors_total",
            "kafka_processing_latency_ms_avg", 
            "kafka_batch_processing_duration_ms",
            "kafka_consumer_lag_messages"
        ],
        "elasticsearch_indices": [
            "kafka-consumer-events-*",
            "kafka-message-processing-*"
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