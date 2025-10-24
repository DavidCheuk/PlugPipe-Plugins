#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enhanced MCP Audit Integration
Extends existing ELK stack plugin with MCP-specific audit events and security monitoring
Following PlugPipe's "REUSE EVERYTHING, REINVENT NOTHING" principle.
"""

import asyncio
import json
import logging
import sys
import os
from datetime import datetime, timedelta
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from enum import Enum
import hashlib
import uuid

# Add parent directory to path for plugin imports
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(__file__))))

class AuditLevel(Enum):
    """MCP audit levels"""
    BASIC = "basic"
    STANDARD = "standard"
    ENTERPRISE = "enterprise"

class MCPEventType(Enum):
    """MCP audit event types"""
    TOOL_EXECUTION = "mcp_tool_execution"
    RESOURCE_ACCESS = "mcp_resource_access"
    PROMPT_REQUEST = "mcp_prompt_request"
    AUTHENTICATION = "mcp_authentication_events"
    AUTHORIZATION = "mcp_authorization_decisions"
    POLICY_VIOLATION = "mcp_policy_violations"
    OAUTH2_TOKEN_USAGE = "mcp_oauth2_token_usage"
    RATE_LIMITING = "mcp_rate_limiting_events"
    SECURITY_THREAT = "mcp_security_threats"
    COMPLIANCE = "mcp_compliance_events"

@dataclass
class MCPAuditEvent:
    """MCP audit event structure"""
    event_id: str
    event_type: MCPEventType
    timestamp: datetime
    user_id: str
    session_id: Optional[str]
    client_id: Optional[str]
    mcp_endpoint: Optional[str]
    event_data: Dict[str, Any]
    severity: str
    source_ip: Optional[str] = None
    user_agent: Optional[str] = None
    correlation_id: Optional[str] = None

class EnhancedMCPAuditIntegration:
    """
    Enhanced MCP Audit Integration
    Extends ELK stack with MCP-specific structured audit events
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # Audit configuration
        self.audit_level = AuditLevel(config.get('mcp_audit_level', 'standard'))
        self.real_time_monitoring = config.get('real_time_monitoring', True)
        self.compliance_frameworks = config.get('compliance_frameworks', [])
        self.retention_days = config.get('retention_days', 365)
        
        # ELK stack integration
        self.elk_plugin = None
        
        # Event configuration
        self.event_configs = {
            MCPEventType.TOOL_EXECUTION: {
                'fields': ['timestamp', 'user_id', 'tool_name', 'arguments', 'result', 'duration_ms', 'cost', 'success'],
                'index': 'mcp-tools',
                'retention_days': 90
            },
            MCPEventType.RESOURCE_ACCESS: {
                'fields': ['timestamp', 'user_id', 'resource_type', 'resource_id', 'action', 'success', 'data_size'],
                'index': 'mcp-resources', 
                'retention_days': 365
            },
            MCPEventType.AUTHENTICATION: {
                'fields': ['timestamp', 'user_id', 'client_id', 'oauth_flow', 'token_type', 'success', 'failure_reason'],
                'index': 'mcp-auth',
                'retention_days': 730
            },
            MCPEventType.AUTHORIZATION: {
                'fields': ['timestamp', 'user_id', 'mcp_endpoint', 'policy_engine', 'decision', 'confidence', 'approval_required'],
                'index': 'mcp-authz',
                'retention_days': 365
            },
            MCPEventType.POLICY_VIOLATION: {
                'fields': ['timestamp', 'user_id', 'violation_type', 'severity', 'details', 'action_taken'],
                'index': 'mcp-violations',
                'retention_days': 2555  # 7 years for compliance
            },
            MCPEventType.SECURITY_THREAT: {
                'fields': ['timestamp', 'user_id', 'threat_type', 'confidence', 'indicators', 'blocked', 'source_ip'],
                'index': 'mcp-threats',
                'retention_days': 1095  # 3 years
            }
        }
        
        # Active events based on audit level
        self.active_events = self._get_active_events()
        
    def _get_active_events(self) -> List[MCPEventType]:
        """Get active event types based on audit level"""
        
        event_levels = {
            AuditLevel.BASIC: [
                MCPEventType.TOOL_EXECUTION,
                MCPEventType.AUTHENTICATION,
                MCPEventType.AUTHORIZATION
            ],
            AuditLevel.STANDARD: [
                MCPEventType.TOOL_EXECUTION,
                MCPEventType.RESOURCE_ACCESS,
                MCPEventType.PROMPT_REQUEST,
                MCPEventType.AUTHENTICATION,
                MCPEventType.AUTHORIZATION,
                MCPEventType.POLICY_VIOLATION
            ],
            AuditLevel.ENTERPRISE: [
                MCPEventType.TOOL_EXECUTION,
                MCPEventType.RESOURCE_ACCESS,
                MCPEventType.PROMPT_REQUEST,
                MCPEventType.AUTHENTICATION,
                MCPEventType.AUTHORIZATION,
                MCPEventType.POLICY_VIOLATION,
                MCPEventType.OAUTH2_TOKEN_USAGE,
                MCPEventType.RATE_LIMITING,
                MCPEventType.SECURITY_THREAT,
                MCPEventType.COMPLIANCE
            ]
        }
        
        return event_levels.get(self.audit_level, event_levels[AuditLevel.STANDARD])
        
    async def initialize_elk_integration(self):
        """Initialize connection to existing ELK stack plugin"""
        try:
            # Import existing ELK stack plugin
            from audit_elk_stack.main import AuditELKStack
            
            elk_config = {
                'elasticsearch_url': self.config.get('elasticsearch_url', 'http://localhost:9200'),
                'kibana_url': self.config.get('kibana_url', 'http://localhost:5601'),
                'index_prefix': 'mcp-audit'
            }
            
            self.elk_plugin = AuditELKStack(elk_config)
            self.logger.info("Successfully initialized ELK stack integration")
            
        except ImportError:
            self.logger.warning("ELK stack plugin not available, using local logging")
            self.elk_plugin = None
            
    async def log_mcp_audit_event(self, event: MCPAuditEvent) -> Dict[str, Any]:
        """
        Log MCP audit event through structured pipeline
        
        Args:
            event: MCP audit event to log
            
        Returns:
            Logging result with event ID and status
        """
        
        # Check if event type is active
        if event.event_type not in self.active_events:
            return {
                'success': True,
                'event_id': event.event_id,
                'status': 'filtered',
                'reason': f'Event type {event.event_type.value} not active for audit level {self.audit_level.value}'
            }
            
        # Prepare structured event data
        structured_event = self._structure_audit_event(event)
        
        # Log with ELK stack if available
        if self.elk_plugin:
            try:
                elk_result = await self._log_with_elk_stack(event.event_type, structured_event)
                
                # Real-time monitoring alerts
                if self.real_time_monitoring:
                    await self._check_real_time_alerts(event, structured_event)
                    
                return {
                    'success': True,
                    'event_id': event.event_id,
                    'status': 'logged',
                    'elk_result': elk_result,
                    'index': self.event_configs[event.event_type]['index']
                }
                
            except Exception as e:
                self.logger.error(f"ELK logging failed for event {event.event_id}: {e}")
                # Fall back to local logging
                return await self._log_locally(event, structured_event)
        else:
            return await self._log_locally(event, structured_event)
            
    def _structure_audit_event(self, event: MCPAuditEvent) -> Dict[str, Any]:
        """Structure audit event for ELK ingestion"""
        
        event_config = self.event_configs.get(event.event_type, {})
        required_fields = event_config.get('fields', [])
        
        # Base event structure
        structured_event = {
            'event_id': event.event_id,
            'event_type': event.event_type.value,
            'timestamp': event.timestamp.isoformat(),
            'user_id': event.user_id,
            'session_id': event.session_id,
            'client_id': event.client_id,
            'mcp_endpoint': event.mcp_endpoint,
            'severity': event.severity,
            'source_ip': event.source_ip,
            'user_agent': event.user_agent,
            'correlation_id': event.correlation_id,
            'audit_level': self.audit_level.value,
            'retention_days': event_config.get('retention_days', self.retention_days)
        }
        
        # Add event-specific data
        for field in required_fields:
            if field in event.event_data:
                structured_event[field] = event.event_data[field]
                
        # Add compliance framework tags
        if self.compliance_frameworks:
            structured_event['compliance_frameworks'] = self.compliance_frameworks
            
        # Add data classification
        structured_event['data_classification'] = self._classify_event_data(event)
        
        return structured_event
        
    async def _log_with_elk_stack(self, event_type: MCPEventType, structured_event: Dict[str, Any]) -> Dict[str, Any]:
        """Log event with ELK stack plugin"""
        
        event_config = self.event_configs.get(event_type, {})
        index_name = f"{event_config.get('index', 'mcp-audit')}-{datetime.utcnow().strftime('%Y-%m')}"
        
        # Prepare ELK event
        elk_event = {
            'operation': 'log_event',
            'event_config': {
                'event_type': 'audit',
                'source': 'mcp_audit_integration',
                'user_id': structured_event.get('user_id'),
                'action': event_type.value,
                'message': f"MCP audit event: {event_type.value}"
            },
            'index_name': index_name,
            'event_data': structured_event
        }
        
        # Call ELK plugin
        elk_result = await self.elk_plugin.log_event(elk_event)
        
        return elk_result
        
    async def _log_locally(self, event: MCPAuditEvent, structured_event: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback local logging when ELK not available"""
        
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': 'AUDIT',
            'event_id': event.event_id,
            'event_type': event.event_type.value,
            'user_id': event.user_id,
            'data': structured_event
        }
        
        # Log to file or stdout
        self.logger.info(f"MCP_AUDIT: {json.dumps(log_entry)}")
        
        return {
            'success': True,
            'event_id': event.event_id,
            'status': 'logged_locally',
            'fallback': True
        }
        
    def _classify_event_data(self, event: MCPAuditEvent) -> str:
        """Classify event data for compliance and retention"""
        
        # Classify based on event type and content
        if event.event_type in [MCPEventType.AUTHENTICATION, MCPEventType.AUTHORIZATION]:
            return 'restricted'
        elif event.event_type == MCPEventType.POLICY_VIOLATION:
            return 'confidential'
        elif event.event_type == MCPEventType.SECURITY_THREAT:
            return 'confidential'
        elif 'sensitive' in str(event.event_data).lower():
            return 'restricted'
        else:
            return 'internal'
            
    async def _check_real_time_alerts(self, event: MCPAuditEvent, structured_event: Dict[str, Any]):
        """Check for real-time security alerts"""
        
        alerts = []
        
        # Multiple authentication failures
        if event.event_type == MCPEventType.AUTHENTICATION and not event.event_data.get('success', True):
            alerts.append({
                'type': 'authentication_failure',
                'severity': 'warning',
                'user_id': event.user_id,
                'details': 'Authentication failure detected'
            })
            
        # Policy violations
        if event.event_type == MCPEventType.POLICY_VIOLATION:
            severity = event.event_data.get('severity', 'medium')
            if severity in ['high', 'critical']:
                alerts.append({
                    'type': 'policy_violation',
                    'severity': severity,
                    'user_id': event.user_id,
                    'details': event.event_data.get('details', 'Policy violation detected')
                })
                
        # Security threats
        if event.event_type == MCPEventType.SECURITY_THREAT:
            confidence = event.event_data.get('confidence', 0.5)
            if confidence > 0.8:
                alerts.append({
                    'type': 'security_threat',
                    'severity': 'critical',
                    'user_id': event.user_id,
                    'confidence': confidence,
                    'details': f"High confidence security threat: {event.event_data.get('threat_type', 'unknown')}"
                })
                
        # Process alerts
        for alert in alerts:
            await self._process_security_alert(alert, event)
            
    async def _process_security_alert(self, alert: Dict[str, Any], original_event: MCPAuditEvent):
        """Process real-time security alert"""
        
        # Create alert event
        alert_event = MCPAuditEvent(
            event_id=str(uuid.uuid4()),
            event_type=MCPEventType.SECURITY_THREAT,
            timestamp=datetime.utcnow(),
            user_id=original_event.user_id,
            session_id=original_event.session_id,
            client_id=original_event.client_id,
            mcp_endpoint=original_event.mcp_endpoint,
            event_data={
                'alert_type': alert['type'],
                'severity': alert['severity'],
                'original_event_id': original_event.event_id,
                'details': alert['details'],
                'auto_generated': True
            },
            severity=alert['severity'],
            source_ip=original_event.source_ip,
            correlation_id=original_event.event_id  # Link to original event
        )
        
        # Log alert event
        await self.log_mcp_audit_event(alert_event)
        
        # Additional alert processing (notifications, etc.)
        self.logger.warning(f"Security alert: {alert['type']} for user {original_event.user_id}")
        
    async def search_audit_events(self, search_config: Dict[str, Any]) -> Dict[str, Any]:
        """Search MCP audit events"""
        
        if not self.elk_plugin:
            return {
                'success': False,
                'error': 'ELK stack not available for searching'
            }
            
        try:
            # Prepare search request for ELK
            elk_search = {
                'operation': 'search_logs',
                'search_config': {
                    'index_pattern': search_config.get('index_pattern', 'mcp-*'),
                    'query': search_config.get('query', '*'),
                    'size': search_config.get('size', 100),
                    'sort': [{'timestamp': {'order': 'desc'}}]
                }
            }
            
            # Add time range if specified
            if 'time_range' in search_config:
                time_range = search_config['time_range']
                elk_search['search_config']['time_range'] = {
                    'gte': time_range.get('start', 'now-1d'),
                    'lte': time_range.get('end', 'now')
                }
                
            # Call ELK search
            search_result = await self.elk_plugin.search_logs(elk_search)
            
            # Process and return results
            return {
                'success': True,
                'total_hits': search_result.get('total', 0),
                'events': search_result.get('events', []),
                'aggregations': search_result.get('aggregations', {}),
                'search_time_ms': search_result.get('took', 0)
            }
            
        except Exception as e:
            self.logger.error(f"Audit search failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
            
    async def get_compliance_report(self, framework: str, time_range: Dict[str, str]) -> Dict[str, Any]:
        """Generate compliance report for specified framework"""
        
        if framework not in self.compliance_frameworks:
            return {
                'success': False,
                'error': f'Compliance framework {framework} not enabled'
            }
            
        # Framework-specific event requirements
        framework_events = {
            'sox': [MCPEventType.TOOL_EXECUTION, MCPEventType.AUTHORIZATION, MCPEventType.POLICY_VIOLATION],
            'gdpr': [MCPEventType.RESOURCE_ACCESS, MCPEventType.AUTHENTICATION, MCPEventType.SECURITY_THREAT],
            'hipaa': [MCPEventType.RESOURCE_ACCESS, MCPEventType.AUTHENTICATION, MCPEventType.AUTHORIZATION]
        }
        
        required_events = framework_events.get(framework, [])
        compliance_data = {}
        
        # Search for each required event type
        for event_type in required_events:
            search_config = {
                'query': f'event_type:{event_type.value}',
                'time_range': time_range,
                'size': 1000  # Compliance reports may need larger samples
            }
            
            event_results = await self.search_audit_events(search_config)
            
            if event_results['success']:
                compliance_data[event_type.value] = {
                    'total_events': event_results['total_hits'],
                    'sample_events': event_results['events'][:10],  # Sample for verification
                    'compliance_status': 'compliant' if event_results['total_hits'] > 0 else 'non_compliant'
                }
            else:
                compliance_data[event_type.value] = {
                    'total_events': 0,
                    'compliance_status': 'unknown',
                    'error': event_results.get('error')
                }
                
        # Calculate overall compliance score
        total_requirements = len(required_events)
        compliant_requirements = sum(
            1 for data in compliance_data.values() 
            if data.get('compliance_status') == 'compliant'
        )
        
        compliance_score = compliant_requirements / total_requirements if total_requirements > 0 else 0
        
        return {
            'success': True,
            'framework': framework,
            'time_range': time_range,
            'compliance_score': compliance_score,
            'compliance_percentage': compliance_score * 100,
            'total_requirements': total_requirements,
            'compliant_requirements': compliant_requirements,
            'detailed_results': compliance_data,
            'generated_at': datetime.utcnow().isoformat()
        }

# Helper functions for creating common MCP audit events
def create_tool_execution_event(user_id: str, tool_name: str, arguments: Dict[str, Any], 
                               result: Any, duration_ms: float, cost: float = 0.0, 
                               success: bool = True, **kwargs) -> MCPAuditEvent:
    """Create a tool execution audit event"""
    
    return MCPAuditEvent(
        event_id=str(uuid.uuid4()),
        event_type=MCPEventType.TOOL_EXECUTION,
        timestamp=datetime.utcnow(),
        user_id=user_id,
        session_id=kwargs.get('session_id'),
        client_id=kwargs.get('client_id'),
        mcp_endpoint='tools/call',
        event_data={
            'tool_name': tool_name,
            'arguments': arguments,
            'result': str(result)[:1000] if result else None,  # Truncate large results
            'duration_ms': duration_ms,
            'cost': cost,
            'success': success
        },
        severity='info' if success else 'warning',
        source_ip=kwargs.get('source_ip'),
        user_agent=kwargs.get('user_agent'),
        correlation_id=kwargs.get('correlation_id')
    )

def create_authentication_event(user_id: str, client_id: str, oauth_flow: str,
                               success: bool, failure_reason: str = None, **kwargs) -> MCPAuditEvent:
    """Create an authentication audit event"""
    
    return MCPAuditEvent(
        event_id=str(uuid.uuid4()),
        event_type=MCPEventType.AUTHENTICATION,
        timestamp=datetime.utcnow(),
        user_id=user_id,
        session_id=kwargs.get('session_id'),
        client_id=client_id,
        mcp_endpoint='server/initialize',
        event_data={
            'oauth_flow': oauth_flow,
            'token_type': kwargs.get('token_type', 'bearer'),
            'success': success,
            'failure_reason': failure_reason
        },
        severity='info' if success else 'warning',
        source_ip=kwargs.get('source_ip'),
        user_agent=kwargs.get('user_agent')
    )

def create_policy_violation_event(user_id: str, violation_type: str, severity: str,
                                 details: str, action_taken: str = 'blocked', **kwargs) -> MCPAuditEvent:
    """Create a policy violation audit event"""
    
    return MCPAuditEvent(
        event_id=str(uuid.uuid4()),
        event_type=MCPEventType.POLICY_VIOLATION,
        timestamp=datetime.utcnow(),
        user_id=user_id,
        session_id=kwargs.get('session_id'),
        client_id=kwargs.get('client_id'),
        mcp_endpoint=kwargs.get('mcp_endpoint'),
        event_data={
            'violation_type': violation_type,
            'severity': severity,
            'details': details,
            'action_taken': action_taken
        },
        severity=severity,
        source_ip=kwargs.get('source_ip'),
        correlation_id=kwargs.get('correlation_id')
    )

def process(context: dict, config: dict = None) -> dict:
    """
    PlugPipe standard process function for Enhanced MCP Audit Integration
    
    Args:
        context: Input context with operation and parameters
        config: Plugin configuration
        
    Returns:
        Result dictionary with success status
    """
    try:
        operation = context.get('operation', 'get_status')
        
        # Initialize audit integration
        audit_integration = EnhancedMCPAuditIntegration(config or {})
        
        if operation == 'get_status':
            return {
                'success': True,
                'operation': operation,
                'audit_level': audit_integration.audit_level.value,
                'active_events': [event.value for event in audit_integration.active_events],
                'real_time_monitoring': audit_integration.real_time_monitoring,
                'compliance_frameworks': audit_integration.compliance_frameworks,
                'retention_days': audit_integration.retention_days,
                'elk_integration': audit_integration.elk_plugin is not None
            }
            
        elif operation == 'log_audit_event':
            # Create audit event from context
            event_data = context.get('event_data', {})
            
            audit_event = MCPAuditEvent(
                event_id=context.get('event_id', str(uuid.uuid4())),
                event_type=MCPEventType(context.get('event_type', 'mcp_tool_execution')),
                timestamp=datetime.fromisoformat(context.get('timestamp', datetime.utcnow().isoformat())),
                user_id=context.get('user_id', 'test_user'),
                session_id=context.get('session_id'),
                client_id=context.get('client_id'),
                mcp_endpoint=context.get('mcp_endpoint'),
                event_data=event_data,
                severity=context.get('severity', 'info'),
                source_ip=context.get('source_ip'),
                user_agent=context.get('user_agent'),
                correlation_id=context.get('correlation_id')
            )
            
            # For testing, simulate logging (cannot use async here)
            return {
                'success': True,
                'operation': operation,
                'event_id': audit_event.event_id,
                'event_type': audit_event.event_type.value,
                'user_id': audit_event.user_id,
                'severity': audit_event.severity,
                'status': 'simulated_logging'
            }
            
        elif operation == 'get_audit_summary':
            return {
                'success': True,
                'operation': operation,
                'audit_level': audit_integration.audit_level.value,
                'total_event_types': len(audit_integration.active_events),
                'event_types': [event.value for event in audit_integration.active_events],
                'compliance_frameworks': audit_integration.compliance_frameworks,
                'real_time_monitoring': audit_integration.real_time_monitoring
            }
            
        else:
            return {
                'success': False,
                'operation': operation,
                'error': f'Unknown operation: {operation}. Available: get_status, log_audit_event, get_audit_summary'
            }
            
    except Exception as e:
        return {
            'success': False,
            'operation': context.get('operation', 'unknown'),
            'error': str(e)
        }

def main(input_json=None):
    """Main plugin entry point"""
    
    # Read configuration
    config = {}
    if len(sys.argv) > 1 and not input_json:
        try:
            with open(sys.argv[1], 'r') as f:
                config = json.load(f)
        except Exception as e:
            print(f"Error loading config: {e}", file=sys.stderr)
    
    # Read input
    try:
        if input_json:
            input_data = json.loads(input_json)
        else:
            input_data = json.load(sys.stdin)
    except Exception as e:
        result = {
            'success': False,
            'error': f'Invalid JSON input: {e}'
        }
        print(json.dumps(result))
        return result
    
    # Use the process function for synchronous processing
    try:
        result = process(input_data, config)
        print(json.dumps(result))
        return result
    except Exception as e:
        result = {
            'success': False,
            'operation': input_data.get('operation', 'unknown'),
            'error': str(e)
        }
        print(json.dumps(result))
        return result

if __name__ == '__main__':
    main()