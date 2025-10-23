#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Security Incident Tracker Plugin for PlugPipe

Tracks and reports security incidents from enterprise monitoring system.
Provides 30-day incident tracking, severity analysis, and trend detection.

Category: enterprise
Version: 1.0.0
Owner: Security Team
"""

import logging
from datetime import datetime, timedelta
from typing import Dict, Any, List

logger = logging.getLogger(__name__)

# Plugin metadata - discoverable by PlugPipe registry
PLUGIN_METADATA = {
    "name": "security_incident_tracker",
    "version": "1.0.0",
    "description": "Tracks security incidents from monitoring system with severity analysis",
    "author": "Security Team",
    "tags": ["security", "incidents", "tracking", "monitoring"],
    "schema_validation": True
}


def process(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point following PlugPipe contract.

    Args:
        context: Plugin execution context containing:
            - input_data: Dict with time_period_days, severity_filter, include_resolved
            - config: Dict[str, Any] - Plugin configuration (optional)
            - metadata: Dict[str, Any] - Execution metadata (optional)

    Returns:
        Dict containing standardized response with security incident tracking data
    """
    try:
        # 1. Extract input data
        input_data = context.get('input_data', {})
        time_period_days = input_data.get('time_period_days', 30)
        severity_filter = input_data.get('severity_filter', ['error', 'critical'])
        include_resolved = input_data.get('include_resolved', False)

        # 2. Get security incidents from enterprise monitoring
        from shares.enterprise_monitoring import get_dashboard_data
        import time

        dashboard_data = get_dashboard_data()
        active_alerts = dashboard_data.get('active_alerts', [])

        # 3. Filter incidents by time period and severity
        cutoff_time = time.time() - (time_period_days * 24 * 3600)

        filtered_incidents = []
        incidents_by_severity = {
            'info': 0,
            'warning': 0,
            'error': 0,
            'critical': 0
        }

        for alert in active_alerts:
            alert_time = alert.get('timestamp', time.time())
            alert_severity = alert.get('severity', 'info')

            # Filter by time period
            if alert_time < cutoff_time:
                continue

            # Filter by severity
            if alert_severity not in severity_filter:
                continue

            # Filter by resolved status
            if not include_resolved and alert.get('resolved', False):
                continue

            filtered_incidents.append({
                'id': alert.get('id', 'unknown'),
                'severity': alert_severity,
                'title': alert.get('title', 'Unknown incident'),
                'description': alert.get('description', ''),
                'timestamp': alert_time,
                'metric_name': alert.get('metric_name', ''),
                'current_value': alert.get('current_value', 0),
                'threshold': alert.get('threshold', 0),
                'acknowledged': alert.get('acknowledged', False),
                'resolved': alert.get('resolved', False)
            })

            incidents_by_severity[alert_severity] += 1

        # 4. Analyze incident trend
        total_incidents = len(filtered_incidents)

        # Simple trend detection: compare first half vs second half
        if len(filtered_incidents) > 4:
            midpoint = len(filtered_incidents) // 2
            first_half_count = len(filtered_incidents[:midpoint])
            second_half_count = len(filtered_incidents[midpoint:])

            if second_half_count > first_half_count * 1.5:
                trend = 'increasing'
            elif second_half_count < first_half_count * 0.5:
                trend = 'decreasing'
            else:
                trend = 'stable'
        else:
            trend = 'insufficient_data'

        # 5. Sort incidents by timestamp (most recent first)
        filtered_incidents.sort(key=lambda x: x['timestamp'], reverse=True)

        # 6. Prepare result data
        result_data = {
            'total_incidents': total_incidents,
            'incidents_by_severity': incidents_by_severity,
            'recent_incidents': filtered_incidents[:10],  # Top 10 most recent
            'incident_trend': trend,
            'time_period_days': time_period_days,
            'severity_filter': severity_filter,
            'analysis_timestamp': datetime.now().isoformat()
        }

        # 7. Return standardized success response
        return {
            'success': True,
            'plugin_name': 'security_incident_tracker',
            'timestamp': datetime.now().isoformat(),
            'message': f'Tracked {total_incidents} security incidents in last {time_period_days} days',
            'processed_data': result_data,
            'metadata': {
                'category': 'enterprise',
                'version': '1.0.0',
                'data_source': 'enterprise_monitoring_system',
                'analysis_pattern': 'time_series_trend'
            }
        }

    except Exception as e:
        logger.error(f"Error in security_incident_tracker: {e}", exc_info=True)
        return {
            'success': False,
            'plugin_name': 'security_incident_tracker',
            'timestamp': datetime.now().isoformat(),
            'message': 'Security incident tracking failed',
            'error': str(e)
        }


if __name__ == "__main__":
    # Test plugin execution
    print("🔒 Security Incident Tracker Plugin")
    print("=" * 60)

    test_context = {
        'input_data': {
            'time_period_days': 30,
            'severity_filter': ['error', 'critical'],
            'include_resolved': False
        }
    }

    result = process(test_context)
    print(f"Success: {result['success']}")
    print(f"Message: {result['message']}")

    if result['success']:
        data = result['processed_data']
        print(f"Total incidents: {data['total_incidents']}")
        print(f"By severity: {data['incidents_by_severity']}")
        print(f"Trend: {data['incident_trend']}")
        print(f"Recent incidents: {len(data['recent_incidents'])}")

    print("✅ Security incident tracker test complete!")
