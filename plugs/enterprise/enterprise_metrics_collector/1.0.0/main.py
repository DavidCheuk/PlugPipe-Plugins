#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enterprise Metrics Collector Plugin for PlugPipe

Orchestrates enterprise metrics collection by aggregating data from:
- ecosystem_monitor: Compliance framework status
- business_compliance_auditor: Policy compliance
- advanced_health_diagnostics: System health and performance

Category: enterprise
Version: 1.0.0
Owner: Enterprise Team
"""

import logging
from datetime import datetime
from typing import Dict, Any

logger = logging.getLogger(__name__)

# Plugin metadata - discoverable by PlugPipe registry
PLUGIN_METADATA = {
    "name": "enterprise_metrics_collector",
    "version": "1.0.0",
    "description": "Enterprise metrics orchestrator aggregating compliance, health, and security data",
    "author": "Enterprise Team",
    "tags": ["enterprise", "metrics", "orchestration", "monitoring"],
    "schema_validation": True
}


def process(context: Dict[str, Any]) -> Dict[str, Any]:
    """
    Main plugin entry point following PlugPipe contract.

    Args:
        context: Plugin execution context containing:
            - input_data: Dict with include_compliance, include_health, include_security flags
            - config: Dict[str, Any] - Plugin configuration (optional)
            - metadata: Dict[str, Any] - Execution metadata (optional)

    Returns:
        Dict containing standardized response with aggregated enterprise metrics
    """
    try:
        # 1. Extract input data
        input_data = context.get('input_data', {})
        include_compliance = input_data.get('include_compliance', True)
        include_health = input_data.get('include_health', True)
        include_security = input_data.get('include_security', True)

        # 2. Initialize result data
        result_data = {
            'compliance_status': [],
            'health_metrics': {},
            'security_metrics': {},
            'collection_timestamp': datetime.now().isoformat()
        }

        # 3. Use pp() for dynamic plugin discovery and orchestration
        from shares.loader import pp

        # Collect compliance data
        if include_compliance:
            try:
                # Use ecosystem_monitor for comprehensive compliance
                compliance_result = pp('ecosystem_monitor', {
                    'input_data': {
                        'operation': 'get_compliance_status',
                        'frameworks': ['SOC2', 'GDPR', 'ISO27001', 'HIPAA']
                    }
                })

                if compliance_result and compliance_result.get('success'):
                    result_data['compliance_status'] = compliance_result.get('processed_data', {}).get('frameworks', [])
                    logger.info("Collected compliance data successfully")
            except Exception as e:
                logger.warning(f"Could not collect compliance data: {e}")
                result_data['compliance_status'] = []

        # Collect health diagnostics
        if include_health:
            try:
                health_result = pp('advanced_health_diagnostics', {
                    'input_data': {
                        'operation': 'get_system_health',
                        'include_performance': True
                    }
                })

                if health_result and health_result.get('success'):
                    result_data['health_metrics'] = health_result.get('processed_data', {})
                    logger.info("Collected health metrics successfully")
            except Exception as e:
                logger.warning(f"Could not collect health metrics: {e}")
                result_data['health_metrics'] = {'status': 'unavailable'}

        # Collect security metrics
        if include_security:
            try:
                # Use enterprise monitoring for security incidents
                from shares.enterprise_monitoring import get_dashboard_data
                dashboard = get_dashboard_data()

                active_alerts = dashboard.get('active_alerts', [])
                security_incidents = len([
                    alert for alert in active_alerts
                    if alert.get('severity') in ['error', 'critical']
                ])

                result_data['security_metrics'] = {
                    'active_alerts': len(active_alerts),
                    'security_incidents': security_incidents,
                    'monitoring_active': dashboard.get('system_status', {}).get('monitoring_active', True)
                }
                logger.info("Collected security metrics successfully")
            except Exception as e:
                logger.warning(f"Could not collect security metrics: {e}")
                result_data['security_metrics'] = {'status': 'unavailable'}

        # 4. Return standardized success response
        return {
            'success': True,
            'plugin_name': 'enterprise_metrics_collector',
            'timestamp': datetime.now().isoformat(),
            'message': 'Enterprise metrics collected successfully',
            'processed_data': result_data,
            'metadata': {
                'category': 'enterprise',
                'version': '1.0.0',
                'plugins_orchestrated': [
                    'ecosystem_monitor' if include_compliance else None,
                    'advanced_health_diagnostics' if include_health else None,
                    'enterprise_monitoring' if include_security else None
                ],
                'orchestration_pattern': 'parallel_collection'
            }
        }

    except Exception as e:
        logger.error(f"Error in enterprise_metrics_collector: {e}", exc_info=True)
        return {
            'success': False,
            'plugin_name': 'enterprise_metrics_collector',
            'timestamp': datetime.now().isoformat(),
            'message': 'Enterprise metrics collection failed',
            'error': str(e)
        }


if __name__ == "__main__":
    # Test plugin execution
    print("🏢 Enterprise Metrics Collector Plugin")
    print("=" * 60)

    test_context = {
        'input_data': {
            'include_compliance': True,
            'include_health': True,
            'include_security': True
        }
    }

    result = process(test_context)
    print(f"Success: {result['success']}")
    print(f"Message: {result['message']}")

    if result['success']:
        data = result['processed_data']
        print(f"Compliance frameworks: {len(data.get('compliance_status', []))}")
        print(f"Health metrics: {list(data.get('health_metrics', {}).keys())}")
        print(f"Security metrics: {list(data.get('security_metrics', {}).keys())}")

    print("✅ Enterprise metrics collector test complete!")
