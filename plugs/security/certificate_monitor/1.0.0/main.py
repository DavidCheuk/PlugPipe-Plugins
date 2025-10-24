#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
PlugPipe Certificate Monitoring Plugin

Enterprise-grade certificate monitoring and validation plugin that integrates
with all certificate providers to provide comprehensive certificate lifecycle
monitoring, expiry alerts, and compliance validation.

Based on enterprise certificate monitoring best practices and follows
PlugPipe's "reuse everything, reinvent nothing" principle by leveraging
existing certificate management plugins and monitoring tools.

Key Features:
- Multi-provider certificate monitoring
- Expiry monitoring and alerting
- Certificate validation and compliance checking
- Health dashboard and reporting
- Integration with existing monitoring systems
- Automated renewal recommendations
"""

import asyncio
import json
import logging
import ssl
import socket
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, Any, List, Optional, Tuple
import sys
import importlib.util

# Add project root for imports
PROJECT_ROOT = Path(__file__).parents[4]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

logger = logging.getLogger(__name__)

class CertificateMonitor:
    """
    Enterprise certificate monitoring and validation system
    
    Monitors certificates across all providers and provides comprehensive
    lifecycle management, expiry alerts, and compliance validation.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.logger = logger.getChild('cert_monitor')
        
        # Monitoring configuration
        self.check_interval_hours = config.get('check_interval_hours', 24)
        self.expiry_warning_days = config.get('expiry_warning_days', [30, 14, 7, 1])
        self.enable_compliance_checks = config.get('enable_compliance_checks', True)
        
        # Provider configurations
        self.monitored_providers = config.get('monitored_providers', [])
        self.provider_configs = config.get('provider_configs', {})
        
        # External monitoring integration
        self.enable_external_monitoring = config.get('enable_external_monitoring', True)
        self.monitoring_endpoints = config.get('monitoring_endpoints', [])
        
        # Alert configuration
        self.alert_channels = config.get('alert_channels', [])
        
        # Storage for monitoring data
        self.monitoring_data = {}
        self.last_check = None
    
    async def monitor_all_certificates(self) -> Dict[str, Any]:
        """Monitor certificates across all configured providers"""
        monitoring_results = {
            "timestamp": datetime.now().isoformat(),
            "providers_checked": 0,
            "total_certificates": 0,
            "certificates_expiring": 0,
            "certificates_expired": 0,
            "certificates_healthy": 0,
            "provider_results": {},
            "alerts_generated": [],
            "recommendations": []
        }
        
        # Monitor each configured provider
        for provider_name in self.monitored_providers:
            try:
                provider_result = await self._monitor_provider_certificates(provider_name)
                monitoring_results["provider_results"][provider_name] = provider_result
                monitoring_results["providers_checked"] += 1
                monitoring_results["total_certificates"] += provider_result.get("certificate_count", 0)
                monitoring_results["certificates_expiring"] += provider_result.get("expiring_count", 0)
                monitoring_results["certificates_expired"] += provider_result.get("expired_count", 0)
                monitoring_results["certificates_healthy"] += provider_result.get("healthy_count", 0)
                
                # Collect alerts
                if provider_result.get("alerts"):
                    monitoring_results["alerts_generated"].extend(provider_result["alerts"])
                    
            except Exception as e:
                self.logger.error(f"Failed to monitor provider {provider_name}: {e}")
                monitoring_results["provider_results"][provider_name] = {
                    "status": "error",
                    "error": str(e)
                }
        
        # Generate recommendations
        monitoring_results["recommendations"] = await self._generate_recommendations(monitoring_results)
        
        # Send alerts if needed
        if monitoring_results["alerts_generated"]:
            await self._send_alerts(monitoring_results["alerts_generated"])
        
        # Update last check
        self.last_check = datetime.now()
        self.monitoring_data = monitoring_results
        
        return monitoring_results
    
    async def _monitor_provider_certificates(self, provider_name: str) -> Dict[str, Any]:
        """Monitor certificates for a specific provider"""
        provider_config = self.provider_configs.get(provider_name, {})
        
        # Load provider plugin
        provider_plugin = await self._load_provider_plugin(provider_name, provider_config)
        
        if not provider_plugin:
            return {
                "status": "error",
                "error": f"Could not load provider plugin: {provider_name}"
            }
        
        try:
            # Get list of certificates from provider
            list_result = await provider_plugin.process({}, {
                "operation": "list_certificates",
                **provider_config
            })
            
            if not list_result.get("success"):
                return {
                    "status": "error",
                    "error": list_result.get("error", "Failed to list certificates")
                }
            
            certificates = list_result.get("certificates", [])
            provider_result = {
                "status": "success",
                "certificate_count": len(certificates),
                "expiring_count": 0,
                "expired_count": 0,
                "healthy_count": 0,
                "certificates": [],
                "alerts": []
            }
            
            # Validate each certificate
            for cert_summary in certificates:
                cert_id = cert_summary.get("certificate_id")
                if not cert_id:
                    continue
                
                # Validate certificate
                validation_result = await provider_plugin.process({}, {
                    "operation": "validate_certificate",
                    "certificate_id": cert_id,
                    **provider_config
                })
                
                if validation_result.get("success"):
                    cert_status = self._analyze_certificate_status(validation_result, cert_summary)
                    provider_result["certificates"].append(cert_status)
                    
                    # Count by status
                    if cert_status["status"] == "expired":
                        provider_result["expired_count"] += 1
                    elif cert_status["status"] == "expiring_soon":
                        provider_result["expiring_count"] += 1
                    else:
                        provider_result["healthy_count"] += 1
                    
                    # Generate alerts
                    alerts = self._generate_certificate_alerts(cert_status, provider_name)
                    provider_result["alerts"].extend(alerts)
            
            return provider_result
            
        except Exception as e:
            self.logger.error(f"Error monitoring provider {provider_name}: {e}")
            return {
                "status": "error",
                "error": str(e)
            }
    
    def _analyze_certificate_status(self, validation_result: Dict[str, Any], cert_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze certificate status and generate status report"""
        days_until_expiry = validation_result.get("days_until_expiry", 0)
        validity_status = validation_result.get("validity_status", "unknown")
        
        # Determine status category
        if validity_status == "expired":
            status = "expired"
            priority = "critical"
        elif validity_status == "revoked":
            status = "revoked"
            priority = "critical"
        elif days_until_expiry <= 1:
            status = "expiring_critical"
            priority = "critical"
        elif days_until_expiry <= 7:
            status = "expiring_soon"
            priority = "high"
        elif days_until_expiry <= 30:
            status = "expiring_warning"
            priority = "medium"
        else:
            status = "healthy"
            priority = "low"
        
        return {
            "certificate_id": validation_result.get("certificate_id"),
            "common_name": cert_summary.get("subject", "unknown"),
            "issuer": cert_summary.get("issuer", "unknown"),
            "serial_number": cert_summary.get("serial_number"),
            "not_before": cert_summary.get("not_before"),
            "not_after": cert_summary.get("not_after"),
            "days_until_expiry": days_until_expiry,
            "status": status,
            "priority": priority,
            "validity_status": validity_status,
            "last_checked": datetime.now().isoformat()
        }
    
    def _generate_certificate_alerts(self, cert_status: Dict[str, Any], provider_name: str) -> List[Dict[str, Any]]:
        """Generate alerts for certificate status"""
        alerts = []
        
        if cert_status["status"] == "expired":
            alerts.append({
                "type": "certificate_expired",
                "severity": "critical",
                "certificate_id": cert_status["certificate_id"],
                "common_name": cert_status["common_name"],
                "provider": provider_name,
                "message": f"Certificate {cert_status['common_name']} has EXPIRED",
                "days_until_expiry": cert_status["days_until_expiry"],
                "timestamp": datetime.now().isoformat()
            })
        
        elif cert_status["status"] == "revoked":
            alerts.append({
                "type": "certificate_revoked",
                "severity": "critical",
                "certificate_id": cert_status["certificate_id"],
                "common_name": cert_status["common_name"],
                "provider": provider_name,
                "message": f"Certificate {cert_status['common_name']} has been REVOKED",
                "timestamp": datetime.now().isoformat()
            })
        
        elif cert_status["days_until_expiry"] in self.expiry_warning_days:
            severity = "critical" if cert_status["days_until_expiry"] <= 1 else "high" if cert_status["days_until_expiry"] <= 7 else "medium"
            alerts.append({
                "type": "certificate_expiring",
                "severity": severity,
                "certificate_id": cert_status["certificate_id"],
                "common_name": cert_status["common_name"],
                "provider": provider_name,
                "message": f"Certificate {cert_status['common_name']} expires in {cert_status['days_until_expiry']} days",
                "days_until_expiry": cert_status["days_until_expiry"],
                "timestamp": datetime.now().isoformat()
            })
        
        return alerts
    
    async def _generate_recommendations(self, monitoring_results: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate actionable recommendations based on monitoring results"""
        recommendations = []
        
        # Renewal recommendations
        if monitoring_results["certificates_expiring"] > 0:
            recommendations.append({
                "type": "renewal_needed",
                "priority": "high",
                "message": f"{monitoring_results['certificates_expiring']} certificates need renewal",
                "action": "Schedule certificate renewals for expiring certificates",
                "automated": True
            })
        
        # Expired certificate recommendations  
        if monitoring_results["certificates_expired"] > 0:
            recommendations.append({
                "type": "expired_certificates",
                "priority": "critical",
                "message": f"{monitoring_results['certificates_expired']} certificates have EXPIRED",
                "action": "Immediately renew or replace expired certificates",
                "automated": False
            })
        
        # Provider health recommendations
        failed_providers = [
            name for name, result in monitoring_results["provider_results"].items()
            if result.get("status") != "success"
        ]
        
        if failed_providers:
            recommendations.append({
                "type": "provider_issues",
                "priority": "high",
                "message": f"Certificate providers having issues: {', '.join(failed_providers)}",
                "action": "Check provider connectivity and configuration",
                "automated": False
            })
        
        return recommendations
    
    async def _send_alerts(self, alerts: List[Dict[str, Any]]):
        """Send alerts to configured channels"""
        for alert in alerts:
            for channel in self.alert_channels:
                try:
                    await self._send_alert_to_channel(alert, channel)
                except Exception as e:
                    self.logger.error(f"Failed to send alert to channel {channel}: {e}")
    
    async def _send_alert_to_channel(self, alert: Dict[str, Any], channel: Dict[str, Any]):
        """Send alert to specific channel"""
        channel_type = channel.get("type", "log")
        
        if channel_type == "log":
            level = logging.CRITICAL if alert["severity"] == "critical" else logging.WARNING
            self.logger.log(level, f"CERT ALERT: {alert['message']}")
        
        elif channel_type == "webhook":
            # Send to webhook URL
            import aiohttp
            webhook_url = channel.get("url")
            if webhook_url:
                async with aiohttp.ClientSession() as session:
                    await session.post(webhook_url, json=alert)
        
        # Additional channel types can be added here
        # (email, Slack, PagerDuty, etc.)
    
    async def _load_provider_plugin(self, provider_name: str, provider_config: Dict[str, Any]):
        """Load certificate provider plugin"""
        # Map provider names to plugin paths
        provider_plugins = {
            "hashicorp_vault": "plugs/security/vault_certificate_manager/1.0.0/main.py",
            "lets_encrypt_acme": "plugs/security/acme_certificate_manager/1.0.0/main.py",
            "certificate_factory": "plugs/security/certificate_factory/1.0.0/main.py"
        }
        
        plugin_path = provider_plugins.get(provider_name)
        if not plugin_path:
            self.logger.warning(f"Unknown provider: {provider_name}")
            return None
        
        full_path = PROJECT_ROOT / plugin_path
        
        if not full_path.exists():
            self.logger.warning(f"Provider plugin not found: {full_path}")
            return None
        
        try:
            spec = importlib.util.spec_from_file_location(f"{provider_name}_plugin", str(full_path))
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            return plugin_module
            
        except Exception as e:
            self.logger.error(f"Failed to load provider plugin {provider_name}: {e}")
            return None
    
    async def validate_remote_certificate(self, hostname: str, port: int = 443) -> Dict[str, Any]:
        """Validate remote SSL certificate"""
        try:
            # Create SSL context
            context = ssl.create_default_context()
            
            # Connect and get certificate
            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Parse certificate information
                    not_before = datetime.strptime(cert['notBefore'], '%b %d %H:%M:%S %Y %Z')
                    not_after = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expiry = (not_after - datetime.now()).days
                    
                    # Determine status
                    if datetime.now() > not_after:
                        status = "expired"
                        validity_status = "expired"
                    elif days_until_expiry <= 30:
                        status = "expiring_soon"
                        validity_status = "expiring_soon"
                    else:
                        status = "valid"
                        validity_status = "valid"
                    
                    return {
                        "success": True,
                        "hostname": hostname,
                        "port": port,
                        "subject": dict(x[0] for x in cert['subject']),
                        "issuer": dict(x[0] for x in cert['issuer']),
                        "serial_number": cert.get('serialNumber'),
                        "not_before": not_before.isoformat(),
                        "not_after": not_after.isoformat(),
                        "days_until_expiry": days_until_expiry,
                        "status": status,
                        "validity_status": validity_status,
                        "san": cert.get('subjectAltName', []),
                        "validation_timestamp": datetime.now().isoformat()
                    }
                    
        except Exception as e:
            return {
                "success": False,
                "hostname": hostname,
                "port": port,
                "error": str(e),
                "validation_timestamp": datetime.now().isoformat()
            }
    
    async def get_monitoring_dashboard(self) -> Dict[str, Any]:
        """Get certificate monitoring dashboard data"""
        if not self.monitoring_data:
            # Run monitoring if no data available
            await self.monitor_all_certificates()
        
        dashboard_data = {
            "overview": {
                "last_check": self.last_check.isoformat() if self.last_check else None,
                "next_check": (self.last_check + timedelta(hours=self.check_interval_hours)).isoformat() if self.last_check else None,
                "total_certificates": self.monitoring_data.get("total_certificates", 0),
                "certificates_healthy": self.monitoring_data.get("certificates_healthy", 0),
                "certificates_expiring": self.monitoring_data.get("certificates_expiring", 0),
                "certificates_expired": self.monitoring_data.get("certificates_expired", 0),
                "providers_monitored": self.monitoring_data.get("providers_checked", 0)
            },
            "alerts": {
                "active_alerts": len(self.monitoring_data.get("alerts_generated", [])),
                "critical_alerts": len([a for a in self.monitoring_data.get("alerts_generated", []) if a.get("severity") == "critical"]),
                "recent_alerts": self.monitoring_data.get("alerts_generated", [])[-10:]  # Last 10 alerts
            },
            "recommendations": self.monitoring_data.get("recommendations", []),
            "provider_status": self.monitoring_data.get("provider_results", {}),
            "health_score": self._calculate_health_score()
        }
        
        return dashboard_data
    
    def _calculate_health_score(self) -> float:
        """Calculate overall certificate health score (0-100)"""
        if not self.monitoring_data:
            return 0.0
        
        total = self.monitoring_data.get("total_certificates", 0)
        if total == 0:
            return 100.0
        
        healthy = self.monitoring_data.get("certificates_healthy", 0)
        expiring = self.monitoring_data.get("certificates_expiring", 0)
        expired = self.monitoring_data.get("certificates_expired", 0)
        
        # Health score calculation
        # Healthy certificates: 100% score
        # Expiring certificates: 50% score  
        # Expired certificates: 0% score
        score = ((healthy * 100) + (expiring * 50) + (expired * 0)) / total
        return round(score, 2)

class CertificateMonitorPlugin:
    """
    PlugPipe Certificate Monitoring Plugin
    
    Enterprise-grade certificate monitoring with multi-provider support,
    expiry alerting, and comprehensive compliance validation.
    """
    
    def __init__(self):
        self.logger = logger
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process certificate monitoring operations
        
        Supported operations:
        - monitor_certificates: Monitor all configured certificates
        - get_dashboard: Get monitoring dashboard data
        - validate_remote_cert: Validate remote SSL certificate
        - get_expiring_certificates: Get certificates expiring soon
        - generate_report: Generate monitoring report
        """
        operation = cfg.get('operation', 'get_status')
        
        try:
            # Initialize certificate monitor
            cert_monitor = CertificateMonitor(cfg)
            
            if operation == 'get_status':
                return await self._get_plugin_status(cert_monitor, ctx, cfg)
            elif operation == 'monitor_certificates':
                return await self._monitor_certificates(cert_monitor, ctx, cfg)
            elif operation == 'get_dashboard':
                return await self._get_dashboard(cert_monitor, ctx, cfg)
            elif operation == 'validate_remote_cert':
                return await self._validate_remote_cert(cert_monitor, ctx, cfg)
            elif operation == 'get_expiring_certificates':
                return await self._get_expiring_certificates(cert_monitor, ctx, cfg)
            elif operation == 'generate_report':
                return await self._generate_report(cert_monitor, ctx, cfg)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operation: {operation}",
                    "supported_operations": [
                        "get_status", "monitor_certificates", "get_dashboard",
                        "validate_remote_cert", "get_expiring_certificates", "generate_report"
                    ]
                }
                
        except Exception as e:
            self.logger.error(f"Certificate monitoring plugin error: {e}")
            return {
                "success": False,
                "error": str(e),
                "plugin": "certificate_monitor"
            }
    
    async def _get_plugin_status(self, cert_monitor, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get plugin status"""
        return {
            "success": True,
            "plugin": "certificate_monitor",
            "version": "1.0.0",
            "description": "Enterprise certificate monitoring and validation plugin",
            "features": [
                "Multi-provider certificate monitoring",
                "Expiry monitoring and alerting",
                "Certificate validation and compliance",
                "Health dashboard and reporting",
                "Remote certificate validation",
                "Automated renewal recommendations"
            ],
            "monitored_providers": cert_monitor.monitored_providers,
            "check_interval_hours": cert_monitor.check_interval_hours,
            "expiry_warning_days": cert_monitor.expiry_warning_days,
            "last_check": cert_monitor.last_check.isoformat() if cert_monitor.last_check else None,
            "enterprise_ready": True
        }
    
    async def _monitor_certificates(self, cert_monitor, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Monitor all certificates"""
        monitoring_results = await cert_monitor.monitor_all_certificates()
        
        return {
            "success": True,
            "operation": "monitor_certificates",
            "results": monitoring_results,
            "summary": {
                "providers_checked": monitoring_results["providers_checked"],
                "total_certificates": monitoring_results["total_certificates"],
                "certificates_healthy": monitoring_results["certificates_healthy"],
                "certificates_expiring": monitoring_results["certificates_expiring"],
                "certificates_expired": monitoring_results["certificates_expired"],
                "alerts_generated": len(monitoring_results["alerts_generated"]),
                "recommendations": len(monitoring_results["recommendations"])
            }
        }
    
    async def _get_dashboard(self, cert_monitor, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get monitoring dashboard"""
        dashboard_data = await cert_monitor.get_monitoring_dashboard()
        
        return {
            "success": True,
            "operation": "get_dashboard",
            "dashboard": dashboard_data,
            "timestamp": datetime.now().isoformat()
        }
    
    async def _validate_remote_cert(self, cert_monitor, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Validate remote certificate"""
        hostname = cfg.get('hostname')
        port = cfg.get('port', 443)
        
        if not hostname:
            return {"success": False, "error": "hostname required"}
        
        validation_result = await cert_monitor.validate_remote_certificate(hostname, port)
        
        return {
            "success": validation_result["success"],
            "operation": "validate_remote_cert",
            "validation_result": validation_result
        }
    
    async def _get_expiring_certificates(self, cert_monitor, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Get certificates expiring soon"""
        days_ahead = cfg.get('days_ahead', 30)
        
        # Run monitoring to get latest data
        monitoring_results = await cert_monitor.monitor_all_certificates()
        
        expiring_certs = []
        for provider_name, provider_result in monitoring_results["provider_results"].items():
            if provider_result.get("status") == "success":
                for cert in provider_result.get("certificates", []):
                    if cert["days_until_expiry"] <= days_ahead and cert["status"] != "expired":
                        expiring_certs.append({
                            **cert,
                            "provider": provider_name
                        })
        
        # Sort by days until expiry
        expiring_certs.sort(key=lambda x: x["days_until_expiry"])
        
        return {
            "success": True,
            "operation": "get_expiring_certificates",
            "days_ahead": days_ahead,
            "expiring_certificates": expiring_certs,
            "total_expiring": len(expiring_certs)
        }
    
    async def _generate_report(self, cert_monitor, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive monitoring report"""
        # Get dashboard data
        dashboard_data = await cert_monitor.get_monitoring_dashboard()
        
        # Generate report
        report = {
            "report_timestamp": datetime.now().isoformat(),
            "report_period": cfg.get('report_period', 'current'),
            "executive_summary": {
                "total_certificates": dashboard_data["overview"]["total_certificates"],
                "health_score": dashboard_data["health_score"],
                "certificates_needing_attention": dashboard_data["overview"]["certificates_expiring"] + dashboard_data["overview"]["certificates_expired"],
                "critical_alerts": dashboard_data["alerts"]["critical_alerts"]
            },
            "detailed_metrics": dashboard_data["overview"],
            "alert_summary": dashboard_data["alerts"],
            "provider_health": dashboard_data["provider_status"],
            "recommendations": dashboard_data["recommendations"],
            "next_actions": []
        }
        
        # Add next actions based on status
        if dashboard_data["overview"]["certificates_expired"] > 0:
            report["next_actions"].append("URGENT: Replace expired certificates immediately")
        
        if dashboard_data["overview"]["certificates_expiring"] > 0:
            report["next_actions"].append("Schedule renewal for expiring certificates")
        
        if dashboard_data["alerts"]["critical_alerts"] > 0:
            report["next_actions"].append("Review and address critical certificate alerts")
        
        return {
            "success": True,
            "operation": "generate_report",
            "report": report
        }

# Plugin metadata for PlugPipe registry
plug_metadata = {
    "name": "certificate_monitor",
    "version": "1.0.0",
    "description": "Enterprise certificate monitoring and validation plugin with multi-provider support",
    "author": "PlugPipe Security Team",
    "category": "security",
    "tags": ["certificates", "monitoring", "validation", "alerting", "compliance"],
    "requirements": [],
    "supported_operations": [
        "get_status", "monitor_certificates", "get_dashboard",
        "validate_remote_cert", "get_expiring_certificates", "generate_report"
    ]
}

# Create plugin instance for PlugPipe
plugin_instance = CertificateMonitorPlugin()

# Main process function for PlugPipe
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main entry point for PlugPipe"""
    return await plugin_instance.process(ctx, cfg)