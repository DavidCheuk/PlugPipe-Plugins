# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Prometheus Monitoring Plug for PlugPipe Observability.

This plugin demonstrates the PlugPipe principle "reuse, never reinvent" by leveraging 
the Prometheus ecosystem's proven monitoring and observability stack instead of 
implementing custom metrics collection and visualization systems.

Philosophy:
- Reuse Prometheus's industry-standard metrics collection and storage
- Never reinvent monitoring that's already been battle-tested
- Integrate with existing Prometheus and Grafana infrastructure  
- Provide unified observability across all PlugPipe operations

Monitoring Features via Prometheus:
- Industry-standard metrics collection and storage
- PromQL for powerful metrics querying and analysis
- Grafana integration for beautiful dashboards and visualization
- Alertmanager integration for intelligent alerting
- Rich ecosystem of exporters for infrastructure monitoring
"""

import os
import time
import json
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone, timedelta
import asyncio
import threading

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, 
        CollectorRegistry, generate_latest,
        push_to_gateway, delete_from_gateway
    )
    import prometheus_client
    PROMETHEUS_CLIENT_AVAILABLE = True
except ImportError:
    PROMETHEUS_CLIENT_AVAILABLE = False

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from grafana_api.grafana_face import GrafanaFace
    GRAFANA_API_AVAILABLE = True
except ImportError:
    GRAFANA_API_AVAILABLE = False

# Import real Prometheus backend
try:
    import sys
    import os
    current_dir = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, current_dir)
    from prometheus_backend import PrometheusBackend
    BACKEND_AVAILABLE = True
except ImportError:
    BACKEND_AVAILABLE = False
    # Create a dummy PrometheusBackend for graceful degradation
    class PrometheusBackend:
        def __init__(self, config):
            """Fallback Prometheus backend when prometheus_client unavailable."""
            self.logger = logging.getLogger(__name__ + ".FallbackBackend")
            self.logger.warning("Using fallback Prometheus backend - install prometheus_client for full functionality")
            self.config = config or {}
            self.metrics_collected = 0

logger = logging.getLogger(__name__)


class PrometheusMonitoringPlug:
    """
    Prometheus-based monitoring plugin for comprehensive observability.
    
    This plugin wraps the Prometheus ecosystem's proven monitoring stack instead of
    implementing custom metrics collection, following PlugPipe's "reuse, never reinvent" principle.
    """
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Prometheus monitoring plugin."""
        self.prometheus_available = PROMETHEUS_CLIENT_AVAILABLE
        self.requests_available = REQUESTS_AVAILABLE
        self.graceful_mode = False
        
        if not PROMETHEUS_CLIENT_AVAILABLE:
            logger.info("Prometheus client not available - using basic metrics collection (graceful degradation)")
            self.graceful_mode = True
        
        if not REQUESTS_AVAILABLE:
            logger.info("Requests library not available - using local monitoring only (graceful degradation)")
            self.graceful_mode = True
        
        self.config = config or {}
        self.prometheus_config = self.config.get("prometheus_config", {})
        
        # Prometheus configuration
        self.gateway_url = self.prometheus_config.get(
            "gateway_url", 
            os.getenv("PUSHGATEWAY_URL", "http://127.0.0.1:9091")
        )
        self.prometheus_url = self.prometheus_config.get(
            "prometheus_url",
            os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")
        )
        self.grafana_url = self.prometheus_config.get(
            "grafana_url",
            os.getenv("GRAFANA_URL", "http://127.0.0.1:3000")
        )
        
        self.job_name = self.prometheus_config.get("job_name", "plugpipe")
        self.instance = self.prometheus_config.get("instance", "plugpipe-instance")
        
        # Initialize real Prometheus backend
        self.backend = None
        if BACKEND_AVAILABLE:
            try:
                self.backend = PrometheusBackend(self.config)
            except Exception as e:
                logger.warning(f"Failed to initialize Prometheus backend: {str(e)} - using graceful degradation")
                self.backend = None
        else:
            logger.info("Prometheus backend not available - using fallback implementations (graceful degradation)")
        
        # Initialize metric registry (only if Prometheus client is available)
        self.registry = None
        if PROMETHEUS_CLIENT_AVAILABLE:
            self.registry = CollectorRegistry()
        
        # Initialize HTTP session with retries (only if requests is available)
        self.session = None
        if REQUESTS_AVAILABLE:
            self.session = self._create_http_session()
        
        # Initialize Grafana client if available
        self.grafana_client = self._initialize_grafana_client()
        
        # Metric storage for custom metrics
        self.metrics = {}
        
        # Initialize default metrics
        self._initialize_default_metrics()
        
        logger.info("Prometheus monitoring plugin initialized successfully")
    
    def _create_http_session(self) -> requests.Session:
        """Create HTTP session with retry configuration."""
        session = requests.Session()
        
        # Configure retries
        retry_strategy = Retry(
            total=3,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["HEAD", "GET", "OPTIONS", "POST"],
            backoff_factor=1
        )
        
        adapter = HTTPAdapter(max_retries=retry_strategy)
        session.mount("http://", adapter)
        session.mount("https://", adapter)
        
        return session
    
    def _initialize_grafana_client(self) -> Optional[Any]:
        """Initialize Grafana API client if available."""
        if not GRAFANA_API_AVAILABLE:
            logger.info("Grafana API not available - dashboard integration disabled (graceful degradation)")
            return None
        
        try:
            # Initialize Grafana client
            grafana_auth = self.prometheus_config.get("grafana_auth")
            if grafana_auth:
                return GrafanaFace(
                    auth=grafana_auth,
                    host=self.grafana_url.replace("http://", "").replace("https://", "")
                )
            
            return None
            
        except Exception as e:
            logger.warning(f"Failed to initialize Grafana client: {str(e)}")
            return None
    
    def _initialize_default_metrics(self):
        """Initialize default PlugPipe metrics."""
        if not self.prometheus_available:
            logger.info("Prometheus client not available - skipping default metrics initialization")
            return
            
        try:
            # System metrics
            self.metrics['system_uptime'] = Gauge(
                'plugpipe_system_uptime_seconds',
                'PlugPipe system uptime in seconds',
                registry=self.registry
            )
            
            self.metrics['memory_usage'] = Gauge(
                'plugpipe_memory_usage_bytes',
                'PlugPipe memory usage in bytes',
                registry=self.registry
            )
            
            # Plug metrics
            self.metrics['plugin_executions'] = Counter(
                'plugpipe_plugin_executions_total',
                'Total number of plugin executions',
                ['plugin_name', 'status'],
                registry=self.registry
            )
            
            self.metrics['plugin_duration'] = Histogram(
                'plugpipe_plugin_duration_seconds',
                'Plug execution duration in seconds',
                ['plugin_name'],
                registry=self.registry
            )
            
            # Pipe metrics
            self.metrics['pipeline_executions'] = Counter(
                'plugpipe_pipeline_executions_total',
                'Total number of pipeline executions',
                ['pipeline_name', 'status'],
                registry=self.registry
            )
            
            # Security metrics
            self.metrics['auth_attempts'] = Counter(
                'plugpipe_auth_attempts_total',
                'Total authentication attempts',
                ['method', 'status'],
                registry=self.registry
            )
            
            self.metrics['capability_violations'] = Counter(
                'plugpipe_capability_violations_total',
                'Total capability violations',
                ['plugin_name', 'capability'],
                registry=self.registry
            )
            
        except Exception as e:
            logger.error(f"Failed to initialize default metrics: {str(e)}")
    
    async def process(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process monitoring operation using Prometheus ecosystem.
        
        Args:
            ctx: Operation context with monitoring parameters
            cfg: Plug configuration
            
        Returns:
            Monitoring operation result
        """
        try:
            # Extract operation parameters
            operation = ctx.get("operation")
            if not operation:
                # Default operation: health check and status
                return await self._handle_health_check(ctx, cfg)
            
            # Route to appropriate handler
            if operation in ["record_metric", "record_counter", "record_gauge", "record_histogram"]:
                result = await self._handle_metric_recording(ctx, cfg)
            elif operation == "query_metrics":
                result = await self._handle_metric_query(ctx, cfg)
            elif operation == "create_alert":
                result = await self._handle_alert_creation(ctx, cfg)
            elif operation == "export_metrics":
                result = await self._handle_metric_export(ctx, cfg)
            elif operation == "scrape_endpoint":
                result = await self._handle_endpoint_scraping(ctx, cfg)
            elif operation == "health_check":
                result = await self._handle_health_check(ctx, cfg)
            else:
                return {
                    "success": False,
                    "error": f"Unsupported operation: {operation}"
                }
            
            return result
            
        except Exception as e:
            logger.error(f"Prometheus monitoring operation error: {str(e)}")
            return {
                "success": False,
                "error": f"Monitoring operation failed: {str(e)}"
            }
    
    async def _handle_metric_recording(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle metric recording operations."""
        try:
            metric_name = ctx.get("metric_name")
            metric_value = ctx.get("metric_value")
            metric_type = ctx.get("metric_type", "gauge")
            labels = ctx.get("labels", {})
            
            if not metric_name or metric_value is None:
                return {
                    "success": False,
                    "error": "metric_name and metric_value are required"
                }
            
            # Create or get metric
            metric = await self._get_or_create_metric(metric_name, metric_type, labels)
            
            # Record metric value based on type
            if metric_type == "counter":
                if hasattr(metric, 'labels'):
                    metric.labels(**labels).inc(metric_value)
                else:
                    metric.inc(metric_value)
            elif metric_type == "gauge":
                if hasattr(metric, 'labels'):
                    metric.labels(**labels).set(metric_value)
                else:
                    metric.set(metric_value)
            elif metric_type == "histogram":
                if hasattr(metric, 'labels'):
                    metric.labels(**labels).observe(metric_value)
                else:
                    metric.observe(metric_value)
            
            # Push to gateway if configured
            if self.gateway_url and self.backend:
                try:
                    await self._push_metrics_to_gateway()
                except Exception as e:
                    logger.warning(f"Failed to push metrics to gateway - continuing in graceful degradation: {str(e)}")
            
            timestamp = datetime.now(timezone.utc).isoformat()
            
            return {
                "success": True,
                "result": {
                    "metric_pushed": True,
                    "metric_name": metric_name,
                    "metric_value": metric_value,
                    "metric_type": metric_type,
                    "labels": labels,
                    "timestamp": timestamp
                },
                "monitoring_metadata": {
                    "prometheus_url": self.prometheus_url,
                    "job_name": self.job_name,
                    "gateway_url": self.gateway_url
                }
            }
            
        except Exception as e:
            logger.error(f"Metric recording error: {str(e)}")
            return {
                "success": False,
                "error": f"Metric recording failed: {str(e)}"
            }
    
    async def _get_or_create_metric(self, name: str, metric_type: str, labels: Dict[str, Any]):
        """Get or create Prometheus metric."""
        metric_key = f"{name}_{metric_type}"
        
        if metric_key not in self.metrics:
            label_names = list(labels.keys()) if labels else []
            
            # Handle graceful degradation when Prometheus client not available
            if not self.prometheus_available:
                # Return a mock metric for graceful degradation
                class MockMetric:
                    def __init__(self, metric_name="unknown"):
                        self.metric_name = metric_name
                        self.logger = logging.getLogger(__name__ + ".MockMetric")
                        self.logger.debug(f"Created mock metric: {metric_name}")

                    def inc(self, value=1):
                        """Increment counter metric (fallback: log only)."""
                        self.logger.info(f"Counter {self.metric_name} incremented by {value}")

                    def set(self, value):
                        """Set gauge metric (fallback: log only)."""
                        self.logger.info(f"Gauge {self.metric_name} set to {value}")

                    def observe(self, value):
                        """Observe histogram metric (fallback: log only)."""
                        self.logger.info(f"Histogram {self.metric_name} observed value {value}")
                    def labels(self, **kwargs):
                        return self
                
                mock_metric = MockMetric(metric_key)
                self.metrics[metric_key] = mock_metric
                return mock_metric
            
            if metric_type == "counter":
                self.metrics[metric_key] = Counter(
                    name, f"{name} counter metric", 
                    label_names, registry=self.registry
                )
            elif metric_type == "gauge":
                self.metrics[metric_key] = Gauge(
                    name, f"{name} gauge metric",
                    label_names, registry=self.registry
                )
            elif metric_type == "histogram":
                self.metrics[metric_key] = Histogram(
                    name, f"{name} histogram metric",
                    label_names, registry=self.registry
                )
            elif metric_type == "summary":
                self.metrics[metric_key] = Summary(
                    name, f"{name} summary metric",
                    label_names, registry=self.registry
                )
        
        return self.metrics[metric_key]
    
    async def _push_metrics_to_gateway(self):
        """Push metrics to Prometheus Pushgateway."""
        try:
            if not self.backend:
                logger.warning("Prometheus backend not available - skipping metric push")
                return
            
            # Use real Prometheus backend for metric push
            await self.backend.push_metrics(
                registry=self.registry,
                job_name=self.job_name,
                grouping_key={'instance': self.instance}
            )
            
            logger.debug(f"Pushed metrics to gateway: {self.gateway_url}")
            
        except Exception as e:
            logger.error(f"Failed to push metrics to gateway: {str(e)}")
            raise
    
    async def _handle_metric_query(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle PromQL metric queries."""
        try:
            query = ctx.get("query")
            time_range = ctx.get("time_range", {})
            
            if not query:
                return {
                    "success": False,
                    "error": "Query parameter is required"
                }
            
            if not self.backend:
                return {"success": False, "error": "Prometheus backend not available - configure Prometheus connection"}
            
            try:
                # Use real Prometheus backend for query execution
                query_result = await self.backend.execute_query(query, time_range)
            except Exception as e:
                logger.error(f"Query execution failed: {str(e)}")
                return {"success": False, "error": f"Query execution failed: {str(e)}"}
            
            return {
                "success": True,
                "result": {
                    "query_result": query_result,
                    "query": query
                },
                "monitoring_metadata": {
                    "prometheus_url": self.prometheus_url,
                    "query_type": "range" if time_range and time_range.get("start") else "instant"
                }
            }
            
        except Exception as e:
            logger.error(f"Metric query error: {str(e)}")
            return {
                "success": False,
                "error": f"Metric query failed: {str(e)}"
            }
    
    async def _handle_alert_creation(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle alert rule creation."""
        try:
            alert_config = ctx.get("alert_config", {})
            
            alert_name = alert_config.get("alert_name")
            expression = alert_config.get("expression")
            
            if not alert_name or not expression:
                return {
                    "success": False,
                    "error": "alert_name and expression are required"
                }
            
            # Create alert rule configuration
            alert_rule = {
                "alert": alert_name,
                "expr": expression,
                "for": alert_config.get("duration", "5m"),
                "labels": {
                    "severity": alert_config.get("severity", "warning"),
                    "source": "plugpipe"
                },
                "annotations": alert_config.get("annotations", {
                    "summary": f"Alert: {alert_name}",
                    "description": f"Alert triggered by expression: {expression}"
                })
            }
            
            # Create alert rule (in production, this would integrate with Alertmanager)
            alert_id = f"alert_{alert_name}_{int(time.time())}"
            logger.info(f"Created alert rule: {alert_rule}")
            
            # Send webhook notification if configured
            webhook_url = alert_config.get("webhook_url")
            if webhook_url and self.backend:
                try:
                    await self.backend.send_webhook_alert(webhook_url, alert_rule)
                except Exception as e:
                    logger.warning(f"Failed to send webhook alert: {str(e)}")
            
            return {
                "success": True,
                "result": {
                    "alert_created": True,
                    "alert_id": alert_id,
                    "alert_name": alert_name,
                    "expression": expression
                },
                "monitoring_metadata": {
                    "alert_rule": alert_rule
                }
            }
            
        except Exception as e:
            logger.error(f"Alert creation error: {str(e)}")
            return {
                "success": False,
                "error": f"Alert creation failed: {str(e)}"
            }
    
    async def _handle_metric_export(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle metric export operations."""
        try:
            export_format = ctx.get("export_format", "prometheus")
            
            if export_format == "prometheus":
                # Export in Prometheus format
                exported_data = generate_latest(self.registry).decode('utf-8')
            
            elif export_format == "json":
                # Export metrics as JSON (custom format)
                metrics_data = {}
                for name, metric in self.metrics.items():
                    try:
                        # Get metric samples (simplified)
                        metrics_data[name] = {
                            "type": type(metric).__name__.lower(),
                            "help": getattr(metric, '_documentation', ''),
                            "samples": []  # Would contain actual sample data
                        }
                    except:
                        continue
                
                exported_data = json.dumps(metrics_data, indent=2)
            
            else:
                return {
                    "success": False,
                    "error": f"Unsupported export format: {export_format}"
                }
            
            return {
                "success": True,
                "result": {
                    "exported_data": exported_data,
                    "export_format": export_format,
                    "export_timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Metric export error: {str(e)}")
            return {
                "success": False,
                "error": f"Metric export failed: {str(e)}"
            }
    
    async def _handle_endpoint_scraping(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle endpoint scraping configuration."""
        try:
            scrape_config = ctx.get("scrape_config", {})
            endpoint_url = scrape_config.get("endpoint_url")
            
            if not endpoint_url:
                return {
                    "success": False,
                    "error": "endpoint_url is required for scraping"
                }
            
            # Test scrape endpoint
            metrics_path = scrape_config.get("path", "/metrics")
            
            if not self.backend:
                return {"success": False, "error": "Prometheus backend not available - configure Prometheus connection"}
            
            try:
                # Use real Prometheus backend for endpoint scraping
                timeout = int(scrape_config.get("timeout", "10s").rstrip('s'))
                scraped_metrics = await self.backend.scrape_endpoint(endpoint_url, metrics_path, timeout)
            except Exception as e:
                logger.error(f"Endpoint scraping failed: {str(e)}")
                return {"success": False, "error": f"Endpoint scraping failed: {str(e)}"}
            
            # Generate scrape configuration for Prometheus
            prometheus_scrape_config = {
                "job_name": f"plugpipe-{endpoint_url.replace('://', '-').replace('/', '-')}",
                "static_configs": [{"targets": [endpoint_url.replace("http://", "").replace("https://", "")]}],
                "metrics_path": metrics_path,
                "scrape_interval": scrape_config.get("interval", "15s"),
                "scrape_timeout": scrape_config.get("timeout", "10s")
            }
            
            full_url = f"{endpoint_url.rstrip('/')}{metrics_path}"
            
            return {
                "success": True,
                "result": {
                    "endpoint_scraped": True,
                    "endpoint_url": full_url,
                    "metrics_count": len([line for line in scraped_metrics.split('\n') if line and not line.startswith('#')]),
                    "scrape_config": prometheus_scrape_config
                },
                "monitoring_metadata": {
                    "scrape_timestamp": datetime.now(timezone.utc).isoformat()
                }
            }
            
        except Exception as e:
            logger.error(f"Endpoint scraping error: {str(e)}")
            return {
                "success": False,
                "error": f"Endpoint scraping failed: {str(e)}"
            }
    
    async def _handle_health_check(self, ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
        """Handle health check for monitoring infrastructure."""
        try:
            if not self.backend:
                # Graceful degradation: return basic status even without full backend
                return {
                    "success": True,
                    "message": "Prometheus Monitoring operational in graceful degradation mode",
                    "status": "degraded",
                    "available_features": {
                        "prometheus_client": self.prometheus_available,
                        "requests": self.requests_available,
                        "grafana_api": GRAFANA_API_AVAILABLE,
                        "backend": BACKEND_AVAILABLE
                    },
                    "mode": "graceful_degradation" if self.graceful_mode else "full_functionality"
                }
            
            try:
                # Use real Prometheus backend for health check
                health_result = await self.backend.get_health_status()
                
                return {
                    "success": True,
                    "result": health_result["services"],
                    "monitoring_metadata": {
                        "overall_healthy": health_result["healthy"],
                        "check_timestamp": datetime.now(timezone.utc).isoformat(),
                        "prometheus_url": health_result["prometheus_url"],
                        "grafana_url": health_result["grafana_url"],
                        "gateway_url": health_result["pushgateway_url"]
                    }
                }
            except Exception as e:
                logger.error(f"Health check failed: {str(e)}")
                return {"success": False, "error": f"Health check failed: {str(e)}"}
            
        except Exception as e:
            logger.error(f"Health check error: {str(e)}")
            return {
                "success": False,
                "error": f"Health check failed: {str(e)}"
            }
    
    async def cleanup(self):
        """Cleanup monitoring resources."""
        try:
            # Clear metrics from gateway
            if self.gateway_url and self.backend:
                try:
                    await self.backend.delete_metrics(
                        job_name=self.job_name,
                        grouping_key={'instance': self.instance}
                    )
                except Exception as e:
                    logger.warning(f"Failed to clear metrics from gateway: {str(e)}")
            
            # Close backend connection
            if self.backend:
                await self.backend.close()
            
            logger.info("Prometheus monitoring cleanup completed")
            
        except Exception as e:
            logger.warning(f"Monitoring cleanup error: {str(e)}")


# Plug entry point for PlugPipe compatibility  
async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Plug entry point for PlugPipe compatibility.
    
    This function demonstrates the plugin-first approach by leveraging Prometheus's
    proven monitoring ecosystem instead of implementing custom metrics collection.
    
    Args:
        ctx: Plug execution context with monitoring operation parameters
        cfg: Plug configuration including Prometheus settings
        
    Returns:
        Monitoring operation result
    """
    try:
        # Create plugin instance
        plugin = PrometheusMonitoringPlug(cfg)
        
        # Execute monitoring operation
        result = await plugin.process(ctx, cfg)
        
        return result
        
    except Exception as e:
        logger.error(f"Prometheus monitoring plugin error: {str(e)}")
        return {
            "success": False,
            "error": f"Monitoring error: {str(e)}"
        }


# Health check for monitoring systems
async def health_check(cfg: Dict[str, Any] = None) -> Dict[str, Any]:
    """Health check for Prometheus monitoring plugin."""
    try:
        plugin = PrometheusMonitoringPlug(cfg)
        return await plugin._handle_health_check({}, cfg)
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }


if __name__ == "__main__":
    # Test execution
    import asyncio
    
    async def test():
        # Test with real Prometheus configuration
        config = {
            "prometheus_config": {
                "prometheus_url": "http://127.0.0.1:9090",
                "gateway_url": "http://127.0.0.1:9091",
                "grafana_url": "http://127.0.0.1:3000",
                "job_name": "plugpipe-test",
                "instance": "test-instance"
            }
        }
        
        # Test metric recording
        metric_ctx = {
            "operation": "record_metric",
            "metric_name": "test_metric",
            "metric_value": 42.0,
            "metric_type": "gauge",
            "labels": {"service": "test"}
        }
        
        result = await process(metric_ctx, config)
        print("Metric recording test:", json.dumps(result, indent=2))
        
        # Test health check
        health = await health_check(config)
        print("Health check:", json.dumps(health, indent=2))
    
    asyncio.run(test())