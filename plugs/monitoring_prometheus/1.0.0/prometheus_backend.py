# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Real Prometheus backend for monitoring operations.

This module provides concrete implementations for Prometheus monitoring operations,
replacing mock implementations with production-ready Prometheus integrations.
"""

import os
import json
import logging
from typing import Dict, Any, Optional, List, Union
from datetime import datetime, timezone
import asyncio

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False

try:
    from prometheus_client import (
        Counter, Gauge, Histogram, Summary, 
        CollectorRegistry, generate_latest,
        push_to_gateway, delete_from_gateway
    )
    PROMETHEUS_CLIENT_AVAILABLE = True
except ImportError:
    PROMETHEUS_CLIENT_AVAILABLE = False

try:
    from grafana_api.grafana_face import GrafanaFace
    GRAFANA_API_AVAILABLE = True
except ImportError:
    GRAFANA_API_AVAILABLE = False

logger = logging.getLogger(__name__)


class PrometheusBackend:
    """Production-ready Prometheus backend for monitoring operations."""
    
    def __init__(self, config: Dict[str, Any] = None):
        """Initialize Prometheus backend."""
        if not PROMETHEUS_CLIENT_AVAILABLE:
            raise ImportError("Prometheus client not available. Install with: pip install prometheus-client")
        
        if not REQUESTS_AVAILABLE:
            raise ImportError("Requests library not available. Install with: pip install requests")
        
        self.config = config or {}
        self.prometheus_config = self.config.get("prometheus_config", {})
        
        # Connection settings
        self.prometheus_url = self.prometheus_config.get(
            "prometheus_url",
            os.getenv("PROMETHEUS_URL", "http://127.0.0.1:9090")
        )
        self.pushgateway_url = self.prometheus_config.get(
            "gateway_url", 
            os.getenv("PUSHGATEWAY_URL", "http://127.0.0.1:9091")
        )
        self.grafana_url = self.prometheus_config.get(
            "grafana_url",
            os.getenv("GRAFANA_URL", "http://127.0.0.1:3000")
        )
        
        # Authentication settings
        self.prometheus_auth = self.prometheus_config.get("prometheus_auth")
        self.grafana_auth = self.prometheus_config.get("grafana_auth")
        
        # Service configuration
        self.job_name = self.prometheus_config.get("job_name", "plugpipe")
        self.instance = self.prometheus_config.get("instance", "plugpipe-instance")
        
        # Initialize clients
        self.session = None
        self.grafana_client = None
        self.registry = None
        self.initialized = False
        
    async def initialize(self):
        """Initialize Prometheus backend and verify connectivity."""
        if self.initialized:
            return
        
        try:
            # Initialize HTTP session with retries
            self.session = self._create_http_session()
            
            # Initialize metric registry
            self.registry = CollectorRegistry()
            
            # Initialize Grafana client if available
            if GRAFANA_API_AVAILABLE and self.grafana_auth:
                self.grafana_client = self._initialize_grafana_client()
            
            # Test connectivity
            await self._verify_connectivity()
            
            self.initialized = True
            logger.info(f"Connected to Prometheus at {self.prometheus_url}")
            
        except Exception as e:
            logger.error(f"Failed to initialize Prometheus backend: {str(e)}")
            raise
    
    def _create_http_session(self) -> requests.Session:
        """Create HTTP session with retry configuration."""
        session = requests.Session()
        
        # Add authentication if configured
        if self.prometheus_auth:
            if isinstance(self.prometheus_auth, tuple):
                session.auth = self.prometheus_auth
            elif isinstance(self.prometheus_auth, dict):
                session.headers.update(self.prometheus_auth)
        
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
        """Initialize Grafana API client."""
        try:
            return GrafanaFace(
                auth=self.grafana_auth,
                host=self.grafana_url.replace("http://", "").replace("https://", "")
            )
        except Exception as e:
            logger.warning(f"Failed to initialize Grafana client: {str(e)}")
            return None
    
    async def _verify_connectivity(self):
        """Verify connectivity to Prometheus services."""
        try:
            # Test Prometheus connection
            response = self.session.get(f"{self.prometheus_url}/-/healthy", timeout=10)
            if response.status_code != 200:
                logger.warning(f"Prometheus health check failed: {response.status_code}")
            
            # Test Pushgateway connection if configured
            if self.pushgateway_url:
                response = self.session.get(f"{self.pushgateway_url}/metrics", timeout=10)
                if response.status_code != 200:
                    logger.warning(f"Pushgateway connection failed: {response.status_code}")
            
        except Exception as e:
            logger.warning(f"Could not verify all Prometheus services: {str(e)}")
    
    async def execute_query(self, query: str, time_range: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        """Execute PromQL query against Prometheus."""
        await self.initialize()
        
        try:
            # Build query URL
            if time_range and time_range.get("start") and time_range.get("end"):
                query_url = f"{self.prometheus_url}/api/v1/query_range"
                params = {
                    "query": query,
                    "start": time_range["start"],
                    "end": time_range["end"],
                    "step": time_range.get("step", "15s")
                }
            else:
                query_url = f"{self.prometheus_url}/api/v1/query"
                params = {"query": query}
            
            # Execute query
            response = self.session.get(query_url, params=params, timeout=30)
            response.raise_for_status()
            
            query_result = response.json()
            
            if query_result["status"] != "success":
                raise ValueError(f"Query failed: {query_result.get('error', 'Unknown error')}")
            
            logger.debug(f"Executed PromQL query: {query}")
            
            return query_result["data"]
            
        except Exception as e:
            logger.error(f"Query execution error: {str(e)}")
            raise
    
    async def push_metrics(self, registry: Any, job_name: str = None, 
                          grouping_key: Optional[Dict[str, str]] = None) -> bool:
        """Push metrics to Prometheus Pushgateway."""
        await self.initialize()
        
        if not self.pushgateway_url:
            raise ValueError("Pushgateway URL not configured")
        
        try:
            job = job_name or self.job_name
            grouping = grouping_key or {'instance': self.instance}
            
            # Push metrics to gateway
            push_to_gateway(
                self.pushgateway_url,
                job=job,
                registry=registry,
                grouping_key=grouping
            )
            
            logger.debug(f"Pushed metrics to gateway: {self.pushgateway_url}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to push metrics: {str(e)}")
            raise
    
    async def delete_metrics(self, job_name: str = None, 
                           grouping_key: Optional[Dict[str, str]] = None) -> bool:
        """Delete metrics from Prometheus Pushgateway."""
        await self.initialize()
        
        if not self.pushgateway_url:
            raise ValueError("Pushgateway URL not configured")
        
        try:
            job = job_name or self.job_name
            grouping = grouping_key or {'instance': self.instance}
            
            # Delete metrics from gateway
            delete_from_gateway(
                self.pushgateway_url,
                job=job,
                grouping_key=grouping
            )
            
            logger.debug(f"Deleted metrics from gateway: {self.pushgateway_url}")
            
            return True
            
        except Exception as e:
            logger.error(f"Failed to delete metrics: {str(e)}")
            raise
    
    async def scrape_endpoint(self, endpoint_url: str, metrics_path: str = "/metrics", 
                            timeout: int = 10) -> str:
        """Scrape metrics from an endpoint."""
        await self.initialize()
        
        try:
            full_url = f"{endpoint_url.rstrip('/')}{metrics_path}"
            
            response = self.session.get(full_url, timeout=timeout)
            response.raise_for_status()
            
            scraped_metrics = response.text
            
            logger.debug(f"Scraped metrics from {full_url}")
            
            return scraped_metrics
            
        except Exception as e:
            logger.error(f"Endpoint scraping error: {str(e)}")
            raise
    
    async def create_grafana_dashboard(self, dashboard_config: Dict[str, Any]) -> Dict[str, Any]:
        """Create Grafana dashboard."""
        await self.initialize()
        
        if not self.grafana_client:
            raise ValueError("Grafana client not available")
        
        try:
            # Create dashboard
            dashboard_result = self.grafana_client.dashboard.create_dashboard(dashboard_config)
            
            logger.info(f"Created Grafana dashboard: {dashboard_config.get('title', 'Unknown')}")
            
            return dashboard_result
            
        except Exception as e:
            logger.error(f"Dashboard creation error: {str(e)}")
            raise
    
    async def send_webhook_alert(self, webhook_url: str, alert_data: Dict[str, Any]) -> bool:
        """Send webhook alert notification."""
        await self.initialize()
        
        try:
            webhook_payload = {
                "alert_data": alert_data,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "source": "plugpipe-prometheus-backend"
            }
            
            response = self.session.post(
                webhook_url,
                json=webhook_payload,
                timeout=10
            )
            response.raise_for_status()
            
            logger.info(f"Sent webhook alert to {webhook_url}")
            
            return True
            
        except Exception as e:
            logger.error(f"Webhook alert error: {str(e)}")
            raise
    
    async def get_health_status(self) -> Dict[str, Any]:
        """Get health status of Prometheus services."""
        try:
            if not self.initialized:
                await self.initialize()
            
            health_status = {
                "prometheus_status": "unknown",
                "grafana_status": "unknown", 
                "pushgateway_status": "unknown"
            }
            
            # Check Prometheus
            try:
                response = self.session.get(f"{self.prometheus_url}/-/healthy", timeout=5)
                health_status["prometheus_status"] = "healthy" if response.status_code == 200 else "unhealthy"
            except Exception:
                health_status["prometheus_status"] = "unreachable"
            
            # Check Grafana
            try:
                response = self.session.get(f"{self.grafana_url}/api/health", timeout=5)
                health_status["grafana_status"] = "healthy" if response.status_code == 200 else "unhealthy"
            except Exception:
                health_status["grafana_status"] = "unreachable"
            
            # Check Pushgateway
            if self.pushgateway_url:
                try:
                    response = self.session.get(f"{self.pushgateway_url}/metrics", timeout=5)
                    health_status["pushgateway_status"] = "healthy" if response.status_code == 200 else "unhealthy"
                except Exception:
                    health_status["pushgateway_status"] = "unreachable"
            
            overall_healthy = all(status in ["healthy", "unknown"] for status in health_status.values())
            
            return {
                "healthy": overall_healthy,
                "monitoring_status": "connected",
                "services": health_status,
                "prometheus_url": self.prometheus_url,
                "grafana_url": self.grafana_url,
                "pushgateway_url": self.pushgateway_url
            }
            
        except Exception as e:
            logger.error(f"Health check error: {str(e)}")
            return {
                "healthy": False,
                "monitoring_status": "error",
                "error": str(e)
            }
    
    async def close(self):
        """Close Prometheus backend connections."""
        if self.session:
            self.session.close()
        
        self.initialized = False
        logger.info("Closed Prometheus backend connections")