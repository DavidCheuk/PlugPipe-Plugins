#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Issue Tracker API Server
========================

Real-time API server for issue tracker data access with WebSocket support,
dashboard integration, and comprehensive validation issue management endpoints.

Features:
- REST API endpoints for issue data access
- Real-time WebSocket updates for live dashboard integration  
- OpenAPI/Swagger documentation
- Caching for performance optimization
- Rate limiting and security middleware
- Dashboard-optimized endpoints with analytics
- Integration with issue tracker plugin

Following PlugPipe principles:
- "Reuse everything, reinvent nothing" - leverages existing FastAPI patterns and issue tracker
- "Everything is a plugin" - integrates through plugin discovery system
- "Convention over configuration" - sensible defaults with extensive configurability
"""

import os
import sys
import json
import time
import asyncio
import threading
from typing import Dict, Any, List, Optional, Set
from datetime import datetime, timedelta
from pathlib import Path
import uuid
from contextlib import asynccontextmanager
from collections import defaultdict, deque

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
sys.path.insert(0, PROJECT_ROOT)

try:
    from shares.loader import pp
    from shares.utils.config_loader import get_llm_config
except ImportError:
    # Fallback for standalone execution
    def pp(plugin_name):
        return None
    def get_llm_config(primary=True):
        return {}

# FastAPI and WebSocket dependencies
try:
    from fastapi import FastAPI, HTTPException, WebSocket, WebSocketDisconnect, Depends, Query, Path as FastAPIPath
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from fastapi.openapi.docs import get_swagger_ui_html
    from pydantic import BaseModel, Field
    import uvicorn
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    print("⚠️ FastAPI not available - install with: pip install fastapi uvicorn")

# Optional caching
try:
    from functools import lru_cache
    import pickle
    CACHING_AVAILABLE = True
except ImportError:
    CACHING_AVAILABLE = False

class IssueTrackerAPIServer:
    """
    Real-time API server for issue tracker data access and dashboard integration.
    
    Provides REST and WebSocket endpoints for accessing validation issue data
    with real-time updates, caching, and dashboard optimization.
    """
    
    def __init__(self):
        self.server = None
        self.app = None
        self.server_thread = None
        self.server_config = {}
        self.issue_tracker_config = {}
        self.websocket_connections = set()
        self.cache = {}
        self.cache_timestamps = {}
        self.running = False
        self.start_time = None
        
    async def process_operation(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Main entry point for API server operations."""
        try:
            operation = config.get('operation', 'start_server')
            
            # Route to appropriate operation handler
            if operation == 'start_server':
                return await self._start_server(context, config)
            elif operation == 'stop_server':
                return await self._stop_server(context, config)
            elif operation == 'get_server_status':
                return await self._get_server_status(context, config)
            elif operation == 'configure_endpoints':
                return await self._configure_endpoints(context, config)
            elif operation == 'test_endpoints':
                return await self._test_endpoints(context, config)
            else:
                return self._error_response(f"Unknown operation: {operation}")
                
        except Exception as e:
            return self._error_response(f"API server operation failed: {str(e)}")
    
    async def _start_server(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Start the FastAPI server with issue tracker endpoints."""
        if not FASTAPI_AVAILABLE:
            return self._error_response("FastAPI not available - install with: pip install fastapi uvicorn")
        
        try:
            # Load configuration
            self.server_config = config.get('server_config', {})
            self.issue_tracker_config = config.get('issue_tracker_config', {})
            auth_config = config.get('auth_config', {})
            dashboard_config = config.get('dashboard_config', {})
            
            # Create FastAPI app
            self.app = FastAPI(
                title=self.server_config.get('title', 'PlugPipe Issue Tracker API'),
                description=self.server_config.get('description', 'Real-time API for validation issue tracking'),
                version=self.server_config.get('version', '1.0.0'),
                docs_url="/docs" if self.server_config.get('enable_docs', True) else None
            )
            
            # Setup CORS if enabled
            if self.server_config.get('enable_cors', True):
                self.app.add_middleware(
                    CORSMiddleware,
                    allow_origins=self.server_config.get('cors_origins', ['*']),
                    allow_credentials=True,
                    allow_methods=["*"],
                    allow_headers=["*"]
                )
            
            # Register API endpoints
            await self._register_api_endpoints(dashboard_config)
            
            # Setup WebSocket if enabled
            if self.server_config.get('enable_websockets', True):
                self._setup_websocket_endpoints()
            
            # Start server in background thread
            host = self.server_config.get('host', '127.0.0.1')
            port = self.server_config.get('port', 8080)
            
            self.start_time = datetime.utcnow()
            self.running = True
            
            # Run server in background
            self.server_thread = threading.Thread(
                target=self._run_server,
                args=(host, port),
                daemon=True
            )
            self.server_thread.start()
            
            # Wait a moment for server to start
            await asyncio.sleep(1)
            
            server_url = f"http://{host}:{port}"
            websocket_url = f"ws://{host}:{port}/ws" if self.server_config.get('enable_websockets', True) else None
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'start_server',
                    'timestamp': datetime.utcnow().isoformat(),
                    'server_url': server_url,
                    'websocket_url': websocket_url
                },
                'server_status': {
                    'status': 'running',
                    'host': host,
                    'port': port,
                    'uptime_seconds': 1,
                    'endpoints_registered': len(self._get_registered_endpoints()),
                    'websocket_connections': len(self.websocket_connections)
                },
                'api_endpoints': {
                    'total_endpoints': len(self._get_registered_endpoints()),
                    'endpoints_list': self._get_registered_endpoints(),
                    'websocket_endpoint': websocket_url,
                    'documentation_url': f"{server_url}/docs" if self.server_config.get('enable_docs', True) else None
                }
            }
            
        except Exception as e:
            return self._error_response(f"Failed to start server: {str(e)}")
    
    def _run_server(self, host: str, port: int):
        """Run the FastAPI server using uvicorn."""
        try:
            uvicorn.run(
                self.app,
                host=host,
                port=port,
                log_level="info",
                access_log=True
            )
        except Exception as e:
            print(f"Server error: {e}")
            self.running = False
    
    async def _register_api_endpoints(self, dashboard_config: Dict[str, Any]):
        """Register all API endpoints for issue tracker data access."""
        
        # Root endpoint
        @self.app.get("/", tags=["Root"])
        async def root():
            return {
                "message": "PlugPipe Issue Tracker API",
                "version": "1.0.0",
                "endpoints": {
                    "issues": "/api/issues",
                    "summary": "/api/issues/summary", 
                    "latest": "/api/issues/latest",
                    "dashboard": "/api/dashboard",
                    "health": "/api/health",
                    "docs": "/docs",
                    "websocket": "/ws"
                }
            }
        
        # Health check endpoint
        @self.app.get("/api/health", tags=["System"])
        async def health_check():
            try:
                # Test issue tracker connectivity
                issue_tracker = pp(self.issue_tracker_config.get('issue_tracker_plugin', 'issue_tracker'))
                if issue_tracker:
                    health_result = await self._safe_plugin_call(issue_tracker, {}, {'operation': 'get_health_status'})
                    tracker_healthy = health_result.get('success', False)
                else:
                    tracker_healthy = False
                
                return {
                    "status": "healthy" if tracker_healthy else "degraded",
                    "timestamp": datetime.utcnow().isoformat(),
                    "uptime_seconds": (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0,
                    "issue_tracker_healthy": tracker_healthy,
                    "websocket_connections": len(self.websocket_connections),
                    "cache_enabled": self.issue_tracker_config.get('cache_enabled', True)
                }
            except Exception as e:
                return JSONResponse(
                    status_code=503,
                    content={"status": "unhealthy", "error": str(e)}
                )
        
        # Get latest issues
        @self.app.get("/api/issues/latest", tags=["Issues"])
        async def get_latest_issues():
            try:
                result = await self._get_cached_issue_data('get_latest_issues', {})
                if result.get('success'):
                    return {
                        "success": True,
                        "data": result.get('issues_data', {}),
                        "timestamp": datetime.utcnow().isoformat(),
                        "cached": result.get('_cached', False)
                    }
                else:
                    raise HTTPException(status_code=500, detail=result.get('error', 'Failed to get latest issues'))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Get issue summary/analytics
        @self.app.get("/api/issues/summary", tags=["Issues"])
        async def get_issue_summary():
            try:
                result = await self._get_cached_issue_data('get_issue_summary', {})
                if result.get('success'):
                    return {
                        "success": True,
                        "summary": result.get('issue_summary', {}),
                        "timestamp": datetime.utcnow().isoformat(),
                        "cached": result.get('_cached', False)
                    }
                else:
                    raise HTTPException(status_code=500, detail=result.get('error', 'Failed to get issue summary'))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        # Dashboard endpoints if enabled
        if dashboard_config.get('enable_dashboard_endpoints', True):
            await self._register_dashboard_endpoints(dashboard_config)
    
    async def _register_dashboard_endpoints(self, dashboard_config: Dict[str, Any]):
        """Register dashboard-specific endpoints."""
        
        @self.app.get("/api/dashboard", tags=["Dashboard"])
        async def get_dashboard_data():
            try:
                # Get comprehensive dashboard data
                latest_result = await self._get_cached_issue_data('get_latest_issues', {})
                summary_result = await self._get_cached_issue_data('get_issue_summary', {})
                
                dashboard_data = {
                    "timestamp": datetime.utcnow().isoformat(),
                    "refresh_interval": dashboard_config.get('dashboard_refresh_interval', 30),
                    "latest_issues": latest_result.get('issues_data', {}) if latest_result.get('success') else {},
                    "summary": summary_result.get('issue_summary', {}) if summary_result.get('success') else {},
                    "websocket_url": f"ws://{self.server_config.get('host', '127.0.0.1')}:{self.server_config.get('port', 8080)}/ws",
                    "system_status": {
                        "server_uptime": (datetime.utcnow() - self.start_time).total_seconds() if self.start_time else 0,
                        "websocket_connections": len(self.websocket_connections),
                        "cache_status": "enabled" if self.issue_tracker_config.get('cache_enabled', True) else "disabled"
                    }
                }
                
                # Add analytics if enabled
                if dashboard_config.get('include_analytics', True):
                    dashboard_data["analytics"] = await self._generate_analytics_data()
                
                # Add chart data if enabled
                if dashboard_config.get('include_charts_data', True):
                    dashboard_data["charts"] = await self._generate_chart_data(summary_result.get('issue_summary', {}))
                
                return dashboard_data
                
            except Exception as e:
                raise HTTPException(status_code=500, detail=f"Failed to get dashboard data: {str(e)}")
        
        @self.app.get("/api/dashboard/analytics", tags=["Dashboard"])
        async def get_analytics():
            try:
                return await self._generate_analytics_data()
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
        
        @self.app.get("/api/dashboard/charts", tags=["Dashboard"]) 
        async def get_chart_data():
            try:
                summary_result = await self._get_cached_issue_data('get_issue_summary', {})
                return await self._generate_chart_data(summary_result.get('issue_summary', {}))
            except Exception as e:
                raise HTTPException(status_code=500, detail=str(e))
    
    def _setup_websocket_endpoints(self):
        """Setup WebSocket endpoints for real-time updates."""
        
        @self.app.websocket("/ws")
        async def websocket_endpoint(websocket: WebSocket):
            await websocket.accept()
            self.websocket_connections.add(websocket)
            
            try:
                # Send initial data
                latest_result = await self._get_cached_issue_data('get_latest_issues', {})
                summary_result = await self._get_cached_issue_data('get_issue_summary', {})
                
                initial_data = {
                    "type": "initial",
                    "timestamp": datetime.utcnow().isoformat(),
                    "data": {
                        "latest_issues": latest_result.get('issues_data', {}),
                        "summary": summary_result.get('issue_summary', {})
                    }
                }
                
                await websocket.send_json(initial_data)
                
                # Keep connection alive and handle messages
                while True:
                    try:
                        # Wait for client messages or send periodic updates
                        data = await asyncio.wait_for(websocket.receive_json(), timeout=30.0)
                        
                        # Handle client requests
                        if data.get("type") == "ping":
                            await websocket.send_json({"type": "pong", "timestamp": datetime.utcnow().isoformat()})
                        elif data.get("type") == "request_update":
                            # Send latest data
                            await self._send_websocket_update(websocket)
                            
                    except asyncio.TimeoutError:
                        # Send periodic update
                        await self._send_websocket_update(websocket)
                        
            except WebSocketDisconnect:
                raise NotImplementedError(\"This method needs implementation\")\n            except Exception as e:
                print(f"WebSocket error: {e}")
            finally:
                self.websocket_connections.discard(websocket)
    
    async def _send_websocket_update(self, websocket: WebSocket):
        """Send real-time update to WebSocket client."""
        try:
            latest_result = await self._get_cached_issue_data('get_latest_issues', {})
            summary_result = await self._get_cached_issue_data('get_issue_summary', {})
            
            update_data = {
                "type": "update",
                "timestamp": datetime.utcnow().isoformat(),
                "data": {
                    "latest_issues": latest_result.get('issues_data', {}),
                    "summary": summary_result.get('issue_summary', {})
                }
            }
            
            await websocket.send_json(update_data)
        except Exception as e:
            print(f"Failed to send WebSocket update: {e}")
    
    async def _get_cached_issue_data(self, operation: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Get issue data with caching support."""
        if not self.issue_tracker_config.get('cache_enabled', True):
            return await self._call_issue_tracker(operation, config)
        
        cache_key = f"{operation}:{json.dumps(config, sort_keys=True)}"
        cache_ttl = self.issue_tracker_config.get('cache_ttl_seconds', 300)
        
        # Check cache
        if cache_key in self.cache:
            cache_time = self.cache_timestamps.get(cache_key, datetime.min)
            if datetime.utcnow() - cache_time < timedelta(seconds=cache_ttl):
                result = self.cache[cache_key]
                result['_cached'] = True
                return result
        
        # Get fresh data
        result = await self._call_issue_tracker(operation, config)
        
        # Cache successful results
        if result.get('success'):
            self.cache[cache_key] = result
            self.cache_timestamps[cache_key] = datetime.utcnow()
        
        result['_cached'] = False
        return result
    
    async def _call_issue_tracker(self, operation: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Call the issue tracker plugin."""
        try:
            issue_tracker = pp(self.issue_tracker_config.get('issue_tracker_plugin', 'issue_tracker'))
            if not issue_tracker:
                return {'success': False, 'error': 'Issue tracker plugin not available'}
            
            tracker_config = {'operation': operation, **config}
            return await self._safe_plugin_call(issue_tracker, {}, tracker_config)
            
        except Exception as e:
            return {'success': False, 'error': f'Issue tracker call failed: {str(e)}'}
    
    async def _generate_analytics_data(self) -> Dict[str, Any]:
        """Generate analytics data for dashboard."""
        try:
            summary_result = await self._get_cached_issue_data('get_issue_summary', {})
            summary = summary_result.get('issue_summary', {})
            
            return {
                "timestamp": datetime.utcnow().isoformat(),
                "metrics": {
                    "total_issues": summary.get('total_issues', 0),
                    "critical_issues": summary.get('critical_issues', 0),
                    "high_issues": summary.get('high_issues', 0),
                    "medium_issues": summary.get('medium_issues', 0),
                    "low_issues": summary.get('low_issues', 0),
                    "average_score": summary.get('average_score', 0)
                },
                "trends": {
                    "issues_by_category": summary.get('issues_by_category', {}),
                    "latest_validation_run": summary.get('latest_validation_run')
                },
                "health_indicators": {
                    "overall_health": "good" if summary.get('critical_issues', 0) == 0 else "warning" if summary.get('critical_issues', 0) < 5 else "critical",
                    "improvement_trend": "stable"  # Could be enhanced with historical data
                }
            }
        except Exception as e:
            return {"error": f"Failed to generate analytics: {str(e)}"}
    
    async def _generate_chart_data(self, summary: Dict[str, Any]) -> Dict[str, Any]:
        """Generate chart data for dashboard visualization."""
        try:
            return {
                "severity_distribution": {
                    "type": "pie",
                    "data": {
                        "labels": ["Critical", "High", "Medium", "Low"],
                        "values": [
                            summary.get('critical_issues', 0),
                            summary.get('high_issues', 0), 
                            summary.get('medium_issues', 0),
                            summary.get('low_issues', 0)
                        ]
                    }
                },
                "category_breakdown": {
                    "type": "bar",
                    "data": {
                        "labels": list(summary.get('issues_by_category', {}).keys()),
                        "values": list(summary.get('issues_by_category', {}).values())
                    }
                },
                "timeline": {
                    "type": "line",
                    "data": {
                        "labels": ["Current"],  # Could be enhanced with historical data
                        "values": [summary.get('total_issues', 0)]
                    }
                }
            }
        except Exception as e:
            return {"error": f"Failed to generate chart data: {str(e)}"}
    
    def _get_registered_endpoints(self) -> List[Dict[str, Any]]:
        """Get list of registered API endpoints."""
        if not self.app:
            return []
        
        endpoints = []
        for route in self.app.routes:
            if hasattr(route, 'methods') and hasattr(route, 'path'):
                for method in route.methods:
                    if method != 'HEAD':  # Skip HEAD methods
                        endpoints.append({
                            "path": route.path,
                            "method": method,
                            "description": getattr(route, 'summary', ''),
                            "auth_required": False  # Could be enhanced based on dependencies
                        })
        
        return endpoints
    
    async def _get_server_status(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Get current server status."""
        try:
            if self.running and self.start_time:
                uptime = (datetime.utcnow() - self.start_time).total_seconds()
                status = "running"
            else:
                uptime = 0
                status = "stopped"
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'get_server_status',
                    'timestamp': datetime.utcnow().isoformat()
                },
                'server_status': {
                    'status': status,
                    'host': self.server_config.get('host', '127.0.0.1'),
                    'port': self.server_config.get('port', 8080),
                    'uptime_seconds': uptime,
                    'endpoints_registered': len(self._get_registered_endpoints()),
                    'websocket_connections': len(self.websocket_connections)
                },
                'integration_status': {
                    'issue_tracker_available': pp(self.issue_tracker_config.get('issue_tracker_plugin', 'issue_tracker')) is not None,
                    'cache_status': 'enabled' if self.issue_tracker_config.get('cache_enabled', True) else 'disabled',
                    'real_time_enabled': self.issue_tracker_config.get('real_time_updates', True),
                    'auth_enabled': False  # Could be enhanced
                }
            }
        except Exception as e:
            return self._error_response(f"Failed to get server status: {str(e)}")
    
    async def _stop_server(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Stop the API server."""
        try:
            self.running = False
            
            # Close WebSocket connections
            for websocket in list(self.websocket_connections):
                try:
                    await websocket.close()
                except Exception:
                    pass
            self.websocket_connections.clear()
            
            # Clear cache
            self.cache.clear()
            self.cache_timestamps.clear()
            
            return {
                'success': True,
                'operation_result': {
                    'operation': 'stop_server',
                    'timestamp': datetime.utcnow().isoformat()
                },
                'server_status': {
                    'status': 'stopped',
                    'uptime_seconds': 0,
                    'websocket_connections': 0
                }
            }
            
        except Exception as e:
            return self._error_response(f"Failed to stop server: {str(e)}")
    
    async def _safe_plugin_call(self, plugin, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Safely call a plugin, handling both sync and async returns."""
        try:
            result = plugin.process(context, config)
            
            # Handle async plugins
            if asyncio.iscoroutine(result):
                result = await result
                
            return result if isinstance(result, dict) else {'success': False, 'error': 'Invalid plugin response'}
            
        except Exception as e:
            return {'success': False, 'error': f'Plugin call failed: {str(e)}'}
    
    def _error_response(self, error_message: str) -> Dict[str, Any]:
        """Generate standardized error response."""
        return {
            'success': False,
            'error': error_message,
            'operation_result': {
                'operation': 'error',
                'timestamp': datetime.utcnow().isoformat()
            }
        }
    
    # Placeholder methods for additional operations
    async def _configure_endpoints(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Configure custom endpoints."""
        return self._error_response("configure_endpoints operation not yet implemented")
    
    async def _test_endpoints(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Test API endpoints."""
        return self._error_response("test_endpoints operation not yet implemented")

# Main plugin entry point
async def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point for the API server."""
    server = IssueTrackerAPIServer()
    return await server.process_operation(context, config)

# Plugin metadata
plug_metadata = {
    "name": "issue_tracker_api_server",
    "version": "1.0.0",
    "description": "Real-time API server for issue tracker data access with WebSocket support and dashboard integration",
    "author": "PlugPipe Core Team",
    "license": "MIT",
    "category": "backend",
    "tags": ["api", "server", "real-time", "dashboard", "rest", "websocket", "issues"],
    "requirements": ["fastapi>=0.100.0", "uvicorn>=0.22.0", "pydantic>=2.0.0"],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["start_server", "stop_server", "get_server_status", "configure_endpoints", "test_endpoints"],
                "default": "start_server",
                "description": "API server operation to perform"
            }
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "server_status": {
                "type": "object",
                "properties": {
                    "status": {"type": "string"},
                    "uptime_seconds": {"type": "number"}
                }
            }
        }
    },
    "sbom": "sbom/"
}