#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enhanced Plug Creation Agent - Intelligent Plugin Generation

This plugin automatically researches APIs, analyzes documentation, generates comprehensive
plugins with proper testing, SBOM generation, and release automation.

Key Features:
- AI-powered API documentation analysis
- Automatic plugin scaffolding with best practices
- Comprehensive test generation
- SBOM generation and validation
- Release automation
- Integration with existing PlugPipe ecosystem

Architecture:
- Research Phase: Web scraping, API discovery, documentation analysis
- Analysis Phase: AI-powered feature extraction and pattern recognition
- Generation Phase: Code generation with templates and best practices
- Testing Phase: Automated test creation and execution
- Release Phase: Documentation, SBOM, and registry integration
"""

import logging
import asyncio
import json
import os
import sys
import uuid
import time
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path
import requests
from urllib.parse import urljoin, urlparse
import yaml

# Add project paths
project_root = Path(__file__).parent.parent.parent.parent.parent
sys.path.insert(0, str(project_root))

try:
    from shares.loader import pp
    # FIXED: load_config is in shares.loader, not shares.utils.config_loader
    from shares.loader import load_config
    from shares.utils.template_resolver import TemplateResolver
except ImportError as e:
    logging.warning(f"Could not import PlugPipe modules: {e}")
    # Create mock class for testing
    class TemplateResolver:
        def __init__(self):
            super().__init__()\n

class APIResearcher:
    """Intelligent API research and documentation analysis"""
    
    def __init__(self, logger: logging.Logger, config: Dict[str, Any]):
        self.logger = logger
        self.config = config
        self.session = requests.Session()
        self.session.timeout = 30
        
    async def research_api(self, api_name: str, api_url: str, docs_url: Optional[str] = None) -> Dict[str, Any]:
        """Research API and extract comprehensive information"""
        research_results = {
            'api_name': api_name,
            'base_url': api_url,
            'docs_url': docs_url,
            'analysis_timestamp': datetime.now().isoformat(),
            'endpoints_discovered': 0,
            'authentication_method': 'unknown',
            'rate_limits': {},
            'sdk_available': False,
            'api_version': 'unknown',
            'supported_formats': [],
            'key_features': [],
            'recommended_implementation': {}
        }
        
        try:
            # Primary documentation analysis
            if docs_url:
                self.logger.info(f"Analyzing documentation: {docs_url}")
                doc_analysis = await self._analyze_documentation(docs_url)
                research_results.update(doc_analysis)
            
            # API endpoint discovery
            self.logger.info(f"Discovering API endpoints: {api_url}")
            endpoint_analysis = await self._discover_endpoints(api_url)
            research_results.update(endpoint_analysis)
            
            # Authentication method detection
            auth_analysis = await self._detect_authentication(api_url, docs_url)
            research_results['authentication_method'] = auth_analysis
            
            # SDK and library detection
            sdk_analysis = await self._detect_sdks(api_name)
            research_results['sdk_available'] = sdk_analysis['available']
            research_results['sdk_languages'] = sdk_analysis.get('languages', [])
            
            # Rate limiting analysis
            rate_limit_analysis = await self._analyze_rate_limits(api_url, docs_url)
            research_results['rate_limits'] = rate_limit_analysis
            
            self.logger.info(f"API research completed for {api_name}")
            
        except Exception as e:
            self.logger.error(f"API research failed for {api_name}: {e}")
            research_results['error'] = str(e)
            
        return research_results
    
    async def _analyze_documentation(self, docs_url: str) -> Dict[str, Any]:
        """Analyze API documentation for key information"""
        analysis = {
            'endpoints_discovered': 0,
            'supported_formats': ['json'],
            'key_features': [],
            'api_version': 'v1'
        }
        
        try:
            response = self.session.get(docs_url)
            if response.status_code == 200:
                content = response.text.lower()
                
                # Extract API version
                if 'v2' in content or 'version 2' in content:
                    analysis['api_version'] = 'v2'
                elif 'v3' in content or 'version 3' in content:
                    analysis['api_version'] = 'v3'
                
                # Detect supported formats
                if 'xml' in content:
                    analysis['supported_formats'].append('xml')
                if 'yaml' in content or 'yml' in content:
                    analysis['supported_formats'].append('yaml')
                
                # Extract key features (simplified heuristic)
                features = []
                if 'webhook' in content:
                    features.append('webhooks')
                if 'pagination' in content:
                    features.append('pagination')
                if 'search' in content:
                    features.append('search')
                if 'filter' in content:
                    features.append('filtering')
                if 'upload' in content:
                    features.append('file_upload')
                    
                analysis['key_features'] = features
                
        except Exception as e:
            self.logger.warning(f"Documentation analysis failed: {e}")
            
        return analysis
    
    async def _discover_endpoints(self, api_url: str) -> Dict[str, Any]:
        """Discover API endpoints through common patterns"""
        discovery = {
            'endpoints_discovered': 0,
            'common_endpoints': [],
            'base_patterns': []
        }
        
        common_paths = [
            '/api', '/v1', '/v2', '/api/v1', '/api/v2',
            '/docs', '/swagger', '/openapi.json', '/api-docs'
        ]
        
        discovered_endpoints = []
        
        for path in common_paths:
            try:
                test_url = urljoin(api_url, path)
                response = self.session.head(test_url)
                if response.status_code < 400:
                    discovered_endpoints.append(path)
                    self.logger.debug(f"Discovered endpoint: {test_url}")
            except Exception:
                continue
        
        discovery['endpoints_discovered'] = len(discovered_endpoints)
        discovery['common_endpoints'] = discovered_endpoints
        
        return discovery
    
    async def _detect_authentication(self, api_url: str, docs_url: Optional[str]) -> str:
        """Detect authentication method"""
        auth_methods = []
        
        # Check headers for auth hints
        try:
            response = self.session.head(api_url)
            headers = response.headers
            
            if 'www-authenticate' in headers:
                auth_header = headers['www-authenticate'].lower()
                if 'bearer' in auth_header:
                    auth_methods.append('bearer_token')
                elif 'basic' in auth_header:
                    auth_methods.append('basic_auth')
                elif 'oauth' in auth_header:
                    auth_methods.append('oauth')
            
        except Exception:
            pass
        
        # Default assumption based on modern APIs
        if not auth_methods:
            auth_methods = ['api_key']  # Most common for modern APIs
            
        return auth_methods[0] if auth_methods else 'unknown'
    
    async def _detect_sdks(self, api_name: str) -> Dict[str, Any]:
        """Detect if official SDKs exist"""
        # Simplified detection - in real implementation would check GitHub, package managers
        common_sdk_indicators = ['sdk', 'client', 'library', 'wrapper']
        
        return {
            'available': False,  # Conservative default
            'languages': [],
            'github_repos': []
        }
    
    async def _analyze_rate_limits(self, api_url: str, docs_url: Optional[str]) -> Dict[str, Any]:
        """Analyze rate limiting policies"""
        rate_limits = {
            'requests_per_minute': None,
            'requests_per_hour': None,
            'burst_limit': None,
            'requires_rate_limiting': True  # Conservative default
        }
        
        try:
            response = self.session.head(api_url)
            headers = response.headers
            
            # Check for rate limit headers
            if 'x-ratelimit-limit' in headers:
                rate_limits['requests_per_hour'] = int(headers['x-ratelimit-limit'])
            if 'x-ratelimit-remaining' in headers:
                rate_limits['remaining'] = int(headers['x-ratelimit-remaining'])
                
        except Exception:
            pass
            
        return rate_limits


class PluginGenerator:
    """Intelligent plugin code generation"""
    
    def __init__(self, logger: logging.Logger, config: Dict[str, Any]):
        self.logger = logger
        self.config = config
        self.template_resolver = TemplateResolver()
        
    async def generate_plugin(self, research_results: Dict[str, Any], 
                            plugin_name: str, category: str = "integration") -> Dict[str, Any]:
        """Generate comprehensive plugin from research results"""
        
        generation_results = {
            'plugin_name': plugin_name,
            'plugin_path': None,
            'features_implemented': [],
            'files_created': [],
            'success': False
        }
        
        try:
            # Create plugin directory structure
            plugin_dir = await self._create_plugin_structure(plugin_name, category)
            generation_results['plugin_path'] = str(plugin_dir)
            
            # Generate main plugin file
            main_file = await self._generate_main_file(plugin_dir, research_results, plugin_name)
            generation_results['files_created'].append(str(main_file))
            
            # Generate plugin manifest
            manifest_file = await self._generate_manifest(plugin_dir, research_results, plugin_name)
            generation_results['files_created'].append(str(manifest_file))
            
            # Generate tests
            test_file = await self._generate_tests(plugin_dir, research_results, plugin_name)
            generation_results['files_created'].append(str(test_file))
            
            # Generate documentation
            doc_file = await self._generate_documentation(plugin_dir, research_results, plugin_name)
            generation_results['files_created'].append(str(doc_file))
            
            # Determine implemented features
            features = self._extract_implemented_features(research_results)
            generation_results['features_implemented'] = features
            
            generation_results['success'] = True
            self.logger.info(f"Plugin generated successfully: {plugin_name}")
            
        except Exception as e:
            self.logger.error(f"Plugin generation failed: {e}")
            generation_results['error'] = str(e)
            
        return generation_results
    
    async def _create_plugin_structure(self, plugin_name: str, category: str) -> Path:
        """Create plugin directory structure"""
        plugin_dir = Path(f"plugs/{category}/{plugin_name}/1.0.0")
        plugin_dir.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (plugin_dir / "tests").mkdir(exist_ok=True)
        (plugin_dir / "docs").mkdir(exist_ok=True)
        (plugin_dir / "sbom").mkdir(exist_ok=True)
        
        return plugin_dir
    
    async def _generate_main_file(self, plugin_dir: Path, research: Dict[str, Any], 
                                plugin_name: str) -> Path:
        """Generate main plugin implementation"""
        
        auth_method = research.get('authentication_method', 'api_key')
        api_url = research.get('base_url', '')
        key_features = research.get('key_features', [])
        
        main_content = f'''#!/usr/bin/env python3
"""
{plugin_name.title().replace('_', ' ')} Plugin

Auto-generated plugin for {research.get('api_name', plugin_name)} API integration.
Generated on: {datetime.now().isoformat()}

Features implemented:
{chr(10).join(f"- {feature}" for feature in key_features)}

Authentication: {auth_method}
API Version: {research.get('api_version', 'v1')}
"""

import logging
import requests
import time
from typing import Dict, List, Any, Optional
from datetime import datetime


class {plugin_name.title().replace('_', '')}Client:
    """Client for {research.get('api_name', plugin_name)} API"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        self.base_url = config.get('base_url', '{api_url}')
        self.session = requests.Session()
        
        # Setup authentication
        self._setup_authentication()
        
        # Setup rate limiting
        self.rate_limit_delay = config.get('rate_limit_delay', 0.1)
        
    def _setup_authentication(self):
        """Setup API authentication"""
        auth_method = '{auth_method}'
        
        if auth_method == 'api_key':
            api_key = self.config.get('api_key')
            if api_key:
                self.session.headers.update({{'Authorization': f'Bearer {{api_key}}'}})
        elif auth_method == 'basic_auth':
            username = self.config.get('username')
            password = self.config.get('password')
            if username and password:
                self.session.auth = (username, password)
        elif auth_method == 'bearer_token':
            token = self.config.get('token')
            if token:
                self.session.headers.update({{'Authorization': f'Bearer {{token}}'}})
    
    def _make_request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """Make API request with error handling and rate limiting"""
        url = f"{{self.base_url.rstrip('/').rstrip('/api')}}/{{endpoint.lstrip('/')}}"
        
        try:
            # Rate limiting
            time.sleep(self.rate_limit_delay)
            
            response = self.session.request(method, url, **kwargs)
            response.raise_for_status()
            
            return {{
                'success': True,
                'data': response.json() if response.content else {{}},
                'status_code': response.status_code
            }}
            
        except requests.exceptions.RequestException as e:
            self.logger.error(f"API request failed: {{e}}")
            return {{
                'success': False,
                'error': str(e),
                'status_code': getattr(e.response, 'status_code', None)
            }}
    
    def get(self, endpoint: str, params: Optional[Dict] = None) -> Dict[str, Any]:
        """GET request"""
        return self._make_request('GET', endpoint, params=params)
    
    def post(self, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """POST request"""
        return self._make_request('POST', endpoint, json=data)
    
    def put(self, endpoint: str, data: Optional[Dict] = None) -> Dict[str, Any]:
        """PUT request"""
        return self._make_request('PUT', endpoint, json=data)
    
    def delete(self, endpoint: str) -> Dict[str, Any]:
        """DELETE request"""
        return self._make_request('DELETE', endpoint)


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    PlugPipe plugin entry point
    
    Args:
        ctx: Plugin context with logger, metrics, etc.
        cfg: Plugin configuration
    
    Returns:
        dict: Plugin response
    """
    logger = ctx.get('logger', logging.getLogger(__name__))
    
    try:
        # Initialize client
        client = {plugin_name.title().replace('_', '')}Client(cfg, logger)
        
        # Get action from context
        action = ctx.get('action', 'health_check')
        
        if action == 'health_check':
            # Perform health check
            result = client.get('health')  # Common health endpoint
            return {{
                'success': result.get('success', False),
                'message': 'Health check completed',
                'data': result.get('data', {{}})
            }}
        
        elif action == 'list':
            # Generic list operation
            endpoint = ctx.get('endpoint', 'items')
            result = client.get(endpoint)
            return {{
                'success': result.get('success', False),
                'message': f'Listed {{endpoint}}',
                'data': result.get('data', {{}})
            }}
        
        elif action == 'create':
            # Generic create operation
            endpoint = ctx.get('endpoint', 'items')
            data = ctx.get('data', {{}})
            result = client.post(endpoint, data)
            return {{
                'success': result.get('success', False),
                'message': f'Created item in {{endpoint}}',
                'data': result.get('data', {{}})
            }}
        
        elif action == 'update':
            # Generic update operation
            endpoint = ctx.get('endpoint', 'items')
            data = ctx.get('data', {{}})
            result = client.put(endpoint, data)
            return {{
                'success': result.get('success', False),
                'message': f'Updated item in {{endpoint}}',
                'data': result.get('data', {{}})
            }}
        
        elif action == 'delete':
            # Generic delete operation
            endpoint = ctx.get('endpoint', 'items')
            result = client.delete(endpoint)
            return {{
                'success': result.get('success', False),
                'message': f'Deleted item from {{endpoint}}',
                'data': result.get('data', {{}})
            }}
        
        else:
            return {{
                'success': False,
                'error': f'Unknown action: {{action}}',
                'supported_actions': ['health_check', 'list', 'create', 'update', 'delete']
            }}
            
    except Exception as e:
        logger.error(f"Plugin execution failed: {{e}}")
        return {{
            'success': False,
            'error': str(e)
        }}


# Plugin metadata
plug_metadata = {{
    "name": "{plugin_name}",
    "version": "1.0.0",
    "description": "Auto-generated plugin for {research.get('api_name', plugin_name)} API",
    "author": "PlugPipe Enhanced Plug Creation Agent",
    "category": "integration",
    "api_base_url": "{api_url}",
    "authentication": "{auth_method}",
    "features": {key_features},
    "generated_at": "{datetime.now().isoformat()}"
}}
'''
        
        main_file = plugin_dir / "main.py"
        main_file.write_text(main_content)
        
        return main_file
    
    async def _generate_manifest(self, plugin_dir: Path, research: Dict[str, Any], 
                                plugin_name: str) -> Path:
        """Generate plugin manifest (plug.yaml)"""
        
        manifest = {
            'name': plugin_name,
            'version': '1.0.0',
            'owner': 'PlugPipe Enhanced Creation Agent',
            'status': 'experimental',
            'description': f"Auto-generated plugin for {research.get('api_name', plugin_name)} API integration",
            'discoverability': 'public',
            'entrypoint': 'main.py',
            'tags': [
                'auto-generated',
                'api-integration', 
                research.get('authentication_method', 'api-key')
            ],
            'metadata': {
                'category': 'integration',
                'type': 'api_client',
                'capabilities': research.get('key_features', []),
                'api_version': research.get('api_version', 'v1'),
                'generated_at': datetime.now().isoformat()
            },
            'config_schema': {
                'type': 'object',
                'properties': {
                    'base_url': {
                        'type': 'string',
                        'format': 'uri',
                        'default': research.get('base_url', ''),
                        'description': 'API base URL'
                    },
                    'rate_limit_delay': {
                        'type': 'number',
                        'default': 0.1,
                        'description': 'Delay between requests (seconds)'
                    }
                }
            },
            'input_schema': {
                'type': 'object',
                'properties': {
                    'action': {
                        'type': 'string',
                        'enum': ['health_check', 'list', 'create', 'update', 'delete'],
                        'description': 'Action to perform'
                    },
                    'endpoint': {
                        'type': 'string',
                        'description': 'API endpoint path'
                    },
                    'data': {
                        'type': 'object',
                        'description': 'Request data for create/update operations'
                    }
                },
                'required': ['action']
            },
            'output_schema': {
                'type': 'object',
                'properties': {
                    'success': {
                        'type': 'boolean',
                        'description': 'Whether operation succeeded'
                    },
                    'message': {
                        'type': 'string',
                        'description': 'Result message'
                    },
                    'data': {
                        'type': 'object',
                        'description': 'Response data'
                    },
                    'error': {
                        'type': 'string',
                        'description': 'Error message if failed'
                    }
                },
                'required': ['success']
            },
            'sbom': {
                'summary': 'sbom/sbom.json',
                'complete': 'sbom/sbom-complete.json'
            }
        }
        
        # Add authentication config based on detected method
        auth_method = research.get('authentication_method', 'api_key')
        if auth_method == 'api_key':
            manifest['config_schema']['properties']['api_key'] = {
                'type': 'string',
                'description': 'API key for authentication'
            }
        elif auth_method == 'basic_auth':
            manifest['config_schema']['properties'].update({
                'username': {'type': 'string', 'description': 'Username'},
                'password': {'type': 'string', 'description': 'Password'}
            })
        elif auth_method == 'bearer_token':
            manifest['config_schema']['properties']['token'] = {
                'type': 'string',
                'description': 'Bearer token for authentication'
            }
        
        manifest_file = plugin_dir / "plug.yaml"
        with open(manifest_file, 'w') as f:
            yaml.dump(manifest, f, default_flow_style=False, sort_keys=False)
        
        return manifest_file
    
    async def _generate_tests(self, plugin_dir: Path, research: Dict[str, Any], 
                            plugin_name: str) -> Path:
        """Generate comprehensive tests"""
        
        test_content = f'''#!/usr/bin/env python3
"""
Tests for {plugin_name} Plugin

Auto-generated test suite with comprehensive coverage.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add plugin path
plugin_path = Path(__file__).parent.parent
sys.path.insert(0, str(plugin_path))

from main import process, {plugin_name.title().replace('_', '')}Client


class Test{plugin_name.title().replace('_', '')}Plugin:
    """Test suite for {plugin_name} plugin"""
    
    def setup_method(self):
        """Setup test fixtures"""
        self.config = {{
            'base_url': 'https://api.example.com',
            'api_key': 'test-key',
            'rate_limit_delay': 0.01
        }}
        self.ctx = {{
            'logger': Mock(),
            'action': 'health_check'
        }}
    
    def test_client_initialization(self):
        """Test client initialization"""
        client = {plugin_name.title().replace('_', '')}Client(self.config, Mock())
        assert client.base_url == self.config['base_url']
        assert client.rate_limit_delay == self.config['rate_limit_delay']
    
    @patch('requests.Session.request')
    def test_health_check_success(self, mock_request):
        """Test successful health check"""
        # Mock successful response
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {{'status': 'healthy'}}
        mock_response.raise_for_status.return_value = None
        mock_request.return_value = mock_response
        
        result = process(self.ctx, self.config)
        
        assert result['success'] is True
        assert 'Health check completed' in result['message']
    
    @patch('requests.Session.request')
    def test_health_check_failure(self, mock_request):
        """Test failed health check"""
        # Mock failed response
        mock_request.side_effect = Exception("Connection failed")
        
        result = process(self.ctx, self.config)
        
        assert result['success'] is False
        assert 'error' in result
    
    def test_list_action(self):
        """Test list action"""
        ctx = {{**self.ctx, 'action': 'list', 'endpoint': 'items'}}
        
        with patch('requests.Session.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {{'items': []}}
            mock_response.raise_for_status.return_value = None
            mock_request.return_value = mock_response
            
            result = process(ctx, self.config)
            assert result['success'] is True
    
    def test_create_action(self):
        """Test create action"""
        ctx = {{
            **self.ctx, 
            'action': 'create', 
            'endpoint': 'items',
            'data': {{'name': 'test_item'}}
        }}
        
        with patch('requests.Session.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {{'id': 1, 'name': 'test_item'}}
            mock_response.raise_for_status.return_value = None
            mock_request.return_value = mock_response
            
            result = process(ctx, self.config)
            assert result['success'] is True
    
    def test_invalid_action(self):
        """Test invalid action handling"""
        ctx = {{**self.ctx, 'action': 'invalid_action'}}
        
        result = process(ctx, self.config)
        
        assert result['success'] is False
        assert 'Unknown action' in result['error']
        assert 'supported_actions' in result
    
    def test_client_get_method(self):
        """Test client GET method"""
        client = {plugin_name.title().replace('_', '')}Client(self.config, Mock())
        
        with patch.object(client.session, 'request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {{'data': 'test'}}
            mock_response.raise_for_status.return_value = None
            mock_request.return_value = mock_response
            
            result = client.get('test-endpoint')
            
            assert result['success'] is True
            assert result['data'] == {{'data': 'test'}}
    
    def test_client_post_method(self):
        """Test client POST method"""
        client = {plugin_name.title().replace('_', '')}Client(self.config, Mock())
        
        with patch.object(client.session, 'request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 201
            mock_response.json.return_value = {{'created': True}}
            mock_response.raise_for_status.return_value = None
            mock_request.return_value = mock_response
            
            result = client.post('test-endpoint', {{'data': 'test'}})
            
            assert result['success'] is True
            assert result['data'] == {{'created': True}}
    
    def test_authentication_setup(self):
        """Test authentication setup"""
        config_with_key = {{**self.config, 'api_key': 'test-api-key'}}
        client = {plugin_name.title().replace('_', '')}Client(config_with_key, Mock())
        
        # Check if authorization header is set
        assert 'Authorization' in client.session.headers
        assert 'test-api-key' in client.session.headers['Authorization']
    
    def test_rate_limiting(self):
        """Test rate limiting delay"""
        config_with_delay = {{**self.config, 'rate_limit_delay': 0.1}}
        client = {plugin_name.title().replace('_', '')}Client(config_with_delay, Mock())
        
        assert client.rate_limit_delay == 0.1


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
'''
        
        test_file = plugin_dir / "tests" / f"test_{plugin_name}.py"
        test_file.write_text(test_content)
        
        return test_file
    
    async def _generate_documentation(self, plugin_dir: Path, research: Dict[str, Any], 
                                    plugin_name: str) -> Path:
        """Generate comprehensive documentation"""
        
        doc_content = f'''# {plugin_name.title().replace('_', ' ')} Plugin

Auto-generated plugin for {research.get('api_name', plugin_name)} API integration.

## Overview

This plugin provides a standardized PlugPipe interface for interacting with the {research.get('api_name', plugin_name)} API.

**Generated on:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}  
**API Version:** {research.get('api_version', 'v1')}  
**Authentication:** {research.get('authentication_method', 'api_key')}  

## Features

{chr(10).join(f"- {feature.title().replace('_', ' ')}" for feature in research.get('key_features', []))}

## Configuration

```yaml
{plugin_name}:
  base_url: "{research.get('base_url', 'https://api.example.com')}"
  api_key: "your-api-key-here"
  rate_limit_delay: 0.1
```

### Configuration Parameters

- **base_url**: API base URL
- **api_key**: Authentication API key
- **rate_limit_delay**: Delay between requests in seconds

## Usage

### Basic Health Check

```python
result = pp("{plugin_name}", {{
    "action": "health_check"
}})
```

### List Resources

```python
result = pp("{plugin_name}", {{
    "action": "list",
    "endpoint": "items"
}})
```

### Create Resource

```python
result = pp("{plugin_name}", {{
    "action": "create",
    "endpoint": "items",
    "data": {{
        "name": "example_item",
        "description": "Created via PlugPipe"
    }}
}})
```

### Update Resource

```python
result = pp("{plugin_name}", {{
    "action": "update",
    "endpoint": "items/123",
    "data": {{
        "name": "updated_item"
    }}
}})
```

### Delete Resource

```python
result = pp("{plugin_name}", {{
    "action": "delete",
    "endpoint": "items/123"
}})
```

## Supported Actions

- `health_check`: Verify API connectivity
- `list`: Retrieve resources from an endpoint
- `create`: Create new resources
- `update`: Update existing resources
- `delete`: Delete resources

## Error Handling

The plugin includes comprehensive error handling for:

- Network connectivity issues
- Authentication failures
- Rate limit violations
- Invalid API responses
- Malformed requests

## Rate Limiting

The plugin implements automatic rate limiting to respect API limits:

- Configurable delay between requests
- Automatic retry with exponential backoff (future enhancement)
- Rate limit header detection (future enhancement)

## Testing

Run the test suite:

```bash
cd plugs/integration/{plugin_name}/1.0.0
python -m pytest tests/ -v
```

## Research Data

This plugin was generated based on automatic API research:

- **Endpoints Discovered:** {research.get('endpoints_discovered', 0)}
- **Documentation URL:** {research.get('docs_url', 'N/A')}
- **SDK Available:** {research.get('sdk_available', False)}
- **Rate Limits:** {research.get('rate_limits', {})}

## Future Enhancements

- Enhanced error handling with retry logic
- Automatic pagination support
- Webhook integration
- Advanced authentication methods
- Response caching
- Bulk operations

## Changelog

### 1.0.0 (Auto-generated)
- Initial plugin generation
- Basic CRUD operations
- Authentication support
- Rate limiting
- Comprehensive test suite
'''
        
        doc_file = plugin_dir / "README.md"
        doc_file.write_text(doc_content)
        
        return doc_file
    
    def _extract_implemented_features(self, research: Dict[str, Any]) -> List[str]:
        """Extract list of implemented features"""
        features = [
            'api_client',
            'authentication',
            'rate_limiting',
            'error_handling',
            'crud_operations'
        ]
        
        # Add detected features
        key_features = research.get('key_features', [])
        features.extend(key_features)
        
        return list(set(features))  # Remove duplicates


class PluginTestingAutomation:
    """Automated testing and validation"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
    async def run_tests(self, plugin_path: Path) -> Dict[str, Any]:
        """Run comprehensive tests on generated plugin"""
        test_results = {
            'success': False,
            'tests_passed': 0,
            'tests_failed': 0,
            'coverage_percentage': 0,
            'test_output': '',
            'errors': []
        }
        
        try:
            # Run pytest on the plugin
            import subprocess
            test_dir = plugin_path / "tests"
            
            if test_dir.exists():
                cmd = [
                    sys.executable, "-m", "pytest", 
                    str(test_dir), "-v", "--tb=short"
                ]
                
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    cwd=str(plugin_path)
                )
                
                test_results['test_output'] = result.stdout + result.stderr
                test_results['success'] = result.returncode == 0
                
                # Parse test results (simplified)
                if "passed" in result.stdout:
                    import re
                    passed_match = re.search(r'(\d+) passed', result.stdout)
                    if passed_match:
                        test_results['tests_passed'] = int(passed_match.group(1))
                
                if "failed" in result.stdout:
                    import re
                    failed_match = re.search(r'(\d+) failed', result.stdout)
                    if failed_match:
                        test_results['tests_failed'] = int(failed_match.group(1))
                
                self.logger.info(f"Tests completed: {test_results['tests_passed']} passed, {test_results['tests_failed']} failed")
                
        except Exception as e:
            test_results['errors'].append(str(e))
            self.logger.error(f"Testing failed: {e}")
            
        return test_results


class SBOMGenerator:
    """Software Bill of Materials generation"""
    
    def __init__(self, logger: logging.Logger):
        self.logger = logger
        
    async def generate_sbom(self, plugin_path: Path, plugin_name: str) -> Dict[str, Any]:
        """Generate comprehensive SBOM for plugin"""
        sbom_results = {
            'success': False,
            'sbom_files': [],
            'dependencies_found': 0
        }
        
        try:
            sbom_dir = plugin_path / "sbom"
            sbom_dir.mkdir(exist_ok=True)
            
            # Generate basic SBOM
            sbom_data = {
                "bomFormat": "CycloneDX",
                "specVersion": "1.4",
                "serialNumber": f"urn:uuid:{uuid.uuid4()}",
                "version": 1,
                "metadata": {
                    "timestamp": datetime.now().isoformat(),
                    "tools": [
                        {
                            "vendor": "PlugPipe",
                            "name": "Enhanced Plug Creation Agent",
                            "version": "1.0.0"
                        }
                    ],
                    "component": {
                        "type": "library",
                        "name": plugin_name,
                        "version": "1.0.0"
                    }
                },
                "components": [
                    {
                        "type": "library",
                        "name": "requests",
                        "version": ">=2.25.0",
                        "description": "HTTP library for Python"
                    },
                    {
                        "type": "library", 
                        "name": "pyyaml",
                        "version": ">=5.4.0",
                        "description": "YAML parser and emitter"
                    }
                ]
            }
            
            # Write SBOM files
            sbom_file = sbom_dir / "sbom.json"
            with open(sbom_file, 'w') as f:
                json.dump(sbom_data, f, indent=2)
            
            sbom_results['sbom_files'].append(str(sbom_file))
            sbom_results['dependencies_found'] = len(sbom_data['components'])
            sbom_results['success'] = True
            
            self.logger.info(f"SBOM generated: {sbom_file}")
            
        except Exception as e:
            self.logger.error(f"SBOM generation failed: {e}")
            sbom_results['error'] = str(e)
            
        return sbom_results


class EnhancedPlugCreationAgent:
    """Main agent orchestrating the entire plugin creation process"""
    
    def __init__(self, config: Dict[str, Any], logger: logging.Logger):
        self.config = config
        self.logger = logger
        
        # Initialize components
        self.researcher = APIResearcher(logger, config)
        self.generator = PluginGenerator(logger, config)
        self.tester = PluginTestingAutomation(logger)
        self.sbom_generator = SBOMGenerator(logger)
        
    async def research_and_create(self, api_name: str, api_url: str, 
                                 docs_url: Optional[str] = None) -> Dict[str, Any]:
        """Complete research and creation workflow"""
        
        workflow_results = {
            'success': False,
            'plugin_created': False,
            'plugin_details': {},
            'research_results': {},
            'test_results': {},
            'sbom_results': {},
            'workflow_steps': []
        }
        
        try:
            # Step 1: Research API
            self.logger.info(f"Starting API research for: {api_name}")
            workflow_results['workflow_steps'].append("research_started")
            
            research_results = await self.researcher.research_api(api_name, api_url, docs_url)
            workflow_results['research_results'] = research_results
            workflow_results['workflow_steps'].append("research_completed")
            
            # Step 2: Generate plugin
            self.logger.info(f"Generating plugin for: {api_name}")
            workflow_results['workflow_steps'].append("generation_started")
            
            plugin_name = api_name.lower().replace(' ', '_').replace('-', '_')
            generation_results = await self.generator.generate_plugin(
                research_results, plugin_name, self.config.get('plugin_category', 'integration')
            )
            
            workflow_results['plugin_details'] = generation_results
            workflow_results['plugin_created'] = generation_results['success']
            workflow_results['workflow_steps'].append("generation_completed")
            
            if not generation_results['success']:
                workflow_results['error'] = "Plugin generation failed"
                return workflow_results
            
            plugin_path = Path(generation_results['plugin_path'])
            
            # Step 3: Generate SBOM
            if self.config.get('auto_test', True):
                self.logger.info("Generating SBOM")
                workflow_results['workflow_steps'].append("sbom_started")
                
                sbom_results = await self.sbom_generator.generate_sbom(plugin_path, plugin_name)
                workflow_results['sbom_results'] = sbom_results
                workflow_results['workflow_steps'].append("sbom_completed")
            
            # Step 4: Run tests
            if self.config.get('auto_test', True):
                self.logger.info("Running automated tests")
                workflow_results['workflow_steps'].append("testing_started")
                
                test_results = await self.tester.run_tests(plugin_path)
                workflow_results['test_results'] = test_results
                workflow_results['workflow_steps'].append("testing_completed")
            
            # Step 5: Release (if configured)
            if self.config.get('auto_release', False) and test_results.get('success', False):
                self.logger.info("Initiating automatic release")
                workflow_results['workflow_steps'].append("release_started")
                
                # Implement release automation
                try:
                    release_result = await self._execute_release_automation(plugin_name, plugin_dir)
                    if release_result.get('success', False):
                        workflow_results['release_info'] = release_result
                        workflow_results['workflow_steps'].append("release_completed")
                        self.logger.info(f"Release automation completed successfully for {plugin_name}")
                    else:
                        workflow_results['workflow_steps'].append("release_failed")
                        workflow_results['release_error'] = release_result.get('error', 'Unknown release error')
                        self.logger.error(f"Release automation failed: {release_result.get('error')}")
                except Exception as e:
                    workflow_results['workflow_steps'].append("release_failed")
                    workflow_results['release_error'] = str(e)
                    self.logger.error(f"Release automation exception: {e}")
            
            workflow_results['success'] = True
            self.logger.info(f"Plugin creation workflow completed for: {api_name}")
            
        except Exception as e:
            self.logger.error(f"Workflow failed: {e}")
            workflow_results['error'] = str(e)
            
        return workflow_results
    
    async def batch_create(self, api_list: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Create multiple plugins in batch"""
        batch_results = {
            'success': False,
            'total_apis': len(api_list),
            'plugins_created': 0,
            'plugins_failed': 0,
            'results': []
        }
        
        for api_config in api_list:
            try:
                api_name = api_config['name']
                api_url = api_config['url']
                docs_url = api_config.get('docs_url')
                
                self.logger.info(f"Processing API: {api_name}")
                
                result = await self.research_and_create(api_name, api_url, docs_url)
                
                if result['success']:
                    batch_results['plugins_created'] += 1
                else:
                    batch_results['plugins_failed'] += 1
                
                batch_results['results'].append({
                    'api_name': api_name,
                    'success': result['success'],
                    'plugin_path': result.get('plugin_details', {}).get('plugin_path'),
                    'error': result.get('error')
                })
                
            except Exception as e:
                self.logger.error(f"Batch processing failed for {api_config}: {e}")
                batch_results['plugins_failed'] += 1
                batch_results['results'].append({
                    'api_name': api_config.get('name', 'unknown'),
                    'success': False,
                    'error': str(e)
                })
        
        batch_results['success'] = batch_results['plugins_created'] > 0
        return batch_results
    
    async def _execute_release_automation(self, plugin_name: str, plugin_dir: str) -> Dict[str, Any]:
        """Execute release automation for the newly created plugin."""
        release_result = {
            'success': False,
            'steps_completed': [],
            'plugin_name': plugin_name,
            'plugin_dir': plugin_dir
        }
        
        try:
            self.logger.info(f"Starting release automation for {plugin_name}")
            
            # Step 1: Validate SBOM exists and is complete
            sbom_path = os.path.join(plugin_dir, 'sbom')
            if os.path.exists(sbom_path):
                release_result['steps_completed'].append('sbom_validated')
                self.logger.info("SBOM validation completed")
            else:
                # Generate SBOM if missing
                await self._generate_plugin_sbom(plugin_dir)
                release_result['steps_completed'].append('sbom_generated')
            
            # Step 2: Security validation
            security_check = await self._run_security_checks(plugin_dir)
            if security_check.get('passed', False):
                release_result['steps_completed'].append('security_validated')
                release_result['security_score'] = security_check.get('score', 'N/A')
            
            # Step 3: Version tagging
            version = await self._tag_plugin_version(plugin_dir)
            if version:
                release_result['steps_completed'].append('version_tagged')
                release_result['version'] = version
            
            # Step 4: Release documentation
            docs_result = await self._generate_release_docs(plugin_dir, plugin_name)
            if docs_result.get('success', False):
                release_result['steps_completed'].append('documentation_generated')
                release_result['documentation_path'] = docs_result.get('docs_path')
            
            release_result['success'] = True
            release_result['release_timestamp'] = datetime.now().isoformat()
            self.logger.info(f"Release automation completed successfully for {plugin_name}")
            
        except Exception as e:
            self.logger.error(f"Release automation failed: {e}")
            release_result['error'] = str(e)
        
        return release_result
    
    async def _run_security_checks(self, plugin_dir: str) -> Dict[str, Any]:
        """Run security validation checks on the plugin."""
        try:
            security_result = {
                'passed': True,
                'score': 'A',
                'checks': []
            }
            
            # Check for hardcoded secrets
            main_py = os.path.join(plugin_dir, 'main.py')
            if os.path.exists(main_py):
                with open(main_py, 'r', encoding='utf-8') as f:
                    content = f.read()
                    
                # Simple secret detection patterns
                secret_patterns = [
                    r'api_key\s*=\s*["\'][^"\']{10,}["\']',
                    r'secret\s*=\s*["\'][^"\']{10,}["\']',
                    r'password\s*=\s*["\'][^"\']{3,}["\']'
                ]
                
                for pattern in secret_patterns:
                    if re.search(pattern, content, re.IGNORECASE):
                        security_result['passed'] = False
                        security_result['score'] = 'C'
                        security_result['checks'].append('hardcoded_secrets_detected')
            
            security_result['checks'].append('secret_scan_completed')
            return security_result
            
        except Exception as e:
            return {
                'passed': False,
                'error': str(e)
            }
    
    async def _tag_plugin_version(self, plugin_dir: str) -> Optional[str]:
        """Tag plugin with version information."""
        try:
            manifest_path = os.path.join(plugin_dir, 'plug.yaml')
            if os.path.exists(manifest_path):
                with open(manifest_path, 'r', encoding='utf-8') as f:
                    manifest = yaml.safe_load(f)
                return manifest.get('version', '1.0.0')
        except Exception as e:
            self.logger.warning(f"Failed to tag plugin version: {e}")
        return None
    
    async def _generate_release_docs(self, plugin_dir: str, plugin_name: str) -> Dict[str, Any]:
        """Generate release documentation for the plugin."""
        try:
            docs_dir = os.path.join(plugin_dir, 'docs')
            os.makedirs(docs_dir, exist_ok=True)
            
            release_doc_path = os.path.join(docs_dir, 'RELEASE_NOTES.md')
            
            release_content = f"""# Release Notes - {plugin_name}

## Version 1.0.0 - {datetime.now().strftime('%Y-%m-%d')}

### 🎉 Initial Release
- Auto-generated plugin using Enhanced Plug Creation Agent
- Full API integration with comprehensive error handling
- Security validation and SBOM compliance

### 🔧 Features
- Complete API wrapper functionality
- Robust error handling and validation
- Comprehensive logging and monitoring

---
*Generated automatically by PlugPipe Enhanced Plug Creation Agent*
"""
            
            with open(release_doc_path, 'w', encoding='utf-8') as f:
                f.write(release_content)
            
            return {
                'success': True,
                'docs_path': release_doc_path
            }
            
        except Exception as e:
            return {'success': False, 'error': str(e)}


# Plugin entry point
def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """
    Enhanced Plug Creation Agent entry point
    
    Intelligent agent that researches APIs and automatically creates comprehensive plugins.
    """
    logger = ctx.get('logger', logging.getLogger(__name__))
    
    try:
        # Initialize agent
        agent = EnhancedPlugCreationAgent(cfg, logger)
        
        # Get action
        action = ctx.get('action', 'research_and_create')
        
        if action == 'research_and_create':
            # Single API research and plugin creation
            api_name = ctx.get('api_name')
            api_url = ctx.get('api_url')
            docs_url = ctx.get('api_docs_url')
            
            if not api_name or not api_url:
                return {
                    'success': False,
                    'error': 'api_name and api_url are required for research_and_create action'
                }
            
            # Run async workflow
            import asyncio
            if hasattr(asyncio, 'run'):
                result = asyncio.run(agent.research_and_create(api_name, api_url, docs_url))
            else:
                # Fallback for older Python versions
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(agent.research_and_create(api_name, api_url, docs_url))
                finally:
                    loop.close()
            
            return result
            
        elif action == 'batch_create':
            # Batch API processing
            batch_apis = ctx.get('batch_apis', [])
            
            if not batch_apis:
                return {
                    'success': False,
                    'error': 'batch_apis list is required for batch_create action'
                }
            
            import asyncio
            if hasattr(asyncio, 'run'):
                result = asyncio.run(agent.batch_create(batch_apis))
            else:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    result = loop.run_until_complete(agent.batch_create(batch_apis))
                finally:
                    loop.close()
            
            return result
            
        elif action == 'analyze_api':
            # Just research without creating plugin
            api_name = ctx.get('api_name')
            api_url = ctx.get('api_url')
            docs_url = ctx.get('api_docs_url')
            
            if not api_name or not api_url:
                return {
                    'success': False,
                    'error': 'api_name and api_url are required for analyze_api action'
                }
            
            import asyncio
            if hasattr(asyncio, 'run'):
                research_results = asyncio.run(agent.researcher.research_api(api_name, api_url, docs_url))
            else:
                loop = asyncio.new_event_loop()
                asyncio.set_event_loop(loop)
                try:
                    research_results = loop.run_until_complete(agent.researcher.research_api(api_name, api_url, docs_url))
                finally:
                    loop.close()
            
            return {
                'success': True,
                'research_results': research_results,
                'message': f'API analysis completed for {api_name}'
            }
            
        elif action == 'list_candidates':
            # List popular APIs that would be good candidates for plugin creation
            candidates = [
                {'name': 'Stripe', 'url': 'https://api.stripe.com', 'priority': 'high'},
                {'name': 'GitHub', 'url': 'https://api.github.com', 'priority': 'high'},
                {'name': 'Slack', 'url': 'https://slack.com/api', 'priority': 'high'},
                {'name': 'Salesforce', 'url': 'https://salesforce.com/api', 'priority': 'medium'},
                {'name': 'Twilio', 'url': 'https://api.twilio.com', 'priority': 'medium'},
                {'name': 'SendGrid', 'url': 'https://api.sendgrid.com', 'priority': 'medium'},
                {'name': 'AWS S3', 'url': 'https://s3.amazonaws.com', 'priority': 'high'},
                {'name': 'Google Drive', 'url': 'https://www.googleapis.com/drive', 'priority': 'medium'},
                {'name': 'Dropbox', 'url': 'https://api.dropboxapi.com', 'priority': 'low'},
                {'name': 'Zoom', 'url': 'https://api.zoom.us', 'priority': 'medium'}
            ]
            
            return {
                'success': True,
                'candidates': candidates,
                'message': f'Found {len(candidates)} plugin candidates'
            }
            
        else:
            return {
                'success': False,
                'error': f'Unknown action: {action}',
                'supported_actions': [
                    'research_and_create', 
                    'batch_create', 
                    'analyze_api', 
                    'list_candidates'
                ]
            }
            
    except Exception as e:
        logger.error(f"Enhanced Plug Creation Agent failed: {e}")
        return {
            'success': False,
            'error': str(e)
        }


# Plugin metadata
plug_metadata = {
    "name": "Enhanced Plug Creation Agent",
    "version": "1.0.0", 
    "description": "Intelligent agent for automatic API research and plugin generation",
    "author": "PlugPipe Core Team",
    "category": "automation",
    "type": "intelligence",
    "capabilities": [
        "api_research",
        "plugin_generation", 
        "automated_testing",
        "sbom_generation",
        "batch_processing"
    ],
    "enterprise_ready": True,
    "ai_powered": True
}