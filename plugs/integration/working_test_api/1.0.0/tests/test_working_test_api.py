#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Tests for working_test_api Plugin

Auto-generated test suite with comprehensive coverage.
"""

import pytest
import sys
from pathlib import Path
from unittest.mock import Mock, patch

# Add plugin path
plugin_path = Path(__file__).parent.parent
sys.path.insert(0, str(plugin_path))

from main import process


class TestWorkingTestApiPlugin:
    """Test suite for working_test_api plugin"""

    def setup_method(self):
        """Setup test fixtures"""
        self.config = {
            'base_url': 'https://jsonplaceholder.typicode.com',
            'api_key': 'test-key',
            'rate_limit_delay': 0.01
        }
        self.ctx = {
            'logger': Mock(),
            'operation': 'health_check'
        }

    def test_plugin_health_check(self):
        """Test plugin health check"""
        with patch('requests.Session.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = {'status': 'ok'}
            mock_response.raise_for_status.return_value = None
            mock_request.return_value = mock_response

            result = process(self.ctx, {'operation': 'health_check'})

            assert result['status'] == 'success'
            assert result['plugin_type'] == 'real_generated_plugin'

    def test_plugin_list_operation(self):
        """Test plugin list operation"""
        with patch('requests.Session.request') as mock_request:
            mock_response = Mock()
            mock_response.status_code = 200
            mock_response.json.return_value = [
                {'id': 1, 'name': 'item1'},
                {'id': 2, 'name': 'item2'}
            ]
            mock_response.raise_for_status.return_value = None
            mock_request.return_value = mock_response

            result = process(self.ctx, {'operation': 'list', 'endpoint': 'items'})

            assert result['status'] == 'success'
            assert result['count'] == 2
            assert 'data' in result

    def test_plugin_error_handling(self):
        """Test plugin error handling"""
        with patch('requests.Session.request') as mock_request:
            mock_request.side_effect = Exception("Connection failed")

            result = process(self.ctx, {'operation': 'health_check'})

            assert result['status'] == 'error'
            assert 'error_details' in result or 'api_status' in result

    def test_invalid_operation(self):
        """Test invalid operation handling"""
        result = process(self.ctx, {'operation': 'invalid_operation'})

        assert result['status'] == 'error'
        assert 'error' in result


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
