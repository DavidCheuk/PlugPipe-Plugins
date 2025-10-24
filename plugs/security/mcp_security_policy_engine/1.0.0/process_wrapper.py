#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Process wrapper for MCP Security Policy Engine
Provides PlugPipe-compatible process() function
"""

import json
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from main import MCPSecurityPolicyEngine

def process(input_data: str) -> str:
    """PlugPipe standard process function"""
    try:
        # Parse input
        if isinstance(input_data, str):
            data = json.loads(input_data)
        else:
            data = input_data
            
        # Get operation
        operation = data.get('operation', 'get_status')
        
        # Create policy engine with default config
        config = {
            'policy_mode': 'standard',
            'rbac_integration': True,
            'opa_integration': False,
            'user_approval_workflows': True
        }
        
        policy_engine = MCPSecurityPolicyEngine(config)
        
        # Handle operations
        if operation == 'get_status':
            return json.dumps({
                'success': True,
                'operation': operation,
                'policy_mode': policy_engine.policy_mode.value,
                'rbac_integration': policy_engine.rbac_integration,
                'opa_integration': policy_engine.opa_integration,
                'user_approval_workflows': policy_engine.user_approval_workflows
            })
            
        elif operation == 'classify_tool':
            tool_name = data.get('tool_name', '')
            classification = policy_engine._classify_tool(tool_name)
            
            return json.dumps({
                'success': True,
                'operation': operation,
                'tool_name': tool_name,
                'classification': classification.value,
                'config': policy_engine.tool_classifications[classification]
            })
            
        else:
            return json.dumps({
                'success': False,
                'operation': operation,
                'error': f'Operation "{operation}" not supported in basic mode'
            })
            
    except Exception as e:
        return json.dumps({
            'success': False,
            'error': str(e)
        })

if __name__ == "__main__":
    if len(sys.argv) > 1:
        input_data = sys.argv[1]
    else:
        input_data = sys.stdin.read()
    
    result = process(input_data)
    print(result)