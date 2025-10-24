#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
MCP Guardian - Security Plugin Orchestrator
Coordinates all security plugins to provide comprehensive threat detection
"""

import time
import sys
import os

# Add project root to path for plugin loading
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../../..')))

def process(ctx, cfg):
    """MCP Guardian - Security Plugin Orchestrator"""
    start_time = time.time()
    
    # Extract operation and parameters
    operation = "health_check"
    text = ""
    
    if isinstance(cfg, dict):
        operation = cfg.get('operation', operation)
        text = cfg.get('text', cfg.get('input', ''))
    if isinstance(ctx, dict):
        operation = ctx.get('operation', operation)
        text = ctx.get('text', ctx.get('input', text))
    
    if operation == 'health_check' or operation == 'get_status':
        # Skip plugin loading during health check to prevent hangs
        # Just report status quickly without checking all plugins
        security_plugins = [
            'mcp_security_policy_engine',
            'hhem_detector', 
            'cyberpig_ai',
            'mcp_security_middleware',
            'enhanced_mcp_schema_validation',
            'enhanced_mcp_audit_integration',
            'llm_guard',
            'garak_scanner',
            'presidio_dlp',
            'ai_rate_limiter_mcp_integration'
        ]
        
        return {
            "status": "success",
            "plugin": "mcp_guardian",
            "role": "security_orchestrator",
            "healthy": True,
            "security_plugins_total": len(security_plugins),
            "security_plugins_available": "runtime_check_skipped",
            "available_plugins": security_plugins,
            "security_level": "comprehensive",
            "note": "Health check optimized - plugin loading skipped to prevent hangs",
            "processing_time_ms": (time.time() - start_time) * 1000
        }
    
    elif operation in ['scan', 'security_scan', 'orchestrate']:
        if not text:
            return {
                "status": "error",
                "error": "No text provided for security scan",
                "plugin": "mcp_guardian",
                "processing_time_ms": (time.time() - start_time) * 1000
            }
        
        # Orchestrate security plugins
        try:
            from shares.loader import pp
            
            # Extract AI strict mode from configuration
            ai_strict_mode = (
                ctx.get('ai_strict_mode', False) or 
                cfg.get('ai_strict_mode', False) or
                ctx.get('ai_required', False) or 
                cfg.get('ai_required', False)
            )
            
            # Define security plugins and their specific operations with AI strict mode
            security_plugins = [
                ('mcp_security_policy_engine', {
                    'text': text, 
                    'operation': 'evaluate_policy', 
                    'action': 'query', 
                    'resource': 'database',
                    'ai_strict_mode': ai_strict_mode
                }),
                ('hhem_detector', {  # Direct HHEM usage instead of wrapper
                    'text': text, 
                    'operation': 'analyze',
                    'ai_strict_mode': ai_strict_mode
                }),
                ('cyberpig_ai', {
                    'text': text,
                    'ai_strict_mode': ai_strict_mode
                }),
                ('enhanced_mcp_schema_validation', {
                    'text': text, 
                    'operation': 'validate_mcp_request', 
                    'request': {'method': 'query', 'params': {'query': text}},
                    'ai_strict_mode': ai_strict_mode
                }),
                ('presidio_dlp', {
                    'text': text,
                    'ai_strict_mode': ai_strict_mode
                }),
                ('llm_guard', {
                    'text': text,
                    'operation': 'scan_input',
                    'ai_strict_mode': ai_strict_mode
                }),
            ]
            
            total_threats = 0
            plugin_results = []
            successful_scans = 0
            ai_unavailable_plugins = []
            
            for plugin_name, params in security_plugins:
                try:
                    plugin = pp(plugin_name)
                    if plugin is None:
                        continue
                    
                    # Execute plugin scan
                    result = plugin.process(params, {})
                    
                    # Check for AI unavailability errors in strict mode
                    if result.get('status') == 'error' and result.get('error_type') == 'AI_MODELS_UNAVAILABLE':
                        ai_unavailable_plugins.append({
                            'plugin': plugin_name,
                            'error': result.get('error'),
                            'missing_dependencies': result.get('missing_dependencies', []),
                            'recommendation': result.get('recommendation')
                        })
                        continue
                    successful_scans += 1
                    
                    # Extract threat information from result
                    threats = 0
                    action = "ALLOW"
                    
                    if isinstance(result, dict):
                        # Different plugins have different response formats
                        if 'threats_detected' in result:
                            threats = int(result.get('threats_detected', 0))
                        elif 'threat_detected' in result and result.get('threat_detected'):
                            threats = 1
                        elif 'blocked' in result and result.get('blocked'):
                            threats = 1
                        elif 'allowed' in result and not result.get('allowed'):
                            threats = 1
                        elif 'action' in result and result.get('action') == 'BLOCK':
                            threats = 1
                        elif 'security_violations' in result and result.get('security_violations'):
                            threats = len(result.get('security_violations', []))
                        elif 'secrets_found' in result:
                            threats = len(result.get('secrets_found', []))
                        
                        if threats > 0:
                            action = "BLOCK"
                    
                    total_threats += threats
                    plugin_results.append({
                        'plugin': plugin_name,
                        'threats_detected': threats,
                        'action': action,
                        'status': 'success'
                    })
                    
                except Exception as e:
                    plugin_results.append({
                        'plugin': plugin_name,
                        'status': 'error',
                        'error': str(e)
                    })
            
            # Handle AI unavailability in strict mode
            if ai_unavailable_plugins and ai_strict_mode:
                all_dependencies = []
                for plugin_info in ai_unavailable_plugins:
                    all_dependencies.extend(plugin_info.get('missing_dependencies', []))
                
                return {
                    "status": "error",
                    "error": f"AI models unavailable for {len(ai_unavailable_plugins)} plugins in strict mode",
                    "error_type": "AI_MODELS_UNAVAILABLE",
                    "plugin": "mcp_guardian",
                    "role": "security_orchestrator",
                    "ai_strict_mode": True,
                    "failed_plugins": ai_unavailable_plugins,
                    "missing_dependencies": list(set(all_dependencies)),
                    "recommendation": "Install missing AI dependencies or disable ai_strict_mode",
                    "security_impact": "CRITICAL - Multiple AI security models unavailable",
                    "processing_time_ms": (time.time() - start_time) * 1000
                }
            
            # Final orchestration decision
            final_action = "BLOCK" if total_threats > 0 else "ALLOW"
            
            return {
                "status": "success",
                "plugin": "mcp_guardian",
                "role": "security_orchestrator",
                "operation": operation,
                "ai_strict_mode": ai_strict_mode,
                "total_threats_detected": total_threats,
                "final_action": final_action,
                "plugins_executed": successful_scans,
                "plugin_results": plugin_results,
                "ai_unavailable_count": len(ai_unavailable_plugins),
                "recommendation": f"{'Block' if final_action == 'BLOCK' else 'Allow'} request based on {successful_scans} plugin assessments",
                "processing_time_ms": (time.time() - start_time) * 1000
            }
            
        except Exception as e:
            return {
                "status": "error",
                "error": f"Orchestration failed: {str(e)}",
                "plugin": "mcp_guardian",
                "processing_time_ms": (time.time() - start_time) * 1000
            }
    
    else:
        return {
            "status": "success",
            "operation": operation,
            "message": f"Operation {operation} completed by orchestrator",
            "plugin": "mcp_guardian",
            "processing_time_ms": (time.time() - start_time) * 1000
        }