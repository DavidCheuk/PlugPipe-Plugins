#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Plugin Change Validation Pipeline
==================================

Comprehensive orchestration plugin that automatically validates plugin changes through:
1. Change detection and analysis
2. Configuration hardening validation  
3. Codebase integrity scanning
4. Business compliance auditing
5. Issue aggregation and storage

This plugin implements the Plugin Lifecycle Quality Assurance System
that triggers on ANY plugin creation or modification.
"""

import os
import sys
import json
import asyncio
from typing import Dict, Any, List, Optional
from datetime import datetime
from pathlib import Path

# Add project root to path for imports
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))))
sys.path.insert(0, PROJECT_ROOT)

try:
    from shares.loader import pp
except ImportError:
    # Fallback for standalone execution
    def pp(plugin_name):
        return None

class PluginChangeValidationPipeline:
    """
    Orchestrates comprehensive validation for any plugin changes.
    
    This pipeline ensures quality assurance by running multiple validation
    steps and aggregating issues for tracking and remediation.
    """
    
    def __init__(self):
        self.results = []
        self.issues_found = []
        self.total_score = 0
        self.validation_timestamp = datetime.utcnow()
        
    async def execute_validation_pipeline(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """
        Execute the complete validation pipeline.
        
        Steps:
        1. Detect plugin changes
        2. Run config hardening validation
        3. Execute integrity scanning
        4. Perform compliance auditing
        5. Aggregate and store issues
        """
        try:
            operation = config.get('operation', 'full_validation')
            target_plugin = config.get('target_plugin', 'all')
            change_type = config.get('change_type', 'unknown')
            
            pipeline_result = {
                'success': True,
                'pipeline_execution': {
                    'target_plugin': target_plugin,
                    'change_type': change_type,
                    'operation': operation,
                    'timestamp': self.validation_timestamp.isoformat(),
                    'steps_executed': [],
                    'total_issues': 0,
                    'critical_issues': 0,
                    'warning_issues': 0,
                    'overall_score': 100
                }
            }
            
            # Step 1: Change Detection
            if operation in ['full_validation', 'detect_changes']:
                change_detection_result = await self._execute_change_detection(context, config)
                pipeline_result['pipeline_execution']['steps_executed'].append('change_detection')
                pipeline_result['change_detection'] = change_detection_result
                self.results.append(change_detection_result)
            
            # Step 2: Configuration Hardening
            if operation in ['full_validation', 'config_validation']:
                config_hardening_result = await self._execute_config_hardening(context, config)
                pipeline_result['pipeline_execution']['steps_executed'].append('config_hardening')
                pipeline_result['config_hardening'] = config_hardening_result
                self.results.append(config_hardening_result)
            
            # Step 3: Integrity Scanning  
            if operation in ['full_validation', 'integrity_scan']:
                integrity_result = await self._execute_integrity_scanning(context, config)
                pipeline_result['pipeline_execution']['steps_executed'].append('integrity_scanning')
                pipeline_result['integrity_scanning'] = integrity_result
                self.results.append(integrity_result)
            
            # Step 4: Compliance Auditing
            if operation in ['full_validation', 'compliance_audit']:
                compliance_result = await self._execute_compliance_auditing(context, config)
                pipeline_result['pipeline_execution']['steps_executed'].append('compliance_auditing')
                pipeline_result['compliance_auditing'] = compliance_result
                self.results.append(compliance_result)
            
            # Step 5: Issue Aggregation and Storage
            if operation in ['full_validation', 'aggregate_issues']:
                aggregation_result = await self._aggregate_and_store_issues(context, config)
                pipeline_result['pipeline_execution']['steps_executed'].append('issue_aggregation')
                pipeline_result['issue_aggregation'] = aggregation_result
            
            # Calculate overall pipeline metrics
            self._calculate_pipeline_metrics(pipeline_result)
            
            return pipeline_result
            
        except Exception as e:
            return {
                'success': False,
                'error': f'Plugin validation pipeline failed: {str(e)}',
                'pipeline_execution': {
                    'timestamp': self.validation_timestamp.isoformat(),
                    'steps_executed': pipeline_result.get('pipeline_execution', {}).get('steps_executed', []),
                    'failure_point': 'pipeline_execution'
                }
            }
    
    async def _execute_change_detection(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute plugin change detection using CLI coordinator."""
        try:
            cli_coordinator = pp('cli_parameter_mapping_coordinator')
            if cli_coordinator:
                change_config = {
                    'operation': 'detect_plugin_changes',
                    'context': {
                        'plugin_changes': [config.get('target_plugin', 'all')],
                        'scan_all_plugins': config.get('scan_all_plugins', True)
                    }
                }
                result = await cli_coordinator.process(context, change_config)
                
                # Extract issues from change detection
                if result.get('success') and result.get('plugin_changes'):
                    for change in result['plugin_changes']:
                        if change.get('requires_mapping_update') or change.get('schema_changes', {}).get('breaking_changes'):
                            self.issues_found.append({
                                'category': 'plugin_changes',
                                'severity': 'high' if change.get('schema_changes', {}).get('breaking_changes') else 'medium',
                                'plugin': change.get('plugin_name'),
                                'description': f"Plugin {change.get('change_type', 'modified')} with potential breaking changes",
                                'details': change
                            })
                
                return result
            else:
                return {'success': False, 'error': 'CLI coordinator plugin not available', 'method': 'change_detection_fallback'}
                
        except Exception as e:
            return {'success': False, 'error': f'Change detection failed: {str(e)}'}
    
    async def _execute_config_hardening(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute configuration hardening validation."""
        try:
            config_hardening = pp('config_hardening')
            if config_hardening:
                hardening_config = {
                    'operation': 'validate',
                    'config_file': config.get('config_file', 'config.yaml'),
                    'environment': config.get('environment', 'production')
                }
                result = await self._safe_plugin_call(config_hardening, context, hardening_config)
                
                # Extract security findings as issues
                if result.get('success') and result.get('security_findings'):
                    for finding in result['security_findings']:
                        self.issues_found.append({
                            'category': 'security_configuration',
                            'severity': finding.get('severity', 'medium'),
                            'description': finding.get('finding'),
                            'recommendation': finding.get('recommendation'),
                            'risk': finding.get('risk'),
                            'details': finding
                        })
                
                return result
            else:
                return {'success': False, 'error': 'Config hardening plugin not available', 'method': 'config_hardening_fallback'}
                
        except Exception as e:
            return {'success': False, 'error': f'Config hardening failed: {str(e)}'}
    
    async def _execute_integrity_scanning(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute codebase integrity scanning."""
        try:
            integrity_scanner = pp('codebase_integrity_scanner')
            if integrity_scanner:
                scanner_config = {
                    'operation': 'scan',
                    'scan_directories': config.get('scan_directories', ['plugs', 'cores']),
                    'max_files': config.get('max_files', 50),
                    'scan_types': ['placeholders', 'incomplete_implementations', 'code_quality']
                }
                result = await self._safe_plugin_call(integrity_scanner, context, scanner_config)
                
                # Extract integrity issues
                if result.get('success') and result.get('integrity_issues'):
                    for issue in result['integrity_issues']:
                        self.issues_found.append({
                            'category': 'code_integrity',
                            'severity': issue.get('severity', 'medium'),
                            'file_path': issue.get('file_path'),
                            'description': issue.get('description'),
                            'fix_suggestion': issue.get('fix_suggestion'),
                            'details': issue
                        })
                
                return result
            else:
                return {'success': False, 'error': 'Integrity scanner plugin not available', 'method': 'integrity_scanner_fallback'}
                
        except Exception as e:
            return {'success': False, 'error': f'Integrity scanning failed: {str(e)}'}
    
    async def _execute_compliance_auditing(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute business compliance auditing."""
        try:
            compliance_auditor = pp('business_compliance_auditor')
            if compliance_auditor:
                audit_config = {
                    'operation': 'audit',
                    'audit_categories': config.get('audit_categories', ['security', 'code_quality', 'architecture']),
                    'config_file': config.get('config_file', 'config.yaml')
                }
                result = await self._safe_plugin_call(compliance_auditor, context, audit_config)
                
                # Extract compliance issues
                if result.get('success') and result.get('compliance_findings'):
                    for finding in result['compliance_findings']:
                        self.issues_found.append({
                            'category': 'business_compliance',
                            'severity': finding.get('severity', 'medium'),
                            'compliance_area': finding.get('area'),
                            'description': finding.get('finding'),
                            'recommendation': finding.get('recommendation'),
                            'details': finding
                        })
                
                return result
            else:
                return {'success': False, 'error': 'Compliance auditor plugin not available', 'method': 'compliance_auditor_fallback'}
                
        except Exception as e:
            return {'success': False, 'error': f'Compliance auditing failed: {str(e)}'}
    
    async def _aggregate_and_store_issues(self, context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Aggregate all issues found and store them using the issue tracker plugin."""
        try:
            # Categorize and prioritize issues
            critical_issues = [issue for issue in self.issues_found if issue.get('severity') == 'critical']
            high_issues = [issue for issue in self.issues_found if issue.get('severity') == 'high']
            medium_issues = [issue for issue in self.issues_found if issue.get('severity') == 'medium']
            low_issues = [issue for issue in self.issues_found if issue.get('severity') == 'low']
            
            issue_summary = {
                'total_issues': len(self.issues_found),
                'critical_issues': len(critical_issues),
                'high_issues': len(high_issues),
                'medium_issues': len(medium_issues),
                'low_issues': len(low_issues),
                'issues_by_category': self._categorize_issues(),
                'timestamp': self.validation_timestamp.isoformat(),
                'target_plugin': config.get('target_plugin', 'all'),
                'all_issues': self.issues_found
            }
            
            # Store issues using the issue tracker plugin
            storage_result = await self._store_issues_with_tracker(issue_summary, config)
            
            return {
                'success': True,
                'issue_summary': issue_summary,
                'storage_status': 'completed' if storage_result.get('success') else 'failed',
                'storage_details': storage_result
            }
            
        except Exception as e:
            return {'success': False, 'error': f'Issue aggregation failed: {str(e)}'}
    
    def _categorize_issues(self) -> Dict[str, int]:
        """Categorize issues by type for summary reporting."""
        categories = {}
        for issue in self.issues_found:
            category = issue.get('category', 'unknown')
            categories[category] = categories.get(category, 0) + 1
        return categories
    
    async def _store_issues_with_tracker(self, issue_summary: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
        """Store issues using the issue tracker plugin with fallback to local storage."""
        try:
            # Try to use the issue tracker plugin
            issue_tracker = pp('issue_tracker')
            if issue_tracker:
                # Prepare data for issue tracker
                tracker_config = {
                    'operation': 'store_issues',
                    'issues': {
                        'validation_run_id': f"validation_{int(self.validation_timestamp.timestamp())}",
                        'timestamp': self.validation_timestamp.isoformat(),
                        'target_plugin': config.get('target_plugin', 'all'),
                        'change_type': config.get('change_type', 'unknown'),
                        'pipeline_score': self._calculate_pipeline_score(),
                        'issues_list': self.issues_found,
                        'metadata': {
                            'validation_pipeline_version': '1.0.0',
                            'triggered_by': 'plugin_change_validation_pipeline',
                            'summary': issue_summary
                        }
                    },
                    'storage_backend': 'auto',
                    'storage_config': {
                        'local_file': {
                            'storage_path': 'validation_issues_storage.json',
                            'backup_enabled': True,
                            'max_history': 100
                        }
                    }
                }
                
                result = await self._safe_plugin_call(issue_tracker, {}, tracker_config)
                if result.get('success'):
                    return {
                        'success': True,
                        'method': 'issue_tracker_plugin',
                        'backend_used': result.get('operation_result', {}).get('storage_backend_used', 'unknown'),
                        'records_stored': result.get('operation_result', {}).get('records_affected', 0)
                    }
                else:
                    print(f"Warning: Issue tracker plugin failed: {result.get('error', 'Unknown error')}")
                    # Fall back to local storage
                    return await self._fallback_local_storage(issue_summary)
            else:
                print("Warning: Issue tracker plugin not available, using local storage fallback")
                return await self._fallback_local_storage(issue_summary)
                
        except Exception as e:
            print(f"Warning: Issue tracker storage failed: {e}")
            return await self._fallback_local_storage(issue_summary)
    
    async def _fallback_local_storage(self, issue_summary: Dict[str, Any]) -> Dict[str, Any]:
        """Fallback to local file storage when issue tracker plugin is unavailable."""
        storage_path = Path('validation_issues_storage.json')
        
        try:
            # Load existing issues if file exists
            existing_issues = []
            if storage_path.exists():
                with open(storage_path, 'r') as f:
                    existing_data = json.load(f)
                    existing_issues = existing_data.get('validation_history', [])
            
            # Add new issue summary
            existing_issues.append(issue_summary)
            
            # Keep only last 100 validation runs
            if len(existing_issues) > 100:
                existing_issues = existing_issues[-100:]
            
            # Write back to storage
            storage_data = {
                'last_updated': datetime.utcnow().isoformat(),
                'validation_history': existing_issues,
                'current_issues': issue_summary
            }
            
            with open(storage_path, 'w') as f:
                json.dump(storage_data, f, indent=2)
            
            return {
                'success': True,
                'method': 'fallback_local_storage',
                'backend_used': 'local_file',
                'records_stored': 1
            }
                
        except Exception as e:
            return {
                'success': False,
                'method': 'fallback_local_storage',
                'error': str(e)
            }
    
    def _calculate_pipeline_score(self) -> int:
        """Calculate pipeline score based on issues found."""
        total_issues = len(self.issues_found)
        critical_issues = len([i for i in self.issues_found if i.get('severity') == 'critical'])
        high_issues = len([i for i in self.issues_found if i.get('severity') == 'high'])
        
        # Calculate score based on issues (100 = perfect, 0 = many critical issues)
        score = 100
        score -= (critical_issues * 20)  # Critical issues: -20 points each
        score -= (high_issues * 10)      # High issues: -10 points each  
        score -= ((total_issues - critical_issues - high_issues) * 2)  # Other issues: -2 points each
        return max(0, score)  # Don't go below 0
    
    def _calculate_pipeline_metrics(self, pipeline_result: Dict[str, Any]):
        """Calculate overall pipeline health metrics."""
        total_issues = len(self.issues_found)
        critical_issues = len([i for i in self.issues_found if i.get('severity') == 'critical'])
        high_issues = len([i for i in self.issues_found if i.get('severity') == 'high'])
        
        # Calculate score based on issues (100 = perfect, 0 = many critical issues)
        score = 100
        score -= (critical_issues * 20)  # Critical issues: -20 points each
        score -= (high_issues * 10)      # High issues: -10 points each  
        score -= ((total_issues - critical_issues - high_issues) * 2)  # Other issues: -2 points each
        score = max(0, score)  # Don't go below 0
        
        pipeline_result['pipeline_execution']['total_issues'] = total_issues
        pipeline_result['pipeline_execution']['critical_issues'] = critical_issues
        pipeline_result['pipeline_execution']['warning_issues'] = total_issues - critical_issues
        pipeline_result['pipeline_execution']['overall_score'] = score
    
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

# Main plugin entry point
async def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point for the validation pipeline."""
    pipeline = PluginChangeValidationPipeline()
    return await pipeline.execute_validation_pipeline(context, config)

# Plugin metadata
plug_metadata = {
    "name": "plugin_change_validation_pipeline",
    "version": "1.0.0",
    "description": "Comprehensive orchestration plugin for validating plugin changes through config hardening, integrity scanning, and compliance auditing",
    "author": "PlugPipe Core Team", 
    "license": "MIT",
    "category": "orchestration",
    "tags": ["validation", "orchestration", "quality-assurance", "pipeline"],
    "requirements": [],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["full_validation", "detect_changes", "config_validation", "integrity_scan", "compliance_audit", "aggregate_issues"],
                "default": "full_validation",
                "description": "Type of validation to perform"
            },
            "target_plugin": {
                "type": "string", 
                "description": "Target plugin to validate (or 'all' for all plugins)"
            },
            "change_type": {
                "type": "string",
                "enum": ["created", "modified", "deleted", "unknown"],
                "default": "unknown",
                "description": "Type of change that triggered validation"
            }
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean"},
            "pipeline_execution": {
                "type": "object",
                "properties": {
                    "overall_score": {"type": "integer", "minimum": 0, "maximum": 100},
                    "total_issues": {"type": "integer"},
                    "critical_issues": {"type": "integer"}
                }
            }
        }
    },
    "sbom": "sbom/"
}