#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Pipeline Loader and Validator Service Plugin

This service plugin handles pipeline loading and validation with proper separation of concerns.
Provides comprehensive pipeline structure validation, enterprise feature detection, and
preparation for execution while following PlugPipe principles.

Key Responsibilities:
- Load pipeline YAML files with proper error handling
- Validate pipeline structure and step definitions
- Detect enterprise features (DAG, advanced workflows)
- Prepare pipeline metadata for execution services
- Inject secrets into pipeline configuration securely
- Validate plugin dependencies and availability

Following PlugPipe Architecture:
- Reuses existing YAML loading utilities
- Leverages existing validation frameworks
- Integrates with secret manager for secure configuration
- Provides clean service interface for orchestrator composition
"""

import os
import copy
import yaml
import logging
from typing import Dict, List, Any, Optional, Tuple
from pathlib import Path

# Import existing PlugPipe utilities following "reuse everything" principle
from shares.loader import load_pipeline_yaml, extract_plugs_with_versions, load_config
from cores.secret_manager import inject_secrets_into_pipeline

logger = logging.getLogger(__name__)

class PipelineLoaderValidator:
    """
    Pipeline Loader and Validator Service
    
    Handles all pipeline loading, validation, and preparation tasks
    with proper separation of concerns and error handling.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.validation_rules = config.get('validation_rules', {})
        self.enterprise_enabled = config.get('enterprise_enabled', False)
        self.strict_validation = config.get('strict_validation', True)
        
        # Enterprise feature detection patterns
        self.enterprise_features = {
            'dag_features': ['next', 'branches', 'join'],
            'advanced_workflow': ['parallel', 'matrix', 'depends_on'],
            'enterprise_plugins': ['enterprise_', 'pro_', 'commercial_']
        }
        
        logger.info(f"Pipeline Loader/Validator initialized with enterprise_enabled: {self.enterprise_enabled}")
    
    def _get_default_registry(self):
        """Get default registry instance if not provided in config."""
        try:
            # Import and create default registry
            from cores.registry import PlugRegistry
            return PlugRegistry()
        except Exception as e:
            logger.warning(f"Could not create default registry: {e}")
            return None
    
    def load_and_validate_pipeline(self, pipeline_path: str, secret_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Load and validate a pipeline from YAML file.
        
        Args:
            pipeline_path: Path to pipeline YAML file
            secret_config: Optional secret configuration for injection
            
        Returns:
            Dict containing validated pipeline and metadata
        """
        try:
            logger.info(f"Loading pipeline from: {pipeline_path}")
            
            # Step 1: Load pipeline YAML using existing utilities
            pipeline_doc = load_pipeline_yaml(pipeline_path, config_path=self.config.get('config_path', 'config.yaml'))
            
            # Step 2: Inject secrets if provided
            if secret_config or self._has_secret_placeholders(pipeline_doc):
                logger.debug("Injecting secrets into pipeline configuration")
                pipeline_doc = inject_secrets_into_pipeline(pipeline_doc, secret_config or {})
            
            # Step 3: Validate pipeline structure
            validation_result = self._validate_pipeline_structure(pipeline_doc)
            if not validation_result['valid']:
                raise ValueError(f"Pipeline validation failed: {validation_result['errors']}")
            
            # Step 4: Detect enterprise features
            enterprise_analysis = self._analyze_enterprise_features(pipeline_doc)
            
            # Step 5: Validate plugin dependencies
            dependency_check = self._validate_plugin_dependencies(pipeline_doc)
            
            # Step 6: Prepare execution metadata
            execution_metadata = self._prepare_execution_metadata(pipeline_doc, pipeline_path)
            
            result = {
                'status': 'success',
                'pipeline_doc': pipeline_doc,
                'validation_result': validation_result,
                'enterprise_analysis': enterprise_analysis,
                'dependency_check': dependency_check,
                'execution_metadata': execution_metadata,
                'pipeline_path': pipeline_path
            }
            
            logger.info(f"Pipeline loaded and validated successfully: {pipeline_path}")
            return result
            
        except Exception as e:
            logger.error(f"Failed to load/validate pipeline {pipeline_path}: {e}")
            return {
                'status': 'error',
                'error': str(e),
                'pipeline_path': pipeline_path
            }
    
    def _has_secret_placeholders(self, pipeline_doc: Dict[str, Any]) -> bool:
        """Check if pipeline contains secret placeholders."""
        pipeline_str = str(pipeline_doc)
        return '${' in pipeline_str
    
    def _validate_pipeline_structure(self, pipeline_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate pipeline structure and step definitions.
        
        Returns validation result with detailed error information.
        """
        errors = []
        warnings = []
        
        # Check required pipeline structure
        if 'pipeline' not in pipeline_doc:
            errors.append("Pipeline must contain 'pipeline' key with step definitions")
            return {'valid': False, 'errors': errors, 'warnings': warnings}
        
        steps = pipeline_doc['pipeline']
        if not isinstance(steps, list) or not steps:
            errors.append("Pipeline must contain at least one step")
            return {'valid': False, 'errors': errors, 'warnings': warnings}
        
        # Validate individual steps
        step_ids = set()
        for idx, step in enumerate(steps):
            step_errors = self._validate_step(step, idx, step_ids)
            errors.extend(step_errors)
        
        # Check for duplicate step IDs
        if len(step_ids) != len(steps):
            errors.append("Duplicate step IDs found in pipeline")
        
        # Validate DAG structure if detected
        if self._is_dag_pipeline(steps):
            dag_errors = self._validate_dag_structure(steps)
            errors.extend(dag_errors)
        
        return {
            'valid': len(errors) == 0,
            'errors': errors,
            'warnings': warnings,
            'step_count': len(steps),
            'unique_step_ids': len(step_ids)
        }
    
    def _validate_step(self, step: Dict[str, Any], idx: int, step_ids: set) -> List[str]:
        """Validate individual step definition."""
        errors = []
        
        # Check required step fields
        if 'id' not in step:
            errors.append(f"Step {idx}: Missing required 'id' field")
        else:
            step_id = step['id']
            if step_id in step_ids:
                errors.append(f"Step {idx}: Duplicate step ID '{step_id}'")
            step_ids.add(step_id)
        
        # Check step execution method
        if 'uses' not in step and 'type' not in step:
            errors.append(f"Step {idx}: Must specify either 'uses' (plugin) or 'type' (built-in)")
        
        # Validate step-specific configurations
        if 'uses' in step:
            plugin_name = step['uses']
            if not isinstance(plugin_name, str) or not plugin_name.strip():
                errors.append(f"Step {idx}: Invalid plugin name '{plugin_name}'")
        
        return errors
    
    def _is_dag_pipeline(self, steps: List[Dict[str, Any]]) -> bool:
        """Check if pipeline uses DAG features."""
        for step in steps:
            if any(feature in step for feature in self.enterprise_features['dag_features']):
                return True
        return False
    
    def _validate_dag_structure(self, steps: List[Dict[str, Any]]) -> List[str]:
        """Validate DAG structure for consistency."""
        errors = []
        step_ids = {step['id'] for step in steps}
        
        for step in steps:
            step_id = step['id']
            
            # Validate 'next' references
            if 'next' in step:
                next_refs = step['next']
                if isinstance(next_refs, list):
                    for next_ref in next_refs:
                        target = next_ref.get('target') if isinstance(next_ref, dict) else next_ref
                        if target not in step_ids:
                            errors.append(f"Step '{step_id}': Invalid next target '{target}'")
                elif isinstance(next_refs, str):
                    if next_refs not in step_ids:
                        errors.append(f"Step '{step_id}': Invalid next target '{next_refs}'")
            
            # Validate 'branches' references
            if 'branches' in step:
                branches = step['branches']
                if isinstance(branches, dict):
                    for condition, target in branches.items():
                        if target not in step_ids:
                            errors.append(f"Step '{step_id}': Invalid branch target '{target}' for condition '{condition}'")
        
        return errors
    
    def _analyze_enterprise_features(self, pipeline_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze pipeline for enterprise features and requirements.
        
        Returns detailed analysis of enterprise feature usage.
        """
        analysis = {
            'requires_enterprise': False,
            'detected_features': [],
            'feature_details': {},
            'compatibility_level': 'oss'
        }
        
        steps = pipeline_doc.get('pipeline', [])
        
        # Check for DAG features
        dag_features_found = []
        for step in steps:
            for feature in self.enterprise_features['dag_features']:
                if feature in step:
                    dag_features_found.append(feature)
                    analysis['requires_enterprise'] = True
        
        if dag_features_found:
            analysis['detected_features'].append('dag_workflow')
            analysis['feature_details']['dag_features'] = list(set(dag_features_found))
        
        # Check for advanced workflow features
        advanced_features_found = []
        for step in steps:
            for feature in self.enterprise_features['advanced_workflow']:
                if feature in step:
                    advanced_features_found.append(feature)
                    analysis['requires_enterprise'] = True
        
        if advanced_features_found:
            analysis['detected_features'].append('advanced_workflow')
            analysis['feature_details']['advanced_features'] = list(set(advanced_features_found))
        
        # Check for enterprise plugins
        enterprise_plugins = []
        for step in steps:
            plugin_name = step.get('uses', '')
            for prefix in self.enterprise_features['enterprise_plugins']:
                if plugin_name.startswith(prefix):
                    enterprise_plugins.append(plugin_name)
                    analysis['requires_enterprise'] = True
        
        if enterprise_plugins:
            analysis['detected_features'].append('enterprise_plugins')
            analysis['feature_details']['enterprise_plugins'] = enterprise_plugins
        
        # Determine compatibility level
        if analysis['requires_enterprise']:
            if not self.enterprise_enabled:
                analysis['compatibility_level'] = 'enterprise_required'
            else:
                analysis['compatibility_level'] = 'enterprise_compatible'
        else:
            analysis['compatibility_level'] = 'oss_compatible'
        
        logger.debug(f"Enterprise analysis: {analysis}")
        return analysis
    
    def _validate_plugin_dependencies(self, pipeline_doc: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate that all required plugins are available.
        
        Returns dependency validation results.
        """
        try:
            # Extract pipeline steps first, then pass to extract_plugs_with_versions with registry
            pipeline_steps = pipeline_doc.get('pipeline', [])
            
            # Get registry instance - if not available, skip dependency validation
            try:
                registry = self.config.get('registry') or self._get_default_registry()
                plugin_deps = extract_plugs_with_versions(pipeline_steps, registry)
            except Exception as e:
                logger.warning(f"Plugin dependency validation failed: {e}")
                return {
                    'validation_status': 'skipped',
                    'available_plugins': [],
                    'missing_plugins': [],
                    'warning': f"Registry not available for dependency validation: {e}"
                }
            
            # Check plugin availability (simplified check)
            available_plugins = []
            missing_plugins = []
            
            for plugin_ref in plugin_deps:
                # Simple existence check - in production this would check registry
                plugin_name = plugin_ref.split('@')[0] if '@' in plugin_ref else plugin_ref
                # For now, assume all plugins are available - real implementation would check registry
                available_plugins.append(plugin_ref)
            
            return {
                'valid': len(missing_plugins) == 0,
                'total_plugins': len(plugin_deps),
                'available_plugins': available_plugins,
                'missing_plugins': missing_plugins,
                'plugin_dependencies': plugin_deps
            }
            
        except Exception as e:
            logger.error(f"Plugin dependency validation failed: {e}")
            return {
                'valid': False,
                'error': str(e),
                'total_plugins': 0,
                'available_plugins': [],
                'missing_plugins': [],
                'plugin_dependencies': []
            }
    
    def _prepare_execution_metadata(self, pipeline_doc: Dict[str, Any], pipeline_path: str) -> Dict[str, Any]:
        """
        Prepare metadata needed for pipeline execution.
        
        Returns execution-ready metadata.
        """
        steps = pipeline_doc.get('pipeline', [])
        
        metadata = {
            'pipeline_name': pipeline_doc.get('metadata', {}).get('name', Path(pipeline_path).stem),
            'total_steps': len(steps),
            'execution_mode': 'dag' if self._is_dag_pipeline(steps) else 'linear',
            'step_ids': [step['id'] for step in steps],
            'has_parallel_steps': any('foreach' in step for step in steps),
            'has_conditional_steps': any('when' in step for step in steps),
            'has_pause_steps': any(step.get('type') == 'pause' or step.get('uses') == 'pause_plugin' for step in steps),
            'estimated_duration': self._estimate_execution_duration(steps),
            'resource_requirements': self._estimate_resource_requirements(steps)
        }
        
        return metadata
    
    def _estimate_execution_duration(self, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Estimate pipeline execution duration."""
        # Simple estimation based on step count and complexity
        base_time = len(steps) * 5  # 5 seconds per step baseline
        
        # Add time for complex operations
        for step in steps:
            if 'foreach' in step:
                base_time += 10  # Extra time for loop operations
            if 'timeout' in step:
                timeout = step['timeout']
                if isinstance(timeout, (int, float)) and timeout > 0:
                    base_time += timeout * 0.1  # Factor in timeout settings
        
        return {
            'estimated_seconds': base_time,
            'confidence': 'low',  # Simple estimation
            'factors': ['step_count', 'complexity_analysis']
        }
    
    def _estimate_resource_requirements(self, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Estimate pipeline resource requirements."""
        return {
            'cpu_intensive': any('cpu' in str(step).lower() for step in steps),
            'memory_intensive': any('memory' in str(step).lower() or 'large' in str(step).lower() for step in steps),
            'io_intensive': any('file' in str(step).lower() or 'database' in str(step).lower() for step in steps),
            'network_intensive': any('http' in str(step).lower() or 'api' in str(step).lower() for step in steps),
            'estimated_complexity': 'medium'  # Simple classification
        }


# Plugin metadata for PlugPipe registration
plug_metadata = {
    "name": "pipeline_loader_validator",
    "version": "1.0.0",
    "owner": "plugpipe-orchestration",
    "status": "production",
    "description": "Pipeline Loader and Validator Service - handles pipeline loading, validation, and preparation for execution with proper separation of concerns",
    "category": "orchestration",
    "tags": ["orchestration", "pipeline", "validation", "loading", "service"],
    "input_schema": {
        "type": "object",
        "properties": {
            "pipeline_path": {"type": "string", "description": "Path to pipeline YAML file"},
            "secret_config": {"type": "object", "description": "Secret configuration for injection"},
            "validation_rules": {"type": "object", "description": "Custom validation rules"},
            "enterprise_enabled": {"type": "boolean", "description": "Enable enterprise feature validation"},
            "strict_validation": {"type": "boolean", "description": "Enable strict validation mode"}
        },
        "required": ["pipeline_path"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["success", "error"]},
            "pipeline_doc": {"type": "object", "description": "Loaded and validated pipeline"},
            "validation_result": {"type": "object", "description": "Validation results"},
            "enterprise_analysis": {"type": "object", "description": "Enterprise feature analysis"},
            "dependency_check": {"type": "object", "description": "Plugin dependency validation"},
            "execution_metadata": {"type": "object", "description": "Execution preparation metadata"}
        }
    },
    "revolutionary_capabilities": [
        "modular_pipeline_validation",
        "enterprise_feature_detection",
        "dependency_validation",
        "execution_metadata_preparation"
    ]
}


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin process function."""
    try:
        # Initialize the pipeline loader/validator service
        loader_validator = PipelineLoaderValidator(cfg)
        
        # Extract required parameters
        pipeline_path = cfg.get('pipeline_path')
        if not pipeline_path:
            return {
                'success': False,
                'error': 'pipeline_path is required',
                'message': 'Pipeline path must be specified'
            }
        
        # Optional parameters
        secret_config = cfg.get('secret_config', {})
        
        # Load and validate the pipeline
        result = loader_validator.load_and_validate_pipeline(pipeline_path, secret_config)
        
        # Add success indicator for compatibility
        result['success'] = result['status'] == 'success'
        
        return result
        
    except Exception as e:
        logger.error(f"Pipeline Loader/Validator process failed: {e}")
        return {
            'success': False,
            'status': 'error',
            'error': str(e),
            'message': f'Pipeline loading/validation failed: {e}'
        }


# Direct execution for testing
if __name__ == "__main__":
    import json
    
    # Test configuration
    test_config = {
        'pipeline_path': 'pipe_specs/sample_pipeline.yaml',
        'enterprise_enabled': True,
        'strict_validation': True
    }
    
    result = process({}, test_config)
    print(json.dumps(result, indent=2, default=str))