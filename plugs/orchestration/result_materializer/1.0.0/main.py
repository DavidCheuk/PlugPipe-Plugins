#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Result Materializer Service Plugin

This service plugin handles result materialization, output management, and artifact storage
with proper separation of concerns. Provides comprehensive result processing, formatting,
and persistence while following PlugPipe principles.

Key Responsibilities:
- Step result materialization and storage
- Pipeline output formatting and aggregation
- Artifact management and organization
- Context preservation and serialization
- Output directory management
- Result validation and verification

Following PlugPipe Architecture:
- Reuses existing materialization utilities
- Leverages existing file management systems
- Integrates with result processing pipelines
- Provides clean service interface for orchestrator composition
"""

import os
import json
import yaml
import logging
from typing import Dict, List, Any, Optional
from pathlib import Path
import datetime
import uuid

# Import existing PlugPipe utilities following "reuse everything" principle
from shares.utils.step_executor import materialize_result

logger = logging.getLogger(__name__)

class ResultMaterializer:
    """
    Result Materializer Service
    
    Handles all result materialization, output management, and artifact storage
    with proper organization and validation.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.materialize_dir = config.get('materialize_dir', 'pipe_runs')
        self.create_timestamped_dirs = config.get('create_timestamped_dirs', True)
        self.save_context = config.get('save_context', True)
        self.save_summary = config.get('save_summary', True)
        self.output_formats = config.get('output_formats', ['json', 'yaml'])
        self.compression_enabled = config.get('compression_enabled', False)
        self.retention_days = config.get('retention_days', 30)
        
        # Result processing configuration
        self.validate_results = config.get('validate_results', True)
        self.aggregate_results = config.get('aggregate_results', True)
        self.create_manifest = config.get('create_manifest', True)
        
        logger.info(f"Result Materializer initialized with materialize_dir: {self.materialize_dir}")
    
    def materialize_pipeline_results(
        self, 
        results: Dict[str, Any], 
        context: Dict[str, Any],
        execution_metadata: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Materialize complete pipeline results.
        
        Args:
            results: Pipeline execution results
            context: Pipeline execution context
            execution_metadata: Optional execution metadata
            
        Returns:
            Materialization result with paths and metadata
        """
        try:
            # Create output directory
            output_dir = self._create_output_directory(context)
            
            # Materialize individual step results
            step_artifacts = {}
            for step_id, step_result in results.items():
                step_artifacts[step_id] = self._materialize_step_result(
                    step_id, step_result, output_dir
                )
            
            # Create aggregated results
            aggregated_results = self._aggregate_pipeline_results(
                results, context, execution_metadata
            ) if self.aggregate_results else None
            
            # Save pipeline context
            context_path = self._save_pipeline_context(context, output_dir) if self.save_context else None
            
            # Create execution summary
            summary_path = self._create_execution_summary(
                results, context, execution_metadata, output_dir
            ) if self.save_summary else None
            
            # Create result manifest
            manifest_path = self._create_result_manifest(
                step_artifacts, aggregated_results, context_path, summary_path, output_dir
            ) if self.create_manifest else None
            
            # Validate results if enabled
            validation_result = self._validate_materialized_results(
                output_dir, step_artifacts
            ) if self.validate_results else None
            
            # Apply compression if enabled
            if self.compression_enabled:
                self._compress_results(output_dir)
            
            materialization_result = {
                'success': True,
                'output_directory': str(output_dir),
                'step_artifacts': step_artifacts,
                'aggregated_results_path': aggregated_results,
                'context_path': context_path,
                'summary_path': summary_path,
                'manifest_path': manifest_path,
                'validation_result': validation_result,
                'total_results': len(results),
                'materialization_timestamp': datetime.datetime.utcnow().isoformat()
            }
            
            logger.info(f"Pipeline results materialized successfully to: {output_dir}")
            return materialization_result
            
        except Exception as e:
            logger.error(f"Pipeline result materialization failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'materialization_timestamp': datetime.datetime.utcnow().isoformat()
            }
    
    def materialize_step_result(
        self, 
        step_id: str, 
        step_result: Any, 
        output_directory: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Materialize individual step result.
        
        Args:
            step_id: Step identifier
            step_result: Step execution result
            output_directory: Optional output directory override
            
        Returns:
            Step materialization result
        """
        try:
            if output_directory:
                output_dir = Path(output_directory)
            else:
                output_dir = self._create_output_directory({})
            
            step_artifacts = self._materialize_step_result(step_id, step_result, output_dir)
            
            return {
                'success': True,
                'step_id': step_id,
                'artifacts': step_artifacts,
                'output_directory': str(output_dir)
            }
            
        except Exception as e:
            logger.error(f"Step result materialization failed for {step_id}: {e}")
            return {
                'success': False,
                'step_id': step_id,
                'error': str(e)
            }
    
    def _create_output_directory(self, context: Dict[str, Any]) -> Path:
        """Create organized output directory structure."""
        base_dir = Path(self.materialize_dir)
        
        if self.create_timestamped_dirs:
            # Create timestamped directory
            execution_id = context.get('execution_id')
            if execution_id:
                dir_name = execution_id
            else:
                timestamp = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S")
                dir_name = f"{timestamp}_{uuid.uuid4().hex[:8]}"
            
            output_dir = base_dir / dir_name
        else:
            # Use pipeline name or default
            pipeline_name = context.get('pipeline_metadata', {}).get('name', 'pipeline')
            output_dir = base_dir / pipeline_name
        
        # Create directory structure
        output_dir.mkdir(parents=True, exist_ok=True)
        (output_dir / 'steps').mkdir(exist_ok=True)
        (output_dir / 'artifacts').mkdir(exist_ok=True)
        (output_dir / 'logs').mkdir(exist_ok=True)
        
        return output_dir
    
    def _materialize_step_result(
        self, 
        step_id: str, 
        step_result: Any, 
        output_dir: Path
    ) -> Dict[str, Any]:
        """
        Materialize individual step result using existing utilities.
        
        Leverages existing materialize_result function with enhanced organization.
        """
        try:
            # Use existing materialization utility
            materialize_result(step_id, step_result, str(output_dir))
            
            # Create additional organized artifacts
            step_dir = output_dir / 'steps' / step_id
            step_dir.mkdir(parents=True, exist_ok=True)
            
            artifacts = {
                'step_directory': str(step_dir),
                'result_files': []
            }
            
            # Save result in multiple formats
            for output_format in self.output_formats:
                if output_format == 'json':
                    json_path = step_dir / f"{step_id}_result.json"
                    with open(json_path, 'w') as f:
                        json.dump(step_result, f, indent=2, default=str)
                    artifacts['result_files'].append(str(json_path))
                
                elif output_format == 'yaml':
                    yaml_path = step_dir / f"{step_id}_result.yaml"
                    with open(yaml_path, 'w') as f:
                        yaml.safe_dump(step_result, f, default_flow_style=False)
                    artifacts['result_files'].append(str(yaml_path))
            
            # Create step metadata
            metadata = {
                'step_id': step_id,
                'materialized_at': datetime.datetime.utcnow().isoformat(),
                'result_type': type(step_result).__name__,
                'result_size': self._calculate_result_size(step_result)
            }
            
            metadata_path = step_dir / f"{step_id}_metadata.json"
            with open(metadata_path, 'w') as f:
                json.dump(metadata, f, indent=2)
            artifacts['metadata_file'] = str(metadata_path)
            
            logger.debug(f"Step result materialized for: {step_id}")
            return artifacts
            
        except Exception as e:
            logger.error(f"Failed to materialize step result for {step_id}: {e}")
            raise
    
    def _aggregate_pipeline_results(
        self, 
        results: Dict[str, Any], 
        context: Dict[str, Any],
        execution_metadata: Optional[Dict[str, Any]]
    ) -> str:
        """Create aggregated pipeline results file."""
        try:
            output_dir = Path(self.materialize_dir) / context.get('execution_id', 'unknown')
            
            # Clean results to prevent circular references
            clean_results = self._clean_results_for_serialization(results)
            
            # Reset recursion depth tracking
            self._recursion_depth = 0
            
            aggregated = {
                'pipeline_metadata': context.get('pipeline_metadata', {}),
                'execution_metadata': execution_metadata or {},
                'execution_summary': {
                    'total_steps': len(clean_results),
                    'successful_steps': sum(1 for r in clean_results.values() if self._is_successful_result(r)),
                    'failed_steps': sum(1 for r in clean_results.values() if not self._is_successful_result(r)),
                    'execution_start': context.get('execution_start'),
                    'execution_end': datetime.datetime.utcnow().isoformat()
                },
                'step_results': clean_results,
                'final_context': {
                    'inputs': context.get('inputs', {}),
                    'step_outputs': context.get('step_outputs', {}),
                    'execution_id': context.get('execution_id')
                },
                'aggregated_at': datetime.datetime.utcnow().isoformat()
            }
            
            # Save aggregated results
            aggregated_path = output_dir / 'pipeline_results_aggregated.json'
            with open(aggregated_path, 'w') as f:
                json.dump(aggregated, f, indent=2, default=str)
            
            # Also save in YAML format
            yaml_path = output_dir / 'pipeline_results_aggregated.yaml'
            with open(yaml_path, 'w') as f:
                yaml.safe_dump(aggregated, f, default_flow_style=False)
            
            logger.debug("Aggregated pipeline results created")
            return str(aggregated_path)
            
        except Exception as e:
            logger.error(f"Failed to create aggregated results: {e}")
            raise
    
    def _save_pipeline_context(self, context: Dict[str, Any], output_dir: Path) -> str:
        """Save complete pipeline context."""
        try:
            context_path = output_dir / 'final_context.yaml'
            
            # Create clean context for serialization
            clean_context = self._clean_context_for_serialization(context)
            
            with open(context_path, 'w') as f:
                yaml.safe_dump(clean_context, f, default_flow_style=False)
            
            logger.debug("Pipeline context saved")
            return str(context_path)
            
        except Exception as e:
            logger.error(f"Failed to save pipeline context: {e}")
            raise
    
    def _create_execution_summary(
        self, 
        results: Dict[str, Any], 
        context: Dict[str, Any],
        execution_metadata: Optional[Dict[str, Any]],
        output_dir: Path
    ) -> str:
        """Create human-readable execution summary."""
        try:
            # Clean results to prevent circular references
            clean_results = self._clean_results_for_serialization(results)
            
            # Reset recursion depth tracking
            self._recursion_depth = 0
            
            summary = {
                'execution_overview': {
                    'pipeline_name': context.get('pipeline_metadata', {}).get('name', 'Unknown'),
                    'execution_id': context.get('execution_id'),
                    'total_steps': len(clean_results),
                    'successful_steps': sum(1 for r in clean_results.values() if self._is_successful_result(r)),
                    'failed_steps': sum(1 for r in clean_results.values() if not self._is_successful_result(r)),
                    'execution_timestamp': datetime.datetime.utcnow().isoformat()
                },
                'step_summary': [],
                'execution_metadata': execution_metadata or {},
                'context_summary': {
                    'inputs_provided': len(context.get('inputs', {})),
                    'outputs_generated': len(context.get('step_outputs', {})),
                    'pipeline_path': context.get('pipeline_path', 'Unknown')
                }
            }
            
            # Create step-by-step summary  
            for step_id, step_result in clean_results.items():
                step_summary = {
                    'step_id': step_id,
                    'status': 'success' if self._is_successful_result(step_result) else 'failed',
                    'result_type': type(step_result).__name__,
                    'has_output': bool(step_result)
                }
                
                if not self._is_successful_result(step_result):
                    # Safely extract error message
                    if isinstance(step_result, dict):
                        step_summary['error'] = str(step_result.get('error', 'Unknown error'))
                    else:
                        step_summary['error'] = f'Failed result of type {type(step_result).__name__}'
                
                summary['step_summary'].append(step_summary)
            
            # Save summary
            summary_path = output_dir / 'execution_summary.json'
            with open(summary_path, 'w') as f:
                json.dump(summary, f, indent=2, default=str)
            
            # Also create human-readable text summary
            text_summary_path = output_dir / 'execution_summary.txt'
            self._create_text_summary(summary, text_summary_path)
            
            logger.debug("Execution summary created")
            return str(summary_path)
            
        except Exception as e:
            logger.error(f"Failed to create execution summary: {e}")
            raise
    
    def _create_result_manifest(
        self, 
        step_artifacts: Dict[str, Any],
        aggregated_results: Optional[str],
        context_path: Optional[str],
        summary_path: Optional[str],
        output_dir: Path
    ) -> str:
        """Create manifest of all generated artifacts."""
        try:
            manifest = {
                'manifest_version': '1.0',
                'generated_at': datetime.datetime.utcnow().isoformat(),
                'output_directory': str(output_dir),
                'artifacts': {
                    'step_artifacts': step_artifacts,
                    'aggregated_results': aggregated_results,
                    'context_file': context_path,
                    'summary_file': summary_path
                },
                'directory_structure': self._analyze_directory_structure(output_dir),
                'total_files': self._count_generated_files(output_dir),
                'total_size_bytes': self._calculate_directory_size(output_dir)
            }
            
            manifest_path = output_dir / 'result_manifest.json'
            with open(manifest_path, 'w') as f:
                json.dump(manifest, f, indent=2, default=str)
            
            logger.debug("Result manifest created")
            return str(manifest_path)
            
        except Exception as e:
            logger.error(f"Failed to create result manifest: {e}")
            raise
    
    def _validate_materialized_results(
        self, 
        output_dir: Path, 
        step_artifacts: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Validate materialized results for completeness and integrity."""
        try:
            validation = {
                'valid': True,
                'errors': [],
                'warnings': [],
                'validated_at': datetime.datetime.utcnow().isoformat()
            }
            
            # Check directory existence
            if not output_dir.exists():
                validation['errors'].append(f"Output directory does not exist: {output_dir}")
                validation['valid'] = False
                return validation
            
            # Validate step artifacts
            for step_id, artifacts in step_artifacts.items():
                step_dir = Path(artifacts.get('step_directory', ''))
                if not step_dir.exists():
                    validation['errors'].append(f"Step directory missing: {step_id}")
                    validation['valid'] = False
                
                # Check result files
                result_files = artifacts.get('result_files', [])
                for result_file in result_files:
                    if not Path(result_file).exists():
                        validation['errors'].append(f"Result file missing: {result_file}")
                        validation['valid'] = False
            
            # Check required files
            required_files = ['final_context.yaml']
            for required_file in required_files:
                if not (output_dir / required_file).exists():
                    validation['warnings'].append(f"Recommended file missing: {required_file}")
            
            validation['validation_summary'] = {
                'total_errors': len(validation['errors']),
                'total_warnings': len(validation['warnings']),
                'artifacts_validated': len(step_artifacts)
            }
            
            logger.debug(f"Result validation completed: {validation['valid']}")
            return validation
            
        except Exception as e:
            logger.error(f"Result validation failed: {e}")
            return {
                'valid': False,
                'errors': [str(e)],
                'validated_at': datetime.datetime.utcnow().isoformat()
            }
    
    def _compress_results(self, output_dir: Path):
        """Apply compression to result files if enabled."""
        try:
            import gzip
            import shutil
            
            # Compress large JSON and YAML files
            for file_path in output_dir.rglob('*.json'):
                if file_path.stat().st_size > 1024 * 1024:  # Files larger than 1MB
                    with open(file_path, 'rb') as f_in:
                        with gzip.open(f"{file_path}.gz", 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    file_path.unlink()  # Remove original
                    logger.debug(f"Compressed large file: {file_path}")
            
            for file_path in output_dir.rglob('*.yaml'):
                if file_path.stat().st_size > 1024 * 1024:  # Files larger than 1MB
                    with open(file_path, 'rb') as f_in:
                        with gzip.open(f"{file_path}.gz", 'wb') as f_out:
                            shutil.copyfileobj(f_in, f_out)
                    file_path.unlink()  # Remove original
                    logger.debug(f"Compressed large file: {file_path}")
            
        except ImportError:
            logger.warning("Compression requested but gzip module not available")
        except Exception as e:
            logger.warning(f"Compression failed: {e}")
    
    def _clean_context_for_serialization(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """Clean context by removing non-serializable objects."""
        clean_context = {}
        
        for key, value in context.items():
            try:
                # Test serialization
                json.dumps(value, default=str)
                clean_context[key] = value
            except (TypeError, ValueError):
                # Skip non-serializable values
                clean_context[key] = f"<Non-serializable {type(value).__name__}>"
        
        return clean_context
    
    def _clean_results_for_serialization(self, results: Dict[str, Any]) -> Dict[str, Any]:
        """Clean results by removing circular references and non-serializable objects."""
        clean_results = {}
        seen_objects = set()
        max_depth = 50  # Maximum depth to prevent excessive nesting
        
        def clean_value(value, depth=0):
            """Recursively clean a value with depth limiting."""
            if depth > max_depth:
                logger.warning(f"Maximum depth {max_depth} reached during serialization cleaning")
                return f"<Max depth exceeded at level {depth}>"
            
            # Check for circular references by tracking object IDs
            if isinstance(value, (dict, list)) and id(value) in seen_objects:
                return f"<Circular reference to {type(value).__name__}>"
            
            try:
                if isinstance(value, dict):
                    if id(value) not in seen_objects:
                        seen_objects.add(id(value))
                    return {k: clean_value(v, depth + 1) for k, v in value.items()}
                elif isinstance(value, list):
                    if id(value) not in seen_objects:
                        seen_objects.add(id(value))
                    return [clean_value(item, depth + 1) for item in value]
                else:
                    # Test serialization for simple values
                    json.dumps(value, default=str)
                    return value
                    
            except (TypeError, ValueError, RecursionError) as e:
                logger.warning(f"Cannot serialize value at depth {depth}: {e}")
                return f"<Non-serializable {type(value).__name__}: {str(e)[:100]}>"
        
        for key, value in results.items():
            try:
                clean_results[key] = clean_value(value, 0)
            except Exception as e:
                logger.error(f"Failed to clean result {key}: {e}")
                clean_results[key] = f"<Cleaning failed: {str(e)[:100]}>"
        
        return clean_results
    
    def _is_successful_result(self, result: Any) -> bool:
        """Check if result indicates successful step execution."""
        try:
            # Add depth check to prevent infinite recursion
            if hasattr(self, '_recursion_depth'):
                self._recursion_depth += 1
                if self._recursion_depth > 100:  # Max recursion depth
                    logger.warning("Maximum recursion depth reached in _is_successful_result, returning False")
                    return False
            else:
                self._recursion_depth = 1
            
            if isinstance(result, dict):
                success = result.get('success', True) and 'error' not in result
                self._recursion_depth -= 1
                return success
            
            success = result is not None
            self._recursion_depth -= 1
            return success
            
        except RecursionError:
            logger.error("RecursionError caught in _is_successful_result, returning False")
            return False
        except Exception as e:
            logger.warning(f"Unexpected error in _is_successful_result: {e}, returning False")
            return False
    
    def _calculate_result_size(self, result: Any) -> int:
        """Calculate approximate size of result data."""
        try:
            return len(json.dumps(result, default=str))
        except:
            return 0
    
    def _analyze_directory_structure(self, output_dir: Path) -> Dict[str, Any]:
        """Analyze generated directory structure."""
        structure = {}
        
        for item in output_dir.rglob('*'):
            if item.is_dir():
                rel_path = item.relative_to(output_dir)
                structure[str(rel_path)] = {
                    'type': 'directory',
                    'files': len(list(item.iterdir()))
                }
        
        return structure
    
    def _count_generated_files(self, output_dir: Path) -> int:
        """Count total number of generated files."""
        return len(list(output_dir.rglob('*')))
    
    def _calculate_directory_size(self, output_dir: Path) -> int:
        """Calculate total size of output directory."""
        total_size = 0
        for file_path in output_dir.rglob('*'):
            if file_path.is_file():
                total_size += file_path.stat().st_size
        return total_size
    
    def _create_text_summary(self, summary: Dict[str, Any], output_path: Path):
        """Create human-readable text summary."""
        try:
            with open(output_path, 'w') as f:
                f.write("PlugPipe Pipeline Execution Summary\n")
                f.write("=" * 40 + "\n\n")
                
                overview = summary['execution_overview']
                f.write(f"Pipeline: {overview['pipeline_name']}\n")
                f.write(f"Execution ID: {overview['execution_id']}\n")
                f.write(f"Total Steps: {overview['total_steps']}\n")
                f.write(f"Successful: {overview['successful_steps']}\n")
                f.write(f"Failed: {overview['failed_steps']}\n")
                f.write(f"Executed At: {overview['execution_timestamp']}\n\n")
                
                f.write("Step Results:\n")
                f.write("-" * 20 + "\n")
                for step in summary['step_summary']:
                    status_symbol = "✅" if step['status'] == 'success' else "❌"
                    f.write(f"{status_symbol} {step['step_id']}: {step['status']}\n")
                    if step['status'] == 'failed' and 'error' in step:
                        f.write(f"    Error: {step['error']}\n")
                
        except Exception as e:
            logger.warning(f"Failed to create text summary: {e}")


# Plugin metadata for PlugPipe registration
plug_metadata = {
    "name": "result_materializer",
    "version": "1.0.0",
    "owner": "plugpipe-orchestration",
    "status": "production",
    "description": "Result Materializer Service - handles result materialization, output management, and artifact storage with proper organization and validation",
    "category": "orchestration",
    "tags": ["orchestration", "results", "materialization", "artifacts", "service"],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["materialize_pipeline", "materialize_step"],
                "description": "Materialization operation to perform"
            },
            "results": {"type": "object", "description": "Pipeline execution results"},
            "context": {"type": "object", "description": "Pipeline execution context"},
            "execution_metadata": {"type": "object", "description": "Execution metadata"},
            "step_id": {"type": "string", "description": "Step identifier for single step materialization"},
            "step_result": {"description": "Step result for single step materialization"},
            "output_directory": {"type": "string", "description": "Output directory override"},
            "materialize_dir": {"type": "string", "description": "Base materialization directory"},
            "output_formats": {"type": "array", "items": {"type": "string"}, "description": "Output formats"},
            "save_context": {"type": "boolean", "description": "Save pipeline context"},
            "save_summary": {"type": "boolean", "description": "Save execution summary"}
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean", "description": "Materialization success indicator"},
            "output_directory": {"type": "string", "description": "Output directory path"},
            "step_artifacts": {"type": "object", "description": "Step artifact paths"},
            "aggregated_results_path": {"type": "string", "description": "Aggregated results file path"},
            "context_path": {"type": "string", "description": "Context file path"},
            "summary_path": {"type": "string", "description": "Summary file path"},
            "manifest_path": {"type": "string", "description": "Manifest file path"},
            "validation_result": {"type": "object", "description": "Validation results"},
            "total_results": {"type": "integer", "description": "Total number of results"},
            "error": {"type": "string", "description": "Error message if materialization failed"}
        }
    },
    "revolutionary_capabilities": [
        "modular_result_materialization",
        "comprehensive_artifact_management",
        "multi_format_output_support",
        "result_validation_verification"
    ]
}


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin process function."""
    try:
        # Initialize the result materializer service
        materializer = ResultMaterializer(cfg)
        
        # Determine operation to perform
        operation = cfg.get('operation', 'materialize_pipeline')
        
        if operation == 'materialize_pipeline':
            results = cfg.get('results', {})
            context = cfg.get('context', {})
            execution_metadata = cfg.get('execution_metadata')
            
            return materializer.materialize_pipeline_results(results, context, execution_metadata)
        
        elif operation == 'materialize_step':
            step_id = cfg.get('step_id', '')
            step_result = cfg.get('step_result')
            output_directory = cfg.get('output_directory')
            
            return materializer.materialize_step_result(step_id, step_result, output_directory)
        
        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'supported_operations': ['materialize_pipeline', 'materialize_step']
            }
        
    except Exception as e:
        logger.error(f"Result Materializer process failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'operation': cfg.get('operation', 'unknown')
        }


# Direct execution for testing
if __name__ == "__main__":
    import json
    
    # Test configuration
    test_config = {
        'operation': 'materialize_pipeline',
        'results': {
            'step1': {'result': 'success', 'output': 'test_output_1'},
            'step2': {'result': 'success', 'output': 'test_output_2'}
        },
        'context': {
            'execution_id': 'test_execution_123',
            'pipeline_metadata': {'name': 'test_pipeline'},
            'inputs': {'test_input': 'value'},
            'step_outputs': {}
        },
        'materialize_dir': '/tmp/test_results'
    }
    
    result = process({}, test_config)
    print(json.dumps(result, indent=2, default=str))