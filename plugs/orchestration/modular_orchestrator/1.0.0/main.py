#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Modular Orchestrator Service Plugin

This service plugin replaces the monolithic orchestrator with a properly modularized
architecture that composes specialized orchestration services. Provides clean separation
of concerns, improved maintainability, and enhanced testability while following
PlugPipe principles.

Key Responsibilities:
- Service composition and orchestration
- Pipeline lifecycle management
- Error handling and recovery
- Service communication coordination
- Backward compatibility with existing orchestrator interface

Service Architecture:
1. Pipeline Loader/Validator Service - handles pipeline loading and validation
2. Context Resolver Service - manages context resolution and environment setup
3. Execution Engine Service - handles DAG and linear execution strategies
4. Result Materializer Service - manages result storage and artifact organization

Following PlugPipe Architecture:
- Reuses existing orchestration services as plugins
- Leverages pp() function for service discovery
- Maintains compatibility with existing orchestrator interface
- Provides clean service composition patterns
"""

import os
import logging
import datetime
from typing import Dict, List, Any, Optional

# Import PlugPipe utilities
from shares.loader import pp

logger = logging.getLogger(__name__)

class ModularOrchestrator:
    """
    Modular Orchestrator Service
    
    Composes specialized orchestration services to provide comprehensive
    pipeline execution with proper separation of concerns.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enterprise_enabled = config.get('enterprise_enabled', False)
        self.materialize = config.get('materialize', True)
        self.materialize_dir = config.get('materialize_dir', 'pipe_runs')
        self.use_enhanced_orchestrator = config.get('use_enhanced_orchestrator', False)
        
        # Service configuration
        self.service_timeout = config.get('service_timeout', 300)  # 5 minutes
        self.enable_service_fallback = config.get('enable_service_fallback', True)
        
        # Initialize services
        self.services = {
            'pipeline_loader': None,
            'context_resolver': None,
            'execution_engine': None,
            'result_materializer': None
        }
        
        self._initialize_services()
        
        logger.info(f"Modular Orchestrator initialized with enterprise_enabled: {self.enterprise_enabled}")
    
    def _initialize_services(self):
        """Initialize orchestration services using pp() discovery."""
        try:
            # Initialize Pipeline Loader/Validator Service
            try:
                self.services['pipeline_loader'] = pp('pipeline_loader_validator')
                logger.info("Pipeline Loader/Validator service initialized")
            except Exception as e:
                logger.warning(f"Pipeline Loader service not available: {e}")
            
            # Initialize Context Resolver Service
            try:
                self.services['context_resolver'] = pp('context_resolver')
                logger.info("Context Resolver service initialized")
            except Exception as e:
                logger.warning(f"Context Resolver service not available: {e}")
            
            # Initialize Execution Engine Service
            try:
                self.services['execution_engine'] = pp('execution_engine')
                logger.info("Execution Engine service initialized")
            except Exception as e:
                logger.warning(f"Execution Engine service not available: {e}")
            
            # Initialize Result Materializer Service
            try:
                self.services['result_materializer'] = pp('result_materializer')
                logger.info("Result Materializer service initialized")
            except Exception as e:
                logger.warning(f"Result Materializer service not available: {e}")
                
        except Exception as e:
            logger.error(f"Service initialization failed: {e}")
            if not self.enable_service_fallback:
                raise
    
    def run_pipeline(
        self,
        pipeline_yaml_path: str,
        registry: Any,
        initial_context: Optional[Dict[str, Any]] = None,
        **kwargs
    ) -> Dict[str, Any]:
        """
        Execute pipeline using modular service architecture.
        
        Args:
            pipeline_yaml_path: Path to pipeline YAML file
            registry: Plugin registry instance
            initial_context: Optional initial context
            **kwargs: Additional configuration options
            
        Returns:
            Pipeline execution results
        """
        try:
            logger.info(f"Starting modular pipeline execution: {pipeline_yaml_path}")
            
            # Check for enhanced orchestrator fallback
            if self.use_enhanced_orchestrator:
                try:
                    return self._fallback_to_enhanced_orchestrator(
                        pipeline_yaml_path, registry, initial_context, **kwargs
                    )
                except Exception as e:
                    logger.warning(f"Enhanced orchestrator fallback failed: {e}")
            
            # Execute using modular service architecture
            execution_start = datetime.datetime.utcnow()
            
            # Stage 1: Pipeline Loading and Validation
            pipeline_data = self._load_and_validate_pipeline(
                pipeline_yaml_path, kwargs.get('secret_config', {})
            )
            
            if not pipeline_data['success']:
                return self._create_error_result(
                    f"Pipeline validation failed: {pipeline_data.get('error')}", 
                    pipeline_yaml_path
                )
            
            # Stage 2: Context Resolution and Initialization
            context_data = self._initialize_pipeline_context(
                pipeline_data['pipeline_doc'], initial_context, pipeline_yaml_path
            )
            
            if not context_data['success']:
                return self._create_error_result(
                    f"Context initialization failed: {context_data.get('error')}", 
                    pipeline_yaml_path
                )
            
            # Stage 3: Pipeline Execution
            execution_data = self._execute_pipeline_steps(
                pipeline_data['pipeline_doc']['pipeline'],
                context_data['context'],
                registry,
                pipeline_data['enterprise_analysis']
            )
            
            if not execution_data['success']:
                return self._create_error_result(
                    f"Pipeline execution failed: {execution_data.get('error')}", 
                    pipeline_yaml_path
                )
            
            # Stage 4: Result Materialization
            if self.materialize:
                materialization_data = self._materialize_results(
                    execution_data['results'],
                    context_data['context'],
                    {
                        'execution_start': execution_start.isoformat(),
                        'execution_end': datetime.datetime.utcnow().isoformat(),
                        'pipeline_data': pipeline_data,
                        'execution_mode': execution_data.get('execution_mode')
                    }
                )
                
                if not materialization_data['success']:
                    logger.warning(f"Result materialization failed: {materialization_data.get('error')}")
            else:
                materialization_data = {'success': True, 'output_directory': None}
            
            # Compile final results
            final_result = {
                'success': True,
                'execution_mode': 'modular',
                'pipeline_path': pipeline_yaml_path,
                'results': execution_data['results'],
                'context': context_data['context'],
                'execution_metadata': {
                    'execution_start': execution_start.isoformat(),
                    'execution_end': datetime.datetime.utcnow().isoformat(),
                    'duration_seconds': (datetime.datetime.utcnow() - execution_start).total_seconds(),
                    'total_steps': execution_data.get('total_steps', 0),
                    'completed_steps': execution_data.get('completed_steps', 0),
                    'execution_mode': execution_data.get('execution_mode', 'unknown'),
                    'services_used': list(self.services.keys())
                },
                'materialization': materialization_data,
                'validation_result': pipeline_data.get('validation_result'),
                'enterprise_analysis': pipeline_data.get('enterprise_analysis')
            }
            
            # Return context for backward compatibility
            if isinstance(context_data['context'], dict):
                # Legacy format - return context directly
                context_data['context'].update({
                    'execution_metadata': final_result['execution_metadata'],
                    'materialization_info': materialization_data
                })
                return context_data['context']
            else:
                return final_result
            
        except Exception as e:
            logger.error(f"Modular pipeline execution failed: {e}")
            return self._create_error_result(str(e), pipeline_yaml_path)
    
    def _load_and_validate_pipeline(
        self, 
        pipeline_path: str, 
        secret_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Load and validate pipeline using Pipeline Loader service."""
        try:
            if not self.services['pipeline_loader']:
                return self._fallback_pipeline_loading(pipeline_path, secret_config)
            
            loader_config = {
                'pipeline_path': pipeline_path,
                'secret_config': secret_config,
                'enterprise_enabled': self.enterprise_enabled,
                'strict_validation': True,
                'config_path': self.config.get('config_path', 'config.yaml')
            }
            
            result = self.services['pipeline_loader'].process({}, loader_config)
            
            if result.get('success'):
                logger.info("Pipeline loaded and validated successfully")
            else:
                logger.error(f"Pipeline validation failed: {result.get('error')}")
            
            return result
            
        except Exception as e:
            logger.error(f"Pipeline loading service failed: {e}")
            if self.enable_service_fallback:
                return self._fallback_pipeline_loading(pipeline_path, secret_config)
            raise
    
    def _initialize_pipeline_context(
        self, 
        pipeline_doc: Dict[str, Any],
        initial_context: Optional[Dict[str, Any]],
        pipeline_path: str
    ) -> Dict[str, Any]:
        """Initialize pipeline context using Context Resolver service."""
        try:
            if not self.services['context_resolver']:
                return self._fallback_context_initialization(
                    pipeline_doc, initial_context, pipeline_path
                )
            
            resolver_config = {
                'operation': 'initialize_pipeline',
                'pipeline_doc': pipeline_doc,
                'initial_context': initial_context,
                'pipeline_path': pipeline_path,
                'secure_env_enabled': True,
                'default_env_vars': ['PATH', 'HOME', 'USER', 'PYTHONPATH', 'VIRTUAL_ENV', 'PLUGPIPE_CONFIG']
            }
            
            # Handle async context resolver service
            import asyncio
            try:
                # Check if we're already in an event loop
                loop = asyncio.get_running_loop()
                # We're in an async context but this function is sync
                # Create a new thread to run the async function
                import concurrent.futures
                import threading
                
                def run_async():
                    return asyncio.run(self.services['context_resolver'].process({}, resolver_config))
                
                with concurrent.futures.ThreadPoolExecutor() as executor:
                    future = executor.submit(run_async)
                    result = future.result()
            except RuntimeError:
                # No event loop running, we can use asyncio.run
                result = asyncio.run(self.services['context_resolver'].process({}, resolver_config))
            
            if result.get('success'):
                logger.info("Pipeline context initialized successfully")
            else:
                logger.error(f"Context initialization failed: {result.get('error')}")
            
            return result
            
        except Exception as e:
            logger.error(f"Context resolver service failed: {e}")
            if self.enable_service_fallback:
                return self._fallback_context_initialization(
                    pipeline_doc, initial_context, pipeline_path
                )
            raise
    
    def _execute_pipeline_steps(
        self,
        steps: List[Dict[str, Any]],
        context: Dict[str, Any],
        registry: Any,
        enterprise_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Execute pipeline steps using Execution Engine service."""
        try:
            if not self.services['execution_engine']:
                return self._fallback_step_execution(steps, context, registry, enterprise_analysis)
            
            engine_config = {
                'steps': steps,
                'context': context,
                'registry': registry,
                'enterprise_enabled': self.enterprise_enabled,
                'global_retries': self.config.get('global_retries', 1),
                'global_timeout': self.config.get('global_timeout', 0),
                'use_external_orchestrator': self.config.get('use_external_orchestrator', False),
                'orchestrator_type': self.config.get('orchestrator_type', 'airflow')
            }
            
            # Auto-detect execution mode if enterprise features are required
            if enterprise_analysis.get('requires_enterprise') and not self.enterprise_enabled:
                return {
                    'success': False,
                    'error': 'Enterprise features detected but not enabled'
                }
            
            result = self.services['execution_engine'].process({}, engine_config)
            
            if result.get('success'):
                logger.info(f"Pipeline execution completed in {result.get('execution_mode')} mode")
            else:
                logger.error(f"Pipeline execution failed: {result.get('error')}")
            
            return result
            
        except Exception as e:
            logger.error(f"Execution engine service failed: {e}")
            if self.enable_service_fallback:
                return self._fallback_step_execution(steps, context, registry, enterprise_analysis)
            raise
    
    def _materialize_results(
        self,
        results: Dict[str, Any],
        context: Dict[str, Any],
        execution_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Materialize results using Result Materializer service."""
        try:
            if not self.services['result_materializer']:
                return self._fallback_result_materialization(results, context, execution_metadata)
            
            materializer_config = {
                'operation': 'materialize_pipeline',
                'results': results,
                'context': context,
                'execution_metadata': execution_metadata,
                'materialize_dir': self.materialize_dir,
                'save_context': True,
                'save_summary': True,
                'output_formats': ['json', 'yaml'],
                'validate_results': True,
                'aggregate_results': True,
                'create_manifest': True
            }
            
            result = self.services['result_materializer'].process({}, materializer_config)
            
            if result.get('success'):
                logger.info(f"Results materialized to: {result.get('output_directory')}")
            else:
                logger.warning(f"Result materialization failed: {result.get('error')}")
            
            return result
            
        except Exception as e:
            logger.error(f"Result materializer service failed: {e}")
            if self.enable_service_fallback:
                return self._fallback_result_materialization(results, context, execution_metadata)
            raise
    
    def _fallback_to_enhanced_orchestrator(
        self, 
        pipeline_yaml_path: str, 
        registry: Any, 
        initial_context: Optional[Dict[str, Any]],
        **kwargs
    ) -> Dict[str, Any]:
        """Fallback to enhanced orchestrator if available."""
        try:
            from cores.enhanced_orchestrator import run_enhanced_pipeline
            logger.info("Using Enhanced Orchestrator fallback")
            
            return run_enhanced_pipeline(
                pipeline_yaml_path, registry, 
                initial_context=initial_context,
                materialize=self.materialize,
                materialize_dir=self.materialize_dir,
                enterprise_enabled=self.enterprise_enabled,
                **kwargs
            )
        except ImportError as e:
            logger.warning(f"Enhanced orchestrator not available: {e}")
            raise
    
    def _fallback_pipeline_loading(
        self, 
        pipeline_path: str, 
        secret_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback pipeline loading using core utilities."""
        try:
            from shares.loader import load_pipeline_yaml
            from cores.secret_manager import inject_secrets_into_pipeline
            
            logger.info("Using fallback pipeline loading")
            
            pipeline_doc = load_pipeline_yaml(
                pipeline_path, 
                config_path=self.config.get('config_path', 'config.yaml')
            )
            
            if secret_config:
                pipeline_doc = inject_secrets_into_pipeline(pipeline_doc, secret_config)
            
            return {
                'success': True,
                'status': 'success',
                'pipeline_doc': pipeline_doc,
                'validation_result': {'valid': True, 'errors': [], 'warnings': []},
                'enterprise_analysis': {'requires_enterprise': False, 'compatibility_level': 'oss_compatible'},
                'pipeline_path': pipeline_path
            }
            
        except Exception as e:
            logger.error(f"Fallback pipeline loading failed: {e}")
            return {
                'success': False,
                'status': 'error',
                'error': str(e),
                'pipeline_path': pipeline_path
            }
    
    def _fallback_context_initialization(
        self, 
        pipeline_doc: Dict[str, Any],
        initial_context: Optional[Dict[str, Any]],
        pipeline_path: str
    ) -> Dict[str, Any]:
        """Fallback context initialization."""
        try:
            logger.info("Using fallback context initialization")
            
            if initial_context and isinstance(initial_context, dict):
                context = initial_context.copy()
            else:
                context = {
                    "inputs": pipeline_doc.get("inputs", {}),
                    "step_outputs": {},
                    "pipeline_path": pipeline_path
                }
            
            # Add execution ID
            execution_id = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S") + "_fallback"
            context["execution_id"] = execution_id
            
            return {
                'success': True,
                'context': context
            }
            
        except Exception as e:
            logger.error(f"Fallback context initialization failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _fallback_step_execution(
        self,
        steps: List[Dict[str, Any]],
        context: Dict[str, Any],
        registry: Any,
        enterprise_analysis: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback to monolithic orchestrator for step execution."""
        try:
            logger.info("Using fallback step execution (monolithic orchestrator)")
            
            # Import monolithic orchestrator
            from cores.orchestrator import run_pipeline
            
            # Create temporary pipeline document
            temp_pipeline_doc = {
                'pipeline': steps,
                'inputs': context.get('inputs', {}),
                'metadata': context.get('pipeline_metadata', {})
            }
            
            # Save temporary pipeline
            import tempfile
            import yaml
            with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
                yaml.safe_dump(temp_pipeline_doc, f)
                temp_path = f.name
            
            try:
                # Execute using monolithic orchestrator
                result = run_pipeline(
                    temp_path, registry, 
                    initial_context=context,
                    materialize=False,  # We'll handle materialization separately
                    enterprise_enabled=self.enterprise_enabled,
                    use_enhanced_orchestrator=False  # Force legacy mode
                )
                
                # Extract results from context
                if isinstance(result, dict) and 'step_outputs' in result:
                    return {
                        'success': True,
                        'results': result['step_outputs'],
                        'execution_mode': 'fallback_monolithic',
                        'total_steps': len(steps),
                        'completed_steps': len(result.get('step_outputs', {}))
                    }
                else:
                    return {
                        'success': False,
                        'error': 'Invalid result format from monolithic orchestrator'
                    }
                    
            finally:
                # Clean up temporary file
                try:
                    os.unlink(temp_path)
                except:
                    pass
                    
        except Exception as e:
            logger.error(f"Fallback step execution failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _fallback_result_materialization(
        self,
        results: Dict[str, Any],
        context: Dict[str, Any],
        execution_metadata: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Fallback result materialization using core utilities."""
        try:
            logger.info("Using fallback result materialization")
            
            import yaml
            from pathlib import Path
            
            # Create output directory
            execution_id = context.get('execution_id', 'unknown')
            output_dir = Path(self.materialize_dir) / execution_id
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Save results
            results_path = output_dir / 'results.json'
            with open(results_path, 'w') as f:
                import json
                json.dump(results, f, indent=2, default=str)
            
            # Save context
            context_path = output_dir / 'final_context.yaml'
            with open(context_path, 'w') as f:
                yaml.safe_dump(context, f, default_flow_style=False)
            
            return {
                'success': True,
                'output_directory': str(output_dir),
                'results_path': str(results_path),
                'context_path': str(context_path)
            }
            
        except Exception as e:
            logger.error(f"Fallback result materialization failed: {e}")
            return {
                'success': False,
                'error': str(e)
            }
    
    def _create_error_result(self, error_message: str, pipeline_path: str) -> Dict[str, Any]:
        """Create standardized error result."""
        return {
            'success': False,
            'error': error_message,
            'pipeline_path': pipeline_path,
            'execution_mode': 'modular',
            'execution_metadata': {
                'execution_start': datetime.datetime.utcnow().isoformat(),
                'execution_end': datetime.datetime.utcnow().isoformat(),
                'duration_seconds': 0,
                'total_steps': 0,
                'completed_steps': 0,
                'services_used': list(self.services.keys())
            },
            'step_outputs': {},
            'inputs': {}
        }


# Plugin metadata for PlugPipe registration
plug_metadata = {
    "name": "modular_orchestrator",
    "version": "1.0.0",
    "owner": "plugpipe-orchestration",
    "status": "production",
    "description": "Modular Orchestrator Service - replaces monolithic orchestrator with properly separated services for improved maintainability and testability",
    "category": "orchestration",
    "tags": ["orchestration", "modular", "service-composition", "pipeline", "separation-of-concerns"],
    "input_schema": {
        "type": "object",
        "properties": {
            "pipeline_yaml_path": {"type": "string", "description": "Path to pipeline YAML file"},
            "registry": {"description": "Plugin registry instance"},
            "initial_context": {"type": "object", "description": "Optional initial context"},
            "enterprise_enabled": {"type": "boolean", "description": "Enable enterprise features"},
            "materialize": {"type": "boolean", "description": "Enable result materialization"},
            "materialize_dir": {"type": "string", "description": "Result materialization directory"},
            "use_enhanced_orchestrator": {"type": "boolean", "description": "Fallback to enhanced orchestrator"},
            "service_timeout": {"type": "integer", "description": "Service operation timeout"},
            "enable_service_fallback": {"type": "boolean", "description": "Enable fallback mechanisms"}
        },
        "required": ["pipeline_yaml_path", "registry"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean", "description": "Execution success indicator"},
            "execution_mode": {"type": "string", "description": "Execution mode used"},
            "pipeline_path": {"type": "string", "description": "Path to executed pipeline"},
            "results": {"type": "object", "description": "Step execution results"},
            "context": {"type": "object", "description": "Final pipeline context"},
            "execution_metadata": {"type": "object", "description": "Execution metadata and timing"},
            "materialization": {"type": "object", "description": "Result materialization info"},
            "validation_result": {"type": "object", "description": "Pipeline validation results"},
            "enterprise_analysis": {"type": "object", "description": "Enterprise feature analysis"},
            "error": {"type": "string", "description": "Error message if execution failed"}
        }
    },
    "revolutionary_capabilities": [
        "service_oriented_orchestration",
        "modular_architecture_composition",
        "separation_of_concerns_execution",
        "backward_compatibility_maintenance"
    ]
}


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin process function."""
    try:
        # Initialize the modular orchestrator
        orchestrator = ModularOrchestrator(cfg)
        
        # Extract required parameters
        pipeline_yaml_path = cfg.get('pipeline_yaml_path')
        registry = cfg.get('registry')
        
        if not pipeline_yaml_path:
            return {
                'success': False,
                'error': 'pipeline_yaml_path is required'
            }
        
        if not registry:
            return {
                'success': False,
                'error': 'registry is required'
            }
        
        # Extract optional parameters
        initial_context = cfg.get('initial_context')
        
        # Execute the pipeline
        # Remove parameters that are already passed explicitly to avoid conflicts
        kwargs = cfg.copy()
        
        # Remove all potential duplicate parameters
        parameters_to_remove = [
            'pipeline_yaml_path', 'registry', 'initial_context',
            'pipeline_yaml_file', 'yaml_path', 'pipe_yaml', 'pipe_path'  # potential variants
        ]
        
        for param in parameters_to_remove:
            kwargs.pop(param, None)
        
        # Filter out None values and non-serializable objects
        filtered_kwargs = {}
        for key, value in kwargs.items():
            if value is not None and not callable(value):
                filtered_kwargs[key] = value
        
        result = orchestrator.run_pipeline(
            pipeline_yaml_path, registry, initial_context, **filtered_kwargs
        )
        
        return result
        
    except Exception as e:
        logger.error(f"Modular Orchestrator process failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'execution_mode': 'modular'
        }


# Direct execution for testing
if __name__ == "__main__":
    import json
    
    # Test configuration
    test_config = {
        'pipeline_yaml_path': 'pipe_specs/sample_pipeline.yaml',
        'enterprise_enabled': True,
        'materialize': True,
        'materialize_dir': '/tmp/test_modular_runs'
    }
    
    # Note: This would fail without a real registry, but shows the interface
    print("Modular Orchestrator Service Plugin - Interface Test")
    print(json.dumps(plug_metadata, indent=2))