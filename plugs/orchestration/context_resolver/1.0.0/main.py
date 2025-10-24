#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Context Resolver Service Plugin

This service plugin handles context resolution, environment setup, and parameter resolution
with proper separation of concerns. Provides secure environment isolation and template
resolution while following PlugPipe principles.

Key Responsibilities:
- Context initialization and management
- Secure environment variable resolution
- Template parameter resolution
- Secret injection and handling
- Context passing between pipeline steps
- Environment isolation for security

Following PlugPipe Architecture:
- Reuses existing template resolution utilities
- Leverages security-first environment isolation
- Integrates with secret management systems
- Provides clean service interface for orchestrator composition
"""

import os
import copy
import logging
from typing import Dict, List, Any, Optional
import uuid
import datetime

# Import existing PlugPipe utilities following "reuse everything" principle
from shares.utils.template_resolver import resolve_param

logger = logging.getLogger(__name__)

class ContextResolver:
    """
    Context Resolver Service
    
    Handles all context resolution, environment setup, and parameter processing
    with proper security and separation of concerns.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.secure_env_enabled = config.get('secure_env_enabled', True)
        self.default_env_vars = config.get('default_env_vars', [
            'PATH', 'HOME', 'USER', 'PYTHONPATH', 'VIRTUAL_ENV', 'PLUGPIPE_CONFIG'
        ])
        
        # Initialize secure environment isolation
        self.env_isolation_module = None
        if self.secure_env_enabled:
            self._initialize_secure_environment()
        
        logger.info(f"Context Resolver initialized with secure_env_enabled: {self.secure_env_enabled}")
    
    def _initialize_secure_environment(self):
        """Initialize secure environment isolation module."""
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location(
                "environment_isolation", 
                "plugs/security/environment_isolation/1.0.0/main.py"
            )
            self.env_isolation_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(self.env_isolation_module)
            logger.info("Secure environment isolation loaded successfully")
        except Exception as e:
            logger.error(f"Failed to load secure environment isolation: {e}")
            if self.secure_env_enabled:
                raise RuntimeError(
                    "🚨 SECURITY ERROR: Environment isolation plugin not available. "
                    "This is a critical security requirement."
                )
    
    async def initialize_pipeline_context(
        self, 
        pipeline_doc: Dict[str, Any],
        initial_context: Optional[Dict[str, Any]] = None,
        pipeline_path: str = ""
    ) -> Dict[str, Any]:
        """
        Initialize the main pipeline execution context.
        
        Args:
            pipeline_doc: Loaded pipeline document
            initial_context: Optional initial context to extend
            pipeline_path: Path to pipeline file
            
        Returns:
            Initialized pipeline context
        """
        try:
            # Create base context structure
            if not initial_context or not isinstance(initial_context, dict):
                context = {
                    "inputs": pipeline_doc.get("inputs", {}),
                    "step_outputs": {},
                    "pipeline_path": pipeline_path
                }
            else:
                # Preserve existing context structure
                if set(("inputs", "step_outputs", "pipeline_path")).issubset(initial_context.keys()):
                    context = copy.deepcopy(initial_context)
                else:
                    context = {
                        "inputs": dict(initial_context),
                        "step_outputs": {},
                        "pipeline_path": pipeline_path
                    }
            
            # Add pipeline metadata
            context["pipeline_metadata"] = {
                "name": pipeline_doc.get("metadata", {}).get("name", "unnamed"),
                "version": pipeline_doc.get("metadata", {}).get("version", "1.0.0"),
                "description": pipeline_doc.get("description", ""),
                "loaded_at": datetime.datetime.utcnow().isoformat()
            }
            
            # Generate execution ID
            context["execution_id"] = datetime.datetime.utcnow().strftime("%Y%m%dT%H%M%S") + "_" + str(uuid.uuid4())[:8]
            
            # Initialize secure environment context
            if self.secure_env_enabled and self.env_isolation_module:
                env_context = await self._create_secure_environment_context(
                    plugin_id="pipeline_context",
                    allowed_vars=set(self.default_env_vars),
                    additional_vars=pipeline_doc.get("env", {})
                )
                context["env"] = env_context
            else:
                # Fallback to limited environment variables
                context["env"] = self._create_limited_environment_context()
            
            # Handle secrets if present in pipeline
            if "secrets" in pipeline_doc:
                context["secrets"] = resolve_param(pipeline_doc["secrets"], context)
            
            logger.info(f"Pipeline context initialized: execution_id={context['execution_id']}")
            return context
            
        except Exception as e:
            logger.error(f"Failed to initialize pipeline context: {e}")
            raise
    
    def resolve_step_context(
        self, 
        step: Dict[str, Any], 
        pipeline_context: Dict[str, Any],
        step_index: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Resolve context for individual step execution.
        
        Args:
            step: Step definition
            pipeline_context: Main pipeline context
            step_index: Optional step index for tracking
            
        Returns:
            Resolved step context
        """
        try:
            # Create step-specific context
            step_context = copy.deepcopy(pipeline_context)
            step_id = step.get("id", f"step_{step_index}")
            
            # Create secure environment scope for this step
            if self.secure_env_enabled and self.env_isolation_module:
                env_context = self._create_secure_environment_context(
                    plugin_id=step.get("uses", step_id),
                    allowed_vars=set(step.get("env_vars", self.default_env_vars)),
                    additional_vars=step.get("env", {})
                )
                step_context["env"] = env_context
                step_context["_secure_scope_id"] = f"step_{step_id}_{pipeline_context['execution_id']}"
            
            # Resolve step parameters
            for key in ("input", "env", "config", "with"):
                if key in step:
                    step[key] = resolve_param(step[key], step_context)
            
            # Handle step-specific secrets
            if "secrets" in step:
                step_context["secrets"] = resolve_param(step["secrets"], step_context)
            elif "secrets" in pipeline_context:
                step_context["secrets"] = resolve_param(pipeline_context["secrets"], step_context)
            
            # Add step metadata
            step_context["current_step"] = {
                "id": step_id,
                "index": step_index,
                "plugin": step.get("uses"),
                "type": step.get("type"),
                "resolved_at": datetime.datetime.utcnow().isoformat()
            }
            
            logger.debug(f"Step context resolved for: {step_id}")
            return step_context
            
        except Exception as e:
            logger.error(f"Failed to resolve step context for {step.get('id', 'unknown')}: {e}")
            raise
    
    def resolve_foreach_context(
        self, 
        step: Dict[str, Any], 
        base_context: Dict[str, Any],
        item: Any,
        iteration: int
    ) -> Dict[str, Any]:
        """
        Resolve context for foreach loop iterations.
        
        Args:
            step: Step definition with foreach
            base_context: Base step context
            item: Current iteration item
            iteration: Iteration number
            
        Returns:
            Resolved foreach context
        """
        try:
            # Create iteration-specific context
            item_context = copy.deepcopy(base_context)
            item_context["item"] = item
            item_context["iteration"] = iteration
            
            # Create secure environment for iteration
            if self.secure_env_enabled and self.env_isolation_module:
                env_context = self._create_secure_environment_context(
                    plugin_id=f"{step.get('uses', 'unknown')}_iter_{iteration}",
                    allowed_vars=set(step.get("env_vars", self.default_env_vars)),
                    additional_vars=step.get("env", {})
                )
                item_context["env"] = env_context
                item_context["_secure_scope_id"] = f"foreach_{step['id']}_{iteration}_{base_context['execution_id']}"
            
            # Resolve parameters with item context
            step_iter = copy.deepcopy(step)
            for key in ("input", "env", "config", "with"):
                if key in step_iter:
                    step_iter[key] = resolve_param(step_iter[key], item_context)
            
            # Handle iteration-specific secrets
            if "secrets" in step_iter:
                item_context["secrets"] = resolve_param(step_iter["secrets"], item_context)
            
            # Update step metadata for iteration
            item_context["current_step"]["iteration"] = iteration
            item_context["current_step"]["item"] = item
            
            logger.debug(f"Foreach context resolved for iteration {iteration}")
            return item_context, step_iter
            
        except Exception as e:
            logger.error(f"Failed to resolve foreach context for iteration {iteration}: {e}")
            raise
    
    async def _create_secure_environment_context(
        self, 
        plugin_id: str, 
        allowed_vars: set,
        additional_vars: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Create secure environment context using environment isolation."""
        try:
            if not self.env_isolation_module:
                return self._create_limited_environment_context()
            
            # Create secure environment scope
            import inspect
            if inspect.iscoroutinefunction(self.env_isolation_module.process):
                env_result = await self.env_isolation_module.process({
                    "operation": "create_scope",
                    "plugin_id": plugin_id,
                    "scope_id": f"{plugin_id}_{uuid.uuid4().hex[:8]}",
                    "allowed_vars": list(allowed_vars) if allowed_vars else self.default_env_vars,
                    "additional_vars": additional_vars or {}
                }, {})
            else:
                env_result = self.env_isolation_module.process({
                    "operation": "create_scope",
                    "plugin_id": plugin_id,
                    "scope_id": f"{plugin_id}_{uuid.uuid4().hex[:8]}",
                    "allowed_vars": list(allowed_vars) if allowed_vars else self.default_env_vars,
                    "additional_vars": additional_vars or {}
                }, {})
            
            if env_result.get("success"):
                # Try to get environment_context, fallback to env_context or limited context
                env_context = env_result.get("environment_context") 
                if env_context is None:
                    env_context = env_result.get("env_context")
                if env_context is None:
                    logger.warning("Environment isolation succeeded but returned no environment context, using fallback")
                    return self._create_limited_environment_context()
                return env_context
            else:
                logger.warning(f"Failed to create secure environment: {env_result.get('error')}")
                return self._create_limited_environment_context()
                
        except Exception as e:
            logger.error(f"Secure environment creation failed: {e}")
            return self._create_limited_environment_context()
    
    def _create_limited_environment_context(self) -> Dict[str, Any]:
        """Create limited environment context as fallback."""
        return {
            var: os.environ.get(var, "") 
            for var in self.default_env_vars
        }
    
    def merge_step_results(
        self, 
        context: Dict[str, Any], 
        step_id: str, 
        step_result: Any
    ) -> Dict[str, Any]:
        """
        Merge step execution results back into pipeline context.
        
        Args:
            context: Pipeline context
            step_id: Step identifier
            step_result: Step execution result
            
        Returns:
            Updated context
        """
        try:
            # Update step outputs
            context["step_outputs"][step_id] = step_result
            
            # Update execution metadata
            if "execution_metadata" not in context:
                context["execution_metadata"] = {}
            
            context["execution_metadata"]["last_completed_step"] = step_id
            context["execution_metadata"]["completed_steps"] = list(context["step_outputs"].keys())
            context["execution_metadata"]["updated_at"] = datetime.datetime.utcnow().isoformat()
            
            logger.debug(f"Step result merged for: {step_id}")
            return context
            
        except Exception as e:
            logger.error(f"Failed to merge step results for {step_id}: {e}")
            raise


# Plugin metadata for PlugPipe registration
plug_metadata = {
    "name": "context_resolver",
    "version": "1.0.0",
    "owner": "plugpipe-orchestration",
    "status": "production",
    "description": "Context Resolver Service - handles context resolution, environment setup, and parameter resolution with security-first approach",
    "category": "orchestration",
    "tags": ["orchestration", "context", "resolution", "security", "service"],
    "input_schema": {
        "type": "object",
        "properties": {
            "operation": {
                "type": "string",
                "enum": ["initialize_pipeline", "resolve_step", "resolve_foreach", "merge_results"],
                "description": "Context resolution operation to perform"
            },
            "pipeline_doc": {"type": "object", "description": "Pipeline document"},
            "initial_context": {"type": "object", "description": "Initial context"},
            "pipeline_path": {"type": "string", "description": "Pipeline file path"},
            "step": {"type": "object", "description": "Step definition"},
            "step_index": {"type": "integer", "description": "Step index"},
            "item": {"description": "Foreach iteration item"},
            "iteration": {"type": "integer", "description": "Foreach iteration number"},
            "step_id": {"type": "string", "description": "Step identifier"},
            "step_result": {"description": "Step execution result"},
            "secure_env_enabled": {"type": "boolean", "description": "Enable secure environment isolation"}
        }
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean", "description": "Operation success indicator"},
            "context": {"type": "object", "description": "Resolved context"},
            "step_context": {"type": "object", "description": "Step-specific context"},
            "resolved_step": {"type": "object", "description": "Step with resolved parameters"},
            "error": {"type": "string", "description": "Error message if operation failed"}
        }
    },
    "revolutionary_capabilities": [
        "modular_context_resolution",
        "security_first_environment_isolation",
        "parameter_resolution_service",
        "context_lifecycle_management"
    ]
}


async def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin process function."""
    try:
        # Initialize the context resolver service
        context_resolver = ContextResolver(cfg)
        
        # Determine operation to perform
        operation = cfg.get('operation', 'initialize_pipeline')
        
        if operation == 'initialize_pipeline':
            pipeline_doc = cfg.get('pipeline_doc', {})
            initial_context = cfg.get('initial_context')
            pipeline_path = cfg.get('pipeline_path', '')
            
            resolved_context = await context_resolver.initialize_pipeline_context(
                pipeline_doc, initial_context, pipeline_path
            )
            
            return {
                'success': True,
                'context': resolved_context,
                'operation': operation
            }
        
        elif operation == 'resolve_step':
            step = cfg.get('step', {})
            pipeline_context = cfg.get('pipeline_context', {})
            step_index = cfg.get('step_index')
            
            step_context = context_resolver.resolve_step_context(
                step, pipeline_context, step_index
            )
            
            return {
                'success': True,
                'step_context': step_context,
                'operation': operation
            }
        
        elif operation == 'resolve_foreach':
            step = cfg.get('step', {})
            base_context = cfg.get('base_context', {})
            item = cfg.get('item')
            iteration = cfg.get('iteration', 0)
            
            item_context, resolved_step = context_resolver.resolve_foreach_context(
                step, base_context, item, iteration
            )
            
            return {
                'success': True,
                'item_context': item_context,
                'resolved_step': resolved_step,
                'operation': operation
            }
        
        elif operation == 'merge_results':
            context = cfg.get('context', {})
            step_id = cfg.get('step_id', '')
            step_result = cfg.get('step_result')
            
            updated_context = context_resolver.merge_step_results(
                context, step_id, step_result
            )
            
            return {
                'success': True,
                'context': updated_context,
                'operation': operation
            }
        
        else:
            return {
                'success': False,
                'error': f'Unknown operation: {operation}',
                'supported_operations': ['initialize_pipeline', 'resolve_step', 'resolve_foreach', 'merge_results']
            }
        
    except Exception as e:
        logger.error(f"Context Resolver process failed: {e}")
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
        'operation': 'initialize_pipeline',
        'pipeline_doc': {
            'inputs': {'test': 'value'},
            'env': {'TEST_VAR': 'test'},
            'metadata': {'name': 'test_pipeline'}
        },
        'pipeline_path': 'test_pipeline.yaml',
        'secure_env_enabled': False  # For testing without isolation
    }
    
    result = process({}, test_config)
    print(json.dumps(result, indent=2, default=str))