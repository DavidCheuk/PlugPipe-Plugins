#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Execution Engine Service Plugin

This service plugin handles both DAG and linear pipeline execution with proper separation of concerns.
Provides comprehensive execution strategies, step management, and flow control while following
PlugPipe principles and leveraging existing orchestration plugins.

Key Responsibilities:
- DAG execution with dependency resolution
- Linear execution with step-by-step processing
- Step execution orchestration and error handling
- Flow control (conditional steps, loops, branching)
- Resume/pause functionality
- Enterprise feature execution

Following PlugPipe Architecture:
- Reuses existing step execution utilities
- Leverages existing orchestration workflow plugins (Airflow, Argo)
- Integrates with condition evaluation and template systems
- Provides clean service interface for orchestrator composition
"""

import os
import copy
import logging
import asyncio
from typing import Dict, List, Any, Optional, Set, Tuple
from enum import Enum
from dataclasses import dataclass

# Import existing PlugPipe utilities following "reuse everything" principle
from shares.utils.step_executor import run_step, pause_step
from shares.utils.safe_evaluator import evaluate_pipeline_condition, evaluate_foreach_items

logger = logging.getLogger(__name__)

class ExecutionMode(Enum):
    LINEAR = "linear"
    DAG = "dag"
    HYBRID = "hybrid"

@dataclass
class ExecutionResult:
    step_id: str
    result: Any
    status: str
    duration: float = 0.0
    error: Optional[str] = None

class ExecutionEngine:
    """
    Execution Engine Service
    
    Handles both DAG and linear pipeline execution with proper flow control,
    error handling, and integration with existing orchestration systems.
    """
    
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.enterprise_enabled = config.get('enterprise_enabled', False)
        self.global_retries = config.get('global_retries', 1)
        self.global_timeout = config.get('global_timeout', 0)
        self.use_external_orchestrator = config.get('use_external_orchestrator', False)
        self.orchestrator_type = config.get('orchestrator_type', 'airflow')
        
        # Initialize external orchestrator if configured
        self.external_orchestrator = None
        if self.use_external_orchestrator:
            self._initialize_external_orchestrator()
        
        logger.info(f"Execution Engine initialized with enterprise_enabled: {self.enterprise_enabled}")
    
    def _initialize_external_orchestrator(self):
        """Initialize external orchestrator plugin if configured."""
        try:
            if self.orchestrator_type == 'airflow':
                # Use existing Airflow workflow runner plugin
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "airflow_runner", 
                    "plugs/orchestration/workflow/airflow_workflow_runner/1.0.0/main.py"
                )
                orchestrator_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(orchestrator_module)
                self.external_orchestrator = orchestrator_module
                logger.info("Airflow orchestrator integration loaded")
                
            elif self.orchestrator_type == 'argo':
                # Use existing Argo workflow runner plugin
                import importlib.util
                spec = importlib.util.spec_from_file_location(
                    "argo_runner", 
                    "plugs/orchestration/workflow/argo_workflow_runner/1.0.0/main.py"
                )
                orchestrator_module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(orchestrator_module)
                self.external_orchestrator = orchestrator_module
                logger.info("Argo orchestrator integration loaded")
                
        except Exception as e:
            logger.warning(f"Failed to initialize external orchestrator {self.orchestrator_type}: {e}")
            self.use_external_orchestrator = False
    
    def execute_pipeline(
        self, 
        steps: List[Dict[str, Any]], 
        context: Dict[str, Any],
        registry: Any,
        execution_mode: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Execute pipeline using appropriate execution strategy.
        
        Args:
            steps: Pipeline steps to execute
            context: Execution context
            registry: Plugin registry
            execution_mode: Optional execution mode override
            
        Returns:
            Execution results
        """
        try:
            # Determine execution mode
            if execution_mode:
                mode = ExecutionMode(execution_mode)
            else:
                mode = self._determine_execution_mode(steps)
            
            logger.info(f"Executing pipeline in {mode.value} mode with {len(steps)} steps")
            
            # Route to appropriate executor
            if mode == ExecutionMode.DAG:
                if not self.enterprise_enabled:
                    raise RuntimeError(
                        "[ERROR] Enterprise-only DAG fields ('next', 'branches', 'join') found in pipeline. "
                        "Please upgrade to PlugPipe Enterprise or enable enterprise features."
                    )
                return self._execute_dag_pipeline(steps, context, registry)
            else:
                return self._execute_linear_pipeline(steps, context, registry)
                
        except Exception as e:
            logger.error(f"Pipeline execution failed: {e}")
            return {
                'success': False,
                'error': str(e),
                'execution_mode': execution_mode,
                'results': {}
            }
    
    def _determine_execution_mode(self, steps: List[Dict[str, Any]]) -> ExecutionMode:
        """Determine appropriate execution mode based on step definitions."""
        dag_features = ['next', 'branches', 'join']
        
        for step in steps:
            if any(feature in step for feature in dag_features):
                return ExecutionMode.DAG
        
        return ExecutionMode.LINEAR
    
    def _execute_dag_pipeline(
        self, 
        steps: List[Dict[str, Any]], 
        context: Dict[str, Any],
        registry: Any
    ) -> Dict[str, Any]:
        """
        Execute pipeline using DAG execution strategy.
        
        Uses existing DAG logic but with proper service separation.
        """
        try:
            # Use external orchestrator if available and configured
            if self.use_external_orchestrator and self.external_orchestrator:
                return self._execute_with_external_orchestrator(steps, context, registry)
            
            # Build DAG structure
            graph = self._build_dag(steps)
            
            # Find entry point
            entry_step = self._find_dag_entry_point(steps)
            
            # Execute DAG
            results = {}
            visited = set()
            
            self._walk_dag(
                graph, entry_step, registry, context,
                results, visited
            )
            
            return {
                'success': True,
                'execution_mode': 'dag',
                'results': results,
                'total_steps': len(steps),
                'completed_steps': len(results)
            }
            
        except Exception as e:
            logger.error(f"DAG execution failed: {e}")
            raise
    
    def _build_dag(self, steps: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Build DAG structure from step definitions."""
        graph = {}
        
        for step in steps:
            step_id = step["id"]
            edges = []
            
            # Handle 'next' field
            if "next" in step:
                next_refs = step["next"]
                if isinstance(next_refs, list):
                    for nxt in next_refs:
                        if isinstance(nxt, dict):
                            edges.append({"target": nxt["target"], "when": nxt.get("when")})
                        else:
                            edges.append({"target": nxt, "when": None})
                else:
                    edges.append({"target": next_refs, "when": None})
            
            # Handle 'branches' field
            if "branches" in step:
                branches = step["branches"]
                if isinstance(branches, dict):
                    for condition, target in branches.items():
                        edges.append({"target": target, "when": condition})
            
            graph[step_id] = {
                "step": step,
                "edges": edges,
                "join": step.get("join", False)
            }
        
        return graph
    
    def _find_dag_entry_point(self, steps: List[Dict[str, Any]]) -> str:
        """Find the entry point for DAG execution."""
        # Look for explicit start step
        for step in steps:
            if step.get("id") == "start":
                return "start"
        
        # Use first step as entry point
        return steps[0]["id"]
    
    def _walk_dag(
        self, 
        graph: Dict[str, Any], 
        entry_id: str, 
        registry: Any, 
        context: Dict[str, Any],
        results: Dict[str, Any], 
        visited: Set[str]
    ):
        """
        Walk DAG and execute steps with dependency resolution.
        
        This is the core DAG execution logic with proper error handling.
        """
        if entry_id in visited:
            return
        
        visited.add(entry_id)
        node = graph[entry_id]
        step = node["step"]
        
        logger.info(f"[DAG] Executing step: {entry_id}")
        
        # Execute step
        step_result = self._execute_single_step(step, registry, context)
        results[entry_id] = step_result
        
        # Update context with step result
        context["step_outputs"][entry_id] = step_result
        
        # Handle join logic
        if step.get("join"):
            logger.info(f"[DAG] Join step completed: {entry_id}")
            return
        
        # Process edges (next steps)
        for edge in node["edges"]:
            condition = edge.get("when")
            
            # Evaluate condition if present
            if condition:
                eval_context = copy.deepcopy(context)
                eval_context["result"] = step_result.get("result")
                
                try:
                    # First resolve template variables in the condition
                    from shares.utils.template_resolver import resolve_param
                    resolved_condition = resolve_param(str(condition), eval_context)
                    logger.debug(f"[DAG] Resolved edge condition '{condition}' to '{resolved_condition}'")
                    
                    # Then evaluate the resolved condition
                    if not evaluate_pipeline_condition(str(resolved_condition), eval_context):
                        logger.info(f"[DAG] Skipping edge to {edge['target']} due to condition: {condition}")
                        continue
                except Exception as e:
                    logger.warning(f"[DAG] Failed to evaluate edge condition '{condition}': {e}")
                    continue
            
            # Execute next step
            next_id = edge["target"]
            self._walk_dag(
                graph, next_id, registry, context,
                results, visited
            )
    
    def _execute_linear_pipeline(
        self, 
        steps: List[Dict[str, Any]], 
        context: Dict[str, Any],
        registry: Any
    ) -> Dict[str, Any]:
        """
        Execute pipeline using linear execution strategy.
        
        Handles step-by-step execution with proper flow control.
        """
        try:
            results = {}
            summary = []
            
            # Resume logic handling
            resume_mode, skip_to_step = self._check_resume_mode(context)
            skip_steps = resume_mode
            
            for idx, step in enumerate(steps):
                step_id = step["id"]
                logger.info(f"[Linear] Processing step: {step_id}")
                
                # Handle resume logic
                if resume_mode:
                    if skip_steps and step_id != skip_to_step:
                        logger.info(f"[Linear] Skipping step {step_id} (resume mode)")
                        continue
                    skip_steps = False
                    
                    # Skip pause steps on resume
                    if step.get("type") == "pause" or step.get("uses") == "pause_plugin":
                        logger.info(f"[Linear] Skipping pause step {step_id} on resume")
                        continue
                
                # Handle pause steps
                if step.get("type") == "pause" or step.get("uses") == "pause_plugin":
                    logger.info(f"[Linear] Pausing at step: {step_id}")
                    self._handle_pause_step(step, context, idx, steps)
                    break
                
                # Handle conditional steps
                if not self._should_execute_step(step, context):
                    summary.append({"id": step_id, "status": "skipped", "reason": "condition_false"})
                    continue
                
                # Handle foreach loops
                if "foreach" in step:
                    loop_results = self._execute_foreach_step(step, context, registry)
                    results[step_id] = loop_results
                    context["step_outputs"][step_id] = loop_results
                    continue
                
                # Execute regular step
                step_result = self._execute_single_step(step, registry, context)
                results[step_id] = step_result
                context["step_outputs"][step_id] = step_result
                
                # Handle exit conditions
                if self._should_exit_pipeline(step, context):
                    summary.append({"id": step_id, "status": "exited", "reason": "exit_condition"})
                    break
            
            return {
                'success': True,
                'execution_mode': 'linear',
                'results': results,
                'summary': summary,
                'total_steps': len(steps),
                'completed_steps': len(results)
            }
            
        except Exception as e:
            logger.error(f"Linear execution failed: {e}")
            raise
    
    def _execute_single_step(
        self, 
        step: Dict[str, Any], 
        registry: Any, 
        context: Dict[str, Any]
    ) -> Any:
        """Execute a single step with proper error handling and retry logic."""
        try:
            # Get step-specific retry and timeout settings
            retries = step.get("retries", self.global_retries)
            timeout = step.get("timeout", self.global_timeout)
            
            # Execute step using existing step executor
            step_result = run_step(
                step, registry, context, [], 
                retries=retries, 
                timeout=timeout
            )
            
            logger.debug(f"Step {step['id']} executed successfully")
            return step_result
            
        except Exception as e:
            logger.error(f"Step execution failed for {step.get('id', 'unknown')}: {e}")
            raise
    
    def _execute_foreach_step(
        self, 
        step: Dict[str, Any], 
        context: Dict[str, Any], 
        registry: Any
    ) -> List[Any]:
        """Execute foreach loop with proper iteration handling."""
        try:
            foreach_expr = step.get("foreach")
            items = evaluate_foreach_items(str(foreach_expr), context)
            
            logger.info(f"[Foreach] Processing {len(items)} items for step {step['id']}")
            
            if not items:
                logger.info(f"[Foreach] No items to process for step {step['id']}")
                return []
            
            results = []
            for i, item in enumerate(items):
                logger.debug(f"[Foreach] Processing item {i+1}/{len(items)}")
                
                # Create item-specific context
                item_context = copy.deepcopy(context)
                item_context["item"] = item
                item_context["iteration"] = i
                
                # Create item-specific step
                item_step = copy.deepcopy(step)
                
                # Remove foreach to prevent infinite loop
                if "foreach" in item_step:
                    del item_step["foreach"]
                
                # Execute item step
                item_result = self._execute_single_step(item_step, registry, item_context)
                results.append(item_result)
            
            logger.info(f"[Foreach] Completed {len(results)} iterations for step {step['id']}")
            return results
            
        except Exception as e:
            logger.error(f"Foreach execution failed for step {step.get('id', 'unknown')}: {e}")
            raise
    
    def _check_resume_mode(self, context: Dict[str, Any]) -> Tuple[bool, Optional[str]]:
        """Check if pipeline should resume from a specific step."""
        if not isinstance(context, dict):
            return False, None
        
        if "step_outputs" in context and "resume_from" in context:
            return True, context["resume_from"]
        
        return False, None
    
    def _should_execute_step(self, step: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if step should be executed based on conditions."""
        when_expr = step.get("when")
        if when_expr:
            try:
                # Create flattened context for template resolution and evaluation
                # Add step outputs as top-level variables for template access
                flattened_context = context.copy()
                if "step_outputs" in context:
                    flattened_context.update(context["step_outputs"])
                
                # First resolve template variables in the condition
                from shares.utils.template_resolver import resolve_param
                resolved_condition = resolve_param(str(when_expr), flattened_context)
                logger.debug(f"Resolved condition '{when_expr}' to '{resolved_condition}'")
                
                # Then evaluate the resolved condition with flattened context
                return evaluate_pipeline_condition(str(resolved_condition), flattened_context)
            except Exception as e:
                logger.warning(f"Failed to evaluate condition '{when_expr}': {e}")
                return False
        return True
    
    def _should_exit_pipeline(self, step: Dict[str, Any], context: Dict[str, Any]) -> bool:
        """Check if pipeline should exit based on exit conditions."""
        exit_if = step.get("exit_if")
        if exit_if:
            try:
                # Create flattened context for template resolution and evaluation
                # Add step outputs as top-level variables for template access
                flattened_context = context.copy()
                if "step_outputs" in context:
                    flattened_context.update(context["step_outputs"])
                
                # First resolve template variables in the condition
                from shares.utils.template_resolver import resolve_param
                resolved_condition = resolve_param(str(exit_if), flattened_context)
                logger.debug(f"Resolved exit condition '{exit_if}' to '{resolved_condition}'")
                
                # Then evaluate the resolved condition with flattened context
                return evaluate_pipeline_condition(str(resolved_condition), flattened_context)
            except Exception as e:
                logger.warning(f"Failed to evaluate exit condition '{exit_if}': {e}")
                return False
        return False
    
    def _handle_pause_step(
        self, 
        step: Dict[str, Any], 
        context: Dict[str, Any], 
        current_index: int,
        all_steps: List[Dict[str, Any]]
    ):
        """Handle pipeline pause with resume preparation."""
        try:
            step_id = step["id"]
            execution_id = context.get("execution_id", "unknown")
            
            # Set resume point
            if current_index + 1 < len(all_steps):
                context["resume_from"] = all_steps[current_index + 1]["id"]
            else:
                context["resume_from"] = None
            
            # Create pause directory and save state
            pause_dir = f"paused_runs/{step_id}_{execution_id}"
            pipeline_path = context.get("pipeline_path", "")
            
            pause_step(pause_dir, pipeline_path, step_id, context, pipeline_path)
            logger.info(f"Pipeline paused at step: {step_id}")
            
        except Exception as e:
            logger.error(f"Failed to handle pause step {step.get('id', 'unknown')}: {e}")
            raise
    
    def _execute_with_external_orchestrator(
        self, 
        steps: List[Dict[str, Any]], 
        context: Dict[str, Any],
        registry: Any
    ) -> Dict[str, Any]:
        """Execute pipeline using external orchestrator (Airflow/Argo)."""
        try:
            if not self.external_orchestrator:
                raise RuntimeError("External orchestrator not available")
            
            # Convert pipeline to external orchestrator format
            orchestrator_config = {
                'workflow_type': self.orchestrator_type,
                'steps': steps,
                'context': context,
                'registry_config': registry.config if hasattr(registry, 'config') else {}
            }
            
            # Execute using external orchestrator plugin
            result = self.external_orchestrator.process({}, orchestrator_config)
            
            if result.get('success'):
                return {
                    'success': True,
                    'execution_mode': f'external_{self.orchestrator_type}',
                    'results': result.get('workflow_results', {}),
                    'orchestrator_result': result
                }
            else:
                raise RuntimeError(f"External orchestrator failed: {result.get('error', 'Unknown error')}")
                
        except Exception as e:
            logger.error(f"External orchestrator execution failed: {e}")
            # Fallback to built-in execution
            logger.info("Falling back to built-in DAG execution")
            return self._execute_dag_pipeline(steps, context, registry)


# Plugin metadata for PlugPipe registration
plug_metadata = {
    "name": "execution_engine",
    "version": "1.0.0",
    "owner": "plugpipe-orchestration",
    "status": "production",
    "description": "Execution Engine Service - handles both DAG and linear pipeline execution with proper separation of concerns and integration with external orchestrators",
    "category": "orchestration",
    "tags": ["orchestration", "execution", "dag", "linear", "engine", "service"],
    "input_schema": {
        "type": "object",
        "properties": {
            "steps": {"type": "array", "description": "Pipeline steps to execute"},
            "context": {"type": "object", "description": "Execution context"},
            "registry": {"description": "Plugin registry instance"},
            "execution_mode": {
                "type": "string", 
                "enum": ["linear", "dag", "hybrid"],
                "description": "Execution mode override"
            },
            "enterprise_enabled": {"type": "boolean", "description": "Enable enterprise features"},
            "global_retries": {"type": "integer", "description": "Global retry count"},
            "global_timeout": {"type": "integer", "description": "Global timeout in seconds"},
            "use_external_orchestrator": {"type": "boolean", "description": "Use external orchestrator"},
            "orchestrator_type": {
                "type": "string",
                "enum": ["airflow", "argo"],
                "description": "External orchestrator type"
            }
        },
        "required": ["steps", "context", "registry"]
    },
    "output_schema": {
        "type": "object",
        "properties": {
            "success": {"type": "boolean", "description": "Execution success indicator"},
            "execution_mode": {"type": "string", "description": "Execution mode used"},
            "results": {"type": "object", "description": "Step execution results"},
            "summary": {"type": "array", "description": "Execution summary"},
            "total_steps": {"type": "integer", "description": "Total number of steps"},
            "completed_steps": {"type": "integer", "description": "Number of completed steps"},
            "error": {"type": "string", "description": "Error message if execution failed"}
        }
    },
    "revolutionary_capabilities": [
        "modular_execution_engine",
        "dag_linear_execution_strategies",
        "external_orchestrator_integration",
        "enterprise_workflow_support"
    ]
}


def process(ctx: Dict[str, Any], cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin process function."""
    try:
        # Initialize the execution engine service
        execution_engine = ExecutionEngine(cfg)
        
        # Extract required parameters
        steps = cfg.get('steps', [])
        context = cfg.get('context', {})
        registry = cfg.get('registry')
        execution_mode = cfg.get('execution_mode')
        
        if not steps:
            return {
                'success': False,
                'error': 'No steps provided for execution',
                'execution_mode': execution_mode
            }
        
        if not registry:
            return {
                'success': False,
                'error': 'Registry is required for step execution',
                'execution_mode': execution_mode
            }
        
        # Execute the pipeline
        result = execution_engine.execute_pipeline(steps, context, registry, execution_mode)
        
        return result
        
    except Exception as e:
        logger.error(f"Execution Engine process failed: {e}")
        return {
            'success': False,
            'error': str(e),
            'execution_mode': cfg.get('execution_mode', 'unknown')
        }


# Direct execution for testing
if __name__ == "__main__":
    import json
    
    # Test configuration
    test_config = {
        'steps': [
            {'id': 'test1', 'uses': 'test_plugin', 'input': {'test': 'value1'}},
            {'id': 'test2', 'uses': 'test_plugin', 'input': {'test': 'value2'}}
        ],
        'context': {
            'inputs': {},
            'step_outputs': {},
            'execution_id': 'test123'
        },
        'execution_mode': 'linear',
        'enterprise_enabled': False
    }
    
    # Note: This would fail without a real registry, but shows the interface
    print("Execution Engine Service Plugin - Interface Test")
    print(json.dumps(plug_metadata, indent=2))