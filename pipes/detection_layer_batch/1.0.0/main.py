#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Detection Layer Batch Pipeline Plugin

This pipe orchestrates comprehensive batch execution of all detection layer plugins
for automated plugin change analysis and issue identification.

Pipeline Structure:
- Phase 1: Environment Setup
- Phase 2: Detection Layer Execution (all detection plugins)  
- Phase 3: Result Consolidation
- Phase 4: Post-Detection Actions

Integration Points:
- Triggered by plugin changes via plugin_change_hooks
- Reports results to issue_tracker
- Triggers background_ai_fixer_service for critical issues
- Updates plugin_change_validation_pipeline with insights
"""

import json
import time
import os
from datetime import datetime
from typing import Dict, List, Any

def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """
    Process function for detection layer batch pipeline plugin.
    
    This is a PIPE plugin that orchestrates other plugins rather than
    performing detection itself.
    
    Args:
        context: Execution context with environment and metadata
        config: Pipeline configuration and inputs
        
    Returns:
        Dict containing pipeline orchestration metadata
    """
    start_time = time.time()
    
    try:
        # Extract input parameters
        trigger_reason = config.get('trigger_reason', 'manual')
        change_scope = config.get('change_scope', 'ecosystem_wide') 
        detection_sensitivity = config.get('detection_sensitivity', 'medium')
        plugin_filter = config.get('plugin_filter')
        
        # This is a pipe plugin - it doesn't execute the pipeline directly
        # Instead, it provides metadata and configuration for the orchestrator
        pipeline_metadata = {
            "pipeline_type": "detection_batch",
            "trigger_reason": trigger_reason,
            "change_scope": change_scope, 
            "detection_sensitivity": detection_sensitivity,
            "plugin_filter": plugin_filter,
            "estimated_duration_minutes": _estimate_duration(detection_sensitivity),
            "expected_phases": [
                "Environment Setup",
                "Detection Layer Execution", 
                "Result Consolidation",
                "Post-Detection Actions"
            ],
            "detection_plugins": [
                "codebase_integrity_scanner",
                "performance_bottleneck_detector",
                "config_hardening", 
                "business_compliance_auditor",
                "intelligent_test_agent",
                "error_handling_analyzer"
            ],
            "integration_points": [
                "cli_parameter_mapping_coordinator",
                "issue_tracker",
                "pp_registry_comprehensive_reporter", 
                "background_ai_fixer_service",
                "plugin_change_validation_pipeline"
            ]
        }
        
        # Check environment readiness
        environment_status = _check_environment_readiness()
        
        processing_time = (time.time() - start_time) * 1000
        
        return {
            "success": True,
            "processing_time_ms": round(processing_time, 2),
            "pipeline_metadata": pipeline_metadata,
            "environment_status": environment_status,
            "ready_for_execution": environment_status["overall_readiness"],
            "recommended_execution_mode": _recommend_execution_mode(detection_sensitivity, change_scope),
            "timestamp": datetime.now().isoformat()
        }
        
    except Exception as e:
        processing_time = (time.time() - start_time) * 1000
        
        return {
            "success": False,
            "processing_time_ms": round(processing_time, 2),
            "error": str(e),
            "timestamp": datetime.now().isoformat()
        }

def _estimate_duration(sensitivity: str) -> int:
    """Estimate pipeline execution duration based on sensitivity."""
    duration_map = {
        "low": 5,
        "medium": 15,
        "high": 30,
        "comprehensive": 60
    }
    return duration_map.get(sensitivity, 15)

def _check_environment_readiness() -> Dict[str, Any]:
    """Check if the environment is ready for detection batch execution."""
    readiness_checks = {
        "detection_plugins_available": _check_detection_plugins(),
        "integration_plugins_available": _check_integration_plugins(),
        "storage_accessible": _check_storage_access(),
        "configuration_valid": _check_configuration_validity()
    }
    
    overall_readiness = all(readiness_checks.values())
    
    return {
        "checks": readiness_checks,
        "overall_readiness": overall_readiness,
        "readiness_score": sum(readiness_checks.values()) / len(readiness_checks),
        "missing_requirements": [k for k, v in readiness_checks.items() if not v]
    }

def _check_detection_plugins() -> bool:
    """Check if core detection plugins are available."""
    required_plugins = [
        "plugs/core/codebase_integrity_scanner",
        "plugs/core/performance_bottleneck_detector", 
        "plugs/security/config_hardening",
        "plugs/governance/business_compliance_auditor"
    ]
    
    available_count = 0
    for plugin_path in required_plugins:
        if os.path.exists(f"{plugin_path}/1.0.0/main.py"):
            available_count += 1
    
    return available_count >= 3  # At least 3/4 core plugins available

def _check_integration_plugins() -> bool:
    """Check if integration plugins are available."""
    integration_plugins = [
        "plugs/governance/issue_tracker",
        "plugs/intelligence/background_ai_fixer_service",
        "plugs/governance/pp_registry_comprehensive_reporter"
    ]
    
    available_count = 0
    for plugin_path in integration_plugins:
        if os.path.exists(f"{plugin_path}/1.0.0"):
            available_count += 1
    
    return available_count >= 2  # At least 2/3 integration plugins

def _check_storage_access() -> bool:
    """Check if storage directories are accessible."""
    try:
        # Try to create a test file in a temp directory
        test_dir = "detection_batch_test"
        os.makedirs(test_dir, exist_ok=True)
        with open(f"{test_dir}/test.txt", "w") as f:
            f.write("test")
        os.remove(f"{test_dir}/test.txt")
        os.rmdir(test_dir)
        return True
    except Exception:
        return False

def _check_configuration_validity() -> bool:
    """Check if configuration files are valid."""
    return os.path.exists("config.yaml")

def _recommend_execution_mode(sensitivity: str, scope: str) -> str:
    """Recommend execution mode based on parameters."""
    if sensitivity == "comprehensive" or scope == "ecosystem_wide":
        return "sequential_with_monitoring"
    elif sensitivity == "high":
        return "parallel_with_limits"
    else:
        return "standard_sequential"

# Plugin metadata
plug_metadata = {
    "name": "detection-layer-batch",
    "version": "1.0.0",
    "type": "pipe",
    "description": "Detection layer batch execution pipeline plugin",
    "category": "orchestration",
    "pipeline_type": "detection_batch"
}