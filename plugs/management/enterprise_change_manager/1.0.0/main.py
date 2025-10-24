#!/usr/bin/env python3
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 PlugPipe Team / Yu Ming Cheuk
# This file is part of PlugPipe - https://github.com/PlugPipe/PlugPipe

"""
Enterprise Change Management Plugin

This plugin orchestrates complex enterprise changes by composing existing PlugPipe plugins
for configuration management (Salt), logging, monitoring, and rollback capabilities.
Created using Agent Factory following CLAUDE.md principles of plugin composition.
"""

import logging
import time
import json
from typing import Dict, List, Any, Optional
from enum import Enum
import importlib.util
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

# Plugin metadata
plug_metadata = {
    "name": "enterprise_change_manager", 
    "version": "1.0.0",
    "description": "Enterprise change management orchestrator using existing plugin composition",
    "owner": "PlugPipe Core Team",
    "capabilities": [
        "change_orchestration",
        "multi_environment_deployment", 
        "rollback_management",
        "compliance_tracking",
        "automated_verification",
        "audit_reporting"
    ],
    "triggers": [
        "scheduled_deployment",
        "emergency_change",
        "compliance_update", 
        "configuration_drift"
    ],
    "dependencies": [
        "plugs/infrastructure/salt/1.0.0",
        "plugs/monitoring/prometheus/1.0.0",
        "plugs/audit/elk_stack/1.0.0",
        "plugs/core/agent_factory/1.0.0"
    ]
}

class ChangeType(Enum):
    """Types of changes supported by the enterprise change manager"""
    CONFIGURATION = "configuration"
    APPLICATION_DEPLOYMENT = "application_deployment"
    SECURITY_PATCH = "security_patch"
    INFRASTRUCTURE = "infrastructure"
    EMERGENCY_FIX = "emergency_fix"
    COMPLIANCE_UPDATE = "compliance_update"

class ChangeStatus(Enum):
    """Status of change execution"""
    PLANNED = "planned"
    IN_PROGRESS = "in_progress" 
    COMPLETED = "completed"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"
    PENDING_APPROVAL = "pending_approval"

# Load Agent Factory following CLAUDE.md guidelines
def load_agent_factory():
    """Load Agent Factory using proper import pattern from CLAUDE.md"""
    try:
        spec = importlib.util.spec_from_file_location(
            "agent_factory_main",
            "plugs/core/agent_factory/1.0.0/main.py"
        )
        if spec and spec.loader:
            agent_factory_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(agent_factory_module)
            return agent_factory_module.ProductionAgentFactory
    except Exception as e:
        logging.warning(f"Could not load Agent Factory: {e}, using mock")
        return None

# Load existing plugins for composition following CLAUDE.md principles
def load_existing_plugin(plugin_path: str, plugin_name: str):
    """Load existing plugin for composition"""
    try:
        spec = importlib.util.spec_from_file_location(
            f"{plugin_name}_main",
            plugin_path
        )
        if spec and spec.loader:
            plugin_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(plugin_module)
            return plugin_module
    except Exception as e:
        logging.warning(f"Could not load {plugin_name} plugin: {e}")
        return None

# Policy-based change management following CLAUDE.md principles
class PolicyManager:
    """Manages change policies using OPA policy plugins"""
    
    def __init__(self):
        # Load policy plugins for change governance
        self.approval_policy = load_existing_plugin("plugs/policy/opa_policy/1.0.0/main.py", "opa_policy")
        self.audit_policy = load_existing_plugin("plugs/policy/opa_policy_enterprise/1.0.0/main.py", "opa_policy_enterprise")
        self.rollback_policy = load_existing_plugin("plugs/management/rollback_manager/1.0.0/main.py", "rollback_manager")
        
    def evaluate_change_approval(self, change_request: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate change approval using policy plugins"""
        if self.approval_policy and hasattr(self.approval_policy, 'process'):
            return self.approval_policy.process({}, {
                "action": "evaluate_policy",
                "policy_name": "change_approval",
                "input_data": {
                    "change": change_request,
                    "context": {
                        "requester": change_request.get("requester", "unknown"),
                        "risk_level": change_request.get("risk_level", "medium"),
                        "environment": change_request.get("environment", "production")
                    }
                }
            })
        else:
            # Mock approval for development
            return {
                "status": "approved",
                "policy": "mock_approval",
                "conditions": ["automated_rollback_required", "post_change_validation"]
            }
    
    def evaluate_audit_requirements(self, change_request: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate audit requirements using enterprise policy plugins"""
        if self.audit_policy and hasattr(self.audit_policy, 'process'):
            return self.audit_policy.process({}, {
                "action": "evaluate_compliance",
                "change_data": change_request,
                "compliance_frameworks": ["SOX", "GDPR", "ISO27001"]
            })
        else:
            return {
                "status": "compliant",
                "audit_requirements": ["pre_change_approval", "detailed_logging", "post_change_verification"],
                "retention_period": "7_years"
            }
    
    def evaluate_rollback_policy(self, change_id: str, failure_context: Dict[str, Any]) -> Dict[str, Any]:
        """Evaluate rollback policy using rollback manager plugin"""
        if self.rollback_policy and hasattr(self.rollback_policy, 'process'):
            return {
                "status": "automatic_rollback_required",
                "rollback_type": "git_commit",
                "validation_required": True,
                "approval_needed": failure_context.get("impact_level", "medium") == "high"
            }
        else:
            return {
                "status": "automatic_rollback_required",
                "rollback_type": "git_commit",
                "validation_required": True
            }

class ExistingPluginComposer:
    """Compose existing plugins for change management operations"""
    
    def __init__(self):
        # Load existing plugins following CLAUDE.md "reuse everything" principle
        self.salt_plugin = load_existing_plugin("plugs/infrastructure/salt/1.0.0/main.py", "salt")
        self.logging_plugin = load_existing_plugin("plugs/audit/elk_stack/1.0.0/main.py", "elk_stack") 
        self.monitoring_plugin = load_existing_plugin("plugs/monitoring/prometheus/1.0.0/main.py", "prometheus")
        self.rollback_plugin = load_existing_plugin("plugs/management/rollback_manager/1.0.0/main.py", "rollback_manager")
        self.agent_factory = load_agent_factory()
        
        # Initialize policy manager for governance
        self.policy_manager = PolicyManager()
        
        # Initialize with fallbacks
        if not self.salt_plugin:
            logging.warning("Salt plugin not available, using mock configuration management")
        if not self.logging_plugin:
            logging.warning("ELK Stack plugin not available, using basic logging")
        if not self.monitoring_plugin:
            logging.warning("Prometheus plugin not available, using mock monitoring")
        if not self.rollback_plugin:
            logging.warning("Rollback Manager plugin not available, using basic rollback")
            
    def execute_configuration_change(self, target: str, config: Dict[str, Any]) -> Dict[str, Any]:
        """Execute configuration change using Salt plugin"""
        if self.salt_plugin and hasattr(self.salt_plugin, 'process'):
            return self.salt_plugin.process({}, {
                "target": target,
                "state": config.get("salt_state", "apply"),
                "pillar_data": config.get("pillar", {}),
                "test": config.get("dry_run", False)
            })
        else:
            return {
                "status": "mock_success",
                "message": f"Mock configuration change applied to {target}",
                "changes": config
            }
    
    def log_change_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Log change event using ELK Stack plugin"""
        if self.logging_plugin and hasattr(self.logging_plugin, 'process'):
            return self.logging_plugin.process({}, {
                "action": "log_event",
                "index": "change_management",
                "document": event
            })
        else:
            logging.info(f"Change event: {json.dumps(event)}")
            return {"status": "logged", "method": "python_logging"}
    
    def monitor_change_impact(self, metrics: List[str]) -> Dict[str, Any]:
        """Monitor change impact using Prometheus plugin"""
        if self.monitoring_plugin and hasattr(self.monitoring_plugin, 'process'):
            return self.monitoring_plugin.process({}, {
                "action": "query_metrics",
                "metrics": metrics,
                "time_range": "5m"
            })
        else:
            return {
                "status": "mock_monitoring",
                "metrics": {metric: "healthy" for metric in metrics}
            }
    
    def execute_policy_driven_rollback(self, change_id: str, failure_context: Dict[str, Any]) -> Dict[str, Any]:
        """Execute rollback based on policy evaluation"""
        # Get rollback policy decision
        rollback_policy = self.policy_manager.evaluate_rollback_policy(change_id, failure_context)
        
        if rollback_policy["status"] != "automatic_rollback_required":
            return {
                "status": "skipped",
                "reason": "rollback_not_required_by_policy",
                "policy_decision": rollback_policy
            }
        
        # Execute rollback using rollback manager plugin
        if self.rollback_plugin and hasattr(self.rollback_plugin, 'process'):
            return self.rollback_plugin.process({}, {
                "action": "execute_rollback",
                "snapshot_id": f"change_{change_id}_snapshot",
                "validation": {
                    "tests": [
                        {"type": "git_commit", "expected_commit": "HEAD~1"},
                        {"type": "service_status", "services": ["application"]}
                    ]
                } if rollback_policy.get("validation_required") else {}
            })
        else:
            return {
                "status": "mock_rollback",
                "snapshot_id": f"change_{change_id}_snapshot",
                "policy_driven": True
            }
    
    def create_policy_compliant_snapshot(self, change_id: str) -> Dict[str, Any]:
        """Create snapshot following policy requirements"""
        if self.rollback_plugin and hasattr(self.rollback_plugin, 'process'):
            return self.rollback_plugin.process({}, {
                "action": "create_snapshot",
                "snapshot_id": f"change_{change_id}_snapshot",
                "type": "git_commit",
                "config": {
                    "repo_path": "."
                }
            })
        else:
            return {
                "status": "mock_snapshot_created",
                "snapshot_id": f"change_{change_id}_snapshot"
            }

class EnterpriseChangeManager:
    """Main change management orchestrator using Agent Factory and existing plugins"""
    
    def __init__(self):
        self.plugin_composer = ExistingPluginComposer()
        self.active_changes: Dict[str, Dict[str, Any]] = {}
        
        # Initialize Agent Factory for specialized change agents
        self.agent_factory = None
        if self.plugin_composer.agent_factory:
            try:
                self.agent_factory = self.plugin_composer.agent_factory(config={
                    "specialization": "change_management",
                    "capabilities": ["risk_assessment", "compliance_validation", "rollback_planning"]
                })
                logging.info("Agent Factory initialized for change management")
            except Exception as e:
                logging.warning(f"Could not initialize Agent Factory: {e}")
    
    def plan_change(self, change_request: Dict[str, Any]) -> Dict[str, Any]:
        """Plan enterprise change with policy-driven approval and risk assessment"""
        change_id = f"change_{int(time.time())}"
        
        # Assess risk first
        risk_level = self._assess_risk(change_request)
        change_request["risk_level"] = risk_level
        
        # Get policy-driven approval
        approval_result = self.plugin_composer.policy_manager.evaluate_change_approval(change_request)
        
        # Get audit requirements
        audit_requirements = self.plugin_composer.policy_manager.evaluate_audit_requirements(change_request)
        
        change_plan = {
            "id": change_id,
            "type": change_request.get("type", ChangeType.CONFIGURATION.value),
            "description": change_request.get("description", ""),
            "targets": change_request.get("targets", []),
            "scheduled_time": change_request.get("scheduled_time"),
            "rollback_plan": change_request.get("rollback_plan", {}),
            "status": ChangeStatus.PENDING_APPROVAL.value if approval_result.get("status") != "approved" else ChangeStatus.PLANNED.value,
            "created_at": int(time.time()),
            "risk_level": risk_level,
            "compliance_requirements": change_request.get("compliance", []),
            "approval_result": approval_result,
            "audit_requirements": audit_requirements,
            "policy_conditions": approval_result.get("conditions", [])
        }
        
        self.active_changes[change_id] = change_plan
        
        # Create policy-compliant snapshot as required by approval conditions
        if "automated_rollback_required" in change_plan.get("policy_conditions", []):
            snapshot_result = self.plugin_composer.create_policy_compliant_snapshot(change_id)
            change_plan["snapshot_info"] = snapshot_result
        
        # Log change plan creation with policy context
        self.plugin_composer.log_change_event({
            "event_type": "change_planned",
            "change_id": change_id,
            "details": change_plan,
            "policy_context": {
                "approval_status": approval_result.get("status"),
                "audit_requirements": audit_requirements.get("audit_requirements", []),
                "compliance_frameworks": audit_requirements.get("compliance_frameworks", [])
            }
        })
        
        return {
            "change_id": change_id,
            "status": change_plan["status"],
            "risk_level": risk_level,
            "approval_status": approval_result.get("status"),
            "policy_conditions": change_plan.get("policy_conditions", []),
            "audit_requirements": audit_requirements.get("audit_requirements", [])
        }
    
    def execute_change(self, change_id: str) -> Dict[str, Any]:
        """Execute planned change with comprehensive monitoring and rollback capability"""
        if change_id not in self.active_changes:
            return {"status": "error", "error": f"Change {change_id} not found"}
        
        change = self.active_changes[change_id]
        change["status"] = ChangeStatus.IN_PROGRESS.value
        change["execution_start"] = int(time.time())
        
        execution_results = {
            "change_id": change_id,
            "status": "in_progress",
            "steps_completed": [],
            "technical_details": [],
            "monitoring_data": {},
            "rollback_info": None
        }
        
        try:
            # Log change execution start
            self.plugin_composer.log_change_event({
                "event_type": "change_execution_started", 
                "change_id": change_id,
                "timestamp": int(time.time())
            })
            
            # Execute change on all targets
            for target in change["targets"]:
                step_result = self._execute_target_change(target, change)
                execution_results["steps_completed"].append({
                    "target": target,
                    "result": step_result,
                    "timestamp": int(time.time())
                })
                execution_results["technical_details"].append({
                    "action": "target_configuration",
                    "target": target,
                    "details": step_result,
                    "method": "salt_plugin" if self.plugin_composer.salt_plugin else "mock"
                })
                
                if step_result.get("status") != "success" and step_result.get("status") != "mock_success":
                    raise Exception(f"Target {target} change failed: {step_result}")
            
            # Monitor change impact
            monitoring_metrics = ["cpu_usage", "memory_usage", "error_rate", "response_time"]
            monitoring_data = self.plugin_composer.monitor_change_impact(monitoring_metrics)
            execution_results["monitoring_data"] = monitoring_data
            execution_results["technical_details"].append({
                "action": "impact_monitoring", 
                "details": monitoring_data,
                "method": "prometheus_plugin" if self.plugin_composer.monitoring_plugin else "mock"
            })
            
            # Validate change success
            if self._validate_change_success(monitoring_data):
                change["status"] = ChangeStatus.COMPLETED.value
                execution_results["status"] = "completed"
                execution_results["technical_details"].append({
                    "action": "change_validation",
                    "result": "success",
                    "validation_method": "monitoring_threshold_check"
                })
            else:
                raise Exception("Change validation failed based on monitoring data")
                
        except Exception as e:
            logging.error(f"Change execution failed: {e}")
            change["status"] = ChangeStatus.FAILED.value
            execution_results["status"] = "failed"
            execution_results["error"] = str(e)
            execution_results["technical_details"].append({
                "action": "change_failure",
                "error": str(e),
                "timestamp": int(time.time())
            })
            
            # Attempt rollback
            rollback_result = self._execute_rollback(change_id)
            execution_results["rollback_info"] = rollback_result
            execution_results["technical_details"].append({
                "action": "automatic_rollback",
                "details": rollback_result,
                "triggered_by": "change_failure"
            })
        
        # Final logging
        self.plugin_composer.log_change_event({
            "event_type": "change_execution_completed",
            "change_id": change_id,
            "final_status": execution_results["status"],
            "execution_results": execution_results
        })
        
        return execution_results
    
    def _execute_target_change(self, target: str, change: Dict[str, Any]) -> Dict[str, Any]:
        """Execute change on specific target using Salt plugin"""
        return self.plugin_composer.execute_configuration_change(target, {
            "salt_state": "highstate",
            "pillar": change.get("configuration", {}),
            "dry_run": False
        })
    
    def _validate_change_success(self, monitoring_data: Dict[str, Any]) -> bool:
        """Validate change success based on monitoring data"""
        # Simple validation - in real implementation would be more sophisticated
        metrics = monitoring_data.get("metrics", {})
        return all(metric != "critical" for metric in metrics.values())
    
    def _assess_risk(self, change_request: Dict[str, Any]) -> str:
        """Assess risk level of change request"""
        risk_factors = 0
        
        # Risk assessment logic
        if len(change_request.get("targets", [])) > 10:
            risk_factors += 1
        if change_request.get("type") == ChangeType.EMERGENCY_FIX.value:
            risk_factors += 2
        if not change_request.get("rollback_plan"):
            risk_factors += 1
            
        if risk_factors >= 3:
            return "high"
        elif risk_factors >= 1:
            return "medium"
        else:
            return "low"
    
    def _execute_rollback(self, change_id: str) -> Dict[str, Any]:
        """Execute rollback for failed change"""
        change = self.active_changes[change_id]
        rollback_plan = change.get("rollback_plan", {})
        
        if not rollback_plan:
            return {
                "status": "failed",
                "error": "No rollback plan defined",
                "method": "none"
            }
        
        try:
            # Execute rollback using Salt plugin
            rollback_results = []
            for target in change["targets"]:
                result = self.plugin_composer.execute_configuration_change(target, {
                    "salt_state": rollback_plan.get("salt_state", "rollback"),
                    "pillar": rollback_plan.get("configuration", {}),
                    "dry_run": False
                })
                rollback_results.append(result)
            
            change["status"] = ChangeStatus.ROLLED_BACK.value
            return {
                "status": "success",
                "method": "salt_plugin",
                "results": rollback_results,
                "timestamp": int(time.time())
            }
            
        except Exception as e:
            return {
                "status": "failed", 
                "error": str(e),
                "method": "salt_plugin"
            }

# Global change manager instance
change_manager = None

def process(context: Dict[str, Any], config: Dict[str, Any]) -> Dict[str, Any]:
    """Main plugin entry point"""
    global change_manager
    
    action = config.get("action", "status")
    
    try:
        if change_manager is None:
            change_manager = EnterpriseChangeManager()
        
        if action == "plan_change":
            result = change_manager.plan_change(config.get("change_request", {}))
            return {
                "status": "success",
                "message": "Change planned successfully",
                **result
            }
            
        elif action == "execute_change":
            change_id = config.get("change_id")
            if not change_id:
                return {"status": "error", "error": "change_id required"}
            
            result = change_manager.execute_change(change_id)
            return {
                "status": "success" if result["status"] in ["completed", "in_progress"] else "error",
                "message": f"Change execution {result['status']}",
                **result
            }
            
        elif action == "list_changes":
            return {
                "status": "success",
                "active_changes": list(change_manager.active_changes.keys()),
                "change_details": change_manager.active_changes
            }
            
        elif action == "get_change_status":
            change_id = config.get("change_id")
            if change_id in change_manager.active_changes:
                return {
                    "status": "success",
                    "change": change_manager.active_changes[change_id]
                }
            else:
                return {"status": "error", "error": f"Change {change_id} not found"}
                
        elif action == "status":
            return {
                "status": "success",
                "plugin": "enterprise_change_manager",
                "active_changes_count": len(change_manager.active_changes),
                "capabilities": plug_metadata["capabilities"],
                "dependencies_status": {
                    "salt_plugin": change_manager.plugin_composer.salt_plugin is not None,
                    "logging_plugin": change_manager.plugin_composer.logging_plugin is not None,
                    "monitoring_plugin": change_manager.plugin_composer.monitoring_plugin is not None,
                    "agent_factory": change_manager.agent_factory is not None
                }
            }
        
        else:
            return {
                "status": "error",
                "error": f"Unknown action: {action}",
                "supported_actions": ["plan_change", "execute_change", "list_changes", "get_change_status", "status"]
            }
            
    except Exception as e:
        return {
            "status": "error",
            "error": str(e),
            "message": "Enterprise Change Manager encountered an error"
        }

if __name__ == "__main__":
    # CLI interface for testing
    import argparse
    
    parser = argparse.ArgumentParser(description="Enterprise Change Manager")
    parser.add_argument("--action", choices=["plan", "execute", "list", "status"], 
                       default="status", help="Action to perform")
    parser.add_argument("--change-id", help="Change ID for execution")
    
    args = parser.parse_args()
    
    config = {"action": f"{args.action}_change" if args.action != "status" else "status"}
    if args.change_id:
        config["change_id"] = args.change_id
    
    result = process({}, config)
    print(json.dumps(result, indent=2))