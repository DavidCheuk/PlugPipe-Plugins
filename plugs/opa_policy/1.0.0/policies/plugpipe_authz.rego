# PlugPipe Authorization Policies
# Open Policy Agent (OPA) policies for PlugPipe authorization framework

package plugpipe.authz

import future.keywords.if
import future.keywords.in

# Default policy - deny unless explicitly allowed
default allow := false
default constraints := {}
default reason := "Default deny policy"

# Allow if basic RBAC allows and no additional restrictions apply
allow if {
    input.basic_decision.allow
    not high_risk_operation
    not sensitive_resource
}

# Admin users have full access (override)
allow if {
    "admin" in user_roles
}

# Allow plugin execution with constraints for developers
allow if {
    "developer" in user_roles
    input.action == "execute"
    input.resource_type == "plugin"
    not in_production_namespace
}

# Generate constraints for plugin execution
constraints := {
    "memory_limit_mb": 512,
    "cpu_limit_percent": 50,
    "timeout_seconds": 30,
    "network_access": false
} if {
    allow
    input.action == "execute"
    input.resource_type == "plugin"
    "developer" in user_roles
}

# Enhanced constraints for production namespace
constraints := {
    "memory_limit_mb": 256,
    "cpu_limit_percent": 25,
    "timeout_seconds": 15,
    "network_access": false,
    "filesystem_access": "read-only"
} if {
    allow
    input.action == "execute"
    in_production_namespace
}

# Compliance constraints for sensitive data
constraints := {
    "memory_limit_mb": 128,
    "cpu_limit_percent": 10,
    "timeout_seconds": 10,
    "network_access": false,
    "audit_level": "detailed",
    "encryption_required": true
} if {
    allow
    sensitive_resource
    length(input.compliance_requirements) > 0
}

# Helper functions

# Check if user has specific roles
user_roles := input.context.roles if input.context.roles
user_roles := [] if not input.context.roles

# Identify high-risk operations
high_risk_operation if {
    input.action in ["delete", "admin"]
}

high_risk_operation if {
    input.resource_type == "config"
    input.action == "write"
}

# Identify sensitive resources
sensitive_resource if {
    startswith(input.resource, "secret_")
}

sensitive_resource if {
    startswith(input.resource, "private_")
}

sensitive_resource if {
    input.resource_type == "config"
    contains(input.resource, "credential")
}

# Check if operation is in production namespace
in_production_namespace if {
    input.resource_namespace in ["production", "prod", "live"]
}

# Time-based access control
working_hours if {
    hour := time.clock(time.now_ns())[0]
    hour >= 9
    hour <= 17
}

# Allow operations during working hours for certain resources
allow if {
    input.basic_decision.allow
    working_hours
    not weekend
    input.resource_namespace == "development"
}

weekend if {
    weekday := time.weekday(time.now_ns())
    weekday in [0, 6]  # Sunday = 0, Saturday = 6
}

# Compliance-specific policies

# SOC2 compliance requirements
allow if {
    input.basic_decision.allow
    "soc2" in input.compliance_requirements
    soc2_compliant
}

soc2_compliant if {
    # Must have audit trail
    input.context.audit_id
    
    # Must have proper authentication
    input.context.authentication_method in ["mfa", "certificate"]
    
    # Must not be sensitive operation during off-hours
    not (sensitive_resource; not working_hours)
}

# PCI-DSS compliance requirements
allow if {
    input.basic_decision.allow
    "pci-dss" in input.compliance_requirements
    pci_compliant
}

pci_compliant if {
    # Enhanced security for payment data
    input.context.authentication_method == "mfa"
    
    # Network segmentation required
    input.context.network_segment == "pci_zone"
    
    # No direct access to cardholder data
    not contains(input.resource, "cardholder")
}

# HIPAA compliance requirements
allow if {
    input.basic_decision.allow
    "hipaa" in input.compliance_requirements
    hipaa_compliant
}

hipaa_compliant if {
    # Must have business associate agreement
    input.context.baa_signed == true
    
    # Must use encryption
    input.context.encryption_enabled == true
    
    # Access logging required
    input.context.access_logging == "enabled"
}

# Risk-based access control
risk_score := score if {
    base_score := 0
    
    # Add risk for sensitive operations
    sensitive_op_score := 30 if high_risk_operation
    sensitive_op_score := 0 if not high_risk_operation
    
    # Add risk for sensitive resources
    sensitive_res_score := 25 if sensitive_resource
    sensitive_res_score := 0 if not sensitive_resource
    
    # Add risk for production namespace
    prod_score := 20 if in_production_namespace
    prod_score := 0 if not in_production_namespace
    
    # Add risk for off-hours access
    time_score := 15 if not working_hours
    time_score := 0 if working_hours
    
    # Add risk for weekend access
    weekend_score := 10 if weekend
    weekend_score := 0 if not weekend
    
    score := base_score + sensitive_op_score + sensitive_res_score + prod_score + time_score + weekend_score
}

# Deny high-risk operations
allow if {
    input.basic_decision.allow
    risk_score < 50
}

# Generate reason for policy decision
reason := sprintf("Risk-based policy: risk_score=%d, working_hours=%t, sensitive=%t", [risk_score, working_hours, sensitive_resource]) if {
    risk_score >= 50
}

reason := sprintf("Allowed with constraints: role=%s, namespace=%s", [user_roles[0], input.resource_namespace]) if {
    allow
    count(user_roles) > 0
}

reason := "SOC2 compliance requirements met" if {
    allow
    "soc2" in input.compliance_requirements
    soc2_compliant
}

reason := "PCI-DSS compliance requirements met" if {
    allow
    "pci-dss" in input.compliance_requirements
    pci_compliant
}

reason := "HIPAA compliance requirements met" if {
    allow
    "hipaa" in input.compliance_requirements
    hipaa_compliant
}

# Metadata for audit and debugging
metadata := {
    "policy_version": "1.0.0",
    "evaluation_timestamp": time.now_ns(),
    "risk_score": risk_score,
    "working_hours": working_hours,
    "weekend": weekend,
    "sensitive_resource": sensitive_resource,
    "high_risk_operation": high_risk_operation,
    "in_production_namespace": in_production_namespace,
    "user_roles": user_roles,
    "compliance_requirements": input.compliance_requirements
}