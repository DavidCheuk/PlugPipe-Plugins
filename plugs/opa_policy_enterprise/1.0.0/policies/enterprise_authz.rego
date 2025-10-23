# Enterprise OPA Policy for PlugPipe
# Advanced multi-tenant authorization with compliance and governance

package plugpipe.enterprise.authz

import future.keywords.if
import future.keywords.in

# ============================================================================
# MAIN AUTHORIZATION DECISION
# ============================================================================

# Default deny for security
default allow := false

# Main allow rule - combines all authorization layers
allow if {
    basic_authorization_check
    tenant_isolation_check
    compliance_requirements_check
    risk_assessment_passed
    rate_limiting_check
    time_based_access_allowed
}

# ============================================================================
# BASIC AUTHORIZATION LAYER
# ============================================================================

# Allow if basic RBAC layer approves
basic_authorization_check if {
    input.basic_decision.allow
}

# Administrative override for emergencies
basic_authorization_check if {
    "emergency_admin" in input.context.roles
    input.context.emergency_reason
    valid_emergency_justification
}

valid_emergency_justification if {
    emergency_reasons := ["security_incident", "system_outage", "data_recovery", "compliance_audit"]
    input.context.emergency_reason in emergency_reasons
}

# ============================================================================
# MULTI-TENANT ISOLATION
# ============================================================================

# Ensure tenant isolation is maintained
tenant_isolation_check if {
    input.enterprise.tenant_id
    valid_tenant_access
    resource_tenant_match
}

valid_tenant_access if {
    # User belongs to the tenant
    input.enterprise.tenant_id in input.context.authorized_tenants
}

valid_tenant_access if {
    # Cross-tenant access with explicit authorization
    input.context.cross_tenant_authorization
    input.context.cross_tenant_reason
    "cross_tenant_admin" in input.context.roles
}

resource_tenant_match if {
    # Resource belongs to user's tenant
    input.resource_namespace == input.enterprise.tenant_id
}

resource_tenant_match if {
    # Shared resources are accessible
    input.resource_namespace == "shared"
}

resource_tenant_match if {
    # Public resources are accessible to all
    input.resource_namespace == "public"
}

# ============================================================================
# COMPLIANCE REQUIREMENTS
# ============================================================================

# Check compliance requirements are met
compliance_requirements_check if {
    count(input.compliance_requirements) == 0  # No compliance required
}

compliance_requirements_check if {
    count(input.compliance_requirements) > 0
    all_compliance_requirements_met
}

all_compliance_requirements_met if {
    required := input.compliance_requirements
    every requirement in required {
        compliance_check(requirement)
    }
}

# SOC2 Compliance
compliance_check("soc2") if {
    input.context.audit_id  # Audit trail required
    input.context.authentication_method in ["mfa", "certificate", "smartcard"]
    input.context.session_timeout_minutes <= 480  # 8 hour max session
    data_classification_appropriate
}

# PCI-DSS Compliance
compliance_check("pci-dss") if {
    input.context.authentication_method == "mfa"
    input.context.network_segment in ["pci_zone", "secure_zone"]
    input.context.encryption_enabled == true
    pci_data_access_authorized
}

# HIPAA Compliance
compliance_check("hipaa") if {
    input.context.baa_signed == true  # Business Associate Agreement
    input.context.authentication_method in ["mfa", "certificate"]
    input.context.access_purpose in ["treatment", "payment", "operations", "authorized_research"]
    phi_access_justified
}

# GDPR Compliance
compliance_check("gdpr") if {
    input.context.data_processing_purpose
    input.context.legal_basis in ["consent", "contract", "legal_obligation", "legitimate_interest"]
    input.context.data_subject_rights_respected == true
    gdpr_retention_compliant
}

# SOX Compliance (Sarbanes-Oxley)
compliance_check("sox") if {
    input.context.financial_controls_verified == true
    input.context.segregation_of_duties == true
    input.context.change_management_approved == true
    sox_audit_trail_complete
}

# ============================================================================
# RISK ASSESSMENT
# ============================================================================

# Risk-based access control
risk_assessment_passed if {
    calculated_risk_score <= acceptable_risk_threshold
}

calculated_risk_score := score if {
    base_score := 0
    
    # Action risk
    action_risk := action_risk_score
    
    # Resource risk
    resource_risk := resource_risk_score
    
    # Context risk
    context_risk := context_risk_score
    
    # Time risk
    time_risk := time_risk_score
    
    # User risk
    user_risk := user_risk_score
    
    score := base_score + action_risk + resource_risk + context_risk + time_risk + user_risk
}

action_risk_score := 30 if {
    input.action in ["delete", "destroy", "admin", "modify"]
} else := 15 if {
    input.action in ["write", "update", "execute"]
} else := 5

resource_risk_score := 40 if {
    input.resource_namespace in ["production", "critical", "sensitive"]
} else := 20 if {
    input.resource_namespace in ["staging", "pre-production"]
} else := 5

context_risk_score := score if {
    base := 0
    
    # Network-based risk
    network_risk := 20 if {
        input.context.source_ip_external == true
    } else := 0
    
    # Authentication risk
    auth_risk := 25 if {
        input.context.authentication_method == "password"
    } else := 10 if {
        input.context.authentication_method == "token"
    } else := 0
    
    # Session risk
    session_risk := 15 if {
        input.context.session_age_minutes > 480  # 8 hours
    } else := 0
    
    score := base + network_risk + auth_risk + session_risk
}

time_risk_score := 20 if {
    outside_business_hours
} else := 10 if {
    weekend_access
} else := 0

user_risk_score := score if {
    base := 0
    
    # New user risk
    new_user_risk := 15 if {
        input.context.user_tenure_days < 30
    } else := 0
    
    # Privilege escalation risk
    privilege_risk := 25 if {
        elevated_privileges_detected
    } else := 0
    
    # Anomaly risk
    anomaly_risk := 20 if {
        input.context.anomaly_score > 0.7
    } else := 0
    
    score := base + new_user_risk + privilege_risk + anomaly_risk
}

acceptable_risk_threshold := 50 if {
    "admin" in input.context.roles
} else := 35 if {
    "privileged_user" in input.context.roles
} else := 25

# ============================================================================
# RATE LIMITING
# ============================================================================

rate_limiting_check if {
    not rate_limit_exceeded
}

rate_limit_exceeded if {
    tenant_config := data.tenants[input.enterprise.tenant_id]
    tenant_config.rate_limits.requests_per_minute
    
    # Check against current usage (would be tracked externally)
    current_usage := data.rate_tracking[input.enterprise.tenant_id][input.subject]
    current_usage.requests_last_minute > tenant_config.rate_limits.requests_per_minute
}

# ============================================================================
# TIME-BASED ACCESS CONTROL
# ============================================================================

time_based_access_allowed if {
    not time_restrictions_enabled
}

time_based_access_allowed if {
    time_restrictions_enabled
    within_allowed_hours
    not weekend_restriction_violated
}

time_restrictions_enabled if {
    input.enterprise.organization_context.time_restrictions == true
}

within_allowed_hours if {
    current_hour := time.clock(time.now_ns())[0]
    start_hour := input.enterprise.organization_context.allowed_hours.start
    end_hour := input.enterprise.organization_context.allowed_hours.end
    
    current_hour >= start_hour
    current_hour <= end_hour
}

weekend_restriction_violated if {
    weekend
    input.enterprise.organization_context.weekend_access_restricted == true
    not weekend_exception_applies
}

weekend_exception_applies if {
    "weekend_access" in input.context.roles
}

weekend_exception_applies if {
    input.context.emergency_reason
}

# ============================================================================
# UTILITY RULES
# ============================================================================

outside_business_hours if {
    current_hour := time.clock(time.now_ns())[0]
    current_hour < 9
}

outside_business_hours if {
    current_hour := time.clock(time.now_ns())[0]
    current_hour > 17
}

weekend if {
    weekday := time.weekday(time.now_ns())
    weekday in [0, 6]  # Sunday = 0, Saturday = 6
}

weekend_access if {
    weekend
}

elevated_privileges_detected if {
    privilege_roles := ["admin", "super_admin", "system_admin", "security_admin"]
    some role in privilege_roles
    role in input.context.roles
}

data_classification_appropriate if {
    data_level := input.context.data_classification
    user_clearance := input.context.clearance_level
    
    clearance_levels := {
        "public": 1,
        "internal": 2, 
        "confidential": 3,
        "restricted": 4,
        "top_secret": 5
    }
    
    clearance_levels[user_clearance] >= clearance_levels[data_level]
}

pci_data_access_authorized if {
    "pci_authorized" in input.context.roles
    input.context.pci_training_completed == true
    input.context.background_check_current == true
}

phi_access_justified if {
    input.context.access_purpose in ["treatment", "payment", "operations"]
}

phi_access_justified if {
    input.context.access_purpose == "authorized_research"
    input.context.research_approval_id
}

gdpr_retention_compliant if {
    data_age_days := input.context.data_age_days
    retention_period := input.context.retention_period_days
    data_age_days <= retention_period
}

sox_audit_trail_complete if {
    input.context.change_request_id
    input.context.approver_id
    input.context.business_justification
}

# ============================================================================
# CONSTRAINTS GENERATION
# ============================================================================

# Generate runtime constraints based on policy evaluation
constraints := result if {
    allow  # Only generate constraints if access is allowed
    
    base_constraints := {}
    
    # Resource constraints based on user role
    resource_constraints := generate_resource_constraints
    
    # Time-based constraints
    time_constraints := generate_time_constraints
    
    # Compliance constraints
    compliance_constraints := generate_compliance_constraints
    
    # Risk-based constraints
    risk_constraints := generate_risk_constraints
    
    result := object.union_n([
        base_constraints,
        resource_constraints, 
        time_constraints,
        compliance_constraints,
        risk_constraints
    ])
}

generate_resource_constraints := constraints if {
    base := {}
    
    # Memory limits based on role
    memory_limits := {
        "memory_limit_mb": 256
    } if {
        "developer" in input.context.roles
    } else := {
        "memory_limit_mb": 512  
    } if {
        "admin" in input.context.roles
    } else := {
        "memory_limit_mb": 128
    }
    
    # CPU limits
    cpu_limits := {
        "cpu_limit_percent": 25
    } if {
        input.resource_namespace == "production"
    } else := {
        "cpu_limit_percent": 50
    }
    
    # Timeout constraints
    timeout_limits := {
        "timeout_seconds": 30
    } if {
        input.action == "execute"
    } else := {
        "timeout_seconds": 60
    }
    
    constraints := object.union_n([base, memory_limits, cpu_limits, timeout_limits])
}

generate_time_constraints := constraints if {
    base := {}
    
    # Session timeout based on risk
    session_constraints := {
        "session_timeout_minutes": 60
    } if {
        calculated_risk_score > 50
    } else := {
        "session_timeout_minutes": 240
    } if {
        calculated_risk_score > 25
    } else := {
        "session_timeout_minutes": 480
    }
    
    constraints := object.union(base, session_constraints)
}

generate_compliance_constraints := constraints if {
    base := {}
    
    # Audit requirements
    audit_constraints := {
        "audit_required": true,
        "detailed_logging": true
    } if {
        count(input.compliance_requirements) > 0
    } else := {}
    
    # Encryption requirements
    encryption_constraints := {
        "encryption_required": true,
        "encryption_algorithm": "AES-256"
    } if {
        "pci-dss" in input.compliance_requirements
    } else := {}
    
    constraints := object.union_n([base, audit_constraints, encryption_constraints])
}

generate_risk_constraints := constraints if {
    base := {}
    
    # High risk additional constraints
    risk_constraints := {
        "additional_approval_required": true,
        "monitoring_level": "enhanced",
        "session_recording": true
    } if {
        calculated_risk_score > 75
    } else := {
        "monitoring_level": "standard"  
    } if {
        calculated_risk_score > 40
    } else := {}
    
    constraints := object.union(base, risk_constraints)
}

# ============================================================================
# METADATA GENERATION
# ============================================================================

metadata := result if {
    base_metadata := {
        "policy_version": "1.0.0",
        "evaluation_timestamp": time.now_ns(),
        "tenant_id": input.enterprise.tenant_id,
        "risk_score": calculated_risk_score,
        "compliance_frameworks": input.compliance_requirements
    }
    
    # Add risk factors if high risk
    risk_metadata := {
        "risk_factors": [
            "high_privilege_action" | elevated_privileges_detected
        ] | [
            "outside_business_hours" | outside_business_hours  
        ] | [
            "external_network" | input.context.source_ip_external
        ] | [
            "sensitive_resource" | input.resource_namespace in ["production", "critical"]
        ]
    } if {
        calculated_risk_score > 50
    } else := {}
    
    # Add compliance metadata
    compliance_metadata := {
        "compliance_status": "verified",
        "compliance_checks_passed": input.compliance_requirements
    } if {
        count(input.compliance_requirements) > 0
    } else := {}
    
    result := object.union_n([base_metadata, risk_metadata, compliance_metadata])
}