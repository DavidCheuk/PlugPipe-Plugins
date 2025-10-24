# Simple OPA Policy Example for PlugPipe
# Demonstrates basic policy structure and common patterns

package plugpipe.simple

import future.keywords.if

# Default deny
default allow := false

# Allow if basic RBAC allows
allow if {
    input.basic_decision.allow
}

# Admin override - admins can do anything
allow if {
    "admin" in input.context.roles
}

# Developers can read and execute plugins
allow if {
    "developer" in input.context.roles
    input.resource_type == "plugin"
    input.action in ["read", "execute"]
}

# Operators can only execute
allow if {
    "operator" in input.context.roles
    input.action == "execute"
}

# Everyone can read public resources
allow if {
    input.resource_namespace == "public"
    input.action == "read"
}

# Simple constraints for plugin execution
constraints := {
    "memory_limit_mb": 256,
    "timeout_seconds": 30
} if {
    allow
    input.action == "execute"
    input.resource_type == "plugin"
}