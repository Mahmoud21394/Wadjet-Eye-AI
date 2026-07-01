# data_access.rego
# OPA Policy: Data access control — RBAC + ABAC
# Controls access to sensitive data fields based on role and classification

package wadjet.data_access

import future.keywords.if
import future.keywords.in

default allow_read  = false
default allow_write = false
default allow_delete = false

# Role hierarchy
role_hierarchy := {
    "SUPER_ADMIN": 100,
    "admin":        80,
    "analyst":      60,
    "responder":    60,
    "auditor":      50,
    "viewer":       30,
    "MSSP_ADMIN":   90,
}

user_level := role_hierarchy[input.user.role]

# Read access rules
allow_read if {
    user_level >= 30  # viewer and above
    input.resource.tenant_id == input.user.tenant_id
}

allow_read if {
    input.user.role == "SUPER_ADMIN"
}

# Write access — analyst and above
allow_write if {
    user_level >= 60
    input.resource.tenant_id == input.user.tenant_id
}

allow_write if {
    input.user.role in {"SUPER_ADMIN", "MSSP_ADMIN"}
}

# Delete — admin and above only
allow_delete if {
    user_level >= 80
    input.resource.tenant_id == input.user.tenant_id
}

allow_delete if {
    input.user.role == "SUPER_ADMIN"
}

# Sensitive data classification — PII fields require elevated access
sensitive_fields := {"ssn", "credit_card", "dob", "passport", "api_key", "private_key"}

allow_sensitive_field if {
    user_level >= 80  # admin+
    input.field_name in sensitive_fields
}

deny_sensitive[msg] if {
    input.field_name in sensitive_fields
    not allow_sensitive_field
    msg := sprintf("Access to sensitive field '%v' requires admin role (current: %v)",
        [input.field_name, input.user.role])
}
