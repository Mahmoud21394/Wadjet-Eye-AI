# tenant_isolation.rego
# OPA Policy: Enforce tenant isolation on all API requests
# Every request must have a matching tenant context

package wadjet.tenant_isolation

import future.keywords.if
import future.keywords.in

default allow = false

# Allow if tenant context matches authenticated user
allow if {
    input.user.tenant_id != ""
    input.request.tenant_id == input.user.tenant_id
}

# SUPER_ADMIN can access any tenant
allow if {
    input.user.role == "SUPER_ADMIN"
}

# Public routes (health, auth) do not require tenant
allow if {
    input.request.path in public_paths
}

public_paths := {
    "/api/health",
    "/api/auth/login",
    "/api/auth/refresh",
    "/api/enterprise/saml/metadata",
}

# Deny cross-tenant data access
deny[msg] if {
    input.request.tenant_id != ""
    input.user.tenant_id != ""
    input.request.tenant_id != input.user.tenant_id
    input.user.role != "SUPER_ADMIN"
    msg := sprintf("Cross-tenant access denied: user=%v tenant=%v requested=%v",
        [input.user.id, input.user.tenant_id, input.request.tenant_id])
}
