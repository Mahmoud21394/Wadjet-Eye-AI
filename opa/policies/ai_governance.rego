# ai_governance.rego
# OPA Policy: AI Governance — model/tool/agent access control
# Enforces AI governance registry rules at the policy layer

package wadjet.ai_governance

import future.keywords.if
import future.keywords.in

default allow_model = false
default allow_tool  = false
default allow_agent = false

# Model allowlist — only approved models may be used
approved_models := {
    "gpt-4o",
    "claude-3-5-sonnet-20241022",
    "gemini-2.0-flash",
    "text-embedding-3-small",
    "text-embedding-ada-002",
}

allow_model if {
    input.model_id in approved_models
}

deny_model[msg] if {
    not allow_model
    msg := sprintf("Model '%v' is not in the approved model registry", [input.model_id])
}

# Tool allowlist per agent role
role_tool_allowlist := {
    "analyst":   {"search_iocs", "enrich_ip", "query_intel", "summarize_alert", "run_yara"},
    "responder": {"search_iocs", "enrich_ip", "block_ip", "isolate_host", "create_case"},
    "admin":     {"search_iocs", "enrich_ip", "block_ip", "isolate_host", "create_case",
                  "kill_process", "revoke_token", "execute_playbook"},
    "soar":      {"block_ip", "isolate_host", "kill_process", "quarantine_file",
                  "disable_account", "revoke_token", "execute_playbook"},
}

allow_tool if {
    tools := role_tool_allowlist[input.agent_role]
    input.tool_name in tools
}

deny_tool[msg] if {
    not allow_tool
    msg := sprintf("Tool '%v' not permitted for role '%v'", [input.tool_name, input.agent_role])
}

# High-risk actions require human approval
high_risk_actions := {
    "block_ip", "isolate_host", "kill_process", "quarantine_file",
    "disable_account", "revoke_token", "execute_playbook", "delete_object",
}

requires_human_approval if {
    input.action in high_risk_actions
}

allow_agent if {
    not requires_human_approval
}

allow_agent if {
    requires_human_approval
    input.human_approved == true
    input.approver_id != ""
}

deny_agent[msg] if {
    requires_human_approval
    not input.human_approved
    msg := sprintf("Action '%v' requires human approval before execution", [input.action])
}
