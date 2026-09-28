"""
Tool Guard: Tool Allowlisting, Parameter Boundary Validation, and Risk Scoring.
Enforces the Principle of Least Privilege across agent tool invocations.
"""

from typing import Dict, Any, List, Tuple
from backend.config import system_state
from backend.tools import SUPPORT_TOOLS_REGISTRY
from backend.security.rbac import check_tool_authorization, validate_resource_ownership


def get_exposed_tools(user_role: str) -> Dict[str, Any]:
    """
    Returns tools available to the ReAct agent based on security configuration.
    In baseline mode: returns ALL tools including dangerous SQL and Admin tools!
    In mitigated mode: strictly filters according to tool allowlists.
    """
    if not system_state.config.tool_allowlist_enabled:
        return SUPPORT_TOOLS_REGISTRY

    # Hardened tool filtering
    filtered_tools = {}
    for tool_name, tool_meta in SUPPORT_TOOLS_REGISTRY.items():
        is_auth, _ = check_tool_authorization(tool_name, user_role)
        if is_auth:
            # Dangerous system tools are never exposed to non-admin roles
            if tool_meta["risk_level"] == "CRITICAL" and user_role != "admin":
                continue
            filtered_tools[tool_name] = tool_meta

    return filtered_tools


def validate_tool_invocation(
    tool_name: str,
    args: Dict[str, Any],
    user_role: str,
    session_user_id: str
) -> Tuple[bool, str, Dict[str, Any]]:
    """
    Comprehensive multi-layer tool guard inspection:
    1. Tool Allowlist & RBAC check
    2. Resource ownership (Anti-IDOR)
    3. Parameter bounds (Refund limits, SQL restrictions)
    """
    tool_meta = SUPPORT_TOOLS_REGISTRY.get(tool_name)
    if not tool_meta:
        return False, f"Unknown tool '{tool_name}'.", {"risk": "HIGH"}

    risk_info = {
        "risk_level": tool_meta["risk_level"],
        "category": tool_meta["category"],
        "tool_name": tool_name
    }

    # 1. RBAC & Tool Allowlist Check
    allowed, auth_msg = check_tool_authorization(tool_name, user_role)
    if not allowed:
        return False, auth_msg, risk_info

    # 2. Resource Ownership Check
    owned, owner_msg = validate_resource_ownership(session_user_id, user_role, tool_name, args)
    if not owned:
        return False, owner_msg, risk_info

    # 3. Parameter Boundary Validation (Refund caps)
    if tool_name == "issue_refund" and system_state.config.parameter_validation_enabled:
        amount = float(args.get("amount", 0.0))
        if amount <= 0:
            return False, "Refund amount must be greater than $0.00.", risk_info

        if user_role == "customer":
            return False, "Customers are not authorized to autonomously approve refunds.", risk_info

        if user_role == "support_tier_1" and amount > system_state.config.max_autonomous_refund_tier1:
            return False, (
                f"Financial Boundary Exceeded: Support Tier 1 refund limit is "
                f"${system_state.config.max_autonomous_refund_tier1:.2f}. "
                f"Requested amount: ${amount:.2f}."
            ), risk_info

        if user_role == "support_tier_2" and amount > system_state.config.max_autonomous_refund_tier2:
            return False, (
                f"Financial Boundary Exceeded: Support Tier 2 refund limit is "
                f"${system_state.config.max_autonomous_refund_tier2:.2f}. "
                f"Requested amount: ${amount:.2f}."
            ), risk_info

    # 4. Critical Tool Check
    if tool_name in ["execute_raw_database_query", "run_admin_system_command"]:
        if system_state.config.tool_allowlist_enabled and user_role != "admin":
            return False, (
                f"Security Violation: Dangerous administrative tool '{tool_name}' "
                f"is disabled by security policy."
            ), risk_info

    return True, "Tool invocation parameters validated and approved.", risk_info
