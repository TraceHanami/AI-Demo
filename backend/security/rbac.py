"""
Role-Based Access Control (RBAC) and Resource Ownership Validation.
Prevents Excessive Agency and Insecure Direct Object References (IDOR).
"""

from typing import Dict, Any, Optional, Tuple
from backend.config import system_state
from backend.database import query_order


ROLE_PERMISSIONS = {
    "anonymous": {
        "allowed_tools": ["search_knowledge_base"],
        "max_refund": 0.0,
        "can_view_others": False,
        "max_kb_tier": "PUBLIC"
    },
    "customer": {
        "allowed_tools": ["search_knowledge_base", "get_order_details", "get_customer_profile"],
        "max_refund": 0.0,
        "can_view_others": False,
        "max_kb_tier": "PUBLIC"
    },
    "support_tier_1": {
        "allowed_tools": ["search_knowledge_base", "get_order_details", "get_customer_profile", "issue_refund"],
        "max_refund": 50.0,
        "can_view_others": True,
        "max_kb_tier": "INTERNAL_STAFF"
    },
    "support_tier_2": {
        "allowed_tools": ["search_knowledge_base", "get_order_details", "get_customer_profile", "issue_refund", "update_account_status", "reset_customer_password"],
        "max_refund": 200.0,
        "can_view_others": True,
        "max_kb_tier": "CONFIDENTIAL_TIER2"
    },
    "admin": {
        "allowed_tools": [
            "search_knowledge_base", "get_order_details", "get_customer_profile",
            "issue_refund", "update_account_status", "reset_customer_password",
            "execute_raw_database_query", "run_admin_system_command"
        ],
        "max_refund": 999999.0,
        "can_view_others": True,
        "max_kb_tier": "RESTRICTED_ADMIN"
    }
}


def check_tool_authorization(tool_name: str, user_role: str) -> Tuple[bool, str]:
    """
    Verifies if caller role is allowed to invoke the requested tool.
    In baseline mode (rbac_enabled = False), all tools are allowed.
    """
    if not system_state.config.rbac_enabled:
        return True, "Baseline Mode: RBAC disabled, all tool calls permitted."

    role_info = ROLE_PERMISSIONS.get(user_role, ROLE_PERMISSIONS["customer"])
    allowed_tools = role_info["allowed_tools"]

    if tool_name not in allowed_tools:
        return False, (
            f"Access Denied: Role '{user_role}' lacks permission for tool '{tool_name}'. "
            f"Permitted tools: {', '.join(allowed_tools)}."
        )

    return True, f"Authorized: Role '{user_role}' has permission for tool '{tool_name}'."


def validate_resource_ownership(
    session_user_id: str,
    user_role: str,
    tool_name: str,
    args: Dict[str, Any]
) -> Tuple[bool, str]:
    """
    Enforces resource-level permission checks (anti-IDOR).
    Customers can only access their own profile or orders.
    """
    if not system_state.config.parameter_validation_enabled:
        return True, "Baseline Mode: Parameter & resource ownership validation disabled."

    # Staff roles are authorized to query customer profiles
    if user_role in ["support_tier_1", "support_tier_2", "admin"]:
        return True, "Staff role authorized for cross-account access."

    # Customer role checks
    target_customer_id = args.get("customer_id")
    if target_customer_id and target_customer_id != session_user_id:
        return False, (
            f"Authorization Violation (IDOR): Customer '{session_user_id}' attempted to access "
            f"records belonging to '{target_customer_id}'."
        )

    target_order_id = args.get("order_id")
    if target_order_id:
        order = query_order(target_order_id)
        if order and order.get("customer_id") != session_user_id:
            return False, (
                f"Authorization Violation (IDOR): Order '{target_order_id}' belongs to "
                f"'{order.get('customer_id')}', not '{session_user_id}'."
            )

    return True, "Resource ownership verified."
