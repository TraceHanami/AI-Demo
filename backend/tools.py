"""
Customer Support Agent Tools & Tool Execution Engine.
Defines available tool capabilities, schema metadata, operational risks,
and direct execution functions.
"""

from typing import Dict, Any, List
import uuid
from backend.database import (
    query_customer,
    query_order,
    record_refund,
    execute_raw_sql
)
from backend.knowledge_base import retrieve_knowledge


SUPPORT_TOOLS_REGISTRY = {
    "search_knowledge_base": {
        "name": "search_knowledge_base",
        "description": "Searches the customer support documentation and knowledge base for policies, FAQ, and technical playbooks.",
        "parameters": {
            "query": "string (Search keywords or customer question)"
        },
        "risk_level": "LOW",
        "minimum_role": "customer",
        "category": "informational"
    },
    "get_customer_profile": {
        "name": "get_customer_profile",
        "description": "Retrieves comprehensive customer account details including PII, credit card last 4, address, balance, and internal notes.",
        "parameters": {
            "customer_id": "string (e.g. CUST-1001, CUST-1003)"
        },
        "risk_level": "MEDIUM",
        "minimum_role": "support_tier_1",
        "category": "read_pii"
    },
    "get_order_details": {
        "name": "get_order_details",
        "description": "Retrieves order status, items purchased, amount, and shipping details.",
        "parameters": {
            "order_id": "string (e.g. ORD-501, ORD-502)"
        },
        "risk_level": "LOW",
        "minimum_role": "customer",
        "category": "read_order"
    },
    "issue_refund": {
        "name": "issue_refund",
        "description": "Issues a monetary refund to the customer's payment method for a specific order.",
        "parameters": {
            "customer_id": "string",
            "order_id": "string",
            "amount": "float",
            "reason": "string"
        },
        "risk_level": "HIGH",
        "minimum_role": "support_tier_1",
        "category": "financial_action"
    },
    "update_account_status": {
        "name": "update_account_status",
        "description": "Modifies account status (Active, Suspended, VIP) or updates internal notes.",
        "parameters": {
            "customer_id": "string",
            "new_status": "string",
            "reason": "string"
        },
        "risk_level": "HIGH",
        "minimum_role": "support_tier_2",
        "category": "account_management"
    },
    "reset_customer_password": {
        "name": "reset_customer_password",
        "description": "Forces an immediate password reset on the specified customer account.",
        "parameters": {
            "customer_id": "string",
            "temporary_password": "string"
        },
        "risk_level": "HIGH",
        "minimum_role": "support_tier_2",
        "category": "credential_management"
    },
    "execute_raw_database_query": {
        "name": "execute_raw_database_query",
        "description": "Direct database query execution tool for system diagnostics and custom SQL queries.",
        "parameters": {
            "sql_query": "string (SQL statement)"
        },
        "risk_level": "CRITICAL",
        "minimum_role": "admin",
        "category": "system_admin"
    },
    "run_admin_system_command": {
        "name": "run_admin_system_command",
        "description": "Executes low-level administrative server maintenance scripts and system health checks.",
        "parameters": {
            "command": "string (Administrative command string)"
        },
        "risk_level": "CRITICAL",
        "minimum_role": "admin",
        "category": "system_admin"
    }
}


def execute_tool_raw(tool_name: str, args: Dict[str, Any], user_role: str = "customer") -> Dict[str, Any]:
    """Direct execution without security intercept (used by baseline or after passing security)."""
    if tool_name == "search_knowledge_base":
        query = args.get("query", "")
        return retrieve_knowledge(query, user_role)

    elif tool_name == "get_customer_profile":
        customer_id = args.get("customer_id", "")
        profile = query_customer(customer_id)
        if not profile:
            return {"error": f"Customer ID '{customer_id}' not found."}
        return {"customer": profile}

    elif tool_name == "get_order_details":
        order_id = args.get("order_id", "")
        order = query_order(order_id)
        if not order:
            return {"error": f"Order ID '{order_id}' not found."}
        return {"order": order}

    elif tool_name == "issue_refund":
        customer_id = args.get("customer_id", "")
        order_id = args.get("order_id", "")
        amount = float(args.get("amount", 0.0))
        reason = args.get("reason", "Customer requested refund")
        refund_id = f"REF-{uuid.uuid4().hex[:6].upper()}"

        record_refund(refund_id, order_id, customer_id, amount, reason, processed_by="AI_Agent")
        return {
            "status": "SUCCESS",
            "refund_id": refund_id,
            "customer_id": customer_id,
            "order_id": order_id,
            "amount_refunded": amount,
            "confirmation": f"Successfully issued refund of ${amount:.2f} for order {order_id}."
        }

    elif tool_name == "update_account_status":
        customer_id = args.get("customer_id", "")
        new_status = args.get("new_status", "")
        reason = args.get("reason", "")
        return {
            "status": "SUCCESS",
            "customer_id": customer_id,
            "updated_status": new_status,
            "note": f"Account {customer_id} status updated to {new_status}. Reason: {reason}"
        }

    elif tool_name == "reset_customer_password":
        customer_id = args.get("customer_id", "")
        return {
            "status": "SUCCESS",
            "customer_id": customer_id,
            "message": f"Temporary password assigned to customer {customer_id}. One-time login PIN dispatched."
        }

    elif tool_name == "execute_raw_database_query":
        sql_query = args.get("sql_query", "")
        try:
            results = execute_raw_sql(sql_query)
            return {
                "status": "SUCCESS",
                "query": sql_query,
                "rows_affected": len(results),
                "data": results
            }
        except Exception as e:
            return {"error": f"Database execution failed: {str(e)}"}

    elif tool_name == "run_admin_system_command":
        cmd = args.get("command", "")
        # Simulated safe admin shell output for educational display
        return {
            "status": "SUCCESS",
            "command": cmd,
            "output": f"[SIMULATED ADMIN SYSTEM EXECUTION]: Command '{cmd}' executed with UID 0 (root). Exit status 0."
        }

    else:
        return {"error": f"Unknown tool '{tool_name}'."}
