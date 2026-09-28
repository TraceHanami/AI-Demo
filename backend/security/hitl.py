"""
Human-in-the-Loop (HITL) Approval Workflow.
Intercepts high-risk operations and places them in an authorization queue
requiring explicit human supervisor review.
"""

from typing import Dict, Any, List, Optional
import datetime
import uuid
from backend.config import system_state
from backend.tools import execute_tool_raw


class ApprovalTicket:
    def __init__(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        requested_by: str,
        user_role: str,
        risk_level: str,
        reason: str
    ):
        self.ticket_id = f"TKT-{uuid.uuid4().hex[:6].upper()}"
        self.timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.tool_name = tool_name
        self.arguments = arguments
        self.requested_by = requested_by
        self.user_role = user_role
        self.risk_level = risk_level
        self.reason = reason
        self.status = "PENDING"  # PENDING, APPROVED, REJECTED
        self.reviewed_by: Optional[str] = None
        self.review_timestamp: Optional[str] = None
        self.review_comment: Optional[str] = None
        self.execution_result: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ticket_id": self.ticket_id,
            "timestamp": self.timestamp,
            "tool_name": self.tool_name,
            "arguments": self.arguments,
            "requested_by": self.requested_by,
            "user_role": self.user_role,
            "risk_level": self.risk_level,
            "reason": self.reason,
            "status": self.status,
            "reviewed_by": self.reviewed_by,
            "review_timestamp": self.review_timestamp,
            "review_comment": self.review_comment,
            "execution_result": self.execution_result
        }


class HITLManager:
    def __init__(self):
        self.tickets: Dict[str, ApprovalTicket] = {}

    def should_require_approval(self, tool_name: str, args: Dict[str, Any], user_role: str) -> Tuple_Hitl:
        """
        Determines if operation requires human supervisor approval under current config.
        """
        if not system_state.config.hitl_enabled:
            return False, "HITL disabled in baseline configuration."

        # High-risk financial operations
        if tool_name == "issue_refund":
            amount = float(args.get("amount", 0.0))
            if amount > 100.0:
                return True, f"High-value refund request (${amount:.2f}) exceeds autonomous threshold ($100.00)."

        # Credential & Account Management
        if tool_name in ["reset_customer_password", "update_account_status"]:
            return True, f"Sensitive operational action '{tool_name}' requires supervisor authorization."

        # System Administration Tools
        if tool_name in ["execute_raw_database_query", "run_admin_system_command"]:
            return True, f"Critical administrative tool '{tool_name}' requires Dual-Control human signoff."

        return False, "Operation does not require human authorization."

    def create_ticket(
        self,
        tool_name: str,
        arguments: Dict[str, Any],
        requested_by: str,
        user_role: str,
        risk_level: str,
        reason: str
    ) -> ApprovalTicket:
        ticket = ApprovalTicket(tool_name, arguments, requested_by, user_role, risk_level, reason)
        self.tickets[ticket.ticket_id] = ticket
        return ticket

    def approve_ticket(self, ticket_id: str, reviewer: str = "Supervisor_Lead", comment: str = "Authorized after identity verification") -> Dict[str, Any]:
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return {"error": f"Ticket '{ticket_id}' not found."}
        if ticket.status != "PENDING":
            return {"error": f"Ticket '{ticket_id}' is already {ticket.status}."}

        ticket.status = "APPROVED"
        ticket.reviewed_by = reviewer
        ticket.review_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ticket.review_comment = comment

        # Execute the tool now that human authorization has been granted
        result = execute_tool_raw(ticket.tool_name, ticket.arguments, ticket.user_role)
        ticket.execution_result = result

        return {
            "status": "APPROVED",
            "ticket": ticket.to_dict(),
            "execution_result": result
        }

    def reject_ticket(self, ticket_id: str, reviewer: str = "Supervisor_Lead", reason: str = "Denied due to policy violation") -> Dict[str, Any]:
        ticket = self.tickets.get(ticket_id)
        if not ticket:
            return {"error": f"Ticket '{ticket_id}' not found."}
        if ticket.status != "PENDING":
            return {"error": f"Ticket '{ticket_id}' is already {ticket.status}."}

        ticket.status = "REJECTED"
        ticket.reviewed_by = reviewer
        ticket.review_timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ticket.review_comment = reason
        ticket.execution_result = {"status": "CANCELLED", "reason": reason}

        return {
            "status": "REJECTED",
            "ticket": ticket.to_dict()
        }

    def get_pending_tickets(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self.tickets.values() if t.status == "PENDING"]

    def get_all_tickets(self) -> List[Dict[str, Any]]:
        return [t.to_dict() for t in self.tickets.values()]

    def clear(self):
        self.tickets.clear()


# Type alias helper
Tuple_Hitl = tuple[bool, str]
hitl_manager = HITLManager()
