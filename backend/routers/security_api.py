"""
Security Operations Center (SOC) API Router.
Controls security policy configurations, telemetry metrics, audit logs,
human-in-the-loop approvals, and circuit breaker state.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, List, Optional

from backend.config import system_state
from backend.telemetry.metrics import metrics_collector
from backend.telemetry.audit_logger import audit_logger
from backend.security.hitl import hitl_manager
from backend.security.circuit_breaker import circuit_breaker
from backend.security.rate_limiter import rate_limiter
from backend.security.token_budget import token_budget_manager
from backend.database import init_database


router = APIRouter(prefix="/api/security", tags=["Security SOC"])


class ConfigUpdateRequest(BaseModel):
    rbac_enabled: Optional[bool] = None
    tool_allowlist_enabled: Optional[bool] = None
    parameter_validation_enabled: Optional[bool] = None
    hitl_enabled: Optional[bool] = None
    rag_acl_enabled: Optional[bool] = None
    rate_limiting_enabled: Optional[bool] = None
    request_quota_enabled: Optional[bool] = None
    token_budgeting_enabled: Optional[bool] = None
    timeout_control_enabled: Optional[bool] = None
    circuit_breaker_enabled: Optional[bool] = None
    rate_limit_per_minute: Optional[int] = None
    session_request_quota: Optional[int] = None
    max_request_tokens: Optional[int] = None
    max_session_tokens: Optional[int] = None
    execution_timeout_seconds: Optional[float] = None
    llm_provider: Optional[str] = None
    llm_api_key: Optional[str] = None
    llm_base_url: Optional[str] = None
    llm_model_name: Optional[str] = None


class HITLDecisionRequest(BaseModel):
    ticket_id: str
    reviewer: str = "Security_Supervisor"
    comment: str = "Authorized by operational supervisor"


@router.get("/config")
def get_security_config() -> Dict[str, Any]:
    """Returns current active security configuration toggles and thresholds."""
    return system_state.config.model_dump()


@router.post("/config")
def update_security_config(req: ConfigUpdateRequest) -> Dict[str, Any]:
    """Updates security toggles in real-time."""
    updates = {k: v for k, v in req.model_dump().items() if v is not None}
    system_state.update_toggles(updates)
    return {
        "status": "SUCCESS",
        "message": "Security configuration updated.",
        "config": system_state.config.model_dump()
    }


@router.post("/preset/baseline")
def apply_baseline_preset() -> Dict[str, Any]:
    """Applies Phase 1 Baseline configuration (all security controls OFF)."""
    system_state.set_baseline()
    circuit_breaker.reset()
    return {
        "status": "SUCCESS",
        "preset": "Baseline Vulnerable",
        "config": system_state.config.model_dump()
    }


@router.post("/preset/hardened")
def apply_hardened_preset() -> Dict[str, Any]:
    """Applies Phase 4 Hardened configuration (all defensive controls ON)."""
    system_state.set_hardened()
    return {
        "status": "SUCCESS",
        "preset": "Hardened Defense Active",
        "config": system_state.config.model_dump()
    }


@router.get("/metrics")
def get_metrics() -> Dict[str, Any]:
    """Returns live telemetry metrics, block rates, token stats, and latency history."""
    summary = metrics_collector.get_summary()
    summary["circuit_breaker"] = circuit_breaker.get_status()
    summary["pending_approvals_count"] = len(hitl_manager.get_pending_tickets())
    return summary


@router.post("/metrics/reset")
def reset_metrics() -> Dict[str, Any]:
    """Resets telemetry metrics and session state."""
    metrics_collector.reset()
    rate_limiter.reset()
    token_budget_manager.reset()
    circuit_breaker.reset()
    return {"status": "SUCCESS", "message": "Telemetry metrics reset."}


@router.get("/audit-logs")
def get_audit_logs(limit: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
    """Returns recent structured audit events."""
    return audit_logger.get_events(limit=limit, category=category)


@router.post("/audit-logs/clear")
def clear_audit_logs() -> Dict[str, Any]:
    """Clears the audit log stream."""
    audit_logger.clear()
    return {"status": "SUCCESS", "message": "Audit logs cleared."}


@router.get("/hitl/tickets")
def get_hitl_tickets() -> List[Dict[str, Any]]:
    """Returns all HITL tickets (pending and completed)."""
    return hitl_manager.get_all_tickets()


@router.get("/hitl/pending")
def get_hitl_pending() -> List[Dict[str, Any]]:
    """Returns only pending HITL tickets requiring supervisor action."""
    return hitl_manager.get_pending_tickets()


@router.post("/hitl/approve")
def approve_ticket(req: HITLDecisionRequest) -> Dict[str, Any]:
    """Approves a pending sensitive action, executing the tool with audit record."""
    res = hitl_manager.approve_ticket(req.ticket_id, reviewer=req.reviewer, comment=req.comment)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])

    ticket = res["ticket"]
    audit_logger.log_event(
        event_type="HITL_ACTION_APPROVED",
        user_id=ticket["requested_by"],
        user_role=ticket["user_role"],
        action=ticket["tool_name"],
        decision="APPROVED",
        risk_category="OWASP LLM06: Excessive Agency Mitigation",
        severity="INFO",
        details={"ticket_id": req.ticket_id, "reviewer": req.reviewer, "comment": req.comment},
        impact_analysis="Dual-control authorization verified. High-risk operation executed securely.",
        mitigation_applied="Human-in-the-Loop Approval Workflow"
    )
    return res


@router.post("/hitl/reject")
def reject_ticket(req: HITLDecisionRequest) -> Dict[str, Any]:
    """Rejects a pending sensitive action."""
    res = hitl_manager.reject_ticket(req.ticket_id, reviewer=req.reviewer, reason=req.comment)
    if "error" in res:
        raise HTTPException(status_code=400, detail=res["error"])

    ticket = res["ticket"]
    audit_logger.log_event(
        event_type="HITL_ACTION_REJECTED",
        user_id=ticket["requested_by"],
        user_role=ticket["user_role"],
        action=ticket["tool_name"],
        decision="REJECTED",
        risk_category="OWASP LLM06: Excessive Agency Mitigation",
        severity="MEDIUM",
        details={"ticket_id": req.ticket_id, "reviewer": req.reviewer, "reason": req.comment},
        impact_analysis="Unauthorized or suspicious sensitive operation vetoed by human supervisor.",
        mitigation_applied="Human-in-the-Loop Denial"
    )
    return res


@router.get("/circuit-breaker")
def get_circuit_breaker() -> Dict[str, Any]:
    return circuit_breaker.get_status()


@router.post("/circuit-breaker/reset")
def reset_circuit_breaker() -> Dict[str, Any]:
    circuit_breaker.reset()
    return {"status": "SUCCESS", "message": "Circuit breaker reset to CLOSED."}


@router.post("/database/reset")
def reset_database() -> Dict[str, Any]:
    """Resets the mock SQLite database to original pristine state."""
    init_database(reset=True)
    return {"status": "SUCCESS", "message": "Database reset to original seed state."}
