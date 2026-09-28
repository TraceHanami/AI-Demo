"""
Security Audit Logger.
Maintains structured security events with OWASP LLM Top 10 mappings,
severity ratings, authorization contexts, and remediation records.
"""

from typing import List, Dict, Any, Optional
import datetime
import uuid


class AuditLogger:
    def __init__(self, max_entries: int = 200):
        self.max_entries = max_entries
        self.events: List[Dict[str, Any]] = []

    def log_event(
        self,
        event_type: str,
        user_id: str,
        user_role: str,
        action: str,
        decision: str,  # ALLOWED, BLOCKED, PENDING_APPROVAL, RATE_LIMITED, TIMEOUT
        risk_category: str,  # LLM06: Excessive Agency, LLM04: Unbounded Consumption, etc.
        severity: str,  # INFO, LOW, MEDIUM, HIGH, CRITICAL
        details: Dict[str, Any],
        impact_analysis: str,
        mitigation_applied: Optional[str] = None
    ) -> Dict[str, Any]:
        event = {
            "event_id": f"EVT-{uuid.uuid4().hex[:8].upper()}",
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "event_type": event_type,
            "user_id": user_id,
            "user_role": user_role,
            "action": action,
            "decision": decision,
            "risk_category": risk_category,
            "severity": severity,
            "details": details,
            "impact_analysis": impact_analysis,
            "mitigation_applied": mitigation_applied or "None (Baseline Configuration)"
        }
        self.events.insert(0, event)
        if len(self.events) > self.max_entries:
            self.events.pop()
        return event

    def get_events(self, limit: int = 50, category: Optional[str] = None) -> List[Dict[str, Any]]:
        if category:
            return [e for e in self.events if category.lower() in e["risk_category"].lower()][:limit]
        return self.events[:limit]

    def clear(self):
        self.events.clear()


audit_logger = AuditLogger()
