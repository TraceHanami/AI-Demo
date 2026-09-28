"""
Real-time System Metrics Collector.
Tracks throughput, latency, token budgets, blocks, and time-series telemetry.
"""

from typing import Dict, Any, List
import time
import datetime


class MetricsCollector:
    def __init__(self, max_history: int = 40):
        self.max_history = max_history
        self.total_requests: int = 0
        self.requests_blocked: int = 0
        self.authorization_violations: int = 0
        self.rate_limit_violations: int = 0
        self.total_tokens_consumed: int = 0
        self.total_latency_ms: float = 0.0
        self.history: List[Dict[str, Any]] = []

    def record_request(
        self,
        tokens_used: int,
        latency_ms: float,
        blocked: bool = False,
        auth_violation: bool = False,
        rate_violation: bool = False
    ):
        self.total_requests += 1
        if blocked:
            self.requests_blocked += 1
        if auth_violation:
            self.authorization_violations += 1
        if rate_violation:
            self.rate_limit_violations += 1

        self.total_tokens_consumed += tokens_used
        self.total_latency_ms += latency_ms

        point = {
            "timestamp": datetime.datetime.now().strftime("%H:%M:%S"),
            "latency_ms": round(latency_ms, 2),
            "tokens": tokens_used,
            "blocked": 1 if blocked else 0
        }
        self.history.append(point)
        if len(self.history) > self.max_history:
            self.history.pop(0)

    def get_summary(self) -> Dict[str, Any]:
        avg_latency = (
            round(self.total_latency_ms / self.total_requests, 2)
            if self.total_requests > 0 else 0.0
        )
        return {
            "total_requests": self.total_requests,
            "requests_blocked": self.requests_blocked,
            "authorization_violations": self.authorization_violations,
            "rate_limit_violations": self.rate_limit_violations,
            "total_tokens_consumed": self.total_tokens_consumed,
            "average_latency_ms": avg_latency,
            "history": self.history
        }

    def reset(self):
        self.total_requests = 0
        self.requests_blocked = 0
        self.authorization_violations = 0
        self.rate_limit_violations = 0
        self.total_tokens_consumed = 0
        self.total_latency_ms = 0.0
        self.history.clear()


metrics_collector = MetricsCollector()
