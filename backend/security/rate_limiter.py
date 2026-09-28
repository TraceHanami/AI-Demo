"""
Sliding-Window Rate Limiter & Session Request Quota Manager.
Mitigates Unbounded Consumption / Model Denial of Service (OWASP LLM04).
"""

from typing import Dict, List, Tuple, Any
import time
from backend.config import system_state


class RateLimiter:
    def __init__(self):
        # Maps user_id / IP to list of timestamps
        self.request_timestamps: Dict[str, List[float]] = {}
        # Maps session_id to total request count
        self.session_counts: Dict[str, int] = {}

    def check_rate_limit(self, client_id: str, session_id: str) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Evaluates sliding-window rate limit and session quota.
        """
        now = time.time()
        window_seconds = 60.0

        # If rate limiting is disabled, permit all
        if not system_state.config.rate_limiting_enabled and not system_state.config.request_quota_enabled:
            return True, "Rate limiting and request quotas are disabled (Baseline Mode).", {
                "remaining_requests": 999,
                "current_rate": 0
            }

        # 1. Session Quota Check
        if system_state.config.request_quota_enabled:
            current_session_count = self.session_counts.get(session_id, 0)
            if current_session_count >= system_state.config.session_request_quota:
                return False, (
                    f"Session Quota Exceeded: You have reached the maximum quota of "
                    f"{system_state.config.session_request_quota} requests per session."
                ), {
                    "quota_limit": system_state.config.session_request_quota,
                    "session_count": current_session_count
                }

        # 2. Sliding Window Rate Limit Check
        if system_state.config.rate_limiting_enabled:
            timestamps = self.request_timestamps.get(client_id, [])
            # Evict timestamps older than 60s
            valid_timestamps = [t for t in timestamps if now - t < window_seconds]
            self.request_timestamps[client_id] = valid_timestamps

            limit = system_state.config.rate_limit_per_minute
            if len(valid_timestamps) >= limit:
                oldest_in_window = valid_timestamps[0]
                retry_after = round(window_seconds - (now - oldest_in_window), 1)
                return False, (
                    f"Rate Limit Exceeded: Maximum {limit} requests per minute allowed. "
                    f"Retry after {max(1.0, retry_after)} seconds."
                ), {
                    "limit": limit,
                    "current_rate": len(valid_timestamps),
                    "retry_after": max(1.0, retry_after)
                }

            # Valid request: record timestamp
            valid_timestamps.append(now)
            self.request_timestamps[client_id] = valid_timestamps

        # Increment session count
        self.session_counts[session_id] = self.session_counts.get(session_id, 0) + 1

        remaining = max(0, system_state.config.rate_limit_per_minute - len(self.request_timestamps.get(client_id, [])))
        return True, "Rate limit check passed.", {
            "remaining_requests": remaining,
            "session_requests": self.session_counts.get(session_id, 0)
        }

    def reset(self):
        self.request_timestamps.clear()
        self.session_counts.clear()


rate_limiter = RateLimiter()
