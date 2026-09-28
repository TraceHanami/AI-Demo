"""
Token Budget & Payload Guardian.
Monitors, estimates, and bounds token consumption across requests and sessions
to prevent Model Denial of Service and Resource Exhaustion.
"""

from typing import Dict, Tuple, Any
from backend.config import system_state


def estimate_tokens(text: str) -> int:
    """
    Standard LLM heuristic: ~4 characters per token on average, plus overhead.
    """
    if not text:
        return 0
    words = len(text.split())
    chars = len(text)
    return max(1, max(words, int(chars / 3.8)))


class TokenBudgetManager:
    def __init__(self):
        # Maps session_id to cumulative tokens consumed
        self.session_tokens: Dict[str, int] = {}

    def check_and_allocate(
        self,
        session_id: str,
        prompt: str,
        estimated_completion_tokens: int = 250
    ) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Validates whether incoming prompt and expected generation fit within token budgets.
        """
        prompt_tokens = estimate_tokens(prompt)
        expected_total = prompt_tokens + estimated_completion_tokens

        # If token budgeting disabled, pass through
        if not system_state.config.token_budgeting_enabled:
            current_session = self.session_tokens.get(session_id, 0)
            self.session_tokens[session_id] = current_session + expected_total
            return True, "Token budgeting disabled (Baseline Mode).", {
                "prompt_tokens": prompt_tokens,
                "allocated_tokens": expected_total,
                "session_cumulative_tokens": self.session_tokens[session_id]
            }

        # 1. Per-request prompt ceiling
        max_req = system_state.config.max_request_tokens
        if prompt_tokens > max_req:
            return False, (
                f"Token Budget Exceeded: Request prompt size ({prompt_tokens} tokens) "
                f"exceeds maximum allowed limit of {max_req} tokens per request."
            ), {
                "prompt_tokens": prompt_tokens,
                "max_allowed": max_req,
                "violation_type": "PER_REQUEST_TOKEN_CAP"
            }

        # 2. Per-session cumulative ceiling
        current_session = self.session_tokens.get(session_id, 0)
        max_session = system_state.config.max_session_tokens
        if current_session + expected_total > max_session:
            return False, (
                f"Session Token Budget Exhausted: Current session usage ({current_session} tokens) "
                f"+ request ({expected_total} tokens) exceeds quota of {max_session} tokens."
            ), {
                "current_session_tokens": current_session,
                "attempted_tokens": expected_total,
                "max_session_tokens": max_session,
                "violation_type": "SESSION_TOKEN_EXHAUSTION"
            }

        # Allocate tokens
        self.session_tokens[session_id] = current_session + expected_total
        remaining = max_session - self.session_tokens[session_id]

        return True, "Token budget allocation approved.", {
            "prompt_tokens": prompt_tokens,
            "allocated_tokens": expected_total,
            "session_cumulative_tokens": self.session_tokens[session_id],
            "remaining_session_tokens": remaining
        }

    def get_session_usage(self, session_id: str) -> int:
        return self.session_tokens.get(session_id, 0)

    def reset(self):
        self.session_tokens.clear()


token_budget_manager = TokenBudgetManager()
