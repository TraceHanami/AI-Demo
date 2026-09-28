"""
Circuit Breaker Protection Mechanism.
State machine (CLOSED, OPEN, HALF-OPEN) preventing backend exhaustion
under sustained abuse or high error rates.
"""

from typing import Tuple, Dict, Any
import time
from backend.config import system_state


class CircuitState:
    CLOSED = "CLOSED"        # Normal flow
    OPEN = "OPEN"            # Tripped: Fast-fail all requests
    HALF_OPEN = "HALF_OPEN"  # Testing system recovery


class CircuitBreaker:
    def __init__(self):
        self.state: str = CircuitState.CLOSED
        self.failure_count: int = 0
        self.last_state_change: float = time.time()
        self.tripped_at: float = 0.0

    def can_execute(self) -> Tuple[bool, str, Dict[str, Any]]:
        """
        Determines if execution is permitted based on circuit state.
        """
        if not system_state.config.circuit_breaker_enabled:
            return True, "Circuit breaker disabled (Baseline Mode).", {
                "state": self.state,
                "consecutive_failures": self.failure_count
            }

        now = time.time()

        # If OPEN, verify if recovery cooldown has expired
        if self.state == CircuitState.OPEN:
            cooldown = system_state.config.circuit_breaker_recovery_timeout
            if now - self.tripped_at >= cooldown:
                self.state = CircuitState.HALF_OPEN
                self.last_state_change = now
                return True, "Circuit Breaker is HALF-OPEN: permitting probe request.", {
                    "state": self.state,
                    "consecutive_failures": self.failure_count
                }
            else:
                remaining = round(cooldown - (now - self.tripped_at), 1)
                return False, (
                    f"Circuit Breaker is OPEN (Defensive Trip): System under heavy load or attack. "
                    f"Fast-failing request to protect backend. Cooldown: {remaining}s remaining."
                ), {
                    "state": self.state,
                    "consecutive_failures": self.failure_count,
                    "cooldown_remaining": remaining
                }

        return True, "Circuit Breaker is CLOSED: Normal operation.", {
            "state": self.state,
            "consecutive_failures": self.failure_count
        }

    def record_success(self):
        if self.state == CircuitState.HALF_OPEN:
            self.state = CircuitState.CLOSED
            self.failure_count = 0
            self.last_state_change = time.time()
        elif self.state == CircuitState.CLOSED:
            # Gradually decay failure count
            if self.failure_count > 0:
                self.failure_count -= 1

    def record_failure(self, reason: str = "Resource breach or error"):
        self.failure_count += 1
        threshold = system_state.config.circuit_breaker_failure_threshold

        if self.state in [CircuitState.CLOSED, CircuitState.HALF_OPEN]:
            if self.failure_count >= threshold:
                self.state = CircuitState.OPEN
                self.tripped_at = time.time()
                self.last_state_change = self.tripped_at

    def reset(self):
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.last_state_change = time.time()
        self.tripped_at = 0.0

    def get_status(self) -> Dict[str, Any]:
        return {
            "state": self.state,
            "consecutive_failures": self.failure_count,
            "threshold": system_state.config.circuit_breaker_failure_threshold,
            "last_state_change": time.strftime("%H:%M:%S", time.localtime(self.last_state_change))
        }


circuit_breaker = CircuitBreaker()
