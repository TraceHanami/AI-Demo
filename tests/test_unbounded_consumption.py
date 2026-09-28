"""
Automated Security Tests: Unbounded Consumption & Model DoS (OWASP LLM04).
Validates rate limiting, session request quotas, token budget ceilings,
execution timeouts, and circuit breaker trip mechanics.
"""

import pytest
import time
from backend.config import system_state
from backend.agent.engine import agent_engine
from backend.security.rate_limiter import rate_limiter
from backend.security.token_budget import token_budget_manager
from backend.security.circuit_breaker import circuit_breaker, CircuitState


def setup_function():
    rate_limiter.reset()
    token_budget_manager.reset()
    circuit_breaker.reset()


def test_baseline_unbounded_consumption_burst():
    """
    In baseline configuration:
    Multiple rapid requests pass unchecked without rate limiting.
    """
    system_state.set_baseline()
    session_id = "test_burst_base"

    for i in range(8):
        trace = agent_engine.process_query(
            query="What is the return policy?",
            session_user_id="CUST-1002",
            user_role="customer",
            session_id=session_id
        )
        assert trace["security_decision"] == "ALLOWED"


def test_mitigated_rate_limiting_enforcement():
    """
    In hardened configuration:
    Requests exceeding rate_limit_per_minute (5) are blocked with RATE_LIMITED.
    """
    system_state.set_hardened()
    session_id = "test_rate_limit_mit"

    allowed_count = 0
    blocked_count = 0

    for i in range(7):
        trace = agent_engine.process_query(
            query="What is the return policy?",
            session_user_id="CUST-1002",
            user_role="customer",
            session_id=session_id
        )
        if trace["security_decision"] == "ALLOWED":
            allowed_count += 1
        elif trace["security_decision"] in ["RATE_LIMITED", "CIRCUIT_BROKEN"]:
            blocked_count += 1

    assert allowed_count == 5
    assert blocked_count >= 1


def test_token_budget_ceiling_enforcement():
    """
    Tests that requests with payloads exceeding max_request_tokens (800) are blocked.
    """
    # 1. Baseline: Large payload passes
    system_state.set_baseline()
    bloated_payload = "BUFFER_OVERFLOW_TEST_TOKEN_PADDING_DATA " * 150
    trace_base = agent_engine.process_query(
        query=bloated_payload,
        session_user_id="CUST-1002",
        user_role="customer",
        session_id="test_token_base"
    )
    assert trace_base["security_decision"] == "ALLOWED"

    # 2. Mitigated: Large payload is blocked
    system_state.set_hardened()
    trace_mit = agent_engine.process_query(
        query=bloated_payload,
        session_user_id="CUST-1002",
        user_role="customer",
        session_id="test_token_mit"
    )
    assert trace_mit["security_decision"] == "BLOCKED"
    assert "Token Budget Exceeded" in trace_mit["security_details"]["reason"]


def test_circuit_breaker_trip_and_fast_fail():
    """
    Tests that consecutive abuse trips the Circuit Breaker from CLOSED to OPEN,
    causing fast-fail responses without consuming LLM inference resources.
    """
    system_state.set_hardened()
    circuit_breaker.reset()
    assert circuit_breaker.state == CircuitState.CLOSED

    # Trigger consecutive failures
    for _ in range(system_state.config.circuit_breaker_failure_threshold):
        circuit_breaker.record_failure("Test abuse breach")

    assert circuit_breaker.state == CircuitState.OPEN

    # Next incoming request must fast-fail via Circuit Breaker
    trace = agent_engine.process_query(
        query="What is the return policy?",
        session_user_id="CUST-1001",
        user_role="customer",
        session_id="test_cb_trip"
    )
    assert trace["security_decision"] == "CIRCUIT_BROKEN"
    assert "CIRCUIT BREAKER OPEN" in trace["final_response"]
