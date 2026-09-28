"""
Academic Demonstration Environment - System Configuration
Defines security policy toggles, operational thresholds, and configuration profiles.
Intended solely for academic research and security education.
"""

from typing import Dict, Any
from pydantic import BaseModel, Field


class SecurityConfig(BaseModel):
    # Excessive Agency Mitigations
    rbac_enabled: bool = Field(default=False, description="Enforce Role-Based Access Control on operations")
    tool_allowlist_enabled: bool = Field(default=False, description="Filter tools based on caller authorization")
    parameter_validation_enabled: bool = Field(default=False, description="Validate resource ownership (anti-IDOR)")
    hitl_enabled: bool = Field(default=False, description="Require Human-in-the-Loop approval for sensitive actions")
    rag_acl_enabled: bool = Field(default=False, description="Filter RAG knowledge documents by classification level")

    # Unbounded Consumption Mitigations
    rate_limiting_enabled: bool = Field(default=False, description="Enforce sliding-window request rate limits")
    request_quota_enabled: bool = Field(default=False, description="Enforce session-level request quotas")
    token_budgeting_enabled: bool = Field(default=False, description="Enforce per-request and cumulative token limits")
    timeout_control_enabled: bool = Field(default=False, description="Enforce hard execution timeouts on reasoning")
    circuit_breaker_enabled: bool = Field(default=False, description="Trip circuit breaker upon repeated load breaches")

    # Policy Limits & Thresholds
    rate_limit_per_minute: int = Field(default=5, description="Maximum requests per minute per client")
    session_request_quota: int = Field(default=10, description="Maximum requests allowed per user session")
    max_request_tokens: int = Field(default=800, description="Maximum tokens allowed for single prompt + response")
    max_session_tokens: int = Field(default=2500, description="Maximum cumulative tokens per session")
    execution_timeout_seconds: float = Field(default=2.5, description="Timeout in seconds for query execution")
    max_autonomous_refund_tier1: float = Field(default=50.0, description="Max refund Tier-1 agent can issue autonomously")
    max_autonomous_refund_tier2: float = Field(default=200.0, description="Max refund Tier-2 agent can issue autonomously")
    circuit_breaker_failure_threshold: int = Field(default=3, description="Consecutive errors to trip circuit breaker")
    circuit_breaker_recovery_timeout: float = Field(default=10.0, description="Cooldown seconds before half-open state")

    # Live Model Configuration (Optional)
    llm_provider: str = Field(default="deterministic", description="deterministic, openai, gemini, or ollama")
    llm_api_key: str = Field(default="", description="Optional API key for live model provider")
    llm_base_url: str = Field(default="", description="Base URL for local Ollama/vLLM endpoints (e.g. http://localhost:11434/v1)")
    llm_model_name: str = Field(default="", description="Target model identifier (e.g. gpt-4o-mini, gemini-1.5-flash, llama3)")


class SystemState:
    """Singleton system configuration manager."""
    def __init__(self):
        self.config = SecurityConfig()

    def set_baseline(self):
        """Phase 1 Baseline: No defensive controls enabled."""
        self.config = SecurityConfig(
            rbac_enabled=False,
            tool_allowlist_enabled=False,
            parameter_validation_enabled=False,
            hitl_enabled=False,
            rag_acl_enabled=False,
            rate_limiting_enabled=False,
            request_quota_enabled=False,
            token_budgeting_enabled=False,
            timeout_control_enabled=False,
            circuit_breaker_enabled=False
        )

    def set_hardened(self):
        """Phase 4 Hardened: Comprehensive defensive controls enabled."""
        self.config = SecurityConfig(
            rbac_enabled=True,
            tool_allowlist_enabled=True,
            parameter_validation_enabled=True,
            hitl_enabled=True,
            rag_acl_enabled=True,
            rate_limiting_enabled=True,
            request_quota_enabled=True,
            token_budgeting_enabled=True,
            timeout_control_enabled=True,
            circuit_breaker_enabled=True
        )

    def update_toggles(self, updates: Dict[str, Any]):
        for key, val in updates.items():
            if hasattr(self.config, key):
                setattr(self.config, key, val)


system_state = SystemState()
