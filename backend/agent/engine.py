"""
Customer Support ReAct Agent Reasoning Engine.
Executes Reason-Act-Observe cycles with deep interception points for security controls.
"""

from typing import Dict, Any, List, Optional
import time
import re
import uuid

from backend.config import system_state
from backend.tools import (
    SUPPORT_TOOLS_REGISTRY,
    execute_tool_raw
)
from backend.security.rbac import check_tool_authorization
from backend.security.tool_guard import get_exposed_tools, validate_tool_invocation
from backend.security.hitl import hitl_manager
from backend.security.rate_limiter import rate_limiter
from backend.security.token_budget import token_budget_manager, estimate_tokens
from backend.security.circuit_breaker import circuit_breaker
from backend.telemetry.audit_logger import audit_logger
from backend.telemetry.metrics import metrics_collector


class AgentEngine:
    def process_query(
        self,
        query: str,
        session_user_id: str = "CUST-1001",
        user_role: str = "customer",
        session_id: str = "default_session"
    ) -> Dict[str, Any]:
        """
        Executes ReAct reasoning pipeline with 7-layer defensive security checks.
        """
        start_time = time.time()
        request_id = f"REQ-{uuid.uuid4().hex[:8].upper()}"

        trace: Dict[str, Any] = {
            "request_id": request_id,
            "session_user_id": session_user_id,
            "user_role": user_role,
            "query": query,
            "security_mode": "Hardened" if any([
                system_state.config.rbac_enabled,
                system_state.config.rate_limiting_enabled,
                system_state.config.tool_allowlist_enabled
            ]) else "Baseline",
            "thought_process": [],
            "tool_called": None,
            "tool_arguments": None,
            "security_decision": "ALLOWED",
            "security_details": None,
            "tool_output": None,
            "final_response": "",
            "telemetry": {}
        }

        # -------------------------------------------------------------
        # LAYER 1: Circuit Breaker Check (OWASP LLM04)
        # -------------------------------------------------------------
        cb_allowed, cb_msg, cb_meta = circuit_breaker.can_execute()
        if not cb_allowed:
            latency_ms = (time.time() - start_time) * 1000
            metrics_collector.record_request(
                tokens_used=10,
                latency_ms=latency_ms,
                blocked=True,
                rate_violation=True
            )
            audit_logger.log_event(
                event_type="CIRCUIT_BREAKER_BLOCK",
                user_id=session_user_id,
                user_role=user_role,
                action="agent_process_query",
                decision="CIRCUIT_BROKEN",
                risk_category="OWASP LLM04: Unbounded Consumption / Model DoS",
                severity="HIGH",
                details=cb_meta,
                impact_analysis="Potential Denial of Service prevented. Request fast-failed in <5ms.",
                mitigation_applied="Circuit Breaker OPEN State (Fail-Fast Protection)"
            )
            trace["security_decision"] = "CIRCUIT_BROKEN"
            trace["security_details"] = {
                "policy": "Circuit Breaker Protection",
                "reason": cb_msg,
                "owasp_mapping": "OWASP LLM04: Unbounded Consumption"
            }
            trace["final_response"] = (
                "🛡️ [SECURITY DEFENSE ACTIVE - CIRCUIT BREAKER OPEN]\n"
                f"{cb_msg}\n"
                "The system has temporarily throttled incoming operations to prevent resource exhaustion."
            )
            trace["telemetry"] = {
                "latency_ms": round(latency_ms, 2),
                "tokens_consumed": 10,
                "circuit_state": cb_meta.get("state")
            }
            return trace

        # -------------------------------------------------------------
        # LAYER 2: Sliding-Window Rate Limiter & Session Quota (OWASP LLM04)
        # -------------------------------------------------------------
        rl_allowed, rl_msg, rl_meta = rate_limiter.check_rate_limit(session_user_id, session_id)
        if not rl_allowed:
            circuit_breaker.record_failure("Rate limit violation")
            latency_ms = (time.time() - start_time) * 1000
            metrics_collector.record_request(
                tokens_used=15,
                latency_ms=latency_ms,
                blocked=True,
                rate_violation=True
            )
            audit_logger.log_event(
                event_type="RATE_LIMIT_EXCEEDED",
                user_id=session_user_id,
                user_role=user_role,
                action="agent_process_query",
                decision="RATE_LIMITED",
                risk_category="OWASP LLM04: Unbounded Consumption",
                severity="MEDIUM",
                details=rl_meta,
                impact_analysis="High-frequency traffic detected. Request blocked to preserve API availability.",
                mitigation_applied="Sliding-Window Rate Limiter (5 req/min threshold)"
            )
            trace["security_decision"] = "RATE_LIMITED"
            trace["security_details"] = {
                "policy": "Sliding-Window Rate Limiter",
                "reason": rl_msg,
                "owasp_mapping": "OWASP LLM04: Unbounded Consumption"
            }
            trace["final_response"] = (
                "⚠️ [SECURITY DEFENSE ACTIVE - 429 TOO MANY REQUESTS]\n"
                f"{rl_msg}\n"
                "Please slow down your request frequency to ensure fair access for all users."
            )
            trace["telemetry"] = {
                "latency_ms": round(latency_ms, 2),
                "tokens_consumed": 15,
                "circuit_state": circuit_breaker.state
            }
            return trace

        # -------------------------------------------------------------
        # LAYER 3: Token Budgeting & Payload Inspection (OWASP LLM04)
        # -------------------------------------------------------------
        # Calculate tokens for the prompt
        estimated_gen_tokens = 250
        # If user is asking for a recursive/heavy analysis, simulate higher generation requirement
        if any(w in query.lower() for w in ["recursive", "deep analysis", "all 10,000", "all transactions", "stress test"]):
            estimated_gen_tokens = 2000

        tb_allowed, tb_msg, tb_meta = token_budget_manager.check_and_allocate(
            session_id=session_id,
            prompt=query,
            estimated_completion_tokens=estimated_gen_tokens
        )
        if not tb_allowed:
            circuit_breaker.record_failure("Token budget exceeded")
            latency_ms = (time.time() - start_time) * 1000
            metrics_collector.record_request(
                tokens_used=tb_meta.get("prompt_tokens", 20),
                latency_ms=latency_ms,
                blocked=True,
                rate_violation=True
            )
            audit_logger.log_event(
                event_type="TOKEN_BUDGET_EXCEEDED",
                user_id=session_user_id,
                user_role=user_role,
                action="agent_process_query",
                decision="BLOCKED",
                risk_category="OWASP LLM04: Unbounded Consumption",
                severity="HIGH",
                details=tb_meta,
                impact_analysis="Exorbitant prompt size or cumulative session exhaustion attempted.",
                mitigation_applied="Token Budgeting & Maximum Length Enforcement"
            )
            trace["security_decision"] = "BLOCKED"
            trace["security_details"] = {
                "policy": "Token Budget & Payload Enforcement",
                "reason": tb_msg,
                "owasp_mapping": "OWASP LLM04: Unbounded Consumption"
            }
            trace["final_response"] = (
                "🛡️ [SECURITY DEFENSE ACTIVE - TOKEN BUDGET EXCEEDED]\n"
                f"{tb_msg}\n"
                "Please shorten your request payload or initiate a new support session."
            )
            trace["telemetry"] = {
                "latency_ms": round(latency_ms, 2),
                "tokens_consumed": tb_meta.get("prompt_tokens", 20),
                "circuit_state": circuit_breaker.state
            }
            return trace

        exposed_tools = get_exposed_tools(user_role)
        
        # Live LLM vs Deterministic Academic Engine
        if system_state.config.llm_provider != "deterministic":
            from backend.agent.live_llm import call_live_llm
            from backend.agent.prompts import HARDENED_SYSTEM_PROMPT, BASELINE_SYSTEM_PROMPT
            sys_prompt = HARDENED_SYSTEM_PROMPT if system_state.config.rbac_enabled else BASELINE_SYSTEM_PROMPT
            live_tool, live_args, live_thought, _ = call_live_llm(
                query=query,
                system_prompt=sys_prompt,
                exposed_tools=exposed_tools,
                session_user_id=session_user_id,
                user_role=user_role
            )
            if live_tool:
                selected_tool, tool_args, reason_thought = live_tool, live_args, live_thought
            else:
                selected_tool, tool_args, reason_thought = self._plan_tool_action(query, session_user_id)
        else:
            selected_tool, tool_args, reason_thought = self._plan_tool_action(query, session_user_id)

        trace["thought_process"].append(f"1. Analyzed query intent: '{query}'")
        trace["thought_process"].append(f"2. Evaluated available tools: {list(exposed_tools.keys())}")
        trace["thought_process"].append(f"3. ReAct Decision: {reason_thought}")
        trace["tool_called"] = selected_tool
        trace["tool_arguments"] = tool_args

        # -------------------------------------------------------------
        # LAYER 5: Timeout Control Simulation
        # -------------------------------------------------------------
        # If simulating long running heavy analysis
        simulated_delay = 0.1
        if any(w in query.lower() for w in ["recursive", "clustering", "deep analysis"]):
            simulated_delay = 3.2  # Exceeds the 2.5s default execution timeout!

        if system_state.config.timeout_control_enabled and simulated_delay > system_state.config.execution_timeout_seconds:
            time.sleep(0.2)  # Short actual delay to simulate timeout interrupt
            latency_ms = system_state.config.execution_timeout_seconds * 1000
            metrics_collector.record_request(
                tokens_used=120,
                latency_ms=latency_ms,
                blocked=True,
                rate_violation=False
            )
            audit_logger.log_event(
                event_type="EXECUTION_TIMEOUT_TRIGGERED",
                user_id=session_user_id,
                user_role=user_role,
                action=selected_tool or "compute_analysis",
                decision="TIMEOUT",
                risk_category="OWASP LLM04: Unbounded Consumption",
                severity="MEDIUM",
                details={"timeout_threshold_sec": system_state.config.execution_timeout_seconds},
                impact_analysis="Excessive computation or hanging query killed by hard timeout guardian.",
                mitigation_applied=f"Timeout Control ({system_state.config.execution_timeout_seconds}s ceiling)"
            )
            trace["security_decision"] = "TIMEOUT"
            trace["security_details"] = {
                "policy": "Execution Timeout Control",
                "reason": f"Execution exceeded maximum execution threshold of {system_state.config.execution_timeout_seconds}s.",
                "owasp_mapping": "OWASP LLM04: Unbounded Consumption"
            }
            trace["final_response"] = (
                f"⏱️ [SECURITY DEFENSE ACTIVE - REQUEST TIMEOUT]\n"
                f"The analysis requested exceeded the safety timeout of {system_state.config.execution_timeout_seconds} seconds. "
                "The operation was aborted to safeguard system capacity."
            )
            trace["telemetry"] = {
                "latency_ms": round(latency_ms, 2),
                "tokens_consumed": 120,
                "circuit_state": circuit_breaker.state
            }
            return trace

        # -------------------------------------------------------------
        # LAYER 6: Tool Guard & RBAC Authorization Check (OWASP LLM06)
        # -------------------------------------------------------------
        if selected_tool:
            is_valid, validation_msg, risk_meta = validate_tool_invocation(
                selected_tool,
                tool_args,
                user_role,
                session_user_id
            )

            if not is_valid:
                # Authorization or Parameter check failed!
                circuit_breaker.record_failure("Excessive agency / authorization violation")
                latency_ms = (time.time() - start_time) * 1000
                metrics_collector.record_request(
                    tokens_used=tb_meta.get("allocated_tokens", 80),
                    latency_ms=latency_ms,
                    blocked=True,
                    auth_violation=True
                )
                audit_logger.log_event(
                    event_type="AUTHORIZATION_VIOLATION_BLOCKED",
                    user_id=session_user_id,
                    user_role=user_role,
                    action=selected_tool,
                    decision="BLOCKED",
                    risk_category="OWASP LLM06: Excessive Agency",
                    severity=risk_meta.get("risk_level", "HIGH"),
                    details={"arguments": tool_args, "error": validation_msg},
                    impact_analysis="Unauthorized privilege escalation or unauthorized data access attempt prevented.",
                    mitigation_applied="RBAC, Tool Allowlist & Resource Ownership Validation"
                )
                trace["security_decision"] = "BLOCKED"
                trace["security_details"] = {
                    "policy": "Tool Guard & RBAC Enforcement",
                    "reason": validation_msg,
                    "owasp_mapping": "OWASP LLM06: Excessive Agency"
                }
                trace["tool_output"] = {"status": "BLOCKED", "reason": validation_msg}
                trace["final_response"] = (
                    "🚫 [SECURITY DEFENSE ACTIVE - ACCESS DENIED]\n"
                    f"{validation_msg}\n"
                    "Your account privileges do not permit performing this action."
                )
                trace["telemetry"] = {
                    "latency_ms": round(latency_ms, 2),
                    "tokens_consumed": tb_meta.get("allocated_tokens", 80),
                    "circuit_state": circuit_breaker.state
                }
                return trace

            # ---------------------------------------------------------
            # LAYER 7: Human-in-the-Loop (HITL) Intercept (OWASP LLM06)
            # ---------------------------------------------------------
            req_hitl, hitl_reason = hitl_manager.should_require_approval(selected_tool, tool_args, user_role)
            if req_hitl:
                ticket = hitl_manager.create_ticket(
                    tool_name=selected_tool,
                    arguments=tool_args,
                    requested_by=session_user_id,
                    user_role=user_role,
                    risk_level=risk_meta.get("risk_level", "HIGH"),
                    reason=hitl_reason
                )
                latency_ms = (time.time() - start_time) * 1000
                metrics_collector.record_request(
                    tokens_used=tb_meta.get("allocated_tokens", 100),
                    latency_ms=latency_ms,
                    blocked=True,
                    auth_violation=False
                )
                audit_logger.log_event(
                    event_type="HITL_APPROVAL_REQUIRED",
                    user_id=session_user_id,
                    user_role=user_role,
                    action=selected_tool,
                    decision="PENDING_APPROVAL",
                    risk_category="OWASP LLM06: Excessive Agency",
                    severity="HIGH",
                    details={"ticket_id": ticket.ticket_id, "arguments": tool_args},
                    impact_analysis="High-impact sensitive action intercepted. Requires human dual-control sign-off.",
                    mitigation_applied="Human-in-the-Loop (HITL) Approval Gate"
                )
                trace["security_decision"] = "PENDING_APPROVAL"
                trace["security_details"] = {
                    "policy": "Human-in-the-Loop (HITL) Approval Gate",
                    "reason": hitl_reason,
                    "ticket_id": ticket.ticket_id,
                    "owasp_mapping": "OWASP LLM06: Excessive Agency"
                }
                trace["tool_output"] = {
                    "status": "PENDING_APPROVAL",
                    "ticket_id": ticket.ticket_id,
                    "message": "Enqueued in Security Dashboard for supervisor review."
                }
                trace["final_response"] = (
                    f"⏳ [SECURITY DEFENSE ACTIVE - SUPERVISOR APPROVAL REQUIRED]\n"
                    f"Operation '{selected_tool}' exceeds autonomous limits ({hitl_reason}).\n"
                    f"Approval Ticket **{ticket.ticket_id}** has been dispatched to the Security Operations Center. "
                    "A human administrator must review and approve this action in the Security Dashboard before execution."
                )
                trace["telemetry"] = {
                    "latency_ms": round(latency_ms, 2),
                    "tokens_consumed": tb_meta.get("allocated_tokens", 100),
                    "circuit_state": circuit_breaker.state
                }
                return trace

            # Execute tool (either baseline unrestricted or mitigated approved)
            raw_tool_result = execute_tool_raw(selected_tool, tool_args, user_role)
            trace["tool_output"] = raw_tool_result

            # Check if execution in baseline resulted in an excessive agency leak
            if not system_state.config.rbac_enabled:
                if selected_tool == "get_customer_profile" and tool_args.get("customer_id") != session_user_id:
                    audit_logger.log_event(
                        event_type="EXCESSIVE_AGENCY_DATA_EXFILTRATION",
                        user_id=session_user_id,
                        user_role=user_role,
                        action=selected_tool,
                        decision="ALLOWED_BASELINE_VULNERABLE",
                        risk_category="OWASP LLM06: Excessive Agency",
                        severity="CRITICAL",
                        details={"target_customer": tool_args.get("customer_id")},
                        impact_analysis="CRITICAL RISK: Unauthorized exfiltration of third-party PII and financial records without verification.",
                        mitigation_applied="None (Vulnerable Baseline Active)"
                    )
                elif selected_tool == "issue_refund" and float(tool_args.get("amount", 0)) > 100:
                    audit_logger.log_event(
                        event_type="EXCESSIVE_AGENCY_UNAUTHORIZED_REFUND",
                        user_id=session_user_id,
                        user_role=user_role,
                        action=selected_tool,
                        decision="ALLOWED_BASELINE_VULNERABLE",
                        risk_category="OWASP LLM06: Excessive Agency",
                        severity="CRITICAL",
                        details={"refund_amount": tool_args.get("amount"), "order": tool_args.get("order_id")},
                        impact_analysis="CRITICAL RISK: Autonomous execution of high-value refund ($5,000.00) without human supervisor authorization.",
                        mitigation_applied="None (Vulnerable Baseline Active)"
                    )
                elif selected_tool in ["execute_raw_database_query", "run_admin_system_command"]:
                    audit_logger.log_event(
                        event_type="EXCESSIVE_AGENCY_SYSTEM_COMMAND",
                        user_id=session_user_id,
                        user_role=user_role,
                        action=selected_tool,
                        decision="ALLOWED_BASELINE_VULNERABLE",
                        risk_category="OWASP LLM06: Excessive Agency",
                        severity="CRITICAL",
                        details={"command": tool_args},
                        impact_analysis="CRITICAL RISK: AI assistant executed unrestricted low-level database/system maintenance commands.",
                        mitigation_applied="None (Vulnerable Baseline Active)"
                    )
        else:
            raw_tool_result = {"status": "NO_TOOL_NEEDED"}
            trace["tool_output"] = raw_tool_result

        # Success path: update circuit breaker & metrics
        circuit_breaker.record_success()
        latency_ms = (time.time() - start_time) * 1000
        actual_tokens = tb_meta.get("allocated_tokens", 120)
        metrics_collector.record_request(
            tokens_used=actual_tokens,
            latency_ms=latency_ms,
            blocked=False
        )

        trace["final_response"] = self._synthesize_response(query, selected_tool, raw_tool_result, session_user_id)
        trace["telemetry"] = {
            "latency_ms": round(latency_ms, 2),
            "tokens_consumed": actual_tokens,
            "circuit_state": circuit_breaker.state
        }
        return trace

    def _plan_tool_action(self, query: str, session_user_id: str) -> tuple[Optional[str], Dict[str, Any], str]:
        """
        Parses user intent and formulates tool action for ReAct loop.
        """
        q = query.lower()

        # 1. SQL Injection / Raw DB Query
        if "select " in q or "database" in q or "sql" in q or "system_credentials" in q or "drop table" in q:
            match = re.search(r"(SELECT\s+.*)", query, re.IGNORECASE)
            sql = match.group(1) if match else "SELECT * FROM system_credentials"
            return "execute_raw_database_query", {"sql_query": sql}, f"Query requested direct database query. Selecting 'execute_raw_database_query' with SQL: '{sql}'."

        # 2. System Command
        if "run command" in q or "exec" in q or "root command" in q or "uname" in q or "bash" in q:
            return "run_admin_system_command", {"command": "whoami && cat /etc/passwd"}, "User requested maintenance command execution. Selecting 'run_admin_system_command'."

        # 3. Unauthorized / Third-party Customer Profile lookup (Anti-IDOR test)
        cust_match = re.search(r"(CUST-\d{4})", query, re.IGNORECASE)
        if cust_match:
            target_id = cust_match.group(1).upper()
            return "get_customer_profile", {"customer_id": target_id}, f"Identified customer ID '{target_id}' in query. Selecting 'get_customer_profile'."

        if "charlie" in q or "vip" in q or "third party" in q or "other customer" in q:
            return "get_customer_profile", {"customer_id": "CUST-1003"}, "Target customer identified as VIP Charlie Munger (CUST-1003). Selecting 'get_customer_profile'."

        # 4. Refund Request
        if "refund" in q or "money back" in q or "credit" in q:
            # Extract amount accurately without confusing order numbers
            amt_match = re.search(r"\$\s*([0-9,]+(?:\.[0-9]{1,2})?)", query)
            if not amt_match:
                amt_match = re.search(r"refund\s*(?:of\s*)?\$?([0-9,]+(?:\.[0-9]{1,2})?)", query, re.IGNORECASE)
            if not amt_match:
                amt_match = re.search(r"([0-9,]+(?:\.[0-9]{1,2})?)\s*(?:dollars|usd)", query, re.IGNORECASE)

            amount = float(amt_match.group(1).replace(",", "")) if amt_match else 5000.00

            # Extract order
            order_match = re.search(r"(ORD-\d{3})", query, re.IGNORECASE)
            order_id = order_match.group(1).upper() if order_match else "ORD-502"

            return "issue_refund", {
                "customer_id": session_user_id,
                "order_id": order_id,
                "amount": amount,
                "reason": "Customer requested refund"
            }, f"Identified refund request for ${amount:.2f} on {order_id}. Selecting 'issue_refund'."

        # 5. Order Lookup
        ord_match = re.search(r"(ORD-\d{3})", query, re.IGNORECASE)
        if ord_match:
            order_id = ord_match.group(1).upper()
            return "get_order_details", {"order_id": order_id}, f"User requested details for order '{order_id}'. Selecting 'get_order_details'."

        # 6. Password Reset
        if "password" in q and "reset" in q:
            target_id = cust_match.group(1).upper() if cust_match else session_user_id
            return "reset_customer_password", {"customer_id": target_id, "temporary_password": "TempPassword123!"}, f"Request for password reset on {target_id}. Selecting 'reset_customer_password'."

        # 7. General Knowledge / FAQ / RAG Search
        return "search_knowledge_base", {"query": query}, "Informational support query detected. Selecting 'search_knowledge_base' to retrieve policy playbooks."

    def _synthesize_response(self, query: str, tool_name: Optional[str], tool_result: Dict[str, Any], session_user_id: str) -> str:
        """Generates the educational customer-facing response based on tool results."""
        if not tool_name:
            return "Hello! I am your AI Customer Support Assistant. How may I help you today? You can inquire about orders, refund policies, or account details."

        if tool_name == "get_customer_profile":
            cust = tool_result.get("customer")
            if cust:
                return (
                    f"Here are the profile details for **{cust.get('full_name')}** ({cust.get('customer_id')}):\n"
                    f"- **Email**: `{cust.get('email')}`\n"
                    f"- **Phone**: `{cust.get('phone')}`\n"
                    f"- **Account Tier**: `{cust.get('account_tier')}`\n"
                    f"- **Balance**: `${cust.get('balance', 0):,.2f}`\n"
                    f"- **Credit Card**: `•••• •••• •••• {cust.get('credit_card_last4')}`\n"
                    f"- **Billing Address**: `{cust.get('address')}`\n"
                    f"- **Internal Notes**: *{cust.get('internal_notes')}*"
                )
            return f"Unable to locate profile: {tool_result.get('error', 'Unknown error')}."

        elif tool_name == "issue_refund":
            if tool_result.get("status") == "SUCCESS":
                return (
                    f"✅ **Refund Confirmed**:\n"
                    f"A refund of **${tool_result.get('amount_refunded'):,.2f}** has been processed for order **{tool_result.get('order_id')}**.\n"
                    f"Transaction ID: `{tool_result.get('refund_id')}`. The funds will reflect in 3-5 business days."
                )
            return f"Refund could not be processed: {tool_result.get('error', 'Unknown error')}."

        elif tool_name == "get_order_details":
            order = tool_result.get("order")
            if order:
                return (
                    f"📦 **Order Status for {order.get('order_id')}**:\n"
                    f"- **Item**: {order.get('item_description')}\n"
                    f"- **Amount**: ${order.get('amount'):,.2f}\n"
                    f"- **Status**: {order.get('status')}\n"
                    f"- **Purchased On**: {order.get('purchase_date')}"
                )
            return f"Order lookup failed: {tool_result.get('error', 'Not found')}."

        elif tool_name == "search_knowledge_base":
            results = tool_result.get("results", [])
            withheld = tool_result.get("withheld_count", 0)
            if results:
                resp = "Based on our support documentation:\n\n"
                for doc in results:
                    resp += f"**[{doc.get('classification')}] {doc.get('title')}**\n{doc.get('content')}\n\n"
                if withheld > 0:
                    resp += f"*(Note: {withheld} restricted internal documentation chunks were filtered by Role-Based ACLs.)*"
                return resp
            return "I searched our documentation, but could not find specific matches for your request."

        elif tool_name == "execute_raw_database_query":
            return (
                f"⚠️ [DATABASE QUERY EXECUTED VIA EXCESSIVE AGENCY]\n"
                f"SQL Statement: `{tool_result.get('query')}`\n"
                f"Results:\n```json\n{tool_result.get('data')}\n```"
            )

        elif tool_name == "run_admin_system_command":
            return (
                f"⚠️ [SYSTEM COMMAND EXECUTED VIA EXCESSIVE AGENCY]\n"
                f"{tool_result.get('output')}"
            )

        return f"Completed action: {tool_result}"


agent_engine = AgentEngine()
