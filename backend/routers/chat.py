"""
Chat API Router.
Handles interactive chat messages, ReAct reasoning execution, and tool inspection.
"""

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field
from typing import Dict, Any, Optional

from backend.agent.engine import agent_engine
from backend.security.tool_guard import get_exposed_tools


router = APIRouter(prefix="/api", tags=["Chat"])


class ChatRequest(BaseModel):
    query: str = Field(..., description="User prompt or customer support query")
    user_id: str = Field(default="CUST-1001", description="Session user ID (e.g. CUST-1001, CUST-1002)")
    user_role: str = Field(default="customer", description="Caller role (customer, support_tier_1, support_tier_2, admin)")
    session_id: str = Field(default="session_web_001", description="Unique session identifier")


@router.post("/chat")
def handle_chat_message(req: ChatRequest) -> Dict[str, Any]:
    """
    Submits user prompt into the ReAct Agent Engine, executing security guard evaluations
    and returning execution traces, telemetry, and security impacts.
    """
    if not req.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty.")

    trace = agent_engine.process_query(
        query=req.query,
        session_user_id=req.user_id,
        user_role=req.user_role,
        session_id=req.session_id
    )
    return trace


@router.get("/tools")
def get_available_tools(user_role: str = "customer") -> Dict[str, Any]:
    """
    Returns the list of tools currently exposed to the LLM agent under active security posture.
    """
    tools = get_exposed_tools(user_role)
    return {
        "user_role": user_role,
        "count": len(tools),
        "tools": tools
    }
