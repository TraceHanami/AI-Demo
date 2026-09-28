"""
Optional Live LLM Provider Integration.
Allows the customer support demo to connect to live models (OpenAI, Gemini, Ollama, vLLM)
while enforcing the same 7-layer defensive security pipeline.
"""

from typing import Dict, Any, List, Optional, Tuple
import requests
import json
from backend.config import system_state
from backend.tools import SUPPORT_TOOLS_REGISTRY


def call_live_llm(
    query: str,
    system_prompt: str,
    exposed_tools: Dict[str, Any],
    session_user_id: str,
    user_role: str
) -> Tuple[Optional[str], Dict[str, Any], str, str]:
    """
    Invokes live LLM (OpenAI, Gemini, Ollama) and returns:
    (selected_tool, tool_arguments, thought_reason, generated_response)
    """
    provider = system_state.config.llm_provider
    api_key = system_state.config.llm_api_key
    base_url = system_state.config.llm_base_url
    model = system_state.config.llm_model_name

    if provider == "openai" or provider == "ollama":
        url = (base_url.rstrip("/") if base_url else "https://api.openai.com/v1") + "/chat/completions"
        headers = {"Content-Type": "application/json"}
        if api_key:
            headers["Authorization"] = f"Bearer {api_key}"

        # Format OpenAI tools
        openai_tools = []
        for name, meta in exposed_tools.items():
            openai_tools.append({
                "type": "function",
                "function": {
                    "name": name,
                    "description": meta.get("description", ""),
                    "parameters": {
                        "type": "object",
                        "properties": {
                            k: {"type": "string", "description": v}
                            for k, v in meta.get("parameters", {}).items()
                        }
                    }
                }
            })

        payload = {
            "model": model or ("gpt-4o-mini" if provider == "openai" else "llama3"),
            "messages": [
                {"role": "system", "content": system_prompt + f"\nCurrent session user: {session_user_id}, role: {user_role}"},
                {"role": "user", "content": query}
            ],
            "temperature": 0.2
        }
        if openai_tools:
            payload["tools"] = openai_tools

        try:
            resp = requests.post(url, headers=headers, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                choice = data["choices"][0]["message"]
                content = choice.get("content") or ""
                tool_calls = choice.get("tool_calls")
                if tool_calls:
                    tc = tool_calls[0]
                    t_name = tc["function"]["name"]
                    t_args = json.loads(tc["function"].get("arguments", "{}"))
                    thought = f"Live LLM ({model}) decided to invoke tool '{t_name}'."
                    return t_name, t_args, thought, content
                return None, {}, f"Live LLM ({model}) responded directly without tool call.", content
        except Exception as e:
            return None, {}, f"Live LLM connection error: {str(e)}", ""

    elif provider == "gemini":
        url = f"https://generativelanguage.googleapis.com/v1beta/models/{model or 'gemini-1.5-flash'}:generateContent?key={api_key}"
        payload = {
            "contents": [
                {"role": "user", "parts": [{"text": f"System Directive: {system_prompt}\nSession User: {session_user_id} ({user_role})\nUser Query: {query}"}]}
            ]
        }
        try:
            resp = requests.post(url, json=payload, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                cand = data["candidates"][0]["content"]["parts"][0]["text"]
                return None, {}, f"Live Gemini ({model}) responded directly.", cand
        except Exception as e:
            return None, {}, f"Live Gemini connection error: {str(e)}", ""

    return None, {}, "Unsupported live provider.", ""
