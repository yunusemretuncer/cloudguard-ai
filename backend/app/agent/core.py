"""CloudGuard AI — Agent Core"""
import sqlite3
from pathlib import Path

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.prebuilt import create_react_agent

from app.agent.prompts import SYSTEM_PROMPT
from app.agent.tools.alert_generator import generate_alert
from app.agent.tools.config_auditor import audit_cloud_config
from app.agent.tools.ip_reputation import check_ip_reputation
from app.agent.tools.log_analyzer import (
    analyze_auth_logs,
    analyze_cloudtrail_logs,
    analyze_vpc_flow_logs,
)
from app.agent.tools.remediation import get_remediation
from app.config import settings

DB_PATH = Path(__file__).parent.parent.parent / "data" / "agent_memory.db"

_agent = None


def build_agent():
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        google_api_key=settings.gemini_api_key,
        temperature=0.2,
    )

    tools = [
        # Detection (log analiz)
        analyze_cloudtrail_logs,
        analyze_vpc_flow_logs,
        analyze_auth_logs,
        # Detection (config audit)
        audit_cloud_config,
        # Threat intel
        check_ip_reputation,
        # Persistence
        generate_alert,
        # Response
        get_remediation,
    ]

    DB_PATH.parent.mkdir(exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), check_same_thread=False)
    checkpointer = SqliteSaver(conn)

    agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=SYSTEM_PROMPT,
        checkpointer=checkpointer,
    )
    return agent


def get_agent():
    global _agent
    if _agent is None:
        _agent = build_agent()
    return _agent


def _normalize_content(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                if block.get("type") == "text" and "text" in block:
                    parts.append(block["text"])
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts).strip()
    return str(content)


def _extract_tool_calls(messages: list) -> list[dict]:
    tool_calls = []
    last_human_idx = -1
    for i in range(len(messages) - 1, -1, -1):
        if messages[i].__class__.__name__ == "HumanMessage":
            last_human_idx = i
            break
    if last_human_idx == -1:
        return []
    for msg in messages[last_human_idx + 1:]:
        if msg.__class__.__name__ == "AIMessage":
            calls = getattr(msg, "tool_calls", None) or []
            for call in calls:
                tool_calls.append({
                    "name": call.get("name", "unknown"),
                    "args": call.get("args", {}),
                })
    return tool_calls


def chat(message: str, thread_id: str = "default") -> dict:
    agent = get_agent()
    config = {"configurable": {"thread_id": thread_id}}
    result = agent.invoke(
        {"messages": [("user", message)]},
        config=config,
    )
    messages = result["messages"]
    return {
        "reply": _normalize_content(messages[-1].content),
        "tool_calls": _extract_tool_calls(messages),
    }
