"""CloudGuard AI — Agent Core"""
import sqlite3
from pathlib import Path

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.prebuilt import create_react_agent

from app.agent.prompts import SYSTEM_PROMPT
from app.agent.tools.ip_reputation import check_ip_reputation
from app.agent.tools.log_analyzer import (
    analyze_auth_logs,
    analyze_cloudtrail_logs,
    analyze_vpc_flow_logs,
)
from app.config import settings

# Bu dosya: backend/app/agent/core.py
# Hedef path: backend/data/agent_memory.db
DB_PATH = Path(__file__).parent.parent.parent / "data" / "agent_memory.db"

_agent = None


def build_agent():
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        google_api_key=settings.gemini_api_key,
        temperature=0.2,
    )

    tools = [
        analyze_cloudtrail_logs,
        analyze_vpc_flow_logs,
        analyze_auth_logs,
        check_ip_reputation,
    ]

    # Kalıcı bellek — backend/data/ altında, mutlak path
    DB_PATH.parent.mkdir(exist_ok=True)  # data/ klasörü yoksa oluştur
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
    """Agent cevabını string'e normalize et."""
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
    """Agent'ın bu turda çağırdığı tool'ları çıkart.

    LangGraph mesaj zinciri tool kullanıldığında şöyle görünür:
        HumanMessage(user input)
        AIMessage(tool_calls=[{name, args, id}])    <- agent karar verdi
        ToolMessage(content=..., tool_call_id=...)  <- tool çıktısı
        AIMessage(content=final answer)             <- agent özetledi

    Bu turda yapılan tool çağrılarını döndürürüz. Önceki turlardaki
    çağrıları katmamak için sondan başa doğru gidip ilk HumanMessage'a
    kadar tarıyoruz.
    """
    tool_calls = []

    # Sondan başa: bu turun başlangıcını bul (en son HumanMessage)
    last_human_idx = -1
    for i in range(len(messages) - 1, -1, -1):
        msg = messages[i]
        if msg.__class__.__name__ == "HumanMessage":
            last_human_idx = i
            break

    if last_human_idx == -1:
        return []

    # Bu turdaki AIMessage'lardaki tool_calls'ları topla
    for msg in messages[last_human_idx + 1:]:
        if msg.__class__.__name__ == "AIMessage":
            calls = getattr(msg, "tool_calls", None) or []
            for call in calls:
                # call: {"name": "...", "args": {...}, "id": "..."}
                tool_calls.append({
                    "name": call.get("name", "unknown"),
                    "args": call.get("args", {}),
                })

    return tool_calls


def chat(message: str, thread_id: str = "default") -> dict:
    """Agent'a mesaj gönder, cevap + tool kullanımı döndür.

    Returns:
        {"reply": str, "tool_calls": [{"name": str, "args": dict}, ...]}
    """
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