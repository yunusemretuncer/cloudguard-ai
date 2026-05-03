"""CloudGuard AI — Agent Core"""
import sqlite3
from pathlib import Path

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.checkpoint.sqlite import SqliteSaver
from langgraph.prebuilt import create_react_agent

from app.agent.prompts import SYSTEM_PROMPT
from app.config import settings

from app.agent.tools.log_analyzer import (
    analyze_cloudtrail_logs,
    analyze_vpc_flow_logs,
    analyze_auth_logs,
)
from app.agent.tools.ip_reputation import check_ip_reputation


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
    """Agent cevabını string'e normalize et.

    LangChain'in AIMessage.content alanı duruma göre üç farklı tipte gelebilir:
    - str: Düz metin cevap (en yaygın)
    - list[dict]: Gemini'nin structured content blocks formatı,
                  tool kullanımı sonrası çıkabiliyor.
                  Örn: [{"type": "text", "text": "..."}, {"type": "tool_use", ...}]
    - list[str]: Bazı LLM'lerde parça parça cevap

    Hepsini tek string'e indirgiyoruz çünkü DB'ye Text olarak yazıyoruz ve
    UI string bekliyor.
    """
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for block in content:
            if isinstance(block, dict):
                # Gemini formatı: {"type": "text", "text": "..."}
                if block.get("type") == "text" and "text" in block:
                    parts.append(block["text"])
                # Diğer block tipleri (tool_use, image vs.) atlanır —
                # kullanıcıya göstermek istemiyoruz
            elif isinstance(block, str):
                parts.append(block)
        return "\n".join(parts).strip()
    # Beklenmedik tip — string'e zorla çevir
    return str(content)


def chat(message: str, thread_id: str = "default") -> str:
    agent = get_agent()
    config = {"configurable": {"thread_id": thread_id}}
    result = agent.invoke(
        {"messages": [("user", message)]},
        config=config,
    )
    last_message = result["messages"][-1]
    return _normalize_content(last_message.content)