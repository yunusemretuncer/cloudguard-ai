"""CloudGuard AI — Agent Core"""
import sqlite3

from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.sqlite import SqliteSaver

from app.config import settings
from app.agent.prompts import SYSTEM_PROMPT


_agent = None


def build_agent():
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        google_api_key=settings.gemini_api_key,
        temperature=0.2,
    )

    tools: list = []

    # Kalıcı bellek — agent_memory.db dosyasına yazılır
    # check_same_thread=False: FastAPI'nin thread pool'unda çalışabilmesi için
    conn = sqlite3.connect("agent_memory.db", check_same_thread=False)
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


def chat(message: str, thread_id: str = "default") -> str:
    agent = get_agent()
    config = {"configurable": {"thread_id": thread_id}}
    result = agent.invoke(
        {"messages": [("user", message)]},
        config=config,
    )
    return result["messages"][-1].content