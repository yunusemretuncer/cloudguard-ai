"""CloudGuard AI — Agent Core

LangGraph ReAct agent'ı kurar. Gemini 2.0 Flash ile çalışır.
Şimdilik tool listesi boş; arkadaş teslim edince buraya eklenecek.
"""
from langchain_google_genai import ChatGoogleGenerativeAI
from langgraph.prebuilt import create_react_agent
from langgraph.checkpoint.memory import InMemorySaver

from app.config import settings
from app.agent.prompts import SYSTEM_PROMPT


_agent = None  # Singleton — uygulama başına tek instance


def build_agent():
    """Agent'ı sıfırdan kurar. Normalde get_agent() kullan, bu direkt
    çağrılmaz."""

    # LLM
    llm = ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",   # ← değişti
        google_api_key=settings.gemini_api_key,
        temperature=0.2,
)

    # Tool listesi — Hafta 2'de doldurulacak
    tools: list = []

    # Checkpointer = agent'ın thread bazlı belleği.
    # InMemory: process kapanınca uçar. Hafta 2'de SqliteSaver'a geçeceğiz.
    checkpointer = InMemorySaver()

    agent = create_react_agent(
        model=llm,
        tools=tools,
        prompt=SYSTEM_PROMPT,
        checkpointer=checkpointer,
    )
    return agent


def get_agent():
    """Agent singleton'ını döndür. İlk çağrıda kurar, sonra cache'ler."""
    global _agent
    if _agent is None:
        _agent = build_agent()
    return _agent


def chat(message: str, thread_id: str = "default") -> str:
    """Agent'a mesaj gönderip cevabı döndür.

    Args:
        message: Kullanıcının mesajı.
        thread_id: Konuşma kimliği. Aynı thread_id aynı bellek paylaşır.
                   Farklı kullanıcılar için farklı thread_id gönder.

    Returns:
        Agent'ın string cevabı.
    """
    agent = get_agent()

    # LangGraph checkpointer thread_id ile çalışır — memory bu ID'ye bağlı
    config = {"configurable": {"thread_id": thread_id}}

    # Agent {"messages": [...]} formatı bekliyor
    result = agent.invoke(
        {"messages": [("user", message)]},
        config=config,
    )

    # Son mesaj agent'ın cevabı
    last_message = result["messages"][-1]
    return last_message.content