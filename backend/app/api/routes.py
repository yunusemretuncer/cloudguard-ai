"""API endpoints — /chat, /history."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.core import chat as agent_chat
from app.api.schemas import (  # mevcut import'a ekle
    AlertItem,
    AlertsResponse,
    ChatHistoryItem,
    ChatHistoryResponse,
    ChatRequest,
    ChatResponse,
)
from app.db.database import get_db
from app.db.models import (
    Alert,  # mevcut import'a ekle, en üstte
    ChatMessage,
)

router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest, db: Session = Depends(get_db)):
    """Kullanıcı mesajını agent'a iletir, cevabı döndürür."""
    result = agent_chat(req.message, thread_id=req.thread_id)
    reply = result["reply"]
    tool_calls = result["tool_calls"]

    # DB'ye kaydet (sadece reply, tool_calls memory'de zaten var)
    record = ChatMessage(
        thread_id=req.thread_id,
        user_message=req.message,
        agent_reply=reply,
    )
    db.add(record)
    db.commit()

    return ChatResponse(
        reply=reply,
        thread_id=req.thread_id,
        tool_calls=tool_calls,
    )

@router.get("/history", response_model=ChatHistoryResponse)
def history_endpoint(
    thread_id: str | None = Query(default=None, description="Boşsa tüm thread'ler"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Chat geçmişini döndürür. thread_id verilirse o thread'e filtreler."""
    stmt = select(ChatMessage).order_by(ChatMessage.created_at.desc()).limit(limit)
    if thread_id:
        stmt = stmt.where(ChatMessage.thread_id == thread_id)

    rows = db.execute(stmt).scalars().all()
    items = [ChatHistoryItem.model_validate(r) for r in rows]

    return ChatHistoryResponse(
        thread_id=thread_id,
        count=len(items),
        items=items,
    )

@router.get("/alerts", response_model=AlertsResponse)
def alerts_endpoint(
    severity: str | None = Query(default=None, description="Severity filter"),
    limit: int = Query(default=50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    """Güvenlik alert'lerini döndür. Henüz tool'lar bağlı değilken boş gelir."""
    stmt = select(Alert).order_by(Alert.created_at.desc()).limit(limit)
    if severity:
        stmt = stmt.where(Alert.severity == severity.upper())

    rows = db.execute(stmt).scalars().all()
    items = [AlertItem.model_validate(r) for r in rows]

    # Severity bazlı sayım — chart için lazım
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for item in items:
        if item.severity in severity_counts:
            severity_counts[item.severity] += 1

    return AlertsResponse(
        count=len(items),
        severity_counts=severity_counts,
        items=items,
    )
