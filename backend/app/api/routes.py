"""API endpoints — /chat, /history."""
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.agent.core import chat as agent_chat
from app.api.schemas import (
    ChatHistoryItem,
    ChatHistoryResponse,
    ChatRequest,
    ChatResponse,
)
from app.db.database import get_db
from app.db.models import ChatMessage

router = APIRouter()


@router.post("/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest, db: Session = Depends(get_db)):
    """Kullanıcı mesajını agent'a iletir, cevabı döndürür.
    Konuşmayı DB'ye kaydeder."""
    reply = agent_chat(req.message, thread_id=req.thread_id)

    # DB'ye kaydet
    record = ChatMessage(
        thread_id=req.thread_id,
        user_message=req.message,
        agent_reply=reply,
    )
    db.add(record)
    db.commit()

    return ChatResponse(reply=reply, thread_id=req.thread_id)


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
