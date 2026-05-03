"""DB modelleri — chat mesajları, alert'ler vs."""
from datetime import datetime, timezone

from sqlalchemy import DateTime, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.db.database import Base


class ChatMessage(Base):
    """Bir konuşma turu: user mesajı + agent cevabı.

    Bu tablo kullanıcıya gösterilecek chat geçmişini tutar.
    Agent'ın iç durumu (tool call'lar, düşünce zinciri) LangGraph
    checkpointer'ında ayrıca tutuluyor — bunlar birbirinden bağımsız.
    """
    __tablename__ = "chat_messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    thread_id: Mapped[str] = mapped_column(String(64), index=True)
    user_message: Mapped[str] = mapped_column(Text)
    agent_reply: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

class Alert(Base):
    """Tool'ların ürettiği güvenlik alert'leri.

    alert_generator tool'u bu tabloya yazar.
    Frontend dashboard'u buradan okur.
    """
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    # CRITICAL, HIGH, MEDIUM, LOW
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(Text)
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    thread_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )
