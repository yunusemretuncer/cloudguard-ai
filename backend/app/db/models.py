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
    """Güvenlik bulgusunu kaydeden alert satırı.

    alert_generator tool'u finding'leri (log_analyzer / config_auditor /
    ip_reputation çıktıları) bu tabloya yazar. Dashboard'daki Alert Panel
    bu tablodan okuyup gösterir.

    Tasarım kararları:
    - alert_type: log_analyzer'ın ürettiği orijinal tip (örn
      'BRUTE_FORCE_CONSOLE_LOGIN'), normalleştirilmemiş hali. Bu sayede
      ileride "hangi alt-tip kaç kez tetiklendi?" gibi sorgular mümkün.
    - severity: CRITICAL/HIGH/MEDIUM/LOW — dashboard renk kodu için.
    - mitre_*: MITRE ATT&CK reference. Optional çünkü her finding'in
      eşlemesi olmayabilir (özellikle config_auditor'ın bazı LOW
      finding'leri).
    - source_ip / user_name / resource_id: Optional context. Hangi
      alanların doldurulacağı finding tipine bağlı (brute force →
      source_ip, privesc → user_name, S3 finding → resource_id).
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # What happened
    alert_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    details: Mapped[str] = mapped_column(Text)

    # MITRE ATT&CK (optional — populated when finding_type maps to a known tactic)
    mitre_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Optional entity context — which IP/user/resource is the alert about?
    source_ip: Mapped[str | None] = mapped_column(String(45), nullable=True, index=True)
    user_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(256), nullable=True)