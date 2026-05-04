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

    alert_generator tool'u bu tabloya yazar (log_analyzer / config_auditor /
    ip_reputation çıktıları). Frontend dashboard'u buradan okur.

    Tasarım kararları (birleşik şema):
    - finding_type: tool'un ürettiği orijinal finding tipi (örn
      'BRUTE_FORCE_CONSOLE_LOGIN'). Normalleştirme alert_generator
      tarafında yapılır, ham hali burada saklanır.
    - title + detail ayrımı: dashboard'da kart başlığı (title) ve
      genişletilince detay (detail) için.
    - mitre_*: 3 ayrı alan (id, tactic, technique) — rapor ve
      dashboard'da MITRE ATT&CK referansını eksiksiz göstermek için.
    - source_ip / user_name / resource_id: Optional context. Hangi
      alanların doldurulacağı finding tipine bağlı.
    - thread_id: alert'i çıkaran chat thread'i. Dashboard'da
      "bu alert hangi konuşmada üretildi" bağlantısı için.
    """

    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        default=lambda: datetime.now(timezone.utc),
        index=True,
    )

    # What happened
    finding_type: Mapped[str] = mapped_column(String(64), index=True)
    severity: Mapped[str] = mapped_column(String(16), index=True)
    title: Mapped[str] = mapped_column(String(256))
    detail: Mapped[str] = mapped_column(Text)

    # MITRE ATT&CK (optional)
    mitre_id: Mapped[str | None] = mapped_column(String(16), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(128), nullable=True)

    # Optional entity context
    source_ip: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    user_name: Mapped[str | None] = mapped_column(String(128), nullable=True)
    resource_id: Mapped[str | None] = mapped_column(String(256), nullable=True)

    # Chat thread that produced this alert
    thread_id: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)