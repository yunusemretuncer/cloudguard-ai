"""SQLAlchemy DB kurulumu — engine, session factory, base model."""
from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, sessionmaker

from app.config import settings

# SQLite için özel arg: same thread kontrolünü kapat (FastAPI thread pool için gerekli)
connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}

engine = create_engine(settings.database_url, connect_args=connect_args)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


class Base(DeclarativeBase):
    """Tüm ORM modellerinin türeyeceği base class."""
    pass


def get_db():
    """FastAPI dependency — her istek için bir DB session açar, kapatır."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db():
    """Tabloları oluştur. main.py lifespan'inden çağrılacak."""
    # Modelleri import et ki Base.metadata onları tanısın
    from app.db import models  # noqa: F401
    Base.metadata.create_all(bind=engine)
