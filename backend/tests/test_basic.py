"""Temel sağlık testleri — uygulama import edilebiliyor mu, config doğru mu."""
from fastapi.testclient import TestClient


def test_app_imports():
    """Uygulama hatasız import edilebilmeli."""
    from app.main import app
    assert app is not None


def test_config_loads():
    """Settings .env'den okunabilmeli."""
    from app.config import settings
    assert settings.app_env in ("development", "production", "test")
    assert settings.gemini_api_key  # boş olmamalı (CI'da dummy)


def test_root_endpoint():
    """GET / 200 dönmeli."""
    from app.main import app
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert data["app"] == "CloudGuard AI"
    assert data["status"] == "ok"


def test_health_endpoint():
    """GET /health 200 dönmeli."""
    from app.main import app
    client = TestClient(app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_chat_validates_input():
    """POST /chat boş mesaj reddetmeli."""
    from app.main import app
    client = TestClient(app)
    response = client.post("/chat", json={"message": "", "thread_id": "test"})
    assert response.status_code == 422  # Pydantic validation error