from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.db.database import init_db
from app.api.routes import router as api_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlangıç/kapanış olayları."""
    print(f"CloudGuard AI baslıyor - env: {settings.app_env}")
    init_db()
    print("DB hazır")
    yield
    print("CloudGuard AI kapanıyor")


app = FastAPI(
    title="CloudGuard AI",
    description="Cloud Security Monitoring & Incident Response Agent",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins_list,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# /chat ve /history endpoint'leri burada bağlanıyor
app.include_router(api_router)


@app.get("/")
def root():
    return {"app": "CloudGuard AI", "status": "ok", "version": "0.1.0"}


@app.get("/health")
def health():
    return {"status": "healthy", "env": settings.app_env}