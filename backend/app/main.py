from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.agent.core import chat as agent_chat

from app.config import settings


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Uygulama başlangıç/kapanış olayları."""
    print(f"🚀 CloudGuard AI başlıyor — env: {settings.app_env}")
    yield
    print("👋 CloudGuard AI kapanıyor")


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


@app.get("/")
def root():
    return {
        "app": "CloudGuard AI",
        "status": "ok",
        "version": "0.1.0",
    }


@app.get("/health")
def health():
    """Health check — LLM bağlantısı henüz test edilmiyor."""
    return {"status": "healthy", "env": settings.app_env}

# --- Schema ---
class ChatRequest(BaseModel):
    message: str
    thread_id: str = "default"


class ChatResponse(BaseModel):
    reply: str
    thread_id: str


# --- Endpoint — dosyanın sonuna ekle ---
@app.post("/chat", response_model=ChatResponse)
def chat_endpoint(req: ChatRequest):
    """Kullanıcı mesajını alır, agent'a iletir, cevabı döndürür."""
    reply = agent_chat(req.message, thread_id=req.thread_id)
    return ChatResponse(reply=reply, thread_id=req.thread_id)