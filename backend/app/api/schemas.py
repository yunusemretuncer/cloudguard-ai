"""Pydantic request/response modelleri."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    thread_id: str = Field(default="default", max_length=64)


class ChatResponse(BaseModel):
    reply: str
    thread_id: str


class ChatHistoryItem(BaseModel):
    id: int
    thread_id: str
    user_message: str
    agent_reply: str
    created_at: datetime

    model_config = {"from_attributes": True}


class ChatHistoryResponse(BaseModel):
    thread_id: str | None
    count: int
    items: list[ChatHistoryItem]
