"""Pydantic request/response modelleri."""
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field


class ChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=4000)
    thread_id: str = Field(default="default", max_length=64)

class ToolCall(BaseModel):
    name: str
    args: dict

class ChatResponse(BaseModel):
    reply: str
    thread_id: str
    tool_calls: list[ToolCall] = []


class ChatHistoryItem(BaseModel):
    id: int
    thread_id: str
    user_message: str
    agent_reply: str
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class ChatHistoryResponse(BaseModel):
    thread_id: str | None
    count: int
    items: list[ChatHistoryItem]


class AlertItem(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    finding_type: str
    severity: str
    title: str
    detail: str
    mitre_id: str | None = None
    mitre_tactic: str | None = None
    mitre_technique: str | None = None
    source_ip: str | None = None
    user_name: str | None = None
    resource_id: str | None = None
    thread_id: str | None = None
    created_at: datetime


class AlertsResponse(BaseModel):
    count: int
    severity_counts: dict[str, int]
    items: list[AlertItem]
