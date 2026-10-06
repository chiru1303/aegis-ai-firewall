"""
Aegis AI Firewall - Provider-Independent Canonical Models & Base Adapter
Normalizes every incoming chatbot / agent protocol (OpenAI, Anthropic, Gemini, Ollama, LiteLLM)
into a canonical representation for the security engine.
"""
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class MessageRole(str, Enum):
    SYSTEM = "system"
    DEVELOPER = "developer"
    USER = "user"
    ASSISTANT = "assistant"
    TOOL = "tool"
    FUNCTION = "function"


@dataclass
class RetrievedContextItem:
    source_id: str
    content: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    quarantined: bool = False
    sanitized: bool = False
    risk_score: float = 0.0


@dataclass
class CanonicalContent:
    text: List[str] = field(default_factory=list)
    documents: List[Dict[str, Any]] = field(default_factory=list)
    images: List[Dict[str, Any]] = field(default_factory=list)
    retrieved_context: List[RetrievedContextItem] = field(default_factory=list)


@dataclass
class CanonicalMessage:
    role: MessageRole
    content: str
    name: Optional[str] = None
    tool_call_id: Optional[str] = None
    tool_calls: Optional[List[Dict[str, Any]]] = None
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CanonicalRequest:
    request_id: str
    tenant_id: str
    application_id: str
    session_id: str
    model: str
    messages: List[CanonicalMessage] = field(default_factory=list)
    content: CanonicalContent = field(default_factory=CanonicalContent)
    tools: List[Dict[str, Any]] = field(default_factory=list)
    stream: bool = False
    temperature: Optional[float] = None
    max_tokens: Optional[int] = None
    provenance: List[Dict[str, Any]] = field(default_factory=list)
    raw_payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CanonicalResponse:
    id: str
    model: str
    content: str
    role: str = "assistant"
    tool_calls: List[Dict[str, Any]] = field(default_factory=list)
    finish_reason: str = "stop"
    usage: Dict[str, int] = field(default_factory=dict)
    raw_response: Dict[str, Any] = field(default_factory=dict)


class BaseProviderAdapter(ABC):
    """
    Abstract adapter translating between provider protocols and Aegis Canonical format.
    """
    provider_name: str

    @abstractmethod
    def to_canonical(self, raw_request: Dict[str, Any], context: Dict[str, Any]) -> CanonicalRequest:
        """Convert a provider request to canonical format."""
        pass

    @abstractmethod
    def from_canonical(self, canonical_req: CanonicalRequest) -> Dict[str, Any]:
        """Convert a sanitized canonical request into the target provider format."""
        pass

    @abstractmethod
    def parse_response(self, raw_resp: Dict[str, Any]) -> CanonicalResponse:
        """Parse provider response into canonical output for output firewall inspection."""
        pass
