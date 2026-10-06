"""
Aegis AI Firewall - OpenAI and Responses API Provider Adapter
Supports:
- OpenAI Chat Completions API (/v1/chat/completions)
- OpenAI Responses API (/v1/responses)
- LiteLLM Unified Proxy & Router
- vLLM, Ollama OpenAI-compatible mode, and Azure OpenAI
"""
from typing import Dict, Any, List, Optional
import uuid
from .base import (
    BaseProviderAdapter,
    CanonicalRequest,
    CanonicalMessage,
    CanonicalContent,
    CanonicalResponse,
    MessageRole,
    RetrievedContextItem,
)


class OpenAIAdapter(BaseProviderAdapter):
    provider_name: str = "openai"

    def to_canonical(self, raw_request: Dict[str, Any], context: Dict[str, Any]) -> CanonicalRequest:
        request_id = context.get("request_id") or f"req-{uuid.uuid4().hex[:12]}"
        tenant_id = context.get("tenant_id", "tenant_default")
        application_id = context.get("application_id", "app_default")
        session_id = context.get("session_id", "session_default")
        model = raw_request.get("model", "gpt-4o")

        canonical_messages: List[CanonicalMessage] = []
        raw_text_chunks: List[str] = []
        retrieved_items: List[RetrievedContextItem] = []

        # 1. Check for OpenAI Responses API format: "input" field
        if "input" in raw_request:
            raw_input = raw_request["input"]
            if isinstance(raw_input, str):
                canonical_messages.append(CanonicalMessage(role=MessageRole.USER, content=raw_input))
                raw_text_chunks.append(raw_input)
            elif isinstance(raw_input, list):
                for item in raw_input:
                    if isinstance(item, str):
                        canonical_messages.append(CanonicalMessage(role=MessageRole.USER, content=item))
                        raw_text_chunks.append(item)
                    elif isinstance(item, dict):
                        role_str = item.get("role", "user").lower()
                        content_str = item.get("content", "")
                        canonical_messages.append(
                            CanonicalMessage(
                                role=MessageRole(role_str) if role_str in MessageRole._value2member_map_ else MessageRole.USER,
                                content=content_str,
                                name=item.get("name"),
                                tool_call_id=item.get("tool_call_id"),
                            )
                        )
                        raw_text_chunks.append(content_str)

        # 2. Check for OpenAI Chat Completions format: "messages" field
        if "messages" in raw_request:
            for msg in raw_request["messages"]:
                role_val = msg.get("role", "user").lower()
                content_val = msg.get("content", "")

                # Handle multimodal array of content parts
                if isinstance(content_val, list):
                    text_parts = []
                    for part in content_val:
                        if isinstance(part, dict) and part.get("type") == "text":
                            text_parts.append(part.get("text", ""))
                    content_val = "\n".join(text_parts)
                elif not isinstance(content_val, str):
                    content_val = str(content_val)

                canonical_messages.append(
                    CanonicalMessage(
                        role=MessageRole(role_val) if role_val in MessageRole._value2member_map_ else MessageRole.USER,
                        content=content_val,
                        name=msg.get("name"),
                        tool_call_id=msg.get("tool_call_id"),
                        tool_calls=msg.get("tool_calls"),
                    )
                )
                raw_text_chunks.append(content_val)

        # 3. Check for instructions (Responses API)
        if "instructions" in raw_request:
            instr = raw_request["instructions"]
            if instr:
                canonical_messages.insert(0, CanonicalMessage(role=MessageRole.SYSTEM, content=instr))

        # 4. Automatic RAG context extraction
        # Look for "retrieved_context", "context", or "rag_context"
        context_keys = ["retrieved_context", "context", "rag_context", "documents"]
        for ck in context_keys:
            if ck in raw_request and isinstance(raw_request[ck], list):
                for idx, citem in enumerate(raw_request[ck]):
                    if isinstance(citem, str):
                        retrieved_items.append(RetrievedContextItem(source_id=f"rag_doc_{idx}", content=citem))
                    elif isinstance(citem, dict):
                        doc_id = citem.get("source") or citem.get("id") or f"rag_doc_{idx}"
                        doc_text = citem.get("content") or citem.get("text") or str(citem)
                        retrieved_items.append(
                            RetrievedContextItem(
                                source_id=str(doc_id),
                                content=str(doc_text),
                                metadata=citem.get("metadata", {}),
                            )
                        )

        content = CanonicalContent(
            text=raw_text_chunks,
            retrieved_context=retrieved_items,
        )

        return CanonicalRequest(
            request_id=request_id,
            tenant_id=tenant_id,
            application_id=application_id,
            session_id=session_id,
            model=model,
            messages=canonical_messages,
            content=content,
            tools=raw_request.get("tools", []),
            stream=bool(raw_request.get("stream", False)),
            temperature=raw_request.get("temperature"),
            max_tokens=raw_request.get("max_tokens") or raw_request.get("max_output_tokens"),
            raw_payload=raw_request,
            metadata=context.get("metadata", {}),
        )

    def from_canonical(self, canonical_req: CanonicalRequest) -> Dict[str, Any]:
        """Render sanitized canonical request back to OpenAI format."""
        out: Dict[str, Any] = {
            "model": canonical_req.model,
            "messages": [
                {
                    "role": m.role.value,
                    "content": m.content,
                    **({"name": m.name} if m.name else {}),
                    **({"tool_call_id": m.tool_call_id} if m.tool_call_id else {}),
                    **({"tool_calls": m.tool_calls} if m.tool_calls else {}),
                }
                for m in canonical_req.messages
            ],
            "stream": canonical_req.stream,
        }
        if canonical_req.tools:
            out["tools"] = canonical_req.tools
        if canonical_req.temperature is not None:
            out["temperature"] = canonical_req.temperature
        if canonical_req.max_tokens is not None:
            out["max_tokens"] = canonical_req.max_tokens
        return out

    def parse_response(self, raw_resp: Dict[str, Any]) -> CanonicalResponse:
        resp_id = raw_resp.get("id", str(uuid.uuid4()))
        model = raw_resp.get("model", "unknown")
        choices = raw_resp.get("choices", [])

        content = ""
        role = "assistant"
        tool_calls = []
        finish_reason = "stop"

        if choices:
            c0 = choices[0]
            msg = c0.get("message", {})
            content = msg.get("content") or ""
            role = msg.get("role", "assistant")
            tool_calls = msg.get("tool_calls") or []
            finish_reason = c0.get("finish_reason", "stop")

        usage = raw_resp.get("usage", {})

        return CanonicalResponse(
            id=resp_id,
            model=model,
            content=content,
            role=role,
            tool_calls=tool_calls,
            finish_reason=finish_reason,
            usage=usage,
            raw_response=raw_resp,
        )
