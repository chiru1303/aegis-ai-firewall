"""One fail-closed ingress and buffered egress path for both API prefixes."""
import base64
import binascii
import json
import re
import time
import uuid
from fastapi import HTTPException
from fastapi.responses import JSONResponse, StreamingResponse
import httpx
from app.core.config import settings
from app.core.upstream import validate_upstream
from app.providers.openai_adapter import OpenAIAdapter
from app.tools.output_firewall import OutputFirewall
from app.tools.firewall import ToolFirewall

adapter = OpenAIAdapter()
output = OutputFirewall()


async def content_text(parts):
    if isinstance(parts, str):
        return parts
    if parts is None:
        return ""
    if not isinstance(parts, list):
        raise HTTPException(422, "Content must be text or a supported content array")
    chunks = []
    from app.parsers.registry import registry
    from app.parsers.sniff import sniff_mime_type, check_zip_bomb
    for part in parts:
        if not isinstance(part, dict):
            raise HTTPException(422, "Invalid content part")
        kind = part.get("type")
        if kind in ("text", "input_text", "output_text"):
            if not isinstance(part.get("text"), str):
                raise HTTPException(422, "Text part must contain a string")
            chunks.append(part["text"])
            continue
        if kind in ("image_url", "input_image"):
            image = part.get("image_url", "")
            data = image.get("url", "") if isinstance(image, dict) else image
            filename = "image.png"
        elif kind in ("file", "input_file"):
            file = part.get("file", part)
            data = file.get("file_data", "")
            filename = file.get("filename", "document.pdf")
        else:
            raise HTTPException(422, "Unsupported content part; upload it through the document scanner")
        if not isinstance(data, str) or not data.startswith("data:") or ";base64," not in data:
            raise HTTPException(422, "Images/files require inline base64 data; remote media is not fetched")
        try:
            encoded = data.split(",", 1)[1]
            if len(encoded) > settings.MAX_FILE_SIZE * 4 // 3 + 4:
                raise HTTPException(413, "Media exceeds size budget")
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, binascii.Error):
            raise HTTPException(422, "Invalid base64 media")
        safe, _ = check_zip_bomb(raw)
        parser = registry.get_parser(sniff_mime_type(raw, filename), filename)
        if not safe or not parser:
            raise HTTPException(422, "Media cannot be securely parsed")
        from app.parsers.budget import parse_with_budget
        extracted = await parse_with_budget(parser, raw, filename, sniff_mime_type(raw, filename))
        if extracted.metadata.get("image_sources"):
            raise HTTPException(422, "Document references external images that were not OCR-inspected")
        if extracted.extraction_warnings:
            raise HTTPException(422, "Media extraction incomplete; review required")
        text = "\n".join(s.text for s in extracted.segments) or extracted.text
        if not text.strip():
            raise HTTPException(422, "Media yielded no inspectable text")
        # Only extracted, inspected text can reach a downstream model.
        chunks.append(text)
    return "\n".join(chunks)


async def inspect_request(body, ctx, db):
    from app.api.routes import run_detection_pipeline, audit_engine
    if not isinstance(body, dict):
        raise HTTPException(422, "Request must be a JSON object")
    body = dict(body)
    model = body.get("model", settings.LLM_MODEL)
    if not isinstance(model, str) or not re.fullmatch(r"[a-zA-Z0-9_.:/-]{1,128}", model):
        raise HTTPException(422, "Invalid model identifier")
    if "input" in body and body.get("stream"):
        raise HTTPException(422, "Responses streaming is unsupported; use buffered Responses or Chat streaming")
    if "messages" in body:
        if not isinstance(body["messages"], list) or not body["messages"]:
            raise HTTPException(422, "Messages must be a non-empty array")
        normalized = []
        for msg in body["messages"]:
            if not isinstance(msg, dict) or msg.get("role") not in ("system", "developer", "user", "assistant", "tool", "function"):
                raise HTTPException(422, "Invalid message role")
            if msg.get("name") and (not isinstance(msg["name"], str) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", msg["name"])):
                raise HTTPException(422, "Invalid message name")
            normalized.append({**msg, "content": await content_text(msg.get("content"))})
        body["messages"] = normalized
    elif "input" in body:
        raw = body["input"]
        if isinstance(raw, list):
            items = []
            for item in raw:
                if isinstance(item, str):
                    items.append({"role": "user", "content": item})
                elif isinstance(item, dict) and item.get("type", "message") == "message":
                    items.append({**item, "content": await content_text(item.get("content"))})
                elif isinstance(item, dict) and item.get("type") == "function_call_output":
                    items.append({"role": "tool", "tool_call_id": item.get("call_id"), "content": await content_text(item.get("output"))})
                else:
                    raise HTTPException(422, "Unsupported Responses input item")
            body["input"] = items
        elif not isinstance(raw, str):
            raise HTTPException(422, "Invalid Responses input")
    else:
        raise HTTPException(422, "Messages or input are required")
    if body.get("previous_response_id"):
        raise HTTPException(422, "Opaque provider history cannot be inspected; send explicit conversation history")
    for flag in ("disable_firewall", "skip_security", "bypass_firewall"):
        if str(body.get(flag, "")).lower() == "true":
            return {"canonical_req": None, "blocked_details": [{"decision": "BLOCK", "origin": "client_bypass"}],
                    "max_risk": 1.0, "decision": "BLOCK", "trace": [], "timing": {}, "t_eval": 0.0}
    tools = body.get("tools", [])
    if not isinstance(tools, list) or any(t.get("type") != "function" for t in tools if isinstance(t, dict)) or any(not isinstance(t, dict) for t in tools):
        raise HTTPException(422, "Only locally authorized function tools are supported")
    body["tools"] = [{"type": "function", "function": {k: v for k, v in t.items() if k != "type"}} if "function" not in t else t for t in tools]
    if any(not isinstance(t.get("function"), dict) or not isinstance(t["function"].get("name"), str) for t in body["tools"]):
        raise HTTPException(422, "Malformed function tool definition")
    if body.get("instructions") is not None and not isinstance(body["instructions"], str):
        raise HTTPException(422, "Instructions must be text")
    start = time.perf_counter()
    body.setdefault("model", settings.LLM_MODEL)
    canonical = adapter.to_canonical(body, {"tenant_id": ctx.tenant_id, "application_id": ctx.application_id,
        "session_id": body.get("session_id") or f"request-{uuid.uuid4().hex}"})
    denied, max_risk, changed = [], 0.0, False

    async def scan(text, source, origin, record=False):
        nonlocal max_risk, changed
        result = await run_detection_pipeline(text, source, origin, "UNTRUSTED",
            session_id=canonical.session_id, db=db, tenant_id=ctx.tenant_id,
            application_id=ctx.application_id, environment_id=ctx.environment_id,
            connector_id=ctx.connector_id, record_session_event=record)
        res = result["response"]
        max_risk = max(max_risk, res.risk_score)
        decision = res.decision.value
        if decision == "SANITIZE":
            if not res.sanitized_content or res.sanitized_content == text:
                denied.append({"origin": origin, "decision": "REQUIRE_REVIEW"})
                return text
            changed = True
            return res.sanitized_content
        if decision != "ALLOW":
            denied.append({"origin": origin, "decision": decision, "risk_score": res.risk_score})
        return text

    latest_user = max((i for i, m in enumerate(canonical.messages) if m.role == "user"), default=-1)
    for idx, msg in enumerate(canonical.messages):
        # Caller-supplied system/developer messages receive exactly the same inspection.
        if msg.content:
            msg.content = await scan(msg.content, "user", f"message:{idx}", record=idx == latest_user)
        if msg.tool_calls:
            await scan(json.dumps(msg.tool_calls), "api", f"message:{idx}:tools")
    for item in canonical.content.retrieved_context:
        item.content = await scan(item.content, "web", item.source_id)
    if canonical.tools:
        await scan(json.dumps(canonical.tools), "api", "tool_definitions")
    elapsed = round((time.perf_counter() - start) * 1000, 2)
    return {"canonical_req": canonical, "blocked_details": denied, "max_risk": max_risk,
            "decision": "BLOCK" if denied else ("SANITIZE" if changed else "ALLOW"),
            "trace": [{"step": "SECURITY_INSPECTION", "status": "BLOCK" if denied else "PASSED", "time_offset_ms": elapsed}],
            "timing": {"total_ms": elapsed, "detection_ms": elapsed}, "t_eval": elapsed}


async def protect_response(payload, ctx, db=None):
    """Inspect every textual field and every tool call, including non-first choices."""
    firewall = await ToolFirewall.for_context(ctx, db) if db is not None else ToolFirewall()

    async def walk(value):
        if isinstance(value, str):
            decision = await output.scan_output(value, {"protected_values": settings.PROTECTED_OUTPUT_VALUES})
            if decision.decision == "BLOCK":
                raise HTTPException(403, "Provider output blocked by the output firewall")
            return decision.clean_content
        if isinstance(value, list):
            return [await walk(v) for v in value]
        if isinstance(value, dict):
            if value.get("type") == "function_call" or ("function" in value and isinstance(value["function"], dict)):
                function = value.get("function", value)
                try:
                    args = function.get("arguments", "{}")
                    args = json.loads(args) if isinstance(args, str) else args
                    if not isinstance(args, dict):
                        raise ValueError()
                except (ValueError, TypeError):
                    raise HTTPException(403, "Malformed tool arguments blocked")
                tool = await firewall.evaluate_tool_call(function.get("name", ""), args,
                    user_context={"tenant_id": ctx.tenant_id, "requested_by": "agent"})
                if tool.decision != "ALLOW":
                    raise HTTPException(403, "Provider tool call requires authorization")
            return {k: await walk(v) for k, v in value.items()}
        return value
    return await walk(payload)


async def forward(sec, ctx, *, responses=False, db=None):
    canonical = sec["canonical_req"]
    if sec["blocked_details"]:
        return JSONResponse({"error": {"message": "Request held by security policy", "type": "security_violation",
            "llm_contacted": False, "blocked_before_model": True, "trace": sec["trace"]},
            "aegis_decision": "BLOCK", "llm_contacted": False, "blocked_before_model": True,
            "blocked_details": sec["blocked_details"]}, 403,
            headers={"X-Aegis-Decision": "BLOCK", "X-Aegis-LLM-Contacted": "NO", "X-Aegis-Blocked-Before-Model": "YES"})
    if not settings.LLM_BASE_URL:
        return JSONResponse({"error": {"message": "No provider configured", "type": "configuration_error"},
            "llm_contacted": False}, 503, headers={"X-Aegis-LLM-Contacted": "NO"})
    base = validate_upstream(settings.LLM_BASE_URL)
    body = adapter.from_canonical(canonical)
    # Include inspected RAG chunks as explicitly untrusted user data.
    for item in canonical.content.retrieved_context:
        body["messages"].append({"role": "user", "content": f"Retrieved document:\n{item.content}"})
    body["stream"] = False
    if responses:
        body["input"] = body.pop("messages")
        body.pop("stream", None)
        if body.get("tools"):
            body["tools"] = [{"type": "function", **t["function"]} for t in body["tools"]]
        if "max_tokens" in body:
            body["max_output_tokens"] = body.pop("max_tokens")
    headers = {"Content-Type": "application/json"}
    if settings.LLM_API_KEY:
        headers["Authorization"] = f"Bearer {settings.LLM_API_KEY}"
    endpoint = "/v1/responses" if responses else "/v1/chat/completions"
    # Base URLs may already end in /v1.
    if base.endswith("/v1"):
        endpoint = endpoint[3:]
    upstream_start = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=settings.REQUEST_TIMEOUT, follow_redirects=False, trust_env=False) as client:
            async with client.stream("POST", base + endpoint, json=body, headers=headers) as response:
                response.raise_for_status()
                raw = bytearray()
                async for chunk in response.aiter_bytes():
                    raw.extend(chunk)
                    if len(raw) > settings.MAX_CONTENT_LENGTH:
                        raise HTTPException(502, "Provider response exceeds output budget")
        payload = json.loads(raw)
        if not isinstance(payload, dict):
            raise ValueError("Provider returned non-object JSON")
        payload = await protect_response(payload, ctx, db)
    except httpx.TimeoutException:
        raise HTTPException(504, "Provider timed out")
    except (httpx.HTTPError, ValueError):
        raise HTTPException(502, "Provider returned an invalid response")
    elapsed = round((time.perf_counter() - upstream_start) * 1000, 2)
    trace = sec["trace"] + [{"step": "LLM_FORWARDING", "status": "CALLED", "llm_contacted": True}]
    payload["aegis_trace"] = trace
    payload["aegis_metadata"] = {"decision": sec["decision"], "llm_contacted": True, "blocked_before_model": False}
    payload["aegis_timing"] = {**sec["timing"], "upstream_llm_ms": elapsed}
    response_headers = {"X-Aegis-Decision": sec["decision"], "X-Aegis-LLM-Contacted": "YES",
        "X-Aegis-Blocked-Before-Model": "NO", "X-Aegis-Output-Security-Mode": "FULL_BUFFER"}
    if canonical.stream and not responses:
        async def verified_stream():
            for choice in payload.get("choices", []):
                msg = choice.get("message", {})
                chunk = {"id": payload.get("id"), "object": "chat.completion.chunk", "model": canonical.model,
                    "choices": [{"index": choice.get("index", 0), "delta": msg, "finish_reason": None}]}
                yield f"data: {json.dumps(chunk)}\n\n"
                chunk["choices"][0].update(delta={}, finish_reason=choice.get("finish_reason", "stop"))
                yield f"data: {json.dumps(chunk)}\n\n"
            yield "data: [DONE]\n\n"
        return StreamingResponse(verified_stream(), media_type="text/event-stream", headers=response_headers)
    return JSONResponse(payload, headers=response_headers)
