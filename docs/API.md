# API Documentation

## POST /api/v1/scan
Scans a prompt or text block.
**Body:**
```json
{
  "content": "Text to scan",
  "source": "user",
  "session_id": "optional-id"
}
```
**Response:** `200 OK`
```json
{
  "decision": "ALLOW",
  "risk_score": 10,
  "action": "pass"
}
```

## POST /api/v1/scan/document
Scans a document (PDF, Text).
**Body:** Multipart form data `file`.

## POST /api/v1/scan/image
Scans an image using OCR.
**Body:** Multipart form data `file`.

## POST /api/v1/scan/web
Scans a webpage URL.
**Body:**
```json
{
  "url": "https://example.com"
}
```

## POST /api/v1/tool/check
Validates a tool invocation.
**Body:**
```json
{
  "tool_name": "execute_sql",
  "arguments": {"query": "SELECT * FROM users"}
}
```

## POST /api/v1/session/event
Logs a session event.

## GET /api/v1/health
Health check endpoint.

## GET /api/v1/metrics
Retrieves system metrics.

## GET /api/v1/audit
Retrieves audit logs.

## GET /api/v1/audit/{id}
Retrieves a specific audit log.

## GET /api/v1/session/{session_id}
Retrieves session details.

## GET /api/v1/policies
Lists current security policies.

## POST /v1/chat/completions
OpenAI compatible endpoint for chatting, routed through the firewall.

## Multi-turn gateway sessions
Send `X-Aegis-Session-ID` with `/v1/chat/completions` or `/v1/responses` to associate requests with bounded conversation history for multi-step jailbreak detection. IDs must be 1–128 characters from letters, digits, `_`, `.`, `:`, or `-`. An explicit JSON `session_id` takes precedence.
