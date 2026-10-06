# Aegis API reference

The running service publishes its authoritative OpenAPI schema and interactive reference at `http://127.0.0.1:8000/docs` (ReDoc: `/redoc`). This guide covers the primary integration endpoints. Requests use JSON unless noted otherwise.

## Authentication

Protected endpoints accept either:

```http
Authorization: Bearer <AEGIS_API_KEY>
```

or:

```http
X-API-Key: <AEGIS_API_KEY>
```

The dashboard signs in through `/api/v1/auth/login` and then uses a signed HTTP-only session cookie. The key itself is only returned to an authenticated superadmin on explicit request at `/api/v1/auth/api-key`; the response is marked `no-store`. Keep the key and upstream provider credentials on a trusted server.

## Scan text

`POST /api/v1/scan`

```json
{
  "content": "Summarize this document.",
  "sourceType": "user",
  "session_id": "conversation-123"
}
```

`content` can be a string or a content object. Supported source types include `user`, `web`, `pdf`, `docx`, `email`, `api`, `ocr`, `database`, `code`, `image`, and `unknown`. Trust is derived by the server; caller-provided trust does not override server policy.

The response includes `request_id`, `decision`, `risk_score`, `risk_level`, `confidence`, `attack_types`, `sanitized_content` when applicable, `evidence`, `provenance`, and measured latency. Risk scores are normalized from 0 to 1. Decisions are `ALLOW`, `SANITIZE`, `BLOCK`, `QUARANTINE`, or `REQUIRE_REVIEW`.

## Scan files and web pages

`POST /api/v1/scan/file` or `POST /api/v1/scan/document` accepts multipart form data:

- `file`: required file upload (maximum size is controlled by `MAX_FILE_SIZE`; default 50 MiB)
- `session_id`: optional session identifier
- `source_type`: optional source override; otherwise the parser/MIME type determines the source

Supported parsers include PDF, DOCX, HTML, Markdown, email, JSON/XML, source code, and text. Image OCR depends on Tesseract and the configured OCR runtime. Incomplete or unsafe extraction can return `REQUIRE_REVIEW` rather than silently allowing a file.

`POST /api/v1/scan/image` accepts an image as multipart form data with `file` and optional `session_id`.

`POST /api/v1/scan/web` fetches and inspects a URL:

```json
{"url":"https://example.org/article","session_id":"web-review-1"}
```

The web fetcher applies SSRF protections. It may reject private, local, or otherwise unsafe destinations.

## Tool and session checks

- `POST /api/v1/tool/check` — evaluate a tool name and structured arguments before execution.
- `POST /api/v1/session/event` — record a session event for multi-step risk tracking.
- `GET /api/v1/sessions` and `GET /api/v1/session/{session_id}` — inspect authorized session state.
- `POST /api/v1/session/{session_id}/quarantine` — quarantine an authorized session.

Use the live OpenAPI schema for exact request/response fields for the deployed version.

## OpenAI-compatible gateway

The gateway inspects requests before forwarding. Configure and verify an upstream provider first. Calls fail with a configuration/unreachable error if no provider is configured; the firewall scan endpoint itself does not require an upstream model.

- `POST /v1/chat/completions`
- `POST /v1/responses`
- `GET /v1/models`

Example:

```bash
curl http://127.0.0.1:8000/v1/chat/completions\
  -H "Authorization: Bearer $AEGIS_API_KEY"\
  -H "Content-Type: application/json"\
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize this report."}]}'
```

`X-Aegis-Session-ID` may be sent to associate calls with a bounded conversation. The gateway returns Aegis decision headers and does not contact the model when the request is blocked.

## Dashboard, health, and administration

- `POST /api/v1/auth/login`, `GET /api/v1/auth/session`, `POST /api/v1/auth/logout`
- `GET /api/v1/health`, `GET /api/v1/metrics`, `GET /api/v1/feed`
- `GET /api/v1/audit`, `GET /api/v1/audit/{request_id}`, `GET /api/v1/audit/verify`
- `GET /api/v1/policies`, `POST /api/v1/policies`, `POST /api/v1/policies/{policy_id}/toggle`
- `GET /api/v1/config/upstream`, `POST /api/v1/config/upstream`, `POST /api/v1/providers/test`
- Tenant, application, connector, and credential management routes are listed in `/docs` and are role-protected.

Health reports actual dependency/model readiness. Optional local model packages and weights are not bundled. Runtime provider configuration is not durable across process restarts; use deployment-managed environment secrets for persistent configuration.
