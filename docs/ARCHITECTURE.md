# Architecture

## Components

- **Dashboard:** React and TypeScript single-page application, built with Vite. It authenticates using an HTTP-only cookie and calls the Aegis API through the same origin in deployment or Vite's local development proxy.
- **FastAPI service:** exposes browser/control routes under `/api/v1`, control-plane routes under `/admin`, and an OpenAI-compatible data plane under `/v1`.
- **Input parsers:** normalize text from supported files, HTML/web pages, email, structured formats, source code, and OCR-capable images. Parsing is bounded by file-size, decompression, extraction, and time budgets.
- **Detection and decision pipeline:** deterministic detectors run locally; optional model classifiers run only when their libraries and model assets are available. The decision layer combines findings and applies policy actions.
- **Output inspection:** gateway responses pass through output checks before returning to the caller.
- **Persistence:** SQLAlchemy stores durable audit and configuration records. SQLite supports local development; PostgreSQL is required by the production startup checks. Redis stores shared session state in production; local mode can use an in-memory fallback.

## Request path

```text
Client -> authentication and tenant context -> parse/normalize -> provenance and trust assignment
       -> deterministic detectors -> available optional models -> risk/policy decision
       -> audit -> block/review/sanitize/allow
       -> configured provider (gateway only) -> output inspection -> client
```

The security API returns a decision to the integrating application; that application must enforce it before making its own model call. The OpenAI-compatible gateway provides that request-path enforcement for supported chat/responses requests. Tool authorization APIs evaluate tool requests but do not execute arbitrary tools on behalf of a client.

## Trust boundaries

- User and retrieved content is treated as untrusted unless server-side identity/policy establishes otherwise. A request body cannot promote its own trust level.
- Provider URLs are restricted by an explicit server-side origin allowlist to reduce SSRF and credential-exfiltration risk.
- Browser sessions use signed, HTTP-only cookies. API secrets are not intended for browser storage.
- Tenant identity is bound by authenticated credentials and enforced in database access paths.
- Parser failures and unsupported/over-budget extraction are held for review instead of silently treated as clean content.

See [API documentation](API.md), [Threat model](THREAT_MODEL.md), and [Security notes](SECURITY.md) for usage and limitations.
