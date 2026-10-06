# Aegis security architecture

This is a concise description of implemented boundaries and controls. It is not a certification or a claim of production readiness. This package does not include test suites or reliability reports.

## Request flow

```text
Untrusted request
      │
      ▼
Bounded ingress ──► format-aware extraction ──► normalization/detection
                                                    │
                                                    ▼
                                              policy decision
                                       allow / verified sanitize / hold
                                                    │
                                      configured provider only
                                                    │
                                                    ▼
                                inspect model output before returning
```

## Trust and enforcement boundaries

- Browser access uses a short-lived, signed, server-revocable HTTP-only session cookie. The raw administrator key is used only to establish a session.
- External content is treated as untrusted. Caller-provided role/trust metadata does not establish server authority.
- A common gateway inspects supported requests before dispatch. Only an allow decision or sanitized content that passes a second scan is eligible for forwarding; review, block, quarantine, unsupported formats, and incomplete extraction are held.
- Provider configuration is privileged and destination-allowlisted. Upstream calls are real network calls; a missing provider does not produce synthetic completion output.
- Tool calls are inspected against policy and narrowly scoped executors. Output is bounded and inspected before return.
- Tenant/session scope, parser/request limits, readiness checks, and audit integrity controls are implemented in the backend.

## Detection coverage and limitations

Detector modules provide implementation paths for all nine hackathon attack classes. Detection reliability is not measured here. Representative benign and malicious artifacts should be evaluated across text, PDF, DOCX, email, HTML, source code, and image/OCR paths before deployment. No D1/D2/D3 reliability or production-readiness claim is made.

For setup and coverage mapping, see the [README](../../README.md) and [requirement traceability](../TRACEABILITY.md).
