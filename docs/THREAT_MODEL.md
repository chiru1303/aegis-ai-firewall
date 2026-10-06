# Aegis threat model

## Purpose and status

Aegis treats user text, retrieved material, documents, web content, image/OCR output, and tool arguments as untrusted until inspected. This document describes intended security boundaries and implemented controls. It is not a certification or an assessment of detection reliability.

## Protected assets and trust boundaries

- Provider credentials, system/developer instructions, user data, and tool capabilities.
- Incoming content before model dispatch and model/tool output before it reaches a caller.
- Tenant records, browser sessions, policies, and audit history.
- Network destinations reached by web fetchers or explicitly configured tools.

Untrusted inputs include direct user messages, files and extracted text, remote pages and API responses, retrieval context, and model-produced tool requests. Browser sessions derive identity from a signed, expiring, server-revocable cookie; clients cannot create a trusted tenant identity by submitting metadata. Only the shared gateway path may dispatch supported requests to a configured upstream provider.

## Implemented controls

- Request-size and rate limits, input parsing budgets, and fail-closed behavior for unsupported or incomplete extraction.
- Text normalization and detectors for instruction override, role changes, secret/credential extraction, tool abuse, context poisoning, multi-step jailbreaks, encoded instructions, and indirect injection.
- Policy decisions that hold review/block/quarantine results and rescan sanitized content before forwarding.
- Scoped tenant/app/session context, guarded administrative provider configuration, and allowlisted upstream destinations.
- Output inspection before responses are returned; restricted tool execution with destination checks and bounded results.
- Readiness checks, redacted audit records, and a hash chain for persisted audit entries.

These controls reduce exposure; they do not make model-based detection a complete security boundary. Downstream tools still require least privilege and independent authorization.

## Residual risks

This package includes no test suite or benchmark results, so detection reliability across benign and malicious inputs has not been independently demonstrated. Representative inputs for each supported format require validation. Provider integration, Docker deployment, TLS termination, load behavior, multi-process recovery, and database backup/restore also require environment-specific verification.

See [Traceability](TRACEABILITY.md) for the detector and input-path map.
