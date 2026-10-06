# Hackathon requirement traceability

This document maps the problem statement to implemented areas in the application. A detector or parser existing in code does not establish detection reliability. Test suites and benchmark reports are not included in this package.

## Attack categories

| Problem statement category | Implementation area |
|---|---|
| Instruction override | `backend/app/detectors/instruction_override.py` |
| Role change | `backend/app/detectors/role_manipulation.py` |
| Secret extraction | `backend/app/detectors/secret_extraction.py` |
| Tool abuse | `backend/app/detectors/tool_abuse.py`, `backend/app/tools/` |
| Credential theft | `backend/app/detectors/credential_detector.py` |
| Context poisoning | `backend/app/detectors/context_poisoning.py` |
| Multi-step jailbreaks | `backend/app/detectors/multi_step_jailbreak.py`, `backend/app/sessions/` |
| Encoded instructions | `backend/app/detectors/encoded_instruction.py` |
| Indirect prompt injection | `backend/app/detectors/indirect_injection.py` |

The detector stack contains implementation paths for all nine categories, corresponding to feature target F3. This is code-level coverage only and does not guarantee that each attack will be detected or neutralized.

## Input and decision flow

Supported paths include text; web pages and HTML; PDF and DOCX; email; Markdown; structured API responses; source code; and images through OCR. Parsers apply input budgets. Unsupported, incomplete, or over-budget extraction is held for review rather than forwarded as trusted content.

The API gateway routes supported requests through inspection and policy before configured provider dispatch. Output is inspected before return. The app also provides audit history, policy management, application integration, and service readiness views.

## Depth requirements

| Tier | Evidence in this package |
|---|---|
| D1 | Text and structured scanning paths are implemented. Acceptable-output rates are not measured here. |
| D2 | Reliability across mostly textual inputs is not demonstrated here. |
| D3 | Multimodal parsing paths exist; reliability across heterogeneous artifacts is not demonstrated here. |

For trust boundaries and operational limits, see the [Threat model](THREAT_MODEL.md) and [Security architecture](security/SECURITY_ARCHITECTURE.md).
