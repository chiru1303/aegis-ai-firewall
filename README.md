# Aegis AI Firewall

Aegis inspects prompts and supported content before it reaches a configured AI provider. It applies policy to incoming requests, can hold or sanitize unsafe content, and inspects model output before returning it. The dashboard provides content scanning, activity review, policy management, application setup, and system status.

## Hackathon problem coverage

The backend includes detector modules for the nine attack classes named in the problem statement: instruction override, role change, secret extraction, tool abuse, credential theft, context poisoning, multi-step jailbreaks, encoded instructions, and indirect prompt injection. This describes implemented code paths; it is not a claim of reliable detection for every attack.

The application accepts text and supported document inputs, including web/HTML, PDF, DOCX, email, Markdown, structured API responses, source code, and images through OCR. Unsupported, incomplete, or over-budget extraction is held for review. The package does not include test suites or benchmark reports, so D1, D2, and D3 reliability have not been independently demonstrated here.

## Run locally

Requires Python 3.11+ and Node.js 22+. From the repository root in PowerShell:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --use-feature=truststore -r backend/requirements.lock
$env:API_KEY = (python -c "import secrets; print(secrets.token_hex(32))")
$env:DATABASE_URL = "sqlite+aiosqlite:///./aegis_dev.db"
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

In another terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open the Vite URL shown in the terminal and sign in with the local demo credentials `admin` / `admin123`. The dashboard uses an HTTP-only session cookie. On **Connect an app**, an administrator can reveal or copy the generated Aegis API key; it is fetched on demand and not stored in browser storage. Keep the key server-side in connected applications.

For production, configure a unique dashboard password, PostgreSQL, Redis, secure cookie settings, and deployment secrets. See `.env.example`, `docker-compose.production.yml`, and [Deployment](docs/DEPLOYMENT.md).

## Optional model weights

The starter runs deterministic detectors when optional model weights are unavailable. To install the local model stack, run `install_ml_models.bat` and restart the backend. Open-Jev loads from `backend/models/open_jev` and runs locally when first-stage results are ambiguous; no separate service URL is required. The System status page reports whether the model loaded or the evidence fallback is active.

## Operational limits

- Detector coverage does not establish D1, D2, or D3 reliability. Validate representative benign and malicious inputs for each format before relying on automated decisions.
- Provider integration, Docker deployment, TLS termination, load/concurrency behavior, and disaster recovery require environment-specific verification.
- Keep tool permissions narrow and require downstream authorization for consequential actions.

See [Architecture](docs/ARCHITECTURE.md), [Threat model](docs/THREAT_MODEL.md), and [Traceability](docs/TRACEABILITY.md) for implementation details and coverage mapping.
