# Aegis AI Firewall

Aegis AI Firewall is a local-first prompt-injection firewall for AI applications. It inspects user prompts and supported retrieved content before forwarding requests to a configured model provider, applies security policy, and checks model output and tool calls before returning them. The dashboard supports scanning, activity review, policy management, app connection setup, and operational status.

## Quick start on Windows

Install Python 3.11 or newer and Node.js 22.12 or newer (Node 22 LTS is recommended). From the project folder, double-click `start.bat`. On first launch it creates the Python environment, installs the locked Python and frontend dependencies, generates a local API key, and starts the backend and dashboard. The launcher prints the dashboard URL and opens it in a browser.

### Local demo credentials

| Credential | Local demo value / source | Used for |
| --- | --- | --- |
| Dashboard username | `admin` | Sign in to the local dashboard |
| Dashboard password | `admin123` | Sign in to the local dashboard; change it before any shared or production deployment |
| Application API key | Generated on first launch and saved in the ignored `.aegis-local-api-key` file; sign in and reveal/copy it on **Connect an app** | Authenticate server-side applications using `X-API-Key` or a Bearer token |
| Ollama credential | None for a local Ollama installation | Local model access |
| Cloud model provider key | Your own provider key, if using a hosted provider | Configure in **Connect an app**; keep it out of source control |

The application API key is intentionally generated per installation; there is no shared repository key. Do not commit `.aegis-local-api-key`, `.env`, provider credentials, or the dashboard demo password. The demo credentials are for local evaluation only.

## Manual setup

From PowerShell in the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --use-feature=truststore -r backend/requirements.lock
$generatedKey = python -c "import secrets; print(secrets.token_hex(32))"
$env:API_KEY = "aegis_dev_$generatedKey"
$env:DASHBOARD_USERNAME = "admin"
$env:DASHBOARD_PASSWORD = "admin123"
$env:ENVIRONMENT = "development"
$env:DATABASE_URL = "sqlite+aiosqlite:///./aegis_dev.db"
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

In a second terminal, from the repository root:

```powershell
cd frontend
npm ci
npm run dev
```

Open the local URL printed by Vite and sign in with the local demo credentials above. For a manual installation, keep the generated `API_KEY` in the backend environment. The dashboard uses an HTTP-only session cookie; the key is fetched only when an administrator requests it on **Connect an app**.

## Connect an application

The OpenAI-compatible gateway base URL is `http://127.0.0.1:8000/v1` for a local backend. In **Connect an app**, configure the upstream provider and model, then copy the generated application API key. A connected server-side client sends requests to `/chat/completions` with that key in `Authorization: Bearer <key>` or `X-API-Key`. See [API documentation](docs/API.md).

The optional [XYZ Company Gradio chatbot](examples/sample_chatbot_app/README.md) runs directly against Ollama by default. To route it through the inspection gateway, set these variables in the terminal that starts the chatbot; copy the key from **Connect an app** and do not paste it into source code:

```powershell
$env:GATEWAY_BASE_URL = "http://127.0.0.1:8000/v1"
$env:GATEWAY_API_KEY = "<paste the generated application key here>"
python app.py
```

For hosted model providers, configure the provider URL, model, and provider key in **Connect an app**. Local Ollama needs no provider API key. Runtime provider changes are not persisted across backend restarts; deployment secrets and durable configuration belong in the server environment.

## Dependencies and optional models

- Backend: Python 3.11+, FastAPI, Uvicorn, SQLAlchemy, SQLite for local use; see the pinned `backend/requirements.lock`.
- Frontend: Node.js 22.12+ recommended, React, TypeScript, and Vite; see `frontend/package-lock.json`.
- Local inference: Ollama is optional for scanning and required only when forwarding requests to a local Ollama model.
- Optional detector weights: run `install_ml_models.bat` to install the ML extras and download the model assets. This may require several gigabytes of disk space. The weights are not stored in Git; deterministic detectors remain available without them.

## Architecture

The FastAPI backend exposes an authenticated data-plane gateway and control-plane APIs. Ingress normalizes and bounds content, parsers extract PDF/DOCX/HTML/email/Markdown/JSON/XML/code and OCR text, detector and policy stages decide allow/block/review/sanitize, audit records retain masked content, and approved model requests pass through the provider adapter and output firewall. The React dashboard uses browser-session authentication for administration. See [Architecture](docs/ARCHITECTURE.md), [Detection](docs/DETECTION.md), and [Threat model](docs/THREAT_MODEL.md).

## Security configuration

Before deployment, set a unique API key with at least 32 characters, a strong dashboard password, explicit browser origins, HTTPS and secure cookies, PostgreSQL, and shared Redis. Set `ENVIRONMENT=production`; startup checks reject unsafe production settings. Use `.env.example` as a variable reference, but never commit a populated `.env`. See [Deployment](docs/DEPLOYMENT.md) and [Security](docs/SECURITY.md).

## Coverage and limits

Detector code covers instruction override, role change, secret extraction, tool abuse, credential theft, context poisoning, multi-step jailbreaks, encoded instructions, and indirect prompt injection across supported text and document paths. Code coverage does not prove detection reliability; tune policies and validate representative benign and malicious examples for each source before relying on automated decisions. The repository does not include benchmark reports or a runnable test suite. Provider connectivity, deployment hardening, and load behavior must be verified in the target environment.
