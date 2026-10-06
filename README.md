# Aegis AI Firewall

Aegis is a security gateway for AI applications. It inspects user prompts and untrusted context before they reach a model, applies a policy decision, and can inspect provider output before returning it. The project includes a browser dashboard, a FastAPI service, an OpenAI-compatible gateway, parsers for common content formats, and optional local detection models.

## What it does

- Scans text, retrieved/web content, uploaded documents, source code, email, structured data, and images using OCR when OCR dependencies are installed.
- Looks for nine prompt-injection and agent-abuse categories: instruction override, role change, secret extraction, tool abuse, credential theft, context poisoning, multi-step jailbreaks, encoded instructions, and indirect prompt injection.
- Returns an `ALLOW`, `SANITIZE`, `BLOCK`, `QUARANTINE`, or `REQUIRE_REVIEW` decision with a risk score and evidence.
- Provides a gateway (`/v1/chat/completions` and `/v1/responses`) that checks a request before forwarding it to a configured model provider.
- Keeps an audit trail and exposes operational status in the dashboard.

The detection stack combines deterministic rules with optional model-based classifiers. Model weights are not committed to this repository because they are large; the default installation can run without them. The dashboard reports which components are actually available. This prototype has not been independently validated to a D1, D2, or D3 reliability level; detection coverage is not a guarantee that every attack will be detected.

## Requirements

For the quickest Windows demo:

- Windows 10 or 11
- Python 3.11 or newer
- Node.js 22.12 or newer (Node 20.19+ also satisfies the frontend runtime)
- npm (installed with Node.js)
- Internet access for the first dependency installation

OCR requires the Tesseract executable to be installed and available on `PATH`. Optional ML models require additional packages, downloads, and several GB of free disk space. A provider such as OpenAI, Ollama, or vLLM is only needed to exercise live model forwarding; text/file scanning works without an upstream model provider.

## Quick start on Windows

1. Download or clone this repository.
2. Install the requirements above.
3. From the repository folder, double-click `start.bat` (or run `./start.bat` in Command Prompt).
4. Wait for the launcher to install the Python and frontend dependencies and open the dashboard.
5. Sign in with the local demo account: **admin** / **admin123**.

The launcher creates a local Python virtual environment, installs the pinned backend and frontend dependencies, generates and stores a local Aegis API key, starts the API and dashboard, and opens the browser. The key is available after sign-in at **Connect an app**. Local demo credentials are public and are for a machine-local hackathon demo only; do not expose this configuration to a network or use it for production.

If the launcher reports that a port is already occupied, close the unrelated application or update the port configuration. It does not terminate unrelated processes. Use `stop.bat` or close the two Aegis terminal windows to stop the local services.

## Manual setup

Run these commands from the repository root. PowerShell is shown; equivalent commands work in a Unix shell with the relevant venv activation syntax.

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend/requirements.lock
Copy-Item .env.example .env
```

Edit `.env` before starting the API. Set `API_KEY` to a fresh random value of at least 32 bytes. For example, generate one with:

```powershell
python -c "import secrets; print('aegis_dev_' + secrets.token_hex(32))"
```

Paste the generated value into `.env`. Set a dashboard username and password for your local run; `admin` / `admin123` are only demo defaults. The `.env` file is ignored by Git.

Start the API in a terminal from the repository root:

```powershell
$env:PYTHONPATH = (Resolve-Path .\backend).Path
python -m uvicorn app.main:app --app-dir backend --host 127.0.0.1 --port 8000
```

In a second terminal from the repository root:

```powershell
cd frontend
npm ci
npm run dev
```

Open the Vite URL printed in the terminal (normally `http://localhost:3000`). API documentation is at `http://127.0.0.1:8000/docs`.

## Configuration

The application reads environment variables and `.env` from its current working directory. The root `.env.example` lists the supported settings; copy it to `.env`, supply secrets, and change defaults before starting. The launcher supplies local development settings itself.

| Setting | Purpose |
| --- | --- |
| `API_KEY` | Master Aegis API credential. Use a unique random value. The dashboard can reveal it to an authenticated administrator. |
| `DASHBOARD_USERNAME`, `DASHBOARD_PASSWORD` | Dashboard sign-in. Replace the demo values outside a local demo. |
| `DATABASE_URL` | Audit and application database. SQLite is used for local development; production requires PostgreSQL. |
| `REDIS_URL` | Session storage. Local development can fall back to in-memory state; production requires Redis. |
| `LLM_PROVIDER` | `openai`, `ollama`, `vllm`, or `custom`. |
| `LLM_BASE_URL`, `LLM_MODEL`, `LLM_API_KEY` | Upstream model endpoint, model identifier, and provider credential. Keep provider credentials server-side. |
| `UPSTREAM_ALLOWED_ORIGINS` | Explicit list of provider origins that administrators may configure. Do not use a wildcard. |
| `REQUIRE_ML_MODELS` | Set `true` to prevent readiness when required model dependencies are missing. |
| `OPEN_JEV_URL` | Optional Open-Jev sidecar URL. |

Provider destinations are restricted by the server allowlist. A URL shown in the UI is not automatically trusted or guaranteed reachable. For Docker, use a service name such as `http://ollama:11434` rather than `localhost` when the provider is another container.

## Optional local models

The normal requirements install is intentionally lightweight. To install optional inference dependencies and download the configured weights, run `install_ml_models.bat` on Windows after `start.bat` has created `.venv`. The process requires substantial disk space and network access. The weights and Hugging Face cache are excluded from Git. Open-Jev is a separately hosted service and must be configured with `OPEN_JEV_URL`.

Without optional model files, deterministic detectors remain available; check **System status** to see the live state. Do not describe an unavailable model as participating in a scan.

## Architecture

```text
Application / user
        |
        v
React dashboard or OpenAI-compatible gateway
        |
        v
FastAPI authentication and tenant context
        |
        v
Input parsing -> normalization/provenance -> deterministic and available model detectors
        |
        v
Risk aggregation -> policy enforcement -> audit record
        |
        +---- ALLOW / sanitized content / BLOCK / REVIEW
        |
        +---- configured model provider (gateway mode only)
                    |
                    v
            output inspection -> caller
```

The dashboard is a React/TypeScript SPA built with Vite. FastAPI exposes the unified scan API at `/api/v1`, the OpenAI-compatible data plane at `/v1`, and administrative routes under `/admin`. SQLAlchemy provides persistence; SQLite is the local default, while the production Compose overlay requires PostgreSQL and Redis. File parsers inspect extracted segments and fail closed when extraction is incomplete or exceeds configured limits.

See [Architecture](docs/ARCHITECTURE.md), [API documentation](docs/API.md), [Threat model](docs/THREAT_MODEL.md), [Security notes](docs/SECURITY.md), [Detection notes](docs/DETECTION.md), and [Deployment](docs/DEPLOYMENT.md).

## API overview

- `POST /api/v1/scan` — inspect text.
- `POST /api/v1/scan/file` or `/api/v1/scan/document` — inspect an uploaded file.
- `POST /api/v1/scan/image` — inspect an image through OCR.
- `POST /api/v1/scan/web` — fetch and inspect a public web page (subject to SSRF protections).
- `POST /v1/chat/completions` and `POST /v1/responses` — inspect then forward OpenAI-compatible model requests.
- `GET /api/v1/health` and `GET /api/v1/metrics` — health and operational metrics.

Protected API calls accept `Authorization: Bearer <AEGIS_API_KEY>` or `X-API-Key: <AEGIS_API_KEY>`. The dashboard uses an HTTP-only session cookie. Full schemas and additional endpoints are documented in [docs/API.md](docs/API.md) and the interactive OpenAPI page at `/docs`.

## GitHub handoff

This folder is prepared as a standalone Git repository. To publish it, create an empty **public** GitHub repository, then from this folder run:

```bash
git add .
git commit -m "Prepare Aegis AI Firewall hackathon prototype"
git branch -M main
git remote add origin https://github.com/<YOUR-ACCOUNT>/<YOUR-REPOSITORY>.git
git push -u origin main
```

Review `git status` before committing. Do not commit `.env`, `.aegis-local-api-key`, database files, downloaded model weights, or any provider credentials. Add the resulting GitHub URL to the hackathon submission form.
