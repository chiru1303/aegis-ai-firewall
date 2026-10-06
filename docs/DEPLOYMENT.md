# Deployment

## Local Windows demo

Use `start.bat` from the repository root. It supplies local-only development settings, creates the local API key, and starts the backend and frontend. The demo account is `admin` / `admin123`; do not expose it to a network.

## Docker development stack

The Compose stack runs the dashboard, API, PostgreSQL, Redis, and a local Nginx entry point. Copy `.env.example` to `.env`, fill the API key and database/cache passwords, and set a random dashboard password before starting:

```powershell
Copy-Item .env.example .env
# Edit .env and set API_KEY, POSTGRES_PASSWORD, REDIS_PASSWORD,
# DASHBOARD_USERNAME, and DASHBOARD_PASSWORD to unique values.
docker compose up --build
```

The local entry point is `http://127.0.0.1:8080`; the API's OpenAPI page is available through the backend at `/docs`. Use strong unique secrets. Do not commit `.env`.

If connecting a provider, add only its required origins to `UPSTREAM_ALLOWED_ORIGINS`, for example `["https://api.openai.com"]` or the private service origin used by your deployment. Do not permit arbitrary destinations. A provider in another Docker container should be addressed using its Compose service name.

The Compose development file uses published base image tags for convenience and development cookie settings. Do not treat it as a hardened production deployment.

## Production overlay

The production overlay intentionally requires immutable image references and deployment secrets. Provide image references pinned by digest for `PYTHON_IMAGE`, `NODE_IMAGE`, `NGINX_IMAGE`, `POSTGRES_IMAGE`, and `REDIS_IMAGE`, plus a strong `DASHBOARD_PASSWORD`, a production HTTPS `CORS_ORIGINS` list, database/cache passwords, and a unique `API_KEY`. Then deploy with:

```bash
docker compose -f docker-compose.yml -f docker-compose.production.yml up --build -d
```

Production startup checks require secure cookies, explicit CORS origins, authentication, rate limiting, a strong dashboard password, PostgreSQL, Redis, and full-buffer output inspection. Terminate TLS at a managed ingress or reverse proxy and restrict access to the backend, database, and Redis. Provision and rotate secrets through your deployment secret manager. Review the compose files and security policy against your own environment before deployment; this prototype has not been independently penetration-tested or load-tested.

## Optional models and OCR

Run `install_ml_models.bat` on Windows to install optional Python inference packages and download model assets to `backend/models`. Keep those binary assets outside Git. The backend container's read-only model mount points to that directory. OCR requires Tesseract to be installed in the relevant host/container image and available on `PATH`; the included backend Dockerfile installs it.
