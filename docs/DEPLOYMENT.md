# Deployment Guide

## Docker Deployment
```bash
docker-compose up -d --build
```

## Production Deployment
- Use managed Postgres & Redis.
- Deploy via Kubernetes using Helm (chart TBA).
- Scale backend pods horizontally.

## Environment Variables
See `.env.example`.
