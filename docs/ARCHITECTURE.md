# System Architecture

## System Overview
Aegis AI Firewall is a zero-trust proxy for LLM interactions. It sits between the user application and the LLM API.

## Component Diagram
- **API Gateway**: FastAPI routing.
- **Normalizer**: Decodes base64, hex, handles typoglycemia.
- **Tier 0**: Regex, entropy, deterministic heuristics.
- **Tier 1**: ML models (LightGBM, DeBERTa, Wolf Defender).
- **Tier 2**: Dynamic LLM evaluation (Laya, Open-Jev).
- **Risk Engine**: Aggregates scores.
- **Policy Engine**: Applies rules based on Risk Score.
- **Provenance Engine**: Tracks origins of context.
- **Session Engine**: Tracks multi-turn interactions.

## Data Flow
Request -> Gateway -> Normalizer -> Detectors -> Risk Engine -> Policy Engine -> Action.

## Security Model
Zero Trust, Defense in Depth.
