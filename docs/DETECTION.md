# Detection Methodology

## Tier 0 (Deterministic)
- Regular expressions for known bad patterns.
- Entropy checks for obfuscation.
- Keyword blocking.

## Tier 1 (ML Classifiers)
- **LightGBM**: Fast feature-based classifier.
- **DeBERTa**: Deep learning semantic analysis.
- **Wolf Defender**: Specialized injection model.

## Tier 2 (LLM Decision)
- **Laya / Open-Jev**: Used for complex, multi-turn, or ambiguous prompts where semantic understanding of intent is required.
