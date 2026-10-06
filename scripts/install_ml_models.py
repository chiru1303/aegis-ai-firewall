"""Download the optional local models used by the Aegis detection pipeline."""
from pathlib import Path

import truststore

truststore.inject_into_ssl()

from huggingface_hub import snapshot_download

ROOT = Path(__file__).resolve().parents[1]
MODEL_DIR = ROOT / "backend" / "models"


def download(repo: str, target: Path, patterns: list[str]) -> None:
    target.mkdir(parents=True, exist_ok=True)
    print(f"Downloading {repo} into {target} ...", flush=True)
    snapshot_download(repo_id=repo, local_dir=str(target), allow_patterns=patterns)


def main() -> None:
    download(
        "protectai/deberta-v3-base-prompt-injection-v2",
        MODEL_DIR / "deberta-v3-base-prompt-injection-v2",
        ["config.json", "model.onnx", "spm.model", "tokenizer.json", "tokenizer_config.json", "special_tokens_map.json"],
    )
    download(
        "patronus-studio/wolf-defender-prompt-injection",
        MODEL_DIR / "wolf_defender",
        ["config.json", "tokenizer.json", "tokenizer_config.json", "onnx/onnx_fp16/model_fp16.onnx"],
    )
    download(
        "convaiinnovations/laya-multilingual",
        MODEL_DIR / "laya" / "multilingual",
        ["config.json", "rl_agent_config.json", "model.safetensors", "encoder/**", "tokenizer/**"],
    )
    download(
        "convaiinnovations/laya",
        MODEL_DIR / "laya" / "english",
        ["config.json", "rl_agent_config.json", "model.safetensors", "encoder/**", "tokenizer/**"],
    )
    print("Model assets are ready. Open-Jev is an optional sidecar; configure OPEN_JEV_URL separately.")


if __name__ == "__main__":
    main()
