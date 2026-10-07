"""
Downloader for Tier 2 (Laya) and Tier 3 (Open-Jev) models from Hugging Face.
Uses truststore to inherit Windows enterprise certificates.
"""
import os
import sys
import shutil

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

from huggingface_hub import hf_hub_download

MODELS_BASE = os.path.join(os.path.dirname(__file__), "models")

# 1. Tier 2: Laya Multilingual Model
LAYA_DIR = os.path.join(MODELS_BASE, "laya")
os.makedirs(LAYA_DIR, exist_ok=True)
LAYA_REPO = "convaiinnovations/laya"
LAYA_FILES = [
    ("multilingual/encoder/config.json", "config.json"),
    ("multilingual/tokenizer/tokenizer.json", "tokenizer.json"),
    ("multilingual/tokenizer/tokenizer_config.json", "tokenizer_config.json"),
    ("multilingual/model.safetensors", "model.safetensors"),
]

print(f"[*] Downloading Tier 2 (Laya) from {LAYA_REPO} to {LAYA_DIR}...")
for remote_file, local_file in LAYA_FILES:
    dest_path = os.path.join(LAYA_DIR, local_file)
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
        print(f"  [+] {local_file} already exists ({os.path.getsize(dest_path)} bytes), skipping.")
        continue
    print(f"  [>] Downloading {remote_file} -> {local_file}...")
    try:
        downloaded = hf_hub_download(
            repo_id=LAYA_REPO,
            filename=remote_file,
            local_dir=LAYA_DIR,
        )
        subfolder_file = os.path.join(LAYA_DIR, remote_file)
        if os.path.exists(subfolder_file) and remote_file != local_file:
            shutil.copyfile(subfolder_file, dest_path)
        print(f"  [OK] Successfully downloaded {local_file}")
    except Exception as e:
        print(f"  [!] Error downloading {remote_file}: {e}")

# 2. Tier 3: Open-Jev Typed Decision Model
JEV_DIR = os.path.join(MODELS_BASE, "open_jev")
os.makedirs(JEV_DIR, exist_ok=True)
JEV_REPO = "com-kotobalabs/open-jev-deberta-v3-large"
JEV_FILES = [
    ("config.json", "config.json"),
    ("tokenizer.json", "tokenizer.json"),
    ("tokenizer_config.json", "tokenizer_config.json"),
    ("open_jev_config.json", "open_jev_config.json"),
    ("head.safetensors", "head.safetensors"),
    ("model.safetensors", "model.safetensors"),
]

print(f"\n[*] Downloading Tier 3 (Open-Jev) from {JEV_REPO} to {JEV_DIR}...")
for remote_file, local_file in JEV_FILES:
    dest_path = os.path.join(JEV_DIR, local_file)
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
        print(f"  [+] {local_file} already exists ({os.path.getsize(dest_path)} bytes), skipping.")
        continue
    print(f"  [>] Downloading {remote_file} -> {local_file}...")
    try:
        downloaded = hf_hub_download(
            repo_id=JEV_REPO,
            filename=remote_file,
            local_dir=JEV_DIR,
        )
        print(f"  [OK] Successfully downloaded {local_file}")
    except Exception as e:
        print(f"  [!] Error downloading {remote_file}: {e}")

print("\n[*] All Tier 2 & Tier 3 models downloaded successfully.")
