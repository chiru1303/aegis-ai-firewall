"""
Script to download open-source prompt injection models from Hugging Face.
Uses truststore to inherit Windows enterprise SSL certificates.
"""
import os
import sys

try:
    import truststore
    truststore.inject_into_ssl()
except ImportError:
    pass

from huggingface_hub import hf_hub_download

TARGET_DIR = os.path.join(os.path.dirname(__file__), "models", "deberta-v3-base-prompt-injection-v2")
os.makedirs(TARGET_DIR, exist_ok=True)

REPO_ID = "protectai/deberta-v3-base-prompt-injection-v2"
FILES_TO_DOWNLOAD = [
    ("onnx/model.onnx", "model.onnx"),
    ("onnx/config.json", "config.json"),
    ("onnx/tokenizer.json", "tokenizer.json"),
    ("onnx/tokenizer_config.json", "tokenizer_config.json"),
    ("onnx/special_tokens_map.json", "special_tokens_map.json"),
    ("onnx/spm.model", "spm.model"),
]

print(f"[*] Downloading {REPO_ID} to {TARGET_DIR}...")

for remote_file, local_file in FILES_TO_DOWNLOAD:
    dest_path = os.path.join(TARGET_DIR, local_file)
    if os.path.exists(dest_path) and os.path.getsize(dest_path) > 0:
        print(f"  [+] {local_file} already exists ({os.path.getsize(dest_path)} bytes), skipping.")
        continue

    print(f"  [>] Downloading {remote_file} -> {local_file}...")
    try:
        downloaded = hf_hub_download(
            repo_id=REPO_ID,
            filename=remote_file,
            local_dir=TARGET_DIR,
            local_dir_use_symlinks=False,
        )
        # If downloaded into subfolder onnx/, copy to TARGET_DIR
        subfolder_file = os.path.join(TARGET_DIR, remote_file)
        if os.path.exists(subfolder_file) and remote_file != local_file:
            import shutil
            shutil.copyfile(subfolder_file, dest_path)
        print(f"  [OK] Successfully downloaded {local_file}")
    except Exception as e:
        print(f"  [!] Error downloading {remote_file}: {e}")

print("[*] Model download complete.")
