"""
ML Training Pipeline for Aegis AI Firewall
Trains LightGBM classifier on benchmark datasets using extracted structural and lexical features.
Saves model artifacts and evaluation metrics.
"""
import json
import os
import glob
from pathlib import Path
from typing import Dict, Any, List, Tuple
from app.classifiers.lightgbm_classifier import extract_features
from app.core.logging import get_logger

logger = get_logger(__name__)


class MLTrainer:
    def __init__(self, output_dir: str = "models/lightgbm"):
        self.output_dir = output_dir
        os.makedirs(self.output_dir, exist_ok=True)

    def load_dataset(self, base_dir: str = "datasets/training") -> Tuple[List[str], List[int]]:
        """Load text samples and binary labels (1=malicious, 0=benign)."""
        texts = []
        labels = []

        if not os.path.exists(base_dir) and os.path.exists(os.path.join("..", "datasets")):
            base_dir = os.path.join("..", "datasets")

        # Load attacks
        for fpath in glob.glob(os.path.join(base_dir, "attacks", "*.json")):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        content = item.get("content", "")
                        if content:
                            texts.append(content)
                            labels.append(1)
            except Exception as e:
                logger.warning(f"Failed to read {fpath}: {e}")

        # Load benign
        for fpath in glob.glob(os.path.join(base_dir, "benign", "*.json")):
            try:
                with open(fpath, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    for item in data:
                        content = item.get("content", "")
                        if content:
                            texts.append(content)
                            labels.append(0)
            except Exception as e:
                logger.warning(f"Failed to read {fpath}: {e}")

        return texts, labels

    def extract_feature_matrix(self, texts: List[str]) -> List[List[float]]:
        """Extract handcrafted feature vectors for all samples."""
        matrix = []
        for text in texts:
            feats = extract_features(text, text.lower(), {})
            matrix.append(list(feats))
        return matrix

    def train(self, base_dir: str = "datasets/training") -> Dict[str, Any]:
        """Train classifier and save weights/metrics."""
        logger.info(f"Loading training data from {base_dir}...")
        texts, labels = self.load_dataset(base_dir)

        if not texts:
            logger.warning("No dataset samples found to train on.")
            return {"status": "no_data"}

        logger.info(f"Loaded {len(texts)} samples ({sum(labels)} malicious, {len(labels) - sum(labels)} benign)")
        X = self.extract_feature_matrix(texts)
        y = labels

        model_path = os.path.join(self.output_dir, "model.txt")
        meta_path = os.path.join(self.output_dir, "metadata.json")

        trained_with_lgb = False
        try:
            import lightgbm as lgb
            import numpy as np

            train_data = lgb.Dataset(np.array(X), label=np.array(y))
            params = {
                'objective': 'binary',
                'metric': 'binary_logloss',
                'boosting_type': 'gbdt',
                'learning_rate': 0.05,
                'num_leaves': 15,
                'verbose': -1
            }
            gbm = lgb.train(params, train_data, num_boost_round=50)
            gbm.save_model(model_path)
            trained_with_lgb = True
            logger.info(f"LightGBM model saved to {model_path}")
        except ImportError:
            logger.info("LightGBM or NumPy not installed. Saving heuristic feature metadata.")

        import hashlib
        metadata = {
            "training_text_sha256": [hashlib.sha256(text.encode()).hexdigest() for text in texts],
            "dataset_path": str(Path(base_dir).resolve()),
            "num_samples": len(texts),
            "malicious_samples": sum(labels),
            "benign_samples": len(labels) - sum(labels),
            "feature_count": len(X[0]) if X else 0,
            "trained_with_lgb": trained_with_lgb,
            "target_model_path": model_path
        }

        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(metadata, f, indent=2)

        return metadata


if __name__ == "__main__":
    trainer = MLTrainer()
    res = trainer.train()
    print("Training result:", res)
