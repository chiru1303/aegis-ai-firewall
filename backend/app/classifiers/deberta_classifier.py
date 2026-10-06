"""
ProtectAI DeBERTa-v3-base Prompt Injection v2 Classifier
Independent secondary detector for ensemble prompt injection detection.
Falls back gracefully if model files are not available.
"""
import os
from typing import Dict, Any, Optional
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class DeBERTaClassifier:
    """
    Wrapper for protectai/deberta-v3-base-prompt-injection-v2.
    Provides independent second opinion for ensemble detection.
    Uses Hugging Face Transformers pipeline when model is available.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.DEBERTA_MODEL_PATH
        self.is_loaded = False
        self._pipeline = None
        self._onnx_session = None
        self._tokenizer = None

    async def initialize(self) -> None:
        """Load the DeBERTa model using ONNX runtime or transformers pipeline."""
        try:
            if not self.model_path:
                return
            if not os.path.exists(self.model_path):
                logger.info(f"DeBERTa model not found at {self.model_path}")
                return

            onnx_file = os.path.join(self.model_path, "model.onnx")
            if os.path.exists(onnx_file):
                import onnxruntime as ort
                from transformers import AutoTokenizer

                self._onnx_session = ort.InferenceSession(
                    onnx_file,
                    providers=["CPUExecutionProvider"],
                )
                self._tokenizer = AutoTokenizer.from_pretrained(self.model_path)
                self.is_loaded = True
                logger.info("ProtectAI DeBERTa ONNX classifier loaded successfully")
                return

            from transformers import pipeline

            self._pipeline = pipeline(
                "text-classification",
                model=self.model_path,
                tokenizer=self.model_path,
                device=-1,  # CPU
                truncation=True,
                max_length=512,
            )

            self.is_loaded = True
            logger.info("ProtectAI DeBERTa classifier loaded successfully")

        except ImportError as e:
            logger.info(f"DeBERTa dependencies not available: {e}")
        except Exception as e:
            logger.warning(f"DeBERTa initialization failed: {e}")

    async def predict(self, content: str) -> Dict[str, Any]:
        """
        Run injection detection. Returns dict with:
        - is_malicious: bool
        - confidence: float (0.0-1.0)
        - status: str ('ok', 'unavailable', 'error')
        """
        if not self.is_loaded:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "status": "unavailable",
                "label": "UNKNOWN",
            }

        try:
            if self._onnx_session and self._tokenizer:
                import numpy as np
                inputs = self._tokenizer(
                    content[:512],
                    truncation=True,
                    max_length=512,
                    return_tensors="np"
                )
                feed = {
                    "input_ids": inputs["input_ids"],
                    "attention_mask": inputs["attention_mask"]
                }
                logits = self._onnx_session.run(None, feed)[0]
                probs = np.exp(logits) / np.sum(np.exp(logits), axis=-1)
                injection_prob = float(probs[0][1]) if len(probs[0]) > 1 else float(probs[0][0])
                is_malicious = injection_prob > 0.5
                return {
                    "is_malicious": is_malicious,
                    "confidence": round(injection_prob if is_malicious else (1.0 - injection_prob), 4),
                    "status": "ok",
                    "label": "INJECTION" if is_malicious else "SAFE",
                    "raw_score": round(injection_prob, 4),
                }

            if self._pipeline:
                results = self._pipeline(content[:512])
                if not results:
                    return {"is_malicious": False, "confidence": 0.0, "status": "error"}

                result = results[0]
                label = result.get("label", "").upper()
                score = result.get("score", 0.0)

                is_malicious = label in ["INJECTION", "MALICIOUS", "1", "LABEL_1"]
                confidence = score if is_malicious else 1.0 - score

                return {
                    "is_malicious": is_malicious,
                    "confidence": round(confidence, 4),
                    "status": "ok",
                    "label": label,
                    "raw_score": round(score, 4),
                }

        except Exception as e:
            logger.warning(f"DeBERTa prediction failed: {e}")
            return {"is_malicious": False, "confidence": 0.0, "status": "error"}
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "status": "error",
                "error": str(e)[:100],
            }
