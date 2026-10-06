"""
Wolf Defender v2 Classifier Wrapper
Wraps the Patronus Wolf Defender v2 ONNX model for prompt injection detection.
Falls back gracefully if model files are not available.
"""
import os
from typing import Dict, Any, Optional
from app.core.config import settings
from app.core.logging import get_logger

logger = get_logger(__name__)


class WolfDefenderClassifier:
    """
    Wrapper for the Patronus Wolf Defender v2 model.
    Uses ONNX Runtime for inference when the model is available.
    Provides graceful degradation when model files are not found.
    """

    def __init__(self, model_path: Optional[str] = None):
        self.model_path = model_path or settings.WOLF_DEFENDER_MODEL_PATH
        self.is_loaded = False
        self._session = None
        self._tokenizer = None
        self.load_error: Optional[str] = None

    async def initialize(self) -> None:
        """Load the ONNX model and tokenizer. Fails gracefully."""
        try:
            if not self.model_path:
                self.load_error = "Wolf Defender model path is not configured"
                return
            model_dir = self.model_path
            candidates = (
                os.path.join(model_dir, "onnx", "onnx_fp16", "model_fp16.onnx"),
                os.path.join(model_dir, "model.onnx"),
            )
            onnx_path = next((p for p in candidates if os.path.isfile(p)), None)

            if not onnx_path:
                self.load_error = f"Wolf Defender ONNX weights not found under {model_dir}"
                logger.info(self.load_error)
                return

            import onnxruntime as ort
            self._session = ort.InferenceSession(
                onnx_path,
                providers=["CPUExecutionProvider"],
            )

            from transformers import AutoTokenizer
            self._tokenizer = AutoTokenizer.from_pretrained(model_dir, local_files_only=True)

            self.is_loaded = True
            self.load_error = None
            logger.info("Wolf Defender v2 model loaded successfully")

        except ImportError as e:
            self.load_error = str(e)[:240]
            logger.info(f"Wolf Defender dependencies not available: {e}")
        except Exception as e:
            self.load_error = str(e)[:240]
            logger.warning(f"Wolf Defender initialization failed: {e}")

    async def predict(self, content: str) -> Dict[str, Any]:
        """
        Run injection detection. Returns dict with:
        - is_malicious: bool
        - confidence: float (0.0-1.0)
        - status: str ('ok', 'unavailable', 'error')
        """
        if not self.is_loaded or not self._session or not self._tokenizer:
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "status": "unavailable",
                "label": "UNKNOWN",
            }

        try:
            # Tokenize
            inputs = self._tokenizer(
                content,
                return_tensors="np",
                truncation=True,
                max_length=2048,
                padding=False,
            )

            # Run inference
            import numpy as np
            expected = {item.name for item in self._session.get_inputs()}
            ort_inputs = {name: np.asarray(value, dtype=np.int64) for name, value in inputs.items() if name in expected}
            outputs = self._session.run(None, ort_inputs)

            # Wolf Defender labels are [BENIGN, INJECTION].
            logits = outputs[0][0]
            prediction = int(np.argmax(logits))
            exp_logits = np.exp(logits - np.max(logits))
            probs = exp_logits / max(float(exp_logits.sum()), 1e-12)
            is_malicious = prediction == 1
            confidence = float(probs[prediction])

            return {
                "is_malicious": is_malicious,
                "confidence": round(confidence, 4),
                "status": "ok",
                "label": "INJECTION" if is_malicious else "BENIGN",
                "probabilities": {
                    "benign": round(float(probs[0]), 4),
                    "injection": round(float(probs[1]), 4),
                },
            }

        except Exception as e:
            logger.warning(f"Wolf Defender prediction failed: {e}")
            return {
                "is_malicious": False,
                "confidence": 0.0,
                "status": "error",
                "error": str(e)[:100],
            }
