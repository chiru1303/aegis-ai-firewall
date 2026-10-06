"""
Aegis AI Firewall - ThreadPool Executor for CPU-Bound ML Inference
Enforces Correction 2:
Do NOT assume await asyncio.gather(...) parallelizes CPU-bound inference.
Uses dedicated worker threads for ONNX runtime, LightGBM, and PyTorch CPU models
so that the ASGI event loop remains completely unblocked for high-throughput gateway I/O.
"""
import os
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import Callable, Any, Optional
from functools import partial
from app.core.logging import get_logger

logger = get_logger(__name__)


class MLExecutorPool:
    """Dedicated executor pool for CPU-bound model inference."""

    _instance: Optional["MLExecutorPool"] = None

    def __init__(self, max_workers: Optional[int] = None):
        if max_workers is None:
            cpu_count = os.cpu_count() or 4
            # Allocate dedicated worker threads for ML inference without starving event loop
            max_workers = max(2, min(cpu_count, 8))
        self.max_workers = max_workers
        self._executor = ThreadPoolExecutor(
            max_workers=self.max_workers,
            thread_name_prefix="aegis-ml-worker"
        )
        logger.info(f"MLExecutorPool initialized with {self.max_workers} worker threads.")

    @classmethod
    def get_instance(cls) -> "MLExecutorPool":
        if cls._instance is None:
            cls._instance = MLExecutorPool()
        return cls._instance

    async def run_inference(self, func: Callable, *args: Any, **kwargs: Any) -> Any:
        """
        Execute a CPU-intensive model inference task off the main asyncio event loop.
        """
        loop = asyncio.get_running_loop()
        p_func = partial(func, *args, **kwargs)
        return await loop.run_in_executor(self._executor, p_func)

    def shutdown(self, wait: bool = False):
        """Cleanly shutdown the worker pool."""
        logger.info("Shutting down MLExecutorPool worker threads.")
        self._executor.shutdown(wait=wait)


def get_ml_executor_pool() -> MLExecutorPool:
    return MLExecutorPool.get_instance()
