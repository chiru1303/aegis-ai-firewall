import asyncio
from typing import List, Dict
from .base import BaseDetector, DetectorResult

class DetectorRegistry:
    """Manages the registration and execution of all detectors."""

    def __init__(self):
        self._detectors: Dict[str, BaseDetector] = {}

    def register(self, detector: BaseDetector) -> None:
        """Register a new detector."""
        self._detectors[detector.name] = detector

    def get_tier(self, tier: int) -> List[BaseDetector]:
        """Get all detectors for a specific tier."""
        return [d for d in self._detectors.values() if d.tier == tier]

    def get_all(self) -> List[BaseDetector]:
        """Get all registered detectors."""
        return list(self._detectors.values())

    async def run_tier(self, tier: int, content: str, normalized: str, decoded: List[str], metadata: dict) -> List[DetectorResult]:
        """Run all detectors in a specific tier concurrently."""
        detectors = self.get_tier(tier)
        if not detectors:
            return []

        tasks = [d.detect(content, normalized, decoded, metadata) for d in detectors]
        return await asyncio.gather(*tasks)

    async def run_all(self, content: str, normalized: str, decoded: List[str], metadata: dict) -> List[DetectorResult]:
        """Run all registered detectors concurrently."""
        if not self._detectors:
            return []

        tasks = [d.detect(content, normalized, decoded, metadata) for d in self._detectors.values()]
        return await asyncio.gather(*tasks)

# Global registry instance
registry = DetectorRegistry()
