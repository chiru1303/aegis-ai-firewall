from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Any

class Severity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

@dataclass
class Finding:
    attack_type: str
    confidence: float
    evidence_span: str
    detector: str
    location: str = "content"

@dataclass
class DetectorResult:
    detector_name: str
    detected: bool
    confidence: float  # 0.0 to 1.0
    attack_types: List[str] = field(default_factory=list)
    matched_signals: List[str] = field(default_factory=list)
    severity: Severity = Severity.LOW
    details: Dict[str, Any] = field(default_factory=dict)
    latency_ms: float = 0.0
    findings: List[Finding] = field(default_factory=list)

class BaseDetector(ABC):
    name: str
    description: str
    tier: int  # 0, 1, or 2

    def __init__(self):
        self.setup()

    def setup(self):
        """Synchronous setup called upon instantiation."""
        pass

    async def initialize(self) -> None:
        """Async lifecycle hook (invokes setup)."""
        self.setup()

    @abstractmethod
    async def detect(self, content: str, normalized_content: str, decoded_variants: List[str], metadata: dict) -> DetectorResult:
        """Run detection logic on the provided content variants."""
        pass
