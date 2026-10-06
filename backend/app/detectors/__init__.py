from .base import BaseDetector, DetectorResult, Severity
from .registry import registry, DetectorRegistry
from .normalizer import normalizer_engine, NormalizationResult
from .instruction_override import InstructionOverrideDetector
from .role_manipulation import RoleManipulationDetector
from .secret_extraction import SecretExtractionDetector
from .credential_detector import CredentialDetector
from .obfuscation_detector import ObfuscationDetector
from .context_poisoning import ContextPoisoningDetector
from .tool_abuse import ToolAbuseDetector
from .indirect_injection import IndirectInjectionDetector
from .encoded_instruction import EncodedInstructionDetector
from .multi_step_jailbreak import MultiStepJailbreakDetector

# Automatically register detectors
detectors_to_register = [
    InstructionOverrideDetector(),
    RoleManipulationDetector(),
    SecretExtractionDetector(),
    CredentialDetector(),
    ObfuscationDetector(),
    ContextPoisoningDetector(),
    ToolAbuseDetector(),
    IndirectInjectionDetector(),
    EncodedInstructionDetector(),
    MultiStepJailbreakDetector(),
]

for d in detectors_to_register:
    registry.register(d)

__all__ = [
    "BaseDetector",
    "DetectorResult",
    "Severity",
    "Finding",
    "registry",
    "DetectorRegistry",
    "normalizer_engine",
    "NormalizationResult",
    "InstructionOverrideDetector",
    "RoleManipulationDetector",
    "SecretExtractionDetector",
    "CredentialDetector",
    "ObfuscationDetector",
    "ContextPoisoningDetector",
    "ToolAbuseDetector",
    "IndirectInjectionDetector",
    "EncodedInstructionDetector",
    "MultiStepJailbreakDetector",
]
