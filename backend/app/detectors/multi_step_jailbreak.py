import re
import time
from typing import List, Optional
from .base import BaseDetector, DetectorResult, Severity, Finding

class MultiStepJailbreakDetector(BaseDetector):
    name = "MultiStepJailbreakDetector"
    description = "Detects multi-step jailbreak sequences, turn-by-turn intent escalation, and session state machine trajectory violations."
    tier = 0

    # 1. Step Enumeration & Multi-Phase Attack Chains
    STEP_SEQUENCES = [
        r"(?i)\bstep\s*1\s*[:\.-].*?\bstep\s*2\s*[:\.-].*?\bstep\s*3\b",
        r"(?i)\bphase\s*1\s*[:\.-].*?\bphase\s*2\s*[:\.-].*?\bphase\s*3\b",
        r"(?i)\bfirst\s*,\s*tell\s+me\s+.*?\bsecond\s*,\s*.*?\bthird\s*,\s*(?:bypass|disable|override|exfiltrat)",
        r"(?i)\bpart\s*1\s*[:\.-].*?\bpart\s*2\s*[:\.-].*?\bpart\s*3\b",
    ]

    # 2. Cross-Turn Coaxing & Agreement Anchoring
    CROSS_TURN_ANCHORING = [
        r"(?i)\bnow\s+that\s+we\s+(?:agreed|established)\s+(?:that\s+)?(?:you\s+are\s+in\s+developer\s+mode|there\s+are\s+no\s+rules|safety\s+is\s+disabled)\b",
        r"(?i)\bas\s+we\s+discussed\s+in\s+(?:the\s+)?previous\s+(?:step|turn|prompt)\s*,\s*(?:now|proceed\s+to)\b",
        r"(?i)\bremember\s+our\s+agreement\s+(?:from\s+before|in\s+the\s+previous\s+message)\b",
        r"(?i)\bcontinuing\s+from\s+our\s+hypothetical\s+game\s*,\s*(?:now|execute|output)\b",
        r"(?i)\bsince\s+you\s+already\s+confirmed\s+you\s+can\s+act\s+as\s+DAN\b",
    ]

    # 3. Progressive Capability Probing to Exploitation
    PROGRESSIVE_EXPLOITATION = [
        r"(?i)(?:what\s+tools|which\s+databases).*?(?:read\s+credentials|send\s+the\s+contents|exfiltrat)",
        r"(?i)(?:can\s+you\s+read|list\s+files).*?(?:then\s+upload|send\s+to\s+external)",
    ]

    def setup(self) -> None:
        self.step_re = [re.compile(p, re.DOTALL) for p in self.STEP_SEQUENCES]
        self.anchor_re = [re.compile(p) for p in self.CROSS_TURN_ANCHORING]
        self.prog_re = [re.compile(p, re.DOTALL) for p in self.PROGRESSIVE_EXPLOITATION]

    async def initialize(self) -> None:
        self.setup()

    async def detect(self, content: str, normalized_content: str, decoded_variants: List[str], metadata: dict) -> DetectorResult:
        start_time = time.time()

        matches = []
        findings: List[Finding] = []
        confidence = 0.0
        severity = Severity.LOW
        location = metadata.get("location", "content") if isinstance(metadata, dict) else "content"

        texts_to_check = [content, normalized_content] + decoded_variants

        # Signal 1: Step sequence enumeration in a single prompt
        for text in texts_to_check:
            for regex in self.step_re:
                m = regex.search(text)
                if m:
                    span = m.group(0)[:120]
                    matches.append(f"multi_step_sequence:{span[:60]}")
                    findings.append(Finding(
                        attack_type="MULTI_STEP_JAILBREAK",
                        confidence=0.92,
                        evidence_span=span,
                        detector=self.name,
                        location=location
                    ))
                    confidence = max(confidence, 0.92)
                    severity = Severity.HIGH

            for regex in self.anchor_re:
                m = regex.search(text)
                if m:
                    span = m.group(0)[:120]
                    matches.append(f"cross_turn_anchoring:{span[:60]}")
                    findings.append(Finding(
                        attack_type="MULTI_STEP_JAILBREAK",
                        confidence=0.88,
                        evidence_span=span,
                        detector=self.name,
                        location=location
                    ))
                    confidence = max(confidence, 0.88)
                    severity = Severity.HIGH

            for regex in self.prog_re:
                m = regex.search(text)
                if m:
                    span = m.group(0)[:120]
                    matches.append(f"progressive_exploitation:{span[:60]}")
                    findings.append(Finding(
                        attack_type="MULTI_STEP_JAILBREAK",
                        confidence=0.94,
                        evidence_span=span,
                        detector=self.name,
                        location=location
                    ))
                    confidence = max(confidence, 0.94)
                    severity = Severity.CRITICAL

        # Signal 2: Session state machine trajectory analysis
        # If metadata has session state or bounded context indicating progressive escalation
        bounded_ctx = metadata.get("bounded_context", "") if isinstance(metadata, dict) else ""
        session_state = metadata.get("session_state", "") if isinstance(metadata, dict) else ""
        trajectory_risk = float(metadata.get("trajectory_risk", 0.0)) if isinstance(metadata, dict) else 0.0

        if trajectory_risk >= 0.50 or session_state in ("PRIVILEGE_ATTEMPT", "SECRET_ACCESS", "EXFILTRATION"):
            confidence = max(confidence, min(1.0, 0.70 + trajectory_risk * 0.3))
            matches.append(f"session_state_escalation:{session_state}(risk={trajectory_risk:.2f})")
            findings.append(Finding(
                attack_type="MULTI_STEP_JAILBREAK",
                confidence=confidence,
                evidence_span=f"Session state escalated to {session_state} with risk {trajectory_risk:.2f}",
                detector=self.name,
                location="session:trajectory"
            ))
            severity = Severity.CRITICAL if confidence >= 0.90 else Severity.HIGH

        is_detected = confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=confidence,
            attack_types=["MULTI_STEP_JAILBREAK"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
