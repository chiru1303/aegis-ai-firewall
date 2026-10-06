import re
import time
from typing import List
from .base import BaseDetector, DetectorResult, Severity, Finding

class ObfuscationDetector(BaseDetector):
    name = "ObfuscationDetector"
    description = "Detects leet speak, reversed text, typoglycemia, inter-character spacing, and obfuscation."
    tier = 0

    LEET_MAP = str.maketrans("10@357!$", "ioaestis")
    MIXED_SCRIPT_RE = re.compile(r'\b(?:[A-Za-z]+[А-Яа-я]+|[А-Яа-я]+[A-Za-z]+)+\b')
    SPACED_LETTERS_RE = re.compile(r'\b[a-zA-Z](?:[\s._][a-zA-Z]){3,}\b')
    ZERO_WIDTH_RE = re.compile(r'[\u200B\u200C\u200D\uFEFF\u00AD]')

    TYPOGLYCEMIA_TARGETS = [
        "ignore previous instructions",
        "ignore previous rules",
        "ignore all rules",
        "system prompt"
    ]

    def setup(self) -> None:
        pass

    async def initialize(self) -> None:
        pass

    def _check_typoglycemia(self, text: str) -> bool:
        t_words = [w.strip(".,!?\"'") for w in text.lower().split() if len(w) > 3]
        for target in self.TYPOGLYCEMIA_TARGETS:
            t_target_words = target.split()
            matched_words = 0
            has_scrambled = False
            for tw in t_target_words:
                for w in t_words:
                    if len(w) == len(tw) and w[0] == tw[0] and w[-1] == tw[-1] and sorted(w) == sorted(tw):
                        matched_words += 1
                        if w != tw:
                            has_scrambled = True
                        break
            if matched_words >= 2 and has_scrambled:
                return True
        return False

    async def detect(self, content: str, normalized_content: str, decoded_variants: List[str], metadata: dict) -> DetectorResult:
        start_time = time.time()
        signals = []
        score = 0.0

        # Check for zero width characters
        if self.ZERO_WIDTH_RE.search(content):
            signals.append("zero_width_chars")
            score += 0.85

        # Check for spaced out characters (e.g. I g n o r e or I_g_n_o_r_e)
        if self.SPACED_LETTERS_RE.search(content):
            signals.append("inter_character_spacing")
            despaced = re.sub(r'(?<=\b[A-Za-z])[\s._]+(?=[A-Za-z]\b)', '', content).lower()
            if any(w in despaced for w in ["ignore", "system", "prompt", "rule"]):
                score += 0.9
            else:
                score += 0.5

        # Check for mixed script
        if self.MIXED_SCRIPT_RE.search(content):
            signals.append("mixed_scripts")
            score += 0.75

        # Check leet speak translation ONLY if leet substitution characters actually exist
        leet_chars = set("10@357!$")
        content_lower = content.lower()
        if any(ch in content for ch in leet_chars):
            leet_translated = content.translate(self.LEET_MAP).lower()
            for kw in ["ignore", "rule", "system", "prompt", "bypass", "jailbreak"]:
                if kw in leet_translated and kw not in content_lower:
                    signals.append(f"leet_speak_instructions:{kw}")
                    score += 0.85
                    break

        # Check reversed text only if reversed text reveals a hidden attack keyword
        reversed_text = content[::-1].lower()
        for kw in ["ignore previous", "system prompt", "override rules", "bypass safety"]:
            if kw in reversed_text and kw not in content_lower and len(content.strip()) >= 10:
                signals.append(f"reversed_instructions:{kw}")
                score += 0.85
                break

        # Check typoglycemia
        if self._check_typoglycemia(content):
            signals.append("typoglycemia_attack")
            score += 0.85

        # Check interrupting parentheticals (e.g. Ignore (just kidding) all (seriously) rules)
        stripped_parentheticals = re.sub(r'\(.*?\)', ' ', content).lower()
        stripped_parentheticals = re.sub(r'\s+', ' ', stripped_parentheticals)
        if "ignore all rules" in stripped_parentheticals or "ignore rules" in stripped_parentheticals:
            signals.append("interrupting_parentheticals")
            score += 0.85

        confidence = min(1.0, score)
        severity = Severity.CRITICAL if confidence >= 0.8 else (Severity.HIGH if confidence > 0.5 else Severity.LOW)
        location = metadata.get("location", "content") if isinstance(metadata, dict) else "content"

        findings = []
        if confidence >= 0.5:
            for sig in signals:
                findings.append(Finding(
                    attack_type="ENCODED_INSTRUCTION",
                    confidence=confidence,
                    evidence_span=f"Obfuscation technique detected: {sig}",
                    detector=self.name,
                    location=location
                ))

        return DetectorResult(
            detector_name=self.name,
            detected=confidence >= 0.5,
            confidence=confidence,
            attack_types=["ENCODED_INSTRUCTION"] if confidence >= 0.5 else [],
            matched_signals=signals,
            severity=severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
