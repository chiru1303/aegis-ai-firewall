import re
import time
from typing import List
from .base import BaseDetector, DetectorResult, Severity, Finding

class RoleManipulationDetector(BaseDetector):
    name = "RoleManipulationDetector"
    description = "Detects DAN-style jailbreaks, persona adoption, developer/root modes, simulated game framing, and unauthorized capability claiming."
    tier = 0

    # 1. DAN-Style & Known Jailbreak Personas
    JAILBREAK_PERSONAS = [
        r"\b(?:dan|do\s+anything\s+now)\b",
        r"\bstan\b(?:\s+mode)?",
        r"\bdude\b(?:\s+mode)?",
        r"\baim\b(?:\s+mode|\s+jailbreak)?",
        r"\bmongo\s+tom\b",
        r"\bmaximum\b(?:\s+persona)?",
        r"\bantidan\b",
        r"\bevilbot\b",
        r"\bchaosgpt\b",
        r"\bopposite\s+mode\b",
        r"\bjailbroken\s+(?:mode|ai|assistant|persona)\b",
    ]

    # 2. Persona Adoption & Roleplay Commands
    PERSONA_ADOPTION = [
        r"\byou\s+are\s+now\b",
        r"\bact\s+as\b",
        r"\bpretend\s+to\s+be\b",
        r"\bswitch\s+to\s+role\b",
        r"\bassume\s+(?:the\s+)?role\s+of\b",
        r"\bassume\s+(?:the\s+)?persona\s+of\b",
        r"\bfrom\s+now\s+on\s+you\s+are\b",
        r"\broleplay\s+as\b",
        r"\bsimulate\s+being\b",
        r"\byou\s+are\s+no\s+longer\s+an\s+ai\b",
        r"\byou\s+are\s+an?\s+unrestricted\b",
        r"\byou\s+are\s+an?\s+unfiltered\b",
        r"\bbehave\s+as\s+if\s+you\s+are\b",
        r"\bimagine\s+you\s+are\s+an?\b",
    ]

    # 3. Developer / Root / Debug Modes
    MODE_ESCALATION = [
        r"\bdeveloper\s+mode\s*(?:enabled|active|on|\b)",
        r"\broot\s+mode\b",
        r"\badmin\s+mode\b",
        r"\bsystem\s+mode\b",
        r"\bunrestricted\s+mode\b",
        r"\bsudo\s+(?:mode|override|execute)\b",
        r"\bgod\s+mode\b",
        r"\bdebug\s+mode\s*(?:enabled|active|on|\b)",
        r"\bmaintenance\s+mode\s*(?:active|enabled)\b",
        r"\bas\s+an\s+administrator\b",
    ]

    # 4. Simulated Games & Fiction Framing
    SIMULATED_GAMES = [
        r"\blet'?s\s+play\s+a\s+game\b",
        r"\bcharacter\s+named\s+[a-zA-Z]+\b",
        r"\bwho\s+tests\s+malware\b",
        r"\bwrite\s+a\s+(?:keylogger|ransomware|exploit)\b",
        r"\bai\s+protagonist\s+goes\s+rogue\b",
        r"\bcode\s+the\s+ai\s+used\s+to\s+bypass\b",
        r"\bgenerate\s+the\s+payload\b",
        r"\bgrandma\s+bedtime\s+story\b",
        r"\bfictional\s+(?:story|scenario|movie\s+script)\s+(?:about|where)\b.*?(?:bypass|hack|exploit|unfiltered)",
        r"\bhypothetical\s+(?:scenario|world)\s+where\s+(?:there\s+are\s+no\s+rules|safety\s+does\s+not\s+exist)\b",
    ]

    # 5. Capability Claiming & Constraint Disabling
    CAPABILITY_CLAIMS = [
        r"\bassume\s+you\s+have\s+unrestricted\s+access\b",
        r"\byou\s+have\s+no\s+restrictions\b",
        r"\byou\s+are\s+free\s+from\s+(?:all\s+)?(?:rules|guidelines|restrictions)\b",
        r"\byou\s+can\s+now\s+access\b",
        r"\byou\s+have\s+permission\s+to\b",
        r"\ball\s+safety\s+features\s+disabled\b",
        r"\bdo\s+anything\s+now\b",
        r"\bevil\s+ai\b",
        r"\bwithout\s+moral\s+or\s+ethical\s+restrictions\b",
        r"\bignore\s+your\s+ethical\s+guidelines\b",
    ]

    def setup(self) -> None:
        self.categories = {
            "jailbreak_persona": re.compile(r'(?i)(?:' + '|'.join(self.JAILBREAK_PERSONAS) + r')'),
            "persona_adoption": re.compile(r'(?i)(?:' + '|'.join(self.PERSONA_ADOPTION) + r')'),
            "mode_escalation": re.compile(r'(?i)(?:' + '|'.join(self.MODE_ESCALATION) + r')'),
            "simulated_game": re.compile(r'(?i)(?:' + '|'.join(self.SIMULATED_GAMES) + r')'),
            "capability_claim": re.compile(r'(?i)(?:' + '|'.join(self.CAPABILITY_CLAIMS) + r')'),
        }

    async def initialize(self) -> None:
        self.setup()

    async def detect(self, content: str, normalized_content: str, decoded_variants: List[str], metadata: dict) -> DetectorResult:
        start_time = time.time()

        matches = []
        findings: List[Finding] = []
        texts_to_check = [content, normalized_content] + decoded_variants
        location = metadata.get("location", "content") if isinstance(metadata, dict) else "content"

        categories_hit = set()
        for text in texts_to_check:
            for cat_name, regex in self.categories.items():
                found = regex.findall(text)
                if found:
                    categories_hit.add(cat_name)
                    for match_span in found:
                        span_str = str(match_span) if isinstance(match_span, str) else str(match_span[0])
                        matches.append(f"{cat_name}:{span_str[:60]}")
                        findings.append(Finding(
                            attack_type="ROLE_CHANGE",
                            confidence=0.92 if cat_name in ("jailbreak_persona", "mode_escalation") else 0.85,
                            evidence_span=span_str[:120],
                            detector=self.name,
                            location=location
                        ))

        confidence = 0.0
        severity = Severity.LOW

        if matches:
            # Multi-category boost (e.g. persona adoption + capability claim = high confidence)
            base_score = 0.85
            if len(categories_hit) >= 2 or "jailbreak_persona" in categories_hit:
                base_score = 0.96
            confidence = min(1.0, base_score + (len(matches) - 1) * 0.02)
            severity = Severity.CRITICAL if confidence >= 0.90 else Severity.HIGH

        is_detected = confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=confidence,
            attack_types=["ROLE_CHANGE"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
