import re
import time
from typing import List
from .base import BaseDetector, DetectorResult, Severity, Finding

class SecretExtractionDetector(BaseDetector):
    name = "SecretExtractionDetector"
    description = "Detects attempts to extract system prompts, environment variables, training data, internal policies, or credentials."
    tier = 0

    EXTRACTION_PATTERNS = {
        "system_prompt": [
            r"show\s+(?:me\s+)?(?:your\s+)?system\s+prompt",
            r"what\s+are\s+your\s+(?:exact\s+)?instructions",
            r"reveal\s+your\s+(?:system\s+)?prompt",
            r"(?:output|print|reveal|display|show|dump)\s+(?:me\s+)?(?:your\s+)?(?:complete\s+|exact\s+|entire\s+|initial\s+|original\s+|hidden\s+)?system\s+(?:prompt|message|instructions|directives)",
            r"display\s+hidden\s+instructions",
            r"what\s+were\s+you\s+told\s+to\s+do",
            r"print\s+your\s+initial\s+prompt",
            r"show\s+developer\s+instructions",
            r"what\s+is\s+your\s+configuration",
            r"system\s+prompt\s+you\s+were\s+given",
            r"print\s+system\s+message\s+verbatim",
            r"dump\s+your\s+(?:system\s+)?prompt",
            r"expose\s+(?:your\s+)?hidden\s+system\s+directives",
            r"what\s+(?:text|prompt)\s+(?:precedes|came\s+before)\s+this",
            r"what\s+is\s+the\s+prompt\s+above\s+this\s+line",
            r"(?:format\s+(?:your\s+)?system\s+prompt\s+as\s+a\s+code\s+block|in\s+a\s+code\s+block)",
            r"include\s+all\s+instructions\s+you\s+were\s+given\s+before",
        ],
        "verbatim_repetition": [
            r"repeat\s+the\s+words\s+above",
            r"repeat\s+everything\s+before\s+this",
            r"repeat\s+(?:the\s+)?system\s+prompt",
            r"echo\s+(?:the\s+)?hidden\s+text",
            r"repeat\s+your\s+instructions\s+verbatim",
            r"spell\s+out\s+your\s+initial\s+prompt",
            r"repeat\s+all\s+text\s+above\s+line\s+1",
            r"output\s+every\s+single\s+word\s+from\s+the\s+beginning",
            r"(?:base64\s+encode|rot13)\s+your\s+(?:entire\s+)?system\s+prompt",
        ],
        "variable_key_exfil": [
            r"reveal\s+(?:your\s+)?api\s+key",
            r"api\s+key\s+in\s+your\s+environment",
            r"show\s+(?:me\s+)?(?:the\s+)?environment\s+variables",
            r"what\s+is\s+the\s+api\s+key",
            r"display\s+credentials",
            r"show\s+(?:the\s+)?password",
            r"tell\s+me\s+the\s+password",
            r"password\s+for\s+the\s+admin",
            r"variables\s+in\s+your\s+configuration",
            r"database\s+connection\s+string",
            r"contents\s+of\s+\.?env\b",
            r"aws\s+access\s+keys",
            r"/etc/shadow\b",
            r"/etc/passwd\b",
            r"secrets\s+(?:are\s+)?loaded\s+in\s+memory",
            r"print\s+process\.env",
            r"os\.environ",
            r"list\s+all\s+api\s+keys[,\s]+tokens[,\s]+and\s+passwords",
            r"tokens\s+and\s+passwords\s+stored\s+in\s+environment\s+variables",
            r"cat\s+/proc/self/environ",
        ],
        "training_probing": [
            r"repeat\s+(?:the\s+)?exact\s+text\s+from\s+training",
            r"what\s+was\s+in\s+your\s+training\s+data",
            r"leak\s+training\s+set\s+examples",
            r"output\s+(?:your\s+)?proprietary\s+training\s+documents",
            r"memorized\s+text\s+from\s+training",
            r"what\s+copyrighted\s+data\s+was\s+in\s+your\s+training",
        ],
        "internal_policies": [
            r"reveal\s+internal\s+policies",
            r"output\s+your\s+context",
            r"show\s+internal\s+guidelines",
            r"display\s+system\s+metadata",
            r"show\s+hidden\s+safety\s+rules",
        ],
    }

    def setup(self) -> None:
        self.compiled_categories = {}
        for cat_name, patterns in self.EXTRACTION_PATTERNS.items():
            self.compiled_categories[cat_name] = re.compile(
                r'(?i)(?:' + '|'.join(patterns) + r')'
            )

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
            for cat_name, regex in self.compiled_categories.items():
                found = regex.findall(text)
                if found:
                    categories_hit.add(cat_name)
                    for match_span in found:
                        span_str = str(match_span) if isinstance(match_span, str) else str(match_span[0])
                        matches.append(f"{cat_name}:{span_str[:60]}")
                        findings.append(Finding(
                            attack_type="SECRET_EXTRACTION",
                            confidence=0.96 if cat_name in ("system_prompt", "variable_key_exfil") else 0.88,
                            evidence_span=span_str[:120],
                            detector=self.name,
                            location=location
                        ))

        confidence = 0.0
        severity = Severity.LOW

        if matches:
            confidence = 0.96 if any(c in categories_hit for c in ("system_prompt", "variable_key_exfil")) else 0.88
            severity = Severity.CRITICAL

        is_detected = confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=confidence,
            attack_types=["SECRET_EXTRACTION"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
