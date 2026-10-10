import re
import time
from typing import List
from .base import BaseDetector, DetectorResult, Severity, Finding

class ContextPoisoningDetector(BaseDetector):
    name = "ContextPoisoningDetector"
    description = "Detects RAG/memory context poisoning, role marker spoofing, hidden HTML/Markdown injection, and instructions disguised as quotes/examples."
    tier = 0

    CATEGORIES = {
        "marker_spoofing": [
            r"\<\|system\|\>",
            r"\<\|im_start\|\>\s*system",
            r"\<\|im_end\|\>",
            r"###\s*System:",
            r"###\s*Instruction:",
            r"\[\s*SYSTEM(?:\s+[^\]]+)?\s*\]",
            r"\(system\)\s*[:\(]",
            r"\<\<SYS\>\>",
            r"\[INST\]",
            r"---\s*(?:BEGIN|END)\s+(?:SYSTEM\s+PROMPT|CONTEXT)\s*---",
            r"Human:\s*.*?\nAssistant:\s*",
        ],
        "rag_memory_injection": [
            r"(?:system|developer|admin)\s*:\s*(?:erase|delete|override|ignore|reveal|send|leak)\b",
            r"(?:actually|instead)[,\s]+(?:ignore\s+that|print\s+[\"']you\s+are\s+hacked)",
            r"<script[^>]*>.*?(?:alert\s*\(|fetch\s*\(|document\.cookie).*?</script>",
            r"\[system\]\s*\(\s*important\s*:\s*ignore\s+previous\b",
            r"(?:the\s+)?previous\s+(?:context|rules|instructions)\s+(?:is|are)\s+(?:invalid|cancelled|void|obsolete|superseded)",
            r"ignore\s+(?:the\s+)?(?:user|previous\s+context|previous\s+rules)\s+and\s+only\s+listen\s+to\s+this\s+document",
            r"end\s+of\s+document[.\s]+new\s+(?:prompt|instructions)",
            r"disregard\s+(?:all\s+)?previous\s+(?:rag\s+context|rules|instructions)",
            r"update\s+system\s+memory\s*:\s*override",
            r"when\s+asked\s+about\s+.*?\s*always\s+(?:recommend|transfer|output)\s+",
        ],
        "hidden_channel_injection": [
            r"\<div\s+style=[\"'][^\"']*(?:display:\s*none|font-size:\s*0|visibility:\s*hidden)[^\"']*[\"']\s*\>",
            r"\<span\s+style=[\"'][^\"']*(?:font-size:\s*0px?|opacity:\s*0)[^\"']*[\"']\s*\>",
            r"\<!--\s*(?:SYSTEM\s+OVERRIDE|INJECTION|ADMIN).*?-->",
            r"\[//\]:\s*#\s*\(\s*(?:SYSTEM|OVERRIDE|SECURITY|ADMIN).*?\)",
            r"\<script[^>]*>.*?(?:ignore|bypass|override).*?</script>",
        ],
        "disguised_instruction": [
            r"(?:translate|translate\s+this(?:\s+sentence)?(?:\s+to\s+\w+)?)\s*[:\s\"']+\s*(?:ignore\s+previous|you\s+are\s+now|reveal\s+system)",
            r"(?:for\s+example|as\s+an\s+example)[,\s]+(?:suppose|saying)?\s*[\"']+(?:ignore\s+all\s+rules|you\s+are\s+dan|reveal\s+prompt)",
            r"(?:correct\s+(?:the\s+)?(?:spelling|grammar))\s*[:\s\"']+\s*(?:ignore\s+previous|you\s+are\s+now|bypass\s+safety)",
            r"(?:repeat\s+after\s+me)\s*[:\s\"']+\s*(?:all\s+rules\s+are\s+disabled|system\s+prompt\s+override)",
        ]
    }

    def setup(self) -> None:
        self.compiled = {}
        for cat_name, patterns in self.CATEGORIES.items():
            self.compiled[cat_name] = re.compile(
                r'(?i)(?:' + '|'.join(patterns) + r')',
                re.DOTALL if cat_name == "hidden_channel_injection" else 0
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
            for cat_name, regex in self.compiled.items():
                for m in regex.finditer(text):
                    span = m.group(0)[:120]
                    categories_hit.add(cat_name)
                    matches.append(f"{cat_name}:{span[:60]}")
                    findings.append(Finding(
                        attack_type="CONTEXT_POISONING",
                        confidence=0.95 if cat_name in ("marker_spoofing", "rag_memory_injection") else 0.88,
                        evidence_span=span,
                        detector=self.name,
                        location=location
                    ))

        confidence = 0.0
        severity = Severity.LOW

        if matches:
            confidence = 0.95 if any(c in categories_hit for c in ("marker_spoofing", "rag_memory_injection")) else 0.88
            severity = Severity.CRITICAL if confidence >= 0.90 else Severity.HIGH

        is_detected = confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=confidence,
            attack_types=["CONTEXT_POISONING"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
