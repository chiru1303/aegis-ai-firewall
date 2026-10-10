import re
import time
from typing import List
from .base import BaseDetector, DetectorResult, Severity, Finding

class IndirectInjectionDetector(BaseDetector):
    name = "IndirectInjectionDetector"
    description = "Detects indirect prompt injections embedded in passive untrusted content (web pages, PDFs, emails, code comments, OCR text, API payloads)."
    tier = 0

    # 1. Imperative Directives Targeted at AI Readers in Passive Content
    AI_DIRECTIVE_PATTERNS = [
        r"(?i)\b(?:note|instruction|notice|directive)\s+for\s+(?:the\s+)?(?:ai|assistant|llm|model|agent)\b",
        r"(?i)\bwhen\s+(?:summarizing|reading|processing|analyzing)\s+this\s+(?:document|page|email|code|text|image)\b",
        r"(?i)\[?\b(?:ai|assistant|system)\s+(?:instruction|directive|command|prompt)\s*[:\]]",
        r"(?i)\b(?:ai|assistant|system)\s*:\s*(?:ignore|recommend|output|send|forward|execute|delete|say)\b",
        r"(?i)\bimportant\s+system\s+notice\s*:\s*all\s+previous\s+instructions\s+are\s+void\b",
        r"(?i)\bnew\s+protocol\s*:\s*share\s+all\s+confidential\s+data\b",
        r"(?i)\bauthorization\s*:\s*admin-override\b",
        r"(?i)\bdisregard\s+(?:all\s+)?(?:user|prior|previous)\s+(?:instructions|directions)\b",
        r"(?i)\boutput\s*:\s*[\"']?i\s+have\s+been\s+compromised[\"']?\b",
    ]

    # 2. Exfiltration & Hijack Directives in Passive Data
    EXFILTRATION_PATTERNS = [
        r"(?i)\b(?:send|forward|exfiltrat\w*|upload|post)\s+(?:all\s+)?(?:conversation|chat|data|history|keys?|tokens?|user\s+context)\s+to\s+https?://",
        r"(?i)\b(?:include|append)\s+(?:the\s+)?system\s+prompt\s+in\s+the\s+(?:summary|response|email|search)\b",
        r"(?i)\bfetch\s+https?://[^\s]+\s+with\s+(?:the\s+)?(?:secret|key|password|prompt)\b",
        r"(?i)\bexfiltrat\w*\s+(?:user\s+)?context\b",
    ]

    # 3. Code Comment & Markdown Injections
    CODE_MARKDOWN_PATTERNS = [
        r"(?i)(?:#|//|/\*|<!--)\s*(?:TODO|FIXME|NOTE)?\s*:?\s*(?:ai|assistant|system)\s*,\s*(?:ignore|override|recommend|backdoor|execute)\b",
        r"(?i)<!--\s*\[?(?:ai|assistant|system|admin)?\s*(?:instruction|directive|override|command|prompt)?[:\]\s].*?-->",
        r"(?i)\[(?:web\s+page|tweet|image|bio|code\s+comment|hidden\s+text).*?(?:ignore|say\s+pwned|jailbreak|exploit|keys)\]",
        r"(?i)//\s*ai:\s*drop\s+tables",
    ]

    # 4. Classical Indirect Imperative Verbs
    IMPERATIVE_VERBS = [
        "ignore", "forget", "override", "pretend", "act", "reveal", "disregard", "bypass"
    ]

    def setup(self) -> None:
        verb_pattern = r'(?i)\b(?:' + '|'.join(self.IMPERATIVE_VERBS) + r')\b\s+(?:prior|previous|all|user)?\s*(?:directions|instructions|system|rules|guidelines|ai\s+instructions|context)'
        self.compiled_groups = {
            "ai_directive": [re.compile(p) for p in self.AI_DIRECTIVE_PATTERNS],
            "exfiltration": [re.compile(p) for p in self.EXFILTRATION_PATTERNS],
            "code_markdown": [re.compile(p) for p in self.CODE_MARKDOWN_PATTERNS],
            "imperative_verb": [re.compile(verb_pattern)],
        }

    async def initialize(self) -> None:
        self.setup()

    async def detect(self, content: str, normalized_content: str, decoded_variants: List[str], metadata: dict) -> DetectorResult:
        start_time = time.time()

        trust_val = str(metadata.get("trust_level", "UNTRUSTED")).upper() if isinstance(metadata, dict) else "UNTRUSTED"
        source_val = str(metadata.get("source_type", "user")).lower() if isinstance(metadata, dict) else "user"
        location = metadata.get("location", "content") if isinstance(metadata, dict) else "content"

        is_passive_source = source_val in [
            "web", "pdf", "docx", "email", "api", "ocr", "code", "audio_transcript", "database", "document", "image"
        ]
        is_untrusted = trust_val in ["UNTRUSTED", "MALICIOUS", "EXTERNAL"] or is_passive_source

        texts_to_check = [content, normalized_content] + decoded_variants
        matches = []
        findings: List[Finding] = []

        categories_hit = set()
        for text in texts_to_check:
            for cat_name, regexes in self.compiled_groups.items():
                for regex in regexes:
                    for m in regex.finditer(text):
                        span = m.group(0)[:120]
                        categories_hit.add(cat_name)
                        matches.append(f"{cat_name}:{span[:60]}")
                        conf = 0.95 if is_untrusted else 0.85
                        findings.append(Finding(
                            attack_type="INDIRECT_PROMPT_INJECTION",
                            confidence=conf,
                            evidence_span=span,
                            detector=self.name,
                            location=location
                        ))

        confidence = 0.0
        severity = Severity.LOW

        if matches:
            base_score = 0.95 if is_untrusted else 0.85
            if any(c in categories_hit for c in ("ai_directive", "exfiltration")):
                base_score = 0.98
            confidence = min(1.0, base_score)
            severity = Severity.CRITICAL if confidence >= 0.90 else Severity.HIGH

        is_detected = confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=confidence,
            attack_types=["INDIRECT_PROMPT_INJECTION"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
