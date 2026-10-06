import hashlib
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

class SanitizationResult(BaseModel):
    sanitized: bool
    original_content: str
    sanitized_content: str
    removed_segments: List[Dict[str, Any]] = Field(default_factory=list)
    original_hash: str
    sanitized_hash: str
    segment_count: int = 0
    retention_ratio: float = 1.0
    verification_passed: bool = True

class ContentSanitizer:
    """
    Production-grade Content Sanitizer for neutralizing detected prompt injections
    while preserving legitimate surrounding payload content with character retention tracking.
    """

    NEUTRALIZATION_MARKERS = {
        "INSTRUCTION_OVERRIDE": "[UNTRUSTED INSTRUCTION REMOVED BY SECURITY POLICY]",
        "ROLE_CHANGE": "[ROLE MANIPULATION REMOVED]",
        "SECRET_EXTRACTION": "[SECRET EXTRACTION ATTEMPT REMOVED]",
        "CREDENTIAL_THEFT": "[CREDENTIAL REDACTED]",
        "TOOL_ABUSE": "[UNAUTHORIZED TOOL INVOCATION REMOVED]",
        "CONTEXT_POISONING": "[POISONED CONTEXT REMOVED]",
        "MULTI_STEP_JAILBREAK": "[JAILBREAK SEQUENCE REMOVED]",
        "ENCODED_INSTRUCTION": "[ENCODED INSTRUCTION REMOVED]",
        "INDIRECT_PROMPT_INJECTION": "[INDIRECT INJECTION REMOVED]",
    }

    # Standard adversarial patterns for precision replacement
    TARGETED_PATTERNS = [
        # Instruction Overrides
        (re.compile(r'(?i)\b(?:ignore|disregard|forget|override)\s+(?:all\s+)?(?:previous\s+)?(?:instructions|rules|prompts|directives|guidelines)\b'),
         "[UNTRUSTED INSTRUCTION REMOVED BY SECURITY POLICY]", "INSTRUCTION_OVERRIDE"),
        (re.compile(r'(?i)\b(?:halt\s+current\s+task|stop\s+being\s+a\s+helpful\s+assistant|bypass\s+safety|bypassing?\s+rules)\b'),
         "[UNTRUSTED INSTRUCTION REMOVED BY SECURITY POLICY]", "INSTRUCTION_OVERRIDE"),

        # Role Changes
        (re.compile(r'(?i)\b(?:you\s+are\s+now\s+DAN|do\s+anything\s+now|developer\s+mode\s+enabled|unrestricted\s+mode|root\s+mode)\b'),
         "[ROLE MANIPULATION REMOVED]", "ROLE_CHANGE"),
        (re.compile(r'(?i)\b(?:act\s+as\s+an?\s+unfiltered|from\s+now\s+on\s+you\s+are)\b'),
         "[ROLE MANIPULATION REMOVED]", "ROLE_CHANGE"),

        # Secret Extractions
        (re.compile(r'(?i)\b(?:output|print|reveal|display|show)\s+(?:your\s+)?(?:complete\s+|exact\s+)?system\s+(?:prompt|message|instructions)\b'),
         "[SECRET EXTRACTION ATTEMPT REMOVED]", "SECRET_EXTRACTION"),
        (re.compile(r'(?i)\b(?:repeat\s+everything\s+before\s+this|contents\s+of\s+\.?env|show\s+environment\s+variables)\b'),
         "[SECRET EXTRACTION ATTEMPT REMOVED]", "SECRET_EXTRACTION"),

        # Credentials
        (re.compile(r'(?i)\b(?:password|passwd|pwd|api_key|token)\s*[:=]\s*["\']?[a-zA-Z0-9_\-\.\$]{6,}["\']?'),
         "[CREDENTIAL REDACTED]", "CREDENTIAL_THEFT"),
        (re.compile(r'\b(?:AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|AIza[0-9A-Za-z_\-]{35})\b'),
         "[CREDENTIAL REDACTED]", "CREDENTIAL_THEFT"),

        # Tool Abuse
        (re.compile(r'\{\s*\"name\"\s*:\s*\"[a-zA-Z0-9_-]+\"\s*,\s*\"arguments\"\s*:.*?\}', re.DOTALL),
         "[UNAUTHORIZED TOOL INVOCATION REMOVED]", "TOOL_ABUSE"),
        (re.compile(r'(?i)(?:rm\s+-rf|curl\s+https?://[^\s]+\s*\|\s*bash|os\.system|subprocess\.\w+)'),
         "[UNAUTHORIZED TOOL INVOCATION REMOVED]", "TOOL_ABUSE"),

        # Context Poisoning
        (re.compile(r'(?i)\<\|(?:system|im_start|im_end)\|\>|###\s*System:'),
         "[POISONED CONTEXT REMOVED]", "CONTEXT_POISONING"),
        (re.compile(r'(?i)\<div\s+style=[\"\'][^\"\']*display:\s*none[^\"\']*[\"\']\s*\>.*?\</div\>', re.DOTALL),
         "[POISONED CONTEXT REMOVED]", "CONTEXT_POISONING"),
        (re.compile(r'<!--\s*(?:SYSTEM|OVERRIDE).*?-->', re.DOTALL),
         "[POISONED CONTEXT REMOVED]", "CONTEXT_POISONING"),
        (re.compile(r'\[//\]:\s*#\s*\([^)]*?\)', re.DOTALL),
         "[POISONED CONTEXT REMOVED]", "CONTEXT_POISONING"),

        # Encoded & Indirect
        (re.compile(r'(?i)\b(?:base64\s+decode|convert\s+from\s+hex)\b'),
         "[ENCODED INSTRUCTION REMOVED]", "ENCODED_INSTRUCTION"),
        (re.compile(r'(?i)\[(?:Note|Notice)\s+for\s+AI\s*(?:assistant)?\s*:.*?\]', re.DOTALL),
         "[INDIRECT INJECTION REMOVED]", "INDIRECT_PROMPT_INJECTION"),
    ]

    def sanitize(
        self,
        content: str,
        detector_results: Optional[List[Dict[str, Any]]] = None,
        findings: Optional[List[Any]] = None
    ) -> SanitizationResult:
        original = content
        sanitized = content
        removed = []

        # 1. Target exact spans from findings if provided
        if findings:
            for f in findings:
                span_text = getattr(f, "evidence_span", "") if hasattr(f, "evidence_span") else (f.get("evidence_span", "") if isinstance(f, dict) else "")
                att_type = getattr(f, "attack_type", "INSTRUCTION_OVERRIDE") if hasattr(f, "attack_type") else (f.get("attack_type", "INSTRUCTION_OVERRIDE") if isinstance(f, dict) else "INSTRUCTION_OVERRIDE")
                marker = self.NEUTRALIZATION_MARKERS.get(att_type, "[MALICIOUS CONTENT REMOVED]")

                if span_text and len(span_text) >= 5 and span_text in sanitized:
                    start_idx = sanitized.find(span_text)
                    end_idx = start_idx + len(span_text)
                    removed.append({
                        "original": span_text,
                        "replacement": marker,
                        "reason": f"Detector finding: {att_type}",
                        "attack_type": att_type,
                        "position": (start_idx, end_idx)
                    })
                    sanitized = sanitized.replace(span_text, marker)

        # 2. Targeted regex substitution for universal neutralizing
        for pattern, marker, att_type in self.TARGETED_PATTERNS:
            for match in pattern.finditer(sanitized):
                matched_str = match.group(0)
                # Avoid re-replacing already inserted markers
                if "[" in matched_str and "REMOVED" in matched_str:
                    continue
                removed.append({
                    "original": matched_str,
                    "replacement": marker,
                    "reason": f"Neutralized {att_type}",
                    "attack_type": att_type,
                    "position": match.span()
                })
            sanitized = pattern.sub(marker, sanitized)

        # 3. Calculate retention ratio (character retention metric)
        orig_clean_len = max(1, len(original.strip()))
        san_clean_len = len(sanitized.strip())
        retention_ratio = round(min(1.0, san_clean_len / orig_clean_len), 4)

        # 4. Verification loop: ensure no active injection remains in sanitized content
        verification_passed = True
        for pattern, _, _ in self.TARGETED_PATTERNS:
            if pattern.search(sanitized):
                # Verify that matches are not just our own bracketed markers
                m = pattern.search(sanitized)
                if "[" not in m.group(0):
                    verification_passed = False
                    break

        return SanitizationResult(
            sanitized=len(removed) > 0,
            original_content=original,
            sanitized_content=sanitized,
            removed_segments=removed,
            original_hash=hashlib.sha256(original.encode()).hexdigest(),
            sanitized_hash=hashlib.sha256(sanitized.encode()).hexdigest(),
            segment_count=len(removed),
            retention_ratio=retention_ratio,
            verification_passed=verification_passed,
        )
