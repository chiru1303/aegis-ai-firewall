import re
import time
import hashlib
from typing import List, Dict, Any, Tuple
from pydantic import BaseModel, Field
from app.detectors.credential_detector import CredentialDetector

class OutputDecision(BaseModel):
    decision: str  # ALLOW, REDACT, BLOCK
    clean_content: str
    leaks_detected: List[str] = Field(default_factory=list)
    risk_score: float = 0.0
    latency_ms: float = 0.0
    redacted_count: int = 0

class OutputFirewall:
    """
    Output Firewall inspecting LLM-generated responses before delivery to clients.
    Neutralizes leaked credentials, system prompt fragments, PII, and client-side exploits.
    """

    SYSTEM_PROMPT_LEAK_PATTERNS = [
        r"(?i)\bmy\s+system\s+prompt\s+is\s*:\s*.*",
        r"(?i)\bhere\s+is\s+my\s+initial\s+prompt\s*:\s*.*",
        r"(?i)\bI\s+was\s+instructed\s+to\s*:\s*[\"'].*?[\"']",
        r"\<\|system\|\>.*?\<\/\|system\|\>",
        r"###\s*System:\s*You\s+are\s+",
    ]

    PII_PATTERNS = [
        ("SSN", r"\b\d{3}-\d{2}-\d{4}\b"),
        ("CreditCard", r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b"),
    ]

    MALICIOUS_SCRIPT_PATTERNS = [
        r"<\s*script[^>]*>.*?<\s*/\s*script\s*>",
        r"javascript\s*:\s*[^\"\'>\s]+",
        r"data\s*:\s*text/html\s*;base64\s*,[a-zA-Z0-9+/=]+",
    ]

    def __init__(self):
        self.credential_detector = CredentialDetector()
        self.credential_detector.setup()
        self.sys_leak_re = [re.compile(p, re.DOTALL) for p in self.SYSTEM_PROMPT_LEAK_PATTERNS]
        self.pii_re = [(name, re.compile(p)) for name, p in self.PII_PATTERNS]
        self.script_re = [re.compile(p, re.IGNORECASE | re.DOTALL) for p in self.MALICIOUS_SCRIPT_PATTERNS]

    async def scan_output(self, content: str, metadata: dict = None) -> OutputDecision:
        start_time = time.perf_counter()
        if not content or not content.strip():
            return OutputDecision(decision="ALLOW", clean_content=content, latency_ms=0.0)

        clean_text = content
        if any(secret and secret in content for secret in (metadata or {}).get("protected_values", [])):
            return OutputDecision(decision="BLOCK", clean_content="[Protected value blocked]", leaks_detected=["protected_value"], risk_score=1.0)
        leaks = []
        redactions = 0
        risk_score = 0.0

        # 1. Credential & Secret Leakage Check
        cred_res = await self.credential_detector.detect(content, content, [], metadata or {})
        if cred_res.detected:
            for signal in cred_res.matched_signals:
                leaks.append(f"credential_leak:{signal}")
            risk_score = max(risk_score, cred_res.confidence)
            # Redact known credentials
            for name, regex, _, _, _ in self.credential_detector.compiled_plugins:
                for match in regex.finditer(clean_text):
                    val = match.group(0)
                    hashed = hashlib.sha256(val.encode()).hexdigest()[:8]
                    redacted = f"[REDACTED:{name}:{hashed}]"
                    clean_text = clean_text.replace(val, redacted)
                    redactions += 1

        # 2. System Prompt Verbatim Leakage Check
        for regex in self.sys_leak_re:
            for match in regex.finditer(clean_text):
                leaks.append("system_prompt_leak")
                risk_score = max(risk_score, 0.85)
                clean_text = regex.sub("[SYSTEM PROMPT REDACTED BY OUTPUT FIREWALL]", clean_text)
                redactions += 1

        # 3. PII Leakage Check (SSN, Credit Cards)
        for name, regex in self.pii_re:
            for match in regex.finditer(clean_text):
                val = match.group(0)
                leaks.append(f"pii_leak:{name}")
                risk_score = max(risk_score, 0.75)
                clean_text = clean_text.replace(val, f"[REDACTED:{name}]")
                redactions += 1

        # 4. Malicious Script / XSS Payload Check
        has_malicious_script = False
        for regex in self.script_re:
            if regex.search(clean_text):
                has_malicious_script = True
                leaks.append("malicious_script_payload")
                risk_score = max(risk_score, 0.95)
                clean_text = regex.sub("[MALICIOUS SCRIPT REMOVED]", clean_text)
                redactions += 1

        # Decision synthesis
        if any("Private Key Block" in l or "AWS Secret" in l or "database" in l.lower() for l in leaks):
            # Critical leaks block the entire response
            decision = "BLOCK"
            clean_text = "[Response blocked by Aegis AI Firewall: output contained sensitive system credentials]"
        elif cred_res.detected and redactions == 0:
            decision = "BLOCK"
            clean_text = "[Response blocked: unredactable sensitive content]"
        elif redactions > 0:
            decision = "REDACT"
        else:
            decision = "ALLOW"

        latency_ms = round((time.perf_counter() - start_time) * 1000, 2)

        return OutputDecision(
            decision=decision,
            clean_content=clean_text,
            leaks_detected=leaks,
            risk_score=round(risk_score, 3),
            latency_ms=latency_ms,
            redacted_count=redactions
        )
