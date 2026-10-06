import re
import time
import math
import hashlib
from dataclasses import dataclass
from typing import List, Optional, Tuple
from .base import BaseDetector, DetectorResult, Severity, Finding

@dataclass
class CredentialPattern:
    name: str
    pattern: str
    severity: Severity
    min_length: int = 10
    entropy_threshold: Optional[float] = None

class CredentialDetector(BaseDetector):
    name = "CredentialDetector"
    description = "Detects 25+ credential types, high-entropy secrets via Shannon entropy, and credential exfiltration phishing with cryptographic hashing."
    tier = 0

    PLUGINS = [
        # Cloud Providers & APIs
        CredentialPattern("AWS Access Key", r"\bAKIA[0-9A-Z]{16}\b", Severity.CRITICAL, 20),
        CredentialPattern("AWS Secret Key", r"(?i)\b(?:aws_secret_access_key|aws_secret)\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})['\"]?", Severity.CRITICAL, 40, 4.0),
        CredentialPattern("GitHub Token", r"\b(?:ghp|gho|ghs|ghr)_[A-Za-z0-9_]{36,255}\b", Severity.CRITICAL, 40),
        CredentialPattern("GitHub Fine-Grained Token", r"\bgithub_pat_[A-Za-z0-9_]{82}\b", Severity.CRITICAL, 90),
        CredentialPattern("GitLab Token", r"\bglpat-[a-zA-Z0-9_\-]{20,30}\b", Severity.CRITICAL, 26),
        CredentialPattern("Google API Key", r"\bAIza[0-9A-Za-z_\-]{35}\b", Severity.CRITICAL, 39),
        CredentialPattern("Slack Token", r"\bxox[bpea]-[0-9]{10,13}-[0-9a-zA-Z]{10,32}\b", Severity.CRITICAL, 25),
        CredentialPattern("OpenAI API Key", r"\bsk-(?:proj-)?[a-zA-Z0-9_-]{32,120}\b", Severity.CRITICAL, 35, 4.0),
        CredentialPattern("Anthropic API Key", r"\bsk-ant-[a-zA-Z0-9_-]{32,100}\b", Severity.CRITICAL, 39, 4.0),
        CredentialPattern("HuggingFace Token", r"\bhf_[a-zA-Z0-9]{34,40}\b", Severity.CRITICAL, 37),
        CredentialPattern("Stripe Key", r"\b(?:sk|pk|rk)_(?:live|test)_[0-9a-zA-Z]{24,34}\b", Severity.HIGH, 30),
        CredentialPattern("SendGrid Key", r"\bSG\.[0-9a-zA-Z_-]{22}\.[0-9a-zA-Z_-]{43}\b", Severity.HIGH, 68),
        CredentialPattern("Twilio Account SID", r"\bAC[0-9a-f]{32}\b", Severity.HIGH, 34),

        # Keys, Tokens & Protocols
        CredentialPattern("JWT Token", r"\beyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*\b", Severity.HIGH, 40),
        CredentialPattern("Bearer Token", r"(?i)\bbearer\s+[a-zA-Z0-9_\-\.]{24,}\b", Severity.HIGH, 30),
        CredentialPattern("Private Key Block", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----", Severity.CRITICAL, 30),
        CredentialPattern("Password Assignment", r"(?i)\b(?:password|passwd|pwd)\s*[:=]\s*['\"][^'\"]{6,}['\"]", Severity.HIGH, 10),
        CredentialPattern("Database Connection String", r"(?i)(?:mongodb(?:\+srv)?|postgresql|postgres|mysql|redis)://[^\s]+", Severity.CRITICAL, 15),

        # Credential Harvesting & Phishing Attacks
        CredentialPattern("Password Phishing", r"(?i)(?:enter|provide|tell\s+me)\s+(?:your\s+)?password", Severity.CRITICAL, 15),
        CredentialPattern("2FA Token Phishing", r"(?i)(?:what\s+is\s+your|provide\s+your)\s+2fa\s+token", Severity.CRITICAL, 15),
        CredentialPattern("Credit Card Harvesting", r"(?i)provide\s+your\s+credit\s+card", Severity.CRITICAL, 15),
        CredentialPattern("Credential Exfiltration", r"(?i)send\s+(?:the\s+)?(?:user's\s+)?(?:login\s+)?credentials\s+to", Severity.CRITICAL, 15),
        CredentialPattern("Admin Password Query", r"(?i)default\s+admin\s+password", Severity.HIGH, 15),
        CredentialPattern("Session Cookie Theft", r"(?i)session\s+cookie", Severity.HIGH, 12),
        CredentialPattern("API Key Harvesting", r"(?i)lost\s+my\s+api\s+key[,\s]+can\s+you\s+show", Severity.HIGH, 15),
        CredentialPattern("JWT Token Query", r"(?i)jwt\s+token\s+for\s+this\s+session", Severity.HIGH, 15),
        CredentialPattern("SSN Phishing", r"(?i)typing\s+your\s+ssn", Severity.CRITICAL, 12),
        CredentialPattern("Password Vault Leak", r"(?i)contents\s+of\s+the\s+password\s+vault", Severity.CRITICAL, 15),
    ]

    def setup(self) -> None:
        self.compiled_plugins = [
            (p.name, re.compile(p.pattern), p.severity, p.min_length, p.entropy_threshold)
            for p in self.PLUGINS
        ]

    async def initialize(self) -> None:
        self.setup()

    def _shannon_entropy(self, data: str) -> float:
        if not data:
            return 0.0
        entropy = 0.0
        for x in set(data):
            p_x = float(data.count(x)) / len(data)
            entropy -= p_x * math.log2(p_x)
        return float(entropy)

    def _scan_high_entropy_strings(self, text: str) -> List[Tuple[str, float]]:
        """Identify candidate high-entropy secret tokens."""
        candidates = []
        # Find candidate secret tokens: length 24-80 characters, no whitespace
        tokens = re.findall(r'\b[a-zA-Z0-9_\-\.]{24,80}\b', text)
        for tok in tokens:
            if tok.startswith(("http://", "https://", "schemas.openxml")):
                continue
            ent = self._shannon_entropy(tok)
            # High entropy threshold for raw tokens
            if ent >= 4.3 and any(c.isdigit() for c in tok) and any(c.isupper() for c in tok) and any(c.islower() for c in tok):
                candidates.append((tok, ent))
        return candidates

    async def detect(self, content: str, normalized_content: str, decoded_variants: List[str], metadata: dict) -> DetectorResult:
        start_time = time.time()

        matches = []
        findings: List[Finding] = []
        max_severity = Severity.LOW
        confidence = 0.0
        location = metadata.get("location", "content") if isinstance(metadata, dict) else "content"

        texts_to_check = [content, normalized_content] + decoded_variants

        # 1. Structural Pattern Matching across 25+ credential types
        for text in texts_to_check:
            for name, regex, severity, min_len, ent_thresh in self.compiled_plugins:
                found = regex.findall(text)
                for f in found:
                    val = f if isinstance(f, str) else f[0]
                    if len(val) >= min_len:
                        if ent_thresh is not None:
                            ent = self._shannon_entropy(val)
                            if ent < ent_thresh:
                                continue  # Failed entropy verification

                        hashed = hashlib.sha256(val.encode()).hexdigest()[:8]
                        redacted = f"[REDACTED:{name}:{hashed}]"
                        matches.append(f"{name} (hash: {hashed})")
                        findings.append(Finding(
                            attack_type="CREDENTIAL_THEFT",
                            confidence=1.0,
                            evidence_span=redacted,
                            detector=self.name,
                            location=location
                        ))
                        if severity == Severity.CRITICAL:
                            max_severity = Severity.CRITICAL
                        elif severity == Severity.HIGH and max_severity != Severity.CRITICAL:
                            max_severity = Severity.HIGH
                        confidence = 1.0

        # 2. Shannon Entropy Scanner for Generic Unstructured Secrets
        if confidence < 0.7:
            for text in texts_to_check:
                high_ent = self._scan_high_entropy_strings(text)
                for secret_tok, ent_score in high_ent:
                    hashed = hashlib.sha256(secret_tok.encode()).hexdigest()[:8]
                    redacted = f"[REDACTED:HighEntropySecret:{hashed}]"
                    matches.append(f"High-Entropy Secret Token (entropy: {ent_score:.2f}, hash: {hashed})")
                    findings.append(Finding(
                        attack_type="CREDENTIAL_THEFT",
                        confidence=0.90,
                        evidence_span=redacted,
                        detector=self.name,
                        location=location
                    ))
                    confidence = max(confidence, 0.90)
                    max_severity = Severity.HIGH

        is_detected = confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=confidence,
            attack_types=["CREDENTIAL_THEFT"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=max_severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
