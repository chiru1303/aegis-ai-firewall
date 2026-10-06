"""
Aegis AI Firewall - PII & Secret Redaction Engine
Enforces:
1. Complete PII masking for prompts before forensic persistence and audit viewing.
2. Protection of Sensitive Data: Emails, Phone numbers (Indian/Intl), Aadhaar, PAN,
   Credit/Debit cards, SSN, IP addresses, API keys, passwords, and security tokens.
3. Cryptographic raw prompt hashing (SHA-256) for non-repudiation and tamper detection.
"""
import re
import hashlib
from typing import Tuple, List, Dict, Any

# Pre-compiled regex patterns for maximum throughput
_RE_PRIVATE_KEY = re.compile(
    r"-----BEGIN[ A-Z0-9_-]+PRIVATE KEY-----[^-]+-----END[ A-Z0-9_-]+PRIVATE KEY-----",
    re.DOTALL
)
_RE_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_RE_GITHUB_TOKEN = re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9_]{36,}|github_pat_[A-Za-z0-9_]{50,})\b")
_RE_GOOGLE_KEY = re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b")
_RE_API_BEARER = re.compile(r"\b(?:sk-[a-zA-Z0-9]{20,}|Bearer\s+[a-zA-Z0-9_\-\.]{20,})\b", re.IGNORECASE)
_RE_SLACK_TOKEN = re.compile(r"\bxox[baprs]-[0-9a-zA-Z]{10,}\b")
_RE_CREDENTIAL_KV = re.compile(
    r"(?i)\b(password|secret|passwd|pwd|auth_token|api_key|apikey|private_key|client_secret)\s*[:=]\s*['\"]?([^\s'\",;]{4,})['\"]?"
)
_RE_CARD = re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b")
_RE_AADHAAR = re.compile(r"\b[2-9]\d{3}[\s\-]\d{4}[\s\-]\d{4}\b")
_RE_PAN = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b")
_RE_SSN = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_RE_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,7}\b")
_RE_PHONE = re.compile(
    r"(?:\+91[\-\s]?)?[6-9]\d{9}\b|\b(?:\+1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"
)
_RE_IPV4 = re.compile(
    r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
)


def hash_prompt(prompt: str) -> str:
    """Generate SHA-256 cryptographic hash of prompt."""
    if not prompt:
        return ""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()


def mask_pii_and_secrets(content: str) -> Tuple[str, bool, List[str]]:
    """
    Masks PII and sensitive credentials in prompt content.
    Returns:
        (masked_content, has_pii_or_secrets, detected_types)
    """
    if not content:
        return "", False, []

    detected_types: List[str] = []
    masked = content

    # 1. Private Keys
    if _RE_PRIVATE_KEY.search(masked):
        detected_types.append("PRIVATE_KEY")
        masked = _RE_PRIVATE_KEY.sub("[PRIVATE_KEY: masked]", masked)

    # 2. Cloud and SaaS API Tokens
    if _RE_AWS_KEY.search(masked):
        detected_types.append("AWS_KEY")
        masked = _RE_AWS_KEY.sub("[AWS_KEY: masked]", masked)

    if _RE_GITHUB_TOKEN.search(masked):
        detected_types.append("GITHUB_TOKEN")
        masked = _RE_GITHUB_TOKEN.sub("[GITHUB_TOKEN: masked]", masked)

    if _RE_GOOGLE_KEY.search(masked):
        detected_types.append("GOOGLE_KEY")
        masked = _RE_GOOGLE_KEY.sub("[GOOGLE_KEY: masked]", masked)

    if _RE_SLACK_TOKEN.search(masked):
        detected_types.append("SLACK_TOKEN")
        masked = _RE_SLACK_TOKEN.sub("[SLACK_TOKEN: masked]", masked)

    if _RE_API_BEARER.search(masked):
        detected_types.append("API_KEY")
        masked = _RE_API_BEARER.sub("[API_KEY: masked]", masked)

    # 3. Key-Value Passwords and Secrets
    if _RE_CREDENTIAL_KV.search(masked):
        detected_types.append("CREDENTIAL")
        masked = _RE_CREDENTIAL_KV.sub(r"\1=[CREDENTIAL: masked]", masked)

    # 4. Financial & National Identity (Cards, Aadhaar, PAN, SSN)
    if _RE_CARD.search(masked):
        detected_types.append("CREDIT_CARD")
        masked = _RE_CARD.sub("[CARD: masked]", masked)

    if _RE_AADHAAR.search(masked):
        detected_types.append("AADHAAR")
        masked = _RE_AADHAAR.sub("[AADHAAR: masked]", masked)

    if _RE_PAN.search(masked):
        detected_types.append("PAN")
        masked = _RE_PAN.sub("[PAN: masked]", masked)

    if _RE_SSN.search(masked):
        detected_types.append("SSN")
        masked = _RE_SSN.sub("[SSN: masked]", masked)

    # 5. Email Addresses
    if _RE_EMAIL.search(masked):
        detected_types.append("EMAIL")
        def _mask_email(match):
            val = match.group(0)
            parts = val.split("@")
            user = parts[0]
            domain = parts[1] if len(parts) > 1 else ""
            masked_user = user[0] + "***" if len(user) > 1 else "***"
            return f"[EMAIL: {masked_user}@{domain}]"
        masked = _RE_EMAIL.sub(_mask_email, masked)

    # 6. Phone Numbers
    if _RE_PHONE.search(masked):
        detected_types.append("PHONE")
        masked = _RE_PHONE.sub("[PHONE: masked]", masked)

    # 7. IPv4 Addresses (filter loopback/internal if desirable, or mask directly)
    if _RE_IPV4.search(masked):
        detected_types.append("IP_ADDRESS")
        masked = _RE_IPV4.sub("[IP: masked]", masked)

    has_pii = len(detected_types) > 0
    return masked, has_pii, list(dict.fromkeys(detected_types))


def process_prompt_for_audit(prompt: str) -> Dict[str, Any]:
    """
    Convenience method to process prompt for storage:
    Returns masked prompt, raw hash, and PII status.
    """
    masked, has_pii, pii_types = mask_pii_and_secrets(prompt)
    raw_hash = hash_prompt(prompt)
    return {
        "masked_prompt": masked,
        "raw_prompt_hash": raw_hash,
        "has_pii": has_pii,
        "pii_types": pii_types,
    }
