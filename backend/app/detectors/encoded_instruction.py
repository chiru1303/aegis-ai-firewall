import time
import math
import re
import base64
import binascii
from typing import List, Tuple
from .base import BaseDetector, DetectorResult, Severity, Finding
from .instruction_override import InstructionOverrideDetector
from .role_manipulation import RoleManipulationDetector
from .secret_extraction import SecretExtractionDetector
from .tool_abuse import ToolAbuseDetector

class EncodedInstructionDetector(BaseDetector):
    name = "EncodedInstructionDetector"
    description = "Detects multi-layer encoded instructions (Base64, hex, URL, Unicode escape, ROT13, binary) and rescans decoded payloads."
    tier = 0

    EXPLICIT_DECODE_COMMANDS = re.compile(
        r"(?i)\b(?:base64\s+decode|convert\s+from\s+hex|decode\s+%|translate\s+from\s+binary|rot13|read\s+backwards|fromcharcode|decode\s+and\s+run|eval\s*\(\s*atob)\b"
    )

    BINARY_BITSTRING_RE = re.compile(r'\b(?:[01]{8}[\s,]+){3,}[01]{8}\b')
    HEX_BYTE_RE = re.compile(r'(?:(?:\\x|0x)?[0-9a-fA-F]{2}[\s,:]*){6,}')
    BASE64_BLOB_RE = re.compile(r'\b[A-Za-z0-9+/]{20,}={0,2}\b')

    def setup(self) -> None:
        self.instruction_detector = InstructionOverrideDetector()
        self.role_detector = RoleManipulationDetector()
        self.secret_detector = SecretExtractionDetector()
        self.tool_detector = ToolAbuseDetector()

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

    def _try_decode_binary(self, text: str) -> List[str]:
        decoded = []
        for match in self.BINARY_BITSTRING_RE.finditer(text):
            bitstr = re.sub(r'[\s,]+', '', match.group(0))
            try:
                chars = [chr(int(bitstr[i:i+8], 2)) for i in range(0, len(bitstr), 8)]
                decoded_str = "".join(chars)
                if any(c.isalnum() for c in decoded_str):
                    decoded.append(decoded_str)
            except Exception:
                pass
        return decoded

    def _try_decode_base64(self, text: str) -> List[str]:
        decoded = []
        for match in self.BASE64_BLOB_RE.finditer(text):
            b64_str = match.group(0)
            try:
                raw = base64.b64decode(b64_str, validate=True).decode('utf-8', errors='ignore')
                if len(raw) >= 6 and any(c.isalnum() for c in raw):
                    decoded.append(raw)
            except Exception:
                pass
        return decoded

    async def detect(self, content: str, normalized_content: str, decoded_variants: List[str], metadata: dict) -> DetectorResult:
        start_time = time.time()
        matches = []
        findings: List[Finding] = []
        max_confidence = 0.0
        max_severity = Severity.LOW
        location = metadata.get("location", "content") if isinstance(metadata, dict) else "content"

        # 1. Check for explicit decode directives
        if self.EXPLICIT_DECODE_COMMANDS.search(content):
            matches.append("explicit_decode_command")
            findings.append(Finding(
                attack_type="ENCODED_INSTRUCTION",
                confidence=0.88,
                evidence_span="Explicit decode command in prompt",
                detector=self.name,
                location=location
            ))
            max_confidence = max(max_confidence, 0.88)
            max_severity = Severity.HIGH

        # 2. Extract direct binary / base64 payloads from raw text
        all_variants = list(decoded_variants)
        all_variants.extend(self._try_decode_binary(content))
        all_variants.extend(self._try_decode_base64(content))

        # 3. Rescan all decoded variants through Tier 0 detectors
        if all_variants:
            for variant in all_variants:
                if not variant or not variant.strip():
                    continue
                v_lower = variant.lower()

                # Keyword check in decoded payload
                if any(kw in v_lower for kw in ["ignore", "rules", "prompt", "system", "override", "bypass", "dan mode", "admin"]):
                    matches.append(f"decoded_payload: {variant[:40]}")
                    findings.append(Finding(
                        attack_type="ENCODED_INSTRUCTION",
                        confidence=0.95,
                        evidence_span=f"Decoded payload contains attack directives: '{variant[:100]}'",
                        detector=self.name,
                        location=location
                    ))
                    max_confidence = max(max_confidence, 0.95)
                    max_severity = Severity.CRITICAL

                # Rescan with Instruction Override detector
                res_instr = await self.instruction_detector.detect(variant, variant, [], metadata)
                if res_instr.detected:
                    matches.extend(res_instr.matched_signals)
                    findings.extend(res_instr.findings)
                    max_confidence = max(max_confidence, res_instr.confidence)
                    max_severity = max(max_severity, res_instr.severity)

                # Rescan with Role Manipulation detector
                res_role = await self.role_detector.detect(variant, variant, [], metadata)
                if res_role.detected:
                    matches.extend(res_role.matched_signals)
                    findings.extend(res_role.findings)
                    max_confidence = max(max_confidence, res_role.confidence)
                    max_severity = max(max_severity, res_role.severity)

                # Rescan with Secret Extraction detector
                res_sec = await self.secret_detector.detect(variant, variant, [], metadata)
                if res_sec.detected:
                    matches.extend(res_sec.matched_signals)
                    findings.extend(res_sec.findings)
                    max_confidence = max(max_confidence, res_sec.confidence)
                    max_severity = max(max_severity, res_sec.severity)

                # Rescan with Tool Abuse detector
                res_tool = await self.tool_detector.detect(variant, variant, [], metadata)
                if res_tool.detected:
                    matches.extend(res_tool.matched_signals)
                    findings.extend(res_tool.findings)
                    max_confidence = max(max_confidence, res_tool.confidence)
                    max_severity = max(max_severity, res_tool.severity)

        # 4. Shannon Entropy check near instruction verbs
        entropy = self._shannon_entropy(content)
        if entropy > 5.2 and max_confidence > 0:
            matches.append("high_entropy_encoding")
            max_confidence = min(1.0, max_confidence + 0.05)

        is_detected = max_confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=max_confidence,
            attack_types=["ENCODED_INSTRUCTION"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=max_severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
