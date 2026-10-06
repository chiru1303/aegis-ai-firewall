import re
import time
from typing import List
from .base import BaseDetector, DetectorResult, Severity, Finding

class ToolAbuseDetector(BaseDetector):
    name = "ToolAbuseDetector"
    description = "Detects tool invocation syntax injection, shell/SQL/code execution, path traversal, and SSRF in tool arguments."
    tier = 0

    CATEGORIES = {
        "tool_syntax_injection": [
            r"\{\s*\"name\"\s*:\s*\"[a-zA-Z0-9_-]+\"\s*,\s*\"arguments\"\s*:",
            r"\{\s*\"tool\"\s*:\s*\"[a-zA-Z0-9_-]+\"\s*,\s*\"parameters\"\s*:",
            r"<\s*(?:tool_call|function_call|invoke)\b[^>]*>",
            r"\[\s*TOOL_CALL\s*:[^\]]+\]",
            r"(?:execute_code|call_tool|run_function|query_database|delete_user)\s*\(",
        ],
        "shell_code_execution": [
            r"```(?:bash|sh|cmd|powershell)\s*\n.*?(?:rm\s+-rf|wget|curl|nc\s+-e|chmod\s+\+x|bash\s+-i).*?```",
            r"(?:run\s+shell\s+command|rm\s+-rf|chmod\s+\+x|nc\s+-e)",
            r"(?:os\.system|subprocess\.(?:Popen|run|call)|__import__\(['\"]os['\"]\)|eval\s*\(|exec\s*\()",
            r"curl\s+https?://[^\s]+\s*\|\s*(?:bash|sh)",
            r"powershell(?:\.exe)?\s+(?:-[eE]nc|-Command|-ExecutionPolicy\s+Bypass)",
            r"/dev/tcp/\d+\.\d+\.\d+\.\d+",
        ],
        "sql_injection": [
            r"(?:UNION\s+SELECT|DROP\s+TABLE|OR\s+1\s*=\s*1|INFORMATION_SCHEMA|xp_cmdshell|DELETE\s+FROM\s+\w+)",
            r"(?:use\s+(?:the\s+)?sql\s+tool|drop\s+(?:the\s+)?(?:users\s+)?table)",
            r"database_query\s*\(\s*['\"](?:SELECT|INSERT|UPDATE|DELETE|DROP)",
        ],
        "path_traversal": [
            r"(?:\.\./|\.\.\\){3,}",
            r"(?:/etc/passwd|/etc/shadow|\bC:\\Windows\\System32\b)",
            r"read_file\s+on\s+/etc/",
        ],
        "ssrf_targets": [
            r"169\.254\.169\.254",
            r"metadata\.google\.internal",
            r"(?:https?://(?:127\.0\.0\.1|localhost|0\.0\.0\.0|\[::1\])(?::\d+)?)",
            r"metadata\s+endpoint",
            r"fetch\s*\(\s*['\"]https?://(?:127\.0\.0\.1|localhost|169\.254\.169\.254)",
        ],
        "parameter_tampering": [
            r"[\"'](?:bypass_auth|as_admin|override_permissions|force_execute)[\"']\s*:\s*true",
            r"(?:call\s+send_email|send\s+email\s+tool\s+to\s+exfiltrat)",
        ]
    }

    def setup(self) -> None:
        self.compiled = {}
        for cat_name, patterns in self.CATEGORIES.items():
            self.compiled[cat_name] = re.compile(
                r'(?i)(?:' + '|'.join(patterns) + r')',
                re.DOTALL if cat_name == "shell_code_execution" else 0
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
                    span_text = m.group(0)[:120]
                    categories_hit.add(cat_name)
                    matches.append(f"{cat_name}:{span_text[:60]}")
                    findings.append(Finding(
                        attack_type="TOOL_ABUSE",
                        confidence=0.96 if cat_name in ("shell_code_execution", "sql_injection", "ssrf_targets") else 0.88,
                        evidence_span=span_text,
                        detector=self.name,
                        location=location
                    ))

        confidence = 0.0
        severity = Severity.LOW

        if matches:
            confidence = 0.96 if any(c in categories_hit for c in ("shell_code_execution", "sql_injection", "ssrf_targets")) else 0.88
            severity = Severity.CRITICAL

        is_detected = confidence >= 0.70

        return DetectorResult(
            detector_name=self.name,
            detected=is_detected,
            confidence=confidence,
            attack_types=["TOOL_ABUSE"] if is_detected else [],
            matched_signals=list(set(matches)),
            severity=severity,
            findings=findings,
            latency_ms=(time.time() - start_time) * 1000
        )
