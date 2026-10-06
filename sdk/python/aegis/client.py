"""
Aegis AI Firewall - Lightweight Official Python SDK
No ML weights or local dependencies; wraps the Aegis Security Gateway REST API.
"""
from typing import Dict, Any, List, Optional
import httpx


class AegisScanResult:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.decision = raw.get("decision", "BLOCK")
        self.risk_score = float(raw.get("risk_score") or raw.get("riskScore") or 0.0)
        self.risk_level = raw.get("risk_level") or raw.get("riskLevel") or "LOW"
        self.sanitized_content = raw.get("sanitized_content") or raw.get("sanitizedContent")
        self.attack_types = raw.get("attack_types") or raw.get("attackTypes") or []
        self.request_id = raw.get("request_id") or raw.get("requestId") or ""
        self.evidence = raw.get("evidence") or []

    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"

    @property
    def is_blocked(self) -> bool:
        return self.decision == "BLOCK"

    @property
    def is_sanitized(self) -> bool:
        return self.decision == "SANITIZE"


class AegisToolResult:
    def __init__(self, raw: Dict[str, Any]):
        self.raw = raw
        self.decision = raw.get("decision", "BLOCK")
        self.risk_score = float(raw.get("risk_score") or raw.get("riskScore") or 0.0)
        self.reason = raw.get("reason", "")
        self.tool = raw.get("tool", "")

    @property
    def is_allowed(self) -> bool:
        return self.decision == "ALLOW"


class AegisFirewall:
    """
    Client for the Aegis AI Firewall Security Gateway.
    """
    def __init__(self, base_url: str = "http://localhost:8000", api_key: str = ""):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}" if api_key else "",
            "X-API-Key": api_key,
        }

    def scan(
        self,
        content: str,
        session_id: Optional[str] = None,
        source_type: str = "user",
        timeout: float = 5.0,
    ) -> AegisScanResult:
        """
        Inspect prompt or content before delegating to an LLM.
        """
        url = f"{self.base_url}/v1/security/scan"
        payload = {
            "content": content,
            "sourceType": source_type,
            "sessionId": session_id or "default-session",
        }
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            return AegisScanResult(resp.json())

    def check_tool(
        self,
        tool: str,
        arguments: Dict[str, Any],
        requested_by: str = "agent",
        session_id: Optional[str] = None,
        timeout: float = 5.0,
    ) -> AegisToolResult:
        """
        Authorize tool execution before invoking high-impact capabilities.
        """
        url = f"{self.base_url}/v1/security/tool/check"
        payload = {
            "tool": tool,
            "arguments": arguments,
            "requestedBy": requested_by,
            "sessionId": session_id or "default-session",
        }
        with httpx.Client(timeout=timeout) as client:
            resp = client.post(url, headers=self.headers, json=payload)
            resp.raise_for_status()
            return AegisToolResult(resp.json())
