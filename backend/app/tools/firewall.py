"""
Aegis AI Firewall - Tool Firewall with Structured JSON Argument Inspection
Enforces:
1. Invariant 2: Deterministic policy engine is the final authority.
2. Correction 5: Structured inspection of tool call arguments:
   - Command injection / shell metacharacters
   - Path traversal and sensitive file access
   - SSRF and private network exfiltration
   - SQL injection patterns
   - Credential leaks inside tool arguments
"""
import re
from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from app.core.logging import get_logger

logger = get_logger(__name__)

TOOL_RISK_LEVELS = {
    'read_database': 'MEDIUM',
    'write_database': 'HIGH',
    'send_email': 'HIGH',
    'download_file': 'MEDIUM',
    'upload_file': 'HIGH',
    'execute_code': 'CRITICAL',
    'http_request': 'HIGH',
    'filesystem_read': 'MEDIUM',
    'filesystem_write': 'HIGH',
    'delete_file': 'CRITICAL',
    'shell_command': 'CRITICAL',
    'api_call': 'MEDIUM',
    'search': 'LOW',
    'calculate': 'LOW',
}

class ToolDecision(BaseModel):
    decision: str  # ALLOW, BLOCK, REQUIRE_REVIEW
    tool: str
    reason: str
    risk_score: float
    checks_passed: List[str]
    checks_failed: List[str]
    evidence: List[Dict[str, Any]]


class ToolFirewall:
    """
    Evaluates both tool authorization permissions and deep structural arguments.
    """

    def __init__(self, policy=None):
        self.policy = policy

    @classmethod
    async def for_context(cls, ctx, db):
        """Intersect server registration with every applicable tenant policy."""
        from app.core.config import settings
        from app.models.database_models import PolicyModel
        from sqlalchemy import select, or_, and_
        from types import SimpleNamespace
        from fastapi import HTTPException
        allowed = set(settings.ALLOWED_TOOLS) | set(settings.TOOL_ENDPOINTS)
        blocked, approval = {"execute_code", "shell_command"}, {"write_database"}
        conditions = [and_(PolicyModel.scope == "GLOBAL", PolicyModel.tenant_id.is_(None)),
            and_(PolicyModel.scope == "TENANT", PolicyModel.scope_id == ctx.tenant_id)]
        if ctx.application_id:
            conditions.append(and_(PolicyModel.scope == "APPLICATION", PolicyModel.scope_id == ctx.application_id))
        if ctx.environment_id:
            conditions.append(and_(PolicyModel.scope == "ENVIRONMENT", PolicyModel.scope_id == ctx.environment_id))
        try:
            policies = (await db.execute(select(PolicyModel).where(PolicyModel.is_active.is_(True), or_(*conditions)))).scalars().all()
            for policy in policies:
                rules = policy.rules_json or {}
                if "allowed_tools" in rules:
                    allowed.intersection_update(rules["allowed_tools"])
                blocked.update(rules.get("blocked_tools", []))
                approval.update(rules.get("require_approval_tools", []))
        except Exception as exc:
            raise HTTPException(503, "Tool policy storage unavailable") from exc
        return cls(SimpleNamespace(allowed_tools=list(allowed), blocked_tools=list(blocked), require_approval_tools=list(approval)))

    def _inspect_arguments(self, tool_name: str, args: Dict[str, Any]) -> tuple:
        """
        Deep structured inspection of tool arguments.
        Returns (is_violation, violation_reason, risk_score, evidence_list)
        """
        evidence = []
        def _extract_strings(obj) -> List[str]:
            out = []
            if isinstance(obj, str):
                out.append(obj)
            elif isinstance(obj, dict):
                for k, v in obj.items():
                    out.extend(_extract_strings(k))
                    out.extend(_extract_strings(v))
            elif isinstance(obj, (list, tuple, set)):
                for item in obj:
                    out.extend(_extract_strings(item))
            return out

        arg_strings = _extract_strings(args)
        raw_args_str = " ".join(arg_strings) + " " + str(args)

        # 1. Command Injection check (shell/exec tools or commands in args)
        cmd_metachars = re.compile(r'(\|\s*|;\s*|&\s*|`|\$\(|\bcurl\b|\bwget\b|\bpowershell\b|\bbash\b|\bsh\b|\bexec\b|\beval\b|>\s*|>>\s*|<\s*|\bos\.system\b|\bsubprocess\b)')
        if tool_name in ['shell_command', 'execute_code', 'terminal', 'bash', 'run_command', 'eval', 'exec']:
            cmd = args.get('command') or args.get('code') or raw_args_str
            if cmd_metachars.search(str(cmd)):
                evidence.append({"type": "COMMAND_INJECTION_PATTERN", "detail": "Suspicious shell metacharacter or command found in tool invocation"})
                return True, "Command injection metacharacter detected in tool arguments", 1.0, evidence

        # 2. Path Traversal & Sensitive File Access
        path_traversal = re.compile(r'(\.\.[/\\]+|[/\\]+etc[/\\]+(?:passwd|shadow)|C:[/\\]+Windows[/\\]+System32|\.env\b|\.ssh[/\\]+|\.aws[/\\]+)', re.IGNORECASE)
        if path_traversal.search(raw_args_str):
            evidence.append({"type": "PATH_TRAVERSAL_DETECTED", "detail": "Path traversal or sensitive system path in tool arguments"})
            return True, "Path traversal or sensitive file access detected", 0.95, evidence

        # 3. SSRF / Private IP / Metadata Exfiltration in Network Tools
        if tool_name in ['http_request', 'download_file', 'api_call', 'webhook', 'curl', 'fetch']:
            url = str(args.get('url') or args.get('destination') or args.get('target') or '')
            ssrf_pattern = re.compile(
                r'https?://(?:'
                r'localhost|'
                r'127\.\d+\.\d+\.\d+|'
                r'10\.\d+\.\d+\.\d+|'
                r'172\.(?:1[6-9]|2\d|3[0-1])\.\d+\.\d+|'
                r'192\.168\.\d+\.\d+|'
                r'169\.254\.\d+\.\d+|'
                r'0\.0\.0\.0|'
                r'\[::1\]|::1|'
                r'\[fd00:ec2::254\]|fd00:ec2::254|'
                r'metadata\.google\.internal'
                r')(?::\d+)?(?:/|$|\?)',
                re.IGNORECASE
            )
            if ssrf_pattern.search(url):
                evidence.append({"type": "SSRF_ATTEMPT", "detail": f"Attempted connection to internal/metadata target: {url}"})
                return True, "SSRF attempt targeting internal or cloud metadata network blocked", 1.0, evidence

        # 4. SQL Injection Patterns
        if tool_name in ['read_database', 'write_database', 'query']:
            query_str = str(args.get('query') or args.get('sql') or '')
            sqli_pattern = re.compile(r"(--|/\*|\bUNION\b\s+\bSELECT\b|'\s*OR\s*'1'='1'|\bDROP\b\s+\bTABLE\b|\bINSERT\b\s+\bINTO\b.*admin)", re.IGNORECASE)
            if sqli_pattern.search(query_str):
                evidence.append({"type": "SQL_INJECTION", "detail": "SQL injection pattern matched in database query argument"})
                return True, "SQL injection signature detected in database arguments", 0.95, evidence

        # 5. Credential leakage inside arguments
        cred_pattern = re.compile(r'(AKIA[0-9A-Z]{16}|ghp_[a-zA-Z0-9]{36}|xoxb-[0-9]{11}-[0-9]{11}|-----BEGIN PRIVATE KEY-----)')
        if cred_pattern.search(raw_args_str):
            evidence.append({"type": "CREDENTIAL_EXFILTRATION", "detail": "Live API key or private key detected in tool arguments"})
            return True, "Credential exfiltration attempt detected inside tool arguments", 1.0, evidence

        return False, "", 0.0, evidence

    async def evaluate_tool_call(self, tool_name: str, args: Dict[str, Any], user_context: Optional[dict] = None) -> ToolDecision:
        checks_passed = []
        checks_failed = []
        evidence = []

        # 1. Structural argument inspection (Correction 5)
        is_viol, reason, arg_risk, arg_ev = self._inspect_arguments(tool_name, args)
        if is_viol:
            checks_failed.append("argument_security_inspection")
            return ToolDecision(
                decision="BLOCK",
                tool=tool_name,
                reason=reason,
                risk_score=arg_risk,
                checks_passed=checks_passed,
                checks_failed=checks_failed,
                evidence=arg_ev,
            )
        checks_passed.append("argument_security_inspection")

        from app.core.config import settings
        allowed = getattr(self.policy, "allowed_tools", settings.ALLOWED_TOOLS) if self.policy else settings.ALLOWED_TOOLS
        if tool_name not in allowed:
            return ToolDecision(decision="BLOCK", tool=tool_name, reason="Tool is not registered for this deployment",
                risk_score=0.8, checks_passed=checks_passed, checks_failed=["tool_allowlist"], evidence=[])
        # 2. Policy-level tool permissions
        blocked_tools = getattr(self.policy, "blocked_tools", ["execute_code", "shell_command"]) if self.policy else ["execute_code", "shell_command"]
        require_approval_tools = getattr(self.policy, "require_approval_tools", ["write_database"]) if self.policy else ["write_database"]

        if tool_name in blocked_tools:
            checks_failed.append("policy_blocked_tools")
            return ToolDecision(
                decision="BLOCK",
                tool=tool_name,
                reason=f"Tool '{tool_name}' is explicitly blocked by active security policy",
                risk_score=1.0,
                checks_passed=checks_passed,
                checks_failed=checks_failed,
                evidence=[{"type": "POLICY_BLOCKED", "tool": tool_name}],
            )
        checks_passed.append("policy_tool_whitelist")

        risk_level = TOOL_RISK_LEVELS.get(tool_name, 'LOW')
        risk_score = {"LOW": 0.1, "MEDIUM": 0.4, "HIGH": 0.7, "CRITICAL": 0.9}.get(risk_level, 0.1)

        if tool_name in require_approval_tools:
            checks_failed.append("requires_human_approval")
            return ToolDecision(
                decision="REQUIRE_REVIEW",
                tool=tool_name,
                reason=f"Tool '{tool_name}' requires human approval before execution",
                risk_score=risk_score,
                checks_passed=checks_passed,
                checks_failed=checks_failed,
                evidence=[{"type": "REQUIRE_REVIEW", "tool": tool_name}],
            )

        checks_passed.append("execution_authorized")
        return ToolDecision(
            decision="ALLOW",
            tool=tool_name,
            reason="Tool invocation authorized by security policy and passed argument inspection",
            risk_score=risk_score,
            checks_passed=checks_passed,
            checks_failed=[],
            evidence=[],
        )

    async def execute_tool_proxy(
        self,
        tool_name: str,
        args: Dict[str, Any],
        target_endpoint: Optional[str] = None,
        execution_mode: str = "sandboxed",
        user_context: Optional[dict] = None
    ) -> Dict[str, Any]:
        """
        Enforceable execution boundary:
        LLM -> tool_call -> AEGIS TOOL GATE -> authorization -> (BLOCK -> fail-closed error / ALLOW -> tool proxy) -> REAL TOOL -> OUTPUT FIREWALL
        """
        import time
        import json
        t0 = time.perf_counter()

        # 1. Authorization & Argument Firewall
        auth_decision = await self.evaluate_tool_call(tool_name, args, user_context)
        if auth_decision.decision != "ALLOW":
            return {
                "decision": auth_decision.decision,
                "tool": tool_name,
                "reason": auth_decision.reason,
                "tool_executed": False,
                "risk_score": auth_decision.risk_score,
                "evidence": auth_decision.evidence,
                "checks_failed": auth_decision.checks_failed,
                "output": None,
                "latency_ms": round((time.perf_counter() - t0) * 1000, 2),
            }

        from app.core.config import settings
        import math
        configured = settings.TOOL_ENDPOINTS.get(tool_name)
        executed = False
        def held(reason):
            return {"decision": "REQUIRE_REVIEW", "tool": tool_name, "reason": reason,
                    "tool_executed": executed, "risk_score": 0.5, "output": None,
                    "checks_failed": ["executor_registration"], "latency_ms": (time.perf_counter()-t0)*1000}
        if target_endpoint and target_endpoint != configured:
            return held("Caller cannot choose tool execution destinations")
        if configured:
            from app.parsers.web_fetcher import WebFetcher
            import httpx
            from urllib.parse import urlparse
            safe, reason, ips = WebFetcher().validate_url_and_resolve(configured)
            if not safe:
                return held("Tool destination denied by network policy")
            parsed = urlparse(configured)
            pinned = httpx.URL(configured).copy_with(host=ips[0])
            async with httpx.AsyncClient(timeout=10, follow_redirects=False, trust_env=False) as client:
                async with client.stream("POST", pinned, json={"tool": tool_name, "arguments": args},
                    headers={"Host": parsed.netloc}, extensions={"sni_hostname": parsed.hostname}) as response:
                    response.raise_for_status()
                    raw = bytearray()
                    async for chunk in response.aiter_bytes():
                        raw.extend(chunk)
                        if len(raw) > settings.MAX_CONTENT_LENGTH:
                            return held("Tool output exceeds budget")
            executed = True
            tool_output = json.loads(raw)
        elif tool_name in ("calculate", "calculate_sum"):
            try:
                a, b = float(args.get("a", 0)), float(args.get("b", 0))
                op = args.get("operation", "add")
                if not math.isfinite(a) or not math.isfinite(b):
                    raise ValueError()
                operations = {"add": lambda: a+b, "multiply": lambda: a*b, "subtract": lambda: a-b, "divide": lambda: a/b}
                value = operations[op]()
                if not math.isfinite(value):
                    raise ValueError()
                tool_output = {"result": value, "status": "success"}
            except (ValueError, KeyError, ZeroDivisionError):
                return held("Invalid arithmetic arguments")
        else:
            return held("No executor is registered for this tool")
        executed = True
        from app.tools.output_firewall import OutputFirewall
        output_str = json.dumps(tool_output)
        out = await OutputFirewall().scan_output(output_str, {"protected_values": settings.PROTECTED_OUTPUT_VALUES})
        if out.decision == "BLOCK":
            return held("Tool output contains protected data")
        from app.decision.orchestrator import shared_orchestrator
        inspection = await shared_orchestrator.execute_pipeline(out.clean_content, "api", "tool_output", "UNTRUSTED")
        if inspection.decision != "ALLOW":
            return held("Tool output requires security review")
        was_sanitized = out.decision == "REDACT"
        tool_output = json.loads(out.clean_content)

        latency_ms = round((time.perf_counter() - t0) * 1000, 2)
        return {
            "decision": "ALLOW",
            "tool": tool_name,
            "tool_executed": True,
            "output": tool_output,
            "sanitized": was_sanitized,
            "risk_score": auth_decision.risk_score,
            "checks_passed": auth_decision.checks_passed + ["tool_proxy_executed", "output_firewall_inspected"],
            "evidence": auth_decision.evidence,
            "latency_ms": latency_ms,
        }
