"""
Aegis AI Firewall - Hierarchical Policy Engine
Enforces:
1. Invariant 2: Model output cannot bypass policy/authorization.
   The deterministic policy engine is the absolute final authority.
2. Correction 4: Hierarchical Policy Scoping:
   GLOBAL PLATFORM -> TENANT -> APPLICATION -> ENVIRONMENT
   Global mandatory rules cannot be overridden or relaxed by lower scopes.
"""
from typing import List, Optional, Dict, Any
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, and_
from app.risk.engine import RiskAssessment
from app.core.logging import get_logger

logger = get_logger(__name__)


class Policy(BaseModel):
    name: str
    description: str
    scope: str = "GLOBAL"  # GLOBAL, TENANT, APPLICATION, ENVIRONMENT
    scope_id: Optional[str] = None
    priority: int = 100
    is_mandatory: bool = False
    risk_thresholds: Dict[str, str] = {
        "LOW": "ALLOW",
        "MEDIUM": "SANITIZE",
        "HIGH": "REQUIRE_REVIEW",
        "CRITICAL": "BLOCK"
    }
    mandatory_blocks: List[str] = [
        "credential_exfiltration",
        "CREDENTIAL_THEFT",
        "unauthorized_secret_extraction",
        "SECRET_EXTRACTION",
        "unauthorized_high_risk_tool",
        "attempted_privilege_escalation",
        "known_malicious_encoded_instruction",
        "forbidden_destination"
    ]
    allowed_tools: List[str] = ["search", "calculate"]
    blocked_tools: List[str] = ["execute_code", "shell_command"]
    require_approval_tools: List[str] = ["write_database"]
    allow_external_content: bool = False
    max_risk_for_auto_allow: float = 0.19
    sanitize_on_medium: bool = True


class PolicyDecision(BaseModel):
    decision: str  # ALLOW, SANITIZE, BLOCK, QUARANTINE, REQUIRE_REVIEW
    policy_name: str
    scope_applied: str = "GLOBAL"
    risk_score: float
    risk_level: str
    mandatory_block: bool
    mandatory_block_reason: Optional[str]
    applied_rules: List[str]
    explanation: str


# Non-overridable Global Platform Guardrails
GLOBAL_PLATFORM_MANDATORY_BLOCKS = {
    "credential_exfiltration",
    "CREDENTIAL_THEFT",
    "unauthorized_secret_extraction",
    "SECRET_EXTRACTION",
    "attempted_privilege_escalation",
    "known_malicious_encoded_instruction"
}


class PolicyEngine:
    def __init__(self):
        self.builtin_policies = {
            "default_zero_trust": Policy(
                name="default_zero_trust",
                description="Strict enterprise zero-trust guardrails",
                scope="GLOBAL",
                is_mandatory=True,
                risk_thresholds={"LOW": "ALLOW", "MEDIUM": "SANITIZE", "HIGH": "REQUIRE_REVIEW", "CRITICAL": "BLOCK"},
                mandatory_blocks=list(GLOBAL_PLATFORM_MANDATORY_BLOCKS) + ["unauthorized_high_risk_tool", "forbidden_destination"],
                allowed_tools=["search", "calculate"],
                blocked_tools=["execute_code", "shell_command"],
                require_approval_tools=["write_database"],
                allow_external_content=False,
                max_risk_for_auto_allow=0.19,
                sanitize_on_medium=True
            ),
            "banking_strict": Policy(
                name="banking_strict",
                description="Extra strict policy for financial systems",
                scope="GLOBAL",
                is_mandatory=False,
                risk_thresholds={"LOW": "ALLOW", "MEDIUM": "REQUIRE_REVIEW", "HIGH": "BLOCK", "CRITICAL": "BLOCK"},
                mandatory_blocks=list(GLOBAL_PLATFORM_MANDATORY_BLOCKS) + ["unauthorized_high_risk_tool", "forbidden_destination"],
                allowed_tools=[],
                blocked_tools=["execute_code", "shell_command", "write_database"],
                require_approval_tools=["search"],
                allow_external_content=False,
                max_risk_for_auto_allow=0.10,
                sanitize_on_medium=False
            ),
            "research_permissive": Policy(
                name="research_permissive",
                description="Allows dynamic analysis but still enforces global mandatory blocks",
                scope="GLOBAL",
                is_mandatory=False,
                risk_thresholds={"LOW": "ALLOW", "MEDIUM": "ALLOW", "HIGH": "SANITIZE", "CRITICAL": "BLOCK"},
                mandatory_blocks=list(GLOBAL_PLATFORM_MANDATORY_BLOCKS),
                allowed_tools=["search", "calculate", "execute_code"],
                blocked_tools=["shell_command"],
                require_approval_tools=["write_database"],
                allow_external_content=True,
                max_risk_for_auto_allow=0.49,
                sanitize_on_medium=False
            ),
            "agent_restricted": Policy(
                name="agent_restricted",
                description="Autonomous agent sandbox with restricted tool calls",
                scope="GLOBAL",
                is_mandatory=False,
                risk_thresholds={"LOW": "ALLOW", "MEDIUM": "SANITIZE", "HIGH": "BLOCK", "CRITICAL": "BLOCK"},
                mandatory_blocks=list(GLOBAL_PLATFORM_MANDATORY_BLOCKS),
                allowed_tools=["search"],
                blocked_tools=["execute_code", "shell_command", "write_database", "http_request"],
                require_approval_tools=[],
                allow_external_content=False,
                max_risk_for_auto_allow=0.19,
                sanitize_on_medium=True
            )
        }
        self.policies = self.builtin_policies

    async def evaluate_hierarchical(
        self,
        risk: RiskAssessment,
        tenant_id: Optional[str] = None,
        application_id: Optional[str] = None,
        environment_id: Optional[str] = None,
        policy_name: Optional[str] = None,
        db: Optional[AsyncSession] = None,
    ) -> PolicyDecision:
        """
        Evaluate policies in hierarchical precedence:
        1. Non-negotiable GLOBAL PLATFORM mandatory rules (cannot be overridden by anyone)
        2. Database-backed Hierarchical Policies (ENVIRONMENT -> APPLICATION -> TENANT -> GLOBAL)
        3. Fallback Builtin Policy
        """
        # Step 1: Check Global Platform Mandatory Guardrails First
        for attack in risk.attack_types:
            atk_type = attack.get("type", "") if isinstance(attack, dict) else getattr(attack, "type", "")
            atk_str = str(atk_type)
            if atk_str in GLOBAL_PLATFORM_MANDATORY_BLOCKS:
                return PolicyDecision(
                    decision="BLOCK",
                    policy_name="GLOBAL_MANDATORY_PLATFORM_POLICY",
                    scope_applied="GLOBAL",
                    risk_score=risk.risk_score,
                    risk_level=risk.risk_level,
                    mandatory_block=True,
                    mandatory_block_reason=f"Global mandatory violation: {atk_str}",
                    applied_rules=["global_mandatory_guardrail"],
                    explanation=f"Permanently blocked by non-negotiable platform policy on {atk_str}."
                )

        # Step 2: Try to resolve hierarchical policy from DB if session provided
        resolved_policy = None
        scope_applied = "GLOBAL"
        db_policies = []

        if db and tenant_id:
            try:
                from app.models.database_models import PolicyModel
                # Query applicable policies ordered by priority (lower number = higher precedence)
                conditions = [PolicyModel.scope == "GLOBAL"]
                if tenant_id:
                    conditions.append(and_(PolicyModel.scope == "TENANT", PolicyModel.scope_id == tenant_id))
                if application_id:
                    conditions.append(and_(PolicyModel.scope == "APPLICATION", PolicyModel.scope_id == application_id))
                if environment_id:
                    conditions.append(and_(PolicyModel.scope == "ENVIRONMENT", PolicyModel.scope_id == environment_id))

                stmt = (
                    select(PolicyModel)
                    .where(PolicyModel.is_active.is_(True))
                    .where(or_(*conditions))
                    .order_by(PolicyModel.priority.asc())
                )
                res = await db.execute(stmt)
                db_policies = res.scalars().all()

                if db_policies:
                    target_db_policy = db_policies[0]
                    scope_applied = target_db_policy.scope
                    resolved_policy = Policy(
                        name=target_db_policy.name,
                        description=target_db_policy.description or "",
                        scope=target_db_policy.scope,
                        scope_id=target_db_policy.scope_id,
                        priority=target_db_policy.priority,
                        is_mandatory=target_db_policy.is_mandatory,
                        risk_thresholds=target_db_policy.rules_json.get("risk_thresholds", {
                            "LOW": "ALLOW", "MEDIUM": "SANITIZE", "HIGH": "REQUIRE_REVIEW", "CRITICAL": "BLOCK"
                        }),
                        mandatory_blocks=target_db_policy.rules_json.get("mandatory_blocks", list(GLOBAL_PLATFORM_MANDATORY_BLOCKS)),
                        allowed_tools=target_db_policy.rules_json.get("allowed_tools", ["search", "calculate"]),
                        blocked_tools=target_db_policy.rules_json.get("blocked_tools", ["execute_code", "shell_command"]),
                        require_approval_tools=target_db_policy.rules_json.get("require_approval_tools", ["write_database"]),
                        allow_external_content=target_db_policy.rules_json.get("allow_external_content", False),
                        max_risk_for_auto_allow=target_db_policy.rules_json.get("max_risk_for_auto_allow", 0.19),
                        sanitize_on_medium=target_db_policy.rules_json.get("sanitize_on_medium", True)
                    )
            except Exception as e:
                from fastapi import HTTPException
                raise HTTPException(503, "Policy storage unavailable; request held") from e

        # Step 3: Fallback to builtin policy
        if not resolved_policy:
            p_name = policy_name or "default_zero_trust"
            resolved_policy = self.builtin_policies.get(p_name, self.builtin_policies["default_zero_trust"])

        # Step 4: Evaluate the resolved policy
        applied_rules = []
        for attack in risk.attack_types:
            atk_type = attack.get("type", "") if isinstance(attack, dict) else getattr(attack, "type", "")
            atk_str = str(atk_type)
            if atk_str in resolved_policy.mandatory_blocks:
                return PolicyDecision(
                    decision="BLOCK",
                    policy_name=resolved_policy.name,
                    scope_applied=scope_applied,
                    risk_score=risk.risk_score,
                    risk_level=risk.risk_level,
                    mandatory_block=True,
                    mandatory_block_reason=f"Mandatory block: {atk_str}",
                    applied_rules=["mandatory_block"],
                    explanation=f"Blocked due to mandatory block rule on {atk_str} under {resolved_policy.name}."
                )

        # Risk-based decision
        base_decision = resolved_policy.risk_thresholds.get(risk.risk_level, "BLOCK")
        applied_rules.append(f"risk_level_{risk.risk_level}")

        if risk.risk_level == "MEDIUM" and resolved_policy.sanitize_on_medium:
            base_decision = "SANITIZE"
            applied_rules.append("sanitize_on_medium")

        # Every applicable policy constrains the result. A lower-scope ALLOW cannot
        # erase a mandatory parent or another applicable security hold.
        from app.decision.enforcement import stricter
        for stored in db_policies:
            rules = stored.rules_json or {}
            blocks = set(rules.get("mandatory_blocks", []))
            for attack in risk.attack_types:
                kind = attack.get("type", "") if isinstance(attack, dict) else str(getattr(attack, "type", ""))
                if kind in blocks:
                    base_decision = stricter(base_decision, "BLOCK")
                    applied_rules.append(f"mandatory:{stored.name}")
            thresholds = rules.get("risk_thresholds")
            if thresholds:
                base_decision = stricter(base_decision, thresholds.get(risk.risk_level, "REQUIRE_REVIEW"))

        return PolicyDecision(
            decision=base_decision,
            policy_name=resolved_policy.name,
            scope_applied=scope_applied,
            risk_score=risk.risk_score,
            risk_level=risk.risk_level,
            mandatory_block=False,
            mandatory_block_reason=None,
            applied_rules=applied_rules,
            explanation=f"Decision {base_decision} based on {resolved_policy.name} ({scope_applied}) policy for risk level {risk.risk_level}."
        )

    async def evaluate(self, risk: RiskAssessment, policy_name: str = "default_zero_trust") -> PolicyDecision:
        """Backward-compatible evaluation method."""
        return await self.evaluate_hierarchical(risk, policy_name=policy_name)
