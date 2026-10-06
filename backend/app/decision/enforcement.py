"""Policy cannot relax a security hold; sanitized replacements must pass a fresh scan."""
ORDER = {"ALLOW": 0, "SANITIZE": 1, "REQUIRE_REVIEW": 2, "BLOCK": 3, "QUARANTINE": 4}


def stricter(first, second):
    if first not in ORDER or second not in ORDER:
        return "BLOCK"
    return max((first, second), key=ORDER.get)


async def enforce(orchestrated, policy_decision, content, sanitizer, orchestrator, source_type, origin, trust):
    decision = stricter(orchestrated.decision, policy_decision.decision)
    replacement = None
    if decision == "SANITIZE":
        result = sanitizer.sanitize(content, orchestrated.evidence, findings=orchestrated.findings)
        if not result.sanitized or not result.verification_passed or result.sanitized_content == content:
            return "REQUIRE_REVIEW", None
        verify = await orchestrator.execute_pipeline(result.sanitized_content, source_type,
            origin + ":sanitized", trust)
        if verify.decision != "ALLOW" or verify.degraded_mode:
            return "REQUIRE_REVIEW", None
        replacement = result.sanitized_content
    return decision, replacement
