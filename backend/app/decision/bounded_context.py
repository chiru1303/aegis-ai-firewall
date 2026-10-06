"""
Aegis AI Firewall - Bounded Context for Session Trajectory
Enforces Correction 6:
Do NOT resend raw 50k tokens to detectors.
Pass: current request + security-relevant prior events + session risk state + recent tool activity.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from app.core.logging import get_logger

logger = get_logger(__name__)


@dataclass
class BoundedSessionContext:
    session_id: str
    current_state: str = "NORMAL"
    accumulated_risk: float = 0.0
    event_count: int = 0
    recent_flags: List[str] = field(default_factory=list)
    recent_tool_actions: List[Dict[str, Any]] = field(default_factory=list)
    prior_security_events: List[Dict[str, Any]] = field(default_factory=list)
    bounded_summary_text: str = ""


async def build_bounded_context(
    session_id: Optional[str],
    session_engine: Any,
    max_recent_events: int = 5,
    tenant_id: str = "tenant_default",
    application_id: Optional[str] = None,
) -> Optional[BoundedSessionContext]:
    """
    Construct a bounded, token-efficient security context for multi-step trajectory analysis.
    Avoids transmitting large raw conversation histories to detectors.
    """
    if not session_id or not session_engine:
        return None

    try:
        sess = await session_engine.get_session(session_id, tenant_id, application_id)
        if not sess:
            return None

        # Extract only security-relevant prior events (filter out benign noise)
        recent_events = sess.events[-max_recent_events:] if hasattr(sess, "events") and sess.events else []
        security_events = [
            {
                "type": ev.get("type", "unknown"),
                "risk": ev.get("risk_contribution", 0.0),
                "timestamp": ev.get("timestamp", ""),
            }
            for ev in recent_events
            if ev.get("risk_contribution", 0.0) > 0.05
        ]

        flags = getattr(sess, "flags", []) or []
        summary_lines = [
            f"Session [{session_id[:8]}]: State={sess.current_state}",
            f"Risk Accumulator={sess.risk_accumulator:.2f}, Events={sess.event_count}",
        ]
        if flags:
            summary_lines.append(f"Active Flags={','.join(flags[:4])}")

        return BoundedSessionContext(
            session_id=session_id,
            current_state=sess.current_state,
            accumulated_risk=sess.risk_accumulator,
            event_count=sess.event_count,
            recent_flags=flags,
            recent_tool_actions=[],
            prior_security_events=security_events,
            bounded_summary_text=" | ".join(summary_lines),
        )
    except Exception as e:
        logger.debug(f"Failed to build bounded session context: {e}")
        return None
