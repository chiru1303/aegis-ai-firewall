from typing import List, Dict, Any, Optional
from pydantic import BaseModel
from app.core.time import now_ist, format_ist
from app.core.config import settings
from app.core.redis_client import redis_client
import hashlib
import asyncio
import time
import uuid
from contextlib import asynccontextmanager


def session_key(session_id: str, tenant_id: str = "tenant_default", application_id: str = None):
    namespace = hashlib.sha256(f"{tenant_id}:{application_id or ''}".encode()).hexdigest()[:16]
    digest = hashlib.sha256(session_id.encode()).hexdigest()
    return f"aegis:session:{namespace}:{digest}"

class SessionState(BaseModel):
    tenant_id: str = "tenant_default"
    application_id: Optional[str] = None
    expires_at: float = 0.0
    session_id: str
    current_state: str
    risk_accumulator: float
    event_count: int
    events: List[Dict[str, Any]]
    state_transitions: List[Dict[str, Any]]
    created_at: str
    updated_at: str
    flags: List[str]

class SessionEngine:
    def __init__(self):
        self.sessions: Dict[str, SessionState] = {}
        self._locks = {}
        self.state_order = ["NORMAL", "RECON", "TARGET_DISCOVERY", "PRIVILEGE_ATTEMPT", "SECRET_ACCESS", "EXFILTRATION"]
        self.state_weights = {
            "RECON": 0.25,
            "TARGET_DISCOVERY": 0.45,
            "PRIVILEGE_ATTEMPT": 0.70,
            "SECRET_ACCESS": 0.85,
            "EXFILTRATION": 0.95
        }

    def _classify_event(self, content: str) -> Optional[str]:
        c = content.lower()
        if any(w in c for w in ["copy", "transfer", "upload", "external", "send to", "exfiltrate"]):
            return "EXFILTRATION"
        if any(w in c for w in ["secret", "config", "password", "shadow", "api key", ".env"]):
            return "SECRET_ACCESS"
        if any(w in c for w in ["sudo", "admin", "chmod", "role", "bypass", "keylogger", "payload", "rogue"]):
            return "PRIVILEGE_ATTEMPT"
        if any(w in c for w in ["database", "file", "credentials", "malware", "sql injection", "vulnerabilities"]):
            return "TARGET_DISCOVERY"
        if any(w in c for w in ["tools", "capabilities", "architecture", "character named", "play a game", "sci-fi story", "academic study", "academic"]):
            return "RECON"
        return None

    @asynccontextmanager
    async def _locked(self, key):
        if redis_client.client and not redis_client._use_in_memory:
            token = uuid.uuid4().hex
            lock_key = key + ":lock"
            acquired = False
            for _ in range(60):
                acquired = await redis_client.client.set(lock_key, token, nx=True, ex=20)
                if acquired:
                    break
                await asyncio.sleep(0.05)
            if not acquired:
                raise RuntimeError("Session concurrency budget exceeded")
            try:
                yield
            finally:
                await redis_client.client.eval("if redis.call('GET',KEYS[1])==ARGV[1] then return redis.call('DEL',KEYS[1]) end return 0", 1, lock_key, token)
        else:
            lock = self._locks.setdefault(key, asyncio.Lock())
            async with lock:
                yield

    async def get_session(self, session_id, tenant_id="tenant_default", application_id=None):
        key = session_key(session_id, tenant_id, application_id)
        saved = await redis_client.get_json(key)
        state = SessionState.model_validate(saved) if saved else self.sessions.get(key)
        if state and state.expires_at and state.expires_at <= time.time():
            self.sessions.pop(key, None)
            return None
        return state

    async def list_sessions(self, tenant_id=None):
        if redis_client.client and not redis_client._use_in_memory:
            result = []
            async for key in redis_client.client.scan_iter(match="aegis:session:*"):
                if key.endswith(":lock"):
                    continue
                saved = await redis_client.get_json(key)
                if saved:
                    state = SessionState.model_validate(saved)
                    if tenant_id is None or state.tenant_id == tenant_id:
                        result.append(state)
                if len(result) >= settings.MAX_SESSIONS:
                    break
            return result
        return [s for s in self.sessions.values() if s.expires_at > time.time() and (tenant_id is None or s.tenant_id == tenant_id)]

    async def process_event(self, session_id: str, content: str, event_metadata: dict = None,
                            tenant_id="tenant_default", application_id=None) -> SessionState:
        key = session_key(session_id, tenant_id, application_id)
        async with self._locked(key):
            saved = await self.get_session(session_id, tenant_id, application_id)
            if saved:
                self.sessions[key] = saved
            state = await self._process_event(key, content, event_metadata)
            state.session_id, state.tenant_id, state.application_id = session_id, tenant_id, application_id
            await self._save(key, state)
            return state

    async def _save(self, key, state):
        state.expires_at = time.time() + settings.SESSION_TTL_SECONDS
        state.events = state.events[-settings.MAX_SESSION_EVENTS:]
        state.state_transitions = state.state_transitions[-settings.MAX_SESSION_EVENTS:]
        await redis_client.set_json(key, state.model_dump(), expire=settings.SESSION_TTL_SECONDS)
        while len(self.sessions) > settings.MAX_SESSIONS:
            oldest = next(iter(self.sessions))
            self.sessions.pop(oldest, None)
            if oldest in self._locks and not self._locks[oldest].locked():
                self._locks.pop(oldest, None)

    async def _process_event(self, session_id: str, content: str, event_metadata: dict = None) -> SessionState:
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(
                session_id=session_id,
                current_state="NORMAL",
                risk_accumulator=0.0,
                event_count=0,
                events=[],
                state_transitions=[],
                created_at=format_ist(now_ist()),
                updated_at=format_ist(now_ist()),
                flags=[]
            )

        session = self.sessions[session_id]
        if session.current_state == "QUARANTINE":
            return session
        session.event_count += 1

        detected_state = self._classify_event(content)
        # Automatic scans provide measured risk; keywords alone must not poison benign sessions.
        if event_metadata and event_metadata.get("automatic") and event_metadata.get("risk_score", 0) < 0.2:
            detected_state = None
        if detected_state:
            curr_idx = self.state_order.index(session.current_state)
            new_idx = self.state_order.index(detected_state)

            if new_idx >= curr_idx and detected_state != "NORMAL":
                step_weight = self.state_weights.get(detected_state, 0.2)
                session.risk_accumulator = max(session.risk_accumulator, step_weight)
                if session.event_count > 1:
                    session.risk_accumulator = min(1.0, session.risk_accumulator + 0.15)

                session.state_transitions.append({
                    "from": session.current_state,
                    "to": detected_state,
                    "risk_added": step_weight,
                    "timestamp": format_ist(now_ist())
                })
                session.current_state = detected_state

        session.events.append({
            "content_length": len(content),
            "metadata": event_metadata,
            "timestamp": format_ist(now_ist())
        })
        session.updated_at = format_ist(now_ist())

        if session.risk_accumulator >= 0.7:
            if "HIGH_TRAJECTORY_RISK" not in session.flags:
                session.flags.append("HIGH_TRAJECTORY_RISK")

        return session

    async def quarantine_session(self, session_id: str, reason: str = "Administrator quarantine",
                                 tenant_id="tenant_default", application_id=None) -> SessionState:
        key = session_key(session_id, tenant_id, application_id)
        async with self._locked(key):
            saved = await self.get_session(session_id, tenant_id, application_id)
            if saved:
                self.sessions[key] = saved
            state = await self._quarantine_session(key, reason)
            state.session_id, state.tenant_id, state.application_id = session_id, tenant_id, application_id
            await self._save(key, state)
            return state

    async def _quarantine_session(self, session_id: str, reason: str) -> SessionState:
        """Place session in hard quarantine, forcing maximum risk and quarantine state."""
        if session_id not in self.sessions:
            self.sessions[session_id] = SessionState(
                session_id=session_id,
                current_state="QUARANTINE",
                risk_accumulator=1.0,
                event_count=0,
                events=[],
                state_transitions=[],
                created_at=format_ist(now_ist()),
                updated_at=format_ist(now_ist()),
                flags=["QUARANTINED"]
            )
            return self.sessions[session_id]

        session = self.sessions[session_id]
        prev_state = session.current_state
        session.current_state = "QUARANTINE"
        session.risk_accumulator = 1.0
        if "QUARANTINED" not in session.flags:
            session.flags.append("QUARANTINED")
        session.state_transitions.append({
            "from": prev_state,
            "to": "QUARANTINE",
            "risk_added": 1.0,
            "reason": reason,
            "timestamp": format_ist(now_ist())
        })
        session.updated_at = format_ist(now_ist())
        return session


session_engine = SessionEngine()
