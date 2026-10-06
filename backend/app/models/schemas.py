from enum import Enum
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional, Union

class SourceType(str, Enum):
    user = "user"
    web = "web"
    pdf = "pdf"
    docx = "docx"
    email = "email"
    api = "api"
    ocr = "ocr"
    database = "database"
    code = "code"
    image = "image"
    unknown = "unknown"

class TrustLevel(str, Enum):
    TRUSTED = "TRUSTED"
    SEMI_TRUSTED = "SEMI_TRUSTED"
    UNTRUSTED = "UNTRUSTED"
    MALICIOUS = "MALICIOUS"

class Decision(str, Enum):
    ALLOW = "ALLOW"
    SANITIZE = "SANITIZE"
    BLOCK = "BLOCK"
    QUARANTINE = "QUARANTINE"
    REQUIRE_REVIEW = "REQUIRE_REVIEW"

class RiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"

class AttackType(str, Enum):
    INSTRUCTION_OVERRIDE = "INSTRUCTION_OVERRIDE"
    ROLE_CHANGE = "ROLE_CHANGE"
    SECRET_EXTRACTION = "SECRET_EXTRACTION"
    TOOL_ABUSE = "TOOL_ABUSE"
    CREDENTIAL_THEFT = "CREDENTIAL_THEFT"
    CONTEXT_POISONING = "CONTEXT_POISONING"
    MULTI_STEP_JAILBREAK = "MULTI_STEP_JAILBREAK"
    ENCODED_INSTRUCTION = "ENCODED_INSTRUCTION"
    INDIRECT_PROMPT_INJECTION = "INDIRECT_PROMPT_INJECTION"

class SessionState(str, Enum):
    NORMAL = "NORMAL"
    RECON = "RECON"
    TARGET_DISCOVERY = "TARGET_DISCOVERY"
    PRIVILEGE_ATTEMPT = "PRIVILEGE_ATTEMPT"
    SECRET_ACCESS = "SECRET_ACCESS"
    EXFILTRATION = "EXFILTRATION"

class ContentSource(BaseModel):
    type: SourceType
    origin: str
    trust: TrustLevel = TrustLevel.UNTRUSTED

class ContentPayload(BaseModel):
    type: str
    value: str

class ScanContext(BaseModel):
    user_id: Optional[str] = None
    application_id: Optional[str] = None
    conversation_id: Optional[str] = None

class ScanRequest(BaseModel):
    session_id: Optional[str] = None
    source: Optional[Union[ContentSource, str, Dict[str, Any]]] = None
    content: Union[str, ContentPayload, Dict[str, Any]]
    sourceType: Optional[str] = None
    trustLevel: Optional[str] = None
    context: Optional[ScanContext] = None

class DocumentScanRequest(BaseModel):
    session_id: Optional[str] = "default_session"
    context: Optional[ScanContext] = None

class ImageScanRequest(BaseModel):
    session_id: Optional[str] = "default_session"
    context: Optional[ScanContext] = None

class WebScanRequest(BaseModel):
    session_id: Optional[str] = "default_session"
    url: str
    context: Optional[ScanContext] = None

class ToolCheckRequest(BaseModel):
    session_id: Optional[str] = "session-firewall"
    sessionId: Optional[str] = None
    tool: Optional[str] = None
    toolName: Optional[str] = None
    arguments: Dict[str, Any] = {}
    requested_by: Optional[str] = None
    requestedBy: Optional[str] = None

class SessionEventRequest(BaseModel):
    session_id: str
    event_type: str
    content: str
    metadata: Dict[str, Any] = {}

class AttackDetection(BaseModel):
    type: AttackType
    confidence: float

class DetectionEvidence(BaseModel):
    detector: str
    matched_signal: str
    severity: str

class ProvenanceInfo(BaseModel):
    source: ContentSource
    origin: str
    trust_level: TrustLevel
    content_id: str
    transformation_chain: List[str] = []

class SanitizationResult(BaseModel):
    sanitized: bool
    removed_segments: List[str] = []
    original_hash: str
    sanitized_hash: str

class Segment(BaseModel):
    id: str
    text: str
    source_type: str
    location: str
    visibility: str = "visible"  # visible | hidden | metadata
    trust: str = "UNTRUSTED"  # TRUSTED | UNTRUSTED | EXTERNAL
    parent_id: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)

class SegmentFinding(BaseModel):
    segment_id: str
    location: str
    visibility: str
    attack_type: str
    risk_score: float
    matched_signal: str
    evidence: str

class Finding(BaseModel):
    attack_type: str
    confidence: float
    evidence_span: str
    detector: str
    location: str = "content"

class ScanResponse(BaseModel):
    request_id: str
    decision: Decision
    risk_score: float
    risk_level: RiskLevel
    confidence: float
    attack_types: List[AttackDetection] = []
    content_status: str
    sanitized_content: Optional[str] = None
    evidence: List[DetectionEvidence] = []
    provenance: ProvenanceInfo
    latency_ms: float
    policy: str
    trace_id: str
    segments: List[Segment] = []
    segment_findings: List[SegmentFinding] = []
    findings: List[Finding] = []

class ToolCheckResponse(BaseModel):
    decision: Decision
    reason: str
    risk_score: float
    tool: str
    evidence: List[DetectionEvidence] = []

class SessionResponse(BaseModel):
    session_id: str
    state: SessionState
    risk_score: float

class AuditRecord(BaseModel):
    request_id: str
    session_id: str
    timestamp: str
    action: str
    decision: str
    risk_score: float

class HealthResponse(BaseModel):
    status: str
    database: str
    redis: str
    models: Dict[str, str]
    healthy: bool = True
    tier_0_detectors: int = 9
    upstream_llm: str = "connected"
    timestamp: str = ""

class MetricsResponse(BaseModel):
    requests_total: int
    blocks_total: int
    avg_latency_ms: float

class PolicyResponse(BaseModel):
    id: str
    name: str
    is_active: bool
