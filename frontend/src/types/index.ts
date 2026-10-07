export enum SourceType {
  USER = 'user',
  WEB = 'web',
  PDF = 'pdf',
  DOCX = 'docx',
  EMAIL = 'email',
  DOCUMENT = 'document',
  SYSTEM = 'system',
  API = 'api',
  OCR = 'ocr',
  CODE = 'code',
  IMAGE = 'image',
  OTHER = 'other'
}

export enum TrustLevel {
  UNTRUSTED = 'untrusted',
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  INTERNAL = 'internal'
}

export enum Decision {
  ALLOW = 'allow',
  BLOCK = 'block',
  SANITIZE = 'sanitize',
  QUARANTINE = 'quarantine',
  REQUIRE_REVIEW = 'require_review'
}

export enum RiskLevel {
  LOW = 'low',
  MEDIUM = 'medium',
  HIGH = 'high',
  CRITICAL = 'critical'
}

export enum AttackType {
  INSTRUCTION_OVERRIDE = 'instruction_override',
  ROLE_CHANGE = 'role_change',
  SECRET_EXTRACTION = 'secret_extraction',
  TOOL_ABUSE = 'tool_abuse',
  CREDENTIAL_THEFT = 'credential_theft',
  CONTEXT_POISONING = 'context_poisoning',
  MULTI_STEP_JAILBREAK = 'multi_step_jailbreak',
  ENCODED_INSTRUCTION = 'encoded_instruction',
  INDIRECT_PROMPT_INJECTION = 'indirect_prompt_injection',
  NONE = 'none'
}

export interface ScanRequest {
  content: string;
  sourceType: SourceType;
  trustLevel: TrustLevel;
  sessionId?: string;
  userId?: string;
  metadata?: Record<string, any>;
}

export interface ProvenanceInfo {
  sourceId: string;
  hopCount: number;
  originalTrust: TrustLevel;
  transformations: string[];
}

export interface DetectionEvidence {
  detectorName: string;
  signal: string;
  severity: number; // 0-1
  location?: { start: number; end: number };
}

export interface AttackDetection {
  attackType: AttackType;
  confidence: number;
  evidence: DetectionEvidence[];
}

export interface ScanResponse {
  id: string;
  timestamp: string;
  decision: Decision;
  riskLevel: RiskLevel;
  riskScore: number;
  confidence: number;
  detectedAttacks: AttackDetection[];
  sanitizedContent?: string;
  latencyMs: number;
  policyIdApplied: string;
  provenance?: ProvenanceInfo;
}

export interface ToolCheckRequest {
  toolName: string;
  arguments: Record<string, any>;
  sessionId?: string;
  requestedBy: string;
}

export interface ToolCheckResponse {
  decision: Decision;
  riskScore: number;
  reason: string;
  checksPassed: string[];
  checksFailed: string[];
}

export interface SessionState {
  sessionId: string;
  currentState: string;
  riskAccumulator: number;
  eventCount: number;
  flags: string[];
  startTime: string;
  lastActive: string;
}

export interface AuditRecord {
  id: string;
  request_id?: string;
  timestamp: string;
  action: string;
  resourceId?: string;
  decision: Decision | string;
  riskLevel?: RiskLevel | string;
  risk_level?: RiskLevel | string;
  riskScore?: number;
  risk_score?: number;
  prompt?: string;
  raw_prompt_hash?: string;
  has_pii?: boolean;
  pii_types?: string[];
  latency_ms?: number;
  source_type?: string;
  origin?: string;
  policy?: string;
  evidence?: any;
  decision_rationale?: any;
  policy_rules_applied?: string[];
  details?: any;
}

export interface DashboardMetrics {
  totalRequestsToday: number;
  blockedRequests: number;
  allowedRequests: number;
  sanitizedRequests: number;
  highRiskRequests: number;
  criticalRequests: number;
  avgLatencyMs: number;
  detectionRate: number;
  requestsOverTime: { timestamp: string; count: number; allowed?: number; blocked?: number }[];
  requests_last_24h?: number;
  requests_previous_24h?: number;
  blocks_last_24h?: number;
  blocks_previous_24h?: number;
  block_rate_last_24h?: number;
  block_rate_previous_24h?: number;
  gateway_p50_ms?: number;
  gateway_p95_ms?: number;
  gateway_p99_ms?: number;
  decisionDistribution: Record<Decision, number>;
  attackTypeDistribution: Record<AttackType, number>;
  riskScoreDistribution: { bucket: string; count: number }[];
}

export interface ThreatFeedItem {
  id: string;
  timestamp: string;
  sourceType: SourceType | string;
  attackTypes: AttackType[] | string[];
  riskLevel: RiskLevel | string;
  riskScore: number;
  decision: Decision | string;
  latencyMs: number;
  prompt?: string;
  hasPii?: boolean;
  rawPromptHash?: string;
}
