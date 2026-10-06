from sqlalchemy import Column, String, Integer, Float, Boolean, DateTime, ForeignKey, JSON, Text
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from app.core.database import Base
from app.core.time import now_ist, now_utc


class TenantModel(Base):
    """Multi-tenant isolation root model."""
    __tablename__ = "tenants"

    id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    slug = Column(String(128), unique=True, index=True, nullable=False)
    tier = Column(String(32), default="standard")  # standard, pro, enterprise
    is_active = Column(Boolean, default=True)
    config_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    applications = relationship("ApplicationModel", back_populates="tenant", cascade="all, delete-orphan")
    connectors = relationship("ConnectorModel", back_populates="tenant", cascade="all, delete-orphan")
    api_credentials = relationship("ApiCredentialModel", back_populates="tenant", cascade="all, delete-orphan")
    users = relationship("UserModel", back_populates="tenant", cascade="all, delete-orphan")
    policies = relationship("PolicyModel", back_populates="tenant")


class ApplicationModel(Base):
    """Application owned by a tenant."""
    __tablename__ = "applications"

    id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id"), index=True, nullable=False)
    name = Column(String(255), nullable=False)
    slug = Column(String(128), index=True, nullable=False)
    description = Column(String(512), nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("TenantModel", back_populates="applications")
    environments = relationship("EnvironmentModel", back_populates="application", cascade="all, delete-orphan")


class EnvironmentModel(Base):
    """Deployment environment (e.g. dev, staging, prod) within an application."""
    __tablename__ = "environments"

    id = Column(String(64), primary_key=True, index=True)
    application_id = Column(String(64), ForeignKey("applications.id"), index=True, nullable=False)
    name = Column(String(64), nullable=False)  # development, staging, production
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    application = relationship("ApplicationModel", back_populates="environments")


class ConnectorModel(Base):
    """
    Ingress / Egress connector configuration.
    The connector configuration on the server determines authoritative trust level.
    Untrusted input cannot change its own trust level.
    """
    __tablename__ = "connectors"

    id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id"), index=True, nullable=False)
    name = Column(String(255), nullable=False)
    connector_type = Column(String(64), nullable=False)  # web_chat, agent_slack, api_gateway, internal_rag, document_pipeline
    default_trust_level = Column(String(32), default="UNTRUSTED")  # TRUSTED, SEMI_TRUSTED, UNTRUSTED, MALICIOUS
    auth_type = Column(String(32), default="api_key")
    config_json = Column(JSON, default=dict)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("TenantModel", back_populates="connectors")


class ApiCredentialModel(Base):
    """
    API keys used for Data Plane ingestion and Control Plane administration.
    Only hashed keys are stored. Trust is bound to the credential's tenant/app/connector mapping.
    """
    __tablename__ = "api_credentials"

    id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id"), index=True, nullable=False)
    application_id = Column(String(64), ForeignKey("applications.id"), index=True, nullable=True)
    environment_id = Column(String(64), ForeignKey("environments.id"), index=True, nullable=True)
    connector_id = Column(String(64), ForeignKey("connectors.id"), index=True, nullable=True)
    key_hash = Column(String(64), unique=True, index=True, nullable=False)  # SHA-256
    key_prefix = Column(String(16), index=True, nullable=False)  # e.g. aegis_live_abc123...
    name = Column(String(255), nullable=False)
    role = Column(String(64), default="data_plane")  # data_plane, admin, security_analyst, read_only
    is_active = Column(Boolean, default=True)
    expires_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    last_used_at = Column(DateTime(timezone=True), nullable=True)

    tenant = relationship("TenantModel", back_populates="api_credentials")


class UserModel(Base):
    """Control plane user accounts."""
    __tablename__ = "users"

    id = Column(String(64), primary_key=True, index=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id"), index=True, nullable=False)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(64), default="security_analyst")  # superadmin, tenant_admin, security_analyst, viewer
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    tenant = relationship("TenantModel", back_populates="users")


class PolicyModel(Base):
    """
    Hierarchical Policy Model:
    Scoping: GLOBAL -> TENANT -> APPLICATION -> ENVIRONMENT
    Mandatory policies cannot be overridden by lower scopes.
    """
    __tablename__ = "policies"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    tenant_id = Column(String(64), ForeignKey("tenants.id"), index=True, nullable=True)  # Null for GLOBAL
    scope = Column(String(32), default="GLOBAL")  # GLOBAL, TENANT, APPLICATION, ENVIRONMENT
    scope_id = Column(String(64), index=True, nullable=True)
    priority = Column(Integer, default=100)  # Lower number = higher precedence
    is_mandatory = Column(Boolean, default=False)  # If True, lower scopes cannot override
    name = Column(String(255), nullable=False)
    description = Column(String(512), nullable=True)
    rules_json = Column(JSON, default=dict)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    tenant = relationship("TenantModel", back_populates="policies")


class RequestModel(Base):
    """Request and decision evaluation log."""
    __tablename__ = "requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, nullable=True, default="tenant_default")
    application_id = Column(String(64), index=True, nullable=True)
    environment_id = Column(String(64), index=True, nullable=True)
    connector_id = Column(String(64), index=True, nullable=True)
    session_id = Column(String(128), index=True, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=now_utc, server_default=func.now())
    source_type = Column(String(64))
    origin = Column(String(255))
    trust_level = Column(String(32))  # Authoritative server-derived trust
    content_hash = Column(String(64))
    content_type = Column(String(64))
    decision = Column(String(32))  # ALLOW, SANITIZE, BLOCK, QUARANTINE, REQUIRE_REVIEW
    risk_score = Column(Float)
    risk_level = Column(String(32))
    confidence = Column(Float)
    attack_types_json = Column(JSON, default=list)
    policy = Column(String(128))
    latency_ms = Column(Float)  # legacy backward-compatible field
    gateway_overhead_ms = Column(Float, default=0.0)
    upstream_llm_ms = Column(Float, default=0.0)
    total_ms = Column(Float, default=0.0)
    trace_id = Column(String(64))
    prompt = Column(Text, nullable=True)  # Captured prompt with PII/secrets masked
    raw_prompt_hash = Column(String(64), nullable=True)  # SHA-256 of original raw prompt


class DetectionModel(Base):
    """Individual detector findings per request."""
    __tablename__ = "detections"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id = Column(String(64), index=True, nullable=False)
    detector_name = Column(String(128), nullable=False)
    attack_type = Column(String(128))
    confidence = Column(Float)
    matched_signal = Column(Text)
    severity = Column(String(32))
    raw_evidence_json = Column(JSON, default=dict)


class SessionModel(Base):
    """Stateful multi-step session trajectory tracker."""
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(String(128), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, nullable=True, default="tenant_default")
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())
    state = Column(String(64), default="NORMAL")
    risk_accumulator = Column(Float, default=0.0)
    event_count = Column(Integer, default=0)
    metadata_json = Column(JSON, default=dict)


class SessionEventModel(Base):
    """Events recorded during session trajectory."""
    __tablename__ = "session_events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    session_id = Column(String(128), index=True, nullable=False)
    event_index = Column(Integer, default=0)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())
    event_type = Column(String(64))
    content_hash = Column(String(64))
    risk_contribution = Column(Float, default=0.0)
    state_transition = Column(String(128))


class ProvenanceModel(Base):
    """Provenance tracking content lineages."""
    __tablename__ = "provenance"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    content_id = Column(String(64), unique=True, index=True, nullable=False)
    source_type = Column(String(64))
    origin = Column(String(255))
    trust_level = Column(String(32))
    received_at = Column(DateTime(timezone=True), server_default=func.now())
    parent_content_id = Column(String(64), nullable=True)
    transformation_chain_json = Column(JSON, default=list)


class ToolRequestModel(Base):
    """Tool firewall invocation log."""
    __tablename__ = "tool_requests"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id = Column(String(64), index=True, nullable=False)
    tenant_id = Column(String(64), index=True, nullable=True, default="tenant_default")
    session_id = Column(String(128), index=True, nullable=True)
    tool_name = Column(String(128), nullable=False)
    arguments_json = Column(JSON, default=dict)
    requested_by = Column(String(128))
    decision = Column(String(32))
    reason = Column(Text)
    risk_score = Column(Float)
    timestamp = Column(DateTime(timezone=True), server_default=func.now())


class AuditLogModel(Base):
    """
    Immutable audit log with SHA-256 hash chaining for tamper evidence.
    """
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    request_id = Column(String(64), index=True, nullable=False)
    tenant_id = Column(String(64), index=True, nullable=True, default="tenant_default")
    session_id = Column(String(128), index=True, nullable=True)
    timestamp = Column(DateTime(timezone=True), default=now_utc, server_default=func.now())
    action = Column(String(64), default="scan")
    decision = Column(String(32), nullable=False)
    risk_score = Column(Float, nullable=False)
    evidence_json = Column(JSON, default=dict)
    policy = Column(String(128))
    latency_ms = Column(Float)  # legacy backward-compatible field
    gateway_overhead_ms = Column(Float, default=0.0)
    upstream_llm_ms = Column(Float, default=0.0)
    total_ms = Column(Float, default=0.0)
    source_type = Column(String(64))
    origin = Column(String(255))
    hash_chain = Column(String(64), nullable=True)  # SHA-256(prev_hash + entry_data)
    prompt = Column(Text, nullable=True)  # Captured prompt with PII/secrets masked
    raw_prompt_hash = Column(String(64), nullable=True)  # SHA-256 of original raw prompt


class AuditOutboxModel(Base):
    """
    Durable Audit Outbox pattern:
    Decision and Outbox are committed in the same database transaction.
    Background publisher ships outbox events to telemetry, SIEM, or Kafka without loss.
    """
    __tablename__ = "audit_outbox"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    tenant_id = Column(String(64), index=True, nullable=True, default="tenant_default")
    event_type = Column(String(64), nullable=False)  # DECISION_RECORDED, THREAT_BLOCKED, TOOL_INVOKED
    payload_json = Column(JSON, nullable=False)
    status = Column(String(32), default="PENDING", index=True)  # PENDING, PUBLISHED, FAILED
    retry_count = Column(Integer, default=0)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    processed_at = Column(DateTime(timezone=True), nullable=True)
