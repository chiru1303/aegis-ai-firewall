"""Defense in depth: tenant identity attached by authentication scopes ORM access."""
from sqlalchemy import event, or_
from sqlalchemy.orm import Session, with_loader_criteria


@event.listens_for(Session, "do_orm_execute")
def tenant_scope(execute_state):
    info = execute_state.session.info
    if not info.get("tenant_id") or info.get("role") == "superadmin" or execute_state.execution_options.get("platform_query"):
        return
    from app.models.database_models import (
        RequestModel, AuditLogModel, SessionModel, ToolRequestModel, ApplicationModel,
        ConnectorModel, ApiCredentialModel, AuditOutboxModel, UserModel, PolicyModel,
    )
    tenant_id = info["tenant_id"]
    for model in (RequestModel, AuditLogModel, SessionModel, ToolRequestModel, ApplicationModel,
                  ConnectorModel, ApiCredentialModel, AuditOutboxModel, UserModel):
        execute_state.statement = execute_state.statement.options(
            with_loader_criteria(model, model.tenant_id == tenant_id, include_aliases=True))
    execute_state.statement = execute_state.statement.options(
        with_loader_criteria(PolicyModel, or_(PolicyModel.tenant_id == tenant_id, PolicyModel.tenant_id.is_(None)), include_aliases=True))
