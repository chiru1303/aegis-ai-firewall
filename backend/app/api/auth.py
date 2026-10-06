import hmac
from fastapi import APIRouter, Request, Response, Depends, HTTPException
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from app.core.database import get_db
from app.core.tenant import resolve_tenant_context, hash_api_key, TenantContext, require_role
from app.core.browser_session import COOKIE_NAME, issue_session
from app.core.config import settings

router = APIRouter()


class LoginRequest(BaseModel):
    username: str = Field(min_length=1, max_length=128)
    password: str = Field(min_length=1, max_length=512)


def identity(ctx: TenantContext):
    user_name = "admin" if ctx.role == "superadmin" else (ctx.credential_name or ctx.tenant_name)
    return {"user": user_name, "role": ctx.role, "tenant": ctx.tenant_name,
            "expires_in": settings.SESSION_TTL_SECONDS}


@router.post("/login")
async def login(payload: LoginRequest, request: Request, response: Response, db=Depends(get_db)):
    username_ok = hmac.compare_digest(payload.username.encode(), settings.DASHBOARD_USERNAME.encode())
    password_ok = hmac.compare_digest(payload.password.encode(), settings.DASHBOARD_PASSWORD.encode())
    if not (username_ok and password_ok):
        raise HTTPException(status_code=401, detail="Invalid username or password")

    # The browser receives only a signed, HttpOnly session cookie; the credential
    # used by the server-side application is never placed in browser storage here.
    ctx = await resolve_tenant_context(request, x_api_key=settings.API_KEY, authorization=None, db=db)
    response.set_cookie(COOKIE_NAME, issue_session(hash_api_key(settings.API_KEY)),
                        httponly=True, secure=settings.COOKIE_SECURE, samesite="strict",
                        max_age=settings.SESSION_TTL_SECONDS, path="/")
    return identity(ctx)


@router.get("/session")
async def session(ctx: TenantContext = Depends(resolve_tenant_context)):
    return identity(ctx)


@router.get("/api-key")
async def get_api_key(ctx: TenantContext = Depends(require_role(["superadmin"]))):
    """Return the server key only to an authenticated superadmin on explicit request."""
    return JSONResponse(
        content={"api_key": settings.API_KEY},
        headers={"Cache-Control": "no-store, no-cache, must-revalidate", "Pragma": "no-cache"},
    )


@router.post("/logout")
async def logout(response: Response):
    response.delete_cookie(COOKIE_NAME, path="/")
    return {"status": "signed_out"}
