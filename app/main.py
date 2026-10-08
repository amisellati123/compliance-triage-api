"""The REST API. Start it with `python -m app`, then open http://127.0.0.1:8000/docs"""
from __future__ import annotations

import logging
import uuid

from fastapi import Body, Depends, FastAPI, HTTPException, Query, Request, status

from .auth import Principal, issue_token, require
from .config import Settings, load_settings
from .models import AuditEntry, ClearedAction, Decision, Finding, FindingIn, Status
from .store import Conflict, NotFound, Store, now
from .triage import needs_approval, triage

log = logging.getLogger("api")

DESCRIPTION = """
Triage endpoint compliance findings with rules plus Claude, and hold every
high-impact fix until a human approves it.

All data in this project is synthetic. The service never touches real devices:
it stops at a list of actions that are cleared to run.
"""


def build_model_client(settings: Settings):
    """Return a Claude client, or None to run on rules only."""
    if not settings.anthropic_api_key:
        return None
    from anthropic import Anthropic

    return Anthropic(api_key=settings.anthropic_api_key, timeout=20.0, max_retries=2)


def create_app(settings: Settings | None = None, model_client=None) -> FastAPI:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(name)s %(message)s")
    settings = settings or load_settings()

    app = FastAPI(title="Compliance Triage API", version="0.1.0", description=DESCRIPTION)
    app.state.settings = settings
    app.state.store = Store(settings.audit_log_path)
    app.state.model_client = model_client or build_model_client(settings)
    log.info("triage mode: %s", "claude" if app.state.model_client else "rules only")

    app.post("/oauth/token", tags=["auth"], summary="Get an access token")(issue_token)

    @app.get("/healthz", tags=["health"])
    def health() -> dict:
        return {"status": "ok"}

    @app.post(
        "/findings",
        tags=["findings"],
        status_code=status.HTTP_201_CREATED,
        response_model=list[Finding],
        summary="Submit findings for triage",
    )
    def submit(
        request: Request,
        findings: list[FindingIn] = Body(..., min_length=1),
        who: Principal = Depends(require("findings:write")),
    ) -> list[Finding]:
        if len(findings) > settings.max_batch:
            raise HTTPException(
                413,
                f"At most {settings.max_batch} findings per request",
            )
        store: Store = request.app.state.store
        results = []
        for item in findings:
            result = triage(item, request.app.state.model_client, settings.claude_model)
            approval = needs_approval(result)
            finding = Finding(
                **item.model_dump(),
                id=uuid.uuid4().hex,
                triage=result,
                requires_approval=approval,
                status=Status.pending_approval if approval else Status.ready,
                submitted_by=who.client_id,
                created_at=now(),
            )
            store.add(finding)
            store.audit(
                "finding_triaged",
                actor=who.client_id,
                finding_id=finding.id,
                detail={
                    "risk": result.risk.value,
                    "action": result.action.value,
                    "source": result.source,
                    "requires_approval": approval,
                },
            )
            results.append(finding)
        return results

    @app.get("/findings", tags=["findings"], response_model=list[Finding])
    def list_findings(
        request: Request,
        status_filter: Status | None = Query(None, alias="status"),
        who: Principal = Depends(require("findings:read")),
    ) -> list[Finding]:
        return request.app.state.store.list(status_filter)

    @app.get("/findings/{finding_id}", tags=["findings"], response_model=Finding)
    def get_finding(
        request: Request, finding_id: str, who: Principal = Depends(require("findings:read"))
    ) -> Finding:
        try:
            return request.app.state.store.get(finding_id)
        except NotFound:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found") from None

    def decide(request: Request, finding_id: str, approve: bool, who: Principal, comment: str):
        store: Store = request.app.state.store
        try:
            finding = store.decide(finding_id, approve, who.client_id, comment)
        except NotFound:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "Finding not found") from None
        except Conflict as exc:
            raise HTTPException(status.HTTP_409_CONFLICT, str(exc)) from None
        except PermissionError as exc:
            raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from None
        store.audit(
            "fix_approved" if approve else "fix_rejected",
            actor=who.client_id,
            finding_id=finding.id,
            detail={"action": finding.triage.action.value, "comment": comment},
        )
        return finding

    @app.post("/findings/{finding_id}/approve", tags=["approval"], response_model=Finding)
    def approve(
        request: Request,
        finding_id: str,
        decision: Decision = Body(default_factory=Decision),
        who: Principal = Depends(require("findings:approve")),
    ) -> Finding:
        return decide(request, finding_id, True, who, decision.comment)

    @app.post("/findings/{finding_id}/reject", tags=["approval"], response_model=Finding)
    def reject(
        request: Request,
        finding_id: str,
        decision: Decision = Body(default_factory=Decision),
        who: Principal = Depends(require("findings:approve")),
    ) -> Finding:
        return decide(request, finding_id, False, who, decision.comment)

    @app.get(
        "/actions",
        tags=["approval"],
        response_model=list[ClearedAction],
        summary="Actions cleared to run",
    )
    def cleared_actions(
        request: Request, who: Principal = Depends(require("findings:read"))
    ) -> list[ClearedAction]:
        """Only low-impact fixes and fixes a human approved ever appear here."""
        cleared = []
        for f in request.app.state.store.list():
            if f.status is Status.ready:
                cleared.append(_cleared(f, "policy"))
            elif f.status is Status.approved:
                cleared.append(_cleared(f, f.decided_by or "unknown"))
        return cleared

    @app.get("/audit", tags=["audit"], response_model=list[AuditEntry])
    def audit_log(
        request: Request, who: Principal = Depends(require("audit:read"))
    ) -> list[AuditEntry]:
        return request.app.state.store.audit_entries()

    return app


def _cleared(finding: Finding, cleared_by: str) -> ClearedAction:
    return ClearedAction(
        finding_id=finding.id,
        device_id=finding.device_id,
        action=finding.triage.action,
        cleared_by=cleared_by,
    )
