"""Findings held in memory, plus an append-only audit log on disk.

Memory is enough for a demo. A real deployment would use a database.
"""
from __future__ import annotations

import threading
from datetime import datetime, timezone

from .models import AuditEntry, Finding, Status


class NotFound(Exception):
    pass


class Conflict(Exception):
    pass


def now() -> datetime:
    return datetime.now(timezone.utc)


class Store:
    def __init__(self, audit_log_path: str | None):
        self._findings: dict[str, Finding] = {}
        self._audit: list[AuditEntry] = []
        self._audit_log_path = audit_log_path
        self._lock = threading.Lock()

    # ---- findings ----------------------------------------------------------
    def add(self, finding: Finding) -> None:
        with self._lock:
            self._findings[finding.id] = finding

    def get(self, finding_id: str) -> Finding:
        with self._lock:
            try:
                return self._findings[finding_id]
            except KeyError:
                raise NotFound(finding_id) from None

    def list(self, status: Status | None = None) -> list[Finding]:
        with self._lock:
            items = list(self._findings.values())
        return [f for f in items if status is None or f.status is status]

    def decide(self, finding_id: str, approve: bool, actor: str, comment: str) -> Finding:
        """Record a human decision. Only pending findings can be decided, once."""
        with self._lock:
            finding = self._findings.get(finding_id)
            if finding is None:
                raise NotFound(finding_id)
            if finding.status is not Status.pending_approval:
                raise Conflict(f"finding is {finding.status.value}, not pending approval")
            if finding.submitted_by == actor:
                raise PermissionError("the submitter cannot decide their own finding")
            updated = finding.model_copy(
                update={
                    "status": Status.approved if approve else Status.rejected,
                    "decided_by": actor,
                    "decided_at": now(),
                    "decision_comment": comment or None,
                }
            )
            self._findings[finding_id] = updated
            return updated

    # ---- audit -------------------------------------------------------------
    def audit(
        self, event: str, actor: str, finding_id: str | None = None, detail: dict | None = None
    ) -> None:
        entry = AuditEntry(
            ts=now(), actor=actor, event=event, finding_id=finding_id, detail=detail or {}
        )
        with self._lock:
            self._audit.append(entry)
            if self._audit_log_path:
                with open(self._audit_log_path, "a", encoding="utf-8") as fh:
                    fh.write(entry.model_dump_json() + "\n")

    def audit_entries(self) -> list[AuditEntry]:
        with self._lock:
            return list(self._audit)
