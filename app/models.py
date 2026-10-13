"""Data shapes. Pydantic rejects anything that does not match before our code runs."""
from __future__ import annotations

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, ConfigDict, Field


class Platform(str, Enum):
    windows = "windows"
    macos = "macos"
    ios = "ios"
    android = "android"


class Issue(str, Enum):
    not_synced = "not_synced"
    os_out_of_date = "os_out_of_date"
    # The scanner (Bandit B105) mistakes this label for a password. It is not one.
    password_policy_missing = "password_policy_missing"  # nosec B105
    firewall_off = "firewall_off"
    antivirus_unhealthy = "antivirus_unhealthy"
    encryption_off = "encryption_off"
    jailbroken_or_rooted = "jailbroken_or_rooted" 
    usb_storage_enabled = "usb_storage_enabled"



class Risk(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Action(str, Enum):
    notify_user = "notify_user"
    force_sync = "force_sync"
    push_os_update = "push_os_update"
    # Same false positive as above: a label, not a password.
    enforce_password_policy = "enforce_password_policy"  # nosec B105
    enable_firewall = "enable_firewall"
    repair_antivirus = "repair_antivirus"
    enable_encryption = "enable_encryption"
    restrict_access = "restrict_access"
    retire_device = "retire_device" 
    block_usb_storage = "block_usb_storage"




class Status(str, Enum):
    ready = "ready"                        # low impact, cleared without approval
    pending_approval = "pending_approval"  # waiting for a human
    approved = "approved"
    rejected = "rejected"


class FindingIn(BaseModel):
    """One non-compliant device, as an analyst would submit it."""

    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9._-]+$")
    device_name: str = Field(min_length=1, max_length=64)
    owner: str = Field(min_length=1, max_length=128)
    platform: Platform
    issue: Issue
    days_non_compliant: int = Field(ge=0, le=3650)
    privileged_user: bool = False
    # Free text copied from the device record. Treated as untrusted everywhere.
    note: str = Field(default="", max_length=500)


class Triage(BaseModel):
    risk: Risk
    action: Action
    rationale: str
    source: str  # "claude" or "rules"
    # What the fixed rules said, so a reviewer can see where the model differed.
    policy_risk: Risk
    policy_action: Action
    fallback_reason: str | None = None


class Finding(FindingIn):
    id: str
    triage: Triage
    requires_approval: bool
    status: Status
    submitted_by: str
    created_at: datetime
    decided_by: str | None = None
    decided_at: datetime | None = None
    decision_comment: str | None = None


class Decision(BaseModel):
    model_config = ConfigDict(extra="forbid")

    comment: str = Field(default="", max_length=300)


class ClearedAction(BaseModel):
    """An action that is allowed to run: low impact, or approved by a human."""

    finding_id: str
    device_id: str
    action: Action
    cleared_by: str


class AuditEntry(BaseModel):
    ts: datetime
    actor: str
    event: str
    finding_id: str | None = None
    detail: dict = Field(default_factory=dict)
