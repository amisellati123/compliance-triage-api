"""Settings come from environment variables. Nothing secret lives in the code."""
from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

MIN_SECRET_LENGTH = 32

# What each client is allowed to do. The two roles do not overlap on purpose:
# whoever submits findings cannot approve fixes.
ANALYST_SCOPES = ("findings:read", "findings:write")
APPROVER_SCOPES = ("findings:read", "findings:approve", "audit:read")


@dataclass(frozen=True)
class Client:
    client_id: str
    secret: str
    scopes: tuple[str, ...]


@dataclass(frozen=True)
class Settings:
    jwt_secret: str
    clients: dict[str, Client]
    token_ttl_seconds: int = 900
    anthropic_api_key: str | None = None
    claude_model: str = "claude-haiku-5-5"
    audit_log_path: str | None = "audit.log"
    max_batch: int = 50


def _secret(name: str) -> str:
    value = os.environ.get(name, "")
    if len(value) < MIN_SECRET_LENGTH:
        raise RuntimeError(
            f"{name} is missing or shorter than {MIN_SECRET_LENGTH} characters. "
            "Run `python scripts/make_env.py` to create a .env file."
        )
    return value


def load_settings() -> Settings:
    """Read settings from the environment (and from .env if present)."""
    load_dotenv()
    analyst = Client(
        os.environ.get("ANALYST_CLIENT_ID", "analyst"),
        _secret("ANALYST_CLIENT_SECRET"),
        ANALYST_SCOPES,
    )
    approver = Client(
        os.environ.get("APPROVER_CLIENT_ID", "approver"),
        _secret("APPROVER_CLIENT_SECRET"),
        APPROVER_SCOPES,
    )
    if analyst.client_id == approver.client_id:
        raise RuntimeError("ANALYST_CLIENT_ID and APPROVER_CLIENT_ID must be different.")
    return Settings(
        jwt_secret=_secret("JWT_SECRET"),
        clients={analyst.client_id: analyst, approver.client_id: approver},
        anthropic_api_key=os.environ.get("ANTHROPIC_API_KEY") or None,
        claude_model=os.environ.get("CLAUDE_MODEL") or "claude-haiku-5-5",
        audit_log_path=os.environ.get("AUDIT_LOG_PATH") or "audit.log",
    )
