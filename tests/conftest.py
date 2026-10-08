"""Shared test helpers. No test calls the real Claude API."""
from __future__ import annotations

import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.config import ANALYST_SCOPES, APPROVER_SCOPES, Client, Settings
from app.main import create_app

ANALYST = Client("analyst", "a" * 40, ANALYST_SCOPES)
APPROVER = Client("approver", "b" * 40, APPROVER_SCOPES)


def make_settings(**overrides) -> Settings:
    values = dict(
        jwt_secret="j" * 48,
        clients={ANALYST.client_id: ANALYST, APPROVER.client_id: APPROVER},
        audit_log_path=None,
    )
    values.update(overrides)
    return Settings(**values)


class FakeClaude:
    """Stands in for the Anthropic client and records what it was sent."""

    def __init__(self, reply=None, stop_reason="end_turn", error=None):
        self.reply = reply
        self.stop_reason = stop_reason
        self.error = error
        self.calls: list[dict] = []
        self.messages = self

    def create(self, **kwargs):
        self.calls.append(kwargs)
        if self.error:
            raise self.error
        text = self.reply if isinstance(self.reply, str) else json.dumps(self.reply)
        return SimpleNamespace(
            stop_reason=self.stop_reason,
            content=[SimpleNamespace(type="text", text=text)],
        )


def make_api(model=None, **settings_overrides) -> TestClient:
    return TestClient(create_app(make_settings(**settings_overrides), model_client=model))


def token_for(api: TestClient, client: Client) -> str:
    response = api.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": client.client_id,
            "client_secret": client.secret,
        },
    )
    assert response.status_code == 200, response.text
    return response.json()["access_token"]


def bearer(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


def finding(**overrides) -> dict:
    values = dict(
        device_id="LAPTOP-0001",
        device_name="Sample laptop",
        owner="user01@example.com",
        platform="windows",
        issue="not_synced",
        days_non_compliant=3,
        privileged_user=False,
        note="",
    )
    values.update(overrides)
    return values


@pytest.fixture
def api() -> TestClient:
    """The API running on rules only (no model)."""
    return make_api()


@pytest.fixture
def analyst(api) -> dict:
    return bearer(token_for(api, ANALYST))


@pytest.fixture
def approver(api) -> dict:
    return bearer(token_for(api, APPROVER))
