"""Who can get in, and what each role can do."""
import time

import jwt

from app.auth import ALGORITHM, ISSUER
from app.config import Client
from tests.conftest import ANALYST, APPROVER, bearer, finding, make_api, make_settings, token_for


def test_health_needs_no_token(api):
    assert api.get("/healthz").json() == {"status": "ok"}


def test_token_issued_for_valid_client(api):
    response = api.post(
        "/oauth/token",
        data={"grant_type": "client_credentials", "client_id": "analyst", "client_secret": "a" * 40},
    )
    body = response.json()
    assert response.status_code == 200
    assert body["token_type"] == "bearer" and body["expires_in"] == 900
    assert body["scope"] == "findings:read findings:write"
    assert response.headers["cache-control"] == "no-store"


def test_token_accepts_http_basic_credentials(api):
    response = api.post(
        "/oauth/token", data={"grant_type": "client_credentials"}, auth=("approver", "b" * 40)
    )
    assert response.status_code == 200
    assert "findings:approve" in response.json()["scope"]


def test_token_refused_for_wrong_secret_unknown_client_or_missing_credentials(api):
    for data in (
        {"client_id": "analyst", "client_secret": "wrong"},
        {"client_id": "nobody", "client_secret": "a" * 40},
        {},
    ):
        response = api.post("/oauth/token", data={"grant_type": "client_credentials", **data})
        assert response.status_code == 401
        assert response.json() == {"error": "invalid_client"}


def test_other_grant_types_are_refused(api):
    response = api.post(
        "/oauth/token",
        data={"grant_type": "password", "client_id": "analyst", "client_secret": "a" * 40},
    )
    assert response.status_code == 400
    assert response.json() == {"error": "unsupported_grant_type"}


def test_every_data_endpoint_requires_a_token(api):
    for method, path in (
        ("get", "/findings"),
        ("post", "/findings"),
        ("get", "/findings/abc"),
        ("post", "/findings/abc/approve"),
        ("post", "/findings/abc/reject"),
        ("get", "/actions"),
        ("get", "/audit"),
    ):
        response = getattr(api, method)(path)
        assert response.status_code == 401, path
        assert response.headers["www-authenticate"] == "Bearer"


def test_tampered_expired_and_wrong_issuer_tokens_are_refused(api):
    secret = "j" * 48
    now = int(time.time())
    claims = {"iss": ISSUER, "sub": "approver", "scope": "findings:approve audit:read", "iat": now}
    forged = jwt.encode({**claims, "exp": now + 60}, "k" * 48, algorithm=ALGORITHM)
    expired = jwt.encode({**claims, "iat": now - 120, "exp": now - 60}, secret, algorithm=ALGORITHM)
    other_issuer = jwt.encode({**claims, "iss": "someone-else", "exp": now + 60}, secret, algorithm=ALGORITHM)
    no_expiry = jwt.encode(claims, secret, algorithm=ALGORITHM)
    unsigned = jwt.encode({**claims, "exp": now + 60}, None, algorithm="none")
    for token in (forged, expired, other_issuer, no_expiry, unsigned, "not-a-token"):
        assert api.get("/audit", headers=bearer(token)).status_code == 401


def test_analyst_cannot_approve_or_read_audit(api, analyst):
    created = api.post("/findings", json=[finding(issue="jailbroken_or_rooted")], headers=analyst).json()
    finding_id = created[0]["id"]
    assert api.post(f"/findings/{finding_id}/approve", headers=analyst).status_code == 403
    assert api.post(f"/findings/{finding_id}/reject", headers=analyst).status_code == 403
    assert api.get("/audit", headers=analyst).status_code == 403


def test_approver_cannot_submit_findings(api, approver):
    assert api.post("/findings", json=[finding()], headers=approver).status_code == 403


def test_submitter_cannot_approve_their_own_finding_even_with_both_scopes():
    both = Client("combined", "c" * 40, ("findings:read", "findings:write", "findings:approve"))
    api = make_api(clients={ANALYST.client_id: ANALYST, APPROVER.client_id: APPROVER, "combined": both})
    combined = bearer(token_for(api, both))
    created = api.post("/findings", json=[finding(issue="encryption_off")], headers=combined).json()
    response = api.post(f"/findings/{created[0]['id']}/approve", headers=combined)
    assert response.status_code == 403
    # A different approver still can.
    other = bearer(token_for(api, APPROVER))
    assert api.post(f"/findings/{created[0]['id']}/approve", headers=other).status_code == 200


def test_denied_access_is_written_to_the_audit_log(api, analyst, approver):
    api.get("/audit", headers=analyst)
    events = [(e["event"], e["actor"]) for e in api.get("/audit", headers=approver).json()]
    assert ("access_denied", "analyst") in events


def test_settings_reject_short_secrets(monkeypatch):
    import pytest

    from app import config

    monkeypatch.setattr(config, "load_dotenv", lambda: None)
    monkeypatch.setenv("JWT_SECRET", "short")
    monkeypatch.setenv("ANALYST_CLIENT_SECRET", "a" * 40)
    monkeypatch.setenv("APPROVER_CLIENT_SECRET", "b" * 40)
    with pytest.raises(RuntimeError, match="JWT_SECRET"):
        config.load_settings()
    assert make_settings().token_ttl_seconds == 900
