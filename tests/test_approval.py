"""The approval gate: high-impact fixes wait for a human."""
from tests.conftest import finding


def submit(api, analyst, **overrides) -> dict:
    response = api.post("/findings", json=[finding(**overrides)], headers=analyst)
    assert response.status_code == 201, response.text
    return response.json()[0]


def cleared_ids(api, headers) -> set:
    return {a["finding_id"] for a in api.get("/actions", headers=headers).json()}


def test_low_impact_fix_is_cleared_without_approval(api, analyst):
    item = submit(api, analyst, issue="not_synced", days_non_compliant=3)
    assert item["triage"]["risk"] == "low" and item["triage"]["action"] == "force_sync"
    assert item["requires_approval"] is False and item["status"] == "ready"
    assert item["id"] in cleared_ids(api, analyst)


def test_high_risk_fix_waits_until_a_human_approves(api, analyst, approver):
    item = submit(api, analyst, issue="jailbroken_or_rooted", platform="ios")
    assert item["triage"]["action"] == "restrict_access"
    assert item["requires_approval"] is True and item["status"] == "pending_approval"
    assert item["id"] not in cleared_ids(api, analyst)

    decided = api.post(
        f"/findings/{item['id']}/approve", json={"comment": "Confirmed with the user"}, headers=approver
    ).json()
    assert decided["status"] == "approved" and decided["decided_by"] == "approver"
    assert decided["decision_comment"] == "Confirmed with the user"

    actions = api.get("/actions", headers=analyst).json()
    assert {"finding_id": item["id"], "device_id": "LAPTOP-0001", "action": "restrict_access", "cleared_by": "approver"} in actions


def test_rejected_fix_is_never_cleared(api, analyst, approver):
    item = submit(api, analyst, issue="encryption_off")
    response = api.post(f"/findings/{item['id']}/reject", headers=approver)
    assert response.json()["status"] == "rejected"
    assert item["id"] not in cleared_ids(api, analyst)


def test_a_decision_cannot_be_changed_or_made_on_a_cleared_finding(api, analyst, approver):
    pending = submit(api, analyst, issue="antivirus_unhealthy")
    assert api.post(f"/findings/{pending['id']}/approve", headers=approver).status_code == 200
    assert api.post(f"/findings/{pending['id']}/reject", headers=approver).status_code == 409
    ready = submit(api, analyst, issue="not_synced")
    assert api.post(f"/findings/{ready['id']}/approve", headers=approver).status_code == 409


def test_unknown_finding_returns_404(api, analyst, approver):
    assert api.get("/findings/does-not-exist", headers=analyst).status_code == 404
    assert api.post("/findings/does-not-exist/approve", headers=approver).status_code == 404


def test_list_can_be_filtered_by_status(api, analyst):
    submit(api, analyst, issue="not_synced")
    submit(api, analyst, issue="encryption_off")
    pending = api.get("/findings", params={"status": "pending_approval"}, headers=analyst).json()
    assert [f["issue"] for f in pending] == ["encryption_off"]
    assert len(api.get("/findings", headers=analyst).json()) == 2


def test_audit_log_records_triage_and_decision(api, analyst, approver):
    item = submit(api, analyst, issue="encryption_off")
    api.post(f"/findings/{item['id']}/approve", headers=approver)
    entries = [e for e in api.get("/audit", headers=approver).json() if e["finding_id"] == item["id"]]
    assert [(e["event"], e["actor"]) for e in entries] == [
        ("finding_triaged", "analyst"),
        ("fix_approved", "approver"),
    ]
    assert entries[0]["detail"] == {
        "risk": "high", "action": "enable_encryption", "source": "rules", "requires_approval": True,
    }


def test_audit_log_is_also_written_to_disk(tmp_path, monkeypatch):
    import json

    from tests.conftest import ANALYST, bearer, make_api, token_for

    path = tmp_path / "audit.log"
    api = make_api(audit_log_path=str(path))
    headers = bearer(token_for(api, ANALYST))
    api.post("/findings", json=[finding()], headers=headers)
    events = [json.loads(line)["event"] for line in path.read_text().splitlines()]
    assert events == ["token_issued", "finding_triaged"]


def test_bad_input_is_rejected_before_triage(api, analyst):
    for bad in (
        finding(issue="made_up_issue"),
        finding(note="x" * 501),
        finding(device_id="LAPTOP 0001; rm -rf /"),
        finding(days_non_compliant=-1),
        {**finding(), "status": "approved"},        # callers cannot set the status
        {**finding(), "requires_approval": False},  # or switch the gate off
    ):
        assert api.post("/findings", json=[bad], headers=analyst).status_code == 422
    assert api.post("/findings", json=[], headers=analyst).status_code == 422


def test_batch_size_is_limited(api, analyst):
    too_many = [finding(device_id=f"LAPTOP-{n:04d}") for n in range(51)]
    assert api.post("/findings", json=too_many, headers=analyst).status_code == 413
    assert api.post("/findings", json=too_many[:50], headers=analyst).status_code == 201
