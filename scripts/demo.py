"""Walk through the whole flow against a running server.

Terminal 1:  python -m app
Terminal 2:  python scripts/demo.py
"""
import json
import os
import sys
from pathlib import Path

import httpx
from dotenv import load_dotenv

ROOT = Path(__file__).resolve().parent.parent
load_dotenv(ROOT / ".env")
BASE = os.environ.get("API_URL", "http://127.0.0.1:8000")


def token(api: httpx.Client, role: str) -> dict:
    response = api.post(
        "/oauth/token",
        data={
            "grant_type": "client_credentials",
            "client_id": os.environ.get(f"{role}_CLIENT_ID", role.lower()),
            "client_secret": os.environ[f"{role}_CLIENT_SECRET"],
        },
    )
    response.raise_for_status()
    return {"Authorization": f"Bearer {response.json()['access_token']}"}


def main() -> None:
    with httpx.Client(base_url=BASE, timeout=120) as api:
        try:
            api.get("/healthz").raise_for_status()
        except httpx.HTTPError:
            sys.exit(f"The API is not running at {BASE}. Start it first with: python -m app")

        analyst, approver = token(api, "ANALYST"), token(api, "APPROVER")
        sample = json.loads((ROOT / "sample_data" / "findings.json").read_text())

        print(f"\n1. Analyst submits {len(sample)} findings\n")
        findings = api.post("/findings", json=sample, headers=analyst).json()
        print(f"   {'device':<13}{'issue':<26}{'risk':<8}{'action':<26}{'status':<18}source")
        for f in findings:
            t = f["triage"]
            print(f"   {f['device_id']:<13}{f['issue']:<26}{t['risk']:<8}{t['action']:<26}{f['status']:<18}{t['source']}")

        cleared = api.get("/actions", headers=analyst).json()
        pending = [f for f in findings if f["status"] == "pending_approval"]
        print(f"\n2. Cleared to run right away: {len(cleared)}. Waiting for a human: {len(pending)}.")

        denied = api.post(f"/findings/{pending[0]['id']}/approve", headers=analyst)
        print(f"\n3. Analyst tries to approve their own finding -> HTTP {denied.status_code} ({denied.json()['detail']})")

        print("\n4. Approver reviews the queue")
        for f in pending:
            t = f["triage"]
            # Approve when the action matches policy, reject when the model went its own way.
            verb = "approve" if t["action"] == t["policy_action"] else "reject"
            done = api.post(f"/findings/{f['id']}/{verb}", json={"comment": "demo review"}, headers=approver).json()
            print(f"   {f['device_id']:<13}{t['action']:<20}-> {done['status']}")
            print(f"      why: {t['rationale']}")

        cleared = api.get("/actions", headers=analyst).json()
        print(f"\n5. Cleared to run now: {len(cleared)}")
        for a in cleared:
            print(f"   {a['device_id']:<13}{a['action']:<26}cleared by {a['cleared_by']}")

        audit = api.get("/audit", headers=approver).json()
        print(f"\n6. Audit log has {len(audit)} entries. Last three:")
        for e in audit[-3:]:
            print(f"   {e['ts'][:19]}  {e['actor']:<9} {e['event']}")
        print()


if __name__ == "__main__":
    main()
