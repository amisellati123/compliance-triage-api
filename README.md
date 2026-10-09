# Compliance Triage API

A small REST API that triages endpoint compliance findings with fixed rules plus
Claude, and holds every high-impact fix until a human approves it.

AI is useful for sorting a long list of security findings. It should not be the thing
that decides to lock a user out or retire a device. This project shows one way to get
the help while keeping that decision with policy and people.

All data here is synthetic. The service never touches real devices. It stops at a
list of actions that are cleared to run.

## How it works

```
analyst client                         approver client
     |                                       |
     | 1. POST /oauth/token                  |
     | 2. POST /findings                     |
     v                                       |
 validate input  ->  rules set the minimum risk
                 ->  Claude suggests risk, action and a reason (optional)
                 ->  policy merges the two: the model can raise risk, never lower it
                 ->  code decides whether a human must approve
     |                                       |
     |-- low impact ------> ready            |
     |-- high risk or high-impact action --> pending_approval
                                             | 3. POST /findings/{id}/approve or /reject
                                             v
 4. GET /actions returns only fixes that are ready or approved
 every step is written to the audit log
```

## Security controls

| Control | Where | Proved by |
|---|---|---|
| OAuth 2.0 client-credentials flow, signed tokens that expire after 15 minutes, per-route scopes | `app/auth.py` | `tests/test_auth.py` |
| Separation of duties: analysts submit, approvers decide, and nobody decides their own finding | `app/config.py`, `app/store.py` | `tests/test_auth.py` |
| Strict input validation. Unknown fields are rejected, so a caller cannot set `status` or switch approval off | `app/models.py` | `tests/test_approval.py` |
| Human approval gate decided in code for any high-risk finding or high-impact action | `app/triage.py` (`needs_approval`) | `tests/test_approval.py` |
| Model treated as untrusted: no tools, answer checked against a schema, can raise risk but never lower it | `app/triage.py` | `tests/test_prompt_injection.py` |
| Prompt-injection handling: finding sent as escaped data, device owner never sent to the model | `app/triage.py` (`build_user_message`) | `tests/test_prompt_injection.py` |
| Fail safe: if the model errors, refuses or returns bad output, the rules are used | `app/triage.py` (`triage`) | `tests/test_triage.py`, `tests/test_sdk_integration.py` |
| Audit log of tokens, denials, triage results and decisions | `app/store.py` | `tests/test_approval.py` |
| Secrets only in environment variables, minimum length enforced, `.env` ignored by git | `app/config.py` | `tests/test_auth.py` |
| CI on every push: tests, static security scan (Bandit), dependency audit (pip-audit) | `.github/workflows/ci.yml` | GitHub Actions |

## Run it

Needs Python 3.10 or newer. Tested on 3.12 and 3.13.

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python scripts/make_env.py       # writes .env with fresh random secrets
python -m pytest -q              # 56 tests, no API key needed
python -m app                    # starts the API on http://127.0.0.1:8000
```

Then, in a second terminal:

```bash
source .venv/bin/activate
python scripts/demo.py           # runs the whole flow and prints each step
```

Interactive docs are at http://127.0.0.1:8000/docs. Click **Authorize**, enter a
client id and secret from your `.env`, and you can call every endpoint from the page.

In GitHub Codespaces the same commands work. Skip the two `venv` lines.

## Turn on Claude

Without an API key the service runs on the rules alone, and every result shows
`"source": "rules"`.

1. Create an API key in the Claude Console: https://platform.claude.com/settings/keys
2. Run `python scripts/set_key.py` and paste the key when it asks. The key is never shown
   on screen. The script checks it, saves it in `.env`, restarts the API and runs the demo.

Results now show `"source": "claude"` with a short reason from the model. Two of the
sample findings carry prompt-injection text in their note, so you can watch what the
model does with them and see the approval gate hold either way.

The default model is `claude-haiku-5-5`. Change it with `CLAUDE_MODEL`. The model
receives the device id and name, platform, issue, days open, privileged flag and note.
It never receives the owner.

## API

| Method and path | Scope | What it does |
|---|---|---|
| `POST /oauth/token` | none | Trade a client id and secret for an access token |
| `POST /findings` | `findings:write` | Submit 1 to 50 findings for triage |
| `GET /findings`, `GET /findings/{id}` | `findings:read` | Read results. Filter with `?status=pending_approval` |
| `POST /findings/{id}/approve` | `findings:approve` | Approve a pending fix |
| `POST /findings/{id}/reject` | `findings:approve` | Reject a pending fix |
| `GET /actions` | `findings:read` | Fixes cleared to run |
| `GET /audit` | `audit:read` | The audit log |
| `GET /healthz` | none | Liveness check |

## Limits

This is a learning project, not a production service.

- Findings live in memory and are lost on restart. Only the audit log is written to disk.
- Tokens are signed with one shared secret (HS256). A real deployment would use an
  identity provider such as Microsoft Entra ID and asymmetric keys.
- There is no rate limiting.
- It does not run the fixes. There is no connection to Intune or any device system.
- The audit log is append-only by design, but the file is not tamper-proof.
- The prompt-injection tests prove the controls hold when the model is fully tricked.
  They do not measure how often a real model is tricked.
- It is not deployed anywhere yet. Next steps: a container image, a cloud deployment
  defined in Terraform, and an infrastructure scan in CI.

## How it was built

Built with Claude as the coding assistant. See `docs/WALKTHROUGH.md` for a plain
explanation of every part.
