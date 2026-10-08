"""Create a .env file with freshly generated secrets. Run once: python scripts/make_env.py"""
import secrets
from pathlib import Path

path = Path(__file__).resolve().parent.parent / ".env"
if path.exists():
    raise SystemExit(".env already exists. Delete it first if you want new secrets.")

path.write_text(
    "\n".join(
        [
            f"JWT_SECRET={secrets.token_urlsafe(48)}",
            "ANALYST_CLIENT_ID=analyst",
            f"ANALYST_CLIENT_SECRET={secrets.token_urlsafe(32)}",
            "APPROVER_CLIENT_ID=approver",
            f"APPROVER_CLIENT_SECRET={secrets.token_urlsafe(32)}",
            "# Optional. Paste a Claude API key here to turn on Claude triage.",
            "ANTHROPIC_API_KEY=",
            "CLAUDE_MODEL=claude-haiku-5-5",
            "",
        ]
    ),
    encoding="utf-8",
)
path.chmod(0o600)
print("Wrote .env with new secrets. It is ignored by git. Do not share it.")
