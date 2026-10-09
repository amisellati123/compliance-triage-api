"""Create a .env file with freshly generated secrets. Run once: python scripts/make_env.py"""
import secrets
from pathlib import Path

ENV_PATH = Path(__file__).resolve().parent.parent / ".env"


def new_env_text() -> str:
    return "\n".join(
        [
            f"JWT_SECRET={secrets.token_urlsafe(48)}",
            "ANALYST_CLIENT_ID=analyst",
            f"ANALYST_CLIENT_SECRET={secrets.token_urlsafe(32)}",
            "APPROVER_CLIENT_ID=approver",
            f"APPROVER_CLIENT_SECRET={secrets.token_urlsafe(32)}",
            "# Optional. Run `python scripts/set_key.py` to add a Claude API key.",
            "ANTHROPIC_API_KEY=",
            "CLAUDE_MODEL=claude-haiku-5-5",
            "",
        ]
    )


def write_env(text: str) -> None:
    ENV_PATH.write_text(text, encoding="utf-8")
    ENV_PATH.chmod(0o600)


def main() -> None:
    if ENV_PATH.exists():
        raise SystemExit(".env already exists. Delete it first if you want new secrets.")
    write_env(new_env_text())
    print("Wrote .env with new secrets. It is ignored by git. Do not share it.")


if __name__ == "__main__":
    main()
