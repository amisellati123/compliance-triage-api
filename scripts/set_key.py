"""Add your Claude API key without it ever showing on screen, then prove it works.

Run:  python scripts/set_key.py

It asks for the key with hidden input, checks the key with one tiny request, saves it
in .env, restarts the API, runs the demo and tells you whether Claude was used.
"""
import getpass
import re
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from make_env import ENV_PATH, new_env_text, write_env  # noqa: E402

LOG = Path("/tmp/app.log")
KEY_LINE = re.compile(r"(?m)^ANTHROPIC_API_KEY=(.*)$")
MODEL_LINE = re.compile(r"(?m)^CLAUDE_MODEL=(.+)$")
SECRET_NAMES = ("JWT_SECRET", "ANALYST_CLIENT_SECRET", "APPROVER_CLIENT_SECRET")


def read_env() -> str:
    """Return the .env text, or a fresh one if the file is missing or damaged."""
    text = ENV_PATH.read_text(encoding="utf-8") if ENV_PATH.exists() else ""
    healthy = all(re.search(rf"(?m)^{name}=\S{{32,}}$", text) for name in SECRET_NAMES)
    return text if healthy else new_env_text()


def looks_like_key(value: str) -> bool:
    return value.startswith("sk-ant-") and len(value) > 40 and not re.search(r"\s", value)


def ask_for_key(saved: str) -> str:
    print("\nPaste your Claude API key below, then press Enter.")
    print("Nothing appears while you paste. That is normal.")
    if saved:
        print("(To reuse the key that is already saved, just press Enter.)")
    print()
    for _ in range(3):
        key = getpass.getpass("Key: ").strip()
        if not key and saved:
            return saved
        if looks_like_key(key):
            return key
        print("That does not look like a Claude API key. It should start with sk-ant-. Try again.\n")
    raise SystemExit("No valid key entered. Nothing was changed.")


def check_key(key: str, model: str) -> str:
    """One tiny request, so a bad key or an empty balance is explained in plain words."""
    import anthropic

    try:
        anthropic.Anthropic(api_key=key, timeout=20.0, max_retries=1).messages.create(
            model=model, max_tokens=5, messages=[{"role": "user", "content": "Reply with OK."}]
        )
    except anthropic.AuthenticationError:
        print("\nClaude did not accept this key. Create a new key in the Console and run this again.")
        return "rejected"
    except anthropic.APIStatusError as exc:
        print(f"\nClaude answered with an error ({exc.status_code}): {exc.message}")
        return "problem"
    except anthropic.APIConnectionError:
        print("\nCould not reach Claude. Check the connection and run this again.")
        return "problem"
    print("\nClaude accepted the key.")
    return "ok"


def restart_app() -> None:
    subprocess.run(["pkill", "-f", r"python[0-9.]* -m app"], check=False)
    time.sleep(1)
    with LOG.open("w") as log:
        subprocess.Popen(
            [sys.executable, "-m", "app"], cwd=ROOT, stdout=log, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    for _ in range(40):
        try:
            urllib.request.urlopen("http://127.0.0.1:8000/healthz", timeout=1)  # noqa: S310
            return
        except OSError:
            time.sleep(0.5)
    raise SystemExit(f"The API did not start. Look at {LOG} for the reason.")


def report() -> None:
    text = LOG.read_text(errors="replace")
    failures = re.findall(r"model call failed, using rules: (\w+)", text)
    print("=" * 72)
    if "triage mode: claude" in text and not failures:
        print("RESULT: Claude was used for every finding. The source column says claude.")
    elif failures:
        kinds = ", ".join(sorted(set(failures)))
        print(f"RESULT: Claude failed on {len(failures)} finding(s) ({kinds}). The rules were used instead.")
    else:
        print("RESULT: the API is still running on rules only.")
    print("=" * 72)


def main() -> None:
    text = read_env()
    saved = KEY_LINE.search(text)
    saved_key = saved.group(1).strip() if saved else ""
    key = ask_for_key(saved_key if looks_like_key(saved_key) else "")
    model = (MODEL_LINE.search(text) or [None, "claude-haiku-5-5"])[1].strip()

    outcome = check_key(key, model)
    if outcome == "rejected":
        raise SystemExit(1)

    line = "ANTHROPIC_API_KEY=" + key
    text = KEY_LINE.sub(lambda m: line, text) if saved else text.rstrip("\n") + "\n" + line + "\n"
    write_env(text)
    print("Saved the key in .env. That file is never uploaded to GitHub.")
    if outcome == "problem":
        print("Fix the problem above, then run this again and press Enter to reuse the saved key.")
        raise SystemExit(1)

    print("Restarting the API and running the demo...\n")
    restart_app()
    subprocess.run([sys.executable, str(ROOT / "scripts" / "demo.py")], check=False)
    report()


if __name__ == "__main__":
    main()
