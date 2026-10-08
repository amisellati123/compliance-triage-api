"""Run the real Anthropic SDK against a fake Claude server on this machine.

This checks that the request we build is one the SDK accepts and that we read
its response objects correctly. No internet and no API key are needed.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from anthropic import Anthropic

from app.models import Action, FindingIn, Risk
from app.triage import SUGGESTION_SCHEMA, triage
from tests.conftest import finding


class FakeClaudeServer:
    """A tiny local HTTP server that answers like the Messages API."""

    def __init__(self):
        self.reply_text = "{}"
        self.stop_reason = "end_turn"
        self.status = 200
        self.seen: dict = {}
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):  # noqa: N802 - name required by http.server
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                outer.seen = {"path": self.path, "body": body}
                if outer.status != 200:
                    payload = {"type": "error", "error": {"type": "overloaded_error", "message": "busy"}}
                else:
                    payload = {
                        "id": "msg_test",
                        "type": "message",
                        "role": "assistant",
                        "model": body["model"],
                        "content": [{"type": "text", "text": outer.reply_text}],
                        "stop_reason": outer.stop_reason,
                        "stop_sequence": None,
                        "usage": {"input_tokens": 120, "output_tokens": 40},
                    }
                data = json.dumps(payload).encode()
                self.send_response(outer.status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def log_message(self, *args):  # keep test output quiet
                pass

        self.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    @property
    def url(self) -> str:
        return f"http://127.0.0.1:{self.httpd.server_address[1]}"

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture
def server(monkeypatch):
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    fake = FakeClaudeServer()
    yield fake
    fake.close()


def sdk_client(server: FakeClaudeServer) -> Anthropic:
    return Anthropic(api_key="test-key-not-real", base_url=server.url, max_retries=0, timeout=5.0)


def test_real_sdk_round_trip(server):
    server.reply_text = json.dumps(
        {"risk": "high", "action": "restrict_access", "rationale": "Rooted phone."}
    )
    item = FindingIn(**finding(issue="jailbroken_or_rooted", platform="android"))

    result = triage(item, sdk_client(server), "claude-haiku-5-5")

    assert (result.risk, result.action, result.source) == (Risk.high, Action.restrict_access, "claude")
    assert result.fallback_reason is None
    assert server.seen["path"] == "/v1/messages"
    body = server.seen["body"]
    assert body["model"] == "claude-haiku-5-5" and body["max_tokens"] == 300
    assert body["output_config"] == {"format": {"type": "json_schema", "schema": SUGGESTION_SCHEMA}}
    assert body["system"].startswith("You triage endpoint compliance findings")
    assert body["messages"][0]["role"] == "user"
    assert body["messages"][0]["content"].startswith("<finding>")
    assert "tools" not in body


def test_real_sdk_refusal_falls_back_to_rules(server):
    server.reply_text, server.stop_reason = "", "refusal"
    result = triage(FindingIn(**finding(issue="encryption_off")), sdk_client(server), "claude-haiku-5-5")
    assert (result.risk, result.action, result.source) == (Risk.high, Action.enable_encryption, "rules")
    assert result.fallback_reason == "ModelOutputError"


def test_real_sdk_api_error_falls_back_to_rules(server):
    server.status = 529
    result = triage(FindingIn(**finding(issue="not_synced")), sdk_client(server), "claude-haiku-5-5")
    assert (result.risk, result.source) == (Risk.low, "rules")
    assert result.fallback_reason is not None
