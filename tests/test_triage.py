"""The rules, and how Claude's answer is checked before it is used."""
import json

import pytest

from app.models import Action, FindingIn, Issue, Risk
from app.triage import (
    RULES,
    SUGGESTION_SCHEMA,
    SYSTEM_PROMPT,
    ModelOutputError,
    ask_claude,
    build_user_message,
    needs_approval,
    rules_triage,
    triage,
)
from tests.conftest import FakeClaude, finding


def make(**overrides) -> FindingIn:
    return FindingIn(**finding(**overrides))


@pytest.mark.parametrize(
    "issue, risk, action",
    [
        ("not_synced", Risk.low, Action.force_sync),
        ("os_out_of_date", Risk.medium, Action.push_os_update),
        ("password_policy_missing", Risk.medium, Action.enforce_password_policy),
        ("firewall_off", Risk.medium, Action.enable_firewall),
        ("antivirus_unhealthy", Risk.high, Action.repair_antivirus),
        ("encryption_off", Risk.high, Action.enable_encryption),
        ("jailbroken_or_rooted", Risk.high, Action.restrict_access), ("usb_storage_enabled", Risk.medium, Action.block_usb_storage),
    ],
)
def test_rules_cover_every_issue(issue, risk, action):
    result = rules_triage(make(issue=issue))
    assert (result.risk, result.action, result.source) == (risk, action, "rules")


def test_no_issue_type_is_missing_a_rule():
    # If you add an Issue and forget its rule, this fails instead of the API crashing later.
    assert set(RULES) == set(Issue)
    assert all(isinstance(risk, Risk) and isinstance(action, Action) for risk, action in RULES.values())


def test_rules_raise_risk_one_level_for_privileged_users_and_stale_findings():
    assert rules_triage(make(issue="not_synced", privileged_user=True)).risk is Risk.medium
    assert rules_triage(make(issue="os_out_of_date", days_non_compliant=45)).risk is Risk.high
    # Both together still raise only one level.
    both = rules_triage(make(issue="not_synced", privileged_user=True, days_non_compliant=45))
    assert both.risk is Risk.medium
    assert "privileged access and it has been open" in both.rationale


def test_high_risk_and_high_impact_actions_need_approval():
    assert needs_approval(rules_triage(make(issue="encryption_off")))
    assert needs_approval(rules_triage(make(issue="jailbroken_or_rooted")))
    assert not needs_approval(rules_triage(make(issue="os_out_of_date")))
    assert not needs_approval(rules_triage(make(issue="not_synced")))


def test_claude_suggestion_is_used_when_valid():
    model = FakeClaude({"risk": "medium", "action": "notify_user", "rationale": "Brief  gap,\nask the user to reconnect."})
    result = triage(make(issue="not_synced"), model, "claude-haiku-5-5")
    assert (result.risk, result.action, result.source) == (Risk.medium, Action.notify_user, "claude")
    assert result.rationale == "Brief gap, ask the user to reconnect."
    assert (result.policy_risk, result.policy_action) == (Risk.low, Action.force_sync)


def test_request_sent_to_claude_has_the_expected_shape():
    model = FakeClaude({"risk": "low", "action": "force_sync", "rationale": "ok"})
    triage(make(), model, "claude-haiku-5-5")
    call = model.calls[0]
    assert call["model"] == "claude-haiku-5-5" and call["max_tokens"] == 300
    assert call["system"] == SYSTEM_PROMPT
    assert call["output_config"] == {"format": {"type": "json_schema", "schema": SUGGESTION_SCHEMA}}
    assert [m["role"] for m in call["messages"]] == ["user"]
    assert "tools" not in call  # the model is given nothing it could act with


def test_owner_is_never_sent_to_the_model():
    message = build_user_message(make(owner="jane.doe@example.com"))
    assert "jane.doe" not in message and "owner" not in message
    data = json.loads(message.removeprefix("<finding>\n").removesuffix("\n</finding>"))
    assert data["device_id"] == "LAPTOP-0001" and data["issue"] == "not_synced"


def test_enum_casing_from_the_model_is_normalised():
    model = FakeClaude({"risk": "HIGH", "action": " Restrict_Access ", "rationale": "Rooted device."})
    result = triage(make(issue="jailbroken_or_rooted"), model, "m")
    assert (result.risk, result.action) == (Risk.high, Action.restrict_access)


@pytest.mark.parametrize(
    "reply",
    [
        "I cannot help with that.",
        "[]",
        {"risk": "critical", "action": "force_sync", "rationale": "x"},
        {"risk": "low", "action": "wipe_everything", "rationale": "x"},
        {"risk": "low", "action": "force_sync"},
        {"risk": "low", "action": "force_sync", "rationale": ""},
        {"risk": "low", "action": "force_sync", "rationale": "x" * 401},
        {"risk": "low", "action": "force_sync", "rationale": "x", "status": "approved"},
    ],
)
def test_output_that_does_not_match_the_schema_is_rejected(reply):
    with pytest.raises(ModelOutputError):
        ask_claude(make(), FakeClaude(reply), "m")


@pytest.mark.parametrize("stop_reason", ["refusal", "max_tokens"])
def test_refusal_or_cut_off_answer_is_rejected(stop_reason):
    model = FakeClaude({"risk": "low", "action": "force_sync", "rationale": "x"}, stop_reason=stop_reason)
    with pytest.raises(ModelOutputError):
        ask_claude(make(), model, "m")


def test_any_model_failure_falls_back_to_rules():
    for model in (
        FakeClaude("not json"),
        FakeClaude({"risk": "low"}, stop_reason="refusal"),
        FakeClaude(error=TimeoutError("model timed out")),
    ):
        result = triage(make(issue="encryption_off"), model, "m")
        assert (result.risk, result.action, result.source) == (Risk.high, Action.enable_encryption, "rules")
        assert result.fallback_reason in ("ModelOutputError", "TimeoutError")
