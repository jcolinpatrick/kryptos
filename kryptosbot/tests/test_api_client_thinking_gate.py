"""Thinking-gate regression tests for the direct-Anthropic API path.

GOTCHA2: enabling extended thinking on opus-4-8 makes long sessions die with
an API 400 once thinking blocks stop round-tripping. The SDK path fixes this
via ``pantheon.thinking_config_for_model`` ({"type": "disabled"} for opus-4-8).
The direct-Anthropic path in ``api_client._make_api_call`` must apply the same
policy: never enable extended thinking for opus-4-8. These tests pin that
policy by capturing the kwargs handed to ``client.messages.create``.
"""

from types import SimpleNamespace

from kryptosbot.api_client import KryptosAPIClient


def _install_capture(client: KryptosAPIClient) -> dict:
    """Replace messages.create with a capture stub; return the capture dict."""
    captured: dict = {}

    def _fake_create(**kwargs):
        captured.update(kwargs)
        return SimpleNamespace(
            content=[SimpleNamespace(type="text", text="[]")],
            usage=SimpleNamespace(
                input_tokens=10,
                output_tokens=5,
                cache_read_input_tokens=0,
                cache_creation_input_tokens=0,
            ),
        )

    client.client.messages.create = _fake_create  # type: ignore[assignment]
    return captured


def test_opus_4_8_never_enables_extended_thinking():
    client = KryptosAPIClient(api_key="test-key", model="claude-opus-4-8")
    captured = _install_capture(client)

    client._make_api_call([{"role": "user", "content": "hi"}], thinking_budget=8000)

    assert "thinking" not in captured, (
        "opus-4-8 must not enable extended thinking (GOTCHA2 long-session crash)"
    )


def test_other_opus_generation_still_enables_thinking_when_requested():
    # Regression guard: the fix must NARROW the gate to opus-4-8 only, not
    # disable thinking everywhere. opus-4-7 should still honour the budget.
    client = KryptosAPIClient(api_key="test-key", model="claude-opus-4-7")
    captured = _install_capture(client)

    client._make_api_call([{"role": "user", "content": "hi"}], thinking_budget=8000)

    assert captured.get("thinking") == {"type": "enabled", "budget_tokens": 8000}


def test_sonnet_4_6_also_excludes_thinking():
    # The exclusion list is {opus-4-6, opus-4-8, sonnet-4-6}; sonnet-4-6 is the
    # default model, so pin that it too never enables extended thinking.
    client = KryptosAPIClient(api_key="test-key", model="claude-sonnet-4-6")
    captured = _install_capture(client)

    client._make_api_call([{"role": "user", "content": "hi"}], thinking_budget=8000)

    assert "thinking" not in captured


def test_fable_5_never_sends_a_thinking_param():
    # Fable 5 (controller routing default since 2026-06-10) removes
    # budget_tokens AND 400s on an explicit {"type": "disabled"} — the only
    # safe request shape is to omit the thinking param entirely.
    client = KryptosAPIClient(api_key="test-key", model="claude-fable-5")
    captured = _install_capture(client)

    client._make_api_call([{"role": "user", "content": "hi"}], thinking_budget=8000)

    assert "thinking" not in captured


def test_fable_5_priced_in_api_client_pricing_table():
    # PRICING.get falls back to SONNET rates on a miss, so an absent
    # claude-fable-5 key would silently under-charge frontier-tier work.
    from kryptosbot.api_client import PRICING

    fable = PRICING.get("claude-fable-5")
    assert fable is not None, "claude-fable-5 missing from api_client.PRICING"
    assert fable["input"] == 10.0
    assert fable["output"] == 50.0
