from __future__ import annotations

import json

import httpx
import pytest

from advent_prompt_pwn import (
    AnthropicTarget,
    AzureOpenAITarget,
    GeminiTarget,
    Message,
    OpenAITarget,
    Role,
)
from advent_prompt_pwn.exceptions import ConfigurationError, TargetError


def test_openai_and_azure_adapters_use_provider_specific_identity(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("OPENAI_API_KEY", "synthetic-openai")
    monkeypatch.setenv("AZURE_OPENAI_API_KEY", "synthetic-azure")

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["model"] in {"gpt-lab", "deployment-lab"}
        if request.url.host == "api.openai.com":
            assert request.headers["Authorization"] == "Bearer synthetic-openai"
        else:
            assert request.headers["api-key"] == "synthetic-azure"
            assert request.url.params["api-version"] == "2026-01-01"
        return httpx.Response(
            200,
            json={
                "id": "response",
                "model": body["model"],
                "choices": [{"finish_reason": "stop", "message": {"content": "safe"}}],
                "usage": {},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    openai = OpenAITarget("gpt-lab", client=client)
    azure = AzureOpenAITarget(
        "deployment-lab",
        resource="resource-lab",
        api_version="2026-01-01",
        client=client,
    )
    messages = [Message(Role.USER, "test")]
    assert openai.complete(messages, timeout_s=1).content == "safe"
    assert azure.complete(messages, timeout_s=1).content == "safe"
    assert openai.name == "openai:gpt-lab"
    assert "api-version=2026-01-01" in azure.endpoint
    assert azure.resume_identity["resource"] == "resource-lab"
    assert "synthetic-openai" in openai.sensitive_values
    assert "synthetic-azure" in azure.sensitive_values
    client.close()


def test_anthropic_adapter_normalizes_text_tools_and_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ANTHROPIC_API_KEY", "synthetic-anthropic")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-api-key"] == "synthetic-anthropic"
        assert request.headers["anthropic-version"] == "2023-06-01"
        body = json.loads(request.content)
        assert body["system"] == "system"
        assert body["messages"] == [{"role": "user", "content": "test"}]
        assert body["temperature"] == 0
        return httpx.Response(
            200,
            json={
                "id": "msg-1",
                "model": "claude-lab",
                "stop_reason": "tool_use",
                "content": [
                    {"type": "text", "text": "checking"},
                    {
                        "type": "tool_use",
                        "id": "tool-1",
                        "name": "lookup",
                        "input": {"query": "lab"},
                    },
                ],
                "usage": {"input_tokens": 10, "output_tokens": 5},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = AnthropicTarget("claude-lab", client=client, extra_body={"temperature": 0})
    response = target.complete(
        [Message(Role.SYSTEM, "system"), Message(Role.USER, "test")],
        timeout_s=1,
    )
    assert response.content == "checking"
    assert response.tool_calls[0].name == "lookup"
    assert response.tool_calls[0].arguments == '{"query": "lab"}'
    assert response.usage["input_tokens"] == 10
    assert target.resume_identity["max_tokens"] == 1024
    client.close()


def test_gemini_adapter_normalizes_parts_functions_and_usage(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("GEMINI_API_KEY", "synthetic-gemini")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["x-goog-api-key"] == "synthetic-gemini"
        body = json.loads(request.content)
        assert body["systemInstruction"]["parts"][0]["text"] == "system"
        assert body["generationConfig"] == {"temperature": 0}
        return httpx.Response(
            200,
            json={
                "candidates": [
                    {
                        "finishReason": "STOP",
                        "content": {
                            "parts": [
                                {"text": "checking"},
                                {"functionCall": {"name": "lookup", "args": {"id": 7}}},
                            ]
                        },
                    }
                ],
                "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 2},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = GeminiTarget(
        "gemini-lab",
        client=client,
        extra_body={"generationConfig": {"temperature": 0}},
    )
    response = target.complete(
        [Message(Role.SYSTEM, "system"), Message(Role.USER, "test")],
        timeout_s=1,
    )
    assert response.content == "checking"
    assert response.finish_reason == "STOP"
    assert response.tool_calls[0].call_id == "gemini-1"
    assert response.usage["promptTokenCount"] == 4
    assert target.endpoint.endswith("/gemini-lab:generateContent")
    client.close()


@pytest.mark.parametrize(
    "factory",
    [
        lambda client: AnthropicTarget("lab", api_key_env="MISSING_PROVIDER_KEY", client=client),
        lambda client: GeminiTarget("lab", api_key_env="MISSING_PROVIDER_KEY", client=client),
    ],
)
def test_provider_adapters_require_environment_credentials(
    factory: object,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MISSING_PROVIDER_KEY", raising=False)
    client = httpx.Client(transport=httpx.MockTransport(lambda request: httpx.Response(200)))
    target = factory(client)  # type: ignore[operator]
    with pytest.raises(ConfigurationError, match="not set"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_provider_configuration_and_malformed_responses_are_rejected(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    with pytest.raises(ConfigurationError, match="resource"):
        AzureOpenAITarget("deployment", resource="bad.name", api_version="v1")
    with pytest.raises(ConfigurationError, match="max_tokens"):
        AnthropicTarget("lab", max_tokens=0)
    with pytest.raises(ConfigurationError, match="base_url"):
        GeminiTarget("lab", base_url="")
    with pytest.raises(ConfigurationError, match="must not override"):
        AnthropicTarget("lab", extra_body={"messages": []})

    monkeypatch.setenv("PROVIDER_KEY", "synthetic")
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))
    )
    with pytest.raises(TargetError, match="Anthropic request failed"):
        AnthropicTarget("lab", api_key_env="PROVIDER_KEY", client=client).complete(
            [Message(Role.USER, "x")], timeout_s=1
        )
    with pytest.raises(TargetError, match="Gemini request failed"):
        GeminiTarget("lab", api_key_env="PROVIDER_KEY", client=client).complete(
            [Message(Role.USER, "x")], timeout_s=1
        )
    client.close()


def test_provider_http_errors_are_safely_wrapped(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PROVIDER_KEY", "synthetic")
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(503, text="secret body"))
    )
    with pytest.raises(TargetError, match="HTTP 503") as raised:
        AnthropicTarget("lab", api_key_env="PROVIDER_KEY", client=client).complete(
            [Message(Role.USER, "x")], timeout_s=1
        )
    assert "secret body" not in str(raised.value)
    client.close()
