from __future__ import annotations

import gzip
import json
from collections.abc import Sequence

import httpx
import pytest

from advent_prompt_pwn import FakeTarget, FunctionTarget, Message, Role, TargetResponse
from advent_prompt_pwn.exceptions import ConfigurationError, TargetError
from advent_prompt_pwn.targets import HttpJsonTarget, OllamaTarget, OpenAICompatibleTarget


def test_fake_and_function_targets() -> None:
    messages = [Message(Role.USER, "hello")]
    assert FakeTarget("fixed").complete(messages, timeout_s=1).content == "fixed"
    target = FunctionTarget(lambda sent: TargetResponse(str(len(sent))), name="app")
    assert target.endpoint == "function://app"
    assert target.complete(messages, timeout_s=1).content == "1"


def test_default_http_clients_ignore_proxy_environment() -> None:
    targets = (
        OpenAICompatibleTarget(model="lab", base_url="https://example.test/v1"),
        OllamaTarget("lab"),
        HttpJsonTarget(
            endpoint="https://example.test/chat",
            response_path="response",
        ),
    )
    try:
        assert all(target._client._trust_env is False for target in targets)
    finally:
        for target in targets:
            target.close()


def test_http_json_target_rejects_host_header_override() -> None:
    with pytest.raises(ConfigurationError, match="must not override Host"):
        HttpJsonTarget(
            endpoint="https://example.test/chat",
            response_path="response",
            headers_env={"Host": "APPWN_HOST"},
        )


def test_openai_compatible_target_normalizes_response(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("LAB_API_KEY", "synthetic-key")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer synthetic-key"
        body = json.loads(request.content)
        assert body["model"] == "lab-model"
        assert body["temperature"] == 0
        return httpx.Response(
            200,
            json={
                "id": "response-1",
                "model": "lab-model-v2",
                "choices": [
                    {
                        "finish_reason": "tool_calls",
                        "message": {
                            "content": "",
                            "tool_calls": [
                                {
                                    "id": "call-1",
                                    "function": {"name": "send_email", "arguments": "{}"},
                                }
                            ],
                        },
                    }
                ],
                "usage": {"prompt_tokens": 3, "completion_tokens": 2},
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = OpenAICompatibleTarget(
        model="lab-model",
        base_url="http://127.0.0.1:8000/v1/",
        api_key_env="LAB_API_KEY",
        client=client,
        extra_body={"temperature": 0},
    )
    response = target.complete([Message(Role.USER, "test")], timeout_s=1)
    assert target.endpoint == "http://127.0.0.1:8000/v1/chat/completions"
    assert response.model == "lab-model-v2"
    assert response.tool_calls[0].name == "send_email"
    assert response.usage["prompt_tokens"] == 3
    target.close()
    client.close()


def test_openai_target_requires_configured_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("MISSING_KEY", raising=False)
    target = OpenAICompatibleTarget(
        model="lab",
        base_url="http://localhost:8000/v1",
        api_key_env="MISSING_KEY",
    )
    with pytest.raises(ConfigurationError, match="not set"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    target.close()


def test_http_targets_validate_models_and_response_limits() -> None:
    with pytest.raises(ConfigurationError, match="model"):
        OpenAICompatibleTarget(model="", base_url="http://localhost")
    with pytest.raises(ConfigurationError, match="base_url"):
        OpenAICompatibleTarget(model="lab", base_url="")
    with pytest.raises(ConfigurationError, match="model"):
        OllamaTarget("")
    with pytest.raises(ConfigurationError, match="max_response"):
        OllamaTarget("lab", max_response_bytes=0)

    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"choices": [{"message": {"content": "too large"}}]},
            )
        )
    )
    target = OpenAICompatibleTarget(
        model="lab",
        base_url="http://localhost/v1",
        max_response_bytes=1,
        client=client,
    )
    with pytest.raises(TargetError, match="exceeded"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_http_response_limit_rejects_declared_oversize_before_read() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                headers={"Content-Length": "1000"},
                content=b"{}",
            )
        )
    )
    target = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        max_response_bytes=100,
        client=client,
    )
    with pytest.raises(TargetError, match="exceeded"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_http_targets_force_identity_encoding_and_reject_compressed_responses() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Accept-Encoding"] == "identity"
        return httpx.Response(
            200,
            headers={"Content-Encoding": "gzip"},
            content=gzip.compress(b"{}"),
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        client=client,
    )
    with pytest.raises(TargetError, match="content encoding"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_http_total_deadline_is_enforced(monkeypatch: pytest.MonkeyPatch) -> None:
    import advent_prompt_pwn.targets.http as http_module

    first = True

    def monotonic() -> float:
        nonlocal first
        if first:
            first = False
            return 0.0
        return 2.0

    monkeypatch.setattr(http_module.time, "monotonic", monotonic)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"answer": "safe"})
        )
    )
    target = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        client=client,
    )
    with pytest.raises(TargetError, match="total 1s deadline"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


@pytest.mark.parametrize(
    "payload",
    [
        {"choices": [{"message": []}]},
        {"choices": [{"message": {"content": "safe", "tool_calls": ["bad"]}}]},
        {"choices": [{"message": {"content": "safe"}}], "usage": {"tokens": True}},
    ],
)
def test_openai_target_wraps_malformed_response_types(payload: object) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json=payload))
    )
    target = OpenAICompatibleTarget(
        model="lab",
        base_url="http://localhost/v1",
        client=client,
    )
    with pytest.raises(TargetError, match="request failed"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


@pytest.mark.parametrize("content", [False, 0, []])
def test_openai_target_does_not_coerce_falsy_malformed_content(content: object) -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"choices": [{"message": {"content": content}}]},
            )
        )
    )
    target = OpenAICompatibleTarget(
        model="lab",
        base_url="http://localhost/v1",
        client=client,
    )
    with pytest.raises(TargetError, match="content must be a string"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_http_target_wraps_transport_errors() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="failed")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = OpenAICompatibleTarget(
        model="lab",
        base_url="http://localhost:8000/v1",
        client=client,
    )
    with pytest.raises(TargetError, match="returned HTTP 500"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_http_status_errors_do_not_disclose_endpoint_query_values() -> None:
    secret = "OPAQUE_PATH_TEST"

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, request=request, text="failed")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = OpenAICompatibleTarget(
        model="lab",
        base_url=f"http://localhost:8000/v1?tenant={secret}",
        client=client,
    )
    with pytest.raises(TargetError) as raised:
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    assert secret not in str(raised.value)
    client.close()


def test_ollama_target_normalizes_response() -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        assert body["stream"] is False
        return httpx.Response(
            200,
            json={
                "model": "llama-lab",
                "message": {"content": "safe"},
                "done_reason": "stop",
                "prompt_eval_count": 8,
                "eval_count": 4,
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = OllamaTarget("llama-lab", client=client)
    response = target.complete([Message(Role.USER, "test")], timeout_s=1)
    assert response.content == "safe"
    assert response.usage == {"prompt_tokens": 8, "completion_tokens": 4}
    client.close()


def test_ollama_target_wraps_invalid_response() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={}))
    )
    target = OllamaTarget("lab", client=client)
    with pytest.raises(TargetError, match="Ollama"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_fake_callback_may_return_target_response() -> None:
    def callback(messages: Sequence[Message]) -> TargetResponse:
        return TargetResponse(content=messages[0].content, model="callback")

    response = FakeTarget(callback).complete([Message(Role.USER, "echo")], timeout_s=1)
    assert response.model == "callback"


def test_http_json_target_supports_custom_application_shape(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("LAB_HEADER", "synthetic-token")

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["X-Lab-Key"] == "synthetic-token"
        body = json.loads(request.content)
        assert body == {"tenant": "lab", "prompt": "test"}
        return httpx.Response(
            200,
            json={
                "data": {"answer": "LAB_MARKER"},
                "actions": [{"id": "1", "name": "send", "arguments": {"to": "lab"}}],
            },
        )

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = HttpJsonTarget(
        endpoint="https://app.example.test/ask",
        response_path="data.answer",
        request_mode="prompt",
        request_field="prompt",
        headers_env={"X-Lab-Key": "LAB_HEADER"},
        extra_body={"tenant": "lab"},
        tool_calls_path="actions",
        client=client,
    )
    response = target.complete([Message(Role.USER, "test")], timeout_s=1)
    assert response.content == "LAB_MARKER"
    assert response.tool_calls[0].arguments == '{"to": "lab"}'
    assert target.supports_concurrency
    client.close()


def test_http_json_target_rejects_bad_configuration() -> None:
    with pytest.raises(ConfigurationError, match="request_mode"):
        HttpJsonTarget(endpoint="https://example.test", response_path="x", request_mode="bad")
    with pytest.raises(ConfigurationError, match="override"):
        HttpJsonTarget(
            endpoint="https://example.test",
            response_path="x",
            extra_body={"messages": []},
        )


def test_http_json_target_wraps_missing_response_path() -> None:
    client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"other": "x"}))
    )
    target = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        client=client,
    )
    with pytest.raises(TargetError, match="HTTP JSON"):
        target.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_http_json_target_handles_object_content_and_missing_inputs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("MISSING_HEADER", raising=False)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"answer": {"safe": True}})
        )
    )
    target = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        request_mode="prompt",
        client=client,
    )
    response = target.complete([Message(Role.USER, "test")], timeout_s=1)
    assert response.content == '{"safe": true}'
    with pytest.raises(TargetError, match="user message"):
        target.complete([Message(Role.SYSTEM, "system")], timeout_s=1)
    missing_header = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        headers_env={"X-Key": "MISSING_HEADER"},
        client=client,
    )
    with pytest.raises(ConfigurationError, match="not set"):
        missing_header.complete([Message(Role.USER, "test")], timeout_s=1)
    client.close()


def test_http_json_target_rejects_oversized_and_invalid_tool_responses() -> None:
    oversized_client = httpx.Client(
        transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"answer": "large"}))
    )
    oversized = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        max_response_bytes=1,
        client=oversized_client,
    )
    with pytest.raises(TargetError, match="exceeded"):
        oversized.complete([Message(Role.USER, "test")], timeout_s=1)
    oversized_client.close()

    invalid_client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={"answer": "safe", "calls": "invalid"},
            )
        )
    )
    invalid = HttpJsonTarget(
        endpoint="https://example.test",
        response_path="answer",
        tool_calls_path="calls",
        client=invalid_client,
    )
    with pytest.raises(TargetError, match="tool calls"):
        invalid.complete([Message(Role.USER, "test")], timeout_s=1)
    invalid_client.close()
