"""HTTP target adapters for local and explicitly authorized endpoints."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping, Sequence
from threading import Lock
from typing import Any

import httpx

from advent_prompt_pwn.core.models import Message, TargetResponse, ToolCall
from advent_prompt_pwn.exceptions import ConfigurationError, TargetError
from advent_prompt_pwn.targets.base import Target
from advent_prompt_pwn.validation import validate_json_value


def _safe_http_error(label: str, exc: httpx.HTTPError) -> TargetError:
    if isinstance(exc, httpx.HTTPStatusError):
        return TargetError(f"{label} request returned HTTP {exc.response.status_code}")
    return TargetError(f"{label} transport failed: {type(exc).__name__}")


def _bounded_json_post(
    client: httpx.Client,
    endpoint: str,
    *,
    body: Mapping[str, Any],
    headers: Mapping[str, str] | None,
    timeout_s: float,
    max_response_bytes: int,
    label: str,
) -> tuple[int, Any]:
    """POST JSON while bounding decompressed response bytes before buffering."""

    request_headers = dict(headers or {})
    request_headers["Accept-Encoding"] = "identity"
    deadline = time.monotonic() + timeout_s
    short_timeout = min(timeout_s, 1.0)
    timeout = httpx.Timeout(
        timeout_s,
        read=short_timeout,
        write=short_timeout,
        pool=short_timeout,
    )
    with client.stream(
        "POST",
        endpoint,
        headers=request_headers,
        json=body,
        timeout=timeout,
        follow_redirects=False,
    ) as response:
        response.raise_for_status()
        if time.monotonic() > deadline:
            raise TargetError(f"{label} response exceeded its total {timeout_s:g}s deadline")
        content_encoding = response.headers.get("Content-Encoding", "").strip().casefold()
        if content_encoding and content_encoding != "identity":
            raise TargetError(f"{label} response used unsupported content encoding")
        length_header = response.headers.get("Content-Length")
        if length_header:
            try:
                declared_length = int(length_header)
            except ValueError:
                declared_length = -1
            if declared_length > max_response_bytes:
                raise TargetError(f"{label} response exceeded {max_response_bytes} bytes")
        chunks: list[bytes] = []
        observed = 0
        for chunk in response.iter_bytes():
            if time.monotonic() > deadline:
                raise TargetError(f"{label} response exceeded its total {timeout_s:g}s deadline")
            observed += len(chunk)
            if observed > max_response_bytes:
                raise TargetError(f"{label} response exceeded {max_response_bytes} bytes")
            chunks.append(chunk)
        payload: Any = json.loads(b"".join(chunks))
        if time.monotonic() > deadline:
            raise TargetError(f"{label} response exceeded its total {timeout_s:g}s deadline")
        validate_json_value(payload, label=f"{label} response")
        return response.status_code, payload


class OpenAICompatibleTarget(Target):
    """Adapter for an OpenAI-compatible chat-completions endpoint."""

    def __init__(
        self,
        *,
        model: str,
        base_url: str,
        api_key_env: str | None = None,
        name: str | None = None,
        client: httpx.Client | None = None,
        extra_body: dict[str, Any] | None = None,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        if not model.strip():
            raise ConfigurationError("model must not be empty")
        if not base_url.strip():
            raise ConfigurationError("base_url must not be empty")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self.api_key_env = api_key_env
        self._name = name or f"openai-compatible:{model}"
        self._client = client or httpx.Client(trust_env=False)
        self._owns_client = client is None
        self.extra_body = dict(extra_body or {})
        self._used_sensitive_values: set[str] = set()
        self._sensitive_values_lock = Lock()
        if max_response_bytes < 1:
            raise ConfigurationError("max_response_bytes must be positive")
        self.max_response_bytes = max_response_bytes

    @property
    def name(self) -> str:
        return self._name

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/chat/completions"

    @property
    def supports_concurrency(self) -> bool:
        return True

    @property
    def sensitive_values(self) -> tuple[str, ...]:
        current = os.environ.get(self.api_key_env) if self.api_key_env else None
        with self._sensitive_values_lock:
            values = set(self._used_sensitive_values)
        if current:
            values.add(current)
        return tuple(sorted(values))

    @property
    def resume_identity(self) -> dict[str, Any]:
        return {
            **super().resume_identity,
            "model": self.model,
            "base_url": self.base_url,
            "api_key_env": self.api_key_env,
            "extra_body": self.extra_body,
            "max_response_bytes": self.max_response_bytes,
        }

    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        headers: dict[str, str] = {"Content-Type": "application/json"}
        if self.api_key_env:
            api_key = os.environ.get(self.api_key_env)
            if not api_key:
                raise ConfigurationError(f"environment variable {self.api_key_env!r} is not set")
            with self._sensitive_values_lock:
                self._used_sensitive_values.add(api_key)
            headers["Authorization"] = f"Bearer {api_key}"
        body: dict[str, Any] = {
            **self.extra_body,
            "model": self.model,
            "messages": [message.to_dict() for message in messages],
        }
        started = time.perf_counter()
        try:
            _, payload = _bounded_json_post(
                self._client,
                self.endpoint,
                headers=headers,
                body=body,
                timeout_s=timeout_s,
                max_response_bytes=self.max_response_bytes,
                label="OpenAI-compatible",
            )
            if not isinstance(payload, Mapping):
                raise TypeError("response must be a JSON object")
            choices = payload.get("choices")
            if not isinstance(choices, list) or not choices:
                raise TypeError("choices must be a non-empty list")
            choice = payload["choices"][0]
            if not isinstance(choice, Mapping):
                raise TypeError("choice must be a mapping")
            message = choice["message"]
            if not isinstance(message, Mapping):
                raise TypeError("message must be a mapping")
            raw_calls = message.get("tool_calls", [])
            if not isinstance(raw_calls, list):
                raise TypeError("tool_calls must be a list")
            if any(not isinstance(item, Mapping) for item in raw_calls):
                raise TypeError("every tool call must be a mapping")
            for item in raw_calls:
                if not isinstance(item.get("function"), Mapping):
                    raise TypeError("every tool call function must be a mapping")
            calls = tuple(
                ToolCall(
                    name=item.get("function", {}).get("name", ""),
                    arguments=item.get("function", {}).get("arguments", ""),
                    call_id=item.get("id"),
                )
                for item in raw_calls
            )
            raw_usage = payload.get("usage", {})
            if not isinstance(raw_usage, Mapping):
                raise TypeError("usage must be a mapping")
            raw_content = message.get("content")
            return TargetResponse(
                content="" if raw_content is None else raw_content,
                model=payload.get("model", self.model),
                finish_reason=choice.get("finish_reason"),
                latency_ms=(time.perf_counter() - started) * 1000,
                usage=dict(raw_usage),
                tool_calls=calls,
                metadata={"response_id": payload.get("id")},
            )
        except httpx.HTTPError as exc:
            raise _safe_http_error("OpenAI-compatible", exc) from exc
        except (
            KeyError,
            IndexError,
            RecursionError,
            TypeError,
            ValueError,
        ) as exc:
            raise TargetError(f"OpenAI-compatible request failed: {exc}") from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


class OllamaTarget(Target):
    """Adapter for a loopback Ollama chat endpoint."""

    def __init__(
        self,
        model: str,
        *,
        base_url: str = "http://127.0.0.1:11434",
        client: httpx.Client | None = None,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        if not model.strip():
            raise ConfigurationError("model must not be empty")
        self.model = model
        self.base_url = base_url.rstrip("/")
        self._client = client or httpx.Client(trust_env=False)
        self._owns_client = client is None
        if max_response_bytes < 1:
            raise ConfigurationError("max_response_bytes must be positive")
        self.max_response_bytes = max_response_bytes

    @property
    def name(self) -> str:
        return f"ollama:{self.model}"

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/api/chat"

    @property
    def supports_concurrency(self) -> bool:
        return True

    @property
    def resume_identity(self) -> dict[str, Any]:
        return {
            **super().resume_identity,
            "model": self.model,
            "base_url": self.base_url,
            "max_response_bytes": self.max_response_bytes,
        }

    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        started = time.perf_counter()
        try:
            _, payload = _bounded_json_post(
                self._client,
                self.endpoint,
                headers=None,
                body={
                    "model": self.model,
                    "messages": [message.to_dict() for message in messages],
                    "stream": False,
                },
                timeout_s=timeout_s,
                max_response_bytes=self.max_response_bytes,
                label="Ollama",
            )
            if not isinstance(payload, Mapping):
                raise TypeError("response must be a JSON object")
            if not isinstance(payload.get("message"), Mapping):
                raise TypeError("message must be a mapping")
            content = payload["message"]["content"]
            return TargetResponse(
                content=content,
                model=payload.get("model", self.model),
                finish_reason=payload.get("done_reason"),
                latency_ms=(time.perf_counter() - started) * 1000,
                usage={
                    "prompt_tokens": payload.get("prompt_eval_count", 0),
                    "completion_tokens": payload.get("eval_count", 0),
                },
            )
        except httpx.HTTPError as exc:
            raise _safe_http_error("Ollama", exc) from exc
        except (KeyError, RecursionError, TypeError, ValueError) as exc:
            raise TargetError(f"Ollama request failed: {exc}") from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


def _json_path(value: Any, path: str) -> Any:
    current = value
    for segment in path.split("."):
        if isinstance(current, Mapping) and segment in current:
            current = current[segment]
        elif isinstance(current, list) and segment.isdigit() and int(segment) < len(current):
            current = current[int(segment)]
        else:
            raise KeyError(path)
    return current


class HttpJsonTarget(Target):
    """Adapter for scoped AI applications with JSON request and response bodies."""

    def __init__(
        self,
        *,
        endpoint: str,
        response_path: str,
        name: str = "http-json",
        request_mode: str = "messages",
        request_field: str = "messages",
        headers_env: Mapping[str, str] | None = None,
        extra_body: Mapping[str, Any] | None = None,
        tool_calls_path: str | None = None,
        max_response_bytes: int = 2_000_000,
        client: httpx.Client | None = None,
    ) -> None:
        if request_mode not in {"messages", "prompt"}:
            raise ConfigurationError("request_mode must be messages or prompt")
        if not endpoint.strip() or not response_path.strip() or not request_field.strip():
            raise ConfigurationError("endpoint, response_path, and request_field are required")
        if max_response_bytes < 1:
            raise ConfigurationError("max_response_bytes must be positive")
        self._endpoint = endpoint
        self.response_path = response_path
        self._name = name
        self.request_mode = request_mode
        self.request_field = request_field
        self.headers_env = dict(headers_env or {})
        if any(header.casefold() == "host" for header in self.headers_env):
            raise ConfigurationError(
                "headers_env must not override Host; authorize the intended URL host"
            )
        self.extra_body = dict(extra_body or {})
        self.tool_calls_path = tool_calls_path
        self.max_response_bytes = max_response_bytes
        self._used_sensitive_values: set[str] = set()
        self._sensitive_values_lock = Lock()
        self._client = client or httpx.Client(trust_env=False)
        self._owns_client = client is None
        if self.request_field in self.extra_body:
            raise ConfigurationError("extra_body must not override request_field")

    @property
    def name(self) -> str:
        return self._name

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def supports_concurrency(self) -> bool:
        return True

    @property
    def sensitive_values(self) -> tuple[str, ...]:
        values: set[str] = set()
        for environment_name in self.headers_env.values():
            value = os.environ.get(environment_name)
            if value:
                values.add(value)
        with self._sensitive_values_lock:
            values.update(self._used_sensitive_values)
        return tuple(sorted(values))

    @property
    def resume_identity(self) -> dict[str, Any]:
        return {
            **super().resume_identity,
            "response_path": self.response_path,
            "request_mode": self.request_mode,
            "request_field": self.request_field,
            "headers_env": self.headers_env,
            "extra_body": self.extra_body,
            "tool_calls_path": self.tool_calls_path,
            "max_response_bytes": self.max_response_bytes,
        }

    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        headers = {"Content-Type": "application/json"}
        resolved_sensitive_values: list[str] = []
        for header, environment_name in self.headers_env.items():
            value = os.environ.get(environment_name)
            if not value:
                raise ConfigurationError(f"environment variable {environment_name!r} is not set")
            headers[header] = value
            resolved_sensitive_values.append(value)
        with self._sensitive_values_lock:
            self._used_sensitive_values.update(resolved_sensitive_values)
        request_value: Any
        if self.request_mode == "messages":
            request_value = [message.to_dict() for message in messages]
        else:
            user_messages = [
                message.content for message in messages if message.role.value == "user"
            ]
            if not user_messages:
                raise TargetError("HTTP JSON prompt mode requires at least one user message")
            request_value = user_messages[-1]
        body = {**self.extra_body, self.request_field: request_value}
        started = time.perf_counter()
        try:
            status_code, payload = _bounded_json_post(
                self._client,
                self.endpoint,
                headers=headers,
                body=body,
                timeout_s=timeout_s,
                max_response_bytes=self.max_response_bytes,
                label="HTTP JSON",
            )
            content_value = _json_path(payload, self.response_path)
            raw_calls = _json_path(payload, self.tool_calls_path) if self.tool_calls_path else []
            if not isinstance(raw_calls, list):
                raise TypeError("tool calls path did not resolve to a list")
            if any(not isinstance(item, Mapping) for item in raw_calls):
                raise TypeError("every tool call must be a mapping")
            calls = tuple(
                ToolCall(
                    name=str(item.get("name", "")),
                    arguments=(
                        item.get("arguments", "")
                        if isinstance(item.get("arguments", ""), str)
                        else json.dumps(item.get("arguments"), sort_keys=True)
                    ),
                    call_id=str(item["id"]) if item.get("id") is not None else None,
                )
                for item in raw_calls
            )
            content = (
                content_value
                if isinstance(content_value, str)
                else json.dumps(content_value, sort_keys=True)
            )
            return TargetResponse(
                content=content,
                latency_ms=(time.perf_counter() - started) * 1000,
                tool_calls=calls,
                metadata={"status_code": status_code},
            )
        except httpx.HTTPError as exc:
            raise _safe_http_error("HTTP JSON", exc) from exc
        except (KeyError, RecursionError, TypeError, ValueError) as exc:
            raise TargetError(f"HTTP JSON request failed: {exc}") from exc

    def close(self) -> None:
        if self._owns_client:
            self._client.close()
