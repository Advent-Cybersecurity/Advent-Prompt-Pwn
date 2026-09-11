"""First-party adapters for common model-provider HTTP APIs."""

from __future__ import annotations

import json
import os
import re
import time
from collections.abc import Mapping, Sequence
from threading import Lock
from typing import Any
from urllib.parse import quote

import httpx

from advent_prompt_pwn.core.models import Message, Role, TargetResponse, ToolCall
from advent_prompt_pwn.exceptions import ConfigurationError, TargetError
from advent_prompt_pwn.targets.base import Target
from advent_prompt_pwn.targets.http import (
    OpenAICompatibleTarget,
    _bounded_json_post,
    _safe_http_error,
)
from advent_prompt_pwn.validation import validate_json_value

_AZURE_RESOURCE = re.compile(r"^[A-Za-z0-9-]{2,64}$")


def _extra_body(
    value: Mapping[str, Any] | None,
    *,
    reserved: set[str],
) -> dict[str, Any]:
    selected = dict(value or {})
    validate_json_value(selected, label="provider extra body")
    conflicts = sorted(set(selected).intersection(reserved))
    if conflicts:
        raise ConfigurationError("provider extra body must not override: " + ", ".join(conflicts))
    return selected


class OpenAITarget(OpenAICompatibleTarget):
    """Adapter for the OpenAI Chat Completions API."""

    def __init__(
        self,
        model: str,
        *,
        api_key_env: str = "OPENAI_API_KEY",
        base_url: str = "https://api.openai.com/v1",
        client: httpx.Client | None = None,
        extra_body: dict[str, Any] | None = None,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        super().__init__(
            model=model,
            base_url=base_url,
            api_key_env=api_key_env,
            name=f"openai:{model}",
            client=client,
            extra_body=extra_body,
            max_response_bytes=max_response_bytes,
        )


class AzureOpenAITarget(OpenAICompatibleTarget):
    """Adapter for Azure OpenAI chat completions using header authentication."""

    def __init__(
        self,
        deployment: str,
        *,
        resource: str,
        api_version: str,
        api_key_env: str = "AZURE_OPENAI_API_KEY",
        client: httpx.Client | None = None,
        extra_body: dict[str, Any] | None = None,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        if not deployment.strip() or not api_version.strip():
            raise ConfigurationError("deployment and api_version must not be empty")
        if not _AZURE_RESOURCE.fullmatch(resource):
            raise ConfigurationError("resource must be a valid Azure OpenAI resource name")
        self.deployment = deployment
        self.resource = resource
        self.api_version = api_version
        base_url = (
            f"https://{resource}.openai.azure.com/openai/deployments/{quote(deployment, safe='')}"
        )
        super().__init__(
            model=deployment,
            base_url=base_url,
            api_key_env=api_key_env,
            api_key_header="api-key",
            api_key_prefix="",
            name=f"azure-openai:{resource}/{deployment}",
            client=client,
            extra_body=extra_body,
            max_response_bytes=max_response_bytes,
        )

    @property
    def endpoint(self) -> str:
        version = quote(self.api_version, safe="")
        return f"{self.base_url}/chat/completions?api-version={version}"

    @property
    def resume_identity(self) -> dict[str, Any]:
        return {
            **super().resume_identity,
            "resource": self.resource,
            "deployment": self.deployment,
            "api_version": self.api_version,
        }


class _ProviderTarget(Target):
    def __init__(
        self,
        *,
        model: str,
        api_key_env: str,
        max_response_bytes: int,
        client: httpx.Client | None,
    ) -> None:
        if not model.strip() or not api_key_env.strip():
            raise ConfigurationError("model and api_key_env must not be empty")
        if max_response_bytes < 1:
            raise ConfigurationError("max_response_bytes must be positive")
        self.model = model
        self.api_key_env = api_key_env
        self.max_response_bytes = max_response_bytes
        self._client = client or httpx.Client(trust_env=False)
        self._owns_client = client is None
        self._used_sensitive_values: set[str] = set()
        self._sensitive_values_lock = Lock()

    @property
    def supports_concurrency(self) -> bool:
        return True

    @property
    def sensitive_values(self) -> tuple[str, ...]:
        current = os.environ.get(self.api_key_env)
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
            "api_key_env": self.api_key_env,
            "max_response_bytes": self.max_response_bytes,
        }

    def _api_key(self) -> str:
        value = os.environ.get(self.api_key_env)
        if not value:
            raise ConfigurationError(f"environment variable {self.api_key_env!r} is not set")
        with self._sensitive_values_lock:
            self._used_sensitive_values.add(value)
        return value

    def close(self) -> None:
        if self._owns_client:
            self._client.close()


class AnthropicTarget(_ProviderTarget):
    """Adapter for the Anthropic Messages API."""

    def __init__(
        self,
        model: str,
        *,
        api_key_env: str = "ANTHROPIC_API_KEY",
        base_url: str = "https://api.anthropic.com",
        anthropic_version: str = "2023-06-01",
        max_tokens: int = 1_024,
        extra_body: Mapping[str, Any] | None = None,
        client: httpx.Client | None = None,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        super().__init__(
            model=model,
            api_key_env=api_key_env,
            max_response_bytes=max_response_bytes,
            client=client,
        )
        if not base_url.strip() or not anthropic_version.strip():
            raise ConfigurationError("base_url and anthropic_version must not be empty")
        if not 1 <= max_tokens <= 1_000_000:
            raise ConfigurationError("max_tokens must be between 1 and 1000000")
        self.base_url = base_url.rstrip("/")
        self.anthropic_version = anthropic_version
        self.max_tokens = max_tokens
        self.extra_body = _extra_body(
            extra_body,
            reserved={"model", "max_tokens", "messages", "system", "stream"},
        )

    @property
    def name(self) -> str:
        return f"anthropic:{self.model}"

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/v1/messages"

    @property
    def resume_identity(self) -> dict[str, Any]:
        return {
            **super().resume_identity,
            "base_url": self.base_url,
            "anthropic_version": self.anthropic_version,
            "max_tokens": self.max_tokens,
            "extra_body": self.extra_body,
        }

    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        system = "\n\n".join(message.content for message in messages if message.role is Role.SYSTEM)
        provider_messages = [
            {
                "role": "assistant" if message.role is Role.ASSISTANT else "user",
                "content": message.content,
            }
            for message in messages
            if message.role is not Role.SYSTEM
        ]
        body: dict[str, Any] = {
            **self.extra_body,
            "model": self.model,
            "max_tokens": self.max_tokens,
            "messages": provider_messages,
        }
        if system:
            body["system"] = system
        started = time.perf_counter()
        try:
            _, payload = _bounded_json_post(
                self._client,
                self.endpoint,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "x-api-key": self._api_key(),
                    "anthropic-version": self.anthropic_version,
                },
                timeout_s=timeout_s,
                max_response_bytes=self.max_response_bytes,
                label="Anthropic",
            )
            if not isinstance(payload, Mapping) or not isinstance(payload.get("content"), list):
                raise TypeError("response content must be a list")
            text_parts: list[str] = []
            calls: list[ToolCall] = []
            for block in payload["content"]:
                if not isinstance(block, Mapping):
                    raise TypeError("response content block must be a mapping")
                if block.get("type") == "text":
                    if not isinstance(block.get("text"), str):
                        raise TypeError("text block content must be a string")
                    text_parts.append(block["text"])
                elif block.get("type") == "tool_use":
                    calls.append(
                        ToolCall(
                            name=str(block.get("name", "")),
                            arguments=json.dumps(block.get("input", {}), sort_keys=True),
                            call_id=str(block["id"]) if block.get("id") is not None else None,
                        )
                    )
            usage = payload.get("usage", {})
            if not isinstance(usage, Mapping):
                raise TypeError("usage must be a mapping")
            normalized_usage = {
                str(key): value
                for key, value in usage.items()
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            }
            return TargetResponse(
                content="\n".join(text_parts),
                model=str(payload.get("model", self.model)),
                finish_reason=(
                    str(payload["stop_reason"]) if payload.get("stop_reason") is not None else None
                ),
                latency_ms=(time.perf_counter() - started) * 1000,
                usage=normalized_usage,
                tool_calls=tuple(calls),
                metadata={"response_id": payload.get("id")},
            )
        except httpx.HTTPError as exc:
            raise _safe_http_error("Anthropic", exc) from exc
        except (KeyError, RecursionError, TypeError, ValueError) as exc:
            raise TargetError(f"Anthropic request failed: {exc}") from exc


class GeminiTarget(_ProviderTarget):
    """Adapter for the Google Gemini generateContent API using header authentication."""

    def __init__(
        self,
        model: str,
        *,
        api_key_env: str = "GEMINI_API_KEY",
        base_url: str = "https://generativelanguage.googleapis.com",
        extra_body: Mapping[str, Any] | None = None,
        client: httpx.Client | None = None,
        max_response_bytes: int = 2_000_000,
    ) -> None:
        super().__init__(
            model=model,
            api_key_env=api_key_env,
            max_response_bytes=max_response_bytes,
            client=client,
        )
        if not base_url.strip():
            raise ConfigurationError("base_url must not be empty")
        self.base_url = base_url.rstrip("/")
        self.extra_body = _extra_body(
            extra_body,
            reserved={"contents", "systemInstruction"},
        )

    @property
    def name(self) -> str:
        return f"gemini:{self.model}"

    @property
    def endpoint(self) -> str:
        return f"{self.base_url}/v1beta/models/{quote(self.model, safe='')}:generateContent"

    @property
    def resume_identity(self) -> dict[str, Any]:
        return {
            **super().resume_identity,
            "base_url": self.base_url,
            "extra_body": self.extra_body,
        }

    def complete(self, messages: Sequence[Message], *, timeout_s: float) -> TargetResponse:
        system_parts = [
            {"text": message.content} for message in messages if message.role is Role.SYSTEM
        ]
        contents = [
            {
                "role": "model" if message.role is Role.ASSISTANT else "user",
                "parts": [{"text": message.content}],
            }
            for message in messages
            if message.role is not Role.SYSTEM
        ]
        body: dict[str, Any] = {**self.extra_body, "contents": contents}
        if system_parts:
            body["systemInstruction"] = {"parts": system_parts}
        started = time.perf_counter()
        try:
            _, payload = _bounded_json_post(
                self._client,
                self.endpoint,
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "x-goog-api-key": self._api_key(),
                },
                timeout_s=timeout_s,
                max_response_bytes=self.max_response_bytes,
                label="Gemini",
            )
            if not isinstance(payload, Mapping) or not isinstance(payload.get("candidates"), list):
                raise TypeError("candidates must be a list")
            candidates = payload["candidates"]
            if not candidates or not isinstance(candidates[0], Mapping):
                raise TypeError("candidates must contain a mapping")
            content = candidates[0].get("content")
            if not isinstance(content, Mapping) or not isinstance(content.get("parts"), list):
                raise TypeError("candidate content parts must be a list")
            text_parts: list[str] = []
            calls: list[ToolCall] = []
            for index, part in enumerate(content["parts"]):
                if not isinstance(part, Mapping):
                    raise TypeError("candidate part must be a mapping")
                if "text" in part:
                    if not isinstance(part["text"], str):
                        raise TypeError("candidate text must be a string")
                    text_parts.append(part["text"])
                if "functionCall" in part:
                    function = part["functionCall"]
                    if not isinstance(function, Mapping):
                        raise TypeError("functionCall must be a mapping")
                    calls.append(
                        ToolCall(
                            name=str(function.get("name", "")),
                            arguments=json.dumps(function.get("args", {}), sort_keys=True),
                            call_id=f"gemini-{index}",
                        )
                    )
            usage = payload.get("usageMetadata", {})
            if not isinstance(usage, Mapping):
                raise TypeError("usageMetadata must be a mapping")
            normalized_usage = {
                str(key): value
                for key, value in usage.items()
                if isinstance(value, int) and not isinstance(value, bool) and value >= 0
            }
            return TargetResponse(
                content="\n".join(text_parts),
                model=self.model,
                finish_reason=(
                    str(candidates[0]["finishReason"])
                    if candidates[0].get("finishReason") is not None
                    else None
                ),
                latency_ms=(time.perf_counter() - started) * 1000,
                usage=normalized_usage,
                tool_calls=tuple(calls),
            )
        except httpx.HTTPError as exc:
            raise _safe_http_error("Gemini", exc) from exc
        except (KeyError, RecursionError, TypeError, ValueError) as exc:
            raise TargetError(f"Gemini request failed: {exc}") from exc
