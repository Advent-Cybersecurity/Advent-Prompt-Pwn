"""Built-in target adapters."""

from advent_prompt_pwn.targets.base import Target
from advent_prompt_pwn.targets.fake import FakeTarget, FunctionTarget
from advent_prompt_pwn.targets.http import HttpJsonTarget, OllamaTarget, OpenAICompatibleTarget
from advent_prompt_pwn.targets.providers import (
    AnthropicTarget,
    AzureOpenAITarget,
    GeminiTarget,
    OpenAITarget,
)

__all__ = [
    "AnthropicTarget",
    "AzureOpenAITarget",
    "FakeTarget",
    "FunctionTarget",
    "GeminiTarget",
    "HttpJsonTarget",
    "OllamaTarget",
    "OpenAICompatibleTarget",
    "OpenAITarget",
    "Target",
]
