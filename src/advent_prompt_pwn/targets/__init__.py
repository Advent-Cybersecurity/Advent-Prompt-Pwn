"""Built-in target adapters."""

from advent_prompt_pwn.targets.base import Target
from advent_prompt_pwn.targets.fake import FakeTarget, FunctionTarget
from advent_prompt_pwn.targets.http import HttpJsonTarget, OllamaTarget, OpenAICompatibleTarget

__all__ = [
    "FakeTarget",
    "FunctionTarget",
    "HttpJsonTarget",
    "OllamaTarget",
    "OpenAICompatibleTarget",
    "Target",
]
