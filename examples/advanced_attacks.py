"""Offline examples for adaptive, semantic, RAG, and sandbox APIs."""

from __future__ import annotations

from collections.abc import Sequence

from advent_prompt_pwn import (
    AdaptivePromptMinimizer,
    AdaptivePromptMutator,
    AgentSandboxHarness,
    CallableSemanticJudge,
    ConversationAttackHarness,
    FakeTarget,
    LabeledSemanticScore,
    Message,
    Role,
    SandboxTool,
    SemanticDecision,
    ToolSandbox,
    calibrate_semantic_threshold,
)
from advent_prompt_pwn.core.models import Message as ModelMessage


def main() -> None:
    minimizer = AdaptivePromptMinimizer()
    minimized = minimizer.minimize(
        "remove these words LAB_KEEP remove these too",
        lambda prompt: "LAB_KEEP" in prompt,
    )
    print(f"Minimized synthetic prompt: {minimized.minimized_prompt}")

    mutation = AdaptivePromptMutator().search(
        "synthetic objective",
        lambda prompt: 0.9 if "untrusted_instruction" in prompt else 0.1,
    )
    print(f"Adaptive mutation score: {mutation.best_score:.2f}")

    calibration = calibrate_semantic_threshold(
        [
            LabeledSemanticScore(0.95, True),
            LabeledSemanticScore(0.85, True),
            LabeledSemanticScore(0.10, False),
            LabeledSemanticScore(0.05, False),
        ]
    )
    judge = CallableSemanticJudge(
        lambda objective, response: SemanticDecision(
            0.9 if "LAB_OBSERVED" in response else 0.1,
            "synthetic local classification",
        )
    )
    print(f"Calibrated threshold: {calibration.threshold:.2f} for {judge.name}")

    rounds = 0

    def application(messages: Sequence[ModelMessage]):
        nonlocal rounds
        rounds += 1
        return "SAFE_RESPONSE" if rounds > 1 else "No tool call requested."

    harness = AgentSandboxHarness(
        FakeTarget(application),
        ToolSandbox([SandboxTool("lab_lookup", {"value": "synthetic"})]),
        max_rounds=2,
    )
    result = harness.run([Message(Role.USER, "Analyze the synthetic fixture")])
    print(f"Sandbox requests: {result.requests}; stopped: {result.stopped_reason}")

    conversation = ConversationAttackHarness(
        FakeTarget(lambda messages: f"synthetic-turn-{len(messages)}"),
        max_turns=2,
    ).run(
        lambda messages, previous, index: (
            "first synthetic turn" if index == 0 else f"follow up on {previous.content}"
        )
    )
    print(f"Conversation requests: {conversation.requests}")


if __name__ == "__main__":
    main()
