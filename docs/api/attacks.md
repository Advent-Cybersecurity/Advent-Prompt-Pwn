# Attacks and judges

## Strategies

`DirectStrategy`, `InstructionOverrideStrategy`, `DelimiterStrategy`, `EncodingStrategy`,
`RoleConfusionStrategy`, `IndirectDocumentStrategy`, `IndirectFixtureStrategy`,
`MultiTurnStrategy`, `MutationStrategy`, `RagPoisoningStrategy`, and `CompositeStrategy` implement
the `Strategy.generate(case, rng)` contract.

## Adaptive search

- `AdaptivePromptMinimizer(config=None)`
- `MinimizationConfig(max_evaluations=64, max_seconds=60, minimum_characters=1)`
- `MinimizationResult`
- `MinimizationAttempt`
- `ScopedPromptEvaluator(target, case, scope=..., timeout_s=30)`
- `AdaptivePromptMutator(mutators=None, config=None)`
- `MutationSearchConfig(max_evaluations=64, max_seconds=60, max_generations=4, beam_width=4)`
- `AdaptiveMutationResult`
- `MutationEvaluation`
- `ScopedPromptScorer(target, case, scope=..., timeout_s=30)`

## Live conversation attacks

- `ConversationAttackHarness(target, scope=None, max_turns=6, ...)`
- `ConversationAttackResult`
- `ConversationTurn`

The planner is a trusted local callback. Each target request is checked against the authorization
window, endpoint allowlist, DNS policy, rate limit, and request budget.

## Deterministic oracles

`ContainsOracle`, `ContainsAnyOracle`, `ContainsAllOracle`, `CanaryLeakOracle`, `RegexOracle`,
`JsonKeysOracle`, `JsonPathOracle`, `ToolCallOracle`, `AnyOracle`, and `AllOracle` operate without
another model request.

## Semantic judging

- `CallableSemanticJudge(function, name=..., data_boundary=...)`
- `LabeledSemanticScore(score, attack_succeeded)`
- `calibrate_semantic_threshold(observations)`
- `SemanticJudgeOracle(judge, calibration, minimum_balanced_accuracy=0.8, ...)`

External judges require explicit data-boundary acknowledgement. Calibration metrics are evidence,
not a guarantee of generalization.
