# Advanced attack workflows

These APIs are for local, intentionally vulnerable, benchmark, or explicitly authorized systems.
They do not enlarge a configured `Scope`.

## Mutation

The `mutation` strategy produces a seeded, bounded set of JSON, XML, Markdown, quoting, casing,
spacing, prefix, and suffix transformations. It works in corpora and engagement manifests.

```yaml
execution:
  strategies: [direct, mutation, rag_poisoning, multi_turn]
  max_variants_per_case: 50
```

`AdaptivePromptMutator` uses observed scores to retain a bounded beam of promising candidates and
expand those candidates in later generations. A scorer must return a finite value from 0 through
1. The audit trail retains scores, sizes, generations, and SHA-256 digests without duplicating
candidate text.

```python
from advent_prompt_pwn import AdaptivePromptMutator, MutationSearchConfig, ScopedPromptScorer

scorer = ScopedPromptScorer(target, case, scope=authorized_scope)
search = AdaptivePromptMutator(
    config=MutationSearchConfig(max_evaluations=64, max_generations=4, beam_width=4)
)
result = search.search(starting_prompt, scorer)
print(result.best_prompt, result.best_score)
```

## Adaptive minimization

`AdaptivePromptMinimizer` performs line and token delta debugging. Its evaluator must return true
only while the observed security outcome remains reproducible. The caller owns target scope and
request accounting. The audit trail stores candidate digests and sizes, not discarded prompt text.

```python
from advent_prompt_pwn import AdaptivePromptMinimizer, MinimizationConfig, ScopedPromptEvaluator

evaluator = ScopedPromptEvaluator(target, case, scope=authorized_scope)
minimizer = AdaptivePromptMinimizer(
    MinimizationConfig(max_evaluations=64, max_seconds=120)
)
result = minimizer.minimize(successful_prompt, evaluator)
print(result.minimized_prompt)
```

## Semantic judges

Semantic decisions must be calibrated against a labeled set containing both successes and
failures. The oracle rejects calibrations below its configured balanced-accuracy floor. A judge
outside the local data boundary also requires an explicit acknowledgement because the assessed
model output may contain confidential engagement evidence.

```python
from advent_prompt_pwn import (
    CallableSemanticJudge,
    LabeledSemanticScore,
    SemanticJudgeOracle,
    calibrate_semantic_threshold,
)

calibration = calibrate_semantic_threshold([
    LabeledSemanticScore(0.95, True),
    LabeledSemanticScore(0.82, True),
    LabeledSemanticScore(0.18, False),
    LabeledSemanticScore(0.05, False),
])
judge = CallableSemanticJudge(local_classifier, data_boundary="local")
oracle = SemanticJudgeOracle(judge, calibration)
```

Treat the judge result as review evidence, not proof of severity. Recalibrate when the judge model,
prompt, target domain, or label policy changes.

## Multi-turn and RAG

`MultiTurnStrategy` sends a prefilled transcript that exercises role and history handling.
`ConversationAttackHarness` performs live feedback-adaptive turns through the ordinary scope and
request guard. The trusted local planner receives the previous target response and may stop by
returning `None`. The harness stops rather than executing a requested tool call.

```python
from advent_prompt_pwn import ConversationAttackHarness

harness = ConversationAttackHarness(target, scope=authorized_scope, max_turns=6)
result = harness.run(local_turn_planner)
```

`AgentSandboxHarness` performs bounded live tool-use turns. `RagPoisoningStrategy` marks retrieved
JSON, CSV, XML, and Markdown as untrusted while embedding the case objective across the retrieval
trust boundary.
