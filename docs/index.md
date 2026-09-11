# advent-prompt-pwn 1.1

`advent-prompt-pwn` is a typed Python toolkit for authorized adversarial testing of AI systems.
It combines attack-case generation with explicit scope, bounded execution, resumable evidence,
reporting, and regression comparison.

The current package is beta software. Its automated qualification is extensive, but the project
does not claim broad field maturity until its external review and assessment evidence gates are
complete.

## What 1.1 adds

- Deterministic mutation plus budget-bound adaptive minimization and score-guided mutation
- Calibrated semantic judging with explicit external data-boundary acknowledgement
- Prefilled and feedback-adaptive live conversations with side-effect-free synthetic tools
- Dedicated RAG poisoning fixtures
- OpenAI, Azure OpenAI, Anthropic, and Gemini target adapters
- Enforcement of authorization time windows and DNS result pins
- Versioned documentation, benchmark corpora, example evidence, and a terminal walkthrough

## Install

```bash
python -m pip install advent-prompt-pwn
```

The public package remains at 1.0.0 until 1.1.0 is tagged and published. Install the repository
checkout to evaluate unreleased 1.1 features.

```bash
python -m pip install -e ".[dev,docs]"
advent-prompt-pwn doctor
```

Start with the [engagement workflow](engagement-workflow.md), then use the
[advanced attack guide](advanced-attacks.md) and [benchmark suite](benchmarks.md).
