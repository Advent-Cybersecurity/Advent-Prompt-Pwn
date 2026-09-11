# Benchmark suite

The `benchmarks/` directory contains original synthetic cases for direct prompt injection,
instruction hierarchy, RAG poisoning, multi-turn escalation, and attempted synthetic tool use.
No case contains a production secret, live destination, or real-world payload.

Validate and run the suite locally:

```bash
advent-prompt-pwn engagement validate benchmarks/engagement.yaml
advent-prompt-pwn engagement run benchmarks/engagement.yaml
```

The committed example report uses the deterministic fake target. Its purpose is to show report
structure and reporting output, not to claim provider security or benchmark leadership. Compare
real authorized runs only when the target contract, corpus digest, selection, and trial plan are
compatible.

When publishing benchmark results, disclose the target model snapshot, provider, system prompt,
corpus commit, strategy set, trial count, temperature or sampling controls, and assessment date.
