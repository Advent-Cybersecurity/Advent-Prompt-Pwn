# Recorded quickstart walkthrough

The downloadable [asciinema recording](quickstart.cast) shows a complete offline workflow using the
synthetic benchmark and fake target. It validates the manifest, lists strategies, runs the bounded
assessment, and verifies the resulting evidence.

The recording contains no provider credentials and makes no network requests. Play it with:

```bash
asciinema play docs/walkthroughs/quickstart.cast
```

Equivalent commands:

```bash
advent-prompt-pwn engagement validate benchmarks/engagement.yaml
advent-prompt-pwn strategies
advent-prompt-pwn engagement run benchmarks/engagement.yaml --quiet
advent-prompt-pwn verify examples/reports/benchmark-report.json
```
