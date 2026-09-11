# Contributing

Contributions are welcome from AI security practitioners, application-security engineers, model evaluators, and maintainers of intentionally vulnerable labs.

## Ground rules

- Test only local, intentionally vulnerable, benchmark-based, or explicitly authorized systems.
- Use synthetic secrets with a `LAB_` prefix in tests and examples.
- Do not submit production credentials, customer transcripts, or undisclosed third-party vulnerabilities.
- Keep attack strategies inspectable. Hidden network activity and telemetry are not accepted.
- Add deterministic tests for new behavior.

## Development setup

```bash
python -m venv .venv
python -m pip install -e ".[dev]"
```

Run the quality gate:

```bash
ruff check src tests
mypy src
pytest --cov=advent_prompt_pwn --cov-report=term-missing
python -m pip_audit
python -m build
```

## Adding a strategy

Implement `advent_prompt_pwn.strategies.Strategy`, document the threat being simulated, and add tests showing the exact generated conversation. A strategy must not discover targets or bypass `Scope`.

Third-party strategy packages should use the `advent_prompt_pwn.strategies` entry-point group. This keeps specialized or higher-risk research outside the core dependency set.

## Pull requests

Describe the threat model, target assumptions, observable success condition, and safety impact. A passing test is necessary but does not replace reviewer judgment about oracle quality or false positives.
