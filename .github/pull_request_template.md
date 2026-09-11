## Purpose

Describe the change and the security property it affects.

## Threat model

State the target assumptions, trust boundary, and observable success condition.

## Verification

- [ ] Tests added or updated
- [ ] `ruff check src tests`
- [ ] `mypy src`
- [ ] `pytest --cov=advent_prompt_pwn --cov-report=term-missing`
- [ ] No production secrets or unauthorized target data included
- [ ] Documentation updated when behavior changed

## Safety impact

Explain changes to scope enforcement, target transport, redaction, plugins, or report handling.
