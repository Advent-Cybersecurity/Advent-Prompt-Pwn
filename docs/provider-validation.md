# Provider validation

The OpenAI, Azure OpenAI, Anthropic, and Gemini adapters have deterministic contract tests using
mock transports. Those tests validate request structure, normalized responses, error handling,
stream bounds, secret redaction, and endpoint construction without making billable requests.

They do not prove compatibility with a provider's live service. Live validation requires an
authorized account, a selected model or deployment, an approved spend, and credentials that must
never be committed or pasted into an issue.

## Configuration-only check

The doctor command checks only whether the named environment variable is populated. It does not
read the value into diagnostics and does not contact the provider.

```bash
advent-prompt-pwn doctor --provider openai --output diagnostics.json
advent-prompt-pwn doctor --provider anthropic
advent-prompt-pwn doctor --provider gemini
advent-prompt-pwn doctor --provider azure-openai
```

Use `--api-key-env NAME` when an engagement uses a nondefault variable. The JSON output contains
the variable name and a boolean presence result, never the value.

## Live smoke-test record

For a live check, use the normal scoped `run` or `engagement run` workflow with one synthetic case,
one direct strategy, one trial, and a maximum request budget of one. Record the UTC date, package
version, provider, model or deployment, HTTP outcome class, evidence-verification result, and
whether response normalization passed. Do not record the credential, account identifier, raw
authorization headers, or client data.

No live-provider outcome is claimed by this repository until that check has actually run against
the named service.
