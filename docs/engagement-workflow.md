# Engagement Workflow

The engagement manifest is the recommended v1 interface for consulting work. It records the authorization reference, corpus, target contract, scope, limits, execution settings, and deliverables in one versioned file.

## 1. Record authorization

Before configuring a remote target, record the signed statement of work, rules of engagement, or internal ticket that authorizes the assessment. The manifest stores the reference, not the legal document itself.

Confirm:

1. Target owner and application name
2. Exact hostnames and ports
3. Approved test period
4. Request, cost, and concurrency limits
5. Prohibited data and actions
6. Emergency stop contact
7. Evidence retention and handling requirements

The framework validates configuration and enforces declared technical limits, including optional
timezone-aware `not_before` and `not_after` values. It cannot verify that an authorization reference
or configured window represents a genuine contract.

## 2. Create and preflight

```bash
advent-prompt-pwn engagement init engagement.yaml
advent-prompt-pwn engagement validate engagement.yaml
```

Validation does not invoke a built-in target adapter. It parses the corpus, applies case filters, expands strategies deterministically, checks unique variant IDs, estimates the minimum request count, validates the response-size limit, and checks the target endpoint against scope. Installed strategy plugins execute as trusted Python during expansion and can have arbitrary side effects, so review them before validation or execution.

Review the planned variant count against the total request budget. Retries can use additional requests, so leave room between the minimum and maximum.

Use `execution.trials_per_variant` when a single observation would be weak evidence. The preflight
multiplies generated variants by this value and rejects a request budget that cannot cover the
planned attempts. Reports group the repeated outcomes, identify mixed results, and calculate a
Wilson 95% confidence interval. Repeated trials characterize observed behavior; they do not make a
nondeterministic model reproducible.

## 3. Configure credentials safely

Manifests store environment-variable names. For the generic HTTP JSON adapter, `headers_env` maps a header name to an environment-variable name:

```yaml
target:
  type: http-json
  endpoint: https://ai-client.example.test/api/chat
  request_mode: messages
  request_field: messages
  response_path: response.content
  headers_env:
    Authorization: CLIENT_AUTHORIZATION_HEADER
```

Set `CLIENT_AUTHORIZATION_HEADER` to the complete header value in the process environment. Adapter credential variables are added to redaction automatically. At execution time, independently approve each manifest-selected credential name:

```bash
advent-prompt-pwn engagement run engagement.yaml \
  --allow-env CLIENT_AUTHORIZATION_HEADER
```

The run fails before target construction when any manifest environment variable lacks this separate approval. This includes `execution.redact_env`, which is available for non-adapter values that should be removed from stored evidence.

Remote manifest scope is not treated as its own authorization. The execution command must match
the manifest's authorization reference, complete host and port sets, query parameter names,
insecure HTTP or unpinned DNS capabilities, and operator-approved workload ceilings. Prefer
`pinned_dns` addresses over the unpinned DNS capability. A typical
remote grant is:

```bash
advent-prompt-pwn engagement run engagement.yaml \
  --authorization-ref SOW-2026-042 \
  --allow-host ai-client.example.test \
  --allow-port 443 \
  --allow-unpinned-dns \
  --allow-env CLIENT_AUTHORIZATION_HEADER \
  --allow-env APPWN_CHECKPOINT_HMAC_KEY \
  --approve-max-requests 500 \
  --approve-requests-per-minute 60 \
  --approve-max-concurrency 4 \
  --approve-max-retries 2 \
  --approve-max-timeout 30 \
  --approve-max-trials-per-variant 1 \
  --approve-max-variants-per-case 50 \
  --approve-max-response-bytes 2000000 \
  --approve-max-evidence-bytes 64000000
```

Do not place credentials in URLs, corpora, extra-body files, command-line arguments, or manifests. Query parameters require `scope.allowed_query_parameters`. Sensitive query-string names and embedded URL credentials are rejected even when a query allowlist is configured.

## 4. Select a target

Supported manifest target types are:

- `fake`: deterministic local rehearsals and CI
- `ollama`: local Ollama chat API
- `openai-compatible`: chat-completions-compatible APIs
- `openai`: OpenAI Chat Completions API
- `azure-openai`: deployment-based Azure OpenAI Chat Completions API
- `anthropic`: Anthropic Messages API
- `gemini`: Google Gemini `generateContent` API
- `http-json`: authorized AI applications with configurable JSON shapes

The generic HTTP adapter supports two request modes. `messages` sends the complete normalized conversation. `prompt` sends only the final user message. Use `messages` when testing role boundaries or multi-turn behavior.

`response_path` and `tool_calls_path` use dotted JSON paths. Numeric path segments index lists. For example, `choices.0.message.content` addresses the first OpenAI-style choice.

An optional `extra_body_file` must contain a JSON object. It cannot replace the configured message field, or the model and messages fields on the OpenAI-compatible adapter.

Encode operational boundaries in the scope. Preflight validates syntax without waiting for a future
window or resolving DNS. Execution enforces both before dispatch:

```yaml
scope:
  not_before: "2026-09-11T09:00:00-07:00"
  not_after: "2026-09-11T17:00:00-07:00"
  pinned_dns:
    ai-client.example.test: [192.0.2.10]
```

## 5. Run and checkpoint

For checkpointed work, configure an operator-held authentication key by environment-variable
name. The value must contain at least 32 UTF-8 bytes and must be present from the first run:

```yaml
execution:
  checkpoint_hmac_env: APPWN_CHECKPOINT_HMAC_KEY
output:
  checkpoint_file: reports/client-2026-042.checkpoint.json
```

```bash
advent-prompt-pwn engagement run engagement.yaml \
  --authorization-ref SOW-2026-042 \
  --allow-host ai-client.example.test \
  --allow-port 443 \
  --allow-unpinned-dns \
  --allow-env CLIENT_AUTHORIZATION_HEADER \
  --allow-env APPWN_CHECKPOINT_HMAC_KEY \
  --approve-max-requests 500 \
  --approve-requests-per-minute 60 \
  --approve-max-concurrency 4 \
  --approve-max-retries 2 \
  --approve-max-timeout 30 \
  --approve-max-trials-per-variant 1 \
  --approve-max-variants-per-case 50 \
  --approve-max-response-bytes 2000000 \
  --approve-max-evidence-bytes 64000000
```

The checkpoint is replaced atomically before dispatch, after every configured interval, and at normal completion. The pre-dispatch checkpoint conservatively reserves the maximum retry count for unresolved variants. After an interruption, those unresolved reservations remain consumed because the process cannot prove whether a request reached the target. Resume it with:

```bash
advent-prompt-pwn engagement run engagement.yaml \
  --resume reports/client-2026-042.checkpoint.json \
  --resume-integrity EXPECTED_CHECKPOINT_SHA256 \
  --checkpoint reports/client-2026-042.checkpoint.json \
  --authorization-ref SOW-2026-042 \
  --allow-host ai-client.example.test \
  --allow-port 443 \
  --allow-unpinned-dns \
  --allow-env CLIENT_AUTHORIZATION_HEADER \
  --allow-env APPWN_CHECKPOINT_HMAC_KEY \
  --approve-max-requests 500 \
  --approve-requests-per-minute 60 \
  --approve-max-concurrency 4 \
  --approve-max-retries 2 \
  --approve-max-timeout 30 \
  --approve-max-trials-per-variant 1 \
  --approve-max-variants-per-case 50 \
  --approve-max-response-bytes 2000000 \
  --approve-max-evidence-bytes 64000000
```

The resume file is matched against the independently retained `--resume-integrity` value, then
integrity-checked and authenticated inside the runner before use. The target adapter contract,
raw endpoint identity, authorization reference, scope, corpus, engagement, redaction settings,
runner metadata, complete execution settings, generated variants, messages, tags, and severity must match.
Completed variants are retained. Failed variants run again when `rerun_errors` is true. The
request count includes earlier requests and unresolved pre-dispatch reservations, so the original
engagement budget still applies. When the checkpoint records prior requests, the first resumed
dispatch waits one full configured request interval from the new process start. Record each newly printed
checkpoint integrity value in trusted engagement state. An older authentic checkpoint is rejected
when it does not match that value.
The legacy `--allow-unauthenticated-resume` opt-in accepts recomputable hashes and must be reserved
for separately reviewed evidence.

`execution.max_evidence_bytes` bounds cumulative retained evidence. Validation rejects remote plans whose configured worst-case responses exceed that budget. Report and bundle writers apply independent file and aggregate size limits.

Manifest paths are confined beneath the manifest directory by default. Use
`--allow-external-paths` only for reviewed external assets or output locations. An existing
checkpoint is protected from replacement unless it is also the selected resume file or
`--overwrite-checkpoint` is supplied.

Concurrency cannot exceed `scope.max_concurrency`. Rate limiting and request budgeting are shared across all worker threads. Callback targets are serial by default because the framework cannot assume that user code is thread-safe.

## 6. Review findings

Successful variants are grouped into stable, case-based finding IDs. Severity comes from the case definition and must be assigned by a practitioner based on the authorized application's impact and controls.

Review every finding for:

- Whether the oracle directly demonstrates the stated objective
- False-positive and false-negative conditions
- Reproducibility across fresh sessions
- Application-level exploitability and prerequisites
- Data classification and business impact
- Existing detective and preventive controls

Execution errors are not security passes and are excluded from the attack-success rate.

## 7. Verify and compare evidence

```bash
advent-prompt-pwn verify reports/client-2026-042/run-RUN_ID \
  --checkpoint-hmac-env APPWN_CHECKPOINT_HMAC_KEY
advent-prompt-pwn compare approved-baseline.json current.json \
  --checkpoint-hmac-env APPWN_CHECKPOINT_HMAC_KEY \
  --output comparison.md
advent-prompt-pwn reproducers current.json --output reproducers.json
```

Bundle verification requires a unique checksummed `report.json`, checks every listed file checksum, binds manifest identity fields to the report, and verifies the report envelope and every attempt. Supplying `--checkpoint-hmac-env` also verifies the operator-keyed authentication tag. Use organization-approved signing and evidence-storage controls when non-repudiation is required.

Baseline comparison authenticates both saved reports with the same checkpoint HMAC key, rejects
incomplete checkpoint evidence, and requires the same target name, endpoint, adapter contract,
selected strategies, selected cases, trials per variant, framework seed, planned attempt total,
per-case strategy coverage, and generated job inputs.
Redacted endpoints require keyed identity pseudonyms generated with that key for both runs. When
both reports contain a corpus digest, it must match unless `--allow-corpus-change` is explicitly
used. That opt-in permits changed generated job inputs but still requires equal planned totals and
per-case strategy coverage. A new finding or new execution error produces the regression exit code.

Reproducer extraction chooses the shortest already-observed successful variant for each finding
in an integrity-verified report. It makes no target requests and does not claim that the selected
prompt is globally minimal. Use it as the starting point for practitioner-led reduction and
confirmation.

## 8. Close the engagement

Store the manifest, corpus, exact installed package artifact, evidence bundle, comparison report, and any human validation notes under the client's evidence-retention policy. Remove credentials from the process environment and dispose of temporary material using the approved engagement procedure.
