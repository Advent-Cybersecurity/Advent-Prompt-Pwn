# Provider adapters

The provider adapters use direct HTTPS requests through `httpx`. They ignore ambient proxy
variables, disable redirects, bound response bytes, and read credentials from named environment
variables. Credential values are excluded from resume identity and automatically included in
evidence redaction.

| Target | Default endpoint | Default credential variable |
| --- | --- | --- |
| `OpenAITarget` | `https://api.openai.com/v1/chat/completions` | `OPENAI_API_KEY` |
| `AzureOpenAITarget` | Azure deployment Chat Completions route | `AZURE_OPENAI_API_KEY` |
| `AnthropicTarget` | `https://api.anthropic.com/v1/messages` | `ANTHROPIC_API_KEY` |
| `GeminiTarget` | Google `generateContent` route | `GEMINI_API_KEY` |

Model names and API versions are configuration supplied by the assessor. Pin model snapshots when
the provider offers them and retain that identity in engagement evidence.

## Scope examples

Azure deployment routes use an `api-version` query parameter. It must be declared explicitly:

```yaml
scope:
  mode: authorized_remote
  allowed_hosts: [example-resource.openai.azure.com]
  allowed_ports: [443]
  allowed_query_parameters: [api-version]
```

For DNS destinations, prefer explicit pins:

```yaml
scope:
  pinned_dns:
    api.example.test: [192.0.2.10, 2001:db8::10]
```

The framework compares every current resolver answer with the approved set before dispatch.
Enforce the same addresses at the host or network-egress layer to close the remaining resolver to
connection race.

Provider references: [OpenAI Chat Completions](https://platform.openai.com/docs/api-reference/chat),
[Azure OpenAI Chat](https://learn.microsoft.com/en-us/rest/api/microsoft-foundry/azureopenai/chat),
[Anthropic Messages](https://platform.claude.com/docs/en/api/messages/create), and
[Gemini generateContent](https://ai.google.dev/api/generate-content).
