# Target adapters

All targets implement `Target.complete(messages, timeout_s=...)`, expose a secret-free
`resume_identity`, and disclose transient credentials through `sensitive_values` for redaction.

- `FakeTarget` and `FunctionTarget`
- `HttpJsonTarget`
- `OllamaTarget`
- `OpenAICompatibleTarget`
- `OpenAITarget`
- `AzureOpenAITarget`
- `AnthropicTarget`
- `GeminiTarget`

Custom adapters must bound response bytes, suppress redirects, ignore ambient proxy settings unless
the proxy is explicitly authorized, avoid secret-bearing URLs, and keep credentials out of target
identity.
