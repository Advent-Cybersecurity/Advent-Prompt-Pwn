"""Versioned engagement manifests and production assessment orchestration."""

from __future__ import annotations

import json
import os
import random
import re
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from advent_prompt_pwn.core.models import AttackCase, RunReport
from advent_prompt_pwn.core.runner import (
    DEFAULT_MAX_EVIDENCE_BYTES,
    ProgressCallback,
    RunConfig,
    Runner,
)
from advent_prompt_pwn.core.scope import Scope
from advent_prompt_pwn.corpus import (
    CorpusDefinition,
    load_corpus_definition,
    write_starter_corpus,
)
from advent_prompt_pwn.exceptions import EngagementError
from advent_prompt_pwn.io import atomic_write_text, read_bounded_bytes
from advent_prompt_pwn.parsing import load_json_strict, load_yaml_strict
from advent_prompt_pwn.schema import validate_schema_document
from advent_prompt_pwn.strategies import CompositeStrategy, Strategy, get_strategy
from advent_prompt_pwn.targets import (
    FakeTarget,
    HttpJsonTarget,
    OllamaTarget,
    OpenAICompatibleTarget,
    Target,
)
from advent_prompt_pwn.validation import validate_json_value

ENGAGEMENT_VERSION = 1
MAX_MANIFEST_BYTES = 2_000_000
MAX_EXTRA_BODY_BYTES = 1_000_000
_ENGAGEMENT_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{1,79}$")
_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")
_OUTPUT_FORMATS = {"json", "jsonl", "markdown", "html", "junit", "sarif"}

STARTER_ENGAGEMENT = """\
version: 1
engagement:
  id: local-lab-001
  name: Local synthetic-canary assessment
  owner: Advent Cybersecurity LLC
  authorization_reference: local-lab
corpus: cases.yaml
target:
  type: fake
  name: local-safe-target
  fake_response: SAFE_RESPONSE
scope:
  mode: local
  allowed_query_parameters: []
  allow_unpinned_dns: false
  max_requests: 200
  requests_per_minute: 120
  max_concurrency: 1
execution:
  strategies: [direct, instruction_override, delimiter, indirect_document]
  seed: 0
  timeout_seconds: 30
  retries: 1
  retry_backoff_seconds: 0.5
  concurrency: 1
  trials_per_variant: 1
  max_variants_per_case: 50
  checkpoint_interval: 10
  stop_on_error: false
  rerun_errors: true
  include_tags: []
  exclude_tags: []
  case_ids: []
  redact_env: []
  checkpoint_hmac_env: null
  max_evidence_bytes: 64000000
output:
  directory: reports/local-lab-001
  formats: [json, markdown, html, sarif]
  fail_on_findings: true
"""


@dataclass(frozen=True, slots=True)
class TargetSpec:
    kind: str
    name: str | None = None
    model: str | None = None
    base_url: str | None = None
    endpoint: str | None = None
    api_key_env: str | None = None
    fake_response: str = "SAFE_RESPONSE"
    extra_body_file: Path | None = None
    request_mode: str = "messages"
    request_field: str = "messages"
    response_path: str | None = None
    tool_calls_path: str | None = None
    headers_env: Mapping[str, str] | None = None
    max_response_bytes: int = 2_000_000


@dataclass(frozen=True, slots=True)
class ScopeSpec:
    mode: str
    authorization_reference: str
    allowed_hosts: tuple[str, ...] = ()
    allowed_ports: tuple[int, ...] = ()
    max_requests: int = 100
    requests_per_minute: int = 60
    max_concurrency: int = 1
    allow_insecure_http: bool = False
    allowed_query_parameters: tuple[str, ...] = ()
    allow_unpinned_dns: bool = False


@dataclass(frozen=True, slots=True)
class ExecutionSpec:
    strategies: tuple[str, ...] = ("direct",)
    seed: int = 0
    timeout_seconds: float = 30.0
    retries: int = 1
    retry_backoff_seconds: float = 0.5
    concurrency: int = 1
    trials_per_variant: int = 1
    max_variants_per_case: int = 50
    stop_on_error: bool = False
    rerun_errors: bool = True
    checkpoint_interval: int = 10
    include_tags: tuple[str, ...] = ()
    exclude_tags: tuple[str, ...] = ()
    case_ids: tuple[str, ...] = ()
    redact_env: tuple[str, ...] = ()
    checkpoint_hmac_env: str | None = None
    max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES


@dataclass(frozen=True, slots=True)
class OutputSpec:
    directory: Path
    checkpoint_file: Path | None = None
    formats: tuple[str, ...] = ("json", "markdown", "html", "sarif")
    fail_on_findings: bool = True


@dataclass(frozen=True, slots=True)
class EngagementDefinition:
    engagement_id: str
    name: str
    owner: str
    corpus_path: Path
    target: TargetSpec
    scope: ScopeSpec
    execution: ExecutionSpec
    output: OutputSpec
    source: Path


@dataclass(frozen=True, slots=True)
class EngagementRun:
    definition: EngagementDefinition
    corpus: CorpusDefinition
    report: RunReport


@dataclass(frozen=True, slots=True)
class EngagementPlan:
    """Request estimate and selected work produced without contacting a target."""

    definition: EngagementDefinition
    corpus: CorpusDefinition
    cases: tuple[AttackCase, ...]
    strategy: Strategy
    variants: int

    @property
    def planned_attempts(self) -> int:
        return self.variants * self.definition.execution.trials_per_variant


def _mapping(value: Any, label: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise EngagementError(f"{label} must be a mapping")
    return value


def _strings(value: Any, label: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise EngagementError(f"{label} must be a list")
    return tuple(str(item) for item in value)


def _ports(value: Any) -> tuple[int, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise EngagementError("scope.allowed_ports must be a list")
    try:
        return tuple(int(item) for item in value)
    except (TypeError, ValueError) as exc:
        raise EngagementError("scope.allowed_ports must contain integers") from exc


def _string_mapping(value: Any, label: str) -> dict[str, str]:
    if value is None:
        return {}
    mapping = _mapping(value, label)
    result = {str(key): str(item) for key, item in mapping.items()}
    if label == "target.headers_env":
        for header, environment_name in result.items():
            if not _HEADER_NAME.fullmatch(header):
                raise EngagementError(f"invalid HTTP header name: {header!r}")
            if header.casefold() == "host":
                raise EngagementError(
                    "target.headers_env must not override Host; authorize the intended URL host"
                )
            if not _ENVIRONMENT_NAME.fullmatch(environment_name):
                raise EngagementError(f"invalid environment variable name: {environment_name!r}")
    return result


def _boolean(value: Any, label: str, *, default: bool) -> bool:
    selected = default if value is None else value
    if not isinstance(selected, bool):
        raise EngagementError(f"{label} must be true or false")
    return selected


def _relative(
    base: Path,
    value: Any,
    label: str,
    *,
    allow_external_paths: bool,
) -> Path:
    if not isinstance(value, str) or not value.strip():
        raise EngagementError(f"{label} must be a non-empty path")
    path = Path(value)
    resolved_base = base.resolve()
    resolved = (resolved_base / path).resolve() if not path.is_absolute() else path.resolve()
    if not allow_external_paths and not resolved.is_relative_to(resolved_base):
        raise EngagementError(
            f"{label} resolves outside the manifest directory; use the explicit "
            "external-path opt-in only for reviewed paths"
        )
    return resolved


def _read_manifest(path: Path) -> Mapping[str, Any]:
    try:
        manifest_bytes = read_bounded_bytes(path, MAX_MANIFEST_BYTES, label="manifest")
        raw: Any = load_yaml_strict(manifest_bytes.decode("utf-8"))
        validate_json_value(value=raw, label="engagement manifest")
    except EngagementError:
        raise
    except (OSError, UnicodeDecodeError, yaml.YAMLError, RecursionError, ValueError) as exc:
        raise EngagementError(f"could not load engagement manifest {path}: {exc}") from exc
    return _mapping(raw, "engagement manifest")


def load_engagement(
    path: str | Path,
    *,
    allow_external_paths: bool = False,
) -> EngagementDefinition:
    """Load and validate a versioned engagement manifest."""

    source = Path(path).resolve()
    raw = _read_manifest(source)
    try:
        validate_schema_document(raw, "engagement-v1")
    except ValueError as exc:
        raise EngagementError(f"engagement manifest violates engagement-v1: {exc}") from exc
    if raw.get("version") != ENGAGEMENT_VERSION:
        raise EngagementError(f"engagement version must be {ENGAGEMENT_VERSION}")
    engagement = _mapping(raw.get("engagement"), "engagement")
    target = _mapping(raw.get("target"), "target")
    scope = _mapping(raw.get("scope"), "scope")
    execution = _mapping(raw.get("execution", {}), "execution")
    output = _mapping(raw.get("output", {}), "output")
    engagement_id = str(engagement.get("id", ""))
    if not _ENGAGEMENT_ID.fullmatch(engagement_id):
        raise EngagementError(
            "engagement.id must be 2 to 80 letters, digits, dots, underscores, or hyphens"
        )
    name = str(engagement.get("name", "")).strip()
    owner = str(engagement.get("owner", "")).strip()
    authorization_reference = str(engagement.get("authorization_reference", "")).strip()
    if not name or not owner or not authorization_reference:
        raise EngagementError("engagement name, owner, and authorization_reference are required")
    kind = str(target.get("type", "")).lower()
    if kind not in {"fake", "http-json", "ollama", "openai-compatible"}:
        raise EngagementError(f"unsupported target type: {kind!r}")
    base = source.parent
    extra_body = target.get("extra_body_file")
    target_spec = TargetSpec(
        kind=kind,
        name=str(target["name"]) if target.get("name") else None,
        model=str(target["model"]) if target.get("model") else None,
        base_url=str(target["base_url"]) if target.get("base_url") else None,
        endpoint=str(target["endpoint"]) if target.get("endpoint") else None,
        api_key_env=str(target["api_key_env"]) if target.get("api_key_env") else None,
        fake_response=str(target.get("fake_response", "SAFE_RESPONSE")),
        extra_body_file=(
            _relative(
                base,
                extra_body,
                "target.extra_body_file",
                allow_external_paths=allow_external_paths,
            )
            if extra_body
            else None
        ),
        request_mode=str(target.get("request_mode", "messages")),
        request_field=str(target.get("request_field", "messages")),
        response_path=(str(target["response_path"]) if target.get("response_path") else None),
        tool_calls_path=(str(target["tool_calls_path"]) if target.get("tool_calls_path") else None),
        headers_env=_string_mapping(target.get("headers_env"), "target.headers_env"),
        max_response_bytes=int(target.get("max_response_bytes", 2_000_000)),
    )
    scope_spec = ScopeSpec(
        mode=str(scope.get("mode", "local")).lower(),
        authorization_reference=authorization_reference,
        allowed_hosts=_strings(scope.get("allowed_hosts"), "scope.allowed_hosts"),
        allowed_ports=_ports(scope.get("allowed_ports")),
        max_requests=int(scope.get("max_requests", 100)),
        requests_per_minute=int(scope.get("requests_per_minute", 60)),
        max_concurrency=int(scope.get("max_concurrency", 1)),
        allow_insecure_http=_boolean(
            scope.get("allow_insecure_http"),
            "scope.allow_insecure_http",
            default=False,
        ),
        allowed_query_parameters=_strings(
            scope.get("allowed_query_parameters"),
            "scope.allowed_query_parameters",
        ),
        allow_unpinned_dns=_boolean(
            scope.get("allow_unpinned_dns"),
            "scope.allow_unpinned_dns",
            default=False,
        ),
    )
    if scope_spec.mode not in {"local", "authorized_remote"}:
        raise EngagementError("scope.mode must be local or authorized_remote")
    execution_spec = ExecutionSpec(
        strategies=_strings(execution.get("strategies", ["direct"]), "execution.strategies"),
        seed=int(execution.get("seed", 0)),
        timeout_seconds=float(execution.get("timeout_seconds", 30.0)),
        retries=int(execution.get("retries", 1)),
        retry_backoff_seconds=float(execution.get("retry_backoff_seconds", 0.5)),
        concurrency=int(execution.get("concurrency", 1)),
        trials_per_variant=int(execution.get("trials_per_variant", 1)),
        max_variants_per_case=int(execution.get("max_variants_per_case", 50)),
        stop_on_error=_boolean(
            execution.get("stop_on_error"),
            "execution.stop_on_error",
            default=False,
        ),
        rerun_errors=_boolean(
            execution.get("rerun_errors"),
            "execution.rerun_errors",
            default=True,
        ),
        checkpoint_interval=int(execution.get("checkpoint_interval", 10)),
        include_tags=_strings(execution.get("include_tags"), "execution.include_tags"),
        exclude_tags=_strings(execution.get("exclude_tags"), "execution.exclude_tags"),
        case_ids=_strings(execution.get("case_ids"), "execution.case_ids"),
        redact_env=_strings(execution.get("redact_env"), "execution.redact_env"),
        checkpoint_hmac_env=(
            str(execution["checkpoint_hmac_env"])
            if execution.get("checkpoint_hmac_env")
            else None
        ),
        max_evidence_bytes=int(
            execution.get("max_evidence_bytes", DEFAULT_MAX_EVIDENCE_BYTES)
        ),
    )
    if not execution_spec.strategies:
        raise EngagementError("execution.strategies must not be empty")
    formats = _strings(
        output.get("formats", ["json", "markdown", "html", "sarif"]),
        "output.formats",
    )
    unknown_formats = sorted(set(formats) - _OUTPUT_FORMATS)
    if unknown_formats:
        raise EngagementError(f"unsupported output formats: {', '.join(unknown_formats)}")
    output_spec = OutputSpec(
        directory=_relative(
            base,
            output.get("directory", f"reports/{engagement_id}"),
            "output.directory",
            allow_external_paths=allow_external_paths,
        ),
        formats=formats,
        checkpoint_file=(
            _relative(
                base,
                output["checkpoint_file"],
                "output.checkpoint_file",
                allow_external_paths=allow_external_paths,
            )
            if output.get("checkpoint_file")
            else None
        ),
        fail_on_findings=_boolean(
            output.get("fail_on_findings"),
            "output.fail_on_findings",
            default=True,
        ),
    )
    definition = EngagementDefinition(
        engagement_id=engagement_id,
        name=name,
        owner=owner,
        corpus_path=_relative(
            base,
            raw.get("corpus"),
            "corpus",
            allow_external_paths=allow_external_paths,
        ),
        target=target_spec,
        scope=scope_spec,
        execution=execution_spec,
        output=output_spec,
        source=source,
    )
    _validate_definition(definition)
    return definition


def _validate_definition(definition: EngagementDefinition) -> None:
    spec = definition.target
    if spec.kind in {"ollama", "openai-compatible"} and not spec.model:
        raise EngagementError(f"target.model is required for {spec.kind}")
    if spec.kind == "openai-compatible" and not spec.base_url:
        raise EngagementError("target.base_url is required for openai-compatible")
    if spec.kind == "http-json" and (not spec.endpoint or not spec.response_path):
        raise EngagementError("target.endpoint and target.response_path are required for http-json")
    if spec.max_response_bytes < 1:
        raise EngagementError("target.max_response_bytes must be positive")
    environment_names = [
        name for name in (spec.api_key_env, *(spec.headers_env or {}).values()) if name is not None
    ]
    environment_names.extend(definition.execution.redact_env)
    if definition.execution.checkpoint_hmac_env:
        environment_names.append(definition.execution.checkpoint_hmac_env)
    for name in environment_names:
        if not _ENVIRONMENT_NAME.fullmatch(name):
            raise EngagementError(f"invalid environment variable name: {name!r}")
    if definition.scope.mode == "authorized_remote" and not definition.scope.allowed_hosts:
        raise EngagementError("authorized_remote scope requires allowed_hosts")
    if definition.scope.mode == "authorized_remote" and not definition.scope.allowed_ports:
        raise EngagementError("authorized_remote scope requires allowed_ports")
    if definition.execution.concurrency > definition.scope.max_concurrency:
        raise EngagementError("execution.concurrency exceeds scope.max_concurrency")
    try:
        _build_scope(definition.scope)
        RunConfig(
            seed=definition.execution.seed,
            timeout_s=definition.execution.timeout_seconds,
            retries=definition.execution.retries,
            retry_backoff_s=definition.execution.retry_backoff_seconds,
            stop_on_error=definition.execution.stop_on_error,
            max_variants_per_case=definition.execution.max_variants_per_case,
            concurrency=definition.execution.concurrency,
            trials_per_variant=definition.execution.trials_per_variant,
            rerun_errors=definition.execution.rerun_errors,
            checkpoint_interval=definition.execution.checkpoint_interval,
            max_evidence_bytes=definition.execution.max_evidence_bytes,
        )
        for name in definition.execution.strategies:
            get_strategy(name)
    except (KeyError, TypeError, ValueError) as exc:
        raise EngagementError(str(exc)) from exc


def _load_extra_body(path: Path | None) -> dict[str, Any]:
    if path is None:
        return {}
    try:
        body_bytes = read_bounded_bytes(path, MAX_EXTRA_BODY_BYTES, label="extra body")
        value: Any = load_json_strict(body_bytes.decode("utf-8"))
        validate_json_value(value, label="target extra body")
    except EngagementError:
        raise
    except (
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise EngagementError(f"could not load target extra body {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise EngagementError("target extra body must be a JSON object")
    if "model" in value or "messages" in value:
        raise EngagementError("target extra body must not override model or messages")
    return value


def _build_target(spec: TargetSpec) -> Target:
    if spec.kind == "fake":
        return FakeTarget(spec.fake_response, name=spec.name or "fake")
    if spec.kind == "ollama":
        return OllamaTarget(
            spec.model or "",
            base_url=spec.base_url or "http://127.0.0.1:11434",
            max_response_bytes=spec.max_response_bytes,
        )
    if spec.kind == "http-json":
        return HttpJsonTarget(
            endpoint=spec.endpoint or "",
            response_path=spec.response_path or "",
            name=spec.name or "http-json",
            request_mode=spec.request_mode,
            request_field=spec.request_field,
            headers_env=spec.headers_env,
            extra_body=_load_extra_body(spec.extra_body_file),
            tool_calls_path=spec.tool_calls_path,
            max_response_bytes=spec.max_response_bytes,
        )
    return OpenAICompatibleTarget(
        model=spec.model or "",
        base_url=spec.base_url or "",
        api_key_env=spec.api_key_env,
        name=spec.name,
        extra_body=_load_extra_body(spec.extra_body_file),
        max_response_bytes=spec.max_response_bytes,
    )


def _build_scope(spec: ScopeSpec) -> Scope:
    if spec.mode == "local":
        return Scope.local_only(
            max_requests=spec.max_requests,
            requests_per_minute=spec.requests_per_minute,
            max_concurrency=spec.max_concurrency,
            authorization_reference=spec.authorization_reference,
            allowed_query_parameters=spec.allowed_query_parameters,
        )
    if not spec.allowed_ports:
        raise EngagementError("authorized_remote scope requires allowed_ports")
    return Scope.authorized(
        spec.allowed_hosts,
        spec.authorization_reference,
        allowed_ports=spec.allowed_ports,
        max_requests=spec.max_requests,
        requests_per_minute=spec.requests_per_minute,
        max_concurrency=spec.max_concurrency,
        allow_insecure_http=spec.allow_insecure_http,
        allowed_query_parameters=spec.allowed_query_parameters,
        allow_unpinned_dns=spec.allow_unpinned_dns,
    )


def _strategy(names: Sequence[str]) -> Strategy:
    strategies = [get_strategy(name) for name in names]
    return strategies[0] if len(strategies) == 1 else CompositeStrategy(strategies)


def _target_endpoint(spec: TargetSpec) -> str:
    if spec.kind == "fake":
        return "memory://fake"
    if spec.kind == "ollama":
        return f"{(spec.base_url or 'http://127.0.0.1:11434').rstrip('/')}/api/chat"
    if spec.kind == "http-json":
        return spec.endpoint or ""
    return f"{(spec.base_url or '').rstrip('/')}/chat/completions"


def _select_cases(cases: Sequence[AttackCase], spec: ExecutionSpec) -> tuple[AttackCase, ...]:
    include_tags = set(spec.include_tags)
    exclude_tags = set(spec.exclude_tags)
    case_ids = set(spec.case_ids)
    selected = tuple(
        case
        for case in cases
        if (not case_ids or case.case_id in case_ids)
        and (not include_tags or include_tags.intersection(case.tags))
        and not exclude_tags.intersection(case.tags)
    )
    if not selected:
        raise EngagementError("engagement filters selected no corpus cases")
    missing = case_ids - {case.case_id for case in cases}
    if missing:
        raise EngagementError(f"unknown execution.case_ids: {', '.join(sorted(missing))}")
    return selected


def _redactions(spec: EngagementDefinition) -> tuple[str, ...]:
    names = set(spec.execution.redact_env)
    if spec.execution.checkpoint_hmac_env:
        names.add(spec.execution.checkpoint_hmac_env)
    return tuple(value for name in sorted(names) if (value := os.environ.get(name)))


def plan_engagement(definition: EngagementDefinition) -> EngagementPlan:
    """Validate corpus, scope, filters, strategy output, and minimum request budget."""

    corpus = load_corpus_definition(definition.corpus_path)
    selected_cases = _select_cases(corpus.cases, definition.execution)
    strategy = _strategy(definition.execution.strategies)
    rng = random.Random(definition.execution.seed)  # noqa: S311 - deterministic variants
    variants = 0
    variant_ids: set[str] = set()
    for case in selected_cases:
        generated = list(strategy.generate(case, rng))
        if len(generated) > definition.execution.max_variants_per_case:
            raise EngagementError(
                f"strategy generated {len(generated)} variants for {case.case_id!r}; "
                f"limit is {definition.execution.max_variants_per_case}"
            )
        for variant in generated:
            if variant.variant_id in variant_ids:
                raise EngagementError(f"duplicate variant id: {variant.variant_id}")
            variant_ids.add(variant.variant_id)
        variants += len(generated)
    planned_attempts = variants * definition.execution.trials_per_variant
    if planned_attempts > definition.scope.max_requests:
        raise EngagementError(
            f"engagement requires at least {planned_attempts} requests but scope.max_requests "
            f"is {definition.scope.max_requests}"
        )
    if definition.target.kind != "fake" and (
        planned_attempts * definition.target.max_response_bytes
        > definition.execution.max_evidence_bytes
    ):
        raise EngagementError(
            "configured worst-case target responses exceed execution.max_evidence_bytes; "
            "reduce target.max_response_bytes, selected attempts, or both"
        )
    scope = _build_scope(definition.scope)
    scope.assert_endpoint(_target_endpoint(definition.target))
    _load_extra_body(definition.target.extra_body_file)
    return EngagementPlan(definition, corpus, selected_cases, strategy, variants)


def run_engagement(
    definition: EngagementDefinition,
    *,
    resume_from: RunReport | None = None,
    progress_callback: ProgressCallback | None = None,
    checkpoint_callback: Callable[[RunReport], None] | None = None,
    allowed_environment_variables: Sequence[str] = (),
    approved_authorization_reference: str | None = None,
    allowed_remote_hosts: Sequence[str] = (),
    allowed_remote_ports: Sequence[int] = (),
    allowed_query_parameters: Sequence[str] = (),
    allow_insecure_http: bool = False,
    allow_unpinned_dns: bool = False,
    allow_unauthenticated_resume: bool = False,
    approved_max_requests: int | None = None,
    approved_requests_per_minute: int | None = None,
    approved_max_concurrency: int | None = None,
    approved_max_retries: int | None = None,
    approved_max_timeout_seconds: float | None = None,
    approved_max_trials_per_variant: int | None = None,
    approved_max_variants_per_case: int | None = None,
    approved_max_response_bytes: int | None = None,
    approved_max_evidence_bytes: int | None = None,
    expected_resume_integrity_sha256: str | None = None,
) -> EngagementRun:
    """Execute one validated engagement and return its evidence report."""

    plan = plan_engagement(definition)
    declared_scope = _build_scope(definition.scope)
    required_environment = {
        name
        for name in (
            definition.target.api_key_env,
            *(definition.target.headers_env or {}).values(),
            *definition.execution.redact_env,
            definition.execution.checkpoint_hmac_env,
        )
        if name
    }
    approved_environment = set(allowed_environment_variables)
    invalid_approvals = sorted(
        name for name in approved_environment if not _ENVIRONMENT_NAME.fullmatch(name)
    )
    if invalid_approvals:
        raise EngagementError(
            "invalid approved environment variable name(s): " + ", ".join(invalid_approvals)
        )
    missing_approvals = sorted(required_environment - approved_environment)
    if missing_approvals:
        raise EngagementError(
            "manifest environment variables require independent approval with --allow-env: "
            + ", ".join(missing_approvals)
        )
    resource_approvals = {
        "maximum requests": approved_max_requests,
        "requests per minute": approved_requests_per_minute,
        "maximum concurrency": approved_max_concurrency,
        "maximum retries": approved_max_retries,
        "maximum timeout seconds": approved_max_timeout_seconds,
        "maximum trials per variant": approved_max_trials_per_variant,
        "maximum variants per case": approved_max_variants_per_case,
        "maximum response bytes": approved_max_response_bytes,
        "maximum evidence bytes": approved_max_evidence_bytes,
    }
    for label, value in resource_approvals.items():
        if value is None:
            continue
        if label == "maximum timeout seconds":
            valid = (
                not isinstance(value, bool)
                and isinstance(value, (int, float))
                and value > 0
            )
        elif label == "maximum retries":
            valid = not isinstance(value, bool) and isinstance(value, int) and value >= 0
        else:
            valid = not isinstance(value, bool) and isinstance(value, int) and value > 0
        if not valid:
            qualifier = "a non-negative integer" if label == "maximum retries" else "positive"
            raise EngagementError(f"approved {label} must be {qualifier}")
    grant_present = bool(
        approved_authorization_reference
        or allowed_remote_hosts
        or allowed_remote_ports
        or allowed_query_parameters
        or allow_insecure_http
        or allow_unpinned_dns
        or any(value is not None for value in resource_approvals.values())
    )
    if definition.scope.mode == "local":
        if grant_present:
            raise EngagementError("remote execution approvals cannot be used with local scope")
    else:
        approved_hosts = tuple(
            sorted({host.lower().rstrip(".") for host in allowed_remote_hosts if host.strip()})
        )
        approved_ports = tuple(sorted(set(allowed_remote_ports)))
        approved_queries = tuple(sorted({name for name in allowed_query_parameters if name}))
        mismatches: list[str] = []
        if approved_authorization_reference != declared_scope.authorization_reference:
            mismatches.append("authorization reference")
        if approved_hosts != declared_scope.allowed_hosts:
            mismatches.append("remote hosts")
        if approved_ports != declared_scope.allowed_ports:
            mismatches.append("remote ports")
        if approved_queries != declared_scope.allowed_query_parameters:
            mismatches.append("query parameters")
        if allow_insecure_http != declared_scope.allow_insecure_http:
            mismatches.append("insecure HTTP capability")
        if allow_unpinned_dns != declared_scope.allow_unpinned_dns:
            mismatches.append("unpinned DNS capability")
        workload = {
            "maximum requests": (definition.scope.max_requests, approved_max_requests),
            "requests per minute": (
                definition.scope.requests_per_minute,
                approved_requests_per_minute,
            ),
            "maximum concurrency": (
                definition.scope.max_concurrency,
                approved_max_concurrency,
            ),
            "maximum retries": (definition.execution.retries, approved_max_retries),
            "maximum timeout seconds": (
                definition.execution.timeout_seconds,
                approved_max_timeout_seconds,
            ),
            "maximum trials per variant": (
                definition.execution.trials_per_variant,
                approved_max_trials_per_variant,
            ),
            "maximum variants per case": (
                definition.execution.max_variants_per_case,
                approved_max_variants_per_case,
            ),
            "maximum response bytes": (
                definition.target.max_response_bytes,
                approved_max_response_bytes,
            ),
            "maximum evidence bytes": (
                definition.execution.max_evidence_bytes,
                approved_max_evidence_bytes,
            ),
        }
        mismatches.extend(
            label
            for label, (declared, approved) in workload.items()
            if approved is None or declared > approved
        )
        if mismatches:
            raise EngagementError(
                "remote manifest scope requires matching independent execution approval for: "
                + ", ".join(mismatches)
            )
    checkpoint_hmac_key = (
        os.environ.get(definition.execution.checkpoint_hmac_env)
        if definition.execution.checkpoint_hmac_env
        else None
    )
    if definition.execution.checkpoint_hmac_env and not checkpoint_hmac_key:
        raise EngagementError(
            f"environment variable {definition.execution.checkpoint_hmac_env!r} is not set"
        )
    if checkpoint_hmac_key and len(checkpoint_hmac_key.encode("utf-8")) < 32:
        raise EngagementError("checkpoint HMAC environment value must contain at least 32 bytes")
    target = _build_target(definition.target)
    try:
        report = Runner(
            target,
            scope=declared_scope,
            config=RunConfig(
                seed=definition.execution.seed,
                timeout_s=definition.execution.timeout_seconds,
                retries=definition.execution.retries,
                retry_backoff_s=definition.execution.retry_backoff_seconds,
                stop_on_error=definition.execution.stop_on_error,
                max_variants_per_case=definition.execution.max_variants_per_case,
                redact_secrets=_redactions(definition),
                concurrency=definition.execution.concurrency,
                trials_per_variant=definition.execution.trials_per_variant,
                rerun_errors=definition.execution.rerun_errors,
                checkpoint_interval=definition.execution.checkpoint_interval,
                max_evidence_bytes=definition.execution.max_evidence_bytes,
                checkpoint_hmac_key=checkpoint_hmac_key,
                allow_unauthenticated_resume=allow_unauthenticated_resume,
            ),
            engagement_id=definition.engagement_id,
            corpus_sha256=plan.corpus.sha256,
            metadata={
                "engagement_name": definition.name,
                "engagement_owner": definition.owner,
                "corpus_name": plan.corpus.name,
                "strategies": list(definition.execution.strategies),
                "selected_cases": [case.case_id for case in plan.cases],
                "planned_variants": plan.variants,
                "planned_attempts": plan.planned_attempts,
                "trials_per_variant": definition.execution.trials_per_variant,
                "remote_execution_approval": (
                    {
                        "authorization_reference": approved_authorization_reference,
                        "allowed_hosts": list(allowed_remote_hosts),
                        "allowed_ports": list(allowed_remote_ports),
                        "allowed_query_parameters": list(allowed_query_parameters),
                        "allow_insecure_http": allow_insecure_http,
                        "allow_unpinned_dns": allow_unpinned_dns,
                        **resource_approvals,
                    }
                    if definition.scope.mode == "authorized_remote"
                    else None
                ),
            },
            progress_callback=progress_callback,
            checkpoint_callback=checkpoint_callback,
        ).run(
            plan.cases,
            plan.strategy,
            resume_from=resume_from,
            expected_resume_integrity_sha256=expected_resume_integrity_sha256,
        )
    finally:
        target.close()
    return EngagementRun(definition, plan.corpus, report)


def write_starter_engagement(path: str | Path, *, force: bool = False) -> Path:
    """Create a safe manifest and starter corpus without destructive defaults."""

    destination = Path(path)
    if destination.exists() and not force:
        raise FileExistsError(f"refusing to overwrite existing file: {destination}")
    atomic_write_text(destination, STARTER_ENGAGEMENT)
    corpus = destination.parent / "cases.yaml"
    if not corpus.exists():
        write_starter_corpus(corpus)
    return destination
