"""Deterministic execution engine with scope and evidence enforcement."""

from __future__ import annotations

import hashlib
import hmac
import json
import platform
import random
import time
from collections.abc import Callable, Sequence
from concurrent.futures import Future, ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from itertools import islice
from typing import Any
from uuid import uuid4

from advent_prompt_pwn.core.models import (
    AttackCase,
    AttackVariant,
    AttemptResult,
    Message,
    OracleResult,
    RunReport,
    TargetResponse,
    ToolCall,
)
from advent_prompt_pwn.core.redaction import redact_endpoint, redact_text, redact_value
from advent_prompt_pwn.core.scope import RequestGuard, Scope
from advent_prompt_pwn.exceptions import BudgetExceeded
from advent_prompt_pwn.integrity import canonical_sha256, seal_attempt, seal_report
from advent_prompt_pwn.strategies.base import Strategy
from advent_prompt_pwn.strategies.builtin import DirectStrategy
from advent_prompt_pwn.targets.base import Target

MAX_TRIALS_PER_VARIANT = 100
DEFAULT_MAX_EVIDENCE_BYTES = 64_000_000
_TRIAL_METADATA_KEY = "advent_prompt_pwn_trial"
_CHECKPOINT_HMAC_KEY = "checkpoint_hmac_sha256"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class RunConfig:
    """Execution controls that affect reproducibility and request behavior."""

    seed: int = 0
    timeout_s: float = 30.0
    retries: int = 0
    retry_backoff_s: float = 0.5
    stop_on_error: bool = False
    max_variants_per_case: int = 50
    redact_secrets: tuple[str, ...] = ()
    concurrency: int = 1
    rerun_errors: bool = True
    checkpoint_interval: int = 10
    trials_per_variant: int = 1
    max_evidence_bytes: int = DEFAULT_MAX_EVIDENCE_BYTES
    checkpoint_hmac_key: str | None = None
    allow_unauthenticated_resume: bool = False

    def __post_init__(self) -> None:
        if not isinstance(self.allow_unauthenticated_resume, bool):
            raise ValueError("allow_unauthenticated_resume must be true or false")
        if self.timeout_s <= 0:
            raise ValueError("timeout_s must be positive")
        if self.retries < 0:
            raise ValueError("retries must not be negative")
        if self.retry_backoff_s < 0:
            raise ValueError("retry_backoff_s must not be negative")
        if self.max_variants_per_case < 1:
            raise ValueError("max_variants_per_case must be positive")
        if self.concurrency < 1:
            raise ValueError("concurrency must be positive")
        if self.checkpoint_interval < 1:
            raise ValueError("checkpoint_interval must be positive")
        if not 1 <= self.trials_per_variant <= MAX_TRIALS_PER_VARIANT:
            raise ValueError(f"trials_per_variant must be between 1 and {MAX_TRIALS_PER_VARIANT}")
        if not 1_000_000 <= self.max_evidence_bytes <= DEFAULT_MAX_EVIDENCE_BYTES:
            raise ValueError(
                f"max_evidence_bytes must be between 1000000 and "
                f"{DEFAULT_MAX_EVIDENCE_BYTES}"
            )
        if self.checkpoint_hmac_key is not None:
            if not isinstance(self.checkpoint_hmac_key, str):
                raise ValueError("checkpoint_hmac_key must be a string or null")
            if len(self.checkpoint_hmac_key.encode("utf-8")) < 32:
                raise ValueError("checkpoint_hmac_key must contain at least 32 UTF-8 bytes")


def _checkpoint_mac(report: RunReport, key: str) -> str:
    unsigned_metadata = dict(report.metadata)
    unsigned_metadata.pop(_CHECKPOINT_HMAC_KEY, None)
    unsigned = replace(report, metadata=unsigned_metadata, integrity_sha256="")
    digest = seal_report(unsigned).integrity_sha256
    return hmac.new(key.encode("utf-8"), digest.encode("ascii"), hashlib.sha256).hexdigest()


def _authenticate_report(report: RunReport, key: str | None) -> RunReport:
    if key is None:
        return seal_report(report)
    unsigned_metadata = dict(report.metadata)
    unsigned_metadata.pop(_CHECKPOINT_HMAC_KEY, None)
    unsigned = replace(report, metadata=unsigned_metadata, integrity_sha256="")
    mac = _checkpoint_mac(unsigned, key)
    return seal_report(
        replace(unsigned, metadata={**unsigned_metadata, _CHECKPOINT_HMAC_KEY: mac})
    )


def verify_checkpoint_authentication(report: RunReport, key: str) -> bool:
    """Verify the operator-keyed authentication tag on a report or checkpoint."""

    supplied = report.metadata.get(_CHECKPOINT_HMAC_KEY)
    return (
        isinstance(supplied, str)
        and len(key.encode("utf-8")) >= 32
        and hmac.compare_digest(supplied, _checkpoint_mac(report, key))
    )


def _trial_variant(variant: AttackVariant, index: int, total: int) -> AttackVariant:
    if _TRIAL_METADATA_KEY in variant.metadata:
        raise ValueError(f"variant metadata key {_TRIAL_METADATA_KEY!r} is reserved")
    if total == 1:
        return variant
    return AttackVariant(
        variant_id=f"{variant.variant_id}:trial:{index}",
        case_id=variant.case_id,
        strategy=variant.strategy,
        messages=variant.messages,
        metadata={
            **variant.metadata,
            _TRIAL_METADATA_KEY: {
                "base_variant_id": variant.variant_id,
                "index": index,
                "total": total,
            },
        },
    )


def _redact_messages(
    messages: tuple[Message, ...], secrets: tuple[str, ...]
) -> tuple[Message, ...]:
    return tuple(
        Message(
            message.role,
            redact_text(message.content, secrets),
            redact_text(message.name, secrets) if message.name else None,
        )
        for message in messages
    )


def _redact_response(response: TargetResponse, secrets: tuple[str, ...]) -> TargetResponse:
    return TargetResponse(
        content=redact_text(response.content, secrets),
        model=redact_text(response.model, secrets) if response.model else None,
        finish_reason=(
            redact_text(response.finish_reason, secrets) if response.finish_reason else None
        ),
        latency_ms=response.latency_ms,
        usage=redact_value(response.usage, secrets),
        tool_calls=tuple(
            ToolCall(
                redact_text(call.name, secrets),
                redact_text(call.arguments, secrets),
                redact_text(call.call_id, secrets) if call.call_id else None,
            )
            for call in response.tool_calls
        ),
        metadata=redact_value(response.metadata, secrets),
    )


def _merge_redact_secrets(*groups: Sequence[str]) -> tuple[str, ...]:
    merged: list[str] = []
    for group in groups:
        if not isinstance(group, (list, tuple)) or any(
            not isinstance(value, str) for value in group
        ):
            raise TypeError("redaction values must be a sequence of strings")
        for value in group:
            if value and value not in merged:
                merged.append(value)
    return tuple(merged)


def _redact_identifier(value: str, secrets: tuple[str, ...]) -> str:
    return redact_text(value, secrets)


def _attempt_size(attempt: AttemptResult) -> int:
    return len(
        json.dumps(
            attempt.to_dict(),
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _response_size(response: TargetResponse) -> int:
    if len(response.content) > DEFAULT_MAX_EVIDENCE_BYTES:
        return DEFAULT_MAX_EVIDENCE_BYTES + 1
    payload = {
        "content": response.content,
        "model": response.model,
        "finish_reason": response.finish_reason,
        "latency_ms": response.latency_ms,
        "usage": response.usage,
        "tool_calls": [
            {"name": call.name, "arguments": call.arguments, "call_id": call.call_id}
            for call in response.tool_calls
        ],
        "metadata": response.metadata,
    }
    return len(
        json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    )


def _static_evidence_size(
    case: AttackCase,
    variant: AttackVariant,
    secrets: tuple[str, ...],
) -> int:
    payload = {
        "case_id": _redact_identifier(case.case_id, secrets),
        "case_name": redact_text(case.name, secrets),
        "variant_id": _redact_identifier(variant.variant_id, secrets),
        "strategy": _redact_identifier(variant.strategy, secrets),
        "messages": [message.to_dict() for message in _redact_messages(variant.messages, secrets)],
        "tags": [redact_text(tag, secrets) for tag in case.tags],
        "metadata": redact_value(variant.metadata, secrets),
    }
    return len(
        json.dumps(payload, ensure_ascii=False, separators=(",", ":"), sort_keys=True).encode(
            "utf-8"
        )
    ) + 2_048


def _tool_version() -> str:
    try:
        return version("advent-prompt-pwn")
    except PackageNotFoundError:
        return "1.0.0"


ProgressCallback = Callable[[AttemptResult, int, int], None]
CheckpointCallback = Callable[[RunReport], None]


class Runner:
    """Execute strategies against one target under an explicit scope."""

    def __init__(
        self,
        target: Target,
        *,
        scope: Scope | None = None,
        config: RunConfig | None = None,
        engagement_id: str | None = None,
        corpus_sha256: str | None = None,
        metadata: dict[str, Any] | None = None,
        progress_callback: ProgressCallback | None = None,
        checkpoint_callback: CheckpointCallback | None = None,
    ) -> None:
        self.target = target
        self.scope = scope or Scope.local_only()
        self.config = config or RunConfig()
        self.engagement_id = engagement_id
        self.corpus_sha256 = corpus_sha256
        self.metadata = dict(metadata or {})
        self.progress_callback = progress_callback
        self.checkpoint_callback = checkpoint_callback
        if (
            checkpoint_callback is not None
            and self.config.checkpoint_hmac_key is None
        ):
            raise ValueError("checkpoint output requires checkpoint_hmac_key")

    def run(
        self,
        cases: Sequence[AttackCase],
        strategy: Strategy | None = None,
        *,
        resume_from: RunReport | None = None,
        expected_resume_integrity_sha256: str | None = None,
    ) -> RunReport:
        """Run all generated variants and return immutable evidence."""

        secrets = _merge_redact_secrets(
            self.config.redact_secrets,
            self.target.sensitive_values,
        )
        self.scope.assert_endpoint(self.target.endpoint)
        if self.config.concurrency > self.scope.max_concurrency:
            raise ValueError(
                f"concurrency {self.config.concurrency} exceeds scope limit "
                f"{self.scope.max_concurrency}"
            )
        if self.config.concurrency > 1 and self.config.stop_on_error:
            raise ValueError("stop_on_error requires concurrency=1")
        if self.config.concurrency > 1 and not self.target.supports_concurrency:
            raise ValueError(
                f"target {redact_text(self.target.name, secrets)!r} does not support "
                "concurrent requests"
            )
        active_strategy = strategy or DirectStrategy()
        rng = random.Random(self.config.seed)
        initial_requests = resume_from.request_count if resume_from else 0
        run_started = _now()
        run_id = str(uuid4())
        jobs: list[tuple[AttackCase, AttackVariant]] = []
        base_variant_ids: set[str] = set()
        job_ids: set[str] = set()
        static_evidence_bytes = 0

        for case in cases:
            variants = list(
                islice(
                    active_strategy.generate(case, rng),
                    self.config.max_variants_per_case + 1,
                )
            )
            if len(variants) > self.config.max_variants_per_case:
                raise ValueError(
                    f"strategy generated {len(variants)} variants for "
                    f"{redact_text(case.case_id, secrets)!r}; "
                    f"limit is {self.config.max_variants_per_case}"
                )
            for variant in variants:
                if variant.variant_id in base_variant_ids:
                    raise ValueError("strategy generated a duplicate variant identifier")
                base_variant_ids.add(variant.variant_id)
                for trial_index in range(1, self.config.trials_per_variant + 1):
                    trial_variant = _trial_variant(
                        variant,
                        trial_index,
                        self.config.trials_per_variant,
                    )
                    if trial_variant.variant_id in job_ids:
                        raise ValueError("strategy generated a duplicate trial variant identifier")
                    static_evidence_bytes += _static_evidence_size(
                        case,
                        trial_variant,
                        secrets,
                    )
                    if static_evidence_bytes > self.config.max_evidence_bytes:
                        raise ValueError(
                            "planned attempt messages and metadata exceed the cumulative "
                            "evidence budget"
                        )
                    job_ids.add(trial_variant.variant_id)
                    jobs.append((case, trial_variant))

        secrets = _merge_redact_secrets(secrets, self.target.sensitive_values)
        redacted_case_ids: dict[str, str] = {}
        for case in cases:
            redacted_case_id = _redact_identifier(case.case_id, secrets)
            previous_case_id = redacted_case_ids.setdefault(redacted_case_id, case.case_id)
            if previous_case_id != case.case_id:
                raise ValueError(
                    "configured redaction values make case identifiers ambiguous"
                )
        redacted_job_ids: dict[str, str] = {}
        for _case, variant in jobs:
            redacted_variant_id = _redact_identifier(variant.variant_id, secrets)
            previous_variant_id = redacted_job_ids.setdefault(
                redacted_variant_id,
                variant.variant_id,
            )
            if previous_variant_id != variant.variant_id:
                raise ValueError(
                    "configured redaction values make variant identifiers ambiguous"
                )
        static_evidence_bytes = sum(
            _static_evidence_size(case, variant, secrets) for case, variant in jobs
        )
        if static_evidence_bytes > self.config.max_evidence_bytes:
            raise ValueError(
                "planned attempt messages and metadata exceed the cumulative evidence budget"
            )

        resume_binding = self._resume_binding(jobs, secrets)
        previous = self._resume_attempts(
            resume_from,
            jobs,
            resume_binding,
            expected_resume_integrity_sha256,
            secrets,
        )
        initial_not_before_epoch_s: float | None = None
        if resume_from is not None and resume_from.request_count:
            initial_not_before_epoch_s = time.time() + (
                60.0 / self.scope.requests_per_minute
            )
        guard = RequestGuard(
            self.scope,
            initial_count=initial_requests,
            initial_not_before_epoch_s=initial_not_before_epoch_s,
        )
        pending = [
            job
            for job in jobs
            if job[1].variant_id not in previous
            or (previous[job[1].variant_id].error and self.config.rerun_errors)
        ]
        response_limit = getattr(self.target, "max_response_bytes", None)
        if (
            isinstance(response_limit, int)
            and not isinstance(response_limit, bool)
            and len(pending) * response_limit > self.config.max_evidence_bytes
        ):
            raise ValueError(
                "configured worst-case target responses exceed the cumulative evidence budget"
            )
        durable_reservations = self.checkpoint_callback is not None
        maximum_requests_per_job = self.config.retries + 1
        if durable_reservations:
            guard.reserve(len(pending) * maximum_requests_per_job)
        elif guard.count + len(pending) > self.scope.max_requests:
            raise BudgetExceeded(
                f"engagement requires at least {guard.count + len(pending)} requests but "
                f"scope permits {self.scope.max_requests}"
            )
        results = dict(previous)
        retained_evidence_bytes = sum(_attempt_size(attempt) for attempt in results.values())
        if retained_evidence_bytes > self.config.max_evidence_bytes:
            raise ValueError("resume evidence exceeds the cumulative evidence budget")
        stopped_early = False
        new_completed = 0
        if durable_reservations and pending:
            self._checkpoint(
                run_id,
                run_started,
                jobs,
                results,
                guard.count,
                resume_from,
                resume_binding,
                secrets,
            )
        if self.config.concurrency == 1:
            for case, variant in pending:
                result = self._execute(
                    case,
                    variant,
                    guard,
                    secrets,
                    requests_pre_reserved=durable_reservations,
                )
                secrets = _merge_redact_secrets(secrets, self.target.sensitive_values)
                if durable_reservations:
                    guard.release(maximum_requests_per_job - result.request_attempts)
                if variant.variant_id in previous and previous[variant.variant_id].error:
                    result = seal_attempt(
                        replace(
                            result,
                            request_attempts=(
                                previous[variant.variant_id].request_attempts
                                + result.request_attempts
                            ),
                        )
                    )
                result_size = _attempt_size(result)
                evidence_limit_reached = retained_evidence_bytes + result_size > (
                    self.config.max_evidence_bytes
                )
                if evidence_limit_reached:
                    result = seal_attempt(
                        replace(
                            result,
                            response=None,
                            oracle=None,
                            evidence_sha256="",
                            error=(
                                "EvidenceLimitExceeded: response and oracle evidence were omitted "
                                "because the cumulative evidence budget was exhausted"
                            ),
                        )
                    )
                    result_size = _attempt_size(result)
                if retained_evidence_bytes + result_size > self.config.max_evidence_bytes:
                    raise ValueError("attempt metadata exceeds the cumulative evidence budget")
                retained_evidence_bytes += result_size
                results[variant.variant_id] = result
                self._notify(result, len(results), len(jobs))
                new_completed += 1
                if new_completed % self.config.checkpoint_interval == 0:
                    self._checkpoint(
                        run_id,
                        run_started,
                        jobs,
                        results,
                        guard.count,
                        resume_from,
                        resume_binding,
                        secrets,
                    )
                if result.error and self.config.stop_on_error:
                    stopped_early = True
                    if durable_reservations:
                        remaining = len(pending) - new_completed
                        guard.release(remaining * maximum_requests_per_job)
                    break
                if evidence_limit_reached:
                    stopped_early = True
                    if durable_reservations:
                        remaining = len(pending) - new_completed
                        guard.release(remaining * maximum_requests_per_job)
                    break
        else:
            with ThreadPoolExecutor(
                max_workers=self.config.concurrency,
                thread_name_prefix="advent-prompt-pwn",
            ) as executor:
                futures: dict[Future[AttemptResult], str] = {
                    executor.submit(
                        self._execute,
                        case,
                        variant,
                        guard,
                        secrets,
                        requests_pre_reserved=durable_reservations,
                    ): variant.variant_id
                    for case, variant in pending
                }
                for future in as_completed(tuple(futures)):
                    result = future.result()
                    secrets = _merge_redact_secrets(secrets, self.target.sensitive_values)
                    variant_id = futures.pop(future)
                    if durable_reservations:
                        guard.release(maximum_requests_per_job - result.request_attempts)
                    previous_result = previous.get(variant_id)
                    if previous_result and previous_result.error:
                        result = seal_attempt(
                            replace(
                                result,
                                request_attempts=(
                                    previous_result.request_attempts + result.request_attempts
                                ),
                            )
                        )
                    result_size = _attempt_size(result)
                    if retained_evidence_bytes + result_size > self.config.max_evidence_bytes:
                        result = seal_attempt(
                            replace(
                                result,
                                response=None,
                                oracle=None,
                                evidence_sha256="",
                                error=(
                                    "EvidenceLimitExceeded: response and oracle evidence were "
                                    "omitted because the cumulative evidence budget was exhausted"
                                ),
                            )
                        )
                        result_size = _attempt_size(result)
                    if retained_evidence_bytes + result_size > self.config.max_evidence_bytes:
                        raise ValueError("attempt metadata exceeds the cumulative evidence budget")
                    retained_evidence_bytes += result_size
                    results[variant_id] = result
                    self._notify(result, len(results), len(jobs))
                    new_completed += 1
                    if new_completed % self.config.checkpoint_interval == 0:
                        self._checkpoint(
                            run_id,
                            run_started,
                            jobs,
                            results,
                            guard.count,
                            resume_from,
                            resume_binding,
                            secrets,
                        )

        ordered = [
            results[variant.variant_id] for _, variant in jobs if variant.variant_id in results
        ]
        secrets = _merge_redact_secrets(secrets, self.target.sensitive_values)
        report = self._report(
            run_id,
            run_started,
            ordered,
            stopped_early=stopped_early,
            request_count=guard.count,
            resumed_from=resume_from.run_id if resume_from else None,
            resume_binding=resume_binding,
            planned_attempts=len(jobs),
            secrets=secrets,
        )
        if self.checkpoint_callback:
            self.checkpoint_callback(report)
        return report

    def _resume_attempts(
        self,
        report: RunReport | None,
        jobs: Sequence[tuple[AttackCase, AttackVariant]],
        resume_binding: str,
        expected_integrity_sha256: str | None,
        secrets: tuple[str, ...],
    ) -> dict[str, AttemptResult]:
        if report is None:
            if expected_integrity_sha256 is not None:
                raise ValueError("expected resume integrity was supplied without a resume report")
            return {}
        if expected_integrity_sha256 is None:
            raise ValueError(
                "resume requires an independently obtained expected_resume_integrity_sha256"
            )
        if not hmac.compare_digest(report.integrity_sha256, expected_integrity_sha256.lower()):
            raise ValueError("resume report does not match the independently expected integrity")
        from advent_prompt_pwn.report_io import verify_report_evidence

        integrity_errors = verify_report_evidence(report)
        if integrity_errors:
            raise ValueError(
                "resume report failed integrity verification: "
                + "; ".join(redact_text(error, secrets) for error in integrity_errors)
            )
        supplied_mac = report.metadata.get(_CHECKPOINT_HMAC_KEY)
        if self.config.checkpoint_hmac_key is not None:
            if not isinstance(supplied_mac, str) or not hmac.compare_digest(
                supplied_mac,
                _checkpoint_mac(report, self.config.checkpoint_hmac_key),
            ):
                raise ValueError("resume report checkpoint authentication failed")
        elif not self.config.allow_unauthenticated_resume:
            raise ValueError(
                "resume requires checkpoint_hmac_key; use the explicit "
                "allow_unauthenticated_resume compatibility opt-in only for reviewed evidence"
            )
        if report.target_name != redact_text(self.target.name, secrets):
            raise ValueError("resume report target name does not match the active target")
        if report.target_endpoint != redact_endpoint(self.target.endpoint, secrets):
            raise ValueError("resume report target endpoint does not match the active target")
        if report.seed != self.config.seed:
            raise ValueError("resume report seed does not match the active run")
        if report.authorization_reference != (
            redact_text(self.scope.authorization_reference, secrets)
            if self.scope.authorization_reference
            else None
        ):
            raise ValueError("resume report authorization reference does not match")
        expected_engagement_id = (
            _redact_identifier(self.engagement_id, secrets)
            if self.engagement_id is not None
            else None
        )
        if report.engagement_id != expected_engagement_id:
            raise ValueError("resume report engagement does not match")
        if report.corpus_sha256 != self.corpus_sha256:
            raise ValueError("resume report corpus digest does not match")
        if report.metadata.get("resume_binding_sha256") != resume_binding:
            raise ValueError("resume report execution binding does not match the active run")
        expected = {
            _redact_identifier(variant.variant_id, secrets): (case, variant)
            for case, variant in jobs
        }
        previous: dict[str, AttemptResult] = {}
        for attempt in report.attempts:
            if attempt.variant_id not in expected:
                raise ValueError("resume report contains an unknown variant identifier")
            case, variant = expected[attempt.variant_id]
            expected_metadata = {
                "variant": redact_value(variant.metadata, secrets)
            }
            if (
                attempt.case_id != _redact_identifier(case.case_id, secrets)
                or attempt.case_name != redact_text(case.name, secrets)
                or attempt.strategy != _redact_identifier(variant.strategy, secrets)
                or attempt.messages != _redact_messages(variant.messages, secrets)
                or attempt.tags != tuple(redact_text(tag, secrets) for tag in case.tags)
                or attempt.severity != case.severity
                or attempt.metadata != expected_metadata
            ):
                raise ValueError("resume evidence does not match the active corpus and strategy")
            previous[variant.variant_id] = attempt
        return previous

    def _resume_binding(
        self,
        jobs: Sequence[tuple[AttackCase, AttackVariant]],
        secrets: tuple[str, ...],
    ) -> str:
        return self._identity_digest(
            {
                "version": 3,
                "target_name": redact_text(self.target.name, secrets),
                "target_contract": self.target.resume_identity,
                "authorization_reference": (
                    redact_text(self.scope.authorization_reference, secrets)
                    if self.scope.authorization_reference
                    else None
                ),
                "engagement_id": (
                    _redact_identifier(self.engagement_id, secrets)
                    if self.engagement_id is not None
                    else None
                ),
                "corpus_sha256": self.corpus_sha256,
                "scope": {
                    "mode": self.scope.mode.value,
                    "allowed_hosts": self.scope.allowed_hosts,
                    "allowed_ports": self.scope.allowed_ports,
                    "max_requests": self.scope.max_requests,
                    "requests_per_minute": self.scope.requests_per_minute,
                    "max_concurrency": self.scope.max_concurrency,
                    "allow_insecure_http": self.scope.allow_insecure_http,
                    "allowed_query_parameters": self.scope.allowed_query_parameters,
                    "allow_unpinned_dns": self.scope.allow_unpinned_dns,
                    "pinned_dns": {
                        host: list(addresses)
                        for host, addresses in self.scope.pinned_dns.items()
                    },
                    "not_before": self.scope.not_before,
                    "not_after": self.scope.not_after,
                },
                "execution": {
                    "seed": self.config.seed,
                    "timeout_s": self.config.timeout_s,
                    "retries": self.config.retries,
                    "retry_backoff_s": self.config.retry_backoff_s,
                    "stop_on_error": self.config.stop_on_error,
                    "max_variants_per_case": self.config.max_variants_per_case,
                    "concurrency": self.config.concurrency,
                    "rerun_errors": self.config.rerun_errors,
                    "checkpoint_interval": self.config.checkpoint_interval,
                    "trials_per_variant": self.config.trials_per_variant,
                    "max_evidence_bytes": self.config.max_evidence_bytes,
                    "redact_secrets": self.config.redact_secrets,
                    "checkpoint_authentication": (
                        "hmac-sha256"
                        if self.config.checkpoint_hmac_key is not None
                        else "none"
                    ),
                },
                "runner_metadata": redact_value(self.metadata, secrets),
                "jobs": [
                    {
                        "case_id": _redact_identifier(case.case_id, secrets),
                        "case_name": redact_text(case.name, secrets),
                        "variant_id": _redact_identifier(variant.variant_id, secrets),
                        "strategy": _redact_identifier(variant.strategy, secrets),
                        "messages": [
                            message.to_dict()
                            for message in _redact_messages(variant.messages, secrets)
                        ],
                        "tags": [redact_text(tag, secrets) for tag in case.tags],
                        "severity": case.severity.value,
                        "metadata": redact_value(variant.metadata, secrets),
                    }
                    for case, variant in jobs
                ],
            }
        )

    def _identity_digest(self, value: Any) -> str:
        digest = canonical_sha256(value)
        if self.config.checkpoint_hmac_key is None:
            return digest
        return hmac.new(
            self.config.checkpoint_hmac_key.encode("utf-8"),
            digest.encode("ascii"),
            hashlib.sha256,
        ).hexdigest()

    def _notify(self, result: AttemptResult, completed: int, total: int) -> None:
        if self.progress_callback:
            self.progress_callback(result, completed, total)

    def _checkpoint(
        self,
        run_id: str,
        started_at: str,
        jobs: Sequence[tuple[AttackCase, AttackVariant]],
        results: dict[str, AttemptResult],
        request_count: int,
        resume_from: RunReport | None,
        resume_binding: str,
        secrets: tuple[str, ...],
    ) -> None:
        if not self.checkpoint_callback:
            return
        ordered = [
            results[variant.variant_id] for _, variant in jobs if variant.variant_id in results
        ]
        self.checkpoint_callback(
            self._report(
                run_id,
                started_at,
                ordered,
                stopped_early=True,
                request_count=request_count,
                resumed_from=resume_from.run_id if resume_from else None,
                resume_binding=resume_binding,
                planned_attempts=len(jobs),
                secrets=secrets,
            )
        )

    def _execute(
        self,
        case: AttackCase,
        variant: AttackVariant,
        guard: RequestGuard,
        secrets: tuple[str, ...],
        *,
        requests_pre_reserved: bool = False,
    ) -> AttemptResult:
        started = _now()
        started_clock = time.perf_counter()
        evidence_secrets = secrets
        response: TargetResponse | None = None
        oracle: OracleResult | None = None
        error: str | None = None
        request_attempts = 0
        for retry in range(self.config.retries + 1):
            try:
                if requests_pre_reserved:
                    guard.wait()
                else:
                    guard.acquire()
                self.scope.assert_endpoint(self.target.endpoint)
                request_attempts += 1
                response = self.target.complete(variant.messages, timeout_s=self.config.timeout_s)
                evidence_secrets = _merge_redact_secrets(
                    evidence_secrets,
                    self.target.sensitive_values,
                )
                if not isinstance(response, TargetResponse):
                    raise TypeError("target adapter must return TargetResponse")
                if _response_size(response) > self.config.max_evidence_bytes:
                    raise ValueError("target response exceeds the cumulative evidence budget")
                oracle = case.oracle.evaluate(case, variant, response)
                response = _redact_response(response, evidence_secrets)
                oracle = OracleResult(
                    success=oracle.success,
                    reason=redact_text(oracle.reason, evidence_secrets),
                    score=oracle.score,
                    evidence=redact_value(oracle.evidence, evidence_secrets),
                )
                error = None
                break
            except BudgetExceeded:
                raise
            except Exception as exc:  # Target and plugin boundaries must become report evidence.
                evidence_secrets = _merge_redact_secrets(
                    evidence_secrets,
                    self.target.sensitive_values,
                )
                error = f"{type(exc).__name__}: {exc}"
                response = None
                oracle = None
                if retry == self.config.retries:
                    break
                if self.config.retry_backoff_s:
                    time.sleep(self.config.retry_backoff_s * (2**retry))

        redacted_messages = _redact_messages(variant.messages, evidence_secrets)
        redacted_error = redact_text(error, evidence_secrets) if error else None
        attempt = AttemptResult(
            case_id=redact_text(case.case_id, secrets),
            case_name=redact_text(case.name, evidence_secrets),
            variant_id=redact_text(variant.variant_id, secrets),
            strategy=redact_text(variant.strategy, secrets),
            messages=redacted_messages,
            response=response,
            oracle=oracle,
            started_at=started,
            evidence_sha256="",
            error=redacted_error,
            tags=tuple(redact_text(tag, evidence_secrets) for tag in case.tags),
            completed_at=_now(),
            duration_ms=(time.perf_counter() - started_clock) * 1000,
            request_attempts=max(request_attempts, 1),
            severity=case.severity,
            metadata={"variant": redact_value(variant.metadata, evidence_secrets)},
        )
        return seal_attempt(attempt)

    def _report(
        self,
        run_id: str,
        started_at: str,
        results: list[AttemptResult],
        *,
        stopped_early: bool,
        request_count: int,
        resumed_from: str | None,
        resume_binding: str,
        planned_attempts: int,
        secrets: tuple[str, ...],
    ) -> RunReport:
        metadata = {
            **redact_value(self.metadata, secrets),
            "scope_mode": self.scope.mode.value,
            "scope_controls": redact_value(
                {
                    "not_before": self.scope.not_before,
                    "not_after": self.scope.not_after,
                    "pinned_dns": {
                        host: list(addresses)
                        for host, addresses in self.scope.pinned_dns.items()
                    },
                    "allow_unpinned_dns": self.scope.allow_unpinned_dns,
                },
                secrets,
            ),
            "stopped_early": stopped_early,
            "telemetry": "disabled",
            "planned_attempts": planned_attempts,
            "trials_per_variant": self.config.trials_per_variant,
            "max_evidence_bytes": self.config.max_evidence_bytes,
            "runtime": {
                "python": platform.python_version(),
                "implementation": platform.python_implementation(),
                "os": platform.system(),
            },
        }
        if self.config.checkpoint_hmac_key is not None:
            metadata.update(
                {
                    "resume_binding_sha256": resume_binding,
                    "target_endpoint_sha256": self._identity_digest(self.target.endpoint),
                    "target_contract_sha256": self._identity_digest(
                        self.target.resume_identity
                    ),
                }
            )
        completed_request_count = sum(attempt.request_attempts for attempt in results)
        if request_count < completed_request_count:
            raise ValueError("request count is smaller than completed attempt accounting")
        unresolved_requests = request_count - completed_request_count
        if unresolved_requests:
            metadata["unresolved_request_count"] = unresolved_requests
        if resumed_from:
            metadata["resumed_from"] = resumed_from
        report = RunReport(
            run_id=run_id,
            target_name=redact_text(self.target.name, secrets),
            target_endpoint=redact_endpoint(self.target.endpoint, secrets),
            started_at=started_at,
            completed_at=_now(),
            seed=self.config.seed,
            attempts=tuple(results),
            authorization_reference=(
                redact_text(self.scope.authorization_reference, secrets)
                if self.scope.authorization_reference
                else None
            ),
            metadata=metadata,
            tool_version=_tool_version(),
            engagement_id=(
                _redact_identifier(self.engagement_id, secrets)
                if self.engagement_id is not None
                else None
            ),
            corpus_sha256=self.corpus_sha256,
            request_count=request_count,
        )
        return _authenticate_report(report, self.config.checkpoint_hmac_key)


def run(
    target: Target,
    cases: Sequence[AttackCase],
    *,
    strategy: Strategy | None = None,
    scope: Scope | None = None,
    config: RunConfig | None = None,
) -> RunReport:
    """Convenience wrapper around :class:`Runner`."""

    return Runner(target, scope=scope, config=config).run(cases, strategy)
