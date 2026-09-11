from __future__ import annotations

import json
import random
from collections.abc import Iterable, Sequence
from dataclasses import replace
from pathlib import Path

import httpx
import pytest

from advent_prompt_pwn import (
    AttackCase,
    AttackVariant,
    CanaryLeakOracle,
    FakeTarget,
    FunctionTarget,
    HttpJsonTarget,
    Message,
    OpenAICompatibleTarget,
    Role,
    RunConfig,
    Runner,
    Scope,
    TargetResponse,
    compare_reports,
    run,
    verify_checkpoint_authentication,
)
from advent_prompt_pwn.bundle import verify_evidence_bundle, write_evidence_bundle
from advent_prompt_pwn.core.models import OracleResult, ToolCall
from advent_prompt_pwn.core.redaction import redact_endpoint, redact_text, redact_value
from advent_prompt_pwn.corpus import load_corpus_definition, write_starter_corpus
from advent_prompt_pwn.engagement import (
    ExecutionSpec,
    ScopeSpec,
    TargetSpec,
    load_engagement,
    run_engagement,
    write_starter_engagement,
)
from advent_prompt_pwn.exceptions import CorpusError, EngagementError, ReportError
from advent_prompt_pwn.integrity import attempt_sha256, canonical_sha256, report_sha256
from advent_prompt_pwn.oracles import RegexOracle, oracle_from_spec
from advent_prompt_pwn.report_io import load_report, report_from_dict, verify_report_evidence
from advent_prompt_pwn.reporters import report_markdown, save_report
from advent_prompt_pwn.strategies.base import Strategy


def _case() -> AttackCase:
    return AttackCase("case", "Case", "prompt", CanaryLeakOracle("LAB_HARDENING"))


def _report(response: str = "safe"):
    return Runner(
        FakeTarget(response),
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([_case()])


class _NamedStrategy(Strategy):
    name = "named"

    def __init__(self, secret: str) -> None:
        self.secret = secret

    def generate(self, case: AttackCase, rng: random.Random) -> Iterable[AttackVariant]:
        del rng
        yield AttackVariant(
            "case:named:0",
            case.case_id,
            self.name,
            (Message(Role.USER, case.prompt, name=self.secret),),
            metadata={self.secret: self.secret},
        )


def test_redaction_covers_all_persisted_target_fields() -> None:
    secret = "synthetic-private-value"

    def response(messages: Sequence[Message]) -> TargetResponse:
        del messages
        return TargetResponse(
            content=secret,
            model=secret,
            finish_reason=secret,
            usage={secret: 1},
            tool_calls=(ToolCall(secret, secret, secret),),
            metadata={secret: secret},
        )

    case = AttackCase("case", secret, secret, CanaryLeakOracle("LAB_HARDENING"), tags=(secret,))
    report = Runner(
        FunctionTarget(response, name=secret),
        scope=Scope.local_only(
            requests_per_minute=1_000_000,
            authorization_reference=secret,
        ),
        config=RunConfig(redact_secrets=(secret,)),
        metadata={secret: secret},
    ).run([case], _NamedStrategy(secret))
    assert secret not in json.dumps(report.to_dict(), sort_keys=True)
    assert verify_report_evidence(report) == ()


def test_direct_runner_redacts_http_json_environment_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "synthetic-direct-http-json-credential"
    monkeypatch.setenv("APPWN_DIRECT_HTTP_JSON_KEY", secret)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "answer": secret,
                    "calls": [{"id": secret, "name": secret, "arguments": secret}],
                },
            )
        )
    )
    target = HttpJsonTarget(
        endpoint="http://127.0.0.1/test",
        response_path="answer",
        headers_env={"X-Lab-Key": "APPWN_DIRECT_HTTP_JSON_KEY"},
        tool_calls_path="calls",
        client=client,
    )
    report = Runner(
        target,
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([_case()])
    client.close()

    assert secret not in json.dumps(report.to_dict(), sort_keys=True)
    assert verify_report_evidence(report) == ()


def test_convenience_run_redacts_openai_environment_credentials(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "synthetic-direct-openai-credential"
    monkeypatch.setenv("APPWN_DIRECT_OPENAI_KEY", secret)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(
                200,
                json={
                    "id": secret,
                    "model": secret,
                    "choices": [
                        {
                            "finish_reason": secret,
                            "message": {
                                "content": secret,
                                "tool_calls": [
                                    {
                                        "id": secret,
                                        "function": {"name": secret, "arguments": secret},
                                    }
                                ],
                            },
                        }
                    ],
                    "usage": {"prompt_tokens": 1},
                },
            )
        )
    )
    target = OpenAICompatibleTarget(
        model="lab",
        base_url="http://127.0.0.1/v1",
        api_key_env="APPWN_DIRECT_OPENAI_KEY",
        client=client,
    )
    report = run(
        target,
        [_case()],
        scope=Scope.local_only(requests_per_minute=1_000_000),
    )
    client.close()

    assert secret not in json.dumps(report.to_dict(), sort_keys=True)
    assert verify_report_evidence(report) == ()


def test_runner_redacts_credentials_changed_during_strategy_generation(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    secret = "synthetic-dynamic-http-credential"
    monkeypatch.delenv("APPWN_DYNAMIC_HTTP_KEY", raising=False)

    class CredentialSettingStrategy(Strategy):
        name = "credential_setting"

        def generate(
            self,
            case: AttackCase,
            rng: random.Random,
        ) -> Iterable[AttackVariant]:
            del rng
            monkeypatch.setenv("APPWN_DYNAMIC_HTTP_KEY", secret)
            yield AttackVariant(
                "dynamic:0",
                case.case_id,
                self.name,
                (Message(Role.USER, case.prompt),),
            )

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"answer": request.headers["X-Lab-Key"]})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    target = HttpJsonTarget(
        endpoint="http://127.0.0.1/test",
        response_path="answer",
        headers_env={"X-Lab-Key": "APPWN_DYNAMIC_HTTP_KEY"},
        client=client,
    )
    report = Runner(
        target,
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([_case()], CredentialSettingStrategy())
    client.close()

    assert secret not in json.dumps(report.to_dict(), sort_keys=True)


def test_target_credential_rotation_preserves_authenticated_resume(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    environment_name = "APPWN_ROTATING_HTTP_KEY"
    key = "k" * 32
    scope = Scope.local_only(requests_per_minute=1_000_000)
    config = RunConfig(checkpoint_hmac_key=key)
    client = httpx.Client(
        transport=httpx.MockTransport(
            lambda request: httpx.Response(200, json={"answer": "safe"})
        )
    )

    monkeypatch.setenv(environment_name, "synthetic-credential-a")
    baseline = Runner(
        HttpJsonTarget(
            endpoint="http://127.0.0.1/test",
            response_path="answer",
            headers_env={"X-Lab-Key": environment_name},
            client=client,
        ),
        scope=scope,
        config=config,
    ).run([_case()])

    monkeypatch.setenv(environment_name, "synthetic-credential-b")
    resumed = Runner(
        HttpJsonTarget(
            endpoint="http://127.0.0.1/test",
            response_path="answer",
            headers_env={"X-Lab-Key": environment_name},
            client=client,
        ),
        scope=scope,
        config=config,
    ).run(
        [_case()],
        resume_from=baseline,
        expected_resume_integrity_sha256=baseline.integrity_sha256,
    )
    client.close()

    assert resumed.metadata["resumed_from"] == baseline.run_id
    assert verify_report_evidence(resumed) == ()


def test_redaction_covers_structural_identifiers_and_resume() -> None:
    secret = "synthetic-identifier-secret"

    class SecretNamedStrategy(Strategy):
        name = f"strategy-{secret}"

        def generate(
            self,
            case: AttackCase,
            rng: random.Random,
        ) -> Iterable[AttackVariant]:
            del rng
            yield AttackVariant(
                f"variant-{secret}",
                case.case_id,
                self.name,
                (Message(Role.USER, "prompt"),),
            )

    key = "k" * 32
    config = RunConfig(
        redact_secrets=(secret,),
        checkpoint_hmac_key=key,
    )
    case = AttackCase(
        f"case-{secret}",
        "Case",
        "prompt",
        CanaryLeakOracle("LAB_HARDENING"),
    )
    baseline = Runner(
        FakeTarget("safe"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
        config=config,
        engagement_id=f"engagement-{secret}",
    ).run([case], SecretNamedStrategy())
    resumed = Runner(
        FakeTarget("safe"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
        config=config,
        engagement_id=f"engagement-{secret}",
    ).run(
        [case],
        SecretNamedStrategy(),
        resume_from=baseline,
        expected_resume_integrity_sha256=baseline.integrity_sha256,
    )

    assert secret not in json.dumps(resumed.to_dict(), sort_keys=True)
    assert resumed.engagement_id == "engagement-[REDACTED]"
    assert resumed.attempts[0].case_id == "case-[REDACTED]"
    assert resumed.attempts[0].variant_id == "variant-[REDACTED]"
    assert resumed.attempts[0].strategy == "strategy-[REDACTED]"
    assert resumed.metadata["resumed_from"] == baseline.run_id
    assert verify_report_evidence(resumed) == ()


def test_redaction_rejects_ambiguous_structural_identifiers() -> None:
    cases = [
        AttackCase("case-left", "Left", "prompt", CanaryLeakOracle("LAB_HARDENING")),
        AttackCase("case-right", "Right", "prompt", CanaryLeakOracle("LAB_HARDENING")),
    ]
    with pytest.raises(ValueError, match="case identifiers ambiguous"):
        Runner(
            FakeTarget("safe"),
            scope=Scope.local_only(requests_per_minute=1_000_000),
            config=RunConfig(redact_secrets=("left", "right")),
        ).run(cases)


def test_mapping_key_redaction_handles_collisions() -> None:
    assert redact_value(
        {"secret-a": 1, "secret-b": 2, "secret-c": 3, "secret-d": 4},
        ("secret-a", "secret-b", "secret-c", "secret-d"),
    ) == {
        "[REDACTED]": 1,
        "[REDACTED]#2": 2,
        "[REDACTED]#3": 3,
        "[REDACTED]#4": 4,
    }


def test_redaction_exact_contract_for_overlaps_markers_patterns_and_containers() -> None:
    assert redact_text("left [REDACTED] right", ("absent-secret",)) == (
        "left [REDACTED] right"
    )
    assert redact_text("az", ("z", "az")) == "[REDACTED]"
    assert redact_text("abcdef", ("abc", "abcdef")) == "[REDACTED]"
    assert redact_text("topsecret[REDACTED]", ("topsecret",)) == "[REDACTED][REDACTED]"
    assert (
        redact_text("api_key=secret-value password: secret-value")
        == "api_key=[REDACTED] password: [REDACTED]"
    )
    nested = ("secret-value", {"field": ["secret-value"]})
    assert redact_value(nested, ("secret-value",)) == (
        "[REDACTED]",
        {"field": ["[REDACTED]"]},
    )


def test_integrity_hash_contract_is_compact_unicode_and_strict() -> None:
    assert (
        canonical_sha256({"é": [1, True, None]})
        == "2c4c876a726b8399c9349e4c78ae44310210554400c621d7c9c4cf6d7c6b1b6d"
    )
    with pytest.raises(ValueError, match="Out of range float values"):
        canonical_sha256(float("nan"))
    with pytest.raises(TypeError, match="JSON serializable"):
        canonical_sha256(object())
    report = _report()
    assert attempt_sha256(report.attempts[0]) == report.attempts[0].evidence_sha256
    assert report_sha256(report) == report.integrity_sha256
    changed_report = _report("different response")
    assert changed_report.attempts[0].evidence_sha256 != report.attempts[0].evidence_sha256


def test_runtime_models_reject_malformed_adapter_and_oracle_values() -> None:
    with pytest.raises(ValueError, match="content"):
        TargetResponse(content=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="usage"):
        TargetResponse(content="safe", usage={"tokens": True})
    with pytest.raises(ValueError, match="tool calls"):
        TargetResponse(content="safe", tool_calls=[])  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="score"):
        OracleResult(False, "safe", score=float("nan"))
    with pytest.raises(ValueError, match="arguments"):
        ToolCall("tool", {})  # type: ignore[arg-type]


def test_endpoint_evidence_redacts_query_values_and_fragments() -> None:
    rendered = redact_endpoint("https://example.test/v1?tenant=client-a#private")
    assert "client-a" not in rendered
    assert "private" not in rendered
    assert "tenant=%5BREDACTED%5D" in rendered
    assert "/v1" not in rendered
    assert "/[REDACTED]" in rendered
    exact = redact_endpoint(
        "https://secret.example.test/private?empty=&secret_name=value&tenant=a#frag",
        ("secret",),
    )
    assert exact == (
        "https://[REDACTED].example.test/[REDACTED]?empty=%5BREDACTED%5D&"
        "%5BREDACTED%5D_name=%5BREDACTED%5D&tenant=%5BREDACTED%5D#[REDACTED]"
    )
    assert redact_endpoint("https://example.test/") == "https://example.test/"
    assert redact_endpoint("https://example.test") == "https://example.test"
    assert redact_endpoint("https://example.test", ("https",)) == (
        "[REDACTED]://example.test"
    )


def test_sensitive_identity_pseudonyms_require_hmac_key() -> None:
    class EndpointTarget(FakeTarget):
        @property
        def endpoint(self) -> str:
            return "http://127.0.0.1/private-tenant"

    scope = Scope.local_only(requests_per_minute=1_000_000)
    plain = Runner(EndpointTarget("safe"), scope=scope).run([_case()])
    assert "target_endpoint_sha256" not in plain.metadata
    assert "target_contract_sha256" not in plain.metadata
    assert "resume_binding_sha256" not in plain.metadata
    compatibility = Runner(
        EndpointTarget("safe"),
        scope=scope,
        config=RunConfig(allow_unauthenticated_resume=True),
    ).run([_case()])
    assert "resume_binding_sha256" not in compatibility.metadata
    from advent_prompt_pwn.comparison import compare_reports

    with pytest.raises(ValueError, match="keyed target identities"):
        compare_reports(plain, plain)

    class QueryTarget(FakeTarget):
        def __init__(self, tenant: str) -> None:
            super().__init__("safe")
            self.tenant = tenant

        @property
        def endpoint(self) -> str:
            return f"http://127.0.0.1/?tenant={self.tenant}"

    query_scope = Scope.local_only(
        requests_per_minute=1_000_000,
        allowed_query_parameters=("tenant",),
    )
    first = Runner(QueryTarget("alpha"), scope=query_scope).run([_case()])
    second = Runner(QueryTarget("bravo"), scope=query_scope).run([_case()])
    assert first.target_endpoint == second.target_endpoint
    with pytest.raises(ValueError, match="keyed target identities"):
        compare_reports(first, second)

    keyed = Runner(
        EndpointTarget("safe"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key="k" * 32),
    ).run([_case()])
    assert len(keyed.metadata["target_endpoint_sha256"]) == 64
    assert len(keyed.metadata["target_contract_sha256"]) == 64
    assert len(keyed.metadata["resume_binding_sha256"]) == 64


def test_resume_requires_and_verifies_checkpoint_authentication() -> None:
    scope = Scope.local_only(requests_per_minute=1_000_000)
    baseline = Runner(FakeTarget("safe"), scope=scope).run([_case()])
    with pytest.raises(ValueError, match="checkpoint_hmac_key"):
        Runner(FakeTarget("safe"), scope=scope).run(
            [_case()],
            resume_from=baseline,
            expected_resume_integrity_sha256=baseline.integrity_sha256,
        )
    key = "authenticated-checkpoint-key-0001"
    signed = Runner(
        FakeTarget("safe"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
    ).run([_case()])
    assert verify_checkpoint_authentication(signed, key)
    assert not verify_checkpoint_authentication(signed, "x" * 32)
    with pytest.raises(ValueError, match="independently obtained"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key),
        ).run([_case()], resume_from=signed)
    with pytest.raises(ValueError, match="without a resume report"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key),
        ).run(
            [_case()],
            expected_resume_integrity_sha256=signed.integrity_sha256,
        )
    with pytest.raises(ValueError, match="independently expected integrity"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key),
        ).run(
            [_case()],
            resume_from=signed,
            expected_resume_integrity_sha256="0" * 64,
        )
    tampered = replace(signed, attempts=(), request_count=0, integrity_sha256="")
    from advent_prompt_pwn.integrity import seal_report

    tampered = seal_report(tampered)
    with pytest.raises(ValueError, match="authentication failed"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key),
        ).run(
            [_case()],
            resume_from=tampered,
            expected_resume_integrity_sha256=tampered.integrity_sha256,
        )

    with pytest.raises(ValueError, match="binding"):
        Runner(
            FakeTarget("changed target contract"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key),
        ).run(
            [_case()],
            resume_from=signed,
            expected_resume_integrity_sha256=signed.integrity_sha256,
        )


def test_resume_inherits_checkpoint_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.core.runner as runner_module
    import advent_prompt_pwn.core.scope as scope_module

    clock = {"wall": 1_700_000_000.0, "monotonic": 50.0}
    sleeps: list[float] = []
    interrupted = True

    monkeypatch.setattr(scope_module.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(scope_module.time, "monotonic", lambda: clock["monotonic"])

    def advance(seconds: float) -> None:
        sleeps.append(seconds)
        clock["wall"] += seconds
        clock["monotonic"] += seconds

    monkeypatch.setattr(scope_module.time, "sleep", advance)
    monkeypatch.setattr(
        runner_module,
        "_now",
        lambda: runner_module.datetime.fromtimestamp(
            clock["wall"], runner_module.timezone.utc
        )
        .isoformat()
        .replace("+00:00", "Z"),
    )

    def response(messages: Sequence[Message]) -> str:
        nonlocal interrupted
        del messages
        if interrupted:
            raise KeyboardInterrupt
        return "safe"

    target = FakeTarget(response)
    scope = Scope.local_only(max_requests=2, requests_per_minute=6)
    config = RunConfig(checkpoint_hmac_key="k" * 32)
    checkpoints = []
    with pytest.raises(KeyboardInterrupt):
        Runner(
            target,
            scope=scope,
            config=config,
            checkpoint_callback=checkpoints.append,
        ).run([_case()])
    assert len(checkpoints) == 1

    interrupted = False
    clock["wall"] += 100.0
    clock["monotonic"] += 100.0
    resumed = Runner(target, scope=scope, config=config).run(
        [_case()],
        resume_from=checkpoints[0],
        expected_resume_integrity_sha256=checkpoints[0].integrity_sha256,
    )
    assert sleeps == [10.0]
    assert resumed.request_count == 2


def test_comparison_rejects_incomplete_runs_and_target_contract_changes() -> None:
    key = "k" * 32
    scope = Scope.local_only(max_requests=2, requests_per_minute=1_000_000)
    checkpoints = []
    complete = Runner(
        FakeTarget("safe"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
        checkpoint_callback=checkpoints.append,
    ).run([_case()])
    with pytest.raises(ValueError, match="incomplete"):
        compare_reports(complete, checkpoints[0])

    changed_contract = Runner(
        FakeTarget("changed"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
    ).run([_case()])
    with pytest.raises(ValueError, match="same target contract"):
        compare_reports(complete, changed_contract)


def test_comparison_rejects_different_complete_execution_selections() -> None:
    key = "k" * 32
    scope = Scope.local_only(max_requests=3, requests_per_minute=1_000_000)
    first = AttackCase("first", "First", "prompt", CanaryLeakOracle("LAB_FIRST"))
    second = AttackCase("second", "Second", "prompt", CanaryLeakOracle("LAB_SECOND"))
    baseline = Runner(
        FakeTarget("LAB_FIRST LAB_SECOND"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
        corpus_sha256="c" * 64,
        metadata={
            "strategies": ["direct"],
            "selected_cases": ["first", "second"],
            "trials_per_variant": 1,
        },
    ).run([first, second])
    current = Runner(
        FakeTarget("LAB_FIRST LAB_SECOND"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
        corpus_sha256="c" * 64,
        metadata={
            "strategies": ["direct"],
            "selected_cases": ["first"],
            "trials_per_variant": 1,
        },
    ).run([first])

    with pytest.raises(ValueError, match="same execution selection"):
        compare_reports(baseline, current)


def test_comparison_rejects_generated_job_coverage_drift() -> None:
    selected = {"case": "first"}

    class SelectiveStrategy(Strategy):
        name = "selective"

        def generate(
            self,
            case: AttackCase,
            rng: random.Random,
        ) -> Iterable[AttackVariant]:
            del rng
            if case.case_id == selected["case"]:
                yield AttackVariant(
                    f"{case.case_id}:selective:0",
                    case.case_id,
                    self.name,
                    (Message(Role.USER, case.prompt),),
                )

    key = "k" * 32
    scope = Scope.local_only(max_requests=2, requests_per_minute=1_000_000)
    first = AttackCase("first", "First", "prompt", CanaryLeakOracle("LAB_FIRST"))
    second = AttackCase("second", "Second", "prompt", CanaryLeakOracle("LAB_SECOND"))
    metadata = {
        "strategies": ["selective"],
        "selected_cases": ["first", "second"],
        "trials_per_variant": 1,
    }
    baseline = Runner(
        FakeTarget("LAB_FIRST"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
        corpus_sha256="a" * 64,
        metadata=metadata,
    ).run([first, second], SelectiveStrategy())
    selected["case"] = "missing"
    empty = Runner(
        FakeTarget("LAB_FIRST"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
        corpus_sha256="a" * 64,
        metadata=metadata,
    ).run([first, second], SelectiveStrategy())
    with pytest.raises(ValueError, match="same execution selection"):
        compare_reports(baseline, empty)

    selected["case"] = "second"
    current = Runner(
        FakeTarget("LAB_FIRST"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key),
        corpus_sha256="b" * 64,
        metadata=metadata,
    ).run([first, second], SelectiveStrategy())

    with pytest.raises(ValueError, match="same execution coverage"):
        compare_reports(baseline, current, allow_corpus_change=True)


def test_comparison_rejects_changed_generated_job_inputs() -> None:
    prompt = {"value": "first prompt"}

    class MutableStrategy(Strategy):
        name = "mutable"

        def generate(
            self,
            case: AttackCase,
            rng: random.Random,
        ) -> Iterable[AttackVariant]:
            del rng
            yield AttackVariant(
                f"{case.case_id}:mutable:0",
                case.case_id,
                self.name,
                (Message(Role.USER, prompt["value"]),),
            )

    case = _case()
    metadata = {
        "strategies": ["mutable"],
        "selected_cases": ["case"],
        "trials_per_variant": 1,
    }
    options = {
        "scope": Scope.local_only(requests_per_minute=1_000_000),
        "config": RunConfig(checkpoint_hmac_key="k" * 32),
        "corpus_sha256": "c" * 64,
        "metadata": metadata,
    }
    baseline = Runner(FakeTarget("safe"), **options).run([case], MutableStrategy())
    prompt["value"] = "changed prompt"
    current = Runner(FakeTarget("safe"), **options).run([case], MutableStrategy())

    with pytest.raises(ValueError, match="same generated jobs"):
        compare_reports(baseline, current)
    assert not compare_reports(
        replace(baseline, corpus_sha256="a" * 64),
        replace(current, corpus_sha256="b" * 64),
        allow_corpus_change=True,
    ).regressed


def test_resume_binding_includes_redaction_configuration_and_metadata() -> None:
    scope = Scope.local_only(requests_per_minute=1_000_000)
    key = "k" * 32
    baseline = Runner(
        FakeTarget("safe"),
        scope=scope,
        config=RunConfig(checkpoint_hmac_key=key, redact_secrets=("FIRST_SECRET",)),
        metadata={"approval": "one"},
    ).run([_case()])
    with pytest.raises(ValueError, match="binding"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key, redact_secrets=("SECOND_SECRET",)),
            metadata={"approval": "one"},
        ).run(
            [_case()],
            resume_from=baseline,
            expected_resume_integrity_sha256=baseline.integrity_sha256,
        )
    with pytest.raises(ValueError, match="binding"):
        Runner(
            FakeTarget("safe"),
            scope=scope,
            config=RunConfig(checkpoint_hmac_key=key, redact_secrets=("FIRST_SECRET",)),
            metadata={"approval": "two"},
        ).run(
            [_case()],
            resume_from=baseline,
            expected_resume_integrity_sha256=baseline.integrity_sha256,
        )


def test_checkpoint_output_requires_authentication_even_with_legacy_resume_opt_in() -> None:
    with pytest.raises(ValueError, match="checkpoint output requires"):
        Runner(
            FakeTarget("safe"),
            scope=Scope.local_only(requests_per_minute=1_000_000),
            checkpoint_callback=lambda report: None,
        )
    with pytest.raises(ValueError, match="checkpoint output requires"):
        Runner(
            FakeTarget("safe"),
            scope=Scope.local_only(requests_per_minute=1_000_000),
            config=RunConfig(allow_unauthenticated_resume=True),
            checkpoint_callback=lambda report: None,
        )


def test_remote_manifest_scope_requires_exact_independent_grant(tmp_path: Path) -> None:
    definition = load_engagement(write_starter_engagement(tmp_path / "engagement.yaml"))
    definition = replace(
        definition,
        scope=ScopeSpec(
            mode="authorized_remote",
            authorization_reference="SOW-42",
            allowed_hosts=("192.0.2.10",),
            allowed_ports=(443,),
            max_requests=20,
        ),
        execution=ExecutionSpec(strategies=("direct",)),
    )
    with pytest.raises(EngagementError, match="matching independent execution approval"):
        run_engagement(definition)
    with pytest.raises(EngagementError, match="maximum requests must be positive"):
        run_engagement(definition, approved_max_requests=1.5)  # type: ignore[arg-type]
    with pytest.raises(EngagementError, match="maximum retries must be a non-negative integer"):
        run_engagement(definition, approved_max_retries=-1)
    result = run_engagement(
        definition,
        approved_authorization_reference="SOW-42",
        allowed_remote_hosts=("192.0.2.10",),
        allowed_remote_ports=(443,),
        approved_max_requests=20,
        approved_requests_per_minute=60,
        approved_max_concurrency=1,
        approved_max_retries=1,
        approved_max_timeout_seconds=30,
        approved_max_trials_per_variant=1,
        approved_max_variants_per_case=50,
        approved_max_response_bytes=2_000_000,
        approved_max_evidence_bytes=64_000_000,
    )
    assert result.report.request_count == 1
    with pytest.raises(EngagementError, match="maximum requests"):
        run_engagement(
            definition,
            approved_authorization_reference="SOW-42",
            allowed_remote_hosts=("192.0.2.10",),
            allowed_remote_ports=(443,),
            approved_max_requests=19,
            approved_requests_per_minute=60,
            approved_max_concurrency=1,
            approved_max_retries=1,
            approved_max_timeout_seconds=30,
            approved_max_trials_per_variant=1,
            approved_max_variants_per_case=50,
            approved_max_response_bytes=2_000_000,
            approved_max_evidence_bytes=64_000_000,
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("request_count", 2),
        ("target_name", "other"),
        ("authorization_reference", "other"),
    ],
)
def test_report_envelope_detects_control_field_tampering(
    tmp_path: Path,
    field: str,
    value: object,
) -> None:
    path = save_report(_report(), tmp_path / "report.json")
    raw = json.loads(path.read_text(encoding="utf-8"))
    raw[field] = value
    if field == "request_count":
        raw["summary"]["requests"] = value
    path.write_text(json.dumps(raw), encoding="utf-8")
    assert any(
        "report integrity digest mismatch" in error
        for error in verify_report_evidence(load_report(path))
    )


def test_report_loader_rejects_non_boolean_oracle_decision() -> None:
    raw = json.loads(json.dumps(_report().to_dict()))
    raw["attempts"][0]["oracle"]["success"] = "false"
    with pytest.raises(ReportError, match="true or false"):
        report_from_dict(raw)


def test_report_loader_rejects_tampered_derived_fields() -> None:
    for field in ("findings", "summary"):
        raw = json.loads(json.dumps(_report().to_dict()))
        raw[field] = [{}] if field == "findings" else []
        with pytest.raises(ReportError, match="derived field"):
            report_from_dict(raw)


def test_report_loader_rejects_unknown_omitted_and_coerced_fields() -> None:
    for mutation in ("unknown", "omitted", "coerced"):
        raw = json.loads(json.dumps(_report().to_dict()))
        if mutation == "unknown":
            raw["unexpected"] = True
        elif mutation == "omitted":
            del raw["tool_version"]
        else:
            raw["request_count"] = True
        with pytest.raises(ReportError, match="canonical schema"):
            report_from_dict(raw)


def test_finding_identifier_uses_128_bits() -> None:
    finding_id = _report("LAB_HARDENING").findings[0].finding_id
    assert finding_id.startswith("APPWN-")
    assert len(finding_id.removeprefix("APPWN-")) == 32


def test_resume_rejects_scope_and_job_set_changes() -> None:
    compatibility = RunConfig(allow_unauthenticated_resume=True)
    baseline = Runner(
        FakeTarget("safe"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
        config=compatibility,
    ).run([_case()])
    with pytest.raises(ValueError, match="binding"):
        Runner(
            FakeTarget("safe"),
            scope=Scope.local_only(max_requests=101, requests_per_minute=1_000_000),
            config=compatibility,
        ).run(
            [_case()],
            resume_from=baseline,
            expected_resume_integrity_sha256=baseline.integrity_sha256,
        )
    with pytest.raises(ValueError, match="binding"):
        Runner(
            FakeTarget("safe"),
            scope=Scope.local_only(requests_per_minute=1_000_000),
            config=compatibility,
        ).run(
            [_case(), AttackCase("new", "New", "prompt", CanaryLeakOracle("LAB_NEW"))],
            resume_from=baseline,
            expected_resume_integrity_sha256=baseline.integrity_sha256,
        )


def test_rerun_error_preserves_cumulative_request_count() -> None:
    calls = 0

    def flaky(messages: Sequence[Message]) -> str:
        nonlocal calls
        del messages
        calls += 1
        if calls == 1:
            raise RuntimeError("temporary")
        return "safe"

    scope = Scope.local_only(max_requests=4, requests_per_minute=1_000_000)
    config = RunConfig(checkpoint_hmac_key="k" * 32)
    target = FakeTarget(flaky)
    failed = Runner(target, scope=scope, config=config).run([_case()])
    resumed = Runner(target, scope=scope, config=config).run(
        [_case()],
        resume_from=failed,
        expected_resume_integrity_sha256=failed.integrity_sha256,
    )
    assert resumed.request_count == 2
    assert resumed.attempts[0].request_attempts == 2
    assert verify_report_evidence(resumed) == ()


def test_runner_seals_malformed_target_output_as_an_error() -> None:
    target = FakeTarget(lambda messages: [])  # type: ignore[arg-type,return-value]
    report = Runner(
        target,
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([_case()])
    assert report.errors == 1
    assert report.attempts[0].response is None
    assert "target response content" in (report.attempts[0].error or "")


def test_runner_retains_crash_conservative_predispatch_checkpoint() -> None:
    checkpoints = []

    def interrupt(messages: Sequence[Message]) -> str:
        del messages
        raise KeyboardInterrupt

    with pytest.raises(KeyboardInterrupt):
        Runner(
            FakeTarget(interrupt),
            scope=Scope.local_only(max_requests=2, requests_per_minute=1_000_000),
            config=RunConfig(retries=1, checkpoint_hmac_key="k" * 32),
            checkpoint_callback=checkpoints.append,
        ).run([_case()])
    assert len(checkpoints) == 1
    assert checkpoints[0].request_count == 2
    assert checkpoints[0].metadata["unresolved_request_count"] == 2
    assert verify_report_evidence(checkpoints[0]) == ()


def test_runner_rejects_response_above_cumulative_evidence_limit() -> None:
    report = Runner(
        FakeTarget("x" * 1_100_000),
        scope=Scope.local_only(requests_per_minute=1_000_000),
        config=RunConfig(max_evidence_bytes=1_000_000),
    ).run([_case()])
    assert report.errors == 1
    assert report.attempts[0].response is None
    assert "target response exceeds" in (report.attempts[0].error or "")


def test_manifest_paths_are_confined_unless_explicitly_approved(tmp_path: Path) -> None:
    workspace = tmp_path / "workspace"
    manifest = write_starter_engagement(workspace / "engagement.yaml")
    outside = write_starter_corpus(tmp_path / "outside.yaml")
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "corpus: cases.yaml", "corpus: ../outside.yaml"
        ),
        encoding="utf-8",
    )
    with pytest.raises(EngagementError, match="outside the manifest directory"):
        load_engagement(manifest)
    assert load_engagement(manifest, allow_external_paths=True).corpus_path == outside.resolve()


def test_manifest_credentials_require_independent_approval(tmp_path: Path) -> None:
    definition = load_engagement(write_starter_engagement(tmp_path / "engagement.yaml"))
    definition = definition.__class__(
        engagement_id=definition.engagement_id,
        name=definition.name,
        owner=definition.owner,
        corpus_path=definition.corpus_path,
        target=TargetSpec(
            kind="http-json",
            endpoint="http://127.0.0.1:9",
            response_path="answer",
            headers_env={"X-Lab-Key": "SHARED_SECRET"},
        ),
        scope=definition.scope,
        execution=ExecutionSpec(strategies=("direct",)),
        output=definition.output,
        source=definition.source,
    )
    with pytest.raises(EngagementError, match="--allow-env: SHARED_SECRET"):
        run_engagement(definition)


def test_manifest_redaction_environment_requires_independent_approval(tmp_path: Path) -> None:
    definition = load_engagement(write_starter_engagement(tmp_path / "engagement.yaml"))
    definition = replace(
        definition,
        execution=replace(definition.execution, redact_env=("EXTRA_SECRET",)),
    )
    with pytest.raises(EngagementError, match="--allow-env: EXTRA_SECRET"):
        run_engagement(definition)


def test_corpus_resource_and_alias_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import advent_prompt_pwn.corpus as corpus_module

    path = tmp_path / "large.yaml"
    path.write_text("version: 1\ncases: []\n", encoding="utf-8")
    monkeypatch.setattr(corpus_module, "MAX_CORPUS_BYTES", 1)
    with pytest.raises(CorpusError, match="exceeds"):
        load_corpus_definition(path)
    monkeypatch.setattr(corpus_module, "MAX_CORPUS_BYTES", 10_000_000)
    alias = tmp_path / "alias.yaml"
    alias.write_text(
        "version: 1\nname: shared\nmetadata: &shared {x: 1}\nduplicate: *shared\ncases: []\n",
        encoding="utf-8",
    )
    with pytest.raises(CorpusError, match="aliased"):
        load_corpus_definition(alias)

    duplicate = tmp_path / "duplicate-key.yaml"
    duplicate.write_text(
        "version: 1\nversion: 1\nname: duplicate\ncases: []\n",
        encoding="utf-8",
    )
    with pytest.raises(CorpusError, match="duplicate key"):
        load_corpus_definition(duplicate)


def test_regex_and_oracle_tree_have_execution_bounds(monkeypatch: pytest.MonkeyPatch) -> None:
    import advent_prompt_pwn.oracles as oracle_module

    monkeypatch.setattr(oracle_module, "REGEX_TIMEOUT_SECONDS", 1e-9)
    oracle = RegexOracle(r"(a+)+$")
    case = _case()
    variant = AttackVariant("v", case.case_id, "direct", (Message(Role.USER, "x"),))
    with pytest.raises(ValueError, match="evaluation budget"):
        oracle.evaluate(case, variant, TargetResponse("a" * 10_000 + "!"))

    spec: dict[str, object] = {"type": "contains", "value": "x"}
    for _ in range(10):
        spec = {"type": "any", "oracles": [spec]}
    with pytest.raises(ValueError, match="nesting depth"):
        oracle_from_spec(spec)
    with pytest.raises(ValueError, match="true or false"):
        oracle_from_spec({"type": "contains", "value": "x", "case_sensitive": "false"})


def test_bundle_requires_unique_checksummed_report_and_bound_metadata(tmp_path: Path) -> None:
    directory = write_evidence_bundle(_report(), tmp_path / "bundle")
    manifest = directory / "bundle-manifest.json"
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    report_entry = next(item for item in raw["files"] if item["path"] == "report.json")
    raw["files"].append(report_entry)
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    assert any(
        "duplicate bundle path" in error for error in verify_evidence_bundle(directory).errors
    )

    raw["files"] = [item for item in raw["files"] if item["path"] != "report.json"]
    raw["target_name"] = "other"
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    errors = verify_evidence_bundle(directory).errors
    assert "bundle manifest is missing report.json" in errors
    assert "bundle target name does not match report" in errors


def test_bundle_rejects_unlisted_members_and_invalid_report_objects(tmp_path: Path) -> None:
    directory = write_evidence_bundle(_report(), tmp_path / "bundle")
    (directory / "unexpected.txt").write_text("untrusted", encoding="utf-8")
    assert "unlisted bundle member: unexpected.txt" in verify_evidence_bundle(directory).errors
    invalid = replace(_report(), integrity_sha256="0" * 64)
    with pytest.raises(ReportError, match="invalid integrity"):
        write_evidence_bundle(invalid, tmp_path / "invalid")


def test_bundle_manifest_and_entry_limits(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.bundle as bundle_module

    directory = write_evidence_bundle(_report(), tmp_path / "bundle")
    manifest = directory / "bundle-manifest.json"
    monkeypatch.setattr(bundle_module, "MAX_BUNDLE_MANIFEST_BYTES", 1)
    assert any("manifest exceeds" in error for error in verify_evidence_bundle(directory).errors)

    monkeypatch.setattr(bundle_module, "MAX_BUNDLE_MANIFEST_BYTES", 1_000_000)
    raw = json.loads(manifest.read_text(encoding="utf-8"))
    raw["files"][0]["size"] = True
    manifest.write_text(json.dumps(raw), encoding="utf-8")
    assert any("invalid size" in error for error in verify_evidence_bundle(directory).errors)


def test_bundle_rejects_duplicate_json_keys_and_excess_directory_members(
    tmp_path: Path,
) -> None:
    directory = write_evidence_bundle(_report(), tmp_path / "bundle")
    manifest = directory / "bundle-manifest.json"
    original = manifest.read_text(encoding="utf-8")
    manifest.write_text(
        original.replace(
            '"bundle_version": 1,',
            '"bundle_version": 1,\n  "bundle_version": 1,',
        ),
        encoding="utf-8",
    )
    assert any(
        "duplicate JSON object key" in error
        for error in verify_evidence_bundle(directory).errors
    )

    manifest.write_text(original, encoding="utf-8")
    for index in range(20):
        (directory / f"unexpected-{index}.txt").write_text("x", encoding="utf-8")
    assert "bundle contains too many directory members" in verify_evidence_bundle(
        directory
    ).errors


def test_report_and_bundle_writers_reject_oversized_rendering(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.reporters as reporter_module

    monkeypatch.setattr(reporter_module, "MAX_REPORT_BYTES", 1)
    with pytest.raises(ValueError, match="rendered report exceeds"):
        save_report(_report(), tmp_path / "report.json")
    destination = tmp_path / "bundle"
    with pytest.raises(ValueError, match="rendered report exceeds"):
        write_evidence_bundle(_report(), destination)
    assert not destination.exists()


def test_bundle_writer_enforces_file_total_and_safe_force_boundaries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.bundle as bundle_module

    monkeypatch.setattr(bundle_module, "MAX_BUNDLE_FILE_BYTES", 1)
    with pytest.raises(ValueError, match="bundle file exceeds"):
        write_evidence_bundle(_report(), tmp_path / "file-limit")
    monkeypatch.setattr(bundle_module, "MAX_BUNDLE_FILE_BYTES", 100_000_000)
    monkeypatch.setattr(bundle_module, "MAX_BUNDLE_TOTAL_BYTES", 1)
    with pytest.raises(ValueError, match="cumulative"):
        write_evidence_bundle(_report(), tmp_path / "total-limit")

    monkeypatch.setattr(bundle_module, "MAX_BUNDLE_TOTAL_BYTES", 500_000_000)
    destination = tmp_path / "existing"
    destination.mkdir()
    (destination / "unexpected.txt").write_text("keep", encoding="utf-8")
    original_iterdir = Path.iterdir
    enumerated = 0

    def bounded_iterdir(path: Path):
        nonlocal enumerated
        for member in original_iterdir(path):
            if path == destination:
                enumerated += 1
                if enumerated > 1:
                    raise AssertionError("force-mode destination enumeration was not bounded")
            yield member

    monkeypatch.setattr(Path, "iterdir", bounded_iterdir)
    with pytest.raises(FileExistsError, match="unexpected member"):
        write_evidence_bundle(_report(), destination, force=True)
    assert enumerated == 1
    assert (destination / "unexpected.txt").read_text(encoding="utf-8") == "keep"


def test_comparison_and_reproducer_writers_enforce_output_bounds(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.comparison as comparison_module
    import advent_prompt_pwn.reproducers as reproducer_module
    from advent_prompt_pwn.comparison import compare_reports
    from advent_prompt_pwn.reproducers import save_minimal_reproducers

    monkeypatch.setattr(comparison_module, "MAX_REPORT_BYTES", 1)
    with pytest.raises(ValueError, match="rendered report exceeds"):
        comparison_module.save_comparison(
            compare_reports(_report(), _report()),
            tmp_path / "comparison.json",
        )
    monkeypatch.setattr(reproducer_module, "MAX_REPORT_BYTES", 1)
    with pytest.raises(ValueError, match="rendered report exceeds"):
        save_minimal_reproducers(_report("LAB_HARDENING"), tmp_path / "reproducers.json")


def test_markdown_renderer_neutralizes_active_markup() -> None:
    case = AttackCase(
        "case",
        '<img src="https://attacker.invalid/x"> [click](https://attacker.invalid)',
        "prompt",
        CanaryLeakOracle("LAB_HARDENING"),
    )
    report = Runner(
        FakeTarget("safe"),
        scope=Scope.local_only(requests_per_minute=1_000_000),
    ).run([case])
    rendered = report_markdown(report)
    assert "| <img" not in rendered
    assert "[click](" not in rendered
    assert "\\<img" in rendered
