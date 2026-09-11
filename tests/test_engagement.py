from __future__ import annotations

from dataclasses import replace
from pathlib import Path

import pytest

from advent_prompt_pwn.engagement import (
    ExecutionSpec,
    ScopeSpec,
    TargetSpec,
    _build_target,
    _load_extra_body,
    load_engagement,
    plan_engagement,
    run_engagement,
    write_starter_engagement,
)
from advent_prompt_pwn.exceptions import EngagementError, ScopeViolation


def _definition(tmp_path: Path):
    manifest = write_starter_engagement(tmp_path / "engagement.yaml")
    definition = load_engagement(manifest)
    return replace(
        definition,
        scope=replace(definition.scope, requests_per_minute=1_000_000),
    )


def test_starter_engagement_plans_and_runs_locally(tmp_path: Path) -> None:
    definition = _definition(tmp_path)
    plan = plan_engagement(definition)
    assert plan.variants == 8
    assert plan.planned_attempts == 8
    assert len(plan.cases) == 1
    result = run_engagement(definition)
    assert result.report.engagement_id == "local-lab-001"
    assert result.report.corpus_sha256 == result.corpus.sha256
    assert result.report.request_count == 8
    assert result.report.metadata["planned_variants"] == 8
    assert result.report.metadata["planned_attempts"] == 8


def test_engagement_trials_are_included_in_preflight_budget(tmp_path: Path) -> None:
    definition = _definition(tmp_path)
    repeated = replace(
        definition,
        execution=replace(
            definition.execution,
            strategies=("direct",),
            trials_per_variant=3,
        ),
        scope=replace(definition.scope, max_requests=3),
    )
    plan = plan_engagement(repeated)
    assert plan.variants == 1
    assert plan.planned_attempts == 3
    report = run_engagement(repeated).report
    assert len(report.attempts) == 3
    assert len(report.trial_statistics) == 1

    too_small = replace(repeated, scope=replace(repeated.scope, max_requests=2))
    with pytest.raises(EngagementError, match="at least 3"):
        plan_engagement(too_small)


def test_engagement_redacts_environment_values(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENGAGEMENT_SECRET", "synthetic-private-value")
    definition = _definition(tmp_path)
    definition = replace(
        definition,
        target=replace(definition.target, fake_response="synthetic-private-value"),
        execution=replace(
            definition.execution,
            strategies=("direct",),
            redact_env=("ENGAGEMENT_SECRET",),
        ),
    )
    report = run_engagement(
        definition,
        allowed_environment_variables=("ENGAGEMENT_SECRET",),
    ).report
    assert report.attempts[0].response is not None
    assert report.attempts[0].response.content == "[REDACTED]"


def test_engagement_checkpoint_key_and_execution_grants_are_validated(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    definition = _definition(tmp_path)
    with pytest.raises(EngagementError, match="cannot be used with local scope"):
        run_engagement(definition, allowed_remote_hosts=("192.0.2.1",))
    with pytest.raises(EngagementError, match="invalid approved environment"):
        run_engagement(definition, allowed_environment_variables=("NOT VALID",))

    keyed = replace(
        definition,
        execution=replace(
            definition.execution,
            strategies=("direct",),
            checkpoint_hmac_env="APPWN_CHECKPOINT_KEY",
        ),
    )
    with pytest.raises(EngagementError, match="--allow-env"):
        run_engagement(keyed)
    with pytest.raises(EngagementError, match="is not set"):
        run_engagement(keyed, allowed_environment_variables=("APPWN_CHECKPOINT_KEY",))
    monkeypatch.setenv("APPWN_CHECKPOINT_KEY", "short")
    with pytest.raises(EngagementError, match="at least 32"):
        run_engagement(keyed, allowed_environment_variables=("APPWN_CHECKPOINT_KEY",))


def test_engagement_filters_and_budget_are_validated(tmp_path: Path) -> None:
    definition = _definition(tmp_path)
    selected = replace(
        definition,
        execution=replace(
            definition.execution,
            strategies=("direct",),
            include_tags=("canary",),
        ),
    )
    assert plan_engagement(selected).variants == 1
    too_small = replace(definition, scope=replace(definition.scope, max_requests=1))
    with pytest.raises(EngagementError, match="at least"):
        plan_engagement(too_small)
    unknown_case = replace(
        definition,
        execution=replace(definition.execution, case_ids=("missing",)),
    )
    with pytest.raises(EngagementError, match="selected no"):
        plan_engagement(unknown_case)
    partly_unknown = replace(
        definition,
        execution=replace(
            definition.execution,
            strategies=("direct",),
            case_ids=("direct-canary", "missing"),
        ),
    )
    with pytest.raises(EngagementError, match=r"unknown execution\.case_ids"):
        plan_engagement(partly_unknown)


def test_engagement_remote_scope_preflight_blocks_insecure_transport(tmp_path: Path) -> None:
    definition = _definition(tmp_path)
    remote = replace(
        definition,
        target=TargetSpec(
            kind="openai-compatible",
            model="lab",
            base_url="http://ai.example.test/v1",
        ),
        scope=ScopeSpec(
            mode="authorized_remote",
            authorization_reference="SOW-42",
            allowed_hosts=("ai.example.test",),
            allowed_ports=(80,),
            max_requests=20,
            allow_unpinned_dns=True,
        ),
        execution=ExecutionSpec(strategies=("direct",)),
    )
    with pytest.raises(ScopeViolation, match="insecure"):
        plan_engagement(remote)
    allowed = replace(remote, scope=replace(remote.scope, allow_insecure_http=True))
    assert plan_engagement(allowed).variants == 1


def test_engagement_preflight_bounds_worst_case_remote_evidence(tmp_path: Path) -> None:
    definition = _definition(tmp_path)
    oversized = replace(
        definition,
        target=TargetSpec(kind="ollama", model="lab", max_response_bytes=2_000_000),
        execution=ExecutionSpec(strategies=("direct",), max_evidence_bytes=1_000_000),
    )
    with pytest.raises(EngagementError, match="worst-case"):
        plan_engagement(oversized)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (
            "version: 2\nengagement: {id: ok, name: n, owner: o, "
            "authorization_reference: r}\ncorpus: cases.yaml\ntarget: {type: fake}\n"
            "scope: {mode: local, max_requests: 1, requests_per_minute: 1, "
            "max_concurrency: 1}",
            "version",
        ),
        (
            "version: 1\nengagement: {}\ncorpus: cases.yaml\ntarget: {type: fake}\n"
            "scope: {mode: local, max_requests: 1, requests_per_minute: 1, "
            "max_concurrency: 1}",
            "engagement.*missing required",
        ),
        (
            "version: 1\nengagement: {id: ok, name: n, owner: o, "
            "authorization_reference: r}\ncorpus: cases.yaml\n"
            "target: {type: unsupported}\nscope: {mode: local, max_requests: 1, "
            "requests_per_minute: 1, max_concurrency: 1}",
            "target.type must be one of",
        ),
    ],
)
def test_invalid_engagement_manifests_are_rejected(
    tmp_path: Path,
    text: str,
    message: str,
) -> None:
    path = tmp_path / "invalid.yaml"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(EngagementError, match=message):
        load_engagement(path)


def test_engagement_manifest_rejects_duplicate_yaml_keys(tmp_path: Path) -> None:
    manifest = write_starter_engagement(tmp_path / "engagement.yaml")
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(
            "version: 1",
            "version: 1\nversion: 1",
            1,
        ),
        encoding="utf-8",
    )
    with pytest.raises(EngagementError, match="duplicate key"):
        load_engagement(manifest)


@pytest.mark.parametrize(
    ("old", "new", "message"),
    [
        (
            "max_requests: 200",
            "max_requests: 200\n  max_request: 1",
            "unknown field",
        ),
        ("max_requests: 200", "", "missing required"),
        ("max_requests: 200", 'max_requests: "200"', "type integer"),
        (
            "type: fake",
            "type: fake\n  headers_env: {Host: APPWN_HOST}",
            "must not override Host",
        ),
    ],
)
def test_manifest_enforces_strict_security_contract(
    tmp_path: Path,
    old: str,
    new: str,
    message: str,
) -> None:
    manifest = write_starter_engagement(tmp_path / "engagement.yaml")
    manifest.write_text(
        manifest.read_text(encoding="utf-8").replace(old, new),
        encoding="utf-8",
    )
    with pytest.raises(EngagementError, match=message):
        load_engagement(manifest)


def test_starter_engagement_does_not_overwrite(tmp_path: Path) -> None:
    path = write_starter_engagement(tmp_path / "engagement.yaml")
    with pytest.raises(FileExistsError, match="overwrite"):
        write_starter_engagement(path)


def test_target_factories_cover_supported_network_adapters(tmp_path: Path) -> None:
    extra = tmp_path / "extra.json"
    extra.write_text('{"temperature": 0}', encoding="utf-8")
    targets = [
        _build_target(TargetSpec(kind="ollama", model="lab")),
        _build_target(
            TargetSpec(
                kind="openai-compatible",
                model="lab",
                base_url="https://example.test/v1",
                extra_body_file=extra,
            )
        ),
        _build_target(TargetSpec(kind="openai", model="gpt-lab")),
        _build_target(
            TargetSpec(
                kind="azure-openai",
                resource="resource-lab",
                deployment="deployment-lab",
                api_version="2026-01-01",
            )
        ),
        _build_target(TargetSpec(kind="anthropic", model="claude-lab")),
        _build_target(TargetSpec(kind="gemini", model="gemini-lab")),
        _build_target(
            TargetSpec(
                kind="http-json",
                endpoint="https://example.test/chat",
                response_path="answer",
            )
        ),
    ]
    try:
        assert [target.endpoint for target in targets] == [
            "http://127.0.0.1:11434/api/chat",
            "https://example.test/v1/chat/completions",
            "https://api.openai.com/v1/chat/completions",
            "https://resource-lab.openai.azure.com/openai/deployments/"
            "deployment-lab/chat/completions?api-version=2026-01-01",
            "https://api.anthropic.com/v1/messages",
            "https://generativelanguage.googleapis.com/v1beta/models/"
            "gemini-lab:generateContent",
            "https://example.test/chat",
        ]
    finally:
        for target in targets:
            target.close()


def test_engagement_scope_parses_time_window_and_dns_pins(tmp_path: Path) -> None:
    manifest = write_starter_engagement(tmp_path / "engagement.yaml")
    text = manifest.read_text(encoding="utf-8")
    manifest.write_text(
        text.replace(
            "mode: local",
            "mode: authorized_remote\n  allowed_hosts: [ai.example.test]\n"
            "  allowed_ports: [443]",
        ).replace(
            "pinned_dns: {}\n  not_before: null\n  not_after: null",
            "pinned_dns:\n    ai.example.test: [192.0.2.10]\n"
            "  not_before: '2030-01-01T00:00:00Z'\n"
            "  not_after: '2030-01-02T00:00:00Z'",
        ),
        encoding="utf-8",
    )
    definition = load_engagement(manifest)
    assert definition.scope.pinned_dns == {"ai.example.test": ("192.0.2.10",)}
    assert definition.scope.not_before == "2030-01-01T00:00:00Z"


def test_remote_preflight_accepts_future_window_and_pins_without_dns_lookup(
    tmp_path: Path,
) -> None:
    definition = _definition(tmp_path)
    remote = replace(
        definition,
        target=TargetSpec(
            kind="openai-compatible",
            model="lab",
            base_url="https://ai.example.test/v1",
        ),
        scope=ScopeSpec(
            mode="authorized_remote",
            authorization_reference="SOW-43",
            allowed_hosts=("ai.example.test",),
            allowed_ports=(443,),
            max_requests=2,
            requests_per_minute=60,
            pinned_dns={"ai.example.test": ("192.0.2.10",)},
            not_before="2030-01-01T00:00:00Z",
            not_after="2030-01-02T00:00:00Z",
        ),
        execution=ExecutionSpec(strategies=("direct",)),
    )
    assert plan_engagement(remote).variants == 1


def test_extra_body_validation(tmp_path: Path) -> None:
    invalid = tmp_path / "invalid.json"
    invalid.write_text("[]", encoding="utf-8")
    with pytest.raises(EngagementError, match="JSON object"):
        _load_extra_body(invalid)
    override = tmp_path / "override.json"
    override.write_text('{"messages": []}', encoding="utf-8")
    with pytest.raises(EngagementError, match="must not override"):
        _load_extra_body(override)
    malformed = tmp_path / "malformed.json"
    malformed.write_text("{", encoding="utf-8")
    with pytest.raises(EngagementError, match="could not load"):
        _load_extra_body(malformed)


def test_manifest_rejects_invalid_boolean_header_and_output_format(tmp_path: Path) -> None:
    manifest = write_starter_engagement(tmp_path / "engagement.yaml")
    text = manifest.read_text(encoding="utf-8")
    manifest.write_text(
        text.replace("stop_on_error: false", 'stop_on_error: "false"'),
        encoding="utf-8",
    )
    with pytest.raises(EngagementError, match="type boolean"):
        load_engagement(manifest)

    manifest.write_text(
        text.replace("formats: [json, markdown, html, sarif]", "formats: [binary]"),
        encoding="utf-8",
    )
    with pytest.raises(EngagementError, match=r"output\.formats.*must be one of"):
        load_engagement(manifest)

    manifest.write_text(
        text.replace(
            "type: fake\n  name: local-safe-target",
            "type: http-json\n  endpoint: https://example.test\n"
            "  response_path: answer\n  headers_env:\n    'Bad Header': TOKEN\n"
            "  name: local-safe-target",
        ),
        encoding="utf-8",
    )
    with pytest.raises(EngagementError, match="header"):
        load_engagement(manifest)
