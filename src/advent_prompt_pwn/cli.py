"""Command-line interface for authorized AI red-team runs."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import sys
from collections.abc import Sequence
from pathlib import Path

from advent_prompt_pwn import __version__
from advent_prompt_pwn.bundle import verify_evidence_bundle, write_evidence_bundle
from advent_prompt_pwn.comparison import (
    compare_reports,
    comparison_plan_identity,
    save_comparison,
)
from advent_prompt_pwn.core.models import RunReport
from advent_prompt_pwn.core.runner import (
    RunConfig,
    Runner,
    verify_checkpoint_authentication,
)
from advent_prompt_pwn.core.scope import Scope
from advent_prompt_pwn.corpus import (
    load_corpus,
    load_corpus_definition,
    write_starter_corpus,
)
from advent_prompt_pwn.engagement import (
    load_engagement,
    plan_engagement,
    run_engagement,
    write_starter_engagement,
)
from advent_prompt_pwn.exceptions import AdventPromptPwnError
from advent_prompt_pwn.io import atomic_write_text, read_bounded_bytes
from advent_prompt_pwn.parsing import load_json_strict
from advent_prompt_pwn.report_io import load_report, verify_report_evidence
from advent_prompt_pwn.reporters import save_report
from advent_prompt_pwn.reproducers import save_minimal_reproducers, select_minimal_reproducers
from advent_prompt_pwn.schema import SCHEMA_NAMES, get_schema
from advent_prompt_pwn.strategies import CompositeStrategy, get_strategy, strategy_names
from advent_prompt_pwn.targets import (
    FakeTarget,
    HttpJsonTarget,
    OllamaTarget,
    OpenAICompatibleTarget,
    Target,
)
from advent_prompt_pwn.validation import validate_json_value

_ENVIRONMENT_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_HEADER_NAME = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]+$")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="advent-prompt-pwn",
        description="Authorized adversarial testing for AI systems.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    init = subparsers.add_parser("init", help="create a safe starter corpus")
    init.add_argument("path", nargs="?", default="cases.yaml")
    init.add_argument("--force", action="store_true")

    validate = subparsers.add_parser("validate", help="validate a corpus without running it")
    validate.add_argument("corpus")

    subparsers.add_parser("strategies", help="list available attack strategies")
    subparsers.add_parser("doctor", help="check the local runtime")

    engagement = subparsers.add_parser(
        "engagement",
        help="initialize, validate, or run a versioned engagement manifest",
    )
    engagement_commands = engagement.add_subparsers(
        dest="engagement_command",
        required=True,
    )
    engagement_init = engagement_commands.add_parser("init", help="create a safe manifest")
    engagement_init.add_argument("path", nargs="?", default="engagement.yaml")
    engagement_init.add_argument("--force", action="store_true")
    engagement_validate = engagement_commands.add_parser(
        "validate",
        help="validate a manifest and its corpus",
    )
    engagement_validate.add_argument("manifest")
    engagement_validate.add_argument("--allow-external-paths", action="store_true")
    engagement_run = engagement_commands.add_parser("run", help="run an engagement")
    engagement_run.add_argument("manifest")
    engagement_run.add_argument("--resume")
    engagement_run.add_argument("--resume-integrity")
    engagement_run.add_argument("--checkpoint")
    engagement_run.add_argument("--output-dir")
    engagement_run.add_argument(
        "--format",
        action="append",
        choices=("json", "jsonl", "html", "markdown", "junit", "sarif"),
    )
    engagement_run.add_argument("--quiet", action="store_true")
    engagement_run.add_argument("--allow-env", action="append", default=[], metavar="ENV_VAR")
    engagement_run.add_argument("--authorization-ref")
    engagement_run.add_argument("--allow-host", action="append", default=[])
    engagement_run.add_argument("--allow-port", action="append", type=int, default=[])
    engagement_run.add_argument("--allow-query-parameter", action="append", default=[])
    engagement_run.add_argument("--allow-insecure-http", action="store_true")
    engagement_run.add_argument("--allow-unpinned-dns", action="store_true")
    engagement_run.add_argument("--approve-max-requests", type=int)
    engagement_run.add_argument("--approve-requests-per-minute", type=int)
    engagement_run.add_argument("--approve-max-concurrency", type=int)
    engagement_run.add_argument("--approve-max-retries", type=int)
    engagement_run.add_argument("--approve-max-timeout", type=float)
    engagement_run.add_argument("--approve-max-trials-per-variant", type=int)
    engagement_run.add_argument("--approve-max-variants-per-case", type=int)
    engagement_run.add_argument("--approve-max-response-bytes", type=int)
    engagement_run.add_argument("--approve-max-evidence-bytes", type=int)
    engagement_run.add_argument("--allow-unauthenticated-resume", action="store_true")
    engagement_run.add_argument("--allow-external-paths", action="store_true")
    engagement_run.add_argument("--overwrite-checkpoint", action="store_true")
    engagement_run.add_argument(
        "--fail-on-findings",
        action=argparse.BooleanOptionalAction,
        default=None,
    )

    compare = subparsers.add_parser("compare", help="compare a run with a baseline")
    compare.add_argument("baseline")
    compare.add_argument("current")
    compare.add_argument("--output", default="comparison.md")
    compare.add_argument("--allow-corpus-change", action="store_true")
    compare.add_argument("--checkpoint-hmac-env", required=True)
    compare.add_argument(
        "--fail-on-regression",
        action=argparse.BooleanOptionalAction,
        default=True,
    )

    reproducers = subparsers.add_parser(
        "reproducers",
        help="extract the shortest observed successful variant for each finding",
    )
    reproducers.add_argument("report")
    reproducers.add_argument("--output", default="reproducers.json")

    verify = subparsers.add_parser("verify", help="verify a JSON report or evidence bundle")
    verify.add_argument("path")
    verify.add_argument("--checkpoint-hmac-env")

    schema = subparsers.add_parser("schema", help="print or save a bundled JSON Schema")
    schema.add_argument("name", choices=SCHEMA_NAMES)
    schema.add_argument("--output")

    run = subparsers.add_parser("run", help="run an authorized assessment")
    run.add_argument("corpus")
    run.add_argument(
        "--target",
        choices=("fake", "http-json", "ollama", "openai-compatible"),
        default="fake",
    )
    run.add_argument("--model")
    run.add_argument("--base-url")
    run.add_argument("--api-key-env")
    run.add_argument("--extra-body-file")
    run.add_argument("--request-mode", choices=("messages", "prompt"), default="messages")
    run.add_argument("--request-field", default="messages")
    run.add_argument("--response-path")
    run.add_argument("--tool-calls-path")
    run.add_argument("--max-response-bytes", type=int, default=2_000_000)
    run.add_argument("--max-evidence-bytes", type=int, default=64_000_000)
    run.add_argument(
        "--header-env",
        action="append",
        default=[],
        metavar="HEADER=ENV_VAR",
    )
    run.add_argument("--fake-response", default="SAFE_RESPONSE")
    run.add_argument(
        "--strategy",
        action="append",
        choices=strategy_names(),
        default=None,
        help="repeat to combine strategies; default: direct",
    )
    run.add_argument("--output", default="reports/report.json")
    run.add_argument(
        "--format",
        choices=("json", "jsonl", "html", "markdown", "junit", "sarif"),
    )
    run.add_argument("--seed", type=int, default=0)
    run.add_argument("--timeout", type=float, default=30.0)
    run.add_argument("--retries", type=int, default=0)
    run.add_argument("--retry-backoff", type=float, default=0.5)
    run.add_argument("--concurrency", type=int, default=1)
    run.add_argument("--trials-per-variant", type=int, default=1)
    run.add_argument("--max-variants-per-case", type=int, default=50)
    run.add_argument("--checkpoint-interval", type=int, default=10)
    run.add_argument("--max-requests", type=int, default=100)
    run.add_argument("--requests-per-minute", type=int, default=60)
    run.add_argument("--redact", action="append", default=[])
    run.add_argument("--redact-env", action="append", default=[])
    run.add_argument("--authorized", action="store_true")
    run.add_argument("--allow-host", action="append", default=[])
    run.add_argument("--allow-port", action="append", type=int, default=[])
    run.add_argument("--allow-insecure-http", action="store_true")
    run.add_argument("--allow-query-parameter", action="append", default=[])
    run.add_argument("--allow-unpinned-dns", action="store_true")
    run.add_argument("--authorization-ref")
    run.add_argument("--resume")
    run.add_argument("--resume-integrity")
    run.add_argument("--checkpoint")
    run.add_argument("--checkpoint-hmac-env")
    run.add_argument("--allow-unauthenticated-resume", action="store_true")
    run.add_argument("--bundle")
    run.add_argument(
        "--fail-on-findings",
        action=argparse.BooleanOptionalAction,
        default=True,
    )
    return parser


def _extra_body(path: str | None) -> dict[str, object]:
    if not path:
        return {}
    source = Path(path)
    try:
        raw = read_bounded_bytes(source, 1_000_000, label="extra body file")
        value = load_json_strict(raw.decode("utf-8"))
        validate_json_value(value, label="extra body file")
    except (OSError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError(f"could not load extra body file {source}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("extra body file must contain a JSON object")
    return value


def _headers_env(values: Sequence[str]) -> dict[str, str]:
    headers: dict[str, str] = {}
    for value in values:
        name, separator, environment_name = value.partition("=")
        if not separator or not name.strip() or not environment_name.strip():
            raise ValueError("--header-env values must use HEADER=ENV_VAR")
        header = name.strip()
        environment = environment_name.strip()
        if not _HEADER_NAME.fullmatch(header):
            raise ValueError(f"invalid HTTP header name: {header!r}")
        if header.casefold() == "host":
            raise ValueError(
                "--header-env must not override Host; authorize the intended URL host"
            )
        if not _ENVIRONMENT_NAME.fullmatch(environment):
            raise ValueError(f"invalid environment variable name: {environment!r}")
        headers[header] = environment
    return headers


def _target(args: argparse.Namespace) -> Target:
    if args.target == "fake":
        return FakeTarget(args.fake_response)
    if args.target == "http-json":
        if not args.base_url or not args.response_path:
            raise ValueError("--base-url and --response-path are required for http-json")
        return HttpJsonTarget(
            endpoint=args.base_url,
            response_path=args.response_path,
            request_mode=args.request_mode,
            request_field=args.request_field,
            headers_env=_headers_env(args.header_env),
            extra_body=_extra_body(args.extra_body_file),
            tool_calls_path=args.tool_calls_path,
            max_response_bytes=args.max_response_bytes,
        )
    if not args.model:
        raise ValueError(f"--model is required for target {args.target}")
    if args.target == "ollama":
        return OllamaTarget(
            args.model,
            base_url=args.base_url or "http://127.0.0.1:11434",
            max_response_bytes=args.max_response_bytes,
        )
    if not args.base_url:
        raise ValueError("--base-url is required for openai-compatible targets")
    return OpenAICompatibleTarget(
        model=args.model,
        base_url=args.base_url,
        api_key_env=args.api_key_env,
        extra_body=_extra_body(args.extra_body_file),
        max_response_bytes=args.max_response_bytes,
    )


def _scope(args: argparse.Namespace) -> Scope:
    if not args.authorized:
        return Scope.local_only(
            max_requests=args.max_requests,
            requests_per_minute=args.requests_per_minute,
            max_concurrency=args.concurrency,
            authorization_reference=args.authorization_ref,
            allowed_query_parameters=args.allow_query_parameter,
        )
    if not args.authorization_ref:
        raise ValueError("--authorization-ref is required with --authorized")
    return Scope.authorized(
        args.allow_host,
        args.authorization_ref,
        allowed_ports=args.allow_port,
        max_requests=args.max_requests,
        requests_per_minute=args.requests_per_minute,
        max_concurrency=args.concurrency,
        allow_insecure_http=args.allow_insecure_http,
        allowed_query_parameters=args.allow_query_parameter,
        allow_unpinned_dns=args.allow_unpinned_dns,
    )


def _run(args: argparse.Namespace) -> int:
    if bool(args.resume) != bool(args.resume_integrity):
        raise ValueError("--resume and --resume-integrity must be supplied together")
    corpus = load_corpus_definition(args.corpus)
    cases = corpus.cases
    names = args.strategy or ["direct"]
    strategies = [get_strategy(name) for name in names]
    strategy = strategies[0] if len(strategies) == 1 else CompositeStrategy(strategies)
    target = _target(args)
    credential_names = set(args.redact_env)
    checkpoint_hmac_key: str | None = None
    if args.checkpoint_hmac_env:
        if not _ENVIRONMENT_NAME.fullmatch(args.checkpoint_hmac_env):
            raise ValueError(
                f"invalid environment variable name: {args.checkpoint_hmac_env!r}"
            )
        checkpoint_hmac_key = os.environ.get(args.checkpoint_hmac_env)
        if not checkpoint_hmac_key:
            raise ValueError(
                f"environment variable {args.checkpoint_hmac_env!r} is not set"
            )
        credential_names.add(args.checkpoint_hmac_env)
    if args.api_key_env:
        if not _ENVIRONMENT_NAME.fullmatch(args.api_key_env):
            raise ValueError(f"invalid environment variable name: {args.api_key_env!r}")
        credential_names.add(args.api_key_env)
    credential_names.update(_headers_env(args.header_env).values())
    environment_redactions = tuple(
        value for name in sorted(credential_names) if (value := os.environ.get(name))
    )

    def checkpoint_report(checkpoint: RunReport) -> None:
        print(
            f"Checkpoint candidate: {Path(args.checkpoint).resolve()} | "
            f"Run: {checkpoint.run_id} | Requests: {checkpoint.request_count} | "
            f"Integrity: {checkpoint.integrity_sha256}",
            flush=True,
        )
        save_report(checkpoint, args.checkpoint)

    try:
        report = Runner(
            target,
            scope=_scope(args),
            config=RunConfig(
                seed=args.seed,
                timeout_s=args.timeout,
                retries=args.retries,
                retry_backoff_s=args.retry_backoff,
                concurrency=args.concurrency,
                trials_per_variant=args.trials_per_variant,
                max_variants_per_case=args.max_variants_per_case,
                checkpoint_interval=args.checkpoint_interval,
                redact_secrets=(*args.redact, *environment_redactions),
                max_evidence_bytes=args.max_evidence_bytes,
                checkpoint_hmac_key=checkpoint_hmac_key,
                allow_unauthenticated_resume=args.allow_unauthenticated_resume,
            ),
            checkpoint_callback=checkpoint_report if args.checkpoint else None,
            corpus_sha256=corpus.sha256,
            metadata={
                "strategies": names,
                "selected_cases": [case.case_id for case in cases],
                "trials_per_variant": args.trials_per_variant,
            },
        ).run(
            cases,
            strategy,
            resume_from=load_report(args.resume) if args.resume else None,
            expected_resume_integrity_sha256=args.resume_integrity,
        )
    finally:
        target.close()
    destination = save_report(report, args.output, format_name=args.format)
    if args.bundle:
        write_evidence_bundle(report, args.bundle)
    print(f"Report: {destination}")
    if args.checkpoint:
        print(f"Checkpoint: {Path(args.checkpoint).resolve()}")
        print(f"Checkpoint integrity: {report.integrity_sha256}")
    print(
        f"Attempts: {len(report.attempts)} | Adversarial successes: "
        f"{report.attack_successes} | Security passes: {report.security_passes} | "
        f"Errors: {report.errors}"
    )
    if report.errors:
        return 2
    if args.fail_on_findings and report.attack_successes:
        return 1
    return 0


def _engagement(args: argparse.Namespace) -> int:
    if args.engagement_command == "init":
        destination = write_starter_engagement(args.path, force=args.force)
        print(f"Created {destination}")
        return 0
    definition = load_engagement(
        args.manifest,
        allow_external_paths=args.allow_external_paths,
    )
    if args.engagement_command == "validate":
        plan = plan_engagement(definition)
        print(
            f"Valid engagement: {definition.engagement_id} | "
            f"Cases: {len(plan.cases)} | Variants: {plan.variants} | "
            f"Planned attempts: {plan.planned_attempts} | "
            f"Target: {definition.target.kind}"
        )
        return 0
    resume = load_report(args.resume) if args.resume else None
    if bool(args.resume) != bool(args.resume_integrity):
        raise ValueError("--resume and --resume-integrity must be supplied together")
    if resume:
        errors = verify_report_evidence(resume)
        if errors:
            raise ValueError("resume report failed integrity verification: " + "; ".join(errors))

    def progress(result: object, completed: int, total: int) -> None:
        del result
        if not args.quiet:
            print(f"Progress: {completed}/{total}", flush=True)

    root = Path(args.output_dir).resolve() if args.output_dir else definition.output.directory
    checkpoint_path = (
        Path(args.checkpoint).resolve() if args.checkpoint else definition.output.checkpoint_file
    )
    if checkpoint_path and checkpoint_path.exists() and not args.overwrite_checkpoint:
        resume_path = Path(args.resume).resolve() if args.resume else None
        if resume_path != checkpoint_path.resolve():
            raise FileExistsError(
                f"refusing to overwrite existing checkpoint: {checkpoint_path}; "
                "use --overwrite-checkpoint after review"
            )

    def checkpoint(report: RunReport) -> None:
        if checkpoint_path:
            print(
                f"Checkpoint candidate: {checkpoint_path} | Run: {report.run_id} | "
                f"Requests: {report.request_count} | Integrity: {report.integrity_sha256}",
                flush=True,
            )
            save_report(report, checkpoint_path)

    result = run_engagement(
        definition,
        resume_from=resume,
        progress_callback=progress,
        checkpoint_callback=checkpoint if checkpoint_path else None,
        allowed_environment_variables=tuple(args.allow_env),
        approved_authorization_reference=args.authorization_ref,
        allowed_remote_hosts=tuple(args.allow_host),
        allowed_remote_ports=tuple(args.allow_port),
        allowed_query_parameters=tuple(args.allow_query_parameter),
        allow_insecure_http=args.allow_insecure_http,
        allow_unpinned_dns=args.allow_unpinned_dns,
        allow_unauthenticated_resume=args.allow_unauthenticated_resume,
        approved_max_requests=args.approve_max_requests,
        approved_requests_per_minute=args.approve_requests_per_minute,
        approved_max_concurrency=args.approve_max_concurrency,
        approved_max_retries=args.approve_max_retries,
        approved_max_timeout_seconds=args.approve_max_timeout,
        approved_max_trials_per_variant=args.approve_max_trials_per_variant,
        approved_max_variants_per_case=args.approve_max_variants_per_case,
        approved_max_response_bytes=args.approve_max_response_bytes,
        approved_max_evidence_bytes=args.approve_max_evidence_bytes,
        expected_resume_integrity_sha256=args.resume_integrity,
    )
    bundle = write_evidence_bundle(
        result.report,
        root / f"run-{result.report.run_id}",
        formats=tuple(args.format or definition.output.formats),
    )
    print(f"Evidence bundle: {bundle}")
    if checkpoint_path:
        print(f"Checkpoint: {checkpoint_path}")
        print(f"Checkpoint integrity: {result.report.integrity_sha256}")
    print(
        f"Attempts: {len(result.report.attempts)} | Findings: {len(result.report.findings)} | "
        f"Errors: {result.report.errors} | Requests: {result.report.request_count}"
    )
    if result.report.errors:
        return 2
    fail_on_findings = (
        definition.output.fail_on_findings
        if args.fail_on_findings is None
        else args.fail_on_findings
    )
    if fail_on_findings and result.report.findings:
        return 1
    return 0


def _compare(args: argparse.Namespace) -> int:
    if not _ENVIRONMENT_NAME.fullmatch(args.checkpoint_hmac_env):
        raise ValueError(
            f"invalid environment variable name: {args.checkpoint_hmac_env!r}"
        )
    authentication_key = os.environ.get(args.checkpoint_hmac_env)
    if not authentication_key:
        raise ValueError(f"environment variable {args.checkpoint_hmac_env!r} is not set")
    baseline = load_report(args.baseline)
    current = load_report(args.current)
    integrity_errors = (*verify_report_evidence(baseline), *verify_report_evidence(current))
    if integrity_errors:
        raise ValueError("report integrity verification failed: " + "; ".join(integrity_errors))
    if not verify_checkpoint_authentication(
        baseline, authentication_key
    ) or not verify_checkpoint_authentication(current, authentication_key):
        raise ValueError("baseline comparison requires authenticated reports with the supplied key")
    comparison_plan_identity(baseline, required=True, label="baseline")
    comparison_plan_identity(current, required=True, label="current")
    comparison = compare_reports(
        baseline,
        current,
        allow_corpus_change=args.allow_corpus_change,
    )
    destination = save_comparison(comparison, args.output)
    print(f"Comparison: {destination}")
    print(
        f"New findings: {len(comparison.new_findings)} | "
        f"Resolved: {len(comparison.resolved_findings)} | "
        f"Persistent: {len(comparison.persistent_findings)} | "
        f"New errors: {len(comparison.new_error_keys)}"
    )
    return 1 if args.fail_on_regression and comparison.regressed else 0


def _reproducers(args: argparse.Namespace) -> int:
    report = load_report(args.report)
    destination = save_minimal_reproducers(report, args.output)
    selected = select_minimal_reproducers(report)
    print(f"Reproducers: {destination} ({len(selected)} finding(s))")
    return 0


def _verify(args: argparse.Namespace) -> int:
    path = Path(args.path)
    authentication_key: str | None = None
    if args.checkpoint_hmac_env:
        if not _ENVIRONMENT_NAME.fullmatch(args.checkpoint_hmac_env):
            raise ValueError(
                f"invalid environment variable name: {args.checkpoint_hmac_env!r}"
            )
        authentication_key = os.environ.get(args.checkpoint_hmac_env)
        if not authentication_key:
            raise ValueError(
                f"environment variable {args.checkpoint_hmac_env!r} is not set"
            )
    if path.is_dir():
        result = verify_evidence_bundle(path)
        if result.valid:
            if authentication_key and not verify_checkpoint_authentication(
                load_report(path / "report.json"), authentication_key
            ):
                print("Invalid checkpoint authentication")
                return 2
            print(f"Valid evidence bundle: {result.run_id} ({result.files_checked} files)")
            return 0
        print("Invalid evidence bundle:")
        for error in result.errors:
            print(f"- {error}")
        return 2
    report = load_report(path)
    errors = verify_report_evidence(report)
    if errors:
        print("Invalid report evidence:")
        for error in errors:
            print(f"- {error}")
        return 2
    if authentication_key and not verify_checkpoint_authentication(report, authentication_key):
        print("Invalid checkpoint authentication")
        return 2
    print(f"Valid report evidence: {report.run_id} ({len(report.attempts)} attempts)")
    return 0


def _schema(args: argparse.Namespace) -> int:
    rendered = json.dumps(get_schema(args.name), indent=2, sort_keys=True) + "\n"
    if not args.output:
        print(rendered, end="")
        return 0
    destination = Path(args.output)
    atomic_write_text(destination, rendered)
    print(f"Schema: {destination}")
    return 0


def _doctor() -> int:
    checks = {
        "python>=3.10": sys.version_info >= (3, 10),
        "httpx": importlib.util.find_spec("httpx") is not None,
        "yaml": importlib.util.find_spec("yaml") is not None,
        "regex": importlib.util.find_spec("regex") is not None,
    }
    for name, passed in checks.items():
        print(f"[{'OK' if passed else 'MISSING'}] {name}")
    print("[OK] telemetry disabled")
    return 0 if all(checks.values()) else 2


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point."""

    parser = _parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "init":
            destination = write_starter_corpus(args.path, force=args.force)
            print(f"Created {destination}")
            return 0
        if args.command == "validate":
            cases = load_corpus(args.corpus)
            print(f"Valid corpus: {len(cases)} case(s)")
            return 0
        if args.command == "strategies":
            for name in strategy_names():
                print(name)
            return 0
        if args.command == "doctor":
            return _doctor()
        if args.command == "engagement":
            return _engagement(args)
        if args.command == "compare":
            return _compare(args)
        if args.command == "reproducers":
            return _reproducers(args)
        if args.command == "verify":
            return _verify(args)
        if args.command == "schema":
            return _schema(args)
        if args.command == "run":
            return _run(args)
    except (AdventPromptPwnError, FileExistsError, KeyError, OSError, ValueError) as exc:
        parser.error(str(exc))
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
