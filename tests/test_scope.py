from __future__ import annotations

from datetime import datetime, timezone

import pytest

from advent_prompt_pwn import Scope
from advent_prompt_pwn.core.scope import RequestGuard, ScopeMode
from advent_prompt_pwn.exceptions import BudgetExceeded, ScopeViolation


@pytest.mark.parametrize(
    "endpoint",
    [
        "memory://fake",
        "function://adapter",
        "http://localhost:8000/v1",
        "http://127.0.0.1:11434/api/chat",
        "http://[::1]:9000/v1",
    ],
)
def test_local_scope_accepts_only_local_endpoints(endpoint: str) -> None:
    Scope.local_only().assert_endpoint(endpoint)


def test_local_scope_rejects_remote_endpoint() -> None:
    with pytest.raises(ScopeViolation, match="non-loopback"):
        Scope.local_only().assert_endpoint("https://models.example.test/v1")


def test_scope_rejects_malformed_endpoint() -> None:
    with pytest.raises(ScopeViolation, match="no valid host"):
        Scope.local_only().assert_endpoint("not-a-url")


def test_scope_errors_do_not_echo_untrusted_endpoint_secrets() -> None:
    secret = "TOPSECRET"
    with pytest.raises(ScopeViolation) as raised:
        Scope.local_only().assert_endpoint(f"http:///v1?api_key={secret}")
    assert secret not in str(raised.value)


def test_authorized_scope_requires_reference_and_host() -> None:
    with pytest.raises(ValueError, match="allowed host"):
        Scope(ScopeMode.AUTHORIZED_REMOTE, authorization_reference="ticket")
    with pytest.raises(ValueError, match="authorization reference"):
        Scope(ScopeMode.AUTHORIZED_REMOTE, allowed_hosts=("example.test",))
    with pytest.raises(ValueError, match="bare hostnames"):
        Scope.authorized(["https://example.test"], "ticket")


def test_authorized_scope_uses_exact_host_allowlist() -> None:
    scope = Scope.authorized(
        ["AI.EXAMPLE.TEST"],
        "ENG-42",
        allow_unpinned_dns=True,
    )
    scope.assert_endpoint("https://ai.example.test/v1")
    with pytest.raises(ScopeViolation, match="not in"):
        scope.assert_endpoint("https://other.example.test/v1")


def test_authorized_scope_restricts_transport_ports_and_credentials() -> None:
    scope = Scope.authorized(
        ["ai.example.test"],
        "ENG-42",
        allowed_ports=[8443],
        allow_unpinned_dns=True,
    )
    scope.assert_endpoint("https://ai.example.test:8443/v1")
    with pytest.raises(ScopeViolation, match="port"):
        scope.assert_endpoint("https://ai.example.test:443/v1")
    with pytest.raises(ScopeViolation, match="insecure"):
        scope.assert_endpoint("http://ai.example.test:8443/v1")
    with pytest.raises(ScopeViolation, match="credentials"):
        scope.assert_endpoint("https://user:pass@ai.example.test:8443/v1")
    with pytest.raises(ScopeViolation, match="unsupported scheme"):
        scope.assert_endpoint("ftp://ai.example.test:8443/v1")
    with pytest.raises(ScopeViolation, match="query"):
        scope.assert_endpoint("https://ai.example.test:8443/v1?api_key=secret")
    with pytest.raises(ScopeViolation, match="invalid port"):
        scope.assert_endpoint("https://ai.example.test:bad/v1")


def test_authorized_scope_requires_explicit_remote_http_opt_in() -> None:
    scope = Scope.authorized(
        ["lab.example.test"],
        "ENG-HTTP",
        allow_insecure_http=True,
        allow_unpinned_dns=True,
    )
    scope.assert_endpoint("http://lab.example.test/v1")


def test_authorized_scope_requires_explicit_unpinned_dns_opt_in() -> None:
    scope = Scope.authorized(["lab.example.test"], "ENG-DNS")
    with pytest.raises(ScopeViolation, match="unpinned-DNS"):
        scope.assert_endpoint("https://lab.example.test/v1")
    Scope.authorized(["192.0.2.10"], "ENG-IP").assert_endpoint("https://192.0.2.10/v1")


def test_authorized_scope_verifies_every_resolved_address_against_dns_pins(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.core.scope as scope_module

    answers = [
        (2, 1, 6, "", ("192.0.2.10", 443)),
        (2, 1, 6, "", ("192.0.2.11", 443)),
    ]
    monkeypatch.setattr(scope_module.socket, "getaddrinfo", lambda *args, **kwargs: answers)
    scope = Scope.authorized(
        ["ai.example.test"],
        "ENG-PIN",
        pinned_dns={"AI.EXAMPLE.TEST": ("192.0.2.10", "192.0.2.11")},
    )
    scope.assert_endpoint("https://ai.example.test/v1")
    assert scope.pinned_dns["ai.example.test"] == ("192.0.2.10", "192.0.2.11")

    answers.append((2, 1, 6, "", ("198.51.100.8", 443)))
    with pytest.raises(ScopeViolation, match="approved IP pins"):
        scope.assert_endpoint("https://ai.example.test/v1")

    monkeypatch.setattr(
        scope_module.socket,
        "getaddrinfo",
        lambda *args, **kwargs: (_ for _ in ()).throw(OSError("synthetic")),
    )
    with pytest.raises(ScopeViolation, match="resolution failed"):
        scope.assert_endpoint("https://ai.example.test/v1")
    scope.assert_endpoint("https://ai.example.test/v1", verify_dns=False)


def test_scope_rejects_invalid_dns_pins() -> None:
    with pytest.raises(ValueError, match="present in allowed_hosts"):
        Scope.authorized(
            ["ai.example.test"],
            "ENG-PIN",
            pinned_dns={"other.example.test": ("192.0.2.10",)},
        )
    with pytest.raises(ValueError, match="IP addresses"):
        Scope.authorized(
            ["ai.example.test"],
            "ENG-PIN",
            pinned_dns={"ai.example.test": ("not-an-ip",)},
        )
    with pytest.raises(ValueError, match="at least one"):
        Scope.authorized(
            ["ai.example.test"],
            "ENG-PIN",
            pinned_dns={"ai.example.test": ()},
        )


def test_scope_enforces_timezone_aware_authorization_window() -> None:
    scope = Scope.local_only(
        not_before="2026-09-11T10:00:00Z",
        not_after="2026-09-11T11:00:00+00:00",
    )
    scope.assert_active(datetime(2026, 9, 11, 10, 30, tzinfo=timezone.utc))
    with pytest.raises(ScopeViolation, match="has not started"):
        scope.assert_active(datetime(2026, 9, 11, 9, 59, tzinfo=timezone.utc))
    with pytest.raises(ScopeViolation, match="has ended"):
        scope.assert_active(datetime(2026, 9, 11, 11, 0, tzinfo=timezone.utc))
    with pytest.raises(ValueError, match="timezone-aware"):
        scope.assert_active(datetime(2026, 9, 11, 10, 30))

    with pytest.raises(ValueError, match="timezone offset"):
        Scope.local_only(not_before="2026-09-11T10:00:00")
    with pytest.raises(ValueError, match="earlier"):
        Scope.local_only(
            not_before="2026-09-11T11:00:00Z",
            not_after="2026-09-11T10:00:00Z",
        )


def test_scope_query_parameters_require_noncredential_allowlist() -> None:
    scope = Scope.local_only(allowed_query_parameters=("tenant",))
    scope.assert_endpoint("http://127.0.0.1/v1?tenant=lab")
    with pytest.raises(ScopeViolation, match="allowlisted"):
        scope.assert_endpoint("http://127.0.0.1/v1?region=west")
    for name in ("client_secret", "Client-Secret", "access%5Ftoken"):
        with pytest.raises(ScopeViolation, match="credentials"):
            scope.assert_endpoint(f"http://127.0.0.1/v1?{name}=synthetic")
    with pytest.raises(ValueError, match="credential-like"):
        Scope.local_only(allowed_query_parameters=("api_key",))


@pytest.mark.parametrize(
    ("field", "value"),
    [("max_requests", 0), ("requests_per_minute", 0), ("max_concurrency", 0)],
)
def test_scope_validates_positive_limits(field: str, value: int) -> None:
    kwargs = {field: value}
    with pytest.raises(ValueError, match="positive"):
        Scope(ScopeMode.LOCAL, **kwargs)


def test_scope_validates_ports_and_initial_request_count() -> None:
    with pytest.raises(ValueError, match="ports"):
        Scope.authorized(["example.test"], "ticket", allowed_ports=[70000])
    with pytest.raises(ValueError, match="initial_count"):
        RequestGuard(Scope.local_only(), initial_count=-1)
    with pytest.raises(ValueError, match="must not exceed"):
        Scope.local_only(max_concurrency=33)


def test_request_guard_enforces_budget() -> None:
    guard = RequestGuard(Scope.local_only(max_requests=1, requests_per_minute=1_000_000))
    guard.acquire()
    assert guard.count == 1
    with pytest.raises(BudgetExceeded, match="exhausted"):
        guard.acquire()


def test_request_guard_accounts_for_resumed_requests() -> None:
    scope = Scope.local_only(max_requests=2, requests_per_minute=1_000_000)
    guard = RequestGuard(scope, initial_count=1)
    guard.acquire()
    assert guard.count == 2
    with pytest.raises(BudgetExceeded, match="exhausted"):
        guard.acquire()
    with pytest.raises(BudgetExceeded, match="previous request"):
        RequestGuard(scope, initial_count=3)


def test_request_guard_honors_resumed_rate_limit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import advent_prompt_pwn.core.scope as scope_module

    clock = {"wall": 100.0, "monotonic": 20.0}
    sleeps: list[float] = []

    monkeypatch.setattr(scope_module.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(scope_module.time, "monotonic", lambda: clock["monotonic"])

    def advance(seconds: float) -> None:
        sleeps.append(seconds)
        clock["wall"] += seconds
        clock["monotonic"] += seconds

    monkeypatch.setattr(scope_module.time, "sleep", advance)
    scope = Scope.local_only(max_requests=2, requests_per_minute=6)
    with pytest.raises(ValueError, match="finite non-negative"):
        RequestGuard(scope, initial_not_before_epoch_s=float("nan"))
    with pytest.raises(ValueError, match="more than one interval"):
        RequestGuard(scope, initial_not_before_epoch_s=111.1)

    guard = RequestGuard(
        scope,
        initial_count=1,
        initial_not_before_epoch_s=110.0,
    )
    guard.acquire()
    assert guard.count == 2
    assert sleeps == [10.0]


def test_request_guard_reserves_and_releases_unused_requests() -> None:
    guard = RequestGuard(Scope.local_only(max_requests=3, requests_per_minute=1_000_000))
    guard.reserve(3)
    assert guard.count == 3
    guard.release(2)
    assert guard.count == 1
    with pytest.raises(ValueError, match="more requests"):
        guard.release(2)
    with pytest.raises(ValueError, match="reservation"):
        guard.reserve(-1)
    with pytest.raises(ValueError, match="release count"):
        guard.release(-1)
    guard.reserve(0)
    guard.release(0)
